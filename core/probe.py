"""链路体检：不抓包，直接分段测量一次真实访问，定位慢在哪一段。

重要：本模块不再假定目标一定是 Web 服务。探测顺序为

    DNS 解析 → TCP 建连 → 协议识别 → 该协议自己的握手/首包阶段

协议识别采用「被动 Banner + 端口画像 + 按协议问候」三段式，绝不硬套 Web 流程：

  1. 建连后先不发任何数据，最多等约 1 秒读服务端首包（MSG_PEEK，不消费数据）
     —— SSH / FTP / SMTP / MySQL / RDP 这类服务会主动报上名来；
  2. 没等到首包，再参考端口画像（80/8080 → HTTP、443 → HTTPS、445/139 → SMB…）；
  3. 只发该协议该发的报文：TLS ClientHello / HTTP GET / SMB2 Negotiate / RDP X.224；
  4. 既没 banner、端口也没画像，就降级为 Opaque TCP：只报建连延迟，不硬下结论。

阶段条（segments）随协议动态生成：
  TLS   → DNS / TCP / 协议识别 / TLS 握手 / HTTP 首字节
  HTTP  → DNS / TCP / 协议识别 / HTTP 首字节
  SMB   → DNS / TCP / 协议识别 / SMB 协商
  SSH…  → DNS / TCP / 协议识别 / 服务端响应
  Opaque→ DNS / TCP / 协议识别 / 服务端响应(跳过)

只用标准库 socket / ssl / select，不需要管理员权限，也不需要 Npcap。
"""
from __future__ import annotations

import select
import socket
import ssl
import struct
import time
from urllib.parse import urlparse

UA = "Mozilla/5.0 (compatible; USBNetDiag/1.0)"

# 协议 id → (中文显示名, 所属层)
PROTO_NAMES: dict[str, tuple[str, str]] = {
    "tls": ("TLS / HTTPS", "L7"),
    "http": ("HTTP（明文）", "L7"),
    "smb": ("SMB（Windows 文件共享）", "L7"),
    "ssh": ("SSH", "L7"),
    "ftp": ("FTP", "L7"),
    "smtp": ("SMTP", "L7"),
    "pop3": ("POP3", "L7"),
    "imap": ("IMAP", "L7"),
    "mysql": ("MySQL", "L7"),
    "rdp": ("RDP（远程桌面）", "L7"),
    "postgres": ("PostgreSQL", "L7"),
    "redis": ("Redis", "L7"),
    "mongodb": ("MongoDB", "L7"),
    "memcached": ("Memcached", "L7"),
    "oracle": ("Oracle", "L7"),
    "telnet": ("Telnet", "L7"),
    "opaque": ("未识别（Opaque TCP）", "L4"),
}

# 端口画像：只作「提示」，最终以首包字节为准
PORT_HINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap",
    80: "http", 81: "http", 3000: "http", 5000: "http", 7001: "http", 8000: "http",
    8008: "http", 8009: "http", 8080: "http", 8081: "http", 8088: "http",
    8090: "http", 8180: "http", 8880: "http", 8888: "http", 9000: "http",
    9001: "http", 9080: "http", 9090: "http", 10000: "http",
    443: "tls", 4443: "tls", 465: "tls", 636: "tls", 853: "tls", 990: "tls",
    992: "tls", 993: "tls", 995: "tls", 8443: "tls", 9443: "tls", 10443: "tls",
    445: "smb", 139: "smb",
    3389: "rdp",
    3306: "mysql", 5432: "postgres", 6379: "redis", 27017: "mongodb",
    11211: "memcached", 1521: "oracle", 2375: "http", 2376: "tls",
}

# 这些协议会「服务端先说」，被动 banner 就能识别
BANNER_PROTOS = {"ssh", "ftp", "smtp", "pop3", "imap", "mysql", "postgres",
                 "redis", "mongodb", "memcached", "oracle", "telnet"}

# 这些协议「客户端先说」，被动等待必然超时，直接按协议问候
ACTIVE_PROTOS = {"tls", "http", "smb", "rdp"}

# SMB2 状态码
SMB_STATUS = {
    0x00000000: "NT_STATUS_OK（协商成功）",
    0xC0000022: "拒绝访问（权限/共享未授权）",
    0xC00000CC: "网络名不存在（共享名不对）",
    0xC000006D: "用户名或密码错误",
    0xC0000016: "请求不被支持",
    0xC00000BB: "不支持的请求（可能是 SMB1 专用服务）",
    0x80090322: "目标未知（Kerberos 认证失败）",
    0xC0000120: "存在冲突",
    0xC0000103: "服务未启动（Server 服务异常）",
}

SMB_DIALECTS = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
                0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", 0x0000: "SMB 1.0"}


def _ms(sec: float) -> float:
    return round(max(0.0, sec) * 1000.0, 1)


def _stat(vals: list[float]) -> dict:
    if not vals:
        return {"n": 0, "min": 0.0, "avg": 0.0, "max": 0.0, "jitter": 0.0}
    n = len(vals)
    avg = sum(vals) / n
    var = sum((v - avg) ** 2 for v in vals) / n
    return {"n": n, "min": round(min(vals), 1), "avg": round(avg, 1),
            "max": round(max(vals), 1), "jitter": round(var ** 0.5, 1)}


def _hex(b: bytes, limit: int = 16) -> str:
    return " ".join(f"{x:02x}" for x in b[:limit])


def _text(b: bytes, limit: int = 120) -> str:
    """把首包转成可读文本：遇到第一个 CRLF 就截断，避免尾巴一长串点。"""
    cut = b[:limit]
    for sep in (b"\r\n", b"\n", b"\r"):
        i = cut.find(sep)
        if i > 0:
            cut = cut[:i]
            break
    return "".join(chr(x) if 32 <= x < 127 else "." for x in cut).strip(" .")


def _parse_target(target: str, port: int | None) -> tuple[str, int, str, bool, bool]:
    """兼容 `example.com`、`https://example.com/a`、`1.2.3.4:8080` 三种写法。

    返回 (host, port, path, scheme_tls, explicit_tls)，explicit_tls 表示协议头里
    明确写了 https://，此时不再做协议猜测。
    """
    t = (target or "").strip()
    if not t:
        raise ValueError("请填写要诊断的域名或 IP")
    explicit_tls = False
    path = "/"
    if "://" in t:
        u = urlparse(t)
        host = u.hostname or ""
        explicit_tls = u.scheme.lower() in ("https", "wss")
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        if port is None:
            port = u.port or (443 if explicit_tls else 80)
        return host, int(port), path, explicit_tls, explicit_tls
    host, _, p = t.partition("/")
    path = "/" + p if p else "/"
    if ":" in host and host.count(":") == 1:
        host, _, port_s = host.partition(":")
        if port_s.isdigit() and port is None:
            port = int(port_s)
    if port is None:
        port = 443
    return host.strip(), int(port), path, port == 443, False


def _resolve(host: str, port: int, rounds: int = 3) -> dict:
    """DNS 解析计时。返回首次（冷）与多次（热）耗时。"""
    try:
        socket.inet_aton(host)
        return {"skipped": True, "ms": 0.0, "ips": [host], "stats": _stat([]),
                "note": "输入已是 IP，跳过解析"}
    except OSError:
        pass
    times: list[float] = []
    ips: list[str] = []
    err = ""
    for _ in range(max(1, rounds)):
        t0 = time.perf_counter()
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
            times.append(_ms(time.perf_counter() - t0))
            for info in infos:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except (socket.gaierror, OSError) as exc:
            err = str(exc)
            times.append(_ms(time.perf_counter() - t0))
    stats = _stat(times)
    return {"skipped": False, "ms": stats["avg"], "cold_ms": times[0] if times else 0.0,
            "ips": ips, "stats": stats, "error": err if not ips else ""}


def _connect(ip: str, port: int, timeout: float) -> tuple[socket.socket | None, float, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.connect((ip, port))
        return s, _ms(time.perf_counter() - t0), ""
    except (OSError, socket.timeout) as exc:
        try:
            s.close()
        except OSError:
            pass
        return None, 0.0, str(exc) or type(exc).__name__


def _tcp(ip: str, port: int, count: int, timeout: float, deadline: float) -> dict:
    """连续建立 TCP 连接，测建连耗时、抖动与失败率（≈丢包/不通）。"""
    samples: list[float] = []
    fails = 0
    last_err = ""
    for _ in range(max(1, count)):
        if time.monotonic() > deadline:
            break
        s, ms, err = _connect(ip, port, timeout)
        if s is not None:
            samples.append(ms)
            try:
                s.close()
            except OSError:
                pass
        else:
            fails += 1
            last_err = err
    stats = _stat(samples)
    return {
        "ok": bool(samples), "stats": stats, "fail": fails,
        "tried": len(samples) + fails,
        "loss": round(fails / (len(samples) + fails) * 100.0, 1) if (samples or fails) else 0.0,
        "error": "" if samples else (last_err or "连接超时"),
    }


def _peek(sock: socket.socket, wait: float, size: int = 256) -> tuple[bytes, float, bool]:
    """被动等待服务端首包，用 MSG_PEEK 读取但不消费数据。

    返回 (bytes, 首包到达耗时, 是否对端主动关闭)。
    """
    wait = max(0.0, wait)
    t0 = time.perf_counter()
    try:
        ready, _, _ = select.select([sock], [], [], wait)
    except (OSError, ValueError):
        return b"", 0.0, False
    if not ready:
        return b"", 0.0, False
    elapsed = _ms(time.perf_counter() - t0)
    try:
        data = sock.recv(size, socket.MSG_PEEK)
    except (OSError, socket.timeout):
        return b"", elapsed, False
    return data, elapsed, data == b""


def _sniff(data: bytes) -> tuple[str, str]:
    """按首字节特征识别协议，返回 (proto_id, 依据)。识别不出返回 ("", "")。"""
    if not data:
        return "", ""
    if data[:2] == b"\x16\x03":
        return "tls", "首包以 0x16 0x03 开头（TLS 记录层握手）"
    if data[:5].upper() == b"HTTP/" or data[:4].upper() in (b"HTTP", b"GET "):
        return "http", "首包以 \"HTTP/\" 开头"
    sig = data[4:8] if data[4:8] in (b"\xffSMB", b"\xfeSMB") else data[:4]
    if sig in (b"\xffSMB", b"\xfeSMB"):
        return "smb", ("首包为 SMB2 报文（0xFE 53 4D 42）" if sig == b"\xfeSMB"
                       else "首包为 SMB1 报文（0xFF 53 4D 42）")
    if data[:4] == b"SSH-":
        return "ssh", f"首包 banner：{_text(data, 40)}"
    if data[:3] == b"\x03\x00\x00":
        return "rdp", "首包为 TPKT/X.224 连接确认（RDP）"
    if data[:3] == b"+OK":
        return "pop3", f"首包 banner：{_text(data, 40)}"
    if data[:4] == b"* OK":
        return "imap", f"首包 banner：{_text(data, 40)}"
    if len(data) >= 5 and data[3] == 0 and data[4] == 0x0A:
        return "mysql", "首包为 MySQL 握手包（协议版本 0x0A）"
    printable = sum(1 for x in data[:48] if 32 <= x < 127 or x in (9, 10, 13))
    if printable >= min(12, len(data[:48])) and printable >= len(data[:48]) * 0.85:
        return "text", f"首包为可读文本：{_text(data, 48)}"
    return "", ""


def _tls(ip: str, port: int, host: str, timeout: float) -> dict:
    """TLS 握手计时。证书不合法时先记下原因，再放开校验测握手本身。"""
    def _handshake(verify: bool) -> tuple[float, ssl.SSLSocket | None, str]:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except (NotImplementedError, AttributeError):
            pass
        raw, _, err0 = _connect(ip, port, timeout)
        if raw is None:
            return 0.0, None, err0
        try:
            t0 = time.perf_counter()
            ss = ctx.wrap_socket(raw, server_hostname=host)
            return _ms(time.perf_counter() - t0), ss, ""
        except (ssl.SSLError, OSError) as exc:
            try:
                raw.close()
            except OSError:
                pass
            return 0.0, None, str(exc)

    ms, ss, err = _handshake(True)
    cert_error = ""
    if ss is None:
        cert_error = err
        ms2, ss, err2 = _handshake(False)
        if ss is None:
            return {"ok": False, "ms": 0.0, "error": err2 or cert_error, "cert_error": "",
                    "version": "", "cipher": "", "alpn": ""}
        ms = ms2
    try:
        alpn = ss.selected_alpn_protocol() or ""
    except (AttributeError, OSError):
        alpn = ""
    info = {"ok": True, "ms": ms, "version": ss.version() or "",
            "cipher": (ss.cipher() or ("",))[0], "cert_error": cert_error, "alpn": alpn}
    try:
        ss.close()
    except OSError:
        pass
    return info


def _http(ip: str, port: int, host: str, path: str, use_tls: bool,
          timeout: float, deadline: float) -> dict:
    """发一个真实 GET，测首字节时间（TTFB）与总耗时。TTFB 才算服务端处理能力。"""
    if time.monotonic() > deadline:
        return {"ok": False, "error": "总耗时超出预算，跳过"}
    req = (f"GET {path or '/'} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
           f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
    raw, _, err0 = _connect(ip, port, timeout)
    if raw is None:
        return {"ok": False, "error": err0}
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)
        t0 = time.perf_counter()
        raw.sendall(req)
        first = raw.recv(4096)
        ttfb = _ms(time.perf_counter() - t0)
        total = ttfb
        body = first
        while len(body) < 65536:
            chunk = raw.recv(8192)
            if not chunk:
                break
            body += chunk
        total = _ms(time.perf_counter() - t0)
        text = body.decode("latin-1", "replace")
        status = 0
        server = ""
        first_line = text.split("\r\n", 1)[0]
        parts = first_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
        for line in text.split("\r\n")[:30]:
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break
        return {"ok": True, "status": status, "ttfb_ms": ttfb, "total_ms": total,
                "server": server, "first_line": first_line[:80]}
    except (OSError, socket.timeout, ssl.SSLError) as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _recv_exact(sock: socket.socket, n: int, timeout: float) -> bytes:
    buf = b""
    sock.settimeout(timeout)
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _smb(ip: str, port: int, timeout: float) -> dict:
    """SMB2 NEGOTIATE：只协商方言，不认证、不读写共享，安全且足够判断服务是否正常。"""
    body = struct.pack("<HHHHI16sQ", 36, 4, 1, 0, 0, b"\x00" * 16, 0)
    body += struct.pack("<HHHH", 0x0202, 0x0210, 0x0300, 0x0302)
    hdr = (b"\xfeSMB" + struct.pack("<HH", 64, 1) + struct.pack("<I", 0)
           + struct.pack("<H", 0) + struct.pack("<H", 31) + struct.pack("<I", 0)
           + struct.pack("<I", 0) + struct.pack("<Q", 0) + struct.pack("<I", 0)
           + struct.pack("<I", 0) + struct.pack("<Q", 0) + b"\x00" * 16)
    msg = hdr + body
    pkt = b"\x00" + len(msg).to_bytes(3, "big") + msg

    sock, _, err0 = _connect(ip, port, timeout)
    if sock is None:
        return {"ok": False, "error": err0}
    try:
        t0 = time.perf_counter()
        sock.sendall(pkt)
        head = _recv_exact(sock, 4, timeout)
        if len(head) < 4:
            return {"ok": False, "error": "SMB 协商无响应（端口通但服务未回包）",
                    "hint": "可能是 SMB1-only 服务、Server 服务未启动，或被安全策略拦截。"}
        ttfb = _ms(time.perf_counter() - t0)
        size = int.from_bytes(head[1:4], "big")
        payload = _recv_exact(sock, min(size, 65536), timeout)
        data = head + payload
        # 按签名定位，NetBIOS 会话头长度可能不固定
        base = data.find(b"\xfeSMB")
        smb2 = base >= 0
        if not smb2:
            base = data.find(b"\xffSMB")
        if base >= 0:
            status = struct.unpack("<I", data[base + 8:base + 12])[0] if smb2 else \
                struct.unpack("<I", data[base + 5:base + 9])[0]
            dialect = 0
            if smb2 and len(data) >= base + 70:
                dialect = struct.unpack("<H", data[base + 68:base + 70])[0]
            return {"ok": True, "ms": ttfb, "status": status,
                    "status_name": SMB_STATUS.get(status, f"0x{status:08X}"),
                    "version": "SMB2" if smb2 else "SMB1",
                    "dialect": SMB_DIALECTS.get(dialect, f"0x{dialect:04X}" if dialect else ""),
                    "first_line": _hex(data[base:base + 16], 20)}
        return {"ok": False, "ms": ttfb, "error": "回包不是 SMB 报文",
                "first_line": _hex(data[:20], 20)}
    except (OSError, socket.timeout) as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _rdp(ip: str, port: int, timeout: float) -> dict:
    """RDP：发一个 X.224 Connection Request，看是否能拿到 Connection Confirm。"""
    pkt = bytes.fromhex("030000130ee000000000000100080003000000")
    sock, _, err0 = _connect(ip, port, timeout)
    if sock is None:
        return {"ok": False, "error": err0}
    try:
        t0 = time.perf_counter()
        sock.sendall(pkt)
        head = _recv_exact(sock, 11, timeout)
        ms = _ms(time.perf_counter() - t0)
        if len(head) < 11:
            return {"ok": False, "error": "RDP 无响应"}
        if head[:3] == b"\x03\x00\x00" and head[5] in (0xD0, 0xD1):
            neg = ""
            if len(head) > 11:
                neg = "标准 RDP" if head[11] & 0x0F == 0 else "TLS/CredSSP"
            return {"ok": True, "ms": ms, "first_line": _hex(head, 11), "note": neg}
        return {"ok": False, "ms": ms, "error": "回包不是 X.224 连接确认",
                "first_line": _hex(head, 11)}
    except (OSError, socket.timeout) as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _banner_text(b: bytes) -> str:
    t = _text(b, 120)
    return t if t and t.count(".") < len(t) * 0.4 else ""


def _identify(ip: str, port: int, host: str, path: str, timeout: float,
              explicit_tls: bool, proto_override: str | None) -> dict:
    """协议识别 + 该协议的探测。返回 proto / 分段 / 各协议明细。"""
    hint = (proto_override or "").strip().lower() or PORT_HINTS.get(port, "")
    hint_src = "手动指定协议" if proto_override else f"端口 {port} 的常见协议画像"
    # 主动型协议（TLS/HTTP/SMB/RDP）绝不会服务端先说，只等 0.45s；其余等足 1s
    wait = 0.45 if hint in ACTIVE_PROTOS else 1.0
    if explicit_tls:
        wait = 0.45

    banner = b""
    banner_ms = 0.0
    closed_early = False
    sock, _, cerr = _connect(ip, port, timeout)
    if sock is not None:
        try:
            banner, banner_ms, closed_early = _peek(sock, min(wait, max(0.3, timeout * 0.4)))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    sniffed, basis = _sniff(banner)

    if explicit_tls:
        proto, basis = "tls", "目标写成 https:// ，按 TLS 探测"
        confident = True
    elif sniffed and sniffed != "text":
        proto, confident = sniffed, True
    elif hint:
        proto, confident = hint, False
        if sniffed == "text":
            basis = f"{basis}；结合{hint_src}判定为 {PROTO_NAMES.get(proto, (proto,))[0]}"
        elif banner:
            basis = f"首包未匹配已知特征（{_hex(banner, 8)}），按{hint_src}判定"
        else:
            basis = f"服务端未主动送 banner，按{hint_src}判定"
    else:
        proto, confident = "opaque", True
        basis = "无 banner 且端口无画像"

    if cerr:
        basis = f"建立探测连接失败：{cerr}"

    res: dict = {
        "proto": {
            "id": proto,
            "name": PROTO_NAMES.get(proto, (proto.upper(), "L7"))[0],
            "layer": PROTO_NAMES.get(proto, ("", "L7"))[1],
            "confident": confident,
            "basis": basis,
            "hint": hint,
            "banner_hex": _hex(banner, 24),
            "banner_text": _banner_text(banner),
            "banner_ms": banner_ms,
            "peer_closed": closed_early,
        },
        "id_ms": banner_ms,
        "id_status": "ok" if confident and banner else "skip",
        "id_note": basis,
        "tls": {"ok": False, "skipped": True, "ms": 0.0},
        "http": {"ok": False, "skipped": True, "error": "未执行 HTTP 探测"},
        "smb": {"ok": False, "skipped": True},
        "rdp": {"ok": False, "skipped": True},
        "extra": [],
    }

    if proto == "tls":
        tls = _tls(ip, port, host, timeout)
        res["tls"] = tls
        if tls.get("ok") and not confident:
            res["proto"].update({"confident": True,
                                 "basis": f"{hint_src}判定，TLS 握手已确认"
                                          f"（{tls.get('version') or 'TLS'}）"})
        res["id_status"] = "ok" if res["proto"]["confident"] else "skip"
        res["id_note"] = res["proto"]["basis"]
        res["extra"].append({"name": "TLS 握手", "ms": tls.get("ms", 0.0),
                             "status": "ok" if tls.get("ok") else "bad",
                             "note": "证书与加密协商" if tls.get("ok") else
                                     f"失败：{tls.get('error', '')[:48]}"})
        if tls.get("ok"):
            http = _http(ip, port, host, path, True, timeout, time.monotonic() + 30)
            res["http"] = http
            res["extra"].append({"name": "HTTP 首字节", "ms": http.get("ttfb_ms", 0.0),
                                 "status": "ok" if http.get("ok") else "skip",
                                 "note": "服务端处理" if http.get("ok") else
                                         f"未取到响应：{http.get('error', '')[:40]}"})
        else:
            # TLS 失败时确认一下：这个端口是不是压根就是明文协议（常见于 443 配错）
            probe = _http(ip, port, host, path, False, min(2.0, timeout),
                          time.monotonic() + 20)
            if probe.get("ok") and probe.get("status"):
                res["proto"].update({
                    "id": "http", "name": PROTO_NAMES["http"][0], "layer": "L7",
                    "confident": True,
                    "basis": f"该端口对明文 GET 返回了 HTTP {probe['status']}，不是 HTTPS 服务",
                })
                res["http"] = probe
                res["proto"]["id"] = "http"
                res["extra"] = [{"name": "HTTP 首字节", "ms": probe.get("ttfb_ms", 0.0),
                                 "status": "ok", "note": "服务端处理（明文 HTTP）"}]
            else:
                res["extra"].append({"name": "HTTP 首字节", "ms": 0.0, "status": "skip",
                                     "note": "TLS 未通过，跳过"})
    elif proto == "http":
        http = _http(ip, port, host, path, False, timeout, time.monotonic() + 30)
        res["http"] = http
        if http.get("ok") and http.get("status") and not confident:
            res["proto"].update({"confident": True,
                                 "basis": f"{hint_src}判定，已收到 HTTP {http['status']} 响应"})
        res["extra"].append({"name": "HTTP 首字节", "ms": http.get("ttfb_ms", 0.0),
                             "status": "ok" if http.get("ok") else "skip",
                             "note": "服务端处理（TTFB）" if http.get("ok") else
                                     f"未取到响应：{http.get('error', '')[:40]}"})
    elif proto == "smb":
        smb = _smb(ip, port, timeout)
        res["smb"] = smb
        note = "SMB 协商"
        if smb.get("ok"):
            note = f"{smb.get('version')} {smb.get('dialect')} · {smb.get('status_name')}"
            res["proto"].update({"confident": True,
                                 "basis": f"{hint_src}判定，已收到 {smb.get('version')} 协商响应"})
        elif smb.get("error"):
            note = str(smb.get("error"))[:60]
        res["extra"].append({"name": "SMB 协商", "ms": smb.get("ms", 0.0),
                             "status": "ok" if smb.get("ok") else "warn", "note": note})
    elif proto == "rdp":
        rdp = _rdp(ip, port, timeout)
        res["rdp"] = rdp
        if rdp.get("ok"):
            res["proto"].update({"confident": True,
                                 "basis": f"{hint_src}判定，已收到 X.224 连接确认"})
        res["extra"].append({"name": "RDP 响应", "ms": rdp.get("ms", 0.0),
                             "status": "ok" if rdp.get("ok") else "warn",
                             "note": "X.224 连接确认正常" if rdp.get("ok") else
                                     str(rdp.get("error", ""))[:60]})
    elif proto in BANNER_PROTOS:
        # banner 本身就是「响应延迟」，不再重复加一段
        if banner:
            res["id_note"] = f"banner（{banner_ms:.0f}ms）：{res['proto']['banner_text'][:60]}"
        elif not banner:
            res["id_note"] += "；服务端未主动送 banner（该服务通常要客户端先问候）"
    else:  # opaque
        res["id_note"] = ("已按手动指定跳过应用层探测，仅评估 TCP 连通性" if proto_override
                          else f"未收到 banner，端口 {port} 也不在常见协议画像内")
        res["extra"].append({"name": "响应延迟", "ms": 0.0, "status": "skip",
                             "note": "未发送任何探测报文，仅评估 TCP 连通性"})

    # 主动探测成功后，协议识别段标记为「已识别」，并显示确认依据
    if proto in ACTIVE_PROTOS and res["proto"]["confident"]:
        res["id_status"] = "ok"
        res["id_note"] = res["proto"]["basis"]
    return res


def run(target: str, port: int | None = None, count: int = 4, timeout: float = 3.0,
        tls_override: bool | None = None, proto: str | None = None) -> dict:
    """执行一次分段体检，返回各段耗时 + 协议 + 结论。

    proto 可手动指定 tls/http/smb/rdp/opaque，用于端口不常见的场景。
    """
    deadline = time.monotonic() + 45
    try:
        host, port, path, scheme_tls, explicit_tls = _parse_target(target, port)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if proto and proto not in PROTO_NAMES:
        proto = None
    if tls_override is True:
        explicit_tls = True
    elif tls_override is False and explicit_tls:
        explicit_tls = False

    dns = _resolve(host, port)
    if dns.get("error") and not dns.get("ips"):
        return {
            "ok": False,
            "level": "严重",
            "headline": f"域名解析失败：{host} 无法解析",
            "target": host, "port": port, "path": path,
            "error": f"DNS 解析失败：{dns['error']}",
            "advice": "确认域名拼写、DNS 服务器地址与网络连通性；可先用 nslookup 换公共 DNS 对比。",
            "segments": [{"name": "DNS 解析", "ms": dns["ms"], "status": "bad",
                          "note": "解析失败，后续步骤无法进行"}],
            "total_ms": 0,
        }

    ip = (dns.get("ips") or [""])[0]
    tcp = _tcp(ip, port, count, timeout, deadline)

    if tcp["ok"]:
        ident = _identify(ip, port, host, path, timeout, explicit_tls, proto)
    else:
        ident = {
            "proto": {"id": "unknown", "name": "未探测", "layer": "-", "confident": False,
                      "basis": "TCP 未连通，无法识别协议", "hint": "",
                      "banner_hex": "", "banner_text": "", "banner_ms": 0.0,
                      "peer_closed": False},
            "id_ms": 0.0, "id_status": "skip", "id_note": "TCP 未连通，跳过",
            "tls": {"ok": False, "skipped": True, "ms": 0.0},
            "http": {"ok": False, "skipped": True, "error": "TCP 未连通"},
            "smb": {"ok": False, "skipped": True},
            "rdp": {"ok": False, "skipped": True},
            "extra": [],
        }

    proto_info = ident["proto"]
    pid = proto_info["id"]
    tls_res = ident["tls"]
    http_res = ident["http"]
    smb_res = ident["smb"]
    rdp_res = ident["rdp"]

    segments = [
        {"name": "DNS 解析", "ms": dns["ms"],
         "status": "skip" if dns.get("skipped") else "ok",
         "note": "输入已是 IP" if dns.get("skipped") else "域名 → IP"},
        {"name": "TCP 建连", "ms": tcp["stats"]["avg"], "status": "ok", "note": "TCP 三次握手"},
        {"name": "协议识别", "ms": ident["id_ms"], "status": ident["id_status"],
         "note": ident["id_note"]},
    ]
    segments += ident["extra"]

    def seg(name: str) -> dict | None:
        return next((s for s in segments if s["name"] == name), None)

    notes: list[str] = []
    worst = 0  # 0=正常 1=警告 2=严重

    # ---------- DNS ----------
    if not dns.get("skipped"):
        ms = dns["ms"]
        if ms >= 800:
            s = seg("DNS 解析")
            if s:
                s.update(status="bad", note=f"解析很慢（{ms:.0f}ms），检查 DNS 服务器")
            notes.append("DNS 解析超过 800ms，打开任何系统都会先卡这一段。")
            worst = max(worst, 2)
        elif ms >= 200:
            s = seg("DNS 解析")
            if s:
                s.update(status="warn", note=f"解析偏慢（{ms:.0f}ms），建议换更近的 DNS")
            notes.append("DNS 解析超过 200ms，属于可优化项。")
            worst = max(worst, 1)

    # ---------- TCP ----------
    if not tcp["ok"]:
        s = seg("TCP 建连")
        if s:
            s.update(status="bad", note=f"连不上（{tcp['error']}）")
        for x in segments[2:]:
            if x["status"] != "bad":
                x["status"], x["note"] = "skip", "TCP 未通，跳过"
        notes.append(f"TCP {port} 端口完全连不上：要么端口没开、要么被防火墙/安全组拦截。")
        worst = 2
    else:
        st = tcp["stats"]
        if tcp["loss"] > 0:
            s = seg("TCP 建连")
            if s:
                s.update(status="bad", note=f"{tcp['loss']:.0f}% 的连接失败（丢包）")
            notes.append(f"连续建连 {tcp['tried']} 次失败 {tcp['fail']} 次，链路存在丢包。")
            worst = max(worst, 2)
        elif st["avg"] >= 500:
            s = seg("TCP 建连")
            if s:
                s.update(status="bad", note=f"建连很慢（{st['avg']:.0f}ms）")
            notes.append("TCP 握手超过 500ms，网络往返明显偏大。")
            worst = max(worst, 2)
        elif st["avg"] >= 150:
            s = seg("TCP 建连")
            if s:
                s.update(status="warn", note=f"建连偏慢（{st['avg']:.0f}ms）")
            notes.append(f"TCP 建连平均 {st['avg']:.0f}ms，超过内网常见的 100ms；"
                         "若目标在本地网段，先看交换机/无线和是否有跨网段绕行。")
            worst = max(worst, 1)
        if st["jitter"] >= 80 and st["n"] >= 3:
            s = seg("TCP 建连")
            if s:
                s.update(status="warn", note=f"抖动大（{st['jitter']:.0f}ms）")
            notes.append("多次建连耗时波动大，链路不稳定（无线/拥塞）。")
            worst = max(worst, 1)

    # ---------- 协议分支 ----------
    if tcp["ok"]:
        if pid == "tls":
            if not tls_res.get("ok"):
                notes.append("TCP 能通但 TLS 握手失败：证书、协议版本或加密套件被中间设备拦截。")
                worst = max(worst, 2)
            else:
                ce = tls_res.get("cert_error") or ""
                if ce:
                    low = ce.lower()
                    fatal = any(k in low for k in ("expired", "mismatch", "doesn't match",
                                                   "has expired", "revoked", "not yet valid"))
                    s = seg("TLS 握手")
                    if fatal:
                        if s:
                            s.update(status="warn", note="证书已过期/域名不匹配（已跳过校验完成握手）")
                        notes.append(f"证书校验不通过：{ce[:80]}")
                        worst = max(worst, 1)
                    else:
                        if s:
                            s.update(note="握手成功，但证书链不受本机信任（代理/自签常见）")
                        notes.append(f"证书链不被本机信任（企业代理或自签证书常见），"
                                     f"已放开校验完成握手：{ce[:60]}")
                if tls_res.get("ms", 0) >= 800:
                    s = seg("TLS 握手")
                    if s:
                        s.update(status="warn", note=f"握手慢（{tls_res['ms']:.0f}ms）")
                    notes.append("TLS 握手超过 800ms，常见于跨地域访问或中间设备解密。")
                    worst = max(worst, 1)
            if http_res.get("ok"):
                ttfb = http_res["ttfb_ms"]
                base = tcp["stats"]["avg"] + tls_res.get("ms", 0.0)
                if ttfb >= 3000:
                    s = seg("HTTP 首字节")
                    if s:
                        s.update(status="bad", note=f"服务端处理很慢（{ttfb:.0f}ms）")
                    notes.append("TCP/TLS 都很快，但首字节等了很久：问题在服务端处理链路"
                                 "（应用、数据库、下游依赖）。")
                    worst = max(worst, 2)
                elif ttfb >= 800 and ttfb > base * 3:
                    s = seg("HTTP 首字节")
                    if s:
                        s.update(status="warn", note=f"服务端响应偏慢（{ttfb:.0f}ms）")
                    notes.append("首字节时间明显大于网络往返，属于服务端处理慢。")
                    worst = max(worst, 1)
                if http_res.get("status", 0) >= 500:
                    s = seg("HTTP 首字节")
                    if s:
                        s.update(status="bad", note=f"服务端返回 {http_res['status']}")
                    notes.append(f"HTTP {http_res['status']}：服务端自身报错，与网络无关。")
                    worst = max(worst, 2)
                elif http_res.get("status", 0) >= 400:
                    notes.append(f"HTTP {http_res['status']}：请求被拒绝或路径不对，"
                                 "检查地址、虚拟主机与访问权限。")
                    worst = max(worst, 1)

        elif pid == "http":
            if http_res.get("ok"):
                ttfb = http_res["ttfb_ms"]
                base = tcp["stats"]["avg"]
                if ttfb >= 3000:
                    s = seg("HTTP 首字节")
                    if s:
                        s.update(status="bad", note=f"服务端处理很慢（{ttfb:.0f}ms）")
                    notes.append("建连很快但首字节等很久：应用层处理慢（程序、数据库、下游依赖）。")
                    worst = max(worst, 2)
                elif ttfb >= 800 and ttfb > base * 3:
                    s = seg("HTTP 首字节")
                    if s:
                        s.update(status="warn", note=f"服务端响应偏慢（{ttfb:.0f}ms）")
                    notes.append("首字节时间明显大于网络往返，属于服务端处理慢。")
                    worst = max(worst, 1)
                if http_res.get("status", 0) >= 500:
                    s = seg("HTTP 首字节")
                    if s:
                        s.update(status="bad", note=f"服务端返回 {http_res['status']}")
                    notes.append(f"HTTP {http_res['status']}：服务端自身报错，与网络无关。")
                    worst = max(worst, 2)
                elif http_res.get("status", 0) >= 400:
                    notes.append(f"HTTP {http_res['status']}：请求被拒绝或路径不对，"
                                 "检查地址、虚拟主机与访问权限。")
                    worst = max(worst, 1)
            else:
                s = seg("HTTP 首字节")
                if s:
                    s.update(status="skip", note=f"未取到响应：{http_res.get('error', '')[:30]}")
                notes.append(f"端口通但没返回 HTTP 响应：{http_res.get('error', '')}"
                             "（该端口可能不是 HTTP 服务，可指定协议或改端口）")

        elif pid == "smb":
            s = seg("SMB 协商")
            if smb_res.get("ok"):
                status = smb_res.get("status", 0)
                if status == 0:
                    if smb_res.get("ms", 0) >= 1500:
                        if s:
                            s.update(status="warn", note=f"协商成功但偏慢（{smb_res['ms']:.0f}ms）")
                        notes.append("SMB 协商成功但耗时偏长，多为服务端负载高或跨网段访问。")
                        worst = max(worst, 1)
                else:
                    if s:
                        s.update(status="warn", note=smb_res.get("status_name", ""))
                    notes.append(f"SMB 协商返回 {smb_res.get('status_name')}："
                                 "网络是通的，问题在共享/认证/服务端策略。")
                    worst = max(worst, 1)
            else:
                if s:
                    s.update(status="warn", note=str(smb_res.get("error", ""))[:50])
                notes.append(str(smb_res.get("hint") or
                                 "SMB 协商无响应：确认 Server 服务、445 端口策略与防火墙。"))
                worst = max(worst, 1)

        elif pid == "rdp":
            s = seg("RDP 响应")
            if rdp_res.get("ok"):
                if rdp_res.get("ms", 0) >= 1500:
                    if s:
                        s.update(status="warn", note=f"响应偏慢（{rdp_res['ms']:.0f}ms）")
                    worst = max(worst, 1)
            else:
                notes.append("RDP 端口通但没返回 X.224 连接确认：可能不是远程桌面服务，"
                             "或被安全策略/NLA 前置设备拦截。")
                worst = max(worst, 1)

        elif pid in BANNER_PROTOS:
            s = seg("协议识别")
            bms = ident["id_ms"]
            if proto_info.get("banner_hex"):
                if bms >= 1500 and s:
                    s.update(status="warn", note=f"banner 返回偏慢（{bms:.0f}ms）")
                    notes.append("服务端首包返回偏慢，多为服务端负载高或链路 RTT 大。")
                    worst = max(worst, 1)
            elif proto_info.get("peer_closed"):
                if s:
                    s.update(status="warn", note="对端立即关闭连接")
                notes.append("建连后对端立即关闭：可能是服务只接受特定客户端，"
                             "或有安全设备在阻断。")
                worst = max(worst, 1)

    total = sum(s["ms"] for s in segments)
    level = {0: "正常", 1: "警告", 2: "严重"}[worst]
    pname = proto_info["name"]
    layers = proto_info["layer"]

    if worst == 0:
        if pid == "opaque":
            headline = (f"TCP 连通正常（建连 {tcp['stats']['avg']:.0f}ms）："
                        f"服务端未主动送数据，按 {pname} 处理")
            advice = ("该端口没有可识别的应用层握手（未发送任何探测报文），因此只评估了网络层："
                      "端口可达、建连延迟正常。若要进一步判断服务，请指定协议类型或改用抓包。")
        elif pid == "smb":
            headline = (f"SMB 服务正常：建连 {tcp['stats']['avg']:.0f}ms，"
                        f"协商 {smb_res.get('ms', 0):.0f}ms（{smb_res.get('dialect') or 'SMB'}）")
            advice = "网络与 SMB 协商都正常。若仍打不开共享，请查共享权限、账号认证与 DNS 名称解析。"
        elif pid == "tls":
            headline = (f"链路正常：总耗时 {total:.0f}ms，"
                        f"{tls_res.get('version', 'TLS')} 握手 "
                        f"{tls_res.get('ms', 0):.0f}ms")
            advice = ("本次体检未发现异常。若用户仍反馈慢，请在其实际操作时抓包，"
                      "或换一个目标地址对比。")
        elif pid in BANNER_PROTOS and proto_info.get("banner_hex"):
            headline = (f"{pname} 响应正常：建连 {tcp['stats']['avg']:.0f}ms，"
                        f"banner {ident['id_ms']:.0f}ms")
            advice = ("端口可达、服务端已按要求返回 banner。若业务仍异常，"
                      "请抓包看完整交互（认证、读写、超时）。")
        else:
            advice = ("本次体检未发现异常。若用户仍反馈慢，请在其实际操作时抓包，"
                      "或换一个目标地址对比。")
    else:
        bad = next((s for s in segments if s["status"] == "bad"), None)
        warn = next((s for s in segments if s["status"] == "warn"), None)
        focus = bad or warn or max(segments, key=lambda s: s["ms"])
        headline = f"瓶颈在「{focus['name']}」：{focus['note']}"
        advice = "；".join(dict.fromkeys(notes)) or "按上表红/黄段落逐项排查。"

    return {
        "ok": True,
        "target": host, "port": port, "path": path, "ip": ip,
        "proto": proto_info,
        "protocol": proto_info["name"],
        "layer": layers,
        "use_tls": pid == "tls",
        "dns": dns, "tcp": tcp, "tls": tls_res, "http": http_res,
        "smb": smb_res, "rdp": rdp_res,
        "segments": segments,
        "total_ms": round(total, 1),
        "level": level,
        "headline": headline,
        "advice": advice,
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
