"""被动流量监听：实时盯着网卡，把流量按会话聚合，用「端口 + 首包特征」识别协议。

与主动体检（probe.py）互补：
    probe   主动发探测包，测「一次访问慢在哪一段」
    passive 被动听流量，看「这台机器实际在跟谁通信、用的到底是不是预期协议」

采集引擎两种，自动选择：
    scapy  已内置到 tools/python/Lib/site-packages（纯 Python，逐包解析，能直接看 payload）
    tshark 兜底：没有 scapy 时用 Wireshark 的 tshark -T fields 抽同样字段
两者输出格式一致，界面不区分引擎，只显示「引擎」标记。

输出是「会话表」：源 IP:端口、目标 IP:端口、协议、包数、字节数、平均包长、
连接状态（SYN 无响应 / ESTABLISHED / RST 重置 / FIN 关闭 / 无连接）。
认不出的协议显示 Unknown TCP / Unknown UDP —— 不猜、不报错。

只读监听：不发任何报文，也不写 pcap 文件。
"""
from __future__ import annotations

import queue
import re
import subprocess
import threading
import time

import probe  # 复用协议特征表与首包识别
import tshark

MAX_FLOWS = 400          # 最多回传多少条会话给界面
PAYLOAD_KEEP = 96        # 每条方向只留首包前 96 字节用于识别

# TCP 端口画像：在 probe 基础上补常见企业端口
TCP_PORTS = dict(probe.PORT_HINTS)
TCP_PORTS.update({
    88: "kerberos", 135: "rpc", 389: "ldap", 593: "rpc", 1433: "mssql",
    2049: "nfs", 3268: "ldap", 3269: "tls", 5985: "http", 5986: "tls",
    9092: "kafka", 5900: "vnc", 5672: "amqp", 8443: "tls", 9091: "http",
})

# UDP 端口画像
UDP_PORTS = {
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 123: "ntp",
    137: "netbios", 138: "netbios", 161: "snmp", 162: "snmp",
    443: "quic", 500: "ike", 514: "syslog", 623: "ipmi", 1194: "openvpn",
    1900: "ssdp", 3478: "stun", 4500: "ipsec", 5060: "sip",
    5353: "mdns", 5355: "llmnr",
}

EXTRA_NAMES = {
    "dns": "DNS", "dhcp": "DHCP", "ntp": "NTP", "quic": "QUIC", "mdns": "mDNS",
    "llmnr": "LLMNR", "ssdp": "SSDP", "netbios": "NetBIOS", "snmp": "SNMP",
    "ike": "IKE", "ipsec": "IPSec", "openvpn": "OpenVPN", "sip": "SIP",
    "stun": "STUN", "syslog": "Syslog", "ipmi": "IPMI", "tftp": "TFTP",
    "ldap": "LDAP", "kerberos": "Kerberos", "rpc": "RPC", "mssql": "MSSQL",
    "nfs": "NFS", "kafka": "Kafka", "vnc": "VNC", "amqp": "AMQP",
}

FLAG_FIN, FLAG_SYN, FLAG_RST, FLAG_PSH, FLAG_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


# ---------------------------------------------------------------- 引擎信息
def engine_status() -> dict:
    """检测当前可用的采集引擎。

    Returns:
        dict: 键 ``engine``（``scapy`` 或 ``tshark``）/ ``scapy``（bool）/
            ``scapy_version`` / ``pcap``（Scapy 是否绑定到 Npcap）/
            ``error``（Scapy 不可用的原因，便于界面直接展示）。
    """
    info = {"engine": "tshark", "scapy": False, "scapy_version": "", "error": ""}
    try:
        import scapy  # noqa: F401
        from scapy.all import conf
        info["scapy"] = True
        info["engine"] = "scapy"
        info["scapy_version"] = getattr(scapy, "__version__", "")
        info["pcap"] = bool(getattr(conf, "use_pcap", False))
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"{type(exc).__name__}: {exc}"[:160]
    return info


# ---------------------------------------------------------------- 工具函数
def _bpf(target: str) -> str:
    """把用户输入变成抓包过滤器；支持直接写 BPF 表达式。

    参数最终以 argv 形式传给 tshark（不经 shell），不存在命令注入；
    但仍要挡住控制字符和明显非法字符，否则只会得到一句看不懂的抓包错误。
    """
    t = (target or "").strip()
    if not t:
        return ""
    t = "".join(c for c in t if 32 <= ord(c) < 127)[:200]
    if not t:
        return ""
    if any(c in t for c in "\"'`;\\"):
        raise ValueError("目标里含有引号或反斜杠等非法字符")
    if " " in t or t.split()[0] in ("host", "net", "port", "tcp", "udp", "icmp"):
        return t
    if "/" in t:
        return f"net {t}"
    return f"host {t}"


def _resolve_iface(interface: str | None) -> tuple[dict | None, str]:
    """把界面传来的序号 / 名称 / 设备路径统一成抓包设备名。"""
    items = tshark.list_interfaces()
    raw = (interface or "").strip()
    chosen = None
    if raw.isdigit():
        chosen = next((i for i in items if i["index"] == int(raw)), None)
    elif raw:
        chosen = next((i for i in items if raw == i["name"] or raw in i["name"]), None)
    if chosen is None:
        chosen = tshark.pick_interface(items)
    name = (chosen or {}).get("name", "")
    m = re.search(r"(\\Device\\NPF_\{[^}]+\})", name)
    return chosen, (m.group(1) if m else name)


def _payload(b: bytes) -> bytes:
    return (b or b"")[:PAYLOAD_KEEP]


def _truth(v: str) -> bool:
    """tshark 的布尔字段输出 True/False（不是 1/0），这里统一判断。"""
    return str(v).strip().lower() in ("1", "true", "yes")


def _name(pid: str, transport: str) -> str:
    """协议 id → 界面显示名；识别不出就按传输层叫 Unknown TCP / UDP。"""
    if not pid:
        return f"Unknown {transport}"
    if pid in probe.PROTO_NAMES:
        return probe.PROTO_NAMES[pid][0]
    return EXTRA_NAMES.get(pid, pid.upper())


def _sniff(buf: bytes) -> tuple[str, str]:
    """首包特征识别（复用 probe 的规则，另补几个纯被动才常见的）。"""
    if not buf:
        return "", ""
    pid, why = probe._sniff(buf)
    if pid and pid != "text":
        return pid, why
    if buf[:4] == b"RFB ":
        return "vnc", "首包为 RFB 协议版本号"
    if buf[:1] in (b"\x00", b"\x01") and len(buf) >= 8 and buf[4:5] == b"\x00":
        # 无法确定时不猜，交给端口画像
        return "", ""
    return "", ""


def _classify(transport: str, sport: int, dport: int,
              c2s: bytes, s2c: bytes) -> tuple[str, str, str]:
    """返回 (协议 id, 显示名, 依据)。服务端先说的协议优先看反方向。"""
    for label, buf in (("服务端", s2c), ("客户端", c2s)):
        pid, why = _sniff(buf)
        if pid:
            return pid, _name(pid, transport), f"{label}首包：{why}"
    table = UDP_PORTS if transport == "UDP" else TCP_PORTS
    hint = table.get(dport) or table.get(sport) or ""
    if hint:
        return hint, _name(hint, transport), f"端口画像（{dport or sport}）"
    return "", f"Unknown {transport}", "无首包特征、端口无画像"


def _guess_roles(a: tuple, b: tuple, transport: str) -> tuple[tuple, tuple]:
    """猜客户端/服务端：知名端口 → 临时端口 → 端口大小，逐级降级判定。"""
    table = UDP_PORTS if transport == "UDP" else TCP_PORTS
    a_srv, b_srv = a[1] in table, b[1] in table
    if a_srv and not b_srv:
        return b, a
    if b_srv and not a_srv:
        return a, b

    def _ephemeral(p: int) -> bool:
        return 32768 <= p <= 65535

    a_eph, b_eph = _ephemeral(a[1]), _ephemeral(b[1])
    if a_eph and not b_eph:
        return a, b          # 临时端口一侧是客户端
    if b_eph and not a_eph:
        return b, a
    return (a, b) if a[1] < b[1] else (b, a)


def _tcp_state(f: dict, end: float) -> str:
    """根据标志位判定连接状态。SYN 只有在「等够 1.5 秒仍无回应」时才判为无响应，
    否则短时抓包会把「还没回」误报成「不回应」。"""
    fl = f["flags"]
    if fl & FLAG_RST:
        return "RST 重置"
    if fl & FLAG_FIN:
        return "FIN 关闭"
    if f["synack"] or (fl & FLAG_ACK and f["packets"] >= 3):
        return "ESTABLISHED"
    if fl & FLAG_SYN:
        return "SYN 无响应" if end - f["last"] >= 1.5 else "SYN 已发"
    return "活跃"


# ---------------------------------------------------------------- 记录采集
def _scapy_rec(pkt) -> dict | None:
    from scapy.all import IP, IPv6, TCP, UDP, Raw

    if IP in pkt:
        ip = pkt[IP]
    elif IPv6 in pkt:
        ip = pkt[IPv6]
    else:
        return None
    load = bytes(pkt[Raw].load) if Raw in pkt else b""
    t = float(getattr(pkt, "time", time.time()))
    size = len(pkt)
    if TCP in pkt:
        tcp = pkt[TCP]
        return {"t": t, "size": size, "transport": "TCP",
                "src_ip": ip.src, "dst_ip": ip.dst,
                "sport": int(tcp.sport), "dport": int(tcp.dport),
                "flags": int(tcp.flags), "payload": _payload(load)}
    if UDP in pkt:
        udp = pkt[UDP]
        return {"t": t, "size": size, "transport": "UDP",
                "src_ip": ip.src, "dst_ip": ip.dst,
                "sport": int(udp.sport), "dport": int(udp.dport),
                "flags": 0, "payload": _payload(load)}
    return None


def _capture_scapy(device: str, duration: int, bpf: str, max_packets: int,
                   logger=None, should_stop=None) -> list[dict]:
    """用 Scapy 实时抓包；逐包就地转成轻量记录，不把所有报文留在内存里。"""
    from scapy.all import AsyncSniffer

    recs: list[dict] = []
    cnt = {"n": 0, "drop": 0}

    def _prn(pkt):
        cnt["n"] += 1
        try:
            rec = _scapy_rec(pkt)
        except Exception:  # noqa: BLE001  畸形包直接跳过
            rec = None
            cnt["drop"] += 1
        if rec:
            recs.append(rec)
        if logger and cnt["n"] % 500 == 0:
            logger(f"已捕获 {cnt['n']} 个报文，会话 {len(recs)} 条…")

    sniffer = AsyncSniffer(iface=device or None, filter=(bpf or None), prn=_prn,
                           store=False, stop_filter=lambda p: cnt["n"] >= max_packets)
    sniffer.start()
    end = time.time() + duration
    while time.time() < end and cnt["n"] < max_packets:
        if should_stop and should_stop():
            if logger:
                logger("收到停止指令，提前结束抓包")
            break
        time.sleep(0.2)
    try:
        sniffer.stop()
    except Exception:  # noqa: BLE001
        pass
    if logger:
        logger(f"scapy 抓包结束：{cnt['n']} 个报文，异常包 {cnt['drop']} 个")
    return recs


TSHARK_FIELDS = [
    "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.push",
    "tcp.flags.reset", "tcp.payload", "udp.payload",
]


def _capture_tshark(device: str, duration: int, bpf: str, max_packets: int,
                    logger=None, should_stop=None) -> list[dict]:
    """兜底引擎：tshark 抽字段，解析成与 scapy 相同的记录结构。

    字段按表头名取值（`-E header=y`），不靠位置，避免以后加字段时错位。
    """
    exe = tshark.find_tshark()
    if not exe:
        raise RuntimeError("既没有 scapy 也找不到 tshark，无法被动抓包")
    args = [str(exe), "-i", device or "1", "-a", f"duration:{duration}",
            "-c", str(max_packets), "-T", "fields", "-E", "header=y",
            "-E", "separator=\t", "-E", "occurrence=f"]
    if bpf:
        args += ["-f", bpf]
    for f in TSHARK_FIELDS:
        args += ["-e", f]

    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace",
                            creationflags=tshark.CREATE_NO_WINDOW)

    # 必须边读边处理：tshark 输出量可达数 MB，管道缓冲区（约 64KB）写满后
    # 子进程会阻塞在 write 上，而父进程若在等进程退出就会死锁。
    lines: queue.Queue = queue.Queue(maxsize=50000)
    SENTINEL = None

    def _reader():
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                lines.put(line.rstrip("\r\n"))
        except Exception:  # noqa: BLE001
            pass
        finally:
            lines.put(SENTINEL)

    threading.Thread(target=_reader, daemon=True).start()

    header: list[str] | None = None
    recs: list[dict] = []
    deadline = time.time() + duration + 20
    stopped = False
    try:
        while True:
            try:
                line = lines.get(timeout=0.25)
            except queue.Empty:
                if should_stop and should_stop():
                    stopped = True
                if stopped or time.time() > deadline or len(recs) >= max_packets:
                    proc.kill()
                    break
                continue
            if line is SENTINEL:
                break
            if should_stop and should_stop():
                stopped = True
                proc.kill()
                break
            parts = line.split("\t")
            if header is None:
                header = parts
                continue
            if len(parts) < len(header):
                parts += [""] * (len(header) - len(parts))
            r = dict(zip(header, parts))
            try:
                t = float(r.get("frame.time_epoch") or 0)
            except ValueError:
                continue
            try:
                size_i = int(r.get("frame.len") or 0)
            except ValueError:
                size_i = 0
            sip = r.get("ip.src") or r.get("ipv6.src") or ""
            dip = r.get("ip.dst") or r.get("ipv6.dst") or ""
            tsp, tdp = r.get("tcp.srcport"), r.get("tcp.dstport")
            usp, udp_dp = r.get("udp.srcport"), r.get("udp.dstport")
            if tsp and tdp:
                transport, sport, dport, raw = "TCP", tsp, tdp, r.get("tcp.payload", "")
                flags = ((FLAG_SYN if _truth(r.get("tcp.flags.syn")) else 0)
                         | (FLAG_ACK if _truth(r.get("tcp.flags.ack")) else 0)
                         | (FLAG_FIN if _truth(r.get("tcp.flags.fin")) else 0)
                         | (FLAG_RST if _truth(r.get("tcp.flags.reset")) else 0)
                         | (FLAG_PSH if _truth(r.get("tcp.flags.push")) else 0))
            elif usp and udp_dp:
                transport, sport, dport, raw, flags = "UDP", usp, udp_dp, r.get("udp.payload", ""), 0
            else:
                continue
            try:
                payload = bytes.fromhex(raw.replace(":", ""))[:PAYLOAD_KEEP] if raw else b""
            except ValueError:
                payload = b""
            recs.append({"t": t, "size": size_i, "transport": transport,
                         "src_ip": sip, "dst_ip": dip,
                         "sport": int(sport or 0), "dport": int(dport or 0),
                         "flags": flags, "payload": payload})
    finally:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
        try:
            err = (proc.stderr.read() or "") if proc.stderr else ""  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            err = ""
        try:
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            pass
        if stopped and logger:
            logger("收到停止指令，提前结束抓包")

    if not recs and err.strip() and proc.returncode not in (0, None):
        raise RuntimeError(err.strip()[:200])
    if logger:
        logger(f"tshark 抓包结束：{len(recs)} 个报文")
    return recs


# ---------------------------------------------------------------- 会话聚合
def build_flows(recs: list[dict]) -> tuple[list[dict], dict]:
    """把逐包记录聚合成双向会话。

    方向和客户端角色由 SYN 方向推断，不靠端口大小猜；同一对端口的双向流量
    合并成一条会话，再分别统计上下行。

    Args:
        recs: 逐包记录列表，每项至少含 ``src_ip`` / ``sport`` / ``dst_ip`` /
            ``dport`` / ``transport`` / ``size`` / ``ts``。

    Returns:
        tuple[list[dict], dict]: ``(flows, summary)``。``flows`` 每项含五元组、
            包数/字节数、协议指纹、状态与应用线索；``summary`` 含会话总数、
            协议分布、扇出（同一本地端口连多个对端）提示等。
    """
    agg: dict[tuple, dict] = {}
    total_bytes = 0
    for r in recs:
        total_bytes += r["size"]
        e1 = (r["src_ip"], r["sport"])
        e2 = (r["dst_ip"], r["dport"])
        key = (r["transport"],) + tuple(sorted([e1, e2]))
        f = agg.get(key)
        if f is None:
            f = agg[key] = {
                "transport": r["transport"], "ep1": key[1], "ep2": key[2],
                "packets": 0, "bytes": 0, "first": r["t"], "last": r["t"],
                "flags": 0, "synack": False, "syn_dir": 0,
                "pkt_ep": {key[1]: 0, key[2]: 0}, "byte_ep": {key[1]: 0, key[2]: 0},
                "data": {},
            }
        f["packets"] += 1
        f["bytes"] += r["size"]
        f["first"] = min(f["first"], r["t"])
        f["last"] = max(f["last"], r["t"])
        f["pkt_ep"][e1] += 1
        f["byte_ep"][e1] += r["size"]
        fl = r.get("flags") or 0
        f["flags"] |= fl
        if fl & FLAG_SYN and not fl & FLAG_ACK:
            f["syn_dir"] = 1 if e1 == key[1] else 2
        if fl & FLAG_SYN and fl & FLAG_ACK:
            f["synack"] = True
        if r["payload"] and e1 not in f["data"]:
            f["data"][e1] = r["payload"]

    flows: list[dict] = []
    end_ts = max((f["last"] for f in agg.values()), default=time.time())
    for f in agg.values():
        a, b = f["ep1"], f["ep2"]
        if f["syn_dir"] == 1:
            client, server = a, b
        elif f["syn_dir"] == 2:
            client, server = b, a
        else:
            client, server = _guess_roles(a, b, f["transport"])

        pid, pname, why = _classify(f["transport"], client[1], server[1],
                                    f["data"].get(client, b""), f["data"].get(server, b""))
        state = _tcp_state(f, end_ts) if f["transport"] == "TCP" else "无连接"
        dur = max(0.0, f["last"] - f["first"])
        flows.append({
            "transport": f["transport"],
            "proto_id": pid,
            "proto": pname,
            "unknown": not pid,
            "src": f"{client[0]}:{client[1]}",
            "dst": f"{server[0]}:{server[1]}",
            "src_ip": client[0], "src_port": client[1],
            "dst_ip": server[0], "dst_port": server[1],
            "packets": f["packets"],
            "bytes": f["bytes"],
            "avg_size": round(f["bytes"] / f["packets"], 1) if f["packets"] else 0,
            "up_bytes": f["byte_ep"][client],
            "down_bytes": f["byte_ep"][server],
            "state": state,
            "evidence": why,
            "first_seen": time.strftime("%H:%M:%S", time.localtime(f["first"])),
            "duration_ms": round(dur * 1000.0, 1),
        })

    flows.sort(key=lambda x: (-x["bytes"], -x["packets"]))
    summary = {
        "flows": len(flows),
        "packets": len(recs),
        "bytes": total_bytes,
        "unknown": sum(1 for x in flows if x["unknown"]),
        "rst": sum(1 for x in flows if x["state"] == "RST 重置"),
        "syn_no_reply": sum(1 for x in flows if x["state"] == "SYN 无响应"),
        "by_proto": _count_by(flows),
        "fanout": _fanout(flows),
    }
    return flows[:MAX_FLOWS], summary


def _fanout(flows: list[dict], min_peers: int = 8) -> list[dict]:
    """找出「同一本地端口同时连很多对端」的会话。

    一线最常见的现象是「机器莫名卡/带宽被占满」，而抓包只看到大量短会话。
    P2P、视频分发、云盘同步、CDN 探测都会这样，值得单独提示一句。
    """
    acc: dict[tuple, dict] = {}
    for f in flows:
        key = (f["src_ip"], f["src_port"], f["transport"])
        it = acc.setdefault(key, {"src": f["src"], "transport": f["transport"],
                                  "peers": set(), "ports": set(),
                                  "bytes": 0, "packets": 0})
        it["peers"].add(f["dst_ip"])
        if f["dst_port"]:
            it["ports"].add(f["dst_port"])
        it["bytes"] += f["bytes"]
        it["packets"] += f["packets"]
    out = [{"src": v["src"], "transport": v["transport"], "peers": len(v["peers"]),
            "ports": sorted(v["ports"])[:6], "bytes": v["bytes"], "packets": v["packets"]}
           for v in acc.values() if len(v["peers"]) >= min_peers]
    out.sort(key=lambda x: (-x["peers"], -x["bytes"]))
    return out[:3]


def _count_by(flows: list[dict]) -> list[dict]:
    acc: dict[str, dict] = {}
    for f in flows:
        it = acc.setdefault(f["proto"], {"proto": f["proto"], "flows": 0,
                                         "bytes": 0, "unknown": f["unknown"]})
        it["flows"] += 1
        it["bytes"] += f["bytes"]
    return sorted(acc.values(), key=lambda x: -x["flows"])


# ---------------------------------------------------------------- 入口
def run(interface: str | None = None, duration: int = 20, target: str = "",
        max_packets: int = 20000, engine: str = "auto", logger=None,
        should_stop=None) -> dict:
    """监听网卡若干秒，返回会话表与汇总。**只听不发**，不构造任何报文。

    Args:
        interface: 网卡序号或名称关键字；空则自动挑选。
        duration: 监听秒数，夹在 3~300。
        target: 只保留与该目标相关的会话（IP/CIDR/域名）；空表示全部流量。
        max_packets: 包数上限，夹在 200~200000，防止长时间监听把内存吃满。
        engine: ``auto`` / ``scapy`` / ``tshark``；``auto`` 优先 Scapy，不可用时回落 tshark。
        logger: 日志回调。
        should_stop: 可选无参回调，返回 True 时提前结束（界面「停止」按钮用）。

    Returns:
        dict: 成功 ``{"ok": True, "interface", "duration", "engine", "bpf",
            "flows": [...], "summary": {...}}``；失败 ``{"ok": False, "error": "..."}``
            （如没有可用网卡、目标过滤器非法）。
    """
    duration = max(3, min(int(duration or 20), 300))
    max_packets = max(200, min(int(max_packets or 20000), 200000))
    target = (target or "").strip()
    try:
        bpf = _bpf(target)
    except ValueError as exc:
        return {"ok": False, "error": f"目标/过滤器不合法：{exc}"}
    chosen, device = _resolve_iface(interface)
    if not device:
        return {"ok": False, "error": "没有可用网卡：请安装 Npcap 并以管理员身份运行"}

    status = engine_status()
    used = status["engine"] if engine in ("auto", "") else engine
    if used == "scapy" and not status["scapy"]:
        used = "tshark"
    if used == "tshark" and not tshark.find_tshark():
        return {"ok": False, "error": "scapy 未安装且找不到 tshark，无法抓包"}

    if logger:
        logger(f"通信观察（被动监听）：网卡 {tshark.short_name(device)}，{duration}s，"
               f"过滤器 {bpf or '全部流量'}，引擎 {used}")

    t0 = time.time()
    try:
        if used == "scapy":
            recs = _capture_scapy(device, duration, bpf, max_packets, logger, should_stop)
        else:
            recs = _capture_tshark(device, duration, bpf, max_packets, logger, should_stop)
    except Exception as exc:  # noqa: BLE001
        if engine in ("auto", "") and used == "scapy":
            if logger:
                logger(f"scapy 不可用（{type(exc).__name__}: {exc}），改用 tshark 兜底")
            used = "tshark"
            try:
                recs = _capture_tshark(device, duration, bpf, max_packets, logger, should_stop)
            except Exception as exc2:  # noqa: BLE001
                return {"ok": False, "error": f"两种引擎都失败：{exc2}"}
        else:
            return {"ok": False, "error": f"{used} 抓包失败：{exc}"}

    flows, summary = build_flows(recs)
    iface_name = tshark.short_name((chosen or {}).get("name") or device)
    elapsed = round(time.time() - t0, 1)
    if logger:
        logger(f"通信观察（被动监听）完成：{summary['packets']} 个报文 / {summary['flows']} 条会话，"
               f"未识别 {summary['unknown']} 条")

    if not recs:
        return {
            "ok": True, "engine": used, "flows": [], "summary": summary,
            "interface": iface_name, "device": device,
            "duration": elapsed, "target": target, "bpf": bpf,
            "headline": "这段时间没有抓到与目标相关的流量",
            "advice": ("确认所选网卡是真正跑业务的那块（多网卡机器常见选错），"
                       "或目标 IP 写错；也可以把目标留空抓全部流量再筛选。"),
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    unknown = summary["unknown"]
    if unknown:
        headline = (f"抓到 {summary['flows']} 条会话，其中 {unknown} 条协议未识别"
                    f"（显示为 Unknown TCP/UDP）")
        advice = ("未识别不代表异常：多为自定义端口或加密私有协议。可对可疑目标用"
                  "「连通与速度测试」指定协议再探，或展开会话看端口与包长判断。")
    else:
        headline = f"抓到 {summary['flows']} 条会话，协议全部识别成功"
        advice = ("识别依据写在协议下方，鼠标悬停可看全文。要看某条连接为什么慢，"
                  "把目标填成它的 IP，用左侧「连通与速度测试」再测一次分段耗时。")

    # 单端口对多对端：带宽被谁占了的常见答案
    fan = summary.get("fanout") or []
    if fan:
        top = fan[0]
        headline += f"；{top['src']} 同时在连 {top['peers']} 个对端"
        advice = (f"{top['src']} 用 {top['transport']} 同时连接 {top['peers']} 个对端"
                  f"（对方端口 {', '.join(str(p) for p in top['ports'][:4]) or '不固定'}），"
                  f"累计 {top['bytes'] / 1024:.0f} KB。这种「一个端口扇出到很多 IP」的模式"
                  f"常见于 P2P 下载、视频分发、网盘同步或 CDN 探测，通常是带宽被占用的原因。"
                  "如非业务需要，可用 netstat -ano 找到对应进程再做限制。")

    return {
        "ok": True, "engine": used, "engine_version": status.get("scapy_version", ""),
        "flows": flows, "summary": summary,
        "interface": iface_name, "device": device,
        "duration": elapsed, "target": target, "bpf": bpf,
        "headline": headline, "advice": advice,
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
