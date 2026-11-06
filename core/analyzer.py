"""抓包分析引擎：网络故障分层定位（主）+ 安全隐患观察（次）。

核心目标：告诉一线运维「问题出在哪一层、哪个协议、哪个对端、有多严重」。
因此按 OSI 层次组织发现：
    L2 本地链路   ARP 无应答、二层可达性
    L3 网络层     ICMP 不可达/超时、路径 RTT、抖动
    L4 传输层     TCP 建连失败/被拒、重传、乱序、零窗口
    L7 应用层     DNS 解析、HTTP 状态码与响应时延、TLS 告警

数据流：tshark 输出按行流式解析，边读边聚合，大 pcap 不会撑爆内存。
仅依赖 Python 标准库 + tshark，可在 U 盘便携 Python 上直接运行。
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import ipaddress
import math
from collections import Counter, defaultdict
from pathlib import Path

try:                                              # 场景一：脚本方式（core/ 在 sys.path）
    from tshark import find_tshark, iter_lines
except ModuleNotFoundError:                        # 场景二：包方式（from core.analyzer import ...）
    import sys as _sys

    _CORE_DIR = str(Path(__file__).resolve().parent)
    if _CORE_DIR not in _sys.path:
        _sys.path.insert(0, _CORE_DIR)
    from tshark import find_tshark, iter_lines

try:                                              # 场景一：extract 作为顶层包（core/ 在 sys.path）
    from extract.fields import parse_flag as _parse_flag
except ModuleNotFoundError:                        # 场景二：包方式（from core.analyzer import ...）
    from core.extract.fields import parse_flag as _parse_flag

ROOT = Path(__file__).resolve().parents[1]

# 单次抓包解析的字段集合（一次 tshark 调用取全，避免多次扫描 pcap）
FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.len",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.flags.fin",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_full",
    "tcp.analysis.lost_segment",
    "tcp.analysis.ack_rtt",
    "udp.dstport",
    "dns.id",
    "dns.qry.name",
    "dns.flags.rcode",
    "dns.flags.response",
    "dns.time",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response.code",
    "http.time",
    "http.authorization",
    "ftp.request.command",
    "ftp.request.arg",
    "tls.handshake.extensions_server_name",
    "tls.alert_message",
    "icmp.type",
    "icmp.code",
    "arp.opcode",
    "arp.dst.proto_ipv4",
    "arp.src.proto_ipv4",
]

# 常见远控 / 后门 / 挖矿端口（安全观察用，非主线）
SUSPICIOUS_PORTS = {
    1080: "代理端口", 1337: "常见后门端口", 31337: "Back Orifice 后门端口",
    4444: "Metasploit 反弹端口", 4899: "Radmin 远控", 5555: "ADB/Meterpreter 常用",
    6667: "IRC C2 常用", 9001: "Tor 中继", 9050: "Tor Socks",
}

ICMP_CODES = {
    (3, 0): "网络不可达", (3, 1): "主机不可达", (3, 2): "协议不可达", (3, 3): "端口不可达",
    (3, 4): "需要分片但 DF 置位(MTU 问题)", (3, 9): "网络被管理禁止", (3, 10): "主机被管理禁止",
    (3, 13): "通信被管理过滤", (11, 0): "TTL 超时(可能存在路由环)",
}

SEV_ORDER = {"严重": 0, "警告": 1, "提示": 2, "—": 3}


def _num(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _flag(v) -> bool:
    """tshark 布尔字段 → ``bool``；逗号聚合值任一段为真即真。

    为什么不能只做精确匹配：``-E occurrence=a -E aggregator=,`` 下，
    同一帧出现两次 ``tcp.analysis.duplicate_ack`` 会输出 ``"1,1"``。
    旧实现 ``str(v).strip().lower() in ("1", "true", "yes")`` 会把它判成 False，
    于是「重复 ACK」恒为 0 —— 依赖 dup-ACK 的方向判定整条链路是死的。

    解析规则直接复用 :func:`core.extract.fields.parse_flag`，不在这里再写一份，
    避免两层对「什么算真」的理解漂移。

    Args:
        v: tshark 原始值，可能是 ``"1"`` / ``"0"`` / ``"True"`` / ``"1,1"`` / 空串。

    Returns:
        bool: 任一分段命中 ``1`` / ``true`` / ``yes``（大小写不敏感）即为真。
    """
    return _parse_flag(v)


def _port(v) -> int:
    """端口转 int：tshark 偶尔给空值或逗号聚合值，别让一行脏数据毁掉整次分析。"""
    try:
        return int(str(v).split(",")[0].strip())
    except (TypeError, ValueError):
        return 0


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


def _pct(part: float, total: float) -> float:
    return (part / total * 100.0) if total else 0.0


def _stats(values: list[float]) -> dict:
    """毫秒级统计：均值 / P95 / 最大 / 抖动(标准差)。"""
    if not values:
        return {"n": 0, "avg": 0.0, "p95": 0.0, "max": 0.0, "jitter": 0.0}
    s = sorted(values)
    n = len(s)
    avg = sum(s) / n
    var = sum((x - avg) ** 2 for x in s) / n
    return {
        "n": n,
        "avg": round(avg, 1),
        "p95": round(s[min(n - 1, int(round(0.95 * (n - 1))))], 1),
        "max": round(s[-1], 1),
        "jitter": round(math.sqrt(var), 1),
    }


def _row(layer: str, protocol: str, category: str, finding: str, severity: str,
         evidence: str, advice: str) -> dict:
    return {
        "layer": layer, "protocol": protocol, "category": category,
        "finding": finding, "severity": severity, "evidence": evidence, "advice": advice,
    }


def _new_stream(sid: str) -> dict:
    return {
        "id": sid, "client": "", "sport": "", "server": "", "dport": "",
        "packets": 0, "bytes": 0, "first": 0.0, "last": 0.0,
        "syn": 0, "syn_ts": 0.0, "synack_ts": 0.0, "ack_ts": 0.0,
        "retrans": 0, "syn_retrans": 0, "fast_retrans": 0, "dup_ack": 0, "ooo": 0,
        "zero_win": 0, "win_full": 0, "lost": 0, "rst": 0, "rst_hs": 0, "fin": 0,
        "cli_data_last": 0.0, "first_resp": 0.0, "think_ms": None,
        "srv_bytes": 0, "rtt": [], "app": "", "frames": [],
    }


def _guess_app(dport: str, sport: str) -> str:
    ports = {str(p) for p in (dport, sport)}
    for p, name in (("80", "HTTP"), ("8080", "HTTP"), ("8000", "HTTP"), ("443", "TLS"),
                    ("8443", "TLS"), ("53", "DNS"), ("22", "SSH"), ("3389", "RDP"),
                    ("445", "SMB"), ("3306", "MySQL"), ("1433", "MSSQL"),
                    ("1521", "Oracle"), ("6379", "Redis"), ("25", "SMTP"), ("110", "POP3")):
        if p in ports:
            return name
    return "TCP"


def _is_handshake_rst(stream: dict, from_client: bool) -> bool:
    """判断这次 RST 是不是「握手阶段被对端拒绝」。

    只有「客户端发出 SYN → 三次握手完成之前 → 服务端回 RST」才算
    「对方明确拒绝」（端口没开 / 被 ACL 或限流主动拒绝）。

    两种情况**不算**拒绝，必须排除，否则 ``conn_refused`` 会被高估：

    * 已建立连接之后再收到 RST —— 那是「连接被中断」，不是「被拒」；
    * 抓包从中途开始、没看到 SYN —— 无从判断，宁可不算。

    Args:
        stream: 该 TCP 流的聚合字典，需含 ``syn`` / ``synack_ts`` / ``ack_ts``。
        from_client: 这个 RST 是否由客户端发出（对端拒绝才是我们要的）。

    Returns:
        bool: True 表示应计入 ``conn_refused``。

    Note:
        只用于 ``conn_refused`` 这一个口径；``streams[].rst`` 的含义
        （该流出现过多少次 RST）保持不变，报告渲染仍依赖它。
    """
    if from_client:
        return False
    return bool(stream.get("syn")) and not stream.get("synack_ts") and not stream.get("ack_ts")


def _dns_timeout_count(q_ids, r_ids) -> int:
    """按 transaction id 配对，统计「发出查询但没收到响应」的次数。

    为什么不能用「查询数 − 响应数」：那只是数量差。响应重传、多问题单包、
    上游缓存返回多次，都会让差值失真 —— 重传一次就同时多算一次超时、
    少算一次失败。

    Args:
        q_ids: 查询侧的 ``(DNS 服务器, transaction id)`` 集合。
        r_ids: 响应侧的 ``(DNS 服务器, transaction id)`` 集合。

    Returns:
        int: 只有查询、没有对应响应的键数量。
    """
    return len(set(q_ids) - set(r_ids))


def collect(pcap: Path, log=None) -> tuple[dict, str]:
    """流式解析 pcap，边读边聚合。

    一次 tshark 调用取全所需字段，避免对同一文件扫多遍；输出按行消费，
    几十万行的 pcap 也不会把内存吃满。

    Args:
        pcap: 抓包文件路径。
        log: 可选日志回调 ``log(str)``，用于输出进度与 tshark 告警首行。

    Returns:
        tuple[dict, str]: ``(stats, error)``。``stats`` 是全部计数器与时间戳的聚合字典；
            ``error`` 为空串表示成功。**非空时必须整体放弃结论** ——
            tshark 退出码非 0（典型：文件不完整 rc=14、被超时杀掉 rc<0）意味着
            只读到一部分报文，此时算出来的「严重 0 条」是假象（见 docs/t00-findings.md）。
    """
    tshark = find_tshark()
    if not tshark:
        return {}, "未找到 tshark，请检查 tools/WiresharkPortable 是否完整"

    args = [
        str(tshark), "-r", str(pcap), "-n",
        "-T", "fields", "-E", "header=y", "-E", "separator=|",
        "-E", "quote=d", "-E", "aggregator=,", "-E", "occurrence=a",
    ]
    for f in FIELDS:
        args += ["-e", f]
    if log:
        log(f"解析抓包文件 {Path(pcap).name} ...")

    st = {
        "packets": 0, "bytes": 0, "first_ts": 0.0, "last_ts": 0.0,
        "tcp_packets": 0, "tcp_data": 0, "udp_packets": 0, "icmp_packets": 0,
        "proto_mix": Counter(), "tcp_bytes": 0,
        "retrans": 0, "syn_retrans": 0, "fast_retrans": 0, "dup_ack": 0, "ooo": 0, "lost": 0,
        "zero_win": 0, "win_full": 0, "rst": 0, "syn": 0, "synack": 0, "fin": 0,
        "streams": {},
        "dns_q": Counter(), "dns_r": Counter(), "dns_nx": Counter(), "dns_rcode": Counter(),
        "dns_times": [], "dns_detail": [], "nx_frames": defaultdict(list),
        "dns_servers": Counter(),
        # 按 (DNS 服务器, transaction id) 配对，用于判「查询发出后没有对应响应」
        "dns_q_ids": set(), "dns_r_ids": set(),
        "http_req": 0, "http_codes": Counter(), "http_times": [], "http_detail": [],
        "http_hosts": Counter(), "http_pending": {},
        "icmp_types": Counter(), "icmp_detail": [],
        "arp_req": Counter(), "arp_rep": set(), "arp_frames": defaultdict(list),
        "tls_alert": 0, "tls_sni": Counter(),
        "basic_auth": [], "uri_secret": [], "ftp_pass": [], "telnet_frames": [],
        "ext_dst": Counter(), "ext_ports": defaultdict(set), "ext_frames": defaultdict(list),
        "dst_all": Counter(),
    }

    sink: dict = {}
    header: list[str] | None = None
    reader_lines = iter_lines(args, timeout=1800, sink=sink)

    for raw in reader_lines:
        if not raw:
            continue
        cols = next(csv.reader(io.StringIO(raw), delimiter="|", quotechar='"'), [])
        if header is None:
            if cols and cols[0].strip().lower() in ("frame.number", "frame"):
                header = [c.strip() for c in cols]
                continue
            header = FIELDS
        if len(cols) < len(header):
            cols += [""] * (len(header) - len(cols))
        r = dict(zip(header, cols))

        st["packets"] += 1
        frame = r.get("frame.number", "")
        ts = _num(r.get("frame.time_epoch"))
        flen = int(_num(r.get("frame.len")))
        st["bytes"] += flen
        if ts:
            if not st["first_ts"] or ts < st["first_ts"]:
                st["first_ts"] = ts
            if ts > st["last_ts"]:
                st["last_ts"] = ts

        src, dst = r.get("ip.src", ""), r.get("ip.dst", "")
        if not src:
            src = r.get("ipv6.src", "")
        if not dst:
            dst = r.get("ipv6.dst", "")
        proto = r.get("ip.proto", "")
        if proto:
            st["proto_mix"][proto] += 1

        sport, dport = r.get("tcp.srcport", ""), r.get("tcp.dstport", "")
        sid = r.get("tcp.stream", "")

        # ---------------- TCP：流级聚合 ----------------
        if sid != "":
            st["tcp_packets"] += 1
            st["tcp_bytes"] += flen
            s = st["streams"].get(sid)
            if s is None:
                s = _new_stream(sid)
                st["streams"][sid] = s
            s["packets"] += 1
            s["bytes"] += flen
            if len(s["frames"]) < 4:
                s["frames"].append(frame)
            if not s["first"] or ts < s["first"]:
                s["first"] = ts
            if ts > s["last"]:
                s["last"] = ts
            is_syn, is_ack = _flag(r.get("tcp.flags.syn")), _flag(r.get("tcp.flags.ack"))
            is_rst, is_fin = _flag(r.get("tcp.flags.reset")), _flag(r.get("tcp.flags.fin"))
            tlen = int(_num(r.get("tcp.len")))

            if not s["client"]:
                try:
                    if int(sport or 0) > int(dport or 0):
                        s["client"], s["sport"], s["server"], s["dport"] = src, sport, dst, dport
                    else:
                        s["client"], s["sport"], s["server"], s["dport"] = dst, dport, src, sport
                except ValueError:
                    s["client"], s["sport"], s["server"], s["dport"] = src, sport, dst, dport
                s["app"] = _guess_app(s["dport"], s["sport"])

            # 只看端口大小是不够的：如果抓到的是 SYN（而非 SYN-ACK），发起方一定是客户端。
            # 这样中途开始抓包、或两端都是高位端口时，方向也不会判反。
            if is_syn and not is_ack and s["packets"] <= 3 and src != s["client"]:
                s["client"], s["sport"], s["server"], s["dport"] = src, sport, dst, dport
                s["app"] = _guess_app(s["dport"], s["sport"])

            from_client = (src == s["client"])

            if is_syn:
                st["syn"] += 1
                s["syn"] += 1
                if is_ack:
                    st["synack"] += 1
                    if not s["synack_ts"]:
                        s["synack_ts"] = ts
                elif from_client and not s["syn_ts"]:
                    s["syn_ts"] = ts
            elif from_client and is_ack and s["synack_ts"] and not s["ack_ts"]:
                s["ack_ts"] = ts

            if is_rst:
                st["rst"] += 1
                s["rst"] += 1
                if _is_handshake_rst(s, from_client):
                    s["rst_hs"] += 1
            if is_fin:
                st["fin"] += 1
                s["fin"] += 1
            if _flag(r.get("tcp.analysis.retransmission")):
                if is_syn:
                    # SYN 重发说明对端没回应（连接建立问题），不能算作链路丢包
                    st["syn_retrans"] += 1
                    s["syn_retrans"] += 1
                else:
                    st["retrans"] += 1
                    s["retrans"] += 1
            if _flag(r.get("tcp.analysis.fast_retransmission")):
                st["fast_retrans"] += 1
                s["fast_retrans"] += 1
            if _flag(r.get("tcp.analysis.duplicate_ack")):
                st["dup_ack"] += 1
                s["dup_ack"] += 1
            if _flag(r.get("tcp.analysis.out_of_order")):
                st["ooo"] += 1
                s["ooo"] += 1
            if _flag(r.get("tcp.analysis.zero_window")):
                st["zero_win"] += 1
                s["zero_win"] += 1
            if _flag(r.get("tcp.analysis.window_full")):
                st["win_full"] += 1
                s["win_full"] += 1
            if _flag(r.get("tcp.analysis.lost_segment")):
                st["lost"] += 1
                s["lost"] += 1
            rtt = _num(r.get("tcp.analysis.ack_rtt"))
            if rtt > 0:
                s["rtt"].append(rtt * 1000.0)

            if tlen > 0:
                st["tcp_data"] += 1
                if from_client:
                    s["cli_data_last"] = ts
                else:
                    s["srv_bytes"] += tlen
                    if not s["first_resp"]:
                        s["first_resp"] = ts
                        if s["cli_data_last"]:
                            gap = (ts - s["cli_data_last"]) * 1000.0
                            if -1 <= gap <= 600000:
                                s["think_ms"] = round(max(0.0, gap), 1)

        # ---------------- DNS ----------------
        qname = r.get("dns.qry.name", "")
        if qname:
            is_resp = _flag(r.get("dns.flags.response"))
            rcode = r.get("dns.flags.rcode", "")
            dns_id = r.get("dns.id", "")
            if dns_id:
                # 查询与响应都用「DNS 服务器的 IP + transaction id」做键：
                # 查询包的服务器是目的地址，响应包的服务器是源地址。
                # 同一个 id 从不同服务器发出不会被误配成一对。
                if is_resp:
                    st["dns_r_ids"].add((src, dns_id))
                else:
                    st["dns_q_ids"].add((dst, dns_id))
            for name in [x.strip().rstrip(".") for x in qname.split(",") if x.strip()]:
                if is_resp:
                    st["dns_r"][name] += 1
                    st["dns_rcode"][rcode or "0"] += 1
                    dns_ms = _num(r.get("dns.time")) * 1000.0
                    if dns_ms > 0:
                        st["dns_times"].append(dns_ms)
                    if rcode == "3":
                        st["dns_nx"][name] += 1
                        if len(st["nx_frames"][name]) < 5:
                            st["nx_frames"][name].append(frame)
                    if len(st["dns_detail"]) < 300:
                        st["dns_detail"].append({
                            "name": name, "rcode": rcode or "0",
                            "ms": round(dns_ms, 1), "frame": frame,
                            "server": src,
                        })
                    if src:
                        st["dns_servers"][src] += 1
                else:
                    st["dns_q"][name] += 1

        # ---------------- HTTP ----------------
        method = r.get("http.request.method", "")
        host = (r.get("http.host") or dst).strip()
        if method:
            st["http_req"] += 1
            st["http_hosts"][host] += 1
            uri = r.get("http.request.uri", "")
            st["http_pending"][sid] = {"host": host, "uri": uri, "method": method,
                                       "ts": ts, "frame": frame}
            if r.get("http.authorization"):
                st["basic_auth"].append({"frame": frame, "host": host,
                                         "uri": uri, "value": r["http.authorization"][:80]})
            if uri and any(k in uri.lower() for k in ("password=", "passwd=", "pwd=", "token=")):
                st["uri_secret"].append({"frame": frame, "host": host, "uri": uri[:120],
                                         "method": method})

        code = r.get("http.response.code", "")
        if code:
            st["http_codes"][code] += 1
            t_ms = _num(r.get("http.time")) * 1000.0
            if t_ms > 0:
                st["http_times"].append(t_ms)
            req = st["http_pending"].pop(sid, None) or {}
            if len(st["http_detail"]) < 300:
                st["http_detail"].append({
                    "host": req.get("host") or host,
                    "uri": (req.get("uri") or "")[:120],
                    "method": req.get("method", ""),
                    "code": code, "ms": round(t_ms, 1),
                    "frame": req.get("frame") or frame,
                    "stream": sid,
                })

        # ---------------- TLS ----------------
        sni = r.get("tls.handshake.extensions_server_name", "")
        if sni:
            for s in [x.strip() for x in sni.split(",") if x.strip()]:
                st["tls_sni"][s] += 1
        if r.get("tls.alert_message"):
            st["tls_alert"] += 1

        # ---------------- ICMP ----------------
        icmp_type = r.get("icmp.type", "")
        if icmp_type:
            st["icmp_packets"] += 1
            st["icmp_types"][icmp_type] += 1
            if icmp_type in ("3", "11") and len(st["icmp_detail"]) < 60:
                st["icmp_detail"].append({
                    "type": icmp_type, "code": r.get("icmp.code", ""),
                    "desc": ICMP_CODES.get((int(_num(icmp_type)), int(_num(r.get("icmp.code")))),
                                           f"ICMP type {icmp_type}/{r.get('icmp.code', '')}"),
                    "src": src, "dst": dst, "frame": frame,
                })

        # ---------------- ARP ----------------
        arp_op = r.get("arp.opcode", "")
        if arp_op:
            target_ip = r.get("arp.dst.proto_ipv4", "")
            src_ip = r.get("arp.src.proto_ipv4", "")
            if arp_op == "1":
                if target_ip:
                    st["arp_req"][target_ip] += 1
                    if len(st["arp_frames"][target_ip]) < 5:
                        st["arp_frames"][target_ip].append(frame)
            elif arp_op == "2":
                st["arp_rep"].add(src_ip)

        # ---------------- 其他应用层 ----------------
        if (r.get("ftp.request.command", "")).upper() == "PASS":
            st["ftp_pass"].append({"frame": frame, "arg": r.get("ftp.request.arg", ""), "dst": dst})
        if dport == "23" or sport == "23":
            if len(st["telnet_frames"]) < 50:
                st["telnet_frames"].append(frame)

        if dst:
            st["dst_all"][dst] += 1
            if _is_public(dst):
                st["ext_dst"][dst] += 1
                port = dport or r.get("udp.dstport")
                if port:
                    st["ext_ports"][dst].add(port)
                if len(st["ext_frames"][dst]) < 5:
                    st["ext_frames"][dst].append(frame)

    rc = sink.get("rc")
    err = (sink.get("stderr") or "").strip()
    if st["packets"] == 0:
        return {}, f"解析失败(rc={rc}): {err[:400] or '未解析到任何报文'}"

    st["duration"] = round(max(0.0, st["last_ts"] - st["first_ts"]), 2)

    # tshark 非 0 退出 = 没读到底（文件写到一半就被分析 / 解析被超时杀掉）。
    # 这时统计是「残缺」的：少几条会话会让严重项凭空消失（实测 3 项变 0 项），
    # 多几条半截会话又会伪造「建连无响应」。必须显式失败，不能返回半份结论。
    # rc=14 是 tshark 的「文件不完整」专用码（cut short），提示要更具体。
    if rc not in (0, None):
        if rc == 14 or "cut short" in err.lower():
            hint = "抓包文件不完整（写盘中断，或抓包进程还没退出就开始分析）"
        elif rc < 0:
            hint = "解析进程被超时中断"
        else:
            hint = f"解析异常退出（rc={rc}）"
        return {}, (f"{hint}：只读到 {st['packets']} 个报文，结论不可信。"
                    f"请等抓包完全结束/文件拷贝完成后再分析；反复出现可换更小的抓包文件。"
                    f"{(' ' + err.splitlines()[0][:160]) if err else ''}")

    if err and log:
        log(f"[提示] tshark 有告警输出：{err.splitlines()[0][:120]}")
    return st, ""


# ---------------------------------------------------------------- 派生指标

def _stream_rows(st: dict) -> list[dict]:
    """把流字典整理成可展示的会话明细，按「问题严重度」排序。"""
    out: list[dict] = []
    for sid, s in st["streams"].items():
        hs = None
        if s["syn_ts"] and s["synack_ts"]:
            hs = round((s["synack_ts"] - s["syn_ts"]) * 1000.0, 1)
        hs_total = None
        if s["syn_ts"] and s["ack_ts"]:
            hs_total = round((s["ack_ts"] - s["syn_ts"]) * 1000.0, 1)
        dur = round(max(0.0, s["last"] - s["first"]), 2)
        rtt = _stats(s["rtt"])
        flags: list[str] = []
        if s["syn"] and not s["synack_ts"] and not s["rst"]:
            flags.append("建连无响应")
        elif s["syn_retrans"]:
            flags.append(f"SYN 重发{s['syn_retrans']}")
        if s["rst"]:
            flags.append("被重置")
        if s["zero_win"]:
            flags.append("零窗口")
        if s["ooo"]:
            flags.append(f"乱序{s['ooo']}")
        if hs is not None and hs >= 300:
            flags.append(f"握手慢 {hs:.0f}ms")
        score = (100 if ("建连无响应" in flags) else 0) + len(flags) * 10 \
            + s["retrans"] * 2 + s["zero_win"] * 3 + s["rst"] * 5 + min(s["bytes"] / 1e6, 20)
        out.append({
            "stream": sid, "client": s["client"], "sport": s["sport"],
            "server": s["server"], "dport": s["dport"], "app": s["app"],
            "packets": s["packets"], "bytes": s["bytes"], "duration": dur,
            "handshake_ms": hs, "handshake_total_ms": hs_total,
            "rtt_avg": rtt["avg"], "rtt_max": rtt["max"],
            "retrans": s["retrans"], "syn_retrans": s["syn_retrans"],
            "dup_ack": s["dup_ack"], "ooo": s["ooo"],
            "zero_win": s["zero_win"], "think_ms": s["think_ms"],
            "srv_bytes": s["srv_bytes"], "rst": s["rst"],
            "flags": flags, "frames": s["frames"][:3], "score": round(score, 1),
        })
    out.sort(key=lambda x: (-x["score"], -x["bytes"]))
    return out


def _metrics(st: dict, streams: list[dict]) -> dict:
    rtt_all: list[float] = []
    for s in st["streams"].values():
        rtt_all += s["rtt"]
    rtt = _stats(rtt_all)
    dns = _stats(st["dns_times"])
    http = _stats(st["http_times"])
    hs = [x["handshake_ms"] for x in streams if x["handshake_ms"] is not None]
    hs_stats = _stats(hs)
    dns_q_total = sum(st["dns_q"].values())
    nx = sum(st["dns_nx"].values())
    codes = st["http_codes"]
    err5 = sum(v for k, v in codes.items() if k.startswith("5"))
    err4 = sum(v for k, v in codes.items() if k.startswith("4"))
    conn_fail = sum(1 for x in streams if "建连无响应" in (x["flags"] or []))
    # 只认「握手阶段被对端 RST」。已建连后的 RST 属于连接中断，
    # 不计入「被拒」——旧实现用 x["rst"] 判，会把正常关闭的 RST 也算进来。
    # 从 st 里取（st["streams"] 不对外暴露），避免给 _stream_rows 的投影加键
    # 而改变 meta.streams_top 的报告结构。
    conn_refused = sum(1 for s in st["streams"].values() if s.get("rst_hs"))
    arp_no_reply = [ip for ip, n in st["arp_req"].items() if n >= 2 and ip not in st["arp_rep"]]
    return {
        "rtt_avg_ms": rtt["avg"], "rtt_p95_ms": rtt["p95"], "rtt_max_ms": rtt["max"],
        "rtt_jitter_ms": rtt["jitter"], "rtt_samples": rtt["n"],
        "hs_samples": len(hs), "dns_samples": dns["n"], "http_samples": http["n"],
        "retrans_rate": round(_pct(st["retrans"], st["tcp_packets"]), 2),
        "dup_ack_rate": round(_pct(st["dup_ack"], st["tcp_packets"]), 2),
        "ooo_rate": round(_pct(st["ooo"], st["tcp_packets"]), 2),
        "dns_avg_ms": dns["avg"], "dns_p95_ms": dns["p95"], "dns_max_ms": dns["max"],
        "dns_jitter_ms": dns["jitter"],
        "dns_fail_rate": round(_pct(nx, dns_q_total), 1) if dns_q_total else 0.0,
        # 超时 = 按 transaction id 配对后「有问无答」的数量。
        # 旧口径 max(0, 查询数 − 响应数) 只是数量差，响应重传/多问题单包都会让它失真。
        "dns_timeouts": _dns_timeout_count(st.get("dns_q_ids", ()), st.get("dns_r_ids", ())),
        "http_avg_ms": http["avg"], "http_p95_ms": http["p95"], "http_max_ms": http["max"],
        "http_err5": err5, "http_err4": err4,
        "http_err5_rate": round(_pct(err5, st["http_req"]), 1) if st["http_req"] else 0.0,
        "hs_avg_ms": hs_stats["avg"], "hs_max_ms": hs_stats["max"],
        "hs_jitter_ms": hs_stats["jitter"],
        "conn_fail": conn_fail, "conn_refused": conn_refused,
        "icmp_unreach": sum(v for k, v in st["icmp_types"].items() if k == "3"),
        "icmp_timeout": sum(v for k, v in st["icmp_types"].items() if k == "11"),
        "arp_no_reply": len(arp_no_reply),
        "throughput_mbps": round(st["bytes"] * 8 / st["duration"] / 1e6, 2) if st["duration"] else 0.0,
        "tcp_throughput_mbps": round(st["tcp_bytes"] * 8 / st["duration"] / 1e6, 2) if st["duration"] else 0.0,
        "streams_total": len(st["streams"]),
    }


# ---------------------------------------------------------------- 分层发现

def build_findings(st: dict, m: dict, streams: list[dict]) -> list[dict]:
    """把统计聚合翻译成「按层归类的发现」，供 UI 与报告消费。

    Args:
        st: :func:`collect` 的统计字典（各类计数器）。
        m: :func:`_metrics` 算出的比率与时延指标（``retrans_rate`` / ``rtt_avg_ms`` 等）。
        streams: :func:`_stream_rows` 聚合出的会话列表。

    Returns:
        list[dict]: 每项 ``{"layer", "category", "severity", "finding", "advice", "evidence"}``，
            全部是**中文文案**（历史包袱，PR2 起改由规则引擎产出 ``findings_v2``）。
            没有异常时仍会有一条「安全观察」行，表示「检查过，没发现」。
    """
    rows: list[dict] = []
    takes = st["duration"] or 0

    # ============ L4 连接建立 ============
    if m["streams_total"] == 0:
        rows.append(_row("L4 传输层", "TCP", "连接建立",
                         "未检测到 TCP 会话（抓包周期内无 TCP 流量）", "—",
                         f"报文 {st['packets']} 个", "确认抓包网卡与过滤器是否选对"))
    else:
        if m["conn_fail"]:
            bad = [x for x in streams if "建连无响应" in x["flags"]][:3]
            detail = "；".join(f"{x['server']}:{x['dport']}（SYN {x['packets']} 包）" for x in bad)
            frames = ",".join(f"#{f}" for f in (bad[0].get("frames") or [])[:3]) if bad else "-"
            rows.append(_row(
                "L4 传输层", "TCP", "连接建立",
                f"{m['conn_fail']} 个连接发出 SYN 后始终没有收到回应，TCP 三次握手未完成",
                "严重",
                f"{detail}｜帧 {frames}",
                "先用「链路体检」测目标端口是否可达；再查中间防火墙/安全组是否放行该端口、"
                "目标服务是否只监听 127.0.0.1、路由是否回指正确。"))
        # 证据只列「握手期被拒」的流，与 conn_refused 的口径保持一致；
        # 若还按 x["rst"] 取，会把正常关闭的 RST 流写进证据里，读者会以为它也拒绝了连接。
        refused = [s for s in st["streams"].values() if s.get("rst_hs")][:3]
        if m["conn_refused"] >= 2:
            detail = "；".join(f"{x['server']}:{x['dport']}" for x in refused)
            rows.append(_row(
                "L4 传输层", "TCP", "连接建立",
                f"{m['conn_refused']} 个连接被对端 RST 重置（对方明确拒绝）",
                "警告" if m["conn_refused"] >= 3 else "提示",
                detail, "说明网络是通的、但端口没有服务在监听（或触发了限流/ACL 拒绝）。"
                        "确认服务进程是否启动、监听地址与端口是否正确。"))
        if m["hs_avg_ms"] and m["hs_avg_ms"] >= 300:
            sev = "警告" if m["hs_avg_ms"] < 800 else "严重"
            rows.append(_row(
                "L4 传输层", "TCP", "连接建立",
                f"TCP 握手平均 {m['hs_avg_ms']:.0f}ms、最大 {m['hs_max_ms']:.0f}ms，"
                f"抖动 {m['hs_jitter_ms']:.0f}ms", sev,
                f"共 {sum(1 for x in streams if x['handshake_ms'] is not None)} 个完整握手样本",
                "握手慢=syn/syn-ack 往返慢。跨地域/跨国访问属正常；同城专线出现该值，"
                "检查链路质量、是否绕行、是否有代理或 VPN 中转。"))
        if not any(r["category"] == "连接建立" and r["severity"] in ("严重", "警告") for r in rows):
            note = f"其中 {m['conn_refused']} 个被 RST（偶发，多为对端主动关闭）" \
                if m["conn_refused"] else "—"
            rows.append(_row("L4 传输层", "TCP", "连接建立",
                             f"建连正常（{m['streams_total']} 个会话，握手平均 "
                             f"{m['hs_avg_ms']:.0f}ms）", "—", note, "无需处理"))

    # ============ L4 传输质量 ============
    if st["tcp_packets"] == 0:
        rows.append(_row("L4 传输层", "TCP", "传输质量", "未检测到 TCP 报文", "—", "—", "确认抓包过滤器"))
    else:
        rr = m["retrans_rate"]
        if rr >= 5:
            sev = "严重"
        elif rr >= 2:
            sev = "警告"
        elif rr >= 0.5:
            sev = "提示"
        else:
            sev = "—"
        if sev != "—":
            top = [x for x in streams if x["retrans"]][:3]
            detail = "；".join(f"Stream {x['stream']} {x['client']}→{x['server']}:{x['dport']} "
                               f"重传 {x['retrans']} 次" for x in top) or "-"
            rows.append(_row(
                "L4 传输层", "TCP", "传输质量",
                f"TCP 重传率 {rr:.2f}%（{st['retrans']}/{st['tcp_packets']} 个报文），"
                f"乱序 {m['ooo_rate']:.2f}%，重复 ACK {m['dup_ack_rate']:.2f}%", sev,
                detail,
                "重传=发出去的数据没收到确认，等于丢包。先看是否集中在少数对端（对端或中间链路问题），"
                "再看是否全网段都高（本机网卡/上行链路问题）。排查顺序：网线/光模块 → 交换机端口"
                "（CRC 错包、双工不匹配）→ 无线信号 → 运营商链路。"))
        else:
            rows.append(_row("L4 传输层", "TCP", "传输质量",
                             f"传输质量正常（重传率 {rr:.2f}%，乱序 {m['ooo_rate']:.2f}%）",
                             "—", f"{st['tcp_packets']} 个 TCP 报文", "无需处理"))
        if st["zero_win"] >= 3 or st["win_full"] >= 10:
            rows.append(_row(
                "L4 传输层", "TCP", "传输质量",
                f"出现 TCP 零窗口 {st['zero_win']} 次、窗口满 {st['win_full']} 次", "警告",
                "零窗口=接收方缓冲区被塞满，发送方只能暂停",
                "这不是网络慢，是接收端应用处理不过来（线程池满、磁盘 IO 慢、GC 停顿）。"
                "排查服务端应用日志与 CPU/IO，而不是查网络。"))

    # ============ L3 网络层 ============
    if m["icmp_unreach"] or m["icmp_timeout"]:
        items = st["icmp_detail"][:3]
        detail = "；".join(f"{i['src']}→{i['dst']} {i['desc']}(帧 #{i['frame']})" for i in items)
        mtu_hit = any("MTU" in i["desc"] or "分片" in i["desc"] for i in st["icmp_detail"])
        rows.append(_row(
            "L3 网络层", "ICMP", "网络可达性",
            f"收到 {m['icmp_unreach']} 条 ICMP 不可达、{m['icmp_timeout']} 条超时"
            + ("，其中包含「需要分片」提示 → 典型 MTU/分片问题" if mtu_hit else ""),
            "严重" if mtu_hit else "警告", detail,
            "「端口不可达」= 网络通但服务没起；「主机/网络不可达」= 路由或防火墙拦截；"
            "「需要分片」= 路径 MTU 小于报文长度，需在 VPN/隧道接口下调小 MTU（如 1400）或修正 MSS。"))
    else:
        rows.append(_row("L3 网络层", "ICMP/IP", "网络可达性",
                         "未收到 ICMP 不可达/超时，三层转发正常", "—", "—", "无需处理"))

    if m["rtt_samples"] >= 5 and (m["rtt_avg_ms"] >= 300 or m["rtt_jitter_ms"] >= 80):
        rows.append(_row(
            "L3 网络层", "TCP/IP", "网络时延",
            f"往返时延 RTT 平均 {m['rtt_avg_ms']:.0f}ms、P95 {m['rtt_p95_ms']:.0f}ms、"
            f"最大 {m['rtt_max_ms']:.0f}ms，抖动 {m['rtt_jitter_ms']:.0f}ms",
            "警告" if m["rtt_avg_ms"] < 600 else "严重",
            f"基于 {m['rtt_samples']} 个 ACK 采样",
            "RTT 高且抖动小 → 物理距离/运营商路径长；RTT 抖动大 → 链路拥塞或无线信号不稳。"
            "可用 tracert 定位是哪一跳开始变慢。"))

    # ============ L7 域名解析 ============
    dns_q_total = sum(st["dns_q"].values())
    if dns_q_total == 0 and not st["dns_r"]:
        rows.append(_row("L7 应用层", "DNS", "域名解析",
                         "未检测到 DNS 报文（可能全部走了 DoH/DoT 或使用 hosts 解析）", "—",
                         "—", "如需验证 DNS，可在体检页直接测域名解析耗时"))
    else:
        total = dns_q_total or sum(st["dns_r"].values())
        fail = m["dns_fail_rate"]
        if fail >= 50:
            sev = "严重"
        elif fail >= 20:
            sev = "警告"
        else:
            sev = "—"
        if sev != "—":
            top = st["dns_nx"].most_common(3)
            detail = "；".join(f"{n} 失败 {c} 次" for n, c in top) or "-"
            rows.append(_row(
                "L7 应用层", "DNS", "域名解析",
                f"域名解析失败率 {fail:.0f}%（NXDOMAIN {sum(st['dns_nx'].values())}/{total}）",
                sev, detail,
                "先确认 DNS 服务器地址是否写错、域名是否拼错；若配置正常且集中在随机域名，"
                "再考虑 DNS 劫持或恶意程序。企业网内可对比 nslookup 与公共 DNS 的结果。"))
        if m["dns_timeouts"] >= 3:
            rows.append(_row(
                "L7 应用层", "DNS", "域名解析",
                f"有 {m['dns_timeouts']} 次查询没有收到响应（超时）", "警告",
                f"查询 {dns_q_total} 次 / 响应 {sum(st['dns_r'].values())} 次",
                "DNS 丢包常见于：UDP 53 被中间设备限速、DNS 服务器过载、"
                "或本地网络拥塞。可改用 TCP 查询或换备用 DNS 验证。"))
        if m["dns_avg_ms"] and m["dns_avg_ms"] >= 300:
            rows.append(_row(
                "L7 应用层", "DNS", "域名解析",
                f"DNS 响应平均 {m['dns_avg_ms']:.0f}ms、最大 {m['dns_max_ms']:.0f}ms",
                "警告" if m["dns_avg_ms"] < 800 else "严重",
                f"{len(st['dns_times'])} 个响应样本，DNS 服务器 "
                f"{'、'.join(ip for ip, _ in st['dns_servers'].most_common(2)) or '-'}",
                "打开网页前的第一段等待常来自这里。换更近的 DNS、开启本地缓存，"
                "或检查 DNS 服务器到目标域名的递归解析是否绕行。"))
        if not any(r["category"] == "域名解析" and r["severity"] in ("严重", "警告") for r in rows):
            rows.append(_row("L7 应用层", "DNS", "域名解析",
                             f"解析正常（{dns_q_total or total} 次查询，平均 "
                             f"{m['dns_avg_ms']:.0f}ms）", "—", "—", "无需处理"))

    # ============ L7 HTTP 响应 ============
    if st["http_req"]:
        codes = st["http_codes"]
        if m["http_err5"]:
            rows.append(_row(
                "L7 应用层", "HTTP", "应用响应",
                f"{m['http_err5']} 个请求返回 5xx（服务端错误，占 {m['http_err5_rate']:.0f}%）",
                "严重" if m["http_err5_rate"] >= 10 else "警告",
                "状态码分布：" + "、".join(f"{k}×{v}" for k, v in codes.most_common(5)),
                "5xx 是服务端自己的问题，网络背锅不成立。按状态码查应用日志："
                "500 看异常栈、502/504 看反向代理到后端的连通与超时、503 看是否过载/限流。"))
        if m["http_err4"] and not m["http_err5"]:
            rows.append(_row(
                "L7 应用层", "HTTP", "应用响应",
                f"{m['http_err4']} 个请求返回 4xx（客户端/权限问题）", "提示",
                "状态码分布：" + "、".join(f"{k}×{v}" for k, v in codes.most_common(5)),
                "401/403 查认证与权限，404 查地址或路由，429 查限流。属于请求本身的问题，不是链路故障。"))
        if m["http_avg_ms"] and (m["http_avg_ms"] >= 1000 or m["http_p95_ms"] >= 3000):
            slow = sorted([h for h in st["http_detail"] if h["ms"] > 0],
                          key=lambda x: -x["ms"])[:3]
            detail = "；".join(f"{h['host']}{h['uri']} {h['ms']:.0f}ms → {h['code']}"
                               for h in slow) or "-"
            rows.append(_row(
                "L7 应用层", "HTTP", "应用响应",
                f"HTTP 响应平均 {m['http_avg_ms']:.0f}ms、P95 {m['http_p95_ms']:.0f}ms、"
                f"最慢 {m['http_max_ms']:.0f}ms", "警告", detail,
                "先区分是「服务端算得慢」还是「网络传得慢」：看同一次请求的 TCP 握手 RTT，"
                "若响应时间远大于 RTT，则是服务端处理慢（查慢查询、下游依赖、GC）。"))
        if not any(r["category"] == "应用响应" and r["severity"] in ("严重", "警告") for r in rows):
            rows.append(_row("L7 应用层", "HTTP", "应用响应",
                             f"HTTP 响应正常（{st['http_req']} 个请求，平均 "
                             f"{m['http_avg_ms']:.0f}ms）", "—", "—", "无需处理"))
    elif st["tls_sni"] or st["tls_alert"]:
        sev = "提示" if st["tls_alert"] >= 10 else "—"
        rows.append(_row("L7 应用层", "TLS", "TLS 会话",
                         f"检测到 TLS 流量（{sum(st['tls_sni'].values())} 个 SNI"
                         + (f"，{st['tls_alert']} 条告警" if st["tls_alert"] else "") + "）",
                         sev,
                         "SNI：" + "、".join(n for n, _ in st["tls_sni"].most_common(3)) or "—",
                         "少量 TLS 告警通常是正常的关闭通知。若告警量大或集中在单个站点，"
                         "再查证书是否过期、域名是否匹配、协议/加密套件是否被中间设备拦截。"))

    # ============ L2 本地链路 ============
    no_reply = [ip for ip, n in st["arp_req"].items() if n >= 2 and ip not in st["arp_rep"]]
    if no_reply:
        rows.append(_row(
            "L2 本地链路", "ARP", "本地可达性",
            f"{len(no_reply)} 个同网段地址的 ARP 请求没有得到应答", "警告",
            "、".join(no_reply[:5]),
            "同网段内 ARP 不通，说明对方没开机、IP 冲突、或者接在了不同 VLAN。"
            "如果这就是网关地址，那么整台机器的外网访问都会断。"))

    # ============ 安全观察（次要） ============
    sec: list[dict] = []
    for ip, pkts in st["ext_dst"].most_common(50):
        ports = st["ext_ports"][ip]
        hit = [p for p in ports if _port(p) in SUSPICIOUS_PORTS]
        if hit:
            desc = "、".join(f"{p}({SUSPICIOUS_PORTS[_port(p)]})" for p in sorted(hit, key=_port))
            sec.append(_row("安全观察", "TCP", "可疑外联",
                            f"外联 {ip} 使用高危端口 {desc}，共 {pkts} 个报文", "警告",
                            "帧 " + ",".join(f"#{f}" for f in st["ext_frames"][ip][:5]),
                            "确认是否为业务需要；非业务用途时在防火墙阻断该方向，并在主机上定位进程。"))
        elif len(ports) >= 15:
            sec.append(_row("安全观察", "TCP", "端口扫描",
                            f"外联 {ip} 发散的端口达 {len(ports)} 个，疑似扫描", "提示",
                            "帧 " + ",".join(f"#{f}" for f in st["ext_frames"][ip][:5]),
                            "确认是否有资产测绘/漏扫任务在运行。"))
    if st["basic_auth"]:
        it = st["basic_auth"][0]
        sec.append(_row("安全观察", "HTTP", "明文凭证",
                        f"HTTP Basic 凭据明文传输（{it['host']}{it['uri'][:50]}）", "警告",
                        f"帧 #{it['frame']}", "改用 HTTPS；该账号口令按已泄露处理。"))
    if st["ftp_pass"]:
        it = st["ftp_pass"][0]
        sec.append(_row("安全观察", "FTP", "明文凭证",
                        f"FTP 明文口令传输到 {it['dst']}", "警告",
                        f"帧 #{it['frame']}", "改用 SFTP/FTPS，并重置口令。"))
    if st["uri_secret"]:
        it = st["uri_secret"][0]
        sec.append(_row("安全观察", "HTTP", "明文凭证",
                        f"URL 参数携带敏感字段（{it['method']} {it['host']}{it['uri'][:50]}）",
                        "提示", f"帧 #{it['frame']}", "改为 POST + HTTPS，避免凭据进入 URL 与日志。"))
    if st["telnet_frames"]:
        sec.append(_row("安全观察", "Telnet", "明文凭证",
                        f"存在 Telnet 明文会话（{len(st['telnet_frames'])} 个报文）", "提示",
                        "帧 " + ",".join(f"#{f}" for f in st["telnet_frames"][:5]),
                        "管理设备改用 SSH。"))
    if sec:
        rows.extend(sec)
    else:
        rows.append(_row("安全观察", "—", "安全观察",
                         "未发现可疑外联与明文认证（此项为附带观察，不是本工具主线）", "—",
                         "—", "无需处理"))
    return rows


def _cred_events(st: dict) -> list[dict]:
    out: list[dict] = []
    for item in st.get("basic_auth", [])[:5]:
        out.append({"type": "HTTP Basic", "where": f"{item['host']}{item['uri'][:50]}",
                    "detail": "Authorization 头 base64 明文", "frame": item["frame"]})
    for item in st.get("ftp_pass", [])[:5]:
        arg = (item["arg"][:2] + "***") if item.get("arg") else "***"
        out.append({"type": "FTP PASS", "where": str(item["dst"]),
                    "detail": f"口令 {arg}", "frame": item["frame"]})
    for item in st.get("uri_secret", [])[:5]:
        out.append({"type": "URL 敏感参数", "where": f"{item['host']}{item['uri'][:50]}",
                    "detail": item.get("method", "GET"), "frame": item["frame"]})
    if st.get("telnet_frames"):
        out.append({"type": "Telnet 会话", "where": "—",
                    "detail": f"{len(st['telnet_frames'])} 个明文报文",
                    "frame": st["telnet_frames"][0]})
    return out


def _ensure_root_on_path() -> None:
    """把项目根目录挂到 ``sys.path``，让 ``core.*`` 形式的包内导入可用。

    背景：本模块历史上是**扁平模块**（``import analyzer``，靠 ``diagnose`` 把
    ``core/`` 塞进 ``sys.path``）。新增的 ``core/rules/legacy_map.py`` 用的是
    包相对导入（``from ..contracts import``），必须以项目根为锚点才能加载。

    Returns:
        None。副作用是修改进程级 ``sys.path``，只在缺失时插入，重复调用无副作用。
    """
    import sys

    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def _build_findings_v2(rows: list, log=None) -> list[dict]:
    """把旧 ``rows[]`` 映射成结构化 ``findings_v2``（T03 迁移桥）。

    **只读 rows，不修改它**：旧的 UI / Markdown / AI 出口继续消费 ``rows``，
    这里只是额外产出一份带机器码的结论，供下游逐步切换。

    Args:
        rows: :func:`build_findings` 产出的旧结构中文字典列表。
        log: 可选日志回调 ``log(str)``；用于提示「有行没被映射」这类迁移期问题。

    Returns:
        可直接 JSON 序列化的字典列表（``Finding.to_dict()`` 的结果）。
        映射失败时返回空列表 —— **绝不抛异常**，否则会让整次诊断失败。

    Note:
        返回的是 dict 而非 ``Finding`` 对象，因为结果会被 ``server.py``
        直接 ``json.dumps`` 下发，dataclass 无法序列化。
    """
    try:
        _ensure_root_on_path()
        from core.rules.legacy_map import coverage, map_rows

        findings = map_rows(rows)
        unmatched = coverage(rows)["unmatched"]
        if unmatched and log:
            log(f"[提示] {unmatched} 条发现未命中迁移映射表（findings_v2 会少这几条）")
        return [f.to_dict() for f in findings]
    except Exception as exc:                       # noqa: BLE001  迁移期兜底，不影响主流程
        if log:
            log(f"[提示] findings_v2 生成失败，已跳过（不影响原有结论）：{exc}")
        return []


_TSHARK_VERSION: dict[str, str | None] = {"v": None}


def _tshark_version() -> str:
    """取 tshark 版本串，进程内缓存（``--version`` 约 200~400ms，不宜每次诊断都跑）。

    Returns:
        形如 ``"TShark (Wireshark) 4.7.4 ..."`` 的首行；取不到时返回空串。
    """
    if _TSHARK_VERSION["v"] is not None:
        return _TSHARK_VERSION["v"]
    value = ""
    try:
        from tshark import run

        exe = find_tshark()
        if exe:
            rc, out, err = run([str(exe), "--version"], timeout=20)
            text = (out or err or "").strip()
            if text:
                value = text.splitlines()[0].strip()[:120]
    except Exception:                              # noqa: BLE001  版本缺失不该影响诊断
        value = ""
    _TSHARK_VERSION["v"] = value
    return value


def _build_provenance() -> dict:
    """组装可复现信息（评审 4.1 第 5 条）：同样的输入为什么结论不同，靠它回答。

    Returns:
        可直接 JSON 序列化的字典，键同 :class:`core.contracts.Provenance` 字段。
        任一来源取不到时该键为空串，不抛异常。

    Note:
        ``config_sha256`` 只覆盖 app 配置与阈值，**不含 AI Key**（见 core.config）。
    """
    info = {
        "app_version": "",
        "schema_version": "",
        "tshark_version": _tshark_version(),
        "rules_version": "legacy",
        "config_sha256": "",
        "prompt_version": "",
        "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        _ensure_root_on_path()
        from core import contracts
        from core.config import config_sha256

        info["schema_version"] = contracts.SCHEMA_VERSION
        info["config_sha256"] = config_sha256()
    except Exception:                              # noqa: BLE001
        pass
    try:
        info["app_version"] = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return info


def analyze(pcap: Path | str, target: str = "", ti_key: str = "", log=None) -> dict:
    """离线分析一个 pcap，产出完整结果字典。

    Args:
        pcap: 抓包文件路径（``Path`` 或字符串）。
        target: 本次诊断目标的展示用名字（IP/域名），可空。
        ti_key: 威胁情报 API Key；为空则跳过可疑外联核对。
        log: 可选日志回调 ``log(str)``。

    Returns:
        dict: 成功时 ``ok=True``，键含 ``meta``（采集与明细）、``metrics``（扁平指标）、
            ``rows``（中文发现列表）、``summary``（计数摘要），以及 T03 新增的
            ``findings_v2``（带机器码的结构化结论）与 ``provenance``（可复现信息）。
            文件不存在或解析失败时返回 ``{"ok": False, "error": "..."}``。
    """
    pcap = Path(pcap)
    if not pcap.is_file():
        return {"ok": False, "error": f"抓包文件不存在: {pcap}"}
    st, err = collect(pcap, log=log)
    if err:
        return {"ok": False, "error": err}

    streams = _stream_rows(st)
    m = _metrics(st, streams)
    rows = build_findings(st, m, streams)
    critical = sum(1 for r in rows if r["severity"] == "严重")
    warning = sum(1 for r in rows if r["severity"] == "警告")

    dns_q_total = sum(st["dns_q"].values())
    nx_total = sum(st["dns_nx"].values())
    summary = {
        "target": target or "全网",
        "pcap_file": str(pcap),
        "critical_count": critical,
        "warning_count": warning,
        "retrans_rate": m["retrans_rate"],
        "dns_fail_rate": m["dns_fail_rate"],
        "rtt_avg_ms": m["rtt_avg_ms"],
        "http_avg_ms": m["http_avg_ms"],
        "conn_fail": m["conn_fail"],
    }

    result = {
        "ok": True,
        "meta": {
            "pcap_file": str(pcap),
            "pcap_name": pcap.name,
            "packets": st["packets"],
            "bytes": st["bytes"],
            "duration": st["duration"],
            "tcp_packets": st["tcp_packets"],
            "tcp_data_packets": st["tcp_data"],
            "retrans": st["retrans"],
            "retrans_rate": m["retrans_rate"],
            "dup_ack": st["dup_ack"],
            "ooo": st["ooo"],
            "zero_win": st["zero_win"],
            "rst": st["rst"],
            "syn": st["syn"],
            "synack": st["synack"],
            "dns_total": dns_q_total or sum(st["dns_r"].values()),
            "dns_resp": sum(st["dns_r"].values()),
            "nxdomain": nx_total,
            "dns_avg_ms": m["dns_avg_ms"],
            "dns_fail_rate": m["dns_fail_rate"],
            "dns_timeouts": m["dns_timeouts"],
            "http_req": st["http_req"],
            "http_err5": m["http_err5"],
            "http_avg_ms": m["http_avg_ms"],
            "rtt_avg_ms": m["rtt_avg_ms"],
            "rtt_max_ms": m["rtt_max_ms"],
            "rtt_jitter_ms": m["rtt_jitter_ms"],
            "hs_avg_ms": m["hs_avg_ms"],
            "conn_fail": m["conn_fail"],
            "conn_refused": m["conn_refused"],
            "icmp_unreach": m["icmp_unreach"],
            "icmp_timeout": m["icmp_timeout"],
            "arp_no_reply": m["arp_no_reply"],
            "throughput_mbps": m["throughput_mbps"],
            "streams_total": m["streams_total"],
            "external_ips": len(st["ext_dst"]),
            "http_hosts": st["http_hosts"].most_common(10),
            "tls_sni": st["tls_sni"].most_common(10),
            "top_external": st["ext_dst"].most_common(10),
            # ---- 技术明细 ----
            "dns_top": st["dns_q"].most_common(10),
            "nx_top": st["dns_nx"].most_common(5),
            "dns_detail": sorted(st["dns_detail"], key=lambda x: -x["ms"])[:15],
            "dns_servers": st["dns_servers"].most_common(3),
            "dns_rcode": st["dns_rcode"].most_common(6),
            "http_codes": st["http_codes"].most_common(8),
            "http_slow": sorted([h for h in st["http_detail"] if h["ms"] > 0],
                                key=lambda x: -x["ms"])[:10],
            "streams_top": streams[:12],
            "icmp_detail": st["icmp_detail"][:10],
            "proto_mix": [{"proto": _proto_name(k), "count": v}
                          for k, v in st["proto_mix"].most_common(6)],
            "retrans_streams": [(x["stream"], x["retrans"]) for x in streams if x["retrans"]][:5],
            "ext_detail": [
                {"ip": ip, "packets": n,
                 "ports": sorted(st["ext_ports"][ip], key=_port)[:12],
                 "risk_ports": sorted([p for p in st["ext_ports"][ip] if _port(p) in SUSPICIOUS_PORTS],
                                      key=_port)}
                for ip, n in st["ext_dst"].most_common(10)
            ],
            "cred_events": _cred_events(st),
            "threat_intel": {},
            "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tshark_path": str(find_tshark() or ""),
        },
        "metrics": m,
        "rows": rows,
        "summary": summary,
    }

    # ---- T03：增量产出结构化结论。旧的 rows[] / meta / metrics 一个字都不动 ----
    result["findings_v2"] = _build_findings_v2(rows, log=log)
    result["provenance"] = _build_provenance()
    return result


PROTO_NAMES = {"6": "TCP", "17": "UDP", "1": "ICMP", "2": "IGMP", "47": "GRE", "50": "ESP", "51": "AH"}


def _proto_name(v: str) -> str:
    return PROTO_NAMES.get(str(v), f"IP/{v}")
