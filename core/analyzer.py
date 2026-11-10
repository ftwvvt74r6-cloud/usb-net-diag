"""抓包分析引擎：网络故障分层定位（主）+ 安全隐患观察（次）。

核心目标：告诉使用者「问题出在哪一层、哪个协议、哪个对端、有多严重」。
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

try:                                              # 文案表访问器（扁平导入：core/ 在 sys.path）
    from copytext import load_table as _copy_load, text as _copy_text
except ModuleNotFoundError:                        # 包方式：仓库根在 sys.path
    from core.copytext import load_table as _copy_load, text as _copy_text

try:                                              # 版本号读取（扁平导入：core/ 在 sys.path）
    from version import read_version
except ModuleNotFoundError:                        # 包方式：仓库根在 sys.path
    from core.version import read_version

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

# 常见远控 / 后门 / 挖矿端口（安全观察用，非主线）。
# 展示用名称在 copy 表 ``suspicious_port.<port>``，这里只保留端口集合。
SUSPICIOUS_PORTS = {1080, 1337, 31337, 4444, 4899, 5555, 6667, 9001, 9050}

#: ICMP 类型/代码 → 展示含义的 copy 表 key（``icmp_code.<type>.<code>``）。
#: 值本身放在 copy 表；这里只维护「哪些 (type, code) 有专名」。
ICMP_CODES = {(3, 0), (3, 1), (3, 2), (3, 3), (3, 4), (3, 9), (3, 10), (3, 13), (11, 0)}


def _t(section: str, key: str, **args) -> str:
    """从 copy 表取文案（缺失时回退成 key 本身，保证渲染不抛异常）。

    Args:
        section: copy 表 section 名。
        key: section 内的键。
        **args: ``{name}`` 占位符实参。

    Returns:
        str: 可直接展示的中文文案。
    """
    return _copy_text(section, key, **args)

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


def _new_direction_stats() -> dict:
    """分方向统计的初始结构：``c2s`` / ``s2c`` 各三项，外加 ``unknown`` 帧数。

    这是 :func:`collect` 的**内部中间结果**，只挂在 ``st["dir"]`` 上供
    :func:`build_findings` 读取；**不进** ``meta`` / ``metrics``，所以不会改变
    报告 JSON 的形状。

    Returns:
        dict: ``{"c2s": {...}, "s2c": {...}, "unknown": 0}``；每侧含
            ``retrans``（数据重传帧数）/ ``dup_ack``（重复 ACK 帧数）/
            ``packets``（该方向 TCP 帧数）。
    """
    def _side() -> dict:
        return {"retrans": 0, "dup_ack": 0, "packets": 0}

    return {"c2s": _side(), "s2c": _side(), "unknown": 0}


def _observe_direction(sid: str, src: str, dst: str, row: dict,
                       dir_client: dict[str, dict]) -> None:
    """用握手帧维护每条 TCP 流的方向基准（客户端是谁）。

    纯 SYN 的发起方、SYN-ACK 的目的方就是客户端。同一 stream 若已经确定
    client，又出现一个**不同端点**的纯 SYN（TCP 同时打开 / 罕见握手），方向会
    随「最后一个 SYN」漂移；此时把该流标记为方向歧义（``ambiguous=True``），
    保留原 client 不覆盖，后续帧由 :func:`_accumulate_dir` 一律计入 ``unknown``。

    Note:
        端口扫描的多次 SYN 各自落在不同 ``tcp.stream``，互不影响，不会被误判
        成方向歧义；同一端点重发的 SYN（``tcp.stream`` 相同、src 相同）也不算。

    Args:
        sid: tshark 的 ``tcp.stream``。
        src: 本帧源地址。
        dst: 本帧目的地址。
        row: 本帧的 tshark 字段字典（只读 ``tcp.flags.syn`` / ``tcp.flags.ack``）。
        dir_client: 流方向基准表，值形如 ``{"client": <ip>, "ambiguous": bool}``；
            由本函数**就地更新**。
    """
    if not _flag(row.get("tcp.flags.syn")):
        return
    state = dir_client.get(sid)
    if _flag(row.get("tcp.flags.ack")):
        # SYN-ACK：目的方是客户端；已有基准（含歧义）时不覆盖。
        if state is None:
            dir_client[sid] = {"client": dst, "ambiguous": False}
        return
    if state is None:
        dir_client[sid] = {"client": src, "ambiguous": False}
    elif state["client"] != src:
        state["ambiguous"] = True


def _dir_of(sid: str, src: str, dir_client: dict[str, dict]) -> str | None:
    """纯函数：判断一帧属于哪个方向桶。

    Args:
        sid: tshark 的 ``tcp.stream``。
        src: 本帧源地址。
        dir_client: :func:`_observe_direction` 维护的方向基准表。

    Returns:
        str | None: ``"c2s"`` / ``"s2c"``；方向未定（没看到握手）或该流方向
            歧义时返回 ``None``，调用方计入 ``unknown``，不用端口大小去猜。
    """
    state = dir_client.get(sid)
    if not state or state.get("ambiguous"):
        return None
    return "c2s" if src == state["client"] else "s2c"


def _accumulate_dir(st: dict, sid: str, src: str, dst: str, row: dict,
                    dir_client: dict[str, dict]) -> str | None:
    """把一帧 TCP 记进 ``st["dir"]`` 的分方向桶，返回所属桶名。

    先 :func:`_observe_direction` 更新方向基准，再按 :func:`_dir_of` 分桶：
    方向未定 / 歧义的帧只累加 ``unknown``，不参与重传与重复 ACK 归属。
    SYN 重发仍只进 ``st["syn_retrans"]``，不混入方向 ``retrans``（与既有口径一致）。

    Args:
        st: :func:`collect` 的统计字典，读取并更新其中的 ``st["dir"]``。
        sid: tshark 的 ``tcp.stream``。
        src: 本帧源地址。
        dst: 本帧目的地址。
        row: 本帧的 tshark 字段字典（``tcp.flags.*`` / ``tcp.analysis.*``）。
        dir_client: 方向基准表（见 :func:`_observe_direction`）。

    Returns:
        str | None: ``"c2s"`` / ``"s2c"``；方向未定或歧义时返回 ``None``。
    """
    _observe_direction(sid, src, dst, row, dir_client)
    bucket_name = _dir_of(sid, src, dir_client)
    if bucket_name is None:
        st["dir"]["unknown"] += 1
        return None
    bucket = st["dir"][bucket_name]
    bucket["packets"] += 1
    # SYN 重发说明对端没回应（连接建立问题），不能算作链路数据丢包。
    if (_flag(row.get("tcp.analysis.retransmission"))
            and not _flag(row.get("tcp.flags.syn"))):
        bucket["retrans"] += 1
    if _flag(row.get("tcp.analysis.duplicate_ack")):
        bucket["dup_ack"] += 1
    return bucket_name


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


#: 行的严重度只有下面两个取值**不是故障**；其余取值（严重/警告/提示）
#: 都会被下游当成「有发现」，进 points、进报告、进 AI 提示词。
#:
#: * :data:`NEUTRAL_SEVERITY` —— 测了，正常。可以报绿色。
#: * :data:`NO_SAMPLE_SEVERITY` —— 没样本，测不了。**不能报绿色**：
#:   「没抓到 TCP 会话」和「TCP 一切正常」是两件事，混成一个标记就是误报。
#:   取值 ``"na"`` 对齐 :class:`core.contracts.Severity.NA` 与
#:   ``verdict.compute_layers()`` 的 ``status="na"``。
NEUTRAL_SEVERITY = "—"
NO_SAMPLE_SEVERITY = "na"

#: 算作「故障」的严重度。中性行与无样本行都不在其中。
FAULT_SEVERITIES = ("严重", "警告")


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


def _conn_no_response(s: dict) -> bool:
    """判断这条 TCP 流是不是「发出了 SYN、始终没有回应」（建连无响应）。

    这是**结构化判定**，与文案彻底解耦：有 SYN、没有 SYN-ACK、也没有 RST。

    与 :func:`_is_handshake_rst` 的异同（**不是「只差一处」**，见下）：

    * ``_is_handshake_rst`` 判的是**某一次 RST 帧**：``not from_client``、
      有 ``syn``、没有 ``synack_ts``、没有 ``ack_ts``；
    * 本函数判的是**整条流**「发过 SYN 却始终没有回应」，不涉及方向。
      它没有显式检查 ``ack_ts``：``ack_ts`` 只在 ``synack_ts`` 存在时写入，
      而这里已要求 ``not synack_ts``，所以该条件天然冗余；
      额外要求 ``not rst`` 让「握手期被对端 RST」的流归入 ``conn_refused``、
      不归 ``conn_fail``（与旧实现的内联 flags 条件逐字等价）。

    为什么必须改：旧实现把中文标记 ``"建连无响应"`` 当查找键，
    ``conn_fail`` 计数与 ``streams_top`` 排序都靠 ``"建连无响应" in flags``。
    那样改 copy 表里的这条文案就会**改变判定结果** —— 文案与逻辑必须解耦。

    Args:
        s: ``st["streams"]`` 里的单条流聚合字典。

    Returns:
        bool: True 表示应计入 ``conn_fail`` / 打「建连无响应」标记。
    """
    return bool(s.get("syn")) and not s.get("synack_ts") and not s.get("rst")


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


def collect(pcap: Path, log=None,
            display_filter: str | None = None) -> tuple[dict, str]:
    """流式解析 pcap，边读边聚合。

    一次 tshark 调用取全所需字段，避免对同一文件扫多遍；输出按行消费，
    几十万行的 pcap 也不会把内存吃满。

    Args:
        pcap: 抓包文件路径。
        log: 可选日志回调 ``log(str)``，用于输出进度与 tshark 告警首行。
        display_filter: 可选的 tshark ``-Y`` 显示过滤表达式；``None``（默认）时
            不加任何过滤、行为与历史版本完全一致。影子探测用它做**第二道隔离**
            （抓包 BPF 之外的防御层）：探针的回复报文方向端口是反的，只靠 BPF
            可能漏进统计。

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
    # 影子探测隔离的防御层：能进统计的报文先过一遍显示过滤。None 时一个参数都不加，
    # 保证离线分析（20 产物红线）的 tshark 命令行与历史版本逐字节一致。
    if display_filter:
        args += ["-Y", display_filter]
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
        # 分方向统计（内部）：只进 build_findings 的重传文案，不进报告 JSON
        "dir": _new_direction_stats(),
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
    # 每条流的方向基准：看到 SYN（客户端发起）或 SYN-ACK（服务端回应）后才确定。
    # 此前抓到的帧属于「方向不明」，计入 st["dir"]["unknown"]，不用端口大小去猜；
    # 同一流出现不同端点的纯 SYN 时标记 ``ambiguous``，后续帧同样进 unknown。
    dir_client: dict[str, dict] = {}
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
            is_retrans = _flag(r.get("tcp.analysis.retransmission"))
            dup_raw = r.get("tcp.analysis.duplicate_ack", "")
            if is_retrans:
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
            if _flag(dup_raw):
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

            # 分方向累计（纯函数分桶，见 _accumulate_dir）：方向未定 / 歧义的帧
            # 只计 unknown，不参与重传 / 重复 ACK 归属。
            _accumulate_dir(st, sid, src, dst, r, dir_client)
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
                code = r.get("icmp.code", "")
                key = (int(_num(icmp_type)), int(_num(code)))
                desc = (_t("icmp_code", f"{key[0]}.{key[1]}") if key in ICMP_CODES
                        else f"ICMP type {icmp_type}/{code}")
                st["icmp_detail"].append({
                    "type": icmp_type, "code": code, "desc": desc,
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

#: L7 应用分布的分桶映射（``app`` → 桶 key）。
#: 桶集合刻意与前端「应用层分布」保持一致：前端从 ``meta.streams_top`` 数**会话数**，
#: 这里数**报文数**，同一组桶才能逐项对比「一个流很重」与「很多流很轻」的差异。
_L7_BUCKETS = (("TLS", "tls"), ("HTTP", "http"))


def _l7_packets(st: dict) -> dict:
    """按**报文数**统计 L7 应用分布（R8-1），与前端「按会话数」的口径并存。

    为什么要有第二套口径：会话数看不出流量结构。10 个 TLS 小流（各 2 包）+ 1 个
    HTTP 大流（2000 包）按会话数是「TLS 91%」，按报文数才是「HTTP 99%」——
    后者才是链路上真正占了带宽的那个。两者都保留，让 UI 按场景选。

    统计范围是 **TCP 会话的报文**（``st["streams"]``）：DNS/UDP 不进流表，
    因此不在分母里；这一点与前端按会话数的实现完全相同，不会造成两套口径互不可比。

    Args:
        st: 流聚合状态（``st["streams"]`` 为 ``{stream_id: 流字典}``，每项含
            ``app`` 与 ``packets``）。

    Returns:
        dict: ``{"basis": "packets", "total_packets": int, "buckets": [...],
            "complete": True}``；``buckets`` 每项 ``{"key", "packets", "pct"}``，
            key 取 ``tls`` / ``http`` / ``other``，三者之和恒等于 ``total_packets``。
            没有可统计报文时 ``total_packets`` 为 0、各桶 ``pct`` 为 0.0。
    """
    counts = {"tls": 0, "http": 0, "other": 0}
    app_to_key = dict(_L7_BUCKETS)
    total = 0
    for s in st["streams"].values():
        n = int(s.get("packets") or 0)
        if n <= 0:
            continue
        total += n
        key = app_to_key.get(str(s.get("app") or "").upper(), "other")
        counts[key] += n
    buckets = [{"key": key, "packets": counts[key],
                "pct": round(_pct(counts[key], total), 1)}
               for _, key in _L7_BUCKETS]
    buckets.append({"key": "other", "packets": counts["other"],
                    "pct": round(_pct(counts["other"], total), 1)})
    return {"basis": "packets", "total_packets": total,
            "buckets": buckets, "complete": True}


def _mark_dns_truncated(meta: dict) -> bool:
    """R8-2：``dns_resp`` 反超 ``dns_total`` 时给 meta 打 ``dns_truncated`` 标记。

    正常情况下 DNS 一问一答，``dns_resp`` 不会大于 ``dns_total``。反超只有两种来源：
    抓包在中途被截断（查询与响应的统计窗口不一致），或响应包被重复计数。此时下游
    若直接算「失败率 = 1 - 响应/查询」会得到负数、算「响应率」会超过 100%，都是
    看不出来的错数。这里在源头打标记，让上层明确知道「这两个数不能相除」。

    **只在成立时加键**：未触发时不写这个字段，因此既有报告快照逐字节不变
    （与 ``probe_baseline`` / ``path_profile`` 的「有数据才注入」同一口径）。
    消费方读不到该键即视为未触发。

    Args:
        meta: 分析结果的 ``meta`` 块（会被就地修改）。

    Returns:
        bool: True 表示命中反超、已打标记；False 表示未触发。
    """
    if int(meta.get("dns_resp") or 0) > int(meta.get("dns_total") or 0):
        meta["dns_truncated"] = True
        return True
    return False


def _stream_rows(st: dict) -> list[dict]:
    """把流字典整理成可展示的会话明细，按「问题严重度」排序。

    Note:
        会话标记文案来自 copy 表 ``stream_flag``。这是逐流热循环（大 pcap 上万条流），
        所以表只读一次、格式化时传 ``table=``，避免每条标记都走一次读盘/解析。
    """
    out: list[dict] = []
    # 热循环里只取一次表：copy 表有缓存，但传 table 连缓存查找也省掉
    flag_table = _copy_load()
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
        no_response = _conn_no_response(s)
        if no_response:
            flags.append(_copy_text("stream_flag", "no_response", table=flag_table))
        elif s["syn_retrans"]:
            flags.append(_copy_text("stream_flag", "syn_retrans",
                                    table=flag_table, count=s["syn_retrans"]))
        if s["rst"]:
            flags.append(_copy_text("stream_flag", "rst", table=flag_table))
        if s["zero_win"]:
            flags.append(_copy_text("stream_flag", "zero_win", table=flag_table))
        if s["ooo"]:
            flags.append(_copy_text("stream_flag", "ooo", table=flag_table, count=s["ooo"]))
        if hs is not None and hs >= 300:
            flags.append(_copy_text("stream_flag", "slow_handshake",
                                    table=flag_table, ms=hs))
        # 排序权重只看结构化条件，不看 flags 里的文案
        score = (100 if no_response else 0) + len(flags) * 10 \
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
    # 建连无响应 = 结构化条件（见 _conn_no_response），不再匹配 flags 里的中文文案
    conn_fail = sum(1 for s in st["streams"].values() if _conn_no_response(s))
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

def _retrans_direction(st: dict) -> str | None:
    """按重复 ACK 证据判定重传集中在哪个方向。

    重复 ACK 是「对端看到了空洞」的信号：``s2c.dup_ack>0`` 说明上行缺段
    （客户端在重传），``c2s.dup_ack>0`` 说明下行缺段（服务端在重传）。
    重传本身只说明「本端重发了」，不能单独定向 —— 可能是本端上行丢，
    也可能是对端 ACK 丢 —— 所以必须两侧证据同时成立才下方向结论。

    判定只用**帧数 > 0**：``"1,1"`` 是同一帧里出现两次，仍按一帧计，
    方向是否存在与出现次数无关。

    Args:
        st: :func:`collect` 的统计字典；``st["dir"]`` 缺失（旧测试的合成 st）
            时视为方向未定。

    Returns:
        str | None: ``"up"`` / ``"down"`` / ``"bidir"``；证据不足返回 ``None``，
            调用方退回现有通用重传行，不添加方向结论。
    """
    dirs = st.get("dir") or {}
    c2s = dirs.get("c2s") or {}
    s2c = dirs.get("s2c") or {}
    up = c2s.get("retrans", 0) > 0 and s2c.get("dup_ack", 0) > 0
    down = s2c.get("retrans", 0) > 0 and c2s.get("dup_ack", 0) > 0
    if up and down:
        return "bidir"
    if up:
        return "up"
    if down:
        return "down"
    return None


def build_findings(st: dict, m: dict, streams: list[dict]) -> list[dict]:
    """把统计聚合翻译成「按层归类的发现」，供 UI 与报告消费。

    Args:
        st: :func:`collect` 的统计字典（各类计数器）。其中 ``st["dir"]`` 是分方向
            统计（``c2s`` / ``s2c`` 的数据重传、重复 ACK、帧数与方向未定的
            ``unknown`` 帧数）；缺失时（旧调用方的合成 st）退回通用重传行。
        m: :func:`_metrics` 算出的比率与时延指标（``retrans_rate`` / ``rtt_avg_ms`` 等）。
        streams: :func:`_stream_rows` 聚合出的会话列表。

    Returns:
        list[dict]: 每项 ``{"layer", "category", "severity", "finding", "advice", "evidence"}``。
            ``finding`` / ``evidence`` / ``advice`` 的中文全部来自
            ``core/copy/zh-CN.json``（section：``finding`` / ``evidence`` / ``advice``），
            本模块只保留 key 与占位符实参。

    Note:
        ``severity`` 有三种非故障取值：``"严重"/"警告"/"提示"`` 之外，
        ``"—"`` 表示「测了，正常」，``"na"`` 表示「没样本」（见 :data:`NEUTRAL_SEVERITY`
        与 :data:`NO_SAMPLE_SEVERITY`）。两者都不是问题，但只有前者能报绿色。

        中性行（``"—"``）的保留与否**不在产出的位置决定**，而是最后按 ``category``
        统一裁定：同类别只要出现过故障行，中性行一律丢弃。否则会出现
        「传输质量正常」与「出现 TCP 零窗口」并列这种自相矛盾的报告。

        ``layer`` / ``category`` / ``severity`` 三个字段是**结构化标识**（既被
        ``verdict`` / ``legacy_map`` 当键匹配，也直接进报告表格）：它们不是本轮
        可迁移的「文案」，改值会连带改变判定与映射，因此保留在代码里。

        方向判定（见 :func:`_retrans_direction`）只换重传行的**文案与建议**，
        不改严重度阈值，也不产生新行：没有重复 ACK 证据时仍是原来的通用行。
    """
    rows: list[dict] = []

    # ============ L4 连接建立 ============
    if m["streams_total"] == 0:
        rows.append(_row("L4 传输层", "TCP", "连接建立",
                         _t("finding", "connect.no_sample"), NO_SAMPLE_SEVERITY,
                         _t("evidence", "connect.no_sample", packets=st["packets"]),
                         _t("advice", "L4.CONNECT.ADVICE.NO_SAMPLE")))
    else:
        if m["conn_fail"]:
            # 用 st["streams"] 的结构化条件筛；再按 streams（已按 score 排序）取前 3，
            # 保持证据条目的原始顺序。不能给 streams_top 的行加键（会改报告快照形状）。
            no_response_ids = {sid for sid, s in st["streams"].items()
                               if _conn_no_response(s)}
            bad = [x for x in streams if x["stream"] in no_response_ids][:3]
            detail = "；".join(
                _t("evidence", "connect.no_response_item", server=x["server"],
                   dport=x["dport"], count=x["packets"]) for x in bad)
            frames = ",".join(f"#{f}" for f in (bad[0].get("frames") or [])[:3]) if bad else "-"
            rows.append(_row(
                "L4 传输层", "TCP", "连接建立",
                _t("finding", "connect.no_response", conn_fail=m["conn_fail"]),
                "严重",
                _t("evidence", "connect.no_response", detail=detail, frames=frames),
                _t("advice", "L4.CONNECT.ADVICE.NO_RESPONSE")))
        # 证据只列「握手期被拒」的流，与 conn_refused 的口径保持一致；
        # 若还按 x["rst"] 取，会把正常关闭的 RST 流写进证据里，读者会以为它也拒绝了连接。
        refused = [s for s in st["streams"].values() if s.get("rst_hs")][:3]
        if m["conn_refused"] >= 2:
            detail = "；".join(f"{x['server']}:{x['dport']}" for x in refused)
            rows.append(_row(
                "L4 传输层", "TCP", "连接建立",
                _t("finding", "connect.refused", conn_refused=m["conn_refused"]),
                "警告" if m["conn_refused"] >= 3 else "提示",
                detail, _t("advice", "L4.CONNECT.ADVICE.RST")))
        if m["hs_avg_ms"] and m["hs_avg_ms"] >= 300:
            sev = "警告" if m["hs_avg_ms"] < 800 else "严重"
            rows.append(_row(
                "L4 传输层", "TCP", "连接建立",
                _t("finding", "connect.slow", avg=m["hs_avg_ms"], max=m["hs_max_ms"],
                   jitter=m["hs_jitter_ms"]), sev,
                _t("evidence", "connect.slow",
                   count=sum(1 for x in streams if x["handshake_ms"] is not None)),
                _t("advice", "L4.CONNECT.ADVICE.SLOW_HANDSHAKE")))
        # 中性行照常产出，是否该留下由函数末尾的「阶段二」统一裁定。
        # 就地判断靠不住：后面还可能追加同类别故障行（零窗口就是这么漏的）。
        note = (_t("evidence", "connect.refused_note", count=m["conn_refused"])
                if m["conn_refused"] else "—")
        rows.append(_row("L4 传输层", "TCP", "连接建立",
                         _t("finding", "connect.ok", streams_total=m["streams_total"],
                            hs_avg=m["hs_avg_ms"]),
                         NEUTRAL_SEVERITY, note, _t("advice", "none")))

    # ============ L4 传输质量 ============
    if st["tcp_packets"] == 0:
        rows.append(_row("L4 传输层", "TCP", "传输质量",
                         _t("finding", "transport.no_sample"), NO_SAMPLE_SEVERITY, "—",
                         _t("advice", "L4.TRANSPORT.ADVICE.NO_SAMPLE")))
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
            detail = "；".join(
                _t("evidence", "transport.retrans", stream=x["stream"], client=x["client"],
                   server=x["server"], dport=x["dport"], retrans=x["retrans"])
                for x in top) or "-"
            # 方向只改文案与建议，不改严重度：没有 dup-ACK 证据时用原通用行。
            dirs = st.get("dir") or {}
            c2s = dirs.get("c2s") or {}
            s2c = dirs.get("s2c") or {}
            direction = _retrans_direction(st)
            if direction == "bidir":
                finding = _t("finding", "transport.retrans_bidir", retrans_rate=rr,
                             c2s_retrans=c2s.get("retrans", 0),
                             s2c_retrans=s2c.get("retrans", 0),
                             c2s_dup_ack=c2s.get("dup_ack", 0),
                             s2c_dup_ack=s2c.get("dup_ack", 0))
                advice_key = "L4.RETRANS.ADVICE.BIDIR"
            elif direction == "up":
                finding = _t("finding", "transport.retrans_up", retrans_rate=rr,
                             c2s_retrans=c2s.get("retrans", 0),
                             s2c_dup_ack=s2c.get("dup_ack", 0))
                advice_key = "L4.RETRANS.ADVICE.UP"
            elif direction == "down":
                finding = _t("finding", "transport.retrans_down", retrans_rate=rr,
                             s2c_retrans=s2c.get("retrans", 0),
                             c2s_dup_ack=c2s.get("dup_ack", 0))
                advice_key = "L4.RETRANS.ADVICE.DOWN"
            else:
                # 通用行的实参与文案保持原样（V5：demo 逐字节不变）
                finding = _t("finding", "transport.retrans", rate=rr,
                             retrans=st["retrans"], tcp_packets=st["tcp_packets"],
                             ooo=m["ooo_rate"], dup=m["dup_ack_rate"])
                advice_key = "L4.RETRANS.ADVICE"
            rows.append(_row(
                "L4 传输层", "TCP", "传输质量", finding, sev, detail,
                _t("advice", advice_key)))
        else:
            rows.append(_row("L4 传输层", "TCP", "传输质量",
                             _t("finding", "transport.ok", rate=rr, ooo=m["ooo_rate"]),
                             NEUTRAL_SEVERITY,
                             _t("evidence", "transport.ok", tcp_packets=st["tcp_packets"]),
                             _t("advice", "none")))
        if st["zero_win"] >= 3 or st["win_full"] >= 10:
            rows.append(_row(
                "L4 传输层", "TCP", "传输质量",
                _t("finding", "transport.zero_win", zero_win=st["zero_win"],
                   win_full=st["win_full"]), "警告",
                _t("evidence", "transport.zero_win"),
                _t("advice", "L4.ZEROWIN.ADVICE")))

    # ============ L3 网络层 ============
    if m["icmp_unreach"] or m["icmp_timeout"]:
        items = st["icmp_detail"][:3]
        detail = "；".join(
            _t("evidence", "net.icmp", src=i["src"], dst=i["dst"], desc=i["desc"],
               frame=i["frame"]) for i in items)
        # 旧实现按 desc 里有没有「MTU/分片」判是否升级严重度；文案迁到 copy 表后
        # 不能再靠文字判（改文案会改判定），改按 ICMP 类型码 (type 3, code 4) 判，
        # 语义等价（只有这一条 desc 提到 MTU/分片）。
        mtu_hit = any(str(i["type"]) == "3" and str(i["code"]) == "4"
                      for i in st["icmp_detail"])
        finding = _t("finding", "net.icmp", icmp_unreach=m["icmp_unreach"],
                     icmp_timeout=m["icmp_timeout"])
        if mtu_hit:
            finding += _t("finding", "net.icmp_mtu")
        rows.append(_row(
            "L3 网络层", "ICMP", "网络可达性", finding,
            "严重" if mtu_hit else "警告", detail,
            _t("advice", "L3.ICMP.ADVICE")))
    else:
        rows.append(_row("L3 网络层", "ICMP/IP", "网络可达性",
                         _t("finding", "net.icmp_ok"), "—", "—", _t("advice", "none")))

    if m["rtt_samples"] >= 5 and (m["rtt_avg_ms"] >= 300 or m["rtt_jitter_ms"] >= 80):
        rows.append(_row(
            "L3 网络层", "TCP/IP", "网络时延",
            _t("finding", "net.rtt", avg=m["rtt_avg_ms"], p95=m["rtt_p95_ms"],
               max=m["rtt_max_ms"], jitter=m["rtt_jitter_ms"]),
            "警告" if m["rtt_avg_ms"] < 600 else "严重",
            _t("evidence", "net.rtt", samples=m["rtt_samples"]),
            _t("advice", "L3.RTT.ADVICE")))

    # ============ L7 域名解析 ============
    dns_q_total = sum(st["dns_q"].values())
    if dns_q_total == 0 and not st["dns_r"]:
        rows.append(_row("L7 应用层", "DNS", "域名解析",
                         _t("finding", "dns.no_sample"), NO_SAMPLE_SEVERITY,
                         "—", _t("advice", "L7.DNS.ADVICE.NO_SAMPLE")))
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
            detail = "；".join(
                _t("evidence", "dns.fail", name=n, count=c) for n, c in top) or "-"
            rows.append(_row(
                "L7 应用层", "DNS", "域名解析",
                _t("finding", "dns.fail", rate=fail, nx=sum(st["dns_nx"].values()),
                   total=total),
                sev, detail, _t("advice", "L7.DNS.ADVICE.FAIL")))
        if m["dns_timeouts"] >= 3:
            rows.append(_row(
                "L7 应用层", "DNS", "域名解析",
                _t("finding", "dns.timeout", timeouts=m["dns_timeouts"]), "警告",
                _t("evidence", "dns.timeout", queries=dns_q_total,
                   responses=sum(st["dns_r"].values())),
                _t("advice", "L7.DNS.ADVICE.TIMEOUT")))
        if m["dns_avg_ms"] and m["dns_avg_ms"] >= 300:
            rows.append(_row(
                "L7 应用层", "DNS", "域名解析",
                _t("finding", "dns.slow", avg=m["dns_avg_ms"], max=m["dns_max_ms"]),
                "警告" if m["dns_avg_ms"] < 800 else "严重",
                _t("evidence", "dns.slow", count=len(st["dns_times"]),
                   servers="、".join(ip for ip, _ in st["dns_servers"].most_common(2)) or "-"),
                _t("advice", "L7.DNS.ADVICE.SLOW")))
        rows.append(_row("L7 应用层", "DNS", "域名解析",
                         _t("finding", "dns.ok", queries=dns_q_total or total,
                            avg=m["dns_avg_ms"]),
                         NEUTRAL_SEVERITY, "—", _t("advice", "none")))

    # ============ L7 HTTP 响应 ============
    if st["http_req"]:
        codes = st["http_codes"]
        dist = "、".join(f"{k}×{v}" for k, v in codes.most_common(5))
        if m["http_err5"]:
            rows.append(_row(
                "L7 应用层", "HTTP", "应用响应",
                _t("finding", "http.5xx", http_err5=m["http_err5"],
                   rate=m["http_err5_rate"]),
                "严重" if m["http_err5_rate"] >= 10 else "警告",
                _t("evidence", "http.status_dist", dist=dist),
                _t("advice", "L7.HTTP.ADVICE.5XX")))
        if m["http_err4"] and not m["http_err5"]:
            rows.append(_row(
                "L7 应用层", "HTTP", "应用响应",
                _t("finding", "http.4xx", http_err4=m["http_err4"]), "提示",
                _t("evidence", "http.status_dist", dist=dist),
                _t("advice", "L7.HTTP.ADVICE.4XX")))
        if m["http_avg_ms"] and (m["http_avg_ms"] >= 1000 or m["http_p95_ms"] >= 3000):
            slow = sorted([h for h in st["http_detail"] if h["ms"] > 0],
                          key=lambda x: -x["ms"])[:3]
            detail = "；".join(f"{h['host']}{h['uri']} {h['ms']:.0f}ms → {h['code']}"
                               for h in slow) or "-"
            rows.append(_row(
                "L7 应用层", "HTTP", "应用响应",
                _t("finding", "http.slow", avg=m["http_avg_ms"], p95=m["http_p95_ms"],
                   max=m["http_max_ms"]), "警告", detail,
                _t("advice", "L7.HTTP.ADVICE.SLOW")))
        rows.append(_row("L7 应用层", "HTTP", "应用响应",
                         _t("finding", "http.ok", http_req=st["http_req"],
                            avg=m["http_avg_ms"]),
                         NEUTRAL_SEVERITY, "—", _t("advice", "none")))
    elif st["tls_sni"] or st["tls_alert"]:
        sev = "提示" if st["tls_alert"] >= 10 else "—"
        sni = sum(st["tls_sni"].values())
        if st["tls_alert"]:
            finding = _t("finding", "tls.session_alerts", sni=sni, alerts=st["tls_alert"])
        else:
            finding = _t("finding", "tls.session", sni=sni)
        rows.append(_row("L7 应用层", "TLS", "TLS 会话", finding, sev,
                         _t("evidence", "tls.sni",
                            sni="、".join(n for n, _ in st["tls_sni"].most_common(3))),
                         _t("advice", "L7.TLS.ADVICE")))

    # ============ L2 本地链路 ============
    no_reply = [ip for ip, n in st["arp_req"].items() if n >= 2 and ip not in st["arp_rep"]]
    if no_reply:
        rows.append(_row(
            "L2 本地链路", "ARP", "本地可达性",
            _t("finding", "arp.no_reply", count=len(no_reply)), "警告",
            "、".join(no_reply[:5]),
            _t("advice", "L2.ARP.ADVICE")))

    # ============ 安全观察（次要） ============
    sec: list[dict] = []
    for ip, pkts in st["ext_dst"].most_common(50):
        ports = st["ext_ports"][ip]
        hit = [p for p in ports if _port(p) in SUSPICIOUS_PORTS]
        if hit:
            desc = "、".join(f"{p}({_t('suspicious_port', str(_port(p)))})"
                             for p in sorted(hit, key=_port))
            sec.append(_row("安全观察", "TCP", "可疑外联",
                            _t("finding", "sec.exfil", ip=ip, ports=desc, packets=pkts),
                            "警告",
                            _t("evidence", "sec.exfil",
                               frames=",".join(f"#{f}" for f in st["ext_frames"][ip][:5])),
                            _t("advice", "SEC.EXFIL.ADVICE")))
        elif len(ports) >= 15:
            sec.append(_row("安全观察", "TCP", "端口扫描",
                            _t("finding", "sec.scan", ip=ip, count=len(ports)), "提示",
                            _t("evidence", "sec.scan",
                               frames=",".join(f"#{f}" for f in st["ext_frames"][ip][:5])),
                            _t("advice", "SEC.SCAN.ADVICE")))
    if st["basic_auth"]:
        it = st["basic_auth"][0]
        sec.append(_row("安全观察", "HTTP", "明文凭证",
                        _t("finding", "sec.basic", host=it["host"], uri=it["uri"][:50]),
                        "警告", _t("evidence", "sec.basic", frame=it["frame"]),
                        _t("advice", "SEC.PLAINTEXT.ADVICE.BASIC")))
    if st["ftp_pass"]:
        it = st["ftp_pass"][0]
        sec.append(_row("安全观察", "FTP", "明文凭证",
                        _t("finding", "sec.ftp", dst=it["dst"]), "警告",
                        _t("evidence", "sec.ftp", frame=it["frame"]),
                        _t("advice", "SEC.PLAINTEXT.ADVICE.FTP")))
    if st["uri_secret"]:
        it = st["uri_secret"][0]
        sec.append(_row("安全观察", "HTTP", "明文凭证",
                        _t("finding", "sec.url", method=it["method"], host=it["host"],
                           uri=it["uri"][:50]), "提示",
                        _t("evidence", "sec.url", frame=it["frame"]),
                        _t("advice", "SEC.PLAINTEXT.ADVICE.URL")))
    if st["telnet_frames"]:
        sec.append(_row("安全观察", "Telnet", "明文凭证",
                        _t("finding", "sec.telnet", count=len(st["telnet_frames"])), "提示",
                        _t("evidence", "sec.telnet",
                           frames=",".join(f"#{f}" for f in st["telnet_frames"][:5])),
                        _t("advice", "SEC.PLAINTEXT.ADVICE.TELNET")))
    if sec:
        rows.extend(sec)
    else:
        rows.append(_row("安全观察", "—", "安全观察",
                         _t("finding", "sec.none"), NEUTRAL_SEVERITY, "—",
                         _t("advice", "none")))

    # ============ 阶段二：抑制自相矛盾的中性行 ============
    # 为什么不在产出的地方就地判断：中性行与故障行的产出顺序没有保证。
    # 「传输质量正常」在重传率达标时就先产出，零窗口行是之后才追加的 ——
    # 就地判断那一步还看不见它，于是同一份报告里同时出现
    # 「传输质量正常（重传率 0.00%）」和「出现 TCP 零窗口 5 次」（见 code-index #29）。
    # 所以先按原顺序把两类行都产出，最后按 category 统一裁定：
    # 某个 category 只要存在故障行，就丢弃该 category 的中性行。
    #
    # 只丢中性行（"—"）：无样本行（"na"）本来就不会与故障行同类别
    # （没有样本就判不出故障），保留它才能让读者看见「这一类没测到」。
    # 顺序不变：下面的列表推导保持 rows 原有的相对次序。
    fault_cats = {r["category"] for r in rows if r.get("severity") in FAULT_SEVERITIES}
    return [r for r in rows
            if not (r.get("severity") == NEUTRAL_SEVERITY and r.get("category") in fault_cats)]


def _cred_events(st: dict) -> list[dict]:
    """把明文凭证事件整理成报告「技术明细」用的行（文案来自 copy 表）。

    Args:
        st: :func:`collect` 的统计字典；读取 ``basic_auth`` / ``ftp_pass`` /
            ``uri_secret`` / ``telnet_frames`` 四类事件。

    Returns:
        list[dict]: 每项 ``{"type", "where", "detail", "frame"}``；口令只保留
            前两位 + 星号，避免把明文写进报告。
    """
    out: list[dict] = []
    for item in st.get("basic_auth", [])[:5]:
        out.append({"type": "HTTP Basic", "where": f"{item['host']}{item['uri'][:50]}",
                    "detail": _t("cred_event", "basic_detail"), "frame": item["frame"]})
    for item in st.get("ftp_pass", [])[:5]:
        arg = (item["arg"][:2] + "***") if item.get("arg") else "***"
        out.append({"type": "FTP PASS", "where": str(item["dst"]),
                    "detail": _t("cred_event", "ftp_detail", arg=arg),
                    "frame": item["frame"]})
    for item in st.get("uri_secret", [])[:5]:
        out.append({"type": _t("cred_event", "url_type"),
                    "where": f"{item['host']}{item['uri'][:50]}",
                    "detail": item.get("method", "GET"), "frame": item["frame"]})
    if st.get("telnet_frames"):
        out.append({"type": _t("cred_event", "telnet_type"), "where": "—",
                    "detail": _t("cred_event", "telnet_detail",
                                 count=len(st["telnet_frames"])),
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
        版本号读不到时回退 ``0.0.0``，其余来源取不到时该键为空串，不抛异常。

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
    info["app_version"] = read_version(ROOT)
    return info


def analyze(pcap: Path | str, target: str = "", ti_key: str = "", log=None,
            display_filter: str | None = None) -> dict:
    """分析抓包文件（离线分析）：读取一个 pcap，产出完整结果字典。

    Args:
        pcap: 抓包文件路径（``Path`` 或字符串）。
        target: 本次诊断目标的展示用名字（IP/域名），可空。
        ti_key: 威胁情报 API Key；为空则跳过可疑外联核对。
        log: 可选日志回调 ``log(str)``。
        display_filter: 可选的 tshark ``-Y`` 显示过滤表达式（影子探测隔离的
            防御层）；``None``（默认）时行为与输出完全不变 —— 离线分析的
            20 个产物逐字节红线靠这个默认值守住。

    Returns:
        dict: 成功时 ``ok=True``，键含 ``meta``（采集与明细）、``metrics``（扁平指标）、
            ``rows``（中文发现列表）、``summary``（计数摘要），以及 T03 新增的
            ``findings_v2``（带机器码的结构化结论）与 ``provenance``（可复现信息）。
            文件不存在或解析失败时返回 ``{"ok": False, "error": "..."}``。
    """
    pcap = Path(pcap)
    if not pcap.is_file():
        return {"ok": False, "error": f"抓包文件不存在: {pcap}"}
    st, err = collect(pcap, log=log, display_filter=display_filter)
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
        "target": target or _t("common", "all_network"),
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
            "dns_total": dns_q_total,
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
            # ARP 请求总条数（不只是「无应答」的那些）。证据充分性闸门用它报告
            # 「这次抓包到底发过几次 ARP」，但**维度判据不用它**（见下一行）。
            "arp_req": sum(st["arp_req"].values()),
            # 同一目标的最大 ARP 请求次数。充分性闸门按「同一目标 ≥ 2 次」判：
            # 两个不同目标各 1 次（总数 2）时，ARP 规则一条都判不出来，
            # 不能算「ARP 维度有样本」。
            "arp_req_max": max(st["arp_req"].values()) if st["arp_req"] else 0,
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

    # ---- R8-1：按**报文数**的 L7 应用分布 ----
    # 放在顶层 ``l7_packets``，**不进 meta**：报告只落 summary/meta/metrics/rows/verdict
    # 五块，所以它只出现在 /api/status、/api/last-run、/api/last-run/result 的响应里，
    # 不写进 reports/（与 server.link_actions 的「加法字段」同一口径），快照不受影响。
    result["l7_packets"] = _l7_packets(st)

    # ---- R8-2：DNS 响应数反超查询数 = 抓包截断 / 重复计数 ----
    # 抽成函数是为了能单测「反超 / 相等 / 缺键」三种输入，不必真造一个截断的 pcap。
    _mark_dns_truncated(result["meta"])

    # ---- T03：增量产出结构化结论。旧的 rows[] / meta / metrics 一个字都不动 ----
    result["findings_v2"] = _build_findings_v2(rows, log=log)
    result["provenance"] = _build_provenance()
    return result


PROTO_NAMES = {"6": "TCP", "17": "UDP", "1": "ICMP", "2": "IGMP", "47": "GRE", "50": "ESP", "51": "AH"}


def _proto_name(v: str) -> str:
    return PROTO_NAMES.get(str(v), f"IP/{v}")
