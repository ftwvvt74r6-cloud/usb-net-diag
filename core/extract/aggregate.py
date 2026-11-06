"""把逐行报文聚合成 ``Features``（T04 的聚合层）。

输入是 :mod:`core.extract.fields` 解析出的行字典列表，输出是
:class:`core.contracts.Features` —— **规则层唯一认识的输入**。
有了这一层，T05 的规则单测可以直接读 ``tests/fixtures/faults_features.json``，
不需要 tshark、不需要网络、不需要管理员权限。

聚合口径刻意与 ``core/analyzer.py`` 保持一致（尤其是 ``retrans`` 不含 SYN、
比率按「百分比」而非 0~1），否则新旧两条链路的结论会打架。
但**不 import analyzer**：依赖方向是单向的 ``analyzer → extract``，
反向依赖会让拆层失去意义，也会把 analyzer 的副作用带进纯函数里。

方向判定只认「SYN 且无 ACK」的一方是客户端。判不出来就**不做方向拆分**
（``dirs`` 留空），而不是按端口大小猜 —— 猜反方向会让上行/下行丢包归因全错，
比没有结论更糟。
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

try:                                    # 包模式：from core.extract.aggregate import ...
    from ..contracts import (
        CaptureMeta, DirStat, Direction, Endpoint, EndpointKind,
        Features, Stats, StreamStat, TcpFeatures,
    )
except ImportError:                     # 扁平模式：core/ 在 sys.path 上
    _ROOT = str(Path(__file__).resolve().parents[2])
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)
    from core.contracts import (         # type: ignore[no-redef]
        CaptureMeta, DirStat, Direction, Endpoint, EndpointKind,
        Features, Stats, StreamStat, TcpFeatures,
    )

from .fields import parse_flag, parse_int, parse_num, parse_port

#: 结束方式文案。刻意用中文：这些串会直接出现在报告与 UI 上。
STATE_CLOSED = "正常关闭"
STATE_RST = "RST"
STATE_NO_REPLY = "无响应"


class _DirAcc:
    """单个方向的累加器（聚合完冻结成 ``DirStat``）。"""

    __slots__ = ("packets", "bytes", "data_packets", "retrans", "syn_retrans",
                 "syn", "dup_ack", "ooo", "zero_win", "win_full", "lost_seg",
                 "rst", "rtt")

    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.data_packets = 0
        self.retrans = 0
        self.syn_retrans = 0
        self.syn = 0
        self.dup_ack = 0
        self.ooo = 0
        self.zero_win = 0
        self.win_full = 0
        self.lost_seg = 0
        self.rst = 0
        self.rtt: list[float] = []

    def freeze(self, direction: Direction) -> DirStat:
        """冻结成不可变的 ``DirStat``。

        Args:
            direction: 该累加器对应的方向。

        Returns:
            DirStat: 计数字段逐一搬过去，``rtt`` 由 ``Stats.from_values`` 现算。
        """
        return DirStat(
            direction=direction,
            packets=self.packets,
            bytes=self.bytes,
            data_packets=self.data_packets,
            retrans=self.retrans,
            syn_retrans=self.syn_retrans,
            syn=self.syn,
            dup_ack=self.dup_ack,
            ooo=self.ooo,
            zero_win=self.zero_win,
            win_full=self.win_full,
            lost_seg=self.lost_seg,
            rst=self.rst,
            rtt=Stats.from_values(self.rtt),
        )


def _src_ip(r: Mapping[str, Any]) -> str:
    """取源 IP，IPv6 自动回落。"""
    return (r.get("ip.src") or r.get("ipv6.src") or "").strip()


def _dst_ip(r: Mapping[str, Any]) -> str:
    """取目的 IP，IPv6 自动回落。"""
    return (r.get("ip.dst") or r.get("ipv6.dst") or "").strip()


def _client_of(rows: Sequence[Mapping[str, Any]]) -> tuple[str, int, str, int] | None:
    """找出发起方与对端：第一个「SYN 且无 ACK」的报文决定谁是客户端。

    **判不出来就返回 None，绝不按端口大小猜。** 端口大小猜方向在
    「两端都是高位端口」或「中途开始抓包」时会判反，而方向一错，
    上/下行丢包的归因就全反了 —— 这种错误比没有结论更糟。

    Args:
        rows: 同一条 ``tcp.stream`` 的报文行，按出现顺序。

    Returns:
        tuple[str, int, str, int] | None: ``(client_ip, client_port, server_ip, server_port)``；
            没有纯 SYN 时返回 None。
    """
    for r in rows:
        if parse_flag(r.get("tcp.flags.syn")) and not parse_flag(r.get("tcp.flags.ack")):
            ip = _src_ip(r)
            if ip:
                return (ip, parse_port(r.get("tcp.srcport")),
                        _dst_ip(r), parse_port(r.get("tcp.dstport")))
    return None


def _build_stream(sid: str, rows: Sequence[Mapping[str, Any]],
                  g_c2s: _DirAcc, g_s2c: _DirAcc) -> StreamStat:
    """把一条 ``tcp.stream`` 的报文行聚合成 ``StreamStat``。

    同时把每个报文累加到全局方向累加器 ``g_c2s`` / ``g_s2c``，
    这样 ``TcpFeatures.dir_totals`` 与流级 ``dirs`` 用的是同一遍数据，
    不会出现「两边算得不一样」。

    Args:
        sid: ``tcp.stream`` 的值（字符串）。
        rows: 该流的报文行。
        g_c2s: 全局上行累加器，原地更新。
        g_s2c: 全局下行累加器，原地更新。

    Returns:
        StreamStat: 含端点角色、方向统计、握手耗时、结束方式、帧号序列。
    """
    client = _client_of(rows)
    local = {Direction.C2S: _DirAcc(), Direction.S2C: _DirAcc()}
    syn_ts: float | None = None
    synack_ts: float | None = None
    has_rst = False
    has_fin = False
    frames: list[int] = []
    total_bytes = 0

    for r in rows:
        flen = parse_int(r.get("frame.len"))
        total_bytes += flen
        frames.append(parse_int(r.get("frame.number")))

        is_syn = parse_flag(r.get("tcp.flags.syn"))
        is_ack = parse_flag(r.get("tcp.flags.ack"))
        is_rst = parse_flag(r.get("tcp.flags.reset"))
        ts = parse_num(r.get("frame.time_epoch")) or 0.0

        if is_syn and not is_ack and syn_ts is None:
            syn_ts = ts
        if is_syn and is_ack and synack_ts is None:
            synack_ts = ts
        has_rst = has_rst or is_rst
        has_fin = has_fin or parse_flag(r.get("tcp.flags.fin"))

        if client is None:
            continue                      # 方向判不出 → 不做方向拆分

        direction = (Direction.C2S
                     if (_src_ip(r), parse_port(r.get("tcp.srcport"))) == client[:2]
                     else Direction.S2C)
        d = local[direction]
        g = g_c2s if direction is Direction.C2S else g_s2c

        for acc in (d, g):
            acc.packets += 1
            acc.bytes += flen
            if parse_int(r.get("tcp.len")) > 0:
                acc.data_packets += 1
            if is_syn and not is_ack:
                acc.syn += 1
            if is_rst:
                acc.rst += 1
            if parse_flag(r.get("tcp.analysis.retransmission")):
                if is_syn:
                    acc.syn_retrans += 1      # SYN 重发是建连问题，不算链路丢包
                else:
                    acc.retrans += 1
            if parse_flag(r.get("tcp.analysis.duplicate_ack")):
                acc.dup_ack += 1
            if parse_flag(r.get("tcp.analysis.out_of_order")):
                acc.ooo += 1
            if parse_flag(r.get("tcp.analysis.zero_window")):
                acc.zero_win += 1
            if parse_flag(r.get("tcp.analysis.window_full")):
                acc.win_full += 1
            if parse_flag(r.get("tcp.analysis.lost_segment")):
                acc.lost_seg += 1
            rtt_s = parse_num(r.get("tcp.analysis.ack_rtt"))
            if rtt_s is not None and rtt_s > 0:
                acc.rtt.append(rtt_s * 1000.0)

    if client is not None:
        dirs: dict[Direction, DirStat] = {
            Direction.C2S: local[Direction.C2S].freeze(Direction.C2S),
            Direction.S2C: local[Direction.S2C].freeze(Direction.S2C),
        }
        client_ep = Endpoint(ip=client[0], port=client[1], kind=EndpointKind.CLIENT)
        server_ep = Endpoint(ip=client[2], port=client[3], kind=EndpointKind.SERVER)
    else:
        dirs = {}
        client_ep = Endpoint(ip="", port=None)
        server_ep = Endpoint(ip="", port=None)

    handshake_ms: float | None = None
    if syn_ts is not None and synack_ts is not None:
        handshake_ms = round((synack_ts - syn_ts) * 1000.0, 1)

    if client is not None and synack_ts is None and not has_rst:
        state = STATE_NO_REPLY
    elif has_rst:
        state = STATE_RST
    elif has_fin:
        state = STATE_CLOSED
    else:
        state = ""

    return StreamStat(
        stream=sid,
        client=client_ep,
        server=server_ep,
        packets=len(rows),
        bytes=total_bytes,
        handshake_ms=handshake_ms,
        state=state,
        frames=tuple(frames),
        dirs=dirs,
    )


def _rate(part: int, total: int) -> float:
    """百分比比率，保留 2 位；分母为 0 时返回 0.0。"""
    return round(part / total * 100.0, 2) if total else 0.0


def build_features(rows: Sequence[Mapping[str, Any]],
                   meta: Mapping[str, Any] | None = None,
                   stats: Mapping[str, Any] | None = None) -> Features:
    """把逐行报文聚合成 ``Features``。

    Args:
        rows: 每个报文一行，键是 tshark 字段名（``"tcp.stream"`` 等），
            值保留原始字符串。由 ``tshark -T fields`` 的输出来。
        meta: 采集元信息，可选键 ``pcap_file`` / ``pcap_name`` / ``mode`` /
            ``interface`` / ``bpf``。
        stats: 兼容 ``analyzer.collect()`` 的统计字典；仅在报文时间戳算不出
            时长时用它兜底填 ``capture.duration_s``。

    Returns:
        Features: 含 TCP 全量特征与 ``missing`` 清单。
            ``missing`` 里登记的键表示「这份抓包里没有可算的样本」，
            规则层必须据此跳过判断，**不得**当成「一切正常」。
    """
    meta = meta or {}
    stats = stats or {}

    streams_raw: dict[str, list[Mapping[str, Any]]] = {}
    tcp_packets = 0
    tcp_bytes = 0
    total_bytes = 0
    first_ts = 0.0
    last_ts = 0.0
    has_tls = has_dns = has_http = has_icmp = has_arp = False

    for r in rows:
        ts = parse_num(r.get("frame.time_epoch")) or 0.0
        if ts:
            if not first_ts or ts < first_ts:
                first_ts = ts
            if ts > last_ts:
                last_ts = ts
        flen = parse_int(r.get("frame.len"))
        total_bytes += flen

        sid = (r.get("tcp.stream") or "").strip()
        if sid != "":
            tcp_packets += 1
            tcp_bytes += flen
            streams_raw.setdefault(sid, []).append(r)

        has_dns = has_dns or bool(r.get("dns.qry.name"))
        has_http = has_http or bool(r.get("http.request.method"))
        has_icmp = has_icmp or bool(r.get("icmp.type"))
        has_arp = has_arp or bool(r.get("arp.opcode"))
        has_tls = has_tls or bool(r.get("tls.handshake.extensions_server_name"))

    g_c2s, g_s2c = _DirAcc(), _DirAcc()
    streams = tuple(_build_stream(sid, rs, g_c2s, g_s2c)
                    for sid, rs in streams_raw.items())

    c2s = g_c2s.freeze(Direction.C2S)
    s2c = g_s2c.freeze(Direction.S2C)

    conn_fail = sum(1 for st in streams if st.state == STATE_NO_REPLY)
    # 只算「握手阶段被 RST」：要求有纯 SYN、且从未收到 SYN-ACK。
    # 正常关闭时对端回 RST（半开连接回收）不该记成「端口被拒」。
    conn_refused = sum(
        1 for st in streams
        if st.state == STATE_RST and st.handshake_ms is None and st.client.ip
    )

    handshakes = [st.handshake_ms for st in streams if st.handshake_ms is not None]

    duration = 0.0
    if first_ts and last_ts >= first_ts:
        duration = round(last_ts - first_ts, 2)
    if not duration and isinstance(stats.get("duration"), (int, float)):
        duration = float(stats["duration"])

    capture = CaptureMeta(
        mode=str(meta.get("mode") or "offline"),
        pcap_file=str(meta.get("pcap_file") or ""),
        pcap_name=str(meta.get("pcap_name") or ""),
        packets=len(rows),
        bytes=total_bytes,
        duration_s=duration,
        interface=str(meta.get("interface") or ""),
        bpf=str(meta.get("bpf") or ""),
        first_ts=first_ts,
        last_ts=last_ts,
    )

    missing: set[str] = set()
    if not c2s.rtt.has_sample:
        missing.add("tcp.rtt")
    if not handshakes:
        missing.add("tcp.handshake")
    if not streams:
        missing.add("tcp.streams")
    if not has_dns:
        missing.add("dns.qry.name")
    if not has_http:
        missing.add("http.request")
    if not has_icmp:
        missing.add("icmp.type")
    if not has_arp:
        missing.add("arp.opcode")
    if not has_tls:
        missing.add("tls.sni")

    tcp = TcpFeatures(
        packets=tcp_packets,
        bytes=tcp_bytes,
        streams=streams,
        retrans_rate=_rate(c2s.retrans + s2c.retrans, tcp_packets),
        dup_ack_rate=_rate(c2s.dup_ack + s2c.dup_ack, tcp_packets),
        ooo_rate=_rate(c2s.ooo + s2c.ooo, tcp_packets),
        rtt=Stats.from_values(g_c2s.rtt + g_s2c.rtt),
        handshake=Stats.from_values(handshakes),
        conn_fail=conn_fail,
        conn_refused=conn_refused,
        dir_totals={"c2s": c2s, "s2c": s2c},
    )

    return Features(capture=capture, tcp=tcp, missing=frozenset(missing))


__all__ = ["build_features", "STATE_CLOSED", "STATE_RST", "STATE_NO_REPLY"]
