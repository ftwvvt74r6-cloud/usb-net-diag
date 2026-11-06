"""tshark 字段清单与逐行解析。

这是**采集边界的另一半**：把 tshark 的 ``-T fields`` 输出变成结构化 ``Record``。
把它单独抽出来的原因（评审第 2 步）：规则测试不应该需要 tshark 才能跑。

字段选择的两个原则：

1. **一次调用取全**：多扫一遍 pcap 就多一遍 IO，大文件上是分钟级差别；
2. **只取判断需要的**：不取 payload、不取 Header 原文——既省内存，也减少泄露面。
   ``http.authorization`` 这类字段只在内存里用于「存在性判断」，**永不落盘、永不出网**。
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Iterator, Mapping, Sequence

from ..contracts import Direction

#: 与现有 ``core/analyzer.py`` 的 FIELDS 保持兼容，并按需要补充。
FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
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
    "udp.srcport",
    "udp.dstport",
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
)

#: 字段 → ``Record`` 属性的映射（集中一处，改动只改这里）。
_FIELD_TO_ATTR: Mapping[str, str] = {
    "frame.number": "frame",
    "frame.time_epoch": "ts",
    "frame.len": "length",
    "ip.src": "src",
    "ip.dst": "dst",
    "ip.proto": "ip_proto",
    "tcp.srcport": "sport",
    "tcp.dstport": "dport",
    "tcp.stream": "stream",
    "tcp.len": "tcp_len",
    "tcp.flags.syn": "syn",
    "tcp.flags.ack": "ack",
    "tcp.flags.reset": "rst",
    "tcp.flags.fin": "fin",
    "tcp.analysis.retransmission": "retrans",
    "tcp.analysis.fast_retransmission": "fast_retrans",
    "tcp.analysis.duplicate_ack": "dup_ack",
    "tcp.analysis.out_of_order": "ooo",
    "tcp.analysis.zero_window": "zero_win",
    "tcp.analysis.window_full": "win_full",
    "tcp.analysis.lost_segment": "lost",
    "tcp.analysis.ack_rtt": "ack_rtt_s",
    "udp.srcport": "udp_sport",
    "udp.dstport": "udp_dport",
    "dns.qry.name": "dns_qname",
    "dns.flags.rcode": "dns_rcode",
    "dns.flags.response": "dns_is_response",
    "dns.time": "dns_time_s",
    "http.request.method": "http_method",
    "http.host": "http_host",
    "http.request.uri": "http_uri",
    "http.response.code": "http_code",
    "http.time": "http_time_s",
    "http.authorization": "http_authorization",
    "ftp.request.command": "ftp_command",
    "ftp.request.arg": "ftp_arg",
    "tls.handshake.extensions_server_name": "tls_sni",
    "tls.alert_message": "tls_alert",
    "icmp.type": "icmp_type",
    "icmp.code": "icmp_code",
    "arp.opcode": "arp_opcode",
    "arp.dst.proto_ipv4": "arp_dst",
    "arp.src.proto_ipv4": "arp_src",
}


@dataclass(slots=True)
class Record:
    """一个报文的**判断相关**字段。缺失值用 ``None``/``0`` 表示，绝不用魔法值。"""

    frame: int = 0
    ts: float = 0.0
    length: int = 0
    src: str = ""
    dst: str = ""
    ip_proto: str = ""
    sport: int | None = None
    dport: int | None = None
    stream: str = ""
    tcp_len: int = 0
    syn: bool = False
    ack: bool = False
    rst: bool = False
    fin: bool = False
    retrans: bool = False
    fast_retrans: bool = False
    dup_ack: bool = False
    ooo: bool = False
    zero_win: bool = False
    win_full: bool = False
    lost: bool = False
    ack_rtt_s: float = 0.0
    udp_sport: int | None = None
    udp_dport: int | None = None
    dns_qname: str = ""
    dns_rcode: str = ""
    dns_is_response: bool = False
    dns_time_s: float = 0.0
    http_method: str = ""
    http_host: str = ""
    http_uri: str = ""
    http_code: str = ""
    http_time_s: float = 0.0
    http_authorization: str = ""     # 只用于「存在性判断」，禁止外传
    ftp_command: str = ""
    ftp_arg: str = ""                # 同上：只判断，不落盘
    tls_sni: str = ""
    tls_alert: str = ""
    icmp_type: str = ""
    icmp_code: str = ""
    arp_opcode: str = ""
    arp_dst: str = ""
    arp_src: str = ""

    @property
    def rtt_ms(self) -> float:
        return round(self.ack_rtt_s * 1000.0, 3)

    def direction(self, client_ip: str) -> Direction:
        """相对抓包点判定方向。**所有方向统计都必须经过这里**。"""
        return Direction.C2S if self.src == client_ip else Direction.S2C


def _int(value: str) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _port(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _truth(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


def parse_line(line: str, header: Sequence[str] | None = None) -> Record:
    """解析一行 ``-T fields`` 输出。字段顺序以 ``header`` 为准。"""
    cols = next(csv.reader(io.StringIO(line), delimiter="|", quotechar='"'), [])
    names = list(header or FIELDS)
    if len(cols) < len(names):
        cols += [""] * (len(names) - len(cols))

    rec = Record()
    for name, raw in zip(names, cols):
        attr = _FIELD_TO_ATTR.get(name)
        if attr is None:
            continue
        if attr in ("frame", "length", "tcp_len"):
            setattr(rec, attr, _int(raw))
        elif attr in ("sport", "dport", "udp_sport", "udp_dport"):
            setattr(rec, attr, _port(raw))
        elif attr in ("ts", "ack_rtt_s", "dns_time_s", "http_time_s"):
            setattr(rec, attr, _float(raw))
        elif attr in ("syn", "ack", "rst", "fin", "retrans", "fast_retrans",
                      "dup_ack", "ooo", "zero_win", "win_full", "lost",
                      "dns_is_response"):
            setattr(rec, attr, _truth(raw))
        else:
            setattr(rec, attr, raw)
    return rec


def looks_like_header(line: str) -> bool:
    """tshark 带 ``-E header=y`` 时会先输出一行表头。"""
    first = line.split("|", 1)[0].strip().lower()
    return first in ("frame.number", "frame")


def iter_records(lines: Iterator[str]) -> Iterator[Record]:
    """从 tshark 输出流里逐条 yield ``Record``，自动跳过表头。"""
    header: list[str] | None = None
    for raw in lines:
        if not raw.strip():
            continue
        if header is None and looks_like_header(raw):
            header = [c.strip() for c in raw.split("|")]
            continue
        yield parse_line(raw, header)


def tshark_args(pcap: str, fields: Sequence[str] = FIELDS,
                separator: str = "|") -> list[str]:
    """构造 ``tshark -r <pcap> -T fields ...`` 参数。

    ``occurrence=a`` 让重复出现的字段用逗号拼接（现有实现依赖这个行为）。
    """
    args = [tshark_placeholder(), "-r", pcap, "-n", "-T", "fields",
            "-E", "header=y", "-E", f"separator={separator}",
            "-E", "quote=d", "-E", "aggregator=,", "-E", "occurrence=a"]
    for field in fields:
        args.extend(["-e", field])
    return args


def tshark_placeholder() -> str:
    """占位符：真实可执行文件路径由 ``capture.tshark.find_tshark()`` 提供。

    独立成函数，是为了让 ``tshark_args`` 在单测里可用（不需要真 tshark）。
    """
    return "tshark"


__all__ = [
    "FIELDS", "Record", "parse_line", "iter_records", "looks_like_header",
    "tshark_args", "tshark_placeholder",
]
