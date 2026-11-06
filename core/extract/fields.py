"""tshark 字段清单与「原始字符串 → Python 值」的解析函数。

为什么单独一层：规则引擎与它的单测不应该需要 tshark 才能跑。
把「tshark 输出长什么样」与「这些数怎么聚合」分成两层，
上层就能拿一份 JSON 回放，CI 里完全不需要装 Wireshark。

**这一层只做一件事**：把 tshark ``-T fields`` 吐出来的字符串，变成可靠的
``bool`` / ``float | None`` / ``int``。任何业务判断都不在这里。

两个必须知道的坑（都来自 tshark 的真实输出）：

1. **布尔字段两种写法**：``tcp.flags.syn`` 这类是 ``1``/``0``，
   但 ``tcp.analysis.retransmission`` 这类分析字段会输出 ``True``/``False``。
   只认 ``"1"`` 会把所有重传漏掉，所以 :func:`parse_flag` 大小写不敏感地
   同时接受 ``1`` / ``true`` / ``yes``。
2. **重复字段是逗号聚合**：``-E occurrence=a -E aggregator=,`` 下，
   一个帧里出现两次 duplicate_ack 会输出 ``"1,1"``。
   拿 ``"1,1"`` 去 ``float()`` 会直接抛异常，所以 :func:`parse_num`
   取第一段、:func:`parse_flag` 任一段为真就算真。
"""

from __future__ import annotations

import csv
import io
from typing import Any, Iterable

#: 与 ``core/analyzer.py`` 的 ``FIELDS`` **逐项相同**。
#:
#: 刻意复制而不是 import：extract 层不允许反向依赖 analyzer
#: （单向依赖 ``analyzer → extract``），否则拆层就失去意义。
#: 两处不一致时以本文件为准，analyzer 侧由 T16 的对照测试守住。
FIELDS: tuple[str, ...] = (
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
)

#: 视为「真」的字符串（小写比较）。
_TRUE_WORDS = frozenset({"1", "true", "yes"})


def parse_flag(v: Any) -> bool:
    """把 tshark 的布尔字段转成 ``bool``。

    任一逗号分段命中 ``1`` / ``true`` / ``yes`` 即为真（大小写不敏感）。
    这样 ``"True"``、``"1,1"``、``" 1 "`` 都能正确识别。

    Args:
        v: tshark 原始值，可能是 ``"1"`` / ``"0"`` / ``"True"`` / ``"False"`` /
            ``"1,1"`` / ``None`` / 空串。

    Returns:
        bool: 为真返回 True；空值、``"0"``、``"False"``、无法识别的串返回 False。
    """
    if v is None:
        return False
    return any(part.strip().lower() in _TRUE_WORDS for part in str(v).split(","))


def parse_num(v: Any) -> float | None:
    """把 tshark 的数值字段转成 ``float``；取不到就返回 ``None``。

    取逗号聚合值的**第一段**（``"0.123,0.456"`` → ``0.123``）。

    为什么返回 ``None`` 而不是 ``0.0``：``0`` 是一个合法测量值
    （零延迟、零窗口），用它表示「没这个字段」会让上层无法区分
    「测到 0」和「没测」，从而把「没样本」误判成「一切正常」。

    Args:
        v: tshark 原始值。

    Returns:
        float | None: 解析成功返回数值；空串 / ``None`` / 非数字返回 None。
    """
    if v is None:
        return None
    first = str(v).split(",")[0].strip()
    if not first:
        return None
    try:
        return float(first)
    except ValueError:
        return None


def parse_port(v: Any) -> int:
    """把 tshark 的端口字段转成 ``int``；失败返回 ``0``。

    Args:
        v: tshark 原始值，可能是 ``"443"`` / ``"443,8080"`` / 空串。

    Returns:
        int: 逗号取第一段；空串与非法值返回 0（端口 0 不是合法业务端口，
            上层可以据此判断「没有端口」）。
    """
    if v is None:
        return 0
    try:
        return int(str(v).split(",")[0].strip())
    except ValueError:
        return 0


def parse_int(v: Any) -> int:
    """把 tshark 的整数字段转成 ``int``；失败返回 ``0``。

    与 :func:`parse_port` 的区别只在于语义：这里用于 frame.number / frame.len /
    tcp.len 这类计数，``0`` 天然表示「没有」。

    Args:
        v: tshark 原始值。

    Returns:
        int: 解析成功返回整数（``"3.0"`` 这类也会转成 3）；失败返回 0。
    """
    if v is None:
        return 0
    first = str(v).split(",")[0].strip()
    if not first:
        return 0
    try:
        return int(first)
    except ValueError:
        try:
            return int(float(first))
        except ValueError:
            return 0


def parse_rows(lines: Iterable[str]) -> list[dict[str, str]]:
    """把 ``tshark -T fields`` 的整段输出解析成行字典列表。

    表头行（``-E header=y`` 产生的）会被识别并用作键名；没有表头时按
    :data:`FIELDS` 的顺序对齐。列数不足时补空串 —— tshark 在字段全空的帧上
    会少输出分隔符，直接 ``zip`` 会让后面的字段整体错位。

    Args:
        lines: tshark 输出的行序列（已去掉行尾换行）。

    Returns:
        list[dict[str, str]]: 每个报文一行，键是字段名，值是**原始字符串**
            （不做类型转换，交给 :func:`parse_flag` 等函数按需解析）。
    """
    header: list[str] | None = None
    out: list[dict[str, str]] = []
    for raw in lines:
        if not raw:
            continue
        cols = next(csv.reader(io.StringIO(raw), delimiter="|", quotechar='"'), [])
        if header is None:
            if cols and cols[0].strip().lower() in ("frame.number", "frame"):
                header = [c.strip() for c in cols]
                continue
            header = list(FIELDS)
        if len(cols) < len(header):
            cols += [""] * (len(header) - len(cols))
        out.append(dict(zip(header, cols)))
    return out


__all__ = [
    "FIELDS",
    "parse_flag",
    "parse_num",
    "parse_port",
    "parse_int",
    "parse_rows",
]
