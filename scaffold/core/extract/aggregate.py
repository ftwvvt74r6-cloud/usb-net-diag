"""流级聚合：``Record`` 流 → ``Features``。

**本文件是评审 P0-2 的落点。** 现有实现把 ``retrans`` / ``dup_ack`` / ``ooo`` /
``zero_win`` 全部按流累加，导致规划第 5 步的三条规则无法写对：
「客户端重传」既可能是上行丢包，也可能是下行 ACK 丢失；「零窗口」甚至可能
来自客户端自己（VDI 场景极常见）。

这里的 ``DirCounters`` 是**可直接复用的小积木**：每个方向一个累加器，
``add(record)`` 里只做计数，不做判断。真正的 ``build_features()`` 由调用方
按下面的 TODO 顺序填。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from ..contracts import (
    CaptureMeta,
    DirStat,
    Direction,
    Endpoint,
    Features,
    Stats,
    StreamStat,
    TcpFeatures,
)
from .fields import Record


@dataclass
class DirCounters:
    """单方向累加器。**方向由 ``Record.direction(client_ip)`` 决定**，不靠猜。"""

    direction: Direction
    packets: int = 0
    bytes: int = 0
    data_packets: int = 0
    retrans: int = 0
    fast_retrans: int = 0
    dup_ack: int = 0
    ooo: int = 0
    zero_win: int = 0
    win_full: int = 0
    rst: int = 0
    syn: int = 0
    rtts: list[float] = field(default_factory=list)

    def add(self, rec: Record) -> None:
        self.packets += 1
        self.bytes += rec.length
        if rec.tcp_len > 0:
            self.data_packets += 1
        if rec.syn:
            self.syn += 1
            # SYN 重发是「建连问题」，不是链路丢包 —— 单列，别混进重传率
            if rec.retrans:
                self.retrans += 0  # 保持语义清晰：不把 SYN 重发计入
        elif rec.retrans:
            self.retrans += 1
        if rec.fast_retrans:
            self.fast_retrans += 1
        if rec.dup_ack:
            self.dup_ack += 1
        if rec.ooo:
            self.ooo += 1
        if rec.zero_win:
            self.zero_win += 1
        if rec.win_full:
            self.win_full += 1
        if rec.rst:
            self.rst += 1
        if rec.ack_rtt_s > 0:
            self.rtts.append(rec.rtt_ms)

    def to_stat(self) -> DirStat:
        return DirStat(
            direction=self.direction,
            packets=self.packets,
            bytes=self.bytes,
            retrans=self.retrans,
            dup_ack=self.dup_ack,
            ooo=self.ooo,
            zero_win=self.zero_win,
            win_full=self.win_full,
            rst=self.rst,
            syn=self.syn,
            data_packets=self.data_packets,
            rtt=Stats.from_values(self.rtts),
        )


class DirPair:
    """一条会话的两个方向。几乎所有规则要的都是「成对」的统计数据。"""

    def __init__(self, client: str, server: str) -> None:
        self.client = client
        self.server = server
        self.by_dir: dict[Direction, DirCounters] = {
            Direction.C2S: DirCounters(Direction.C2S),
            Direction.S2C: DirCounters(Direction.S2C),
        }

    def add(self, rec: Record) -> None:
        self.by_dir[rec.direction(self.client)].add(rec)

    def stats(self) -> dict[Direction, DirStat]:
        return {d: c.to_stat() for d, c in self.by_dir.items()}

    @property
    def total_packets(self) -> int:
        return sum(c.packets for c in self.by_dir.values())


def per_direction_totals(streams: Sequence[StreamStat]) -> dict[str, DirStat]:
    """把所有会话按方向**汇总**成两个 ``DirStat``（喂给 L4 规则的就是这个）。"""
    acc: dict[Direction, DirCounters] = {
        Direction.C2S: DirCounters(Direction.C2S),
        Direction.S2C: DirCounters(Direction.S2C),
    }
    for stream in streams:
        for direction, stat in stream.dirs.items():
            target = acc[Direction(direction) if not isinstance(direction, Direction) else direction]
            target.packets += stat.packets
            target.bytes += stat.bytes
            target.data_packets += stat.data_packets
            target.retrans += stat.retrans
            target.dup_ack += stat.dup_ack
            target.ooo += stat.ooo
            target.zero_win += stat.zero_win
            target.win_full += stat.win_full
            target.rst += stat.rst
            target.syn += stat.syn
    return {d.value: c.to_stat() for d, c in acc.items()}


def retrans_rate(streams: Sequence[StreamStat], tcp_packets: int) -> float:
    """重传率 = 重传包 / TCP 包。**分母是 TCP 包数**，不是数据包数（与现有实现一致）。"""
    if tcp_packets <= 0:
        return 0.0
    retrans = sum(s.dirs[d].retrans for s in streams for d in s.dirs)
    return round(retrans / tcp_packets * 100.0, 2)


def empty_features(capture: CaptureMeta | None = None) -> Features:
    """空特征集。所有 ``requires`` 都会判定为「缺失」，于是规则不跑。"""
    return Features(capture=capture or CaptureMeta(),
                    missing=frozenset({"tcp.packets", "tcp.retrans_rate", "tcp.dir_totals",
                                       "tcp.rtt", "dns.fail_rate", "dns.avg_ms",
                                       "http.requests", "icmp.unreach", "arp.no_reply",
                                       "app.plaintext_creds"}))


def build_features(pcap: str, adapter: object | None = None, log=None) -> Features:
    """读 pcap → ``Features``。**这是迁移期的主要工作量所在。**

    TODO(迁移) 按这个顺序填，每步都能单独测试：

    1. ``adapter.iter_fields(pcap)`` 拿记录流 → ``fields.iter_records()``；
    2. 逐条 ``Record``：TCP 按 ``tcp.stream`` 分组，用 ``DirPair`` 累计**双向**统计；
    3. 同一遍里累计 DNS / HTTP / TLS / ICMP / ARP 到 ``Features`` 的对应 dict；
    4. 由 ``DirPair`` 产出 ``StreamStat``（含 ``handshake_ms`` / ``think_ms``）；
    5. ``per_direction_totals()`` → ``TcpFeatures.dir_totals``；
    6. 标 ``missing``：凡是**没有样本**的键都写进去（这是充足性判定的输入）——
       例如没有 DNS 报文时 ``dns.samples`` 缺失，而不是 ``dns.avg_ms = 0``；
    7. 返回 ``Features``，并支持 ``json.dump(features.to_dict())`` 落盘成
       ``features.json``（CI 回放就用这个文件，不需要 tshark）。

    实现要点：

    * **不要**在这里做任何「严重/警告」判断——那是 rules 的事；
    * **不要**把 ``http_authorization`` / ``ftp_arg`` 放进 ``Features``，
      只把「存在明文凭证」的事实与位置放进去（``app.plaintext_creds``）；
    * 单遍扫描，别为了某个指标再扫一遍 pcap。
    """
    raise NotImplementedError("build_features(): 见 docstring 的第 1~7 步")


__all__ = [
    "DirCounters", "DirPair", "per_direction_totals", "retrans_rate",
    "empty_features", "build_features",
]
