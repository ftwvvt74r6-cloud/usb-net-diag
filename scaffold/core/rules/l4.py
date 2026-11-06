"""L4 传输层规则。

本文件是**规划第 5 步两处方向错误**的修正示范：

1. ``L4.RETRANS.HIGH``：不再用「重传率高 + RTT 稳定 → 服务端未收到数据」下结论。
   抓包点在本机，客户端重传只能证明「发了两次没收到 ACK」，方向必须靠
   **对端是否持续返回重复 ACK** 来判：

   * 客户端重传 + 服务端 dup-ACK  → 服务端见到了后续包、中间缺一段 = 上行丢包
   * 服务端重传 + 客户端 dup-ACK  → 下行丢包
   * 两侧都重传                    → 双向 / 中间设备
   * 只有单侧重传、无 dup-ACK      → 方向不定，置信度降到 0.4 并写「疑似」

   因此结论一律带 ``evidence_kind=INFERRED`` 与 ``confidence < 1.0``，
   由渲染层输出「疑似 + 证据 + 怎么证伪」，而不是一句确定的错话。

2. ``L4.ZEROWIN.CLIENT/SERVER``：零窗口是**接收方**通告的。
   服务端通告 → 客户端在上传、服务端读不过来 = 服务端瓶颈；
   客户端通告 → 客户端在下载、客户端消费不过来 = **客户端瓶颈**（VDI 极常见）。
   现有实现只累加总数，所以这条规则以前根本不可能写对。
"""

from __future__ import annotations

from ..contracts import (
    Category,
    DirStat,
    Direction,
    Endpoint,
    EndpointKind,
    EvidenceKind,
    Finding,
    Layer,
    Severity,
)
from .base import Rule, RuleContext, Thresholds


# ---------------------------------------------------------------- 公共小工具


def _severity_for_rate(rate: float, th: Thresholds) -> Severity:
    if rate >= th.num("l4.retrans.critical", 5.0):
        return Severity.CRITICAL
    if rate >= th.num("l4.retrans.warning", 2.0):
        return Severity.WARNING
    if rate >= th.num("l4.retrans.info", 0.5):
        return Severity.INFO
    return Severity.OK


def _classify_direction(c2s: DirStat, s2c: DirStat) -> tuple[Direction | None, EvidenceKind, float, str]:
    """按「谁重传 + 谁在发 dup-ACK」判定丢包方向。

    返回 ``(direction, evidence_kind, confidence, headline_key_suffix)``。

    注意 ``dup_ack`` 的语义：**收到乱序数据的一方**会重复确认最后一段连续字节，
    所以「服务端发 dup-ACK」= 服务端在客户端的数据流里看到缺口 = 上行有丢包。
    """
    up_loss = c2s.retrans > 0 and s2c.dup_ack > 0
    down_loss = s2c.retrans > 0 and c2s.dup_ack > 0

    if up_loss and not down_loss:
        return Direction.C2S, EvidenceKind.INFERRED, 0.85, ".UP"
    if down_loss and not up_loss:
        return Direction.S2C, EvidenceKind.INFERRED, 0.85, ".DOWN"
    if up_loss and down_loss:
        return Direction.BIDIR, EvidenceKind.INFERRED, 0.7, ".BIDIR"
    # 只有重传、没有 dup-ACK：可能是对端没处理，也可能是 ACK 丢了 —— 方向不定
    return None, EvidenceKind.INFERRED, 0.4, ".UNKNOWN"


def _top_streams(ctx: RuleContext, limit: int = 3):
    """按「重传数」挑出最值得看的几条会话，用于给出 targets / frames。"""

    def retrans_of(stream) -> int:
        return sum(d.retrans for d in stream.dirs.values())

    ranked = sorted(ctx.features.tcp.streams, key=retrans_of, reverse=True)
    return [s for s in ranked if retrans_of(s) > 0][:limit]


# ---------------------------------------------------------------- 规则


def retrans_high(ctx: RuleContext) -> list[Finding]:
    tcp = ctx.features.tcp
    severity = _severity_for_rate(tcp.retrans_rate, ctx.thresholds)
    if severity is Severity.OK:
        return []

    c2s = tcp.total(Direction.C2S)
    s2c = tcp.total(Direction.S2C)
    direction, kind, confidence, suffix = _classify_direction(c2s, s2c)

    tops = _top_streams(ctx)
    targets = tuple(
        Endpoint(ip=s.server.ip, port=s.server.port, kind=EndpointKind.SERVER)
        for s in tops
    )
    frames = tuple(f for s in tops for f in s.frames[:2])[:8]

    return [Finding(
        rule_id="L4.RETRANS.HIGH",
        layer=Layer.L4,
        severity=severity,
        category=Category.TRANSPORT,
        metric={
            "retrans_rate": round(tcp.retrans_rate, 2),
            "retrans_total": c2s.retrans + s2c.retrans,
            "tcp_packets": tcp.packets,
            "c2s_retrans": c2s.retrans,
            "s2c_retrans": s2c.retrans,
            "c2s_dup_ack": c2s.dup_ack,
            "s2c_dup_ack": s2c.dup_ack,
            "dir_confidence": confidence,
        },
        targets=targets,
        frames=frames,
        streams=tuple(s.stream for s in tops),
        direction=direction,
        confidence=confidence,
        evidence_kind=kind,
        # 文案 key：标题按方向给不同措辞，建议同理
        headline_key="L4.RETRANS.HIGH" + suffix,
        advice_key="L4.RETRANS.ADVICE" + (".UP" if suffix == ".UP" else
                                          ".DOWN" if suffix == ".DOWN" else ""),
    )]


def zero_window_side(ctx: RuleContext) -> list[Finding]:
    """零窗口归属。谁通告，谁是瓶颈方；受影响的**数据方向**与之相反。"""
    tcp = ctx.features.tcp
    c2s = tcp.total(Direction.C2S)   # 客户端发的包（含它通告的零窗口）
    s2c = tcp.total(Direction.S2C)

    adv_client, adv_server = c2s.zero_win, s2c.zero_win
    if adv_client == 0 and adv_server == 0:
        return []

    warning_at = int(ctx.thresholds.num("l4.zero_window.warning_count", 3))
    if adv_client >= adv_server:
        advertiser, count, rule_suffix = "client", adv_client, "CLIENT"
        data_direction = Direction.S2C          # 服务端在往客户端发，被卡住
        bottleneck_kind = EndpointKind.CLIENT
        targets = tuple(Endpoint(ip=s.client.ip, kind=EndpointKind.CLIENT)
                        for s in tcp.streams
                        if (s.dir_of(Direction.C2S) or DirStat(Direction.C2S)).zero_win)[:3]
    else:
        advertiser, count, rule_suffix = "server", adv_server, "SERVER"
        data_direction = Direction.C2S          # 客户端在往服务端发，被卡住
        bottleneck_kind = EndpointKind.SERVER
        targets = tuple(Endpoint(ip=s.server.ip, port=s.server.port)
                        for s in tcp.streams
                        if (s.dir_of(Direction.S2C) or DirStat(Direction.S2C)).zero_win)[:3]

    return [Finding(
        rule_id=f"L4.ZEROWIN.{rule_suffix}",
        layer=Layer.L4,
        severity=Severity.WARNING if count >= warning_at else Severity.INFO,
        category=Category.TRANSPORT,
        metric={
            # 关键：把「通告方」显式写进 metric，别让下游再猜
            "advertised_by": advertiser,
            "zero_win": count,
            "client_advertised": adv_client,
            "server_advertised": adv_server,
            "bottleneck_side": bottleneck_kind.value,
            "win_full": c2s.win_full + s2c.win_full,
        },
        targets=targets,
        confidence=0.9,                     # 通告方是直接观测到的，只有「是不是应用慢」是推断
        evidence_kind=EvidenceKind.MEASURED,
        direction=data_direction,
        advice_key="L4.ZEROWIN.ADVICE",
        headline_key=f"L4.ZEROWIN.{rule_suffix}",
    )]


def connect_failed(ctx: RuleContext) -> list[Finding]:
    """SYN 无响应 / 被 RST。两类都属「连接建立」，但严重度与处置完全不同。"""
    tcp = ctx.features.tcp
    out: list[Finding] = []

    if tcp.conn_fail:
        out.append(Finding(
            rule_id="L4.CONNECT.NO_RESPONSE",
            layer=Layer.L4,
            severity=Severity.CRITICAL,
            category=Category.CONNECT,
            metric={"conn_fail": tcp.conn_fail},
            confidence=1.0,
            evidence_kind=EvidenceKind.MEASURED,
            advice_key="L4.CONNECT.ADVICE",
            headline_key="L4.CONNECT.NO_RESPONSE",
        ))

    rst_warn = int(ctx.thresholds.num("l4.connect.rst_warning_count", 3))
    if tcp.conn_refused:
        out.append(Finding(
            rule_id="L4.CONNECT.RST",
            # 注意：RST 的判据建议用「SYN 后立刻 RST」，而不是「流里出现过 RST」。
            # 现有实现是后者，会把正常关闭后的 RST 也算进来（评审 P1）。
            layer=Layer.L4,
            severity=Severity.WARNING if tcp.conn_refused >= rst_warn else Severity.INFO,
            category=Category.CONNECT,
            metric={"conn_refused": tcp.conn_refused},
            confidence=0.8,
            evidence_kind=EvidenceKind.MEASURED,
            advice_key="L4.CONNECT.ADVICE",
            headline_key="L4.CONNECT.RST",
        ))
    return out


RULES: tuple[Rule, ...] = (
    Rule(
        id="L4.RETRANS.HIGH",
        layer=Layer.L4,
        fn=retrans_high,
        # 只有拿到双向拆分才算得出来；没有方向数据就不要下结论
        requires=frozenset({"tcp.packets", "tcp.retrans_rate"}),
        version=2,
        description="TCP 重传率超阈值，按 dup-ACK 方向判定上行/下行丢包",
    ),
    Rule(
        id="L4.ZEROWIN.SIDE",
        layer=Layer.L4,
        fn=zero_window_side,
        requires=frozenset({"tcp.dir_totals"}),
        version=2,
        description="TCP 零窗口按「通告方」归属到客户端或服务端瓶颈",
    ),
    Rule(
        id="L4.CONNECT",
        layer=Layer.L4,
        fn=connect_failed,
        requires=frozenset({"tcp.packets"}),
        version=1,
        description="TCP 建连无响应 / 被 RST",
    ),
)

__all__ = ["RULES", "retrans_high", "zero_window_side", "connect_failed"]
