"""L3 网络层规则：ICMP 不可达 / 超时、RTT 与抖动。

「需要分片」是路径 MTU 问题的典型信号，必须升级为严重——它是少数
「抓包能直接定性」的故障之一。
"""

from __future__ import annotations

from ..contracts import Category, Direction, Endpoint, Finding, Layer, Severity
from .base import Rule, RuleContext


def icmp_unreach(ctx: RuleContext) -> list[Finding]:
    icmp = ctx.features.icmp or {}
    unreach = int(icmp.get("unreach", 0))
    timeout = int(icmp.get("timeout", 0))
    count = unreach + timeout
    if count <= 0:
        return []

    mtu_hit = bool(icmp.get("mtu_hit"))
    escalate = ctx.thresholds.boolean("l3.icmp.mtu_escalates_to_critical", True)

    detail = icmp.get("detail") or []
    targets = tuple(
        Endpoint(ip=str(x.get("dst", "")))
        for x in detail[:3] if x.get("dst")
    )
    frames = tuple(int(x["frame"]) for x in detail[:6] if "frame" in x)

    return [Finding(
        rule_id="L3.ICMP.UNREACH",
        layer=Layer.L3,
        severity=Severity.CRITICAL if (mtu_hit and escalate) else Severity.WARNING,
        category=Category.NET_UNREACH,
        metric={
            "unreach": unreach,
            "timeout": timeout,
            "count": count,
            "mtu_hit": mtu_hit,
            "codes": [str(x.get("desc", "")) for x in detail[:5]],
        },
        targets=targets,
        frames=frames,
        confidence=1.0,
        advice_key="L3.ICMP.ADVICE",
    )]


def rtt_high(ctx: RuleContext) -> list[Finding]:
    tcp = ctx.features.tcp
    rtt = tcp.rtt
    min_samples = int(ctx.thresholds.num("l3.rtt.min_samples", 5))
    if rtt.n < min_samples:
        return []

    warn_ms = ctx.thresholds.num("l3.rtt.warning_ms", 300.0)
    crit_ms = ctx.thresholds.num("l3.rtt.critical_ms", 600.0)
    jitter_warn = ctx.thresholds.num("l3.rtt.jitter_warning_ms", 80.0)

    slow = rtt.avg >= warn_ms
    jittery = rtt.jitter >= jitter_warn
    if not slow and not jittery:
        return []

    return [Finding(
        rule_id="L3.RTT.HIGH",
        layer=Layer.L3,
        severity=Severity.CRITICAL if rtt.avg >= crit_ms else Severity.WARNING,
        category=Category.NET_LATENCY,
        metric={
            "rtt_avg_ms": rtt.avg,
            "rtt_p95_ms": rtt.p95,
            "rtt_max_ms": rtt.max,
            "rtt_jitter_ms": rtt.jitter,
            "samples": rtt.n,
        },
        # 时延是双向的，不做方向归属
        direction=Direction.BIDIR,
        confidence=1.0,
        advice_key="L3.RTT.ADVICE",
    )]


RULES: tuple[Rule, ...] = (
    Rule(
        id="L3.ICMP.UNREACH",
        layer=Layer.L3,
        fn=icmp_unreach,
        requires=frozenset({"icmp.unreach"}),
        version=1,
        description="ICMP 不可达/超时（含「需要分片」时升级为严重）",
    ),
    Rule(
        id="L3.RTT.HIGH",
        layer=Layer.L3,
        fn=rtt_high,
        requires=frozenset({"tcp.rtt"}),
        version=1,
        description="RTT 均值或抖动超阈值",
    ),
)

__all__ = ["RULES", "icmp_unreach", "rtt_high"]
