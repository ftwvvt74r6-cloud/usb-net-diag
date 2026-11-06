"""L2 本地链路规则：ARP 无应答 = 二层不可达。

判据要点：**请求次数 ≥ 阈值且全程无应答**才算。单次请求无应答可能只是对方
在睡眠/开机中，误报会直接摧毁信任，所以阈值放在 ``thresholds.json``。
"""

from __future__ import annotations

from ..contracts import Category, Endpoint, EndpointKind, Finding, Layer, Severity
from .base import Rule, RuleContext


def arp_no_reply(ctx: RuleContext) -> list[Finding]:
    arp = ctx.features.arp or {}
    items = arp.get("no_reply") or []
    need = int(ctx.thresholds.num("l2.arp.min_requests", 2))
    hits = [x for x in items if int(x.get("requests", 0)) >= need]
    if not hits:
        return []

    targets = tuple(
        Endpoint(ip=str(x.get("ip", "")),
                 kind=EndpointKind.GATEWAY if x.get("is_gateway") else EndpointKind.UNKNOWN)
        for x in hits[:5]
    )
    frames = tuple(int(f) for x in hits for f in (x.get("frames") or [])[:2])[:8]

    gw_hit = any(x.get("is_gateway") for x in hits)
    return [Finding(
        rule_id="L2.ARP.NO_REPLY",
        layer=Layer.L2,
        severity=Severity.CRITICAL if gw_hit else Severity.WARNING,
        category=Category.L2_ARP,
        metric={
            "count": len(hits),
            "addresses": [str(x.get("ip", "")) for x in hits[:8]],
            "min_requests": need,
            "gateway_affected": gw_hit,
        },
        targets=targets,
        frames=frames,
        confidence=1.0,
        advice_key="L2.ARP.ADVICE",
    )]


RULES: tuple[Rule, ...] = (
    Rule(
        id="L2.ARP.NO_REPLY",
        layer=Layer.L2,
        fn=arp_no_reply,
        requires=frozenset({"arp.no_reply"}),
        version=1,
        description="同网段 ARP 多次请求无应答（含网关时升级为严重）",
    ),
)

__all__ = ["RULES", "arp_no_reply"]
