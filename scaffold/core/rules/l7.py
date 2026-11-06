"""L7 应用层规则：DNS 失败/慢、HTTP 5xx、TLS 告警。

L7 的判据最容易和「网络慢」混淆，所以每条规则都必须能回答：
**这个数字是应用产生的，还是链路产生的？** 为此在这里只做「应用层自身」的判断，
跨层的因果（服务端慢 vs 链路慢）交给 verdict 层用 RTT/首字节对比。
"""

from __future__ import annotations

from ..contracts import Category, Finding, Layer, Severity
from .base import Rule, RuleContext


def dns_fail(ctx: RuleContext) -> list[Finding]:
    dns = ctx.features.dns or {}
    rate = float(dns.get("fail_rate", 0.0))
    if rate <= 0:
        return []

    warn = ctx.thresholds.num("l7.dns_fail.warning", 20.0)
    crit = ctx.thresholds.num("l7.dns_fail.critical", 50.0)
    if rate < warn:
        return []

    return [Finding(
        rule_id="L7.DNS.FAIL",
        layer=Layer.L7,
        severity=Severity.CRITICAL if rate >= crit else Severity.WARNING,
        category=Category.DNS,
        metric={
            "rate": round(rate, 1),
            "nxdomain": int(dns.get("nxdomain", 0)),
            "queries": int(dns.get("queries", 0)),
            "responses": int(dns.get("responses", 0)),
            "top_names": list(dns.get("nx_top") or [])[:3],
        },
        confidence=1.0,
        advice_key="L7.DNS.ADVICE",
    )]


def dns_slow(ctx: RuleContext) -> list[Finding]:
    dns = ctx.features.dns or {}
    avg = float(dns.get("avg_ms", 0.0))
    warn = ctx.thresholds.num("l7.dns_latency.warning_ms", 300.0)
    crit = ctx.thresholds.num("l7.dns_latency.critical_ms", 800.0)
    if avg < warn:
        return []

    return [Finding(
        rule_id="L7.DNS.SLOW",
        layer=Layer.L7,
        severity=Severity.CRITICAL if avg >= crit else Severity.WARNING,
        category=Category.DNS,
        metric={"avg_ms": round(avg, 1),
                "max_ms": float(dns.get("max_ms", 0.0)),
                "samples": int(dns.get("samples", 0)),
                "servers": list(dns.get("servers") or [])[:2]},
        confidence=1.0,
        advice_key="L7.DNS.ADVICE",
    )]


def http_5xx(ctx: RuleContext) -> list[Finding]:
    http = ctx.features.http or {}
    err5 = int(http.get("err5", 0))
    if err5 <= 0:
        return []

    rate = float(http.get("err5_rate", 0.0))
    warn = ctx.thresholds.num("l7.http_5xx_rate.warning", 1.0)
    crit = ctx.thresholds.num("l7.http_5xx_rate.critical", 10.0)

    return [Finding(
        rule_id="L7.HTTP.5XX",
        layer=Layer.L7,
        severity=Severity.CRITICAL if rate >= crit else Severity.WARNING,
        category=Category.APP,
        metric={"err5": err5, "err5_rate": round(rate, 1),
                "requests": int(http.get("requests", 0)),
                "codes": list(http.get("codes") or [])[:5]},
        confidence=1.0,
        advice_key="L7.HTTP.ADVICE",
    )]


RULES: tuple[Rule, ...] = (
    Rule(
        id="L7.DNS.FAIL",
        layer=Layer.L7,
        fn=dns_fail,
        requires=frozenset({"dns.fail_rate"}),
        version=1,
        description="DNS 失败率（NXDOMAIN）超阈值",
    ),
    Rule(
        id="L7.DNS.SLOW",
        layer=Layer.L7,
        fn=dns_slow,
        requires=frozenset({"dns.avg_ms"}),
        version=1,
        description="DNS 平均耗时超阈值",
    ),
    Rule(
        id="L7.HTTP.5XX",
        layer=Layer.L7,
        fn=http_5xx,
        requires=frozenset({"http.requests"}),
        version=1,
        description="HTTP 5xx（服务端错误，网络不背锅）",
    ),
)

__all__ = ["RULES", "dns_fail", "dns_slow", "http_5xx"]
