"""安全观察规则（附带项，不参与网络故障主判定）。

两条纪律：

1. **只在 ``layer=SEC``**，verdict 计算主结论时必须排除，避免安全问题抢主线；
2. **绝不把明文内容放进 Finding**。现有实现把 ``Authorization`` 头的前 80 字节
   和带 ``password=`` 的 URI 放进 ``finding`` 文本，于是它们同时进入报告、
   AI prompt 和 MCP 返回——这是评审 P0-3 指出的真实泄露路径。
   这里只记「类型 + 位置 + 帧号」，内容一律不落。
"""

from __future__ import annotations

from ..contracts import Category, Endpoint, Finding, Layer, Severity
from .base import Rule, RuleContext


def plaintext_creds(ctx: RuleContext) -> list[Finding]:
    app = ctx.features.app or {}
    events = app.get("plaintext_creds") or []
    if not events:
        return []

    # 按类型汇总，避免同一类问题刷屏
    by_type: dict[str, int] = {}
    targets: list[Endpoint] = []
    frames: list[int] = []
    for ev in events:
        kind = str(ev.get("type", "unknown"))
        by_type[kind] = by_type.get(kind, 0) + 1
        if ev.get("ip"):
            targets.append(Endpoint(ip=str(ev["ip"])))
        if ev.get("frame") is not None:
            try:
                frames.append(int(ev["frame"]))
            except (TypeError, ValueError):
                pass

    return [Finding(
        rule_id="SEC.PLAINTEXT",
        layer=Layer.SEC,
        severity=Severity.WARNING,
        category=Category.SEC_PLAINTEXT,
        metric={
            "count": len(events),
            "by_type": by_type,
            # 只有「位置」与「帧号」，没有口令本身
            "where": [str(ev.get("where", ""))[:60] for ev in events[:5]],
        },
        targets=tuple(targets[:5]),
        frames=tuple(frames[:8]),
        confidence=1.0,
        advice_key="SEC.PLAINTEXT.ADVICE",
    )]


RULES: tuple[Rule, ...] = (
    Rule(
        id="SEC.PLAINTEXT",
        layer=Layer.SEC,
        fn=plaintext_creds,
        requires=frozenset({"app.plaintext_creds"}),
        version=1,
        description="明文凭证传输（HTTP Basic / FTP PASS / URL 敏感参数 / Telnet）",
    ),
)

__all__ = ["RULES", "plaintext_creds"]
