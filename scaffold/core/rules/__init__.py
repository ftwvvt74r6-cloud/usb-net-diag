"""规则包：注册表入口。

用法::

    from core.rules import registry, run_rules
    from core.rules.base import RuleContext, Thresholds

    ctx = RuleContext(features=features, thresholds=Thresholds.from_dict(raw))
    result = run_rules(registry(), ctx)
    result.findings   # 已排序
    result.skipped    # 因缺特征没跑的规则（→ Sufficiency）
"""

from .base import (
    LAYER_ORDER,
    Rule,
    RuleContext,
    RuleRun,
    Thresholds,
    by_layer,
    registry,
    run_rules,
    sort_findings,
)

__all__ = [
    "LAYER_ORDER", "Rule", "RuleContext", "RuleRun", "Thresholds",
    "by_layer", "registry", "run_rules", "sort_findings",
]
