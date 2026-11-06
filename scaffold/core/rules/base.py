"""规则框架：Rule 协议 + 注册表 + ``requires`` 校验。

**为什么需要 ``requires``**（对应评审 P0-4 / P1）：

现有实现里「没抓到样本」和「样本为 0」无法区分——没有 DNS 样本时
``dns_avg_ms == 0``，于是规则判「正常」。这就是 1 KB 的空抓包被报成
「各层指标正常」的根因。

这里的做法：``Features.missing`` 记录**没能算出来**的特征键，规则声明自己依赖哪些键；
缺失时规则**不执行**，并把「因缺什么而跳过」记进 ``RuleRun.skipped``，
最终由 ``Sufficiency`` 决定结论是否降级为「证据不足」。

**为什么规则不写中文**：文案在 ``core/copy/zh-CN.json``。这样

* 改文案不动逻辑，CI 断言 ``rule_id`` 不会因为改字而红；
* 多语言只是加一份 json；
* AI prompt 与 UI 用的是同一份措辞，不会出现「工具说 A、AI 说 B」。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from ..contracts import Finding, Features, Layer, RULE_ID_RE, Severity

#: 同严重度时的层优先级：越底层越先处理（与现有 verdict 一致）。
LAYER_ORDER: dict[Layer, int] = {
    Layer.L2: 0, Layer.L3: 1, Layer.L4: 2, Layer.L7: 3, Layer.SEC: 9,
}


@dataclass(frozen=True)
class Thresholds:
    """嵌套 JSON 的只读访问器，路径用点号：``get("l4.retrans.critical", 5.0)``。"""

    data: Mapping[str, Any] = field(default_factory=dict)
    version: str = ""

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any] | None) -> "Thresholds":
        raw = dict(raw or {})
        version = ""
        meta = raw.get("_meta")
        if isinstance(meta, Mapping):
            version = str(meta.get("rules_version") or "")
        return cls(data=raw, version=version)

    def get(self, path: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in path.split("."):
            if not isinstance(cur, Mapping) or part not in cur:
                return default
            cur = cur[part]
        return default if cur is None else cur

    def num(self, path: str, default: float = 0.0) -> float:
        try:
            return float(self.get(path, default))
        except (TypeError, ValueError):
            return float(default)

    def boolean(self, path: str, default: bool = False) -> bool:
        return bool(self.get(path, default))


@dataclass(frozen=True)
class RuleContext:
    """规则能看到的全部输入。刻意只有两样：特征 + 阈值（纯数据，无 IO）。"""

    features: Features
    thresholds: Thresholds

    def num(self, path: str, default: float = 0.0) -> float:
        return self.thresholds.num(path, default)


RuleFn = Callable[[RuleContext], Sequence[Finding]]


@dataclass(frozen=True)
class Rule:
    id: str
    layer: Layer
    fn: RuleFn
    requires: frozenset[str] = frozenset()
    version: int = 1
    description: str = ""
    enabled: bool = True

    def __post_init__(self) -> None:
        if not RULE_ID_RE.match(self.id):
            raise ValueError(f"rule_id 形态不合法：{self.id!r}（应形如 L4.RETRANS.HIGH）")
        object.__setattr__(self, "layer", Layer(self.layer))
        object.__setattr__(self, "requires", frozenset(self.requires))

    def missing(self, features: Features) -> tuple[str, ...]:
        return tuple(sorted(k for k in self.requires if not features.has(k)))


@dataclass
class RuleRun:
    findings: list[Finding] = field(default_factory=list)
    #: rule_id → 缺少的特征键（这些规则**没跑**，不是「跑过但没命中」）
    skipped: dict[str, str] = field(default_factory=dict)
    #: rule_id → 异常信息（规则写错不该让整个诊断失败）
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(f.rule_id for f in self.findings)

    def by_layer(self, layer: Layer) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.layer is Layer(layer))


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """严重度 → 层 → rule_id。与现有「自下而上」的判定习惯一致。"""
    return sorted(
        findings,
        key=lambda f: (f.rank, LAYER_ORDER.get(f.layer, 8), f.rule_id),
    )


def run_rules(rules: Iterable[Rule], ctx: RuleContext) -> RuleRun:
    """逐条执行。**一条规则失败不影响其他规则**，失败原因进 ``errors``。"""
    out = RuleRun()
    for rule in rules:
        if not rule.enabled:
            out.skipped[rule.id] = "disabled"
            continue
        missing = rule.missing(ctx.features)
        if missing:
            out.skipped[rule.id] = ", ".join(missing)
            continue
        try:
            produced = list(rule.fn(ctx) or ())
        except Exception as exc:  # noqa: BLE001  规则隔离
            out.errors[rule.id] = f"{type(exc).__name__}: {exc}"
            continue
        for finding in produced:
            if not isinstance(finding, Finding):  # 提前暴露契约违规
                raise TypeError(f"{rule.id} 返回了非 Finding 对象：{type(finding)!r}")
        out.findings.extend(produced)
    out.findings = sort_findings(out.findings)
    return out


# ---------------------------------------------------------------- 注册表


def _load_all() -> tuple[Rule, ...]:
    """延迟导入，避免 rule 模块与 base 循环依赖。"""
    from . import l2, l3, l4, l7, security  # noqa: PLC0415

    return (*l2.RULES, *l3.RULES, *l4.RULES, *l7.RULES, *security.RULES)


_ALL: tuple[Rule, ...] | None = None


def registry() -> tuple[Rule, ...]:
    global _ALL
    if _ALL is None:
        rules = _load_all()
        ids = [r.id for r in rules]
        dup = {i for i in ids if ids.count(i) > 1}
        if dup:
            raise ValueError(f"rule_id 重复：{sorted(dup)}")
        _ALL = rules
    return _ALL


def by_layer(layer: Layer) -> tuple[Rule, ...]:
    return tuple(r for r in registry() if r.layer is Layer(layer))


__all__ = [
    "LAYER_ORDER", "Thresholds", "RuleContext", "Rule", "RuleRun",
    "sort_findings", "run_rules", "registry", "by_layer", "Severity",
]
