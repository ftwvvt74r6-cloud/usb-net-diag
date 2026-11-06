"""文案表的读取与格式化。

所有面向人的字符串都必须经过这里，**不允许在规则/判定/渲染代码里内联中文**。

三个降级规则（U 盘场景很重要）：

* 文案表缺失 → 返回 key 本身，不抛异常（报告难看但不会崩）；
* 占位符不全 → 返回半成品模板，不抛异常（少一个数字也比整个报告没了强）；
* ``label`` 大写/小写都认（``Layer.L4`` 的 value 是 ``"L4"``，文案表里是 ``"l4"``）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


def lookup(table: Mapping | None, key: str, default: Any = None) -> Any:
    """点号路径取值，**并支持「键名里本身带点」**。

    这一点很关键：``rule_id`` 是 ``L4.RETRANS.HIGH`` 这种点分形式，
    而文案表里它就是**一个整键**：``{"headline": {"L4.RETRANS.HIGH": "..."}}``。
    如果按纯点号拆分去查，永远查不到。所以这里按「最长前缀优先」递归：:

        lookup(t, "headline.L4.RETRANS.HIGH")
          → t["headline"] 命中 → lookup(t["headline"], "L4.RETRANS.HIGH")
          → 整键命中 → 返回文案
    """
    if not isinstance(table, Mapping) or not key:
        return default
    if key in table:
        return table[key]
    parts = key.split(".")
    for i in range(len(parts) - 1, 0, -1):        # 从最长前缀开始试
        prefix = ".".join(parts[:i])
        if prefix in table:
            inner = table[prefix]
            if isinstance(inner, Mapping):
                got = lookup(inner, ".".join(parts[i:]), default)
                if got is not None:
                    return got
    return default


def fmt(template: Any, args: Mapping | None = None) -> str:
    """安全格式化：缺占位符不抛，保留原文。"""
    if template is None:
        return ""
    if not isinstance(template, str):
        return str(template)
    try:
        return template.format(**(dict(args or {})))
    except (KeyError, IndexError, ValueError):
        return template


@dataclass(frozen=True)
class CopyTable:
    """把 ``copy/zh-CN.json`` 包一层，提供语义化取用方法。"""

    data: Mapping = None  # type: ignore[assignment]

    @classmethod
    def load(cls, lang: str = "zh-CN") -> "CopyTable":
        from ..config import load_copy  # 延迟导入，避免循环

        return cls(data=load_copy(lang) or {})

    # ---- 取文案 ----
    def text(self, key: str, args: Mapping | None = None, default: str = "") -> str:
        raw = lookup(self.data, key)
        if raw is None:
            return default or key
        return fmt(raw, args)

    def label(self, group: str, value: str) -> str:
        """如 ``label("layer", "L4")`` → 「L4 传输层」（大小写都认）。"""
        text = str(value)
        for candidate in (text, text.lower(), text.upper()):
            raw = lookup(self.data, f"{group}.{candidate}")
            if raw is not None:
                return fmt(raw)
        return text

    def headline(self, verdict: Any) -> str:
        return self.text(verdict.headline_key, verdict.headline_args)

    def impact(self, verdict: Any) -> str:
        return self.text(verdict.impact_key, default="需关注")

    def advice(self, key: str) -> str:
        """``key`` 形如 ``L4.RETRANS.ADVICE.UP``（规则产出的 advice_key）。"""
        return self.text(f"advice.{key}") if key else ""

    def next_step(self, key: str) -> str:
        return self.text(f"next_step.{key}", default=key)

    def layer_detail(self, status: Any) -> str:
        if not status.detail_key:
            return ""
        return self.text(status.detail_key, status.detail_args)

    def insufficient(self, sufficiency: Any) -> list[str]:
        out: list[str] = []
        for reason in getattr(sufficiency, "reasons", ()) or ():
            args = (getattr(sufficiency, "reason_args", {}) or {}).get(reason, {})
            out.append(self.text(f"insufficient.{reason}", args, default=reason))
        return out


__all__ = ["lookup", "fmt", "CopyTable"]
