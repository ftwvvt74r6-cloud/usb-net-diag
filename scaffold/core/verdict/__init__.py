"""判定层：findings → Verdict（纯函数）。"""

from .verdict import NET_LAYERS, RULE_NEXT_STEPS, assess_sufficiency, build, build_layers

__all__ = ["NET_LAYERS", "RULE_NEXT_STEPS", "assess_sufficiency", "build", "build_layers"]
