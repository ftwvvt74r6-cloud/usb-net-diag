"""文案表访问器：``core/copy/zh-CN.json`` 的唯一读取入口。

设计约束（为什么要有这一层）：

1. **单一来源**：报告 / 判定 / 建议 / AI prompt 的中文全部从这里取，代码里只留 key。
   改文案只改 JSON，不该出现「代码里还有一份、copy 表是假话」。
2. **读数即真**：每次调用都重新读盘，测试可以 monkeypatch ``core.config.load_copy``
   或改 JSON 文件，立即反映到输出上；不引入进程级缓存。
3. **绝不抛异常**：U盘场景下文案表可能被拔盘/截断。读不到 → 返回 ``{}``；
   取不到 key → 返回 key 本身；占位符实参缺失 → 返回原文模板。
   「报告难看」可以接受，「报告渲染崩在文案表上」不可以。

占位符约定：文案值里的 ``{name}`` 由消费方 ``str.format(**args)`` 填充，
与 ``core/copy/zh-CN.json`` 的 ``_meta.note`` 一致。
"""
from __future__ import annotations

import sys
from pathlib import Path

#: 仓库根：``core.config`` 是包模块，必须让仓库根在 ``sys.path`` 上。
_ROOT = Path(__file__).resolve().parents[1]


def load_table() -> dict:
    """读取最新文案表。

    Returns:
        dict: 解析后的 copy 表；文件缺失 / 损坏 / 顶层不是对象时返回空表。
            不抛异常 —— 调用方会回退成显示 key。
    """
    try:
        if str(_ROOT) not in sys.path:
            sys.path.insert(0, str(_ROOT))
        from core.config import load_copy

        table = load_copy() or {}
    except Exception:  # noqa: BLE001  文案表问题不许拖垮诊断
        return {}
    return table if isinstance(table, dict) else {}


def section(table: dict, path: str) -> dict:
    """按点号路径取子表（如 ``verdict.titles``）。

    Args:
        table: :func:`load_table` 返回的表。
        path: 点号分隔的 section 路径。

    Returns:
        dict: 命中的子表；任一层缺失或不是对象时返回空表。
    """
    node: object = table
    for part in path.split("."):
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})
    return node if isinstance(node, dict) else {}


def get(table: dict, path: str, key: str, default=None):
    """从给定表里取字符串文案（不格式化）。

    Args:
        table: 文案表。
        path: section 点号路径。
        key: section 内的键（键本身可以带点，如 ``L4.RETRANS.ADVICE``）。
        default: 缺失或不是字符串时的返回值。

    Returns:
        str | None: 命中返回字符串，否则返回 ``default``。
    """
    value = section(table, path).get(key)
    return value if isinstance(value, str) else default


def text(path: str, key: str, default: str = "", **args) -> str:
    """取文案并按 ``str.format(**args)`` 填充占位符。

    Args:
        path: section 点号路径（如 ``report`` / ``verdict.titles``）。
        key: section 内的键。
        default: 缺 key 时的回退值；为空时回退成 key 本身。
        **args: 占位符实参。

    Returns:
        str: 可直接展示的文案。缺 key / 缺实参都不抛异常。
    """
    raw = get(load_table(), path, key)
    if raw is None:
        return default or key
    if not args:
        return raw
    try:
        return raw.format(**args)
    except (KeyError, IndexError, ValueError):
        return raw


__all__ = ["load_table", "section", "get", "text"]
