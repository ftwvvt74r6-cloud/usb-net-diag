"""文案表访问器：``core/copy/zh-CN.json`` 的唯一读取入口（带进程内缓存）。

设计约束（为什么要有这一层）：

1. **单一来源**：报告 / 判定 / 建议 / AI prompt 的中文全部从这里取，代码里只留 key。
   改文案只改 JSON，不该出现「代码里还有一份、copy 表是假话」。
2. **缓存 + 显式失效**：文案表 35KB，逐条文案都重读重解析会让大 pcap 的会话标记
   渲染退化（审查实测 10,000 条流 232 倍）。所以按「(文件 mtime_ns, size)」缓存：
   改 JSON 文件后下一次读自动失效。
   ⚠️ 但 **monkeypatch ``core.config.load_copy`` 不会改变文件 mtime**，缓存不会失效 ——
   凡是用 patch 注入自定义表的用例，必须在 patch 前后调用 :func:`reload()` 清缓存，
   否则会静默读到真表而假绿。
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

#: 文案表文件路径（缓存失效只看它）。
_COPY_PATH = _ROOT / "core" / "copy" / "zh-CN.json"

#: 缓存哨兵：``reload()`` 后置为该值，保证下一次一定重读。
_UNSET = object()

#: 进程内缓存：``{"key": (mtime_ns, size) | ("missing",) | _UNSET, "table": dict}``。
#: 只缓存最后一次读到的表；改文件或调用 :func:`reload` 即失效。
_CACHE: dict = {"key": _UNSET, "table": {}}


def _file_key():
    """文件缓存键：``(mtime_ns, size)``；文件不存在时返回 ``("missing",)``。"""
    try:
        st = _COPY_PATH.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return ("missing",)


def _read_table() -> dict:
    """真正读盘并解析（走 ``core.config.load_copy``，保留 patch 兼容性）。"""
    try:
        if str(_ROOT) not in sys.path:
            sys.path.insert(0, str(_ROOT))
        from core.config import load_copy

        table = load_copy() or {}
    except Exception:  # noqa: BLE001  文案表问题不许拖垮诊断
        return {}
    return table if isinstance(table, dict) else {}


def reload() -> None:
    """清空文案表缓存。

    正常运行时不需要调用（文件变化会按 mtime/size 自动失效）。
    只有「测试 monkeypatch 了 ``core.config.load_copy``」这种**文件没变、来源变了**
    的场景必须显式调用，否则会读到缓存里的真实表。
    """
    _CACHE["key"] = _UNSET
    _CACHE["table"] = {}


def load_table() -> dict:
    """读取文案表（按文件 mtime/size 缓存，重复调用 O(1)）。

    Returns:
        dict: 解析后的 copy 表；文件缺失 / 损坏 / 顶层不是对象时返回空表。
            不抛异常 —— 调用方会回退成显示 key。
    """
    key = _file_key()
    if _CACHE["key"] == key:
        return _CACHE["table"]
    table = _read_table()
    _CACHE["key"] = key
    _CACHE["table"] = table
    return table


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


def text(path: str, key: str, default: str = "", table: dict | None = None,
         **args) -> str:
    """取文案并按 ``str.format(**args)`` 填充占位符。

    Args:
        path: section 点号路径（如 ``report`` / ``verdict.titles``）。
        key: section 内的键。
        default: 缺 key 时的回退值；为空时回退成 key 本身。
        table: 可选的已加载表。热循环（如 ``_stream_rows`` 的会话标记）传它可以把
            「读表」摊销到一次；不传时走 :func:`load_table`（有缓存，O(1)）。
        **args: 占位符实参。

    Returns:
        str: 可直接展示的文案。缺 key / 缺实参都不抛异常。
    """
    raw = get(load_table() if table is None else table, path, key)
    if raw is None:
        return default or key
    if not args:
        return raw
    try:
        return raw.format(**args)
    except (KeyError, IndexError, ValueError):
        return raw


__all__ = ["load_table", "reload", "section", "get", "text"]
