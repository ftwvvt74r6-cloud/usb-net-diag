"""渲染层：契约 → 人可读的 Markdown / JSON。

约束：本层**只做排版**，不许做判断，不许访问网络，不许写文件（``save`` 除外）。
"""

from .json_report import dumps, save, to_document
from .markdown import render
from .text import CopyTable, fmt, lookup

__all__ = ["dumps", "save", "to_document", "render", "CopyTable", "fmt", "lookup"]
