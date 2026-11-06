"""规则包（渐进迁移中）。

当前只落地 ``legacy_map``（旧 rows[] → Finding 的迁移桥，T03）。
完整的规则框架（base / l2 / l3 / l4 / l7 / security）在 T05 落地，
届时本文件替换为 scaffold/core/rules/__init__.py 的内容。
"""

__all__ = ["legacy_map"]
