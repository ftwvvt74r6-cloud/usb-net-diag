"""出口包：所有「数据离开本机」的动作集中在这里。

约定：除本包以外，任何模块都不许直接调用 ``urllib`` / ``requests`` 发外网请求，
也不许直接把 ``AnalyzeResult`` 写进日志或交给 MCP。
"""

from . import ai, sanitize  # noqa: F401

__all__ = ["ai", "sanitize"]
