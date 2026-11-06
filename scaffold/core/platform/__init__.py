"""平台适配层：只做「与操作系统打交道」的事，不含业务判断。"""

from . import paths, winapi  # noqa: F401  re-export

__all__ = ["paths", "winapi"]
