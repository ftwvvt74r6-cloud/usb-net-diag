"""目录约定与根目录探测。

**关键设计**：不靠固定的 ``parents[N]``，而是靠「标记文件」向上找根。

原因：现有代码 ``core/analyzer.py`` 用 ``parents[1]``，一旦把 ``core/`` 变成
真正的包（``core/__init__.py`` + 子包），或者文件搬深一层，所有相对路径都会错，
而且是静默错到 ``C:\\`` 上去。这是「重构 = 全盘崩」的根源之一。

标记：同时存在 ``VERSION`` 与 ``start.bat``；或存在 ``config/`` + ``core/``。
优先级：环境变量 ``USB_NET_DIAG_ROOT`` > 向上找标记 > 当前工作目录。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_MARKERS = ("VERSION", "start.bat")


def _looks_like_root(path: Path) -> bool:
    if all((path / m).is_file() for m in _MARKERS):
        return True
    if (path / "config").is_dir() and (path / "core").is_dir():
        return True
    # 「自己就是一个包根」：core/copy 存在。这样 scaffold/core/... 与
    # 迁移后的 core/... 都能各就各位，不需要改代码。
    return (path / "core" / "copy").is_dir()


def find_root(start: Path | None = None) -> Path:
    """向上找到项目根；找不到就退回 ``start`` 的两级父目录（保持可用）。"""
    env = os.environ.get("USB_NET_DIAG_ROOT")
    if env:
        p = Path(env)
        if p.is_dir():
            return p.resolve()

    here = (start or Path(__file__)).resolve()
    for candidate in [here, *here.parents]:
        if _looks_like_root(candidate):
            return candidate
    return here.parents[1] if len(here.parents) > 1 else here.parent


ROOT = find_root()


@dataclass(frozen=True)
class Paths:
    """仓库内所有约定目录。任何模块都不许自己拼 ``Path(__file__).parent...``。"""

    root: Path = ROOT

    @property
    def core(self) -> Path:
        return self.root / "core"

    @property
    def config(self) -> Path:
        return self.root / "config"

    @property
    def captures(self) -> Path:
        return self.root / "captures"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def data(self) -> Path:
        return self.root / "data"          # history.db 等（新增）

    @property
    def ui(self) -> Path:
        return self.root / "ui"

    @property
    def tools(self) -> Path:
        return self.root / "tools"

    @property
    def skills(self) -> Path:
        return self.root / "skills"

    @property
    def mcp(self) -> Path:
        return self.root / "mcp"

    @property
    def tshark_exe(self) -> Path:
        return self.tools / "WiresharkPortable" / "App" / "Wireshark" / "tshark.exe"

    @property
    def python_exe(self) -> Path:
        return self.tools / "python" / "python.exe"

    def ensure(self, *which: str) -> tuple[Path, ...]:
        """按需创建目录；返回创建后的路径元组。"""
        out: list[Path] = []
        for name in which:
            p = getattr(self, name)
            p.mkdir(parents=True, exist_ok=True)
            out.append(p)
        return tuple(out)

    def writable(self, name: str = "reports") -> bool:
        """启动时探测（U 盘写保护 / 只读盘符会静默失败）。"""
        p = getattr(self, name)
        try:
            p.mkdir(parents=True, exist_ok=True)
            probe = p / f"._probe_{os.getpid()}"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return True
        except OSError:
            return False


PATHS = Paths()

__all__ = ["ROOT", "Paths", "PATHS", "find_root"]
