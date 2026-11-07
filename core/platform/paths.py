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
    """向上找到项目根目录（靠在标记文件，不靠固定的 ``parents[N]``）。

    标记：同时存在 ``VERSION`` 与 ``start.bat``；或存在 ``config/`` + ``core/``。

    Args:
        start: 从哪里开始找；省略时以本文件位置为起点。

    Returns:
        Path: 解析后的绝对路径。优先级：环境变量 ``USB_NET_DIAG_ROOT`` >
            向上找标记 > 兜底「上两级父目录」（保证返回一个可用路径，不抛异常）。
    """
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
        """源代码目录。

        Returns:
            Path: ``<root>/core``。
        """
        return self.root / "core"

    @property
    def config(self) -> Path:
        """配置文件目录（``app-config.json`` / ``ai-config.json``）。

        Returns:
            Path: ``<root>/config``。
        """
        return self.root / "config"

    @property
    def captures(self) -> Path:
        """抓包落盘目录，也是分析抓包文件唯一允许读取的位置。

        Returns:
            Path: ``<root>/captures``。
        """
        return self.root / "captures"

    @property
    def reports(self) -> Path:
        """报告输出目录（``.md`` / ``.json``）。

        Returns:
            Path: ``<root>/reports``。
        """
        return self.root / "reports"

    @property
    def logs(self) -> Path:
        """运行日志与 PID 文件目录。

        Returns:
            Path: ``<root>/logs``。
        """
        return self.root / "logs"

    @property
    def data(self) -> Path:
        """持久化数据目录（历史基线 ``history.db`` 等）。

        Returns:
            Path: ``<root>/data``。首次使用时才创建。
        """
        return self.root / "data"          # history.db 等（新增）

    @property
    def ui(self) -> Path:
        """前端资源目录（单文件 ``index.html``）。

        Returns:
            Path: ``<root>/ui``。
        """
        return self.root / "ui"

    @property
    def tools(self) -> Path:
        """便携工具链目录（Python / Wireshark / Npcap 安装包）。

        Returns:
            Path: ``<root>/tools``。
        """
        return self.root / "tools"

    @property
    def skills(self) -> Path:
        """配套 Skill 文档目录。

        Returns:
            Path: ``<root>/skills``。
        """
        return self.root / "skills"

    @property
    def mcp(self) -> Path:
        """MCP 服务端目录。

        Returns:
            Path: ``<root>/mcp``。
        """
        return self.root / "mcp"

    @property
    def tshark_exe(self) -> Path:
        """便携版 tshark 的预期路径。

        Returns:
            Path: ``<root>/tools/WiresharkPortable/App/Wireshark/tshark.exe``。
                **不保证存在** —— 需要实际可用时请用 ``tshark.find_tshark()``（它还会找系统安装）。
        """
        return self.tools / "WiresharkPortable" / "App" / "Wireshark" / "tshark.exe"

    @property
    def python_exe(self) -> Path:
        """便携版解释器路径。

        Returns:
            Path: ``<root>/tools/python/python.exe``。
        """
        return self.tools / "python" / "python.exe"

    def ensure(self, *which: str) -> tuple[Path, ...]:
        """按需创建目录（启动时调用，避免各模块自己 mkdir）。

        Args:
            *which: 属性名列表，如 ``"captures"`` / ``"reports"`` / ``"logs"``。
                传不存在的属性名会抛 ``AttributeError``。

        Returns:
            tuple[Path, ...]: 与入参一一对应的、已确保存在的目录路径。
        """
        out: list[Path] = []
        for name in which:
            p = getattr(self, name)
            p.mkdir(parents=True, exist_ok=True)
            out.append(p)
        return tuple(out)

    def writable(self, name: str = "reports") -> bool:
        """探测某目录是否真的能写。

        U 盘写保护、只读盘符、被安全软件锁定时，``mkdir`` 可能成功但写入失败 ——
        所以这里真写一个探针文件再删掉。

        Args:
            name: 属性名，默认 ``"reports"``。

        Returns:
            bool: True 表示可写。失败时不抛异常，只返回 False，
                由调用方提示「请检查写保护开关」。
        """
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
