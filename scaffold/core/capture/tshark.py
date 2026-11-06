"""tshark 适配器 —— **唯一**允许拼 tshark 命令行的地方。

迁移原则：不重写、只搬家。现有 ``core/tshark.py`` 已经处理了这些踩坑经验：

* 候选目录（便携 Wireshark / 系统 Wireshark / ``TSHARK_PATH`` 环境变量 / PATH）；
* ``WIRESHARK_CONFIG_DIR`` 指回 U 盘，避免污染目标机器；
* ``CREATE_NO_WINDOW``，不弹黑框；
* 超时、``FileNotFoundError``、``OSError`` 一律转成返回值而不是异常。

本文件把 ``find()`` / ``run()`` / ``version()`` 实现出来（够用且可测），
``interfaces()`` / ``iter_fields()`` 留占位，由 ``core/tshark.py`` 平移。
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

from ..platform.paths import PATHS

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def _candidate_dirs() -> list[Path]:
    return [
        PATHS.tshark_exe.parent,                                   # 便携版（首选）
        PATHS.tools / "Wireshark",                                 # 另一种便携布局
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark",
    ]


def find_tshark() -> Path | None:
    """定位 tshark。顺序：``TSHARK_PATH`` 环境变量 → 候选目录 → PATH。

    ``TSHARK_PATH`` 优先级最高：MCP 配置里就是靠它指到便携 tshark
    （见 ``config/mcp-wireshark.json``）。
    """
    env = os.environ.get("TSHARK_PATH")
    if env and Path(env).is_file():
        return Path(env)
    names = ("tshark.exe", "tshark") if os.name == "nt" else ("tshark",)
    for directory in _candidate_dirs():
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    hit = shutil.which("tshark")
    return Path(hit) if hit else None


def env_for_tshark() -> dict:
    """让 Wireshark 的个人配置写回 U 盘（不污染目标机器）。"""
    env = os.environ.copy()
    data = PATHS.tools / "WiresharkPortable" / "Data" / "settings"
    try:
        if (PATHS.tools / "WiresharkPortable").is_dir():
            data.mkdir(parents=True, exist_ok=True)
            env.setdefault("WIRESHARK_CONFIG_DIR", str(data))
    except OSError:
        pass
    return env


@dataclass(frozen=True)
class TsharkAdapter:
    """一个 tshark 实例。做成对象而不是模块函数，便于测试时注入假实现。"""

    exe: Path | None = None
    timeout_s: int = 180

    @property
    def available(self) -> bool:
        return self.exe is not None and Path(self.exe).is_file()

    @classmethod
    def discover(cls, timeout_s: int = 180) -> "TsharkAdapter":
        return cls(exe=find_tshark(), timeout_s=timeout_s)

    # ---------------------------------------------------------------- 执行

    def run(self, args: Sequence[str], timeout: int | None = None) -> tuple[int, str, str]:
        """执行子进程，返回 ``(rc, stdout, stderr)``。**不抛异常**。"""
        if not self.available:
            return -2, "", "未找到 tshark"
        cmd = [str(self.exe), *args]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout or self.timeout_s, creationflags=CREATE_NO_WINDOW,
                env=env_for_tshark(),
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            return -9, "", f"命令超时（{timeout or self.timeout_s}s）"
        except FileNotFoundError:
            return -2, "", f"找不到可执行文件：{cmd[0]}"
        except OSError as exc:
            return -3, "", f"执行失败：{exc}"

    def version(self) -> str:
        rc, out, err = self.run(["-v"], timeout=30)
        for line in (out or err).splitlines():
            if line.strip():
                return line.strip()
        return f"tshark 版本未知 (rc={rc})"

    # ---------------------------------------------------------------- 占位

    def interfaces(self) -> list[dict]:
        """解析 ``tshark -D``，返回 ``[{"index":1,"name":"..."}]``。

        TODO(迁移)：平移 ``core/tshark.py:list_interfaces()``。
        注意部分环境下 ``-D`` 把列表输出到 stderr，两路都要看。
        """
        raise NotImplementedError("TsharkAdapter.interfaces(): 平移 core/tshark.py:list_interfaces")

    def iter_fields(self, pcap: str | Path, fields: Sequence[str]) -> Iterator[str]:
        """流式读取 ``-T fields`` 输出，逐行 yield。

        TODO(迁移)：平移 ``core/tshark.py:iter_lines()``。要点：
        ``bufsize`` 调大、读到 EOF 后 ``proc.wait()``、把 rc/stderr 写回 sink，
        超时用 ``threading.Timer(proc.kill)`` 而不是阻塞等待。
        """
        raise NotImplementedError("TsharkAdapter.iter_fields(): 平移 core/tshark.py:iter_lines")


__all__ = ["CREATE_NO_WINDOW", "find_tshark", "env_for_tshark", "TsharkAdapter"]
