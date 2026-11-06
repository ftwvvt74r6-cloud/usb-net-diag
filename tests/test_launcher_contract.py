"""启动器契约测试。

目的：AI 可以随便重写内部实现，但不能悄悄改掉「入口文件名 / 目录位置」——
一旦 start.bat 引用的文件被改名或搬走，双击启动就会失败，而这类问题
单纯看代码 review 很容易漏。

本测试只依赖标准库，不 import 任何项目模块（避免需要 scapy / tshark）。
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START_BAT = ROOT / "start.bat"

# 便携运行环境不进仓库，跳过不校验
SKIP_PREFIX = ("tools", "harness")

REF_PATTERN = re.compile(r'%ROOT%\\([^"\s]+)')


def _source_refs() -> list[str]:
    """从 start.bat 里解析出所有 %ROOT%\\xxx 引用，只保留源码类路径。"""
    text = START_BAT.read_text(encoding="utf-8", errors="replace")
    refs: list[str] = []
    for match in REF_PATTERN.finditer(text):
        ref = match.group(1).rstrip('\\')
        if any(ch in ref for ch in "*?"):
            continue
        if ref.split("\\")[0].lower() in SKIP_PREFIX:
            continue
        refs.append(ref)
    return refs


class LauncherContract(unittest.TestCase):
    def test_start_bat_exists(self):
        self.assertTrue(START_BAT.is_file(), "start.bat 丢失，便携包入口没了")

    def test_launcher_referenced_files_exist(self):
        refs = _source_refs()
        self.assertGreaterEqual(
            len(refs), 2,
            "没能从 start.bat 解析出源码入口，启动脚本格式可能被整体改写了",
        )
        for ref in refs:
            target = ROOT.joinpath(*ref.split("\\"))
            with self.subTest(ref=ref):
                self.assertTrue(target.exists(), f"start.bat 引用了不存在的路径：{ref}")

    def test_core_entrypoints_present(self):
        for name in ("core/server.py", "core/bootstrap.py"):
            with self.subTest(name=name):
                self.assertTrue((ROOT / name).is_file(), f"核心入口缺失：{name}")

    def test_ui_present(self):
        ui = ROOT / "ui" / "index.html"
        self.assertTrue(ui.is_file(), "ui/index.html 缺失")
        self.assertGreater(ui.stat().st_size, 1024, "ui/index.html 像是空文件")

    def test_mcp_server_present(self):
        server = ROOT / "mcp" / "wireshark-mcp" / "server.py"
        self.assertTrue(server.is_file(), "MCP 服务器缺失")

    def test_all_python_compiles(self):
        """语法检查：比 compileall 更细，能指出具体文件。"""
        targets = sorted((ROOT / "core").glob("*.py")) + sorted((ROOT / "mcp").rglob("*.py"))
        self.assertTrue(targets, "没找到任何 Python 源码")
        for path in targets:
            with self.subTest(path=str(path.relative_to(ROOT))):
                compile(path.read_text(encoding="utf-8"), str(path), "exec")

    def test_version_file(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$", f"VERSION 格式不对：{version!r}")

    def test_demo_sample_present(self):
        self.assertTrue(
            (ROOT / "captures" / "faults_demo.pcap").is_file(),
            "示例抓包缺失，README 首次试跑的引导会失效",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
