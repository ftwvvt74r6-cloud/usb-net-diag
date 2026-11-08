"""启动器契约测试。

目的：AI 可以随便重写内部实现，但不能悄悄改掉「入口文件名 / 目录位置」——
一旦 start.bat 引用的文件被改名或搬走，双击启动就会失败，而这类问题
单纯看代码 review 很容易漏。

本测试只依赖标准库；唯一导入的项目模块 ``core.version`` 也是纯标准库实现，
不 import 需要 scapy / tshark 的模块。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.version import read_version  # noqa: E402

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
    def test_start_bat_python_fallback(self):
        self.assertTrue(START_BAT.is_file(), "start.bat 丢失，便携包入口没了")
        text = START_BAT.read_text(encoding="utf-8", errors="replace")
        markers = [
            "tools\\python\\python.exe",
            "where python",
            "where py",
            "https://www.python.org/downloads/windows/",
        ]
        positions = []
        for marker in markers:
            idx = text.find(marker)
            with self.subTest(marker=marker):
                self.assertGreaterEqual(idx, 0, f"start.bat 缺少 Python 回退契约：{marker}")
            positions.append(idx)
        self.assertEqual(positions, sorted(positions),
                         "start.bat 的 Python 回退顺序不是 包内 -> python -> py -3")
        self.assertIn('"%PY%" %PYARGS% "%ROOT%\\core\\bootstrap.py"', text,
                      "start.bat 调用 bootstrap.py 时没有带上回退运行时的参数")
        self.assertIn('"%PY%" %PYARGS% "%ROOT%\\core\\server.py"', text,
                      "start.bat 调用 server.py 时没有带上回退运行时的参数")

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

    # ------------------------------------------------ S1：缺 tshark 不阻塞
    def test_missing_tshark_block_warns_and_continues(self):
        """start.bat 是 lite 回退入口：缺 tshark 只提示，不 pause、不 exit。"""
        text = START_BAT.read_text(encoding="utf-8", errors="replace")
        self.assertIn("if errorlevel 3 goto :no_tshark", text,
                      "bootstrap 的缺 tshark 退出码必须仍被识别")
        begin = text.index(":no_tshark")
        end = text.index("\n:check_npcap", begin)
        block = text[begin:end]
        self.assertIn("未找到 tshark", block)
        self.assertIn("其余功能照常", block)
        self.assertIn("goto :check_npcap", block,
                      "提示后必须继续走 Npcap 检测与启动流程")
        self.assertNotRegex(block, r"(?im)^\s*pause\b", "缺 tshark 不许 pause")
        self.assertNotRegex(block, r"(?im)^\s*exit\s+/b\b", "缺 tshark 不许硬退出")
        # 旧的开发者硬路径提示已删除（S4 文案红线）。
        self.assertNotIn("请将 Wireshark 便携版解压到", block)
        self.assertNotIn("WiresharkPortable", block)

    @unittest.skipUnless(os.name == "nt" and shutil.which("python"),
                         "需要 Windows + 可用的 Python 才能真实执行 start.bat")
    def test_missing_tshark_rc_is_zero_in_temp_harness(self):
        """真跑一份临时 start.bat：bootstrap 返回 3 时仍继续启动并 rc=0。

        临时目录里放两个桩：``core/bootstrap.py``（--npcap 之外返回 3）与
        ``core/server.py``（立即返回 0）；PATH 指向当前 Python，保证能走到
        「缺包内运行时 → 系统 Python」这条真实回退路径。不碰仓库文件/网络。
        """
        with tempfile.TemporaryDirectory(prefix="netdiag-startbat-") as tmp:
            root = Path(tmp)
            shutil.copyfile(START_BAT, root / "start.bat")
            (root / "core").mkdir()
            (root / "core" / "bootstrap.py").write_text(
                "import sys\n"
                "raise SystemExit(0 if '--npcap' in sys.argv else 3)\n",
                encoding="utf-8", newline="\n")
            (root / "core" / "server.py").write_text(
                "raise SystemExit(0)\n", encoding="utf-8", newline="\n")
            env = dict(os.environ)
            env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
            proc = subprocess.run(
                ["cmd", "/c", "start.bat"], cwd=str(root), env=env,
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=60,
            )
        output = (proc.stdout or "") + (proc.stderr or "")
        self.assertEqual(proc.returncode, 0,
                         f"缺 tshark 不该让 start.bat 失败：{output[-1500:]}")
        self.assertIn("未找到 tshark", output)
        self.assertIn("其余功能照常", output)
        self.assertIn("服务已退出", output,
                      "start.bat 必须继续调用 core/server.py（进入主界面）")

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
        version = read_version()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$", f"VERSION 格式不对：{version!r}")

    def test_demo_sample_present(self):
        self.assertTrue(
            (ROOT / "captures" / "faults_demo.pcap").is_file(),
            "示例抓包缺失，README 首次试跑的引导会失效",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
