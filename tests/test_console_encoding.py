"""cp936 控制台打印兜底回归测试（B1）。

Windows 中文控制台默认 cp936，而报告里的 ``❌`` / ``✅`` 不在 GBK 字符集里。
入口 :func:`diagnose.main` 必须先调用 :func:`diagnose._harden_console` 把
stdout/stderr 的 ``errors`` 改成 ``backslashreplace``；否则打印报告会抛
``UnicodeEncodeError``，把一次已经成功、报告也已落盘的诊断变成 exit 1。

这里用**子进程 + ``PYTHONIOENCODING=cp936``** 复现真实控制台：子进程 stdout 是
管道，编码被强制成 cp936、errors 保持 strict，与 Windows 中文控制台默认行为一致。
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIAGNOSE = ROOT / "core" / "diagnose.py"
SAMPLE = ROOT / "captures" / "faults_demo.pcap"
sys.path.insert(0, str(ROOT / "core"))

from tshark import find_tshark  # noqa: E402

NO_TSHARK = find_tshark() is None


@unittest.skipIf(NO_TSHARK, "没有 tshark，跳过 cp936 控制台实测")
class Cp936ConsoleTest(unittest.TestCase):
    """cp936 编码下跑真实 CLI：能打印完整报告、exit 0、中文不乱码。"""

    def test_cp936_console_prints_report_without_crash(self):
        """``PYTHONIOENCODING=cp936`` 跑离线诊断：exit 0，``❌`` 转义不崩。"""
        self.assertTrue(SAMPLE.is_file(), f"缺少示例抓包：{SAMPLE}")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report-out"
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = "cp936"  # 模拟中文 Windows 默认控制台
            env["NETDIAG_LOG_DIR"] = str(Path(tmp) / "logs")
            proc = subprocess.run(
                [sys.executable, str(DIAGNOSE), "--pcap", str(SAMPLE),
                 "--report-out", str(out)],
                capture_output=True, env=env, timeout=180,
            )
            stderr = proc.stderr.decode("cp936", errors="backslashreplace")
            self.assertEqual(proc.returncode, 0,
                             f"cp936 控制台下打印报告崩了（exit {proc.returncode}）：\n{stderr}")
            # 严格解码：中文必须仍是合法 cp936（证明只改 errors、没改编码）。
            stdout = proc.stdout.decode("cp936")
            self.assertIn("报告已生成", stdout)
            self.assertIn("\\u274c", stdout)  # ❌ 被 backslashreplace 成可见转义
            self.assertNotIn("Traceback", stderr)
            self.assertTrue((out / f"{SAMPLE.stem}.md").is_file(), "Markdown 没落盘")
            self.assertTrue((out / f"{SAMPLE.stem}.json").is_file(), "JSON 没落盘")


if __name__ == "__main__":
    unittest.main(verbosity=2)
