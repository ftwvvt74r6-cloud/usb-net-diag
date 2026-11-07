"""``core/server.py`` 的产品版本号必须来自仓库根 ``VERSION``。

背景（J 轮复审阻塞 B1）：``APP_VERSION`` 曾写死 ``"1.2"``，而 ``VERSION`` 是
``0.2.0`` —— 启动横幅、``/api/ping``、``/api/app`` 会与报告、CHANGELOG 自相矛盾。
这里把「读文件」这个行为钉住：既比对文件内容，也确认它读的是**文件里的值**，
而不是某个恰好等于当前版本的写死字面量。
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import server  # noqa: E402


class AppVersionTest(unittest.TestCase):
    """``server.APP_VERSION`` 与 ``VERSION`` 文件的一致性。"""

    def test_app_version_matches_version_file(self):
        expected = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(
            server.APP_VERSION, expected,
            f"server.APP_VERSION={server.APP_VERSION!r} 与 VERSION={expected!r} 不一致",
        )
        self.assertRegex(server.APP_VERSION, r"^\d+\.\d+\.\d+$")

    def test_app_version_is_not_a_hardcoded_literal(self):
        """回归钉：``APP_VERSION`` 不许再写死字面量（含当前值的字面量）。"""
        source = (ROOT / "core" / "server.py").read_text(encoding="utf-8")
        self.assertIsNone(
            re.search(r"(?m)^APP_VERSION\s*=\s*[\"']", source),
            "APP_VERSION 必须由 VERSION 文件推导，不能写死字面量",
        )
        self.assertIn("APP_VERSION = _read_version()", source)

    def test_read_version_reads_the_file(self):
        """判别性：换一份 VERSION 文件，读到的就必须是文件内容。"""
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "VERSION").write_text("9.9.9\n", encoding="utf-8")
            self.assertEqual(server._read_version(Path(tmp)), "9.9.9")

    def test_read_version_fallback(self):
        """文件缺失或为空时回退 ``0.0.0``，不能抛异常空转。"""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(server._read_version(Path(tmp)), "0.0.0")
            (Path(tmp) / "VERSION").write_text("  \n", encoding="utf-8")
            self.assertEqual(server._read_version(Path(tmp)), "0.0.0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
