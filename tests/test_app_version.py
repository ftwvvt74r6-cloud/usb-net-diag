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

import analyzer  # noqa: E402
import diagpack  # noqa: E402
import logstore  # noqa: E402
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

    def test_read_version_strips_utf8_bom(self):
        """带 UTF-8 BOM 的 ``VERSION`` 必须读回 ``0.2.0``（L 轮 V6）。

        回归钉：``strip()`` 只去空白不去 BOM，否则读到的是「不可见 BOM + 0.2.0」，
        这个值会经 ``APP_VERSION`` 流进启动横幅 / ``/api/ping`` / ``/api/app`` 与报告。
        """
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "VERSION").write_text("\ufeff0.2.0\n", encoding="utf-8")
            version = server._read_version(Path(tmp))
            self.assertEqual(version, "0.2.0")
            self.assertNotIn("\ufeff", version, "读到的版本号里仍带 UTF-8 BOM")
            # BOM 与空白混排：BOM 在前、正文两边有空白，一样要剥干净
            (Path(tmp) / "VERSION").write_text("\ufeff 0.2.0 \n", encoding="utf-8")
            self.assertEqual(server._read_version(Path(tmp)), "0.2.0")
            # 只有 BOM 的「空」文件仍按空处理，回退 0.0.0
            (Path(tmp) / "VERSION").write_text("\ufeff", encoding="utf-8")
            self.assertEqual(server._read_version(Path(tmp)), "0.0.0")

    def test_all_consumers_read_bom_version(self):
        """判别性：4 个调用点读同一份带 BOM 的 ``VERSION``，都必须返回 ``0.2.0``。

        L 轮补丁把 ``server`` / ``analyzer`` / ``logstore`` / ``diagpack`` 四处
        各自裸读 ``VERSION`` 收敛到 :func:`core.version.read_version`。这里逐个
        调用真实消费点（不只测公共函数）：任何一处改回裸读都会让本用例变红。
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "VERSION").write_text("\ufeff0.2.0\n", encoding="utf-8")
            patched = (analyzer, logstore, diagpack)
            originals = {module: module.ROOT for module in patched}
            try:
                for module in patched:
                    module.ROOT = root
                observed = {
                    "server._read_version": server._read_version(root),
                    "analyzer._build_provenance": analyzer._build_provenance()["app_version"],
                    "logstore._env_info": logstore._env_info()["version"],
                    "diagpack._version": diagpack._version(),
                }
            finally:
                for module, original in originals.items():
                    module.ROOT = original
        self.assertEqual(
            observed, dict.fromkeys(observed, "0.2.0"),
            f"带 BOM 的 VERSION 在各消费点读出的版本号不一致：{observed!r}",
        )
        for site, value in observed.items():
            self.assertNotIn("\ufeff", value, f"{site} 读到的版本号仍带 UTF-8 BOM")

    def test_version_is_read_from_one_place_only(self):
        """回归钉：四个消费方只许调用公共读取函数，不许各自裸读 ``VERSION``。"""
        for rel in ("core/server.py", "core/analyzer.py",
                    "core/logstore.py", "core/diagpack.py"):
            source = (ROOT / rel).read_text(encoding="utf-8")
            self.assertIsNone(
                re.search(r'(?:ROOT|root)\s*/\s*"VERSION"', source),
                f"{rel} 仍在直接读 VERSION，应改用 core/version.py::read_version",
            )
            self.assertIn("read_version", source, f"{rel} 没有调用公共版本读取函数")
        impl = (ROOT / "core" / "version.py").read_text(encoding="utf-8")
        self.assertIn('(base / "VERSION")', impl, "公共读取函数不再读 VERSION 文件")


if __name__ == "__main__":
    unittest.main(verbosity=2)
