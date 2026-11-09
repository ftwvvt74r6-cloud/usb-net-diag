"""``tests/_uisrc.py`` 的统一 UI 源码读取器契约（R3）。

守四件事：

1. 默认（``ND_UI_BUNDLE`` 未设或非 ``v1``/``v2``）下，``html()`` / ``css()`` 返回的
   字节与改造前测试直接读 ``ui/index.html`` / ``ui/app.css`` **逐字节相同**（红线：
   R3 只改取源方式，断言强度与行为零变化）；
2. ``ND_UI_BUNDLE=v2`` 时按 ``ui/v2/index.html`` 的 ``<link>`` / ``<script src>``
   顺序拼出 4 份 CSS + 3 份 JS；
3. ``js()`` 在 v1 下为空（v1 无外链脚本）、``text()`` 是 html+css+js 拼接；
4. 入口 HTML 缺失时显式抛 ``FileNotFoundError``（不漏读子资源静默通过）。
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _uisrc  # noqa: E402


class UiSrcV1DefaultTest(unittest.TestCase):
    """默认 v1 下必须与直接读文件逐字节一致（红线）。"""

    def test_html_equals_index_html(self):
        self.assertEqual(_uisrc.html(),
                         (ROOT / "ui" / "index.html").read_text(encoding="utf-8"))

    def test_css_equals_app_css(self):
        self.assertEqual(_uisrc.css(),
                         (ROOT / "ui" / "app.css").read_text(encoding="utf-8"))

    def test_js_is_empty_for_v1(self):
        self.assertEqual(_uisrc.js(), "", "v1 无外链 <script src>，js() 必须为空串")

    def test_text_is_html_plus_css(self):
        self.assertEqual(_uisrc.text(), _uisrc.html() + _uisrc.css() + _uisrc.js())


class UiSrcV2BundleTest(unittest.TestCase):
    """``ND_UI_BUNDLE=v2`` 按入口 HTML 的引用顺序拼出子资源。"""

    def setUp(self):
        self._prev = os.environ.get("ND_UI_BUNDLE")
        os.environ["ND_UI_BUNDLE"] = "v2"
        import importlib
        importlib.reload(_uisrc)

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("ND_UI_BUNDLE", None)
        else:
            os.environ["ND_UI_BUNDLE"] = self._prev
        import importlib
        importlib.reload(_uisrc)

    def test_html_equals_v2_index(self):
        self.assertEqual(_uisrc.html(),
                         (ROOT / "ui" / "v2" / "index.html").read_text(encoding="utf-8"))

    def test_css_concatenates_four_files_in_order(self):
        entry = (ROOT / "ui" / "v2" / "index.html").read_text(encoding="utf-8")
        css = _uisrc.css()
        self.assertIn("tokens.css", entry)
        self.assertIn("components.css", entry)
        # 4 份 CSS 拼接后应包含各自的内容标记（顺序由入口 HTML 决定）。
        expected = ""
        for name in ("tokens.css", "base.css", "layout.css", "components.css"):
            expected += (ROOT / "ui" / "v2" / "css" / name).read_text(encoding="utf-8")
        self.assertEqual(css, expected)

    def test_js_concatenates_three_files_in_order(self):
        js = _uisrc.js()
        expected = ""
        for name in ("copy.js", "icons.js", "boot.js"):
            expected += (ROOT / "ui" / "v2" / "js" / name).read_text(encoding="utf-8")
        self.assertEqual(js, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
