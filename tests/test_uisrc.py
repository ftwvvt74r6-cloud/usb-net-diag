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
import re
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

    @staticmethod
    def _declared(attr: str, ext: str):
        """从入口 HTML 里按文档顺序取出外链文件名（只保留指定扩展名）。"""
        entry = (ROOT / "ui" / "v2" / "index.html").read_text(encoding="utf-8")
        pat = rf'<link\b[^>]*\bhref="([^"]+)"' if attr == "href" else rf'<script\b[^>]*\bsrc="([^"]+)"'
        names = []
        for href in re.findall(pat, entry, re.IGNORECASE):
            name = href.rsplit("/", 1)[-1]
            if name.endswith(ext):
                names.append(name)
        return names

    def test_css_concatenates_declared_stylesheets_in_order(self):
        """CSS 拼接结果必须等于「入口 HTML 声明的顺序」逐份拼接。

        不写死文件数量：v2 增删样式时这一条不用改，只校验「顺序与内容」这一契约。
        """
        names = self._declared("href", ".css")
        self.assertGreaterEqual(len(names), 1, "入口 HTML 未声明任何样式表")
        expected = "".join((ROOT / "ui" / "v2" / "css" / n).read_text(encoding="utf-8") for n in names)
        self.assertEqual(_uisrc.css(), expected)

    def test_js_concatenates_declared_scripts_in_order(self):
        """JS 拼接结果必须等于「入口 HTML 声明的顺序」逐份拼接（同上，不写死数量）。"""
        names = self._declared("src", ".js")
        self.assertGreaterEqual(len(names), 1, "入口 HTML 未声明任何脚本")
        expected = "".join((ROOT / "ui" / "v2" / "js" / n).read_text(encoding="utf-8") for n in names)
        self.assertEqual(_uisrc.js(), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
