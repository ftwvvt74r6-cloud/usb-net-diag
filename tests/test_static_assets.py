"""``/app.css`` 与 ``/js/*.js`` 的静态资源路由契约。

P1 把内联 ``<style>`` 抽成 ``ui/app.css`` 之后，前端从「单文件」变成「HTML + 子资源」，
于是服务端必须真的能把子资源发出去 —— 否则浏览器拿到 404，页面直接白屏（样式全丢）。

这个文件钉四件事：

* 白名单内的路径返回 200，且 ``Content-Type`` 精确（``.js`` 必须是
  ``application/javascript``，**不能被 Windows 注册表猜成 ``text/plain``**，
  否则浏览器拒绝执行脚本）；
* 白名单外的一切返回 404（``ui/`` 不是整目录静态服务）；
* 路径穿越（``/../`` / ``%2e%2e`` / ``js/../index.html`` / 反斜杠 / NUL）一律 404；
* 路由位置在 ``/api/*`` 之后 —— 静态资源不许抢 API 的路径。

测试把 ``server.UI_DIR`` 指到临时目录，避免往仓库里塞测试用的假 JS 文件。
"""
from __future__ import annotations

import http.client
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "tests"))

import _uisrc  # noqa: E402
import logstore  # noqa: E402
import server  # noqa: E402

CSS_BODY = "/* test stylesheet */\n:root{--fs-base:13px}\n".encode("utf-8")
JS_BODY = "// test script\nwindow.__probe = 1;\n".encode("utf-8")


class StaticAssetRouteTest(unittest.TestCase):
    """起真实 DiagServer（端口 0），把 UI_DIR 换成临时目录。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="netdiag_static_")
        ui = Path(cls._tmp.name) / "ui"
        (ui / "js").mkdir(parents=True)
        (ui / "app.css").write_bytes(CSS_BODY)
        (ui / "js" / "api.js").write_bytes(JS_BODY)
        (ui / "index.html").write_bytes(b"<!doctype html><title>stub</title>")
        # 白名单外的诱饵：命中即说明静态路由开得太宽
        (ui / "notes.txt").write_bytes(b"secret")
        (ui / "js" / "notes.txt").write_bytes(b"secret")
        (Path(cls._tmp.name) / "outside.txt").write_bytes(b"outside")
        cls.ui = ui

        cls._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(Path(cls._tmp.name) / "logs")})
        cls._env.start()
        logstore.close_streams()
        cls._ui_patch = mock.patch.object(server, "UI_DIR", ui)
        cls._ui_patch.start()
        cls.httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._ui_patch.stop()
        logstore.close_streams()
        cls._env.stop()
        cls._tmp.cleanup()

    # ------------------------------------------------ 工具
    def _get(self, path: str):
        """用 http.client 原样发路径 —— urllib 会规范化 ``..``，测不到真穿越。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, (resp.getheader("Content-Type") or ""), resp.read()
        finally:
            conn.close()

    # ------------------------------------------------ 200 + MIME
    def test_app_css_is_served_with_css_mime(self):
        status, ctype, body = self._get("/app.css")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "text/css; charset=utf-8")
        self.assertEqual(body, CSS_BODY)

    def test_js_is_served_with_javascript_mime(self):
        status, ctype, body = self._get("/js/api.js")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "application/javascript; charset=utf-8",
                         "必须显式给 application/javascript：text/plain 会被浏览器拒执行")
        self.assertEqual(body, JS_BODY)

    def test_v1_index_still_served_from_ui_dir(self):
        """?ui=v1 时 / 仍由入口路由返回 ui/index.html（静态路由不劫持入口页）。"""
        status, ctype, body = self._get("/?ui=v1")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "text/html; charset=utf-8")
        self.assertIn(b"stub", body)

    def test_static_responses_are_not_cached(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", "/app.css")
            resp = conn.getresponse()
            self.assertEqual(resp.getheader("Cache-Control"), "no-store")
            resp.read()
        finally:
            conn.close()

    # ------------------------------------------------ 404：穿越
    def test_path_traversal_is_404(self):
        for path in ("/../core/server.py",
                     "/%2e%2e/core/server.py",
                     "/js/../index.html",
                     "/js/%2e%2e/app.css",
                     "/..%5ccore%5cserver.py",
                     "/app.css%00.png"):
            with self.subTest(path=path):
                status, _, body = self._get(path)
                self.assertEqual(status, 404, f"{path} 不应被服务：{body[:80]!r}")

    # ------------------------------------------------ 404：白名单外
    def test_paths_outside_whitelist_are_404(self):
        for path in ("/notes.txt", "/js/notes.txt", "/js/", "/app.css/extra",
                     "/outside.txt", "/js/api.js.bak", "/js/api"):
            with self.subTest(path=path):
                status, _, _ = self._get(path)
                self.assertEqual(status, 404, f"{path} 在白名单外，必须 404")

    # ------------------------------------------------ 解析函数本身
    def test_static_asset_helper_rejects_unsafe_input(self):
        for path in ("/../x", "/%2e%2e/x", "/js/../x", "/js/a\\b.js", "",
                     "/a\x00b", "js/api.js", "/js/"):
            with self.subTest(path=path):
                self.assertIsNone(server.static_asset(path))

    def test_static_asset_helper_accepts_whitelist(self):
        self.assertEqual(server.static_asset("/app.css"),
                         (self.ui / "app.css").resolve())
        self.assertEqual(server.static_asset("/js/api.js"),
                         (self.ui / "js" / "api.js").resolve())

    def test_static_asset_helper_returns_none_for_missing_file(self):
        self.assertIsNone(server.static_asset("/js/not_here.js"))

    def test_does_not_depend_on_mimetypes_guess(self):
        """MIME 必须来自显式表：Windows 注册表会把 .js 猜成 text/plain。"""
        import inspect
        helper = inspect.getsource(server.static_asset)
        self.assertNotIn("mimetypes", helper,
                         "静态路由不许走 mimetypes 猜测（Windows 上 .js 会被猜成 text/plain）")
        self.assertEqual(server.STATIC_MIME[".js"], "application/javascript; charset=utf-8")
        self.assertEqual(server.STATIC_MIME[".css"], "text/css; charset=utf-8")


class UiSplitContract(unittest.TestCase):
    """样式搬出去之后，HTML 侧必须真的引用它（否则拆分等于丢样式）。"""

    def test_index_links_app_css_and_has_no_inline_style_block(self):
        html = _uisrc.html()
        css = _uisrc.css()
        self.assertIn('<link rel="stylesheet" href="/app.css"', html)
        self.assertNotIn("<style>", html, "样式必须只在 app.css 里，避免两份真源")
        self.assertGreater(len(css.splitlines()), 400, "app.css 像是没搬全")

    def test_app_css_keeps_the_design_tokens(self):
        css = _uisrc.css()
        for token in ("--accent:#2563eb", "--muted:", "--mono:", "--r:12px"):
            with self.subTest(token=token):
                self.assertIn(token, css)


if __name__ == "__main__":
    unittest.main(verbosity=2)
