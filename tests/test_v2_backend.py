"""R1/R2 回归测试：``ui/v2/**`` 静态白名单 + UI 入口版本切换。

R1 —— 静态白名单扩展到 ``ui/v2/**``：

* 合法路径（``/v2/css/*.css`` / ``/v2/js/*.js`` / ``/v2/img/*.svg|png|ico``）返回
  200 且 MIME 精确；
* 非法路径一律 404：目录穿越（``/v2/../`` / ``%2e%2e`` / 反斜杠 / NUL）、
  非白名单扩展名（``/v2/index.html`` / ``/v2/secret.txt``）、v1 之外的未知段
  （``/v1/**``）；
* 段数只能是 2 或 3，3 段时第二段必须是 css / js / img。

R2 —— 入口开关与一键回滚：

* ``ui_entry`` 优先级：``?ui=`` > Cookie ``nd_ui`` > ``config/ui-version.json``
  ``.default`` > 内置 ``v2``；
* ``?ui=`` 命中时回写 ``Set-Cookie``（``_send`` 的 ``extra_headers``）；
* 路由覆盖 ``/`` / ``/index.html`` / ``/v2/`` / ``/v2/index.html``；
* ``scripts/ui_switch.py v1|v2`` 写 ``config/ui-version.json``（无需重启）。

测试把 ``server.UI_DIR`` 指到临时目录，避免往仓库塞假文件。
"""
from __future__ import annotations

import http.client
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import logstore  # noqa: E402
import server  # noqa: E402


# ---- R1 静态白名单 ----

class V2StaticAssetTest(unittest.TestCase):
    """真实 DiagServer（端口 0），UI_DIR 换成临时目录，塞 v2 假文件。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="netdiag_v2_")
        ui = Path(cls._tmp.name) / "ui"
        v2 = ui / "v2"
        for sub in ("css", "js", "img"):
            (v2 / sub).mkdir(parents=True)
        (v2 / "css" / "tokens.css").write_bytes(b"/* v2 tokens */\n")
        (v2 / "js" / "boot.js").write_bytes(b"// v2 boot\n")
        (v2 / "img" / "logo.svg").write_bytes(b"<svg></svg>")
        (v2 / "img" / "favicon.ico").write_bytes(b"\x00\x00\x01\x00")
        # v1 入口与诱饵
        (ui / "index.html").write_bytes(b"<!doctype html><title>v1 stub</title>")
        (v2 / "index.html").write_bytes(b"<!doctype html><title>v2 stub</title>")
        (v2 / "secret.txt").write_bytes(b"secret")
        (ui / "app.css").write_bytes(b"/* v1 app.css */\n")
        cls.ui = ui

        cls._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(Path(cls._tmp.name) / "logs")})
        cls._env.start()
        logstore.close_streams()
        cls._ui_patch = mock.patch.object(server, "UI_DIR", ui)
        cls._ui_patch.start()
        cls._cfg_patch = mock.patch.object(
            server, "UI_VERSION_CONFIG", Path(cls._tmp.name) / "ui-version.json")
        cls._cfg_patch.start()
        cls.httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._cfg_patch.stop()
        cls._ui_patch.stop()
        logstore.close_streams()
        cls._env.stop()
        cls._tmp.cleanup()

    def _get(self, path: str, headers: dict | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            return (resp.status, resp.getheader("Content-Type") or "",
                    resp.getheader("Set-Cookie") or "", resp.read())
        finally:
            conn.close()

    # ---- 200 + MIME
    def test_v2_css_served_with_css_mime(self):
        status, ctype, _, body = self._get("/v2/css/tokens.css")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "text/css; charset=utf-8")
        self.assertEqual(body, b"/* v2 tokens */\n")

    def test_v2_js_served_with_javascript_mime(self):
        status, ctype, _, body = self._get("/v2/js/boot.js")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "application/javascript; charset=utf-8")
        self.assertEqual(body, b"// v2 boot\n")

    def test_v2_svg_served_with_svg_mime(self):
        status, ctype, _, body = self._get("/v2/img/logo.svg")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "image/svg+xml")
        self.assertEqual(body, b"<svg></svg>")

    def test_v2_ico_served(self):
        status, ctype, _, _ = self._get("/v2/img/favicon.ico")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "image/x-icon")

    # ---- 404：穿越 + 编码
    def test_v2_path_traversal_is_404(self):
        for path in ("/v2/../app.css", "/v2/js/../../core/server.py",
                     "/v2/%2e%2e/app.css", "/v2/js/%2e%2e/%2e%2e/core/server.py",
                     "/v2/js/..%5c..%5ccore%5cserver.py", "/v2/css%00tokens.css"):
            with self.subTest(path=path):
                status, _, _, body = self._get(path)
                self.assertEqual(status, 404, f"{path} 不应被服务：{body[:80]!r}")

    # ---- 404：白名单外
    def test_v2_non_whitelist_extensions_are_404(self):
        # 注意 /v2/index.html 走入口路由（R2）→ 200，不在此列；它作为「静态子资源」
        # 的拒绝已由 test_static_asset_v2_rejects_unsafe 覆盖（纯函数返回 None）。
        for path in ("/v2/secret.txt", "/v2/css/tokens.css.bak",
                     "/v2/js/boot", "/v2/css/"):
            with self.subTest(path=path):
                status, _, _, _ = self._get(path)
                self.assertEqual(status, 404, f"{path} 白名单外，必须 404")

    def test_v1_prefix_is_404(self):
        for path in ("/v1/css/tokens.css", "/v1/index.html"):
            with self.subTest(path=path):
                status, _, _, _ = self._get(path)
                self.assertEqual(status, 404, f"{path} 不在白名单（只有 v2），必须 404")

    # ---- static_asset 纯函数
    def test_static_asset_v2_whitelist(self):
        self.assertEqual(server.static_asset("/v2/css/tokens.css"),
                         (self.ui / "v2" / "css" / "tokens.css").resolve())
        self.assertEqual(server.static_asset("/v2/js/boot.js"),
                         (self.ui / "v2" / "js" / "boot.js").resolve())

    def test_static_asset_v2_rejects_unsafe(self):
        for path in ("/v2/../app.css", "/v2/js/../../core/server.py",
                     "/v2/index.html", "/v2/secret.txt", "/v1/css/tokens.css",
                     "/v2/css/tokens.css.bak", "/v2/img", "/v2", "/v2/css/"):
            with self.subTest(path=path):
                self.assertIsNone(server.static_asset(path))


# ---- R2 入口开关 ----

class UiEntryTest(unittest.TestCase):
    """``ui_entry`` 纯函数优先级 + ``_parse_ui_cookie``。"""

    def _entry(self, query="", cookie=None):
        parsed = urllib.parse.urlparse(f"/?{query}")
        return server.ui_entry(parsed, cookie)

    def test_query_param_wins_over_cookie(self):
        self.assertEqual(self._entry("ui=v2", "v1"), "v2")
        self.assertEqual(self._entry("ui=v1", "v2"), "v1")

    def test_cookie_used_when_no_query(self):
        self.assertEqual(self._entry("", "v2"), "v2")
        self.assertEqual(self._entry("", "v1"), "v1")

    def test_config_default_used_when_no_query_no_cookie(self):
        cfg = server.UI_VERSION_CONFIG
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "ui-version.json"
            p.write_text('{"default": "v2"}', encoding="utf-8")
            with mock.patch.object(server, "UI_VERSION_CONFIG", p):
                self.assertEqual(self._entry("", None), "v2")

    def test_defaults_to_v2(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(server, "UI_VERSION_CONFIG",
                                   Path(tmp) / "nope.json"):
                self.assertEqual(self._entry("", None), "v2")
                self.assertEqual(self._entry("ui=bad", "v3"), "v2")

    def test_parse_ui_cookie(self):
        class _H:
            def __init__(self, c): self._c = c
            def get(self, k): return self._c
        self.assertEqual(server._parse_ui_cookie(_H("nd_ui=v2; a=1")), "v2")
        self.assertEqual(server._parse_ui_cookie(_H("")), None)
        self.assertEqual(server._parse_ui_cookie(_H("nd_ui=v3")), None)
        self.assertEqual(server._parse_ui_cookie(_H("other=x")), None)


class UiEntryRouteTest(unittest.TestCase):
    """入口路由：``?ui=v2`` 回 200 且带 Set-Cookie；带 Cookie 再访问仍 v2。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="netdiag_entry_")
        ui = Path(cls._tmp.name) / "ui"
        (ui / "v2").mkdir(parents=True)
        (ui / "index.html").write_bytes(b"V1_ENTRY")
        (ui / "v2" / "index.html").write_bytes(b"V2_ENTRY")
        cls.ui = ui
        cls._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(Path(cls._tmp.name) / "logs")})
        cls._env.start()
        logstore.close_streams()
        cls._ui_patch = mock.patch.object(server, "UI_DIR", ui)
        cls._ui_patch.start()
        cls._cfg_patch = mock.patch.object(
            server, "UI_VERSION_CONFIG", Path(cls._tmp.name) / "ui-version.json")
        cls._cfg_patch.start()
        cls.httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._cfg_patch.stop()
        cls._ui_patch.stop()
        logstore.close_streams()
        cls._env.stop()
        cls._tmp.cleanup()

    def _get(self, path: str, headers: dict | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            return (resp.status, resp.getheader("Content-Type") or "",
                    resp.getheader("Set-Cookie") or "", resp.read())
        finally:
            conn.close()

    def test_default_root_is_v2(self):
        status, ctype, _, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "text/html; charset=utf-8")
        self.assertEqual(body, b"V2_ENTRY")

    def test_query_ui_v2_returns_v2_and_sets_cookie(self):
        status, ctype, set_cookie, body = self._get("/?ui=v2")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"V2_ENTRY")
        self.assertIn("nd_ui=v2", set_cookie)

    def test_cookie_keeps_v2_without_query(self):
        status, _, _, body = self._get("/", headers={"Cookie": "nd_ui=v2"})
        self.assertEqual(status, 200)
        self.assertEqual(body, b"V2_ENTRY")

    def test_v2_index_route_serves_entry(self):
        status, _, _, body = self._get("/v2/index.html")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"V2_ENTRY")  # 无 query/cookie 时仍回 v1

    def test_missing_entry_returns_500_not_fallback(self):
        # 把 v2 入口文件临时挪走，用 ?ui=v2 时应 500 且写明缺哪个文件，不回退 v1；
        # 结束后还原，避免影响同类的后续用例（setUpClass 共享同一份 fixture）。
        v2_index = self.ui / "v2" / "index.html"
        v2_index.rename(self.ui / "v2" / "index.html.bak")
        try:
            status, ctype, _, body = self._get("/?ui=v2")
            self.assertEqual(status, 500)
            self.assertIn(b"v2/index.html", body)
        finally:
            (self.ui / "v2" / "index.html.bak").rename(v2_index)


if __name__ == "__main__":
    unittest.main(verbosity=2)
