"""S4：``POST /api/quit`` 必须与其它 POST 走同一套请求防护（``_guard``）。

复审确认：``/api/quit`` 已挂在 ``_route_post`` 的 ``_guard()`` 之后（Host + Origin
同源校验），但此前没有针对这个「会真的停服务」的端点写显式回归。这里用真实
``DiagServer``（127.0.0.1 临时端口）+ mock ``request_quit`` 钉住：

* 本机同源请求 → 200 ``{ok: true}``，并且只安排一次关停；
* 外部 Origin → 403，**不**安排关停；
* 伪造 Host（DNS rebinding）→ 403，**不**安排关停；
* 被拒后服务仍健康（``/api/ping`` 200）。

绝不真停测试进程：``request_quit`` 全用例 mock。
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import logstore  # noqa: E402
import server  # noqa: E402

HOST = "127.0.0.1"


class QuitGuardTest(unittest.TestCase):
    """真实 HTTP 请求 + mock 关停：只验证请求防护与响应契约。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="netdiag_quit_guard_")
        cls._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: cls.tmp.name})
        cls._env.start()
        logstore.close_streams()
        cls.httpd = server.DiagServer((HOST, 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(
            target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        logstore.close_streams()
        cls._env.stop()
        cls.tmp.cleanup()

    def setUp(self) -> None:
        self._quit = mock.patch.object(server, "request_quit")
        self.request_quit = self._quit.start()

    def tearDown(self) -> None:
        self._quit.stop()

    # ---------- helpers ----------
    def _post_quit(self, headers: dict | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(HOST, self.port, timeout=5)
        try:
            conn.request("POST", "/api/quit", body=b"{}",
                         headers=headers or {})
            resp = conn.getresponse()
            payload = json.loads(resp.read().decode("utf-8", "replace"))
            return resp.status, payload
        finally:
            conn.close()

    def _check_alive(self) -> None:
        conn = http.client.HTTPConnection(HOST, self.port, timeout=5)
        try:
            conn.request("GET", "/api/ping")
            resp = conn.getresponse()
            status = resp.status
            body = json.loads(resp.read().decode("utf-8"))
        finally:
            conn.close()
        self.assertEqual(status, 200)
        self.assertTrue(body.get("ok"), body)

    # ---------- cases ----------
    def test_same_origin_quit_returns_200_and_requests_shutdown(self):
        status, body = self._post_quit({
            "Host": f"{HOST}:{self.port}",
            "Origin": f"http://{HOST}:{self.port}",
        })
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("ok"), body)
        self.assertIn("服务已停止", body.get("message", ""))
        self.request_quit.assert_called_once()
        reason = self.request_quit.call_args.args[0]
        self.assertIn("退出", reason)

    def test_localhost_origin_is_accepted(self):
        status, body = self._post_quit({
            "Host": f"localhost:{self.port}",
            "Origin": f"http://localhost:{self.port}",
        })
        self.assertEqual(status, 200, body)
        self.request_quit.assert_called_once()

    def test_cross_origin_quit_is_rejected_without_shutdown(self):
        status, body = self._post_quit({
            "Host": f"{HOST}:{self.port}",
            "Origin": "http://evil.example",
        })
        self.assertEqual(status, 403, body)
        self.assertFalse(body.get("ok"), body)
        self.assertIn("禁止外部页面", body.get("error", ""))
        self.request_quit.assert_not_called()
        self._check_alive()

    def test_dns_rebinding_host_is_rejected_without_shutdown(self):
        status, body = self._post_quit({"Host": "evil.example"})
        self.assertEqual(status, 403, body)
        self.assertFalse(body.get("ok"), body)
        self.request_quit.assert_not_called()
        self._check_alive()


if __name__ == "__main__":
    unittest.main(verbosity=2)
