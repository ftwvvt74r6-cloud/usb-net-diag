"""``POST /api/elevate`` 的结构化返回与「失败不杀进程」契约。

C1 把「启动不提权」落到代码后，提权只剩界面按需触发这一条路：
``server.request_elevation()`` 调 ``app.relaunch_as_admin()``，然后返回
``{ok, restarted, error}``。这个文件用**真实 HTTP 路由** + mock 启动器来钉住：

* 成功 → ``{ok: true, restarted: true}`` 并安排旧服务退出；
* 用户取消（relaunch 返回 False）→ ``{ok: false, restarted: false, error}``，
  路由不抛、旧服务继续响应 ``/api/ping``；
* 启动器抛异常（策略禁止 / 无窗口站）→ 同样结构化失败，不把栈吐给浏览器；
* 已是管理员 → 不再请求 UAC（``relaunch`` 不被调用）。

**绝不真的起 UAC**：所有用例都把 ``app.relaunch_as_admin`` 换成 mock；
``setUp`` 里先装一个默认返回 False 的 mock，单个用例再改返回值。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import app  # noqa: E402
import logstore  # noqa: E402
import server  # noqa: E402


def _http(port: int, method: str, path: str, body: bytes | None = None,
          timeout: int = 15) -> tuple[int, str]:
    """发一个本机 HTTP 请求；HTTPError 也当响应返回（和 test_http_drain 同口径）。"""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


class ElevateRouteTest(unittest.TestCase):
    """起真实 DiagServer（端口 0），只 mock 提权本身。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="netdiag_elevate_")
        cls._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(Path(cls._tmp.name) / "logs")})
        cls._env.start()
        logstore.close_streams()
        cls.httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        logstore.close_streams()
        cls._env.stop()
        cls._tmp.cleanup()

    def setUp(self) -> None:
        # 先装「默认取消」的 mock：任何用例漏改返回值也绝不会碰真 UAC。
        self._relaunch = mock.patch.object(app, "relaunch_as_admin", return_value=False)
        self.relaunch = self._relaunch.start()
        self._admin = mock.patch.object(server.tshark, "is_admin", return_value=False)
        self.is_admin = self._admin.start()
        self._quit = mock.patch.object(server, "request_quit")
        self.request_quit = self._quit.start()
        self._timer = mock.patch.object(server.threading, "Timer")
        self.timer = self._timer.start()

    def tearDown(self) -> None:
        for patch in (self._relaunch, self._admin, self._quit, self._timer):
            patch.stop()

    def _post_elevate(self) -> dict:
        code, text = _http(self.port, "POST", "/api/elevate", b"")
        self.assertEqual(code, 200, f"/api/elevate 返回 HTTP {code}: {text[:300]}")
        return json.loads(text)

    def test_success_returns_structured_restarted(self):
        self.relaunch.return_value = True
        data = self._post_elevate()
        self.assertTrue(data["ok"], data)
        self.assertTrue(data["restarted"], data)
        self.assertNotIn("error", data)
        self.timer.assert_called_once()
        self.timer.return_value.start.assert_called_once()
        # 真正的 request_quit 由 Timer 在 0.8s 后调用；Timer 是 mock，所以这里没调。
        self.request_quit.assert_not_called()

    def test_cancelled_elevation_keeps_service_alive(self):
        self.relaunch.return_value = False
        data = self._post_elevate()
        self.assertFalse(data["ok"], data)
        self.assertFalse(data["restarted"], data)
        self.assertIn("未获得管理员权限", data["error"])
        self.timer.assert_not_called()
        self.request_quit.assert_not_called()

        # 失败后旧服务必须继续可用（进程没被退出、端口还在）。
        code, text = _http(self.port, "GET", "/api/ping")
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(text)["ok"])
        self.assertEqual(self.relaunch.call_count, 1,
                         "取消后不应自动重试提权")

    def test_relaunch_exception_becomes_structured_error(self):
        self.relaunch.side_effect = PermissionError("UAC denied by policy")
        data = self._post_elevate()
        self.assertFalse(data["ok"], data)
        self.assertFalse(data["restarted"], data)
        self.assertIn("提权请求失败", data["error"])
        self.assertIn("PermissionError", data["error"])
        self.timer.assert_not_called()
        # 异常没有把路由打挂：还能正常再请求一次 /api/ping。
        code, text = _http(self.port, "GET", "/api/ping")
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(text)["ok"])

    def test_already_admin_does_not_prompt_uac(self):
        self.is_admin.return_value = True
        data = self._post_elevate()
        self.assertTrue(data["ok"], data)
        self.assertFalse(data["restarted"], data)
        self.assertTrue(data.get("already_admin"), data)
        self.relaunch.assert_not_called()
        self.timer.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
