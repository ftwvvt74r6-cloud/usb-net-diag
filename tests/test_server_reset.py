"""G4：浏览器提前断开（连接重置/中止/断管）不许打印 traceback。

真起一个本地 ``DiagServer``（127.0.0.1 + 临时端口），用 ``SO_LINGER(1, 0)`` 的
TCP RST 制造两种半开场景：

1. 请求还没发完就 RST；
2. 请求发完、还没读响应就 RST。

两种场景都必须：stderr 没有 ``Traceback``；磁盘日志只有一行 debug（不显示给用户）；
server 仍健康（后续 ``/api/ping`` 返回 200）。依赖真实 socket，但只连本机临时端口，
不需要管理员 / tshark / 外网。
"""
from __future__ import annotations

import contextlib
import io
import json
import socket
import struct
import sys
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import server  # noqa: E402

HOST = "127.0.0.1"


def _rst_close(port: int, payload: bytes) -> None:
    """发一段请求后立刻 RST 关闭（SO_LINGER timeout=0）。"""
    sock = socket.create_connection((HOST, port), timeout=5)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
        sock.sendall(payload)
    finally:
        sock.close()


def _get(port: int, path: str = "/api/ping") -> tuple[int, bytes]:
    with urllib.request.urlopen(f"http://{HOST}:{port}{path}", timeout=5) as resp:
        return resp.status, resp.read()


class ConnectionResetNoiseTest(unittest.TestCase):
    """两个半开场景 + 后续健康检查；断言 stderr 无 traceback。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = server.DiagServer((HOST, 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _scenario(self, payload: bytes) -> str:
        """制造一次 RST，返回 server 的 stderr（供断言无 Traceback）。"""
        stderr = io.StringIO()
        logs: list[str] = []
        with contextlib.redirect_stderr(stderr), \
                mock.patch.object(server.logstore, "diag_log",
                                  side_effect=lambda line: logs.append(str(line))):
            _rst_close(self.port, payload)
            time.sleep(0.5)
            # 连接噪音处理后 server 必须还能正常服务。
            status, body = _get(self.port)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body.decode("utf-8")).get("ok"))
        text = stderr.getvalue()
        self.assertNotIn("Traceback", text,
                         f"连接重置不许打印 traceback，实际 stderr：{text[-800:]}")
        self.assertNotIn("ConnectionResetError", text)
        self.assertNotIn("BrokenPipeError", text)
        for line in logs:
            self.assertNotIn("\n", line.strip("\n"),
                             "连接噪音只允许一行 debug，不许把栈写进日志")
        return text

    def test_reset_before_request_finished(self):
        """场景 1：请求行/头还没读完就 RST。"""
        self._scenario(b"GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1\r\n")

    def test_reset_after_request_before_read_response(self):
        """场景 2：请求已发完、客户端不读响应就 RST。"""
        self._scenario(b"GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")

    def test_connection_noise_is_logged_as_one_debug_line(self):
        """至少有一个场景确实走到我们的捕获分支（而不是碰巧没异常）。"""
        logs: list[str] = []
        with mock.patch.object(server.logstore, "diag_log",
                               side_effect=lambda line: logs.append(str(line))):
            _rst_close(self.port, b"GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1\r\n")
            time.sleep(0.5)
        noisy = [line for line in logs if "客户端提前断开" in line]
        self.assertTrue(noisy, f"没有捕获到连接重置日志：{logs}")
        self.assertTrue(any("[debug]" in line for line in noisy))
        self.assertTrue(all("Traceback" not in line for line in logs))


class ServerHandleErrorTest(unittest.TestCase):
    """``DiagServer.handle_error``：连接异常一行 debug；其他异常一行 error + 类型。"""

    def _handle(self, exc: BaseException) -> list[str]:
        httpd = server.DiagServer((HOST, 0), server.Handler)
        logs: list[str] = []
        stderr = io.StringIO()
        try:
            with mock.patch.object(server.logstore, "diag_log",
                                   side_effect=lambda line: logs.append(str(line))), \
                    contextlib.redirect_stderr(stderr):
                try:
                    raise exc
                except type(exc):
                    httpd.handle_error(object(), (HOST, 1))
        finally:
            httpd.server_close()
        self.assertNotIn("Traceback", stderr.getvalue())
        return logs

    def test_connection_reset_is_debug_line_only(self):
        logs = self._handle(ConnectionResetError("client went away"))
        self.assertTrue(any("[debug]" in line and "客户端提前断开" in line
                            for line in logs), logs)
        self.assertFalse(any("[错误]" in line for line in logs), logs)

    def test_broken_pipe_and_aborted_are_noise_too(self):
        for exc in (BrokenPipeError("pipe"), ConnectionAbortedError("aborted")):
            with self.subTest(exc=type(exc).__name__):
                logs = self._handle(exc)
                self.assertTrue(any("客户端提前断开" in line for line in logs), logs)

    def test_other_exception_keeps_one_line_with_type(self):
        logs = self._handle(RuntimeError("boom"))
        self.assertTrue(any("[错误] 请求处理异常：RuntimeError: boom" in line
                            for line in logs), logs)
        self.assertFalse(any("Traceback" in line for line in logs))


if __name__ == "__main__":
    unittest.main(verbosity=2)
