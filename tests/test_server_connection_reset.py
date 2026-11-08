"""G4/B1 回归：大响应 ``GET /`` + 客户端 RST，磁盘日志里不许出现 traceback。

背景（G 批次复审 B1）：``Handler._send()`` 只把 ``wfile.write(body)`` 包进
``except CONNECTION_NOISE``，而真正会被 RST 打断的是 ``end_headers()`` 的头部刷写。
异常冒到 ``do_GET`` 的宽泛 ``except`` → 先 ``_log_to_file(traceback.format_exc())``
再降级；小响应（``/api/ping``）通常在 RST 到达前就写完了，所以旧用例没拦住。

本文件用**真实** ``DiagServer``（127.0.0.1 临时端口）与真实 ``NETDIAG_LOG_DIR``
临时目录，覆盖两个场景：

1. 大响应：连续 12 次 ``GET /`` 后立刻 ``SO_LINGER(1, 0)`` RST，再读**磁盘上的**
   ``diag-*.log``，断言没有 ``Traceback`` / ``ConnectionResetError``；
2. 请求未读完：请求行/头还没结束就 RST（异常发生在读请求阶段）。

两个场景都必须：服务仍健康（随后 ``/api/ping`` 200）、连接噪音只落一行 debug。
不依赖管理员 / tshark / 外网，不写仓库 ``logs/``。
"""
from __future__ import annotations

import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import logstore  # noqa: E402
import server  # noqa: E402

HOST = "127.0.0.1"
NOISE_MARK = "客户端提前断开"


def _rst(port: int, payload: bytes) -> None:
    """发一段请求后立刻 RST 关闭（SO_LINGER timeout=0，等 0 秒即发 RST）。"""
    sock = socket.create_connection((HOST, port), timeout=5)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
        sock.sendall(payload)
    finally:
        sock.close()


def _get_ping(port: int) -> tuple[int, dict]:
    with urllib.request.urlopen(f"http://{HOST}:{port}/api/ping", timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


class LargeResponseResetDiskLogTest(unittest.TestCase):
    """真实 server + 真实日志目录：断言的是**磁盘文件**，不是内存日志列表。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="netdiag_reset_disk_")
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

    def _diag_text(self) -> str:
        """读临时目录里全部 ``diag-*.log``（这才是复审要求检查的落盘产物）。"""
        parts = []
        for path in sorted(Path(self.tmp.name).glob("diag-*.log")):
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
        return "\n".join(parts)

    def _assert_disk_log_clean(self) -> str:
        text = self._diag_text()
        self.assertNotIn("Traceback", text,
                         f"连接重置被写成 traceback（B1 回归）：\n{text[-1500:]}")
        self.assertNotIn("ConnectionResetError", text,
                         f"连接重置类名不许进磁盘日志：\n{text[-1500:]}")
        self.assertNotIn("BrokenPipeError", text)
        self.assertNotIn("ConnectionAbortedError", text)
        return text

    def test_twelve_large_get_resets_leave_no_traceback_on_disk(self):
        """大响应 ``GET /`` ×12 + RST：磁盘日志零 traceback，服务仍健康。"""
        for _ in range(12):
            _rst(self.port, b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            time.sleep(0.25)
        time.sleep(0.5)

        status, body = _get_ping(self.port)
        self.assertEqual(status, 200)
        self.assertTrue(body.get("ok"), body)

        text = self._assert_disk_log_clean()
        self.assertIn("[debug]", text,
                      "连接噪音必须留下可诊断的一行 debug（不是静默吞掉）")
        self.assertIn(NOISE_MARK, text)

    def test_reset_before_request_finished_leaves_no_traceback_on_disk(self):
        """请求行/头没读完就 RST：读请求阶段的连接异常同样只落一行 debug。"""
        _rst(self.port, b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        time.sleep(0.5)

        status, body = _get_ping(self.port)
        self.assertEqual(status, 200)
        self.assertTrue(body.get("ok"), body)

        text = self._assert_disk_log_clean()
        self.assertIn(NOISE_MARK, text)

    def test_noise_entries_are_single_line_each(self):
        """连接的异常只允许单行 debug；任何一行都不许带 ``File "...`` 栈帧。"""
        _rst(self.port, b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        time.sleep(0.5)
        status, _ = _get_ping(self.port)
        self.assertEqual(status, 200)

        lines = self._diag_text().splitlines()
        noisy = [line for line in lines if NOISE_MARK in line]
        self.assertTrue(noisy, "没有捕获到连接噪音降级日志")
        for line in noisy:
            self.assertNotIn("Traceback", line)
            self.assertNotIn('File "', line)
            self.assertRegex(line, r"^\[\d{2}:\d{2}:\d{2}\] \[INFO\] ",
                             "落盘日志必须是单行记录（栈帧会破坏这个前缀）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
