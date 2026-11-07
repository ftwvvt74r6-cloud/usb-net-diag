"""HTTP 早退请求体回归：必须 drain（防 RST）且禁止 keep-alive 请求走私。

背景（PR #13 复审 B1）：``/api/upload`` 扩展名不合法、``_guard`` 403 等早退分支
在读完 ``Content-Length`` 之前就返回；残留 body 既会让客户端看到
``ConnectionAbortedError: 10053``，又会被 ``BaseHTTPRequestHandler`` 当成
**下一条请求**执行（请求走私 / CSRF 绕过）。本文件把这两条钉死：

* 4 MB body × 20 次上传非 pcap → 0 次连接中断；
* 外层非法 Origin 的 403 请求里内嵌 ``POST /api/passive/stop`` → 内层绝不执行；
* 正常小文件上传路径不受影响。

日志根目录用 ``NETDIAG_LOG_DIR`` 注入临时目录（SPEC V7），不写仓库 ``logs/``。
"""

from __future__ import annotations

import json
import os
import socket
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

import logstore  # noqa: E402
import server  # noqa: E402


def _http(port: int, method: str, path: str, body: bytes | None = None,
          headers: dict | None = None, timeout: int = 30) -> tuple[int, str]:
    """发一个 urllib 请求，返回 ``(状态码, 文本)``；HTTPError 也按响应返回。"""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                 method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _read_one_response(sock: socket.socket) -> tuple[int, bytes]:
    """从 socket 精确读一个 HTTP 响应（按 Content-Length 截断）。"""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("连接在响应头之前就关闭了")
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(b":")
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get(b"content-length", b"0"))
    body = rest
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return status, body[:length]


class HttpBodyDrainTests(unittest.TestCase):
    """起一个真实 ``DiagServer``，用真 socket 验证早退路径的请求体处理。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="netdiag_http_")
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

    def test_upload_4mb_bad_extension_never_aborts(self):
        """4 MB body 上传非 pcap：20 次都必须拿到明确的 200，不许连接被重置（B1）。

        修复前服务端在扩展名检查处直接返回，4 MB 停在接收缓冲区，关闭 socket 时
        Windows 发 RST —— 实测 20 次里 15 次 ``ConnectionAbortedError: 10053``。
        """
        body = b"MZ" + b"\x00" * (4 << 20)
        failures: dict[str, int] = {}
        for _ in range(20):
            try:
                code, text = _http(
                    self.port, "POST", "/api/upload?name=evil.exe", body,
                    {"Content-Type": "application/octet-stream"})
            except Exception as exc:  # noqa: BLE001  连接中断就是要抓的失败
                failures[type(exc).__name__] = failures.get(type(exc).__name__, 0) + 1
                continue
            self.assertEqual(code, 200, f"应返回业务错误 200，实际 HTTP {code}")
            self.assertIn('"ok": false', text)
        self.assertEqual(failures, {}, f"4MB 早退仍出现连接中断：{failures}")

    def test_smuggled_request_in_403_body_not_executed(self):
        """外层非法 Origin 的 403 请求里内嵌 stop：内层请求绝不能被执行（B1）。

        请求走私的成立条件是 keep-alive：外层不带 ``Connection: close``，body 用
        ``Content-Length`` 精确指向内嵌的完整请求。修复前会收到 2 个响应且
        ``PJOB["stop"]`` 被置 True；修复后 body 被 drain，内层不执行。
        """
        old = dict(server.PJOB)
        server.PJOB.update({"state": "idle", "stop": False, "error": "", "result": None})
        try:
            inner = (b"POST /api/passive/stop HTTP/1.1\r\n"
                     b"Host: 127.0.0.1\r\n"
                     b"Content-Length: 0\r\n\r\n")
            outer_head = (b"POST /api/upload?name=evil.exe HTTP/1.1\r\n"
                          b"Host: 127.0.0.1\r\n"
                          b"Origin: http://evil.example\r\n"
                          b"Content-Type: application/octet-stream\r\n"
                          b"Content-Length: " + str(len(inner)).encode() + b"\r\n\r\n")
            with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
                sock.sendall(outer_head + inner)
                status, payload = _read_one_response(sock)
                self.assertEqual(status, 403, payload[:120])
                time.sleep(0.5)  # 给走私请求足够时间执行（修复前必然触发）
                self.assertFalse(server.PJOB.get("stop"),
                                 "内嵌的 POST /api/passive/stop 被执行了（请求走私）")
        finally:
            server.PJOB.update(old)

    def test_chunked_body_without_content_length_cannot_smuggle(self):
        """``Transfer-Encoding: chunked`` 且无 ``Content-Length``：连接必须关闭，内嵌请求不许执行。

        第 2 轮复审抓到的顺序缺陷：``_discard_body`` 里 ``left <= 0`` 的早返回原本在
        ``Transfer-Encoding`` 判断之前，chunked 请求既不会被 drain 也不会被 close，
        残留字节被当成下一条请求执行（实测外层 403 后内嵌 ``stop`` 仍执行）。
        修复顺序后：只回 1 个响应、连接被关闭、内嵌请求不执行。
        """
        old = dict(server.PJOB)
        server.PJOB.update({"state": "idle", "stop": False, "error": "", "result": None})
        try:
            inner = (b"POST /api/passive/stop HTTP/1.1\r\n"
                     b"Host: 127.0.0.1\r\n"
                     b"Content-Length: 0\r\n\r\n")
            outer = (b"POST /api/upload?name=evil.exe HTTP/1.1\r\n"
                     b"Host: 127.0.0.1\r\n"
                     b"Origin: http://evil.example\r\n"
                     b"Transfer-Encoding: chunked\r\n"
                     b"Content-Type: application/octet-stream\r\n\r\n")
            with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
                sock.sendall(outer + inner)
                status, payload = _read_one_response(sock)
                self.assertEqual(status, 403, payload[:120])
                sock.settimeout(2.0)
                try:
                    leftover = sock.recv(4096)
                except socket.timeout:      # 没关连接，但也没再吐响应 —— 仍算失败
                    leftover = b"<timeout>"
                self.assertEqual(leftover, b"",
                                 "chunked 请求后连接未关闭，残留 body 可能被当成下一条请求")
                time.sleep(0.3)
                self.assertFalse(server.PJOB.get("stop"),
                                 "内嵌的 POST /api/passive/stop 被执行了（请求走私）")
        finally:
            server.PJOB.update(old)

    def test_valid_upload_still_works(self):
        """正常上传路径不受影响：合法扩展名 + 小文件仍能落盘并返回成功。"""
        with tempfile.TemporaryDirectory(prefix="netdiag_up_") as tmp:
            captures = Path(tmp) / "captures"
            with mock.patch.object(server, "CAPTURES", captures):
                payload = b"\xd4\xc3\xb2\xa1" + b"\x00" * 60
                code, text = _http(
                    self.port, "POST", "/api/upload?name=sample.pcap", payload,
                    {"Content-Type": "application/octet-stream"})
                data = json.loads(text)
                self.assertEqual(code, 200)
                self.assertTrue(data.get("ok"), text)
                self.assertEqual(data.get("size"), len(payload))
                files = list(captures.glob("upload_*_sample.pcap"))
                self.assertEqual(len(files), 1, "正常上传没有落盘")
                self.assertEqual(files[0].read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
