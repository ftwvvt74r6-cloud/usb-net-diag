"""端口策略：8787 → 8788~8796 → 端口 0（系统分配），并把真实端口传给启动器。

为什么单独一个文件：端口是**整机资源**，这条策略有三处实现（服务的顺延、启动器的
就绪探测、停止脚本的退出请求），任何一处退回硬编码 8787 都会让「端口被占满 → 界面
打不开」重新出现，而这种现象在单机测试里很难复现（要正好占满 10 个端口）。

这里钉四件事：
1. ``create_server`` 能落到端口 0，并返回**真实**绑定端口（不是 0、不是配置值）；
2. 真实端口写进 ``logs/netdiag.port``，``app.find_running`` 优先读它 ——
   不读就会「端口 0 起的实例，第二次双击被当成没启动，再起一个」；
3. 端口文件坏了/陈旧了不能把程序带崩，只能退回按区间扫；
4. 三个消费方（启动器 .cs、停止器 .vbs、构建契约）都真的读这个文件。

不 import 启动器代码（C#），只做源码文本断言 —— 与 ``test_launcher_contract.py``
同一约定：仓库不提交 exe，CI 上也没有 csc。
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import app as app_mod  # noqa: E402
import server  # noqa: E402

LAUNCHER = ROOT / "launcher" / "NetDiagLauncher.cs"
STOP_VBS = ROOT / "NetDiag-stop.vbs"
BUILD_LAUNCHER = ROOT / "scripts" / "build_launcher.py"


def _read_vbs(path: Path) -> str:
    """读 WSH 脚本：UTF-16 LE BOM 或 UTF-8 都能读（与 test_vbs_launcher 一致）。"""
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8", errors="replace")


def _occupy(ports: list[int]) -> list[socket.socket]:
    """把给定端口全部占住（监听状态），返回要由调用方关闭的 socket。

    不监听就只是「绑过又放开」，别的进程照样能绑 —— 必须真正 listen 才算占用。
    """
    socks: list[socket.socket] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        sock.listen(1)
        socks.append(sock)
    return socks


class PortFileTestCase(unittest.TestCase):
    """把 PID/端口文件重定向到临时目录，避免污染仓库 logs/。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.logdir = Path(self._tmp.name)
        self._patches = [
            mock.patch.dict(os.environ, {"NETDIAG_LOG_DIR": str(self.logdir)}),
            mock.patch.object(server, "PORT_FILE", self.logdir / "netdiag.port"),
            mock.patch.object(server, "PID_FILE", self.logdir / "netdiag.pid"),
        ]
        for patch in self._patches:
            patch.start()
        self.addCleanup(self._stop_patches)

    def _stop_patches(self) -> None:
        for patch in reversed(self._patches):
            patch.stop()
        self._tmp.cleanup()

    def serve(self, port: int = 0) -> tuple[server.DiagServer, str, int]:
        """起一个真监听（register_pid=True），返回 (httpd, url, 真实端口)。"""
        httpd, url = server.create_server(port, quiet=True, register_pid=True)
        self.assertIsNotNone(httpd, "端口 0 必须总能绑上（除非本机回环栈不可用）")
        assert httpd is not None
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        def _shutdown() -> None:
            httpd.shutdown()
            httpd.server_close()

        self.addCleanup(_shutdown)
        actual = int(httpd.server_address[1])
        return httpd, url, actual


class CreateServerPortTest(PortFileTestCase):
    """服务侧：顺延 → 端口 0，且返回真实端口。"""

    def test_returns_requested_port_when_free(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        base = probe.getsockname()[1]
        probe.close()
        _httpd, url, actual = self.serve(base)
        self.assertEqual(actual, base)
        self.assertEqual(url, f"http://127.0.0.1:{base}/")
        self.assertFalse(server.SERVER.get("ephemeral"))

    def test_binds_ephemeral_when_range_is_full(self):
        """8787~8796 全被占 → 落端口 0，返回**真实**端口而不是 0。"""
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        base = probe.getsockname()[1]
        probe.close()
        if base + 9 > 65535:                        # 极端情况：换一段再试
            base = 20000
        blockers = _occupy(list(range(base, base + 10)))
        self.addCleanup(lambda: [s.close() for s in blockers])

        httpd, url, actual = self.serve(base)
        self.assertTrue(server.SERVER.get("ephemeral"),
                        "区间全占时必须标记 ephemeral，否则日志/自检会说是常规端口")
        self.assertNotIn(actual, range(base, base + 10),
                         "系统分配的端口不该落在被占满的区间里")
        self.assertIn(f":{actual}/", url, "url 里必须是被系统分配的端口，不是 0")
        self.assertTrue(url.startswith("http://127.0.0.1:"))
        assert httpd is not None

    def test_port_zero_url_has_actual_port(self):
        """直接传 0 也一样：url 不能是 http://127.0.0.1:0/。"""
        _httpd, url, actual = self.serve(0)
        self.assertGreater(actual, 0)
        self.assertNotIn(":0/", url)

    def test_writes_port_file_with_real_port(self):
        _httpd, url, actual = self.serve(0)
        data = json.loads((self.logdir / "netdiag.port").read_text(encoding="utf-8"))
        self.assertEqual(data["port"], actual)
        self.assertEqual(data["url"], url)
        self.assertEqual(str(data["pid"]), str(os.getpid()))
        self.assertIn("started_at", data)

    def test_port_file_not_written_when_register_pid_false(self):
        """自测实例（register_pid=False）不许覆盖正在运行的应用的端口文件。"""
        httpd, _url = server.create_server(0, quiet=True, register_pid=False)
        assert httpd is not None
        self.addCleanup(httpd.server_close)
        self.assertFalse((self.logdir / "netdiag.port").exists())


class ReadPortFileTest(PortFileTestCase):
    """端口文件的读侧：坏文件一律 None，不抛。"""

    def test_missing_file(self):
        self.assertIsNone(server.read_port_file())

    def test_broken_json(self):
        (self.logdir / "netdiag.port").write_text("{not json", encoding="utf-8")
        self.assertIsNone(server.read_port_file())

    def test_port_out_of_range(self):
        for bad in (0, -1, 70000, "abc", None):
            with self.subTest(port=bad):
                (self.logdir / "netdiag.port").write_text(
                    json.dumps({"port": bad}), encoding="utf-8")
                self.assertIsNone(server.read_port_file())

    def test_reads_valid_file_and_fills_url(self):
        (self.logdir / "netdiag.port").write_text(
            json.dumps({"port": 8799, "pid": 42}), encoding="utf-8")
        data = server.read_port_file()
        assert data is not None
        self.assertEqual(data["port"], 8799)
        self.assertEqual(data["url"], "http://127.0.0.1:8799/")
        self.assertEqual(data["pid"], 42)
        self.assertFalse(data["ephemeral"])

    def test_cleanup_removes_own_port_file(self):
        self.serve(0)
        self.assertTrue((self.logdir / "netdiag.port").exists())
        server.cleanup_pid()
        self.assertFalse((self.logdir / "netdiag.port").exists())

    def test_cleanup_keeps_other_process_port_file(self):
        """别的进程（真应用）的端口文件不能被测试进程删掉。"""
        (self.logdir / "netdiag.port").write_text(
            json.dumps({"port": 8799, "pid": 999999}), encoding="utf-8")
        server.cleanup_pid()
        self.assertTrue((self.logdir / "netdiag.port").exists())


class FindRunningTest(PortFileTestCase):
    """复用侧：已有实例在端口 0 上，也必须被找到。"""

    def test_finds_instance_outside_the_range(self):
        _httpd, url, _actual = self.serve(0)
        self.assertEqual(app_mod.find_running(), url)

    def test_stale_port_file_falls_back_to_scan(self):
        """陈旧文件（进程已死）：端口敲不通 → 退回扫区间 → 没实例就返回空串。"""
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
        probe.close()
        (self.logdir / "netdiag.port").write_text(
            json.dumps({"port": dead, "pid": 999999}), encoding="utf-8")
        with mock.patch.object(server.diagnose, "load_config",
                               return_value={"server_port": 1}):
            self.assertEqual(app_mod.find_running(), "")

    def test_port_file_wins_over_range_scan(self):
        """端口文件里的实例优先于区间扫描（区间里再放一个假的也还是它）。"""
        _httpd, url, _actual = self.serve(0)
        called: list[int] = []
        real_probe = app_mod._probe_ping

        def _spy(port: int) -> str:
            called.append(port)
            return real_probe(port)

        with mock.patch.object(app_mod, "_probe_ping", side_effect=_spy):
            self.assertEqual(app_mod.find_running(), url)
        self.assertEqual(len(called), 1, "命中端口文件后不该再扫区间")


class PortPlanTest(unittest.TestCase):
    """port_plan：区间空闲 → 端口号；区间满 → 0（系统分配）；都不行 → None。"""

    def test_returns_first_free_in_range(self):
        with mock.patch.object(app_mod, "first_free_port", side_effect=[8791]):
            self.assertEqual(app_mod.port_plan(), 8791)

    def test_returns_zero_when_range_full(self):
        with mock.patch.object(app_mod, "first_free_port", side_effect=[None, 49152]):
            self.assertEqual(app_mod.port_plan(), 0)

    def test_returns_none_when_even_zero_fails(self):
        with mock.patch.object(app_mod, "first_free_port", side_effect=[None, None]):
            self.assertIsNone(app_mod.port_plan())

    def test_zero_is_not_falsy_for_callers(self):
        """0 是「系统分配」的合法标记；写成 if port: 会把它当没有端口。"""
        with mock.patch.object(app_mod, "first_free_port", side_effect=[None, 49152]):
            plan = app_mod.port_plan()
        self.assertIsNotNone(plan)
        self.assertEqual(plan, 0)


class LauncherReadsPortFileTest(unittest.TestCase):
    """启动器/停止器/构建契约：三处都必须真的读端口文件（静态断言）。"""

    def test_launcher_declares_port_file(self):
        src = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("netdiag.port", src,
                      "启动器不再读 logs/netdiag.port，端口 0 起的实例永远扫不到")
        self.assertIn("ProbePortFile", src)

    def test_launcher_reads_file_before_scanning(self):
        src = LAUNCHER.read_text(encoding="utf-8")
        body = src[src.index("private static string ProbeExisting()"):]
        body = body[:body.index("private static string ProbePortFile()")]
        file_at = body.find("ProbePortFile()")
        loop_at = body.find("for (int port = PortMin;")
        self.assertGreaterEqual(file_at, 0, "ProbeExisting 没调 ProbePortFile")
        self.assertGreaterEqual(loop_at, 0, "ProbeExisting 的区间扫描被删了")
        self.assertLess(file_at, loop_at,
                        "必须先读端口文件再扫区间，否则端口 0 的实例要等满 30 秒超时")

    def test_stop_script_reads_port_file(self):
        src = _read_vbs(STOP_VBS)
        self.assertIn("netdiag.port", src,
                      "停止器不再读端口文件，端口 0 起的服务只能靠强杀兜底")
        self.assertIn("/api/quit", src)
        self.assertIn("netdiag.pid", src, "强杀兜底被删了")

    def test_build_contract_requires_port_file(self):
        src = BUILD_LAUNCHER.read_text(encoding="utf-8")
        marker_block = src[src.index("REQUIRED_SOURCE_MARKERS"):]
        marker_block = marker_block[:marker_block.index(")")]
        self.assertIn('"netdiag.port"', marker_block,
                      "构建契约没把端口文件列为必需标记，回归时不会有人发现")


class AgentDoesNotListenTest(unittest.TestCase):
    """agent 只采样、不对外服务：它不该绑任何端口（端口预算留给界面）。"""

    def test_agent_source_has_no_listener(self):
        src = (ROOT / "core" / "agent.py").read_text(encoding="utf-8")
        for token in ("create_server", "serve_forever", ".listen(", "ThreadingHTTPServer"):
            with self.subTest(token=token):
                self.assertNotIn(token, src,
                                 "agent 不该监听端口：它只写 JSONL，界面才是唯一服务")

    def test_agent_does_not_write_port_file(self):
        src = (ROOT / "core" / "agent.py").read_text(encoding="utf-8")
        self.assertNotIn("netdiag.port", src)


class PreferredPortTest(unittest.TestCase):
    """``--port N``：提权重启时把当前端口带过去，绑回同一个地址。"""

    def test_parses_space_form(self):
        self.assertEqual(app_mod.preferred_port(["app.py", "--elevated", "--port", "49152"]),
                         49152)

    def test_parses_equals_form(self):
        self.assertEqual(app_mod.preferred_port(["app.py", "--port=8793"]), 8793)

    def test_missing_or_invalid_gives_none(self):
        for argv in (["app.py"], ["app.py", "--port"], ["app.py", "--port", "abc"],
                     ["app.py", "--port", "0"], ["app.py", "--port", "70000"]):
            with self.subTest(argv=argv):
                self.assertIsNone(app_mod.preferred_port(argv))

    def test_relaunch_passes_port_to_child(self):
        """提权链路必须把端口写进 params，否则新进程会换端口、旧标签页失联。"""
        calls: list[str] = []

        def _fake_shell(*args):
            calls.append(args[3])          # (hwnd, "runas", exe, params, cwd, show)
            return 33

        with mock.patch.object(app_mod.ctypes.windll.shell32, "ShellExecuteW",
                               side_effect=_fake_shell), \
                mock.patch.dict(os.environ, {}, clear=False):
            self.assertTrue(app_mod.relaunch_as_admin(port=49152))
        self.assertEqual(len(calls), 1)
        self.assertIn("--elevated", calls[0])
        self.assertIn("--port 49152", calls[0])

    def test_relaunch_without_port_keeps_old_params(self):
        calls: list[str] = []

        def _fake_shell(*args):
            calls.append(args[3])
            return 33

        with mock.patch.object(app_mod.ctypes.windll.shell32, "ShellExecuteW",
                               side_effect=_fake_shell), \
                mock.patch.dict(os.environ, {}, clear=False):
            self.assertTrue(app_mod.relaunch_as_admin())
        self.assertNotIn("--port", calls[0])


if __name__ == "__main__":
    unittest.main()
