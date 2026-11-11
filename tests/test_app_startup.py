"""F1 启动不阻塞：缺 tshark 只降级，绝不弹原生错误框退出。

这个文件钉住 SPEC §5 的两类**物理例外**与新增的「缺可选组件不阻塞」：

1. **缺 tshark**：``app.main()`` 不调用 ``msgbox``、返回 0、仍调用
   ``server.create_server`` 并进入 ``serve_forever``；日志明确写出
   「未找到 tshark：实时抓包/通信观察/分析抓包文件不可用；其余功能继续」。
2. **8787~8796 全被占用**：物理上起不了服务，仍是 ``msgbox`` + 返回 1；
   但文案面向一线、可操作，不出现本机绝对路径/开发者口吻。
3. **初始化失败**（``bootstrap.gen_configs`` 抛异常）：保持原行为（提示 + 退出码 1）。

测试全部 mock：不写仓库 ``logs/``、不启动真实服务、不打开浏览器、不发网络请求。
"""
from __future__ import annotations

import contextlib
import io
import sys
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import app as app_module  # noqa: E402
import bootstrap  # noqa: E402
import diagnose  # noqa: E402
import server  # noqa: E402
import tshark  # noqa: E402

TSHARK_WARNING = "未找到 tshark：实时抓包/通信观察/分析抓包文件不可用；其余功能继续"


class _FakeHTTPD:
    """假 httpd：``serve_forever`` 立即返回，``server_close`` 只记录调用。"""

    def __init__(self) -> None:
        self.served = False
        self.closed = False

    def serve_forever(self) -> None:
        self.served = True

    def server_close(self) -> None:
        self.closed = True


class AppStartupTest(unittest.TestCase):
    """``app.main()`` 的启动路径（缺 tshark / 端口全占 / 初始化失败）。"""

    @classmethod
    def setUpClass(cls) -> None:
        # 整个类期间都 patch 浏览器：即使 _open 线程晚于断言触发，也绝不会真开浏览器。
        cls._browser_patch = mock.patch.object(app_module.webbrowser, "open")
        cls.browser_open = cls._browser_patch.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._browser_patch.stop()

    def setUp(self) -> None:
        self.browser_open.reset_mock()

    def _run_main(self, *, tshark_found: bool = True,
                  create_server_result: str = "ok",
                  bootstrap_error: Exception | None = None):
        """跑一次 ``app.main()`` 并返回 (退出码, stdout, fake_httpd, mocks)。

        Args:
            tshark_found: ``tshark.find_tshark()`` 的返回值是否为路径。
            create_server_result: ``ok``（假 httpd 可服务）或 ``busy``（ ``(None, "")``）。
            bootstrap_error: 非空时让 ``bootstrap.gen_configs`` 抛这个异常。

        Returns:
            tuple: ``(rc, output, fake_httpd, msgbox, create_server, gen_configs)``。
        """
        fake = _FakeHTTPD()
        create_result = ((fake, "http://127.0.0.1:8787/")
                         if create_server_result == "ok" else (None, ""))
        msgbox = mock.Mock()
        create_server = mock.Mock(return_value=create_result)
        gen_configs = mock.Mock()
        if bootstrap_error is not None:
            gen_configs.side_effect = bootstrap_error

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(app_module.logstore, "ensure_dirs"))
            stack.enter_context(mock.patch.object(app_module.logstore, "prune"))
            stack.enter_context(mock.patch.object(app_module.logstore,
                                                  "write_env_snapshot"))
            stack.enter_context(mock.patch.object(app_module.logstore,
                                                  "install_excepthooks"))
            stack.enter_context(mock.patch.object(app_module, "msgbox", msgbox))
            stack.enter_context(mock.patch.object(app_module, "find_running",
                                                  return_value=""))
            stack.enter_context(mock.patch.object(app_module, "is_admin",
                                                  return_value=False))
            stack.enter_context(mock.patch.object(
                tshark, "find_tshark",
                return_value=Path("C:/fake/tshark.exe") if tshark_found else None))
            stack.enter_context(mock.patch.object(bootstrap, "gen_configs",
                                                  gen_configs))
            stack.enter_context(mock.patch.object(
                diagnose, "load_config",
                return_value={"server_port": 8787, "idle_exit_min": 0}))
            stack.enter_context(mock.patch.object(server, "create_server",
                                                  create_server))
            stack.enter_context(mock.patch.object(server, "cleanup_pid"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = app_module.main()
            # _open 线程 sleep 0.4s 后才开浏览器；等它在 mock 下跑完，避免悬空线程。
            if create_server_result == "ok":
                deadline = time.time() + 2.0
                while time.time() < deadline and not self.browser_open.called:
                    time.sleep(0.05)
        return rc, output.getvalue(), fake, msgbox, create_server, gen_configs

    # -------------------------------------------------------------- 缺 tshark
    def test_missing_tshark_does_not_block_startup(self):
        rc, output, fake, msgbox, create_server, _ = self._run_main(
            tshark_found=False)
        self.assertEqual(rc, 0, "缺 tshark 必须继续启动，不能返回 1")
        msgbox.assert_not_called()
        self.assertTrue(create_server.called, "缺 tshark 也必须继续走 server.create_server")
        create_server.assert_called_once_with(8787, idle_exit_min=0, quiet=True)
        self.assertTrue(fake.served, "假 httpd 的 serve_forever 应被调用（服务已起来）")
        self.assertTrue(fake.closed, "退出路径仍应 server_close")
        self.assertIn(TSHARK_WARNING, output, "日志必须写清缺 tshark 的影响面")
        self.assertIn("docs/startup.md", output)
        self.browser_open.assert_called_once_with("http://127.0.0.1:8787/")

    def test_missing_tshark_never_shows_hard_path_developer_copy(self):
        _rc, output, _fake, msgbox, _create, _gen = self._run_main(
            tshark_found=False)
        msgbox.assert_not_called()
        self.assertNotIn("请把 Wireshark 便携版解压到", output)
        self.assertNotIn("没找到 tshark，抓包与分析抓包文件都不可用", output)

    # --------------------------------------------- 连端口 0 都绑不上（罕见）
    def test_bind_failure_still_uses_friendly_msgbox_and_exit_1(self):
        """8787~8796 全被占不再是失败（会自动落端口 0）；只有连端口 0 都绑不上才退 1。"""
        rc, _output, fake, msgbox, create_server, _ = self._run_main(
            create_server_result="busy")
        self.assertEqual(rc, 1, "一个端口都绑不上是真的起不来，保持退出码 1")
        create_server.assert_called_once()
        msgbox.assert_called_once()
        text = msgbox.call_args.args[0]
        self.assertIn("重启", text, "提示必须可操作")
        self.assertNotIn(str(ROOT), text, "面向一线的提示不许出现本机绝对路径")
        self.assertNotIn("tools", text)
        self.assertFalse(fake.served)
        self.assertFalse(fake.closed)

    def test_missing_tshark_plus_bind_failure_only_reports_the_port_exception(self):
        """两个缺项同时出现时，不能误报缺 tshark，也不能弹两次框。"""
        rc, _output, _fake, msgbox, _create, _gen = self._run_main(
            tshark_found=False, create_server_result="busy")
        self.assertEqual(rc, 1)
        msgbox.assert_called_once()
        text = msgbox.call_args.args[0]
        self.assertIn("端口", text)
        self.assertNotIn("tshark", text.lower())
        self.assertNotIn("Wireshark", text)

    # ---------------------------------------------------------- 初始化失败
    def test_bootstrap_failure_keeps_original_init_failure_behavior(self):
        rc, _output, _fake, msgbox, create_server, gen_configs = self._run_main(
            bootstrap_error=RuntimeError("config write boom"))
        self.assertEqual(rc, 1, "初始化失败仍是真实失败，保持退出码 1")
        gen_configs.assert_called_once()
        create_server.assert_not_called()
        msgbox.assert_called_once()
        self.assertIn("初始化失败", msgbox.call_args.args[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
