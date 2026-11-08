"""H1 单次打开浏览器：``NETDIAG_NO_BROWSER=1`` 是所有打开点的总闸。

这个文件钉住四件事（对应 H-SPEC V1）：

1. **app.py 的两个打开点**（复用已运行实例、启动服务后的后台线程）都受 env 控制：
   env=1 时 ``webbrowser.open`` 一次都不调用，而且连打开线程都不启动；
2. **server.py ``__main__`` 的打开点**同样受控；
3. **未设 env 时保持兼容**：直接 ``python core\\app.py`` / ``python core\\server.py``
   仍然各自动打开一次（老用户的手工启动方式不能被 H1 改坏）；
4. **提权重启不重开**：``--elevated`` 新进程和 :func:`app.relaunch_as_admin` 都走
   「不自动打开」路径（同源 env），避免提权后再多一个标签页。

测试全部 mock：不启动真实服务、不写仓库 ``logs/``、绝不打开可见浏览器。
"""
from __future__ import annotations

import contextlib
import io
import os
import sys
import threading
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

NO_BROWSER_ENV = app_module.NO_BROWSER_ENV


class _FakeHTTPD:
    """假 httpd：serve_forever 立即返回，退出路径可断言。"""

    def __init__(self) -> None:
        self.served = False
        self.closed = False

    def serve_forever(self) -> None:
        self.served = True

    def server_close(self) -> None:
        self.closed = True


class _ImmediateTimer:
    """把 threading.Timer 换成同步执行：server.main 的浏览器打开是定时器触发的。"""

    def __init__(self, interval, function, args=None, kwargs=None):
        self.interval = interval
        self.function = function
        self.args = args or ()
        self.kwargs = kwargs or {}

    def start(self) -> None:
        self.function(*self.args, **self.kwargs)

    def cancel(self) -> None:
        pass


@contextlib.contextmanager
def browser_env(value: str | None):
    """临时设置 / 清除 ``NETDIAG_NO_BROWSER``（其它环境变量保持原样）。

    Args:
        value: ``"1"`` 表示启动器已接管；``None`` 表示完全删除该变量（兼容路径）。

    Yields:
        None: 退出时恢复原环境。
    """
    with mock.patch.dict(os.environ, {}, clear=False):
        if value is None:
            os.environ.pop(NO_BROWSER_ENV, None)
        else:
            os.environ[NO_BROWSER_ENV] = value
        yield


class _AppHarness:
    """跑一次 ``app.main()``：可指定 env、是否已有实例、是否提权。"""

    def __init__(self, *, env: str | None, running: str = "",
                 elevated: bool = False, create_ok: bool = True) -> None:
        self.env = env
        self.running = running
        self.elevated = elevated
        self.create_ok = create_ok

    def run(self):
        fake = _FakeHTTPD()
        result = ((fake, "http://127.0.0.1:8787/") if self.create_ok else (None, ""))
        browser = mock.Mock()
        create_server = mock.Mock(return_value=result)
        threads: list[threading.Thread] = []
        real_thread = threading.Thread

        def record_thread(*args, **kwargs):
            thread = real_thread(*args, **kwargs)
            threads.append(thread)
            return thread

        argv = ["app.py"] + (["--elevated"] if self.elevated else [])
        with ExitStack() as stack:
            stack.enter_context(browser_env(self.env))
            stack.enter_context(mock.patch.object(app_module.webbrowser, "open", browser))
            stack.enter_context(mock.patch.object(app_module.logstore, "ensure_dirs"))
            stack.enter_context(mock.patch.object(app_module.logstore, "prune"))
            stack.enter_context(mock.patch.object(app_module.logstore, "write_env_snapshot"))
            stack.enter_context(mock.patch.object(app_module.logstore, "install_excepthooks"))
            stack.enter_context(mock.patch.object(app_module, "msgbox"))
            stack.enter_context(mock.patch.object(app_module, "find_running",
                                                  return_value=self.running))
            stack.enter_context(mock.patch.object(app_module, "is_admin", return_value=False))
            stack.enter_context(mock.patch.object(
                tshark, "find_tshark", return_value=Path("C:/fake/tshark.exe")))
            stack.enter_context(mock.patch.object(bootstrap, "gen_configs"))
            stack.enter_context(mock.patch.object(
                diagnose, "load_config",
                return_value={"server_port": 8787, "idle_exit_min": 0}))
            stack.enter_context(mock.patch.object(server, "create_server", create_server))
            stack.enter_context(mock.patch.object(server, "cleanup_pid"))
            stack.enter_context(mock.patch.object(app_module.threading, "Thread",
                                                  side_effect=record_thread))
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = app_module.main()
            if self.create_ok and not self.running:
                # _open 线程 sleep 0.4s 才开浏览器；等它在 mock 下跑完。
                deadline = time.time() + 2.0
                while time.time() < deadline and not browser.called:
                    time.sleep(0.05)
        return rc, browser, create_server, threads, output.getvalue()


class AppMainBrowserTest(unittest.TestCase):
    """app.py 两个打开点：env=1 不开 / 未设时各开一次。"""

    def test_reuse_instance_env_one_does_not_open(self):
        rc, browser, create_server, threads, _out = _AppHarness(
            env="1", running="http://127.0.0.1:8787/").run()
        self.assertEqual(rc, 0)
        browser.assert_not_called()
        create_server.assert_not_called()
        self.assertEqual(threads, [], "env=1 时连打开线程都不许启动")

    def test_reuse_instance_without_env_opens_exactly_once(self):
        rc, browser, create_server, _threads, _out = _AppHarness(
            env=None, running="http://127.0.0.1:8787/").run()
        self.assertEqual(rc, 0)
        browser.assert_called_once_with("http://127.0.0.1:8787/")
        create_server.assert_not_called()

    def test_start_service_env_one_does_not_open_or_start_thread(self):
        rc, browser, create_server, threads, output = _AppHarness(env="1").run()
        self.assertEqual(rc, 0)
        create_server.assert_called_once()
        browser.assert_not_called()
        self.assertEqual(threads, [], "env=1 时不应启动浏览器打开线程")
        self.assertIn("浏览器打开由启动器接管", output)

    def test_start_service_without_env_opens_once(self):
        rc, browser, create_server, threads, _out = _AppHarness(env=None).run()
        self.assertEqual(rc, 0)
        create_server.assert_called_once()
        browser.assert_called_once_with("http://127.0.0.1:8787/")
        self.assertEqual(len(threads), 1, "未设 env 时仍走原来的后台打开线程")

    def test_elevated_restart_never_opens_a_second_tab(self):
        """--elevated 是「界面已经开着」的提权重启，不许再弹一个标签页。"""
        rc, browser, _create, threads, output = _AppHarness(env=None, elevated=True).run()
        self.assertEqual(rc, 0)
        browser.assert_not_called()
        self.assertEqual(threads, [], "--elevated 不应启动浏览器打开线程")
        self.assertIn("浏览器打开由启动器接管", output)

    def test_env_truthy_variants_are_recognised(self):
        for value in ("1", "true", "YES", " on "):
            with self.subTest(value=value), browser_env(value):
                self.assertTrue(app_module.browser_disabled(), value)
        for value in ("", "0", "false", "off", "no"):
            with self.subTest(value=value), browser_env(value):
                self.assertFalse(app_module.browser_disabled(), value)


class ServerMainBrowserTest(unittest.TestCase):
    """server.py ``__main__`` 的打开点同样受 NETDIAG_NO_BROWSER 控制。"""

    def _run(self, env: str | None):
        browser = mock.Mock()
        fake = _FakeHTTPD()
        with ExitStack() as stack:
            stack.enter_context(browser_env(env))
            # S2：server.main 必须走 app.open_browser() 这一受控入口，
            # 不再直接调 webbrowser.open（第二套逻辑）。
            stack.enter_context(mock.patch.object(server.app, "open_browser", browser))
            stack.enter_context(mock.patch.object(server.logstore, "ensure_dirs"))
            stack.enter_context(mock.patch.object(server.logstore, "prune"))
            stack.enter_context(mock.patch.object(server.logstore, "write_env_snapshot"))
            stack.enter_context(mock.patch.object(server.logstore, "install_excepthooks"))
            stack.enter_context(mock.patch.object(
                server.diagnose, "load_config",
                return_value={"server_port": 8787, "auto_open_browser": True}))
            stack.enter_context(mock.patch.object(server.bootstrap, "gen_configs"))
            stack.enter_context(mock.patch.object(
                server, "create_server", return_value=(fake, "http://127.0.0.1:8787/")))
            stack.enter_context(mock.patch.object(server, "cleanup_pid"))
            stack.enter_context(mock.patch("threading.Timer", _ImmediateTimer))
            with contextlib.redirect_stdout(io.StringIO()):
                rc = server.main()
        return rc, browser, fake

    def test_env_one_does_not_open_browser(self):
        rc, browser, fake = self._run("1")
        self.assertEqual(rc, 0)
        browser.assert_not_called()
        self.assertTrue(fake.served)

    def test_without_env_opens_browser_once(self):
        rc, browser, fake = self._run(None)
        self.assertEqual(rc, 0)
        browser.assert_called_once_with("http://127.0.0.1:8787/")
        self.assertTrue(fake.served)

    def test_server_source_has_no_second_webbrowser_open_point(self):
        """S2 变异锚点：server 直接调 webbrowser.open 必须红。"""
        source = Path(server.__file__).read_text(encoding="utf-8")
        self.assertNotIn("webbrowser.open(", source,
                         "server 不许有第二套打开逻辑，统一走 app.open_browser()")
        self.assertIn("app.open_browser(url)", source,
                      "server.main 的定时器必须调用 app.open_browser(url)")


class RelaunchKeepsSingleTabTest(unittest.TestCase):
    """UAC 提权重启：新进程继承 NETDIAG_NO_BROWSER=1，不再多开一个标签页。"""

    def test_relaunch_sets_no_browser_env_before_uac(self):
        fake_shell32 = mock.Mock()
        fake_shell32.ShellExecuteW.return_value = 33   # > 32 = 已拉起
        fake_windll = mock.Mock()
        fake_windll.shell32 = fake_shell32
        with browser_env(None), \
                mock.patch.object(app_module.ctypes, "windll", fake_windll, create=True):
            started = app_module.relaunch_as_admin()
            self.assertTrue(started)
            self.assertEqual(os.environ.get(NO_BROWSER_ENV), "1",
                             "提权前必须置位 env：子进程继承后才不会开第二个标签页")
            verb = fake_shell32.ShellExecuteW.call_args.args[1]
            self.assertEqual(verb, "runas")
            params = fake_shell32.ShellExecuteW.call_args.args[3]
            self.assertIn("--elevated", params)


if __name__ == "__main__":
    unittest.main(verbosity=2)
