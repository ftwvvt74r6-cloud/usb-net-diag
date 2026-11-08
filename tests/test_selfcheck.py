"""C2 首屏自检：``GET /api/selfcheck`` 五项结构 + 首次运行标记 + FAIL-OPEN 契约。

这个文件钉住三件容易「看起来能用、实际悄悄坏掉」的事：

1. **五项固定结构**：``python`` / ``tshark`` / ``npcap`` / ``port`` / ``admin``，
   每项都有 ``key/name/ok/detail/fix_kind/fix_url/fix_command``；失败项的
   ``detail`` 必须可执行（含原因），修复信息必须指向官网链接或命令。
2. **首次运行标记**：位置在 ``<root>/config/ui-first-run.json``；写了之后
   ``first_run`` 变 False；**写失败（U 盘只读）返回 ok:false 但绝不抛异常**，
   更不许阻塞界面（``collect`` 仍能正常返回）。
3. **纯读边界**：检查过程不写文件、不触发 UAC、不启动抓包子进程；全部探测用 mock
   （本机没有 Npcap/tshark 时也不 skip，CI 两端行为一致）。

``POST /api/selfcheck/ack`` 用真实 DiagServer 验证路由接线，但把落盘函数换成
mock —— 测试绝不写仓库 ``config/``。
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
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import selfcheck  # noqa: E402
import server  # noqa: E402

CHECK_FIELDS = {"key", "name", "ok", "detail", "fix_kind", "fix_url", "fix_command"}
EXPECTED_KEYS = ["python", "tshark", "npcap", "port", "admin"]


def _http(port: int, method: str, path: str, body: bytes | None = None,
          timeout: int = 15) -> tuple[int, str]:
    """发一个本机 HTTP 请求；HTTPError 也当响应返回（与 test_elevate_api 同口径）。"""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _mock_env():
    """一组默认『全部通过』的 mock 上下文（单测按需在外层再覆盖返回值）。

    Returns:
        contextlib.ExitStack: 已经 start 的 mock 栈；调用方用 ``with`` 包住。
    """
    stack = ExitStack()
    stack.enter_context(mock.patch.object(
        selfcheck.tshark, "find_tshark", return_value=Path("C:/fake/tshark.exe")))
    stack.enter_context(mock.patch.object(
        selfcheck.tshark, "version", return_value="TShark (Wireshark) 4.7.4"))
    stack.enter_context(mock.patch.object(selfcheck, "_npcap_installed", return_value=True))
    stack.enter_context(mock.patch.object(selfcheck, "_is_admin", return_value=True))
    stack.enter_context(mock.patch.object(selfcheck.app, "find_running", return_value=""))
    stack.enter_context(mock.patch.object(selfcheck.app, "first_free_port", return_value=8787))
    return stack


class CollectContractTest(unittest.TestCase):
    """五项固定 key/字段/顺序；通过时 ok=True；版本与 first_run 从注入的 root 读。"""

    def test_five_checks_with_fixed_keys_and_fields(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_selfcheck_") as tmp:
            root = Path(tmp)
            (root / "VERSION").write_text("9.9.9\n", encoding="utf-8")
            with _mock_env():
                data = selfcheck.collect(root=root)
        self.assertEqual([c["key"] for c in data["checks"]], EXPECTED_KEYS)
        self.assertEqual(data["version"], "9.9.9")
        self.assertTrue(data["first_run"], "临时目录没有标记文件 → 必须是首次运行")
        self.assertTrue(data["ok"], "五项都 mock 成通过时 ok 必须为 True")
        for item in data["checks"]:
            with self.subTest(key=item["key"]):
                self.assertEqual(set(item), CHECK_FIELDS,
                                 f"{item['key']} 的字段集合不稳定，UI/测试会读不到键")
                self.assertTrue(item["name"].strip(), "name 不能为空")
                self.assertTrue(item["detail"].strip(), "detail 不能为空")
                self.assertIn(item["fix_kind"], ("none", "url", "command", "elevate"))
                self.assertIsInstance(item["fix_url"], str)
                self.assertIsInstance(item["fix_command"], str)
        self.assertIn("startup", data["ui_copy"])
        self.assertTrue(data["ui_copy"]["startup"]["panel_title"].strip())

    def test_ui_copy_has_each_check_name(self):
        copy = selfcheck.ui_copy()
        for key in EXPECTED_KEYS:
            with self.subTest(key=key):
                self.assertIn(f"check_{key}", copy)
                self.assertTrue(copy[f"check_{key}"].strip())


class FailureDetailTest(unittest.TestCase):
    """失败项必须给可执行 detail + 修复信息（官网链接 / 命令 / 提权入口）。"""

    def test_python_too_old_has_upgrade_link(self):
        with mock.patch.object(selfcheck.sys, "version_info", (3, 10, 9)), \
                mock.patch.object(selfcheck, "_python_runtime", return_value="系统 Python"):
            item = selfcheck.check_python()
        self.assertFalse(item["ok"])
        self.assertIn("3.10.9", item["detail"])
        self.assertIn("3.11", item["detail"])
        self.assertEqual(item["fix_kind"], "url")
        self.assertIn("python.org", item["fix_url"])

    def test_python_311_is_the_boundary(self):
        with mock.patch.object(selfcheck.sys, "version_info", (3, 11, 0)), \
                mock.patch.object(selfcheck, "_python_runtime", return_value="系统 Python"):
            self.assertTrue(selfcheck.check_python()["ok"])
        with mock.patch.object(selfcheck.sys, "version_info", (3, 10, 99)), \
                mock.patch.object(selfcheck, "_python_runtime", return_value="系统 Python"):
            self.assertFalse(selfcheck.check_python()["ok"])

    def test_tshark_missing_has_download_and_interfaces_command(self):
        with mock.patch.object(selfcheck.tshark, "find_tshark", return_value=None):
            item = selfcheck.check_tshark()
        self.assertFalse(item["ok"])
        self.assertIn("tshark", item["detail"])
        self.assertEqual(item["fix_kind"], "url")
        self.assertIn("wireshark.org", item["fix_url"])
        self.assertIn("--interfaces", item["fix_command"])

    def test_npcap_missing_has_official_link(self):
        with mock.patch.object(selfcheck, "_npcap_installed", return_value=False):
            item = selfcheck.check_npcap()
        self.assertFalse(item["ok"])
        self.assertIn("Npcap", item["detail"])
        self.assertEqual(item["fix_kind"], "url")
        self.assertIn("npcap.com", item["fix_url"])

    def test_port_busy_has_command_fix(self):
        with mock.patch.object(selfcheck.app, "find_running", return_value=""), \
                mock.patch.object(selfcheck.app, "first_free_port", return_value=None):
            item = selfcheck.check_port()
        self.assertFalse(item["ok"])
        self.assertIn("8787", item["detail"])
        self.assertEqual(item["fix_kind"], "command")
        self.assertIn("netstat", item["fix_command"])

    def test_running_instance_wins_over_free_port(self):
        with mock.patch.object(
                selfcheck.app, "find_running",
                return_value="http://127.0.0.1:8787/"), \
                mock.patch.object(selfcheck.app, "first_free_port") as free:
            item = selfcheck.check_port()
        self.assertTrue(item["ok"])
        self.assertIn("127.0.0.1:8787", item["detail"])
        free.assert_not_called()

    def test_admin_required_has_elevate_fix(self):
        with mock.patch.object(selfcheck, "_is_admin", return_value=False):
            item = selfcheck.check_admin()
        self.assertFalse(item["ok"])
        self.assertIn("管理员", item["detail"])
        self.assertEqual(item["fix_kind"], "elevate")


class FirstRunMarkerTest(unittest.TestCase):
    """标记文件读写：路径在 config/、写失败不抛、写成功后 first_run=False。"""

    def test_marker_path_is_under_config(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_marker_") as tmp:
            path = selfcheck.marker_path(Path(tmp))
        self.assertEqual(path.parent.name, "config")
        self.assertEqual(path.name, "ui-first-run.json")

    def test_ack_writes_marker_and_flips_first_run(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_marker_") as tmp:
            root = Path(tmp)
            (root / "VERSION").write_text("9.9.9\n", encoding="utf-8")
            self.assertTrue(selfcheck.is_first_run(root))
            result = selfcheck.ack_first_run(root)
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["writable"], result)
            self.assertTrue((root / "config" / "ui-first-run.json").is_file())
            payload = json.loads((root / "config" / "ui-first-run.json")
                                 .read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], "9.9.9")
            self.assertFalse(selfcheck.is_first_run(root))
            with _mock_env():
                data = selfcheck.collect(root=root)
            self.assertFalse(data["first_run"])

    def test_ack_write_failure_does_not_raise_or_flip_first_run(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_marker_") as tmp:
            root = Path(tmp)
            with mock.patch.object(Path, "write_text", side_effect=OSError("read-only")):
                result = selfcheck.ack_first_run(root)
            self.assertFalse(result["ok"], result)
            self.assertFalse(result["writable"], result)
            self.assertIn("read-only", result["error"])
            self.assertTrue(selfcheck.is_first_run(root),
                            "写失败时不能假装已经记过标记")
            with _mock_env():
                data = selfcheck.collect(root=root)
            self.assertTrue(data["first_run"], "写失败后重新检查仍应显示面板")
            self.assertIn("checks", data, "写失败不许把检查接口打成异常")

    def test_collect_does_not_write_files(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_marker_") as tmp:
            root = Path(tmp)
            (root / "VERSION").write_text("9.9.9\n", encoding="utf-8")
            before = sorted(p.name for p in root.rglob("*"))
            with _mock_env():
                selfcheck.collect(root=root)
            after = sorted(p.name for p in root.rglob("*"))
        self.assertEqual(before, after, "collect 是只读接口，不许写标记/日志")


class PureReadBoundaryTest(unittest.TestCase):
    """不触发 UAC、不启动抓包子进程。"""

    def test_collect_never_calls_relaunch_or_tshark_run(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_marker_") as tmp:
            with _mock_env(), \
                    mock.patch.object(selfcheck.app, "relaunch_as_admin") as relaunch, \
                    mock.patch.object(selfcheck.tshark, "run") as run:
                data = selfcheck.collect(root=Path(tmp))
        self.assertEqual(len(data["checks"]), 5)
        relaunch.assert_not_called()
        run.assert_not_called()

    def test_npcap_and_admin_delegate_to_winapi(self):
        if selfcheck.winapi is None:  # pragma: no cover - 只在裁剪发行包里出现
            self.skipTest("core.platform.winapi 不可用")
        with mock.patch.object(selfcheck.winapi, "npcap_installed",
                               return_value=True) as npcap, \
                mock.patch.object(selfcheck.winapi, "is_admin",
                                  return_value=False) as admin:
            self.assertTrue(selfcheck.check_npcap()["ok"])
            self.assertFalse(selfcheck.check_admin()["ok"])
        npcap.assert_called_once()
        admin.assert_called_once()


class SelfcheckRoutesTest(unittest.TestCase):
    """真实 HTTP 路由：GET /api/selfcheck + POST /api/selfcheck/ack（落盘 mock）。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._env = mock.patch.dict(
            os.environ, {"NETDIAG_LOG_DIR": str(Path(tempfile.gettempdir()) /
                                               "netdiag_selfcheck_logs")})
        cls._env.start()
        cls.httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._env.stop()

    def test_get_selfcheck_returns_five_checks(self):
        fixture = {"ok": True, "version": "9.9.9", "first_run": True,
                   "checks": [{"key": k, "name": k, "ok": True, "detail": "d",
                               "fix_kind": "none", "fix_url": "", "fix_command": ""}
                              for k in EXPECTED_KEYS],
                   "ui_copy": {"startup": {}}}
        with mock.patch.object(server.selfcheck, "collect", return_value=fixture):
            code, text = _http(self.port, "GET", "/api/selfcheck")
        self.assertEqual(code, 200, text[:300])
        data = json.loads(text)
        self.assertEqual([c["key"] for c in data["checks"]], EXPECTED_KEYS)
        self.assertTrue(data["first_run"])

    def test_ack_route_returns_failure_without_http_error(self):
        """落盘失败也必须是 200 + ok:false，不能 500（否则界面会崩在 ack 上）。"""
        with mock.patch.object(
                server.selfcheck, "ack_first_run",
                return_value={"ok": False, "writable": False, "error": "read-only"}):
            code, text = _http(self.port, "POST", "/api/selfcheck/ack", b"{}")
        self.assertEqual(code, 200, text[:300])
        data = json.loads(text)
        self.assertFalse(data["ok"])
        self.assertFalse(data["writable"])

    def test_app_exposes_first_run_and_startup_copy(self):
        with mock.patch.object(server.selfcheck, "is_first_run", return_value=False), \
                mock.patch.object(server.selfcheck, "ui_copy",
                                  return_value={"panel_title": "准备检查"}):
            code, text = _http(self.port, "GET", "/api/app")
        self.assertEqual(code, 200, text[:300])
        data = json.loads(text)
        self.assertFalse(data["first_run"])
        self.assertEqual(data["ui_copy"]["startup"]["panel_title"], "准备检查")


if __name__ == "__main__":
    unittest.main(verbosity=2)
