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

CHECK_FIELDS = {"key", "name", "ok", "detail", "fix_kind", "fix_url", "fix_command",
                "impact", "doc_url"}
EXPECTED_KEYS = ["python", "tshark", "npcap", "port", "admin"]
CAPABILITY_FIELDS = {"probe", "offline", "live", "passive", "reports", "settings",
                     "missing", "scapy"}


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
                self.assertTrue(item["impact"].strip(), "impact 不能为空（缺了会怎样）")
                self.assertIn("docs/startup.md", item["doc_url"])
        self.assertIn("startup", data["ui_copy"])
        self.assertTrue(data["ui_copy"]["startup"]["panel_title"].strip())
        self.assertEqual(set(data["capabilities"]), CAPABILITY_FIELDS,
                         "collect 必须下发完整能力矩阵（UI 置灰的唯一出处）")

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


def _cap_checks(tshark_ok: bool, npcap_ok: bool, admin_ok: bool = False) -> list[dict]:
    """构造一份只关心 tshark/npcap/admin 的五项检查结果（其余恒通过）。"""
    return [
        {"key": "python", "ok": True},
        {"key": "tshark", "ok": tshark_ok},
        {"key": "npcap", "ok": npcap_ok},
        {"key": "port", "ok": True},
        {"key": "admin", "ok": admin_ok},
    ]


class CapabilitiesMatrixTest(unittest.TestCase):
    """能力矩阵真值表：probe/reports/settings 恒真；offline/live/passive 按组件折算。"""

    def test_truth_table_all_eight_combinations(self):
        for tshark_ok in (True, False):
            for npcap_ok in (True, False):
                for scapy_ok in (True, False):
                    with self.subTest(tshark=tshark_ok, npcap=npcap_ok, scapy=scapy_ok), \
                            mock.patch.object(selfcheck, "_scapy_available",
                                              return_value=scapy_ok):
                        caps = selfcheck.capabilities(
                            _cap_checks(tshark_ok, npcap_ok))
                    self.assertTrue(caps["probe"], "probe 不依赖任何抓包组件")
                    self.assertTrue(caps["reports"])
                    self.assertTrue(caps["settings"])
                    self.assertEqual(caps["offline"], tshark_ok,
                                     "offline 只取决于 tshark")
                    self.assertEqual(caps["live"], tshark_ok and npcap_ok,
                                     "live = tshark 且 npcap")
                    self.assertEqual(caps["passive"],
                                     npcap_ok and (tshark_ok or scapy_ok),
                                     "passive = Npcap 且（tshark 或 scapy）："
                                     "没有驱动时引擎可用也打不开网卡")
                    self.assertEqual(caps["scapy"], scapy_ok)

                    expected_missing = {}
                    if not tshark_ok:
                        expected_missing["offline"] = "tshark"
                    if not (tshark_ok and npcap_ok):
                        if not tshark_ok and not npcap_ok:
                            expected_missing["live"] = "tshark|npcap"
                        else:
                            expected_missing["live"] = "tshark" if not tshark_ok else "npcap"
                    if not (npcap_ok and (tshark_ok or scapy_ok)):
                        reasons = []
                        if not (tshark_ok or scapy_ok):
                            reasons.append("tshark|scapy")
                        if not npcap_ok:
                            reasons.append("npcap")
                        expected_missing["passive"] = "|".join(reasons)
                    self.assertEqual(caps["missing"], expected_missing)

    def test_admin_is_not_a_hard_gate(self):
        with mock.patch.object(selfcheck, "_scapy_available", return_value=True):
            caps = selfcheck.capabilities(_cap_checks(True, True, admin_ok=False))
        for mode in ("probe", "offline", "live", "passive", "reports", "settings"):
            self.assertTrue(caps[mode], f"非管理员不许置灰 {mode}（按需提权即可）")
        self.assertEqual(caps["missing"], {})

    def test_scapy_reuses_passive_engine_status(self):
        if selfcheck.passive is None:  # pragma: no cover - 只在裁剪发行包里出现
            self.skipTest("core/passive.py 不可用")
        with mock.patch.object(selfcheck.passive, "engine_status",
                               return_value={"engine": "scapy", "scapy": True}) as status:
            caps = selfcheck.capabilities(_cap_checks(False, True))
        status.assert_called_once()
        self.assertTrue(caps["scapy"])
        self.assertTrue(caps["passive"],
                        "Npcap 在 + 有 scapy 时 passive 不必依赖 tshark")
        self.assertNotIn("passive", caps["missing"])

    def test_scapy_without_npcap_is_still_locked(self):
        """B1：scapy 可导入但 Npcap 缺 → 通信观察不可用，原因是 npcap。"""
        with mock.patch.object(selfcheck, "_scapy_available", return_value=True):
            caps = selfcheck.capabilities(_cap_checks(False, False))
        self.assertTrue(caps["scapy"])
        self.assertFalse(caps["passive"])
        self.assertEqual(caps["missing"]["passive"], "npcap")

    def test_passive_missing_reason_codes_are_specific(self):
        cases = [
            # (tshark, npcap, scapy, passive, missing["passive"])
            (True, False, False, False, "npcap"),
            (False, False, True, False, "npcap"),
            (False, True, False, False, "tshark|scapy"),
            (False, True, True, True, None),
            (False, False, False, False, "tshark|scapy|npcap"),
            (True, True, False, True, None),
        ]
        for tshark_ok, npcap_ok, scapy_ok, expected, reason in cases:
            with self.subTest(tshark=tshark_ok, npcap=npcap_ok, scapy=scapy_ok), \
                    mock.patch.object(selfcheck, "_scapy_available",
                                      return_value=scapy_ok):
                caps = selfcheck.capabilities(_cap_checks(tshark_ok, npcap_ok))
            self.assertEqual(caps["passive"], expected)
            if reason is None:
                self.assertNotIn("passive", caps["missing"])
            else:
                self.assertEqual(caps["missing"]["passive"], reason)

    def test_default_runs_the_five_checks(self):
        fixture = {
            "python": {"key": "python", "ok": True},
            "tshark": {"key": "tshark", "ok": True},
            "npcap": {"key": "npcap", "ok": True},
            "port": {"key": "port", "ok": True},
            "admin": {"key": "admin", "ok": False},
        }
        with ExitStack() as stack:
            mocks = {
                key: stack.enter_context(
                    mock.patch.object(selfcheck, f"check_{key}", return_value=item))
                for key, item in fixture.items()
            }
            stack.enter_context(mock.patch.object(selfcheck, "_scapy_available",
                                                  return_value=False))
            caps = selfcheck.capabilities()
        for key, caller in mocks.items():
            with self.subTest(key=key):
                caller.assert_called_once()
        self.assertTrue(caps["live"])
        self.assertTrue(caps["offline"])


class SelfcheckCacheTest(unittest.TestCase):
    """S2：``/api/app`` 与 ``/api/selfcheck`` 共用短 TTL 缓存，别把全套检查跑两遍。"""

    def setUp(self):
        selfcheck.invalidate_cache()

    def tearDown(self):
        selfcheck.invalidate_cache()

    def _fixture(self) -> dict:
        return {
            "ok": True, "version": "9.9.9", "first_run": True,
            "checks": [{"key": k, "name": k, "ok": True, "detail": "d",
                        "fix_kind": "none", "fix_url": "", "fix_command": "",
                        "impact": "i", "doc_url": "docs/startup.md"}
                       for k in EXPECTED_KEYS],
            "capabilities": {"probe": True, "offline": True, "live": True,
                             "passive": True, "reports": True, "settings": True,
                             "missing": {}, "scapy": False},
            "ui_copy": {"startup": {}},
        }

    def test_two_calls_run_collect_once(self):
        with mock.patch.object(selfcheck, "collect",
                               return_value=self._fixture()) as collect:
            first = selfcheck.collect_cached()
            second = selfcheck.collect_cached()
        self.assertEqual(collect.call_count, 1, "TTL 内第二次必须复用缓存")
        self.assertEqual(first, second)

    def test_force_and_invalidate_run_collect_again(self):
        with mock.patch.object(selfcheck, "collect",
                               return_value=self._fixture()) as collect:
            selfcheck.collect_cached()
            selfcheck.collect_cached(force=True)
            self.assertEqual(collect.call_count, 2, "force=True 必须重新检查")
            selfcheck.invalidate_cache()   # ack 处理器走这条
            selfcheck.collect_cached()
            self.assertEqual(collect.call_count, 3, "ack 清缓存后必须重新检查")

    def test_expired_ttl_runs_collect_again(self):
        with mock.patch.object(selfcheck, "CACHE_TTL_SECONDS", 0), \
                mock.patch.object(selfcheck, "collect",
                                  return_value=self._fixture()) as collect:
            selfcheck.collect_cached()
            selfcheck.collect_cached()
        self.assertEqual(collect.call_count, 2, "TTL 归零后缓存必须失效")

    def test_cached_result_is_a_deep_copy(self):
        with mock.patch.object(selfcheck, "collect",
                               return_value=self._fixture()):
            first = selfcheck.collect_cached()
            first["checks"][0]["ok"] = False
            second = selfcheck.collect_cached()
        self.assertTrue(second["checks"][0]["ok"],
                        "调用方修改返回值不许污染缓存")


class CollectResilienceTest(unittest.TestCase):
    """能力矩阵随 collect 下发；单项检查异常只降级该项，绝不让接口整体抛。"""

    def test_collect_has_capabilities_and_impacts(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_caps_") as tmp, \
                _mock_env(), \
                mock.patch.object(selfcheck, "_scapy_available", return_value=False):
            data = selfcheck.collect(root=Path(tmp))
        caps = data["capabilities"]
        self.assertEqual(set(caps), CAPABILITY_FIELDS)
        self.assertTrue(caps["probe"])
        self.assertTrue(caps["offline"])
        self.assertTrue(caps["live"])
        self.assertTrue(caps["passive"], "tshark 在时 passive 可用")
        self.assertFalse(caps["scapy"])
        for item in data["checks"]:
            with self.subTest(key=item["key"]):
                self.assertTrue(item["impact"].strip())
                self.assertTrue(item["doc_url"].strip())

    def test_one_check_raising_does_not_break_collect(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_caps_") as tmp, \
                _mock_env(), \
                mock.patch.object(selfcheck, "_scapy_available", return_value=False), \
                mock.patch.object(selfcheck, "check_npcap",
                                  side_effect=RuntimeError("driver query boom")):
            data = selfcheck.collect(root=Path(tmp))
        self.assertEqual(len(data["checks"]), 5)
        by_key = {item["key"]: item for item in data["checks"]}
        npcap = by_key["npcap"]
        self.assertFalse(npcap["ok"])
        self.assertIn("RuntimeError", npcap["detail"])
        self.assertIn("driver query boom", npcap["detail"])
        self.assertTrue(npcap["impact"].strip(), "异常项也要有 impact 文案")
        self.assertFalse(data["capabilities"]["live"])
        self.assertEqual(data["capabilities"]["missing"]["live"], "npcap")
        self.assertFalse(data["capabilities"]["passive"],
                         "Npcap 查询异常按缺驱动处理：通信观察也不可用")
        self.assertEqual(data["capabilities"]["missing"]["passive"], "npcap")
        self.assertFalse(data["ok"])
        for key in ("python", "tshark", "port", "admin"):
            self.assertTrue(by_key[key]["ok"], f"{key} 不该被 npcap 的异常连累")

    def test_check_returning_non_dict_is_treated_as_failure(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_caps_") as tmp, \
                _mock_env(), \
                mock.patch.object(selfcheck, "_scapy_available", return_value=False), \
                mock.patch.object(selfcheck, "check_tshark", return_value=None):
            data = selfcheck.collect(root=Path(tmp))
        tshark_item = {item["key"]: item for item in data["checks"]}["tshark"]
        self.assertFalse(tshark_item["ok"])
        self.assertFalse(data["capabilities"]["offline"])


class StartupCopyContractTest(unittest.TestCase):
    """新增文案：impact/修复指引/能力标签齐全，且不出现开发商硬路径口吻。"""

    REQUIRED_KEYS = (
        "impact_python", "impact_tshark", "impact_npcap", "impact_port",
        "impact_admin", "fix_python", "fix_tshark", "fix_npcap", "fix_port",
        "fix_admin", "need_tshark", "need_npcap", "need_passive",
        "lock_tag_tshark", "lock_tag_npcap", "disabled_title", "disabled_hint",
        "disabled_recheck", "disabled_close", "docs_hint", "selfcheck_failed",
    )

    def test_required_keys_exist_and_non_empty(self):
        copy = selfcheck.ui_copy()
        for key in self.REQUIRED_KEYS:
            with self.subTest(key=key):
                self.assertIn(key, copy)
                self.assertTrue(str(copy[key]).strip(), f"{key} 不能为空")

    def test_fix_copy_is_actionable(self):
        copy = selfcheck.ui_copy()
        self.assertIn("Wireshark", copy["fix_tshark"])
        self.assertIn("TSHARK_PATH", copy["fix_tshark"])
        self.assertIn("重启", copy["fix_tshark"],
                      "TSHARK_PATH 对已启动进程不生效，必须写明要重启/重新运行")
        self.assertIn("docs/startup.md", copy["fix_tshark"])
        self.assertIn("Npcap", copy["fix_npcap"])
        self.assertIn("3.11", copy["fix_python"])
        self.assertIn("8787", copy["fix_port"])

    def test_passive_copy_mentions_npcap(self):
        """B1：通信观察的「需要什么」必须包含 Npcap，不能只说引擎。"""
        copy = selfcheck.ui_copy()
        self.assertIn("Npcap", copy["need_passive"])
        self.assertIn("通信观察", copy["impact_npcap"])
        self.assertIn("Npcap", copy["npcap_missing"])

    def test_no_developer_hard_path_copy(self):
        raw = (ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8")
        self.assertNotIn("请把 Wireshark 便携版解压到", raw)
        for forbidden in ("G:\\\\", "C:\\\\"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, raw)


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

    def setUp(self) -> None:
        selfcheck.invalidate_cache()

    def tearDown(self) -> None:
        selfcheck.invalidate_cache()

    @staticmethod
    def _snapshot(checks=None, caps=None, first_run=True) -> dict:
        """构造一份与 ``collect()`` 同结构的响应（路由/缓存测试共用）。"""
        checks = checks or [
            {"key": k, "name": k, "ok": True, "detail": "d", "fix_kind": "none",
             "fix_url": "", "fix_command": ""} for k in EXPECTED_KEYS]
        caps = caps or {"probe": True, "offline": True, "live": True,
                        "passive": True, "reports": True, "settings": True,
                        "missing": {}, "scapy": False}
        return {"ok": True, "version": "9.9.9", "first_run": first_run,
                "checks": checks, "capabilities": caps,
                "ui_copy": {"startup": {}}}

    def test_get_selfcheck_returns_five_checks(self):
        with mock.patch.object(server.selfcheck, "collect_cached",
                               return_value=self._snapshot()):
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
        snap = self._snapshot(first_run=False)
        snap["ui_copy"] = {"startup": {"panel_title": "准备检查"}}
        with mock.patch.object(server.selfcheck, "collect_cached",
                               return_value=snap):
            code, text = _http(self.port, "GET", "/api/app")
        self.assertEqual(code, 200, text[:300])
        data = json.loads(text)
        self.assertFalse(data["first_run"])
        self.assertEqual(data["ui_copy"]["startup"]["panel_title"], "准备检查")

    def test_app_exposes_capabilities_additively(self):
        caps = {"probe": True, "offline": False, "live": False, "passive": False,
                "reports": True, "settings": True,
                "missing": {"offline": "tshark", "live": "tshark|npcap",
                            "passive": "tshark|scapy|npcap"}, "scapy": False}
        snap = self._snapshot(caps=caps)
        with mock.patch.object(server.selfcheck, "collect_cached",
                               return_value=snap) as caller:
            code, text = _http(self.port, "GET", "/api/app")
        self.assertEqual(code, 200, text[:300])
        data = json.loads(text)
        self.assertEqual(data["capabilities"], caps)
        # 加法字段：首屏一次拿全（checks 同批下发），既有字段照旧。
        self.assertEqual([c["key"] for c in data["checks"]], EXPECTED_KEYS)
        caller.assert_called_once()
        self.assertEqual(data["app"], "USBNetDiag")
        self.assertIn("admin", data)
        self.assertIn("version", data)

    def test_app_and_selfcheck_share_one_collect(self):
        """S2：首屏先 /api/app 再 /api/selfcheck，只允许跑一次全套检查。"""
        with mock.patch.object(server.selfcheck, "collect",
                               return_value=self._snapshot()) as collect:
            code_a, text_a = _http(self.port, "GET", "/api/app")
            code_b, text_b = _http(self.port, "GET", "/api/selfcheck")
        self.assertEqual(code_a, 200, text_a[:300])
        self.assertEqual(code_b, 200, text_b[:300])
        self.assertEqual(collect.call_count, 1,
                         "两个首屏接口必须复用同一份缓存结果")
        self.assertEqual(json.loads(text_a)["capabilities"],
                         json.loads(text_b)["capabilities"])

    def test_ack_clears_cache_for_next_selfcheck(self):
        """ack 改了 first_run：缓存必须作废，下一次请求重新检查。"""
        with mock.patch.object(server.selfcheck, "collect",
                               return_value=self._snapshot()) as collect, \
                mock.patch.object(server.selfcheck, "ack_first_run",
                                  return_value={"ok": True, "writable": True}):
            _http(self.port, "GET", "/api/selfcheck")
            code, text = _http(self.port, "POST", "/api/selfcheck/ack", b"{}")
            self.assertEqual(code, 200, text[:300])
            _http(self.port, "GET", "/api/selfcheck")
        self.assertEqual(collect.call_count, 2,
                         "ack 后第一次 /api/selfcheck 必须重新检查")


if __name__ == "__main__":
    unittest.main(verbosity=2)
