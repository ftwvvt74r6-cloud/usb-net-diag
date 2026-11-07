"""UI 2.0 ⑪：导航 / 按模式控件 / 权限置灰的静态契约测试。

界面是单文件 ``ui/index.html``，没有打包步骤，也没有前端测试框架。这里不去跑
浏览器（CI 没有 Edge），而是把「模式 → 显示哪些控件」「哪些模式需要管理员」
做成页面里的 ``application/json`` 配置块，再用标准库读它 —— 这样改坏显隐逻辑
或把「全网扫描」的目标框加回来，测试会直接红。

同时覆盖本轮新增的两个后端交互点：
* ``scan`` 模式即使收到 target 也必须忽略并记日志（历史 bug：target 被当过滤条件）；
* ``/api/elevate`` 调启动器已有的提权路径，用户取消时旧服务不受影响。
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import app  # noqa: E402
import server  # noqa: E402

HTML = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")

CONFIG_RE = re.compile(
    r'<script type="application/json" id="ui-config">(.*?)</script>', re.S)


def ui_config() -> dict:
    """把页面里的 UI 配置块解析成 dict（失败让用例红，而不是静默跳过）。"""
    match = CONFIG_RE.search(HTML)
    if match is None:
        raise AssertionError("ui/index.html 缺少 id=ui-config 的 JSON 配置块")
    return json.loads(match.group(1))


class ModeFieldContractTest(unittest.TestCase):
    """每个模式只显示相关控件（需求 #4/#11 的核心口径）。"""

    def test_five_top_level_entries_exist(self):
        for label in ("实时诊断", "链路体检", "离线分析", "报告与导出", "设置"):
            with self.subTest(label=label):
                self.assertIn(label, HTML)

    def test_realtime_second_level_entries_exist(self):
        for mode in ("scan", "live", "passive"):
            with self.subTest(mode=mode):
                self.assertIn(f'data-mode="{mode}"', HTML)
        for view in ("reports", "export"):
            with self.subTest(view=view):
                self.assertIn(f'data-view="{view}"', HTML)

    def test_settings_second_level_entries_exist(self):
        for view in ("ai", "sysinfo"):
            with self.subTest(view=view):
                self.assertIn(f'data-view="{view}"', HTML)

    def test_scan_has_no_target_field(self):
        cfg = ui_config()["modes"]["scan"]
        self.assertNotIn("target", cfg["fields"],
                         "全网扫描不得显示目标框：填了会被当过滤条件（历史 bug）")
        self.assertEqual(set(cfg["fields"]), {"duration", "iface"})

    def test_live_has_target_duration_and_iface(self):
        cfg = ui_config()["modes"]["live"]
        self.assertEqual(set(cfg["fields"]), {"target", "duration", "iface"})

    def test_passive_has_no_target(self):
        cfg = ui_config()["modes"]["passive"]
        self.assertNotIn("target", cfg["fields"], "被动监听只显示时长 + 网卡")
        self.assertEqual(set(cfg["fields"]), {"duration", "iface", "engine"})

    def test_offline_only_shows_file_picker(self):
        cfg = ui_config()["modes"]["offline"]
        self.assertEqual(set(cfg["fields"]), {"offline"},
                         "离线分析只显示文件选择，不显示目标/时长/网卡")

    def test_probe_is_single_page_and_free(self):
        cfg = ui_config()["modes"]["probe"]
        self.assertFalse(cfg["needs_admin"], "链路体检不需要管理员权限")
        self.assertEqual(cfg["fields"], [])

    def test_admin_required_modes(self):
        self.assertEqual(set(ui_config()["locked_modes"]), {"scan", "live", "passive"},
                         "非管理员时必须置灰的是实时抓包三入口")
        for mode in ("offline", "probe"):
            with self.subTest(mode=mode):
                self.assertFalse(ui_config()["modes"][mode]["needs_admin"])


class GuidanceContractTest(unittest.TestCase):
    """新手引导文字与术语说明必须真的在页面上。"""

    def test_every_mode_has_when_to_use_copy(self):
        for mode, cfg in ui_config()["modes"].items():
            with self.subTest(mode=mode):
                self.assertTrue(cfg["guide"].strip(), f"{mode} 缺少「什么时候用这个」")
                self.assertTrue(cfg["label"].strip())

    def test_target_placeholder_has_example(self):
        self.assertIn("例：192.168.1.1 或 www.baidu.com", HTML)

    def test_offline_terminology_explained(self):
        text = HTML + json.dumps(ui_config(), ensure_ascii=False)
        self.assertIn("离线分析 = 分析已有", text,
                      "必须说明离线分析分析的是已有 pcap 文件，不是实时抓包")
        self.assertIn("不碰网卡", text)

class ScanTargetSuppressionTest(unittest.TestCase):
    """后端兜底：scan 模式收到 target 也不参与抓包过滤。"""

    def test_scan_ignores_target_and_logs(self):
        saved = dict(server.JOB)
        saved_logs = list(server.JOB["logs"])
        try:
            with mock.patch.object(server.logstore, "diag_log"), \
                    mock.patch.object(server, "_worker") as worker, \
                    mock.patch.object(server.threading, "Thread") as thread:
                thread.return_value.start.return_value = None
                res = server.start_job({"mode": "scan", "target": "10.0.0.1",
                                        "duration": 5})
            self.assertTrue(res["ok"], res)
            self.assertEqual(server.JOB["target"], "全网")
            self.assertEqual(thread.call_args.kwargs["args"][1], "",
                             "scan 模式传给 worker 的 target 必须是空串")
            text = "\n".join(row["m"] for row in server.JOB["logs"])
            self.assertIn("全网扫描模式忽略目标 10.0.0.1", text)
            self.assertIn("抓取全部流量", text)
        finally:
            server.JOB.clear()
            server.JOB.update(saved)
            server.JOB["logs"] = saved_logs


class ReportIndexTest(unittest.TestCase):
    """历史报告二级页的数据源：只读目录、按时间倒序、附带 JSON 兄弟文件。"""

    def test_report_index_lists_md_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "old.md").write_text("# old\n", encoding="utf-8")
            (root / "new.md").write_text("# new\n", encoding="utf-8")
            (root / "new.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(server, "REPORTS", root):
                files = server.report_index()
        self.assertEqual([f["name"] for f in files], ["new.md", "old.md"],
                         "历史报告应按修改时间倒序")
        self.assertEqual(files[0]["json"], "new.json")
        self.assertEqual(files[1]["json"], "")
        self.assertGreater(files[0]["size"], 0)


class ElevationTest(unittest.TestCase):
    """非管理员一键提权：取消时旧服务继续可用，成功才安排退出。"""

    def test_cancelled_elevation_keeps_service(self):
        with mock.patch.object(server.tshark, "is_admin", return_value=False), \
                mock.patch.object(app, "relaunch_as_admin", return_value=False), \
                mock.patch.object(server, "request_quit") as quit_mock:
            res = server.request_elevation()
        self.assertFalse(res["ok"])
        self.assertIn("未获得管理员权限", res["error"])
        quit_mock.assert_not_called()

    def test_successful_elevation_schedules_restart(self):
        with mock.patch.object(server.tshark, "is_admin", return_value=False), \
                mock.patch.object(app, "relaunch_as_admin", return_value=True), \
                mock.patch.object(server, "request_quit"), \
                mock.patch.object(server.threading, "Timer") as timer:
            res = server.request_elevation()
        self.assertTrue(res["ok"])
        timer.return_value.start.assert_called_once()

    def test_admin_does_not_prompt_uac_again(self):
        with mock.patch.object(server.tshark, "is_admin", return_value=True), \
                mock.patch.object(app, "relaunch_as_admin") as relaunch:
            res = server.request_elevation()
        self.assertTrue(res["ok"])
        self.assertTrue(res.get("already_admin"))
        relaunch.assert_not_called()


class AdminLockStaticTest(unittest.TestCase):
    """置灰逻辑必须由后端 is_admin 驱动，而不是写死。"""

    def test_lock_state_uses_backend_admin_flag(self):
        self.assertIn("app.admin", HTML)
        self.assertIn("isLocked", HTML)
        self.assertIn("aria-disabled", HTML)
        self.assertIn("perm-mask", HTML)
        self.assertIn("/api/elevate", HTML)


if __name__ == "__main__":
    unittest.main(verbosity=2)
