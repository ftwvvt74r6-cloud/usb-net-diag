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
import time
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

    def test_console_named_packet_console_on_the_right(self):
        self.assertIn("采集控制台", HTML)
        self.assertIn("Packet Console", HTML)
        self.assertNotIn('<b>运行日志</b>', HTML,
                         "运行日志已改名为「采集控制台」（2.0）")
        self.assertNotIn('id="logwrap"', HTML, "左侧旧日志抽屉已移除")
        # 控制台必须在 main 里（右侧主区下方），不在 aside 里
        aside = HTML.split("<aside", 1)[1].split("</aside>", 1)[0]
        self.assertNotIn('id="console"', aside)
        main = HTML.split('<main class="main">', 1)[1].split("</main>", 1)[0]
        self.assertIn('id="consolepanel"', main)


class VisualContractTest(unittest.TestCase):
    """② 运行态与视觉的静态契约（不跑浏览器也能钉住关键样式/语义）。"""

    def test_progress_panel_exists(self):
        for element_id in ("runpanel", "run-bar", "run-count", "run-phase", "run-retry"):
            with self.subTest(id=element_id):
                self.assertIn(f'id="{element_id}"', HTML)
        self.assertIn("剩余 ", HTML, "倒计时必须写「剩余 Ns / 共 Ms」")
        self.assertIn("第 ", HTML)

    def test_stat_cards_use_auto_fill_and_nowrap_value(self):
        self.assertIn("grid-template-columns:repeat(auto-fill,minmax(160px,1fr))", HTML)
        self.assertIn(".statgrid .stat span{display:block;white-space:normal", HTML)
        self.assertIn(".statgrid .stat b{white-space:nowrap", HTML)
        self.assertIn("padding-right:6px", HTML)

    def test_console_is_dark_mono_with_prefix(self):
        self.assertIn("background:#0b1220", HTML)
        self.assertIn('content:"›"', HTML)
        self.assertIn("var(--mono)", HTML)

    def test_console_color_semantics(self):
        """info 灰白 / success 青绿 / warn 琥珀 / 红仅真正错误。"""
        self.assertIn(".console .l.i span{color:#cbd5e1}", HTML)
        self.assertIn(".console .l.s span{color:#67e8f9}", HTML)
        self.assertIn(".console .l.w span{color:#fcd34d}", HTML)
        self.assertIn(".console .l.e span{color:#fca5a5}", HTML)
        classify_fn = HTML.split("function classifyLog", 1)[1].split("function appendLog", 1)[0]
        self.assertIn("0 包", classify_fn, "0 包必须落到 warn，不能落到 error")

    def test_error_card_and_degrade_card_renderers_exist(self):
        self.assertIn("function failedResult", HTML)
        self.assertIn("function renderDegraded", HTML)
        self.assertIn("查看日志", HTML)
        self.assertIn("未捕获业务报文", HTML)
        self.assertIn("RTT 平均", HTML)

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
                mock.patch.object(server.logstore, "diag_log"), \
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


class DegradedEmptyCaptureTest(unittest.TestCase):
    """0 包优雅降级：目标可达 / 网关回退 / 都不可达三条分支。"""

    def _degrade(self, target: str, stats: list[dict], gateway: str = "192.168.31.1"):
        with mock.patch.object(server.diagnose, "_link_stats", side_effect=stats), \
                mock.patch.object(server.diagnose, "_resolve_ips",
                                  return_value=["93.184.216.34"]), \
                mock.patch.object(server.diagnose.winapi, "default_gateway",
                                  return_value=gateway):
            return server.diagnose.degraded_empty_capture_result(
                target=target, duration=10, interface="12",
                capture_error="0 packets", bpf="", logger=lambda _m: None)

    def test_target_reachable_reports_rtt_jitter_loss(self):
        res = self._degrade("baidu.com", [{
            "ok": True, "host": "baidu.com", "avg_ms": 12.5, "jitter_ms": 1.5,
            "loss_pct": 0.0, "sent": 4, "recv": 4}])
        self.assertIsNotNone(res)
        self.assertTrue(res["ok"] and res["degraded"])
        self.assertEqual(res["link"]["via"], "target")
        self.assertIn("RTT 平均 12.5 ms", res["plain"])
        self.assertIn("抖动 1.5 ms", res["plain"])
        self.assertIn("丢包 0%", res["plain"])
        self.assertIn("未捕获业务报文", res["headline"])

    def test_unreachable_target_falls_back_to_gateway(self):
        res = self._degrade("10.255.255.1", [
            {"ok": False, "host": "10.255.255.1", "avg_ms": 0, "jitter_ms": 0,
             "loss_pct": 100.0, "sent": 4, "recv": 0},
            {"ok": True, "host": "192.168.31.1", "avg_ms": 2.0, "jitter_ms": 0.5,
             "loss_pct": 0.0, "sent": 4, "recv": 4},
        ])
        self.assertIsNotNone(res)
        self.assertEqual(res["link"]["via"], "gateway")
        self.assertIn("10.255.255.1 当前没有响应", res["plain"])
        self.assertIn("默认网关 192.168.31.1", res["plain"])

    def test_no_link_info_returns_none_for_real_failure(self):
        res = self._degrade("10.255.255.1", [
            {"ok": False, "host": "10.255.255.1", "avg_ms": 0, "jitter_ms": 0,
             "loss_pct": 100.0, "sent": 4, "recv": 0},
            {"ok": False, "host": "192.168.31.1", "avg_ms": 0, "jitter_ms": 0,
             "loss_pct": 100.0, "sent": 4, "recv": 0},
        ])
        self.assertIsNone(res, "连降级信息都拿不到时必须走真正的失败分支")

    def test_worker_completes_with_degraded_result_instead_of_error(self):
        """服务端接线：empty_capture → 调链路体检 → JOB=done（不是红失败）。"""
        saved = dict(server.JOB)
        saved_logs = list(server.JOB["logs"])
        try:
            with mock.patch.object(
                    server.diagnose, "run_scan",
                    return_value={"ok": False, "empty_capture": True,
                                  "error": "0 packets", "bpf": "",
                                  "interface": "以太网"}), \
                    mock.patch.object(
                        server.diagnose, "degraded_empty_capture_result",
                        return_value={"ok": True, "degraded": True,
                                      "headline": "未捕获业务报文，但链路可达"}), \
                    mock.patch.object(server, "log"):
                server._worker("live", "10.255.255.1", 5, "12", None)
            self.assertEqual(server.JOB["state"], "done")
            self.assertTrue(server.JOB["result"].get("degraded"))
        finally:
            server.JOB.clear()
            server.JOB.update(saved)
            server.JOB["logs"] = saved_logs


class ProgressStatusTest(unittest.TestCase):
    """进度条 / 倒计时 / 重试文案需要的状态字段（后端加法）。"""

    def test_phase_walks_probe_capture_analyze_done(self):
        logs = [{"m": "探测网卡流量（每块 2 秒）"}]
        self.assertEqual(server._job_phase("running", logs), "探测网卡")
        logs.append({"m": "开始抓包：网卡[5] WLAN，时长 10s"})
        self.assertEqual(server._job_phase("running", logs), "抓包中")
        logs.append({"m": "开始分析报文 ..."})
        self.assertEqual(server._job_phase("running", logs), "分析中")
        logs.append({"m": "报告已生成：reports/x.md"})
        self.assertEqual(server._job_phase("running", logs), "完成")

    def test_attempt_parses_retry_log(self):
        self.assertEqual(server._job_attempt(
            [{"m": "开始抓包（第 2/3 块）：网卡[5] WLAN，时长 10s"}]),
            (2, 3))
        self.assertEqual(server._job_attempt([{"m": "开始抓包"}]), (0, 0))

    def test_passive_status_exposes_duration_and_phase(self):
        saved = dict(server.PJOB)
        try:
            server.PJOB.update({"state": "running", "duration": 10,
                                "started_at": time.time() - 2, "stop": False})
            with mock.patch.object(server, "engine_info", return_value={}):
                snap = server.passive_status()
            self.assertEqual(snap["duration"], 10)
            self.assertEqual(snap["phase"], "监听中")
        finally:
            server.PJOB.clear()
            server.PJOB.update(saved)

    def test_start_job_records_duration_for_countdown(self):
        saved = dict(server.JOB)
        saved_logs = list(server.JOB["logs"])
        try:
            with mock.patch.object(server.logstore, "diag_log"), \
                    mock.patch.object(server, "_worker"), \
                    mock.patch.object(server.threading, "Thread") as thread:
                thread.return_value.start.return_value = None
                server.start_job({"mode": "live", "target": "baidu.com",
                                  "duration": 12})
            self.assertEqual(server.JOB["duration"], 12)
        finally:
            server.JOB.clear()
            server.JOB.update(saved)
            server.JOB["logs"] = saved_logs


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
