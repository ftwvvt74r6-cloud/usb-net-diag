"""G5 UI：上次结果提示条 + 设置页后台退出（源码定位 + Node 纯函数，不跑浏览器）。

守的口径（``G-SPEC`` G5 / V8）：

* 页面加载（``DOMContentLoaded``）与 ``pageshow``（``event.persisted``，bfcache）
  都请求 ``/api/last-run``；有记录才渲染提示条，无记录必须隐藏（**不得误报**）；
* 提示条文案/时间格式来自 ``copy/zh-CN.json`` 的 ``last_run``：本地时区
  「今天 14:32 / 昨天 09:10」，不是固定字符串；
* ``[查看]`` 拉 ``/api/last-run/result`` 后用现有 ``render()`` / ``renderDegraded()``
  渲染；``full_result=false`` 时按钮禁用并说明「只能看摘要」；
* ``[开始新任务]`` **POST** ``/api/last-run/clear``，清结果区回默认首屏、提示条消失；
* 设置页「网卡与运行信息」有「后台空闲退出：<idle_exit_min> 分钟」+「立即退出后台」
  （复用 ``POST /api/quit``；本文件只断言接了这条请求，**绝不真杀测试进程**）。

页面是单文件 ``ui/index.html``，CI 没有 Edge：这里用源码定位钉行为接线；纯函数段
用 Node 直接跑（本机/CI windows 自带 node，缺了跳过），headless 截图证据在
``D:\\utest\\review\\g-samples\\`` 单独留档。
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import _uisrc  # noqa: E402
HTML = _uisrc.html()
#: P1 起样式搬进 ``ui/app.css``；样式类断言改读这个文件，
#: 断言内容与严格程度与拆分前完全一致（不是放宽）。
CSS = _uisrc.css()
COPY = json.loads((ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8"))
LAST_RUN_COPY = COPY["last_run"]
SETTINGS_COPY = COPY["settings"]

PURE_START = "/* ---------- 上次结果提示条：纯函数"
PURE_END = "/* ---------- 上次结果提示条结束 ---------- */"
NODE = shutil.which("node")


def _slice(start: str, end: str, label: str) -> str:
    """取 ``start`` 到 ``end`` 之间的源码（找不到就让用例红）。"""
    if start not in HTML:
        raise AssertionError(f"{label}: 找不到起点 {start!r}")
    begin = HTML.index(start)
    if end not in HTML[begin:]:
        raise AssertionError(f"{label}: 找不到终点 {end!r}")
    return HTML[begin:begin + HTML[begin:].index(end)]


def _pure_js() -> str:
    """抽取标记过的纯函数段（不碰 DOM，可直接在 Node 里跑）。"""
    return _slice(PURE_START, PURE_END, "last-run pure functions")


def _run_pure_harness() -> dict:
    """用 Node 执行提示条纯函数，返回各输入的输出。"""
    if not NODE:
        raise unittest.SkipTest("本机没有 Node.js：提示条纯函数用例跳过（CI windows 自带）")
    prelude = (
        f"const COPY = {json.dumps(LAST_RUN_COPY, ensure_ascii=False)};\n"
        f"const SETTINGS = {json.dumps(SETTINGS_COPY, ensure_ascii=False)};\n"
        "const MODES = {live: {label: \"单目标诊断\"}, scan: {label: \"全网体检\"},\n"
        "               offline: {label: \"分析抓包文件\"}};\n"
    )
    harness = """
const out = {};
const now = new Date(2026, 10, 9, 10, 0, 0).getTime();
const at = (h, m) => new Date(2026, 10, 9, h, m, 0).toISOString();
const yesterday = new Date(2026, 10, 8, 9, 10, 0).toISOString();
const older = new Date(2026, 9, 31, 14, 32, 0).toISOString();
const rec = {time: at(9, 5), mode: "live", target: "example.com",
             ok: true, full_result: true};
out.today = lastRunBannerText(rec, now, COPY, MODES);
out.yesterday = lastRunBannerText(
  {time: yesterday, mode: "scan", target: "", ok: true, full_result: true},
  now, COPY, MODES);
out.older = lastRunBannerText(
  {time: older, mode: "offline", target: "sample.pcap", ok: true, full_result: false},
  now, COPY, MODES);
out.missing = lastRunBannerText(null, now, COPY, MODES);
out.empty = lastRunBannerText({}, now, COPY, MODES);
out.failed = lastRunBannerText(
  {time: at(8, 0), mode: "live", target: "example.com", ok: false, full_result: false},
  now, COPY, MODES);
out.unknown_mode = lastRunBannerText(
  {time: at(8, 0), mode: "weird", target: "x", ok: true, full_result: true},
  now, COPY, MODES);
out.can_view = [lastRunCanView({full_result: true}),
                lastRunCanView({full_result: false}),
                lastRunCanView(null)];
out.note = lastRunNote({full_result: false}, COPY);
out.note_viewable = lastRunNote({full_result: true}, COPY);
out.bad_time = lastRunBannerText(
  {time: "not-a-date", mode: "live", target: "x", ok: true, full_result: true},
  now, COPY, MODES);
console.log(JSON.stringify(out));
"""
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "last_run_pure.js"
        script.write_text(prelude + _pure_js() + harness, encoding="utf-8")
        proc = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                              encoding="utf-8", timeout=60)
    if proc.returncode != 0:
        raise AssertionError(f"Node 执行提示条纯函数失败：\n{proc.stderr[-2000:]}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


class LastRunBannerMarkupTest(unittest.TestCase):
    """提示条 DOM：默认隐藏、两个按钮、正文/说明槽位，位置在结果栏之前。"""

    def test_banner_slots_and_controls_exist(self):
        for element_id in ("lastrun-banner", "lastrun-text", "lastrun-view",
                           "lastrun-new", "lastrun-note"):
            with self.subTest(id=element_id):
                self.assertIn(f'id="{element_id}"', HTML)
        self.assertIn('<div class="lastrun hidden" id="lastrun-banner"', HTML,
                      "刷新前默认不显示，避免误报")
        banner = _slice('<div class="lastrun hidden" id="lastrun-banner"',
                        '<div class="resultbar">', "banner markup")
        self.assertIn('aria-live="polite"', banner)
        self.assertIn(">查看<", banner)
        self.assertIn(">开始新任务<", banner)

    def test_banner_sits_above_result_area(self):
        self.assertLess(HTML.index('id="lastrun-banner"'),
                        HTML.index('<div class="resultbar">'),
                        "提示条必须在结果区顶部，不能挤进左栏/右侧面板结构")
        self.assertGreater(HTML.index('id="lastrun-banner"'),
                           HTML.index('<div class="main-scroll" id="main-scroll">'))

    def test_banner_has_neutral_notice_style(self):
        css = CSS[CSS.index("/* 上次结果提示条（G5）"):
                  CSS.index("/* 侧栏固定在底部")]
        self.assertIn(".lastrun", css)
        self.assertIn("display:flex", css)
        self.assertIn(".lastrun .lr-note", css)


class LastRunSyncWiringTest(unittest.TestCase):
    """加载 / bfcache 同步：两边都以服务端为准，无记录不渲染。"""

    def test_dom_content_loaded_and_pageshow_persisted_sync(self):
        self.assertIn('document.addEventListener("DOMContentLoaded", syncLastRun);', HTML)
        page_show = _slice('window.addEventListener("pageshow"',
                           "/* ---------- 上次结果提示条：DOM 接线结束", "pageshow")
        self.assertIn("e.persisted", page_show)
        self.assertIn("syncLastRun()", page_show)
        boot_chain = HTML[HTML.index("boot().then(poll)"):]
        self.assertIn(".then(syncLastRun)", boot_chain,
                      "首屏 boot 完成后也要同步一次，避免 /api/app 文案晚到")

    def test_sync_fetches_last_run_and_hides_when_no_record(self):
        sync = _slice("async function syncLastRun", "async function viewLastRun", "sync")
        self.assertIn('fetch("/api/last-run")', sync)
        self.assertIn("if (r.ui_copy && r.ui_copy.last_run)", sync)
        self.assertIn("if (r.last) paintLastRun(r.last); else", sync)
        self.assertIn("hideLastRun()", sync)
        self.assertIn("LAST_RUN_BUSY", sync, "并发请求要互斥，避免旧响应覆盖新状态")

    def test_paint_only_shows_when_banner_text_is_non_empty(self):
        paint = _slice("function paintLastRun", "async function syncLastRun", "paint")
        self.assertIn("lastRunBannerText(LAST_RUN", paint)
        self.assertIn("if (!bar || !text)", paint)
        self.assertIn("hideLastRun()", paint)
        self.assertIn('$("#lastrun-text").textContent = text;', paint)


class LastRunActionsTest(unittest.TestCase):
    """[查看] 恢复结果；full_result=false 禁用；[开始新任务] 清服务端并回首屏。"""

    def test_view_calls_result_endpoint_and_renders(self):
        view = _slice("async function viewLastRun", "async function startNewTask", "view")
        self.assertIn('fetch("/api/last-run/result")', view)
        self.assertIn("if (r.result.degraded) renderDegraded(r.result", view)
        self.assertIn("else render(r.result", view)
        self.assertIn("CONCLUSION_COPY = r.result.ui_copy.conclusion", view,
                      "恢复的结果也要带结论卡文案，不能退回旧数据降级")

    def test_view_button_disabled_when_summary_only(self):
        view = _slice("async function viewLastRun", "async function startNewTask", "view")
        self.assertIn("if (!lastRunCanView(LAST_RUN)) return;", view)
        paint = _slice("function paintLastRun", "async function syncLastRun", "paint")
        self.assertIn("const canView = lastRunCanView(LAST_RUN);", paint)
        self.assertIn("view.disabled = !canView;", paint)
        self.assertIn("LAST_RUN_COPY.view_disabled", paint)
        self.assertIn("lastRunNote(LAST_RUN", paint)

    def test_new_task_posts_clear_and_resets_first_screen(self):
        new_task = _slice("async function startNewTask",
                          'if ($("#lastrun-view"))', "startNewTask")
        self.assertIn('fetch("/api/last-run/clear", { method: "POST" })', new_task)
        self.assertIn("if (!r || !r.ok)", new_task)
        self.assertIn("LAST_RUN = null;", new_task)
        self.assertIn("LAST_RESULT = null;", new_task)
        self.assertIn("hideLastRun();", new_task)
        self.assertIn('setMode("scan");', new_task,
                      "「开始新任务」必须回默认首屏（不是停在旧结果）")
        self.assertLess(new_task.index("fetch(\"/api/last-run/clear\""),
                        new_task.index("setMode(\"scan\");"),
                        "先清服务端再重置界面：刷新后才不会再出现")

    def test_new_run_hides_stale_banner(self):
        start = _slice("async function startCapture()", "function stopRun", "startCapture")
        self.assertIn("hideLastRun();", start)
        passive = _slice("async function startPassive", "function stopPassiveUI",
                         "startPassive")
        self.assertIn("hideLastRun();", passive)
        probe = _slice("async function runProbe", "$(\"#probe-run\").onclick",
                       "runProbe")
        self.assertIn("hideLastRun();", probe)


class LastRunPureFunctionTest(unittest.TestCase):
    """纯函数：本地时区可读时间、无记录不误报、摘要只能看摘要。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.out = _run_pure_harness()

    def test_today_text_uses_copy_template_time_mode_target(self):
        expected = (LAST_RUN_COPY["banner"]
                    .replace("{time}", f'{LAST_RUN_COPY["today"]} 09:05')
                    .replace("{mode}", "单目标诊断")
                    .replace("{target}", "example.com"))
        self.assertEqual(self.out["today"], expected)

    def test_yesterday_and_older_dates_are_human_readable(self):
        self.assertIn(LAST_RUN_COPY["yesterday"] + " 09:10", self.out["yesterday"])
        self.assertIn("全网", self.out["yesterday"], "全网体检空目标回退成「全网」")
        self.assertIn("10-31 14:32", self.out["older"])

    def test_no_record_does_not_render(self):
        self.assertEqual(self.out["missing"], "")
        self.assertEqual(self.out["empty"], "")

    def test_bad_time_is_explicit_instead_of_silent(self):
        # 有记录但时间解析不了：显式写「时间未知」，不假装没有这条记录。
        self.assertIn(LAST_RUN_COPY["time_unknown"], self.out["bad_time"])
        self.assertIn("x", self.out["bad_time"])

    def test_failed_run_is_still_explicit(self):
        self.assertTrue(self.out["failed"].endswith(LAST_RUN_COPY["failed_suffix"]))
        self.assertIn(LAST_RUN_COPY["today"], self.out["failed"])

    def test_unknown_mode_uses_copy_fallback(self):
        self.assertIn(LAST_RUN_COPY["mode_unknown"], self.out["unknown_mode"])

    def test_summary_only_disables_view_and_has_note(self):
        self.assertEqual(self.out["can_view"], [True, False, False])
        self.assertEqual(self.out["note"], LAST_RUN_COPY["summary_only"])
        self.assertEqual(self.out["note_viewable"], "")


class SettingsServicePanelTest(unittest.TestCase):
    """设置页：后台空闲退出说明 + 立即退出后台（复用 /api/quit）。"""

    def test_markup_has_idle_info_and_quit_button(self):
        for element_id in ("settings-service-title", "idle-exit-info",
                           "idle-exit-hint", "quit-background"):
            with self.subTest(id=element_id):
                self.assertIn(f'id="{element_id}"', HTML)
        self.assertIn('data-view="sysinfo"', HTML, "放在设置 → 网卡与运行信息里")
        sysinfo = _slice('id="view-sysinfo"', 'id="view-export"', "sysinfo view")
        self.assertIn('id="idle-exit-info"', sysinfo)
        self.assertIn('id="quit-background"', sysinfo)
        self.assertIn("立即退出后台", sysinfo)

    def test_idle_copy_mentions_minutes_and_config_key(self):
        self.assertIn("{minutes}", SETTINGS_COPY["idle_exit"])
        self.assertIn("idle_exit_min", SETTINGS_COPY["idle_exit"])
        self.assertTrue(SETTINGS_COPY["idle_exit_label"].strip())
        self.assertIn("已关闭", SETTINGS_COPY["idle_exit_off"])
        self.assertIn("立即退出后台", SETTINGS_COPY["quit_background"])

    def test_paint_service_panel_uses_copy_and_app_info(self):
        paint = _slice("function paintServicePanel", "function paintAIPanel", "paintServicePanel")
        self.assertIn("SETTINGS_COPY", paint)
        self.assertIn("idle_exit_min", paint)
        self.assertIn('$("#idle-exit-info")', paint)
        self.assertIn('$("#quit-background")', paint)
        self.assertIn('idle > 0', paint)
        self.assertIn("idle_exit_off", paint)
        self.assertIn("{minutes}", paint)

    def test_settings_panel_painted_from_app_payload(self):
        self.assertIn("paintServicePanel(app);", HTML)
        load_app = _slice("async function loadAppInfo",
                          "/* ---------------- 导出诊断包", "loadAppInfo")
        self.assertIn("r.ui_copy.settings", load_app)
        self.assertIn("paintServicePanel(r)", load_app)

    def test_quit_background_reuses_api_quit_without_killing_tests(self):
        quit_fn = _slice("async function quitService", "async function quitApp", "quitService")
        self.assertIn('fetch("/api/quit", { method: "POST" })', quit_fn)
        self.assertIn("quit_confirm", quit_fn)
        self.assertIn("$(\"#quit-app\").onclick = quitApp;", HTML,
                      "顶部「退出」入口必须保留")
        self.assertIn('$("#quit-background").onclick = () => quitService($("#quit-background"));',
                      HTML)
        self.assertIn("async function quitApp() {", HTML)
        self.assertIn('return quitService($("#quit-app"));', HTML)

    def test_quit_button_is_not_a_dead_end(self):
        """点击后要么退出、要么回显失败；不许把按钮禁用了却没有任何反馈。"""
        quit_fn = _slice("async function quitService", "async function quitApp", "quitService")
        self.assertIn("button.disabled = false;", quit_fn)
        self.assertIn("alert(", quit_fn, "失败必须明确告诉用户，不能静默")


class LastRunCopyTableTest(unittest.TestCase):
    """copy 表：提示条所有用户可见文案都从这里来，不散落在 HTML 里。"""

    def test_required_keys_are_non_empty(self):
        for key in ("banner", "view", "view_disabled", "new_task", "summary_only",
                    "failed_suffix", "restoring", "restore_failed", "cleared",
                    "clear_failed", "today", "yesterday", "time_unknown",
                    "mode_unknown", "target_all"):
            with self.subTest(key=key):
                self.assertTrue(str(LAST_RUN_COPY.get(key, "")).strip(), f"{key} 不能为空")

    def test_banner_keeps_three_placeholders(self):
        for token in ("{time}", "{mode}", "{target}"):
            with self.subTest(token=token):
                self.assertIn(token, LAST_RUN_COPY["banner"])
        self.assertIn("{reason}", LAST_RUN_COPY["restore_failed"])
        self.assertIn("{reason}", LAST_RUN_COPY["clear_failed"])

    def test_settings_section_required_keys(self):
        for key in ("service_title", "idle_exit_label", "idle_exit",
                    "idle_exit_off", "idle_exit_hint",
                    "quit_background", "quit_confirm", "quitting",
                    "quit_done_title", "quit_done_hint"):
            with self.subTest(key=key):
                self.assertTrue(str(SETTINGS_COPY.get(key, "")).strip(), f"{key} 不能为空")


if __name__ == "__main__":
    unittest.main(verbosity=2)
