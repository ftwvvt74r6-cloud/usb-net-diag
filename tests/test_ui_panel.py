"""H4：右侧统一面板（运行进度 + 运行日志 + 结果卡同一容器）。

口径（``H-SPEC`` H4 / V6）：

* 运行中 / 结束后右侧是**一个整体面板**（同一背景，禁止黑色 console 块）；
* 顶部进度条 + 倒计时 + 阶段 + 第几块网卡；中部运行日志等宽、浅灰中性面、
  ``›`` 前缀、自动滚到底、运行中实时追加（不丢行不重复）；
* 结束后日志自动折叠为一行「运行日志（展开）」，结果卡紧接在同一面板下方；
* 正常 / 降级 / 失败 / 被动监听 / 探针路径都写入同一 ``#result``（或同一面板里的探针结果区）。

CI 没有浏览器：DOM/源码断言 + Node 跑纯函数段；真实 headless 截图证据在
``D:\\utest\\review\\h-samples\\ui\\`` 单独留档（不进 CI）。
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")

NODE = shutil.which("node")
LOG_PURE_START = "/* ---------- 运行日志增量：纯函数"
LOG_PURE_END = "/* ---------- 运行日志增量结束 ---------- */"


def _slice(start: str, end: str, label: str) -> str:
    """取 ``start`` 到 ``end`` 之间的源码（找不到就让用例红）。"""
    if start not in HTML:
        raise AssertionError(f"{label}: 找不到起点 {start!r}")
    begin = HTML.index(start)
    if end not in HTML[begin:]:
        raise AssertionError(f"{label}: 找不到终点 {end!r}")
    return HTML[begin:begin + HTML[begin:].index(end)]


def _workpanel() -> str:
    return _slice('<section class="workpanel" id="workpanel">',
                  "</section><!-- /workpanel -->", "workpanel")


def _run_log_pure_harness() -> dict:
    if not NODE:
        raise unittest.SkipTest("本机没有 Node.js：运行日志纯函数用例跳过（CI windows 自带）")
    pure = _slice(LOG_PURE_START, LOG_PURE_END, "运行日志纯函数")
    harness = """
const out = {};
out.all = newLogsSince([1, 2, 3], 0);
out.tail = newLogsSince([1, 2, 3, 4, 5], 2);
out.reset = newLogsSince([1, 2, 3, 4], 10);
out.nullish = newLogsSince(null, 0);
out.empty = newLogsSince([], 5);
out.negative = newLogsSince([1, 2], -3);
out.same = newLogsSince([1, 2], 2);
console.log(JSON.stringify(out));
"""
    with tempfile.TemporaryDirectory(prefix="netdiag-h4-js-") as tmp:
        script = Path(tmp) / "run_log_pure.js"
        script.write_text(pure + harness, encoding="utf-8", newline="\n")
        proc = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    if proc.returncode != 0:
        raise AssertionError(f"Node 运行日志纯函数执行失败：{proc.stderr[-2000:]}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


class UnifiedPanelStructureTest(unittest.TestCase):
    """一个面板：进度 → 运行日志 → 结果，DOM 顺序固定。"""

    def test_run_console_and_result_share_one_workpanel(self):
        panel = _workpanel()
        for element_id in ("runpanel", "consolepanel", "result", "probe-panel"):
            with self.subTest(id=element_id):
                self.assertIn(f'id="{element_id}"', panel)
        order = [panel.index('id="runpanel"'), panel.index('id="consolepanel"'),
                 panel.index('id="result"'), panel.index('id="probe-panel"')]
        self.assertEqual(order, sorted(order),
                         "同一面板内顺序必须是 进度 → 运行日志 → 结果 → 探针结果")

    def test_only_one_console_and_it_is_inside_main(self):
        self.assertEqual(HTML.count('id="consolepanel"'), 1,
                         "只允许一个运行日志容器（不能既有底部固定条又有面板内一份）")
        self.assertEqual(HTML.count('<section class="consolepanel'), 1)
        aside = HTML.split("<aside", 1)[1].split("</aside>", 1)[0]
        main = HTML.split('<main class="main">', 1)[1].split("</main>", 1)[0]
        self.assertNotIn('id="consolepanel"', aside)
        self.assertIn('id="consolepanel"', main)
        self.assertIn('id="consolepanel"', _workpanel())

    def test_no_black_console_or_json_block(self):
        self.assertNotIn("background:#0b1220", HTML,
                         "H4 起禁止黑色 console 块；机器可读 JSON 也改成浅灰面")
        self.assertIn(".console{background:#f8fafc", HTML)
        self.assertIn(".json{background:#f8fafc", HTML)

    def test_console_is_mono_with_prefix_and_light_neutral_rows(self):
        self.assertIn(".console{background:#f8fafc", HTML)
        self.assertIn('content:"›"', HTML)
        self.assertIn("var(--mono)", HTML)
        # 颜色语义：info 灰白 / success 青绿 / warn 琥珀 / 仅真错误红
        for token in (".console .l.i span{color:#475569}",
                      ".console .l.s span{color:#0f766e}",
                      ".console .l.w span{color:#b45309}",
                      ".console .l.e span{color:#b91c1c}"):
            with self.subTest(token=token):
                self.assertIn(token, HTML)

    def test_progress_header_has_phase_count_and_attempt(self):
        panel = _workpanel()
        for element_id in ("run-phase", "run-count", "run-bar", "run-barwrap",
                           "run-stages", "run-retry"):
            with self.subTest(id=element_id):
                self.assertIn(f'id="{element_id}"', panel)
        self.assertIn("剩余 ", HTML)
        self.assertIn("共 ", HTML)
        self.assertIn("块网卡", HTML)
        self.assertIn("STAGE_SETS", HTML)


class ConsoleFoldStaticTest(unittest.TestCase):
    """结束后自动折叠为一行「运行日志（展开）」，点击可展开/收起。"""

    def test_initial_markup_is_one_line_collapsed(self):
        block = _slice('<section class="consolepanel collapsed" id="consolepanel"',
                       '<div id="result">', "console markup")
        self.assertIn('aria-expanded="false"', block)
        self.assertIn("运行日志", block)
        self.assertIn("（展开）", block)
        self.assertIn('id="console-state"', block)
        self.assertIn("采集控制台", block, "旧名保留，便于老用户/测试定位")
        self.assertIn("Packet Console", block)

    def test_toggle_updates_class_aria_and_label(self):
        fold = _slice("function setConsoleCollapsed", "function classifyLog",
                      "setConsoleCollapsed")
        self.assertIn('classList.toggle("collapsed"', fold)
        self.assertIn('setAttribute("aria-expanded"', fold)
        self.assertIn("（展开）", fold)
        self.assertIn("（收起）", fold)
        toggle = _slice('$("#console-toggle").onclick', 'async function pollPassive',
                        "console-toggle")
        self.assertIn("setConsoleCollapsed(!panel.classList.contains(\"collapsed\"))",
                      toggle)

    def test_running_expands_and_terminal_states_collapse(self):
        running = _slice("function runningResult", "function adviceFor",
                         "runningResult")
        self.assertIn("expandConsole()", running)
        stop = _slice("function stopRun", "function runningResult", "stopRun")
        self.assertIn("collapseConsole()", stop)
        self.assertIn("collapseConsole()", _slice(
            'if (s.state === "done")', '} else if (s.state === "error")', "done branch"))
        self.assertIn("collapseConsole()", _slice(
            'if (s.state === "error")', '} else if (s.state === "running")',
            "error branch"))
        self.assertIn("collapseConsole()", _slice(
            "function stopPassiveUI", "async function pollPassive", "stopPassiveUI"))
        probe = _slice("async function runProbe", '$("#probe-run").onclick', "runProbe")
        self.assertGreaterEqual(probe.count("collapseConsole()"), 2,
                                "探针成功/失败都要回到折叠态")

    def test_true_error_expands_then_result_collapses(self):
        append = _slice("function appendLog", '$("#console-toggle").onclick',
                        "appendLog")
        self.assertIn('if (cls === "e")', append)
        self.assertIn("expandConsole()", append)
        wire = _slice("function wireFailureActions", "async function loadIfacesForError",
                      "wireFailureActions")
        self.assertIn("expandConsole()", wire, "失败卡的「查看日志」必须展开日志")
        self.assertNotIn('$("#consolepanel").classList.remove("collapsed")', wire)


class LiveLogAppendTest(unittest.TestCase):
    """运行中实时追加：按 count 增量切片，不丢行、不重复。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.out = _run_log_pure_harness()

    def test_new_logs_are_incremental_and_ordered(self):
        self.assertEqual(self.out["all"], [1, 2, 3])
        self.assertEqual(self.out["tail"], [3, 4, 5])
        self.assertEqual(self.out["same"], [])

    def test_backend_reset_restarts_from_zero_without_loss(self):
        self.assertEqual(self.out["reset"], [1, 2, 3, 4],
                         "后端日志被清空/重置时必须从头补，不能丢行")

    def test_nullish_and_negative_count_are_safe(self):
        self.assertEqual(self.out["nullish"], [])
        self.assertEqual(self.out["empty"], [])
        self.assertEqual(self.out["negative"], [1, 2])

    def test_poll_uses_incremental_helper_not_blind_slice(self):
        poll = _slice("async function poll()", "/* ---------- 被动监听",
                      "poll")
        self.assertIn("newLogsSince(s.logs, lastLogCount)", poll)
        self.assertNotIn("(s.logs || []).slice(lastLogCount)", poll,
                         "轮询不能再用盲 slice：日志重置时会丢行")
        passive = _slice("async function pollPassive", 'if (p.state === "running")',
                         "pollPassive")
        self.assertIn("newLogsSince(s.logs, lastLogCount)", passive)

    def test_append_log_writes_row_caps_and_autoscrolls(self):
        append = _slice("function appendLog", '$("#console-toggle").onclick',
                        "appendLog")
        for token in ('document.createElement("div")', 'row.className = "l " + cls',
                      'c.appendChild(row)', "c.scrollTop = c.scrollHeight",
                      "c.children.length > 400", "等待任务"):
            with self.subTest(token=token):
                self.assertIn(token, append)


class ResultPathsStayInPanelTest(unittest.TestCase):
    """正常 / 降级 / 失败 / 被动监听 / 旧载荷都写同一个结果区。"""

    def test_all_result_renderers_target_result_container(self):
        for start, end, label in (
            ("function render(res, actions)", "/* ---------- 0 包降级结果页", "render"),
            ("function renderDegraded(res, actions)", "/* ---------- 链路体检",
             "renderDegraded"),
            ("function renderFailureCard(kind, why)", "function failedResult",
             "renderFailureCard"),
            ("function failedResult(title, detail, code)", "function classifyLog",
             "failedResult"),
            ("function renderPassiveEmpty(res)", "function renderPassive(res)",
             "renderPassiveEmpty"),
            ("function renderPassive(res)", "/* ---------- 结果渲染",
             "renderPassive"),
        ):
            block = _slice(start, end, label)
            with self.subTest(label=label):
                self.assertIn('$("#result").innerHTML', block)
                self.assertIn("showResultArea()", block,
                              "进入结果区前必须确保结果容器可见（统一面板）")

    def test_degraded_path_has_conclusion_card_in_same_result_area(self):
        degraded = _slice("function renderDegraded", "/* ---------- 链路体检",
                          "renderDegraded")
        self.assertIn("+ conclusionCard(res)", degraded)
        self.assertIn("wireConclusionActions(res);", degraded)
        self.assertIn("showResultArea()", degraded)

    def test_failure_path_has_conclusion_card_in_same_result_area(self):
        failure = _slice("function renderFailureCard", "function failedResult",
                         "renderFailureCard")
        self.assertIn("+ conclusionCard(null)", failure)
        self.assertIn("wireConclusionActions(null);", failure)


if __name__ == "__main__":
    unittest.main(verbosity=2)
