"""C2 UI 静态接线：首屏自检 / 权限卡 / sessionStorage 表单保留。

界面是单文件 ``ui/index.html``，CI 没有浏览器，所以这里用**源码定位 + copy 表解析**
钉住行为接线（Puppeteer/Edge 只在本机证据里做一次 headless 验证，不进 CI）：

* 首屏「准备检查」：元素 id、``fetch /api/selfcheck``、重新检测 / 受限进入、
  ``first_run`` 判断（旧载荷没有该字段时绝不能把面板弹出来）；
* 权限卡：非管理员触发抓包 → ``POST /api/elevate``；取消只关卡片不发请求；
  已管理员不显示卡片、不请求提权；抓包入口不许绕过 ``checkAdmin()`` 静默失败；
* 表单保留：固定 key ``netdiag.form.v1`` 的写入 / 恢复 / 清空点，字段 id 与页面一致；
* 文案：新增 ``startup`` section 在 copy 表里，页面上不再保留旧的「表单不会带过去」。
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
COPY = json.loads((ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8"))
STARTUP = COPY["startup"]


def _slice(start: str, end: str, label: str) -> str:
    """取 ``start`` 到 ``end`` 之间的源码（找不到就让用例红）。"""
    if start not in HTML:
        raise AssertionError(f"{label}: 找不到起点 {start!r}")
    begin = HTML.index(start)
    if end not in HTML[begin:]:
        raise AssertionError(f"{label}: 找不到终点 {end!r}")
    return HTML[begin:begin + HTML[begin:].index(end)]


def _onclick(selector: str) -> str:
    """取 ``$(selector).onclick = ...`` 到下一个顶层 ``};`` 的源码。"""
    start = f'$("{selector}").onclick = '
    if start not in HTML:
        raise AssertionError(f"找不到 {selector} 的点击处理")
    begin = HTML.index(start)
    end = HTML.index("\n};", begin)
    return HTML[begin:end]


class StartupPanelStaticTest(unittest.TestCase):
    """首屏「准备检查」面板与后端接口的静态接线。"""

    def test_panel_elements_exist(self):
        for element_id in ("startup-mask", "startup-checks", "startup-recheck",
                           "startup-limited", "startup-msg"):
            with self.subTest(id=element_id):
                self.assertIn(f'id="{element_id}"', HTML)

    def test_panel_is_hidden_until_first_run_check(self):
        mask = _slice('<div class="mask hidden" id="startup-mask">',
                      "</div>\n</div>", "startup-mask")
        self.assertIn("startup-mask", mask)
        self.assertIn("startup-checks", mask)

    def test_panel_copy_comes_from_copy_table(self):
        for key in ("panel_title", "panel_sub", "panel_hint", "recheck",
                    "limited_enter"):
            with self.subTest(key=key):
                self.assertIn(f'data-copy="{key}"', HTML)
                self.assertIn(key, STARTUP)

    def test_fetches_selfcheck_and_ack(self):
        self.assertIn('fetch("/api/selfcheck"', HTML)
        self.assertIn('fetch("/api/selfcheck/ack"', HTML)
        self.assertIn("first_run", HTML)
        self.assertIn("location.reload()", HTML)

    def test_first_run_guard_is_old_payload_safe(self):
        # 旧后端没有 first_run 字段时必须不显示；== true 才显示。
        self.assertIn("data.first_run !== true", HTML)
        self.assertIn("旧后端", HTML)

    def test_recheck_and_limited_enter_buttons_wired(self):
        recheck = _onclick("#startup-recheck")
        self.assertIn("initStartup", recheck)
        self.assertIn('$("#startup-limited").onclick = () => { finishStartup(false); };',
                      HTML)
        finish = _slice("async function finishStartup", "async function initStartup",
                        "finishStartup")
        self.assertIn("ackFirstRun()", finish)

    def test_all_pass_auto_enters_and_acks(self):
        init = _slice("async function initStartup", "function waitForElevatedReload",
                      "initStartup")
        self.assertIn("data.first_run !== true", init)
        self.assertIn("finishStartup(true)", init)
        self.assertIn("checks.length === 5", init)


class PermissionCardStaticTest(unittest.TestCase):
    """权限卡：POST /api/elevate、取消不发请求、管理员不弹卡。"""

    def test_elevate_button_posts_to_elevate_after_saving_form(self):
        block = _onclick("#perm-elevate")
        self.assertIn('fetch("/api/elevate"', block)
        self.assertIn("saveForm();", block)
        self.assertLess(block.index("saveForm();"), block.index('fetch("/api/elevate"'),
                        "必须先把表单写进 sessionStorage，再发起提权")

    def test_cancel_only_closes_card(self):
        self.assertIn('$("#perm-cancel").onclick = closePerm;', HTML)
        self.assertNotIn('fetch("/api/elevate"',
                         HTML[HTML.index('$("#perm-cancel").onclick'):
                              HTML.index('$("#perm-cancel").onclick') + 80])

    def test_admin_environment_does_not_show_card(self):
        show = _slice("function showPermModal()", "function closePerm()",
                      "showPermModal")
        self.assertIn("IS_ADMIN === true", show)
        self.assertIn("return;", show)

    def test_capture_actions_go_through_check_admin(self):
        start = _slice("async function startCapture", "function stopRun",
                       "startCapture")
        self.assertIn("if (!checkAdmin()) return;", start,
                      "被动监听入口必须走权限卡")
        self.assertIn("cfg.needs_admin && !checkAdmin()", start,
                      "实时抓包入口必须走权限卡，不许静默失败")
        check = _slice("function checkAdmin()", "$(\"#perm-close\")", "checkAdmin")
        self.assertIn("showPermModal();", check)

    def test_elevate_failure_keeps_non_admin_and_explains(self):
        block = _onclick("#perm-elevate")
        self.assertIn("elevate_fail", block)
        self.assertIn("elevate_safe", block)
        self.assertIn("b.disabled = false;", block)
        self.assertNotIn("location.reload()", block,
                         "失败路径不许刷新/重启；只有成功后才等新进程")


class FormPersistenceStaticTest(unittest.TestCase):
    """sessionStorage 表单保留：固定 key、写入点、恢复点、清空点。"""

    def test_fixed_key(self):
        self.assertIn('const FORM_KEY = "netdiag.form.v1";', HTML)

    def test_write_point(self):
        save = _slice("function saveForm()", "function loadForm()", "saveForm")
        self.assertIn("sessionStorage.setItem(FORM_KEY", save)
        self.assertIn("sessionStorage.removeItem(FORM_KEY)", save,
                      "表单恢复默认值时也要清掉旧 key")

    def test_restore_point_in_boot(self):
        boot = _slice("async function boot()", "async function loadCaptures",
                      "boot")
        self.assertIn("restoreForm();", boot,
                      "页面加载必须恢复 sessionStorage 里的表单")
        restore = _slice("function restoreForm()", "function clearForm()",
                         "restoreForm")
        self.assertIn("sessionStorage.getItem", _slice(
            "function loadForm()", "function clearFormStorage()", "loadForm"))
        for name in ("#target", "#duration", "#iface", "#pcap-select",
                     "#probe-target", "#probe-port"):
            with self.subTest(field=name):
                self.assertIn(f'"{name}"', restore)

    def test_clear_points(self):
        clear = _slice("function clearForm()", "function wireFormPersistence()",
                       "clearForm")
        self.assertIn("clearFormStorage();", clear)
        self.assertIn("sessionStorage.removeItem(FORM_KEY)",
                      _slice("function clearFormStorage()", "function restoreForm()",
                             "clearFormStorage"))
        for selector in ("#form-reset", "#probe-reset"):
            with self.subTest(selector=selector):
                self.assertIn(f'id="{selector[1:]}"', HTML)
                self.assertIn(f'$("{selector}").onclick = clearForm;', HTML)

    def test_all_form_fields_are_listened(self):
        for field in ("#target", "#duration", "#iface", "#engine", "#pcap-select",
                      "#probe-target", "#probe-port", "#probe-count",
                      "#probe-proto", "#shadow-toggle", "#probe-path-toggle"):
            with self.subTest(field=field):
                self.assertIn(f'"{field}"', HTML)
        wire = _slice("function wireFormPersistence()", "function setStartupMsg",
                      "wireFormPersistence")
        self.assertIn('addEventListener("input", saveForm)', wire)
        self.assertIn('addEventListener("change", saveForm)', wire)
        self.assertIn("wireFormPersistence();", HTML)

    def test_pcap_restore_after_async_load(self):
        load = _slice("async function loadCaptures()", "/* ---------- 上传",
                      "loadCaptures")
        self.assertIn("FORM_CACHE", load)
        self.assertIn('sel.value = wanted', load)


class CopySourceStaticTest(unittest.TestCase):
    """文案唯一来源：startup section 覆盖新面板/权限卡，旧长句已删除。"""

    def test_startup_section_has_required_keys(self):
        for key in ("panel_title", "panel_sub", "panel_hint", "checking",
                    "recheck", "limited_enter", "all_ok", "some_failed",
                    "ack_failed", "elevate_title", "elevate_sub", "elevate_hint",
                    "elevate_wait", "elevate_ok", "elevate_fail", "elevate_safe",
                    "elevate_button", "elevate_cancel", "check_python",
                    "check_tshark", "check_npcap", "check_port", "check_admin",
                    "python_ok", "python_low", "tshark_ok", "tshark_missing",
                    "npcap_ok", "npcap_missing", "port_running", "port_free",
                    "port_busy", "admin_ok", "admin_no", "form_reset"):
            with self.subTest(key=key):
                self.assertIn(key, STARTUP)
                self.assertTrue(str(STARTUP[key]).strip(), f"{key} 不能为空")

    def test_elevate_hint_promises_form_is_kept(self):
        self.assertIn("自动保留", STARTUP["elevate_hint"])
        self.assertNotIn("当前表单不会自动带过去", HTML,
                         "旧文案与 sessionStorage 表单保留矛盾，必须删掉")

    def test_ui_fetches_copy_with_payload(self):
        self.assertIn("ui_copy", HTML)
        self.assertIn("data.ui_copy", HTML)
        self.assertIn("applyCopy()", HTML)


class ServerWiringStaticTest(unittest.TestCase):
    """后端路由以加法形式接上（不改既有 /api/doctor）。"""

    def test_server_has_selfcheck_routes(self):
        server = (ROOT / "core" / "server.py").read_text(encoding="utf-8")
        self.assertIn('path == "/api/selfcheck"', server)
        self.assertIn('parsed.path == "/api/selfcheck/ack"', server)
        self.assertIn("selfcheck.collect()", server)
        self.assertIn("selfcheck.ack_first_run()", server)

    def test_selfcheck_module_has_no_write_in_collect(self):
        source = (ROOT / "core" / "selfcheck.py").read_text(encoding="utf-8")
        collect = source[source.index("def collect("):source.index("__all__")]
        for forbidden in ("write_text", "mkdir", "relaunch_as_admin", "Popen",
                          "subprocess"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, collect,
                                 "collect() 必须纯读：不写文件/不触发 UAC/不抓包")


if __name__ == "__main__":
    unittest.main(verbosity=2)
