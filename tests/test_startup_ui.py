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
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
#: P1 起样式在 ``ui/app.css``；样式类断言改读这个文件（内容与严格程度不变）。
CSS = (ROOT / "ui" / "app.css").read_text(encoding="utf-8")
COPY = json.loads((ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8"))
STARTUP = COPY["startup"]

#: 纯 JS 能力锁矩阵用 Node 直接跑（不启浏览器）；CI windows 自带 node，缺了跳过。
NODE = shutil.which("node")
LOCK_START = "/* ---------- 能力锁矩阵：纯函数"
LOCK_END = "/* ---------- 能力锁矩阵结束 ---------- */"


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


def _check(key: str, ok: bool) -> dict:
    """构造一项与后端 ``collect()`` 同结构的检查结果（只填 UI 用得到的键）。"""
    return {
        "key": key,
        "name": key,
        "ok": ok,
        "detail": f"{key}-detail",
        "fix_kind": "none" if ok else "url",
        "fix_url": "" if ok else f"https://example.invalid/{key}",
        "fix_command": "",
        "impact": f"{key}-impact（缺了会怎样）",
        "doc_url": "docs/startup.md",
    }


def _checks(tshark: bool = True, npcap: bool = True, python: bool = True,
            port: bool = True, admin: bool = True) -> list[dict]:
    return [_check("python", python), _check("tshark", tshark),
            _check("npcap", npcap), _check("port", port), _check("admin", admin)]


def _caps(tshark: bool = True, npcap: bool = True, scapy: bool = False) -> dict:
    """按 ``core/selfcheck.py::capabilities()`` 的真值表构造能力矩阵（B1：passive 要 Npcap）。"""
    live = tshark and npcap
    offline = tshark
    passive = npcap and (tshark or scapy)
    missing = {}
    if not offline:
        missing["offline"] = "tshark"
    if not live:
        if not tshark and not npcap:
            missing["live"] = "tshark|npcap"
        else:
            missing["live"] = "tshark" if not tshark else "npcap"
    if not passive:
        reasons = []
        if not (tshark or scapy):
            reasons.append("tshark|scapy")
        if not npcap:
            reasons.append("npcap")
        missing["passive"] = "|".join(reasons)
    return {"probe": True, "offline": offline, "live": live, "passive": passive,
            "reports": True, "settings": True, "missing": missing, "scapy": scapy}


def _payload(tshark: bool = True, npcap: bool = True, scapy: bool = False,
             first_run: bool = False, with_caps: bool = True) -> dict:
    data = {
        "ok": tshark and npcap,
        "version": "0.3.2",
        "first_run": first_run,
        "checks": _checks(tshark=tshark, npcap=npcap),
        "ui_copy": {"startup": STARTUP},
    }
    if with_caps:
        data["capabilities"] = _caps(tshark=tshark, npcap=npcap, scapy=scapy)
    return data


def _lock_js() -> str:
    """抽取 ``ui/index.html`` 里标记过的纯函数段（能力锁矩阵，不碰 DOM）。"""
    begin = HTML.index(LOCK_START)
    end = HTML.index(LOCK_END, begin)
    return HTML[begin:end]


def _run_lock_harness(payloads: dict) -> dict:
    """用 Node 在无浏览器环境执行纯 JS 锁矩阵，返回各载荷 × 管理员组合的锁态。"""
    if not NODE:
        raise unittest.SkipTest("本机没有 Node.js：纯 JS 锁矩阵用例跳过（CI windows 自带）")
    prelude = (
        "let CAPS = null;\n"
        "let CHECKS = [];\n"
        "let IS_ADMIN = null;\n"
        'const LOCKED = new Set(["scan", "live", "passive"]);\n'
        f"const UI_COPY = {json.dumps(STARTUP, ensure_ascii=False)};\n"
    )
    harness = """
const PAYLOADS = __PAYLOADS__;
const MODES = ["scan", "live", "passive", "offline", "probe", "reports", "settings"];
const out = { payloads: {}, panel: {}, recheck: {} };
Object.keys(PAYLOADS).forEach((name) => {
  out.payloads[name] = {};
  [false, true].forEach((admin) => {
    applyCapabilities(PAYLOADS[name]);
    IS_ADMIN = admin;
    const row = {};
    MODES.forEach((mode) => {
      const lock = lockInfo(mode);
      row[mode] = lock ? { locked: true, kind: lock.kind, tag: lock.tag }
                       : { locked: false };
    });
    out.payloads[name][String(admin)] = row;
  });
});
function panel(name) {
  applyCapabilities(PAYLOADS[name]);
  return shouldShowStartup(PAYLOADS[name]);
}
out.panel.first_run_green = panel("first_run_green");
out.panel.critical_missing = panel("missing_tshark");
out.panel.green_not_first = panel("all_green");
out.panel.old_green = panel("old_payload_green");
out.panel.old_missing = panel("old_payload_missing");
out.panel.null_payload = shouldShowStartup(null);
applyCapabilities(PAYLOADS.missing_tshark);
IS_ADMIN = true;
const before = { scan: isLocked("scan"), offline: isLocked("offline"),
                 passive: isLocked("passive") };
applyCapabilities(PAYLOADS.all_green);
const afterLock = lockInfo("scan");
const after = { scan: isLocked("scan"), offline: isLocked("offline"),
                passive: isLocked("passive"),
                tag: afterLock ? afterLock.tag : "" };
out.recheck = { before: before, after: after };
// S5：selfcheck 请求失败（data=null）时 applyCapabilities 必须保留上一次 CAPS/CHECKS，
// 不许把能力锁清空（fail-open）；随后成功载荷仍能恢复/更新。
applyCapabilities(PAYLOADS.missing_tshark);
const failBefore = { passive: isLocked("passive"), offline: isLocked("offline") };
const failReturn = applyCapabilities(null);
out.failure = {
  before: failBefore,
  capsKept: !!CAPS,
  checksKept: (CHECKS || []).length,
  passiveLocked: isLocked("passive"),
  offlineLocked: isLocked("offline"),
  returnedTruthy: !!failReturn,
};
applyCapabilities(PAYLOADS.all_green);
out.failure.afterRecoverPassiveLocked = isLocked("passive");
console.log(JSON.stringify(out));
""".replace("__PAYLOADS__", json.dumps(payloads, ensure_ascii=False))
    with tempfile.TemporaryDirectory(prefix="netdiag-f2-js-") as tmp:
        script = Path(tmp) / "lock_matrix.js"
        script.write_text(prelude + _lock_js() + harness, encoding="utf-8", newline="\n")
        proc = subprocess.run(
            [NODE, str(script)], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120,
        )
    if proc.returncode != 0:
        raise AssertionError(f"Node 锁矩阵执行失败：{proc.stderr[-2000:]}")
    lines = [line for line in (proc.stdout or "").splitlines() if line.strip()]
    if not lines:
        raise AssertionError("Node 锁矩阵没有输出")
    return json.loads(lines[-1])


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
        # G2：自检从五项扩为六项（+scapy），全绿判定统一走 checksAllPassed。
        self.assertIn("checksAllPassed(checks)", init)

    def test_all_pass_helper_knows_six_checks_and_legacy_five(self):
        helper = _slice("function checksAllPassed", "function allChecksPassed",
                        "checksAllPassed")
        self.assertIn("checks.length === 6", helper)
        self.assertIn('c.key === "scapy"', helper,
                      "旧后端五项载荷兼容：没有 scapy 项才算旧载荷")
        self.assertIn("function allChecksPassed(checks) {\n  return checksAllPassed(checks);\n}",
                      HTML, "旧函数名保留，避免其他入口失效")


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
        self.assertIn("if (!guardMode(MODE)) return;", start,
                      "强制入口必须走统一闸门（能力锁与管理员锁都不许绕过）")
        self.assertIn("if (!checkAdmin()) return;", start,
                      "被动监听入口必须走权限卡/说明卡")
        self.assertIn("cfg.needs_admin && !checkAdmin()", start,
                      "实时抓包入口必须走权限卡/说明卡，不许静默失败")
        check = _slice("function checkAdmin()", "$(\"#perm-close\")", "checkAdmin")
        self.assertIn("guardMode(MODE);", check,
                      "能力锁要弹说明卡、管理员锁要弹权限卡，统一由 guardMode 分派")

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
        self.assertIn("selfcheck.collect_cached()", server)
        self.assertIn("selfcheck.ack_first_run()", server)

    def test_selfcheck_module_has_no_write_in_collect(self):
        source = (ROOT / "core" / "selfcheck.py").read_text(encoding="utf-8")
        collect = source[source.index("def collect("):source.index("__all__")]
        for forbidden in ("write_text", "mkdir", "relaunch_as_admin", "Popen",
                          "subprocess"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, collect,
                                 "collect() 必须纯读：不写文件/不触发 UAC/不抓包")


class CapabilityMatrixRuntimeTest(unittest.TestCase):
    """能力置灰矩阵：Node 执行 UI 的纯 JS 锁函数（无浏览器 / 无网络 / 无 tshark）。"""

    @classmethod
    def setUpClass(cls):
        hostile = _payload()
        hostile["capabilities"]["probe"] = False   # 即使后端异常，probe 也必须可点
        payloads = {
            "missing_tshark": _payload(tshark=False),
            "missing_npcap": _payload(tshark=True, npcap=False),
            "all_green": _payload(),
            "missing_both": _payload(tshark=False, npcap=False),
            "old_payload_green": _payload(with_caps=False),
            "old_payload_missing": _payload(tshark=False, with_caps=False),
            "first_run_green": _payload(first_run=True),
            "hostile_probe_false": hostile,
        }
        # 8 组合覆盖：tshark × Npcap × scapy（B1 的核心真值表，UI 只消费后端结果）。
        for tshark in (True, False):
            for npcap in (True, False):
                for scapy in (True, False):
                    payloads[f"combo_{int(tshark)}{int(npcap)}{int(scapy)}"] = _payload(
                        tshark=tshark, npcap=npcap, scapy=scapy)
        cls.matrix = _run_lock_harness(payloads)

    def _row(self, name: str, admin: bool = False) -> dict:
        return self.matrix["payloads"][name][str(admin).lower()]

    def _assert_cap(self, row: dict, mode: str, tag: str):
        with self.subTest(mode=mode):
            self.assertTrue(row[mode]["locked"], f"{mode} 应置灰")
            self.assertEqual(row[mode]["kind"], "cap")
            self.assertEqual(row[mode]["tag"], tag)

    def test_tshark_missing_locks_scan_live_passive_offline(self):
        row = self._row("missing_tshark")
        for mode in ("scan", "live", "passive", "offline"):
            self._assert_cap(row, mode, STARTUP["lock_tag_tshark"])
        for mode in ("probe", "reports", "settings"):
            with self.subTest(mode=mode):
                self.assertFalse(row[mode]["locked"], f"{mode} 不许置灰")

    def test_npcap_missing_locks_live_and_passive(self):
        """B1：缺 Npcap 时 live/scan/passive 都置灰；offline 与 probe 不受影响。"""
        row = self._row("missing_npcap")
        for mode in ("scan", "live", "passive"):
            self._assert_cap(row, mode, STARTUP["lock_tag_npcap"])
        for mode in ("offline", "probe", "reports", "settings"):
            with self.subTest(mode=mode):
                self.assertFalse(row[mode]["locked"],
                                 f"缺 Npcap 不该锁 {mode}（分析 pcap / 探针不需要驱动）")

    def test_npcap_missing_admin_still_locks_passive(self):
        """admin=true 且 Npcap 缺：能力锁优先，passive 必须置灰（点击弹说明卡）。"""
        row = self._row("missing_npcap", admin=True)
        for mode in ("scan", "live", "passive"):
            with self.subTest(mode=mode, admin=True):
                self._assert_cap(row, mode, STARTUP["lock_tag_npcap"])
        for mode in ("offline", "probe"):
            with self.subTest(mode=mode, admin=True):
                self.assertFalse(row[mode]["locked"])

    def test_all_eight_component_combinations_lock_passive(self):
        """8 组合全覆盖：UI 的 passive 锁必须严格跟随后端真值表。"""
        for tshark in (True, False):
            for npcap in (True, False):
                for scapy in (True, False):
                    name = f"combo_{int(tshark)}{int(npcap)}{int(scapy)}"
                    expected = npcap and (tshark or scapy)
                    for admin in (False, True):
                        row = self._row(name, admin=admin)
                        with self.subTest(tshark=tshark, npcap=npcap,
                                          scapy=scapy, admin=admin):
                            # 非管理员还有 C2 的管理员锁；这里只钉「能力锁」语义。
                            self.assertEqual(row["passive"].get("kind") == "cap",
                                             not expected,
                                             "passive 能力锁与后端能力矩阵不一致")
                            if not expected:
                                self.assertEqual(row["passive"]["kind"], "cap")
                                engines_missing = not (tshark or scapy)
                                if engines_missing and not npcap:
                                    expected_tag = STARTUP["lock_tag_both"]
                                elif not npcap:
                                    expected_tag = STARTUP["lock_tag_npcap"]
                                else:
                                    expected_tag = STARTUP["lock_tag_tshark"]
                                self.assertEqual(row["passive"]["tag"], expected_tag)
                            elif admin:
                                self.assertFalse(row["passive"]["locked"],
                                                 "管理员 + 能力可用时 passive 不许有锁")

    def test_all_present_is_only_admin_locked(self):
        row = self._row("all_green")
        for mode in ("scan", "live", "passive"):
            with self.subTest(mode=mode):
                self.assertEqual(row[mode]["kind"], "admin")
                self.assertEqual(row[mode]["tag"], STARTUP["lock_tag_admin"])
        for mode in ("offline", "probe", "reports", "settings"):
            with self.subTest(mode=mode):
                self.assertFalse(row[mode]["locked"])
        admin_row = self._row("all_green", admin=True)
        self.assertFalse(any(admin_row[m]["locked"] for m in admin_row),
                         "管理员 + 组件齐全时不许有任何锁")

    def test_both_missing_tags_are_specific(self):
        row = self._row("missing_both")
        self._assert_cap(row, "live", STARTUP["lock_tag_both"])
        self._assert_cap(row, "scan", STARTUP["lock_tag_both"])
        self._assert_cap(row, "offline", STARTUP["lock_tag_tshark"])
        # Npcap 与两个引擎都缺：原因码是 tshark|scapy|npcap → 角标「需 Wireshark 与 Npcap」
        self._assert_cap(row, "passive", STARTUP["lock_tag_both"])

    def test_old_payload_without_capabilities_keeps_c2_admin_only(self):
        # 旧载荷：即使 checks 里 tshark 是 ❌，也不能凭 checks 自造能力锁。
        row = self._row("old_payload_missing")
        for mode in ("scan", "live", "passive"):
            with self.subTest(mode=mode):
                self.assertEqual(row[mode]["kind"], "admin")
                self.assertEqual(row[mode]["tag"], STARTUP["lock_tag_admin"],
                                 "旧载荷只能显示管理员锁，不许误灰成缺组件")
        for mode in ("offline", "probe", "reports", "settings"):
            with self.subTest(mode=mode):
                self.assertFalse(row[mode]["locked"], "旧载荷不许误灰")
        admin_row = self._row("old_payload_missing", admin=True)
        self.assertFalse(any(admin_row[m]["locked"] for m in admin_row),
                         "旧载荷 + 管理员：全部可点（C2 现状）")

    def test_probe_never_locked_even_with_hostile_caps(self):
        row = self._row("hostile_probe_false", admin=True)
        self.assertFalse(row["probe"]["locked"],
                         "probe 只用标准库 socket，任何 capability 载荷都不许锁")

    def test_recheck_all_green_unlocks_and_clears_tags(self):
        recheck = self.matrix["recheck"]
        self.assertEqual(recheck["before"], {"scan": True, "offline": True,
                                             "passive": True})
        self.assertEqual(recheck["after"], {"scan": False, "offline": False,
                                            "passive": False, "tag": ""})

    def test_selfcheck_failure_keeps_previous_locks(self):
        """S5：请求失败（data=null）不许清空 CAPS/CHECKS，锁状态必须保留。"""
        fail = self.matrix["failure"]
        self.assertEqual(fail["before"], {"passive": True, "offline": True})
        self.assertTrue(fail["capsKept"], "失败时 CAPS 被清空 → 能力锁全部放开（fail-open）")
        self.assertEqual(fail["checksKept"], 5, "失败时 CHECKS 也不许清空")
        self.assertTrue(fail["passiveLocked"], "失败后 passive 必须仍置灰")
        self.assertTrue(fail["offlineLocked"], "失败后 offline 必须仍置灰")
        self.assertTrue(fail["returnedTruthy"], "保留时应返回上一次 CAPS")
        self.assertFalse(fail["afterRecoverPassiveLocked"],
                         "随后成功的全绿载荷仍要能恢复")

    def test_panel_visibility_rules(self):
        panel = self.matrix["panel"]
        self.assertTrue(panel["first_run_green"], "全绿但首次运行 → 显示")
        self.assertTrue(panel["critical_missing"], "非首次但有缺件 → 显示")
        self.assertFalse(panel["green_not_first"], "全绿且非首次 → 不显示（保持 C2）")
        self.assertFalse(panel["old_green"], "旧载荷无 capabilities → 不显示")
        self.assertFalse(panel["old_missing"], "旧载荷不许凭 checks 弹出缺件面板")
        self.assertFalse(panel["null_payload"])


class StartupExtensionStaticTest(unittest.TestCase):
    """首屏自检扩展：always fetch / impact + 指引 / 重新检测后重绘 / 恢复入口。"""

    def test_fetches_selfcheck_even_when_not_first_run(self):
        init = _slice("async function initStartup", "function setCapMsg", "initStartup")
        self.assertLess(init.index("loadSelfcheck()"), init.index("data.first_run !== true"),
                        "必须先拉 selfcheck 存 CAPS，再看 first_run 决定面板")
        load = _slice("async function loadSelfcheck", "async function initStartup",
                      "loadSelfcheck")
        self.assertIn('fetch("/api/selfcheck"', load)
        self.assertIn("applyCapabilities(data)", load)
        self.assertIn("paintLocks();", load,
                      "首屏/重新检测拿到能力矩阵后必须立即重绘置灰矩阵")

    def test_failed_rows_have_impact_fix_text_and_doc_link(self):
        render = _slice("function renderStartup", "function setStartupEnter",
                        "renderStartup")
        for token in ("c.impact", "fixTextFor(c.key)", "fixtext",
                      "startupDocLink()", 'target="_blank" rel="noopener"'):
            with self.subTest(token=token):
                self.assertIn(token, render)
        self.assertIn('class="impact"', render)
        self.assertIn("data-startup-elevate", render)
        self.assertIn('replace(/[；;]?\\s*详见\\s*docs\\/startup\\.md/g, "")',
                      _slice("function fixTextFor", "function startupDocLink",
                             "fixTextFor"),
                      "fix_* 已含文档路径：额外渲染可点击链接前必须去重")

    def test_recheck_rebuilds_panel_and_matrix(self):
        recheck = _slice("async function recheckSelfcheck", "function waitForElevatedReload",
                         "recheckSelfcheck")
        self.assertIn("loadSelfcheck()", recheck)
        self.assertIn("showCapabilityCard(capMode)", recheck,
                      "没恢复时说明卡也要同步刷新原因")
        self.assertIn("renderStartup(data)", recheck)
        self.assertIn("setStartupEnter(true)", recheck,
                      "恢复后要提供「进入主界面」")

    def test_all_green_offers_enter_after_manual_recheck(self):
        init = _slice("async function initStartup", "function setCapMsg", "initStartup")
        self.assertIn("setStartupEnter(allGreen)", init)
        self.assertIn("UI_COPY.ready_enter", init)
        self.assertIn("finishStartup(true)", init, "C2 全绿首次运行仍要自动 ack")
        enter = _slice("function setStartupEnter", "function showStartup", "setStartupEnter")
        self.assertIn('"enter"', enter)
        self.assertIn("limited_enter", enter)

    def test_panel_can_be_reopened_from_settings(self):
        self.assertIn('id="sysinfo-startup"', HTML)
        self.assertIn('data-copy="startup_open"', HTML)
        sysinfo = _slice('$("#sysinfo-startup").onclick', 'wireFormPersistence();',
                         "sysinfo-startup")
        self.assertIn("initStartup({ manual: true, force: true })", sysinfo)

    def test_boot_fetches_selfcheck_payload_once(self):
        """S2：首屏复用 /api/app 下发的 checks/capabilities，不再背靠背跑全套。"""
        boot = _slice("async function boot()", "async function loadCaptures", "boot")
        self.assertIn("applyCapabilities(app)", boot,
                      "boot 必须直接用 /api/app 的 capabilities + checks")
        self.assertIn("BOOT_STARTUP = Array.isArray(app.checks) ? app : null;", boot)
        init = _slice("async function initStartup", "function setCapMsg", "initStartup")
        self.assertIn("data = BOOT_STARTUP;", init)
        self.assertLess(init.index("data = BOOT_STARTUP;"),
                        init.index("await loadSelfcheck()"),
                        "boot 载荷优先复用；只有没有载荷时才请求 selfcheck")
        load_app = _slice("async function loadAppInfo", "/* ---------------- 导出诊断包",
                          "loadAppInfo")
        self.assertIn("let r = APP_INFO;", load_app,
                      "loadAppInfo 复用 boot 已拿到的 /api/app，不再重复请求")

    def test_selfcheck_failure_is_fail_closed_with_hint(self):
        """S5：请求失败保留上一份 CAPS/CHECKS，只轻提示；不把锁放开。"""
        self.assertIn('id="selfcheck-note"', HTML)
        self.assertTrue(str(STARTUP.get("selfcheck_failed", "")).strip())
        load = _slice("async function loadSelfcheck", "async function initStartup",
                      "loadSelfcheck")
        self.assertIn("if (!resp.ok) throw new Error", load,
                      "非 2xx 必须按失败处理，不能把错误 JSON 当能力载荷")
        self.assertIn("setSelfcheckNote(note)", load)
        self.assertIn("return null;", load)
        self.assertLess(load.index("if (!data)"),
                        load.index("STARTUP_DATA = data;"),
                        "失败分支必须在覆盖 CAPS/CHECKS 之前返回")
        caps = _slice("function applyCapabilities", "function criticalMissing",
                      "applyCapabilities")
        self.assertIn('if (!data || typeof data !== "object") return CAPS;', caps,
                      "applyCapabilities(null) 必须保留上一次结果")
        recheck = _slice("async function recheckSelfcheck", "function waitForElevatedReload",
                         "recheckSelfcheck")
        self.assertIn("if (!data) {", recheck)
        self.assertIn("selfcheck_failed", recheck)
        self.assertLess(recheck.index("if (!data) {"),
                        recheck.index("const checks ="),
                        "重新检测失败时不许按「0 项失败」继续走全绿分支")


class CapabilityCardStaticTest(unittest.TestCase):
    """点击置灰项 → 能力说明卡：缺什么 / 缺了会怎样 / 怎么修复 / 重新检测 / 知道了。"""

    def test_card_markup_exists_and_uses_copy_table(self):
        for element_id in ("cap-mask", "cap-title", "cap-sub", "cap-need",
                           "cap-impact", "cap-fix", "cap-recheck", "cap-close2"):
            with self.subTest(id=element_id):
                self.assertIn(f'id="{element_id}"', HTML)
        for key in ("disabled_title", "disabled_recheck", "disabled_close",
                    "disabled_need_label", "disabled_impact_label",
                    "disabled_fix_label"):
            with self.subTest(key=key):
                self.assertTrue(str(STARTUP.get(key, "")).strip())

    def test_card_body_has_need_impact_fix_and_links(self):
        card = _slice("function showCapabilityCard", "async function recheckSelfcheck",
                      "showCapabilityCard")
        for token in ("cap-need", "cap-impact", "cap-fix", "disabled_need",
                      "disabled_impact", "disabled_fix", "impact_", "fix_",
                      "startupDocLink()", "fix_url", "fixUrl", "_url",
                      'rel="noopener"'):
            with self.subTest(token=token):
                self.assertIn(token, card)
        self.assertIn('UI_COPY[key + "_url"]', card,
                      "CHECKS 尚未到达时下载链接回退到 copy 表 URL，不能缺指引")

    def test_guard_mode_dispatches_two_kinds_of_locks(self):
        guard = _slice("function guardMode", "function paintLocks", "guardMode")
        self.assertIn("capLockInfo(mode)", guard)
        self.assertIn("showCapabilityCard(mode)", guard)
        self.assertIn("showPermModal()", guard,
                      "管理员锁仍走 C2 权限卡，不能被能力卡合并")
        self.assertIn("return false;", guard)

    def test_locked_mode_click_is_not_silent(self):
        nav = _slice('$("#nav").addEventListener("click"', 'function markActive',
                     "nav handler")
        self.assertIn("switchMode(modeBtn.dataset.mode)", nav)
        self.assertNotIn("if (isLocked(mode)) { showPermModal(); return; }", HTML,
                         "旧实现只弹权限卡，必须换成 guardMode 分派")
        switch = _slice("function switchMode", "function setMode", "switchMode")
        self.assertIn("guardMode(mode)", switch)
        self.assertIn("if (!guardMode(mode)) return false;", switch)

    def test_failure_card_shortcuts_go_through_guard(self):
        """S3：失败卡的 #err-offline / #err-probe 也走 switchMode（guardMode）。"""
        wire = _slice("function wireFailureActions", "async function loadIfacesForError",
                      "wireFailureActions")
        self.assertIn('switchMode("offline")', wire,
                      "失败卡「去分析抓包文件」必须过能力锁，不许直接 setMode")
        self.assertNotIn('setMode("offline")', wire)
        self.assertIn('switchMode("probe")', wire)
        self.assertNotIn('setMode("probe")', wire)
        switch = _slice("function switchMode", "function setMode", "switchMode")
        self.assertIn("if (!guardMode(mode)) return false;", switch,
                      "switchMode 自身必须过统一闸门，否则失败卡入口仍可绕过")

    def test_card_buttons_wired(self):
        self.assertIn('$("#cap-close").onclick = hideCapCard;', HTML)
        self.assertIn('$("#cap-close2").onclick = hideCapCard;', HTML)
        recheck = _onclick("#cap-recheck")
        self.assertIn("recheckSelfcheck", recheck)
        self.assertIn('$("#cap-mask").addEventListener("mousedown"', HTML)

    def test_nav_badge_uses_dynamic_data_lock(self):
        self.assertEqual(CSS.count("content:attr(data-lock)"), 2,
                         "导航角标必须按锁定原因动态渲染")
        locks = _slice("function paintLocks", "function legacyCapMode", "paintLocks")
        self.assertIn('b.setAttribute("data-lock", tag)', locks)
        self.assertIn('t.setAttribute("data-lock", tag)', locks)
        self.assertIn("lock_tag_both", _slice("function capTag", "function capLockInfo",
                                              "capTag"))


class NoHardcodedPathStaticTest(unittest.TestCase):
    """文案红线：不出现开发商口吻硬路径；新文案可操作。"""

    def test_forbidden_phrases_are_absent(self):
        corpus = HTML + "\n" + json.dumps(COPY, ensure_ascii=False)
        for phrase in ("请把 Wireshark 便携版解压到", "G:\\", "C:\\"):
            with self.subTest(phrase=phrase):
                self.assertEqual(corpus.count(phrase), 0,
                                 f"文案里不许出现 {phrase!r}")

    def test_capability_copy_is_actionable(self):
        for key in ("fix_tshark", "fix_npcap", "fix_python", "fix_port",
                    "lock_tag_tshark", "lock_tag_npcap", "lock_tag_admin",
                    "lock_tag_both", "need_tshark", "need_npcap", "need_both",
                    "missing_tshark", "missing_npcap", "need_passive",
                    "disabled_title", "disabled_hint",
                    "disabled_need", "disabled_impact_label", "disabled_fix_label",
                    "disabled_recheck", "disabled_close", "disabled_rechecking",
                    "recheck_still", "recheck_all_ok", "ready_enter", "enter",
                    "lock_banner_caps", "lock_banner_admin", "startup_open",
                    "docs_url", "docs_hint", "wireshark_url", "npcap_url",
                    "selfcheck_failed"):
            with self.subTest(key=key):
                self.assertTrue(str(STARTUP.get(key, "")).strip(), f"{key} 不能为空")
        self.assertIn("TSHARK_PATH", STARTUP["fix_tshark"])
        self.assertIn("重启", STARTUP["fix_tshark"],
                      "TSHARK_PATH 对已启动进程不生效，文案必须写明重启")
        self.assertIn("Npcap", STARTUP["need_passive"],
                      "通信观察需要 Npcap（B1）")
        self.assertIn("docs/startup.md", STARTUP["fix_tshark"])
        self.assertIn("Wireshark", STARTUP["need_tshark"])
        self.assertIn("Npcap", STARTUP["need_npcap"])
        self.assertIn("docs/startup.md", STARTUP["docs_hint"])
        self.assertTrue(STARTUP["docs_url"].startswith("https://"))

    def test_docs_url_reuses_payload_relative_doc(self):
        self.assertEqual(STARTUP["docs_url"].rsplit("/", 1)[-1], "startup.md")
        self.assertIn("docs/startup.md",
                      (ROOT / "core" / "selfcheck.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
