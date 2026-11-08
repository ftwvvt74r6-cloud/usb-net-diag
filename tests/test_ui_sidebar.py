"""H5：左侧减负（4 项一级菜单 + 右上角齿轮设置 + 二级默认收起 + 说明卡右移）。

口径（``H-SPEC`` H5 / V7）：

* 一级菜单 **4 项**：实时诊断 / 连通与速度测试 / 分析抓包文件 / 报告与导出；
  设置从左侧移除，改为右上角齿轮（仍能打开「网卡与运行信息」与「AI 模型配置」）；
* 二级菜单默认收起（标记不预置 open），但首屏会展开**当前选中**的一级组：
  用户既能看到「全网体检」是当前项，又不会四个组全摊开（S6 复审建议）；
* 「什么时候用这个」说明卡在右侧内容区顶部、随模式变化，不再常驻左栏；
* 左侧只保留菜单 + 当前模式输入 + 主按钮，1024px 下无横向溢出（真实 headless
  尺寸断言在 ``D:\\utest\\review\\h-samples\\ui\\`` 的 DOM 摘要里）。

CI 没有浏览器，这里用源码/结构断言钉住接线；Node 只跑纯函数用例（提示条那套
风格），布局尺寸由本机 headless Edge 证据补足。
"""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")

TOP_LEVEL_GROUPS = ["realtime", "probe", "offline", "reports"]


def _slice(start: str, end: str, label: str) -> str:
    if start not in HTML:
        raise AssertionError(f"{label}: 找不到起点 {start!r}")
    begin = HTML.index(start)
    if end not in HTML[begin:]:
        raise AssertionError(f"{label}: 找不到终点 {end!r}")
    return HTML[begin:begin + HTML[begin:].index(end)]


def _aside() -> str:
    return HTML.split("<aside", 1)[1].split("</aside>", 1)[0]


class FourTopLevelMenuTest(unittest.TestCase):
    """一级菜单=4，设置搬去齿轮，其他功能入口不丢。"""

    def test_exactly_four_navgroups(self):
        self.assertEqual(HTML.count('class="navgroup"'), 4,
                         "H5：一级菜单只允许 4 组（设置已移到右上角齿轮）")
        for group in TOP_LEVEL_GROUPS:
            with self.subTest(group=group):
                self.assertIn(f'data-group="{group}"', HTML)
        self.assertNotIn('data-group="settings"', HTML,
                         "设置分组必须从左侧移除")

    def test_settings_gear_exists_in_header_outside_aside(self):
        gear = _slice('<button class="topbtn gear" id="settings-gear"',
                      "<button class=\"topbtn\" id=\"ai-open\"", "settings gear")
        self.assertIn('data-view="sysinfo"', gear)
        self.assertIn("设置", gear)
        self.assertIn('aria-label="设置"', gear)
        self.assertLess(HTML.index('id="settings-gear"'), HTML.index("<aside"),
                        "齿轮必须在顶栏，而不是左侧菜单")
        self.assertNotIn('id="settings-gear"', _aside())

    def test_gear_opens_settings_and_ai_entry_remains(self):
        self.assertIn('$("#settings-gear").onclick = () => setView("sysinfo");', HTML)
        self.assertIn('id="settings-ai" data-view="ai"', HTML)
        self.assertIn('$("#settings-ai").onclick = () => setView("ai");', HTML)
        # G5 的四个设置页 id 与 AI 入口必须仍在
        for element_id in ("settings-service-title", "idle-exit-info",
                           "settings-idle-label", "quit-background"):
            with self.subTest(id=element_id):
                self.assertIn(f'id="{element_id}"', HTML)

    def test_all_modes_and_reports_entries_remain_reachable(self):
        for mode in ("scan", "live", "passive", "probe", "offline"):
            with self.subTest(mode=mode):
                self.assertIn(f'data-mode="{mode}"', HTML)
        for view in ("reports", "export", "sysinfo", "ai"):
            with self.subTest(view=view):
                self.assertIn(f'data-view="{view}"', HTML)
        self.assertIn('id="run"', HTML, "主按钮不能随左栏减负一起丢")
        self.assertIn('id="side-actions"', HTML)

    def test_left_column_has_no_guide_or_settings_entries(self):
        aside = _aside()
        self.assertNotIn('id="mode-guide"', aside,
                         "「什么时候用这个」必须移到右侧内容区")
        self.assertNotIn('data-view="sysinfo"', aside)
        self.assertNotIn('data-view="ai"', aside)
        self.assertNotIn('data-group="settings"', aside)
        self.assertNotIn('id="console"', aside)


class SubmenuCollapseTest(unittest.TestCase):
    """二级菜单默认收起；选中一级/二级后（含首屏当前模式）展开所在分组。"""

    def test_markup_has_no_open_group_and_no_expanded_aria(self):
        nav = _slice('<nav class="nav" id="nav">', "</nav>", "nav")
        self.assertNotIn('class="navgroup open"', nav,
                         "标记里不能预置 open（展开由 JS 按当前模式决定）")
        self.assertNotIn('aria-expanded="true"', nav,
                         "默认不能有展开态")
        self.assertEqual(nav.count('aria-expanded="false"'), 2,
                         "两个可展开分组（实时诊断 / 报告与导出）默认收起")

    def test_active_group_opens_on_selection_including_boot(self):
        """S6：首屏也要展开当前选中一级菜单，否则看不到「全网体检」被选中。"""
        mark = _slice("function markActive", "function hideViews", "markActive")
        self.assertNotIn("NAV_USER_PICK", mark,
                         "展开不能再依赖「用户点过」：首屏 setMode 也必须展开")
        self.assertIn("if (hit)", mark)
        self.assertIn('g.classList.add("open")', mark)
        self.assertIn('setAttribute("aria-expanded", "true")', mark)
        boot = _slice("async function boot()", "async function loadCaptures", "boot")
        self.assertIn("setMode(MODE);", boot, "首屏必须走 setMode，由 markActive 展开 active 组")

    def test_nav_clicks_toggle_group_and_switch_mode(self):
        nav = _slice('$("#nav").addEventListener("click"', "function markActive",
                     "nav handler")
        self.assertIn("classList.toggle(\"open\", open)", nav)
        self.assertIn('setAttribute("aria-expanded", open ? "true" : "false")', nav)
        self.assertIn("switchMode(modeBtn.dataset.mode)", nav)
        self.assertIn("setView(viewBtn.dataset.view)", nav)
        self.assertNotIn("NAV_USER_PICK", nav, "旧的用户点过标记已由「按当前命中展开」替代")


class GuideCardPlacementTest(unittest.TestCase):
    """「什么时候用这个」在右侧顶部，随模式更新。"""

    def test_guide_is_in_main_before_question_card(self):
        self.assertEqual(HTML.count('id="mode-guide"'), 1)
        guide = HTML.index('id="mode-guide"')
        self.assertGreater(guide, HTML.index('<main class="main">'))
        self.assertLess(guide, HTML.index('<section class="qcard" id="qcard"'),
                        "说明卡应在内容区顶部、问题卡之前")
        self.assertLess(HTML.index('<div class="resultbar">'), guide,
                        "说明卡必须在结果栏之后的内容区顶部")
        self.assertNotIn('id="mode-guide"', _aside())
        self.assertIn('<div class="guide modetop" id="mode-guide"></div>', HTML)

    def test_set_mode_updates_and_reveals_guide(self):
        set_mode = _slice("function setMode", "/* 「它回答什么问题」卡片",
                          "setMode")
        self.assertIn('$("#mode-guide").innerHTML', set_mode)
        self.assertIn('$("#mode-guide").classList.remove("hidden")', set_mode)
        self.assertIn("cfg.guide", set_mode)
        self.assertIn("cfg.term", set_mode)

    def test_result_view_hides_intro_cards_and_mode_switch_restores(self):
        hide = _slice("function hideQuestion", "function showIdle", "hideQuestion")
        self.assertIn('"#qcard", "#mode-guide"', hide)
        self.assertIn('card.classList.add("hidden")', hide)
        set_mode = _slice("function setMode", "/* 「它回答什么问题」卡片",
                          "setMode")
        self.assertIn('paintQuestion(mode);', set_mode)


class SidebarLayoutStaticTest(unittest.TestCase):
    """左栏更窄、可滚动、不横向溢出；1024 仍可用。"""

    def test_shell_uses_narrower_flexible_columns(self):
        self.assertIn("grid-template-columns:276px minmax(0,1fr)", HTML)
        self.assertIn("grid-template-columns:244px minmax(0,1fr)", HTML)
        self.assertNotIn("grid-template-columns:300px", HTML)
        self.assertNotIn("grid-template-columns:264px", HTML)
        self.assertIn("@media (max-width:1150px)", HTML)

    def test_side_scrolls_vertically_and_does_not_overflow(self):
        side = _slice("  .side{background:#fff", "  /* ---------------- 一级 / 二级菜单",
                      "side")
        self.assertIn("min-height:0", side)
        self.assertIn("overflow:hidden", side)
        scroll = _slice("  .side-scroll{", "  .sidehead", "side-scroll")
        self.assertIn("overflow:auto", scroll)
        self.assertIn("min-height:0", scroll)

    def test_form_inputs_still_present_and_full_width(self):
        for element_id in ("target", "duration", "iface", "pcap-select",
                           "probe-target", "probe-port", "run", "form-reset"):
            with self.subTest(id=element_id):
                self.assertIn(f'id="{element_id}"', HTML)
        self.assertIn("input[type=text],input[type=number],input[type=password],select{",
                      HTML)
        self.assertIn("width:100%", HTML)

    def test_1024_breakpoint_keeps_main_fluid(self):
        # CI 没有布局引擎：这里钉住「左侧固定 ≤276 / 主区 minmax(0,1fr)」的规则，
        # 真实 1024×768 的 scrollWidth 断言由 headless 证据（h-samples/ui）补足。
        self.assertIn("minmax(0,1fr)", HTML)
        self.assertIn(".side{background:#fff;border-right:1px solid var(--line);"
                      "display:flex;flex-direction:column;", HTML)
        self.assertIn("min-width:0", HTML)


if __name__ == "__main__":
    unittest.main(verbosity=2)
