"""B3：用户真机反馈四项（删废话行 / 旧名清尾 / 被动选卡 / 结果页联动）的回归测试。

这组用例不跑浏览器、不抓包、不需要管理员：
* ① 静态读 ``ui/index.html``，断言「任务完成：结果已渲染到右侧」不再出现；
* ② 命名映射：copy 表 / verdict / UI / 文档里的用户可见文案不再出现旧模式名，
  旧名只允许作为「新名（旧技术名）」括号里的别名出现；
* ③ 被动选卡：``passive._resolve_iface`` 复用实时抓包的「候选排序 + 2 秒真实探测」，
  ``passive.run`` 在 0 包时按候选换下一块（≤3 块），并给出 0 会话结论卡数据；
* ④ 结果页联动：``server.link_actions`` 的 URL/参数拼装（模式 / 目标 / 端口 /
  确认文案），以及 UI 侧确认框、切模式、预填表单的静态契约。

变异锚点（改回旧逻辑必须让用例红）：
* ``_resolve_iface`` 若退回 ``tshark.pick_interface``（只按名字，选中断线以太网），
  :class:`PassiveSelectionTest` 的 auto 用例红；
* ``_candidate_plan`` 若退化成只返回首选网卡，0 包换卡用例红；
* copy 表若把「连通与速度测试」改回旧名，:class:`NamingSweepTest` 红。
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import passive  # noqa: E402
import server  # noqa: E402
import tshark  # noqa: E402
import verdict  # noqa: E402

HTML = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
COPY = json.loads((ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8"))
CONFIG_RE = re.compile(
    r'<script type="application/json" id="ui-config">(.*?)</script>', re.S)

#: 旧模式名 → 新名（B2 已改名；B3 清报告/建议文案的残留）。
OLD_TO_NEW = {
    "全网扫描": "全网体检",
    "定向抓包": "单目标诊断",
    "被动监听": "通信观察",
    "链路体检": "连通与速度测试",
    "离线分析": "分析抓包文件",
}

IFACES = [
    {"index": 5, "name": "5. \\Device\\NPF_WLAN (WLAN)", "raw": ""},
    {"index": 10, "name": "10. \\Device\\NPF_META (Meta)", "raw": ""},
    {"index": 12, "name": "12. \\Device\\NPF_ETH (以太网)", "raw": ""},
    {"index": 6, "name": "6. \\Device\\NPF_VM (VMware Network Adapter VMnet8)", "raw": ""},
]


def ui_config() -> dict:
    """解析页面里的 ``ui-config`` JSON 块。"""
    match = CONFIG_RE.search(HTML)
    if match is None:
        raise AssertionError("ui/index.html 缺少 id=ui-config 的 JSON 配置块")
    return json.loads(match.group(1))


def _walk_strings(node):
    """递归产出 copy 表里的所有字符串叶子（含 key 名之外的版本）。"""
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_strings(value)
    elif isinstance(node, str):
        yield node


class NoBoilerplateLogTest(unittest.TestCase):
    """① 「任务完成：结果已渲染到右侧」是废话行，删掉；其它日志不许一起删。"""

    def test_completion_boilerplate_removed(self):
        self.assertNotIn("任务完成：结果已渲染到右侧", HTML)
        self.assertIn("监听完成：会话表已渲染到右侧", HTML,
                      "只删采集完成那一行，被动监听完成日志要保留")

    def test_poll_still_renders_result(self):
        block = HTML.split("if (s.state === \"done\")", 1)[1].split(
            "} else if (s.state === \"error\")", 1)[0]
        self.assertIn("render(res,", block)
        self.assertIn("renderDegraded(res", block)


class NamingSweepTest(unittest.TestCase):
    """② 用户可见文案不再单独使用旧模式名；旧名只作「新名（旧名）」别名。"""

    def test_copy_table_has_no_old_mode_name(self):
        joined = "\n".join(_walk_strings(COPY))
        for old in OLD_TO_NEW:
            with self.subTest(old=old):
                self.assertNotIn(old, joined, f"copy 文案仍含旧模式名：{old}")

    def test_degraded_advice_now_uses_new_name(self):
        advice = COPY["advice"]["L4.CONNECT.ADVICE"]
        self.assertIn("连通与速度测试", advice)
        self.assertNotIn("链路体检", advice)
        normal = COPY["verdict"]["plain"]["normal_suffix"]
        self.assertIn("连通与速度测试", normal)
        self.assertNotIn("链路体检", normal)

    def test_offline_report_marker_uses_new_name_but_reads_legacy(self):
        self.assertEqual(verdict.OFFLINE_BPF, "分析抓包文件")
        self.assertTrue(verdict._is_offline({"bpf": "分析抓包文件"}))
        # 历史报告 / 旧调用方写的是旧名，仍必须按「分析抓包文件」处理。
        self.assertTrue(verdict._is_offline({"bpf": "离线分析"}))
        self.assertFalse(verdict._is_offline({"bpf": "无（全网）"}))

    def test_ui_nav_keeps_old_name_only_as_parenthetical_alias(self):
        modes = ui_config()["modes"]
        for mode, cfg in modes.items():
            with self.subTest(mode=mode):
                old = cfg["tech"]
                new = cfg["label"]
                self.assertIn(old, OLD_TO_NEW, f"{mode} 的技术名不是已知旧名")
                self.assertEqual(cfg["display"], f"{new}（{old}）")

    def test_ui_visible_copy_uses_new_names(self):
        for new in OLD_TO_NEW.values():
            with self.subTest(new=new):
                self.assertIn(new, HTML)

    def test_historical_docs_annotated(self):
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("模式名对照", changelog)
        for old, new in OLD_TO_NEW.items():
            with self.subTest(old=old):
                self.assertIn(f"{old} → **{new}**", changelog)
        plan = (ROOT / "docs" / "plan-review.md").read_text(encoding="utf-8")
        self.assertIn("历史文档说明", plan)
        t00 = (ROOT / "docs" / "t00-findings.md").read_text(encoding="utf-8")
        self.assertIn("历史文档说明", t00)

    def test_scaffold_copy_uses_new_name(self):
        text = (ROOT / "scaffold" / "core" / "copy" / "zh-CN.json").read_text(
            encoding="utf-8")
        self.assertNotIn("链路体检", text)


class PassiveSelectionTest(unittest.TestCase):
    """③ 被动选卡：候选排序 + 真实探测，0 包换下一块（≤3）。"""

    def test_candidate_plan_keeps_chosen_first_and_dedups(self):
        ordered = tshark.order_interfaces(IFACES)
        plan = passive._candidate_plan(IFACES[0], ordered, limit=3)
        self.assertEqual(plan[0]["index"], 5)
        self.assertEqual(len(plan), 3)
        self.assertEqual(len({p["index"] for p in plan}), 3)
        empty = passive._candidate_plan(None, ordered, limit=3)
        self.assertEqual([p["index"] for p in empty], [p["index"] for p in ordered[:3]])

    def test_auto_probe_wins_over_name_based_ethernet(self):
        """旧逻辑 pick_interface 会选「以太网」(断线)；新逻辑必须用探测结果。"""
        with mock.patch.object(tshark, "list_interfaces", return_value=IFACES), \
                mock.patch.object(tshark, "find_tshark", return_value=Path("tshark.exe")), \
                mock.patch.object(tshark, "probe_interface", return_value=IFACES[0]) as probe, \
                mock.patch.object(tshark, "pick_interface", return_value=IFACES[2]) as pick:
            chosen, device, explicit, ordered = passive._resolve_iface(None)
        self.assertFalse(explicit)
        self.assertEqual(chosen["index"], 5, "必须选探测到流量的 WLAN，而不是名字像以太网的断线卡")
        self.assertIn("NPF_WLAN", device)
        self.assertEqual(len(ordered), len(IFACES))
        probe.assert_called_once()
        pick.assert_not_called()

    def test_explicit_interface_skips_probe(self):
        with mock.patch.object(tshark, "list_interfaces", return_value=IFACES), \
                mock.patch.object(tshark, "probe_interface") as probe:
            chosen, device, explicit, _ordered = passive._resolve_iface("12")
        self.assertTrue(explicit)
        self.assertEqual(chosen["index"], 12)
        self.assertIn("NPF_ETH", device)
        probe.assert_not_called()

    def test_zero_packet_switches_to_next_candidate(self):
        """0 包换卡：第 1 块（以太网）0 包 → 第 2 块（WLAN）抓到会话。"""
        rec = {"t": 1.0, "size": 200, "transport": "TCP", "src_ip": "10.0.0.9",
               "dst_ip": "93.184.216.34", "sport": 50000, "dport": 443,
               "flags": 0x12, "payload": b""}
        logs: list[str] = []
        captured: list[str] = []

        def fake_capture(device, duration, bpf, max_packets, logger=None, should_stop=None):
            captured.append(device)
            return [] if "ETH" in device else [rec]

        with mock.patch.object(passive, "_resolve_iface",
                               return_value=(IFACES[2], passive._device_name(IFACES[2]),
                                             False, tshark.order_interfaces(IFACES))), \
                mock.patch.object(passive, "engine_status",
                                  return_value={"engine": "scapy", "scapy": True,
                                                "scapy_version": "2.8.0"}), \
                mock.patch.object(passive, "_capture_scapy", side_effect=fake_capture):
            res = passive.run(duration=3, engine="auto", logger=logs.append)

        self.assertTrue(res["ok"], res)
        self.assertEqual([p["index"] for p in res["tried"]], [12, 5])
        self.assertEqual(res["interface"], "WLAN")
        self.assertEqual(res["summary"]["flows"], 1)
        joined = "\n".join(logs)
        self.assertIn("第 1/3 块网卡 以太网[12] 无流量", joined)
        self.assertIn("换第 2/3 块 WLAN[5]", joined)
        self.assertEqual(len(captured), 2)

    def test_zero_flow_result_has_empty_sessions_card_fields(self):
        with mock.patch.object(passive, "_resolve_iface",
                               return_value=(IFACES[2], passive._device_name(IFACES[2]),
                                             False, tshark.order_interfaces(IFACES))), \
                mock.patch.object(passive, "engine_status",
                                  return_value={"engine": "scapy", "scapy": True}), \
                mock.patch.object(passive, "_capture_scapy", return_value=[]):
            res = passive.run(duration=3, engine="auto", logger=lambda _m: None)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["summary"]["flows"], 0)
        self.assertEqual(res["card"], "empty_sessions")
        self.assertEqual(res["headline"], "未观察到任何 TCP/IP 会话")
        self.assertTrue(res["next_steps"])
        self.assertEqual([p["packets"] for p in res["tried"]], [0, 0, 0])

    def test_explicit_zero_packet_does_not_switch(self):
        with mock.patch.object(passive, "_resolve_iface",
                               return_value=(IFACES[2], passive._device_name(IFACES[2]),
                                             True, tshark.order_interfaces(IFACES))), \
                mock.patch.object(passive, "engine_status",
                                  return_value={"engine": "scapy", "scapy": True}), \
                mock.patch.object(passive, "_capture_scapy", return_value=[]) as cap:
            res = passive.run(interface="12", duration=3, engine="auto",
                              logger=lambda _m: None)
        self.assertEqual(cap.call_count, 1, "显式指定网卡必须被尊重，不得静默换卡")
        self.assertIn("显式指定", res["advice"])
        self.assertEqual(len(res["tried"]), 1)

    def test_ui_renders_empty_session_card(self):
        block = HTML.split("function renderPassiveEmpty", 1)[1].split(
            "function renderPassive(res)", 1)[0]
        for text in ('data-card="empty_sessions"', "未观察到任何 TCP/IP 会话",
                     "试过的候选网卡", "接下来怎么做（建议按顺序执行）",
                     "pempty-retry", "pempty-probe"):
            with self.subTest(text=text):
                self.assertIn(text, block)


class LinkActionsTest(unittest.TestCase):
    """④ 结果页「接下来怎么做」联动：参数拼装 + 确认框 + 预填。"""

    RESULT = {
        "ok": True,
        "meta": {"streams_top": [
            {"server": "10.0.0.5", "dport": 8080, "flags": [], "retrans": 0,
             "packets": 6},
            {"server": "43.159.7.66", "dport": 443, "flags": ["重传 2"],
             "retrans": 2, "packets": 30},
        ]},
        "verdict": {"level": "严重", "next_steps": ["检查链路"]},
    }

    def test_stream_peer_action_has_mode_target_port_and_confirm(self):
        actions = server.link_actions(self.RESULT, gateway="")
        self.assertEqual(len(actions), 1)
        live = actions[0]
        self.assertEqual(live["mode"], "live")
        self.assertEqual(live["target"], "43.159.7.66")
        self.assertEqual(live["port"], 443)
        self.assertEqual(live["display"], "43.159.7.66:443")
        self.assertEqual(live["label"], "用单目标诊断复测对端")
        self.assertEqual(live["confirm"],
                         "将切换到『单目标诊断』并预填 43.159.7.66:443，是否继续？")

    def test_gateway_action_uses_given_gateway(self):
        actions = server.link_actions(self.RESULT, gateway="192.168.31.1")
        kinds = [a["kind"] for a in actions]
        self.assertEqual(kinds, ["live", "probe"])
        probe = actions[1]
        self.assertEqual(probe["mode"], "probe")
        self.assertEqual(probe["target"], "192.168.31.1")
        self.assertIsNone(probe["port"])
        self.assertEqual(probe["label"], "用连通与速度测试复测网关")
        self.assertEqual(probe["confirm"],
                         "将切换到『连通与速度测试』并预填网关 192.168.31.1，是否继续？")

    def test_degraded_gateway_falls_back_to_link_host(self):
        degraded = {"ok": True, "degraded": True,
                    "link": {"via": "gateway", "host": "198.18.0.2"},
                    "capture": {"target": "10.255.255.1"}}
        actions = server.link_actions(degraded, gateway="")
        self.assertEqual([a["kind"] for a in actions], ["probe"])
        self.assertEqual(actions[0]["target"], "198.18.0.2")

    def test_no_actions_when_no_peer_and_no_gateway(self):
        self.assertEqual(server.link_actions({}, gateway=""), [])
        self.assertEqual(server.link_actions(None, gateway=""), [])
        self.assertEqual(server.link_actions(
            {"meta": {"streams_top": [{"server": "127.0.0.1", "dport": 80}]}},
            gateway=""), [])

    def test_status_endpoint_ships_link_actions_for_done_job(self):
        server_src = (ROOT / "core" / "server.py").read_text(encoding="utf-8")
        self.assertIn('data["link_actions"] = link_actions(data["result"], _gateway_now())',
                      server_src)

    def test_ui_has_confirm_modal_and_prefill(self):
        for element_id in ("link-mask", "link-confirm-text", "link-cancel", "link-go"):
            with self.subTest(id=element_id):
                self.assertIn(f'id="{element_id}"', HTML)
        self.assertIn("function linkActionsHtml", HTML)
        self.assertIn("function askLinkAction", HTML)
        self.assertIn("function applyLinkAction", HTML)
        self.assertIn("action.confirm", HTML)
        prefill = HTML.split("function applyLinkAction", 1)[1].split(
            "function wireLinkActions", 1)[0]
        self.assertIn('$("#target").value = action.target', prefill)
        self.assertIn('$("#probe-target").value = action.target', prefill)
        self.assertIn('$("#probe-port").value = ""', prefill)
        self.assertIn("已预填发现的对端", prefill)
        self.assertIn("已预填网关", prefill)
        self.assertIn("wireLinkActions(actions)", HTML)
        self.assertIn("s.link_actions || []", HTML)

    def test_link_buttons_live_inside_next_steps_block(self):
        render_block = HTML.split("function render(res, actions)", 1)[1].split(
            "function renderDegraded", 1)[0]
        self.assertIn("${steps}\n    ${linkActionsHtml(actions)}", render_block)
        degraded = HTML.split("function renderDegraded(res, actions)", 1)[1].split(
            "/* ---------- 链路体检", 1)[0]
        self.assertIn("linkActionsHtml(actions)", degraded)


class MutationAnchorsTest(unittest.TestCase):
    """把关键实现改回旧逻辑时，上面的用例必须能红（这里只钉住代码形状）。"""

    def test_passive_uses_probe_and_candidate_plan(self):
        src = (ROOT / "core" / "passive.py").read_text(encoding="utf-8")
        self.assertIn("probe_interface(ts, ordered[:3])", src)
        self.assertIn("_candidate_plan(chosen, ordered, limit=3)", src)
        self.assertIn("换第 ", src)
        self.assertIn("card\": \"empty_sessions\"", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
