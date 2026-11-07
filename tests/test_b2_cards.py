"""B2：命名映射、每模式问题卡、9 种结果卡片与降级报告落盘的契约测试。

这些用例不启动浏览器、不抓包、不依赖管理员：
* UI 侧读 ``ui/index.html`` 里的 ``ui-config``，断言 5 个新名 / 旧技术名 / 9 张卡片标题；
* 后端侧直接调 ``diagnose.degraded_empty_capture_result`` 与 ``server._worker``，
  用 mock 固定 ICMP 结果，断言降级卡片分支与报告真的落盘。
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

import diagnose  # noqa: E402
import report  # noqa: E402
import server  # noqa: E402

HTML = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
CONFIG_RE = re.compile(
    r'<script type="application/json" id="ui-config">(.*?)</script>', re.S)

NEW_NAMES = {
    "scan": ("全网体检", "全网扫描", "抓本机所有流量，看整体状况", "开始体检"),
    "live": ("单目标诊断", "定向抓包", "只看我和某个 IP/网站的通信，判断卡在哪一环",
             "开始诊断"),
    "passive": ("通信观察", "被动监听", "不发包，只看谁在和谁通信", "开始观察"),
    "probe": ("连通与速度测试", "链路体检", "主动探测，10 秒给出通不通、多快", "开始测试"),
    "offline": ("分析抓包文件", "离线分析", "别人抓的/之前存的 pcap，导入分析", "开始分析"),
}

CARD_TITLES = {
    "fault": "发现问题：四层结论与问题清单",
    "normal": "四层均正常",
    "empty_sessions": "未观察到任何 TCP/IP 会话",
    "target_unreachable": "目标不可达",
    "no_npcap": "无法抓包：缺少抓包驱动",
    "no_admin": "权限不足",
    "no_interface": "网卡不可用",
    "bad_file": "无法解析该文件",
    "internal": "分析失败",
}


def ui_config() -> dict:
    """解析页面里的 ``ui-config`` JSON 块。"""
    match = CONFIG_RE.search(HTML)
    if match is None:
        raise AssertionError("ui/index.html 缺少 id=ui-config 的 JSON 配置块")
    return json.loads(match.group(1))


class NamingContractTest(unittest.TestCase):
    """① 5 个模式改名，旧技术名保留在括号里，按钮同步。"""

    def test_five_modes_have_new_names_and_tech_alias(self):
        modes = ui_config()["modes"]
        for mode, (label, tech, sub, btn) in NEW_NAMES.items():
            with self.subTest(mode=mode):
                cfg = modes[mode]
                self.assertEqual(cfg["label"], label)
                self.assertEqual(cfg["tech"], tech)
                self.assertEqual(cfg["display"], f"{label}（{tech}）")
                self.assertEqual(cfg["sub"], sub)
                self.assertEqual(cfg["btn"], btn)

    def test_nav_shows_new_names_with_old_name_in_parentheses(self):
        for mode, (label, tech, _sub, _btn) in NEW_NAMES.items():
            with self.subTest(mode=mode):
                self.assertRegex(
                    HTML, rf'data-mode="{mode}"[\s\S]{{0,400}}?{re.escape(label)}'
                          rf'[\s\S]{{0,120}}?（{re.escape(tech)}）',
                    f"导航里必须同时出现新名 {label} 和旧技术名（{tech}）")

    def test_question_card_has_question_points_and_example(self):
        modes = ui_config()["modes"]
        for mode in NEW_NAMES:
            with self.subTest(mode=mode):
                cfg = modes[mode]
                self.assertTrue(cfg["question"].strip(), f"{mode} 缺少大问题")
                self.assertGreaterEqual(len(cfg["points"]), 2)
                self.assertLessEqual(len(cfg["points"]), 3)
                self.assertIn("例：", cfg["example"])
        for element_id in ("qcard", "q-question", "q-points", "q-example"):
            self.assertIn(f'id="{element_id}"', HTML)
        self.assertIn("function paintQuestion", HTML)

    def test_readme_and_docs_use_new_names(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for label, tech in [(v[0], v[1]) for v in NEW_NAMES.values()]:
            with self.subTest(label=label):
                self.assertIn(label, readme)
                self.assertIn(tech, readme)
        for rel in ("docs/overview.md", "docs/HANDOVER-AI.md"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            with self.subTest(doc=rel):
                for label, tech in [(v[0], v[1]) for v in NEW_NAMES.values()]:
                    self.assertTrue(label in text or tech in text,
                                    f"{rel} 缺少 {label} / {tech}")


class OutcomeCardContractTest(unittest.TestCase):
    """③ 9 种结局各有一张卡片；结果区不允许只给红字。"""

    def test_nine_cards_declared_with_exact_titles(self):
        cards = ui_config()["cards"]
        self.assertEqual(set(cards), set(CARD_TITLES))
        for kind, title in CARD_TITLES.items():
            with self.subTest(kind=kind):
                self.assertEqual(cards[kind]["title"], title)

    def test_failure_branches_map_to_each_error_card(self):
        fn = HTML.split("function failureKind", 1)[1].split("function wireFailureActions", 1)[0]
        for kind in ("no_npcap", "no_admin", "no_interface", "bad_file", "internal"):
            with self.subTest(kind=kind):
                self.assertIn(f'return "{kind}"', fn)
        for code in ("E_NO_NPCAP", "E_NO_ADMIN", "E_NO_INTERFACE",
                     "E_BAD_PCAP", "E_INTERNAL"):
            self.assertIn(code, fn)

    def test_renderers_emit_data_card_for_every_kind(self):
        for marker in ('data-card="${isNormal ? "normal" : "fault"}"',
                       'data-card="\' + esc(kind) + \'"',
                       'data-card="generic"'):
            with self.subTest(marker=marker):
                self.assertIn(marker, HTML)
        self.assertIn("四层均正常", HTML)
        self.assertIn("DNS 成功率", HTML)
        self.assertIn("未观察到任何 TCP/IP 会话", HTML)
        self.assertIn("目标不可达", HTML)

    def test_degraded_card_has_facts_reasons_three_steps_and_report_link(self):
        block = HTML.split("function renderDegraded", 1)[1].split(
            "/* ---------- 链路体检", 1)[0]
        for text in ("ICMP RTT 平均", "ICMP 响应", "目标丢包", "为什么判定目标不可达",
                     "接下来怎么做（建议按顺序执行）", "降级结论已落盘", "/api/report"):
            with self.subTest(text=text):
                self.assertIn(text, block)


class DegradedBackendTest(unittest.TestCase):
    """0 包降级的两条分支 + 落盘（复审遗留 #7 的硬验收）。"""

    def _degrade(self, target: str, stats: list[dict], gateway: str = "192.168.31.1"):
        with mock.patch.object(diagnose, "_link_stats", side_effect=stats), \
                mock.patch.object(diagnose.winapi, "default_gateway",
                                  return_value=gateway):
            return diagnose.degraded_empty_capture_result(
                target=target, duration=10, interface="12",
                capture_error="0 packets", bpf="", logger=lambda _m: None)

    def test_target_reachable_is_no_sessions_card_with_icmp_facts(self):
        res = self._degrade("baidu.com", [{
            "ok": True, "host": "baidu.com", "avg_ms": 12.5, "jitter_ms": 1.5,
            "loss_pct": 0.0, "sent": 4, "recv": 4}])
        self.assertIsNotNone(res)
        self.assertEqual(res["kind"], "empty_sessions")
        self.assertEqual(res["card_title"], "未观察到任何 TCP/IP 会话")
        self.assertTrue(res["link"]["target"]["ok"])
        self.assertIn("RTT 平均 12.5 ms", res["plain"])
        self.assertEqual(len(res["next_steps"]), 3)

    def test_unreachable_target_is_target_unreachable_card(self):
        res = self._degrade("10.255.255.1", [
            {"ok": False, "host": "10.255.255.1", "avg_ms": 0, "jitter_ms": 0,
             "loss_pct": 100.0, "sent": 4, "recv": 0},
            {"ok": True, "host": "192.168.31.1", "avg_ms": 2.0, "jitter_ms": 0.5,
             "loss_pct": 0.0, "sent": 4, "recv": 4},
        ])
        self.assertIsNotNone(res)
        self.assertEqual(res["kind"], "target_unreachable")
        self.assertEqual(res["card_title"], "目标不可达")
        self.assertFalse(res["link"]["target"]["ok"])
        self.assertEqual(res["link"]["target"]["host"], "10.255.255.1")
        self.assertEqual(len(res["next_steps"]), 3)
        joined = "".join(res["reasons"])
        self.assertIn("路由", joined)
        self.assertIn("防火墙", joined)

    def test_save_degraded_writes_markdown_and_json(self):
        res = self._degrade("10.255.255.1", [
            {"ok": False, "host": "10.255.255.1", "avg_ms": 0, "jitter_ms": 0,
             "loss_pct": 100.0, "sent": 4, "recv": 0},
            {"ok": True, "host": "192.168.31.1", "avg_ms": 2.0, "jitter_ms": 0.5,
             "loss_pct": 0.0, "sent": 4, "recv": 4},
        ])
        with tempfile.TemporaryDirectory() as tmp:
            paths = report.save_degraded(res, Path(tmp))
            md = Path(paths["markdown"])
            js = Path(paths["json"])
            self.assertTrue(md.is_file() and js.is_file())
            self.assertRegex(md.name, r"^degraded_\d{8}_\d{6}\.md$")
            text = md.read_text(encoding="utf-8")
            self.assertIn("目标不可达", text)
            self.assertIn("10.255.255.1", text)
            payload = json.loads(js.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "target_unreachable")
            self.assertEqual(payload["card_title"], "目标不可达")

    def test_worker_persists_degraded_report_and_finishes_done(self):
        saved = dict(server.JOB)
        saved_logs = list(server.JOB["logs"])
        fake = {"ok": True, "degraded": True, "kind": "empty_sessions",
                "card_title": "未观察到任何 TCP/IP 会话", "headline": "未捕获业务报文",
                "plain": "链路可达", "link": {"via": "target", "host": "1.1.1.1"},
                "reasons": ["原因"], "next_steps": ["建议"], "capture": {},
                "at": "2026-11-08 00:00:00"}
        try:
            with tempfile.TemporaryDirectory() as tmp, \
                    mock.patch.object(server.diagnose, "run_scan",
                                      return_value={"ok": False,
                                                    "empty_capture": True,
                                                    "error": "0 packets",
                                                    "bpf": "",
                                                    "interface": "12"}), \
                    mock.patch.object(server.diagnose,
                                      "degraded_empty_capture_result",
                                      return_value=fake), \
                    mock.patch.object(server, "REPORTS", Path(tmp)), \
                    mock.patch.object(server, "log"):
                server._worker("live", "10.255.255.1", 5, "12", None)
                reports = list(Path(tmp).glob("degraded_*.md"))
                self.assertEqual(server.JOB["state"], "done")
                self.assertTrue(server.JOB["result"].get("degraded"))
                self.assertEqual(len(reports), 1, "降级卡片必须同时落盘一份报告")
                self.assertIn(reports[0].name,
                              server.JOB["result"]["report"]["markdown"])
        finally:
            server.JOB.clear()
            server.JOB.update(saved)
            server.JOB["logs"] = saved_logs


class ErrorCodeTest(unittest.TestCase):
    """后端把失败归类成稳定错误码，前端才能落到对应卡片。"""

    def test_error_codes_cover_four_cards(self):
        cases = [
            ({"error": "Npcap 未安装或未生效，实时抓包不可用。", "degraded": True},
             "E_NO_NPCAP"),
            ({"error": "抓包权限不足（需要管理员权限 + Npcap 驱动）。", "degraded": True},
             "E_NO_ADMIN"),
            ({"error": "未枚举到可用网卡，请确认 Npcap 已安装", "degraded": True},
             "E_NO_INTERFACE"),
            ({"error": "解析失败(rc=2): The file isn't a capture file", "degraded": False},
             "E_BAD_PCAP"),
        ]
        for result, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(diagnose._error_code(result), expected)

    def test_worker_exposes_error_code_for_ui_card(self):
        saved = dict(server.JOB)
        saved_logs = list(server.JOB["logs"])
        try:
            with mock.patch.object(server.diagnose, "run_scan",
                                   return_value={"ok": False, "degraded": True,
                                                 "error": "Npcap 未安装或未生效"}), \
                    mock.patch.object(server, "log"):
                server._worker("live", "", 5, None, None)
            self.assertEqual(server.JOB["state"], "error")
            self.assertEqual(server.JOB["error_code"], "E_NO_NPCAP")
        finally:
            server.JOB.clear()
            server.JOB.update(saved)
            server.JOB["logs"] = saved_logs


class ScanLogNamingTest(unittest.TestCase):
    """日志前缀同步：scan 模式忽略目标时必须用新名，同时保留旧技术名。"""

    def test_scan_log_uses_new_name_with_tech_alias(self):
        saved = dict(server.JOB)
        saved_logs = list(server.JOB["logs"])
        try:
            with mock.patch.object(server.logstore, "diag_log"), \
                    mock.patch.object(server, "_worker"), \
                    mock.patch.object(server.threading, "Thread") as thread:
                thread.return_value.start.return_value = None
                self.assertTrue(server.start_job(
                    {"mode": "scan", "target": "10.0.0.1", "duration": 5})["ok"])
            text = "\n".join(row["m"] for row in server.JOB["logs"])
            self.assertIn("全网体检（全网扫描）模式忽略目标 10.0.0.1", text)
        finally:
            server.JOB.clear()
            server.JOB.update(saved)
            server.JOB["logs"] = saved_logs


class NameMappingDocsTest(unittest.TestCase):
    """⑤ 文档同步不能只改 UI：README 模式段 + 生成后的 api-reference 都要有新名。"""

    def test_api_reference_contains_new_names(self):
        text = (ROOT / "docs" / "api-reference.md").read_text(encoding="utf-8")
        self.assertIn("单目标诊断（定向抓包）", text)
        self.assertIn("全网体检", text)
        self.assertIn("连通与速度测试", text)

    def test_copy_table_has_degraded_report_section_but_old_report_unchanged(self):
        copy = json.loads((ROOT / "core" / "copy" / "zh-CN.json").read_text(
            encoding="utf-8"))
        self.assertIn("degraded_report", copy)
        # 旧报告章节不许被本次改动删掉或改名
        for key in ("section_points", "section_steps", "section_streams",
                    "section_app", "section_tech", "section_machine"):
            self.assertIn(key, copy["report"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
