"""E2 UI / HTTP 结论卡：状态加法字段、复制整块、导出 .md/.json、旧载荷降级。

守的口径（``E-IMPL-SPEC`` V9 / 用户定稿 §1-四）：

* ``/api/status`` 用**加法字段**下发同一 ``build_conclusion`` 产物 +
  服务端预渲染的 ``conclusion_text`` / ``conclusion_markdown`` / ``conclusion_export``；
* 结论卡在正常 / 故障 / 降级 / 失败四条路径都渲染，同一卡片连续展示
  「结论 → 依据 → 本次覆盖 → 明确未覆盖 → 置信等级/关键边界」，**不可折叠**；
* 「复制给协作方」复制服务端 ``render_conclusion_text`` 整块（含报告标识），
  不是只复制结论句；`.json` 导出 = CLI ``--json`` 的 conclusion + 元信息；
* 旧 payload 没有边界字段时显式降级为「未知（原因：旧数据缺少边界字段）」+ 低等级。

本文件不跑浏览器（CI 没有 Edge）：headless 证据在 ``D:\\utest\\review`` 单独留档。
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import conclusion  # noqa: E402
import diagnose  # noqa: E402
import server  # noqa: E402
import verdict  # noqa: E402

HTML = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
#: P1 起样式在 ``ui/app.css``；样式切片与断言改读这个文件。
CSS = (ROOT / "ui" / "app.css").read_text(encoding="utf-8")
COPY = json.loads(
    (ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8"))
CONCL_COPY = COPY["conclusion"]


def _result() -> dict:
    """造一份最小可渲染诊断结果（与 report/CLI 用例同形）。"""
    result = {
        "ok": True,
        "meta": {
            "pcap_name": "ui_sample.pcap", "packets": 20, "duration": 10.0,
            "tcp_packets": 8, "streams_total": 2, "dns_total": 3, "http_req": 1,
            "icmp_unreach": 0, "icmp_timeout": 0, "arp_req": 1, "arp_req_max": 1,
            "interface": "test0", "bpf": "", "generated_at": "2026-01-01 00:00:00",
            "streams_top": [
                {"stream": "0", "client": "192.0.2.10", "sport": "50000",
                 "server": "192.0.2.20", "dport": "443", "app": "TLS",
                 "packets": 9, "bytes": 900, "rtt_avg": 10.0, "retrans": 0,
                 "frames": ["1", "2"]},
            ],
        },
        "rows": [],
        "metrics": {"retrans_rate": 0.0},
        "summary": {"target": "192.0.2.20", "critical_count": 0, "warning_count": 0},
        "report": {"markdown": "reports/ui_sample.md", "json": "reports/ui_sample.json"},
    }
    result["verdict"] = verdict.build(result)
    return result


def _slice(start: str, end: str) -> str:
    begin = HTML.index(start)
    return HTML[begin:HTML.index(end, begin)]


class StatusConclusionPayloadTest(unittest.TestCase):
    """状态接口加法字段：同一 build_conclusion、预渲染整块、导出结构。"""

    def setUp(self):
        self.result = _result()
        self.block = conclusion.build_conclusion(self.result, self.result["verdict"])
        self.enriched = server._attach_conclusion(self.result)

    def test_status_conclusion_is_build_conclusion_output(self):
        self.assertEqual(server.build_status_conclusion(self.result), self.block)

    def test_attach_does_not_mutate_job_result_and_adds_fields(self):
        self.assertNotIn("conclusion", self.result)
        self.assertIsNot(self.enriched, self.result)
        self.assertEqual(self.enriched["conclusion"], self.block)
        for key in ("conclusion_text", "conclusion_markdown", "conclusion_export"):
            with self.subTest(key=key):
                self.assertIn(key, self.enriched)

    def test_copy_text_is_whole_block_with_report_identity(self):
        report_id = server.conclusion_report_id(self.result)
        self.assertIn("ui_sample.md", report_id)
        self.assertEqual(
            self.enriched["conclusion_text"],
            conclusion.render_conclusion_text(self.block, report_id))
        text = self.enriched["conclusion_text"]
        self.assertIn(self.block["conclusion"], text)
        for item in (self.block["basis"] + self.block["coverage"]
                     + self.block["not_covered"]):
            self.assertIn(item, text)
        self.assertIn(self.block["confidence_level"], text)
        self.assertIn(self.block["key_limit"], text)
        self.assertIn("报告标识", text)
        self.assertIn("ui_sample.md", text)

    def test_markdown_export_is_renderer_output_with_report_identity(self):
        report_id = server.conclusion_report_id(self.result)
        self.assertEqual(
            self.enriched["conclusion_markdown"],
            conclusion.render_conclusion_markdown(self.block, report_id))
        self.assertIn("报告标识", self.enriched["conclusion_markdown"])

    def test_export_json_is_cli_conclusion_plus_meta(self):
        export = self.enriched["conclusion_export"]
        self.assertEqual(export["conclusion"], diagnose._cli_payload(self.result)["conclusion"])
        self.assertEqual(set(export["meta"]),
                         {"report_id", "generated_at", "pcap_name", "report"})
        self.assertIn("ui_sample.md", export["meta"]["report_id"])
        self.assertEqual(export["meta"]["pcap_name"], "ui_sample.pcap")
        self.assertEqual(export["meta"]["report"],
                         {"markdown": "ui_sample.md", "json": "ui_sample.json"})

    def test_ui_copy_labels_come_from_copy_table(self):
        labels = self.enriched["ui_copy"]["conclusion"]
        self.assertEqual(labels["btn_copy"], CONCL_COPY["btn_copy"])
        self.assertEqual(labels["ui_title"], CONCL_COPY["ui_title"])
        self.assertEqual(labels["ui_kicker"], CONCL_COPY["ui_kicker"])

    def test_old_payload_has_explicit_fallback_text_and_low_level(self):
        legacy = CONCL_COPY["fallback_unknown"]
        self.assertEqual(legacy, "未知（原因：旧数据缺少边界字段）")
        self.assertEqual(CONCL_COPY["fallback_title"], "旧数据兼容（低置信）")
        card_fn = _slice("function conclusionData(res)", "function conclusionTextFallback")
        self.assertIn("fallback_unknown", card_fn)
        self.assertIn("confidence: 0.3", card_fn)
        self.assertIn('confidence_level: "低"', card_fn)

    def test_degraded_result_still_gets_a_low_conclusion(self):
        degraded = {"ok": True, "degraded": True,
                    "headline": "未捕获业务报文，但链路可达",
                    "capture": {"duration": 10, "target": "192.0.2.20"}}
        block = server.build_status_conclusion(degraded)
        self.assertIn("未捕获业务报文", block["conclusion"])
        self.assertEqual(block["confidence"], 0.3)
        self.assertEqual(block["confidence_level"], "低")
        self.assertEqual(block["key_limit"], CONCL_COPY["key_limit"]["low"])
        self.assertTrue(block["basis"] and block["coverage"] and block["not_covered"])

    def test_status_route_ships_status_conclusion_additively(self):
        source = (ROOT / "core" / "server.py").read_text(encoding="utf-8")
        begin = source.index('if path == "/api/status":')
        status_route = source[begin:source.index('if path == "/api/interfaces":', begin)]
        self.assertIn('data["conclusion"] = build_status_conclusion', status_route)
        self.assertIn("_attach_conclusion", status_route)
        self.assertIn('data["ui_copy"] = {"conclusion": _conclusion_ui_copy()}', status_route)

    def test_ui_copy_helper_reads_copy_table(self):
        table = {"conclusion": {"ui_title": "自定义标题", "btn_copy": "复制"}}
        with mock.patch.object(server.copytext, "load_table", return_value=table):
            labels = server._conclusion_ui_copy()
        self.assertEqual(labels["ui_title"], "自定义标题")
        self.assertEqual(labels["btn_copy"], "复制")


class UiCardStructureTest(unittest.TestCase):
    """结论卡：同卡片连续四段 + 置信行、不可折叠、按钮齐全。"""

    def test_card_contains_all_parts_in_reading_order(self):
        card = _slice("function conclusionCard(res)", "function downloadText")
        order = [
            'data-concl="conclusion"',
            'list(copy.ui_basis_heading || "依据", "basis"',
            'list(copy.ui_coverage_heading || "本次覆盖", "coverage"',
            'list(copy.ui_not_covered_heading || "明确未覆盖", "not_covered"',
            'data-concl="confidence"',
        ]
        positions = [card.index(marker) for marker in order]
        self.assertEqual(positions, sorted(positions),
                         "结论卡 DOM 顺序必须是 结论→依据→覆盖→未覆盖→置信/边界")
        self.assertNotIn("<details", card, "边界不允许默认折叠")
        self.assertNotIn("hidden", card, "边界不允许默认隐藏")
        for element_id in ("conclusion-copy", "conclusion-export-md",
                           "conclusion-export-json", "conclusion-card"):
            with self.subTest(id=element_id):
                self.assertIn(element_id, card)

    def test_card_has_no_collapsible_css(self):
        css = CSS[CSS.index("/* ---------------- 结论与边界卡"):CSS.index("/* ---------------- 分层条")]
        self.assertNotIn("display:none", css)
        self.assertNotIn("visibility:hidden", css)

    def test_all_result_paths_render_the_card(self):
        render_fn = _slice("function render(res, actions)", "/* ---------- 0 包降级结果页")
        self.assertIn("${conclusionCard(res)}", render_fn)
        self.assertIn("wireConclusionActions(res);", render_fn)
        degraded_fn = _slice("function renderDegraded(res, actions)", "/* ---------- 链路体检")
        self.assertIn("+ conclusionCard(res)", degraded_fn)
        self.assertIn("wireConclusionActions(res);", degraded_fn)
        failure_fn = _slice("function renderFailureCard(kind, why)", "function failedResult")
        self.assertIn("+ conclusionCard(null)", failure_fn)
        self.assertIn("wireConclusionActions(null);", failure_fn)
        generic_fn = _slice("function failedResult(title, detail, code)",
                           "function classifyLog")
        self.assertIn("+ conclusionCard(null)", generic_fn)
        self.assertIn("wireConclusionActions(null);", generic_fn)

    def test_copy_button_copies_server_rendered_whole_block(self):
        wire = _slice("function wireConclusionActions(res)", "function render(res, actions)")
        self.assertIn("res.conclusion_text", wire)
        self.assertIn("text = (res && typeof res.conclusion_text", wire)
        self.assertIn("conclusionTextFallback(res)", wire)
        # 复制内容不是只取结论句：
        self.assertNotIn("text = res.conclusion.conclusion", wire)

    def test_export_buttons_use_server_payload(self):
        wire = _slice("function wireConclusionActions(res)", "function render(res, actions)")
        self.assertIn("res.conclusion_markdown", wire)
        self.assertIn("res.conclusion_export", wire)
        self.assertIn("-conclusion.md", wire)
        self.assertIn("-conclusion.json", wire)
        json_export = wire[wire.index("const payload = (res && res.conclusion_export"):
                           wire.index("const meta = (res && res.meta)", wire.index("const payload = (res && res.conclusion_export"))]
        self.assertIn("conclusion_export", json_export)

    def test_poll_picks_up_ui_copy_conclusion(self):
        self.assertIn("s.ui_copy.conclusion", HTML)
        self.assertIn("CONCLUSION_COPY", HTML)


class RendererReportIdentityTest(unittest.TestCase):
    """报告标识只在复制/导出追加；报告正文不传 id，保持逐字节不变。"""

    def setUp(self):
        self.block = conclusion.build_conclusion(_result())
        self.plain = conclusion.render_conclusion_text(self.block)
        self.identified = conclusion.render_conclusion_text(
            self.block, "reports/ui_sample.md · 2026-01-01 00:00:00")

    def test_text_report_id_is_additive_single_line(self):
        self.assertEqual(self.identified, self.plain + "报告标识：reports/ui_sample.md · 2026-01-01 00:00:00\n")

    def test_markdown_report_id_is_additive_single_line(self):
        plain = conclusion.render_conclusion_markdown(self.block)
        identified = conclusion.render_conclusion_markdown(
            self.block, "reports/ui_sample.md · 2026-01-01 00:00:00")
        self.assertEqual(identified, plain + "报告标识：reports/ui_sample.md · 2026-01-01 00:00:00\n")

    def test_markdown_without_report_id_is_unchanged(self):
        self.assertNotIn("报告标识", conclusion.render_conclusion_markdown(self.block))


if __name__ == "__main__":
    unittest.main(verbosity=2)
