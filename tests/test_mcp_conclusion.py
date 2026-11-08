"""E2 MCP 契约：诊断工具返回结构化结论 + 边界必填 + 描述措辞 + 工具名不变。

守的口径（``E-IMPL-SPEC`` V12 / 用户定稿 §1-四）：

* 输出 JSON Schema 把 ``conclusion`` 里的 ``basis`` / ``coverage`` / ``not_covered``
  设为 **required**；本地最小校验器缺一即报错，不允许静默返回；
* ``analyze_pcap`` / ``capture_live_packets`` / ``scan_network_threats`` 返回
  ``{ok, conclusion, markdown, summary?}``，结论来自同一 ``build_conclusion``；
* 工具 description 逐字包含「返回的结论必须连同边界字段一起读取，单独展示结论视为误用」；
* 既有工具名 / 参数名不变（AGENTS：改已有工具名/参数名算破坏）。

本文件不需要 tshark / 网络 / 管理员权限：``diagnose.run_scan`` 全部替身。
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import verdict  # noqa: E402

SERVER_PATH = ROOT / "mcp" / "wireshark-mcp" / "server.py"
_spec = importlib.util.spec_from_file_location("wireshark_mcp_server_e2", SERVER_PATH)
mcp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mcp)

WORDING = "返回的结论必须连同边界字段一起读取，单独展示结论视为误用"
DIAG_TOOLS = ("analyze_pcap", "capture_live_packets", "scan_network_threats")
LEGACY_TOOLS = ("probe_link", "listen_flows")
ALL_TOOLS = DIAG_TOOLS + LEGACY_TOOLS + ("list_interfaces", "doctor")


def _result() -> dict:
    """造一份最小可渲染诊断结果（verdict 用真实 build 现算）。"""
    result = {
        "ok": True,
        "meta": {
            "pcap_name": "mcp_sample.pcap", "packets": 20, "duration": 10.0,
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
    }
    result["verdict"] = verdict.build(result)
    return result


def _tool(name: str) -> dict:
    return next(item for item in mcp.TOOLS if item["name"] == name)


def _payload_from_tool(name: str, args: dict) -> dict:
    """调用工具并把 content[0].text 解析成 JSON（非 JSON 直接让用例红）。"""
    response = mcp.call_tool(name, args)
    assert response["isError"] is False, response
    assert len(response["content"]) == 1
    return json.loads(response["content"][0]["text"])


class OutputSchemaTest(unittest.TestCase):
    """输出 Schema：三个边界字段 required，本地校验器缺一即拒。"""

    def test_schema_requires_conclusion_and_three_boundary_fields(self):
        required = set(mcp.CONCLUSION_SCHEMA["required"])
        for key in ("conclusion", "basis", "coverage", "not_covered",
                    "confidence", "confidence_level", "key_limit"):
            with self.subTest(key=key):
                self.assertIn(key, required)

    def test_valid_payload_passes(self):
        payload = mcp.build_diagnostic_payload(_result())
        self.assertEqual(mcp.validate_payload(payload), [])

    def test_missing_each_required_boundary_field_is_rejected(self):
        base = mcp.build_diagnostic_payload(_result())
        for key in ("basis", "coverage", "not_covered"):
            with self.subTest(key=key):
                broken = json.loads(json.dumps(base, ensure_ascii=False))
                broken["conclusion"].pop(key)
                errors = mcp.validate_payload(broken)
                self.assertTrue(errors, f"删掉 conclusion.{key} 必须被校验器拒绝")
                self.assertTrue(any(key in line for line in errors), errors)

    def test_diag_text_refuses_invalid_payload(self):
        broken = {"ok": True, "conclusion": {"conclusion": "只有一句结论"},
                  "markdown": "x"}
        with mock.patch.object(mcp, "build_diagnostic_payload", return_value=broken):
            response = mcp._diag_text(_result())
        self.assertTrue(response["isError"])
        self.assertIn("缺 required", response["content"][0]["text"])

    def test_only_diagnostic_tools_declare_output_schema(self):
        for name in DIAG_TOOLS:
            with self.subTest(name=name):
                self.assertIs(_tool(name)["outputSchema"], mcp.DIAG_OUTPUT_SCHEMA)
        for name in LEGACY_TOOLS:
            with self.subTest(name=name):
                self.assertNotIn("outputSchema", _tool(name),
                                 "不产生诊断结论的工具不应伪装成结论出口")


class DiagnosticToolReturnTest(unittest.TestCase):
    """三个诊断工具统一返回结构化 JSON；结论字段必填且与渲染器同源。"""

    def test_three_diagnostic_tools_return_structured_conclusion(self):
        result = _result()
        cases = [
            ("analyze_pcap", {"pcap_file": "dummy.pcap"}),
            ("capture_live_packets", {"target_ip": "192.0.2.20", "duration": 5}),
            ("scan_network_threats", {"duration": 5}),
        ]
        with mock.patch.object(mcp.diagnose, "run_scan", return_value=result) as scan:
            for name, args in cases:
                with self.subTest(name=name):
                    payload = _payload_from_tool(name, args)
                    self.assertTrue(payload["ok"])
                    block = payload["conclusion"]
                    for key in ("conclusion", "basis", "coverage", "not_covered",
                                "confidence", "confidence_level", "key_limit"):
                        self.assertIn(key, block)
                    self.assertTrue(block["conclusion"].strip())
                    self.assertTrue(block["basis"])
                    self.assertTrue(block["coverage"])
                    self.assertTrue(block["not_covered"])
                    self.assertIn(block["conclusion"], payload["markdown"])
                    self.assertEqual(set(payload["summary"]),
                                     {"target", "critical_count", "warning_count"})
            self.assertEqual(scan.call_count, len(cases))

    def test_conclusion_comes_from_shared_build_conclusion(self):
        result = _result()
        expected = mcp.conclusion.build_conclusion(result, result["verdict"])
        with mock.patch.object(mcp.diagnose, "run_scan", return_value=result):
            payload = _payload_from_tool("analyze_pcap", {"pcap_file": "dummy.pcap"})
        self.assertEqual(payload["conclusion"], expected)

    def test_tool_description_carries_user_wording(self):
        for name in DIAG_TOOLS:
            with self.subTest(name=name):
                self.assertIn(WORDING, _tool(name)["description"])


class ToolCompatibilityTest(unittest.TestCase):
    """工具名 / 参数名回归：MCP 是外部契约，已有名字不能改。"""

    def test_tool_names_unchanged(self):
        self.assertEqual({item["name"] for item in mcp.TOOLS}, set(ALL_TOOLS))

    def test_input_properties_unchanged(self):
        expected = {
            "list_interfaces": set(),
            "capture_live_packets": {"target_ip", "duration", "interface"},
            "scan_network_threats": {"duration", "interface"},
            "analyze_pcap": {"pcap_file", "target"},
            "probe_link": {"target", "port", "count", "proto"},
            "listen_flows": {"target", "duration", "interface", "engine"},
            "doctor": set(),
        }
        for name, keys in expected.items():
            with self.subTest(name=name):
                self.assertEqual(set(_tool(name)["inputSchema"]["properties"]), keys)

    def test_required_arguments_unchanged(self):
        self.assertEqual(_tool("analyze_pcap")["inputSchema"]["required"], ["pcap_file"])
        self.assertEqual(_tool("probe_link")["inputSchema"]["required"], ["target"])
        for name in ("capture_live_packets", "scan_network_threats", "listen_flows"):
            with self.subTest(name=name):
                self.assertNotIn("required", _tool(name)["inputSchema"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
