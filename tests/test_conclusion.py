"""E1 结论边界结构化：契约 / 推导 / 模板 / 渲染器 / 报告 / CLI / 取证单 / 诊断包。

守的口径（对应 ``E-IMPL-SPEC`` V1~V8、V10、V11、V13~V16）：

* ``Verdict`` 的 ``confidence`` 有 [0,1] 校验，``confidence_level`` 是派生属性
  （不是 dataclass 字段、无法人工赋值），阈值常量可测；
* ``derive_confidence`` 三档 0.9 / 0.65 / 0.3 全部由证据形态算出来，没有 setter；
* ``key_limit`` 由等级从 copy 表选（高/中/低三条与用户原文一致），且不落库；
* conclusion 句只由 copy 模板渲染，必须同时含 ``basis_short`` 与 ``key_limit``，
  禁止绝对化措辞；
* 双轨：静态覆盖项在 copy 表，运行时事实来自本次 result；两条不同结果不串味；
* 填 充失败 → 「未知（原因：…）」且 confidence=0.3/低，禁止空串、禁止吞异常；
* 报告 md 同节输出结论+覆盖/未覆盖，JSON 的 verdict 块只新增四键；
* CLI ``--json`` 与报告/取证单同源；人读模式就是同一份报告；诊断包 README 有说明。

本文件**不需要 tshark / 网络 / 管理员权限**：CLI 路径 mock 掉 ``run_scan``。
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import conclusion                                          # noqa: E402
import contracts                                           # noqa: E402
import copytext                                            # noqa: E402
import diagnose                                            # noqa: E402
import diagpack                                            # noqa: E402
import evidence                                            # noqa: E402
import logstore                                            # noqa: E402
import report                                              # noqa: E402
import server                                              # noqa: E402
import verdict                                             # noqa: E402

COPY_PATH = ROOT / "core" / "copy" / "zh-CN.json"
COPY = json.loads(COPY_PATH.read_text(encoding="utf-8"))
CONCL = COPY["conclusion"]


def _row(layer: str = "L4 传输层", category: str = "传输质量",
         severity: str = "警告", protocol: str = "TCP") -> dict:
    """造一条与 analyzer 同形的 ``rows[]`` 行。"""
    return {"layer": layer, "protocol": protocol, "category": category,
            "finding": f"构造行：{category}", "severity": severity,
            "evidence": "构造证据", "advice": "构造建议"}


def _meta(**overrides) -> dict:
    """一份「单侧证据」形态的最小 meta（可用关键字覆盖任意键）。"""
    meta = {
        "pcap_name": "conclusion_sample.pcap", "packets": 20, "duration": 10.0,
        "tcp_packets": 8, "streams_total": 2, "dns_total": 3, "http_req": 1,
        "icmp_unreach": 0, "icmp_timeout": 0, "arp_req": 1, "arp_req_max": 1,
        "interface": "test0", "bpf": "", "generated_at": "",
        "streams_top": [
            {"stream": "0", "client": "192.0.2.10", "sport": "50000",
             "server": "192.0.2.20", "dport": "443", "app": "TLS",
             "packets": 9, "bytes": 900, "rtt_avg": 10.0, "retrans": 0,
             "frames": ["1", "2"]},
            {"stream": "1", "client": "192.0.2.10", "sport": "50001",
             "server": "192.0.2.30", "dport": "8080", "app": "HTTP",
             "packets": 6, "bytes": 600, "rtt_avg": 12.0, "retrans": 0,
             "frames": ["3", "4"]},
        ],
    }
    meta.update(overrides)
    return meta


def _result(meta: dict | None = None, rows: list[dict] | None = None,
            target: str = "192.0.2.20") -> dict:
    """造一份最小可渲染 result（verdict 用真实 ``verdict.build`` 现算）。"""
    result = {
        "ok": True,
        "meta": meta if meta is not None else _meta(),
        "rows": rows if rows is not None else [],
        "metrics": {"retrans_rate": 0.0},
        "summary": {"target": target, "critical_count": 0, "warning_count": 0},
    }
    result["verdict"] = verdict.build(result)
    return result


def _probe_baseline(gateway_n: int = 3, target_n: int = 3,
                    gateway_loss: float = 0.0, target_loss: float = 0.0) -> dict:
    """造一份「网关 + 对端」双侧探针基线（默认两侧样本都够且不丢包）。"""
    return {
        "probe_count": 12, "sent": 12, "recv": 12, "excluded_packets": 0,
        "roles": [
            {"role": "gateway", "kind": "icmp", "target": "192.0.2.1",
             "sent": gateway_n, "recv": gateway_n, "loss_pct": gateway_loss,
             "n": gateway_n},
            {"role": "target", "kind": "tcp_syn", "target": "192.0.2.20",
             "sent": target_n, "recv": target_n, "loss_pct": target_loss,
             "n": target_n},
        ],
    }


@contextlib.contextmanager
def _patched_copy(table: dict):
    """把文案来源临时换成 ``table``；必须显式清 copytext 缓存（按 mtime 失效）。"""
    with mock.patch("core.config.load_copy", return_value=table):
        copytext.reload()
        try:
            yield
        finally:
            copytext.reload()


def _conclusion_copy() -> dict:
    """深拷贝真实 conclusion section（用于局部改模板的变异式用例）。"""
    return copy.deepcopy(CONCL)


# ---------------------------------------------------------------- V1 契约


class VerdictContractTests(unittest.TestCase):
    """V1：契约字段、[0,1] 校验、派生属性与阈值常量。"""

    def test_verdict_has_confidence_and_three_boundary_tuples(self):
        v = contracts.Verdict(level=contracts.Severity.OK, headline_key="VERDICT.OK",
                              confidence=0.65, basis=("b1",), coverage=("c1",),
                              not_covered=("n1",))
        self.assertEqual(v.confidence, 0.65)
        self.assertEqual(v.basis, ("b1",))
        self.assertEqual(v.coverage, ("c1",))
        self.assertEqual(v.not_covered, ("n1",))
        self.assertEqual(v.confidence_level, "中")

    def test_confidence_out_of_range_raises_value_error(self):
        for bad in (-0.01, 1.01, "abc", None, float("nan")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    contracts.Verdict(level=contracts.Severity.OK,
                                      headline_key="x", confidence=bad)

    def test_confidence_level_thresholds_are_exact(self):
        cases = ((1.0, "高"), (0.85, "高"), (0.849, "中"),
                 (0.5, "中"), (0.499, "低"), (0.0, "低"))
        for value, want in cases:
            with self.subTest(value=value):
                self.assertEqual(contracts.confidence_level_of(value), want)
                v = contracts.Verdict(level=contracts.Severity.OK,
                                      headline_key="x", confidence=value)
                self.assertEqual(v.confidence_level, want)

    def test_threshold_constants_exist_and_match_user_definition(self):
        self.assertEqual(contracts.CONFIDENCE_HIGH_MIN, 0.85)
        self.assertEqual(contracts.CONFIDENCE_MEDIUM_MIN, 0.5)

    def test_confidence_level_is_not_a_dataclass_field(self):
        names = {f.name for f in fields(contracts.Verdict)}
        self.assertNotIn("confidence_level", names)
        self.assertNotIn("key_limit", names)

    def test_confidence_level_cannot_be_assigned_by_hand(self):
        with self.assertRaises(TypeError):
            contracts.Verdict(level=contracts.Severity.OK, headline_key="x",
                              confidence_level="高")
        v = contracts.Verdict(level=contracts.Severity.OK, headline_key="x")
        with self.assertRaises(FrozenInstanceError):
            v.confidence_level = "低"

    def test_schema_version_was_bumped_for_contract_change(self):
        self.assertEqual(contracts.SCHEMA_VERSION, "2.2")
        fixture = ROOT / "tests" / "fixtures" / "faults_features.json"
        data = json.loads(fixture.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], contracts.SCHEMA_VERSION)

    def test_verdict_to_dict_serializes_boundary_but_not_level_or_key_limit(self):
        v = contracts.Verdict(level=contracts.Severity.OK, headline_key="x",
                              confidence=0.3, basis=("b",), coverage=("c",),
                              not_covered=("n",))
        data = v.to_dict()
        self.assertEqual(data["confidence"], 0.3)
        self.assertEqual(data["basis"], ["b"])
        self.assertNotIn("confidence_level", data)
        self.assertNotIn("key_limit", data)


# ---------------------------------------------------------------- V2 推导


class DeriveConfidenceTests(unittest.TestCase):
    """V2：三档 confidence 由证据推导；没有人工 setter。"""

    def test_has_no_setter_or_manual_entry(self):
        self.assertFalse(hasattr(conclusion, "set_confidence"))
        self.assertFalse(hasattr(conclusion, "confidence_score"))
        with self.assertRaises(TypeError):
            conclusion.derive_confidence()             # 必填 result

    def test_contrast_both_sides_consistent_is_high(self):
        result = _result(_meta(probe_baseline=_probe_baseline()))
        self.assertEqual(conclusion.derive_confidence(result), 0.9)
        self.assertEqual(conclusion.build_conclusion(result)["confidence_level"], "高")

    def test_contrast_requires_both_roles(self):
        baseline = _probe_baseline()
        baseline["roles"] = [baseline["roles"][1]]        # 只有 target
        result = _result(_meta(probe_baseline=baseline))
        self.assertEqual(conclusion.derive_confidence(result), 0.65)

    def test_contrast_requires_two_samples_per_side(self):
        result = _result(_meta(probe_baseline=_probe_baseline(
            gateway_n=1, target_n=3)))
        self.assertEqual(conclusion.derive_confidence(result), 0.65)

    def test_contrast_with_high_loss_is_not_consistent(self):
        result = _result(_meta(probe_baseline=_probe_baseline(
            gateway_loss=40.0, target_loss=0.0)))
        self.assertEqual(conclusion.derive_confidence(result), 0.65)

    def test_contrast_pointing_at_target_blocks_high(self):
        result = _result(_meta(probe_baseline=_probe_baseline()),
                         rows=[_row(severity="严重")])
        result["verdict"]["probe_contrast"] = {"code": "PROBE.CONTRAST.TARGET_SIDE"}
        self.assertEqual(conclusion.derive_confidence(result), 0.65)

    def test_capture_only_is_single_side_medium(self):
        self.assertEqual(conclusion.derive_confidence(_result()), 0.65)

    def test_empty_packet_is_indirect_low(self):
        result = _result(_meta(packets=0, duration=0.0))
        self.assertEqual(conclusion.derive_confidence(result), 0.3)

    def test_insufficient_dimension_is_indirect_low(self):
        result = _result(_meta(packets=3, duration=1.0, tcp_packets=0,
                               streams_total=0, dns_total=0, http_req=0,
                               icmp_unreach=0, icmp_timeout=0, arp_req=0,
                               arp_req_max=0))
        self.assertEqual(conclusion.derive_confidence(result), 0.3)

    def test_icmp_timeout_only_is_indirect_low(self):
        result = _result(_meta(packets=5, duration=5.0, tcp_packets=0,
                               streams_total=0, dns_total=0, http_req=0,
                               icmp_timeout=2, arp_req=0, arp_req_max=0))
        self.assertEqual(conclusion.derive_confidence(result), 0.3)

    def test_sampling_anomaly_is_indirect_low(self):
        result = _result(_meta(packets=5, duration=0.0))
        self.assertEqual(conclusion.derive_confidence(result), 0.3)

    def test_bad_input_is_indirect_low(self):
        self.assertEqual(conclusion.derive_confidence(None), 0.3)
        self.assertEqual(conclusion.derive_confidence("not-a-result"), 0.3)


# ---------------------------------------------------------------- V3 key_limit


class KeyLimitTests(unittest.TestCase):
    """V3：等级→key_limit 映射存在且与用户原文逐字一致。"""

    def test_copy_texts_match_user_wording_exactly(self):
        self.assertEqual(CONCL["key_limit"]["high"],
                         "业务流量 QoS/DSCP 路径未覆盖（理论边界）")
        self.assertEqual(CONCL["key_limit"]["medium"],
                         "探测/逐跳基于 ICMP，不代表 TCP 路径")
        self.assertEqual(CONCL["key_limit"]["low"],
                         "本次无有效样本或采样异常")

    def test_high_medium_low_each_select_their_own_text(self):
        high = conclusion.build_conclusion(
            _result(_meta(probe_baseline=_probe_baseline())))
        medium = conclusion.build_conclusion(_result())
        low = conclusion.build_conclusion(_result(_meta(packets=0, duration=0.0)))
        self.assertEqual((high["confidence_level"], high["key_limit"]),
                         ("高", CONCL["key_limit"]["high"]))
        self.assertEqual((medium["confidence_level"], medium["key_limit"]),
                         ("中", CONCL["key_limit"]["medium"]))
        self.assertEqual((low["confidence_level"], low["key_limit"]),
                         ("低", CONCL["key_limit"]["low"]))

    def test_key_limit_is_not_in_contract_or_report_json(self):
        names = {f.name for f in fields(contracts.Verdict)}
        self.assertNotIn("key_limit", names)
        with tempfile.TemporaryDirectory() as tmp:
            paths = report.save(_result(), Path(tmp))
            doc = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        self.assertNotIn("key_limit", doc["verdict"])
        self.assertNotIn("confidence_level", doc["verdict"])

    def test_mapping_table_is_the_only_level_to_key_source(self):
        self.assertEqual(conclusion.KEY_LIMIT_KEYS,
                         {"高": "high", "中": "medium", "低": "low"})


# ---------------------------------------------------------------- V4 模板渲染


class ConclusionTemplateTests(unittest.TestCase):
    """V4：conclusion 句必须同时含 basis_short 与 key_limit，且不许绝对化。"""

    def _block(self) -> tuple[dict, dict]:
        result = _result()
        return conclusion.build_conclusion(result), result

    def test_conclusion_contains_basis_short_and_key_limit(self):
        block, result = self._block()
        facts = conclusion._runtime_facts(result)
        basis_short = CONCL["basis_short"].format(**facts)
        self.assertIn(basis_short, block["conclusion"])
        self.assertIn(block["key_limit"], block["conclusion"])

    def test_conclusion_is_rendered_from_copy_template(self):
        result = _result()
        vd = result["verdict"]
        custom = {"conclusion": _conclusion_copy()}
        custom["conclusion"]["template"] = (
            "自定义结论：{headline}｜{basis_short}｜{key_limit}")
        with _patched_copy(custom):
            block = conclusion.build_conclusion(result, vd)
        self.assertTrue(block["conclusion"].startswith("自定义结论："))
        self.assertIn(block["key_limit"], block["conclusion"])

    def test_template_change_changes_output(self):
        result = _result()
        vd = result["verdict"]
        with _patched_copy({"conclusion": _conclusion_copy()}):
            first = conclusion.build_conclusion(result, vd)["conclusion"]
        custom = {"conclusion": _conclusion_copy()}
        custom["conclusion"]["basis_short"] = "自定义依据：{packets} 包"
        with _patched_copy(custom):
            second = conclusion.build_conclusion(result, vd)["conclusion"]
        self.assertNotEqual(first, second)
        self.assertIn("自定义依据：20 包", second)

    def test_no_absolute_wording_in_conclusion_or_boundaries(self):
        results = [
            _result(),
            _result(_meta(probe_baseline=_probe_baseline())),
            _result(_meta(packets=0, duration=0.0)),
        ]
        for result in results:
            block = conclusion.build_conclusion(result)
            blob = json.dumps(block, ensure_ascii=False)
            for phrase in conclusion.ABSOLUTE_WORDING:
                with self.subTest(phrase=phrase):
                    self.assertNotIn(phrase, blob)

    def test_normal_headline_keeps_existing_wording(self):
        result = _result(meta=_meta(tcp_packets=8), rows=[
            _row(severity="—", category="传输质量")])
        block = conclusion.build_conclusion(result)
        self.assertIn(result["verdict"]["headline"], block["conclusion"])
        self.assertNotIn("链路正常", block["conclusion"])


# ---------------------------------------------------------------- V5 双轨


class DualTrackTests(unittest.TestCase):
    """V5：静态项来自 copy 表，运行时值来自本次 result，两者不混淆。"""

    def test_static_coverage_items_are_shared_by_two_results(self):
        a = conclusion.build_conclusion(_result(target="alpha.example"))
        b = conclusion.build_conclusion(_result(target="beta.example"))
        for item in CONCL["coverage_static"]:
            self.assertIn(item, a["coverage"])
            self.assertIn(item, b["coverage"])
        for item in CONCL["not_covered_static"]:
            self.assertIn(item, a["not_covered"])
            self.assertIn(item, b["not_covered"])

    def test_runtime_values_differ_between_two_results(self):
        a = conclusion.build_conclusion(_result(_meta(duration=7.0), target="alpha.example"))
        b = conclusion.build_conclusion(_result(_meta(duration=9.0), target="beta.example"))
        joined_a = "\n".join(a["coverage"])
        joined_b = "\n".join(b["coverage"])
        self.assertIn("7 秒", joined_a)
        self.assertIn("9 秒", joined_b)
        self.assertIn("alpha.example", joined_a)
        self.assertIn("beta.example", joined_b)
        self.assertNotIn("9 秒", joined_a)
        self.assertNotIn("alpha.example", joined_b)

    def test_runtime_templates_are_placeholders_not_baked_values(self):
        runtime_templates = [CONCL["basis_short"]]
        runtime_templates += list(CONCL["basis"].values())
        runtime_templates += CONCL["coverage_runtime"]
        runtime_templates.append(CONCL["coverage_runtime_probe"])
        runtime_templates.append(CONCL["not_covered_runtime"])
        for template in runtime_templates:
            with self.subTest(template=template):
                self.assertRegex(template, r"\{[a-z_]+\}",
                                 "运行时模板必须留占位符，禁止写死本次数据")

    def test_copy_table_has_no_sample_specific_numbers_or_ips(self):
        blob = json.dumps(CONCL, ensure_ascii=False)
        for baked in ("54 个报文", "16 秒", "192.168.", "判定 8 项"):
            with self.subTest(baked=baked):
                self.assertNotIn(baked, blob)

    def test_runtime_values_come_from_result_not_from_copy(self):
        result = _result(_meta(duration=7.0, packets=33), target="gamma.example")
        block = conclusion.build_conclusion(result)
        joined = "\n".join(block["coverage"])
        self.assertIn("7 秒", joined)
        self.assertIn("报文 33 个", joined)
        self.assertIn("gamma.example", joined)
        self.assertNotIn("99 秒", joined)


# ---------------------------------------------------------------- V6 降级


class DegradeTests(unittest.TestCase):
    """V6：任何填充失败 → 「未知（原因：…）」+ 低置信，禁止空串/吞异常。"""

    def test_missing_placeholder_degrades_with_reason(self):
        result = _result()
        vd = result["verdict"]
        custom = {"conclusion": _conclusion_copy()}
        custom["conclusion"]["basis_short"] = "{no_such_fact}"
        with _patched_copy(custom):
            block = conclusion.build_conclusion(result, vd)
        self.assertIn("未知（原因：", block["conclusion"])
        self.assertIn("no_such_fact", block["conclusion"])
        self.assertEqual(block["confidence"], 0.3)
        self.assertEqual(block["confidence_level"], "低")
        self.assertEqual(block["key_limit"], CONCL["key_limit"]["low"])

    def test_missing_template_degrades_with_reason(self):
        result = _result()
        vd = result["verdict"]
        custom = {"conclusion": _conclusion_copy()}
        del custom["conclusion"]["basis_short"]
        with _patched_copy(custom):
            block = conclusion.build_conclusion(result, vd)
        self.assertIn("未知（原因：", block["conclusion"])
        self.assertIn("basis_short", block["conclusion"])
        self.assertEqual(block["confidence_level"], "低")

    def test_broken_copy_table_does_not_crash_and_has_no_empty_strings(self):
        result = _result()
        for bad in ({}, {"conclusion": []}, {"conclusion": {"template": 1}}):
            with self.subTest(bad=bad), _patched_copy(bad):
                block = conclusion.build_conclusion(result, result["verdict"])
                self.assertTrue(block["conclusion"].strip())
                for key in ("basis", "coverage", "not_covered"):
                    self.assertTrue(block[key])
                    for item in block[key]:
                        self.assertTrue(str(item).strip(), f"{key} 出现空串")
                self.assertEqual(block["confidence"], 0.3)
                self.assertEqual(block["confidence_level"], "低")

    def test_bad_result_object_degrades(self):
        block = conclusion.build_conclusion(None, None)
        self.assertTrue(block["conclusion"].strip())
        self.assertEqual(block["confidence"], 0.3)
        self.assertEqual(block["confidence_level"], "低")

    def test_bad_block_renders_unknown_not_empty(self):
        for bad in (None, {}, {"conclusion": ""}):
            with self.subTest(bad=bad):
                md = conclusion.render_conclusion_markdown(bad)
                text = conclusion.render_conclusion_text(bad)
                self.assertIn("未知（原因：", md)
                self.assertIn("未知（原因：", text)
                self.assertTrue(md.strip())
                self.assertTrue(text.strip())

    def test_fill_failure_marks_basis_item_unknown_not_dropped(self):
        result = _result(_meta(probe_baseline=_probe_baseline()))
        vd = result["verdict"]
        custom = {"conclusion": _conclusion_copy()}
        custom["conclusion"]["basis"]["probe"] = "{probe_missing}"
        with _patched_copy(custom):
            block = conclusion.build_conclusion(result, vd)
        self.assertTrue(any("未知（原因：" in item for item in block["basis"]))
        self.assertEqual(block["confidence"], 0.3)


# ---------------------------------------------------------------- 渲染器


class RendererTests(unittest.TestCase):
    """统一渲染器：Markdown / 纯文本整块都含结论与边界，且纯文本无 Markdown 符号。"""

    def setUp(self):
        self.block = conclusion.build_conclusion(_result())
        self.md = conclusion.render_conclusion_markdown(self.block)
        self.text = conclusion.render_conclusion_text(self.block)

    def test_markdown_has_conclusion_basis_coverage_not_covered_and_confidence(self):
        self.assertIn(self.block["conclusion"], self.md)
        for item in self.block["basis"] + self.block["coverage"] + self.block["not_covered"]:
            self.assertIn(item, self.md)
        self.assertIn(self.block["key_limit"], self.md)
        self.assertIn(self.block["confidence_level"], self.md)

    def test_text_has_conclusion_basis_coverage_not_covered_and_confidence(self):
        self.assertIn(self.block["conclusion"], self.text)
        for item in self.block["basis"] + self.block["coverage"] + self.block["not_covered"]:
            self.assertIn(item, self.text)
        self.assertIn(self.block["key_limit"], self.text)
        self.assertIn("置信度", self.text)

    def test_text_is_plain(self):
        self.assertNotIn("|", self.text)
        self.assertNotIn("###", self.text)

    def test_markdown_ends_with_single_newline(self):
        self.assertTrue(self.md.endswith("\n"))
        self.assertFalse(self.md.endswith("\n\n"))


# ---------------------------------------------------------------- V7 报告


class ReportConclusionTests(unittest.TestCase):
    """V7：报告 md 同节输出结论+覆盖/未覆盖；JSON 只新增四键。"""

    def setUp(self):
        self.result = _result(_meta(probe_baseline=_probe_baseline()))
        self.vd = self.result["verdict"]
        self.block = conclusion.build_conclusion(self.result, self.vd)

    def test_markdown_renders_conclusion_in_first_section(self):
        md = report.render_markdown(self.result, self.vd)
        start = md.index("## 一、故障定位")
        end = md.index("### 分层定位")
        section = md[start:end]
        self.assertIn(self.block["conclusion"], section)
        self.assertIn("**本次覆盖**", section)
        self.assertIn("**明确未覆盖**", section)
        for item in self.block["coverage"] + self.block["not_covered"]:
            self.assertIn(item, section)

    def test_markdown_block_is_pure_insertion(self):
        md = report.render_markdown(copy.deepcopy(self.result), self.vd)
        rendered = conclusion.render_conclusion_markdown(self.block)
        self.assertIn(rendered, md)
        without = md.replace(rendered + "\n", "", 1)
        with mock.patch.object(report.conclusion_mod, "render_conclusion_markdown",
                               return_value=""):
            baseline = report.render_markdown(copy.deepcopy(self.result), self.vd)
        self.assertEqual(without, baseline)

    def test_markdown_ends_with_one_newline(self):
        md = report.render_markdown(self.result, self.vd)
        self.assertTrue(md.endswith("\n"))
        self.assertFalse(md.endswith("\n\n"))

    def test_json_verdict_adds_exactly_four_keys(self):
        base = verdict.build(copy.deepcopy(self.result))
        with tempfile.TemporaryDirectory() as tmp:
            paths = report.save(self.result, Path(tmp))
            doc = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        added = set(doc["verdict"]) - set(base)
        self.assertEqual(added, {"confidence", "basis", "coverage", "not_covered"})

    def test_json_verdict_excludes_render_only_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = report.save(self.result, Path(tmp))
            blob = Path(paths["json"]).read_text(encoding="utf-8")
            doc = json.loads(blob)
        self.assertNotIn("confidence_level", doc["verdict"])
        self.assertNotIn("key_limit", doc["verdict"])
        self.assertNotIn("conclusion", doc["verdict"])

    def test_json_confidence_equals_derived_confidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = report.save(self.result, Path(tmp))
            doc = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        self.assertEqual(doc["verdict"]["confidence"],
                         conclusion.derive_confidence(self.result))
        for key in ("basis", "coverage", "not_covered"):
            self.assertIsInstance(doc["verdict"][key], list)
            self.assertTrue(doc["verdict"][key])
            self.assertTrue(all(isinstance(x, str) and x.strip()
                                for x in doc["verdict"][key]))

    def test_json_still_has_exactly_five_top_level_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = report.save(self.result, Path(tmp))
            doc = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        self.assertEqual(set(doc), {"summary", "meta", "metrics", "rows", "verdict"})


# ---------------------------------------------------------------- B1 降级报告

def _degraded_result(target: str = "10.255.255.1", duration: int = 10) -> dict:
    """造一份与 ``diagnose.degraded_empty_capture_result`` 同形的降级结果。"""
    return {
        "ok": True, "degraded": True, "kind": "target_unreachable",
        "card_title": "目标不可达",
        "headline": "未捕获业务报文，但本地链路可达",
        "plain": (f"抓包窗口内没有业务报文；目标 {target} 当前没有响应，"
                  "但本机到默认网关 192.0.2.1 的链路可达。"),
        "capture": {"target": target, "interface": "WLAN",
                    "duration": duration, "bpf": f"host {target}", "error": ""},
        "link": {"via": "gateway", "host": "192.0.2.1", "avg_ms": 2.0,
                 "jitter_ms": 0.5, "loss_pct": 0.0},
        "reasons": ["目标对 ICMP 探测没有响应"], "next_steps": ["先查路由"],
        "at": "2026-11-08 20:00:00",
    }


class DegradedReportBoundaryTests(unittest.TestCase):
    """B1：0 包降级报告也是导出路径，必须同帧输出结论+边界（E-SPEC §1-四）。"""

    def setUp(self):
        self.result = _degraded_result()
        self.md = report.render_degraded(self.result)

    def test_degraded_markdown_has_conclusion_and_five_boundary_parts(self):
        """降级 md 同帧连续包含：结论 / 依据 / 本次覆盖 / 明确未覆盖 / 置信+边界。"""
        start = self.md.index("### 结论与边界")
        end = self.md.index(COPY["degraded_report"]["section_facts"])
        block = self.md[start:end]
        order = ["**结论**：", "**依据**", "**本次覆盖**", "**明确未覆盖**", "**置信度**"]
        positions = [block.index(label) for label in order]
        self.assertEqual(positions, sorted(positions), "降级结论块五要素顺序不对")
        self.assertIn("目标不可达（基于", block, "降级结论句没有用 card_title")
        self.assertIn("**置信度**：低（0.30）", block)
        self.assertIn("**关键边界**：本次无有效样本或采样异常", block)
        # 边界不是空壳：依据/覆盖/未覆盖都要有实际条目。
        for heading in ("**依据**", "**本次覆盖**", "**明确未覆盖**"):
            after = block[block.index(heading):]
            self.assertRegex(after, r"\n- \S", f"{heading} 下没有条目")

    def test_degraded_markdown_uses_shared_renderer_and_json_carries_same_object(self):
        """md 整块就是 ``render_conclusion_markdown`` 的输出；json 存同一 7 键对象。"""
        with tempfile.TemporaryDirectory() as tmp:
            paths = report.save_degraded(self.result, Path(tmp))
            md = Path(paths["markdown"]).read_text(encoding="utf-8")
            doc = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        keys = ("conclusion", "basis", "coverage", "not_covered",
                "confidence", "confidence_level", "key_limit")
        for key in keys:
            self.assertIn(key, doc, f"降级 json 缺结论键：{key}")
        block = {key: doc[key] for key in keys}
        rendered = conclusion.render_conclusion_markdown(block)
        self.assertIn(rendered, md, "降级 md 与 json 不是同一个结论对象")
        self.assertEqual(block["confidence"], 0.3)
        self.assertEqual(block["confidence_level"], "低")
        self.assertEqual(block["key_limit"], CONCL["key_limit"]["low"])
        for key in ("basis", "coverage", "not_covered"):
            self.assertTrue(block[key], f"{key} 为空")
            self.assertTrue(all(isinstance(item, str) and item.strip()
                                for item in block[key]))

    def test_degraded_conclusion_facts_come_from_capture(self):
        """facts 取 capture（target/duration），不能退回空结果或写死样本值。"""
        res = _degraded_result(target="198.51.100.7", duration=42)
        md = report.render_degraded(res)
        with tempfile.TemporaryDirectory() as tmp:
            paths = report.save_degraded(res, Path(tmp))
            doc = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        joined = "\n".join(doc["basis"] + doc["coverage"])
        self.assertIn("抓包窗口 42 秒", joined)
        self.assertIn("诊断目标 198.51.100.7", joined)
        self.assertIn("本次无有效样本或采样异常", doc["conclusion"])
        self.assertNotIn("16 秒", md)
        self.assertNotIn("54 个报文", md)


# ---------------------------------------------------------------- V8 CLI


@contextlib.contextmanager
def _temp_log_env():
    """把 ``NETDIAG_LOG_DIR`` 指到临时目录（CLI 会写 env/run 日志）。"""
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch.dict(os.environ,
                             {logstore.ENV_LOG_DIR: str(Path(tmp) / "logs")}):
            logstore.close_streams()
            try:
                yield
            finally:
                logstore.close_streams()


def _run_cli(argv: list[str], result: dict) -> tuple[int, str, str]:
    """进程内跑 CLI（``run_scan`` 用合成结果替身），返回 (rc, stdout, stderr)。"""
    out, err = io.StringIO(), io.StringIO()
    with _temp_log_env(), \
            mock.patch.object(diagnose, "run_scan", return_value=result), \
            mock.patch.object(diagnose, "_log_to_file", lambda _line: None), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = diagnose.main(argv)
    return rc, out.getvalue(), err.getvalue()


class CliConclusionTests(unittest.TestCase):
    """V8：``--json`` 输出完整结论对象；人读模式就是同一份报告。"""

    def setUp(self):
        self.result = _result()

    def test_json_has_complete_conclusion_object(self):
        rc, out, _err = _run_cli(["--pcap", "dummy.pcap", "--json"], self.result)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(set(payload),
                         {"summary", "conclusion", "level", "headline", "layer",
                          "next_steps"})
        self.assertEqual(set(payload["conclusion"]),
                         {"conclusion", "basis", "coverage", "not_covered",
                          "confidence", "confidence_level", "key_limit"})
        self.assertTrue(payload["conclusion"]["coverage"])
        self.assertIn("采样窗口", "\n".join(payload["conclusion"]["coverage"]))

    def test_json_conclusion_is_build_conclusion_output(self):
        rc, out, _err = _run_cli(["--pcap", "dummy.pcap", "--json"], self.result)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        expected = conclusion.build_conclusion(self.result,
                                               self.result["verdict"])
        self.assertEqual(payload["conclusion"], expected)

    def test_human_mode_uses_same_renderer_and_report(self):
        rc, out, _err = _run_cli(["--pcap", "dummy.pcap"], self.result)
        self.assertEqual(rc, 0)
        expected_md = report.render_markdown(self.result, self.result["verdict"])
        self.assertIn(expected_md.strip(), out)
        block = conclusion.build_conclusion(self.result, self.result["verdict"])
        self.assertIn(conclusion.render_conclusion_markdown(block).rstrip("\n"), out)

    def test_help_documents_json_behavior_change(self):
        # CI 的 Windows runner 控制台是 cp1252；``_harden_console`` 会把中文转成
        # ``\uXXXX`` 可见转义。断言只取 ASCII 片段，避免测试依赖终端编码。
        proc = subprocess.run(
            [sys.executable, str(ROOT / "core" / "diagnose.py"), "--help"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--json", proc.stdout)
        self.assertIn("summary + conclusion", proc.stdout)


# ---------------------------------------------------------------- V11 取证单


class EvidenceConclusionTests(unittest.TestCase):
    """V11：取证单 markdown / text / API 都前置同一结论+边界块，7 维 4 字段不变。"""

    def setUp(self):
        self.result = _result(rows=[_row(layer="L2 本地链路", category="本地可达性",
                                         severity="严重", protocol="ARP")])
        self.checklist = evidence.build_checklist(self.result)
        self.block = self.checklist["conclusion"]

    def test_checklist_carries_same_conclusion_object(self):
        self.assertEqual(self.block,
                         conclusion.build_conclusion(self.result, self.result["verdict"]))

    def test_markdown_prepends_conclusion_block(self):
        md = evidence.render_checklist_markdown(self.checklist)
        sentence = self.block["conclusion"]
        self.assertIn(sentence, md)
        self.assertLess(md.index(sentence), md.index(
            COPY["evidence_checklist"]["section_title"]))
        self.assertIn("**明确未覆盖**", md)

    def test_text_prepends_conclusion_block(self):
        text = evidence.render_checklist_text(self.checklist)
        sentence = self.block["conclusion"]
        self.assertIn(sentence, text)
        self.assertLess(text.index(sentence),
                        text.index(COPY["evidence_checklist"]["text_title"]))
        self.assertIn("明确未覆盖", text)
        self.assertNotIn("|", text)

    def test_seven_dimensions_and_four_fields_unchanged(self):
        self.assertEqual(list(evidence.DIMENSION_KEYS),
                         list(json.loads((ROOT / "core" / "copy" /
                                          "evidence_checklist.json")
                                         .read_text(encoding="utf-8"))["dimensions"]))
        for dim in self.checklist["dimensions"]:
            for item in dim["items"]:
                self.assertEqual(set(item), set(evidence.ITEM_FIELDS))

    def test_api_evidence_content_includes_conclusion(self):
        payload = server.evidence_payload(self.result, fmt="md")
        self.assertTrue(payload["ok"], payload)
        self.assertIn(self.block["conclusion"], payload["content"])
        text_payload = server.evidence_payload(self.result, fmt="txt")
        self.assertIn(self.block["conclusion"], text_payload["content"])

    def test_full_blank_version_does_not_fake_a_conclusion(self):
        blank = evidence.build_checklist({}, full=True)
        self.assertNotIn("conclusion", blank)


# ---------------------------------------------------------------- V10 诊断包


class DiagpackReadmeTests(unittest.TestCase):
    """V10：包内 README 说明报告结论含边界字段、要整块阅读。"""

    def test_readme_tells_reader_to_read_boundary_block(self):
        readme = diagpack._render_readme([], [], False, True)
        self.assertIn("报告结论含边界字段", readme)
        self.assertIn("请整块阅读", readme)

    def test_readme_mentions_reports_when_included(self):
        readme = diagpack._render_readme([], [], False, True)
        self.assertIn("reports/", readme)


# ---------------------------------------------------------------- V13 不串味


class NoCrossTalkTests(unittest.TestCase):
    """V13：同一进程连续渲染两条不同结果，运行时值互不串味。"""

    def test_two_results_do_not_leak_runtime_values(self):
        a = _result(_meta(duration=7.0, packets=33), target="alpha.example")
        b = _result(_meta(duration=9.0, packets=44), target="beta.example")
        block_a = conclusion.build_conclusion(a)
        block_b = conclusion.build_conclusion(b)
        text_a = "\n".join(block_a["basis"] + block_a["coverage"])
        text_b = "\n".join(block_b["basis"] + block_b["coverage"])
        self.assertIn("7 秒", text_a)
        self.assertIn("报文 33 个", text_a)
        self.assertIn("alpha.example", text_a)
        self.assertNotIn("9 秒", text_a)
        self.assertNotIn("beta.example", text_a)
        self.assertIn("9 秒", text_b)
        self.assertIn("报文 44 个", text_b)
        self.assertIn("beta.example", text_b)
        self.assertNotIn("7 秒", text_b)
        self.assertNotIn("alpha.example", text_b)

    def test_rendering_a_again_after_b_is_stable(self):
        a = _result(_meta(duration=7.0), target="alpha.example")
        b = _result(_meta(duration=9.0), target="beta.example")
        first = conclusion.build_conclusion(a)
        conclusion.build_conclusion(b)
        again = conclusion.build_conclusion(a)
        self.assertEqual(first, again)

    def test_no_module_level_result_cache(self):
        module_vars = vars(conclusion)
        for name, value in module_vars.items():
            if name.startswith("__") or name in {
                    "KEY_LIMIT_KEYS", "_LABEL_FALLBACK", "_BASIS_ORDER",
                    "ABSOLUTE_WORDING", "_KNOWN_ROLES"}:
                continue
            self.assertNotIsInstance(
                value, (dict, list, set), f"模块级可变事实缓存：{name}")


# ---------------------------------------------------------------- copy 来源


class CopySourceTests(unittest.TestCase):
    """copy 表是唯一文案来源；畸形表只降级，不崩溃。"""

    def test_output_follows_copy_source(self):
        result = _result()
        vd = result["verdict"]
        custom = {"conclusion": _conclusion_copy()}
        custom["conclusion"]["template"] = "来源级：{headline}｜{key_limit}"
        with _patched_copy(custom):
            block = conclusion.build_conclusion(result, vd)
        self.assertTrue(block["conclusion"].startswith("来源级："))

    def test_static_coverage_follows_copy_source(self):
        result = _result()
        vd = result["verdict"]
        custom = {"conclusion": _conclusion_copy()}
        custom["conclusion"]["coverage_static"] = ["来源级覆盖项"]
        with _patched_copy(custom):
            block = conclusion.build_conclusion(result, vd)
        self.assertIn("来源级覆盖项", block["coverage"])
        self.assertNotIn(CONCL["coverage_static"][0], block["coverage"])

    def test_malformed_table_does_not_leak_empty_template(self):
        result = _result()
        vd = result["verdict"]
        custom = {"conclusion": {"template": "", "unknown": ""}}
        with _patched_copy(custom):
            block = conclusion.build_conclusion(result, vd)
        self.assertTrue(block["conclusion"].strip())
        self.assertIn("未知（原因：", block["conclusion"])
        self.assertFalse(re.search(r"\n\s*\n\s*$", block["conclusion"]))


if __name__ == "__main__":
    unittest.main()
