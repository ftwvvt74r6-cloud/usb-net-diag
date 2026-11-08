"""D+ 增量 3：通用「取证请求单」（V19~V24）的验收测试。

覆盖口径（对应 ``D-SPEC`` §4-E）：

* **V19 模板数据化**：``core/copy/evidence_checklist.json`` 可 ``json.load``；
  7 个「证据来源方」维度齐全；每项恰好 ``field/why/where/criteria`` 四字段且非空；
  代码里不硬编码清单正文（正文只在 JSON）。
* **V20 结论驱动映射**：L2/ARP、DNS 超时、TLS 失败三个真实故障场景映射到
  **互不相同**的维度集合；证据不足 → 全 7 维；正常且无 points → 空。
* **V21 报告与输出形态**：``render_markdown`` 追加「取证请求单」区块且是**纯后缀**
  （去掉后与无区块时逐字节相同）；纯文本无 Markdown 表格符号；通用空白版 7 维完整。
* **V22 禁厂商名**：清单 JSON、``core/evidence.py``、UI 与 ``copy.evidence_checklist`` 里
  不得出现具体厂商/产品名（出现即红）。
* **V23 UI / API**：结果页区块与复制/导出按钮接线；``/api/evidence`` 纯计算返回
  ``md`` / ``txt``，无结果时给可解释错误；``/api/status`` 只做加法字段。
* **V24 回填不做**：本批没有回填表单/接口（文档说明属 0.3.0 观察项）。

全部用例只依赖标准库与合成 result，**不需要 tshark / 网络 / 管理员权限**。
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import evidence  # noqa: E402
import report  # noqa: E402
import server  # noqa: E402
import verdict  # noqa: E402

TEMPLATE_PATH = ROOT / "core" / "copy" / "evidence_checklist.json"
COPY = json.loads((ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8"))
HTML = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
EVIDENCE_SOURCE = (ROOT / "core" / "evidence.py").read_text(encoding="utf-8")
TEMPLATE_TEXT = TEMPLATE_PATH.read_text(encoding="utf-8")
#: 新增取证文档也要守门（V22）；内容目前干净，扫描目标防后续回归。
DOC_EVIDENCE = (ROOT / "docs" / "evidence-checklist.md").read_text(encoding="utf-8")
DOC_PATH_PROBE = (ROOT / "docs" / "path-probe.md").read_text(encoding="utf-8")
DOC_SHADOW_PROBE = (ROOT / "docs" / "shadow-probe.md").read_text(encoding="utf-8")

#: 用户点名的厂商/产品名（V22）。清单是**通用**取证模板，任何一家都不该出现。
BANNED_VENDORS = (
    "深信服", "华为", "H3C", "H3c", "新华三", "Cisco", "cisco", "CISCO",
    "Juniper", "juniper", "F5", "VMware", "vmware", "Citrix", "citrix",
    "Fortinet", "fortinet", "Palo Alto", "palo alto", "奇安信", "绿盟",
    "天融信", "锐捷", "中兴", "阿里云", "腾讯云",
)


def _row(layer: str, category: str, severity: str = "严重",
         protocol: str = "—") -> dict:
    """造一条与 analyzer 同形的 ``rows[]`` 行。

    Args:
        layer: 层名（如 ``L2 本地链路``）。
        category: 类别（如 ``本地可达性``）。
        severity: 严重度；``"—"`` 表示测了正常，不参与问题映射。
        protocol: 协议名，仅用于排版。

    Returns:
        dict: 七个约定键的故障行。
    """
    return {"layer": layer, "protocol": protocol, "category": category,
            "finding": f"构造行：{category}", "severity": severity,
            "evidence": "构造证据", "advice": "构造建议"}


def _point(layer: str, category: str, severity: str = "严重") -> dict:
    """造一条与 ``verdict.build()`` 同形的 ``points[]`` 条目。"""
    return {"severity": severity, "layer": layer, "protocol": "—",
            "category": category, "title": "构造标题", "plain": "构造解释",
            "proof": "构造依据", "action": "构造动作"}


def _result(rows: list[dict], level: str = "警告", layer: str = "—",
            points: list[dict] | None = None, ok: bool = True,
            contrast: dict | None = None) -> dict:
    """造一份最小可渲染结果（含已算好的 verdict，避免测试里重复判定）。

    Args:
        rows: 故障行。
        level: ``verdict.level``。
        layer: ``verdict.layer``。
        points: 问题条目；省略时按 rows 里的严重行自动生成同类别条目。
        ok: ``verdict.sufficiency.ok``。
        contrast: 可选的 ``verdict.probe_contrast``。

    Returns:
        dict: ``meta`` / ``rows`` / ``metrics`` / ``summary`` / ``verdict``。
    """
    if points is None:
        points = [_point(r["layer"], r["category"], r["severity"])
                  for r in rows if r["severity"] in ("严重", "警告")]
    vd = {"level": level, "layer": layer, "points": points,
          "headline": f"构造结论（{level}）", "plain": "构造白话解释",
          "impact": "构造影响", "layers": [], "next_steps": ["构造处置建议"],
          "flags": {}, "sufficiency": {"ok": ok}}
    if contrast is not None:
        vd["probe_contrast"] = contrast
    return {
        "meta": {"pcap_name": "evidence_sample.pcap", "packets": 30,
                 "duration": 5.0, "interface": "test0", "bpf": "", "generated_at": ""},
        "rows": rows,
        "metrics": {},
        "summary": {"target": "全网", "critical_count": 0, "warning_count": 0},
        "verdict": vd,
    }


def _l2_result() -> dict:
    """L2/ARP 场景：同一目标多次 ARP 无应答。"""
    rows = [_row("L2 本地链路", "本地可达性", protocol="ARP")]
    return _result(rows, level="警告", layer="L2 本地链路｜ARP")


def _dns_result() -> dict:
    """DNS 超时场景：域名解析超时。"""
    rows = [_row("L7 应用层", "域名解析", protocol="DNS")]
    return _result(rows, level="警告", layer="L7 应用层｜DNS")


def _tls_result() -> dict:
    """TLS 失败场景：证书/握手失败（用合成 verdict/result，无需真抓包）。"""
    rows = [_row("L7 应用层", "TLS 会话", protocol="TLS")]
    return _result(rows, level="严重", layer="L7 应用层｜TLS")


def _normal_result() -> dict:
    """正常且无问题的结果（报告不应出现取证区块）。"""
    return _result([_row("L4 传输层", "传输质量", severity="—", protocol="TCP")],
                   level="正常", layer="—", points=[], ok=True)


def _dimension_keys(checklist: dict) -> list[str]:
    """清单字典 → 维度机器码列表（测试辅助）。"""
    return [dim["key"] for dim in checklist.get("dimensions") or []]


# ---------------------------------------------------------------- V19 模板


class TemplateSchemaTest(unittest.TestCase):
    """V19：模板 JSON 结构、7 维、每项四字段、无厂商名。"""

    def test_template_is_valid_json(self):
        """清单模板必须能被 json.load（U 盘/换行/手改都可能弄坏它）。"""
        data = json.loads(TEMPLATE_TEXT)
        self.assertIsInstance(data, dict)

    def test_seven_dimensions_in_fixed_order(self):
        """7 个证据来源方维度齐全，且顺序固定（报告/界面按此顺序展示）。"""
        data = json.loads(TEMPLATE_TEXT)
        self.assertEqual(list(data["dimensions"]), list(evidence.DIMENSION_KEYS))
        self.assertEqual(len(evidence.DIMENSION_KEYS), 7)
        for key in evidence.DIMENSION_KEYS:
            dim = data["dimensions"][key]
            self.assertTrue(dim["name"].strip(), f"{key} 缺中文名")
            self.assertTrue(dim["note"].strip(), f"{key} 缺说明")

    def test_every_item_has_exactly_four_fields(self):
        """每项恰好四个字段，一个不多一个不少（V19 硬要求）。"""
        data = json.loads(TEMPLATE_TEXT)
        for key, dim in data["dimensions"].items():
            self.assertIsInstance(dim["items"], list, f"{key}.items 必须是列表")
            for index, item in enumerate(dim["items"]):
                with self.subTest(dimension=key, index=index):
                    self.assertEqual(set(item), set(evidence.ITEM_FIELDS))
                    for field in evidence.ITEM_FIELDS:
                        self.assertIsInstance(item[field], str)
                        self.assertTrue(item[field].strip(),
                                        f"{key}.items[{index}].{field} 不能为空")

    def test_terminal_declares_already_collected(self):
        """终端侧必须声明「工具已自采、无需外部提供」，并给出至少一条已具备项。"""
        dim = json.loads(TEMPLATE_TEXT)["dimensions"]["terminal"]
        self.assertIn("已具备", dim["note"])
        self.assertGreaterEqual(len(dim["items"]), 1)
        self.assertTrue(any("已提供" in item["field"] for item in dim["items"]))

    def test_no_vendor_product_names(self):
        """V22：清单 JSON / evidence.py / UI / copy 与三份取证文档不得出现厂商名。"""
        targets = {
            "evidence_checklist.json": TEMPLATE_TEXT,
            "core/evidence.py": EVIDENCE_SOURCE,
            "ui/index.html": HTML,
            "copy.evidence_checklist": json.dumps(COPY["evidence_checklist"], ensure_ascii=False),
            "docs/evidence-checklist.md": DOC_EVIDENCE,
            "docs/path-probe.md": DOC_PATH_PROBE,
            "docs/shadow-probe.md": DOC_SHADOW_PROBE,
        }
        for name, text in targets.items():
            for vendor in BANNED_VENDORS:
                with self.subTest(file=name, vendor=vendor):
                    self.assertNotIn(vendor, text,
                                     f"{name} 出现了厂商名 {vendor}（清单必须按来源方组织）")

    def test_validate_template_clean(self):
        """真实模板通过结构校验（问题列表为空）。"""
        self.assertEqual(evidence.validate_template(json.loads(TEMPLATE_TEXT)), [])

    def test_validate_template_flags_missing_dimension(self):
        """变异锚点：删一个维度 → 结构校验必须报问题。"""
        data = copy.deepcopy(json.loads(TEMPLATE_TEXT))
        del data["dimensions"]["naming"]
        problems = evidence.validate_template(data)
        self.assertTrue(problems)
        self.assertIn("naming", " ".join(problems))

    def test_validate_template_flags_missing_field(self):
        """变异锚点：删一项里的一个字段 → 结构校验必须报问题。"""
        data = copy.deepcopy(json.loads(TEMPLATE_TEXT))
        del data["dimensions"]["wired"]["items"][0]["criteria"]
        problems = evidence.validate_template(data)
        self.assertTrue(problems)
        self.assertIn("criteria", " ".join(problems))

    def test_load_template_rejects_bad_schema(self):
        """显式 loader 对坏模板抛 ValueError（不是静默返回半张表）。"""
        data = json.loads(TEMPLATE_TEXT)
        del data["dimensions"]["service"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                evidence.load_template(path)


# ---------------------------------------------------------------- V20 映射


class DimensionMappingTest(unittest.TestCase):
    """V20：结论 → 维度映射必须可测、且三个故障场景互不相同。"""

    def test_l2_arp_maps_wired_and_wireless_not_crypto(self):
        keys = evidence.dimensions_for(_l2_result())
        self.assertEqual(keys, ["terminal", "wireless", "wired"])
        self.assertNotIn("crypto_proxy", keys)

    def test_dns_timeout_maps_naming(self):
        keys = evidence.dimensions_for(_dns_result())
        self.assertEqual(keys, ["terminal", "naming"])
        self.assertNotIn("crypto_proxy", keys)

    def test_tls_failure_maps_crypto_proxy(self):
        keys = evidence.dimensions_for(_tls_result())
        self.assertEqual(keys, ["terminal", "crypto_proxy", "service"])

    def test_three_scenarios_have_different_dimension_sets(self):
        """三个场景的维度集合两两不同（不是同一张表换个标题）。"""
        l2 = evidence.dimensions_for(_l2_result())
        dns = evidence.dimensions_for(_dns_result())
        tls = evidence.dimensions_for(_tls_result())
        self.assertNotEqual(set(l2), set(dns))
        self.assertNotEqual(set(l2), set(tls))
        self.assertNotEqual(set(dns), set(tls))
        # 条目内容也要不同：L2 清单里有线/无线条目不会出现在 DNS 清单里。
        l2_fields = {item["field"] for dim in evidence.build_checklist(_l2_result())["dimensions"]
                     for item in dim["items"]}
        dns_fields = {item["field"] for dim in evidence.build_checklist(_dns_result())["dimensions"]
                      for item in dim["items"]}
        self.assertTrue(l2_fields - dns_fields)
        self.assertTrue(dns_fields - l2_fields)

    def test_insufficient_returns_all_seven(self):
        """证据不足 → 通用空白版：全 7 维（明确规则，不是随机空集）。"""
        result = _result([], level="证据不足", points=[], ok=False)
        self.assertEqual(evidence.dimensions_for(result), list(evidence.DIMENSION_KEYS))

    def test_zero_packet_collection_point_returns_all_seven(self):
        """0 包降级（level=警告 + 采集有效性）也按通用空白版处理。"""
        result = _result([], level="警告", points=[_point("—", "采集有效性", "警告")])
        self.assertEqual(evidence.dimensions_for(result), list(evidence.DIMENSION_KEYS))

    def test_normal_without_points_returns_empty(self):
        """正常且无 points → 空集合（报告不出现区块）。"""
        self.assertEqual(evidence.dimensions_for(_normal_result()), [])

    def test_normal_with_hint_still_maps(self):
        """「正常」但有提示条目（如 404）仍按结论给服务侧清单。"""
        result = _result([_row("L7 应用层", "应用响应", severity="提示")],
                         level="正常", points=[_point("L7 应用层", "应用响应", "提示")])
        self.assertEqual(evidence.dimensions_for(result), ["terminal", "service"])

    def test_probe_contrast_target_side_adds_service(self):
        """方向对照指向对端 → 追加服务侧（V12 对照证据参与映射）。"""
        result = _result([_row("L4 传输层", "传输质量", protocol="TCP")],
                         contrast={"code": "PROBE.CONTRAST.TARGET_SIDE",
                                   "confidence": 0.6})
        self.assertIn("service", evidence.dimensions_for(result))

    def test_probe_contrast_local_side_adds_wired(self):
        """方向对照指向本地出口 → 追加有线接入侧。"""
        result = _result([_row("L4 传输层", "传输质量", protocol="TCP")],
                         contrast={"code": "PROBE.CONTRAST.LOCAL_SIDE",
                                   "confidence": 0.6})
        self.assertIn("wired", evidence.dimensions_for(result))

    def test_security_rows_do_not_add_crypto_or_service(self):
        """安全观察不参与取证映射（它不是本次网络故障的证据来源）。"""
        result = _result([_row("安全观察", "明文凭证", protocol="HTTP")],
                         level="警告")
        keys = evidence.dimensions_for(result)
        self.assertNotIn("crypto_proxy", keys)
        self.assertNotIn("service", keys)

    def test_unknown_category_falls_back_to_transport(self):
        """有故障但类别未知 → 兜底问承载与出口侧，不返回空清单。"""
        result = _result([_row("L9 未知层", "未知类别")])
        self.assertEqual(evidence.dimensions_for(result), ["terminal", "transport"])

    def test_mapping_computes_verdict_when_absent(self):
        """result 未带 verdict 时现算一次（纯函数，不联网）。"""
        result = _l2_result()
        result.pop("verdict")
        self.assertEqual(evidence.dimensions_for(result), ["terminal", "wireless", "wired"])

    def test_accepts_precomputed_verdict(self):
        """显式传入已算好的判定时以它为准（报告路径避免重复计算）。"""
        result = _normal_result()
        vd = {"level": "警告", "layer": "L2 本地链路｜ARP",
              "points": [_point("L2 本地链路", "本地可达性")],
              "sufficiency": {"ok": True}}
        self.assertEqual(evidence.dimensions_for(result, verdict=vd),
                         ["terminal", "wireless", "wired"])


# ---------------------------------------------------------------- V21 构建/渲染


class BuildChecklistTest(unittest.TestCase):
    """V21：结论驱动只取相关维度；full 版 7 维完整。"""

    def test_conclusion_driven_selects_only_related_dimensions(self):
        checklist = evidence.build_checklist(_l2_result())
        self.assertFalse(checklist["full"])
        self.assertEqual(_dimension_keys(checklist), ["terminal", "wireless", "wired"])
        self.assertEqual(checklist["level"], "警告")
        self.assertIn("L2", checklist["layer"])

    def test_full_version_has_all_seven_and_four_fields(self):
        checklist = evidence.build_checklist(_normal_result(), full=True)
        self.assertTrue(checklist["full"])
        self.assertEqual(_dimension_keys(checklist), list(evidence.DIMENSION_KEYS))
        for dim in checklist["dimensions"]:
            self.assertTrue(dim["name"])
            self.assertTrue(dim["note"])
            for item in dim["items"]:
                self.assertEqual(set(item), set(evidence.ITEM_FIELDS))
                for field in evidence.ITEM_FIELDS:
                    self.assertTrue(item[field].strip())

    def test_full_version_ignores_conclusion(self):
        """通用空白版不依赖本次结论：正常结果也要 7 维。"""
        checklist = evidence.build_checklist(_normal_result(), full=True)
        self.assertEqual(len(checklist["dimensions"]), 7)

    def test_full_version_without_any_result(self):
        """通用空白版不依赖 ``JOB["result"]``：空结果也能出全 7 维。"""
        checklist = evidence.build_checklist({}, full=True)
        self.assertTrue(checklist["full"])
        self.assertEqual(_dimension_keys(checklist), list(evidence.DIMENSION_KEYS))
        self.assertEqual(len(checklist["dimensions"]), 7)
        for dim in checklist["dimensions"]:
            self.assertTrue(dim["items"])

    def test_broken_template_degrades_to_empty_dimensions(self):
        """模板坏掉时降级为无维度（报告少区块，但不许崩）。"""
        checklist = evidence.build_checklist(_l2_result(), template={"dimensions": {}})
        self.assertEqual(checklist["dimensions"], [])


class RenderChecklistTest(unittest.TestCase):
    """V21：Markdown 四字段成表；纯文本无 Markdown 表格符号。"""

    def setUp(self):
        self.checklist = evidence.build_checklist(_l2_result())
        self.md = evidence.render_checklist_markdown(self.checklist)
        self.text = evidence.render_checklist_text(self.checklist)

    def test_markdown_has_title_and_dimension_names(self):
        self.assertIn(COPY["evidence_checklist"]["section_title"], self.md)
        self.assertIn("终端侧", self.md)
        self.assertIn("无线接入侧", self.md)
        self.assertIn("有线接入侧", self.md)

    def test_markdown_contains_every_item_field(self):
        for dim in self.checklist["dimensions"]:
            for item in dim["items"]:
                for field in evidence.ITEM_FIELDS:
                    with self.subTest(field=item[field]):
                        self.assertIn(item[field], self.md)

    def test_markdown_header_labels_come_from_copy(self):
        for key in ("th_field", "th_why", "th_where", "th_criteria"):
            with self.subTest(key=key):
                self.assertIn(COPY["evidence_checklist"][key], self.md)

    def test_text_has_no_markdown_table_or_heading_symbols(self):
        self.assertNotIn("|", self.text, "纯文本不能带 Markdown 表格符号")
        self.assertNotIn("###", self.text, "纯文本不能带 Markdown 标题符号")
        self.assertIn(COPY["evidence_checklist"]["text_title"], self.text)

    def test_text_contains_every_item_field(self):
        for dim in self.checklist["dimensions"]:
            for item in dim["items"]:
                for field in evidence.ITEM_FIELDS:
                    with self.subTest(field=item[field]):
                        self.assertIn(item[field], self.text)

    def test_empty_checklist_renders_empty_string(self):
        empty = {"full": False, "level": "正常", "layer": "—", "dimensions": []}
        self.assertEqual(evidence.render_checklist_markdown(empty), "")
        self.assertEqual(evidence.render_checklist_text(empty), "")

    def test_full_checklist_contains_all_dimension_names(self):
        full = evidence.build_checklist(_normal_result(), full=True)
        text = evidence.render_checklist_text(full)
        names = json.loads(TEMPLATE_TEXT)["dimensions"]
        for key in evidence.DIMENSION_KEYS:
            with self.subTest(key=key):
                self.assertIn(names[key]["name"], text)


# ---------------------------------------------------------------- 报告集成


class ReportIntegrationTest(unittest.TestCase):
    """报告区块：结论驱动出现/不出现；只追加、不动旧内容；JSON 快照不变。"""

    def test_report_appends_block_for_l2(self):
        result = _l2_result()
        md = report.render_markdown(result, result["verdict"])
        self.assertIn(COPY["evidence_checklist"]["section_title"], md)
        self.assertIn("有线接入侧", md)
        self.assertNotIn("加密与代理", md)

    def test_report_appends_nothing_for_normal(self):
        result = _normal_result()
        md = report.render_markdown(result, result["verdict"])
        self.assertNotIn(COPY["evidence_checklist"]["section_title"], md)

    def test_report_insufficient_uses_generic_checklist(self):
        result = _result([], level="证据不足", points=[], ok=False)
        md = report.render_markdown(result, result["verdict"])
        self.assertIn(COPY["evidence_checklist"]["section_title"], md)
        self.assertIn("加密与代理", md)   # 通用空白版含全部 7 维

    def test_block_is_pure_suffix(self):
        """去掉新增区块后，报告与「没有该区块」逐字节相同。"""
        result = _l2_result()
        vd = result["verdict"]
        with mock.patch.object(evidence, "dimensions_for", return_value=[]):
            without = report.render_markdown(copy.deepcopy(result), vd)
        with_block = report.render_markdown(copy.deepcopy(result), vd)
        block = evidence.render_checklist_markdown(
            evidence.build_checklist(result, verdict=vd)).rstrip("\n")
        self.assertEqual(with_block, without + "\n\n" + block + "\n")
        self.assertTrue(with_block.startswith(without))

    def test_markdown_ends_with_exactly_one_newline(self):
        """R14：与 main 一致，报告以单个 \\n 结尾（含追加区块时）。"""
        for result in (_l2_result(), _normal_result()):
            with self.subTest(level=result["verdict"]["level"]):
                md = report.render_markdown(result, result["verdict"])
                self.assertTrue(md.endswith("\n"))
                self.assertFalse(md.endswith("\n\n"))
                self.assertFalse(md.endswith("\n\n\n"))

    def test_save_keeps_five_json_blocks_and_no_evidence(self):
        """JSON 快照仍是 5 块，清单只进 md / UI，不进 JSON。"""
        with tempfile.TemporaryDirectory() as tmp:
            paths = report.save(_l2_result(), Path(tmp))
            doc = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
            md = Path(paths["markdown"]).read_text(encoding="utf-8")
        self.assertEqual(set(doc), {"summary", "meta", "metrics", "rows", "verdict"})
        # rows[] 本来就有 evidence 键（证据列）；这里钉的是**清单**不进 JSON。
        self.assertNotIn("evidence_checklist", json.dumps(doc, ensure_ascii=False))
        self.assertIn(COPY["evidence_checklist"]["section_title"], md)


# ---------------------------------------------------------------- V23 API


class EvidenceApiTest(unittest.TestCase):
    """/api/evidence：纯计算、无结果可解释、full/fmt 行为正确；路由为加法。"""

    def test_no_result_returns_explainable_error(self):
        payload = server.evidence_payload(None)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["error"])

    def test_no_result_full_returns_generic_blank(self):
        """空白版入口不依赖 JOB["result"]：无结果时 full=1 也必须成功。"""
        payload = server.evidence_payload(None, full=True, fmt="txt")
        self.assertTrue(payload["ok"], payload)
        self.assertTrue(payload["full"])
        self.assertEqual(payload["dimensions"], list(evidence.DIMENSION_KEYS))
        self.assertIn("字段名", payload["content"])

    def test_full_payload_without_result_is_markdown_too(self):
        payload = server.evidence_payload(None, full=True, fmt="md")
        self.assertTrue(payload["ok"])
        self.assertIn(COPY["evidence_checklist"]["section_title"], payload["content"])

    def test_payload_passes_precomputed_verdict_to_checklist(self):
        """/api/evidence 必须把判定显式传给 build_checklist，避免回退读 copy 表。"""
        result = _l2_result()
        with mock.patch.object(server.evidence, "build_checklist",
                               return_value={"full": False, "level": "警告",
                                             "layer": "", "dimensions": []}) as build:
            server.evidence_payload(result, full=False, fmt="md")
        self.assertIs(build.call_args.kwargs["verdict"], result["verdict"])

    def test_payload_does_not_rebuild_verdict_when_present(self):
        """结果里已有 verdict 时不许再调 verdict.build（reviewer 实测 20 次 copy 读）。"""
        result = _l2_result()
        with mock.patch.object(server.verdict, "build",
                               side_effect=AssertionError("不应重复判定")):
            payload = server.evidence_payload(result, full=False, fmt="txt")
        self.assertTrue(payload["ok"], payload)

    def test_normal_result_returns_error_with_full_hint(self):
        payload = server.evidence_payload(_normal_result())
        self.assertFalse(payload["ok"])
        self.assertIn("full=1", payload["error"])

    def test_markdown_payload_has_dimensions_and_content(self):
        payload = server.evidence_payload(_l2_result(), full=False, fmt="md")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["fmt"], "md")
        self.assertEqual(payload["dimensions"], ["terminal", "wireless", "wired"])
        self.assertIn(COPY["evidence_checklist"]["section_title"], payload["content"])

    def test_text_payload_is_plain(self):
        payload = server.evidence_payload(_l2_result(), full=False, fmt="txt")
        self.assertTrue(payload["ok"])
        self.assertNotIn("|", payload["content"])
        self.assertIn("字段名", payload["content"])

    def test_full_payload_has_seven_dimensions(self):
        payload = server.evidence_payload(_normal_result(), full=True, fmt="md")
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["full"])
        self.assertEqual(payload["dimensions"], list(evidence.DIMENSION_KEYS))

    def test_route_is_get_and_only_reads_job_result(self):
        source = (ROOT / "core" / "server.py").read_text(encoding="utf-8")
        self.assertIn('if path == "/api/evidence":', source)
        self.assertIn("evidence_payload(latest, full=full, fmt=fmt)", source)
        self.assertIn('_to_bool((q.get("full") or [None])[0], False)', source)
        self.assertIn('if fmt not in ("md", "txt"):', source)

    def test_attach_status_adds_evidence_fields(self):
        enriched = server._attach_probe_ui_copy(_l2_result())
        self.assertIn("evidence_checklist", enriched)
        self.assertIn("evidence", enriched["ui_copy"])
        self.assertEqual(_dimension_keys(enriched["evidence_checklist"]),
                         ["terminal", "wireless", "wired"])

    def test_attach_status_leaves_normal_result_untouched(self):
        """没有取证维度时 /api/status 结果保持原对象（加法字段不硬塞）。"""
        result = _normal_result()
        self.assertIs(server._attach_probe_ui_copy(result), result)

    def test_evidence_ui_copy_comes_from_copy_table(self):
        with mock.patch.object(server.copytext, "load_table",
                               return_value={"evidence_checklist": {"ui_title": "自定义标题"}}):
            self.assertEqual(server._evidence_ui_copy(), {"ui_title": "自定义标题"})


# ---------------------------------------------------------------- V23 UI


class EvidenceUiTest(unittest.TestCase):
    """V23：结果页区块 + 复制/导出按钮接线；文案走 copy 表。"""

    def test_render_function_exists_and_reads_payload(self):
        self.assertIn("function renderEvidenceChecklist(ev, copy)", HTML)
        start = HTML.index("function renderEvidenceChecklist(ev, copy)")
        body = HTML[start:HTML.index("\nasync function copyPlainText", start)]
        for token in ("ev.dimensions", "dim.items", "it.field", "it.why",
                      "it.where", "it.criteria", "copy.th_field"):
            with self.subTest(token=token):
                self.assertIn(token, body)

    def test_result_page_renders_evidence_block(self):
        start = HTML.index("function render(res, actions)")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn("renderEvidenceChecklist", body)
        self.assertIn("res.evidence_checklist", body)
        self.assertIn("evidenceBlock", body)

    def test_three_buttons_are_wired(self):
        for value in ("copy", "copy-full", "download"):
            with self.subTest(value=value):
                self.assertIn(f'data-evidence="{value}"', HTML)
        self.assertIn('document.querySelectorAll("[data-evidence]")', HTML)
        self.assertIn("evidenceAction(btn.dataset.evidence", HTML)

    def test_actions_fetch_evidence_api(self):
        start = HTML.index("async function evidenceAction(kind, pcapName, button)")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn('"/api/evidence?full=" + full + "&fmt=" + fmt', body)
        self.assertIn("navigator.clipboard", HTML)
        self.assertIn("new Blob([r.content]", body)
        self.assertIn('"-evidence.md"', body)

    def test_generic_blank_entry_independent_of_result(self):
        """正常结果 / 无结果时也能复制、导出全 7 维空白版（独立入口）。"""
        for token in ('id="evidence-fixed-copy"', 'id="evidence-fixed-download"',
                      "function wireFixedEvidenceButtons()",
                      'evidenceAction("copy-full"', 'evidenceAction("download-full"'):
            with self.subTest(token=token):
                self.assertIn(token, HTML)
        # 静态入口在「报告与导出」页，不依赖 render(res) 的 innerHTML。
        reports = HTML[HTML.index('id="view-reports"'):HTML.index('id="view-sysinfo"')]
        self.assertIn('id="evidence-fixed-copy"', reports)
        self.assertIn('id="evidence-fixed-download"', reports)
        # 结果页工具条也有独立入口：正常结果 evidenceBlock 为空时仍可用。
        render = HTML[HTML.index("function render(res, actions)"):
                      HTML.index("\nfunction ", HTML.index("function render(res, actions)"))]
        self.assertIn('id="evidence-copy-full-result"', render)
        self.assertIn('id="evidence-download-full-result"', render)
        self.assertIn('evidenceAction("copy-full"', render)
        self.assertIn('evidenceAction("download-full"', render)

    def test_download_full_requests_full_version(self):
        """通用空白版导出必须请求 full=1，而不是当前结论清单。"""
        start = HTML.index("async function evidenceAction(kind, pcapName, button)")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn('kind === "download-full"', body)
        self.assertIn('kind.indexOf("download") === 0 ? "md" : "txt"', body)

    def test_ui_does_not_embed_checklist_body(self):
        """清单正文只在 JSON，页面只搬数据（禁止把一整张表抄进 HTML）。"""
        self.assertNotIn("无线控制器/AP 管理后台的终端详情页或客户端列表", HTML)
        self.assertNotIn("接入交换机端口状态 / 速率 / 双工", HTML)

    def test_ui_labels_come_from_copy_table(self):
        for key in ("ui_title", "ui_hint", "th_field", "th_why", "th_where",
                    "th_criteria", "btn_copy", "btn_copy_full", "btn_download",
                    "copy_ok", "copy_fail", "error_prefix"):
            with self.subTest(key=key):
                self.assertIn(key, COPY["evidence_checklist"])

    def test_no_backfill_ui_in_this_batch(self):
        """V24：本批只做生成/复制/导出，不做回填表单或接口。"""
        self.assertNotIn("/api/evidence/backfill", HTML)
        self.assertNotIn("/api/evidence/backfill", (ROOT / "core" / "server.py")
                         .read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
