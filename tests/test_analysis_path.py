"""分析路径丢失修复（issue: 分析路径丢失）的回归测试。

守的口径（用户定稿，2026-11-09）：

* **② pcap 绝对化 + 持久化**：``diagnose._run_params`` 里的 ``pcap`` 必须是绝对路径，
  并同时保存 ``pcap_file`` / ``pcap_size`` / ``pcap_exists`` 与 ``record_schema`` /
  ``ui_contract_version``；旧实现只存文件名（``Path(...).name``），工作目录/盘符一变
  就拼出 ``F:\\`` 这类怪路径。
* **① 错误卡补全**：``FileNotFoundError`` / ``OSError`` 映射成用户话术
  「抓包文件不存在或已不可访问」，错误卡必须带 pcap 绝对路径 / 是否存在 / 大小 /
  失败阶段，并给「重新抓包」按钮；resolve 前后路径 / cwd / 盘符只进本地日志。
* **③ 旧记录兼容**：run 记录带 schema 版本字段；读旧记录（无该字段）时标记
  ``legacy``，UI 只显示「旧版本结果」横幅、不渲染四层未知卡、禁用导出按钮；
  本次运行失败时结果区不混入上一次的结论区。
* **④ 变异验证**：把绝对路径改回只存文件名 → 用例必须红；把旧记录横幅去掉 → 用例必须红。

本文件不跑浏览器、不联网、不依赖 tshark：UI 行为用源码切片断言，后端用纯函数断言。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "core"))

import diagnose  # noqa: E402
import server  # noqa: E402
import _uisrc  # noqa: E402

HTML = _uisrc.html()
COPY = json.loads(
    (ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8"))


def _slice(start: str, end: str) -> str:
    begin = HTML.index(start)
    return HTML[begin:HTML.index(end, begin)]


class PcapAbsolutePathTest(unittest.TestCase):
    """② pcap 绝对化：run 记录里的 params.pcap 必须是绝对路径并持久化。"""

    def test_run_params_stores_absolute_path_not_basename(self):
        params = diagnose._run_params("example.com", 30, None, "captures/demo.pcap")
        pcap = params["pcap"]
        self.assertTrue(Path(pcap).is_absolute(),
                        f"params.pcap 必须是绝对路径，实际是 {pcap!r}")
        self.assertEqual(params["pcap_file"], "demo.pcap")
        # 存在性只用于展示；文件不存在时也必须给出字段，不能省略。
        self.assertIn("pcap_exists", params)
        self.assertIn("pcap_size", params)

    def test_run_params_records_schema_version(self):
        params = diagnose._run_params("example.com", 30, None, "captures/demo.pcap")
        self.assertEqual(params["record_schema"], diagnose.RUN_RECORD_SCHEMA)
        self.assertEqual(params["ui_contract_version"], diagnose.UI_CONTRACT_VERSION)

    def test_run_params_without_pcap_has_no_pcap_fields(self):
        params = diagnose._run_params("example.com", 30, None, None)
        self.assertNotIn("pcap", params)
        self.assertNotIn("pcap_file", params)
        # 实时抓包也必须带 schema 版本（run 记录兼容判断统一看它）。
        self.assertEqual(params["record_schema"], diagnose.RUN_RECORD_SCHEMA)

    def test_resolve_never_raises_on_drive_root(self):
        # 事故里的怪值 'F:\'（盘符根）也必须能安全采集元信息，不能抛二次异常。
        meta = diagnose._pcap_file_meta("F:\\")
        self.assertEqual(meta["exists"], False)
        self.assertEqual(meta["size"], 0)


class PcapErrorCardTest(unittest.TestCase):
    """① 错误卡：FileNotFoundError 映射 + 路径/存在性/大小/阶段字段齐全。"""

    def test_file_not_found_maps_to_user_wording(self):
        card = diagnose._pcap_error_card("F:\\missing.pcap", "analyze",
                                         FileNotFoundError("no such file"))
        self.assertFalse(card["ok"])
        self.assertEqual(card["error"], "抓包文件不存在或已不可访问")
        self.assertEqual(card["code"], "E_BAD_PCAP")
        self.assertTrue(card["re_capture"])

    def test_error_card_has_all_diagnostic_fields(self):
        card = diagnose._pcap_error_card("F:\\missing.pcap", "parse",
                                         OSError("bad path"))
        for key in ("pcap_path", "pcap_exists", "pcap_size", "pcap_name", "stage"):
            self.assertIn(key, card, f"错误卡缺少字段 {key}")
        self.assertEqual(card["stage"], "parse")
        self.assertEqual(card["pcap_exists"], False)
        self.assertEqual(card["pcap_size"], 0)
        # 三条常见原因齐备。
        self.assertEqual(len(card["reasons"]), 3)

    def test_error_card_log_section_carries_resolve_and_cwd(self):
        # resolve 前后 / cwd / 盘符只进 _log（本地日志专用），不随响应外发。
        card = diagnose._pcap_error_card("F:\\x.pcap", "analyze", FileNotFoundError())
        log = card["_log"]
        self.assertIn("raw_path", log)
        self.assertIn("resolved_path", log)
        self.assertIn("cwd", log)
        self.assertIn("drive", log)
        # 外发字段里绝不能带 _log（白名单外）。
        public = {k: v for k, v in card.items() if k != "_log"}
        self.assertNotIn("cwd", public)
        self.assertNotIn("drive", public)

    def test_run_scan_missing_pcap_returns_full_error_card(self):
        import core.logstore as logstore  # noqa: E402
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ,
                                 {logstore.ENV_LOG_DIR: tmp}), \
                    mock.patch.object(diagnose, "_log_pcap_card",
                                      side_effect=lambda card: None):
                logstore.close_streams()
                res = diagnose._run_scan(pcap="Z:\\definitely-missing.pcap",
                                         logger=lambda m: None,
                                         report_dir=tempfile.gettempdir())
                logstore.close_streams()
        self.assertFalse(res.get("ok"))
        self.assertEqual(res.get("error"), "抓包文件不存在或已不可访问")
        self.assertEqual(res.get("stage"), "analyze")
        self.assertIn("pcap_path", res)
        self.assertIn("pcap_exists", res)
        self.assertIn("pcap_size", res)
        self.assertTrue(res.get("re_capture"))

    def test_non_fs_error_keeps_original_message(self):
        card = diagnose._pcap_error_card("x.pcap", "analyze", ValueError("boom"))
        self.assertEqual(card["error"], "boom")
        self.assertEqual(card["code"], "E_INTERNAL")


class ServerErrorDetailTest(unittest.TestCase):
    """server 端把错误卡的可诊断性字段以白名单形式外发。"""

    def test_error_detail_extracts_whitelist_fields(self):
        res = diagnose._pcap_error_card("F:\\missing.pcap", "analyze",
                                        FileNotFoundError())
        detail = server._error_detail_from(res)
        self.assertIsNotNone(detail)
        for key in ("stage", "pcap_path", "pcap_name", "pcap_exists", "pcap_size",
                    "reasons", "re_capture"):
            self.assertIn(key, detail)
        # 本地日志专用字段绝不外发。
        self.assertNotIn("_log", detail)
        self.assertNotIn("cwd", detail)

    def test_error_detail_none_for_plain_error(self):
        self.assertIsNone(server._error_detail_from({"ok": False, "error": "boom"}))


class LegacyRecordTest(unittest.TestCase):
    """③ 旧记录兼容：读旧记录标记 legacy，UI 只显示横幅不渲染四层未知卡。"""

    def test_legacy_banner_copy_exists(self):
        self.assertIn("legacy_banner", COPY["conclusion"])
        self.assertIn("legacy_rerun", COPY["conclusion"])
        self.assertIn("缺少结论边界信息", COPY["conclusion"]["legacy_banner"])

    def test_conclusion_card_renders_banner_not_four_sections_when_legacy(self):
        card = _slice("function conclusionCard(res)", "function downloadText")
        # legacy 分支渲染横幅 + 重新诊断按钮，不渲染四层未知卡和导出按钮。
        self.assertIn("legacy-banner", card)
        self.assertIn("conclusion-rerun", card)
        self.assertIn("data-legacy=\"1\"", card)
        # 四层未知卡与导出按钮只出现在非 legacy 分支，且 legacy 分支先 return。
        legacy_part = card[card.index("if (d.legacy)"):card.index("const label =")]
        self.assertNotIn("conclusion-export-md", legacy_part)
        self.assertNotIn("conclusion-export-json", legacy_part)
        self.assertNotIn("data-concl=\"basis\"", legacy_part)

    def test_wire_rerun_does_not_wire_export_buttons(self):
        wire = _slice("function wireConclusionActions(res)", "function render(res, actions)")
        self.assertIn("conclusion-rerun", wire)
        # legacy 分支 return 早退，不再接线复制/导出按钮。
        self.assertIn("return;", wire[:wire.index("const btnCopy")])

    def test_failure_path_does_not_render_conclusion_card(self):
        # 本次运行失败时结果区只显示失败卡，不混入结论区（四层未知卡/导出按钮）。
        failure_fn = _slice("function renderFailureCard(kind, why, errDetail)", "function failedResult")
        self.assertNotIn("conclusionCard", failure_fn)
        generic_fn = _slice("function failedResult(title, detail, code, errDetail)",
                            "function classifyLog")
        self.assertNotIn("conclusionCard", generic_fn)

    def test_runs_fallback_marks_legacy_when_no_schema(self):
        # 旧 run 记录（无 record_schema / ui_contract_version）必须标记 legacy=True。
        from pathlib import Path as _P
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ,
                                 {"NETDIAG_LOG_DIR": tmp}):
                runs = _P(tmp) / "runs"
                runs.mkdir(parents=True, exist_ok=True)
                (runs / "20261109-010000-aaaa1111.json").write_text(
                    json.dumps({
                        "mode": "offline",
                        "params": {"pcap": "captures/legacy.pcap"},  # 旧记录：只有文件名、无 schema
                        "duration_ms": 1234, "level": "严重", "ok": True,
                    }), encoding="utf-8")
                last = server._last_run_from_runs()
                self.assertIsNotNone(last)
                self.assertTrue(last.get("legacy"),
                                "旧记录（无 schema 字段）必须标记 legacy=True")

    def test_runs_fallback_not_legacy_when_schema_present(self):
        from pathlib import Path as _P
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"NETDIAG_LOG_DIR": tmp}):
                runs = _P(tmp) / "runs"
                runs.mkdir(parents=True, exist_ok=True)
                (runs / "20261109-010000-bbbb2222.json").write_text(
                    json.dumps({
                        "mode": "offline",
                        "params": {"pcap": "captures/new.pcap",
                                   "record_schema": 2, "ui_contract_version": "2"},
                        "duration_ms": 1234, "level": "严重", "ok": True,
                    }), encoding="utf-8")
                last = server._last_run_from_runs()
                self.assertIsNotNone(last)
                self.assertFalse(last.get("legacy"),
                                 "新记录（带 schema 字段）不能标记 legacy")


if __name__ == "__main__":
    unittest.main(verbosity=2)
