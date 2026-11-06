"""报告**形状**契约：``reports/*.json`` 的顶层键与 ``rows[]`` 的键不得随手增减。

这个文件不是在防 bug（现有代码没有制造这些键的 bug），是在防**一类改动**：
有人顺手把 ``findings_v2`` / ``provenance`` / 新的调试字段塞进报告 JSON 里。

为什么必须拦住：

* 报告 JSON 是**快照**，会被提交、被 diff、被当成基线比对。多一个
  ``findings_v2``（它本身就有十几条带 evidence 的对象）就会让每次分析
  产生上千行 diff，快照立刻失去「一眼看出指标变化」的作用。
* ``rows[]`` 是 UI / Markdown / AI 三个出口的公共数据结构，加一个键意味着
  三个消费方都要判断「这个键有没有」，而它们大多不会判断 —— 加键的人
  记得，改键的人不记得。
* 五个顶层键本身就是文档（见 AGENTS.md「报告结构」）：要加新块，
  应该先改这里、改文档、再动代码，而不是让契约跟着实现漂。

测试不需要 tshark：用一份合成 result 直接调 ``report.save()``，读回落盘文件断言。
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

# 与 diagnose.py 一致：report 用的是扁平导入（``import verdict``），
# 所以 ``core/`` 必须在 sys.path 上，不能写成 ``from core import report``。
import report  # noqa: E402

#: 报告 JSON 的**全部**顶层键，顺序不重要，集合必须相等。
TOP_LEVEL_KEYS = {"summary", "meta", "metrics", "rows", "verdict"}

#: ``verdict`` 必须提供的键（UI 与 Markdown 都按名取）。
VERDICT_KEYS = {
    "level", "headline", "plain", "impact", "layer",
    "layers", "points", "next_steps", "flags",
}

#: ``rows[]`` 每行的**全部**键。
ROW_KEYS = {"layer", "protocol", "category", "finding", "severity", "evidence", "advice"}


def _synthetic_result() -> dict:
    """造一份最小的、结构真实的 result：一条故障行 + 一条无样本行。

    Returns:
        dict: 含 ``meta`` / ``metrics`` / ``summary`` / ``rows``。
            故意同时放 ``"—"`` 与 ``"na"`` 两种非故障严重度，
            这样如果哪天有人给行加键，两条都会被检查到。
    """
    return {
        "meta": {"pcap_name": "contract_sample.pcap", "packets": 12, "tcp_packets": 8,
                 "duration": 3.5, "interface": "test0", "bpf": "tcp"},
        "metrics": {"retrans_rate": 0.0, "rtt_avg_ms": 12.0, "dns_avg_ms": 0.0,
                    "http_avg_ms": 0.0, "hs_avg_ms": 20.0, "conn_fail": 0},
        "summary": {"target": "全网", "critical_count": 0, "warning_count": 0},
        "rows": [
            {"layer": "L4 传输层", "protocol": "TCP", "category": "传输质量",
             "finding": "构造行：用于校验行键集合", "severity": "—",
             "evidence": "—", "advice": "无需处理"},
            {"layer": "L7 应用层", "protocol": "DNS", "category": "域名解析",
             "finding": "构造行：无样本严重度", "severity": "na",
             "evidence": "—", "advice": "—"},
        ],
    }


class ReportShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.paths = report.save(_synthetic_result(), Path(cls._tmp.name))
        cls.doc = json.loads(Path(cls.paths["json"]).read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_top_level_keys_are_exactly_five(self):
        """报告 JSON 顶层只有 summary / meta / metrics / rows / verdict 五块。

        多出来通常是 ``findings_v2`` 或 ``provenance`` 被顺手写进去了 —— 它们
        随每次分析变化，进快照等于让 diff 失去意义（见模块 docstring）。
        """
        self.assertEqual(set(self.doc), TOP_LEVEL_KEYS,
                         "报告顶层键变了；要加新块请先改本契约与 AGENTS.md")

    def test_verdict_has_all_consumed_keys(self):
        """``verdict`` 必须含 UI 与 Markdown 按名读取的全部键。"""
        self.assertIsInstance(self.doc.get("verdict"), dict)
        missing = VERDICT_KEYS - set(self.doc["verdict"])
        self.assertEqual(missing, set(), f"verdict 缺键：{sorted(missing)}")

    def test_every_row_has_exactly_seven_keys(self):
        """``rows[]`` 每行只含七个约定键（层/协议/类别/发现/严重度/证据/建议）。

        这条是**精确相等**不是包含：行结构一改，四个消费方（UI、Markdown、
        AI 提示词、对外 JSON）全都要跟着判断，不能靠「反正多了也不报错」蒙过去。
        """
        rows = self.doc.get("rows") or []
        self.assertEqual(len(rows), len(_synthetic_result()["rows"]))
        for i, row in enumerate(rows):
            with self.subTest(index=i):
                self.assertEqual(set(row), ROW_KEYS, f"第 {i} 行的键变了")

    def test_markdown_is_written_too(self):
        """两份产物都要落地：只有 JSON 说明 save() 半途失败了。"""
        self.assertTrue(Path(self.paths["markdown"]).exists())
        self.assertTrue(Path(self.paths["json"]).exists())


if __name__ == "__main__":
    unittest.main()
