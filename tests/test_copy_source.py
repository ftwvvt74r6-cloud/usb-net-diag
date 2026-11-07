"""文案单一来源（PR E）：报告/判定/建议/prompt 的文案只从 copy 表来，判定不靠文案。

守的口径（可机械证伪）：

* **反向断言**：把 copy 表（来源）换成自定义值，用户可见输出必须跟着变。
  这条能杀死「copy 读不到、悄悄回退内联常量」的假绿 —— 只 patch 消费方函数
  是证明不了这一点的，必须从 ``core.config.load_copy`` 这个来源打补丁。
* **V4 机制化**：``is_normal()`` 只看 ``Severity``：``"na"``（没样本）不是 normal；
  非 OK 严重度的行哪怕文案里有「未检测到」也不算 normal（不再做文本匹配）。
* **V4 coverage**：``coverage()`` 有独立的 ``no_sample`` 桶，且 ``na`` 行不算漏映射。
* **V5 / B1**：证据不足时层状态是 ``na``，指标短语必须是「无样本」类文案，
  不许出现「…正常」的肯定句。
"""

from __future__ import annotations

import sys
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

from core import verdict                                    # noqa: E402
from core.analyzer import build_findings                    # noqa: E402
from core.rules import legacy_map                           # noqa: E402

import report as report_mod                                 # noqa: E402  （与运行时一致：扁平导入）


#: 自定义文案表：只覆盖本文件要断言的 key；其余 key 缺失时消费方回退成 key 本身。
CUSTOM = {
    "next_step": {},
    "insufficient": {},
    "state": {"bad": "自定义异常", "warn": "自定义注意", "ok": "自定义正常",
              "na": "自定义无样本", "insufficient": "自定义证据不足"},
    "impact": {"dns": "自定义影响"},
    "layer_note": {"l2.na": "自定义无样本短语"},
    "verdict": {
        "titles": {"dns": "自定义标题"},
        "explain": {"dns": "自定义解释"},
        "headline": {"dns.fail": "自定义结论 {rate:.0f}%"},
        "plain": {},
        "fact": {},
        "layer_name": {},
    },
    "report": {"section_points": "## 自定义章节"},
    "finding": {"connect.no_sample": "自定义无会话"},
    "evidence": {"connect.no_sample": "自定义证据"},
    "advice": {"L4.CONNECT.ADVICE.NO_SAMPLE": "自定义建议"},
}


class CopySelectsTextTests(unittest.TestCase):
    """V1 反向断言：patch 文案来源 → verdict/report 的文字必须跟着变。"""

    def _result(self) -> dict:
        rows = [{
            "layer": "L7 应用层", "protocol": "DNS", "category": "域名解析",
            "severity": "严重", "finding": "构造 DNS 故障", "evidence": "构造证据",
            "advice": "构造建议",
        }]
        return {
            "meta": {"packets": 10},
            "rows": rows,
            "metrics": {"dns_fail_rate": 40.0},
            "summary": {},
        }

    def test_verdict_and_report_follow_copy_source(self):
        with mock.patch("core.config.load_copy", return_value=CUSTOM):
            vd = verdict.build(self._result())
            md = report_mod.render_markdown(self._result(), vd)
        self.assertEqual(vd["headline"], "自定义结论 40%")
        self.assertIn("自定义标题", md)
        self.assertIn("自定义解释", md)
        self.assertIn("自定义异常", md, "层状态文案也必须来自 copy 表")
        self.assertIn("## 自定义章节", md, "报告静态文案必须来自 copy 表")
        self.assertNotIn("域名解析（DNS）出了问题", md, "禁止回退到内联旧文案")


class AnalyzerCopySelectsTextTests(unittest.TestCase):
    """V1 反向断言：analyzer 产出的 finding/evidence/advice 也必须来自 copy 表。"""

    @staticmethod
    def _no_tcp_st() -> tuple[dict, dict]:
        st = {
            "packets": 3, "duration": 1.0, "tcp_packets": 0, "streams": {},
            "dns_q": Counter(), "dns_r": Counter(), "dns_nx": Counter(), "dns_times": [],
            "dns_servers": Counter(), "http_req": 0, "http_codes": Counter(),
            "http_detail": [], "http_times": [], "icmp_detail": [], "icmp_types": Counter(),
            "arp_req": Counter(), "arp_rep": set(), "ext_dst": Counter(),
            "ext_ports": {}, "ext_frames": {}, "basic_auth": [], "ftp_pass": [],
            "uri_secret": [], "telnet_frames": [], "zero_win": 0, "win_full": 0,
            "retrans": 0, "tls_sni": Counter(), "tls_alert": 0,
        }
        m = {
            "streams_total": 0, "conn_fail": 0, "conn_refused": 0, "hs_avg_ms": 0,
            "hs_max_ms": 0, "hs_jitter_ms": 0, "retrans_rate": 0.0, "ooo_rate": 0.0,
            "dup_ack_rate": 0.0, "icmp_unreach": 0, "icmp_timeout": 0, "rtt_samples": 0,
            "rtt_avg_ms": 0.0, "rtt_p95_ms": 0.0, "rtt_jitter_ms": 0.0,
            "dns_fail_rate": 0.0, "dns_timeouts": 0, "dns_avg_ms": 0.0, "dns_max_ms": 0.0,
            "http_err5": 0, "http_err5_rate": 0.0, "http_err4": 0, "http_avg_ms": 0.0,
            "http_p95_ms": 0.0, "http_max_ms": 0.0,
        }
        return st, m

    def test_rows_follow_copy_source(self):
        st, m = self._no_tcp_st()
        with mock.patch("core.config.load_copy", return_value=CUSTOM):
            rows = build_findings(st, m, [])
        connect = next(r for r in rows if r["category"] == "连接建立")
        self.assertEqual(connect["finding"], "自定义无会话")
        self.assertEqual(connect["evidence"], "自定义证据")
        self.assertEqual(connect["advice"], "自定义建议")


class IsNormalMechanismTests(unittest.TestCase):
    """V4：is_normal 只看 Severity，NA 不算 normal，也不再对文案做关键词匹配。"""

    def test_na_is_not_normal(self):
        row = {"severity": "na", "finding": "未检测到 TCP 会话（抓包周期内无 TCP 流量）"}
        self.assertFalse(legacy_map.is_normal(row))

    def test_na_without_normal_hint_is_not_normal(self):
        # 旧实现靠「未检测到」兜住 na；现在机制化后与文案彻底解耦
        row = {"severity": "na", "finding": "本次无任何样本"}
        self.assertFalse(legacy_map.is_normal(row))

    def test_ok_severity_is_normal(self):
        self.assertTrue(legacy_map.is_normal({"severity": "—", "finding": "随便写的"}))

    def test_non_ok_severity_with_hint_text_is_not_normal(self):
        # 旧实现会对所有严重度做文本匹配：提示行写「未检测到」会被误判成 normal
        self.assertFalse(legacy_map.is_normal({"severity": "提示", "finding": "未检测到某东西"}))

    def test_na_rows_do_not_become_unmatched(self):
        rows = [{"severity": "na", "layer": "L4 传输层", "category": "连接建立",
                 "finding": "未检测到 TCP 会话"}]
        self.assertEqual(legacy_map.find_unmatched(rows), [])
        self.assertEqual(legacy_map.map_rows(rows), [])


class CoverageNoSampleBucketTests(unittest.TestCase):
    """V4：coverage() 增加 no_sample 桶。"""

    def test_no_sample_bucket(self):
        rows = [
            {"layer": "L4 传输层", "category": "连接建立", "severity": "na",
             "finding": "未检测到 TCP 会话"},
            {"layer": "L3 网络层", "category": "网络可达性", "severity": "—",
             "finding": "未收到 ICMP 不可达/超时，三层转发正常"},
            {"layer": "L2 本地链路", "category": "本地可达性", "severity": "警告",
             "finding": "构造行"},
        ]
        cov = legacy_map.coverage(rows)
        self.assertEqual(cov["total"], 3)
        self.assertEqual(cov["normal"], 1)
        self.assertEqual(cov["no_sample"], 1)
        self.assertEqual(cov["unmatched"], 0)


class LayerNoteNaPhraseTests(unittest.TestCase):
    """V5 / B1：证据不足时层状态 na 的指标短语必须是「无样本」类，不许说「正常」。"""

    @staticmethod
    def _base_meta() -> dict:
        return {
            "packets": 3, "pcap_name": "synth.pcap",
            "tcp_packets": 0, "streams_total": 0,
            "dns_total": 0, "http_req": 0,
            "icmp_unreach": 0, "icmp_timeout": 0,
            "arp_req": 0, "arp_req_max": 0,
        }

    def test_l2_na_detail_has_no_normal_assertion(self):
        import json
        copy = json.loads((ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8"))
        v = verdict.build({"meta": self._base_meta(), "rows": [], "metrics": {},
                           "summary": {}})
        l2 = next(x for x in v["layers"] if x["id"] == "L2")
        self.assertEqual(l2["status"], "na")
        self.assertEqual(l2["detail"], copy["layer_note"]["l2.na"])
        self.assertIn("无样本", l2["detail"])
        self.assertNotIn("正常", l2["detail"])


if __name__ == "__main__":
    unittest.main()
