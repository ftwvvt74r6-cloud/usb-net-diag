"""证据充分性闸门（PR D）：没有可判定维度时，不许把「没样本」报成「正常」。

守的是一条口径（不是某个具体 bug）：

* ``verdict.build()`` 在「抓到了包，但 TCP / DNS / HTTP / ICMP / ARP 五个维度
  全都凑不出一个可判定样本」时，``level`` 必须是「证据不足」，而不是「正常」。
* 闸门只看「有没有维度可判」，不看「报文够不够多」——captures 里的
  ``arp_no_reply`` 只有 5 个包却抓到了真故障，按报文数卡会把结论埋掉。

纯函数用例不依赖 tshark，CI 干净环境也能跑完整套维度口径校验；
涉及 ``analyze()`` 现跑的用例在无 tshark 时跳过。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import verdict                                        # noqa: E402
from core.analyzer import analyze                               # noqa: E402
from core.tshark import find_tshark                            # noqa: E402

DEMO = ROOT / "captures" / "faults_demo.pcap"
NO_TSHARK = find_tshark() is None


def _base_meta() -> dict:
    """一份「五个维度全无」的最小 meta；各用例只改自己关心的键。"""
    return {
        "packets": 3, "pcap_name": "synth.pcap",
        "tcp_packets": 0, "streams_total": 0,
        "dns_total": 0, "http_req": 0,
        "icmp_unreach": 0, "icmp_timeout": 0, "arp_req": 0,
    }


def _verdict(meta: dict, rows: list[dict] | None = None) -> dict:
    return verdict.build({
        "meta": meta,
        "rows": rows or [],
        "metrics": {},
        "summary": {},
    })


class SufficiencyPureTests(unittest.TestCase):
    """纯函数维度口径：不跑 tshark，直接喂最小 meta 组合。"""

    def test_no_dimension_is_insufficient(self):
        v = _verdict(_base_meta())
        self.assertFalse(v["sufficiency"]["ok"])
        self.assertEqual(v["level"], "证据不足")
        self.assertNotEqual(v["level"], "正常")
        self.assertTrue(v["sufficiency"]["reasons"], "reasons 至少要给一个 key")
        self.assertTrue(v["sufficiency"]["needed"], "needed 要给出可执行建议")

    def test_tcp_packets_meets_threshold(self):
        m = _base_meta(); m["tcp_packets"] = 5
        self.assertTrue(_verdict(m)["sufficiency"]["ok"])

    def test_tcp_single_stream_counts(self):
        m = _base_meta(); m["streams_total"] = 1
        self.assertTrue(_verdict(m)["sufficiency"]["ok"])

    def test_dns_dimension(self):
        m = _base_meta(); m["dns_total"] = 1
        self.assertTrue(_verdict(m)["sufficiency"]["ok"])

    def test_http_dimension(self):
        m = _base_meta(); m["http_req"] = 1
        self.assertTrue(_verdict(m)["sufficiency"]["ok"])

    def test_icmp_dimension(self):
        m = _base_meta(); m["icmp_unreach"] = 1
        self.assertTrue(_verdict(m)["sufficiency"]["ok"])

    def test_icmp_timeout_counts_too(self):
        m = _base_meta(); m["icmp_timeout"] = 1
        self.assertTrue(_verdict(m)["sufficiency"]["ok"])

    def test_icmp_echo_alone_is_not_enough(self):
        # echo request 不产生故障行，也不构成 ICMP 维度（规则只看错误报文）
        m = _base_meta()
        self.assertFalse(_verdict(m)["sufficiency"]["ok"])

    def test_arp_needs_two_requests(self):
        m = _base_meta(); m["arp_req"] = 1
        self.assertFalse(_verdict(m)["sufficiency"]["ok"])
        m["arp_req"] = 2
        self.assertTrue(_verdict(m)["sufficiency"]["ok"])

    def test_fault_row_wins_even_without_dimensions(self):
        # 已有故障行 → ok=True，不看任何维度；否则会把真结论埋掉
        rows = [{"layer": "L3 网络层", "protocol": "ICMP", "category": "网络可达性",
                 "finding": "构造故障", "severity": "严重",
                 "evidence": "—", "advice": "—"}]
        v = _verdict(_base_meta(), rows)
        self.assertTrue(v["sufficiency"]["ok"])
        self.assertEqual(v["level"], "严重")

    def test_sufficiency_present_even_when_ok(self):
        # ok=True 时 sufficiency 键也必须存在（结构契约，不是只在失败时补）
        m = _base_meta(); m["dns_total"] = 1
        v = _verdict(m)
        self.assertIn("sufficiency", v)
        self.assertTrue(v["sufficiency"]["ok"])


@unittest.skipIf(NO_TSHARK, "无 tshark，跳过现跑用例")
class SufficiencyAnalyzeTests(unittest.TestCase):
    """在真实 pcap 上跑 analyze() + verdict.build()。"""

    def test_demo_still_critical_and_sufficient(self):
        res = analyze(DEMO)
        v = verdict.build(res)
        self.assertEqual(v["level"], "严重")
        self.assertTrue(v["sufficiency"]["ok"])

    def test_demo_sufficiency_shape(self):
        res = analyze(DEMO)
        v = verdict.build(res)
        s = v["sufficiency"]
        self.assertIsInstance(s, dict)
        for key in ("ok", "reasons", "needed", "reason_args"):
            self.assertIn(key, s)


if __name__ == "__main__":
    unittest.main()
