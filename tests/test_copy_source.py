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

import json
import sys
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

from core import analyzer                                    # noqa: E402
from core import verdict                                    # noqa: E402
from core.analyzer import build_findings                    # noqa: E402
from core.rules import legacy_map                           # noqa: E402

import report as report_mod                                 # noqa: E402  （与运行时一致：扁平导入）

COPY_PATH = ROOT / "core" / "copy" / "zh-CN.json"


def _copy_table() -> dict:
    return json.loads(COPY_PATH.read_text(encoding="utf-8"))


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


class SuspiciousPortLabelTests(unittest.TestCase):
    """阻塞 1（审查第 1 轮）：9 个高危端口必须**每一个**都有非空标签。

    为什么 10 样本比对没抓到：没有样本命中高危端口，逐字节比对覆盖不到这条路径；
    当年代码把 `9050: "Tor Socks"` 的标签丢掉后，报告会从 `9050(Tor Socks)`
    退化成 `9050(9050)`。
    """

    #: 旧实现（d7c1bbe analyzer.SUSPICIOUS_PORTS）里 9 个端口的原标签。
    EXPECTED = {
        "1080": "代理端口",
        "1337": "常见后门端口",
        "31337": "Back Orifice 后门端口",
        "4444": "Metasploit 反弹端口",
        "4899": "Radmin 远控",
        "5555": "ADB/Meterpreter 常用",
        "6667": "IRC C2 常用",
        "9001": "Tor 中继",
        "9050": "Tor Socks",
    }

    def test_all_nine_labels_exist_and_are_not_port_echoes(self):
        labels = _copy_table()["suspicious_port"]
        self.assertEqual(set(labels), set(self.EXPECTED))
        for port, expected in self.EXPECTED.items():
            with self.subTest(port=port):
                self.assertEqual(labels[port], expected)
                self.assertTrue(labels[port].strip(), "标签不能为空")
                self.assertNotEqual(labels[port], port, "缺标签时消费方会回退成端口号")
                self.assertEqual(analyzer._t("suspicious_port", port), expected)

    def test_high_risk_port_row_renders_every_label(self):
        # 一条外联命中全部 9 个高危端口：行文案里每个端口都必须带原标签
        st = {
            "packets": 10, "duration": 1.0, "tcp_packets": 10, "streams": {},
            "dns_q": Counter(), "dns_r": Counter(), "dns_nx": Counter(),
            "dns_times": [], "dns_servers": Counter(), "http_req": 0,
            "http_codes": Counter(), "http_detail": [], "http_times": [],
            "icmp_detail": [], "icmp_types": Counter(), "arp_req": Counter(),
            "arp_rep": set(), "ext_dst": Counter({"203.0.113.9": 9}),
            "ext_ports": {"203.0.113.9": set(self.EXPECTED)},
            "ext_frames": {"203.0.113.9": ["31"]}, "basic_auth": [],
            "ftp_pass": [], "uri_secret": [], "telnet_frames": [], "zero_win": 0,
            "win_full": 0, "retrans": 0, "tls_sni": Counter(), "tls_alert": 0,
        }
        m = {
            "streams_total": 1, "conn_fail": 0, "conn_refused": 0, "hs_avg_ms": 0,
            "hs_max_ms": 0, "hs_jitter_ms": 0, "retrans_rate": 0.0, "ooo_rate": 0.0,
            "dup_ack_rate": 0.0, "icmp_unreach": 0, "icmp_timeout": 0,
            "rtt_samples": 0, "rtt_avg_ms": 0.0, "rtt_p95_ms": 0.0,
            "rtt_jitter_ms": 0.0, "dns_fail_rate": 0.0, "dns_timeouts": 0,
            "dns_avg_ms": 0.0, "dns_max_ms": 0.0, "http_err5": 0,
            "http_err5_rate": 0.0, "http_err4": 0, "http_avg_ms": 0.0,
            "http_p95_ms": 0.0, "http_max_ms": 0.0,
        }
        rows = build_findings(st, m, [])
        finding = next(r["finding"] for r in rows if r["category"] == "可疑外联")
        for port, label in self.EXPECTED.items():
            with self.subTest(port=port):
                self.assertIn(f"{port}({label})", finding)
        self.assertNotIn("9050(9050)", finding, "9050 的标签不许退化成端口号")


class StreamFlagDecouplingTests(unittest.TestCase):
    """阻塞 2（审查第 1 轮）：会话标记的文案与判定彻底解耦。

    * 标记文字必须来自 copy 表（改 copy → 渲染跟着变）；
    * ``conn_fail`` 计数与 ``streams_top`` 排序必须基于结构化条件，
      **不看**标记文案（改 copy 不得改变判定）。
    """

    @staticmethod
    def _stream_dict(**kw) -> dict:
        s = analyzer._new_stream("0")
        s.update({"client": "192.168.1.100", "sport": "51515",
                  "server": "10.0.0.5", "dport": "8080", "app": "TCP",
                  "first": 0.0, "last": 1.0, "bytes": 900, "packets": 4,
                  "frames": ["1", "2"]})
        s.update(kw)
        return s

    def _state(self) -> dict:
        """两条流：0 号「建连无响应」（小流量），1 号正常握手但零窗口 + 海量字节。

        返回的 st 是 ``collect()`` 内部的流聚合形状（与真实数据一致）。
        """
        st = {"streams": {
            "0": self._stream_dict(syn=1, synack_ts=0.0, ack_ts=0.0, rst=0, bytes=900),
            "1": self._stream_dict(syn=1, synack_ts=1.0, ack_ts=1.1, rst=0,
                                   zero_win=4, bytes=5_000_000, packets=50),
        }}
        st["streams"]["1"]["first"] = 0.0
        st["streams"]["1"]["last"] = 1.0
        # _metrics() 需要的采集级计数器（取空/零，不影响 conn_fail 断言）
        st.update({"dns_times": [], "http_times": [], "dns_q": Counter(),
                   "dns_nx": Counter(), "http_codes": Counter(),
                   "dns_q_ids": set(), "dns_r_ids": set(), "retrans": 0,
                   "tcp_packets": 20, "icmp_types": Counter(), "arp_req": Counter(),
                   "arp_rep": set(), "bytes": 1000, "duration": 1.0, "http_req": 0,
                   "dup_ack": 0, "ooo": 0, "tcp_bytes": 1000})
        return st

    def test_flags_follow_copy_but_decisions_do_not(self):
        st = self._state()
        # 基准：真实 copy 表
        base_rows = analyzer._stream_rows(st)
        base_fail = analyzer._metrics(st, base_rows)["conn_fail"]
        base_order = [r["stream"] for r in base_rows]
        self.assertIn("建连无响应", base_rows[0]["flags"])
        self.assertEqual(base_fail, 1)

        # 改 copy 里「建连无响应」的文案 → 渲染跟着变，但计数与排序不变
        table = _copy_table()
        table["stream_flag"] = dict(table["stream_flag"],
                                    no_response="自定义无响应标记")
        with mock.patch("core.config.load_copy", return_value=table):
            new_rows = analyzer._stream_rows(st)
            new_fail = analyzer._metrics(st, new_rows)["conn_fail"]
        self.assertIn("自定义无响应标记", new_rows[0]["flags"])
        self.assertNotIn("建连无响应", new_rows[0]["flags"])
        self.assertEqual(new_fail, base_fail, "conn_fail 不许受标记文案影响")
        self.assertEqual([r["stream"] for r in new_rows], base_order,
                         "排序（score）不许受标记文案影响")

    def test_conn_fail_uses_structured_condition(self):
        # 直接打结构化条件：SYN 无 SYN-ACK 无 RST → 计入；带 RST 的握手拒绝不算
        st = self._state()
        st["streams"]["2"] = self._stream_dict(syn=1, synack_ts=0.0, rst=1)
        rows = analyzer._stream_rows(st)
        self.assertEqual(analyzer._metrics(st, rows)["conn_fail"], 1)
        flags_by_stream = {r["stream"]: r["flags"] for r in rows}
        self.assertIn("被重置", flags_by_stream["2"])
        self.assertNotIn("建连无响应", flags_by_stream["2"])


class RstTitleTests(unittest.TestCase):
    """审查修复回合：``is_rst`` 去掉中文文案匹配后，RST 行仍要选「被拒」标题。"""

    def test_rst_row_gets_rst_title(self):
        table = _copy_table()
        row = {"layer": "L4 传输层", "protocol": "TCP", "category": "连接建立",
               "severity": "警告",
               "finding": "3 个连接被对端 RST 重置（对方明确拒绝）",
               "evidence": "10.0.0.5:8080", "advice": "构造"}
        result = {"meta": {"packets": 20, "tcp_packets": 20, "streams_total": 1},
                  "rows": [row], "metrics": {"conn_refused": 3, "conn_fail": 0},
                  "summary": {}}
        vd = verdict.build(result)
        point = next(p for p in vd["points"] if p["category"] == "连接建立")
        self.assertEqual(point["title"], table["verdict"]["titles"]["connect_rst"])


if __name__ == "__main__":
    unittest.main()

