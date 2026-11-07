"""文案单一来源（PR E）：报告/判定/建议/prompt 的文案只从 copy 表来，判定不靠文案。

守的口径（可机械证伪）：

* **反向断言**：把 copy 表（来源）换成自定义值，用户可见输出必须跟着变。
  这条能杀死「copy 读不到、悄悄回退内联常量」的假绿 —— 只 patch 消费方函数
  是证明不了这一点的，必须从 ``core.config.load_copy`` 这个来源打补丁。
  ⚠️ ``copytext`` 现在按文件 mtime/size 缓存文案表：**patch 来源不会改变文件**，
  所以必须用 :func:`_patched_copy`（内部显式 ``copytext.reload()``），
  否则用例会静默读到真表而假绿。
* **V4 机制化**：``is_normal()`` 只看 ``Severity``：``"na"``（没样本）不是 normal；
  非 OK 严重度的行哪怕文案里有「未检测到」也不算 normal（不再做文本匹配）。
* **V4 coverage**：``coverage()`` 有独立的 ``no_sample`` 桶，且 ``na`` 行不算漏映射。
* **V5 / B1**：证据不足时层状态是 ``na``，指标短语必须是「无样本」类文案，
  不许出现「…正常」的肯定句。
* **判定与文案解耦**：会话标记、连接建立证据、RST 标题都不许把中文文案当哨兵。
* **缓存不破坏可测性 + 性能回归守卫**：重复取表不重复解析；1000 条流的标记渲染
  必须远低于 0.5s（去掉缓存会立刻破线）。
"""

from __future__ import annotations

import contextlib
import json
import sys
import time
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import copytext                                             # noqa: E402  （与 analyzer/report 同一个模块实例）
from core import analyzer                                   # noqa: E402
from core import config as core_config                      # noqa: E402
from core import verdict                                    # noqa: E402
from core.analyzer import build_findings                    # noqa: E402
from core.rules import legacy_map                           # noqa: E402

import report as report_mod                                 # noqa: E402  （与运行时一致：扁平导入）

COPY_PATH = ROOT / "core" / "copy" / "zh-CN.json"


def _copy_table() -> dict:
    return json.loads(COPY_PATH.read_text(encoding="utf-8"))


@contextlib.contextmanager
def _patched_copy(table: dict):
    """临时把文案来源换成 ``table``，并**显式清 copytext 缓存**。

    为什么要 reload：缓存按「文件 mtime/size」失效，而 patch ``load_copy``
    改的是读取函数、不是文件；不清缓存就会静默读回真表（测试假绿）。
    """
    with mock.patch("core.config.load_copy", return_value=table):
        copytext.reload()
        try:
            yield
        finally:
            copytext.reload()


def _empty_st() -> dict:
    """``build_findings`` 需要的最小采集统计字典（全部空计数）。"""
    return {
        "packets": 10, "duration": 1.0, "bytes": 1000, "tcp_packets": 0,
        "tcp_bytes": 1000, "streams": {}, "dns_q": Counter(), "dns_r": Counter(),
        "dns_nx": Counter(), "dns_times": [], "dns_servers": Counter(),
        "http_req": 0, "http_codes": Counter(), "http_detail": [], "http_times": [],
        "icmp_detail": [], "icmp_types": Counter(), "arp_req": Counter(),
        "arp_rep": set(), "ext_dst": Counter(), "ext_ports": {}, "ext_frames": {},
        "basic_auth": [], "ftp_pass": [], "uri_secret": [], "telnet_frames": [],
        "zero_win": 0, "win_full": 0, "retrans": 0, "dup_ack": 0, "ooo": 0,
        "tls_sni": Counter(), "tls_alert": 0,
    }


def _empty_m() -> dict:
    """``build_findings`` 需要的最小指标表（全部 0）。"""
    return {
        "streams_total": 0, "conn_fail": 0, "conn_refused": 0, "hs_avg_ms": 0,
        "hs_max_ms": 0, "hs_jitter_ms": 0, "hs_samples": 0, "retrans_rate": 0.0,
        "ooo_rate": 0.0, "dup_ack_rate": 0.0, "icmp_unreach": 0, "icmp_timeout": 0,
        "rtt_samples": 0, "rtt_avg_ms": 0.0, "rtt_p95_ms": 0.0, "rtt_jitter_ms": 0.0,
        "rtt_max_ms": 0.0, "dns_fail_rate": 0.0, "dns_timeouts": 0,
        "dns_avg_ms": 0.0, "dns_max_ms": 0.0, "dns_samples": 0,
        "http_err5": 0, "http_err5_rate": 0.0, "http_err4": 0,
        "http_avg_ms": 0.0, "http_p95_ms": 0.0, "http_max_ms": 0.0,
        "http_samples": 0, "arp_no_reply": 0,
    }


def _tcp_stream(server: str = "10.0.0.5", dport: str = "8080",
                syn: int = 3, **kw) -> dict:
    """一条「发了 SYN 但无回应」的完整内部流字典（collect() 的形状）。"""
    s = analyzer._new_stream("0")
    s.update({"client": "192.168.1.100", "sport": "51515",
              "server": server, "dport": dport, "app": "TCP",
              "first": 0.0, "last": 1.0, "bytes": 900, "packets": syn,
              "syn": syn, "syn_ts": 0.1, "synack_ts": 0.0, "ack_ts": 0.0,
              "rst": 0, "frames": ["1", "2", "3"]})
    s.update(kw)
    return s


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
    "stream_flag": {"no_response": "自定义会话标记"},
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
        with _patched_copy(CUSTOM):
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

    def test_rows_follow_copy_source(self):
        st, m = _empty_st(), _empty_m()
        with _patched_copy(CUSTOM):
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
        copy = _copy_table()
        v = verdict.build({"meta": self._base_meta(), "rows": [], "metrics": {},
                           "summary": {}})
        l2 = next(x for x in v["layers"] if x["id"] == "L2")
        self.assertEqual(l2["status"], "na")
        self.assertEqual(l2["detail"], copy["layer_note"]["l2.na"])
        self.assertIn("无样本", l2["detail"])
        self.assertNotIn("正常", l2["detail"])


class SuspiciousPortLabelTests(unittest.TestCase):
    """审查第 1 轮阻塞 1：9 个高危端口必须**每一个**都有非空标签。

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
        st, m = _empty_st(), _empty_m()
        st.update({"tcp_packets": 10,
                   "ext_dst": Counter({"203.0.113.9": 9}),
                   "ext_ports": {"203.0.113.9": set(self.EXPECTED)},
                   "ext_frames": {"203.0.113.9": ["31"]}})
        m.update({"streams_total": 1})
        rows = build_findings(st, m, [])
        finding = next(r["finding"] for r in rows if r["category"] == "可疑外联")
        for port, label in self.EXPECTED.items():
            with self.subTest(port=port):
                self.assertIn(f"{port}({label})", finding)
        self.assertNotIn("9050(9050)", finding, "9050 的标签不许退化成端口号")


class StreamFlagDecouplingTests(unittest.TestCase):
    """审查第 1 轮阻塞 2：会话标记的文案与判定彻底解耦。

    * 标记文字必须来自 copy 表（改 copy → 渲染跟着变）；
    * ``conn_fail`` 计数、``streams_top`` 排序、连接建立证据都必须基于结构化条件，
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
        # 基准值与基线文案全部从 copy 表取（不写死默认文案，避免合法改文案时误红）
        copy = _copy_table()
        base_label = copy["stream_flag"]["no_response"]
        base_rows = analyzer._stream_rows(st)
        base_fail = analyzer._metrics(st, base_rows)["conn_fail"]
        base_order = [r["stream"] for r in base_rows]
        self.assertIn(base_label, base_rows[0]["flags"])
        self.assertEqual(base_fail, 1)

        # 改 copy 里「建连无响应」的文案 → 渲染跟着变，但计数与排序不变
        table = _copy_table()
        table["stream_flag"] = dict(table["stream_flag"],
                                    no_response="自定义无响应标记")
        with _patched_copy(table):
            new_rows = analyzer._stream_rows(st)
            new_fail = analyzer._metrics(st, new_rows)["conn_fail"]
        self.assertIn("自定义无响应标记", new_rows[0]["flags"])
        self.assertNotIn(base_label, new_rows[0]["flags"])
        self.assertEqual(new_fail, base_fail, "conn_fail 不许受标记文案影响")
        self.assertEqual([r["stream"] for r in new_rows], base_order,
                         "排序（score）不许受标记文案影响")

    def test_conn_fail_uses_structured_condition(self):
        # 直接打结构化条件：SYN 无 SYN-ACK 无 RST → 计入；带 RST 的握手拒绝不算
        copy = _copy_table()
        st = self._state()
        st["streams"]["2"] = self._stream_dict(syn=1, synack_ts=0.0, rst=1)
        rows = analyzer._stream_rows(st)
        self.assertEqual(analyzer._metrics(st, rows)["conn_fail"], 1)
        flags_by_stream = {r["stream"]: r["flags"] for r in rows}
        self.assertIn(copy["stream_flag"]["rst"], flags_by_stream["2"])
        self.assertNotIn(copy["stream_flag"]["no_response"], flags_by_stream["2"])


class EvidenceDecouplingTests(unittest.TestCase):
    """审查第 2 轮 C2：``build_findings`` 的连接建立证据不许依赖 finding 文案。

    变异「把证据筛选改回按 finding 文案匹配」时本条必须变红：改掉 copy 的
    ``finding.connect.no_response`` 后，证据里仍必须有 ``server:dport`` / SYN 包数。
    """

    def test_evidence_keeps_target_when_finding_text_changes(self):
        st, _ = _empty_st(), _empty_m()
        st["streams"] = {"0": _tcp_stream()}
        st["tcp_packets"] = 9

        table = _copy_table()
        table["finding"] = dict(table["finding"],
                                **{"connect.no_response": "改了 Finding 文案（无哨兵）"})
        # 关键：会话标记也必须一起改。只改 finding 文案的话，``streams[].flags`` 里仍是
        # 真表的「建连无响应」，于是「按 flags 文案筛证据」的旧实现照样能匹配上 —— 用例假绿。
        table["stream_flag"] = dict(table["stream_flag"],
                                    **{"no_response": "改了会话标记（无哨兵）"})
        with _patched_copy(table):
            # streams 必须在 patch 内生成，flags 才会用被改过的文案
            streams = analyzer._stream_rows(st)
            m = analyzer._metrics(st, streams)
            self.assertEqual(m["conn_fail"], 1,
                             "conn_fail 必须来自结构化判定，不受文案改动影响")
            rows = build_findings(st, m, streams)
        row = next(r for r in rows
                   if r["category"] == "连接建立" and r["severity"] == "严重")
        self.assertEqual(row["finding"], "改了 Finding 文案（无哨兵）")
        self.assertIn("10.0.0.5:8080", row["evidence"],
                      "证据不许依赖 finding/flag 的中文文案（旧哨兵实现会退化成“帧 -”）")
        self.assertIn("SYN 3 包", row["evidence"])


class RstTitleTests(unittest.TestCase):
    """审查修复回合：RST 行选「被拒」标题；双 token 行必须选「建连失败/偏慢」标题。"""

    @staticmethod
    def _result(finding: str) -> dict:
        row = {"layer": "L4 传输层", "protocol": "TCP", "category": "连接建立",
               "severity": "警告", "finding": finding,
               "evidence": "10.0.0.5:8080", "advice": "构造"}
        return {"meta": {"packets": 20, "tcp_packets": 20, "streams_total": 1},
                "rows": [row], "metrics": {"conn_refused": 3, "conn_fail": 0},
                "summary": {}}

    def test_rst_row_gets_rst_title(self):
        table = _copy_table()
        vd = verdict.build(self._result("3 个连接被对端 RST 重置（对方明确拒绝）"))
        point = next(p for p in vd["points"] if p["category"] == "连接建立")
        self.assertEqual(point["title"], table["verdict"]["titles"]["connect_rst"])

    def test_dual_token_row_keeps_plain_title(self):
        """finding 同时含 "RST" 与「无响应」时，标题必须是「建连失败/偏慢」。

        这是 ``is_rst`` 里 ``"无响应" not in finding`` 守卫的判别性用例：
        守卫被去掉后本用例必红（标题会翻成「对方明确拒绝了连接」+ RST_EXPLAIN）。
        """
        table = _copy_table()
        vd = verdict.build(self._result("未收到 SYN-ACK/RST，无响应"))
        point = next(p for p in vd["points"] if p["category"] == "连接建立")
        self.assertEqual(point["title"], table["verdict"]["titles"]["connect"])
        self.assertEqual(point["plain"].startswith(table["verdict"]["explain"]["connect"]),
                         True)


class LayerProtocolValidationTests(unittest.TestCase):
    """审查第 2 轮 C5：``layer_protocol`` 也要进 ``_load_copy`` 的结构白名单。

    畸形时整表回退（渲染成 key）而不是静默读半张表；本用例在漏加白名单时会变红
    （畸形表被当合法表，protocol 拿到畸形值/None）。
    """

    def test_malformed_layer_protocol_falls_back_to_keys(self):
        table = _copy_table()
        # 只弄畸形 l2，保留 l3/l4/l7 为合法字符串 —— 否则删掉白名单后其余层也会退化成 key，
        # 断言照样成立，用例就抓不住"漏加白名单"这个回归（审查第 3 轮指出）。
        table["layer_protocol"] = dict(table["layer_protocol"], l2=[])   # 畸形：值不是字符串
        with _patched_copy(table):
            vd = verdict.build({"meta": {"packets": 5}, "rows": [],
                                "metrics": {}, "summary": {}})
        protocols = {x["id"]: x["protocol"] for x in vd["layers"]}
        self.assertEqual(protocols, {"L2": "l2", "L3": "l3", "L4": "l4", "L7": "l7"},
                         "畸形表必须整体回退成 key，不许把畸形值透传")


class CopytextCacheTests(unittest.TestCase):
    """审查第 2 轮必修 2：copytext 缓存（性能回归守卫）+ reload 语义。"""

    def tearDown(self):
        copytext.reload()      # 任何用例都不许把自定义/旧表留在缓存里

    def test_repeated_load_does_not_reparse(self):
        copytext.reload()
        copytext.load_table()                      # 预热：第一次读盘
        with mock.patch.object(core_config, "read_json") as spy:
            copytext.load_table()
            copytext.load_table()
            copytext.text("stream_flag", "no_response")
        spy.assert_not_called()

    def test_reload_forces_reread(self):
        warm = copytext.load_table()
        self.assertIs(copytext.load_table(), warm, "缓存命中应返回同一对象")
        with mock.patch.object(core_config, "read_json", return_value={"a": "b"}):
            copytext.reload()
            self.assertEqual(copytext.load_table(), {"a": "b"})

    @staticmethod
    def _bulk_st(n: int = 1000) -> dict:
        streams = {}
        for i in range(n):
            s = analyzer._new_stream(str(i))
            s.update({"syn": 1, "synack_ts": 0.0, "ack_ts": 0.0, "rst": 0,
                      "client": "192.168.1.100", "sport": "51515",
                      "server": "10.0.0.5", "dport": "8080", "app": "TCP",
                      "first": float(i), "last": float(i) + 1.0,
                      "bytes": 900, "packets": 4, "frames": ["1"]})
            streams[str(i)] = s
        return {"streams": streams}

    def test_stream_rows_1000_flows_under_half_second(self):
        st = self._bulk_st()
        copytext.reload()
        copytext.load_table()                     # 预热：把首次读盘排除在计时外
        analyzer._stream_rows(st)                 # 预热：_stream_rows 的表加载
        started = time.perf_counter()
        rows = analyzer._stream_rows(st)
        elapsed = time.perf_counter() - started
        self.assertEqual(len(rows), 1000)
        self.assertLess(elapsed, 0.5,
                        f"1000 条流的标记渲染耗时 {elapsed:.3f}s，疑似缓存失效（应 << 0.5s）")

    def test_repeated_flag_render_under_half_second(self):
        # 5000 次直接渲染 ≈ 10,000 条流 × 半个标记的调用量：
        # 缓存命中 ~0.06s；**去掉缓存**后每次重读 35KB JSON ≈ 1s+，必红。
        copytext.reload()
        copytext.load_table()                     # 预热
        started = time.perf_counter()
        for _ in range(5000):
            copytext.text("stream_flag", "no_response")
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 0.5,
                        f"5000 次标记渲染耗时 {elapsed:.3f}s，疑似每次重读 35KB JSON")


if __name__ == "__main__":
    unittest.main()
