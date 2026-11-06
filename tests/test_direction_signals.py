"""「会误导用户的结论」四个缺陷的回归护栏（PR B）。

这四个 bug 的共同点是**不报错、只是结论错了**，比崩溃更难发现：

1. ``duplicate_ack`` 输出的是逗号聚合值 ``"1,1"``，旧的 ``_flag`` 只认 ``"1"``，
   于是重复 ACK 恒为 0 —— 依赖 dup-ACK 的方向判定整条链路是死的。
2. ``conn_refused`` 用「流里出现过 RST」判定，把正常关闭阶段的 RST 也算成
   「对方拒绝连接」，高估故障面。
3. ``dns_timeouts`` 用「查询数 − 响应数」，只是数量差：响应重传一次就同时
   多算一次超时、少算一次失败。
4. 零窗口的 headline 分支读的是 ``metrics["zero_win"]``，而这个键根本不存在
   （计数在 ``meta``），分支永不成立 → 把「接收端处理不过来」误报成「链路丢包」。

前四个用例类都是纯函数，不需要 tshark；最后一个类现跑 demo 抓包，
用来守住「这些修复不许在 demo 上产生任何变化」这条底线。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.analyzer import _dns_timeout_count, _flag, _is_handshake_rst, _metrics  # noqa: E402
from core.extract.fields import parse_flag                                        # noqa: E402
from core.tshark import find_tshark                                              # noqa: E402
from core import verdict                                                         # noqa: E402

from core.analyzer import analyze                                                # noqa: E402

SAMPLE = ROOT / "captures" / "faults_demo.pcap"
NO_TSHARK = find_tshark() is None


def _fake_st(**over) -> dict:
    """构造 ``_metrics`` 需要的最小统计字典（不含任何 tshark 依赖）。

    Args:
        **over: 覆盖字段，键名与 ``collect()`` 产出的 ``st`` 一致。

    Returns:
        dict: 只填 ``_metrics`` 会读到的键，其余用零值兜底。
    """
    st = {
        "streams": {}, "dns_times": [], "http_times": [],
        "dns_q": {}, "dns_r": {}, "dns_nx": {}, "http_codes": {}, "http_req": 0,
        "icmp_types": {}, "arp_req": {}, "arp_rep": set(),
        "retrans": 0, "tcp_packets": 0, "dup_ack": 0, "ooo": 0,
        "bytes": 0, "duration": 0.0, "tcp_bytes": 0,
        "dns_q_ids": set(), "dns_r_ids": set(),
    }
    st.update(over)
    return st


def _stream(rtt=(), rst_hs=0):
    """造一条流的最小结构（只保留 ``_metrics`` 会读的字段）。"""
    return {"rtt": list(rtt), "rst_hs": rst_hs}


class FlagParseTest(unittest.TestCase):
    """``parse_flag`` / ``_flag``：逗号聚合值必须判为真。"""

    def test_parse_flag_accepts_comma_aggregated(self):
        """``"1,1"`` 是真实出现过两次的 duplicate_ack，必须判真。"""
        self.assertTrue(parse_flag("1,1"))
        self.assertTrue(parse_flag("1,0"))
        self.assertTrue(parse_flag("0,1"))

    def test_parse_flag_single_values(self):
        """单个值的四种写法。"""
        self.assertTrue(parse_flag("1"))
        self.assertTrue(parse_flag("True"))
        self.assertTrue(parse_flag("YES"))
        self.assertFalse(parse_flag("0"))
        self.assertFalse(parse_flag("False"))
        self.assertFalse(parse_flag(""))
        self.assertFalse(parse_flag(None))

    def test_analyzer_flag_matches_parse_flag(self):
        """analyzer 侧不许自己再写一份解析，两边必须一致。"""
        for raw in ("1,1", "1", "True", "", "0", "False", None, " 1 "):
            self.assertEqual(_flag(raw), parse_flag(raw), f"两处判定不一致：{raw!r}")


class ConnRefusedTest(unittest.TestCase):
    """``conn_refused`` 只认握手阶段的 RST。"""

    def test_established_stream_rst_is_not_refused(self):
        """已建连（收到过 SYN-ACK + 客户端 ACK）后的 RST 属于连接中断。"""
        established = {"syn": 1, "synack_ts": 1.0, "ack_ts": 1.1}
        self.assertFalse(_is_handshake_rst(established, from_client=False))

    def test_handshake_rst_is_refused(self):
        """SYN 之后、握手完成之前被服务端 RST —— 这才是「端口没开」。"""
        handshake = {"syn": 1, "synack_ts": 0.0, "ack_ts": 0.0}
        self.assertTrue(_is_handshake_rst(handshake, from_client=False))

    def test_client_side_rst_is_not_refused(self):
        """客户端自己发的 RST 不是「被对方拒绝」。"""
        handshake = {"syn": 1, "synack_ts": 0.0, "ack_ts": 0.0}
        self.assertFalse(_is_handshake_rst(handshake, from_client=True))

    def test_no_syn_seen_is_not_refused(self):
        """抓包从中途开始、没看到 SYN：无从判断，宁可不算。"""
        midstream = {"syn": 0, "synack_ts": 0.0, "ack_ts": 0.0}
        self.assertFalse(_is_handshake_rst(midstream, from_client=False))

    def test_metric_counts_only_handshake_rst(self):
        """两条流各有一次 RST，但只有一条是握手期被拒。"""
        st = _fake_st(streams={"0": _stream(rst_hs=1), "1": _stream(rst_hs=0)})
        self.assertEqual(_metrics(st, [])["conn_refused"], 1)


class DnsTimeoutTest(unittest.TestCase):
    """``dns_timeouts`` 按 transaction id 配对。"""

    def test_pairing_counts_unanswered_query(self):
        """3 个查询、2 个不同响应 → 1 次超时。"""
        self.assertEqual(_dns_timeout_count({("8.8.8.8", "1"), ("8.8.8.8", "2"),
                                             ("8.8.8.8", "3")},
                                            {("8.8.8.8", "1"), ("8.8.8.8", "2")}), 1)

    def test_duplicate_response_is_not_a_timeout(self):
        """响应重传（同一 id 出现两次）不能把数量差冲成 0。"""
        q = {("8.8.8.8", "1"), ("8.8.8.8", "2")}
        r = {("8.8.8.8", "1"), ("8.8.8.8", "2"), ("8.8.8.8", "2")}
        self.assertEqual(_dns_timeout_count(q, r), 0)
        # 旧口径 max(0, 查询数 - 响应数) 在这里会得到 0，看不出差别；
        # 真正失真的是下面这个：响应来自另一台服务器、id 相同。
        self.assertEqual(_dns_timeout_count({("8.8.8.8", "7")}, {("1.1.1.1", "7")}), 1)

    def test_metric_uses_transaction_pairing(self):
        """``_metrics`` 必须走配对，而不是数量差。"""
        st = _fake_st(dns_q={"a.com": 2, "b.com": 1},
                      dns_r={"a.com": 2, "b.com": 0},
                      dns_q_ids={("8.8.8.8", "1"), ("8.8.8.8", "2"), ("8.8.8.8", "3")},
                      dns_r_ids={("8.8.8.8", "1"), ("8.8.8.8", "2")})
        self.assertEqual(_metrics(st, [])["dns_timeouts"], 1)


class ZeroWindowHeadlineTest(unittest.TestCase):
    """零窗口场景的 headline 必须指向接收端，而不是链路。"""

    ROW = {
        "layer": "L4 传输层", "protocol": "TCP", "category": "传输质量",
        "severity": "警告", "finding": "出现 TCP 零窗口 5 次、窗口满 0 次",
        "evidence": "零窗口=接收方缓冲区被塞满，发送方只能暂停",
        "advice": "这不是网络慢，是接收端应用处理不过来。",
    }

    def _result(self, meta_extra: dict) -> dict:
        meta = {"packets": 11, "tcp_packets": 10, "interface": "eth0", "bpf": ""}
        meta.update(meta_extra)
        return {"meta": meta, "rows": [dict(self.ROW)],
                "metrics": {"retrans_rate": 0.0, "zero_win": 0}, "summary": {}}

    def test_headline_points_at_receiver(self):
        """meta.zero_win=5 且重传率 <2% → 结论是「接收端处理不过来」。"""
        out = verdict.build(self._result({"zero_win": 5}))
        self.assertIn("零窗口", out["headline"])
        self.assertIn("接收", out["headline"])

    def test_zero_win_in_metrics_alone_is_not_enough(self):
        """守住旧 bug：把计数放进 metrics 不该影响结果（它属于 meta）。"""
        res = self._result({})
        res["metrics"]["zero_win"] = 5
        self.assertIn("链路上在丢包", verdict.build(res)["headline"])


@unittest.skipIf(NO_TSHARK, "没有 tshark，跳过现跑回归")
class DemoUnchangedTest(unittest.TestCase):
    """demo 抓包上这四个修复一个都不许触发。"""

    def test_demo_metrics_keep_zero(self):
        """demo 没有重复 ACK / 握手期 RST / DNS 超时，三个数都必须还是 0。"""
        self.assertTrue(SAMPLE.is_file(), f"缺少示例抓包：{SAMPLE}")
        res = analyze(SAMPLE)
        self.assertTrue(res.get("ok"), res.get("error"))
        self.assertEqual(res["meta"]["dup_ack"], 0, "demo 的重复 ACK 变了")
        self.assertEqual(res["metrics"]["conn_refused"], 0, "demo 的被拒连接数变了")
        self.assertEqual(res["metrics"]["dns_timeouts"], 0, "demo 的 DNS 超时数变了")


if __name__ == "__main__":
    unittest.main(verbosity=2)
