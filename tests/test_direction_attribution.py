"""PR F：重传方向判定（上行 / 下行 / 双向 / 方向未定）。

守的口径：

* **方向统计在 collect() 内部累计**（``st["dir"]``），只用于文案，**不进报告**；
* **分桶走 ``_accumulate_dir`` 纯函数**：c2s/s2c 计数可以用合成帧回归，
  不需要 tshark（把分桶改成「永远 c2s」必须让用例变红）；
* **同一 stream 出现两个不同端点的纯 SYN → 方向歧义**：不覆盖原 client，
  后续帧一律计入 ``unknown``；端口扫描的每个 SYN 各自一条 stream，不受影响；
* **只有 dup-ACK 证据才定向**：UP = c2s 有数据重传且 s2c 有重复 ACK，
  DOWN 反之，两侧同时成立才是 BIDIR；其余一律退回现有通用重传行；
* **严重度阈值不变**：方向只改 finding/advice 文案，不改等级；
* **旧调用方兼容**：合成 ``st`` 没有 ``st["dir"]`` 时不许 KeyError，也不许冒方向结论。

需要 tshark 的用例在干净 checkout（无 ``tools/``）里跳过，与 CI 形态一致。
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

from core import analyzer                                             # noqa: E402
from core.analyzer import (                                           # noqa: E402
    _accumulate_dir, _dir_of, _retrans_direction, build_findings,
)
from core.tshark import find_tshark                                   # noqa: E402

COPY_PATH = ROOT / "core" / "copy" / "zh-CN.json"
SAMPLE = ROOT / "captures" / "faults_demo.pcap"
NO_TSHARK = find_tshark() is None


def _copy_table() -> dict:
    return json.loads(COPY_PATH.read_text(encoding="utf-8"))


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


def _dir(c2s_retrans=0, c2s_dup=0, s2c_retrans=0, s2c_dup=0, unknown=0) -> dict:
    """按 ``collect()`` 的形状造分方向统计（默认两侧全 0）。"""
    return {
        "c2s": {"retrans": c2s_retrans, "dup_ack": c2s_dup, "packets": 5},
        "s2c": {"retrans": s2c_retrans, "dup_ack": s2c_dup, "packets": 6},
        "unknown": unknown,
    }


def _frame(syn: int = 0, ack: int = 0, retrans: int = 0, dup: str = "") -> dict:
    """单个 TCP 帧的最小 tshark 字段字典（合成帧，不需要 tshark）。"""
    return {
        "tcp.flags.syn": str(syn),
        "tcp.flags.ack": str(ack),
        "tcp.analysis.retransmission": "1" if retrans else "",
        "tcp.analysis.duplicate_ack": dup,
    }


def _drive(frames: list[tuple[str, str, dict]], sid: str = "0") -> tuple[dict, dict]:
    """把合成帧逐条喂给 ``_accumulate_dir``，返回 ``(st["dir"], dir_client)``。"""
    st = {"dir": analyzer._new_direction_stats()}
    dir_client: dict = {}
    for src, dst, row in frames:
        _accumulate_dir(st, sid, src, dst, row, dir_client)
    return st["dir"], dir_client


def _generated_sample(name: str, out_dir: str) -> Path:
    """用 scaffold 的纯标准库生成器造样本（不依赖 scapy / tshark）。"""
    spec = importlib.util.spec_from_file_location(
        "_netdiag_gen_pcap", ROOT / "scaffold" / "tests" / "fixtures" / "gen_pcap.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    frames = getattr(mod, f"case_{name}")()
    path = Path(out_dir) / f"{name}.pcap"
    mod.write_pcap(path, frames)
    return path


def _stream(stream: str = "0", retrans: int = 1) -> dict:
    """``_stream_rows()`` 形状的一条会话（只填重传证据会用到的键）。"""
    return {"stream": stream, "client": "192.168.1.100", "sport": "51516",
            "server": "10.0.0.5", "dport": "8080", "retrans": retrans}


def _rows(st_extra: dict | None = None, rr: float = 9.09) -> list[dict]:
    """跑 ``build_findings``，返回「传输质量」类别的行。"""
    st, m = _empty_st(), _empty_m()
    st["tcp_packets"] = 11
    st["retrans"] = 1
    m.update({"streams_total": 1, "retrans_rate": rr})
    if st_extra:
        st.update(st_extra)
    return [r for r in build_findings(st, m, [_stream()]) if r["category"] == "传输质量"]


def _retrans_row(rows: list[dict]) -> dict:
    """取「重传」那条故障行（排除零窗口/正常行）。"""
    return next(r for r in rows if r["severity"] in ("严重", "警告", "提示"))


class DirectionStatsShapeTests(unittest.TestCase):
    """V1：``st["dir"]`` 的固定结构（两侧三项 + unknown）。"""

    def test_direction_stats_shape(self):
        stats = analyzer._new_direction_stats()
        self.assertEqual(set(stats), {"c2s", "s2c", "unknown"})
        for side in ("c2s", "s2c"):
            self.assertEqual(set(stats[side]), {"retrans", "dup_ack", "packets"})
            self.assertTrue(all(v == 0 for v in stats[side].values()))
        self.assertIsInstance(stats["unknown"], int)


class BucketAssignmentTests(unittest.TestCase):
    """C1：分桶必须按方向归属，不能「永远算 c2s」。

    合成帧的帧数取自真实样本的实测值（``collect()`` + tshark 4.7.4）：
    ``faults_demo`` c2s 21 / s2c 15，``tcp_retransmission`` c2s 6 / s2c 5。
    真实 pcap 的同一组数字由 ``CollectDirectionTests`` /
    ``TcpRetransmissionIntegrationTests`` 在 tshark 可用时再核一遍。
    """

    C, S = "192.168.1.100", "10.0.0.5"

    def test_demo_bucket_counts_match_measured(self):
        """``faults_demo.pcap`` 实测 c2s 21 / s2c 15（含 c2s 重传 2）。"""
        frames = [(self.C, self.S, _frame(syn=1))]
        frames += [(self.C, self.S, _frame()) for _ in range(18)]
        frames += [(self.C, self.S, _frame(retrans=1)) for _ in range(2)]
        frames += [(self.S, self.C, _frame()) for _ in range(15)]
        stats, dir_client = _drive(frames)
        self.assertEqual(_dir_of("0", self.C, dir_client), "c2s")
        self.assertEqual(_dir_of("0", self.S, dir_client), "s2c")
        self.assertEqual(stats["c2s"], {"retrans": 2, "dup_ack": 0, "packets": 21})
        self.assertEqual(stats["s2c"], {"retrans": 0, "dup_ack": 0, "packets": 15})
        self.assertEqual(stats["unknown"], 0)
        self.assertEqual(stats["c2s"]["packets"] + stats["s2c"]["packets"], 36)

    def test_tcp_retransmission_bucket_counts_match_measured(self):
        """``tcp_retransmission.pcap`` 实测 c2s 6 / s2c 5、c2s 重传 1、s2c dup-ACK 2。"""
        frames = [
            (self.C, self.S, _frame(syn=1)),
            (self.S, self.C, _frame(syn=1, ack=1)),
            (self.C, self.S, _frame(ack=1)),
            (self.C, self.S, _frame()),
            (self.S, self.C, _frame(ack=1)),
            (self.C, self.S, _frame()),
            (self.S, self.C, _frame(ack=1, dup="1,1")),
            (self.C, self.S, _frame()),
            (self.S, self.C, _frame(ack=1, dup="1,1")),
            (self.C, self.S, _frame(retrans=1)),
            (self.S, self.C, _frame(ack=1)),
        ]
        stats, _ = _drive(frames)
        self.assertEqual(stats["c2s"], {"retrans": 1, "dup_ack": 0, "packets": 6})
        self.assertEqual(stats["s2c"], {"retrans": 0, "dup_ack": 2, "packets": 5})
        self.assertEqual(stats["unknown"], 0)
        self.assertEqual(stats["c2s"]["packets"] + stats["s2c"]["packets"], 11)

    def test_frames_before_handshake_are_unknown(self):
        """没看到握手的抓包：不许猜方向，全部计入 unknown。"""
        stats, _ = _drive([(self.C, self.S, _frame())])
        self.assertEqual(stats["unknown"], 1)
        self.assertEqual(stats["c2s"]["packets"], 0)
        self.assertEqual(stats["s2c"]["packets"], 0)

    def test_syn_retransmission_is_not_data_retransmission(self):
        """同一端点的 SYN 重发只算握手帧，不混入方向 retrans。"""
        stats, _ = _drive([
            (self.C, self.S, _frame(syn=1)),
            (self.C, self.S, _frame(syn=1, retrans=1)),
        ])
        self.assertEqual(stats["c2s"]["packets"], 2)
        self.assertEqual(stats["c2s"]["retrans"], 0)


class DirectionAmbiguityTests(unittest.TestCase):
    """C2：同一 stream 出现两个不同端点的纯 SYN → 方向歧义，不许覆盖原 client。"""

    A, B = "192.168.1.100", "10.0.0.5"

    def test_two_pure_syns_make_stream_ambiguous(self):
        """TCP 同时打开 / 罕见握手：两个纯 SYN 不同端点 → 后续帧全部 unknown。"""
        st = {"dir": analyzer._new_direction_stats()}
        dir_client: dict = {}
        _accumulate_dir(st, "0", self.A, self.B, _frame(syn=1), dir_client)
        _accumulate_dir(st, "0", self.B, self.A, _frame(syn=1), dir_client)
        _accumulate_dir(st, "0", self.A, self.B, _frame(), dir_client)
        _accumulate_dir(st, "0", self.B, self.A, _frame(), dir_client)
        self.assertEqual(dir_client["0"]["client"], self.A,
                         "原 client 不许被后一个 SYN 覆盖")
        self.assertTrue(dir_client["0"]["ambiguous"])
        self.assertEqual(st["dir"]["c2s"]["packets"], 1, "歧义前的帧保持原归属")
        self.assertEqual(st["dir"]["s2c"]["packets"], 0)
        self.assertEqual(st["dir"]["unknown"], 3, "第二个 SYN 及其后帧一律计入 unknown")

    def test_same_endpoint_syn_retransmission_is_not_ambiguous(self):
        """同一端点重发 SYN 是正常重传，不是歧义。"""
        st = {"dir": analyzer._new_direction_stats()}
        dir_client: dict = {}
        _accumulate_dir(st, "0", self.A, self.B, _frame(syn=1), dir_client)
        _accumulate_dir(st, "0", self.A, self.B, _frame(syn=1), dir_client)
        self.assertFalse(dir_client["0"]["ambiguous"])
        self.assertEqual(st["dir"]["c2s"]["packets"], 2)
        self.assertEqual(st["dir"]["unknown"], 0)

    def test_port_scan_streams_are_not_ambiguous(self):
        """端口扫描：每次 SYN 一条独立 stream → 各自 c2s，绝不能判成歧义。"""
        st = {"dir": analyzer._new_direction_stats()}
        dir_client: dict = {}
        for sid in ("0", "1", "2", "3"):
            _accumulate_dir(st, sid, self.A, self.B, _frame(syn=1), dir_client)
            _accumulate_dir(st, sid, self.A, self.B, _frame(), dir_client)
        self.assertEqual(len(dir_client), 4)
        self.assertFalse(any(s["ambiguous"] for s in dir_client.values()))
        self.assertEqual(st["dir"]["c2s"]["packets"], 8)
        self.assertEqual(st["dir"]["unknown"], 0)


class DirectionHintTests(unittest.TestCase):
    """V2：四个分支的判定表（纯函数，不依赖 tshark）。"""

    def test_up(self):
        """客户端重传 + 服务端重复 ACK → 上行。"""
        self.assertEqual(_retrans_direction({"dir": _dir(c2s_retrans=1, s2c_dup=2)}), "up")

    def test_down(self):
        """服务端重传 + 客户端重复 ACK → 下行。"""
        self.assertEqual(_retrans_direction({"dir": _dir(s2c_retrans=1, c2s_dup=2)}), "down")

    def test_bidir(self):
        """两侧都重传、两侧都有重复 ACK → 双向。"""
        self.assertEqual(
            _retrans_direction({"dir": _dir(c2s_retrans=2, c2s_dup=1,
                                            s2c_retrans=3, s2c_dup=4)}), "bidir")

    def test_retrans_alone_is_not_directional(self):
        """只有重传、没有 dup-ACK：不能定向（可能只是对端 ACK 丢）。"""
        self.assertIsNone(_retrans_direction({"dir": _dir(c2s_retrans=3, s2c_retrans=2)}))

    def test_dup_ack_alone_is_not_directional(self):
        """只有 dup-ACK、没有重传：同样不能定向。"""
        self.assertIsNone(_retrans_direction({"dir": _dir(c2s_dup=2, s2c_dup=2)}))

    def test_missing_dir_is_none(self):
        """旧测试的合成 st 没有 ``dir`` → 方向未定，不许 KeyError。"""
        self.assertIsNone(_retrans_direction({}))
        self.assertIsNone(_retrans_direction({"dir": {}}))


class BuildFindingsDirectionTests(unittest.TestCase):
    """V2/V3/V4：行文案跟着方向走，严重度与通用行保持原口径。"""

    def setUp(self) -> None:
        self.copy = _copy_table()

    def test_up_row_uses_up_copy_and_advice(self):
        row = _retrans_row(_rows({"dir": _dir(c2s_retrans=1, s2c_dup=2)}))
        self.assertIn("c2s 重传 1", row["finding"])
        self.assertIn("s2c 重复 ACK 2", row["finding"])
        self.assertNotIn("{", row["finding"], "占位符必须全部被 format 消费")
        self.assertEqual(row["advice"], self.copy["advice"]["L4.RETRANS.ADVICE.UP"])
        self.assertEqual(row["severity"], "严重")

    def test_down_row_uses_down_copy_and_advice(self):
        row = _retrans_row(_rows({"dir": _dir(s2c_retrans=3, c2s_dup=2)}))
        self.assertIn("s2c 重传 3", row["finding"])
        self.assertIn("c2s 重复 ACK 2", row["finding"])
        self.assertNotIn("{", row["finding"])
        self.assertEqual(row["advice"], self.copy["advice"]["L4.RETRANS.ADVICE.DOWN"])

    def test_bidir_row_uses_bidir_copy_and_advice(self):
        row = _retrans_row(_rows({"dir": _dir(c2s_retrans=2, c2s_dup=1,
                                               s2c_retrans=3, s2c_dup=4)}))
        self.assertIn("c2s 重传 2", row["finding"])
        self.assertIn("s2c 重传 3", row["finding"])
        self.assertNotIn("{", row["finding"])
        self.assertEqual(row["advice"], self.copy["advice"]["L4.RETRANS.ADVICE.BIDIR"])
        self.assertNotEqual(row["advice"], self.copy["advice"]["L4.RETRANS.ADVICE"])

    def test_no_evidence_falls_back_to_generic_row(self):
        """V2：没有方向证据时文案必须与现有通用行逐字相同。"""
        row = _retrans_row(_rows())          # 完全不传 dir
        expected = self.copy["finding"]["transport.retrans"].format(
            rate=9.09, retrans=1, tcp_packets=11, ooo=0.0, dup=0.0)
        self.assertEqual(row["finding"], expected)
        self.assertEqual(row["advice"], self.copy["advice"]["L4.RETRANS.ADVICE"])

    def test_retrans_without_dup_ack_keeps_generic_row(self):
        row = _retrans_row(_rows({"dir": _dir(c2s_retrans=1, s2c_retrans=1)}))
        self.assertNotIn("上行", row["finding"])
        self.assertNotIn("下行", row["finding"])
        self.assertIn("TCP 重传率 9.09%", row["finding"])

    def test_severity_thresholds_unchanged(self):
        """V4：方向只改文案；阈值仍是 ≥5 严重 / ≥2 警告 / ≥0.5 提示。"""
        dirs = {"dir": _dir(c2s_retrans=1, s2c_dup=1)}
        cases = [(5.0, "严重"), (4.99, "警告"), (2.0, "警告"),
                 (1.99, "提示"), (0.5, "提示")]
        for rate, expected in cases:
            with self.subTest(rate=rate):
                self.assertEqual(_retrans_row(_rows(dirs, rr=rate))["severity"], expected)

    def test_below_threshold_has_no_row_at_all(self):
        rows = _rows({"dir": _dir(c2s_retrans=1, s2c_dup=1)}, rr=0.49)
        self.assertFalse(any(r["severity"] in ("严重", "警告", "提示") for r in rows))


class CopyKeyTests(unittest.TestCase):
    """V3：新 copy key 存在、非空、不是旧文案占位。"""

    KEYS = ("transport.retrans_up", "transport.retrans_down", "transport.retrans_bidir")

    def test_new_finding_keys_exist(self):
        copy = _copy_table()
        for key in self.KEYS:
            with self.subTest(key=key):
                self.assertIn(key, copy["finding"])
                self.assertTrue(copy["finding"][key].strip())
        self.assertIn("L4.RETRANS.ADVICE.BIDIR", copy["advice"])
        self.assertTrue(copy["advice"]["L4.RETRANS.ADVICE.BIDIR"].strip())

    def test_advice_up_down_still_exist(self):
        copy = _copy_table()
        self.assertIn("L4.RETRANS.ADVICE.UP", copy["advice"])
        self.assertIn("L4.RETRANS.ADVICE.DOWN", copy["advice"])

    def test_placeholders_are_named_and_format_safe(self):
        """每个新模板的占位符都必须是命名参数，且用本文件覆盖的实参可 format。"""
        import string

        copy = _copy_table()
        args = {"c2s_retrans": 1, "s2c_retrans": 2, "c2s_dup_ack": 3,
                "s2c_dup_ack": 4, "retrans_rate": 9.09}
        for key in self.KEYS:
            with self.subTest(key=key):
                template = copy["finding"][key]
                fields = {f for _, f, _, _ in string.Formatter().parse(template) if f}
                self.assertTrue(fields, "模板必须含占位符")
                for name in fields:
                    self.assertIn(name, args, f"未知占位符：{name}")
                self.assertNotIn("{", template.format(**args))


@unittest.skipIf(NO_TSHARK, "没有 tshark，跳过现跑校验")
class CollectDirectionTests(unittest.TestCase):
    """V1/C1：现跑 demo，``st["dir"]`` 必须真实累计；报告里不许出现新键。"""

    def test_collect_accumulates_direction_stats(self):
        st, err = analyzer.collect(SAMPLE)
        self.assertEqual(err, "")
        stats = st.get("dir")
        self.assertIsInstance(stats, dict)
        self.assertEqual(set(stats), {"c2s", "s2c", "unknown"})
        for side in ("c2s", "s2c"):
            self.assertEqual(set(stats[side]), {"retrans", "dup_ack", "packets"})
        total = stats["c2s"]["packets"] + stats["s2c"]["packets"] + stats["unknown"]
        self.assertEqual(total, st["tcp_packets"],
                         "每个 TCP 帧必须且只能落进一个方向桶（或 unknown）")
        self.assertGreater(stats["c2s"]["packets"] + stats["s2c"]["packets"], 0)

    def test_demo_bucket_counts_match_measured(self):
        """``faults_demo.pcap`` 实测 c2s 21 / s2c 15（tshark 4.7.4，重测确认）。"""
        st, err = analyzer.collect(SAMPLE)
        self.assertEqual(err, "")
        stats = st["dir"]
        self.assertEqual((stats["c2s"]["packets"], stats["s2c"]["packets"]), (21, 15))
        self.assertEqual((stats["c2s"]["retrans"], stats["s2c"]["retrans"]), (2, 0))
        self.assertEqual((stats["c2s"]["dup_ack"], stats["s2c"]["dup_ack"]), (0, 0))
        self.assertEqual(stats["unknown"], 0)

    def test_report_json_has_no_direction_keys(self):
        res = analyzer.analyze(SAMPLE)
        self.assertTrue(res.get("ok"), res.get("error"))
        for block in ("meta", "metrics"):
            self.assertNotIn("dir", res[block], f"{block} 不许出现方向统计")
            bad = [k for k in res[block] if "c2s" in str(k).lower()
                   or "s2c" in str(k).lower()]
            self.assertEqual(bad, [], f"{block} 出现方向字段：{bad}")


@unittest.skipIf(NO_TSHARK, "没有 tshark，跳过现跑校验")
class TcpRetransmissionIntegrationTests(unittest.TestCase):
    """C1 集成断言：真实 ``tcp_retransmission`` 样本必须端到端产出 UP 行。

    样本由 ``scaffold/tests/fixtures/gen_pcap.py`` 在临时目录里现生成：
    生成器是纯标准库、确定性输出，sha256 与 ``captures/`` 外的样本一致，
    因此不需要把被 ``.gitignore`` 忽略的 ``*.pcap`` 提交进仓库。
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="netdiag_tcp_")
        cls.pcap = _generated_sample("tcp_retransmission", cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_collect_buckets_match_measured(self):
        """``tcp_retransmission.pcap`` 实测 c2s 6 / s2c 5（重测确认）。"""
        st, err = analyzer.collect(self.pcap)
        self.assertEqual(err, "")
        stats = st["dir"]
        self.assertEqual((stats["c2s"]["packets"], stats["s2c"]["packets"]), (6, 5))
        self.assertEqual(stats["c2s"]["retrans"], 1)
        self.assertEqual(stats["s2c"]["dup_ack"], 2)
        self.assertEqual(stats["unknown"], 0)

    def test_analyze_emits_up_finding(self):
        """真正的验收：分析结果里必须有「疑似上行丢包」且等级为「严重」。"""
        res = analyzer.analyze(str(self.pcap))
        self.assertTrue(res.get("ok"), res.get("error"))
        rows = [r for r in res["rows"]
                if r["category"] == "传输质量" and r["severity"] == "严重"]
        self.assertTrue(rows, "tcp_retransmission 必须产出严重级传输质量行")
        row = rows[0]
        self.assertIn("疑似上行丢包", row["finding"])
        self.assertIn("c2s 重传 1", row["finding"])
        self.assertEqual(row["severity"], "严重")


if __name__ == "__main__":
    unittest.main()
