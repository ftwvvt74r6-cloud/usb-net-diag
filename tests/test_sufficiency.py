"""证据充分性闸门（PR D 及审查修复）：没有可判定维度时，不许把「没样本」报成「正常」。

守的口径（不是某个具体 bug）：

* ``verdict.build()`` 在「抓到了包，但 TCP / DNS / HTTP / ICMP / ARP 五个维度
  全都凑不出一个可判定样本」时，``level`` 必须是「证据不足」，而不是「正常」。
* 闸门只看「每个维度有没有能支撑对应规则的样本」，不看「报文总数」——
  captures 里的 ``arp_no_reply`` 只有 5 个包却抓到了真故障，按总包数卡会把结论埋掉。
* ARP 维度按**同一目标**的最大请求次数（``meta.arp_req_max``）判：两个不同目标
  各 1 次（总数 2）时规则一条都判不出来，维度不成立。

审查修复补充的口径：

* 「证据不足」时 ``points`` 追加采集有效性点而不是覆盖——已成立的安全观察命中必须保留；
* ``flags.network_ok`` 在证据不足时是 ``None``（与空包分支一致），不是 ``True``；
* 证据不足的文案来自 ``core/copy/zh-CN.json``（copy 缺失时回退内联常量）；
* ``empty_capture`` 的期望值（expected.json）必须有人读。

纯函数用例不依赖 tshark，CI 干净环境也能跑完整套维度口径校验；
涉及 ``analyze()`` 现跑的用例在无 tshark 时跳过。
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import verdict                                        # noqa: E402
from core.analyzer import analyze                               # noqa: E402
from core.tshark import find_tshark                            # noqa: E402

DEMO = ROOT / "captures" / "faults_demo.pcap"
COPY_PATH = ROOT / "core" / "copy" / "zh-CN.json"
NO_TSHARK = find_tshark() is None


def _base_meta() -> dict:
    """一份「五个维度全无」的最小 meta；各用例只改自己关心的键。"""
    return {
        "packets": 3, "pcap_name": "synth.pcap",
        "tcp_packets": 0, "streams_total": 0,
        "dns_total": 0, "http_req": 0,
        "icmp_unreach": 0, "icmp_timeout": 0,
        "arp_req": 0, "arp_req_max": 0,
    }


def _verdict(meta: dict, rows: list[dict] | None = None) -> dict:
    return verdict.build({
        "meta": meta,
        "rows": rows or [],
        "metrics": {},
        "summary": {},
    })


def _copy_table() -> dict:
    return json.loads(COPY_PATH.read_text(encoding="utf-8"))


def _gen_module():
    """把 scaffold 里的确定性样本生成器加载成模块（不依赖包结构）。"""
    gen_path = ROOT / "scaffold" / "tests" / "fixtures" / "gen_pcap.py"
    spec = importlib.util.spec_from_file_location("gen_pcap_fixture", gen_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _gen_quiet(out_dir: Path, **kw) -> dict:
    """生成样本但吞掉 gen_pcap 的中文 stdout。

    为什么：generate() 会 ``print("3 包 …")``，Windows CI runner 的控制台编码是
    cp1252，中文「包」编码不进去 → UnicodeEncodeError（本地 UTF-8 控制台看不见
    这个坑，AGENTS.md §4.2 的「本地能跑 ≠ CI 能跑」）。redirect 到 StringIO
    绕过控制台编码，生成行为不变。
    """
    with contextlib.redirect_stdout(io.StringIO()):
        return _gen_module().generate(out_dir, **kw)


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
        # 一次只有 ICMP echo request 的抓包：echo 不产生故障行，也不构成 ICMP 维度
        # （规则只看错误报文）。构造「有包、但错误报文计数为 0」的 meta，
        # 断言五个维度计数确实全 0，且结论是证据不足 —— 而不是只复读空 meta。
        m = _base_meta()
        m["packets"] = 2
        m["icmp_unreach"] = 0
        m["icmp_timeout"] = 0
        v = _verdict(m)
        self.assertFalse(v["sufficiency"]["ok"])
        self.assertEqual(v["level"], "证据不足")
        args = v["sufficiency"]["reason_args"]["no_decidable_dimension"]
        self.assertEqual(args["icmp_err"], 0)
        self.assertEqual(args["tcp_packets"], 0)
        self.assertEqual(args["arp_req"], 0)

    def test_arp_dimension_needs_same_target_twice(self):
        # ARP 维度看「同一目标」的最大请求次数：总数 2 但分属两个目标时仍不成立。
        m = _base_meta(); m["arp_req"] = 1; m["arp_req_max"] = 1
        self.assertFalse(_verdict(m)["sufficiency"]["ok"])
        m["arp_req"] = 2; m["arp_req_max"] = 1       # 两个不同目标各 1 次
        self.assertFalse(_verdict(m)["sufficiency"]["ok"])
        m["arp_req_max"] = 2                          # 同一目标 2 次
        self.assertTrue(_verdict(m)["sufficiency"]["ok"])

    def test_meta_without_arp_keys_is_insufficient(self):
        # 旧版 analyze() 的结果没有 arp_req / arp_req_max 键：不许崩，
        # 缺键按 0 处理，方向偏向「证据不足」而不是「正常」。
        m = _base_meta()
        m.pop("arp_req")
        m.pop("arp_req_max")
        v = _verdict(m)
        self.assertFalse(v["sufficiency"]["ok"])
        self.assertEqual(v["level"], "证据不足")

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

    def test_insufficient_verdict_is_internally_consistent(self):
        # 审查阻塞 1：level / flags / next_steps 必须自洽 —— 证据不足时
        # network_ok 是 None（与空包分支一致），不是「bad 为空所以 True」。
        v = _verdict(_base_meta())
        self.assertEqual(v["level"], "证据不足")
        self.assertIsNone(v["flags"]["network_ok"])
        self.assertTrue(v["next_steps"], "处置建议必须是「怎么重新采样」")

    def test_empty_packet_branch_has_impact_and_none_flags(self):
        # 审查建议 11：空包早返回分支必须带 impact（docstring 承诺过）。
        v = verdict.build({"meta": {"packets": 0}, "rows": [], "metrics": {},
                           "summary": {}})
        self.assertEqual(v["level"], "警告")
        self.assertIn("impact", v)
        self.assertIsNone(v["flags"]["network_ok"])
        self.assertFalse(v["sufficiency"]["ok"])


class SufficiencySecurityTests(unittest.TestCase):
    """审查阻塞 2：只有安全观察命中时，命中必须留在 points 里。"""

    def test_security_finding_survives_insufficient(self):
        rows = [{"layer": "安全观察", "protocol": "TCP", "category": "可疑外联",
                 "finding": "外联 203.0.113.9:23", "severity": "警告",
                 "evidence": "帧 #1", "advice": "确认"}]
        v = _verdict(_base_meta(), rows)
        self.assertEqual(v["level"], "证据不足")
        cats = [p["category"] for p in v["points"]]
        self.assertIn("采集有效性", cats, "主结论必须是采集有效性")
        self.assertIn("可疑外联", cats, "已成立的安全命中不许被覆盖")
        self.assertFalse(v["flags"]["security_ok"])


class SufficiencyCopyTests(unittest.TestCase):
    """审查阻塞 3：copy 表是证据不足文案的唯一来源；缺失时回退内联常量。"""

    def test_steps_come_from_copy(self):
        c = _copy_table()
        v = _verdict(_base_meta())
        self.assertEqual(v["next_steps"],
                         [c["next_step"]["collect_longer"],
                          c["next_step"]["confirm_traffic_path"]])
        self.assertEqual(v["points"][0]["action"], c["next_step"]["collect_longer"])

    def test_proof_comes_from_copy_template(self):
        c = _copy_table()
        m = _base_meta(); m["arp_req"] = 1; m["arp_req_max"] = 1
        v = _verdict(m)
        tpl = c["insufficient"]["no_decidable_dimension"]
        args = v["sufficiency"]["reason_args"]["no_decidable_dimension"]
        self.assertEqual(v["points"][0]["proof"], tpl.format(**args))

    def test_copy_missing_falls_back_to_constants(self):
        with mock.patch.object(verdict, "_load_copy", return_value={}):
            v = _verdict(_base_meta())
        self.assertEqual(v["next_steps"], list(verdict.INSUFFICIENT_STEPS))
        self.assertIn("没有一个可判定的维度", v["points"][0]["proof"])

    def test_offline_steps_use_offline_copy(self):
        # 审查建议 12：离线（--pcap）场景没有网卡可换，第一条建议换离线版。
        c = _copy_table()
        m = _base_meta(); m["bpf"] = "离线分析"
        v = _verdict(m)
        self.assertEqual(v["next_steps"][0], c["next_step"]["collect_longer_offline"])
        self.assertEqual(v["sufficiency"]["needed"][0], "collect_longer_offline")


class EmptyCaptureManifestTests(unittest.TestCase):
    """审查建议 9：empty_capture 的期望值必须有人读（expected.json → 断言）。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        _gen_quiet(Path(cls.tmp.name), only=["empty_capture"], manifest=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_expected_json_declares_insufficient(self):
        doc = json.loads((Path(self.tmp.name) / "expected.json").read_text(encoding="utf-8"))
        case = next(c for c in doc["cases"] if c["file"] == "empty_capture.pcap")
        self.assertEqual(case["severity"], "insufficient")
        self.assertEqual(case["expect"]["rule_ids"], [])
        self.assertEqual(case["packets"], 3)

    def test_sample_file_exists(self):
        self.assertTrue((Path(self.tmp.name) / "empty_capture.pcap").is_file())


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

    def test_empty_capture_sample_is_insufficient(self):
        # 真实 pcap 侧的口径钉死：3 个包、五维度全不成立 → 证据不足。
        with tempfile.TemporaryDirectory() as td:
            _gen_quiet(Path(td), only=["empty_capture"], manifest=False)
            res = analyze(str(Path(td) / "empty_capture.pcap"))
            v = verdict.build(res)
            self.assertEqual(v["level"], "证据不足")
            self.assertFalse(v["sufficiency"]["ok"])
            self.assertIn("no_decidable_dimension", v["sufficiency"]["reasons"])


if __name__ == "__main__":
    unittest.main()
