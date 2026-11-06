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

第 2 轮审查修复补充的口径：

* 证据不足时**没有样本行的层**在 ``layers[]`` 里必须是 ``na``，不许是 ``ok``
  （有真实样本行、判定为正常的层仍保持 ``ok``）；
* AI 解读的 prompt 顶部必须带 ``level`` / ``headline`` / ``sufficiency``，
  不能只给模型 ``L2：ok`` 这种分层机器码（模型会据此写「网络正常」）；
* copy 用例的断言口径是「输出跟着 copy 表变」：patch 文案**来源**也要生效，
  否则把 ``_load_copy`` 改成 ``return {}`` 照样全绿（第 2 轮审查的证伪手法）；
* copy 表结构畸形（``next_step`` 是列表、模板不是字符串……）必须回退内联常量，
  不许把 ``AttributeError`` 抛给用户。

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
from core import ai as ai_mod                                    # noqa: E402
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


class InsufficientLayerTests(unittest.TestCase):
    """第 2 轮 F1：证据不足时没有样本的层必须 ``na``，渲染层不许再给 ✅ 正常。"""

    def _statuses(self, v: dict) -> dict:
        return {x["id"]: x["status"] for x in v["layers"]}

    def test_no_sample_layers_are_na_not_ok(self):
        # 审查给的五维度全不成立输入（rows 为空）：四层都没样本，谁都不许是 ok。
        v = _verdict(_base_meta())
        self.assertFalse(v["sufficiency"]["ok"])
        self.assertEqual(self._statuses(v),
                         {"L2": "na", "L3": "na", "L4": "na", "L7": "na"})

    def test_layer_with_test_row_keeps_ok(self):
        # 反向钉子：「有真实样本且判定为正常」的层仍保持 ok。
        # analyzer 契约里 "—" = 测了正常（见 analyzer.NEUTRAL_SEVERITY），不算没样本。
        rows = [{"layer": "L2 本地链路", "protocol": "ARP", "category": "本地可达性",
                 "finding": "构造：测了正常", "severity": "—",
                 "evidence": "—", "advice": "无需处理"}]
        v = _verdict(_base_meta(), rows)
        self.assertEqual(v["level"], "证据不足")        # 五维度仍然全不成立
        st = self._statuses(v)
        self.assertEqual(st["L2"], "ok", "有样本行（—=测了正常）的层应保持 ok")
        self.assertEqual(st["L3"], "na")
        self.assertEqual(st["L7"], "na")

    def test_neutral_fallback_rows_do_not_fake_samples(self):
        # empty_capture 的真实行形状：L3 那条「未收到 ICMP…三层转发正常」是
        # analyzer 无条件产出的兜底中性行（没有 ICMP/RTT 样本也写正常），
        # L4/L7 是 "na" 行。这些都不算样本：四层必须仍是 na，
        # 否则真实样本（empty_capture）渲染出来 L3 还是 ✅。
        rows = [
            {"layer": "L3 网络层", "protocol": "ICMP/IP", "category": "网络可达性",
             "finding": "未收到 ICMP 不可达/超时，三层转发正常", "severity": "—",
             "evidence": "—", "advice": "无需处理"},
            {"layer": "L4 传输层", "protocol": "TCP", "category": "连接建立",
             "finding": "未检测到 TCP 会话（抓包周期内无 TCP 流量）", "severity": "na",
             "evidence": "报文 3 个", "advice": "确认抓包网卡与过滤器是否选对"},
            {"layer": "L7 应用层", "protocol": "DNS", "category": "域名解析",
             "finding": "未检测到 DNS 报文", "severity": "na",
             "evidence": "—", "advice": "如需验证 DNS，可在体检页直接测域名解析耗时"},
        ]
        v = _verdict(_base_meta(), rows)
        self.assertEqual(v["level"], "证据不足")
        self.assertEqual(self._statuses(v),
                         {"L2": "na", "L3": "na", "L4": "na", "L7": "na"})

    def test_insufficient_markdown_has_no_ok_layers(self):
        # 直接钉渲染产物：结论是「证据不足」时，L2/L3/L7 不许出现 ✅ 正常。
        # report 用扁平导入（import verdict），所以 core/ 必须在 sys.path 上。
        core_dir = str(ROOT / "core")
        sys.path.insert(0, core_dir)
        try:
            import report
            md = report.render_markdown({"meta": _base_meta(), "rows": [],
                                         "metrics": {}, "summary": {}})
        finally:
            sys.path.remove(core_dir)
        table = [ln for ln in md.splitlines() if ln.startswith("| L")]
        self.assertEqual(len(table), 4, "分层定位表应有四层")
        for ln in table:
            with self.subTest(line=ln):
                self.assertNotIn("✅", ln, f"证据不足时这一层不许显示正常：{ln}")
                self.assertIn("无样本", ln)


class AiPromptSyncTests(unittest.TestCase):
    """第 2 轮 F2：AI 解读 prompt 顶部必须带规则引擎结论，不能只给分层机器码。"""

    def _prompt(self, v: dict) -> str:
        res = {"meta": {}, "rows": [], "metrics": {}, "verdict": v}
        return ai_mod.build_messages(res)[1]["content"]

    def test_prompt_top_carries_level_and_headline(self):
        v = _verdict(_base_meta())
        p = self._prompt(v)
        self.assertIn(v["level"], p)
        self.assertIn(v["headline"], p)
        # 必须排在分层指标之前：模型先读到结论，才不会被 L2：ok 带偏。
        self.assertLess(p.index(v["headline"]), p.index("【分层指标】"))

    def test_prompt_flags_insufficient_sufficiency(self):
        p = self._prompt(_verdict(_base_meta()))
        self.assertIn("证据充分性：不足", p)
        self.assertIn("禁止输出「网络正常」", p)

    def test_prompt_says_sufficient_when_ok(self):
        m = _base_meta(); m["dns_total"] = 1
        p = self._prompt(_verdict(m))
        self.assertIn("证据充分性：充分", p)


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

    def test_output_follows_monkeypatched_copy_table(self):
        """第 2 轮 F3a：把 ``_load_copy`` 换成自定义表，用户可见文案必须跟着变。

        断言口径是「输出跟着 copy 表变」，不是「内联常量与 copy 逐字相等」——
        后者在「copy 断开、回退内联」时照样成立（第 2 轮审查证伪手法）。
        """
        custom = {
            "next_step": {"collect_longer": "自定义：加长抓包",
                          "confirm_traffic_path": "自定义：确认路径"},
            "insufficient": {"no_decidable_dimension": "自定义证词：报文 {packets} 个"},
        }
        with mock.patch.object(verdict, "_load_copy", return_value=custom):
            v = _verdict(_base_meta())
        self.assertEqual(v["next_steps"],
                         ["自定义：加长抓包", "自定义：确认路径"])
        self.assertEqual(v["points"][0]["action"], "自定义：加长抓包")
        self.assertEqual(v["points"][0]["proof"], "自定义证词：报文 3 个")

    def test_copy_source_disconnect_turns_red(self):
        """第 2 轮 F3a 的反向钉子：patch 文案**来源**也必须生效。

        为什么不能只 patch ``verdict._load_copy``：那证明不了它真的去读了 copy ——
        把 ``_load_copy`` 改成 ``return {}`` 时，那条用例照样 PASS（内联回退与
        copy 表逐字相同，正是第 2 轮审查的证伪手法）。从来源打补丁，
        「断开 copy」这个变异才会真的变红。
        """
        custom = {
            "next_step": {"collect_longer": "来源级自定义一",
                          "confirm_traffic_path": "来源级自定义二"},
            "insufficient": {"no_decidable_dimension": "来源级证词：{packets}"},
        }
        with mock.patch("core.config.load_copy", return_value=custom):
            v = _verdict(_base_meta())
        self.assertEqual(v["next_steps"], ["来源级自定义一", "来源级自定义二"])
        self.assertEqual(v["points"][0]["proof"], "来源级证词：3")

    def test_malformed_copy_falls_back_without_crash(self):
        """第 2 轮 F3b：copy 表结构畸形时必须回退内联常量，不许抛异常。

        这些是本 PR 新增的崩溃路径（以前 copy 无人消费）：
        ``{"next_step": []}`` → ``'list' object has no attribute 'get'``；
        ``{"insufficient": {"no_decidable_dimension": {...}}}`` →
        ``'dict' object has no attribute 'format'``。
        """
        bad_tables = (
            {"next_step": []},
            {"insufficient": {"no_decidable_dimension": {"packets": 3}}},
            {"next_step": {"collect_longer": 123}},
            [],
        )
        for bad in bad_tables:
            with self.subTest(bad=bad), \
                    mock.patch("core.config.load_copy", return_value=bad):
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
            # 第 2 轮 F1：没有样本的层在渲染层不许再是 ✅（L3 的兜底中性行不算样本）。
            self.assertEqual({x["id"]: x["status"] for x in v["layers"]},
                             {"L2": "na", "L3": "na", "L4": "na", "L7": "na"})


if __name__ == "__main__":
    unittest.main()
