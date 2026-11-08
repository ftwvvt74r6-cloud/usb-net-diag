"""D 批次：影子探测（Shadow Probing）的验收测试（V2~V8 + F1）。

覆盖口径（与 D-SPEC §4 对应）：

* **V2 探针可识别**：``exclusion_bpf()`` / ``exclusion_display_filter()`` 由账本
  生成（纯函数）；空账本返回空串；ICMP 固定 id、TCP/UDP 固定端口段的字符串钉死。
* **V3 调度生命周期**：首轮立即发、按轮数封顶、``stop()+join(3)`` 能退出；发送器
  异常只记 ``error``；离线/被动路径不构造探针（离线用 mock 断言 ``capture_live``
  没被调用，被动用源码静态断言）。
* **V4 探针隔离**：scapy 造「业务 + 探针」pcap，带显示过滤分析的统计与纯净业务
  pcap 逐字段相同，不带过滤时统计不同（证明测试本身有效）；另用 tshark 统计
  探针报文数，验证「已排除 N 包」的取数口。
* **V5 记录与统计**：按 role 聚合出 sent/recv/loss/n/RTT/抖动；没有 RTT 样本
  必须 ``n=0`` 且 ``rtt_* is None``（不是 0.0）。
* **V6 报告区块**：有基线才出现「探针基线」；0 样本写「未探到」；无基线输出与
  原实现逐字节一致（同输入两次渲染 + verdict 序列化比对）。
* **V7 方向对照**：有基线 + 方向类 finding 才产出 ``probe_contrast``，
  confidence < 1.0，渲染文案含「疑似」；无基线时 verdict 里没有该键。
* **V8 UI 开关**：live/scan 显示、默认勾选、payload 带 ``shadow``；passive/offline
  不显示；结果页有探针区块的接线。

依赖真 tshark / scapy 的用例全部 ``skipUnless``：CI 没有它们时必须 skip 而不是红。
"""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import analyzer  # noqa: E402
import diagnose  # noqa: E402
import pathprobe  # noqa: E402
import report  # noqa: E402
import server  # noqa: E402
import tshark  # noqa: E402
import verdict  # noqa: E402

HTML = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
COPY = json.loads((ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8"))

#: 探针固定标记（测试里直接用字面量，防止常量被改坏后测试跟着一起错）。
PROBE_ID = 0x4E44
PORT_LOW, PORT_HIGH = 39000, 39999

#: 文档示例地址（RFC 5737），仓库里不出现真实 IP。
GW = "192.0.2.1"
TARGET = "198.51.100.20"


def _spec(kind=pathprobe.ProbeKind.ICMP, target=GW, role="gateway", port=None):
    """造一个单包探针规格（测试辅助）。"""
    return pathprobe.ProbeSpec(kind, target, port=port, samples=1, timeout_s=0.1,
                               interval_s=5.0, role=role)


def _record(spec, seq=1, rtt=1.0, responded=True, responder="", error=""):
    """造一条探针记录（测试辅助）。"""
    return pathprobe.ProbeRecord(spec=spec, sent_monotonic=1.0, sent_epoch=2.0,
                                 rtt_ms=rtt, responded=responded,
                                 responder=responder, error=error, seq=seq)


def _ledger(*records) -> pathprobe.ProbeLedger:
    """按记录造账本（测试辅助）。"""
    return pathprobe.ProbeLedger(records=list(records), started_epoch=1.0,
                                 finished_epoch=2.0)


def _tshark_ready() -> bool:
    """本机是否有可用的 tshark（CI 没有 → 真抓包/真过滤用例 skip）。"""
    try:
        return tshark.find_tshark() is not None
    except Exception:                                  # noqa: BLE001
        return False


HAVE_SCAPY = importlib.util.find_spec("scapy") is not None
HAVE_TSHARK = _tshark_ready()


# ---------------------------------------------------------------- V2 过滤串


class ProbeFilterTest(unittest.TestCase):
    """探针可识别 + 两种排除表达式（账本 → 字符串，纯函数）。"""

    def test_empty_ledger_returns_empty_strings(self):
        ledger = pathprobe.ProbeLedger()
        self.assertEqual(ledger.exclusion_bpf(), "")
        self.assertEqual(ledger.exclusion_display_filter(), "")
        self.assertEqual(ledger.baseline()["probe_count"], 0)
        self.assertEqual(ledger.baseline()["roles"], [])

    def test_icmp_bpf_uses_fixed_id_and_both_types(self):
        ledger = _ledger(_record(_spec(pathprobe.ProbeKind.ICMP)))
        expression = ledger.exclusion_bpf()
        self.assertIn("icmp[icmptype] == 8", expression)
        self.assertIn("icmp[icmptype] == 0", expression)
        self.assertIn("icmp[4:2] == 0x4e44", expression)
        self.assertTrue(expression.startswith("not ("),
                        "ICMP 排除式必须以 not 开头，否则会把探针自己抓进去")

    def test_tcp_bpf_covers_both_source_and_destination_port(self):
        ledger = _ledger(_record(_spec(pathprobe.ProbeKind.TCP_SYN, TARGET,
                                       role="target", port=443)))
        expression = ledger.exclusion_bpf()
        self.assertIn(
            "not (tcp src portrange 39000-39999 or tcp dst portrange 39000-39999)",
            expression)
        self.assertNotIn("udp", expression)

    def test_udp_bpf_covers_both_source_and_destination_port(self):
        ledger = _ledger(_record(_spec(pathprobe.ProbeKind.UDP, TARGET,
                                       role="dns", port=53)))
        expression = ledger.exclusion_bpf()
        self.assertIn(
            "not (udp src portrange 39000-39999 or udp dst portrange 39000-39999)",
            expression)
        self.assertNotIn("tcp", expression)

    def test_all_kinds_joined_with_and(self):
        ledger = _ledger(
            _record(_spec(pathprobe.ProbeKind.ICMP)),
            _record(_spec(pathprobe.ProbeKind.TCP_SYN, TARGET, role="target", port=443)),
            _record(_spec(pathprobe.ProbeKind.UDP, TARGET, role="dns", port=53)),
        )
        expression = ledger.exclusion_bpf()
        # 4 个片段（ICMP 请求 + ICMP 回复 + TCP + UDP）→ 3 个 " and " 连接符
        self.assertEqual(expression.count(") and not ("), 3)
        for part in ("icmp[icmptype]", "tcp src portrange", "udp src portrange"):
            self.assertIn(part, expression)

    def test_display_filter_uses_icmp_ident_and_port_ranges(self):
        ledger = _ledger(
            _record(_spec(pathprobe.ProbeKind.ICMP)),
            _record(_spec(pathprobe.ProbeKind.TCP_SYN, TARGET, role="target", port=443)),
        )
        expression = ledger.exclusion_display_filter()
        self.assertIn("icmp.type == 8", expression)
        self.assertIn("icmp.ident == 0x4e44", expression)
        self.assertIn("tcp.srcport >= 39000", expression)
        self.assertIn("tcp.dstport <= 39999", expression)

    def test_marker_filter_only_matches_probe_packets(self):
        expression = pathprobe.probe_marker_display_filter(
            [pathprobe.ProbeKind.ICMP, pathprobe.ProbeKind.TCP_SYN])
        self.assertIn("icmp.ident == 0x4e44", expression)
        self.assertIn("tcp.dstport >= 39000", expression)
        self.assertNotIn("udp", expression)

    def test_ignore_icmp_false_keeps_only_port_rules(self):
        ledger = _ledger(_record(_spec(pathprobe.ProbeKind.ICMP)),
                         _record(_spec(pathprobe.ProbeKind.TCP_SYN, TARGET,
                                       role="target", port=443)))
        self.assertNotIn("icmp", ledger.exclusion_bpf(ignore_icmp=False).lower())
        self.assertIn("tcp", ledger.exclusion_bpf(ignore_icmp=False))

    def test_baseline_records_filters_for_reproduction(self):
        payload = _ledger(_record(_spec(pathprobe.ProbeKind.ICMP))).to_dict()
        self.assertEqual(payload["probe_count"], 1)
        self.assertEqual(payload["kinds"], ["icmp"])
        self.assertIn("icmp[icmptype]", payload["exclusion_bpf"])
        self.assertIn("icmp.ident", payload["exclusion_display_filter"])
        self.assertEqual(len(payload["records"]), 1)
        record = payload["records"][0]
        for key in ("spec", "sent_monotonic", "sent_epoch", "rtt_ms",
                    "responded", "responder", "error", "seq"):
            self.assertIn(key, record)


# ---------------------------------------------------------------- V5 聚合


class ProbeAggregateTest(unittest.TestCase):
    """按 role 聚合：sent / recv / loss / RTT / 抖动；无样本必须 n=0。"""

    def test_rtt_stats_and_loss(self):
        gateway = _spec(pathprobe.ProbeKind.ICMP)
        ledger = _ledger(
            _record(gateway, seq=1, rtt=10.0, responder=GW),
            _record(gateway, seq=2, rtt=20.0, responder=GW),
        )
        roles = ledger.baseline()["roles"]
        self.assertEqual(len(roles), 1)
        item = roles[0]
        self.assertEqual((item["role"], item["kind"], item["target"]),
                         ("gateway", "icmp", GW))
        self.assertEqual((item["sent"], item["recv"], item["n"]), (2, 2, 2))
        self.assertEqual(item["loss_pct"], 0.0)
        self.assertEqual((item["rtt_min_ms"], item["rtt_avg_ms"], item["rtt_max_ms"]),
                         (10.0, 15.0, 20.0))
        self.assertEqual(item["jitter_ms"], 5.0)

    def test_no_rtt_samples_are_none_not_zero(self):
        spec = _spec(pathprobe.ProbeKind.TCP_SYN, TARGET, role="target", port=443)
        ledger = _ledger(_record(spec, rtt=None, responded=False, error="timeout"))
        item = ledger.baseline()["roles"][0]
        self.assertEqual(item["n"], 0)
        self.assertIsNone(item["rtt_min_ms"])
        self.assertIsNone(item["rtt_avg_ms"])
        self.assertIsNone(item["rtt_max_ms"])
        self.assertIsNone(item["jitter_ms"])
        self.assertEqual(item["loss_pct"], 100.0)
        self.assertEqual(item["errors"], ["timeout"])

    def test_roles_sorted_gateway_dns_target(self):
        ledger = _ledger(
            _record(_spec(pathprobe.ProbeKind.TCP_SYN, TARGET, role="target", port=443)),
            _record(_spec(pathprobe.ProbeKind.UDP, "192.0.2.53", role="dns", port=53)),
            _record(_spec(pathprobe.ProbeKind.ICMP, GW, role="gateway")),
        )
        roles = ledger.baseline()["roles"]
        self.assertEqual([item["role"] for item in roles],
                         ["gateway", "dns", "target"])
        self.assertEqual(ledger.baseline()["sent"], 3)
        self.assertEqual(ledger.baseline()["recv"], 3)

    def test_responded_without_rtt_counts_as_recv_but_not_rtt_sample(self):
        """UDP 收到 ICMP port-unreachable = 通（有响应但不产生 RTT 样本）。"""
        spec = _spec(pathprobe.ProbeKind.UDP, "192.0.2.53", role="dns", port=53)
        ledger = _ledger(_record(spec, rtt=None, responded=True,
                                 error="icmp_port_unreachable"))
        item = ledger.baseline()["roles"][0]
        self.assertEqual((item["sent"], item["recv"], item["n"]), (1, 1, 0))
        self.assertEqual(item["loss_pct"], 0.0)
        self.assertIsNone(item["rtt_avg_ms"])


# ---------------------------------------------------------------- V3 生命周期


class ProbeLifecycleTest(unittest.TestCase):
    """首轮立即发、轮数封顶、stop/join 3s 内退出、异常只降级。"""

    def test_first_round_is_immediate(self):
        calls: list[int] = []

        def sender(spec, seq):
            calls.append(seq)
            return True, 1.0, spec.target, ""

        prober = pathprobe.ShadowProber(
            [_spec()], interval_s=5.0, max_rounds=3, sender=sender)
        self.addCleanup(prober.stop)
        prober.start()
        deadline = time.time() + 2.0
        while prober.sent_count < 1 and time.time() < deadline:
            time.sleep(0.01)
        self.assertGreaterEqual(prober.sent_count, 1,
                                "首轮必须在 start() 后立刻发出，不能等 5 秒")
        self.assertEqual(calls, [1], "第一轮只发 1 包/目标")
        prober.stop()
        self.assertTrue(prober.join(3.0))

    def test_max_rounds_caps_packet_count(self):
        prober = pathprobe.ShadowProber(
            [_spec()], interval_s=0.01, max_rounds=2,
            sender=lambda spec, seq: (True, 1.0, spec.target, ""))
        prober.start()
        self.assertTrue(prober.join(5.0))
        self.assertEqual(prober.sent_count, 2, "轮数封顶后不再发")

    def test_stop_and_join_within_three_seconds(self):
        def slow_sender(spec, seq):
            time.sleep(0.2)
            return True, 1.0, spec.target, ""

        prober = pathprobe.ShadowProber(
            [_spec()], interval_s=0.05, max_rounds=50, sender=slow_sender)
        prober.start()
        time.sleep(0.05)
        prober.stop()
        started = time.time()
        self.assertTrue(prober.join(3.0), "抓包结束后探针线程必须 3s 内退出")
        self.assertLess(time.time() - started, 3.0)

    def test_sender_exception_is_recorded_not_raised(self):
        def boom(spec, seq):
            raise RuntimeError("raw socket denied")

        prober = pathprobe.ShadowProber(
            [_spec()], interval_s=0.01, max_rounds=1, sender=boom)
        records = prober.run_round()
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0].responded)
        self.assertIsNone(records[0].rtt_ms)
        self.assertIn("raw socket denied", records[0].error)
        self.assertEqual(prober.ledger.baseline()["probe_count"], 1)

    def test_packet_bound_for_max_duration(self):
        """duration≤180 → 每目标 ≤38 包（5s 一轮，首轮立即）。"""
        rounds = pathprobe.rounds_for(180)
        self.assertLessEqual(rounds, 38, "单目标包数上限 38")
        self.assertEqual(rounds, 37)
        specs = pathprobe.shadow_specs({"gateway": GW, "vdi": TARGET})
        self.assertEqual(len(specs), 2, "每个目标每轮只发 1 包（不是 samples 包）")
        self.assertTrue(all(spec.samples == 1 for spec in specs))

    def test_offline_path_never_calls_capture_live(self):
        """离线分析（--pcap）不构造探针：capture_live 一次都不许被调用。"""
        ok_result = {"ok": True, "meta": {"packets": 1}, "rows": [],
                     "metrics": {},
                     "summary": {"critical_count": 0, "warning_count": 0,
                                 "target": "全网", "pcap_file": "x"}}
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "x.pcap"
            pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
            with mock.patch.object(diagnose, "capture_live") as capture, \
                    mock.patch.object(diagnose.analyzer, "analyze",
                                      return_value=copy.deepcopy(ok_result)), \
                    mock.patch.object(diagnose.report, "save",
                                      return_value={"markdown": "m", "json": "j"}), \
                    mock.patch.object(diagnose.logstore, "record_run"), \
                    mock.patch.object(diagnose, "REPORTS", Path(tmp)):
                result = diagnose.run_scan(pcap=str(pcap), logger=lambda _m: None,
                                           shadow=True)
        self.assertTrue(result.get("ok"))
        self.assertEqual(capture.call_count, 0,
                         "离线分析绝不允许启动探针（用户可能只是分析别人的 pcap）")
        self.assertNotIn("probe_baseline", result["meta"])

    def test_shadow_false_does_not_construct_prober(self):
        result = diagnose.capture_live(
            target="8.8.8.8", duration=3, logger=lambda _m: None, shadow=False)
        # 环境没有 tshark/Npcap 时会在更早的入口返回；这里只守「没造探针」。
        self.assertNotIn("probe", result)
        with mock.patch.object(diagnose, "_shadow_prober_for") as factory:
            diagnose.capture_live(target="8.8.8.8", duration=3,
                                  logger=lambda _m: None, shadow=False)
        self.assertEqual(factory.call_count, 0,
                         "shadow=False 时不许构造影子探针")

    def test_passive_module_never_imports_pathprobe(self):
        """被动监听「只听不发」是产品承诺：源码里不许出现探针调用。"""
        source = (ROOT / "core" / "passive.py").read_text(encoding="utf-8")
        for needle in ("pathprobe", "send_probe", "ShadowProber"):
            self.assertNotIn(needle, source)


# ---------------------------------------------------------------- V4 隔离


@unittest.skipUnless(HAVE_SCAPY and HAVE_TSHARK,
                     "需要 scapy + tshark 才能造/读 pcap")
class ProbeIsolationSyntheticTest(unittest.TestCase):
    """合成 pcap 隔离证明：带过滤 == 纯净业务；不带过滤 != 纯净业务。"""

    #: 业务统计里要求「逐字段相同」的键（不含时长/路径/生成时间这类元信息）。
    STAT_KEYS = (
        "packets", "tcp_packets", "tcp_data_packets", "streams_total",
        "retrans", "dup_ack", "ooo", "rst", "syn", "synack",
        "dns_total", "dns_resp", "icmp_unreach", "icmp_timeout", "arp_no_reply",
    )

    @classmethod
    def setUpClass(cls):
        """用 scapy 造纯净业务 pcap 与「业务 + 探针」pcap（各写一次）。"""
        from scapy.all import (DNS, DNSQR, ICMP, IP, Raw, TCP, UDP, wrpcap)

        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        business = [
            IP(src="192.0.2.10", dst=TARGET) / TCP(sport=50000, dport=443,
                                                  flags="S", seq=100),
            IP(src=TARGET, dst="192.0.2.10") / TCP(sport=443, dport=50000,
                                                  flags="SA", seq=900, ack=101),
            IP(src="192.0.2.10", dst=TARGET) / TCP(sport=50000, dport=443,
                                                  flags="A", seq=101, ack=901),
            IP(src="192.0.2.10", dst=TARGET) / TCP(sport=50000, dport=443,
                                                  flags="PA", seq=101, ack=901)
            / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            IP(src=TARGET, dst="192.0.2.10") / TCP(sport=443, dport=50000,
                                                  flags="PA", seq=901, ack=140)
            / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        ]
        probes = [
            # ICMP 请求 + 回复：固定 id 0x4E44
            IP(src="192.0.2.10", dst=GW) / ICMP(type=8, id=PROBE_ID, seq=1)
            / Raw(pathprobe.PROBE_PAYLOAD),
            IP(src=GW, dst="192.0.2.10") / ICMP(type=0, id=PROBE_ID, seq=1)
            / Raw(pathprobe.PROBE_PAYLOAD),
            # TCP 探针：源端口在固定段；回复的「目的端口」也在段内（只排源端口会漏）
            IP(src="192.0.2.10", dst=TARGET) / TCP(sport=39001, dport=443,
                                                  flags="S", seq=7),
            IP(src=TARGET, dst="192.0.2.10") / TCP(sport=443, dport=39001,
                                                  flags="SA", seq=8, ack=8),
            # UDP DNS 探针：请求 + 响应
            IP(src="192.0.2.10", dst="192.0.2.53") / UDP(sport=39002, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="netdiag-probe.example")),
            IP(src="192.0.2.53", dst="192.0.2.10") / UDP(sport=53, dport=39002)
            / DNS(id=0, qr=1, qd=DNSQR(qname="netdiag-probe.example")),
        ]
        cls.business_pcap = base / "business.pcap"
        cls.probed_pcap = base / "probed.pcap"
        wrpcap(str(cls.business_pcap), business)
        wrpcap(str(cls.probed_pcap), business + probes)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _stats(self, result: dict) -> dict:
        """抽出要求逐字段比较的业务统计。"""
        return {key: result["meta"][key] for key in self.STAT_KEYS}

    def test_filtered_stats_equal_pure_business(self):
        filtered = analyzer.analyze(
            self.probed_pcap,
            display_filter=pathprobe.exclusion_display_filter(
                [pathprobe.ProbeKind.ICMP, pathprobe.ProbeKind.TCP_SYN,
                 pathprobe.ProbeKind.UDP]))
        pure = analyzer.analyze(self.business_pcap)
        self.assertTrue(filtered.get("ok"), filtered.get("error"))
        self.assertEqual(self._stats(filtered), self._stats(pure),
                         "带隔离过滤的业务统计必须与纯净业务 pcap 逐字段相同")
        self.assertEqual(verdict.build(filtered)["level"],
                         verdict.build(pure)["level"])

    def test_without_filter_stats_differ(self):
        """证明上一条不是因为「探针包本来就数不出来」：不过滤时统计确实变了。"""
        raw = analyzer.analyze(self.probed_pcap)
        pure = analyzer.analyze(self.business_pcap)
        self.assertGreater(raw["meta"]["packets"], pure["meta"]["packets"])
        self.assertNotEqual(self._stats(raw), self._stats(pure))

    def test_count_marked_packets_reports_probe_packets(self):
        """「已排除 N 个探针包」的取数口：合成 pcap 里 6 个探针包都能数出来。"""
        count = pathprobe.count_marked_packets(
            tshark.find_tshark(), self.probed_pcap,
            [pathprobe.ProbeKind.ICMP, pathprobe.ProbeKind.TCP_SYN,
             pathprobe.ProbeKind.UDP])
        self.assertEqual(count, 6)
        self.assertEqual(pathprobe.count_marked_packets(
            tshark.find_tshark(), self.business_pcap,
            [pathprobe.ProbeKind.ICMP, pathprobe.ProbeKind.TCP_SYN,
             pathprobe.ProbeKind.UDP]), 0)


# ---------------------------------------------------------------- V6/V7 报告与判定


def _baseline(gateway_loss=0.0, gateway_recv=2, gateway_n=2,
              target_loss=100.0, target_recv=0, target_n=0,
              excluded=4) -> dict:
    """造一份探针基线（文档示例地址；不出现真实 IP）。"""
    return {
        "probe_count": 3,
        "sent": 3,
        "recv": gateway_recv + target_recv,
        "window": {"started_epoch": 1.0, "finished_epoch": 2.0},
        "excluded_packets": excluded,
        "roles": [
            {"role": "gateway", "kind": "icmp", "target": GW,
             "sent": 2, "recv": gateway_recv, "loss_pct": gateway_loss, "n": gateway_n,
             "rtt_min_ms": 1.0 if gateway_n else None,
             "rtt_avg_ms": 1.5 if gateway_n else None,
             "rtt_max_ms": 2.0 if gateway_n else None,
             "jitter_ms": 0.5 if gateway_n else None, "errors": []},
            {"role": "target", "kind": "tcp_syn", "target": TARGET,
             "sent": 1, "recv": target_recv, "loss_pct": target_loss, "n": target_n,
             "rtt_min_ms": 9.0 if target_n else None,
             "rtt_avg_ms": 9.0 if target_n else None,
             "rtt_max_ms": 9.0 if target_n else None,
             "jitter_ms": 0.0 if target_n else None,
             "errors": [] if target_n else ["timeout"]},
        ],
    }


def _transport_row() -> dict:
    """方向类 finding（传输质量 / 严重），用于触发两侧对照。"""
    return {
        "layer": "L4 传输层｜TCP", "protocol": "TCP", "category": "传输质量",
        "finding": "TCP 重传率 5.00%（25/500 个报文）",
        "severity": "严重", "evidence": "Stream 0 重传 25 次",
        "advice": "查网线与交换机端口",
    }


def _result(baseline: dict | None = None, transport: bool = False) -> dict:
    """最小可渲染结果：可选探针基线、可选方向类 finding。"""
    meta = {
        "pcap_file": "captures/faults_demo.pcap", "pcap_name": "faults_demo.pcap",
        "packets": 100, "bytes": 2000, "duration": 5.0, "tcp_packets": 50,
        "tcp_data_packets": 20, "streams_total": 3, "interface": "WLAN",
        "bpf": "", "generated_at": "", "tshark_path": "",
    }
    if baseline is not None:
        meta["probe_baseline"] = baseline
    return {
        "ok": True, "meta": meta, "metrics": {"retrans_rate": 5.0},
        "rows": [_transport_row()] if transport else [],
        "summary": {"target": "全网", "critical_count": 1 if transport else 0,
                    "warning_count": 0, "pcap_file": "captures/faults_demo.pcap"},
    }


class ProbeReportTest(unittest.TestCase):
    """V6：报告「探针基线」区块（有数据才出现；0 样本写「未探到」）。"""

    def test_block_renders_roles_and_excluded_count(self):
        result = _result(_baseline())
        md = report.render_markdown(result, verdict.build(result))
        self.assertIn("探针基线", md)
        self.assertIn("网关", md)
        self.assertIn("对端目标", md)
        self.assertIn(GW, md)
        self.assertIn(TARGET, md)
        self.assertIn("已从业务统计排除（4 包）", md)
        self.assertIn("1.0/1.5/2.0 ms", md)

    def test_zero_samples_show_not_probed_not_zero_ms(self):
        result = _result(_baseline())
        md = report.render_markdown(result, verdict.build(result))
        self.assertIn("未探到", md)
        self.assertNotIn("0/0/0 ms", md)
        self.assertNotIn("0ms", md.split("探针基线", 1)[1],
                         "0 样本不许显示 0ms（没有样本 ≠ 很快）")

    def test_no_baseline_has_no_block(self):
        result = _result(None)
        md = report.render_markdown(result, verdict.build(result))
        self.assertNotIn("探针基线", md)
        self.assertNotIn("未探到", md)

    def test_no_baseline_render_and_verdict_are_byte_identical(self):
        """无探针数据时：verdict 无新键、render 输出逐字节不变。"""
        first = _result(None, transport=True)
        second = copy.deepcopy(first)
        vd_first = verdict.build(first)
        vd_second = verdict.build(second)
        self.assertNotIn("probe_contrast", vd_first)
        self.assertEqual(json.dumps(vd_first, ensure_ascii=False, sort_keys=True),
                         json.dumps(vd_second, ensure_ascii=False, sort_keys=True))
        self.assertEqual(report.render_markdown(first, vd_first),
                         report.render_markdown(second, vd_second))


class ProbeContrastTest(unittest.TestCase):
    """V7：方向对照（两侧基线 + 方向类 finding），措辞「疑似」、confidence < 1。"""

    def _verdict(self, baseline, transport=True):
        return verdict.build(_result(baseline, transport=transport))

    def test_local_side_when_gateway_loses_more(self):
        vd = self._verdict(_baseline(gateway_loss=40.0, gateway_recv=1, gateway_n=2,
                                     target_loss=0.0, target_recv=1, target_n=1))
        contrast = vd["probe_contrast"]
        self.assertEqual(contrast["code"], "PROBE.CONTRAST.LOCAL_SIDE")
        self.assertLess(contrast["confidence"], 1.0)
        md = report.render_markdown(_result(_baseline(
            gateway_loss=40.0, gateway_recv=1, gateway_n=2,
            target_loss=0.0, target_recv=1, target_n=1), transport=True), vd)
        self.assertIn("疑似", md)
        self.assertIn("本地侧", md)

    def test_target_side_when_target_loses_more(self):
        baseline = _baseline(gateway_loss=0.0, gateway_recv=2, gateway_n=2,
                             target_loss=40.0, target_recv=1, target_n=1)
        vd = self._verdict(baseline)
        self.assertEqual(vd["probe_contrast"]["code"],
                         "PROBE.CONTRAST.TARGET_SIDE")
        self.assertLess(vd["probe_contrast"]["confidence"], 1.0)
        md = report.render_markdown(_result(baseline, transport=True), vd)
        self.assertIn("疑似", md)
        self.assertIn("对端侧", md)

    def test_insufficient_when_one_side_has_no_rtt(self):
        vd = self._verdict(_baseline(gateway_n=0, gateway_recv=0,
                                     target_n=0, target_recv=0))
        self.assertEqual(vd["probe_contrast"]["code"],
                         "PROBE.CONTRAST.INSUFFICIENT")
        self.assertLess(vd["probe_contrast"]["confidence"], 1.0)

    def test_no_contrast_without_direction_finding(self):
        vd = self._verdict(_baseline(), transport=False)
        self.assertNotIn("probe_contrast", vd)

    def test_no_contrast_without_baseline(self):
        vd = self._verdict(None, transport=True)
        self.assertNotIn("probe_contrast", vd)


# ---------------------------------------------------------------- F1


class DegradedModeTest(unittest.TestCase):
    """F1：``render_degraded`` 的模式行——非空且 ≠「全网」才算单目标诊断。"""

    @staticmethod
    def _res(target: str) -> dict:
        return {
            "ok": True, "degraded": True, "card_title": "未捕获业务报文",
            "plain": "抓包窗口内没有会话。",
            "capture": {"target": target, "interface": "WLAN", "duration": 20,
                        "bpf": ""},
            "link": {"via": "gateway", "host": GW, "avg_ms": 1.0,
                     "jitter_ms": 0.1, "loss_pct": 0.0},
            "reasons": [], "next_steps": [], "at": "2026-01-01 00:00:00",
        }

    def test_empty_target_is_all_network(self):
        self.assertIn("模式：全网体检", report.render_degraded(self._res("")))

    def test_all_network_text_is_not_single_target(self):
        text = report.render_degraded(self._res("全网"))
        self.assertIn("模式：全网体检", text)
        self.assertNotIn("模式：单目标诊断", text)

    def test_concrete_target_is_single_target(self):
        self.assertIn("模式：单目标诊断",
                      report.render_degraded(self._res("10.255.255.1")))


# ---------------------------------------------------------------- V8 API/UI


class ShadowApiTest(unittest.TestCase):
    """服务端 ``/api/scan`` 的 ``shadow`` 加法字段（旧载荷默认开）。"""

    def _start(self, payload: dict):
        """跑一次 ``start_job``，返回传给 worker 线程的 shadow 值。"""
        saved = dict(server.JOB)
        saved_logs = list(server.JOB["logs"])
        try:
            with mock.patch.object(server, "_worker") as worker, \
                    mock.patch.object(server.threading, "Thread") as thread, \
                    mock.patch.object(server, "log"), \
                    mock.patch.object(server.logstore, "diag_log"):
                thread.return_value.start.return_value = None
                result = server.start_job(dict(payload))
            self.assertTrue(result.get("ok"), result)
            return thread.call_args.kwargs.get("kwargs", {}).get("shadow")
        finally:
            server.JOB.clear()
            server.JOB.update(saved)
            server.JOB["logs"] = saved_logs

    def test_old_payload_without_shadow_defaults_true(self):
        self.assertIs(self._start({"mode": "live", "target": "example.com",
                                   "duration": 5}), True)

    def test_explicit_shadow_false(self):
        self.assertIs(self._start({"mode": "live", "duration": 5,
                                   "shadow": False}), False)

    def test_string_false_is_still_false(self):
        self.assertIs(self._start({"mode": "scan", "duration": 5,
                                   "shadow": "false"}), False)

    def test_offline_payload_ignores_shadow(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "x.pcap"
            pcap.write_bytes(b"\x0a\x0d\x0d\x0a")
            saved_captures = server.CAPTURES
            try:
                server.CAPTURES = Path(tmp)
                shadow = self._start({"mode": "offline", "pcap": "x.pcap"})
            finally:
                server.CAPTURES = saved_captures
        self.assertIs(shadow, True)  # 字段照传，但离线路径不会用它

    def test_to_bool_parsing(self):
        for value, expected in ((None, True), (True, True), (False, False),
                                ("0", False), ("off", False), ("yes", True),
                                (1, True), ("garbage", True)):
            with self.subTest(value=value):
                self.assertIs(server._to_bool(value, True), expected)


class ShadowUiTest(unittest.TestCase):
    """V8：live/scan 显示开关（默认勾选）、payload 带 shadow、结果页有区块。"""

    CONFIG_RE = __import__("re").compile(
        r'<script type="application/json" id="ui-config">(.*?)</script>', __import__("re").S)

    def _config(self) -> dict:
        match = self.CONFIG_RE.search(HTML)
        self.assertIsNotNone(match, "ui/index.html 缺少 ui-config")
        return json.loads(match.group(1))

    def test_shadow_flag_only_on_realtime_modes(self):
        modes = self._config()["modes"]
        self.assertTrue(modes["scan"].get("shadow"))
        self.assertTrue(modes["live"].get("shadow"))
        self.assertFalse(modes["passive"].get("shadow", False))
        self.assertFalse(modes["offline"].get("shadow", False))

    def test_checkbox_exists_and_default_checked(self):
        self.assertIn('id="shadow-toggle"', HTML)
        block = HTML.split('id="shadow-toggle"', 1)[1].split("</label>", 1)[0]
        self.assertIn("checked", block, "探针开关默认必须勾选（SPEC：默认开）")

    def test_shadow_field_hidden_by_mode_config(self):
        self.assertIn('id="field-shadow"', HTML)
        self.assertIn(
            '$("#field-shadow").classList.toggle("hidden", !cfg.shadow)', HTML)

    def test_payload_carries_shadow(self):
        start = HTML.index("async function startCapture()")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn("payload.shadow", body)
        self.assertIn("cfg.shadow", body)

    def test_result_page_renders_probe_block(self):
        start = HTML.index("function render(res, actions)")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn("renderProbeBaseline", body)
        self.assertIn("probe_baseline", body)

    def test_probe_ui_copy_comes_from_copy_table(self):
        """探针区块的中文不写死在页面里，由后端 copy 表下发。"""
        probe_copy = COPY["probe"]
        for key in ("ui_title", "ui_hint", "excluded", "th_role", "role_gateway",
                    "contrast_local_side", "contrast_target_side",
                    "contrast_insufficient"):
            with self.subTest(key=key):
                self.assertIn(key, probe_copy)
        start = HTML.index("function renderProbeBaseline(pb, copy, contrast)")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn("copy.ui_title", body)
        self.assertIn("copy.excluded", body)
        for hardcoded in ("未探到", "已从业务统计排除", "疑似"):
            self.assertNotIn(hardcoded, body,
                             "探针区块的文案必须来自 copy 表，不能在页面里写死")


if __name__ == "__main__":
    unittest.main(verbosity=2)
