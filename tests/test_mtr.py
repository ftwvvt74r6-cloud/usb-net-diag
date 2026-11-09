"""D+ 增量 2：MTR 逐跳（V6~V10）+ DNS 角色补全（V5 遗留）的验收测试。

覆盖口径（与 ``D-SPEC`` §4-B 对应）：

* **V6 逐跳数据**：TTL 1..max_hops 递增、按批发送、到目标即停；每跳
  ``sent/lost/loss_pct/rtt_min·avg·max/jitter/rtt_n/status``；参数安全夹取；
  ``to_dict()`` 可 JSON。
* **V7 劣化判定**：``first_degraded_hop`` / ``degraded_hops`` / ``summarize_path``
  是纯函数；丢包（≥20%）与 RTT 突增（≥基线 3 倍且 +50ms）两条判据；无样本必须是
  ``PATH.NO_DATA``（证据不足）而不是 ``PATH.OK``。
* **V8 ICMP 降级**：ICMP 全丢但目标端口 TCP 可达 → 自动改用 TCP SYN 逐跳重扫，
  ``icmp_filtered=True`` / ``method="tcp"``；TCP 也不可达 → ``NO_DATA`` + 不可达。
* **V9 与抓包并存**：``capture_live(shadow=True)`` 在有目标时启动 MTR 后台线程，
  BPF 合并两种探针标记；无目标不跑；线程失败/取消只降级，不改变抓包结果。
* **V10 报告区块**：有 ``meta.path_profile`` 才出现「路径剖面」；无数据时输出
  逐字节不变（20 产物红线）；探测方式 / 劣化跳 / TUN 提示 / 未完成标注齐全。
* **隔离（硬性）**：MTR 探针标记进 BPF；ICMP time-exceeded 无法按 id 认领 →
  显示过滤追加 ``not (icmp.type == 11)``，并用 ``count_time_exceeded_packets``
  统计「被排除的路径探测相关 ICMP 数」。合成 pcap 证明带过滤 == 纯净业务。
* **DNS 角色**：``winapi.dns_servers()`` 读注册表（不解析 CLI 文本）、失败返回
  ``()``；环回 DNS 优雅跳过；``shadow_specs`` 出现 DNS/UDP 角色。

依赖真 scapy / tshark 的用例全部 ``skipUnless``：CI 没有它们时必须 skip 而不是红。
"""
from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "core"))

import analyzer  # noqa: E402
import diagnose  # noqa: E402
import pathprobe  # noqa: E402
import report  # noqa: E402
import server  # noqa: E402
import tshark  # noqa: E402
import verdict  # noqa: E402
import _uisrc  # noqa: E402
from core.platform import winapi  # noqa: E402

HTML = _uisrc.html()
COPY = json.loads((ROOT / "core" / "copy" / "zh-CN.json").read_text(encoding="utf-8"))

#: 文档示例地址（RFC 5737），仓库里不出现真实 IP。
GW = "192.0.2.1"
ROUTER = "192.0.2.2"
TARGET = "198.51.100.20"


def _row(ttl, responded=True, rtt=None, responder=GW):
    """造一条原始采样记录（测试辅助）。"""
    return {"ttl": ttl, "seq": ttl, "responded": responded, "rtt_ms": rtt,
            "responder": responder if responded else "",
            "error": "" if responded else "timeout"}


def _hop(ttl, ip="", sent=3, lost=0, rtts=None):
    """造一条逐跳统计（测试辅助）；状态与 ``build_hop_stats`` 的新口径一致。"""
    rtts = list(rtts or [])
    lost = int(lost)
    if lost == sent and sent:
        status = pathprobe.HopStatus.LOSS
    elif sent and lost / sent * 100.0 >= pathprobe.PATH_LOSS_DEGRADED_PCT:
        status = pathprobe.HopStatus.DEGRADED
    else:
        status = pathprobe.HopStatus.OK
    if not rtts:
        return pathprobe.HopStat(ttl=ttl, ip=ip, sent=sent, lost=lost,
                                 status=status)
    avg = sum(rtts) / len(rtts)
    jitter = (sum((value - avg) ** 2 for value in rtts) / len(rtts)) ** 0.5
    return pathprobe.HopStat(
        ttl=ttl, ip=ip, sent=sent, lost=lost,
        rtt_min_ms=round(min(rtts), 1), rtt_avg_ms=round(avg, 1),
        rtt_max_ms=round(max(rtts), 1), jitter_ms=round(jitter, 1),
        rtt_n=len(rtts), status=status)


def _profile(**overrides) -> dict:
    """造一份 ``meta.path_profile``：R5 的典型「中间跳限速、目标正常」场景。"""
    profile = {
        "target": "example.com", "target_ip": TARGET,
        "verdict_key": pathprobe.PATH_OK, "degraded_ttl": None,
        "baseline_ms": 1.0, "icmp_filtered": False,
        "target_port_reachable": True, "method": "icmp",
        "reached_target": True, "completed": True, "tun_suspected": False,
        "unreachable": False, "max_hops": 16, "samples": 3, "timeout_s": 0.8,
        "probes_sent": 12, "error": "", "excluded_icmp": 6,
        "middle_loss_suspected": True, "middle_loss_ttls": [2, 3],
        "hops": [
            {"ttl": 1, "ip": GW, "sent": 3, "lost": 0, "loss_pct": 0.0,
             "rtt_min_ms": 0.5, "rtt_avg_ms": 1.0, "rtt_max_ms": 1.5,
             "jitter_ms": 0.4, "rtt_n": 3, "status": "ok"},
            {"ttl": 2, "ip": "", "sent": 3, "lost": 3, "loss_pct": 100.0,
             "rtt_min_ms": None, "rtt_avg_ms": None, "rtt_max_ms": None,
             "jitter_ms": None, "rtt_n": 0, "status": "loss"},
            {"ttl": 3, "ip": "", "sent": 3, "lost": 3, "loss_pct": 100.0,
             "rtt_min_ms": None, "rtt_avg_ms": None, "rtt_max_ms": None,
             "jitter_ms": None, "rtt_n": 0, "status": "loss"},
            {"ttl": 4, "ip": TARGET, "sent": 3, "lost": 0, "loss_pct": 0.0,
             "rtt_min_ms": 8.0, "rtt_avg_ms": 9.0, "rtt_max_ms": 10.0,
             "jitter_ms": 0.8, "rtt_n": 3, "status": "ok"},
        ],
    }
    profile.update(overrides)
    return profile


def _degraded_profile(**overrides) -> dict:
    """造一份「劣化持续到目标」的路径剖面（R5）：第 2 跳起持续丢包，目标也丢。"""
    profile = _profile(
        verdict_key=pathprobe.PATH_TRANSPORT_NET, degraded_ttl=2,
        middle_loss_suspected=False, middle_loss_ttls=[],
        hops=[
            {"ttl": 1, "ip": GW, "sent": 3, "lost": 0, "loss_pct": 0.0,
             "rtt_min_ms": 0.5, "rtt_avg_ms": 1.0, "rtt_max_ms": 1.5,
             "jitter_ms": 0.4, "rtt_n": 3, "status": "ok"},
            {"ttl": 2, "ip": ROUTER, "sent": 3, "lost": 2, "loss_pct": 66.7,
             "rtt_min_ms": None, "rtt_avg_ms": None, "rtt_max_ms": None,
             "jitter_ms": None, "rtt_n": 0, "status": "degraded"},
            {"ttl": 3, "ip": ROUTER, "sent": 3, "lost": 2, "loss_pct": 66.7,
             "rtt_min_ms": 5.0, "rtt_avg_ms": 5.0, "rtt_max_ms": 5.0,
             "jitter_ms": 0.0, "rtt_n": 1, "status": "degraded"},
            {"ttl": 4, "ip": TARGET, "sent": 3, "lost": 1, "loss_pct": 33.3,
             "rtt_min_ms": 8.0, "rtt_avg_ms": 9.0, "rtt_max_ms": 10.0,
             "jitter_ms": 0.8, "rtt_n": 2, "status": "degraded"},
        ])
    profile.update(overrides)
    return profile


def _result(path_profile: dict | None = None) -> dict:
    """最小可渲染结果：可选路径剖面。"""
    meta = {
        "pcap_file": "captures/faults_demo.pcap", "pcap_name": "faults_demo.pcap",
        "packets": 100, "bytes": 2000, "duration": 5.0, "tcp_packets": 50,
        "tcp_data_packets": 20, "streams_total": 3, "interface": "WLAN",
        "bpf": "", "generated_at": "", "tshark_path": "",
    }
    if path_profile is not None:
        meta["path_profile"] = path_profile
    return {
        "ok": True, "meta": meta, "metrics": {"retrans_rate": 0.0},
        "rows": [], "summary": {"target": "全网", "critical_count": 0,
                                "warning_count": 0,
                                "pcap_file": "captures/faults_demo.pcap"},
    }


def _tshark_ready() -> bool:
    """本机是否有可用的 tshark（CI 没有 → 真过滤用例 skip）。"""
    try:
        return tshark.find_tshark() is not None
    except Exception:                                  # noqa: BLE001
        return False


HAVE_SCAPY = importlib.util.find_spec("scapy") is not None
HAVE_TSHARK = _tshark_ready()


# ---------------------------------------------------------------- V6 参数 / 聚合


class PathOptionClampTest(unittest.TestCase):
    """参数安全夹取：max_hops 1..32、samples 1..10、timeout 0.2..3.0。"""

    def test_defaults(self):
        self.assertEqual(pathprobe.clamp_path_options(), (16, 5, 1.0))

    def test_upper_bounds(self):
        self.assertEqual(pathprobe.clamp_path_options(999, 99, 99.0), (32, 10, 3.0))

    def test_lower_bounds(self):
        self.assertEqual(pathprobe.clamp_path_options(0, 0, 0.0), (1, 1, 0.2))

    def test_dirty_values_fall_back_to_defaults(self):
        self.assertEqual(pathprobe.clamp_path_options(None, "x", object()),
                         (16, 5, 1.0))


class HopStatsTest(unittest.TestCase):
    """原始采样 → 逐跳统计（min/avg/max/jitter/loss；无样本不许用 0.0 冒充）。"""

    def test_aggregates_min_avg_max_and_jitter(self):
        hops = pathprobe.build_hop_stats([
            _row(1, rtt=10.0), _row(1, rtt=20.0), _row(1, rtt=30.0),
        ])
        self.assertEqual(len(hops), 1)
        hop = hops[0]
        self.assertEqual((hop.ttl, hop.sent, hop.lost, hop.rtt_n), (1, 3, 0, 3))
        self.assertEqual((hop.rtt_min_ms, hop.rtt_avg_ms, hop.rtt_max_ms),
                         (10.0, 20.0, 30.0))
        self.assertEqual(hop.jitter_ms, 8.2)          # 总体标准差
        self.assertEqual(hop.loss_pct, 0.0)
        self.assertIs(hop.status, pathprobe.HopStatus.OK)

    def test_loss_and_no_rtt_samples_are_none_not_zero(self):
        hops = pathprobe.build_hop_stats([
            _row(2, responded=False), _row(2, responded=False), _row(2, responded=False),
        ])
        hop = hops[0]
        self.assertEqual((hop.sent, hop.lost, hop.rtt_n), (3, 3, 0))
        self.assertEqual(hop.loss_pct, 100.0)
        self.assertIsNone(hop.rtt_min_ms)
        self.assertIsNone(hop.rtt_avg_ms)
        self.assertIsNone(hop.rtt_max_ms)
        self.assertIsNone(hop.jitter_ms)
        self.assertIs(hop.status, pathprobe.HopStatus.LOSS)

    def test_partial_loss_keeps_rtt_of_responded_samples(self):
        hops = pathprobe.build_hop_stats([
            _row(1, rtt=4.0), _row(1, responded=False),
        ])
        hop = hops[0]
        self.assertEqual((hop.lost, hop.loss_pct, hop.rtt_n), (1, 50.0, 1))
        self.assertEqual(hop.rtt_avg_ms, 4.0)

    def test_partial_loss_status_is_degraded_not_ok(self):
        """R6：50% 丢包的跳必须显示「劣化」，不能显示「正常」。"""
        hop = pathprobe.build_hop_stats([
            _row(1, rtt=4.0), _row(1, responded=False),
        ])[0]
        self.assertIs(hop.status, pathprobe.HopStatus.DEGRADED)
        profile = _profile(verdict_key=pathprobe.PATH_TRANSPORT_NET,
                           degraded_ttl=1, hops=[hop.to_dict()])
        md = report.render_markdown(_result(profile))
        row = next(line for line in md.splitlines() if line.startswith("| 1 |"))
        self.assertIn("劣化", row)
        self.assertNotIn("正常", row, "丢包 ≥ 阈值的跳不能显示成正常")

    def test_rtt_spike_status_is_degraded_not_ok(self):
        """R6：RTT 突增的跳也不能显示「正常」（与劣化判定同源）。"""
        hops = pathprobe.build_hop_stats([_row(1, rtt=10.0), _row(2, rtt=60.0)])
        self.assertIs(hops[0].status, pathprobe.HopStatus.OK)
        self.assertIs(hops[1].status, pathprobe.HopStatus.DEGRADED)
        self.assertEqual(pathprobe.degraded_hops(hops), (2,))

    def test_ordered_by_ttl_and_ip_from_responder(self):
        hops = pathprobe.build_hop_stats([
            _row(3, rtt=1.0, responder=TARGET),
            _row(1, responded=False),
            _row(2, rtt=2.0, responder=ROUTER),
        ])
        self.assertEqual([hop.ttl for hop in hops], [1, 2, 3])
        self.assertEqual(hops[1].ip, ROUTER)
        self.assertEqual(hops[2].ip, TARGET)

    def test_to_dict_is_json_serializable(self):
        payload = pathprobe.PathProbeResult(
            target="example.com", target_ip=TARGET,
            hops=pathprobe.build_hop_stats([_row(1, rtt=1.0)]),
            verdict_key=pathprobe.PATH_OK, method="tcp", icmp_filtered=True,
            degraded_ttl=None, baseline_ms=1.0, reached_target=True,
            max_hops=16, samples=3, timeout_s=0.8, probes_sent=3).to_dict()
        text = json.dumps(payload, ensure_ascii=False)
        restored = json.loads(text)
        self.assertEqual(restored["hops"][0]["rtt_avg_ms"], 1.0)
        self.assertEqual(restored["method"], "tcp")
        for key in ("ttl", "ip", "sent", "lost", "loss_pct", "rtt_min_ms",
                    "rtt_avg_ms", "rtt_max_ms", "jitter_ms", "rtt_n", "status"):
            self.assertIn(key, restored["hops"][0])


# ---------------------------------------------------------------- V7 劣化判定


class DegradationTest(unittest.TestCase):
    """劣化判定是纯函数：丢包阈值、RTT 突增阈值、无样本三态。"""

    def test_loss_threshold_boundary(self):
        # 19.9% 不算，20.0% 算（阈值 20%，边界含等号）。
        below = pathprobe.build_hop_stats([_row(1, rtt=1.0)] * 20
                                          + [_row(1, responded=False)])
        at = pathprobe.build_hop_stats([_row(1, rtt=1.0)] * 4
                                       + [_row(1, responded=False)])
        self.assertEqual(below[0].loss_pct, 4.8)
        self.assertIsNone(pathprobe.first_degraded_hop(below))
        self.assertEqual(at[0].loss_pct, 20.0)
        self.assertEqual(pathprobe.first_degraded_hop(at), 1)

    def test_rtt_spike_needs_both_factor_and_delta(self):
        # 基线 10ms：30ms = 3 倍但只 +20ms → 不算；60ms = 6 倍且 +50ms → 算。
        small = [_hop(1, rtts=[10.0]), _hop(2, rtts=[30.0])]
        big = [_hop(1, rtts=[10.0]), _hop(2, rtts=[60.0])]
        self.assertIsNone(pathprobe.first_degraded_hop(small))
        self.assertEqual(pathprobe.first_degraded_hop(big), 2)

    def test_first_responding_hop_is_baseline_not_spike(self):
        # 第一跳自己不能当突增（否则每个路径都「第 1 跳劣化」）；
        # 基线 500ms 时必须 ≥ 1500ms 且 +50ms 才算突增。
        hops = [_hop(1, rtts=[500.0]), _hop(2, rtts=[900.0])]
        self.assertEqual(pathprobe.degraded_hops(hops), ())
        hops = [_hop(1, rtts=[500.0]), _hop(2, rtts=[1600.0])]
        self.assertEqual(pathprobe.degraded_hops(hops), (2,))

    def test_first_degraded_hop_returns_first_ttl(self):
        hops = [_hop(1, rtts=[1.0]), _hop(2, rtts=[1.0], sent=4, lost=2),
                _hop(3, rtts=[1.0], sent=4, lost=3)]
        self.assertEqual(pathprobe.first_degraded_hop(hops), 2)
        self.assertEqual(pathprobe.degraded_hops(hops), (2, 3))

    def test_middle_hop_loss_with_healthy_target_is_ok_not_degraded(self):
        """R5 核心：中间跳 100% 不回 ICMP、目标正常 → 不能判承载网/第 2 跳劣化。

        这是企业网里路由器对 TTL 回复限速的典型形态；旧口径「任意跳丢包 ≥ 20%
        即劣化」会误报 PATH.TRANSPORT_NET。这里同时钉住判定、字段与状态三件事。
        """
        hops = [_hop(1, ip=GW, rtts=[1.0]),
                _hop(2, sent=3, lost=3),
                _hop(3, sent=3, lost=3),
                _hop(4, ip=TARGET, rtts=[9.0])]
        summary = pathprobe.summarize_path(hops, target_ip=TARGET)
        self.assertEqual(summary["verdict_key"], pathprobe.PATH_OK)
        self.assertIsNone(summary["degraded_ttl"])
        self.assertTrue(summary["middle_loss_suspected"])
        self.assertEqual(summary["middle_loss_ttls"], [2, 3])
        self.assertTrue(summary["reached_target"])
        self.assertEqual(pathprobe.degraded_hops(hops), ())
        self.assertIsNone(pathprobe.first_degraded_hop(hops))

        stats = pathprobe.build_hop_stats([
            _row(1, rtt=1.0, responder=GW),
            _row(2, responded=False), _row(2, responded=False),
            _row(2, responded=False),
            _row(3, responded=False), _row(3, responded=False),
            _row(3, responded=False),
            _row(4, rtt=9.0, responder=TARGET),
        ], target_ip=TARGET)
        self.assertIs(stats[1].status, pathprobe.HopStatus.LOSS)
        self.assertIs(stats[2].status, pathprobe.HopStatus.LOSS)
        self.assertIs(stats[3].status, pathprobe.HopStatus.OK)

    def test_middle_loss_persisting_to_target_is_transport_net(self):
        """R5：从第 2 跳开始的丢包持续到目标（目标自身也丢）→ 仍判劣化。"""
        hops = [_hop(1, ip=GW, rtts=[1.0]),
                _hop(2, sent=3, lost=3),
                _hop(3, sent=3, lost=3),
                _hop(4, ip=TARGET, sent=3, lost=1, rtts=[5.0])]
        summary = pathprobe.summarize_path(hops, target_ip=TARGET)
        self.assertEqual(summary["verdict_key"], pathprobe.PATH_TRANSPORT_NET)
        self.assertEqual(summary["degraded_ttl"], 2,
                         "连续劣化段的第一跳是 2，不是目标跳 4")
        self.assertFalse(summary["middle_loss_suspected"])
        self.assertEqual(summary["middle_loss_ttls"], [])
        self.assertEqual(pathprobe.degraded_hops(hops), (2, 3, 4))

    def test_target_hop_loss_alone_is_server_edge(self):
        """R5：只有目标跳自身丢包 ≥ 阈值 → 对端侧（保持既有判定）。"""
        hops = [_hop(1, ip=GW, rtts=[1.0]),
                _hop(2, ip=ROUTER, rtts=[2.0]),
                _hop(3, ip=TARGET, sent=4, lost=2, rtts=[9.0, 9.0])]
        summary = pathprobe.summarize_path(hops, target_ip=TARGET)
        self.assertEqual(summary["verdict_key"], pathprobe.PATH_SERVER_EDGE)
        self.assertEqual(summary["degraded_ttl"], 3)
        self.assertEqual(summary["middle_loss_ttls"], [])

    def test_single_hop_behaviour_unchanged(self):
        """单跳（目标 = 第 1 跳）：正常仍 OK；丢包仍第 1 跳劣化（本地出口）。"""
        healthy = pathprobe.summarize_path(
            [_hop(1, ip=TARGET, rtts=[1.0])], target_ip=TARGET)
        self.assertEqual(healthy["verdict_key"], pathprobe.PATH_OK)
        self.assertIsNone(healthy["degraded_ttl"])
        self.assertFalse(healthy["middle_loss_suspected"])

        lossy = pathprobe.summarize_path(
            [_hop(1, ip=TARGET, sent=3, lost=1)], target_ip=TARGET)
        self.assertEqual(lossy["verdict_key"], pathprobe.PATH_LOCAL_SIDE)
        self.assertEqual(lossy["degraded_ttl"], 1)

    def test_all_hops_lost_is_no_data_not_ok(self):
        """全丢不是「正常」；没有 TCP 可达证据时也不能冒充 ICMP 被过滤。"""
        summary = pathprobe.summarize_path(
            [_hop(1, sent=3, lost=3), _hop(2, sent=3, lost=3)],
            target_ip=TARGET)
        self.assertEqual(summary["verdict_key"], pathprobe.PATH_NO_DATA)
        self.assertIsNone(summary["degraded_ttl"])
        self.assertFalse(summary["middle_loss_suspected"])
        self.assertFalse(summary["unreachable"])

    def test_target_unreachable_tail_loss_keeps_existing_verdict(self):
        """目标没探到、路径末尾持续不回包 → 不能因为更早的跳正常就判 PATH.OK。"""
        summary = pathprobe.summarize_path(
            [_hop(1, ip=GW, rtts=[1.0]), _hop(2, sent=3, lost=3)],
            target_ip=TARGET)
        self.assertEqual(summary["verdict_key"], pathprobe.PATH_SERVER_EDGE)
        self.assertEqual(summary["degraded_ttl"], 2)
        self.assertFalse(summary["reached_target"])

    def test_no_samples_is_no_data_not_ok(self):
        self.assertEqual(pathprobe.summarize_path(())["verdict_key"],
                         pathprobe.PATH_NO_DATA)
        empty = [pathprobe.HopStat(ttl=1, sent=0, lost=0)]
        summary = pathprobe.summarize_path(empty)
        self.assertEqual(summary["verdict_key"], pathprobe.PATH_NO_DATA)
        self.assertIsNone(summary["degraded_ttl"])

    def test_verdict_keys_for_each_side(self):
        ok = pathprobe.summarize_path([_hop(1, rtts=[1.0]), _hop(2, rtts=[2.0])],
                                      target_ip=TARGET)
        self.assertEqual(ok["verdict_key"], pathprobe.PATH_OK)
        local = pathprobe.summarize_path([_hop(1, sent=3, lost=1),
                                          _hop(2, sent=3, lost=1)])
        self.assertEqual(local["verdict_key"], pathprobe.PATH_LOCAL_SIDE)
        transport = pathprobe.summarize_path([_hop(1, rtts=[1.0]),
                                              _hop(2, sent=3, lost=1),
                                              _hop(3, sent=3, lost=1)])
        self.assertEqual(transport["verdict_key"], pathprobe.PATH_TRANSPORT_NET)
        server_edge = pathprobe.summarize_path([_hop(1, rtts=[1.0]),
                                                _hop(2, sent=3, lost=1)])
        self.assertEqual(server_edge["verdict_key"], pathprobe.PATH_SERVER_EDGE)

    def test_icmp_filtered_only_when_tcp_reachable(self):
        all_lost = [_hop(1, sent=3, lost=3), _hop(2, sent=3, lost=3)]
        self.assertEqual(
            pathprobe.summarize_path(all_lost, True)["verdict_key"],
            pathprobe.PATH_ICMP_FILTERED)
        self.assertTrue(pathprobe.summarize_path(all_lost, True)["icmp_filtered"])
        unreachable = pathprobe.summarize_path(all_lost, False)
        self.assertEqual(unreachable["verdict_key"], pathprobe.PATH_NO_DATA)
        self.assertTrue(unreachable["unreachable"])

    def test_tun_suspected_signals(self):
        # 唯一可靠证据是 198.18.0.0/15（mihomo/Clash 的 fake-ip 段）：
        # 目标命中、或任一有响应的跳命中。
        self.assertTrue(pathprobe.looks_like_tun([_hop(1, rtts=[1.0])], "198.18.0.2"))
        self.assertTrue(pathprobe.looks_like_tun(
            [_hop(1, ip="198.18.0.7", rtts=[1.0])], TARGET))

        # 回归锚点（变异锚点）：on-link 物理网关只有 1 跳响应，但它是正常直连，
        # 不是 TUN。旧规则「有响应的最大 TTL ≤ 2 ⇒ True」在这里会返回 True；
        # 谁把旧启发式改回来，下面的 False 断言必红。
        gateway = [_hop(1, ip=GW, sent=2, rtts=[1.0, 1.0])]
        self.assertTrue(max(hop.ttl for hop in gateway) <= 2,
                        "变异锚点失效：这个用例必须能区分新旧规则")
        self.assertFalse(pathprobe.looks_like_tun(gateway, GW))

        # 1 跳响应但响应方未知（ip 为空）→ 证据不足，不提示。
        self.assertFalse(pathprobe.looks_like_tun([_hop(1, rtts=[1.0])], TARGET))

        # 普通 3 跳公网：目标与响应方都不在基准段 → 不提示。
        three = [_hop(1, ip=GW, rtts=[1.0]), _hop(2, ip=ROUTER, rtts=[2.0]),
                 _hop(3, ip=TARGET, rtts=[3.0])]
        self.assertFalse(pathprobe.looks_like_tun(three, TARGET))

        # 全丢包是「没数据」，不是「只探到 1~2 跳」；没有响应就不算证据，
        # 即使构造出的 hop ip 落在基准段也不算。
        self.assertFalse(pathprobe.looks_like_tun([_hop(1, sent=3, lost=3)], TARGET))
        self.assertFalse(pathprobe.looks_like_tun(
            [_hop(1, ip="198.18.0.9", sent=3, lost=3)], TARGET))


# ---------------------------------------------------------------- V6/V8 run()


class RunIcmpTest(unittest.TestCase):
    """``run()`` 的 TTL 递增 / 批量 / 到目标即停 / 取消 / 参数夹取（注入发送器）。"""

    @staticmethod
    def _sender(target_ttl=None):
        """造一个假发送器：记录请求的 TTL，可选在某一跳到达目标。"""
        calls = []

        def sender(ip, method, probes, timeout_s, port):
            calls.append({"method": method,
                          "ttls": [p["ttl"] for p in probes],
                          "port": port})
            rows = []
            for probe in probes:
                ttl = probe["ttl"]
                if target_ttl is not None and ttl >= target_ttl:
                    rows.append(_row(ttl, rtt=9.0, responder=ip))
                elif ttl >= 2:
                    rows.append(_row(ttl, rtt=2.0, responder=ROUTER))
                else:
                    rows.append(_row(ttl, rtt=1.0, responder=GW))
            return rows

        sender.calls = calls
        return sender

    def _run(self, sender, **kwargs):
        kwargs.setdefault("max_hops", 8)
        kwargs.setdefault("samples", 2)
        kwargs.setdefault("timeout_s", 0.2)
        return pathprobe.run(TARGET, sender=sender,
                             tcp_checker=lambda *_a: False, **kwargs)

    def test_ttl_increments_across_batches(self):
        sender = self._sender()
        result = self._run(sender)
        self.assertEqual([hop.ttl for hop in result.hops], [1, 2, 3, 4, 5, 6, 7, 8])
        requested = [ttl for call in sender.calls for ttl in call["ttls"]]
        self.assertEqual(sorted(requested), sorted([ttl for ttl in range(1, 9)
                                                    for _ in range(2)]))
        self.assertEqual(len(sender.calls), 2, "8 跳应按每批 4 跳分两批发")

    def test_stops_at_target_and_truncates_extra_ttls(self):
        sender = self._sender(target_ttl=3)
        result = self._run(sender)
        self.assertTrue(result.reached_target)
        self.assertEqual([hop.ttl for hop in result.hops], [1, 2, 3],
                         "目标之后的 TTL 不能重复算成多跳")
        self.assertEqual(result.verdict_key, pathprobe.PATH_OK)

    def test_middle_hop_timeouts_with_healthy_target_are_ok_end_to_end(self):
        """R5：run() 全链路 —— 第 2/3 跳 100% 不回但目标正常 → PATH.OK。"""
        def sender(ip, method, probes, timeout_s, port):
            rows = []
            for probe in probes:
                ttl = probe["ttl"]
                if ttl == 1:
                    rows.append(_row(ttl, rtt=1.0, responder=GW))
                elif ttl >= 4:
                    rows.append(_row(ttl, rtt=9.0, responder=ip))
                else:
                    rows.append(_row(ttl, responded=False))
            return rows

        result = pathprobe.run(TARGET, port=443, max_hops=8, samples=2,
                               timeout_s=0.2, sender=sender,
                               tcp_checker=lambda *_a: False)
        self.assertTrue(result.reached_target)
        self.assertEqual(result.verdict_key, pathprobe.PATH_OK)
        self.assertIsNone(result.degraded_ttl)
        self.assertTrue(result.middle_loss_suspected)
        self.assertEqual(result.middle_loss_ttls, (2, 3))
        self.assertEqual([hop.status for hop in result.hops],
                         [pathprobe.HopStatus.OK, pathprobe.HopStatus.LOSS,
                          pathprobe.HopStatus.LOSS, pathprobe.HopStatus.OK])

        payload = result.to_dict()
        self.assertTrue(payload["middle_loss_suspected"])
        self.assertEqual(payload["middle_loss_ttls"], [2, 3])
        md = report.render_markdown(_result(payload))
        self.assertIn("中间跳（第 2、3 跳）未响应或丢包", md)
        self.assertIn("疑似 ICMP 限速/策略过滤", md)
        self.assertIn("不能据此判承载网故障", md)
        self.assertIn("整条路径未观察到劣化", md)
        self.assertNotIn("问题更像在承载网", md)
        self.assertNotIn("第 2 跳开始劣化", md)

    def test_partial_middle_loss_with_healthy_target_is_rate_limited(self):
        """R5：中间跳 50% 丢包但目标正常 → 状态「疑似限速」，不是「劣化」。"""
        def sender(ip, method, probes, timeout_s, port):
            rows = []
            for index, probe in enumerate(probes):
                ttl = probe["ttl"]
                if ttl == 1:
                    rows.append(_row(ttl, rtt=1.0, responder=GW))
                elif ttl == 2:
                    rows.append(_row(ttl, responded=(index % 2 == 0),
                                     rtt=1.0, responder=GW))
                else:
                    rows.append(_row(ttl, rtt=9.0, responder=ip))
            return rows

        result = pathprobe.run(TARGET, port=443, max_hops=8, samples=2,
                               timeout_s=0.2, sender=sender,
                               tcp_checker=lambda *_a: False)
        self.assertEqual(result.verdict_key, pathprobe.PATH_OK)
        self.assertIsNone(result.degraded_ttl)
        self.assertTrue(result.middle_loss_suspected)
        self.assertEqual(result.middle_loss_ttls, (2,))
        partial = result.hops[1]
        self.assertEqual(partial.loss_pct, 50.0)
        self.assertIs(partial.status, pathprobe.HopStatus.RATE_LIMITED)
        self.assertIsNot(partial.status, pathprobe.HopStatus.DEGRADED)

        md = report.render_markdown(_result(result.to_dict()))
        row = next(line for line in md.splitlines() if line.startswith("| 2 |"))
        self.assertIn("疑似限速", row)
        self.assertNotIn("劣化", row)
        self.assertIn("中间跳（第 2 跳）", md)

    def test_probes_sent_counts_actual_packets_not_truncated_rows(self):
        """R4：probes_sent 数实际发出的包，不数截断后的 hops 行。"""
        sender = self._sender(target_ttl=1)
        result = self._run(sender)
        self.assertEqual([hop.ttl for hop in result.hops], [1])
        # 第一批 4 个 TTL × 2 个样本 = 8 包；到目标即停，但后面的 TTL 也已发出。
        self.assertEqual(len(sender.calls[0]["ttls"]), 8)
        self.assertEqual(result.probes_sent, 8)
        self.assertEqual(result.ledger["probes_sent"], 8)

    def test_cancel_returns_partial_and_not_completed(self):
        sender = self._sender()
        result = pathprobe.run(TARGET, max_hops=8, samples=1, timeout_s=0.2,
                               sender=sender, tcp_checker=lambda *_a: False,
                               should_stop=lambda: True)
        self.assertFalse(result.completed)
        self.assertEqual(result.hops, ())
        self.assertEqual(sender.calls, [], "取消后一个探测包都不该发")

    def test_parameters_are_clamped(self):
        sender = self._sender()
        # 显式给极小 hop 数也要被夹到 1，且 samples/timeout 夹取可见。
        result = pathprobe.run(TARGET, max_hops=0, samples=0, timeout_s=0.0,
                               sender=sender, tcp_checker=lambda *_a: False)
        self.assertEqual(result.max_hops, 1)
        self.assertEqual(result.samples, 1)
        self.assertEqual(result.timeout_s, 0.2)
        self.assertEqual([hop.ttl for hop in result.hops], [1])

    def test_sender_failure_degrades_without_raising(self):
        def boom(*_a):
            raise RuntimeError("scapy 不可用")

        result = pathprobe.run(TARGET, sender=boom, tcp_checker=lambda *_a: False)
        self.assertEqual(result.hops, ())
        self.assertIn("scapy", result.error)
        self.assertEqual(result.verdict_key, pathprobe.PATH_NO_DATA)

    def test_ipv6_target_is_rejected(self):
        sender = self._sender()
        result = pathprobe.run("2001:db8::1", sender=sender)
        self.assertEqual(result.hops, ())
        self.assertIn("IPv4", result.error)
        self.assertEqual(sender.calls, [])

    def test_dns_failure_is_reported_not_raised(self):
        with mock.patch.object(pathprobe.socket, "getaddrinfo",
                               side_effect=OSError("no dns")):
            result = pathprobe.run("no-such-host.invalid", sender=self._sender())
        self.assertEqual(result.hops, ())
        self.assertIn("DNS", result.error)

    def test_probes_are_marked_for_isolation(self):
        """探测包必须可识别：ICMP 固定 id、TCP 源端口在固定段（纯字符串口径）。"""
        condition = pathprobe.path_exclusion_display_filter(
            [pathprobe.ProbeKind.ICMP, pathprobe.ProbeKind.TCP_SYN])
        self.assertIn(f"{pathprobe.PROBE_ID:#06x}", condition)
        low, high = pathprobe.PROBE_SRC_PORT_RANGE
        self.assertIn(f"tcp.srcport >= {low}", condition)
        self.assertIn(f"tcp.dstport <= {high}", condition)
        self.assertIn(f"not (icmp.type == {pathprobe.ICMP_TIME_EXCEEDED})",
                      condition)


class RunFallbackTest(unittest.TestCase):
    """V8：ICMP 全丢 → TCP 可达则降级重扫；不可达则证据不足。"""

    @staticmethod
    def _sender(method_filter):
        calls = []

        def sender(ip, method, probes, timeout_s, port):
            calls.append({"method": method, "port": port,
                          "ttls": [p["ttl"] for p in probes]})
            rows = []
            for probe in probes:
                responded = method == "tcp" and probe["ttl"] == 1
                rows.append(_row(probe["ttl"], responded=responded,
                                 rtt=1.5 if responded else None,
                                 responder=ip))
            return rows

        sender.calls = calls
        return sender

    def test_icmp_all_lost_but_tcp_reachable_switches_to_tcp(self):
        sender = self._sender("tcp")
        result = pathprobe.run(TARGET, port=443, max_hops=4, samples=2,
                               timeout_s=0.2, sender=sender,
                               tcp_checker=lambda *_a: True)
        self.assertTrue(result.icmp_filtered)
        self.assertEqual(result.method, "tcp")
        self.assertTrue(result.target_port_reachable)
        self.assertEqual([call["method"] for call in sender.calls],
                         ["icmp", "tcp"])
        self.assertEqual(sender.calls[1]["port"], 443)
        self.assertEqual([hop.ttl for hop in result.hops], [1])
        self.assertNotEqual(result.hops[0].rtt_avg_ms, None)
        self.assertEqual(result.samples, 1, "TCP 重扫样本应减半")

    def test_run_icmp_filtered_verdict_end_to_end(self):
        """R3：ICMP 全丢 + TCP 回退成功 → verdict 必须是 PATH.ICMP_FILTERED。

        报告不能既写「ICMP 被过滤，改用 TCP 探测」又写「整条路径未观察到劣化」。
        """
        sender = self._sender("tcp")
        result = pathprobe.run(TARGET, port=443, max_hops=4, samples=2,
                               timeout_s=0.2, sender=sender,
                               tcp_checker=lambda *_a: True)
        self.assertTrue(result.icmp_filtered)
        self.assertEqual(result.method, "tcp")
        self.assertEqual(result.verdict_key, pathprobe.PATH_ICMP_FILTERED)
        md = report.render_markdown(_result(result.to_dict()))
        self.assertIn("ICMP 被过滤，改用 TCP 探测", md)
        self.assertIn("结论：ICMP 被过滤", md)
        self.assertNotIn("整条路径未观察到劣化", md)

    def test_probes_sent_includes_tcp_fallback_packets(self):
        """R4：TCP 回退包也必须计入实际发出的探测包数。"""
        sender = self._sender("tcp")
        result = pathprobe.run(TARGET, port=443, max_hops=2, samples=2,
                               timeout_s=0.2, sender=sender,
                               tcp_checker=lambda *_a: True)
        # ICMP：2 个 TTL × 2 样本 = 4；TCP 回退样本减半：2 个 TTL × 1 = 2。
        self.assertEqual(result.probes_sent, 6)
        self.assertEqual(result.ledger["probes_sent"], 6)
        self.assertNotEqual(result.probes_sent, len(result.hops),
                            "不能拿截断后的 hops 行数当发送计数")

    def test_icmp_and_tcp_both_lost_is_no_data(self):
        sender = self._sender(None)
        result = pathprobe.run(TARGET, port=443, max_hops=4, samples=2,
                               timeout_s=0.2, sender=sender,
                               tcp_checker=lambda *_a: False)
        self.assertFalse(result.icmp_filtered)
        self.assertEqual(result.method, "icmp")
        self.assertEqual(result.verdict_key, pathprobe.PATH_NO_DATA)
        self.assertTrue(result.unreachable)
        self.assertEqual([call["method"] for call in sender.calls], ["icmp"],
                         "TCP 不可达时不许再发 TCP 探测")

    def test_tcp_fallback_failure_keeps_icmp_data(self):
        """TCP 重扫整批抛异常时，不能把已经拿到的 ICMP 结果弄丢。"""
        def sender(ip, method, probes, timeout_s, port):
            if method == "tcp":
                raise RuntimeError("tcp 不可用")
            return [_row(probe["ttl"], responded=False) for probe in probes]

        result = pathprobe.run(TARGET, port=443, max_hops=4, samples=1,
                               timeout_s=0.2, sender=sender,
                               tcp_checker=lambda *_a: True)
        self.assertTrue(result.icmp_filtered)
        self.assertEqual(result.method, "icmp", "TCP 重扫失败时保留 ICMP 方式")
        self.assertIn("tcp", result.error)
        self.assertEqual(len(result.hops), 4, "ICMP 的逐跳数据必须保留")


class TracertParseTest(unittest.TestCase):
    """G2：系统 tracert 的命令形状与**结构化**解析（不依赖本地化关键词）。"""

    def test_command_shape_and_clamping(self):
        command = pathprobe._tracert_command(TARGET, 99, 0.05)
        self.assertIn("-d", command, "必须 -d：只拿 IP，不做反向解析")
        index = command.index("-h")
        self.assertEqual(command[index + 1], "16", "max_hops 必须夹到 16")
        wait = command.index("-w")
        self.assertEqual(command[wait + 1], "200", "timeout 必须夹到 PATH_TIMEOUT_RANGE")
        self.assertEqual(command[-1], TARGET)
        slow = pathprobe._tracert_command(TARGET, 4, 9)
        self.assertEqual(slow[slow.index("-h") + 1], "4")
        self.assertEqual(slow[slow.index("-w") + 1], "3000")

    def test_english_output_is_parsed_structurally(self):
        text = (
            "Tracing route to 198.51.100.20 over a maximum of 4 hops\n\n"
            "  1    <1 ms    <1 ms    <1 ms  192.0.2.1\n"
            "  2     5 ms     6 ms     7 ms  192.0.2.2\n"
            "  3     *        *        *     Request timed out.\n"
            "  4    12 ms    13 ms    14 ms  198.51.100.20\n\n"
            "Trace complete.\n"
        )
        rows, malformed = pathprobe._parse_tracert_output(text)
        self.assertEqual(malformed, 0)
        self.assertEqual(len(rows), 12, "每跳固定 3 个采样")
        hops = pathprobe.build_hop_stats(rows, target_ip=TARGET)
        self.assertEqual([hop.ttl for hop in hops], [1, 2, 3, 4])
        self.assertEqual((hops[0].sent, hops[0].lost, hops[0].rtt_n), (3, 0, 3))
        self.assertEqual(hops[0].ip, GW)
        self.assertEqual(hops[0].rtt_avg_ms, 0.5, "<1ms 取 0.5 作为代表值")
        self.assertEqual(hops[1].rtt_avg_ms, 6.0)
        self.assertEqual((hops[2].sent, hops[2].lost, hops[2].rtt_n), (3, 3, 0))
        self.assertIsNone(hops[2].rtt_avg_ms, "没有 RTT 样本不许用 0.0 冒充")
        self.assertEqual(hops[3].ip, TARGET)

    def test_localized_timeout_text_is_ignored(self):
        """中文/其它语言的「请求超时」不参与判定：只看前 3 个字段。"""
        text = (
            "通过最多 4 个跃点跟踪到 198.51.100.20 的路由\n\n"
            "  1    <1 毫秒    <1 毫秒    <1 毫秒  192.0.2.1\n"
            "  2     *        *        *     请求超时。\n"
            "  3     4,5 ms   5 ms     6 ms  192.0.2.2\n"
        )
        rows, malformed = pathprobe._parse_tracert_output(text)
        self.assertEqual(malformed, 0)
        hops = pathprobe.build_hop_stats(rows, target_ip=TARGET)
        self.assertEqual((hops[0].sent, hops[0].lost), (3, 0))
        self.assertEqual((hops[1].sent, hops[1].lost), (3, 3))
        self.assertEqual(hops[2].rtt_min_ms, 4.5, "小数逗号也要能解析")
        self.assertNotIn("请求超时", str(rows), "本地化文字不得进入数据")

    def test_rtt_without_ip_is_malformed_not_fabricated(self):
        rows, malformed = pathprobe._parse_tracert_output(
            "  1     5 ms     5 ms     5 ms\n")
        self.assertEqual(rows, [])
        self.assertEqual(malformed, 1, "有 RTT 没响应方 → 结构不完整，跳过而不是编 IP")

    def test_no_hop_lines_returns_empty(self):
        rows, malformed = pathprobe._parse_tracert_output(
            "Tracing route to 198.51.100.20\nover a maximum of 30 hops:\n\n"
            "Trace complete.\n")
        self.assertEqual((rows, malformed), ([], 0))


def _tracert_row(ttl, responded=True, rtt=1.0, responder=GW):
    """造一条 tracert 采样记录（与 `_parse_tracert_output` 同构）。"""
    return {"ttl": ttl, "seq": ttl, "responded": bool(responded),
            "rtt_ms": float(rtt) if responded else None,
            "responder": responder if responded else "",
            "error": "" if responded else "timeout"}


class TracertFallbackRunTest(unittest.TestCase):
    """G2：``run()`` 在 scapy 不可用时降级系统 tracert，语义/报告字段不变。"""

    def _run(self, tracert, *, logger=None, samples=5, max_hops=8):
        with mock.patch.object(pathprobe, "scapy_available", return_value=False), \
                mock.patch.object(pathprobe, "_tracert_rows",
                                  side_effect=tracert) as called:
            result = pathprobe.run(
                TARGET, port=443, max_hops=max_hops, samples=samples,
                timeout_s=0.8, tcp_checker=lambda *_a: False, logger=logger)
        return result, called

    def test_fallback_returns_tracert_result_with_three_samples(self):
        def tracert(target, max_hops, timeout_s, should_stop=None):
            return ([_tracert_row(1, True, 1.0, GW),
                     _tracert_row(2, True, 8.0, TARGET)], 6, True, "")

        result, called = self._run(tracert)
        self.assertEqual(result.method, "tracert")
        self.assertEqual(result.samples, 3, "tracert 固定每跳 3 次探测")
        self.assertEqual(result.probes_sent, 6)
        self.assertEqual(result.ledger["probes_sent"], 6)
        self.assertEqual(result.verdict_key, pathprobe.PATH_OK)
        self.assertTrue(result.reached_target)
        self.assertEqual(result.error, "")
        self.assertEqual(called.call_count, 1)
        self.assertEqual(called.call_args.args[1], 8, "max_hops 要传给 tracert")
        self.assertEqual(called.call_args.args[2], 0.8)

    def test_r5_middle_loss_with_healthy_target_stays_ok(self):
        """tracert 中途丢包、目标正常 → PATH.OK + middle_loss_suspected（R5 不变）。"""
        def tracert(target, max_hops, timeout_s, should_stop=None):
            return ([_tracert_row(1, True, 1.0, GW),
                     _tracert_row(2, False), _tracert_row(3, False),
                     _tracert_row(4, True, 9.0, TARGET)], 12, True, "")

        result, _ = self._run(tracert)
        self.assertEqual(result.verdict_key, pathprobe.PATH_OK)
        self.assertIsNone(result.degraded_ttl)
        self.assertTrue(result.middle_loss_suspected)
        self.assertEqual(result.middle_loss_ttls, (2, 3))

    def test_degraded_path_keeps_transport_net_verdict(self):
        def tracert(target, max_hops, timeout_s, should_stop=None):
            return ([_tracert_row(1, True, 1.0, GW),
                     _tracert_row(2, False), _tracert_row(3, False),
                     _tracert_row(4, False)], 12, True, "")

        result, _ = self._run(tracert)
        self.assertEqual(result.verdict_key, pathprobe.PATH_TRANSPORT_NET)
        self.assertEqual(result.degraded_ttl, 2)
        self.assertEqual(result.degraded_ttl, pathprobe.first_degraded_hop(result.hops))

    def test_parse_failure_is_explicit_no_data(self):
        def tracert(target, max_hops, timeout_s, should_stop=None):
            return ([], 0, False, "tracert 解析失败/不可用：命令没有输出")

        result, _ = self._run(tracert)
        self.assertEqual(result.verdict_key, pathprobe.PATH_NO_DATA)
        self.assertEqual(result.hops, ())
        self.assertEqual(result.method, "tracert")
        self.assertIn("tracert 解析失败/不可用", result.error)
        self.assertNotIn("ModuleNotFoundError", result.error)

    def test_unexpected_exception_does_not_escape(self):
        def tracert(target, max_hops, timeout_s, should_stop=None):
            raise RuntimeError("boom")

        result, _ = self._run(tracert)
        self.assertEqual(result.verdict_key, pathprobe.PATH_NO_DATA)
        self.assertIn("tracert 不可用", result.error)
        self.assertIn("RuntimeError", result.error)

    def test_engine_is_logged(self):
        log: list[str] = []

        def tracert(target, max_hops, timeout_s, should_stop=None):
            return ([_tracert_row(1, True, 1.0, TARGET)], 3, True, "")

        self._run(tracert, logger=log.append)
        text = "\n".join(log)
        self.assertIn("路径剖面：scapy 不可用，使用系统 tracert 降级", text)
        self.assertIn("每跳 3 次探测", text)

    def test_scapy_available_still_uses_scapy_engine(self):
        calls: list[dict] = []

        def fake_sender(ip, method, probes, timeout_s, port):
            calls.append({"method": method, "probes": len(probes)})
            return [_row(probe["ttl"], responded=False) for probe in probes]

        log: list[str] = []
        with mock.patch.object(pathprobe, "scapy_available", return_value=True), \
                mock.patch.object(pathprobe, "_scapy_send_batch", side_effect=fake_sender):
            result = pathprobe.run(TARGET, port=443, max_hops=1, samples=1,
                                   timeout_s=0.2, tcp_checker=lambda *_a: False,
                                   logger=log.append)
        self.assertEqual(result.method, "icmp", "有 scapy 时行为不变")
        self.assertEqual(calls, [{"method": "icmp", "probes": 1}])
        self.assertIn("使用 scapy 逐跳", "\n".join(log))

    def test_injected_sender_works_even_without_scapy(self):
        """sender 是单测接缝：没有 scapy 也必须按注入实现走，不被降级分支抢走。"""
        class _Sender:
            def __init__(self):
                self.calls = []

            def __call__(self, ip, method, probes, timeout_s, port):
                self.calls.append(method)
                return [_row(probe["ttl"], responded=False) for probe in probes]

        sender = _Sender()
        with mock.patch.object(pathprobe, "scapy_available", return_value=False), \
                mock.patch.object(pathprobe, "_tracert_rows") as tracert_rows:
            result = pathprobe.run(TARGET, port=443, max_hops=1, samples=1,
                                   timeout_s=0.2, sender=sender,
                                   tcp_checker=lambda *_a: False)
        self.assertEqual(result.method, "icmp")
        self.assertEqual(sender.calls, ["icmp"])
        tracert_rows.assert_not_called()


class PathProfilerTest(unittest.TestCase):
    """后台线程：可取消、失败只降级、快照带两种过滤串。"""

    def test_stop_returns_within_three_seconds(self):
        def runner(target, should_stop=None, **_kwargs):
            while not (should_stop and should_stop()):
                time.sleep(0.02)
            return pathprobe.PathProbeResult(target=target)

        profiler = pathprobe.PathProfiler(TARGET, budget_s=30.0, runner=runner)
        profiler.start()
        time.sleep(0.1)
        profiler.stop()
        self.assertTrue(profiler.join(3.0))
        self.assertGreater(profiler.finished_epoch, 0.0)

    def test_runner_exception_is_captured(self):
        def boom(*_a, **_k):
            raise RuntimeError("探测炸了")

        profiler = pathprobe.PathProfiler(TARGET, runner=boom)
        profiler.start()
        self.assertTrue(profiler.join(3.0))
        self.assertIn("探测炸了", profiler.error)
        self.assertIsNone(profiler.result)
        self.assertIsNone(profiler.snapshot()["profile"])

    def test_snapshot_exposes_filters_and_budget(self):
        profiler = pathprobe.PathProfiler(TARGET, budget_s=8.0,
                                          runner=lambda *_a, **_k: None)
        snapshot = profiler.snapshot()
        self.assertEqual(snapshot["planned_kinds"], ["icmp", "tcp_syn"])
        self.assertIn("portrange", snapshot["exclusion_bpf"])
        self.assertIn("icmp.type == 11", snapshot["exclusion_display_filter"])
        self.assertEqual(snapshot["budget_s"], 8.0)


# ---------------------------------------------------------------- V9 接线


class CaptureLivePathWiringTest(unittest.TestCase):
    """``capture_live(shadow=True)``：有目标起 MTR、无目标不跑、失败只降级。"""

    IFACES = [{"index": 5, "name": r"\Device\NPF_{W} (WLAN)", "raw": "5"}]

    def _capture(self, target="93.184.216.34", logs=None, **patches):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        captures = Path(tmp.name) / "captures"
        filters: list[str] = []

        def fake_run(args, timeout=180):
            if "-w" in args:
                if "-f" in args:
                    filters.append(args[args.index("-f") + 1])
                pcap = Path(args[args.index("-w") + 1])
                pcap.parent.mkdir(parents=True, exist_ok=True)
                pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 200)
                return 0, "", ""
            if "-r" in args:
                return 0, "1\n", ""
            return 0, "", ""

        base = {
            "capture": mock.patch.object(diagnose, "CAPTURES", captures),
            "stable": mock.patch.object(diagnose, "_wait_file_stable",
                                        return_value=True),
            "find": mock.patch.object(tshark, "find_tshark",
                                      return_value=Path("tshark.exe")),
            "npcap": mock.patch.object(tshark, "npcap_installed", return_value=True),
            "ifaces": mock.patch.object(tshark, "list_interfaces",
                                        return_value=list(self.IFACES)),
            "tshark_run": mock.patch.object(tshark, "run", side_effect=fake_run),
            "targets": mock.patch.object(diagnose.pathprobe, "discover_targets",
                                         return_value={"gateway": GW}),
            "send": mock.patch.object(diagnose.pathprobe, "send_probe",
                                      return_value=(True, 1.0, GW, "")),
        }
        base.update(patches)
        stack = []
        try:
            for patcher in base.values():
                stack.append(patcher)
                patcher.start()
            result = diagnose.capture_live(target=target, duration=3,
                                           interface="5", shadow=True,
                                           logger=(logs.append if logs is not None
                                                   else (lambda _m: None)))
        finally:
            for patcher in reversed(stack):
                patcher.stop()
        return result, filters

    def test_target_starts_mtr_and_injects_path_snapshot(self):
        fake = pathprobe.PathProbeResult(
            target="93.184.216.34", target_ip="93.184.216.34",
            hops=(pathprobe.HopStat(ttl=1, ip=GW, sent=3, lost=0,
                                    rtt_min_ms=1.0, rtt_avg_ms=1.0,
                                    rtt_max_ms=1.0, jitter_ms=0.0, rtt_n=3),),
            verdict_key=pathprobe.PATH_OK, method="icmp", reached_target=True,
            max_hops=16, samples=3, timeout_s=0.8, probes_sent=3)
        result, filters = self._capture(
            mtr=mock.patch.object(diagnose.pathprobe, "run", return_value=fake))
        self.assertTrue(result.get("ok"), result)
        snapshot = result.get("path") or {}
        self.assertIsNotNone(snapshot.get("profile"))
        self.assertEqual(len(snapshot["profile"]["hops"]), 1)
        self.assertIn("icmp.type == 11", snapshot["exclusion_display_filter"])
        # BPF 必须同时排 ICMP 与 TCP（TCP 是 ICMP 被过滤时的降级方式）。
        merged = filters[0]
        self.assertIn("icmp[4:2]", merged)
        self.assertIn("tcp src portrange", merged)

    def test_no_target_never_runs_mtr(self):
        result, filters = self._capture(
            target="",
            targets=mock.patch.object(diagnose.pathprobe, "discover_targets",
                                      return_value={}),
            mtr=mock.patch.object(diagnose.pathprobe, "run"))
        self.assertTrue(result.get("ok"), result)
        self.assertNotIn("path", result)
        self.assertEqual(filters, [], "没有目标时不许凭空造过滤器")

    def test_mtr_exception_only_degrades(self):
        logs: list[str] = []

        def boom(*_a, **_k):
            raise RuntimeError("scapy 不可用")

        result, _filters = self._capture(
            logs=logs, mtr=mock.patch.object(diagnose.pathprobe, "run",
                                             side_effect=boom))
        self.assertTrue(result.get("ok"), result)
        self.assertNotIn("path", result, "MTR 失败不许注入空剖面")
        self.assertIn("路径探测", "\n".join(logs))

    def test_empty_profile_not_injected(self):
        empty = pathprobe.PathProbeResult(target="93.184.216.34", error="DNS")
        result, _filters = self._capture(
            mtr=mock.patch.object(diagnose.pathprobe, "run", return_value=empty))
        self.assertTrue(result.get("ok"), result)
        self.assertNotIn("path", result)


class RunScanInjectionTest(unittest.TestCase):
    """``run_scan``：合并两种显示过滤、注入 ``meta.path_profile``、离线不注入。"""

    @staticmethod
    def _ok_result() -> dict:
        return {
            "ok": True, "meta": {"packets": 10, "bytes": 100, "duration": 5.0,
                                 "streams_total": 1},
            "rows": [], "metrics": {},
            "summary": {"target": "全网", "critical_count": 0, "warning_count": 0,
                        "pcap_file": "x.pcap"},
        }

    def _run(self, cap: dict, profile_patch=None, analyze_side_effect=None,
             logger=None, counted_icmp: int = 7, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(diagnose, "capture_live", return_value=cap), \
                    mock.patch.object(diagnose.analyzer, "analyze",
                                      side_effect=analyze_side_effect,
                                      return_value=copy.deepcopy(self._ok_result())) as analyze, \
                    mock.patch.object(diagnose.report, "save",
                                      return_value={"markdown": "m", "json": "j"}), \
                    mock.patch.object(diagnose.logstore, "record_run"), \
                    mock.patch.object(diagnose, "REPORTS", Path(tmp)), \
                    mock.patch.object(diagnose.tshark, "find_tshark",
                                      return_value=Path("tshark.exe")), \
                    mock.patch.object(diagnose.pathprobe,
                                      "count_time_exceeded_packets",
                                      return_value=counted_icmp) as counted:
                result = diagnose.run_scan(
                    logger=logger or (lambda _m: None), **kwargs)
        return result, analyze, counted

    def _cap(self, profile: dict | None = None) -> dict:
        kinds = [pathprobe.ProbeKind.ICMP, pathprobe.ProbeKind.TCP_SYN]
        cap = {"ok": True, "pcap": "x.pcap", "interface": "WLAN", "bpf": "",
               "duration": 5,
               "probe": {"exclusion_display_filter":
                         pathprobe.exclusion_display_filter([pathprobe.ProbeKind.ICMP])},
               "path": {"exclusion_display_filter":
                        pathprobe.path_exclusion_display_filter(kinds),
                        "profile": profile}}
        return cap

    def test_path_profile_injected_with_excluded_icmp(self):
        result, analyze, counted = self._run(self._cap(_profile()),
                                            target=TARGET, shadow=True, duration=5)
        self.assertTrue(result.get("ok"), result)
        injected = result["meta"]["path_profile"]
        self.assertEqual(injected["excluded_icmp"], 7)
        self.assertEqual(len(injected["hops"]), 4)
        self.assertTrue(injected["middle_loss_suspected"], "R5 字段必须随快照注入报告")
        self.assertEqual(injected["middle_loss_ttls"], [2, 3])
        self.assertTrue(counted.called)
        display_filter = analyze.call_args.kwargs.get("display_filter") or ""
        self.assertIn("icmp.type == 11", display_filter)
        self.assertIn("tcp.srcport", display_filter)

    def test_zero_excluded_icmp_log_omits_exclusion_sentence(self):
        """S5：日志与报告同口径 —— 0 个 ICMP 超时包时不写「剔除 0」。"""
        logs: list[str] = []
        self._run(self._cap(_profile()), target=TARGET, shadow=True, duration=5,
                  logger=logs.append, counted_icmp=0)
        text = "\n".join(logs)
        self.assertIn("路径剖面", text)
        self.assertNotIn("ICMP 超时包", text,
                         f"0 值不应打印排除句：\n{text}")
        self.assertNotIn("剔除", text)

    def test_positive_excluded_icmp_log_keeps_exclusion_sentence(self):
        """N>0 时排除句保留，且数字来自 count_time_exceeded_packets。"""
        logs: list[str] = []
        self._run(self._cap(_profile()), target=TARGET, shadow=True, duration=5,
                  logger=logs.append, counted_icmp=7)
        text = "\n".join(logs)
        self.assertIn("剔除 7 个 ICMP 超时包", text)

    def test_display_filter_failure_always_retries_without_filter(self):
        """R7：显示过滤失败（错误串不含 filter）也必须无条件回退一次。"""
        calls = []
        ok_result = self._ok_result()

        def fake_analyze(*_args, **kwargs):
            calls.append(dict(kwargs))
            if len(calls) == 1:
                # 真实 tshark 对未知字段的报错，不含 "filter"。
                return {"ok": False,
                        "error": '解析失败(rc=4): "bogus.field" is not a valid '
                                 'protocol or protocol field.'}
            return copy.deepcopy(ok_result)

        logs: list[str] = []
        result, _analyze, _counted = self._run(
            self._cap(_profile()), target=TARGET, shadow=True, duration=5,
            analyze_side_effect=fake_analyze, logger=logs.append)
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(len(calls), 2, "只允许回退一次，不能死循环")
        self.assertIsNotNone(calls[0].get("display_filter"))
        self.assertIsNone(calls[1].get("display_filter"),
                          "第二次分析必须是不带显示过滤的")
        self.assertIn("本次统计可能包含探针流量", "\n".join(logs))
        self.assertIn("已退回未过滤分析", "\n".join(logs))

    def test_no_hops_does_not_inject(self):
        result, analyze, _ = self._run(self._cap({"hops": []}), target=TARGET,
                                      shadow=True, duration=5)
        self.assertNotIn("path_profile", result["meta"])
        display_filter = analyze.call_args.kwargs.get("display_filter") or ""
        # 即使没注入，MTR 期间的 type 11 防御层照样生效（它有独立的过滤串）。
        self.assertIn("icmp.type == 11", display_filter)

    def test_offline_never_injects_path(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pcap = Path(tmp.name) / "x.pcap"
        pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
        with mock.patch.object(diagnose, "capture_live") as capture, \
                mock.patch.object(diagnose.analyzer, "analyze",
                                  return_value=copy.deepcopy(self._ok_result())), \
                mock.patch.object(diagnose.report, "save",
                                  return_value={"markdown": "m", "json": "j"}), \
                mock.patch.object(diagnose.logstore, "record_run"), \
                mock.patch.object(diagnose, "REPORTS", Path(tmp.name)):
            result = diagnose.run_scan(pcap=str(pcap), logger=lambda _m: None,
                                       shadow=True)
        self.assertTrue(result.get("ok"))
        self.assertEqual(capture.call_count, 0)
        self.assertNotIn("path_profile", result["meta"])


# ---------------------------------------------------------------- V10 报告


class PathReportTest(unittest.TestCase):
    """报告「路径剖面」区块：有数据才出现；无数据输出不变（红线）。"""

    def test_block_renders_hops_and_conclusion(self):
        md = report.render_markdown(_result(_degraded_profile()))
        self.assertIn("路径剖面", md)
        self.assertIn("| TTL |", md)
        self.assertIn("0.5/1.0/1.5 ms", md)
        self.assertIn("66.7%", md)
        self.assertIn("未探到", md)
        self.assertIn("第 2 跳开始劣化", md)
        self.assertIn("持续到目标或最后响应跳", md)
        self.assertIn("基线 RTT", md)
        self.assertIn("ICMP", md)
        self.assertIn("已探测到目标", md)
        self.assertIn("ICMP 超时", md)
        self.assertIn("6 为上限", md)

    def test_middle_loss_hint_only_without_persistent_degradation(self):
        """R5：中间跳丢包、目标正常 → 报告明确「不能据此判承载网」。"""
        md = report.render_markdown(_result(_profile()))
        self.assertIn("中间跳（第 2、3 跳）未响应或丢包", md)
        self.assertIn("疑似 ICMP 限速/策略过滤", md)
        self.assertIn("后续跳与目标正常，不能据此判承载网故障", md)
        self.assertIn("整条路径未观察到劣化", md)
        self.assertNotIn("第 2 跳开始劣化", md)
        self.assertNotIn("问题更像在承载网", md)
        # 持续劣化（目标也丢）时，不许再给「限速」解读，否则与承载网结论矛盾。
        degraded_md = report.render_markdown(_result(_degraded_profile()))
        self.assertNotIn("疑似 ICMP 限速", degraded_md)
        self.assertNotIn("中间跳（第", degraded_md)

    def test_excluded_icmp_copy_says_packets_not_counted(self):
        """R1：剔除的 ICMP 超时包必须明说「这些包未计入业务统计」。"""
        md = report.render_markdown(_result(_profile()))
        self.assertIn("这些包未计入业务统计", md)
        self.assertIn("6 为上限", md)
        self.assertIn("含非探针流量", md)

    def test_zero_excluded_icmp_omits_count_line(self):
        """S5：没有样本就明说 —— ``excluded_icmp=0`` 时不打印「剔除 0 个」。"""
        md = report.render_markdown(_result(_profile(excluded_icmp=0)))
        block = md.split("路径剖面", 1)[1].split("\n## ", 1)[0]
        self.assertNotIn("剔除 0", block)
        self.assertNotIn("业务统计", block,
                         "0 值没有信息量，不能和 G3 的 N=0 静默口径相矛盾")
        self.assertIn("路径剖面", md, "有逐跳数据时区块本身仍必须存在")

    def test_missing_excluded_icmp_old_payload_omits_count_line(self):
        """旧载荷没有 ``excluded_icmp`` 键时按 0 处理，同样不打印。"""
        profile = _profile()
        profile.pop("excluded_icmp")
        block = report.render_markdown(_result(profile)).split("路径剖面", 1)[1]
        self.assertNotIn("剔除", block.split("\n## ", 1)[0])

    def test_tcp_method_and_icmp_filtered_wording(self):
        md = report.render_markdown(_result(_profile(
            method="tcp", icmp_filtered=True, verdict_key=pathprobe.PATH_ICMP_FILTERED,
            degraded_ttl=None, middle_loss_suspected=False, middle_loss_ttls=[])))
        self.assertIn("ICMP 被过滤，改用 TCP 探测", md)
        self.assertIn("ICMP 被过滤", md)

    def test_tracert_method_uses_tracert_wording_not_tcp_fallback(self):
        md = report.render_markdown(_result(_profile(
            method="tracert", icmp_filtered=True,
            verdict_key=pathprobe.PATH_ICMP_FILTERED,
            degraded_ttl=None, middle_loss_suspected=False, middle_loss_ttls=[])))
        self.assertIn("基于系统 tracert", md)
        self.assertIn("样本数 3（每跳 3 次探测）", md)
        self.assertNotIn("本次已改用 TCP 探测", md,
                         "tracert 降级没有 TCP 重扫，不能照抄 TCP 文案")
        self.assertIn("未做 TCP 逐跳重扫", md)

    def test_tracert_plain_method_line(self):
        md = report.render_markdown(_result(_profile(method="tracert")))
        self.assertIn("基于系统 tracert", md)
        self.assertNotIn("TCP SYN", md)

    def test_verdict_keys_have_text(self):
        keys = {
            pathprobe.PATH_OK: "未观察到劣化",
            pathprobe.PATH_LOCAL_SIDE: "本地出口",
            pathprobe.PATH_TRANSPORT_NET: "承载网",
            pathprobe.PATH_SERVER_EDGE: "对端侧",
            pathprobe.PATH_ICMP_FILTERED: "ICMP 被过滤",
            pathprobe.PATH_NO_DATA: "证据不足",
        }
        for key, needle in keys.items():
            with self.subTest(key=key):
                md = report.render_markdown(_result(_profile(
                    verdict_key=key, degraded_ttl=None, reached_target=False,
                    middle_loss_suspected=False, middle_loss_ttls=[])))
                self.assertIn(needle, md)

    def test_unreachable_uses_target_unreachable_wording(self):
        md = report.render_markdown(_result(_profile(
            verdict_key=pathprobe.PATH_NO_DATA, unreachable=True,
            degraded_ttl=None, reached_target=False,
            middle_loss_suspected=False, middle_loss_ttls=[])))
        self.assertIn("目标不可达", md)

    def test_tun_hint_and_not_completed(self):
        md = report.render_markdown(_result(_profile(
            tun_suspected=True, completed=False,
            middle_loss_suspected=False, middle_loss_ttls=[])))
        self.assertIn("代理/TUN", md)
        self.assertIn("探测未完成", md)

    def test_no_samples_never_prints_zero_ms(self):
        hop = {"ttl": 1, "ip": "", "sent": 3, "lost": 3, "loss_pct": 100.0,
               "rtt_min_ms": None, "rtt_avg_ms": None, "rtt_max_ms": None,
               "jitter_ms": None, "rtt_n": 0, "status": "loss"}
        md = report.render_markdown(_result(_profile(hops=[hop], reached_target=False,
                                                    degraded_ttl=1)))
        block = md.split("路径剖面", 1)[1].split("\n## ", 1)[0]
        self.assertIn("未探到", block)
        for fake in ("0.0/0.0/0.0", "0ms |", " 0ms"):
            self.assertNotIn(fake, block)

    def test_no_path_profile_has_no_block(self):
        md = report.render_markdown(_result())
        self.assertNotIn("路径剖面", md)

    def test_empty_hops_has_no_block(self):
        md = report.render_markdown(_result(_profile(hops=[], reached_target=False)))
        self.assertNotIn("路径剖面", md)

    def test_without_path_profile_output_is_byte_identical(self):
        plain = _result()
        once = report.render_markdown(copy.deepcopy(plain))
        twice = report.render_markdown(copy.deepcopy(plain))
        self.assertEqual(once, twice)
        self.assertNotIn("path_profile", json.dumps(plain))
        self.assertEqual(verdict.build(copy.deepcopy(plain))["level"],
                         verdict.build(copy.deepcopy(plain))["level"])


# ---------------------------------------------------------------- API / UI


class ProbeApiPathTest(unittest.TestCase):
    """``/api/probe`` 的 ``path`` 开关（默认开、关闭不发探测、失败只降级）。"""

    @staticmethod
    def _path_result():
        return pathprobe.PathProbeResult(
            target="example.com", target_ip=TARGET,
            hops=(pathprobe.HopStat(ttl=1, ip=GW, sent=3, lost=0,
                                    rtt_min_ms=1.0, rtt_avg_ms=1.0,
                                    rtt_max_ms=1.0, jitter_ms=0.0, rtt_n=3),),
            verdict_key=pathprobe.PATH_OK, method="icmp", reached_target=True,
            max_hops=16, samples=5, timeout_s=1.0, probes_sent=3)

    def _guarded(self, **kwargs):
        with mock.patch.object(server.probe, "run",
                               return_value={"ok": True, "level": "正常"}), \
                mock.patch.object(server, "_record_ui_run"), \
                mock.patch.object(server, "log"):
            return server._probe_guarded("example.com", None, 4, 1.0, None,
                                         **kwargs)

    def test_default_does_not_run_mtr(self):
        with mock.patch.object(server.pathprobe, "run") as mtr:
            result = self._guarded()
        self.assertEqual(mtr.call_count, 0)
        self.assertNotIn("path_profile", result)

    def test_path_true_attaches_profile_and_ui_copy(self):
        with mock.patch.object(server.pathprobe, "run",
                               return_value=self._path_result()):
            result = self._guarded(path=True)
        self.assertEqual(result["path_profile"]["hops"][0]["ttl"], 1)
        self.assertEqual(result["path_profile"]["excluded_icmp"], 0)
        self.assertIn("path", result["ui_copy"])
        self.assertIn("ui_title", result["ui_copy"]["path"])

    def test_path_failure_only_degrades(self):
        with mock.patch.object(server.pathprobe, "run",
                               side_effect=RuntimeError("scapy 不可用")):
            result = self._guarded(path=True)
        self.assertTrue(result["ok"])
        self.assertNotIn("path_profile", result)

    def test_path_with_zero_hops_attaches_nothing(self):
        with mock.patch.object(server.pathprobe, "run",
                               return_value=pathprobe.PathProbeResult(
                                   target="example.com", error="DNS")):
            result = self._guarded(path=True)
        self.assertNotIn("path_profile", result)

    def test_routes_default_path_to_true(self):
        source = (ROOT / "core" / "server.py").read_text(encoding="utf-8")
        self.assertIn('_to_bool(payload.get("path"), True)', source)
        self.assertIn('_to_bool((q.get("path") or [None])[0], True)', source)
        self.assertIn('params = {"target"', source)

    def test_path_probe_has_time_budget_and_cancellation_hook(self):
        """S6：同步 ``/api/probe?path=true`` 必须带时间预算（不干等约 60s）。"""
        captured: dict = {}

        def fake_run(target, port=None, **kwargs):
            captured.update(kwargs)
            return self._path_result()

        with mock.patch.object(server.pathprobe, "run", side_effect=fake_run), \
                mock.patch.object(server, "log"):
            profile = server._probe_path_profile("example.com", 443, budget_s=1)
        self.assertIsNotNone(profile)
        should_stop = captured.get("should_stop")
        self.assertTrue(callable(should_stop), "必须把取消判定传给 pathprobe.run")
        self.assertFalse(should_stop())
        time.sleep(1.02)  # 预算最小 1s（防误传 0 立即取消）
        self.assertTrue(should_stop(), "预算到点后必须让 pathprobe 收尾")

    def test_budget_stop_keeps_partial_profile_and_marks_not_completed(self):
        """到预算被取消时：保留已完成的跳、completed=false、日志明说未跑完。"""
        partial = pathprobe.PathProbeResult(
            target="example.com", target_ip=TARGET,
            hops=(pathprobe.HopStat(ttl=1, ip=GW, sent=3, lost=0,
                                    rtt_min_ms=1.0, rtt_avg_ms=1.0,
                                    rtt_max_ms=1.0, jitter_ms=0.0, rtt_n=3),),
            verdict_key=pathprobe.PATH_OK, method="tracert", reached_target=False,
            completed=False, error="tracert 被取消，已保留部分跳",
            max_hops=16, samples=3, timeout_s=1.0, probes_sent=3)
        logs: list[str] = []
        with mock.patch.object(server.pathprobe, "run", return_value=partial), \
                mock.patch.object(server, "log", side_effect=logs.append):
            profile = server._probe_path_profile("example.com", 443, budget_s=1)
        self.assertIsNotNone(profile)
        self.assertFalse(profile["completed"])
        self.assertEqual(len(profile["hops"]), 1)
        text = "\n".join(logs)
        self.assertIn("部分降级", text)
        self.assertIn("未跑完", text)


class PathUiTest(unittest.TestCase):
    """UI：逐跳 checkbox 默认勾选、payload 带 path、结果页渲染路径剖面。"""

    CONFIG_RE = re.compile(
        r'<script type="application/json" id="ui-config">(.*?)</script>', re.S)

    def test_probe_path_toggle_default_checked(self):
        self.assertIn('id="probe-path-toggle"', HTML)
        block = HTML.split('id="probe-path-toggle"', 1)[1].split("</label>", 1)[0]
        self.assertIn("checked", block, "逐跳开关默认必须勾选（SPEC：默认开）")
        self.assertIn("逐跳路径", block)

    def test_probe_payload_carries_path(self):
        start = HTML.index("async function runProbe()")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn("path:", body)
        self.assertIn('$("#probe-path-toggle")', body)

    def test_probe_result_renders_path_profile(self):
        start = HTML.index("async function runProbe()")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn("renderPathProfile", body)
        self.assertIn("path_profile", body)

    def test_live_result_renders_path_block(self):
        start = HTML.index("function render(res, actions)")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn("renderPathProfile", body)
        self.assertIn("path_profile", body)
        self.assertIn("pathBlock", body)

    def test_shadow_checkbox_wording_covers_mtr(self):
        block = HTML.split('id="shadow-toggle"', 1)[1].split("</label>", 1)[0]
        self.assertIn("路径剖面", block)
        self.assertIn("探针基线", block)

    def test_path_block_text_comes_from_copy_table(self):
        path_copy = COPY["path"]
        for key in ("ui_title", "ui_hint", "th_ttl", "target_line", "verdict_ok",
                    "verdict_icmp_filtered", "tun_hint", "not_completed_line",
                    "excluded_icmp", "method_tcp", "middle_loss_hint",
                    "status_rate_limited", "method_tracert",
                    "verdict_icmp_filtered_tracert"):
            with self.subTest(key=key):
                self.assertIn(key, path_copy)
        start = HTML.index("function renderPathProfile(pp, copy)")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn("copy.ui_title", body)
        self.assertIn("copy.target_line", body)
        self.assertIn("copy.middle_loss_hint", body)
        for hardcoded in ("未探到", "劣化", "代理/TUN", "路径剖面（"):
            self.assertNotIn(hardcoded, body,
                             "路径区块的文案必须来自 copy 表，不能在页面里写死")

    def test_tracert_method_and_verdict_branch(self):
        start = HTML.index("function renderPathProfile(pp, copy)")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn('pp.method === "tracert"', body)
        self.assertIn("copy.method_tracert", body)
        self.assertIn("verdict_icmp_filtered_tracert", body,
                      "tracert 降级不能显示「已改用 TCP 探测」")

    def test_status_ui_copy_includes_path_when_present(self):
        with mock.patch.object(server, "_probe_ui_copy", return_value={"ui_title": "x"}), \
                mock.patch.object(server, "_path_ui_copy", return_value={"ui_title": "y"}):
            enriched = server._attach_probe_ui_copy(
                {"meta": {"path_profile": _profile()}})
        self.assertEqual(enriched["ui_copy"]["path"], {"ui_title": "y"})
        self.assertNotIn("probe", enriched["ui_copy"])

    def test_path_block_hides_zero_excluded_icmp(self):
        """S5：UI 与报告/日志同口径，0 个 ICMP 超时包不渲染「剔除 0」。"""
        start = HTML.index("function renderPathProfile(pp, copy)")
        body = HTML[start:HTML.index("\nfunction ", start)]
        self.assertIn("excludedIcmp > 0", body,
                      "0 值必须跳过 excluded_icmp 文案（没有样本就明说）")
        self.assertNotIn("? 0 : pp.excluded_icmp", body,
                         "旧的无条件渲染写法必须消失")


# ---------------------------------------------------------------- 隔离（硬性）


@unittest.skipUnless(HAVE_SCAPY and HAVE_TSHARK,
                     "需要 scapy + tshark 才能造/读 pcap")
class PathIsolationSyntheticTest(unittest.TestCase):
    """合成 pcap：MTR 探测包 + ICMP time-exceeded + 业务包 → 过滤后与纯净相同。"""

    STAT_KEYS = (
        "packets", "tcp_packets", "tcp_data_packets", "streams_total",
        "retrans", "dup_ack", "ooo", "rst", "syn", "synack",
        "dns_total", "dns_resp", "icmp_unreach", "icmp_timeout", "arp_no_reply",
    )

    @classmethod
    def setUpClass(cls):
        from scapy.all import ICMP, IP, Raw, TCP, wrpcap

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
        # MTR 探测包：ICMP echo（固定 id）+ 路径设备回的 time-exceeded（type 11）
        # + ICMP 被过滤时降级用的 TCP SYN（源端口在固定段）。
        probes = [
            IP(src="192.0.2.10", dst=TARGET, ttl=1)
            / ICMP(type=8, id=pathprobe.PROBE_ID, seq=1) / Raw(pathprobe.PROBE_PAYLOAD),
            IP(src=GW, dst="192.0.2.10")
            / ICMP(type=11, code=0)
            / IP(src="192.0.2.10", dst=TARGET, ttl=1)
            / ICMP(type=8, id=pathprobe.PROBE_ID, seq=1) / Raw(pathprobe.PROBE_PAYLOAD),
            IP(src="192.0.2.10", dst=TARGET, ttl=2)
            / ICMP(type=8, id=pathprobe.PROBE_ID, seq=2) / Raw(pathprobe.PROBE_PAYLOAD),
            IP(src=ROUTER, dst="192.0.2.10")
            / ICMP(type=11, code=0)
            / IP(src="192.0.2.10", dst=TARGET, ttl=2)
            / ICMP(type=8, id=pathprobe.PROBE_ID, seq=2) / Raw(pathprobe.PROBE_PAYLOAD),
            IP(src="192.0.2.10", dst=TARGET, ttl=3)
            / TCP(sport=39001, dport=443, flags="S", seq=7),
            IP(src=TARGET, dst="192.0.2.10") / TCP(sport=443, dport=39001,
                                                  flags="RA", seq=0, ack=8),
            # 同一窗口里「别的流量」的 TTL 超时：外层不是我们的 id、内层也不是我们
            # 的端口 —— 只有 `not (icmp.type == 11)` 这一条能把它排除（残余风险）。
            IP(src="203.0.113.5", dst="198.51.100.9")
            / ICMP(type=11, code=0)
            / IP(src="192.0.2.10", dst="198.51.100.9", ttl=1)
            / TCP(sport=50000, dport=80, flags="S", seq=1),
        ]
        cls.business_pcap = base / "business.pcap"
        cls.probed_pcap = base / "probed.pcap"
        wrpcap(str(cls.business_pcap), business)
        wrpcap(str(cls.probed_pcap), business + probes)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _stats(self, result: dict) -> dict:
        return {key: result["meta"][key] for key in self.STAT_KEYS}

    def _filters(self) -> list:
        return [pathprobe.ProbeKind.ICMP, pathprobe.ProbeKind.TCP_SYN]

    def test_filtered_stats_equal_pure_business(self):
        filtered = analyzer.analyze(
            self.probed_pcap,
            display_filter=pathprobe.path_exclusion_display_filter(self._filters()))
        pure = analyzer.analyze(self.business_pcap)
        self.assertTrue(filtered.get("ok"), filtered.get("error"))
        self.assertEqual(self._stats(filtered), self._stats(pure),
                         "带 MTR 隔离过滤的业务统计必须与纯净业务 pcap 逐字段相同")

    def test_without_type11_clause_stats_differ(self):
        """只排探针标记、不排 type 11 → 旁路流量的 TTL 超时会多出来。

        注意：**我们自己的** ICMP 探针被回 type 11 时，Wireshark 的 ``icmp.type``
        会命中错误报文里内嵌的原始 ICMP，所以按标记也能排掉；真正需要整类排除的是
        「同一抓包窗口里别人的 TTL 超时」（共享口/镜像口/TUN 上很常见）。
        """
        only_markers = pathprobe.exclusion_display_filter(self._filters())
        filtered = analyzer.analyze(self.probed_pcap, display_filter=only_markers)
        pure = analyzer.analyze(self.business_pcap)
        self.assertNotEqual(self._stats(filtered), self._stats(pure))
        self.assertGreater(filtered["meta"]["icmp_timeout"], 0)

    def test_without_filter_stats_differ(self):
        raw = analyzer.analyze(self.probed_pcap)
        pure = analyzer.analyze(self.business_pcap)
        self.assertGreater(raw["meta"]["packets"], pure["meta"]["packets"])

    def test_counters_report_probe_and_time_exceeded(self):
        ts = tshark.find_tshark()
        self.assertEqual(
            pathprobe.count_time_exceeded_packets(ts, self.probed_pcap), 3)
        self.assertEqual(
            pathprobe.count_time_exceeded_packets(ts, self.business_pcap), 0)
        # 4 = 2 个 echo 请求 + TCP SYN + RST；两个内嵌我们 id 的 type 11 归
        # excluded_icmp 计数，标记计数显式排除 type 11（R1：两处口径互斥）。
        self.assertEqual(
            pathprobe.count_marked_packets(ts, self.probed_pcap, self._filters()), 4)
        self.assertEqual(
            pathprobe.count_marked_packets(ts, self.business_pcap, self._filters()), 0)
        # 互斥性程序证明：标记 ∪ type11 = 4 + 3；若重复计数，并集会小于 7。
        expression = (f"({pathprobe.probe_marker_display_filter(self._filters())}) "
                      f"or icmp.type == {pathprobe.ICMP_TIME_EXCEEDED}")
        rc, out, _err = tshark.run(
            [str(ts), "-r", str(self.probed_pcap), "-Y", expression,
             "-T", "fields", "-e", "frame.number"], timeout=120)
        self.assertEqual(rc, 0)
        union = len([line for line in (out or "").splitlines() if line.strip()])
        self.assertEqual(union, 7, "标记包与 type 11 必须互不重叠（4 + 3）")


# ---------------------------------------------------------------- DNS 角色


class DnsParseTest(unittest.TestCase):
    """注册表原始值 → 有效 IPv4 列表（纯函数）。"""

    def test_splits_and_dedupes(self):
        self.assertEqual(
            winapi._parse_dns_list(["192.0.2.53 198.51.100.53,10.255.255.1",
                                    "192.0.2.53"]),
            ("192.0.2.53", "198.51.100.53", "10.255.255.1"))

    def test_skips_invalid_unspecified_ipv6(self):
        self.assertEqual(
            winapi._parse_dns_list(["", "0.0.0.0", "fe80::1%12", "not-an-ip",
                                    "224.0.0.1", "192.0.2.53"]),
            ("192.0.2.53",))

    def test_empty_input(self):
        self.assertEqual(winapi._parse_dns_list([]), ())
        self.assertEqual(winapi._parse_dns_list(None), ())

    def test_dns_servers_uses_registry_values(self):
        with mock.patch.object(winapi, "_registry_dns_values",
                               return_value=["192.0.2.53,198.51.100.53"]):
            self.assertEqual(winapi.dns_servers(),
                             ("192.0.2.53", "198.51.100.53"))

    def test_dns_servers_returns_empty_on_failure(self):
        with mock.patch.object(winapi, "_registry_dns_values",
                               side_effect=OSError("no registry")):
            self.assertEqual(winapi.dns_servers(), ())


class DnsRoleDiscoveryTest(unittest.TestCase):
    """``discover_targets`` 的 DNS 角色：可用则加、环回则优雅跳过。"""

    class _FakeWinapi:
        def __init__(self, gateway: str, servers: tuple):
            self._gateway = gateway
            self._servers = servers

        def default_gateway(self, dest: str = "8.8.8.8") -> str:
            return self._gateway

        def dns_servers(self) -> tuple:
            return self._servers

    def _discover(self, gateway, servers, **kwargs):
        with mock.patch.object(pathprobe, "_winapi",
                               return_value=self._FakeWinapi(gateway, servers)):
            return pathprobe.discover_targets(**kwargs)

    def test_dns_role_added(self):
        targets = self._discover(GW, ("192.0.2.53",), target=TARGET)
        self.assertEqual(targets["gateway"], GW)
        self.assertEqual(targets["dns"], "192.0.2.53")
        self.assertEqual(targets["vdi"], TARGET)

    def test_loopback_dns_is_skipped_with_reason(self):
        targets = self._discover(GW, ("127.0.0.1",), target=TARGET)
        self.assertNotIn("dns", targets)
        self.assertEqual(targets["dns_skip"], "loopback")

    def test_loopback_dns_does_not_hide_a_usable_one(self):
        """第一台是环回、第二台可用时，用可用的那台（环回只是本机 stub）。"""
        targets = self._discover(GW, ("127.0.0.1", "192.0.2.53"), target=TARGET)
        self.assertEqual(targets["dns"], "192.0.2.53")
        self.assertNotIn("dns_skip", targets)

    def test_all_invalid_dns_is_skipped(self):
        targets = self._discover(GW, ("0.0.0.0", "not-an-ip"), target=TARGET)
        self.assertNotIn("dns", targets)
        self.assertIn(targets.get("dns_skip"), ("loopback", "unusable"))

    def test_shadow_specs_include_dns_udp_role(self):
        targets = {"gateway": GW, "dns": "192.0.2.53", "vdi": TARGET,
                   "vdi_port": "443"}
        specs = pathprobe.shadow_specs(targets)
        roles = [(spec.role, spec.kind.value, spec.port) for spec in specs]
        self.assertEqual(roles, [("gateway", "icmp", None),
                                 ("dns", "udp", 53),
                                 ("target", "tcp_syn", 443)])

    def test_loopback_dns_logs_skip_reason(self):
        logs: list[str] = []
        with mock.patch.object(diagnose.pathprobe, "discover_targets",
                               return_value={"gateway": GW,
                                             "dns_skip": "loopback"}):
            prober = diagnose._shadow_prober_for(TARGET, 5, logs.append)
        self.assertIsNotNone(prober)
        self.assertIn("跳过 DNS 角色", "\n".join(logs))


@unittest.skipUnless(winapi.IS_WINDOWS, "注册表 DNS 只在 Windows 上有意义")
class WindowsDnsIntegrationTest(unittest.TestCase):
    """真机注册表读取：只断言「不抛 + 类型/格式正确」，不依赖具体网络配置。"""

    def test_dns_servers_returns_ipv4_tuple_or_empty(self):
        servers = winapi.dns_servers()
        self.assertIsInstance(servers, tuple)
        for server in servers:
            self.assertRegex(server, r"^\d{1,3}(\.\d{1,3}){3}$")
            self.assertNotEqual(server, "0.0.0.0")


if __name__ == "__main__":
    unittest.main()
