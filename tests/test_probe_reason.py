"""ICMP 被过滤的真相判定：探测层原因 + 判定层不得误判承载网。

背景（真机证据）：目标 www.baidu.com 不回 ICMP，影子探针「8 发 0 收」，
报告把丢包率写成 100% 并判「运营商·承载网」—— 而同一份报告里 TCP 侧
RTT 27.7ms、重传 3.06%，两个结论互相矛盾。

本文件钉死四件事：

1. **原因枚举**：``reason`` 只有 ok / icmp_filtered / refused / timeout 四值，
   ICMP 全丢但 TCP 连上必须是 ``icmp_filtered``，不是 ``timeout``；
2. **逐跳**：目标不回 ICMP 时末段全丢**不进劣化段**，路径结论是「ICMP 被过滤」
   而不是「中间跳开始劣化（承载网）」；TCP 也不可达时才照旧判黑洞；
3. **探针基线**：每个角色带 ``reason``，TCP 旁证只作用于 ICMP 探针；
4. **判定层**：方向对照给出 ``PROBE.CONTRAST.ICMP_FILTERED``（不判丢包），
   网关同时丢包时仍按本地侧判（不能因为目标免疫就放过本地证据）；
   md 报告在丢包率旁注明口径。

变异验证口令见 tests/../scripts 说明：把 ``endpoint_reason`` 的
``if tcp == TCP_OK: return REASON_ICMP_FILTERED`` 改成 ``return REASON_TIMEOUT``
必须让本文件多条用例变红。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import pathprobe  # noqa: E402
import probe_reason  # noqa: E402
import report  # noqa: E402
import verdict  # noqa: E402


def _rows(spec):
    """把 ``[(ttl, responded, responder), ...]`` 转成逐跳原始记录。"""
    return [{"ttl": ttl, "responded": ok,
             "rtt_ms": 10.0 if ok else None, "responder": ip}
            for ttl, ok, ip in spec]


#: 典型公网路径：前三跳正常，末两跳（含目标）不回 ICMP。
TAIL_SILENT = [(1, True, "192.168.1.1"), (2, True, "10.0.0.1"),
               (3, True, "202.97.1.1"), (4, False, ""), (5, False, "")]


class ReasonEnumTest(unittest.TestCase):
    """``reason`` 的取值域与判定顺序。"""

    def test_reason_domain_is_fixed(self):
        self.assertEqual(probe_reason.PROBE_REASONS,
                         ("ok", "icmp_filtered", "refused", "timeout"))

    def test_icmp_all_lost_with_tcp_ok_is_filtered(self):
        got = probe_reason.endpoint_reason(icmp_sent=8, icmp_recv=0, tcp="ok")
        self.assertEqual(got, "icmp_filtered")
        self.assertTrue(probe_reason.is_target_alive(got))

    def test_icmp_all_lost_with_tcp_refused_is_refused(self):
        got = probe_reason.endpoint_reason(icmp_sent=8, icmp_recv=0, tcp="refused")
        self.assertEqual(got, "refused")
        self.assertTrue(probe_reason.is_target_alive(got))

    def test_icmp_all_lost_without_tcp_is_timeout(self):
        for tcp in ("", "timeout", "unreachable"):
            self.assertEqual(
                probe_reason.endpoint_reason(icmp_sent=8, icmp_recv=0, tcp=tcp),
                "timeout", tcp)
        self.assertFalse(probe_reason.is_target_alive("timeout"))

    def test_partial_loss_is_still_ok(self):
        """部分丢包是「丢多少」的问题，不是「为什么没响应」，原因仍是 ok。"""
        self.assertEqual(
            probe_reason.endpoint_reason(icmp_sent=8, icmp_recv=3), "ok")

    def test_tcp_only_endpoint(self):
        self.assertEqual(probe_reason.endpoint_reason(tcp="ok"), "ok")
        self.assertEqual(probe_reason.endpoint_reason(tcp="refused"), "refused")
        self.assertEqual(probe_reason.endpoint_reason(tcp="timeout"), "timeout")
        self.assertEqual(probe_reason.endpoint_reason(), "timeout")

    def test_unknown_reason_normalizes_to_timeout(self):
        for raw in ("", None, "OK ", "whatever", 5):
            self.assertIn(probe_reason.normalize(raw), probe_reason.PROBE_REASONS)
        self.assertEqual(probe_reason.normalize("whatever"), "timeout")
        self.assertEqual(probe_reason.normalize("OK"), "ok")
        self.assertFalse(probe_reason.is_target_alive("whatever"))


class HopReasonTest(unittest.TestCase):
    """逐跳：沉默尾巴标 filtered，且不进劣化段。"""

    def test_target_silent_with_tcp_ok_is_not_degraded(self):
        hops = pathprobe.build_hop_stats(_rows(TAIL_SILENT), target_ip="1.2.3.4",
                                         target_port_reachable=True)
        tail = [hop for hop in hops if hop.ttl >= 4]
        self.assertEqual([hop.reason for hop in tail],
                         ["icmp_filtered", "icmp_filtered"])
        self.assertEqual([hop.status.value for hop in tail], ["filtered", "filtered"])
        summary = pathprobe.summarize_path(hops, True, method="icmp",
                                           target_ip="1.2.3.4")
        self.assertEqual(summary["verdict_key"], pathprobe.PATH_ICMP_FILTERED)
        self.assertIsNone(summary["degraded_ttl"])          # 不判劣化
        self.assertTrue(summary["target_icmp_filtered"])
        self.assertEqual(summary["silent_ttls"], [4, 5])

    def test_target_silent_without_tcp_is_still_black_hole(self):
        """TCP 也不可达时不能拿「ICMP 被过滤」开脱 —— 那可能是真的不通。"""
        hops = pathprobe.build_hop_stats(_rows(TAIL_SILENT), target_ip="1.2.3.4",
                                         target_port_reachable=False)
        self.assertTrue(all(hop.reason == "timeout" for hop in hops if hop.ttl >= 4))
        summary = pathprobe.summarize_path(hops, False, method="icmp",
                                           target_ip="1.2.3.4")
        self.assertEqual(summary["verdict_key"], pathprobe.PATH_TRANSPORT_NET)
        self.assertFalse(summary["target_icmp_filtered"])

    def test_partial_loss_still_judged(self):
        """ICMP 部分丢包 → 仍要判（这条路上确实在丢包）。"""
        rows = _rows([(1, True, "192.168.1.1"), (2, True, "10.0.0.1"),
                      (3, True, "202.97.1.1")])
        rows += [{"ttl": 4, "responded": False, "rtt_ms": None, "responder": ""},
                 {"ttl": 4, "responded": True, "rtt_ms": 30.0, "responder": "1.2.3.4"}]
        hops = pathprobe.build_hop_stats(rows, target_ip="1.2.3.4",
                                         target_port_reachable=True)
        self.assertEqual(hops[-1].reason, "ok")
        summary = pathprobe.summarize_path(hops, True, method="icmp",
                                           target_ip="1.2.3.4")
        self.assertEqual(summary["verdict_key"], pathprobe.PATH_SERVER_EDGE)
        self.assertEqual(summary["degraded_ttl"], 4)

    def test_tcp_method_never_filters(self):
        """TCP SYN 逐跳每跳都该回 SYN-ACK：末段全丢就是真丢包。"""
        hops = pathprobe.build_hop_stats(_rows(TAIL_SILENT), target_ip="1.2.3.4",
                                         target_port_reachable=True)
        summary = pathprobe.summarize_path(hops, True, method="tcp",
                                           target_ip="1.2.3.4")
        self.assertFalse(summary["target_icmp_filtered"])
        self.assertEqual(summary["verdict_key"], pathprobe.PATH_TRANSPORT_NET)

    def test_hop_to_dict_carries_reason(self):
        hops = pathprobe.build_hop_stats(_rows(TAIL_SILENT), target_ip="1.2.3.4",
                                         target_port_reachable=True)
        payload = hops[-1].to_dict()
        self.assertEqual(payload["reason"], "icmp_filtered")
        self.assertEqual(payload["status"], "filtered")


class ProbeBaselineReasonTest(unittest.TestCase):
    """探针基线：每个角色带 reason，TCP 旁证只作用于 ICMP 角色。"""

    def _baseline(self, kind="icmp", sent=8, recv=0, role="target"):
        return {"sent": sent, "recv": recv, "timeout": sent - recv,
                "roles": [{"role": role, "kind": kind, "target": "1.2.3.4",
                           "sent": sent, "recv": recv, "n": 0,
                           "loss_pct": 100.0 if not recv else 0.0}]}

    def test_aggregate_marks_timeout_without_tcp_evidence(self):
        spec = pathprobe.ProbeSpec(pathprobe.ProbeKind.ICMP, "1.2.3.4", role="target")
        rec = pathprobe.ProbeRecord(spec=spec, sent_monotonic=1.0,
                                    sent_epoch=1.0, responded=False,
                                    error="timeout", seq=1)
        item = pathprobe.aggregate_records([rec])[0]
        self.assertEqual(item["reason"], "timeout")

    def test_apply_tcp_evidence_upgrades_icmp_role(self):
        got = pathprobe.apply_tcp_evidence(self._baseline(), {"target": "ok"})
        self.assertEqual(got["roles"][0]["reason"], "icmp_filtered")
        # 入参不被修改（快照可能还被别人持有）
        self.assertNotIn("reason", self._baseline()["roles"][0])

    def test_apply_tcp_evidence_ignores_non_icmp_kinds(self):
        got = pathprobe.apply_tcp_evidence(self._baseline(kind="tcp_syn"),
                                           {"target": "ok"})
        self.assertEqual(got["roles"][0]["reason"], "timeout")

    def test_apply_tcp_evidence_keeps_partial_loss_ok(self):
        got = pathprobe.apply_tcp_evidence(self._baseline(sent=8, recv=6),
                                           {"target": "timeout"})
        self.assertEqual(got["roles"][0]["reason"], "ok")

    def test_target_tcp_evidence_prefers_reachable(self):
        calls = []

        def checker(ip, port, timeout):
            calls.append((ip, port))
            return "refused" if port == 443 else "ok"

        self.assertEqual(pathprobe.target_tcp_evidence("1.2.3.4", None, 1.0, checker),
                         "refused")
        self.assertEqual(calls, [("1.2.3.4", 443)])
        self.assertEqual(pathprobe.target_tcp_evidence("", None, 1.0, checker),
                         "unreachable")


def _contrast_meta(target_reason="", gateway_loss=0.0, target_loss=100.0):
    """构造一份「有方向类 finding + 两侧探针」的最小 meta。"""
    return {
        "probe_baseline": {
            "sent": 16, "recv": 8, "timeout": 8,
            "roles": [
                {"role": "gateway", "kind": "icmp", "target": "192.168.1.1",
                 "sent": 8, "recv": 8, "n": 8, "loss_pct": gateway_loss,
                 "reason": "ok" if gateway_loss < 100 else "timeout"},
                {"role": "target", "kind": "icmp", "target": "1.2.3.4",
                 "sent": 8, "recv": 0, "n": 0, "loss_pct": target_loss,
                 "reason": target_reason},
            ],
        },
    }


#: 一条「传输质量」警告行（verdict 只有存在方向类 finding 时才做对照）。
TRANSPORT_ROW = {"severity": "警告", "layer": "L4 传输层", "protocol": "TCP",
                 "category": "传输质量", "finding": "重传率 3.06%"}


class VerdictContrastTest(unittest.TestCase):
    """判定层：ICMP 被过滤时不得判「对端侧丢包」，更不能判承载网。"""

    def test_filtered_target_is_not_target_side_loss(self):
        meta = _contrast_meta(target_reason="icmp_filtered")
        got = verdict._probe_contrast(meta, [TRANSPORT_ROW])
        self.assertIsNotNone(got)
        self.assertEqual(got["code"], "PROBE.CONTRAST.ICMP_FILTERED")
        self.assertEqual(got["target_reason"], "icmp_filtered")

    def test_filtered_target_still_carries_loss_for_display(self):
        """数值不改：报告要能显示「发出 8 / 收到 0」，只是旁边注明口径。"""
        meta = _contrast_meta(target_reason="icmp_filtered")
        got = verdict._probe_contrast(meta, [TRANSPORT_ROW])
        self.assertEqual(got["target_loss_pct"], 100.0)

    def test_gateway_loss_wins_over_filtered_target(self):
        """网关自己也在丢包：本地/接入侧证据成立，不能被目标免疫带偏。"""
        meta = _contrast_meta(target_reason="icmp_filtered", gateway_loss=60.0)
        got = verdict._probe_contrast(meta, [TRANSPORT_ROW])
        self.assertEqual(got["code"], "PROBE.CONTRAST.LOCAL_SIDE")

    def test_plain_timeout_target_is_still_target_side(self):
        """没有 TCP 旁证的全丢仍然是「对端侧丢包」—— 不许拿新规则开脱真故障。"""
        meta = _contrast_meta(target_reason="timeout")
        got = verdict._probe_contrast(meta, [TRANSPORT_ROW])
        self.assertEqual(got["code"], "PROBE.CONTRAST.TARGET_SIDE")

    def test_no_transport_finding_no_contrast(self):
        """没有方向类 finding 时不产生对照（与无探针时逐字节一致）。"""
        meta = _contrast_meta(target_reason="icmp_filtered")
        self.assertIsNone(verdict._probe_contrast(meta, []))


class ReportWordingTest(unittest.TestCase):
    """md 报告：丢包率旁注明口径，且不改数值。"""

    def _md(self, reason):
        baseline = pathprobe.apply_tcp_evidence(
            {"sent": 8, "recv": 0, "timeout": 8, "excluded_packets": 0,
             "roles": [{"role": "target", "kind": "icmp", "target": "1.2.3.4",
                        "sent": 8, "recv": 0, "n": 0, "loss_pct": 100.0}]},
            {"target": "ok"} if reason == "icmp_filtered" else {})
        vd = {"headline": "x", "probe_contrast": {
            "code": "PROBE.CONTRAST.ICMP_FILTERED", "confidence": 0.5,
            "gateway_loss_pct": 0.0, "target_loss_pct": 100.0,
            "gateway_n": 8, "target_n": 0, "target_reason": reason}}
        return "\n".join(report._render_probe_baseline(baseline, vd))

    def test_loss_cell_has_reason_suffix(self):
        md = self._md("icmp_filtered")
        self.assertIn("100%（ICMP 被过滤）", md)
        self.assertIn("目标不响应 ICMP", md)
        self.assertIn("以 TCP", md)

    def test_timeout_role_keeps_plain_loss(self):
        md = self._md("timeout")
        self.assertIn("100%", md)
        self.assertNotIn("ICMP 被过滤", md)

    def test_path_profile_wording_for_filtered_target(self):
        profile = {"target": "www.baidu.com", "target_ip": "1.2.3.4",
                   "verdict_key": pathprobe.PATH_ICMP_FILTERED,
                   "target_icmp_filtered": True, "method": "icmp",
                   "probes_sent": 25, "hops": [
                       {"ttl": 4, "ip": "", "sent": 5, "lost": 5, "loss_pct": 100.0,
                        "rtt_n": 0, "status": "filtered", "reason": "icmp_filtered"},
                   ]}
        md = "\n".join(report._render_path_profile(profile))
        self.assertIn("目标不响应 ICMP", md)
        self.assertIn("以 TCP 指标为准", md)
        self.assertIn("被过滤", md)
        self.assertNotIn("承载网", md)


class AgentReasonTest(unittest.TestCase):
    """常驻采集：样本里的 ``reason`` 必须能区分「被过滤」与「真丢」。"""

    def setUp(self):
        import agent as agent_mod
        self.agent = agent_mod

    def test_icmp_all_lost_tcp_ok_marks_filtered(self):
        icmp = {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                "method": "icmp", "ok": False, "reason": "timeout"}
        tcp = {"rtt_ms": 27.7, "loss_pct": 0.0, "jitter_ms": 1.2,
               "method": "tcp", "ok": True, "port": 443, "reason": "ok"}
        from unittest import mock
        with mock.patch.object(self.agent, "measure_icmp", return_value=dict(icmp)), \
                mock.patch.object(self.agent, "measure_tcp", return_value=dict(tcp)):
            out = self.agent.probe_endpoint("t", "www.baidu.com")
        self.assertEqual(out["reason"], "icmp_filtered")
        self.assertEqual(out["icmp_loss_pct"], 100.0)   # 原始事实保留
        self.assertEqual(out["rtt_ms"], 27.7)           # RTT 用 TCP 的，不是 0

    def test_icmp_all_lost_without_tcp_stays_timeout(self):
        icmp = {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                "method": "icmp", "ok": False, "reason": "timeout"}
        tcp = {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
               "method": "tcp", "ok": False, "reason": "timeout"}
        from unittest import mock
        with mock.patch.object(self.agent, "measure_icmp", return_value=dict(icmp)), \
                mock.patch.object(self.agent, "measure_tcp", return_value=dict(tcp)):
            out = self.agent.probe_endpoint("t", "www.baidu.com")
        self.assertEqual(out["reason"], "timeout")

    def test_measure_icmp_partial_loss_reason_ok(self):
        stats = {"ok": True, "avg_ms": 12.0, "loss_pct": 50.0, "jitter_ms": 2.0}
        from unittest import mock
        with mock.patch.object(self.agent, "resolve_ip", return_value="1.2.3.4"), \
                mock.patch.object(self.agent.winapi, "icmp_stats", return_value=stats):
            out = self.agent.measure_icmp("a.com", count=2)
        self.assertEqual(out["reason"], "ok")

    def test_measure_tcp_refused_is_refused(self):
        from unittest import mock
        with mock.patch.object(self.agent, "_connect_ms",
                               return_value=(None, "ConnectionRefusedError: 10061")):
            out = self.agent.measure_tcp("1.1.1.1", 443, count=1)
        self.assertEqual(out["reason"], "refused")
        self.assertEqual(out["loss_pct"], 100.0)


class UiWordingTest(unittest.TestCase):
    """前端文案与判定：不得再把「目标不回 ICMP」算成中途丢包。"""

    def _js(self, name):
        return (ROOT / "ui" / "v2" / "js" / name).read_text(encoding="utf-8")

    def test_first_loss_skips_filtered_hops(self):
        js = self._js("verdict.js")
        self.assertIn('.reason === "icmp_filtered"', js)
        self.assertIn('h.status === "filtered"', js)

    def test_blame_has_icmp_filtered_branch(self):
        js = self._js("verdict.js")
        self.assertIn('kind: "icmpFiltered"', js)
        # TCP 侧同时异常时仍按链路判（不能被目标免疫带偏）
        self.assertIn("tcpBad(meta)", js)

    def test_copy_has_icmp_filtered_texts(self):
        js = self._js("copy.js")
        for key in ("icmpFiltered", "probeRoleFiltered", "hopFiltered",
                    "reasonIcmpFiltered"):
            self.assertIn(key, js, key)
        self.assertIn("目标不响应 ICMP（常见于服务器侧策略），本次以 TCP 指标为准", js)


if __name__ == "__main__":
    unittest.main(verbosity=2)