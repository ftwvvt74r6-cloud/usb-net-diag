"""骨架自检。

覆盖 5 组（对应 docs/plan-review.md 里最该先做的几件事）：

1. 契约校验（rule_id 形态、推断必须带置信度）；
2. L4 规则的**方向判定**与**零窗口归属**（规划第 5 步的两处修正）；
3. 证据充分性闸门（P0-4）；
4. 出口脱敏（P0-3）；
5. JobStore / 路由 / 渲染（API 与报告的可运维性）。

设计约束：**不依赖 tshark、不联网、不写仓库目录**（临时目录一律 tempfile）。
运行::

    cd scaffold
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from core.api.app import create_app
from core.api.jobs import JobStore
from core.contracts import (
    AnalyzeResult,
    CaptureMeta,
    Category,
    DirStat,
    Direction,
    Endpoint,
    EvidenceKind,
    Features,
    Finding,
    JobState,
    Layer,
    Provenance,
    Severity,
    Stats,
    StreamStat,
    TcpFeatures,
)
from core.egress import sanitize as sz
from core.extract.fields import FIELDS, Record, parse_line
from core.render import json_report, markdown
from core.render.text import CopyTable
from core.rules import base as rbase
from core.rules import l4
from core.verdict import assess_sufficiency
from core.verdict import build as build_verdict

THRESHOLDS_RAW = {
    "_meta": {"rules_version": "test"},
    "l2": {"arp": {"min_requests": 2}},
    "l3": {"rtt": {"warning_ms": 300, "critical_ms": 600, "jitter_warning_ms": 80,
                   "min_samples": 5}},
    "l4": {"retrans": {"info": 0.5, "warning": 2.0, "critical": 5.0},
           "zero_window": {"warning_count": 3}},
    "l7": {"dns_fail": {"warning": 20.0, "critical": 50.0}},
}


def make_features(*, retrans_rate: float = 0.0, retr_c: int = 0, retr_s: int = 0,
                  dup_c: int = 0, dup_s: int = 0, zero_c: int = 0, zero_s: int = 0,
                  duration: float = 30.0, packets: int = 120) -> Features:
    """构造一份「健康但可调」的特征集，避免每个用例重复拼装。"""
    c2s = DirStat(Direction.C2S, packets=60, bytes=8000, retrans=retr_c,
                  dup_ack=dup_c, zero_win=zero_c, syn=1,
                  rtt=Stats(n=10, avg=40.0, p95=60.0, max=80.0, jitter=8.0))
    s2c = DirStat(Direction.S2C, packets=60, bytes=40000, retrans=retr_s,
                  dup_ack=dup_s, zero_win=zero_s,
                  rtt=Stats(n=10, avg=42.0, p95=61.0, max=85.0, jitter=9.0))
    stream = StreamStat(
        stream="3",
        client=Endpoint("192.168.1.100", 51234, kind="client"),
        server=Endpoint("10.0.0.5", 8080, kind="server"),
        app_hint="HTTP", packets=120, bytes=48000, handshake_ms=25.0,
        frames=(11, 12, 13), dirs={Direction.C2S: c2s, Direction.S2C: s2c},
    )
    # 另外两条「干净会话」：让样本量达到充分性门槛（>=3 条），
    # 这样「健康抓包」用例才真的会判 OK 而不是「证据不足」。
    extra = tuple(
        StreamStat(
            stream=sid,
            client=Endpoint("192.168.1.100", 50000 + i, kind="client"),
            server=Endpoint("10.0.0.9", 443, kind="server"),
            app_hint="TLS", packets=20, bytes=4000, handshake_ms=18.0,
            frames=(30 + i,), dirs={
                Direction.C2S: DirStat(Direction.C2S, packets=10, bytes=800,
                                       rtt=Stats(n=3, avg=38.0)),
                Direction.S2C: DirStat(Direction.S2C, packets=10, bytes=3200,
                                       rtt=Stats(n=3, avg=39.0)),
            },
        )
        for i, sid in enumerate(("4", "5"))
    )
    tcp = TcpFeatures(
        packets=packets, bytes=48000, streams=(stream, *extra),
        retrans_rate=retrans_rate,
        rtt=Stats(n=20, avg=41.0, p95=60.0, max=85.0, jitter=8.5),
        handshake=Stats(n=1, avg=25.0, p95=25.0, max=25.0, jitter=0.0),
        dir_totals={"c2s": c2s, "s2c": s2c},
    )
    cap = CaptureMeta(mode="live", pcap_name="t.pcap", packets=packets,
                      duration_s=duration, interface="以太网")
    return Features(
        capture=cap, tcp=tcp,
        dns={"samples": 6, "queries": 6, "responses": 6, "fail_rate": 0.0, "avg_ms": 60.0},
        http={"requests": 3, "err5": 0},
        arp={"no_reply": []},
        icmp={"unreach": 0, "timeout": 0},
        missing=frozenset(),
    )


def rule_ctx(features: Features) -> rbase.RuleContext:
    return rbase.RuleContext(features=features,
                            thresholds=rbase.Thresholds.from_dict(THRESHOLDS_RAW))


def run_one(rule_id: str, features: Features) -> rbase.RuleRun:
    rule = next(r for r in l4.RULES if r.id == rule_id)
    return rbase.run_rules([rule], rule_ctx(features))


# ---------------------------------------------------------------- 1. 契约


class ContractTests(unittest.TestCase):
    def test_rule_id_form_is_enforced(self):
        with self.assertRaises(ValueError):
            Finding(rule_id="bad rule id", layer=Layer.L4,
                    severity=Severity.WARNING, category=Category.TRANSPORT)

    def test_inferred_must_be_below_certainty(self):
        with self.assertRaises(ValueError):
            Finding(rule_id="L4.RETRANS.HIGH", layer=Layer.L4,
                    severity=Severity.WARNING, category=Category.TRANSPORT,
                    evidence_kind=EvidenceKind.INFERRED, confidence=1.0)

    def test_stats_never_pretend_zero_samples(self):
        empty = Stats.from_values([])
        self.assertFalse(empty.has_sample)
        self.assertEqual(empty.n, 0)
        self.assertEqual(Stats.from_values([10, 20, 30]).avg, 20.0)


# ---------------------------------------------------------------- 2. L4 方向


class L4DirectionTests(unittest.TestCase):
    def test_client_retrans_plus_server_dup_ack_means_upstream(self):
        """客户端重传 + 服务端 dup-ACK = 服务端见到后续包、缺一段 = 上行丢包。"""
        result = run_one("L4.RETRANS.HIGH", make_features(
            retrans_rate=6.0, retr_c=6, dup_s=4))
        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(f.direction, Direction.C2S)
        self.assertEqual(f.evidence_kind, EvidenceKind.INFERRED)
        self.assertLess(f.confidence, 1.0)
        self.assertEqual(f.metric["c2s_retrans"], 6)
        self.assertEqual(f.metric["s2c_dup_ack"], 4)
        self.assertEqual(f.targets[0].ip, "10.0.0.5")

    def test_server_retrans_plus_client_dup_ack_means_downstream(self):
        result = run_one("L4.RETRANS.HIGH", make_features(
            retrans_rate=7.5, retr_s=9, dup_c=5))
        f = result.findings[0]
        self.assertEqual(f.direction, Direction.S2C)
        self.assertTrue(f.advice_key.endswith(".DOWN"))

    def test_retrans_without_dup_ack_is_low_confidence(self):
        """只有重传、没有 dup-ACK：方向不定，必须降置信度，不许下确定结论。"""
        f = run_one("L4.RETRANS.HIGH", make_features(
            retrans_rate=6.0, retr_c=6)).findings[0]
        self.assertIsNone(f.direction)
        self.assertLessEqual(f.confidence, 0.4)

    def test_below_threshold_emits_nothing(self):
        result = run_one("L4.RETRANS.HIGH", make_features(retrans_rate=0.1))
        self.assertEqual(result.findings, [])


class L4ZeroWindowTests(unittest.TestCase):
    def test_client_advertised_zero_window_blames_client(self):
        """客户端通告零窗口 → 客户端下载侧消费不过来 → 客户端瓶颈（不是服务端）。"""
        f = run_one("L4.ZEROWIN.SIDE", make_features(zero_c=3)).findings[0]
        self.assertEqual(f.rule_id, "L4.ZEROWIN.CLIENT")
        self.assertEqual(f.metric["advertised_by"], "client")
        self.assertEqual(f.metric["bottleneck_side"], "client")
        # 受影响的是「服务端→客户端」的数据流
        self.assertEqual(f.direction, Direction.S2C)

    def test_server_advertised_zero_window_blames_server(self):
        f = run_one("L4.ZEROWIN.SIDE", make_features(zero_s=4)).findings[0]
        self.assertEqual(f.rule_id, "L4.ZEROWIN.SERVER")
        self.assertEqual(f.metric["bottleneck_side"], "server")
        self.assertEqual(f.direction, Direction.C2S)


# ---------------------------------------------------------------- 3. 充分性


class SufficiencyTests(unittest.TestCase):
    def test_short_capture_is_not_judged_normal(self):
        features = make_features(duration=3.0, packets=8)
        suff = assess_sufficiency(features, {"sufficiency": {"min_duration_s": 10}})
        self.assertFalse(suff.ok)
        self.assertIn("duration_too_short", suff.reasons)
        self.assertEqual(suff.reason_args["duration_too_short"]["actual"], 3.0)

        verdict = build_verdict(features, (), cfg={"sufficiency": {"min_duration_s": 10}})
        self.assertEqual(verdict.level, Severity.NA)
        self.assertEqual(verdict.headline_key, "VERDICT.INSUFFICIENT")

    def test_empty_capture_is_explicit(self):
        features = make_features(packets=0, duration=0.0)
        verdict = build_verdict(features, ())
        self.assertEqual(verdict.headline_key, "VERDICT.EMPTY")

    def test_healthy_capture_is_ok(self):
        verdict = build_verdict(make_features(), ())
        self.assertEqual(verdict.level, Severity.OK)
        self.assertEqual(verdict.headline_key, "VERDICT.OK")


# ---------------------------------------------------------------- 4. verdict


class VerdictTests(unittest.TestCase):
    def _finding(self, rule_id: str, layer: Layer, severity: Severity) -> Finding:
        return Finding(rule_id=rule_id, layer=layer, severity=severity,
                       category=Category.TRANSPORT,
                       metric={"detail": "x"}, confidence=1.0)

    def test_lower_layer_wins_on_tie(self):
        findings = (self._finding("L7.HTTP.5XX", Layer.L7, Severity.WARNING),
                    self._finding("L2.ARP.NO_REPLY", Layer.L2, Severity.WARNING))
        verdict = build_verdict(make_features(), rbase.sort_findings(findings))
        self.assertEqual(verdict.headline_key, "headline.L2.ARP.NO_REPLY")
        self.assertEqual(verdict.level, Severity.WARNING)

    def test_higher_severity_beats_layer(self):
        findings = (self._finding("L2.ARP.NO_REPLY", Layer.L2, Severity.WARNING),
                    self._finding("L4.RETRANS.HIGH", Layer.L4, Severity.CRITICAL))
        verdict = build_verdict(make_features(), rbase.sort_findings(findings))
        self.assertEqual(verdict.level, Severity.CRITICAL)
        self.assertEqual(verdict.headline_key, "headline.L4.RETRANS.HIGH")

    def test_untested_layer_is_na_not_ok(self):
        features = make_features()
        features.dns = {}
        features.http = {}
        verdict = build_verdict(features, ())
        l7 = next(x for x in verdict.layers if x.layer is Layer.L7)
        self.assertEqual(l7.severity, Severity.NA)


# ---------------------------------------------------------------- 5. 脱敏


class SanitizeTests(unittest.TestCase):
    PAYLOAD = {
        "streams": [{"client": "192.168.1.100:51234", "server": "93.184.216.40:443"}],
        "http": {"uri": "https://app.corp.example.com/login?password=Abc123&user=zhang"},
        "headers": {"Authorization": "Bearer sk-live-abcdef123456"},
        "capture": {"pcap_name": "diag_20261006_120000.pcapng"},
    }

    def test_cloud_profile_masks_identifiers_but_keeps_shape(self):
        safe, ledger = sz.sanitize(self.PAYLOAD, sz.Profile.CLOUD_MASK)
        blob = json.dumps(safe, ensure_ascii=False)

        self.assertNotIn("192.168.1.100", blob)
        self.assertNotIn("93.184.216.40", blob)
        self.assertNotIn("Abc123", blob)
        self.assertNotIn("sk-live-abcdef123456", blob)
        self.assertNotIn("app.corp.example.com", blob)

        # —— 这些必须保留，否则报告就废了 ——
        self.assertIn(":51234", blob)          # 端口保留
        self.assertIn("example.com", blob)     # 域名后缀保留
        self.assertIn("pcapng", blob)          # 文件名不当成域名抹掉
        self.assertIn("[REDACTED]", blob)
        self.assertGreater(ledger.count, 0)
        self.assertEqual(sz.verify(safe, ["192.168.1.100", "Abc123"]), [])

    def test_local_profile_keeps_ip_for_troubleshooting(self):
        safe, _ = sz.sanitize(self.PAYLOAD, sz.Profile.LOCAL)
        blob = json.dumps(safe, ensure_ascii=False)
        self.assertIn("192.168.1.100", blob)      # 本地排障需要
        self.assertNotIn("Abc123", blob)          # 但口令永远不外露

    def test_lan_profile_masks_private_only(self):
        safe, _ = sz.sanitize(self.PAYLOAD, sz.Profile.LAN_MASK)
        blob = json.dumps(safe, ensure_ascii=False)
        self.assertNotIn("192.168.1.100", blob)
        self.assertIn("93.184.216.40", blob)      # 公网地址保留（威胁情报要用）

    def test_verify_reports_leak(self):
        self.assertEqual(sz.verify({"a": "192.168.1.9"}, ["192.168.1.9"]), ["192.168.1.9"])


# ---------------------------------------------------------------- 6. 解析积木


class ExtractTests(unittest.TestCase):
    def _line(self, **values) -> str:
        return "|".join(str(values.get(f, "")) for f in FIELDS)

    def test_parse_line_and_direction(self):
        line = self._line(**{
            "frame.number": "42",
            "frame.time_epoch": "1712345678.5",
            "frame.len": "120",
            "ip.src": "192.168.1.100",
            "ip.dst": "10.0.0.5",
            "tcp.srcport": "51234",
            "tcp.dstport": "8080",
            "tcp.stream": "3",
            "tcp.len": "60",
            "tcp.analysis.ack_rtt": "0.023",
            "tcp.analysis.retransmission": "1",
        })
        rec = parse_line(line)
        self.assertEqual(rec.frame, 42)
        self.assertEqual(rec.sport, 51234)
        self.assertTrue(rec.retrans)
        self.assertAlmostEqual(rec.rtt_ms, 23.0, places=3)
        self.assertEqual(rec.direction("192.168.1.100"), Direction.C2S)
        self.assertEqual(rec.direction("10.0.0.5"), Direction.S2C)

    def test_syn_retransmission_is_not_counted_as_packet_loss(self):
        counters = __import__("core.extract.aggregate", fromlist=["DirCounters"]).DirCounters(
            Direction.C2S)
        counters.add(Record(syn=True, retrans=True, length=60))
        counters.add(Record(retrans=True, length=100))
        stat = counters.to_stat()
        self.assertEqual(stat.syn, 1)
        self.assertEqual(stat.retrans, 1)      # SYN 重发不算丢包
        self.assertEqual(stat.packets, 2)


# ---------------------------------------------------------------- 7. 任务 / API


class JobStoreTests(unittest.TestCase):
    def test_state_machine_and_logs(self):
        store = JobStore()
        job = store.submit("demo", lambda stop, log: (log("working"), 42)[1])
        done = store.wait(job.job_id, timeout=5)
        self.assertEqual(done.state, JobState.DONE)
        self.assertEqual(done.result, 42)
        self.assertTrue(store.logs(job.job_id))
        self.assertTrue(store.snapshot(job.job_id)["has_result"])

    def test_cancel_is_cooperative(self):
        store = JobStore()

        def slow(stop, log):
            for _ in range(300):
                if stop():
                    return "stopped"
                time.sleep(0.005)
            return "timeout"

        job = store.submit("slow", slow)
        time.sleep(0.05)
        self.assertTrue(store.cancel(job.job_id))
        done = store.wait(job.job_id, timeout=5)
        self.assertEqual(done.state, JobState.CANCELLED)

    def test_concurrency_limit(self):
        store = JobStore(max_concurrent=1)
        store.submit("blocker", lambda stop, log: time.sleep(0.3))
        with self.assertRaises(Exception) as ctx:
            store.submit("second", lambda stop, log: None)
        code = getattr(ctx.exception, "code", None)
        self.assertEqual(getattr(code, "value", str(code)), "E_JOB_BUSY")


class ApiTests(unittest.TestCase):
    def test_envelope_and_404(self):
        app = create_app()
        status, env = app.dispatch("GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(env["ok"])
        self.assertEqual(env["schema_version"], "2.0")

        status, env = app.dispatch("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertFalse(env["ok"])
        self.assertEqual(env["error"]["code"], "E_BAD_PARAM")

    def test_unimplemented_route_returns_structured_error(self):
        status, env = create_app().dispatch("GET", "/api/doctor")
        self.assertEqual(status, 501)
        self.assertEqual(env["error"]["code"], "E_NOT_IMPLEMENTED")


# ---------------------------------------------------------------- 8. 渲染


class RenderTests(unittest.TestCase):
    def _result(self) -> AnalyzeResult:
        features = make_features(retrans_rate=6.0, retr_c=6, dup_s=4)
        findings = run_one("L4.RETRANS.HIGH", features).findings
        verdict = build_verdict(features, findings)
        return AnalyzeResult(
            capture=features.capture, features=features,
            findings=tuple(findings), metrics={"retrans_rate": 6.0, "rtt_avg_ms": 41.0},
            verdict=verdict,
            provenance=Provenance(app_version="0.1.0", rules_version="test",
                                  config_sha256="deadbeef", generated_at="2026-11-06 12:00:00"),
        )

    def test_markdown_renders_without_inline_chinese_in_rules(self):
        md = markdown.render(self._result(), CopyTable.load())
        self.assertIn("网络故障诊断报告", md)
        self.assertIn("L4 传输层", md)
        self.assertIn("疑似上行丢包", md)

    def test_report_files_never_overwrite(self):
        result = self._result()
        # 临时目录放在 tests/ 下：U 盘/沙箱环境下系统 TEMP 可能不可写
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            first = json_report.save(result, tmp)
            second = json_report.save(result, tmp)
            self.assertNotEqual(first["json"], second["json"])
            self.assertTrue(Path(first["json"]).is_file())
            self.assertTrue(Path(second["markdown"]).is_file())

    def test_normalize_strips_volatile_fields_for_snapshot(self):
        doc = json_report.to_document(self._result())
        norm = json_report.normalize(doc)
        self.assertNotIn("generated_at", norm["provenance"])
        self.assertIn("findings", norm)


if __name__ == "__main__":
    unittest.main(verbosity=2)
