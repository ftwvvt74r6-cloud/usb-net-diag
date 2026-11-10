"""R6-5 / R8-1 / R8-2 回归测试（fix/backend-polish）。

**R6-5 —— 离线分析的 meta 契约**

S3 报告指出：离线分析时 ``meta.interface = "-"``、``meta.bpf = "分析抓包文件"``，
两个字段塞的都不是各自该有的东西（网卡是「-」，过滤器是模式文案）。后果是每个
消费方都得自己猜「哪些值是垃圾」：AI prompt 打印「网卡 -，过滤器 分析抓包文件」、
UI 的过滤器一栏点不动也删不掉。

修法是**修根**，不是在出口擦：

* 离线分析时 ``meta.interface`` / ``meta.bpf`` 一律空串 —— 空串就是「本模式不适用」；
* 模式由独立字段 ``meta.capture_mode`` 承载，取值 ``live`` / ``offline`` / ``passive``；
* 判定侧 ``verdict._is_offline()`` **只认 capture_mode**，不再看 ``bpf`` 的取值；
  旧报告（只有 ``bpf``）仍兼容，否则历史数据会被当成在线抓包，给出
  「换一块网卡再抓」这种做不到的建议。

人读的 Markdown 不能留空白，所以展示层统一回落（``verdict.display_capture_fields``）：
网卡空 → ``-``，过滤器空且离线 → 仍显示模式名。这也保证 ``reports/`` 里的 md 逐字节不变。

**R8-1 —— 按报文数的 L7 分布**

前端「应用层分布」是拿 ``meta.streams_top`` 数**会话数**，看不出流量结构：10 个 TLS
小流（各 2 包）+ 1 个 HTTP 大流（2000 包）按会话数是「TLS 91%」，按报文数才是
「HTTP 99%」。后端补 ``result["l7_packets"]``（按报文数），与前端口径**并存**。

它放在**结果顶层**而不是 ``meta``：报告只落 summary/meta/metrics/rows/verdict 五块，
所以它只随 API（``/api/status``、``/api/last-run``、``/api/last-run/result``）下发，
不写进 ``reports/``，快照不受影响 —— 与 ``server.link_actions`` 的加法字段同一口径。

**R8-2 —— dns_resp 反超 dns_total**

DNS 一问一答，``dns_resp`` 不该大于 ``dns_total``。反超只有两种来源：抓包中途被截断
（查询/响应统计窗口不一致）或响应被重复计数。此时下游若直接相除，会得到负数失败率或
>100% 的响应率 —— 都是看不出来的错数。所以在源头打 ``meta.dns_truncated``。

**只在成立时加键**：未触发不写该字段，因此既有报告快照逐字节不变（与
``probe_baseline`` / ``path_profile`` 的「有数据才注入」同一口径）。
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import analyzer      # noqa: E402
import diagnose      # noqa: E402
import logstore      # noqa: E402
import report        # noqa: E402
import server        # noqa: E402
import verdict       # noqa: E402

SAMPLE = ROOT / "captures" / "faults_demo.pcap"

#: 被 patch 掉 analyze 时返回的最小可用结果：只填 _run_scan 会读的键。
FAKE_RESULT = {
    "ok": True,
    "meta": {"packets": 5, "tcp_packets": 2},
    "metrics": {},
    "rows": [],
    "summary": {"critical_count": 0, "warning_count": 0},
}


def _fake_analyze(*_args, **_kwargs) -> dict:
    """替身：不跑 tshark，返回一份新拷贝（避免用例之间互相污染）。"""
    return json.loads(json.dumps(FAKE_RESULT))


class _RunScanBase(unittest.TestCase):
    """``_run_scan`` 会真的写报告，所以统一把输出目录指到临时目录。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="netdiag_polish_")
        self.out = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self._save = mock.patch.object(
            report, "save", side_effect=lambda result, out_dir: {
                "markdown": str(Path(out_dir) / "x.md"),
                "json": str(Path(out_dir) / "x.json")})
        self._save.start()
        self.addCleanup(self._save.stop)
        self._analyze = mock.patch.object(analyzer, "analyze", side_effect=_fake_analyze)
        self._analyze.start()
        self.addCleanup(self._analyze.stop)

    def _offline(self) -> dict:
        return diagnose._run_scan(pcap=str(SAMPLE), logger=lambda _m: None,
                                  report_dir=self.out)


class OfflineCaptureMetaTest(_RunScanBase):
    """R6-5：离线分析的 interface / bpf 置空，模式由 capture_mode 承载。"""

    def test_offline_meta_interface_and_bpf_are_empty(self):
        meta = self._offline()["meta"]
        self.assertEqual(meta["interface"], "", "离线分析没有网卡，必须是空串")
        self.assertEqual(meta["bpf"], "", "离线分析没有 BPF 过滤器，必须是空串")

    def test_offline_meta_never_carries_mode_copy(self):
        """核心断言：这两个字段不得等于任何模式文案 / 占位符。"""
        meta = self._offline()["meta"]
        forbidden = {verdict.OFFLINE_BPF, "离线分析", "-", "分析抓包文件"}
        self.assertNotIn(meta["interface"], forbidden)
        self.assertNotIn(meta["bpf"], forbidden)

    def test_offline_sets_capture_mode(self):
        meta = self._offline()["meta"]
        self.assertEqual(meta["capture_mode"], verdict.CAPTURE_MODE_OFFLINE)
        self.assertIn(meta["capture_mode"], verdict.CAPTURE_MODES)

    def test_capture_mode_is_machine_readable(self):
        """契约取值固定为三个小写英文串，不许变成中文文案。"""
        self.assertEqual(verdict.CAPTURE_MODES, ("live", "offline", "passive"))

    def test_live_keeps_interface_and_bpf(self):
        """实时抓包：网卡与过滤器是真实值，不许被 R6-5 顺手清掉。"""
        cap = {"ok": True, "pcap": str(SAMPLE), "interface": "以太网",
               "interface_index": 3, "bpf": "host 192.0.2.1", "duration": 5}
        with mock.patch.object(diagnose, "capture_live", return_value=cap):
            result = diagnose._run_scan(target="192.0.2.1", duration=5,
                                        logger=lambda _m: None,
                                        report_dir=self.out)
        meta = result["meta"]
        self.assertEqual(meta["capture_mode"], verdict.CAPTURE_MODE_LIVE)
        self.assertEqual(meta["interface"], "以太网")
        self.assertEqual(meta["bpf"], "host 192.0.2.1")
        self.assertNotEqual(meta["bpf"], verdict.OFFLINE_BPF)


class IsOfflineTest(unittest.TestCase):
    """R6-5：离线判据只看 capture_mode，旧 bpf 取值仍兼容。"""

    def test_capture_mode_offline(self):
        self.assertTrue(verdict._is_offline({"capture_mode": "offline"}))

    def test_capture_mode_live_wins_over_legacy_bpf(self):
        """capture_mode 存在时以它为准，即使 bpf 里还残留旧模式文案。"""
        self.assertFalse(verdict._is_offline(
            {"capture_mode": "live", "bpf": verdict.OFFLINE_BPF}))

    def test_legacy_bpf_still_recognized(self):
        """历史报告没有 capture_mode，靠 bpf 仍然要判成离线。"""
        self.assertTrue(verdict._is_offline({"bpf": verdict.OFFLINE_BPF}))
        self.assertTrue(verdict._is_offline({"bpf": "离线分析"}))

    def test_real_bpf_is_not_offline(self):
        self.assertFalse(verdict._is_offline({"bpf": "无（全网）"}))
        self.assertFalse(verdict._is_offline({}))


class DisplayCaptureFieldsTest(unittest.TestCase):
    """R6-5 展示层回落：契约空串 → 人读文案，保证 md 逐字节不变。"""

    def test_offline_empty_shows_mode_name(self):
        iface, bpf = verdict.display_capture_fields(
            {"interface": "", "bpf": "", "capture_mode": "offline"})
        self.assertEqual(iface, "-")
        self.assertEqual(bpf, verdict.OFFLINE_BPF)

    def test_empty_without_mode_falls_back_to_dash(self):
        iface, bpf = verdict.display_capture_fields({})
        self.assertEqual((iface, bpf), ("-", "-"))

    def test_live_values_pass_through(self):
        iface, bpf = verdict.display_capture_fields(
            {"interface": "以太网", "bpf": "tcp port 443", "capture_mode": "live"})
        self.assertEqual((iface, bpf), ("以太网", "tcp port 443"))


class L7PacketsTest(unittest.TestCase):
    """R8-1：按报文数的 L7 分布。"""

    @staticmethod
    def _st(flows: list[tuple[str, int]]) -> dict:
        streams = {}
        for i, (app, packets) in enumerate(flows):
            streams[str(i)] = {"app": app, "packets": packets}
        return {"streams": streams}

    def test_buckets_by_packet_count(self):
        got = analyzer._l7_packets(self._st([("TLS", 2), ("TLS", 2), ("HTTP", 2000)]))
        self.assertEqual(got["basis"], "packets")
        self.assertEqual(got["total_packets"], 2004)
        by_key = {b["key"]: b for b in got["buckets"]}
        self.assertEqual(by_key["http"]["packets"], 2000)
        self.assertEqual(by_key["tls"]["packets"], 4)
        self.assertEqual(by_key["other"]["packets"], 0)
        self.assertEqual(by_key["http"]["pct"], 99.8)

    def test_unknown_app_goes_to_other(self):
        got = analyzer._l7_packets(self._st([("SSH", 10), ("HTTP", 10)]))
        by_key = {b["key"]: b for b in got["buckets"]}
        self.assertEqual(by_key["other"]["packets"], 10)
        self.assertEqual(by_key["other"]["pct"], 50.0)

    def test_bucket_sum_equals_total(self):
        got = analyzer._l7_packets(self._st([("TLS", 7), ("HTTP", 5), ("TCP", 3)]))
        self.assertEqual(sum(b["packets"] for b in got["buckets"]), got["total_packets"])

    def test_app_match_is_case_insensitive(self):
        got = analyzer._l7_packets(self._st([("tls", 4)]))
        by_key = {b["key"]: b for b in got["buckets"]}
        self.assertEqual(by_key["tls"]["packets"], 4)

    def test_empty_streams_yield_zero(self):
        got = analyzer._l7_packets(self._st([]))
        self.assertEqual(got["total_packets"], 0)
        self.assertTrue(all(b["pct"] == 0.0 for b in got["buckets"]))

    def test_zero_packet_stream_is_ignored(self):
        """packets=0 的流不进分母，否则会产生 0/0 的伪桶。"""
        got = analyzer._l7_packets(self._st([("TLS", 0), ("TLS", 5)]))
        self.assertEqual(got["total_packets"], 5)


class L7RealAnalysisTest(unittest.TestCase):
    """R8-1 端到端：真实 pcap 的结果里有 l7_packets，但报告 JSON 里没有。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = analyzer.analyze(str(SAMPLE))

    def test_result_has_l7_packets(self):
        self.assertTrue(self.result.get("ok"))
        l7 = self.result.get("l7_packets")
        self.assertIsInstance(l7, dict)
        self.assertEqual(l7["basis"], "packets")
        self.assertEqual({b["key"] for b in l7["buckets"]}, {"tls", "http", "other"})
        self.assertEqual(sum(b["packets"] for b in l7["buckets"]), l7["total_packets"])

    def test_l7_is_not_written_into_report_json(self):
        """红线守卫：l7_packets 是 API 加法字段，不许进 reports/。"""
        with tempfile.TemporaryDirectory(prefix="netdiag_l7_") as tmp:
            paths = report.save(json.loads(json.dumps(self.result)), Path(tmp))
            payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        self.assertNotIn("l7_packets", payload)
        self.assertEqual(set(payload), {"summary", "meta", "metrics", "rows", "verdict"})


class DnsTruncatedTest(unittest.TestCase):
    """R8-2：dns_resp 反超 dns_total 时打标记，其余情况不加键。"""

    def test_resp_greater_than_total_marks_truncated(self):
        meta = {"dns_total": 3, "dns_resp": 5}
        self.assertTrue(analyzer._mark_dns_truncated(meta))
        self.assertIs(meta["dns_truncated"], True)

    def test_equal_does_not_add_key(self):
        meta = {"dns_total": 7, "dns_resp": 7}
        self.assertFalse(analyzer._mark_dns_truncated(meta))
        self.assertNotIn("dns_truncated", meta)

    def test_resp_less_than_total_does_not_add_key(self):
        meta = {"dns_total": 9, "dns_resp": 4}
        self.assertFalse(analyzer._mark_dns_truncated(meta))
        self.assertNotIn("dns_truncated", meta)

    def test_missing_keys_are_treated_as_zero(self):
        meta: dict = {}
        self.assertFalse(analyzer._mark_dns_truncated(meta))
        self.assertNotIn("dns_truncated", meta)

    def test_real_sample_is_not_truncated(self):
        result = analyzer.analyze(str(SAMPLE))
        self.assertNotIn("dns_truncated", result["meta"],
                         "demo 样本是一问一答，不该被误判成截断")


class LastRunL7Test(unittest.TestCase):
    """R8-1：``/api/last-run`` 把 l7_packets 作为加法字段带出去。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="netdiag_l7api_")
        cls._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(Path(cls._tmp.name) / "logs")})
        cls._env.start()
        cls._uicfg = mock.patch.object(
            server, "UI_VERSION_CONFIG",
            Path(cls._tmp.name) / "config" / "ui-version.json")
        cls._uicfg.start()
        cls.httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._uicfg.stop()
        cls._env.stop()
        cls._tmp.cleanup()

    def tearDown(self) -> None:
        with server.LOCK:
            server.LAST_RUN.update({"summary": {}, "result": None, "cleared_at": 0.0})

    def _get(self, path: str) -> dict:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return json.loads(resp.read().decode("utf-8"))
        finally:
            conn.close()

    def test_last_run_carries_l7_packets(self):
        l7 = {"basis": "packets", "total_packets": 10,
              "buckets": [{"key": "tls", "packets": 6, "pct": 60.0},
                          {"key": "http", "packets": 4, "pct": 40.0},
                          {"key": "other", "packets": 0, "pct": 0.0}],
              "complete": True}
        server._remember_last_run("offline", "demo", time.time(),
                                  {"ok": True, "l7_packets": l7,
                                   "summary": {"critical_count": 0, "warning_count": 0}})
        data = self._get("/api/last-run")
        self.assertTrue(data.get("ok"))
        self.assertEqual(data["last"]["l7_packets"], l7)

    def test_last_run_without_result_has_no_l7_key(self):
        data = self._get("/api/last-run")
        self.assertTrue(data.get("ok"))
        self.assertIsNone(data.get("last"))


if __name__ == "__main__":
    unittest.main()
