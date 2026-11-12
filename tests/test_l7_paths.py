"""P1 契约测试：``result.l7_packets`` 必须在**三条路径**上都在，且是前端读得懂的形状。

**为什么单独立一组**
--------------------
``l7_packets`` 曾经「后端有、前端读不到」：后端给的是嵌套口径
``{basis, total_packets, buckets:[{key,packets,pct}]}``，而
``ui/v2/js/metricstable.js`` 读的是扁平键 ``tls / http / other / total``。
两边都「没错」，合起来的效果却是**按报文数的分布永远不出现**，界面静默回退
「按会话数」—— 于是同一份结果里「HTTP 99%（报文）」这个结论谁也看不见。

这组用例钉三件事：

1. **形状**：扁平键与嵌套 buckets 同时存在、同源（同一次遍历），三桶之和 == ``total``；
2. **三条路径**：``scan``（全网体检）/ ``live``（单目标）/ ``offline``（解析抓包）
   的 ``result`` 顶层都带 ``l7_packets`` —— 走的是真 ``_run_scan``，只是把
   ``capture_live`` 换成回放一份真实 pcap（不联网、不开网卡）；
3. **不丢**：``/api/last-run/result`` 的那条链（``_attach_probe_ui_copy`` →
   ``build_status_conclusion`` → ``_attach_conclusion``）不许把该字段吃掉。

用 ``captures/faults_demo.pcap``：它是红线比对的同一份真实抓包，不额外造样本。
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import analyzer  # noqa: E402
import diagnose  # noqa: E402
import server  # noqa: E402
import tshark  # noqa: E402

DEMO = ROOT / "captures" / "faults_demo.pcap"

#: 前端 ``metricstable.js::l7Buckets`` 会挨个读的键。少一个就静默回退会话数。
FLAT_KEYS = ("ok", "tls", "http", "other", "total", "basis")


def _have_tools() -> bool:
    return DEMO.is_file() and tshark.find_tshark() is not None


SKIP_REAL = "需要真实 pcap 与 tshark：captures/faults_demo.pcap + Wireshark"


class L7ShapeTest(unittest.TestCase):
    """扁平口径与嵌套口径必须同源同值。"""

    @staticmethod
    def _st(flows):
        return {"streams": {str(i): {"app": app, "packets": n}
                            for i, (app, n) in enumerate(flows)}}

    def test_flat_keys_exist_and_are_ints(self):
        got = analyzer._l7_packets(self._st([("TLS", 22), ("HTTP", 7736), ("SSH", 8)]))
        for key in FLAT_KEYS:
            self.assertIn(key, got, f"前端要读 {key}，缺了就会回退会话数")
        self.assertEqual(got["basis"], "packets")
        self.assertIs(got["ok"], True)
        for key in ("tls", "http", "other", "total"):
            self.assertIsInstance(got[key], int, key)

    def test_flat_values_match_nested_buckets(self):
        got = analyzer._l7_packets(self._st([("TLS", 22), ("HTTP", 7736), ("SSH", 8)]))
        by_key = {b["key"]: b["packets"] for b in got["buckets"]}
        self.assertEqual({k: got[k] for k in ("tls", "http", "other")}, by_key)
        self.assertEqual(got["total"], got["total_packets"])
        self.assertEqual(got["total"], sum(by_key.values()))

    def test_empty_capture_is_not_ok(self):
        # 没有报文的抓包：ok=False，让前端去用会话数口径，而不是画一条 0% 的假分布
        got = analyzer._l7_packets(self._st([]))
        self.assertIs(got["ok"], False)
        self.assertEqual(got["total"], 0)
        self.assertEqual((got["tls"], got["http"], got["other"]), (0, 0, 0))

    def test_packet_basis_differs_from_session_basis(self):
        """这条是「为什么要按报文数」的存在理由，别在重构时被抹平。"""
        got = analyzer._l7_packets(self._st([("TLS", 2), ("TLS", 2), ("HTTP", 2000)]))
        by_key = {b["key"]: b for b in got["buckets"]}
        self.assertEqual(by_key["tls"]["pct"], 0.2)       # 会话数是 TLS 2/3 = 67%
        self.assertEqual(by_key["http"]["pct"], 99.8)


@unittest.skipUnless(_have_tools(), SKIP_REAL)
class L7ThreePathsTest(unittest.TestCase):
    """scan / live / offline 三条路径的 ``result`` 顶层都要有 l7_packets。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="netdiag_l7path_")
        self.out = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _live_capture(self, **cap):
        return {"ok": True, "pcap": str(DEMO), "interface": "以太网",
                "interface_index": 3, "bpf": "", "duration": 5, **cap}

    def _assert_l7(self, result: dict, mode: str) -> dict:
        self.assertTrue(result.get("ok"), result.get("error"))
        self.assertEqual((result.get("meta") or {}).get("capture_mode"), mode)
        l7 = result.get("l7_packets")
        self.assertIsInstance(l7, dict, "result 顶层没有 l7_packets")
        for key in FLAT_KEYS:
            self.assertIn(key, l7)
        self.assertEqual(l7["basis"], "packets")
        self.assertEqual(l7["total"], l7["tls"] + l7["http"] + l7["other"])
        self.assertEqual(l7["total"], l7["total_packets"])
        return l7

    def test_offline_path_has_l7_packets(self):
        result = diagnose._run_scan(pcap=str(DEMO), logger=lambda _m: None,
                                    report_dir=self.out)
        l7 = self._assert_l7(result, "offline")
        self.assertGreater(l7["total"], 0, "演示抓包里应当有 TCP 会话报文")

    def test_live_path_has_l7_packets(self):
        with mock.patch.object(diagnose, "capture_live",
                               return_value=self._live_capture()):
            result = diagnose._run_scan(target="192.0.2.1", duration=5,
                                        logger=lambda _m: None,
                                        report_dir=self.out, shadow=False)
        self._assert_l7(result, "live")

    def test_scan_path_has_l7_packets(self):
        # 全网体检：不带目标、抓全部流量（capture_live 换成回放同一份真实抓包）
        with mock.patch.object(diagnose, "capture_live",
                               return_value=self._live_capture()):
            result = diagnose._run_scan(target="", duration=5,
                                        logger=lambda _m: None,
                                        report_dir=self.out, shadow=False)
        self._assert_l7(result, "live")

    def test_last_run_result_chain_keeps_l7_packets(self):
        """``/api/last-run/result`` 的富化链不许吃掉该字段（前端「查看上次结果」）。"""
        result = diagnose._run_scan(pcap=str(DEMO), logger=lambda _m: None,
                                    report_dir=self.out)
        enriched = server._attach_probe_ui_copy(result)
        block = server.build_status_conclusion(enriched)
        enriched = server._attach_conclusion(enriched, block)
        self.assertIn("l7_packets", enriched)
        self.assertEqual(enriched["l7_packets"], result["l7_packets"])

    def test_report_json_still_has_no_l7_packets(self):
        """红线：l7_packets 只走 API，不许混进 reports/ 的五个块。"""
        import json
        import report

        result = diagnose._run_scan(pcap=str(DEMO), logger=lambda _m: None,
                                    report_dir=self.out)
        paths = report.save(json.loads(json.dumps(result)), self.out)
        payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        self.assertNotIn("l7_packets", payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
