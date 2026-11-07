"""``capture_live`` 返回协议：所有路径都必须带 ``bpf`` / ``interface``。

复审阻塞 1：auto 模式「候选网卡全部 0 包」的返回 dict 漏了 ``bpf`` /
``interface``，``server._worker`` 只能把空值交给降级卡，于是实际过滤器
``host 8.8.8.8`` 被写成「无（全网）」，并落进 ``degraded_*.md|json``。

这里守两条：

1. 任何返回路径（缺 tshark / 缺 Npcap / 无网卡 / 无法挑卡 / 目标非法 /
   权限不足 / 显式网卡 0 包 / 自动换卡全 0 包 / 成功）都有 ``bpf`` 与
   ``interface`` 两个键；删掉任意一条路径的字段，对应用例必红。
2. auto 全 0 包这条真实数据流一路传到 server 降级卡与落盘报告，``bpf`` 仍是
   ``host 8.8.8.8``，``interface`` 是最后尝试的网卡（不是「自动选择」）。

全部用 mock，不需要 Npcap / tshark / 管理员权限。
"""
from __future__ import annotations

import contextlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import diagnose  # noqa: E402
import server  # noqa: E402
import tshark  # noqa: E402


def _iface(index: int, name: str) -> dict:
    """造一条与 ``tshark -D`` 同形的网卡记录。"""
    raw = f"{index}. \\Device\\NPF_TEST_{index} ({name})"
    return {"index": index, "name": raw, "raw": raw}


_UNSET = object()


# 现场顺序：低序号是 Wi-Fi Direct / 蓝牙，WLAN 在 5，Meta 在 10，断线以太网在 12。
IFACES = [
    _iface(1, "本地连接* 8"),
    _iface(4, "蓝牙网络连接"),
    _iface(5, "WLAN"),
    _iface(6, "VMware Network Adapter VMnet8"),
    _iface(10, "Meta"),
    _iface(11, "Adapter for loopback traffic capture"),
    _iface(12, "以太网"),
]


def _run_with_packets(args, timeout=180):
    """假 tshark：``-w`` 落盘，``-r`` 永远读得到一帧（成功路径）。"""
    if "-w" in args:
        pcap = Path(args[args.index("-w") + 1])
        pcap.parent.mkdir(parents=True, exist_ok=True)
        pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 200)
        return 0, "", ""
    if "-r" in args:
        return 0, "1\n", ""
    return 0, "", ""


def _run_without_packets(args, timeout=180):
    """假 tshark：``-w`` 写一个只有文件头的 pcap，``-r`` 读不到帧（0 包）。"""
    if "-w" in args:
        pcap = Path(args[args.index("-w") + 1])
        pcap.parent.mkdir(parents=True, exist_ok=True)
        pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 200)
        return 0, "", ""
    return 0, "", ""


class CaptureLiveReturnMetaTest(unittest.TestCase):
    """``capture_live`` 的每一条 return 都必须交代最终过滤器与网卡。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.captures = Path(self._tmp.name) / "captures"
        patcher = mock.patch.object(diagnose, "CAPTURES", self.captures)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(diagnose, "_wait_file_stable", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _assert_meta(self, result: dict, path: str) -> None:
        self.assertIn("bpf", result, f"{path} 返回缺少 bpf：{result}")
        self.assertIn("interface", result, f"{path} 返回缺少 interface：{result}")

    def _common_patches(self, *, interfaces=None, probe=_UNSET, pick=_UNSET,
                        run=None):
        """装好 find/npcap/list/run 这组公共 mock（返回 ``ExitStack`` 用 with）。"""
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(
            tshark, "find_tshark", return_value=Path("tshark.exe")))
        stack.enter_context(mock.patch.object(
            tshark, "npcap_installed", return_value=True))
        stack.enter_context(mock.patch.object(
            tshark, "list_interfaces",
            return_value=list(IFACES if interfaces is None else interfaces)))
        if probe is not _UNSET:
            stack.enter_context(mock.patch.object(
                tshark, "probe_interface", return_value=probe))
        if pick is not _UNSET:
            stack.enter_context(mock.patch.object(
                tshark, "pick_interface", return_value=pick))
        if run is not None:
            stack.enter_context(mock.patch.object(tshark, "run", side_effect=run))
        return stack

    def test_no_tshark_return_has_meta(self):
        with mock.patch.object(tshark, "find_tshark", return_value=None):
            result = diagnose.capture_live(
                target="8.8.8.8", duration=3, logger=lambda _m: None)
        self.assertFalse(result.get("ok"))
        self._assert_meta(result, "no_tshark")

    def test_no_npcap_return_has_meta(self):
        with mock.patch.object(
                tshark, "find_tshark", return_value=Path("tshark.exe")), \
                mock.patch.object(tshark, "npcap_installed", return_value=False):
            result = diagnose.capture_live(
                target="8.8.8.8", duration=3, logger=lambda _m: None)
        self.assertFalse(result.get("ok"))
        self._assert_meta(result, "no_npcap")

    def test_no_interfaces_return_has_meta(self):
        with self._common_patches(interfaces=[]):
            result = diagnose.capture_live(
                target="8.8.8.8", duration=3, logger=lambda _m: None)
        self.assertFalse(result.get("ok"))
        self._assert_meta(result, "no_interfaces")

    def test_unpickable_interface_return_has_meta(self):
        with self._common_patches(probe=None, pick=None):
            result = diagnose.capture_live(
                target="8.8.8.8", duration=3, logger=lambda _m: None)
        self.assertFalse(result.get("ok"))
        self._assert_meta(result, "no_interface")

    def test_invalid_target_return_has_meta(self):
        with self._common_patches(probe=IFACES[-1]):
            result = diagnose.capture_live(
                target="bad target", duration=3, logger=lambda _m: None)
        self.assertFalse(result.get("ok"))
        self._assert_meta(result, "invalid_target")

    def test_permission_denied_return_has_meta(self):
        def denied(args, timeout=180):
            return 1, "", "access is denied"

        with self._common_patches(probe=IFACES[-1], run=denied):
            result = diagnose.capture_live(
                target="8.8.8.8", duration=3, logger=lambda _m: None)
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("bpf"), "host 8.8.8.8")
        self.assertEqual(result.get("interface"), tshark.short_name(IFACES[-1]["name"]))
        self._assert_meta(result, "permission_denied")

    def test_explicit_interface_empty_capture_return_has_meta(self):
        with self._common_patches(run=_run_without_packets):
            result = diagnose.capture_live(
                target="", duration=3, interface="12", logger=lambda _m: None)
        self.assertFalse(result.get("ok"))
        self.assertTrue(result.get("empty"))
        self.assertEqual(result.get("interface"), tshark.short_name(IFACES[-1]["name"]))
        self._assert_meta(result, "explicit_empty")

    def test_success_return_has_meta(self):
        with self._common_patches(probe=IFACES[-1], run=_run_with_packets):
            result = diagnose.capture_live(
                target="", duration=3, logger=lambda _m: None)
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("interface"), tshark.short_name(IFACES[-1]["name"]))
        self._assert_meta(result, "success")

    def test_auto_all_empty_returns_actual_bpf_and_last_interface(self):
        """auto 全 0 包：bpf 必须是实际下发的 host，interface 是最后试的网卡。"""
        with self._common_patches(probe=None, pick=IFACES[-1],
                                  run=_run_without_packets):
            result = diagnose.capture_live(
                target="8.8.8.8", duration=8, logger=lambda _m: None)

        self.assertFalse(result.get("ok"))
        self.assertTrue(result.get("empty"), "全 0 包必须带 empty 供降级判定")
        self.assertEqual(result.get("bpf"), "host 8.8.8.8",
                         "auto 0 包路径丢了实际 BPF，降级卡会误报「无（全网）」")
        plan = diagnose._capture_candidates(
            IFACES[-1], tshark.order_interfaces(IFACES), 3)
        self.assertEqual(result.get("interface"),
                         tshark.short_name(plan[-1]["name"]))
        self.assertEqual(result.get("interface_index"), plan[-1]["index"])
        self._assert_meta(result, "auto_all_empty")


class AutoZeroPacketDataFlowTest(unittest.TestCase):
    """阻塞 1 的真实数据流：capture_live → run_scan → server 降级卡/报告。"""

    def test_degraded_card_and_report_keep_actual_bpf_and_interface(self):
        saved = dict(server.JOB)
        saved_logs = list(server.JOB["logs"])
        plan = diagnose._capture_candidates(
            IFACES[-1], tshark.order_interfaces(IFACES), 3)
        last_name = tshark.short_name(plan[-1]["name"])
        link_ok = {"ok": True, "host": "8.8.8.8", "avg_ms": 12.0,
                   "jitter_ms": 1.0, "loss_pct": 0.0, "sent": 4, "recv": 4}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                reports = Path(tmp) / "reports"
                with mock.patch.object(
                        diagnose, "CAPTURES", Path(tmp) / "captures"), \
                        mock.patch.object(diagnose, "_wait_file_stable",
                                          return_value=True), \
                        mock.patch.object(tshark, "find_tshark",
                                          return_value=Path("tshark.exe")), \
                        mock.patch.object(tshark, "npcap_installed",
                                          return_value=True), \
                        mock.patch.object(tshark, "list_interfaces",
                                          return_value=list(IFACES)), \
                        mock.patch.object(tshark, "probe_interface",
                                          return_value=None), \
                        mock.patch.object(tshark, "pick_interface",
                                          return_value=IFACES[-1]), \
                        mock.patch.object(tshark, "run",
                                          side_effect=_run_without_packets), \
                        mock.patch.object(diagnose, "_link_stats",
                                          return_value=link_ok), \
                        mock.patch.object(diagnose, "_tshark_version",
                                          return_value="test"), \
                        mock.patch.object(diagnose.logstore, "record_run"), \
                        mock.patch.object(server, "REPORTS", reports), \
                        mock.patch.object(server, "log"):
                    server._worker("live", "8.8.8.8", 5, None, None)

                self.assertEqual(server.JOB["state"], "done")
                res = server.JOB["result"]
                self.assertTrue(res.get("degraded"))
                self.assertEqual(res["capture"]["bpf"], "host 8.8.8.8",
                                 "降级卡把实际过滤器误报成「无（全网）」")
                self.assertEqual(res["capture"]["interface"], last_name)
                md = Path(res["report"]["markdown"]).read_text(encoding="utf-8")
                payload = json.loads(
                    Path(res["report"]["json"]).read_text(encoding="utf-8"))
                self.assertIn("host 8.8.8.8", md,
                              "degraded_*.md 没写实际过滤器")
                self.assertIn(last_name, md, "degraded_*.md 没写最终网卡")
                self.assertEqual(payload["capture"]["bpf"], "host 8.8.8.8")
                self.assertEqual(payload["capture"]["interface"], last_name)
        finally:
            server.JOB.clear()
            server.JOB.update(saved)
            server.JOB["logs"] = saved_logs


if __name__ == "__main__":
    unittest.main(verbosity=2)
