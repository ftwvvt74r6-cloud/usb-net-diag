"""网卡自动选择与「0 包换卡重试」的回归测试（fix/interface-autopick）。

现场缺陷：用户机器上同时有 WLAN、断开的以太网、mihomo 的 Meta TUN、VMware、
蓝牙等网卡。旧逻辑先按名字挑中「以太网」（已断线），探测列表的前 5 块又被
低序号的虚拟网卡占满，真正的 WLAN/Meta 根本没被试到；抓完 0 包后直接把空
pcap 交给分析器，最后只报一句「未捕获到任何报文」。

这里守五件事：

1. ``SKIP_HINTS`` 覆盖 Meta/VMware/蓝牙等，但**只降优先级、不删除**候选；
2. ``order_interfaces`` 把物理网卡排在虚拟网卡前面；
3. ``capture_live`` 无显式网卡时先用 ``probe_interface`` 找有流量的那块；
4. 自动模式抓到 0 包/0 字节会自动换下一块候选（最多 3 块），全失败时错误里必须带
   ``--interfaces`` / ``--interface`` 指引与常见原因；
5. **显式 ``--interface`` 抓到 0 包绝不换卡**：报错要说清「停在你指定的网卡」、
   列出本次探测发现有流量的候选，并给 ``--interfaces`` / 不指定 ``--interface``
   两条命令（Lead 裁定：指定 Meta 时静默换到 WLAN 会给出错误结论）。

全部用例都不依赖真 Npcap / tshark：``tshark.run`` 与 ``probe_interface`` 都是 mock。
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import diagnose                                            # noqa: E402
import tshark                                              # noqa: E402


def _iface(index: int, name: str) -> dict:
    """造一条与 ``tshark -D`` 同形的网卡记录。"""
    raw = f"{index}. \\Device\\NPF_TEST_{index} ({name})"
    return {"index": index, "name": raw, "raw": raw}


# 按用户机器上的真实顺序造数据：低序号是 Wi-Fi Direct / 蓝牙，Meta 在 10，
# 以太网在 12 且已断线。
IFACES = [
    _iface(1, "本地连接* 8"),
    _iface(4, "蓝牙网络连接"),
    _iface(5, "WLAN"),
    _iface(6, "VMware Network Adapter VMnet8"),
    _iface(10, "Meta"),
    _iface(11, "Adapter for loopback traffic capture"),
    _iface(12, "以太网"),
]


class SkipHintsTest(unittest.TestCase):
    """``SKIP_HINTS`` 必须命中现场这些虚拟/无线外设网卡名。"""

    def test_skip_hints_cover_virtual_and_wireless_peripherals(self):
        names = [
            "Meta", "Meta Tunnel", "mihomo tun", "TAP-Windows Adapter V9",
            "VMware Network Adapter VMnet8", "VirtualBox Host-Only Network",
            "vboxnet0", "Hyper-V Virtual Ethernet Adapter",
            "vEthernet (Default Switch)", "Adapter for loopback traffic capture",
            "Npcap Loopback Adapter", "蓝牙网络连接", "Bluetooth Device (PAN)",
            "Docker (vEthernet)", "WSL (vEthernet)",
            "ciscodump (Cisco remote capture)", "wifidump (Wi-Fi remote capture)",
            "randpkt (Random packet generator)", "sshdump (SSH remote capture)",
        ]
        for name in names:
            self.assertTrue(
                any(hint in name.lower() for hint in tshark.SKIP_HINTS),
                f"SKIP_HINTS 没覆盖网卡名：{name}",
            )


class PickInterfaceTest(unittest.TestCase):
    """按名字挑默认网卡：物理优先，虚拟靠后但不丢。"""

    def test_pick_prefers_ethernet_or_wlan(self):
        picked = tshark.pick_interface(IFACES)
        self.assertIsNotNone(picked)
        self.assertIn(picked["index"], (12, 5),
                      f"默认网卡应是以太网/WLAN，实际 {picked!r}")

    def test_pick_never_returns_meta_vmware_or_bluetooth(self):
        picked = tshark.pick_interface(IFACES)
        name = tshark.short_name(picked["name"]).lower()
        for bad in ("meta", "vmware", "蓝牙", "bluetooth", "loopback"):
            self.assertNotIn(bad, name)

    def test_virtual_nics_are_deprioritized_not_removed(self):
        """只剩虚拟网卡时（例如 VPN 是唯一通路）仍要返回一块，且优先 VPN/TUN。"""
        virtual = [i for i in IFACES
                   if any(hint in i["name"].lower() for hint in tshark.SKIP_HINTS)]
        self.assertGreaterEqual(len(virtual), 4)
        picked = tshark.pick_interface(virtual)
        self.assertIn(picked, virtual)
        self.assertEqual(picked["index"], 10,
                         "只有虚拟网卡时，Meta/TUN 应排在蓝牙/回环前面")

    def test_order_puts_physical_before_virtual(self):
        ordered = tshark.order_interfaces(IFACES)
        self.assertEqual(len(ordered), len(IFACES), "排序不能丢网卡")
        self.assertEqual(sorted(i["index"] for i in ordered),
                         sorted(i["index"] for i in IFACES))
        indexes = [i["index"] for i in ordered]
        self.assertEqual(indexes[:2], [12, 5])
        self.assertLess(indexes.index(12), indexes.index(10))
        self.assertLess(indexes.index(10), indexes.index(4),
                        "VPN/TUN 应排在蓝牙等其它虚拟网卡前面")


class ProbeInterfaceTest(unittest.TestCase):
    """真实探测：按候选顺序试，每块 2 秒，最多 5 块。"""

    def test_probe_picks_first_candidate_with_traffic(self):
        seen: list[int] = []

        def fake_run(args, timeout=180):
            idx = int(args[args.index("-i") + 1])
            seen.append(idx)
            return (0, "1\n" if idx == 5 else "", "")

        with mock.patch.object(tshark, "run", side_effect=fake_run):
            got = tshark.probe_interface(Path("tshark.exe"),
                                         tshark.order_interfaces(IFACES))
        self.assertEqual(got["index"], 5, "探测应跳过没流量的以太网，选中 WLAN")
        self.assertEqual(seen, [12, 5])

    def test_probe_stops_after_five_candidates(self):
        seen: list[int] = []

        def fake_run(args, timeout=180):
            seen.append(int(args[args.index("-i") + 1]))
            return 0, "", ""

        with mock.patch.object(tshark, "run", side_effect=fake_run):
            got = tshark.probe_interface(Path("tshark.exe"),
                                         tshark.order_interfaces(IFACES))
        self.assertIsNone(got)
        self.assertEqual(seen, [12, 5, 10, 1, 4],
                         "最多只能探测 5 块候选网卡；VPN 应排在其他虚拟网卡前")


class CaptureLiveRetryTest(unittest.TestCase):
    """``diagnose.capture_live`` 的探测优先与 0 包换卡重试。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.captures = Path(self._tmp.name) / "captures"
        self.capture_calls: list[int] = []
        self.written: dict[str, int] = {}
        self.probe_calls: list[list[int]] = []
        self.traffic_probe_calls: list[int] = []
        patches = [
            mock.patch.object(diagnose, "CAPTURES", self.captures),
            mock.patch.object(diagnose, "_wait_file_stable", return_value=True),
            mock.patch.object(tshark, "find_tshark", return_value=Path("tshark.exe")),
            mock.patch.object(tshark, "npcap_installed", return_value=True),
            mock.patch.object(tshark, "list_interfaces", return_value=list(IFACES)),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _install_run(self, traffic: set[int], zero_bytes: set[int] = frozenset(),
                     probe_traffic: set[int] = frozenset()) -> None:
        """假 tshark：``-w`` 落盘，``-r`` 按接口报告是否读到第一帧。

        ``probe_traffic`` 是显式 0 包后「探测其它候选」里哪些网卡有流量
        （形如 ``-a duration:2 -c 20 -T fields``，没有 ``-w`` / ``-r``）。
        """

        def fake_run(args, timeout=180):
            if "-w" in args:
                idx = int(args[args.index("-i") + 1])
                pcap = Path(args[args.index("-w") + 1])
                self.capture_calls.append(idx)
                if idx in zero_bytes:
                    return 0, "", ""  # tshark 没落盘 → 0 字节
                pcap.parent.mkdir(parents=True, exist_ok=True)
                pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 200)
                self.written[str(pcap)] = idx
                return 0, "", ""
            if "-r" in args:
                idx = self.written.get(args[args.index("-r") + 1])
                return 0, ("1\n" if idx in traffic else ""), ""
            idx = int(args[args.index("-i") + 1])
            self.traffic_probe_calls.append(idx)
            return 0, ("1\n" if idx in probe_traffic else ""), ""

        patcher = mock.patch.object(tshark, "run", side_effect=fake_run)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _install_probe(self, result) -> None:
        def fake_probe(ts, candidates, seconds=2):
            self.probe_calls.append([c["index"] for c in candidates])
            return result

        patcher = mock.patch.object(tshark, "probe_interface", side_effect=fake_probe)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_zero_packet_capture_retries_next_candidate(self):
        """第一块（以太网）0 包，第二块（WLAN）有包 → 最终必须用第二块。"""
        self._install_probe(None)
        self._install_run(traffic={5})

        result = diagnose.capture_live(duration=8, logger=lambda _m: None)

        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["interface_index"], 5)
        self.assertEqual(self.capture_calls, [12, 5],
                         "0 包后没有换下一块候选网卡重试")

    def test_zero_byte_capture_also_retries(self):
        """tshark 连文件都没写出来（0 字节）也要换卡，而不是直接失败。"""
        self._install_probe(None)
        self._install_run(traffic={5}, zero_bytes={12})

        result = diagnose.capture_live(duration=8, logger=lambda _m: None)

        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["interface_index"], 5)
        self.assertEqual(self.capture_calls, [12, 5])

    def test_probe_result_wins_over_name_based_pick(self):
        """探测到 Meta 有流量时就用 Meta，而不是名字更「像」的以太网。"""
        meta = next(i for i in IFACES if i["index"] == 10)
        self._install_probe(meta)
        self._install_run(traffic={10})

        result = diagnose.capture_live(duration=8, logger=lambda _m: None)

        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["interface_index"], 10)
        self.assertEqual(self.capture_calls, [10])
        self.assertEqual(self.probe_calls[0][:2], [12, 5],
                         "探测顺序没有把物理网卡排在虚拟网卡前面")

    def test_all_zero_packets_returns_actionable_error(self):
        """全部 0 包：最多试 3 块，错误必须给出自助命令与常见原因。"""
        self._install_probe(None)
        self._install_run(traffic=set())

        result = diagnose.capture_live(duration=8, logger=lambda _m: None)

        self.assertFalse(result.get("ok"))
        error = result.get("error", "")
        for needle in ("--interfaces", "--interface", "未连接", "VPN"):
            self.assertIn(needle, error)
        self.assertGreater(len(error), 80, "错误信息不能只有一句「未捕获到任何报文」")
        self.assertEqual(self.capture_calls, [12, 5, 10],
                         "重试上限应为 3 块候选网卡；第三块应是 VPN 而不是蓝牙")

    def test_explicit_interface_zero_packets_does_not_switch(self):
        """显式指定 12（断线以太网）0 包：不换卡，列出有流量候选与两条命令。"""
        self._install_run(traffic=set(), probe_traffic={5, 10})
        logs: list[str] = []

        result = diagnose.capture_live(duration=8, interface="12", logger=logs.append)

        self.assertFalse(result.get("ok"))
        self.assertEqual(self.capture_calls, [12],
                         "显式指定时 0 包后绝不允许换卡")
        error = result.get("error", "")
        for needle in ("你指定的网卡 #12", "以太网", "8 秒内没抓到任何包",
                       "#5 WLAN", "#10 Meta", "--interfaces",
                       "python core\\diagnose.py --duration 8"):
            self.assertIn(needle, error)
        self.assertEqual(self.traffic_probe_calls, [5, 10, 1, 4, 6],
                         "应探测除显式网卡外的候选（最多 5 块），顺序按物理/VPN/虚拟")
        self.assertEqual(self.probe_calls, [], "显式指定时不应走自动探测")
        self.assertFalse(any("自动换下一块" in line for line in logs),
                         "显式指定时日志里不能出现换卡提示")
        self.assertTrue(any("已删除空抓包" in line for line in logs),
                        "删除 0 包 pcap 要留一行日志")
        self.assertEqual(list(self.captures.glob("*.pcapng")), [],
                         "0 包 pcap 必须删除")

    def test_explicit_interface_zero_bytes_does_not_switch(self):
        """显式指定 12 连文件都没写出来（0 字节）同样不换卡、同样可操作。"""
        self._install_run(traffic=set(), zero_bytes={12}, probe_traffic={5})

        result = diagnose.capture_live(duration=8, interface="12",
                                       logger=lambda _m: None)

        self.assertFalse(result.get("ok"))
        self.assertEqual(self.capture_calls, [12], "0 字节也不能换卡")
        error = result.get("error", "")
        self.assertIn("你指定的网卡 #12", error)
        self.assertIn("#5 WLAN", error)
        self.assertIn("--interfaces", error)
        self.assertIn("python core\\diagnose.py --duration 8", error)


if __name__ == "__main__":
    unittest.main(verbosity=2)
