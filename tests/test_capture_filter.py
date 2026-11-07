"""定向抓包过滤器决策 + 换卡重试时长的单元测试。

覆盖路测 bug：域名解析到 mihomo fake-ip（198.18.0.0/15）时不能再把
``host <域名>`` 交给 tshark（必然 0 包）；只有全公网解析结果才做 host 过滤。
DNS 用 ``mock.patch(diagnose._resolve_ips)`` 注入，测试不联网。
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "core"
sys.path.insert(0, str(CORE))

import diagnose  # noqa: E402
import tshark  # noqa: E402

IFACES = [
    {"index": 5, "name": r"\Device\NPF_{W} (WLAN)", "raw": "5"},
    {"index": 10, "name": r"\Device\NPF_{M} (Meta)", "raw": "10"},
    {"index": 12, "name": r"\Device\NPF_{E} (以太网)", "raw": "12"},
]


class CaptureFilterDecisionTest(unittest.TestCase):
    """五种输入的决策：fake-ip / 私网 / 公网 / CIDR / IP。"""

    def _decide(self, target: str, ips: list[str] | None = None):
        logs: list[str] = []
        with mock.patch.object(diagnose, "_resolve_ips", return_value=list(ips or [])):
            decision = diagnose.capture_filter_for(target, logger=logs.append)
        return decision, logs

    def test_fake_ip_domain_uses_no_capture_filter(self):
        """baidu.com → 198.18.1.145（mihomo fake-ip）→ 不加过滤器，日志说明原因。"""
        decision, logs = self._decide("baidu.com", ["198.18.1.145"])

        self.assertEqual(decision["bpf"], "")
        self.assertEqual(decision["kind"], "domain")
        self.assertEqual(decision["resolved"], ["198.18.1.145"])
        text = "\n".join(logs)
        for needle in ("baidu.com", "198.18.1.145", "代理假 IP 段",
                       "不做 host 过滤", "分析阶段再按目标筛选"):
            self.assertIn(needle, text)

    def test_private_domain_uses_no_capture_filter(self):
        decision, logs = self._decide("intranet.example", ["192.168.1.10"])

        self.assertEqual(decision["bpf"], "")
        self.assertIn("私网地址", "\n".join(logs))

    def test_public_domain_uses_host_filter(self):
        decision, logs = self._decide("www.example.com", ["93.184.216.34"])

        self.assertEqual(decision["bpf"], "host 93.184.216.34")
        self.assertEqual(decision["kind"], "domain")
        self.assertIn("公网地址", "\n".join(logs))

    def test_multiple_public_ips_are_ored(self):
        decision, _logs = self._decide("multi.example", ["1.1.1.1", "8.8.8.8"])

        self.assertEqual(decision["bpf"], "host 1.1.1.1 or host 8.8.8.8")

    def test_mixed_public_and_fake_ip_uses_no_filter(self):
        """只要结果里出现 fake-ip 就不可信，宁可抓全网也不漏业务流量。"""
        decision, _logs = self._decide("mixed.example", ["93.184.216.34", "198.18.1.145"])

        self.assertEqual(decision["bpf"], "")

    def test_cidr_uses_net(self):
        decision, logs = self._decide("192.168.1.0/24")

        self.assertEqual(decision["bpf"], "net 192.168.1.0/24")
        self.assertEqual(decision["kind"], "cidr")
        self.assertIn("net 192.168.1.0/24", "\n".join(logs))

    def test_cidr_with_host_bits_is_normalized(self):
        decision, _logs = self._decide("192.168.1.5/24")

        self.assertEqual(decision["bpf"], "net 192.168.1.0/24")

    def test_plain_ip_uses_host_even_for_private_gateway(self):
        """用户显式给 IP（如内网网关）时必须按 host 抓，这是定向抓包的主用法。"""
        decision, logs = self._decide("192.168.1.1")

        self.assertEqual(decision["bpf"], "host 192.168.1.1")
        self.assertEqual(decision["kind"], "ip")
        self.assertIn("host 192.168.1.1", "\n".join(logs))

    def test_fake_ip_literal_still_uses_host(self):
        """显式输入的 fake-ip 也尊重用户，但决策按 IP 而非域名（不含 DNS）。"""
        decision, _logs = self._decide("198.18.1.145")

        self.assertEqual(decision["bpf"], "host 198.18.1.145")

    def test_dns_failure_uses_no_filter(self):
        decision, logs = self._decide("no-such-host.invalid", [])

        self.assertEqual(decision["bpf"], "")
        text = "\n".join(logs)
        self.assertIn("解析失败", text)
        self.assertIn("不做 host 过滤", text)

    def test_injection_still_rejected(self):
        for bad in ("1.1.1.1 or host 8.8.8.8", 'a"b', "x;y"):
            with self.assertRaises(ValueError):
                diagnose.bpf_for(bad)

    def test_empty_target_uses_no_filter(self):
        decision = diagnose.capture_filter_for("")

        self.assertEqual(decision["bpf"], "")
        self.assertEqual(decision["kind"], "none")


class RetryDurationTest(unittest.TestCase):
    """自动换卡重试：第 2/3 块缩短为 min(用户时长, 10s)。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.captures = Path(self._tmp.name) / "captures"
        self.durations: list[int] = []
        self.filters: list[str] = []

        def fake_run(args, timeout=180):
            if "-w" in args:
                self.durations.append(int(args[args.index("-a") + 1].split(":")[1]))
                self.filters.append(args[args.index("-f") + 1] if "-f" in args else "")
                pcap = Path(args[args.index("-w") + 1])
                pcap.parent.mkdir(parents=True, exist_ok=True)
                pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 200)
                return 0, "", ""
            if "-r" in args:
                return 0, "", ""  # 0 包
            return 0, "", ""

        patches = [
            mock.patch.object(diagnose, "CAPTURES", self.captures),
            mock.patch.object(diagnose, "_wait_file_stable", return_value=True),
            mock.patch.object(tshark, "find_tshark", return_value=Path("tshark.exe")),
            mock.patch.object(tshark, "npcap_installed", return_value=True),
            mock.patch.object(tshark, "list_interfaces", return_value=list(IFACES)),
            mock.patch.object(tshark, "probe_interface", return_value=IFACES[2]),
            mock.patch.object(tshark, "run", side_effect=fake_run),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_second_and_third_attempts_shrink_to_ten_seconds(self):
        logs: list[str] = []
        result = diagnose.capture_live(duration=30, logger=logs.append)

        self.assertFalse(result.get("ok"))
        self.assertEqual(self.durations, [30, 10, 10],
                         "首块 30s，换卡重试两块都必须缩到 10s")
        self.assertEqual(self.filters, ["", "", ""],
                         "未指定 target 时不应给 tshark 任何 BPF 过滤器")
        text = "\n".join(logs)
        self.assertIn("重试缩短时长，原 30s", text)
        self.assertIn("第 2/3 块", text)
        self.assertIn("第 3/3 块", text)

    def test_short_user_duration_is_not_extended(self):
        result = diagnose.capture_live(duration=3, logger=lambda _m: None)

        self.assertFalse(result.get("ok"))
        self.assertEqual(self.durations, [3, 3, 3],
                         "min(3,10)=3，重试不能比用户时长更长")


if __name__ == "__main__":
    unittest.main(verbosity=2)
