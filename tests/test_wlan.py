"""``core/wlan.py`` 的解析与快照契约测试。

覆盖点
------
1. 中文 / 英文 ``netsh wlan show interfaces`` 输出都能解析出关键字段；
2. 无 SSID（有线连接、未连接）时返回空字典，由上层判定不可用；
3. 估计信噪比派生规则：RSSI − (−95)；
4. 快照短缓存：第二次调用命中缓存，``force=True`` 强制重采；
5. 服务端确实注册了 ``GET /api/wifi``（源码级接线守卫，与项目既有 UI 接线测试同风格）。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import wlan  # noqa: E402

ZH = """    There is 1 interface on the system:

    Name                   : WLAN
    Description            : Intel(R) Wireless-AC 9462
    GUID                   : 5eb22b48-acef-437c-818d-920cdadba9a0
    Physical address       : a6:e9:88:ee:38:ba
    State                  : connected
    SSID                   : RR
    AP BSSID               : 50:4f:3b:e2:98:93
    Band                   : 5 GHz
    Channel                : 153
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Receive rate (Mbps)    : 433.3
    Transmit rate (Mbps)   : 433.3
    Signal                 : 99%
    Rssi                   : -54
"""

EN = """    Name                   : Wi-Fi
    State                  : connected
    SSID                   : Office-5G
    AP BSSID               : aa:bb:cc:dd:ee:ff
    Band                   : 5 GHz
    Channel                : 44
    Radio type             : 802.11ax
    Receive rate (Mbps)    : 866.7
    Transmit rate (Mbps)   : 866.7
    Signal                 : 78%
    Rssi                   : -62
"""

NO_WIFI = """    There is 1 interface on the system:

    Name                   : WLAN
    State                  : disconnected
"""


class ParseNetshInterfacesTest(unittest.TestCase):
    """解析器：中英双份键名、派生字段、异常输入。"""

    def test_parses_chinese_labels(self):
        out = wlan.parse_netsh_interfaces(ZH)
        self.assertEqual(out["ssid"], "RR")
        self.assertEqual(out["bssid"], "50:4f:3b:e2:98:93")
        self.assertEqual(out["band"], "5 GHz")
        self.assertEqual(out["channel"], 153)
        self.assertEqual(out["radio"], "802.11ac")
        self.assertEqual(out["rssi_dbm"], -54)
        self.assertEqual(out["signal_pct"], 99)
        self.assertAlmostEqual(out["rx_mbps"], 433.3)
        self.assertAlmostEqual(out["tx_mbps"], 433.3)

    def test_parses_english_labels(self):
        out = wlan.parse_netsh_interfaces(EN)
        self.assertEqual(out["ssid"], "Office-5G")
        self.assertEqual(out["radio"], "802.11ax")
        self.assertEqual(out["rssi_dbm"], -62)

    def test_snr_is_derived_from_rssi(self):
        out = wlan.parse_netsh_interfaces(ZH)
        self.assertEqual(out["snr_est_db"], -54 - wlan.NOISE_FLOOR_DBM)

    def test_no_ssid_means_unavailable(self):
        self.assertEqual(wlan.parse_netsh_interfaces(NO_WIFI), {})
        self.assertEqual(wlan.parse_netsh_interfaces(""), {})


class SnapshotCacheTest(unittest.TestCase):
    """快照缓存：默认命中、force 强制重采、异常转可读错误。"""

    def setUp(self):
        wlan._CACHE["value"] = None
        wlan._CACHE["at"] = 0.0

    def tearDown(self):
        wlan._CACHE["value"] = None
        wlan._CACHE["at"] = 0.0

    def test_second_call_hits_cache(self):
        payload = {"ok": True, "available": True, "wlan": {"ssid": "RR"}, "host": {}, "probe": {}, "external": []}
        with mock.patch.object(wlan, "collect", side_effect=[payload]) as mocked:
            first = wlan.snapshot()
            second = wlan.snapshot()
        self.assertEqual(mocked.call_count, 1)
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])

    def test_force_recollects(self):
        payload = {"ok": True, "available": False, "wlan": {}, "host": {}, "probe": {}, "external": []}
        with mock.patch.object(wlan, "collect", side_effect=[payload, payload]) as mocked:
            wlan.snapshot()
            wlan.snapshot(force=True)
        self.assertEqual(mocked.call_count, 2)

    def test_collect_exception_becomes_readable_error(self):
        with mock.patch.object(wlan, "collect", side_effect=RuntimeError("boom")):
            out = wlan.snapshot(force=True)
        self.assertFalse(out["ok"])
        self.assertIn("boom", out["error"])


class WifiRouteWiringTest(unittest.TestCase):
    """源码级接线守卫：/api/wifi 必须注册在 GET 路由里（与既有 UI 接线测试同风格）。"""

    def test_server_registers_wifi_route(self):
        src = (ROOT / "core" / "server.py").read_text(encoding="utf-8")
        self.assertIn('if path == "/api/wifi":', src)
        self.assertIn("wlan.snapshot(", src)

    def test_no_local_ip_leak_in_module_docstring(self):
        """wlan.py 不应把真实 IP/域名写进源码（红线：不写死真实地址）。"""
        src = (ROOT / "core" / "wlan.py").read_text(encoding="utf-8")
        self.assertNotIn("192.168.", src.split('"""', 2)[0])
        self.assertNotIn("198.18.", src.split('"""', 2)[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
