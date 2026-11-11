"""``core/agent.py`` 的契约测试：采样 / 事件 / 落盘 / 主循环 / 安装脚本。

为什么要这么多层断言
--------------------
常驻 agent 的失败方式很隐蔽：字段缺一个键，热力图就错位；事件重复落，列表就被
噪声淹没；主循环被一次异常带走，样本就断一整天 —— 而这些在界面上都「看起来正常」。
所以这里按「数据形状 → 判定规则 → 主循环 → 安装脚本」四层各钉一遍。

所有用例都把 ``NETDIAG_LOG_DIR`` / ``NETDIAG_AGENT_CONFIG`` 指到临时目录，
不碰仓库的 ``logs/`` 与 ``config/``（``tests/test_zz_no_repo_logs.py`` 会兜底检查）。
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import agent as agent_mod  # noqa: E402
from core import config as config_mod  # noqa: E402
from core import logstore  # noqa: E402


class _AgentCase(unittest.TestCase):
    """把日志根与 agent 配置都重定向到临时目录。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.logs = self.tmp / "logs"
        self.config_file = self.tmp / "agent.json"
        self._env = mock.patch.dict(os.environ, {
            "NETDIAG_LOG_DIR": str(self.logs),
            "NETDIAG_AGENT_CONFIG": str(self.config_file),
        })
        self._env.start()
        agent_mod._IP_CACHE.clear()

    def tearDown(self) -> None:
        # 日志句柄在 Windows 上会锁住文件，不先关掉临时目录删不掉（WinError 32）
        for sink in list(logstore._SINKS.values()):
            try:
                sink.close()
            except Exception:  # noqa: BLE001  清理阶段的异常不该让用例失败
                pass
        logstore._SINKS.clear()
        self._env.stop()
        self._tmp.cleanup()

    def write_config(self, payload: dict) -> None:
        self.config_file.write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------- 配置

class AgentConfigTest(_AgentCase):
    """配置归一化：坏值不能让后台进程起不来，显式写错必须报错。"""

    def test_defaults_when_file_missing(self):
        cfg = config_mod.load_agent()
        self.assertEqual(cfg["interval_s"], 10)
        self.assertEqual(cfg["targets"], [])
        self.assertEqual(cfg["thresholds"],
                         {"rtt_ms": 120.0, "jitter_ms": 40.0, "loss_pct": 2.0})
        self.assertEqual(cfg["retain_days"], 7)
        self.assertEqual(cfg["event_retain_days"], 30)

    def test_invalid_interval_on_read_falls_back_to_default(self):
        self.write_config({"interval_s": 7})
        self.assertEqual(config_mod.load_agent()["interval_s"], 10)

    def test_string_interval_is_coerced(self):
        self.write_config({"interval_s": "30"})
        self.assertEqual(config_mod.load_agent()["interval_s"], 30)

    def test_save_rejects_illegal_interval(self):
        with self.assertRaises(ValueError) as ctx:
            config_mod.save_agent({"interval_s": 7})
        self.assertIn("5", str(ctx.exception))
        self.assertFalse(self.config_file.exists(), "非法值不应该落盘")

    def test_save_accepts_all_four_choices(self):
        for value in (5, 10, 30, 60):
            with self.subTest(value=value):
                self.assertEqual(config_mod.save_agent({"interval_s": value})["interval_s"],
                                 value)

    def test_targets_truncated_to_three(self):
        self.write_config({"targets": [
            {"key": "a", "host": "1.1.1.1"},
            {"key": "b", "host": "2.2.2.2"},
            {"key": "c", "host": "3.3.3.3"},
            {"key": "d", "host": "4.4.4.4"},
        ]})
        targets = config_mod.load_agent()["targets"]
        self.assertEqual([t["key"] for t in targets], ["a", "b", "c"])

    def test_target_accepts_bare_string_and_drops_empty_host(self):
        self.write_config({"targets": ["example.com", {"key": "x", "host": ""}, 42]})
        targets = config_mod.load_agent()["targets"]
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["host"], "example.com")
        self.assertEqual(targets[0]["key"], "target-1")

    def test_target_port_coercion(self):
        self.write_config({"targets": [
            {"key": "tcp", "host": "a.com", "port": "443"},
            {"key": "bad", "host": "b.com", "port": 0},
            {"key": "out", "host": "c.com", "port": 70000},
        ]})
        by_key = {t["key"]: t for t in config_mod.load_agent()["targets"]}
        self.assertEqual(by_key["tcp"]["port"], 443)
        for key in ("bad", "out"):
            self.assertNotIn("port", by_key[key], "非法端口应退化成「无端口=ICMP」")

    def test_non_numeric_port_falls_back_to_icmp(self):
        self.write_config({"targets": [{"key": "junk", "host": "d.com", "port": "abc"}]})
        self.assertNotIn("port", config_mod.load_agent()["targets"][0])

    def test_thresholds_partial_merge_keeps_other_defaults(self):
        self.write_config({"thresholds": {"rtt_ms": 80}})
        thresholds = config_mod.load_agent()["thresholds"]
        self.assertEqual(thresholds["rtt_ms"], 80.0)
        self.assertEqual(thresholds["jitter_ms"], 40.0)
        self.assertEqual(thresholds["loss_pct"], 2.0)

    def test_broken_json_falls_back_to_defaults(self):
        self.config_file.write_text("{ not json", encoding="utf-8")
        self.assertEqual(config_mod.load_agent()["interval_s"], 10)


# ---------------------------------------------------------------- 地址解析

class ResolveIpTest(_AgentCase):
    """``icmp_stats`` 只吃 IPv4 字面量，解析层必须把边界情况说清楚。"""

    def test_ipv4_literal_passes_through(self):
        self.assertEqual(agent_mod.resolve_ip("192.168.1.1"), "192.168.1.1")

    def test_ipv6_literal_returns_empty(self):
        self.assertEqual(agent_mod.resolve_ip("2001:db8::1"), "")

    def test_empty_returns_empty(self):
        self.assertEqual(agent_mod.resolve_ip("   "), "")

    def test_domain_resolved_and_cached(self):
        fake = [(2, 1, 6, "", ("203.0.113.9", 0))]
        with mock.patch.object(agent_mod.socket, "getaddrinfo", return_value=fake) as fn:
            self.assertEqual(agent_mod.resolve_ip("example.com", now=1000.0), "203.0.113.9")
            # 缓存命中：不再查 DNS
            self.assertEqual(agent_mod.resolve_ip("example.com", now=1001.0), "203.0.113.9")
        self.assertEqual(fn.call_count, 1)

    def test_cache_expires(self):
        fake = [(2, 1, 6, "", ("203.0.113.9", 0))]
        with mock.patch.object(agent_mod.socket, "getaddrinfo", return_value=fake) as fn:
            agent_mod.resolve_ip("example.com", now=1000.0, ttl_s=10)
            agent_mod.resolve_ip("example.com", now=1100.0, ttl_s=10)
        self.assertEqual(fn.call_count, 2)

    def test_dns_failure_returns_empty(self):
        with mock.patch.object(agent_mod.socket, "getaddrinfo", side_effect=OSError("no")):
            self.assertEqual(agent_mod.resolve_ip("nope.invalid"), "")


# ---------------------------------------------------------------- 测量

class MeasureTest(_AgentCase):
    """ICMP / TCP 两条测量通路，以及 ICMP 被禁时的降级。"""

    def test_icmp_ok_maps_stats(self):
        stats = {"ok": True, "host": "1.1.1.1", "sent": 2, "recv": 2,
                 "loss_pct": 0.0, "avg_ms": 12.5, "jitter_ms": 1.5, "error": ""}
        with mock.patch.object(agent_mod.winapi, "icmp_stats", return_value=stats):
            out = agent_mod.measure_icmp("1.1.1.1", count=2, timeout_ms=800)
        self.assertEqual(out["method"], "icmp")
        self.assertEqual(out["rtt_ms"], 12.5)
        self.assertEqual(out["jitter_ms"], 1.5)
        self.assertEqual(out["loss_pct"], 0.0)
        self.assertTrue(out["ok"])

    def test_icmp_unresolvable_sets_full_loss_and_error(self):
        out = agent_mod.measure_icmp("nope.invalid")
        self.assertEqual(out["loss_pct"], 100.0)
        self.assertIsNone(out["rtt_ms"])
        self.assertFalse(out["ok"])
        self.assertIn("DNS", out["error"])

    def test_tcp_all_failed_reports_full_loss_without_zero_rtt(self):
        with mock.patch.object(agent_mod, "_connect_ms", return_value=(None, "timeout")):
            out = agent_mod.measure_tcp("1.1.1.1", 443, count=2)
        self.assertEqual(out["loss_pct"], 100.0)
        self.assertIsNone(out["rtt_ms"], "失败时 rtt 必须是 None，不能写 0")
        self.assertFalse(out["ok"])

    def test_tcp_partial_loss(self):
        results = [(10.0, ""), (None, "refused")]
        with mock.patch.object(agent_mod, "_connect_ms", side_effect=results):
            out = agent_mod.measure_tcp("1.1.1.1", 443, count=2)
        self.assertEqual(out["loss_pct"], 50.0)
        self.assertEqual(out["rtt_ms"], 10.0)

    def test_endpoint_with_port_uses_tcp(self):
        with mock.patch.object(agent_mod, "measure_tcp",
                               return_value={"rtt_ms": 5.0, "loss_pct": 0.0,
                                             "jitter_ms": 0.0, "method": "tcp"}) as m:
            out = agent_mod.probe_endpoint("k", "a.com", 443)
        self.assertEqual(out["method"], "tcp")
        self.assertEqual(out["key"], "k")
        m.assert_called_once()

    def test_endpoint_without_port_uses_icmp(self):
        with mock.patch.object(agent_mod, "measure_icmp",
                               return_value={"rtt_ms": 3.0, "loss_pct": 0.0,
                                             "jitter_ms": 0.0, "method": "icmp",
                                             "ok": True}):
            out = agent_mod.probe_endpoint("k", "a.com")
        self.assertEqual(out["method"], "icmp")
        self.assertNotIn("degraded", out)

    def test_endpoint_degrades_to_tcp_when_icmp_blocked(self):
        icmp = {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                "method": "icmp", "ok": False}
        tcp = {"rtt_ms": 8.0, "loss_pct": 0.0, "jitter_ms": 1.0,
               "method": "tcp", "ok": True, "port": 443}
        with mock.patch.object(agent_mod, "measure_icmp", return_value=dict(icmp)), \
                mock.patch.object(agent_mod, "measure_tcp", return_value=dict(tcp)):
            out = agent_mod.probe_endpoint("k", "a.com")
        self.assertEqual(out["method"], "tcp")
        self.assertTrue(out["degraded"])
        self.assertEqual(out["method_note"], "icmp_blocked")

    def test_endpoint_records_tried_ports_when_everything_fails(self):
        icmp = {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                "method": "icmp", "ok": False}
        tcp = {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
               "method": "tcp", "ok": False}
        with mock.patch.object(agent_mod, "measure_icmp", return_value=dict(icmp)), \
                mock.patch.object(agent_mod, "measure_tcp", return_value=dict(tcp)):
            out = agent_mod.probe_endpoint("k", "a.com")
        self.assertEqual(out["tried_tcp_ports"], list(agent_mod.DEGRADE_TCP_PORTS))

    def test_endpoint_with_empty_host_is_none_method(self):
        out = agent_mod.probe_endpoint("k", "")
        self.assertEqual(out["method"], "none")
        self.assertIsNone(out["rtt_ms"])
        self.assertIsNone(out["loss_pct"])


# ---------------------------------------------------------------- 样本

class CollectSampleTest(_AgentCase):
    """样本形状：字段齐、顺序稳、拿不到的角色是 None 而不是 0。"""

    def _cfg(self, **over) -> dict:
        cfg = dict(config_mod.AGENT_DEFAULTS)
        cfg["targets"] = []
        cfg.update(over)
        return cfg

    def test_record_has_all_required_keys(self):
        with mock.patch.object(agent_mod, "_gateway", return_value="192.168.1.1"), \
                mock.patch.object(agent_mod, "_first_dns", return_value=""), \
                mock.patch.object(agent_mod, "wlan_block", return_value={k: None for k in agent_mod.WLAN_FIELDS}), \
                mock.patch.object(agent_mod, "probe_endpoint",
                                  return_value={"key": "gateway", "rtt_ms": 1.0,
                                                "loss_pct": 0.0, "jitter_ms": 0.0,
                                                "method": "icmp"}):
            record = agent_mod.collect_sample(self._cfg(), now=1000.0)
        self.assertEqual(set(record), {"t", "epoch", "interval_s", "gateway", "dns",
                                       "targets", "wlan"})
        self.assertEqual(record["interval_s"], 10)
        self.assertEqual(record["epoch"], 1000.0)
        self.assertIn("+08:00", record["t"])

    def test_gateway_block_has_no_key(self):
        with mock.patch.object(agent_mod, "_gateway", return_value="192.168.1.1"), \
                mock.patch.object(agent_mod, "_first_dns", return_value=""), \
                mock.patch.object(agent_mod, "wlan_block", return_value={}), \
                mock.patch.object(agent_mod, "probe_endpoint",
                                  return_value={"key": "gateway", "rtt_ms": 1.0,
                                                "loss_pct": 0.0, "jitter_ms": 0.0,
                                                "method": "icmp"}):
            record = agent_mod.collect_sample(self._cfg(), now=1000.0)
        self.assertNotIn("key", record["gateway"], "网关块不该自报家门")

    def test_missing_gateway_and_dns_are_none_not_zero(self):
        with mock.patch.object(agent_mod, "_gateway", return_value=""), \
                mock.patch.object(agent_mod, "_first_dns", return_value=""), \
                mock.patch.object(agent_mod, "wlan_block", return_value={}):
            record = agent_mod.collect_sample(self._cfg(), now=1000.0)
        self.assertIsNone(record["gateway"])
        self.assertIsNone(record["dns"], "没有 DNS 是「没采样」，不是 0 丢包")

    def test_targets_keep_configured_order(self):
        cfg = self._cfg(targets=[{"key": "a", "host": "1.1.1.1"},
                                 {"key": "b", "host": "2.2.2.2", "port": 443}])
        with mock.patch.object(agent_mod, "_gateway", return_value=""), \
                mock.patch.object(agent_mod, "_first_dns", return_value=""), \
                mock.patch.object(agent_mod, "wlan_block", return_value={}), \
                mock.patch.object(agent_mod, "probe_endpoint",
                                  side_effect=lambda key, host, port=None, **kw:
                                  {"key": key, "port": port, "rtt_ms": 1.0,
                                   "loss_pct": 0.0, "jitter_ms": 0.0, "method": "icmp"}):
            record = agent_mod.collect_sample(cfg, now=1000.0)
        self.assertEqual([t["key"] for t in record["targets"]], ["a", "b"])
        self.assertIsNone(record["targets"][0]["port"])

    def test_wlan_block_keeps_seven_keys_when_netsh_fails(self):
        with mock.patch.object(agent_mod.wlan, "link_info", side_effect=OSError("boom")):
            block = agent_mod.wlan_block()
        self.assertEqual(set(block), set(agent_mod.WLAN_FIELDS))
        self.assertTrue(all(v is None for v in block.values()))

    def test_wlan_block_maps_netsh_fields(self):
        info = {"ssid": "RR", "bssid": "aa:bb", "rssi_dbm": -54,
                "rx_mbps": 433.3, "tx_mbps": 433.3, "band": "5 GHz",
                "channel": 153, "snr_est_db": 41}
        with mock.patch.object(agent_mod.wlan, "link_info", return_value=info):
            block = agent_mod.wlan_block()
        self.assertEqual(block["bssid"], "aa:bb")
        self.assertEqual(block["channel"], 153)
        self.assertNotIn("snr_est_db", block, "热力图字段是固定 7 个，不多带派生值")


# ---------------------------------------------------------------- 事件

class EventTrackerTest(_AgentCase):
    """连续 2 次才落事件；同一场故障只落 1 条；恢复后重新武装。"""

    @staticmethod
    def _record(epoch: float, rtt: float | None = None, jitter: float | None = 0.0,
                loss: float | None = 0.0, bssid: str | None = None) -> dict:
        return {
            "t": f"T{epoch}",
            "epoch": epoch,
            "gateway": {"rtt_ms": rtt, "loss_pct": loss, "jitter_ms": jitter,
                        "method": "icmp"},
            "targets": [],
            "wlan": {"bssid": bssid, "rssi_dbm": -60},
        }

    def test_single_hit_does_not_fire(self):
        tracker = agent_mod.EventTracker()
        self.assertEqual(tracker.observe(self._record(1000.0, rtt=500.0)), [])

    def test_two_consecutive_hits_fire_once(self):
        tracker = agent_mod.EventTracker()
        tracker.observe(self._record(1000.0, rtt=500.0))
        events = tracker.observe(self._record(1010.0, rtt=500.0))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["target"], "gateway")
        self.assertEqual(event["type"], "rtt")
        self.assertEqual(event["value"], 500.0)
        self.assertEqual(event["threshold"], 120.0)
        self.assertEqual(event["duration_s"], 10.0)

    def test_ongoing_fault_does_not_repeat(self):
        tracker = agent_mod.EventTracker()
        fired = []
        for i in range(6):
            fired += tracker.observe(self._record(1000.0 + i * 10, rtt=500.0))
        self.assertEqual(len(fired), 1, "条件没恢复就不该再写事件")

    def test_recovery_rearms_tracker(self):
        tracker = agent_mod.EventTracker()
        tracker.observe(self._record(1000.0, rtt=500.0))
        self.assertEqual(len(tracker.observe(self._record(1010.0, rtt=500.0))), 1)
        tracker.observe(self._record(1020.0, rtt=10.0))      # 恢复
        tracker.observe(self._record(1030.0, rtt=500.0))
        self.assertEqual(len(tracker.observe(self._record(1040.0, rtt=500.0))), 1,
                         "恢复后再次连续越线应算新事件")

    def test_value_equal_to_threshold_does_not_fire(self):
        tracker = agent_mod.EventTracker()
        tracker.observe(self._record(1000.0, rtt=120.0))
        self.assertEqual(tracker.observe(self._record(1010.0, rtt=120.0)), [])

    def test_missing_value_breaks_the_streak(self):
        tracker = agent_mod.EventTracker()
        tracker.observe(self._record(1000.0, rtt=500.0))
        tracker.observe(self._record(1010.0, rtt=None))       # 没测到
        self.assertEqual(tracker.observe(self._record(1020.0, rtt=500.0)), [],
                         "中间断了一次，连续计数要归零")

    def test_loss_type_uses_loss_threshold(self):
        tracker = agent_mod.EventTracker()
        tracker.observe(self._record(1000.0, loss=50.0))
        events = tracker.observe(self._record(1010.0, loss=50.0))
        self.assertEqual(events[0]["type"], "loss")
        self.assertEqual(events[0]["threshold"], 2.0)

    def test_jitter_type(self):
        tracker = agent_mod.EventTracker()
        tracker.observe(self._record(1000.0, jitter=90.0))
        events = tracker.observe(self._record(1010.0, jitter=90.0))
        self.assertEqual(events[0]["type"], "jitter")
        self.assertEqual(events[0]["threshold"], 40.0)

    def test_event_carries_wlan_snapshot(self):
        tracker = agent_mod.EventTracker()
        tracker.observe(self._record(1000.0, rtt=500.0, bssid="aa:bb:cc"))
        event = tracker.observe(self._record(1010.0, rtt=500.0, bssid="aa:bb:cc"))[0]
        self.assertEqual(event["bssid"], "aa:bb:cc")
        self.assertEqual(event["rssi_dbm"], -60)

    def test_targets_are_tracked_by_key(self):
        tracker = agent_mod.EventTracker()
        record = {"t": "T", "epoch": 1000.0, "gateway": None, "wlan": {},
                  "targets": [{"key": "公司官网", "rtt_ms": 900.0, "loss_pct": 0.0,
                               "jitter_ms": 0.0, "method": "tcp"}]}
        tracker.observe(record)
        record2 = dict(record, epoch=1010.0)
        events = tracker.observe(record2)
        self.assertEqual(events[0]["target"], "公司官网")

    def test_custom_consecutive_one_fires_immediately(self):
        tracker = agent_mod.EventTracker(consecutive=1)
        self.assertEqual(len(tracker.observe(self._record(1000.0, rtt=500.0))), 1)

    def test_thresholds_from_config_object(self):
        tracker = agent_mod.EventTracker({"rtt_ms": 10})
        tracker.observe(self._record(1000.0, rtt=50.0))
        events = tracker.observe(self._record(1010.0, rtt=50.0))
        self.assertEqual(events[0]["threshold"], 10.0)


# ---------------------------------------------------------------- 落盘

class HistoryWriterTest(_AgentCase):
    """分片、滚动、清理：这三件事一起决定「历史还在不在」。"""

    def _record(self, epoch: float) -> dict:
        return {"t": agent_mod._iso(epoch), "epoch": epoch, "interval_s": 10,
                "gateway": None, "dns": None, "targets": [],
                "wlan": {k: None for k in agent_mod.WLAN_FIELDS}}

    def test_append_writes_one_jsonl_line(self):
        path = agent_mod.append_record(self._record(1000.0))
        self.assertTrue(path.is_file())
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertEqual(payload["epoch"], 1000.0)
        self.assertEqual(set(payload["wlan"]), set(agent_mod.WLAN_FIELDS))

    def test_append_is_append_not_overwrite(self):
        agent_mod.append_record(self._record(1000.0))
        path = agent_mod.append_record(self._record(1010.0))
        self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 2)

    def test_file_rolls_when_exceeding_limit(self):
        first = agent_mod.append_record(self._record(1000.0), max_bytes=1)
        second = agent_mod.append_record(self._record(1010.0), max_bytes=1)
        self.assertNotEqual(first, second)
        self.assertRegex(second.name, r"^\d{4}-\d{2}-\d{2}\.1\.jsonl$")

    def test_prune_history_drops_old_shards_only(self):
        directory = agent_mod.history_dir()
        directory.mkdir(parents=True, exist_ok=True)
        for name in ("2026-11-01.jsonl", "2026-11-01.2.jsonl", "2026-11-10.jsonl",
                     "events.jsonl", "marks.jsonl", "notes.txt"):
            (directory / name).write_text("{}\n", encoding="utf-8")
        removed = agent_mod.prune_history(
            retain_days=7, today=agent_mod.dt.date(2026, 11, 11))
        self.assertEqual(sorted(removed), ["2026-11-01.2.jsonl", "2026-11-01.jsonl"])
        self.assertTrue((directory / "2026-11-10.jsonl").is_file())
        self.assertTrue((directory / "events.jsonl").is_file())
        self.assertTrue((directory / "notes.txt").is_file())

    def test_prune_events_keeps_recent_and_drops_bad_lines(self):
        path = agent_mod.events_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        now = 1_800_000_000.0
        rows = [
            json.dumps({"epoch": now - 10, "target": "gateway"}, ensure_ascii=False),
            json.dumps({"epoch": now - 40 * 86400, "target": "gateway"}, ensure_ascii=False),
            "not json",
        ]
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        dropped = agent_mod.prune_events(retain_days=30, path=path, now=now)
        self.assertEqual(dropped, 2)
        kept = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(kept), 1)
        self.assertEqual(json.loads(kept[0])["epoch"], now - 10)

    def test_append_event_creates_file(self):
        path = agent_mod.append_event({"epoch": 1, "target": "gateway"})
        self.assertTrue(path.is_file())
        self.assertEqual(path.name, "events.jsonl")


# ---------------------------------------------------------------- 告警节流

class WarnGateTest(_AgentCase):
    """断网时每轮都失败，日志不能被刷爆。"""

    def test_first_warn_passes_then_throttled(self):
        sink = mock.Mock()
        gate = agent_mod.WarnGate(every_s=60.0, clock=lambda: 1000.0, sink=sink)
        self.assertTrue(gate.warn("采样失败"))
        self.assertFalse(gate.warn("采样失败"))
        self.assertFalse(gate.warn("采样失败"))
        self.assertEqual(sink.call_count, 1)

    def test_suppressed_count_is_merged_into_next_line(self):
        sink = mock.Mock()
        now = {"t": 1000.0}
        gate = agent_mod.WarnGate(every_s=60.0, clock=lambda: now["t"], sink=sink)
        gate.warn("采样失败")
        gate.warn("采样失败")
        gate.warn("采样失败")
        now["t"] = 1061.0
        gate.warn("采样失败")
        text = sink.call_args_list[-1][0][0]
        self.assertIn("另有 2 条", text)
        self.assertTrue(text.startswith("WARN"))

    def test_throttle_window_measured_in_seconds(self):
        sink = mock.Mock()
        now = {"t": 0.0}
        gate = agent_mod.WarnGate(every_s=60.0, clock=lambda: now["t"], sink=sink)
        gate.warn("a")
        now["t"] = 30.0
        self.assertFalse(gate.warn("b"))
        now["t"] = 60.0
        self.assertTrue(gate.warn("c"))


# ---------------------------------------------------------------- 主循环

class AgentLoopTest(_AgentCase):
    """主循环：跑得动、间隔对了、出错不退出、单实例生效。"""

    def _agent(self, sampler, cycles_log=None, cfg=None):
        cfg = cfg or {"interval_s": 10, "targets": [], "thresholds": {},
                      "icmp_count": 2, "icmp_timeout_ms": 800, "tcp_timeout_s": 1.5}
        clock = {"t": 0.0}

        def fake_sleep(seconds):
            clock["t"] += seconds
            if cycles_log is not None:
                cycles_log.append(seconds)

        return agent_mod.Agent(
            config_loader=lambda: dict(cfg),
            sampler=sampler,
            record_writer=lambda record: None,
            event_writer=lambda event: None,
            clock=lambda: clock["t"],
            sleeper=fake_sleep,
        )

    def _record(self, epoch=0.0):
        return {"t": "T", "epoch": epoch, "interval_s": 10, "gateway": None,
                "dns": None, "targets": [], "wlan": {}}

    def test_runs_requested_cycles(self):
        calls = []
        sleeps = []
        loop = self._agent(lambda cfg: calls.append(1) or self._record(), sleeps)
        code = loop.run(max_cycles=3, guard_instance=False)
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 3)
        self.assertEqual(loop.cycles, 3)

    def test_waits_interval_minus_elapsed(self):
        sleeps = []
        loop = self._agent(lambda cfg: self._record(), sleeps)
        loop.run(max_cycles=3, guard_instance=False)
        self.assertEqual(sleeps, [10.0, 10.0], "最后一轮结束后不该再等")

    def test_interval_change_takes_effect_next_cycle_and_is_logged(self):
        """第 2 轮采样**期间**改配置：本轮仍按 10s 等，第 3 轮才用 30s。"""
        cfg = {"interval_s": 10, "targets": [], "thresholds": {},
               "icmp_count": 2, "icmp_timeout_ms": 800, "tcp_timeout_s": 1.5}
        sleeps = []
        calls = {"n": 0}

        def sampler(_cfg):
            calls["n"] += 1
            if calls["n"] == 2:
                cfg["interval_s"] = 30        # 本轮配置已经读过了，改动下轮生效
            return self._record()

        loop = self._agent(sampler, sleeps, cfg=cfg)
        with mock.patch.object(agent_mod, "_log_line") as log:
            loop.run(max_cycles=4, guard_instance=False)
        self.assertEqual(sleeps, [10.0, 10.0, 30.0],
                         "改动应在下一轮生效：第 2 轮仍等旧间隔，第 3 轮才用 30s")
        messages = [c[0][0] for c in log.call_args_list]
        self.assertTrue(any("10s → 30s" in m for m in messages),
                        f"缺少间隔变更日志：{messages}")

    def test_sampler_error_does_not_stop_the_loop(self):
        calls = []

        def sampler(cfg):
            calls.append(1)
            if len(calls) == 2:
                raise OSError("disk gone")
            return self._record(len(calls))

        warner = mock.Mock()
        loop = self._agent(sampler)
        loop.warner = warner
        code = loop.run(max_cycles=3, guard_instance=False)
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 3, "单次失败后必须继续")
        self.assertEqual(loop.cycles, 2, "失败的轮次不计入成功采样数")
        warner.warn.assert_called_once()

    def test_single_instance_blocks_second_agent(self):
        calls = []
        loop = self._agent(lambda cfg: calls.append(1) or self._record())
        lock = agent_mod.instance_path()
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text("1", encoding="utf-8")          # 另一个「活着的」实例
        with mock.patch.object(agent_mod, "_pid_alive", return_value=True):
            code = loop.run(max_cycles=1, guard_instance=True)
        self.assertEqual(code, 0)
        self.assertEqual(calls, [], "已有实例时不该再采样")
        self.assertEqual(loop.cycles, 0)


class InstanceTest(_AgentCase):
    """单实例锁：活进程要拒，死进程要覆盖（否则崩溃一次就再也起不来）。"""

    def test_acquire_then_release(self):
        path = self.tmp / "agent.pid"
        self.assertTrue(agent_mod.acquire_instance(path))
        self.assertEqual(path.read_text(encoding="utf-8").strip(), str(os.getpid()))
        agent_mod.release_instance(path)
        self.assertFalse(path.exists())

    def test_alive_other_pid_blocks(self):
        path = self.tmp / "agent.pid"
        path.write_text("1", encoding="utf-8")
        with mock.patch.object(agent_mod, "_pid_alive", return_value=True):
            self.assertFalse(agent_mod.acquire_instance(path))

    def test_stale_pid_is_overwritten(self):
        path = self.tmp / "agent.pid"
        path.write_text("999999", encoding="utf-8")
        with mock.patch.object(agent_mod, "_pid_alive", return_value=False):
            self.assertTrue(agent_mod.acquire_instance(path))
        self.assertEqual(path.read_text(encoding="utf-8").strip(), str(os.getpid()))

    def test_garbage_pid_file_is_overwritten(self):
        path = self.tmp / "agent.pid"
        path.write_text("not-a-pid", encoding="utf-8")
        self.assertTrue(agent_mod.acquire_instance(path))

    def test_release_only_removes_own_pid(self):
        path = self.tmp / "agent.pid"
        path.write_text("1", encoding="utf-8")
        agent_mod.release_instance(path)
        self.assertTrue(path.exists(), "不该删掉别的实例的锁")


# ---------------------------------------------------------------- 命令行

class AgentCliTest(_AgentCase):
    """``--once`` / ``--status`` / ``--interval`` 三个直连命令。"""

    def test_once_prints_record_json(self):
        record = {"t": "T", "epoch": 1.0, "interval_s": 10, "gateway": None,
                  "dns": None, "targets": [], "wlan": {}}
        buffer = io.StringIO()
        with mock.patch.object(agent_mod, "collect_sample", return_value=record), \
                contextlib.redirect_stdout(buffer):
            code = agent_mod.main(["--once"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue())["interval_s"], 10)

    def test_interval_writes_config(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = agent_mod.main(["--interval", "30"])
        self.assertEqual(code, 0)
        self.assertEqual(config_mod.load_agent()["interval_s"], 30)
        self.assertIn("30s", buffer.getvalue())

    def test_interval_rejects_illegal_value(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = agent_mod.main(["--interval", "7"])
        self.assertEqual(code, 2)
        self.assertIn("5", buffer.getvalue())

    def test_status_reports_history_dir(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = agent_mod.main(["--status"])
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue().split("\n分片")[0])
        self.assertEqual(payload["history_dir"], str(agent_mod.history_dir()))
        self.assertEqual(payload["samples_total"], 0)

    def test_build_agent_uses_configured_thresholds(self):
        """``--daemon`` 的阈值必须来自配置，而不是模块默认值。"""
        self.write_config({"thresholds": {"rtt_ms": 300}})
        built = agent_mod.build_agent()
        self.assertIsNotNone(built.tracker)
        self.assertEqual(built.tracker.thresholds["rtt_ms"], 300.0)
        self.assertEqual(built.tracker.thresholds["jitter_ms"], 40.0)

    def test_no_args_prints_usage_and_returns_2(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = agent_mod.main([])
        self.assertEqual(code, 2)
        self.assertIn("--daemon", buffer.getvalue())


# ---------------------------------------------------------------- 安装脚本

class AgentInstallScriptTest(unittest.TestCase):
    """两条 bat 只用 schtasks、只建一个任务、纯 ASCII、CRLF。"""

    def setUp(self) -> None:
        self.install = (ROOT / "install-agent.bat").read_bytes()
        self.uninstall = (ROOT / "uninstall-agent.bat").read_bytes()

    def test_files_exist(self):
        self.assertTrue((ROOT / "install-agent.bat").is_file())
        self.assertTrue((ROOT / "uninstall-agent.bat").is_file())

    def test_pure_ascii(self):
        for name, raw in (("install", self.install), ("uninstall", self.uninstall)):
            with self.subTest(script=name):
                bad = [b for b in raw if b >= 0x80]
                self.assertEqual(bad, [], f"{name}-agent.bat 出现非 ASCII 字节")

    def test_crlf_line_endings(self):
        for name, raw in (("install", self.install), ("uninstall", self.uninstall)):
            with self.subTest(script=name):
                self.assertGreater(raw.count(b"\r\n"), 10, f"{name} 不是 CRLF")

    def test_install_creates_logon_task_with_limited_rights(self):
        text = self.install.decode("ascii")
        self.assertIn('set "TASK_NAME=NetDiag Agent"', text)
        self.assertIn('schtasks /create /tn "%TASK_NAME%"', text)
        self.assertIn("/sc onlogon", text)
        self.assertIn("/delay 0001:00", text)
        self.assertIn("/rl limited", text)
        self.assertIn("--daemon", text)
        self.assertIn("/f", text)

    def test_install_never_installs_a_service(self):
        text = self.install.decode("ascii").lower()
        for banned in ("sc create", "sc.exe", "new-service", "instsrv", "srvany"):
            self.assertNotIn(banned, text, "agent 不许装 Windows 服务")

    def test_install_has_no_silent_uac(self):
        text = self.install.decode("ascii").lower()
        self.assertNotIn("runas", text, "安装脚本不该提权")
        self.assertNotIn("-verb runas", text)

    def test_uninstall_deletes_the_same_task(self):
        text = self.uninstall.decode("ascii")
        self.assertIn('schtasks /delete /tn "%TASK_NAME%" /f', text)

    def test_uninstall_keeps_history(self):
        text = self.uninstall.decode("ascii").lower()
        self.assertNotIn("rd /s", text, "卸载不许删历史数据")
        self.assertNotIn("del logs", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
