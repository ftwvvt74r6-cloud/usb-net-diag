"""T2 契约测试：``/api/history*`` 五个接口 + ``core/history.py`` 的聚合/缺口/导出口径。

为什么分五层钉
--------------
历史接口最容易「看起来对、实际错」的地方不在路由，而在口径：

* **聚合**：把「没测到」聚成 0，图上就是一条贴着横轴的完美直线 —— 用户会以为
  网络从来没坏过。所以 ``rtt_ms`` 必须是 ``null``，不是 ``0``。
* **时间**：``series[].t`` 必须是 **epoch 秒**。``history.js`` 用
  ``Number(s.t)`` 过滤、``new Date(t * 1000)`` 画横轴 —— 给它 ISO 字符串，
  点会被整批过滤掉，界面只会显示「没数据」。
* **缺口**：断档的桶不能补点连线。``coverage.gaps`` 是缺失桶数，
  ``coverage.gap_ranges`` 给出真实起止；空区间也必须报缺口，不许回 ``gaps: 0``。
* **导出**：CSV 列头是给 Excel 公式用的契约，列序/列名改一个字符，别人的表就错位。
* **路由**：非法参数必须 400 并说明原因，不许静默回落成默认区间。

``NETDIAG_LOG_DIR`` 指向临时目录，不碰仓库 ``logs/``。
"""
from __future__ import annotations

import datetime as dt
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import history as history_mod  # noqa: E402  扁平导入 = server 里用的那一份
import logstore  # noqa: E402
import server  # noqa: E402

#: 任务单钉死的 CSV 列头。**逐字符**比较：列序就是契约。
CSV_HEADER = ("time,interval_s,gateway_rtt_ms,gateway_loss_pct,gateway_jitter_ms,"
              "dns_rtt_ms,target_key,target_rtt_ms,target_loss_pct,"
              "bssid,rssi_dbm,rx_mbps,band,channel")


def _local(when: float) -> dt.datetime:
    """epoch → 本地 aware datetime（测试里造期望值时用）。"""
    return dt.datetime.fromtimestamp(float(when), tz=dt.timezone.utc).astimezone()


class _HistoryCase(unittest.TestCase):
    """把日志根指到临时目录，并提供造样本 / 造事件的快捷方法。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.logs = self.tmp / "logs"
        self.dir = self.logs / "history"
        self.dir.mkdir(parents=True)
        self._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(self.logs)})
        self._env.start()
        # 固定基准：2026-11-11 10:00:00 本地时间
        self.base = dt.datetime(2026, 11, 11, 10, 0, 0).timestamp()
        self.day = history_mod.iso(self.base)[:10]

    def tearDown(self) -> None:
        # 日志句柄在 Windows 上会锁住文件，不先关掉临时目录删不掉（WinError 32）
        logstore.close_streams()
        self._env.stop()
        self._tmp.cleanup()

    # ---- 造数据

    def sample(self, offset: float, **over) -> dict:
        """造一条样本：``offset`` 是相对基准时间的秒数。"""
        epoch = self.base + float(offset)
        record = {
            "t": history_mod.iso(epoch),
            "epoch": round(epoch, 3),
            "interval_s": 10,
            "gateway": {"rtt_ms": 5.0, "loss_pct": 0.0, "jitter_ms": 1.0,
                        "method": "icmp"},
            "dns": {"rtt_ms": 9.0, "loss_pct": 0.0, "jitter_ms": 2.0,
                    "method": "icmp"},
            "targets": [{"key": "baidu", "rtt_ms": 20.0, "loss_pct": 0.0,
                         "jitter_ms": 3.0, "method": "icmp"}],
            "wlan": {"ssid": "Home-5G", "bssid": "aa:bb:cc:00:00:01",
                     "rssi_dbm": -55, "rx_mbps": 300, "tx_mbps": 200,
                     "band": "5G", "channel": 36},
        }
        record.update(over)
        return record

    def write(self, records, *, name: str | None = None) -> Path:
        """写一个样本分片（默认当天主分片）。"""
        path = self.dir / (name or f"{self.day}.jsonl")
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return path

    def write_events(self, events) -> Path:
        """写 ``events.jsonl``。"""
        path = self.dir / "events.jsonl"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for event in events:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        return path

    def event(self, offset: float, *, target="gateway", etype="rtt",
              value=200.0, threshold=120.0, bssid="aa:bb:cc:00:00:01",
              rssi=-55) -> dict:
        """造一条事件（字段与 ``agent.EventTracker.observe`` 一致）。"""
        epoch = self.base + float(offset)
        return {"t": history_mod.iso(epoch), "epoch": round(epoch, 3),
                "target": target, "type": etype, "value": value,
                "threshold": threshold, "duration_s": 60,
                "bssid": bssid, "rssi_dbm": rssi}

    def _read(self, start_off=0, end_off=600):
        return history_mod.read_samples(self.base + start_off, self.base + end_off)


# ====================================================================== 参数解析

class HistoryParseTest(_HistoryCase):
    """时间 / 区间 / 桶的解析：错就 400，对就必须准。"""

    def test_parse_time_accepts_epoch_and_numeric_text(self):
        self.assertEqual(history_mod.parse_time(1762000000, default=0), 1762000000.0)
        self.assertEqual(history_mod.parse_time("1762000000.5", default=0), 1762000000.5)

    def test_parse_time_accepts_iso_with_offset(self):
        self.assertEqual(history_mod.parse_time("2026-11-11T10:00:00+08:00", default=0),
                         dt.datetime(2026, 11, 11, 2, 0, 0,
                                     tzinfo=dt.timezone.utc).timestamp())

    def test_parse_time_treats_naive_as_local(self):
        expected = dt.datetime(2026, 11, 11, 10, 0, 0).timestamp()
        self.assertEqual(history_mod.parse_time("2026-11-11T10:00:00", default=0),
                         expected)
        self.assertEqual(history_mod.parse_time("2026-11-11 10:00", default=0),
                         expected)
        self.assertEqual(history_mod.parse_time("2026-11-11", default=0),
                         dt.datetime(2026, 11, 11, 0, 0, 0).timestamp())

    def test_parse_time_handles_z_suffix(self):
        self.assertEqual(history_mod.parse_time("2026-11-11T02:00:00Z", default=0),
                         dt.datetime(2026, 11, 11, 2, 0, 0,
                                     tzinfo=dt.timezone.utc).timestamp())

    def test_parse_time_empty_falls_back_to_default(self):
        for value in (None, "", "   "):
            with self.subTest(value=value):
                self.assertEqual(history_mod.parse_time(value, default=42.0), 42.0)

    def test_parse_time_rejects_garbage(self):
        with self.assertRaises(ValueError):
            history_mod.parse_time("昨天下午", default=0)

    def test_parse_range_defaults_to_last_hour(self):
        start, end = history_mod.parse_range(None, None, now=1_000_000)
        self.assertEqual(end, 1_000_000.0)
        self.assertEqual(start, 1_000_000.0 - 3600)

    def test_parse_range_rejects_reversed(self):
        with self.assertRaises(ValueError) as ctx:
            history_mod.parse_range("2026-11-11T11:00:00", "2026-11-11T10:00:00")
        self.assertIn("晚于", str(ctx.exception))

    def test_bucket_seconds_whitelist(self):
        self.assertEqual(history_mod.bucket_seconds("1m"), ("1m", 60))
        self.assertEqual(history_mod.bucket_seconds("5M"), ("5m", 300))
        self.assertEqual(history_mod.bucket_seconds("1h"), ("1h", 3600))
        self.assertEqual(history_mod.bucket_seconds(None), ("1m", 60))
        with self.assertRaises(ValueError):
            history_mod.bucket_seconds("2m")

    def test_bucket_start_aligns_to_local_clock(self):
        # 5m 桶落在 :00/:05/…（按本地时间对齐，不是按 UTC 对齐）
        stamp = self.base + 7 * 60
        aligned = history_mod.bucket_start(stamp, 300)
        local = _local(aligned)
        self.assertEqual((local.minute % 5, local.second), (0, 0))
        self.assertEqual(local.hour, _local(stamp).hour)

        hour = history_mod.bucket_start(stamp, 3600)
        local = _local(hour)
        self.assertEqual((local.minute, local.second), (0, 0))
        self.assertEqual(local.hour, _local(stamp).hour)

    def test_bucket_start_is_idempotent(self):
        for seconds in (60, 300, 3600):
            with self.subTest(seconds=seconds):
                once = history_mod.bucket_start(self.base + 123, seconds)
                self.assertEqual(history_mod.bucket_start(once, seconds), once)


# ====================================================================== 聚合

class HistoryAggregateTest(_HistoryCase):
    """series：均值 / 最大 / 主 BSSID、缺测不补 0、空桶不出现、时间是 epoch 秒。"""

    def test_rtt_mean_loss_max_jitter_mean(self):
        self.write([self.sample(0, targets=self._target(rtt=4.0, loss=0.0, jitter=1.0)),
                    self.sample(10, targets=self._target(rtt=8.0, loss=6.0, jitter=2.0))])
        points = history_mod.aggregate_points(self._read(), 60)
        self.assertEqual(len(points), 1)
        point = points[0]
        self.assertEqual(point["n"], 2)
        self.assertEqual(point["rtt_ms"], 6.0)      # 均值
        self.assertEqual(point["loss_pct"], 6.0)    # 最大值，不是 3
        self.assertEqual(point["jitter_ms"], 1.5)   # 均值

    @staticmethod
    def _target(rtt=20.0, loss=0.0, jitter=3.0):
        return [{"key": "baidu", "rtt_ms": rtt, "loss_pct": loss,
                 "jitter_ms": jitter, "method": "icmp"}]

    def test_missing_measurement_is_null_not_zero(self):
        # ICMP 被禁：rtt/jitter 拿不到；loss 是真实测得的 100%
        self.write([self.sample(0, targets=[{"key": "baidu", "rtt_ms": None,
                                             "loss_pct": 100.0, "jitter_ms": None,
                                             "method": "none"}])])
        point = history_mod.aggregate_points(self._read(), 60)[0]
        self.assertIsNone(point["rtt_ms"])
        self.assertIsNone(point["jitter_ms"])
        self.assertEqual(point["loss_pct"], 100.0)
        # 关键：不是 0（0 会被读成「0 毫秒，网络极好」）
        self.assertNotEqual(point["rtt_ms"], 0)

    def test_gap_bucket_is_absent_from_series(self):
        # 10:00 与 10:02 有数据，10:01 整段没有 → 只出两个点，绝不补一个 0 点
        self.write([self.sample(0), self.sample(120)])
        points = history_mod.aggregate_points(self._read(), 60)
        self.assertEqual(len(points), 2)
        self.assertEqual([p["ts"][11:16] for p in points], ["10:00", "10:02"])

    def test_point_time_is_epoch_seconds(self):
        # history.js: Number(s.t) 过滤 + new Date(t * 1000) 画横轴
        self.write([self.sample(0)])
        point = history_mod.aggregate_points(self._read(), 60)[0]
        self.assertIsInstance(point["t"], float)
        self.assertEqual(point["t"], self.base)
        self.assertEqual(point["ts"], history_mod.iso(self.base))
        self.assertIn("+", point["ts"][-6:], "对外时间必须带时区偏移")

    def test_bssid_is_primary_ap_of_bucket(self):
        self.write([
            self.sample(0, wlan={**self.sample(0)["wlan"], "bssid": "aa:00"}),
            self.sample(10, wlan={**self.sample(0)["wlan"], "bssid": "bb:00"}),
            self.sample(20, wlan={**self.sample(0)["wlan"], "bssid": "aa:00"}),
        ])
        self.assertEqual(history_mod.aggregate_points(self._read(), 60)[0]["bssid"],
                         "aa:00")

    def test_bssid_null_when_no_wireless(self):
        empty = {"ssid": None, "bssid": None, "rssi_dbm": None, "rx_mbps": None,
                 "tx_mbps": None, "band": None, "channel": None}
        self.write([self.sample(0, wlan=empty)])
        point = history_mod.aggregate_points(self._read(), 60)[0]
        self.assertIsNone(point["bssid"])
        self.assertIsNone(point["rssi_dbm"])
        self.assertIsNone(point["rx_mbps"])

    def test_point_carries_rssi_and_rx_mean(self):
        self.write([self.sample(0, wlan={**self.sample(0)["wlan"], "rssi_dbm": -50,
                                         "rx_mbps": 200}),
                    self.sample(10, wlan={**self.sample(0)["wlan"], "rssi_dbm": -60,
                                          "rx_mbps": 400})])
        point = history_mod.aggregate_points(self._read(), 60)[0]
        self.assertEqual(point["rssi_dbm"], -55.0)
        self.assertEqual(point["rx_mbps"], 300.0)

    def test_series_keys_keeps_target_prefix(self):
        # 目标恰好叫 gateway：不带前缀就会和网关序列撞名
        self.write([self.sample(0, targets=[{"key": "gateway", "rtt_ms": 30.0,
                                             "loss_pct": 0.0, "jitter_ms": 1.0,
                                             "method": "icmp"}])])
        self.assertEqual(history_mod.series_keys(self._read()),
                         ["gateway", "dns", "target:gateway"])

    def test_reads_rolled_shards_and_sorts_by_time(self):
        # 滚动后主分片重新接收新数据：文件名顺序 ≠ 时间顺序，必须按 epoch 排
        self.write([self.sample(120)], name=f"{self.day}.1.jsonl")
        self.write([self.sample(0)])
        stamps = [rec["epoch"] for rec in self._read()]
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual(len(stamps), 2)

    def test_skips_broken_lines_and_out_of_range(self):
        path = self.dir / f"{self.day}.jsonl"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(self.sample(0)) + "\n")
            handle.write("{半行截断\n")
            handle.write("\n")
            handle.write(json.dumps({"t": "x", "epoch": "not-a-number"}) + "\n")
            handle.write(json.dumps(self.sample(10)) + "\n")
        self.assertEqual(len(self._read(0, 60)), 2)
        # 区间过滤：只看前 5 秒 → 只剩第一条
        self.assertEqual(len(self._read(0, 5)), 1)


# ====================================================================== 看哪条曲线

class HistorySelectTest(_HistoryCase):
    """默认画哪条序列、能不能指定、指定错了怎么办。"""

    def test_default_target_is_first_configured_target(self):
        self.write([self.sample(0)])
        self.assertEqual(history_mod.primary_key(self._read()), "target:baidu")
        self.assertEqual(history_mod.aggregate_points(self._read(), 60)[0]["rtt_ms"],
                         20.0)

    def test_falls_back_to_dns_then_gateway(self):
        self.write([self.sample(0, targets=[])])
        self.assertEqual(history_mod.primary_key(self._read()), "dns")
        self.assertEqual(history_mod.aggregate_points(self._read(), 60)[0]["rtt_ms"],
                         9.0)
        self.write([self.sample(0, targets=[], dns=None)])
        self.assertEqual(history_mod.primary_key(self._read()), "gateway")
        self.assertEqual(history_mod.aggregate_points(self._read(), 60)[0]["rtt_ms"],
                         5.0)

    def test_explicit_target_by_key(self):
        self.write([self.sample(0)])
        points = history_mod.aggregate_points(self._read(), 60, "baidu")
        self.assertEqual(points[0]["rtt_ms"], 20.0)

    def test_explicit_gateway(self):
        self.write([self.sample(0)])
        points = history_mod.aggregate_points(self._read(), 60, "gateway")
        self.assertEqual(points[0]["rtt_ms"], 5.0)

    def test_unknown_target_rejected_when_data_exists(self):
        self.write([self.sample(0)])
        with self.assertRaises(ValueError) as ctx:
            history_mod.build_history(self.base, self.base + 60, "1m", "aliyun")
        self.assertIn("target", str(ctx.exception))
        self.assertIn("target:baidu", str(ctx.exception))

    def test_unknown_target_allowed_when_no_data(self):
        # 区间里一条数据都没有时回 400，会把「agent 还没跑」误报成「参数写错了」
        data = history_mod.build_history(self.base, self.base + 60, "1m", "aliyun")
        self.assertEqual((data["series"], data["target"]), ([], ""))


# ====================================================================== 覆盖率

class HistoryCoverageTest(_HistoryCase):
    """样本级覆盖（导出用）与桶级覆盖（界面断线用）两套口径都得对。"""

    def test_sample_coverage_empty_range_reports_one_explicit_gap(self):
        cover = history_mod.sample_coverage([], self.base, self.base + 600, 10)
        self.assertEqual(cover["samples"], 0)
        self.assertEqual(cover["expected"], 60)
        self.assertEqual(cover["ratio"], 0)
        self.assertEqual(len(cover["gaps"]), 1)
        gap = cover["gaps"][0]
        self.assertEqual(gap["from"], history_mod.iso(self.base))
        self.assertEqual(gap["to"], history_mod.iso(self.base + 600))
        self.assertEqual(gap["seconds"], 600)
        # 缺口里的缺失样本数是「该有但没有」，不是 0
        self.assertEqual(gap["missing"], 60)

    def test_sample_coverage_middle_gap_boundaries_and_missing(self):
        samples = [{"epoch": self.base + offset} for offset in (0, 10, 20, 60, 70)]
        cover = history_mod.sample_coverage(samples, self.base, self.base + 70, 10)
        self.assertEqual(cover["samples"], 5)
        self.assertEqual(len(cover["gaps"]), 1)
        gap = cover["gaps"][0]
        self.assertEqual(gap["from"], history_mod.iso(self.base + 20))
        self.assertEqual(gap["to"], history_mod.iso(self.base + 60))
        self.assertEqual(gap["seconds"], 40)
        self.assertEqual(gap["missing"], 3)      # 30/40/50

    def test_sample_coverage_leading_and_trailing_gaps(self):
        samples = [{"epoch": self.base + offset} for offset in (60, 70, 80)]
        cover = history_mod.sample_coverage(samples, self.base, self.base + 120, 10)
        self.assertEqual([(g["seconds"], g["missing"]) for g in cover["gaps"]],
                         [(60, 6), (40, 4)])

    def test_slight_jitter_is_not_a_gap(self):
        # 一轮采样本身要花几秒：14 秒间隔（1.4 倍）不算缺口，15 秒以上才算
        samples = [{"epoch": self.base + offset} for offset in (0, 14, 28)]
        self.assertEqual(
            history_mod.sample_coverage(samples, self.base, self.base + 28,
                                        10)["gaps"], [])

    def test_interval_defaults_to_mode_of_samples(self):
        samples = [{"epoch": self.base + i, "interval_s": 30} for i in range(3)]
        samples.append({"epoch": self.base + 5, "interval_s": 10})
        cover = history_mod.sample_coverage(samples, self.base, self.base + 5)
        self.assertEqual(cover["interval_s"], 30)

    def test_sample_coverage_ratio(self):
        samples = [{"epoch": self.base + offset} for offset in range(0, 600, 10)]
        cover = history_mod.sample_coverage(samples, self.base, self.base + 600, 10)
        self.assertEqual(cover["samples"], 60)
        self.assertEqual(cover["ratio"], 1.0)

    def test_bucket_gaps_counts_missing_buckets(self):
        # 10:00 / 10:02 / 10:03 有数据，10:01 缺 → gaps = 1
        self.write([self.sample(0), self.sample(120), self.sample(180)])
        data = history_mod.build_history(self.base, self.base + 180, "1m")
        cover = data["coverage"]
        self.assertEqual(cover["expected"], 4)
        self.assertEqual(cover["gaps"], 1)
        self.assertEqual(cover["samples"], 3)
        self.assertEqual([(g["from"][11:16], g["to"][11:16], g["missing"])
                          for g in cover["gap_ranges"]], [("10:01", "10:02", 1)])

    def test_bucket_gaps_merges_adjacent_buckets(self):
        self.write([self.sample(0), self.sample(300)])
        cover = history_mod.build_history(
            self.base, self.base + 300, "1m")["coverage"]
        self.assertEqual(cover["gaps"], 4)
        self.assertEqual(len(cover["gap_ranges"]), 1)
        self.assertEqual(cover["gap_ranges"][0]["seconds"], 240)

    def test_bucket_gaps_never_zero_without_data(self):
        # 空区间：全部桶都缺。填 0 会让前端显示「0 个缺口」，正好反了。
        data = history_mod.build_history(self.base, self.base + 600, "1m")
        cover = data["coverage"]
        self.assertEqual(data["series"], [])
        self.assertEqual(cover["samples"], 0)
        self.assertEqual(cover["expected"], 11)
        self.assertEqual(cover["gaps"], 11)
        self.assertNotEqual(cover["gaps"], 0)
        self.assertEqual(len(cover["gap_ranges"]), 1)

    def test_bucket_gaps_full_coverage_is_zero(self):
        self.write([self.sample(offset) for offset in (0, 60, 120, 180, 240)])
        cover = history_mod.build_history(
            self.base, self.base + 240, "1m")["coverage"]
        self.assertEqual((cover["gaps"], cover["ratio"]), (0, 1.0))


# ====================================================================== 载荷形状

class HistoryBuildTest(_HistoryCase):
    """``build_history`` 的键与形状：前端按这些键画图，少一个就是空白页。"""

    def test_payload_shape_matches_ui_contract(self):
        self.write([self.sample(0)])
        data = history_mod.build_history(self.base, self.base + 60, "1m")
        self.assertTrue(data["ok"])
        self.assertEqual(data["target"], "baidu")
        self.assertEqual(data["targets"], ["gateway", "dns", "target:baidu"])
        self.assertEqual(data["bucket"], "1m")
        self.assertEqual(data["samples"], 1)
        point = data["series"][0]
        for key in ("t", "rtt_ms", "loss_pct", "jitter_ms", "rssi_dbm",
                    "rx_mbps", "bssid"):
            with self.subTest(key=key):
                self.assertIn(key, point)
        self.assertEqual(set(data["coverage"]),
                         {"from", "to", "samples", "gaps", "expected", "ratio",
                          "bucket_s", "gap_ranges"})

    def test_marks_are_numeric_epoch(self):
        self.write([self.sample(0)])
        history_mod.add_mark("换过 AP", now=self.base + 30)
        data = history_mod.build_history(self.base, self.base + 60, "1m")
        self.assertEqual(len(data["marks"]), 1)
        self.assertIsInstance(data["marks"][0]["t"], float)
        self.assertEqual(data["marks"][0]["t"], round(self.base + 30, 3))
        self.assertEqual(data["marks"][0]["note"], "换过 AP")
        self.assertIn("+", data["marks"][0]["ts"][-6:])

    def test_accepts_iso_and_epoch_equally(self):
        self.write([self.sample(0)])
        by_epoch = history_mod.build_history(self.base, self.base + 60, "1m")
        by_iso = history_mod.build_history(history_mod.iso(self.base),
                                           history_mod.iso(self.base + 60), "1m")
        self.assertEqual(by_epoch["series"], by_iso["series"])
        self.assertEqual(by_epoch["from"], by_iso["from"])

    def test_marks_outside_range_are_dropped(self):
        self.write([self.sample(0)])
        history_mod.add_mark("区间外", now=self.base + 3600)
        data = history_mod.build_history(self.base, self.base + 60, "1m")
        self.assertEqual(data["marks"], [])


# ====================================================================== 事件形状

class HistoryEventViewTest(_HistoryCase):
    """事件字段：``type`` 映射成 latency/jitter/loss，时间同时给两种写法。"""

    def test_rtt_becomes_latency(self):
        self.assertEqual(history_mod.event_type_name("rtt"), "latency")
        self.assertEqual(history_mod.event_type_name("jitter"), "jitter")
        self.assertEqual(history_mod.event_type_name("loss"), "loss")
        self.assertEqual(history_mod.event_type_name(""), "")

    def test_event_view_has_all_ui_fields(self):
        view = history_mod.event_view(self.event(10, value=300.0, threshold=120.0))
        self.assertEqual(set(view), {"t", "ts", "target", "type", "value",
                                     "threshold", "duration_s", "bssid",
                                     "rssi_dbm"})
        self.assertEqual(view["type"], "latency")
        self.assertEqual(view["value"], 300.0)
        self.assertEqual(view["duration_s"], 60.0)
        self.assertEqual(view["bssid"], "aa:bb:cc:00:00:01")
        self.assertEqual(view["rssi_dbm"], -55.0)
        self.assertIsInstance(view["t"], float)
        self.assertEqual(view["t"], round(self.base + 10, 3))

    def test_event_view_missing_fields_become_null(self):
        view = history_mod.event_view({"epoch": self.base, "type": "loss"})
        self.assertIsNone(view["value"])
        self.assertIsNone(view["threshold"])
        self.assertIsNone(view["bssid"])
        self.assertIsNone(view["rssi_dbm"])
        self.assertEqual(view["target"], "")

    def test_events_sorted_by_time(self):
        self.write_events([self.event(30), self.event(0), self.event(20)])
        events = history_mod.read_events(self.base, self.base + 60)
        self.assertEqual([item["epoch"] for item in events],
                         sorted(item["epoch"] for item in events))


# ====================================================================== 导出

class HistoryExportTest(_HistoryCase):
    """CSV 列头固定、缺失留空、MD 摘要信息完备。"""

    def _samples(self, count=2, targets=None):
        records = []
        for index in range(count):
            record = self.sample(index * 10)
            if targets is not None:
                record["targets"] = targets
            records.append(record)
        self.write(records)
        return history_mod.read_samples(self.base, self.base + 600)

    def test_csv_header_is_fixed(self):
        self.assertEqual(",".join(history_mod.CSV_COLUMNS), CSV_HEADER)
        text = history_mod.export_csv(self._samples())
        self.assertEqual(text.splitlines()[0], CSV_HEADER)

    def test_csv_has_one_row_per_sample_and_target(self):
        samples = self._samples(3, targets=[
            {"key": "baidu", "rtt_ms": 20.0, "loss_pct": 0.0, "jitter_ms": 1.0},
            {"key": "aliyun", "rtt_ms": 30.0, "loss_pct": 0.0, "jitter_ms": 1.0},
        ])
        rows = history_mod.export_csv(samples).splitlines()
        self.assertEqual(len(rows), 1 + 3 * 2)
        self.assertIn(",baidu,20,0,", rows[1])

    def test_csv_leaves_missing_cells_empty(self):
        records = [self.sample(0, gateway=None, dns={"rtt_ms": None, "loss_pct": None,
                                                     "jitter_ms": None,
                                                     "method": "none"},
                               targets=[],
                               wlan={"ssid": None, "bssid": None, "rssi_dbm": None,
                                     "rx_mbps": None, "tx_mbps": None, "band": None,
                                     "channel": None})]
        self.write(records)
        samples = history_mod.read_samples(self.base, self.base + 60)
        row = history_mod.export_csv(samples).splitlines()[1].split(",")
        header = CSV_HEADER.split(",")
        cells = dict(zip(header, row))
        # 没有网关 / 没有目标 / 没有无线：全部留空，一个 0 都不许出现
        for column in ("gateway_rtt_ms", "gateway_loss_pct", "gateway_jitter_ms",
                       "dns_rtt_ms", "target_key", "target_rtt_ms",
                       "bssid", "rssi_dbm", "channel"):
            with self.subTest(column=column):
                self.assertEqual(cells[column], "")
        self.assertEqual(len(row), len(header))

    def test_csv_quotes_values_with_comma(self):
        text = history_mod.export_csv([
            {"epoch": self.base, "t": history_mod.iso(self.base), "interval_s": 10,
             "targets": [{"key": "北京,联通", "rtt_ms": 1.0, "loss_pct": 0.0}]}])
        self.assertIn('"北京,联通"', text)

    def test_markdown_contains_time_samples_coverage_and_top5(self):
        self.write([self.sample(i * 10) for i in range(6)])
        self.write_events([self.event(10, value=500.0, threshold=120.0),
                           self.event(20, value=130.0, threshold=120.0),
                           self.event(30, value=400.0, threshold=120.0),
                           self.event(40, value=200.0, threshold=120.0),
                           self.event(50, value=300.0, threshold=120.0),
                           self.event(0, value=125.0, threshold=120.0)])
        samples = history_mod.read_samples(self.base, self.base + 600)
        text = history_mod.export_markdown(samples, self.base, self.base + 600,
                                           history_mod.read_events(self.base,
                                                                   self.base + 600))
        self.assertIn("# 网络历史摘要", text)
        self.assertIn("时段：", text)
        self.assertIn("样本数：6", text)
        self.assertIn("覆盖率：", text)
        self.assertIn("## 异常 Top5", text)
        # 500 最严重排第一，125 被截掉（只有 5 行数据）
        self.assertLess(text.index("| 1 |"), text.index("500"))
        self.assertIn("Home-5G", text)                   # 当时 AP
        self.assertIn("-55 dBm", text)                   # 当时信号

    def test_markdown_without_events_says_none(self):
        self.write([self.sample(0)])
        samples = history_mod.read_samples(self.base, self.base + 600)
        text = history_mod.export_markdown(samples, self.base, self.base + 600, [])
        self.assertIn("无（区间内没有连续超阈值的事件）", text)
        self.assertIn("不是「丢包 0」", text)

    def test_markdown_shows_short_gap_in_seconds(self):
        # 21 秒的断档写成「0 分钟」会被读成「没有缺口」
        self.write([self.sample(0), self.sample(21)])
        samples = history_mod.read_samples(self.base, self.base + 21)
        text = history_mod.export_markdown(samples, self.base, self.base + 21, [])
        self.assertIn("21 秒", text)
        self.assertNotIn("0 分钟", text)

    def test_export_document_names_and_ctype(self):
        self.write([self.sample(0)])
        body, ctype, name = history_mod.export_document(
            "csv", self.base, self.base + 60)
        self.assertTrue(body.startswith(CSV_HEADER))
        self.assertEqual(ctype, "text/csv; charset=utf-8")
        self.assertRegex(name, r"^netdiag-history-\d{8}-\d{4}\.csv$")
        body, ctype, name = history_mod.export_document(
            "md", self.base, self.base + 60)
        self.assertTrue(body.startswith("# 网络历史摘要"))
        self.assertTrue(ctype.startswith("text/markdown"))
        self.assertTrue(name.endswith(".md"))
        with self.assertRaises(ValueError):
            history_mod.export_document("xlsx", self.base, self.base + 60)


# ====================================================================== 路由

class HistoryHttpTest(_HistoryCase):
    """真起 ``DiagServer``（端口 0），从 HTTP 层验五个接口。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _request(self, path: str, *, body: bytes | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            if body is None:
                conn.request("GET", path)
            else:
                conn.request("POST", path, body=body,
                             headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            return (resp.status, resp.getheader("Content-Type") or "",
                    resp.getheader("Content-Disposition") or "", resp.read())
        finally:
            conn.close()

    def _json(self, path: str, *, body: bytes | None = None):
        status, _, _, raw = self._request(path, body=body)
        return status, json.loads(raw.decode("utf-8"))

    def _seed(self):
        self.write([self.sample(0), self.sample(10), self.sample(20)])
        self.write_events([self.event(10, value=300.0)])

    def test_history_returns_flat_series_and_coverage(self):
        self._seed()
        status, data = self._json(
            f"/api/history?from={self.base}&to={self.base + 60}&bucket=1m")
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["bucket"], "1m")
        self.assertEqual(data["bucket_s"], 60)
        self.assertEqual(data["samples"], 3)
        self.assertEqual(data["target"], "baidu")
        # 扁平时间轴：一个桶一项，不是「每条序列一捆 points」
        self.assertEqual(len(data["series"]), 1)
        point = data["series"][0]
        self.assertEqual(point["n"], 3)
        self.assertEqual(point["rtt_ms"], 20.0)
        self.assertIsInstance(point["t"], float)
        self.assertEqual(data["marks"], [])
        self.assertIn("gaps", data["coverage"])

    def test_history_accepts_epoch_seconds_like_the_ui(self):
        # history.js 传的是 epoch 秒（from=...&to=...），不是 ISO
        self._seed()
        status, data = self._json(
            f"/api/history?from={int(self.base)}&to={int(self.base + 60)}&bucket=1m")
        self.assertEqual(status, 200)
        self.assertEqual(data["samples"], 3)
        self.assertEqual(data["from_epoch"], self.base)

    def test_history_target_param_switches_series(self):
        self._seed()
        status, data = self._json(
            f"/api/history?from={self.base}&to={self.base + 60}&target=gateway")
        self.assertEqual(status, 200)
        self.assertEqual(data["target"], "gateway")
        self.assertEqual(data["series"][0]["rtt_ms"], 5.0)

    def test_history_rejects_unknown_target(self):
        self._seed()
        status, data = self._json(
            f"/api/history?from={self.base}&to={self.base + 60}&target=aliyun")
        self.assertEqual(status, 400)
        self.assertIn("target", data["error"])

    def test_history_marks_are_inlined(self):
        self._seed()
        self.assertEqual(self._json("/api/history/mark", body=json.dumps(
            {"note": "15:20 换了 AP"}).encode("utf-8"))[0], 200)
        status, data = self._json(
            f"/api/history?from={self.base}&to={time.time()}&bucket=1m")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["marks"]), 1)
        self.assertEqual(data["marks"][0]["note"], "15:20 换了 AP")
        self.assertIsInstance(data["marks"][0]["t"], float)

    def test_history_rejects_bad_parameters(self):
        cases = {
            "bucket=2m": "bucket",
            f"from={urllib.parse.quote('昨天')}": "时间格式",
            f"from={self.base + 600}&to={self.base}": "晚于",
        }
        for query, needle in cases.items():
            with self.subTest(query=query):
                status, data = self._json(f"/api/history?{query}")
                self.assertEqual(status, 400)
                self.assertFalse(data["ok"])
                self.assertIn(needle, data["error"])

    def test_history_events_shape(self):
        self._seed()
        status, data = self._json(
            f"/api/history/events?from={self.base}&to={self.base + 600}")
        self.assertEqual(status, 200)
        event = data["events"][0]
        self.assertEqual(event["type"], "latency")        # rtt → latency
        self.assertEqual(set(event), {"t", "ts", "target", "type", "value",
                                      "threshold", "duration_s", "bssid",
                                      "rssi_dbm"})
        self.assertIsInstance(event["t"], float)

    def test_history_events_filtered_by_range(self):
        self._seed()
        self.write_events([self.event(0, value=130.0), self.event(3600, value=999.0)])
        status, data = self._json(
            f"/api/history/events?from={self.base}&to={self.base + 600}")
        self.assertEqual(status, 200)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["events"][0]["value"], 130.0)
        # 全量再看一次：两条都在
        status, data = self._json(
            f"/api/history/events?from={self.base}&to={self.base + 7200}")
        self.assertEqual(data["count"], 2)

    def test_history_events_empty_file_is_not_an_error(self):
        status, data = self._json("/api/history/events")
        self.assertEqual(status, 200)
        self.assertEqual((data["count"], data["events"]), (0, []))

    def test_mark_post_returns_iso_time(self):
        status, data = self._json("/api/history/mark",
                                  body=json.dumps({"note": " 重启路由器 "}).encode())
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertIsInstance(data["t"], str)
        self.assertIn("+", data["t"][-6:])
        self.assertEqual(data["mark"]["note"], "重启路由器")

    def test_mark_list_roundtrip_uses_epoch_time(self):
        self._json("/api/history/mark", body=json.dumps({"note": "重启路由器"}).encode())
        status, listed = self._json(
            f"/api/history/marks?from={self.base - 3600}&to={time.time() + 60}")
        self.assertEqual(status, 200)
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["marks"][0]["note"], "重启路由器")
        self.assertEqual(set(listed["marks"][0]), {"t", "ts", "note"})
        self.assertIsInstance(listed["marks"][0]["t"], float)

    def test_mark_rejects_empty_and_overlong_note(self):
        for payload, needle in ({"note": "   "}, "note 不能为空"), \
                ({"note": "长" * 501}, "最长"):
            with self.subTest(payload=str(payload)[:20]):
                status, data = self._json("/api/history/mark",
                                          body=json.dumps(payload).encode())
                self.assertEqual(status, 400)
                self.assertIn(needle, data["error"])
        # 没写进去：列表仍是空的
        status, listed = self._json(
            f"/api/history/marks?from=0&to={time.time() + 60}")
        self.assertEqual(listed["count"], 0)

    def test_export_csv_headers_and_attachment(self):
        self._seed()
        status, ctype, disposition, raw = self._request(
            f"/api/history/export?format=csv&from={self.base}&to={self.base + 60}")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "text/csv; charset=utf-8")
        self.assertIn("attachment", disposition)
        self.assertIn(".csv", disposition)
        text = raw.decode("utf-8")
        self.assertEqual(text.splitlines()[0], CSV_HEADER)
        self.assertEqual(len(text.splitlines()), 1 + 3)

    def test_export_markdown(self):
        self._seed()
        status, ctype, disposition, raw = self._request(
            f"/api/history/export?format=md&from={self.base}&to={self.base + 60}")
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("text/markdown"))
        self.assertIn(".md", disposition)
        text = raw.decode("utf-8")
        self.assertIn("# 网络历史摘要", text)
        self.assertIn("异常 Top5", text)

    def test_export_rejects_unknown_format(self):
        status, data = self._json("/api/history/export?format=xlsx")
        self.assertEqual(status, 400)
        self.assertIn("csv / md", data["error"])

    def test_unknown_subpath_is_404(self):
        for path in ("/api/history/unknown", "/api/history/export/x"):
            with self.subTest(path=path):
                status, _, _, _ = self._request(path)
                self.assertEqual(status, 404)

    def test_history_with_no_data_still_answers(self):
        status, data = self._json(
            f"/api/history?from={self.base}&to={self.base + 600}")
        self.assertEqual(status, 200)
        self.assertEqual(data["series"], [])
        self.assertEqual(data["coverage"]["samples"], 0)
        # 一条数据都没有时缺口 = 全部桶，绝不是 0
        self.assertEqual(data["coverage"]["gaps"], 11)


if __name__ == "__main__":
    unittest.main()
