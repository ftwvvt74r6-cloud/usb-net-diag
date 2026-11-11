"""G5：上次结果的内存记录 + ``/api/last-run`` 三个接口（方案 C，不重启服务）。

守的口径（``G-SPEC`` G5 / V8）：

* 每次诊断完成都把「摘要 + 完整结果」写进内存 ``LAST_RUN``（单槽、新运行覆盖、
  进程退出即失）；完整结果超过内存上限时只留摘要；
* ``GET /api/last-run``：无记录返回 ``null``（界面不得误报）；有记录返回
  ``time / mode / target / level / ok / duration_ms`` 等摘要字段；
* ``GET /api/last-run/result``：内存里没有完整结果时返回 **404 JSON**（不抛异常）；
* ``POST /api/last-run/clear``：清内存后再查必须为 ``null``，且不再被 ``runs/``
  兜底记录「复活」；历史文件本身不删；
* 进程重启后无内存记录时，用 ``logs/runs/*.json`` 最近一条**诊断类**记录兜底，
  摘要带 ``full_result=False`` / ``source="runs"``（probe/passive 记录不参与）。

本文件只连本机临时端口、写 ``NETDIAG_LOG_DIR`` 临时目录；不杀进程、不联网、
不请求 UAC。/api/quit 的真实退出验证放在真机证据，不放进单测。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import logstore  # noqa: E402
import server  # noqa: E402
import verdict  # noqa: E402

HOST = "127.0.0.1"


def _result(level: str = "正常") -> dict:
    """造一份最小可渲染诊断结果（与 report/CLI 用例同形，便于断言结论恢复）。"""
    result = {
        "ok": True,
        "meta": {
            "pcap_name": "last_run_sample.pcap", "packets": 20, "duration": 10.0,
            "tcp_packets": 8, "streams_total": 2, "dns_total": 3, "http_req": 1,
            "icmp_unreach": 0, "icmp_timeout": 0, "arp_req": 1, "arp_req_max": 1,
            "interface": "test0", "bpf": "", "generated_at": "2026-01-01 00:00:00",
            "streams_top": [],
        },
        "rows": [],
        "metrics": {"retrans_rate": 0.0},
        "summary": {"target": "192.0.2.20", "critical_count": 1, "warning_count": 2},
        "report": {"markdown": "reports/last_run_sample.md",
                   "json": "reports/last_run_sample.json"},
    }
    built = verdict.build(result)
    built["level"] = level
    result["verdict"] = built
    return result


def _reset_last_run() -> None:
    """把模块级内存清回初始状态（用例之间互不影响）。"""
    server.LAST_RUN.update({"summary": None, "result": None, "cleared_at": 0.0})


class LastRunHttpTest(unittest.TestCase):
    """真起 ``DiagServer``，走三个接口的 HTTP 契约。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: cls.tmp.name})
        cls._env.start()
        logstore.close_streams()
        _reset_last_run()
        cls.httpd = server.DiagServer((HOST, 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(
            target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.15)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._env.stop()
        logstore.close_streams()
        cls.tmp.cleanup()

    def setUp(self) -> None:
        _reset_last_run()
        runs = Path(self.tmp.name) / "runs"
        if runs.is_dir():
            for path in runs.glob("*.json"):
                path.unlink()

    # ---------- helpers ----------
    def _get(self, path: str) -> tuple[int, dict]:
        try:
            with urllib.request.urlopen(
                    f"http://{HOST}:{self.port}{path}", timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _post(self, path: str) -> tuple[int, dict]:
        request = urllib.request.Request(
            f"http://{HOST}:{self.port}{path}", data=b"{}", method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _write_run(self, name: str, payload: dict, age_seconds: float = 0.0) -> Path:
        """在临时 ``runs/`` 目录写一条历史记录，可回拨 mtime 模拟新旧顺序。"""
        runs = Path(self.tmp.name) / "runs"
        runs.mkdir(parents=True, exist_ok=True)
        path = runs / name
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        if age_seconds:
            stamp = time.time() - age_seconds
            os.utime(path, (stamp, stamp))
        return path

    # ---------- GET /api/last-run ----------
    def test_without_any_record_returns_null(self):
        status, body = self._get("/api/last-run")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertIsNone(body["last"], "没有记录时必须返回 null，界面不得误报")

    def test_summary_has_time_mode_target_level_ok_and_duration(self):
        server._remember_last_run("live", "example.com", time.time() - 2.5,
                                  _result("警告"))
        status, body = self._get("/api/last-run")
        self.assertEqual(status, 200)
        last = body["last"]
        self.assertEqual(last["mode"], "live")
        self.assertEqual(last["target"], "example.com")
        self.assertEqual(last["level"], "警告")
        self.assertTrue(last["ok"])
        self.assertGreaterEqual(last["duration_ms"], 2000)
        self.assertTrue(last["time"].strip(), "时间必须非空（前端按本地时区渲染）")
        self.assertEqual(last["source"], "memory")
        self.assertTrue(last["full_result"], "内存里有完整结果时必须标记可查看")

    def test_new_run_overwrites_the_single_memory_slot(self):
        server._remember_last_run("live", "old.example", time.time(), _result())
        server._remember_last_run("offline", "sample.pcap", time.time(), _result())
        status, body = self._get("/api/last-run")
        self.assertEqual(status, 200)
        self.assertEqual(body["last"]["mode"], "offline")
        self.assertEqual(body["last"]["target"], "sample.pcap")

    def test_failed_run_is_recorded_but_has_no_full_result(self):
        server._remember_last_run("live", "example.com", time.time(),
                                  {"ok": False, "error": "boom"})
        status, body = self._get("/api/last-run")
        self.assertEqual(status, 200)
        self.assertFalse(body["last"]["ok"])
        self.assertFalse(body["last"]["full_result"])
        status, result_body = self._get("/api/last-run/result")
        self.assertEqual(status, 404)
        self.assertFalse(result_body["ok"])

    def test_oversized_result_keeps_summary_only(self):
        with mock.patch.object(server, "LAST_RUN_MAX_BYTES", 10):
            server._remember_last_run("live", "example.com", time.time(), _result())
        status, body = self._get("/api/last-run")
        self.assertEqual(status, 200)
        self.assertFalse(body["last"]["full_result"])
        self.assertTrue(body["last"].get("trimmed"), "超限时必须显式标记 trimmed")
        self.assertEqual(self._get("/api/last-run/result")[0], 404)

    def test_limit_counts_utf8_bytes_not_characters(self):
        """S3：8MB 上限按 UTF-8 字节算；中文按字符数算会放大到约 3 倍。"""
        result = _result()
        encoded = json.dumps(result, ensure_ascii=False)
        char_count = len(encoded)
        byte_count = len(encoded.encode("utf-8"))
        self.assertLess(char_count, byte_count, "样本必须含中文（否则字符数 == 字节数）")

        # 上限卡在「字符数够、字节数不够」之间：旧实现会收下，新实现必须丢弃。
        with mock.patch.object(server, "LAST_RUN_MAX_BYTES", byte_count - 1):
            server._remember_last_run("live", "example.com", time.time(), result)
        last = server._last_run_view()
        self.assertFalse(last["full_result"],
                         f"UTF-8 {byte_count}B > 上限 {byte_count - 1}B 时必须只留摘要")
        self.assertTrue(last.get("trimmed"))
        self.assertIsNone(server._last_run_result())

    def test_limit_accepts_result_exactly_at_byte_limit(self):
        result = _result()
        byte_count = len(json.dumps(result, ensure_ascii=False).encode("utf-8"))
        with mock.patch.object(server, "LAST_RUN_MAX_BYTES", byte_count):
            server._remember_last_run("live", "example.com", time.time(), result)
        last = server._last_run_view()
        self.assertTrue(last["full_result"], "等于上限（不是超过）时必须保留完整结果")
        self.assertIsNotNone(server._last_run_result())

    # ---------- GET /api/last-run/result ----------
    def test_result_returns_full_result_and_conclusion(self):
        server._remember_last_run("live", "example.com", time.time() - 1, _result())
        status, body = self._get("/api/last-run/result")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        result = body["result"]
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["meta"]["pcap_name"], "last_run_sample.pcap")
        # 与 /api/status 同源：结论对象 + 预渲染整块必须一起返回，界面才能直接 render()。
        self.assertIn("conclusion", result)
        self.assertIn("conclusion_text", result)
        self.assertTrue(result["conclusion_text"])
        self.assertEqual(body["summary"]["mode"], "live")

    def test_result_404_json_when_no_memory(self):
        status, body = self._get("/api/last-run/result")
        self.assertEqual(status, 404)
        self.assertFalse(body["ok"])
        self.assertIn("没有上次的完整结果", body["error"])

    # ---------- POST /api/last-run/clear ----------
    def test_clear_then_query_is_null(self):
        server._remember_last_run("live", "example.com", time.time(), _result())
        with server.LOCK:
            server.JOB.update({"state": "done", "result": _result(),
                               "error": "", "error_code": "", "logs": []})
        status, body = self._post("/api/last-run/clear")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertIsNone(self._get("/api/last-run")[1]["last"])
        self.assertEqual(self._get("/api/last-run/result")[0], 404)
        # 刷新页面走 /api/status：旧结果必须已经不在，否则「开始新任务」会被刷新打回原形。
        status_body = self._get("/api/status")[1]
        self.assertEqual(status_body["state"], "idle")
        self.assertIsNone(status_body["result"])

    def test_clear_suppresses_runs_fallback_but_keeps_history_file(self):
        path = self._write_run("20261109-010000-aaaa1111.json", {
            "mode": "live", "params": {"target": "history.example"},
            "duration_ms": 1234, "level": "警告", "ok": True,
        })
        self.assertEqual(self._get("/api/last-run")[1]["last"]["source"], "runs")
        self._post("/api/last-run/clear")
        self.assertIsNone(self._get("/api/last-run")[1]["last"],
                          "清空后再查必须为 null（刷新不再出现）")
        self.assertTrue(path.is_file(), "clear 只清内存，不许删 logs/runs 历史记录")

    # ---------- runs/ 兜底 ----------
    def test_runs_fallback_builds_summary_only(self):
        self._write_run("20261109-010000-bbbb2222.json", {
            "mode": "offline", "params": {"pcap": "captures/legacy.pcap"},
            "duration_ms": 4321, "level": "严重", "ok": True,
            "critical": 3, "warning": 1,
        })
        status, body = self._get("/api/last-run")
        self.assertEqual(status, 200)
        last = body["last"]
        self.assertEqual(last["mode"], "offline")
        self.assertEqual(last["target"], "captures/legacy.pcap")
        self.assertEqual(last["duration_ms"], 4321)
        self.assertEqual(last["level"], "严重")
        self.assertEqual(last["critical"], 3)
        self.assertTrue(last["time"].strip())
        self.assertFalse(last["full_result"], "兜底只有摘要，必须标记 full_result=false")
        self.assertEqual(last["source"], "runs")
        self.assertEqual(self._get("/api/last-run/result")[0], 404)

    def test_runs_fallback_uses_newest_diagnostic_record(self):
        self._write_run("20261109-000000-cccc3333.json", {
            "mode": "live", "params": {"target": "older.example"},
            "duration_ms": 1, "level": "正常", "ok": True,
        }, age_seconds=120)
        self._write_run("20261109-020000-dddd4444.json", {
            "mode": "live", "params": {"target": "newer.example"},
            "duration_ms": 2, "level": "警告", "ok": True,
        }, age_seconds=0)
        last = self._get("/api/last-run")[1]["last"]
        self.assertEqual(last["target"], "newer.example")

    def test_runs_fallback_skips_probe_and_corrupt_records(self):
        runs = Path(self.tmp.name) / "runs"
        runs.mkdir(parents=True, exist_ok=True)
        (runs / "20261109-030000-eeee5555.json").write_text(
            "{not json", encoding="utf-8")
        self._write_run("20261109-040000-ffff6666.json", {
            "mode": "probe", "params": {"target": "probe.example"},
            "duration_ms": 9, "level": "正常", "ok": True,
        }, age_seconds=10)
        self._write_run("20261109-050000-9999aaaa.json", {
            "mode": "live", "params": {"target": "real-run.example"},
            "duration_ms": 10, "level": "正常", "ok": True,
        }, age_seconds=20)
        last = self._get("/api/last-run")[1]["last"]
        self.assertEqual(last["target"], "real-run.example",
                         "probe/passive 与损坏记录不能当成「上次诊断结果」")

    def test_offline_target_uses_basename_not_absolute_path(self):
        # 摘要里的目标不能带本机绝对路径：离线模式只留抓包文件名。
        self.assertEqual(
            server._last_run_target("offline", "", r"D:\secret\captures\a.pcap"),
            "a.pcap")
        self.assertEqual(server._last_run_target("scan", "", None), "全网",
                         "全网体检不允许回空串：空白既可能是「全网」也可能是"
                         "「界面没拿到数据」，导出报告里分不清")
        self.assertEqual(server._last_run_target("live", " example.com ", None),
                         "example.com")

    def test_summary_target_is_never_empty_on_both_endpoints(self):
        # A 的导出报告直接读 summary.target：空串会让「目标」一栏在报告里空白，
        # 而空白既可能是全网也可能是没取到数据 —— 两个接口都必须给字符串。
        target = server._last_run_target("scan", "", None)
        server._remember_last_run("scan", target, time.time(), _result())
        status, body = self._get("/api/last-run")
        self.assertEqual(status, 200)
        self.assertEqual(body["last"]["target"], "全网")
        status, body = self._get("/api/last-run/result")
        self.assertEqual(status, 200)
        self.assertEqual(body["summary"]["target"], "全网")

    def test_summary_target_keeps_real_host_and_port(self):
        # 「域名或 IP:端口」原样保留：用户在报告里要对得上自己填的目标
        result = _result()
        result["summary"]["target"] = "www.baidu.com:443"
        server._remember_last_run("live", "www.baidu.com:443", time.time(), result)
        status, body = self._get("/api/last-run")
        self.assertEqual(body["last"]["target"], "www.baidu.com:443")
        status, body = self._get("/api/last-run/result")
        self.assertEqual(body["summary"]["target"], "www.baidu.com:443")
        self.assertEqual(body["result"]["summary"]["target"], "www.baidu.com:443")

    # ---------- /api/app 文案下发 ----------
    def test_app_ships_last_run_and_settings_copy(self):
        snap = {"ok": True, "first_run": False, "checks": [],
                "capabilities": {}, "ui_copy": {"startup": {"panel_title": "x"}}}
        with mock.patch.object(server.selfcheck, "collect_cached",
                               return_value=snap):
            status, body = self._get("/api/app")
        self.assertEqual(status, 200)
        ui_copy = body["ui_copy"]
        self.assertEqual(ui_copy["startup"], {"panel_title": "x"})
        self.assertTrue(ui_copy["last_run"]["banner"])
        self.assertIn("{time}", ui_copy["last_run"]["banner"])
        self.assertIn("{mode}", ui_copy["last_run"]["banner"])
        self.assertIn("{target}", ui_copy["last_run"]["banner"])
        self.assertEqual(ui_copy["settings"]["quit_background"], "立即退出后台")
        self.assertIn("{minutes}", ui_copy["settings"]["idle_exit"])

    def test_broken_copy_table_returns_empty_sections(self):
        with mock.patch.object(server.copytext, "load_table",
                               side_effect=OSError("copy table missing")):
            self.assertEqual(server._last_run_ui_copy(), {})
            self.assertEqual(server._settings_ui_copy(), {})


class WorkerRemembersRunTest(unittest.TestCase):
    """``_worker`` 完成/失败后都必须更新内存（页面刷新才能看到提示条）。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: self.tmp.name})
        self._env.start()
        logstore.close_streams()
        _reset_last_run()
        server.JOB.update({"state": "idle", "started_at": time.time(),
                           "result": None, "error": "", "error_code": "",
                           "logs": [], "finished_at": 0})

    def tearDown(self) -> None:
        self._env.stop()
        logstore.close_streams()
        self.tmp.cleanup()

    def test_successful_worker_records_summary_and_result(self):
        with mock.patch.object(server.diagnose, "run_scan",
                               return_value=_result("警告")):
            server._worker("live", "example.com", 10, None, None)
        last = server._last_run_view()
        self.assertIsNotNone(last)
        self.assertEqual(last["mode"], "live")
        self.assertEqual(last["target"], "example.com")
        self.assertEqual(last["level"], "警告")
        self.assertTrue(last["full_result"])
        self.assertTrue(server._last_run_result())

    def test_failed_worker_records_summary_without_result(self):
        with mock.patch.object(
                server.diagnose, "run_scan",
                return_value={"ok": False, "error": "抓包失败",
                              "empty_capture": False}):
            server._worker("live", "example.com", 10, None, None)
        last = server._last_run_view()
        self.assertIsNotNone(last)
        self.assertFalse(last["ok"])
        self.assertFalse(last["full_result"])
        self.assertIsNone(server._last_run_result())


if __name__ == "__main__":
    unittest.main(verbosity=2)
