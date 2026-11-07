"""``core/logstore.py`` 的回归测试：目录/日文件/快照/runs/crashes/裁剪/异常钩子。

所有用例都把 ``NETDIAG_LOG_DIR`` 指到临时目录（SPEC V7）：跑测试**绝不写仓库 logs/**。
日志内容与文件名规则见 ``docs/logging.md``。
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import app        # noqa: E402
import diagnose   # noqa: E402
import logstore   # noqa: E402
import server     # noqa: E402

SAMPLE = ROOT / "captures" / "faults_demo.pcap"
REPO_LOGS = ROOT / "logs"

#: ``runs/*.json`` 必须有的字段（V4）；``ok`` 是便于排查的附加布尔。
RUN_KEYS = {"mode", "params", "duration_ms", "level", "critical", "warning",
            "sufficiency_ok", "error_code", "tshark_version", "ok"}
RUN_NAME = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{8}\.json$")
CRASH_NAME = re.compile(r"^\d{8}-\d{6}-\d+-\d+-[0-9a-f]{4}\.txt$")
FAKE_VERDICT = {"level": "警告", "sufficiency": {"ok": True},
                "layers": [], "points": [], "next_steps": [], "flags": {}}


def _dir_state(path: Path) -> tuple:
    """目录内每个文件的 ``(名字, 大小, mtime_ns)``。"""
    if not path.is_dir():
        return ()
    return tuple(
        (p.name, p.stat().st_size, p.stat().st_mtime_ns)
        for p in sorted(path.iterdir()) if p.is_file()
    )


def _today_file(root: Path, prefix: str) -> Path:
    return root / f"{prefix}-{dt.date.today():%Y%m%d}.log"


def _fake_result() -> dict:
    """能过 ``run_scan`` 后处理的最小分析结果。"""
    return {
        "ok": True,
        "meta": {"packets": 1, "pcap_name": SAMPLE.name, "duration": 0,
                 "interface": "-", "bpf": "-"},
        "rows": [],
        "metrics": {},
        "summary": {"target": "全网", "critical_count": 2, "warning_count": 3},
    }


class _TempLogCase(unittest.TestCase):
    """公共夹具：日志根目录注入临时目录，跑完关闭句柄再清理（Windows 才能删）。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="netdiag_log_")
        self.root = Path(self._tmp.name) / "logs"
        self._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(self.root)})
        self._env.start()
        logstore.close_streams()

    def tearDown(self) -> None:
        logstore.close_streams()
        self._env.stop()
        self._tmp.cleanup()


class LogRootTests(_TempLogCase):
    def test_env_overrides_root(self):
        """``NETDIAG_LOG_DIR`` 非空时日志根目录就是它（测试隔离的基础）。"""
        self.assertEqual(logstore.log_root(), self.root)

    def test_default_root_is_repo_logs(self):
        """没设环境变量时回落到仓库 ``logs/``。"""
        with mock.patch.dict(os.environ, {logstore.ENV_LOG_DIR: ""}):
            self.assertEqual(logstore.log_root(), ROOT / "logs")


class LayoutAndSnapshotTests(_TempLogCase):
    def test_ensure_dirs_creates_tree_and_today_files(self):
        """目录树固定为 logs/{runs,crashes} + 当天 app/diag 日文件（V1）。"""
        logstore.ensure_dirs()
        self.assertTrue((self.root / "runs").is_dir())
        self.assertTrue((self.root / "crashes").is_dir())
        self.assertTrue(_today_file(self.root, "app").is_file())
        self.assertTrue(_today_file(self.root, "diag").is_file())

    def test_env_snapshot_has_required_fields(self):
        """``env.json`` 字段齐全、可 ``json.load``，且不含 ``ai-config`` 的值（V3/红线 5）。"""
        info = logstore.write_env_snapshot({"entry": "test"})
        path = self.root / "env.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        required = {"version", "windows", "windows_version", "admin", "npcap",
                    "tshark_version", "tshark_path", "python_version",
                    "console_encoding", "config_sha256", "started_at"}
        self.assertEqual(required - set(data), set())
        self.assertEqual(data["entry"], "test")
        self.assertEqual(data["version"], (ROOT / "VERSION").read_text(
            encoding="utf-8").strip())
        self.assertNotIn("api_key", path.read_text(encoding="utf-8"))
        self.assertEqual(info["entry"], "test")

    def test_env_snapshot_overwrites(self):
        """快照是覆盖写：第二次不再带第一次的附加字段。"""
        logstore.write_env_snapshot({"entry": "first"})
        logstore.write_env_snapshot({"entry": "second"})
        data = json.loads((self.root / "env.json").read_text(encoding="utf-8"))
        self.assertEqual(data["entry"], "second")


class DailyFileTests(_TempLogCase):
    def test_app_and_diag_line_format(self):
        """行格式 ``[HH:MM:SS] [LEVEL] msg``；多行逐行加前缀（SPEC §5.1）。"""
        logstore.app_log("hello-app")
        logstore.diag_log("first-line\nsecond-line")
        app_text = _today_file(self.root, "app").read_text(encoding="utf-8")
        diag_text = _today_file(self.root, "diag").read_text(encoding="utf-8")
        self.assertRegex(app_text, r"(?m)^\[\d{2}:\d{2}:\d{2}\] \[INFO\] hello-app$")
        self.assertRegex(diag_text, r"(?m)^\[\d{2}:\d{2}:\d{2}\] \[INFO\] first-line$")
        self.assertRegex(diag_text, r"(?m)^\[\d{2}:\d{2}:\d{2}\] \[INFO\] second-line$")

    def test_redirect_output_writes_app_log(self):
        """``app.redirect_output()`` 委托 logstore：pythonw 下的 print 落 app 日文件。"""
        with mock.patch.object(sys, "stdout", None), \
                mock.patch.object(sys, "stderr", None):
            app.redirect_output()
            self.assertIsNotNone(sys.stdout)
            print("from-redirected-print", flush=True)
            sys.stdout.write("partial-line\n")
        text = _today_file(self.root, "app").read_text(encoding="utf-8")
        self.assertIn("from-redirected-print", text)
        self.assertIn("partial-line", text)

    def test_open_stream_reuses_single_handle(self):
        """同一进程只打开一次底层句柄（SPEC 陷阱 2）。"""
        first = logstore.open_stream()
        second = logstore.open_stream()
        self.assertIs(first._sink, second._sink)


class RecordRunTests(_TempLogCase):
    def test_three_runs_three_files_with_fields(self):
        """连跑 3 次 → 3 个 ``runs/<ts>-<8位随机>.json``，字段齐全（V4）。"""
        for i in range(3):
            path = logstore.record_run({
                "mode": "offline", "params": {"pcap": "faults_demo.pcap"},
                "duration_ms": 10 + i, "level": "警告", "critical": 1,
                "warning": 2, "sufficiency_ok": True, "error_code": "",
                "tshark_version": "TShark (Wireshark) 4.7.4", "ok": True,
            })
            self.assertIsNotNone(path)
        files = sorted((self.root / "runs").glob("*.json"))
        self.assertEqual(len(files), 3)
        for path in files:
            self.assertRegex(path.name, RUN_NAME)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(RUN_KEYS - set(data), set(), f"{path.name} 缺字段")

    def test_record_run_bad_payload_returns_none(self):
        """不可序列化的内容不抛异常、不留下半个文件。"""
        self.assertIsNone(logstore.record_run({"bad": object()}))
        self.assertEqual(list((self.root / "runs").glob("*")), [])

    def test_run_scan_records_offline_run(self):
        """CLI/库入口：``diagnose.run_scan()`` 自己记一条，字段来自分析结果。"""
        with mock.patch.object(diagnose.analyzer, "analyze",
                               side_effect=lambda *a, **k: _fake_result()), \
                mock.patch.object(diagnose.verdict, "build",
                                  return_value=dict(FAKE_VERDICT)), \
                mock.patch.object(diagnose.report, "save",
                                  return_value={"markdown": "x.md", "json": "x.json"}):
            result = diagnose.run_scan(pcap=str(SAMPLE), logger=lambda m: None)
        self.assertTrue(result["ok"])
        files = list((self.root / "runs").glob("*.json"))
        self.assertEqual(len(files), 1, "一次分析只能有一条 run 记录")
        data = json.loads(files[0].read_text(encoding="utf-8"))
        self.assertEqual(RUN_KEYS - set(data), set())
        self.assertEqual(data["mode"], "offline")
        self.assertEqual(data["level"], "警告")
        self.assertEqual((data["critical"], data["warning"]), (2, 3))
        self.assertTrue(data["sufficiency_ok"])
        self.assertEqual(data["error_code"], "")
        self.assertEqual(data["params"]["pcap"], SAMPLE.name)
        self.assertNotIn("D:", json.dumps(data["params"], ensure_ascii=False))
        self.assertNotIn("\\", json.dumps(data["params"], ensure_ascii=False))

    def test_run_scan_failure_records_error_code(self):
        """失败也要记：``error_code`` 是稳定码，``level`` 留空。"""
        result = diagnose.run_scan(pcap=str(self.root / "missing.pcap"),
                                   logger=lambda m: None)
        self.assertFalse(result["ok"])
        data = json.loads(next((self.root / "runs").glob("*.json")).read_text(
            encoding="utf-8"))
        self.assertEqual(data["mode"], "offline")
        self.assertEqual(data["level"], "")
        self.assertFalse(data["ok"])
        self.assertEqual(data["error_code"], "E_BAD_PCAP")

    def test_ui_worker_records_one_run(self):
        """UI 入口：``server._worker`` → ``run_scan``，同样只产生一条记录。"""
        old_state = dict(server.JOB)
        try:
            with mock.patch.object(diagnose.analyzer, "analyze",
                                   side_effect=lambda *a, **k: _fake_result()), \
                    mock.patch.object(diagnose.verdict, "build",
                                      return_value=dict(FAKE_VERDICT)), \
                    mock.patch.object(diagnose.report, "save",
                                      return_value={"markdown": "x.md", "json": "x.json"}):
                server._worker("offline", "", 0, None, str(SAMPLE))
            files = list((self.root / "runs").glob("*.json"))
            self.assertEqual(len(files), 1, "UI 分析一次应只有一条 run 记录")
            data = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(data["mode"], "offline")
            self.assertEqual(server.JOB["state"], "done")
        finally:
            server.JOB.update(old_state)

    def test_probe_records_run(self):
        """UI 的链路体检也记一条（mode=probe，V4 的 mode 取值之一）。"""
        with mock.patch.object(server.probe, "run",
                               return_value={"ok": True, "level": "正常"}):
            res = server._probe_guarded("example.com", None, 4, 1.0, "tls")
        self.assertTrue(res["ok"])
        data = json.loads(next((self.root / "runs").glob("*.json")).read_text(
            encoding="utf-8"))
        self.assertEqual(data["mode"], "probe")
        self.assertEqual(data["level"], "正常")

    def test_passive_records_run(self):
        """UI 的被动监听也记一条（mode=passive）。"""
        old_state = dict(server.PJOB)
        try:
            with mock.patch.object(server.passive, "run",
                                   return_value={"ok": True, "summary": {"packets": 1}}):
                server._passive_worker(None, 5, "", "auto")
            data = json.loads(next((self.root / "runs").glob("*.json")).read_text(
                encoding="utf-8"))
            self.assertEqual(data["mode"], "passive")
            self.assertEqual(server.PJOB["state"], "done")
        finally:
            server.PJOB.update(old_state)


class CrashTests(_TempLogCase):
    def test_record_crash_contains_traceback_and_env(self):
        """崩溃快照：类型/消息/traceback/环境摘要（V5）。"""
        try:
            {}["missing"]
        except KeyError as exc:
            path = logstore.record_crash(type(exc), exc, exc.__traceback__)
        self.assertIsNotNone(path)
        self.assertRegex(path.name, CRASH_NAME)
        text = path.read_text(encoding="utf-8")
        self.assertIn("KeyError", text)
        self.assertIn("Traceback (most recent call last):", text)
        self.assertIn("环境摘要", text)
        self.assertIn("Python:", text)

    def test_excepthooks_write_crash_and_fatal_file(self):
        """子进程真抛未捕获异常：``crashes/<ts>.txt`` 有 traceback，faulthandler 文件在。"""
        env = dict(os.environ, **{logstore.ENV_LOG_DIR: str(self.root)},
                   PYTHONIOENCODING="utf-8")
        script = ("import sys; sys.path.insert(0, 'core'); import logstore; "
                  "logstore.install_excepthooks(); "
                  "raise RuntimeError('boom-hook-123')")
        proc = subprocess.run([sys.executable, "-c", script], cwd=str(ROOT), env=env,
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("RuntimeError: boom-hook-123", proc.stderr, "原钩子没把栈打到 stderr")
        crashes = list((self.root / "crashes").glob("*.txt"))
        self.assertTrue(crashes, "sys.excepthook 没写崩溃快照")
        text = crashes[0].read_text(encoding="utf-8")
        self.assertIn("RuntimeError", text)
        self.assertIn("boom-hook-123", text)
        self.assertIn("Traceback (most recent call last):", text)
        self.assertTrue(list((self.root / "crashes").glob("fatal-*.log")),
                        "faulthandler 没开或文件没建")

    def test_thread_excepthook_writes_crash(self):
        """子线程未捕获异常也要留快照（threading.excepthook）。"""
        env = dict(os.environ, **{logstore.ENV_LOG_DIR: str(self.root)},
                   PYTHONIOENCODING="utf-8")
        script = ("import sys, threading; sys.path.insert(0, 'core'); import logstore; "
                  "logstore.install_excepthooks(); "
                  "t = threading.Thread(target=lambda: 1 / 0); t.start(); t.join()")
        proc = subprocess.run([sys.executable, "-c", script], cwd=str(ROOT), env=env,
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        texts = [p.read_text(encoding="utf-8")
                 for p in (self.root / "crashes").glob("*.txt")]
        self.assertTrue(any("ZeroDivisionError" in t for t in texts),
                        "threading.excepthook 没写崩溃快照")

    def test_record_crash_concurrent_threads_all_persist(self):
        """60 线程同秒 ``record_crash``：恰好 60 个文件、内容互不覆盖（B3）。

        修复前是「exists → write」竞态，60 个线程会看到同一个不存在的路径，
        实测只落 1 个文件（丢 59 个）。
        """
        crashes = self.root / "crashes"
        crashes.mkdir(parents=True, exist_ok=True)
        calls = 60
        barrier = threading.Barrier(calls)
        errors: list[BaseException] = []
        paths: list[Path] = []
        paths_lock = threading.Lock()

        def _crash(i: int) -> None:
            try:
                barrier.wait(timeout=30)
                try:
                    raise ValueError(f"crash-{i}")
                except ValueError as exc:
                    path = logstore.record_crash(type(exc), exc, exc.__traceback__)
                if path is None:
                    errors.append(RuntimeError(f"record_crash 返回 None: {i}"))
                    return
                with paths_lock:
                    paths.append(path)
            except BaseException as exc:  # noqa: BLE001  测试里收集所有线程错误
                errors.append(exc)

        threads = [threading.Thread(target=_crash, args=(i,)) for i in range(calls)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)

        self.assertEqual(errors, [])
        files = sorted(crashes.glob("*.txt"))
        self.assertEqual(len(files), calls,
                         f"并发崩溃快照丢失：calls={calls} files={len(files)}")
        self.assertEqual(len(paths), calls)
        for path in paths:
            self.assertRegex(path.name, CRASH_NAME)
        messages = set()
        for path in files:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.startswith("消息: crash-"):
                    messages.add(line[len("消息: "):])
        self.assertEqual(messages, {f"crash-{i}" for i in range(calls)},
                         "崩溃快照内容被覆盖（不是 60 份独立现场）")


class PruneTests(_TempLogCase):
    def setUp(self) -> None:
        super().setUp()
        self.root.mkdir(parents=True, exist_ok=True)

    def _make(self, directory: Path, names, payload: bytes = b"{}\n"):
        directory.mkdir(parents=True, exist_ok=True)
        for name in names:
            (directory / name).write_bytes(payload)

    def test_prune_keeps_newest_runs_and_crashes(self):
        """``runs/`` 留最近 3 个、``crashes/`` 留最近 2 个（V2 小上限注入）。"""
        run_names = [f"2026010{i}-000000-abcdef0{i}.json" for i in range(1, 8)]
        crash_names = [f"2026010{i}-000000.txt" for i in range(1, 7)]
        self._make(self.root / "runs", run_names)
        self._make(self.root / "crashes", crash_names)
        with mock.patch.multiple(logstore, KEEP_RUNS=3, KEEP_CRASHES=2,
                                 MAX_FILE_BYTES=5 << 20, MAX_TOTAL_BYTES=100 << 20):
            stats = logstore.prune()
        left_runs = sorted(p.name for p in (self.root / "runs").glob("*.json"))
        left_crashes = sorted(p.name for p in (self.root / "crashes").glob("*.txt"))
        self.assertEqual(left_runs, run_names[-3:])
        self.assertEqual(left_crashes, crash_names[-2:])
        self.assertGreaterEqual(stats["removed"], 8)

    def test_prune_crashes_by_mtime_keeps_crash_txt_next_to_fatal(self):
        """55 个 fatal + 2 个 txt：按 mtime 裁到 50 后必须留 2 个 txt 与 48 个 fatal（B2）。

        修复前按文件名字典序排序：数字开头的 ``*.txt`` 永远排在 ``fatal-*`` 前面，
        裁 50 个时 txt 会先被删光（实测 50 fatal / 0 txt）。
        """
        crashes = self.root / "crashes"
        crashes.mkdir(parents=True, exist_ok=True)
        base_ns = 2_000_000_000 * 1_000_000_000
        for i in range(55):
            path = crashes / f"fatal-20260101-{i:06d}.log"
            path.write_bytes(b"")
            os.utime(path, ns=(base_ns - (1000 + i) * 1_000_000_000,) * 2)
        txt_paths = []
        for i, name in enumerate(("20261001-100000.txt", "20261107-100000.txt")):
            path = crashes / name
            path.write_text("old crash\n", encoding="utf-8")
            os.utime(path, ns=(base_ns + (10 + i) * 1_000_000_000,) * 2)
            txt_paths.append(path)

        with mock.patch.multiple(logstore, KEEP_CRASHES=50, MAX_FILE_BYTES=5 << 20,
                                 MAX_TOTAL_BYTES=100 << 20):
            logstore.prune()

        left = [p for p in crashes.iterdir() if p.is_file()]
        left_txt = sorted(p.name for p in left if p.suffix.lower() == ".txt")
        left_fatal = sorted(p.name for p in left if p.name.startswith("fatal-"))
        self.assertEqual(left_txt, sorted(p.name for p in txt_paths),
                         "崩溃快照 *.txt 被 fatal 挤掉了（应按 mtime 而不是文件名裁剪）")
        self.assertEqual(len(left_fatal), 48, f"应删 7 个最旧 fatal，实际留 {len(left_fatal)}")
        self.assertEqual(len(left), 50)
        for path in txt_paths:
            self.assertTrue(path.exists())

    def test_prune_truncates_oversized_file_but_never_deletes_today(self):
        """单文件超限只截尾；当天正在写的文件不删除（V2 / 陷阱 4）。"""
        old = self.root / "app-20200101.log"
        today = _today_file(self.root, "app")
        old.write_bytes(b"x" * 4096)
        today.write_bytes(b"y" * 4096)
        old_mtime = old.stat().st_mtime_ns
        with mock.patch.object(logstore, "MAX_FILE_BYTES", 1024), \
                mock.patch.object(logstore, "MAX_TOTAL_BYTES", 1024):
            stats = logstore.prune()
        self.assertGreaterEqual(stats["truncated"], 1)
        self.assertTrue(old.exists() and today.exists(), "裁剪不许删当天的日志文件")
        self.assertLessEqual(old.stat().st_size, 1024)
        self.assertLessEqual(today.stat().st_size, 1024)
        self.assertEqual(old.stat().st_mtime_ns, old_mtime,
                         "截尾不该改 mtime（总量裁剪按最旧优先，顺序不能被洗乱）")

    def test_prune_total_limit_deletes_oldest_not_today(self):
        """总量超限：删最旧的历史文件，跳过 ``env.json`` 与当天文件。"""
        old_a = self.root / "diag-20200101.log"
        old_b = self.root / "diag-20200102.log"
        old_a.write_bytes(b"a" * 2048)
        old_b.write_bytes(b"b" * 2048)
        today = _today_file(self.root, "diag")
        today.write_bytes(b"c" * 2048)
        (self.root / "env.json").write_text("{}", encoding="utf-8")
        with mock.patch.object(logstore, "MAX_FILE_BYTES", 1 << 20), \
                mock.patch.object(logstore, "MAX_TOTAL_BYTES", 1024):
            logstore.prune()
        self.assertFalse(old_a.exists(), "最旧的历史日志应被删")
        self.assertTrue(today.exists(), "当天文件不许删")
        self.assertTrue((self.root / "env.json").exists(), "env.json 不许删")


class RepoLogsGuardTests(unittest.TestCase):
    """日志出口再全，也不许写仓库 ``logs/``（V7）。"""

    def test_all_log_paths_keep_repo_logs_untouched(self):
        before = _dir_state(REPO_LOGS)
        with tempfile.TemporaryDirectory(prefix="netdiag_log_") as tmp:
            with mock.patch.dict(os.environ,
                                 {logstore.ENV_LOG_DIR: str(Path(tmp) / "logs")}):
                logstore.close_streams()
                logstore.ensure_dirs()
                logstore.app_log("guard-app")
                logstore.diag_log("guard-diag")
                logstore.write_env_snapshot({"entry": "guard"})
                logstore.record_run({"mode": "offline"})
                try:
                    raise ValueError("guard-crash")
                except ValueError as exc:
                    logstore.record_crash(type(exc), exc, exc.__traceback__)
                server.log("guard-server")
                diagnose._log_to_file("guard-diagnose")
                logstore.close_streams()
        self.assertEqual(_dir_state(REPO_LOGS), before,
                         "日志出口写了仓库 logs/：所有测试必须注入 NETDIAG_LOG_DIR")


if __name__ == "__main__":
    unittest.main(verbosity=2)
