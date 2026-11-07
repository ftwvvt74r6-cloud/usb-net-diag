"""``diagnose.py --report-out`` 的回归测试（PR G · V2）。

要守四件事：

1. ``--help`` 里确实有这个开关，且文案说清「只写该目录（不再写 reports/）」。
2. 不给 ``--report-out`` 时，``run_scan`` 仍然写 ``reports/``（老行为逐字节不变）。
3. 给了 ``--report-out`` 时，完整 ``.md`` / ``.json`` 落到指定目录（含多级新目录），
   且**不碰**仓库里的 ``reports/``。
4. 跑 CLI 的实测用例不往仓库 ``logs/`` 写 ``diag_*.log``（B3：mock ``_log_to_file``）。

第 3 条的真实分析用例需要 tshark，干净 checkout（CI）里自动 skip；
不依赖 tshark 的路径选择逻辑用 mock 在 CI 里也能跑。
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import diagnose                                            # noqa: E402
from tshark import find_tshark                             # noqa: E402

DIAGNOSE = ROOT / "core" / "diagnose.py"
SAMPLE = ROOT / "captures" / "faults_demo.pcap"
REPORTS = ROOT / "reports"
LOGS = ROOT / "logs"

NO_TSHARK = find_tshark() is None

# report.save() 内部会再算一次 verdict 并渲染 Markdown；mock 掉 verdict.build 时
# 必须给全 render_markdown 会读的键，否则会 KeyError。
_FAKE_VERDICT = {
    "level": "正常",
    "headline": "正常",
    "layer": "L7",
    "impact": "—",
    "plain": "",
    "layers": [],
    "points": [],
    "next_steps": ["检查链路"],
}


def _fake_result() -> dict:
    """造一份能过 ``run_scan`` 后处理的最小分析结果。"""
    return {
        "ok": True,
        "meta": {"packets": 1, "pcap_name": SAMPLE.name, "duration": 0,
                 "interface": "-", "bpf": "-"},
        "rows": [],
        "metrics": {},
        "summary": {"target": "全网", "critical_count": 0, "warning_count": 0},
    }


def _report_hashes() -> dict:
    """仓库 ``reports/`` 下所有文件的 sha256（用来证明导出没有污染默认目录）。"""
    if not REPORTS.is_dir():
        return {}
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(REPORTS.iterdir()) if p.is_file()
    }


def _dir_state(path: Path) -> tuple:
    """目录内每个文件的 ``(名字, 大小, mtime_ns)``；用来证明「没有新增/改动」。"""
    if not path.is_dir():
        return ()
    return tuple(
        (p.name, p.stat().st_size, p.stat().st_mtime_ns)
        for p in sorted(path.iterdir()) if p.is_file()
    )


class ReportOutArgTest(unittest.TestCase):
    """不需要 tshark：``--help`` 与输出目录选择。"""

    def test_help_lists_report_out(self):
        """``--help`` 必须列出 ``--report-out`` 且写清「不再写 reports/」。"""
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.run(
            [sys.executable, str(DIAGNOSE), "--help"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=env, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--report-out", proc.stdout)
        self.assertIn("--json", proc.stdout)
        # B4：不能只写「导出到指定目录」——必须明确给定后不再写 reports/。
        self.assertIn("不再写 reports/", proc.stdout,
                      "--help 没写清「只写该目录、不再写 reports/」")

    def test_run_scan_routes_to_reports_by_default(self):
        """不给 ``report_dir`` 时 ``report.save`` 收到的仍是 ``reports/``。"""
        saved: list[Path] = []

        def fake_save(result, out_dir):
            saved.append(Path(out_dir))
            return {"markdown": str(Path(out_dir) / "x.md"),
                    "json": str(Path(out_dir) / "x.json")}

        with mock.patch.object(diagnose.analyzer, "analyze",
                               side_effect=lambda *a, **k: _fake_result()), \
                mock.patch.object(diagnose.verdict, "build",
                                  return_value=dict(_FAKE_VERDICT)), \
                mock.patch.object(diagnose.report, "save", side_effect=fake_save):
            diagnose.run_scan(pcap=str(SAMPLE), logger=lambda m: None)
            self.assertEqual(saved[-1], diagnose.REPORTS,
                             "默认输出目录变了（应保持 reports/）")

            with tempfile.TemporaryDirectory() as tmp:
                want = Path(tmp) / "nested" / "out"
                diagnose.run_scan(pcap=str(SAMPLE), logger=lambda m: None,
                                  report_dir=str(want))
                self.assertEqual(saved[-1], want,
                                 "给了 --report-out 时没有写到指定目录")

    def test_report_out_leaves_reports_untouched(self):
        """给了 ``--report-out`` 时真实落盘只写临时目录，仓库 ``reports/`` 零新增。

        不依赖 tshark：``analyzer.analyze`` / ``verdict.build`` 用 mock，
        ``report.save`` 走真实实现（真的写 .md/.json），比只断言参数更接近 CLI 行为。
        """
        before = _report_hashes()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "nested" / "report-out"
            with mock.patch.object(diagnose.analyzer, "analyze",
                                   side_effect=lambda *a, **k: _fake_result()), \
                    mock.patch.object(diagnose.verdict, "build",
                                      return_value=dict(_FAKE_VERDICT)), \
                    mock.patch.object(diagnose, "_log_to_file"):
                diagnose.run_scan(pcap=str(SAMPLE), logger=lambda m: None,
                                  report_dir=str(out))

            md = out / f"{SAMPLE.stem}.md"
            js = out / f"{SAMPLE.stem}.json"
            self.assertTrue(md.is_file(), f"没有生成 Markdown：{md}")
            self.assertTrue(js.is_file(), f"没有生成 JSON：{js}")
            doc = json.loads(js.read_text(encoding="utf-8"))
            self.assertEqual(set(doc), {"summary", "meta", "metrics", "rows", "verdict"})
        self.assertEqual(_report_hashes(), before,
                         "指定了 --report-out 仍写了仓库 reports/")


@unittest.skipIf(NO_TSHARK, "没有 tshark，跳过 CLI 离线导出实测")
class ReportOutLiveTest(unittest.TestCase):
    """装了 tshark 时真的跑一遍离线分析，确认两份文件落地且默认目录/日志不动。"""

    def test_offline_export_writes_md_and_json(self):
        self.assertTrue(SAMPLE.is_file(), f"缺少示例抓包：{SAMPLE}")
        reports_before = _report_hashes()
        logs_before = _dir_state(LOGS)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "nested" / "report-out"
            stdout = io.StringIO()
            # B3：进程内跑 CLI，才能 mock 掉 _log_to_file；否则子进程会写仓库
            # logs/diag_YYYYMMDD.log（LOGS 是模块常量，没法通过环境变量改道）。
            with mock.patch.object(diagnose, "_log_to_file"), \
                    contextlib.redirect_stdout(stdout):
                rc = diagnose.main(["--pcap", str(SAMPLE), "--report-out", str(out)])
            self.assertEqual(rc, 0, stdout.getvalue()[-800:])
            self.assertIn("报告已生成", stdout.getvalue())

            md = out / f"{SAMPLE.stem}.md"
            js = out / f"{SAMPLE.stem}.json"
            self.assertTrue(md.is_file(), f"没有生成 Markdown：{md}")
            self.assertTrue(js.is_file(), f"没有生成 JSON：{js}")

            text = md.read_text(encoding="utf-8")
            self.assertIn("网络故障诊断报告", text)
            self.assertIn("## 一、故障定位", text)

            doc = json.loads(js.read_text(encoding="utf-8"))
            self.assertEqual(set(doc), {"summary", "meta", "metrics", "rows", "verdict"},
                             "导出的 JSON 不是完整报告的五块结构")

        self.assertEqual(_report_hashes(), reports_before,
                         "指定了 --report-out 不应再写仓库 reports/")
        self.assertEqual(_dir_state(LOGS), logs_before,
                         "跑 CLI 往仓库 logs/ 写了文件：应 mock diagnose._log_to_file")


if __name__ == "__main__":
    unittest.main(verbosity=2)
