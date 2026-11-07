"""``diagnose.py --report-out`` 的回归测试（PR G · V2）。

要守三件事：

1. ``--help`` 里确实有这个开关（CLI 契约，防止哪天被顺手删掉）。
2. 不给 ``--report-out`` 时，``run_scan`` 仍然写 ``reports/``（老行为逐字节不变）。
3. 给了 ``--report-out`` 时，完整 ``.md`` / ``.json`` 落到指定目录（含多级新目录），
   且**不碰**仓库里的 ``reports/``。

第 3 条的真实分析用例需要 tshark，干净 checkout（CI）里自动 skip；
不依赖 tshark 的路径选择逻辑用 mock 在 CI 里也能跑。
"""

from __future__ import annotations

import hashlib
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

NO_TSHARK = find_tshark() is None


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


class ReportOutArgTest(unittest.TestCase):
    """不需要 tshark：``--help`` 与输出目录选择。"""

    def test_help_lists_report_out(self):
        """``--help`` 必须列出 ``--report-out``（同时确认 ``--json`` 老接口还在）。"""
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.run(
            [sys.executable, str(DIAGNOSE), "--help"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=env, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--report-out", proc.stdout)
        self.assertIn("--json", proc.stdout)

    def test_run_scan_routes_to_reports_by_default(self):
        """不给 ``report_dir`` 时 ``report.save`` 收到的仍是 ``reports/``。"""
        saved: list[Path] = []

        def fake_save(result, out_dir):
            saved.append(Path(out_dir))
            return {"markdown": str(Path(out_dir) / "x.md"),
                    "json": str(Path(out_dir) / "x.json")}

        with mock.patch.object(diagnose.analyzer, "analyze",
                               side_effect=lambda *a, **k: _fake_result()), \
                mock.patch.object(diagnose.verdict, "build", return_value={"level": "正常"}), \
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


@unittest.skipIf(NO_TSHARK, "没有 tshark，跳过 CLI 离线导出实测")
class ReportOutLiveTest(unittest.TestCase):
    """装了 tshark 时真的跑一遍离线分析，确认两份文件落地且默认目录不动。"""

    def test_offline_export_writes_md_and_json(self):
        self.assertTrue(SAMPLE.is_file(), f"缺少示例抓包：{SAMPLE}")
        before = _report_hashes()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "nested" / "report-out"
            env = dict(os.environ, PYTHONIOENCODING="utf-8")
            proc = subprocess.run(
                [sys.executable, str(DIAGNOSE), "--pcap", str(SAMPLE),
                 "--report-out", str(out)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                env=env, cwd=str(ROOT), timeout=600,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[-800:])

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

            self.assertEqual(_report_hashes(), before,
                             "指定了 --report-out 不应再写仓库 reports/")


if __name__ == "__main__":
    unittest.main(verbosity=2)
