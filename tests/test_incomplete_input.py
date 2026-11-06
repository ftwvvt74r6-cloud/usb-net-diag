"""输入不完整时的行为回归测试（T00 的结论落地）。

背景：`logs/diag_20261106.log` 里同一份 pcapng 出现过「警告 2 项 → 0 项 → 0 项」。
根因不是算法不稳定，而是**分析了一个不完整的文件**：
tshark 读到半个包时会以 rc=14 退出并打印 "appears to have been cut short"，
而旧版 `analyzer.collect()` 只看「有没有解析到报文」，于是把半份数据当成完整结论——
严重项会凭空消失，半截会话又会伪造「建连无响应」。

本测试守住这条线：
  1. 完整样本 → 结论稳定且等于基线（严重 3 / 警告 5）；
  2. 截断样本 → 必须显式失败，不许返回「各层正常」；
  3. 同一文件连跑两次 → 结果逐字节一致。

不依赖网络与管理员权限；没有 tshark 或没有样本时自动跳过（CI 无 tshark 也不会红）。
运行：``tools\\python\\python.exe -m unittest discover -s tests -v``
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import analyzer  # noqa: E402
import tshark  # noqa: E402

SAMPLE = ROOT / "captures" / "faults_demo.pcap"

# 基线来自 README 与 reports/faults_demo.md，改动规则时这里要同步更新
BASELINE_CRITICAL = 3
BASELINE_WARNING = 5

NO_TSHARK = tshark.find_tshark() is None
NO_SAMPLE = not SAMPLE.is_file()


def _write_truncated(dst: Path, fraction: float) -> Path:
    """按字节比例截断样本，模拟「抓包写到一半」或「拷贝没拷全」。"""
    data = SAMPLE.read_bytes()
    dst.write_bytes(data[: int(len(data) * fraction)])
    return dst


@unittest.skipIf(NO_TSHARK, "没有 tshark，跳过解析类测试")
@unittest.skipIf(NO_SAMPLE, "缺少 captures/faults_demo.pcap 样本")
class IncompleteInputTest(unittest.TestCase):
    def test_complete_sample_matches_baseline(self):
        """完整样本必须给出 README 声明的基线结论。"""
        res = analyzer.analyze(SAMPLE)
        self.assertTrue(res.get("ok"), f"完整样本不应失败：{res.get('error')}")
        summary = res["summary"]
        self.assertEqual(summary["critical_count"], BASELINE_CRITICAL)
        self.assertEqual(summary["warning_count"], BASELINE_WARNING)

    def test_truncated_file_fails_loudly(self):
        """截断到 30%：tshark rc=14，必须报错，而不是给出「严重 0」的假正常。"""
        tmp = ROOT / "logs" / "_test_trunc30.pcap"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        try:
            _write_truncated(tmp, 0.30)
            res = analyzer.analyze(tmp)
            self.assertFalse(res.get("ok"), "截断文件被当成了完整分析")
            self.assertIn("结论不可信", res.get("error", ""))
        finally:
            tmp.unlink(missing_ok=True)

    def test_truncated_tail_fails_loudly(self):
        """只缺尾部 15%（最接近真实场景：抓包刚结束就点分析）。"""
        tmp = ROOT / "logs" / "_test_trunc85.pcap"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        try:
            _write_truncated(tmp, 0.85)
            res = analyzer.analyze(tmp)
            self.assertFalse(res.get("ok"), "尾部缺失仍被判为完整分析")
        finally:
            tmp.unlink(missing_ok=True)

    def test_same_input_gives_same_result(self):
        """可复现性：同一文件连跑两次，归一化后必须逐字节一致。"""
        def norm(res: dict) -> str:
            data = json.loads(json.dumps(res, sort_keys=True, ensure_ascii=False))
            data.get("meta", {}).pop("generated_at", None)
            return json.dumps(data, sort_keys=True, ensure_ascii=False)

        first = analyzer.analyze(SAMPLE)
        second = analyzer.analyze(SAMPLE)
        self.assertTrue(first.get("ok") and second.get("ok"))
        self.assertEqual(norm(first), norm(second))


if __name__ == "__main__":
    unittest.main(verbosity=2)
