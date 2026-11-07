"""``extract`` 层（T04）的回归测试。

守两件事：

1. **口径不能漂**。``faults_features.json`` 里那些数字是从
   ``captures/faults_demo.pcap`` 算出来的基线，改任何一个都意味着
   「重传率 / 时延 / 握手」的定义变了 —— 这类改动会让报告里的结论
   悄悄换含义，比代码报错更难发现。
2. **fixture 不能被手改坏**。第二个用例现跑一遍 pcap 重新算，
   要求与 fixture 逐项相同；没有 tshark 时自动跳过（CI 里就靠第一个用例）。
3. **换 tshark 版本要显式重生成**。fixture 记录了生成时的 ``tshark_version``；
   现跑版本的**主次版本**对不上时给出「怎么重新生成」的命令，而不是只报数字不同。

第一个用例不 import tshark，因此 CI 的干净环境里也能跑完整套判断口径的校验。
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.extract import FIELDS, build_features, parse_rows   # noqa: E402
from core.tshark import find_tshark, iter_lines, version       # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "faults_features.json"
SAMPLE = ROOT / "captures" / "faults_demo.pcap"

NO_TSHARK = find_tshark() is None

#: fixture 里 tshark_version 的比对口径：只比主次版本（``4.7``）。
#: 完整版本串含构建哈希（``4.7.4 (v4.7.4-0-g...).``），同一主次版本的不同补丁／
#: 不同构建之间数字也可能不变 —— 比整行会让正常升级误报，不是我们要守的东西。
_VERSION_RE = re.compile(r"(\d+)\.(\d+)")


def _major_minor(version_text: str) -> str:
    """从 tshark 版本串里取 ``主.次`` 版本（取不到返回空串）。

    Args:
        version_text: 形如 ``TShark (Wireshark) 4.7.4 (v4.7.4-0-g...).`` 的版本首行。

    Returns:
        str: ``"4.7"``；串里没有版本号时返回 ``""``。
    """
    match = _VERSION_RE.search(version_text or "")
    return f"{match.group(1)}.{match.group(2)}" if match else ""

#: golden 基线：来自 demo pcap，改动即代表口径变化。
G_PACKETS = 36
G_BYTES = 6397
G_STREAMS = 4
G_CONN_FAIL = 1
G_CONN_REFUSED = 0
G_RETRANS_RATE = 5.56
G_DUP_ACK_RATE = 0.0
G_OOO_RATE = 0.0

G_RTT = {"n": 10, "avg": 54.3, "p95": 200.0, "max": 200.0, "jitter": 61.9}
G_HANDSHAKE = {"n": 3, "avg": 63.3, "p95": 120.0, "max": 120.0, "jitter": 40.3}

G_C2S = {"packets": 21, "bytes": 4945, "retrans": 2, "syn": 6,
         "syn_retrans": 2, "dup_ack": 0, "zero_win": 0}
G_S2C = {"packets": 15, "bytes": 1452, "retrans": 0, "syn": 0,
         "syn_retrans": 0, "dup_ack": 0, "zero_win": 0}

G_HANDSHAKE_PER_STREAM = {"0": 120.0, "1": 30.0, "2": None, "3": 40.0}


def _assert_golden(tc: unittest.TestCase, tcp: dict) -> None:
    """把 ``TcpFeatures.to_dict()`` 的结果与 golden 逐项比对。

    Args:
        tc: 当前 TestCase，用来发断言。
        tcp: ``Features.to_dict()["tcp"]``。
    """
    tc.assertEqual(tcp["packets"], G_PACKETS, "TCP 帧数变了")
    tc.assertEqual(tcp["bytes"], G_BYTES, "TCP 字节数变了")
    tc.assertEqual(len(tcp["streams"]), G_STREAMS, "TCP 会话数变了")
    tc.assertEqual(tcp["conn_fail"], G_CONN_FAIL, "建连无响应会话数变了")
    tc.assertEqual(tcp["conn_refused"], G_CONN_REFUSED, "被拒会话数变了")
    tc.assertEqual(tcp["retrans_rate"], G_RETRANS_RATE, "重传率口径变了")
    tc.assertEqual(tcp["dup_ack_rate"], G_DUP_ACK_RATE, "重复 ACK 率口径变了")
    tc.assertEqual(tcp["ooo_rate"], G_OOO_RATE, "乱序率口径变了")

    for key in ("n", "avg", "p95", "max", "jitter"):
        tc.assertEqual(tcp["rtt"][key], G_RTT[key], f"rtt.{key} 变了")
        tc.assertEqual(tcp["handshake"][key], G_HANDSHAKE[key], f"handshake.{key} 变了")

    for side, golden in (("c2s", G_C2S), ("s2c", G_S2C)):
        for field, want in golden.items():
            tc.assertEqual(tcp["dir_totals"][side][field], want,
                           f"dir_totals.{side}.{field} 变了")

    got_hs = {s["stream"]: s["handshake_ms"] for s in tcp["streams"]}
    tc.assertEqual(got_hs, G_HANDSHAKE_PER_STREAM, "每个流的握手耗时变了")


def _rows_from_pcap(pcap: Path) -> tuple[list[dict], dict]:
    """现跑 tshark 把 pcap 读成行字典（仅在装了 tshark 时调用）。"""
    tshark = find_tshark()
    args = [str(tshark), "-r", str(pcap), "-n", "-T", "fields",
            "-E", "header=y", "-E", "separator=|", "-E", "quote=d",
            "-E", "aggregator=,", "-E", "occurrence=a"]
    for field in FIELDS:
        args += ["-e", field]
    sink: dict = {}
    lines = iter_lines(args, timeout=600, sink=sink)
    try:
        return parse_rows(lines), sink
    finally:
        lines.close()


class FeaturesFixtureTest(unittest.TestCase):
    """不需要 tshark：只读已落盘的 fixture。"""

    def test_fixture_matches_golden(self):
        """fixture 里的数字必须等于 golden —— 口径漂了就在这里炸。"""
        self.assertTrue(FIXTURE.is_file(), f"缺少特征样本：{FIXTURE}")
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], "2.1", "fixture 的 schema 版本与契约不一致")
        _assert_golden(self, data["tcp"])


@unittest.skipIf(NO_TSHARK, "没有 tshark，跳过现跑比对")
class FeaturesLiveTest(unittest.TestCase):
    """装了 tshark 时现跑一遍，确认 fixture 没被手改坏。"""

    def test_live_run_matches_fixture(self):
        """现跑 demo pcap 的特征必须与 fixture 逐项一致。"""
        self.assertTrue(SAMPLE.is_file(), f"缺少示例抓包：{SAMPLE}")
        rows, sink = _rows_from_pcap(SAMPLE)
        self.assertTrue(rows, f"tshark 没解析出报文：rc={sink.get('rc')}")
        feats = build_features(rows, meta={"pcap_name": SAMPLE.name})
        _assert_golden(self, feats.tcp.to_dict())

    def test_tshark_version_matches_fixture(self):
        """现跑 tshark 的主次版本必须与 golden 记录一致（不一致时给重生成命令）。"""
        self.assertTrue(FIXTURE.is_file(), f"缺少特征样本：{FIXTURE}")
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        recorded = data.get("tshark_version", "")
        current = version()
        recorded_mm = _major_minor(recorded)
        current_mm = _major_minor(current)
        hint = (
            "用 `python scripts/dump_features.py --pcap captures/faults_demo.pcap "
            "--out tests/fixtures/faults_features.json` 重新生成"
        )
        if not recorded_mm:
            self.fail(
                f"fixture 没有可用的 tshark_version（记录值：{recorded!r}）；{hint}"
            )
        if recorded_mm != current_mm:
            self.fail(
                "tshark 主次版本不同："
                f"fixture 记录 {recorded_mm} / 当前 {current_mm} / {hint}"
                f"（当前完整版本：{current}）"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
