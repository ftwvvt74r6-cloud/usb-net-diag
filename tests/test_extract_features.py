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
from unittest import mock
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


def _version_skip_reason(recorded: str, current: str) -> str | None:
    """判断「现跑 tshark 与 fixture 记录的主次版本是否一致」。

    Args:
        recorded: fixture 里记录的 ``tshark_version`` 首行。
        current: 当前机器上 ``tshark --version`` 的首行。

    Returns:
        str | None: 主次版本不一致时返回**跳过原因**（含两边完整版本号）；
        一致、或 fixture 压根没记版本时返回 ``None``（照常执行原断言）。

    Note:
        这里区分的是「环境不符」与「产品回归」：换了一台机器 / 升级了 tshark，
        现跑数字当然会和 golden 不同，那不是代码坏了；而 fixture 丢版本字段
        属于 fixture 被改坏，必须继续 fail（所以那种情况返回 ``None``）。
    """
    recorded_mm = _major_minor(recorded)
    if not recorded_mm:
        return None
    current_mm = _major_minor(current)
    if recorded_mm == current_mm:
        return None
    return (
        "tshark 主次版本与 fixture 不一致，跳过现跑比对（不是产品回归）："
        f"fixture 记录 {recorded or '(空)'}（主次 {recorded_mm}） / "
        f"当前检测到 {current or '(空)'}（主次 {current_mm or '未知'}）。"
        "确认要跟随新版本时，用 `python scripts/dump_features.py "
        "--pcap captures/faults_demo.pcap --out tests/fixtures/faults_features.json` 重生成。"
    )


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
        self.assertEqual(data["schema_version"], "2.2", "fixture 的 schema 版本与契约不一致")
        _assert_golden(self, data["tcp"])


@unittest.skipIf(NO_TSHARK, "没有 tshark，跳过现跑比对")
class FeaturesLiveTest(unittest.TestCase):
    """装了 tshark 时现跑一遍，确认 fixture 没被手改坏。"""

    def setUp(self) -> None:
        """版本不一致时整类跳过：否则同一份 pcap 会因 tshark 升级而被判「回归」。"""
        if not FIXTURE.is_file():
            return
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        reason = _version_skip_reason(data.get("tshark_version", ""), version())
        if reason:
            self.skipTest(reason)

    def test_live_run_matches_fixture(self):
        """现跑 demo pcap 的特征必须与 fixture 逐项一致。"""
        self.assertTrue(SAMPLE.is_file(), f"缺少示例抓包：{SAMPLE}")
        rows, sink = _rows_from_pcap(SAMPLE)
        self.assertTrue(rows, f"tshark 没解析出报文：rc={sink.get('rc')}")
        feats = build_features(rows, meta={"pcap_name": SAMPLE.name})
        _assert_golden(self, feats.tcp.to_dict())

    def test_tshark_version_matches_fixture(self):
        """兜底断言：走到这里说明 setUp 的版本门已判定一致。

        版本不一致时 ``setUp`` 会 ``skipTest`` 并打印两边版本；这一条留着是为了
        「fixture 丢字段 / 有人删掉 setUp」时仍然 fail，而不是静默放过。
        """
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


class TsharkVersionGateTest(unittest.TestCase):
    """钉住版本门的两条分支：同版本必须执行、不同版本必须跳过。

    这一组用**注入假版本**的方式验证，不依赖本机装的是哪个 tshark：
    否则「跳过逻辑写反了」在一台恰好版本一致的机器上永远发现不了。
    """

    RECORDED_DIFF_PATCH = "TShark (Wireshark) 9.9.9 (v9.9.9-0-gdeadbeef)."

    def test_same_major_minor_does_not_skip(self):
        self.assertIsNone(_version_skip_reason(
            "TShark (Wireshark) 4.7.4 (v4.7.4-0-gabc).",
            "TShark (Wireshark) 4.7.0 (v4.7.0-0-gdef)."),
            "主次版本相同（4.7）时不许跳过，否则现跑比对会被永久绕过")

    def test_different_major_minor_skips_with_both_versions(self):
        reason = _version_skip_reason("TShark (Wireshark) 4.7.4 (v4.7.4-0-gabc).",
                                      "TShark (Wireshark) 4.6.8 (v4.6.8-0-gxyz).")
        self.assertIsNotNone(reason, "主次版本不同必须跳过")
        self.assertIn("4.7.4", reason, "跳过原因要打印 fixture 记录的版本")
        self.assertIn("4.6.8", reason, "跳过原因要打印当前检测到的版本")

    def test_missing_recorded_version_still_fails_the_assertion(self):
        """fixture 丢版本字段属「fixture 被改坏」，必须继续 fail，不能变成 skip。"""
        self.assertIsNone(_version_skip_reason("", "TShark (Wireshark) 4.6.8."))

    def test_setup_skips_on_injected_mismatch(self):
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        recorded = data.get("tshark_version", "")
        if not _major_minor(recorded):
            self.skipTest("fixture 没有可用的 tshark_version，本用例无意义")
        case = FeaturesLiveTest("test_live_run_matches_fixture")
        with mock.patch.object(sys.modules[__name__], "version",
                               return_value=self.RECORDED_DIFF_PATCH):
            with self.assertRaises(unittest.SkipTest) as ctx:
                case.setUp()
        self.assertIn("9.9.9", str(ctx.exception))

    def test_setup_runs_when_versions_match(self):
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        recorded = data.get("tshark_version", "")
        if not _major_minor(recorded):
            self.skipTest("fixture 没有可用的 tshark_version，本用例无意义")
        case = FeaturesLiveTest("test_live_run_matches_fixture")
        with mock.patch.object(sys.modules[__name__], "version", return_value=recorded):
            case.setUp()  # 不抛 SkipTest 就代表会真的执行原断言


if __name__ == "__main__":
    unittest.main(verbosity=2)
