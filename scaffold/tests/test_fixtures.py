"""样本生成器 + 迁移桥的自检。

覆盖两组：

1. `tests/fixtures/gen_pcap.py`：确定性、pcap 结构合法、expected.json 自洽。
2. `core/rules/legacy_map.py`：每个真实 row 都有归宿、正常行不产出 Finding、
   方向未知的规则被降到低置信度、漏项能被发现。

**不依赖 tshark**：生成器只写字节，测试只读字节。
（「样本能否让 tshark 产出 tcp.analysis.* 字段」由 `gen_pcap.py --verify` 负责，
那一步需要真 tshark，所以不进 CI 的纯 Python job。）
"""

from __future__ import annotations

import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from core.contracts import EvidenceKind, Layer, Severity
from core.rules import legacy_map as lm
from tests.fixtures import gen_pcap

HERE = Path(__file__).parent


def _read_pcap(path: Path) -> tuple[dict, list[dict]]:
    """最小 pcap 解析器（只用标准库），返回 (全局头, 记录列表)。"""
    raw = path.read_bytes()
    if len(raw) < 24:
        raise AssertionError("文件太小，不是 pcap")
    magic, vmaj, vmin, _tz, _sig, snap, linktype = struct.unpack("<IHHiIII", raw[:24])
    header = {"magic": magic, "vmajor": vmaj, "vminor": vmin,
              "snaplen": snap, "linktype": linktype, "size": len(raw)}
    records: list[dict] = []
    offset = 24
    while offset + 16 <= len(raw):
        sec, usec, incl, orig = struct.unpack("<IIII", raw[offset:offset + 16])
        offset += 16
        data = raw[offset:offset + incl]
        offset += incl
        records.append({"ts": sec + usec / 1_000_000, "incl": incl,
                        "orig": orig, "len": len(data)})
    return header, records


class GenPcapTests(unittest.TestCase):
    def _generate(self, out: Path, manifest: bool = True) -> dict:
        with contextlib.redirect_stdout(io.StringIO()):
            return gen_pcap.generate(out, manifest=manifest)

    def test_all_cases_present(self):
        self.assertEqual(len(gen_pcap.CASES), 9)
        names = [c.filename for c in gen_pcap.CASES]
        self.assertEqual(len(names), len(set(names)), "样本文件名不能重复")
        self.assertEqual({Path(n).stem for n in names}, set(gen_pcap.BY_NAME))

    def test_output_is_deterministic(self):
        """同版本两次生成，字节必须完全一致 —— 否则 CLI 断言 sha256 就没意义。"""
        with tempfile.TemporaryDirectory(dir=HERE) as a, \
                tempfile.TemporaryDirectory(dir=HERE) as b:
            first = self._generate(Path(a), manifest=False)
            second = self._generate(Path(b), manifest=False)
            hashes_a = {c["file"]: c["sha256"] for c in first["cases"]}
            hashes_b = {c["file"]: c["sha256"] for c in second["cases"]}
            self.assertEqual(hashes_a, hashes_b)
            for case in first["cases"]:
                self.assertEqual(
                    (Path(a) / case["file"]).read_bytes(),
                    (Path(b) / case["file"]).read_bytes(),
                    f"{case['file']} 两次生成不一致",
                )

    def test_pcap_structure_is_valid(self):
        with tempfile.TemporaryDirectory(dir=HERE) as tmp:
            doc = self._generate(Path(tmp), manifest=False)
            for case in doc["cases"]:
                header, records = _read_pcap(Path(tmp) / case["file"])
                with self.subTest(file=case["file"]):
                    self.assertEqual(header["magic"], gen_pcap.PCAP_MAGIC)
                    self.assertEqual((header["vmajor"], header["vminor"]), (2, 4))
                    self.assertEqual(header["linktype"], gen_pcap.PCAP_LINKTYPE_ETHERNET)
                    self.assertEqual(len(records), case["packets"])
                    for rec in records:
                        self.assertEqual(rec["incl"], rec["orig"])
                        self.assertEqual(rec["len"], rec["incl"])
                        self.assertGreater(rec["len"], 14)      # 至少以太网头
                    # 时间戳必须单调不减（剧本是顺序写的）
                    stamps = [r["ts"] for r in records]
                    self.assertEqual(stamps, sorted(stamps))

    def test_expected_manifest(self):
        with tempfile.TemporaryDirectory(dir=HERE) as tmp:
            doc = self._generate(Path(tmp))
            written = json.loads((Path(tmp) / "expected.json").read_text(encoding="utf-8"))
        self.assertEqual(written, doc)
        self.assertEqual(written["schema_version"], "1.0")
        self.assertEqual(len(written["cases"]), 9)
        for case in written["cases"]:
            with self.subTest(file=case["file"]):
                self.assertTrue(case["file"].endswith(".pcap"))
                self.assertRegex(case["sha256"], r"^[0-9a-f]{64}$")
                expect = case["expect"]
                self.assertIsInstance(expect["rule_ids"], list)
                # 同一个 rule_id 不能既「必须命中」又「不许命中」
                overlap = set(expect["rule_ids"]) & set(expect.get("must_not") or ())
                self.assertEqual(overlap, set(), f"{case['file']} 的期望自相矛盾")
                self.assertTrue(case["note"], "每个样本都要写清它守的是什么")

    def test_negative_control_has_no_expectation(self):
        """负向对照（udp_no_response）必须期望「零命中」，否则它就失去意义了。"""
        case = next(c for c in gen_pcap.CASES if c.filename == "udp_no_response.pcap")
        self.assertEqual(case.expect_rule_ids, ())
        self.assertTrue(case.must_not)


class LegacyMapTests(unittest.TestCase):
    #: 真实 rows —— 直接取自 analyzer 对 8 个样本的实跑输出（见 docs/code-index.md）
    ROWS: tuple[tuple[dict, str | None], ...] = (
        ({"layer": "L2 本地链路", "category": "本地可达性",
          "finding": "1 个同网段地址的 ARP 请求没有得到应答", "severity": "警告",
          "evidence": "192.168.1.1"}, "L2.ARP.NO_REPLY"),
        ({"layer": "L3 网络层", "category": "网络可达性",
          "finding": "收到 3 条 ICMP 不可达、0 条超时，其中包含「需要分片」提示 → 典型 MTU/分片问题",
          "severity": "严重", "evidence": "10.0.0.7→192.168.1.100"}, "L3.ICMP.UNREACH"),
        ({"layer": "L3 网络层", "category": "网络时延",
          "finding": "往返时延 RTT 平均 322ms、P95 1010ms、最大 1010ms，抖动 449ms",
          "severity": "警告", "evidence": "基于 10 个 ACK 采样"}, "L3.RTT.HIGH"),
        ({"layer": "L4 传输层", "category": "连接建立",
          "finding": "1 个连接发出 SYN 后始终没有收到回应，TCP 三次握手未完成",
          "severity": "严重", "evidence": "10.0.0.5:8080（SYN 3 包）"}, "L4.CONNECT.NO_RESPONSE"),
        ({"layer": "L4 传输层", "category": "连接建立",
          "finding": "2 个连接被对端 RST 重置（对方明确拒绝）", "severity": "警告",
          "evidence": "10.0.0.5:8080"}, "L4.CONNECT.RST"),
        ({"layer": "L4 传输层", "category": "连接建立",
          "finding": "TCP 握手平均 480ms、最大 620ms，抖动 90ms", "severity": "警告",
          "evidence": "共 4 个完整握手样本"}, "L4.CONNECT.SLOW_HANDSHAKE"),
        ({"layer": "L4 传输层", "category": "连接建立",
          "finding": "建连正常（1 个会话，握手平均 20ms）", "severity": "—",
          "evidence": "—"}, None),
        ({"layer": "L4 传输层", "category": "传输质量",
          "finding": "TCP 重传率 9.09%（1/11 个报文），乱序 0.00%，重复 ACK 0.00%",
          "severity": "严重", "evidence": "Stream 3"}, "L4.RETRANS.HIGH"),
        ({"layer": "L4 传输层", "category": "传输质量",
          "finding": "出现 TCP 零窗口 5 次、窗口满 0 次", "severity": "警告",
          "evidence": "零窗口=接收方缓冲区被塞满"}, "L4.ZEROWIN.SIDE"),
        ({"layer": "L7 应用层", "category": "域名解析",
          "finding": "域名解析失败率 25%（NXDOMAIN 1/4）", "severity": "警告",
          "evidence": "app.corp.local 失败 1 次"}, "L7.DNS.FAIL"),
        ({"layer": "L7 应用层", "category": "域名解析",
          "finding": "有 3 次查询没有收到响应（超时）", "severity": "警告",
          "evidence": "查询 4 次 / 响应 1 次"}, "L7.DNS.TIMEOUT"),
        ({"layer": "L7 应用层", "category": "域名解析",
          "finding": "DNS 响应平均 385ms、最大 385ms", "severity": "警告",
          "evidence": "1 个响应样本，DNS 服务器 192.168.1.53"}, "L7.DNS.SLOW"),
        ({"layer": "L7 应用层", "category": "域名解析",
          "finding": "解析正常（1 次查询，平均 42ms）", "severity": "—",
          "evidence": "—"}, None),
        ({"layer": "L7 应用层", "category": "应用响应",
          "finding": "1 个请求返回 5xx（服务端错误，占 50%）", "severity": "严重",
          "evidence": "状态码分布：200×1、500×1"}, "L7.HTTP.5XX"),
        ({"layer": "L7 应用层", "category": "应用响应",
          "finding": "1 个请求返回 4xx（客户端/权限问题）", "severity": "提示",
          "evidence": "状态码分布：404×1"}, "L7.HTTP.4XX"),
        ({"layer": "L7 应用层", "category": "应用响应",
          "finding": "HTTP 响应正常（1 个请求，平均 2ms）", "severity": "—",
          "evidence": "—"}, None),
        ({"layer": "L7 应用层", "category": "TLS 会话",
          "finding": "检测到 TLS 流量（6 个 SNI，12 条告警）", "severity": "提示",
          "evidence": "SNI：app.corp.local"}, "L7.TLS.ALERTS"),
        ({"layer": "安全观察", "category": "可疑外联",
          "finding": "外联 203.0.113.9 使用高危端口 4444(Metasploit 反弹端口)，共 3 个报文",
          "severity": "警告", "evidence": "帧 #41"}, "SEC.EXFIL"),
        ({"layer": "安全观察", "category": "端口扫描",
          "finding": "外联 203.0.113.9 发散的端口达 22 个，疑似扫描", "severity": "提示",
          "evidence": "帧 #44"}, "SEC.SCAN"),
        ({"layer": "安全观察", "category": "明文凭证",
          "finding": "HTTP Basic 凭据明文传输（app.corp.local/login）", "severity": "警告",
          "evidence": "帧 #51"}, "SEC.PLAINTEXT"),
        ({"layer": "安全观察", "category": "安全观察",
          "finding": "未发现可疑外联与明文认证（此项为附带观察，不是本工具主线）",
          "severity": "—", "evidence": "—"}, None),
        ({"layer": "L4 传输层", "category": "连接建立",
          "finding": "未检测到 TCP 会话（抓包周期内无 TCP 流量）", "severity": "—",
          "evidence": "报文 5 个"}, None),
    )

    def test_every_row_has_a_home(self):
        for row, want in self.ROWS:
            with self.subTest(finding=row["finding"][:30]):
                self.assertEqual(lm.find_unmatched([row]), [], "有 row 没被映射")
                finding = lm.to_finding(row)
                if want is None:
                    self.assertIsNone(finding, "正常行不应该产出 Finding")
                else:
                    self.assertIsNotNone(finding)
                    self.assertEqual(finding.rule_id, want)

    def test_unmatched_is_detected(self):
        orphan = {"layer": "L4 传输层", "category": "未知类别",
                  "finding": "这条没人认识它", "severity": "警告"}
        self.assertNotEqual(lm.find_unmatched([orphan]), [])
        self.assertEqual(lm.coverage([orphan])["unmatched"], 1)

    def test_direction_dependent_rules_are_downgraded(self):
        """旧数据没有方向：靠方向判结论的规则必须是「推断 + 低置信度 + 无方向」。"""
        retrans = lm.to_finding(next(r for r, w in self.ROWS if w == "L4.RETRANS.HIGH"))
        zero = lm.to_finding(next(r for r, w in self.ROWS if w == "L4.ZEROWIN.SIDE"))
        for finding in (retrans, zero):
            self.assertIsNone(finding.direction)
            self.assertEqual(finding.evidence_kind, EvidenceKind.INFERRED)
            self.assertLess(finding.confidence, 1.0)

    def test_numbers_are_extracted_for_templates(self):
        retrans = lm.to_finding(next(r for r, w in self.ROWS if w == "L4.RETRANS.HIGH"))
        self.assertEqual(retrans.metric["retrans_rate"], 9.09)
        dns = lm.to_finding(next(r for r, w in self.ROWS if w == "L7.DNS.FAIL"))
        self.assertEqual(dns.metric["rate"], 25.0)
        http = lm.to_finding(next(r for r, w in self.ROWS if w == "L7.HTTP.5XX"))
        self.assertEqual(http.metric["err5"], 1)
        self.assertEqual(http.metric["err5_rate"], 50.0)
        zero = lm.to_finding(next(r for r, w in self.ROWS if w == "L4.ZEROWIN.SIDE"))
        self.assertEqual(zero.metric["zero_win"], 5)

    def test_security_rows_go_to_sec_layer(self):
        for row, want in self.ROWS:
            if want and want.startswith("SEC."):
                finding = lm.to_finding(row)
                self.assertEqual(finding.layer, Layer.SEC)
                self.assertIn(finding.severity, (Severity.WARNING, Severity.INFO))

    def test_mapping_never_returns_chinese_advice_key(self):
        """规则里不许出现中文 —— advice_key / headline_key 必须是机器码。"""
        for pattern in lm.PATTERNS:
            with self.subTest(rule_id=pattern.rule_id):
                for text in (pattern.rule_id, pattern.advice_key):
                    self.assertFalse(any("\u4e00" <= ch <= "\u9fff" for ch in text),
                                     f"{text!r} 里出现了中文")

    def test_missing_from_registry_is_the_migration_checklist(self):
        """脚手架比 registry 宽是正常的；这个函数就是 T05 的待办清单。"""
        missing = lm.missing_from_registry()
        self.assertIsInstance(missing, tuple)
        self.assertTrue(set(missing) <= set(lm.mapped_rule_ids()))
        # 至少有 L7.DNS.TIMEOUT / L7.HTTP.4XX 这类还没被 rules/ 吃下的
        self.assertIn("L7.DNS.TIMEOUT", missing)


if __name__ == "__main__":
    unittest.main(verbosity=2)
