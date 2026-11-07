"""``core/sanitize.py`` 的回归测试：诊断包脱敏规则（M2 · V4 / V8 / 红线 4）。

测试只调纯函数，不读项目日志、不依赖 tshark / 网络。要钉死五件事：

1. 五类对象（私有 IP / 公网 IP / 域名 / 用户目录 / MAC）的脱敏形态正确；
2. **同一对象各处伪名一致**（方便看「同一对端出现 N 次」）；
3. 文件名（``faults_demo.json``）与版本号不会被误判成域名；
4. **幂等**：对已脱敏文本再跑一遍不二次打码（SPEC 陷阱 2）；
5. ``sanitize`` 不 import 任何网络模块（SPEC V8）。
"""

from __future__ import annotations

import hashlib
import re
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import sanitize  # noqa: E402

MASKED_HEX = re.compile(r"#[0-9a-f]{4}")
#: 允许出现在 ``sanitize.py`` / ``diagpack.py`` 里的 import 前缀（白名单之外的网络模块都要抓）。
NETWORK_MODULES = ("socket", "urllib", "http", "ftplib", "smtplib", "telnetlib",
                   "xmlrpc", "requests", "asyncio", "ssl")


def _hash4(text: str) -> str:
    """测试侧独立算一遍伪名，避免用被测函数自证。"""
    return hashlib.sha1(text.lower().encode("utf-8")).hexdigest()[:4]


class PseudonymTests(unittest.TestCase):
    def test_deterministic_and_case_insensitive(self):
        """伪名 = sha1(小写原文) 前 4 位；大小写不同视为同一对象。"""
        self.assertEqual(sanitize.pseudonym("192.168.1.100"), _hash4("192.168.1.100"))
        self.assertEqual(sanitize.pseudonym("WWW.Company.COM"), _hash4("www.company.com"))
        self.assertRegex(sanitize.pseudonym("1.2.3.4"), r"^[0-9a-f]{4}$")

    def test_empty_returns_empty(self):
        """空串不产生伪名（没有对象可标识）。"""
        self.assertEqual(sanitize.pseudonym(""), "")


class IPMaskTests(unittest.TestCase):
    def test_private_ip_masks_last_octet(self):
        """私有 IP 只打码尾段，并带稳定伪名（SPEC V4）。"""
        out = sanitize.mask_text("访问 192.168.1.100 的 445 端口")
        self.assertIn(f"192.168.1.***#{_hash4('192.168.1.100')}", out)
        self.assertNotIn("192.168.1.100", out)
        self.assertIn("445", out, "端口是诊断必需信息，不许打码")

    def test_public_ip_masks_last_two_octets(self):
        """公网 IP 后两段打码（SPEC V4）。"""
        out = sanitize.mask_text("DNS 8.8.8.8 超时")
        self.assertIn(f"8.8.***.***#{_hash4('8.8.8.8')}", out)
        self.assertNotIn("8.8.8.8", out)

    def test_private_ranges(self):
        """RFC1918 / 回环 / 链路本地都按私有地址处理（只打码尾段）。"""
        for ip in ("10.1.2.3", "172.16.5.7", "127.0.0.1", "169.254.10.20"):
            with self.subTest(ip=ip):
                out = sanitize.mask_text(ip)
                self.assertTrue(out.endswith(".***" + f"#{_hash4(ip)}"), out)
                self.assertNotIn(ip, out)

    def test_invalid_ip_untouched(self):
        """长得像 IP 但不是（999.999.999.999）的串保持原样。"""
        text = "版本 999.999.999.999 不是地址"
        self.assertEqual(sanitize.mask_text(text), text)

    def test_same_ip_same_pseudonym_everywhere(self):
        """同一 IP 在日志不同位置得到完全相同的脱敏串。"""
        out = sanitize.mask_text("192.168.1.100 -> 192.168.1.100；peer=192.168.1.100")
        masked = re.findall(r"192\.168\.1\.\*\*\*#[0-9a-f]{4}", out)
        self.assertEqual(len(masked), 3)
        self.assertEqual(len(set(masked)), 1, "同一 IP 的伪名不一致")

    def test_already_masked_ip_is_idempotent(self):
        """已经脱敏的 IP（``***`` + ``#伪名``）不会被再打一次码。"""
        once = sanitize.mask_text("8.8.8.8")
        self.assertEqual(sanitize.mask_text(once), once)


class DomainMaskTests(unittest.TestCase):
    def test_domain_keeps_tld_and_first_char(self):
        """域名每段留首字符、其余 ``*``，顶级域保留，末尾带稳定伪名。"""
        out = sanitize.mask_text("访问 www.company.com 失败")
        self.assertIn(f"w**.c******.com#{_hash4('www.company.com')}", out)
        self.assertNotIn("www.company.com", out)
        self.assertNotIn("company", out)

    def test_internal_suffix_domain_masked(self):
        """内网后缀（``.local`` / ``.internal``）同样按域名脱敏。"""
        for domain in ("printer.local", "db.internal"):
            with self.subTest(domain=domain):
                out = sanitize.mask_text(domain)
                self.assertNotIn(domain, out)
                self.assertTrue(out.endswith("#" + _hash4(domain)), out)

    def test_filenames_are_not_domains(self):
        """**普通**文件名不能被当成域名（SPEC 陷阱 4）。

        注意：``report.ai.md`` 不在此列 —— ``.ai`` 是真实顶级域，stem 看起来就是域名，
        按「宁可多脱敏」会打码；这里用 ``report.v2.md`` 验证「扩展名不当域名」。
        """
        for name in ("faults_demo.json", "app-20261107.log", "docs/api-reference.md",
                     "report.v2.md", "captures/faults_demo.pcap"):
            with self.subTest(name=name):
                self.assertEqual(sanitize.mask_text(name), name)

    def test_email_domain_part_is_masked(self):
        """``user@company.com``：用户名与域名都脱敏（审查建议：本地部分也是用户名）。"""
        out = sanitize.mask_text("联系 alice@company.com")
        self.assertNotIn("company.com", out)
        self.assertNotIn("alice", out)
        self.assertIn("<user>@", out)
        self.assertIn(f"c******.com#{_hash4('company.com')}", out)


class PathMaskTests(unittest.TestCase):
    def test_windows_user_path(self):
        """``C:\\Users\\alice\\x.log`` → ``C:\\Users\\<user>\\x.log``（SPEC V4 原例）。"""
        out = sanitize.mask_text(r"C:\Users\alice\x.log")
        self.assertEqual(out, r"C:\Users\<user>\x.log")
        self.assertNotIn("alice", out)

    def test_forward_slash_user_path(self):
        """正斜杠写法同样处理，且保持原分隔符。"""
        out = sanitize.mask_text("C:/Users/alice/x.log")
        self.assertEqual(out, "C:/Users/<user>/x.log")

    def test_other_absolute_path_becomes_root_relative(self):
        """非用户目录的绝对路径：盘符与上层目录隐去，留最后两段便于排障。"""
        path = r"D:\builds\agent-7\NetDiag\tools\WiresharkPortable\App\Wireshark\tshark.exe"
        out = sanitize.mask_text(path)
        self.assertEqual(out, r"<root>\Wireshark\tshark.exe")
        self.assertNotIn("D:", out)
        self.assertNotIn("agent-7", out)

    def test_already_masked_user_path_is_stable(self):
        """``C:\\Users\\<user>`` 再跑一遍仍是原样（幂等，陷阱 2）。"""
        text = r"C:\Users\<user>\x.log"
        self.assertEqual(sanitize.mask_text(text), text)


class FilenameMaskTests(unittest.TestCase):
    """审查阻塞 ①：文件名 stem 里的 IP / 域名必须脱敏，扩展名保留。"""

    def test_private_ip_filename_keeps_extension(self):
        """``192.168.1.100.pcap`` → ``192.168.1.***#25c9.pcap``。"""
        out = sanitize.mask_text("192.168.1.100.pcap")
        self.assertEqual(out, f"192.168.1.***#{_hash4('192.168.1.100')}.pcap")
        self.assertNotIn("192.168.1.100", out)

    def test_public_ip_filename_keeps_extension(self):
        """公网 IP 文件名同样打码，扩展名不变。"""
        out = sanitize.mask_text("8.8.8.8.pcap")
        self.assertIn(f"8.8.***.***#{_hash4('8.8.8.8')}", out)
        self.assertTrue(out.endswith(".pcap"), out)

    def test_domain_filename_keeps_extension(self):
        """``www.company.com.pcap`` → ``w**.c******.com#37f4.pcap``。"""
        out = sanitize.mask_text("www.company.com.pcap")
        self.assertEqual(out, f"w**.c******.com#{_hash4('www.company.com')}.pcap")

    def test_uppercase_domain_filename_keeps_extension(self):
        """``MAIL.Corp.Example.COM.md`` 不能因为 ``.md`` 像扩展名就整串放过。"""
        out = sanitize.mask_text("MAIL.Corp.Example.COM.md")
        self.assertTrue(out.endswith(".md"), out)
        self.assertNotIn("MAIL.Corp.Example.COM", out)
        self.assertIn(f"M***.C***.E******.COM#{_hash4('MAIL.Corp.Example.COM')}", out)

    def test_trailing_sentence_period_does_not_bypass(self):
        """句末点号不能绕过 IPv4 规则（``192.168.1.100.``）。"""
        out = sanitize.mask_text("目标 192.168.1.100.")
        self.assertNotIn("192.168.1.100", out)
        self.assertIn(f"192.168.1.***#{_hash4('192.168.1.100')}.", out)

    def test_masked_filename_is_idempotent(self):
        """已脱敏的文件名再跑一遍不二次打码。"""
        once = sanitize.mask_text("www.company.com.pcap")
        self.assertEqual(sanitize.mask_text(once), once)


class LeadingZeroIpTests(unittest.TestCase):
    """审查阻塞 ②：前导零 IPv4 先归一化再判断，不许因 ``ipaddress`` 拒绝而跳过。"""

    def test_leading_zero_ip_is_masked(self):
        """``192.168.001.100`` 必须脱敏，且与 ``192.168.1.100`` 是同一个伪名。"""
        out = sanitize.mask_text("peer=192.168.001.100")
        self.assertNotIn("192.168.001.100", out)
        self.assertIn(f"192.168.1.***#{_hash4('192.168.1.100')}", out)

    def test_leading_zero_public_ip_masked(self):
        """公网前导零（``008.008.008.008``）同样归一化后打码。"""
        out = sanitize.mask_text("dns=008.008.008.008")
        self.assertNotIn("008.008.008.008", out)
        self.assertIn(f"8.8.***.***#{_hash4('8.8.8.8')}", out)


class PathVariantTests(unittest.TestCase):
    """审查阻塞 ②：``%USERPROFILE%`` / UNC / 混合斜杠 / Documents and Settings。"""

    def test_userprofile_username_masked(self):
        """``%USERPROFILE%\\alice`` → ``<home>\\<user>``（原值全消失）。"""
        out = sanitize.mask_text(r"%USERPROFILE%\alice")
        self.assertNotIn("alice", out)
        self.assertNotIn("%USERPROFILE%", out)
        self.assertIn(r"<home>\<user>", out)

    def test_userprofile_with_trailing_file(self):
        """``%USERPROFILE%\\alice\\x.log`` 只抹用户名，文件名保留。"""
        out = sanitize.mask_text(r"%USERPROFILE%\alice\x.log")
        self.assertNotIn("alice", out)
        self.assertIn(r"<home>\<user>\x.log", out)

    def test_userprofile_known_subdir_not_mistaken_for_user(self):
        """``%USERPROFILE%\\AppData`` 的 ``AppData`` 不是用户名，不要误伤。"""
        out = sanitize.mask_text(r"%USERPROFILE%\AppData\Local")
        self.assertEqual(out, r"<home>\AppData\Local")

    def test_unc_host_masked(self):
        """``\\\\fileserver\\share\\z`` 的主机名段 → ``<host>``。"""
        out = sanitize.mask_text(r"\\fileserver\share\z")
        self.assertNotIn("fileserver", out)
        self.assertIn(r"\\<host>\share\z", out)

    def test_mixed_separator_user_path(self):
        """``C:\\Users/alice/x.log``（正反斜杠混用）用户名必须消失。"""
        out = sanitize.mask_text(r"C:\Users/alice/x.log")
        self.assertNotIn("alice", out)
        self.assertIn(r"<user>", out)
        self.assertIn("x.log", out)

    def test_documents_and_settings_user(self):
        """``C:\\Documents and Settings\\alice`` 的用户目录分支必须可达。"""
        out = sanitize.mask_text(r"C:\Documents and Settings\alice\z.log")
        self.assertNotIn("alice", out)
        self.assertIn(r"C:\Documents and Settings\<user>\z.log", out)

    def test_standalone_users_segment_masked(self):
        """没有盘符的 ``/Users/alice``（例如 JSON 片段）也覆盖。"""
        out = sanitize.mask_text("/Users/alice/x.log")
        self.assertEqual(out, "/Users/<user>/x.log")


class VariantTableTests(unittest.TestCase):
    """验收变体表（16 项）一次跑完：不含原值、端口保留、幂等。"""

    CASES = (
        ("10.0.0.1:8080", ("10.0.0.1",), (":8080",)),
        ("http://192.168.1.100/x", ("192.168.1.100",), ("http://", "/x")),
        ("172.16.5.5", ("172.16.5.5",), ()),
        ("8.8.8.8", ("8.8.8.8",), ()),
        ("1.1.1.1", ("1.1.1.1",), ()),
        ("MAIL.Corp.Example.COM", ("MAIL.Corp.Example.COM", "mail.corp.example.com"), ("COM#",)),
        ("a.b.c.d.example.com", ("a.b.c.d.example.com",), ("com#",)),
        ("192.168.001.100", ("192.168.001.100",), ("192.168.1.***",)),
        (r"%USERPROFILE%\alice", ("%USERPROFILE%", "alice"), ("<home>", "<user>")),
        (r"\\fileserver\share\z", ("fileserver",), (r"\\<host>\share\z",)),
        (r"C:\Users/alice/x.log", ("alice",), ("<user>", "x.log")),
        (r"C:\Documents and Settings\alice", ("alice",), ("<user>",)),
        ("aa:bb:cc:dd:ee:ff", ("aa:bb:cc:dd:ee:ff", "dd:ee:ff"), ("aa:bb:cc:",)),
        ("AA-BB-CC-DD-EE-FF", ("AA-BB-CC-DD-EE-FF", "DD-EE-FF"), ("AA-BB-CC-",)),
        ("2001:db8::1", ("2001:db8::1", "db8"), ("<ipv6>#",)),
        ("::ffff:192.168.1.100", ("::ffff:192.168.1.100", "192.168.1.100"), ("<ipv6>#",)),
    )

    def test_all_16_variants_have_no_original_value(self):
        """16 个变体逐个断言：原值搜不到、必须保留的片段仍在、再跑一遍不变。"""
        for text, forbidden, required in self.CASES:
            with self.subTest(text=text):
                out = sanitize.mask_text(text)
                lowered = out.lower()
                for value in forbidden:
                    self.assertNotIn(value.lower(), lowered, f"{text} 仍含原值 {value!r}")
                for value in required:
                    self.assertIn(value.lower(), lowered)
                self.assertEqual(sanitize.mask_text(out), out, f"{text} 脱敏不幂等")

    def test_same_object_same_pseudonym(self):
        """同一 IP 的不同变体（前导零 / 大小写域名）得到同一伪名。"""
        canonical = sanitize.mask_text("192.168.1.100")
        leading_zero = sanitize.mask_text("192.168.001.100")
        self.assertEqual(canonical, leading_zero)
        upper = sanitize.mask_text("WWW.Company.COM")
        lower = sanitize.mask_text("www.company.com")
        self.assertEqual(upper.lower(), lower.lower())


class TokenCollectionTests(unittest.TestCase):
    """泄漏自检的输入：收集到的 token 类别必须准确，且普通文本不产生噪声。"""

    def test_collects_all_categories(self):
        """IPv4/IPv6/域名/MAC/用户名/UNC 主机名各一个。"""
        tokens = sanitize.collect_tokens(
            "peer=10.0.0.1 host=www.company.com mac=aa:bb:cc:dd:ee:ff "
            r"log=C:\Users\alice\x.log unc=\\fileserver\share "
            "ipv6=2001:db8::1"
        )
        self.assertEqual(tokens["10.0.0.1"], "ipv4")
        self.assertEqual(tokens["2001:db8::1"], "ipv6")
        self.assertEqual(tokens["www.company.com"], "domain")
        self.assertEqual(tokens["aa:bb:cc:dd:ee:ff"], "mac")
        self.assertEqual(tokens["alice"], "user")
        self.assertEqual(tokens["fileserver"], "host")

    def test_filename_tokens_collected(self):
        """文件名里的 IP / 域名也是 token（供 diagpack 自检）。"""
        self.assertEqual(sanitize.collect_tokens("192.168.1.100.pcap"),
                         {"192.168.1.100": "ipv4"})
        self.assertEqual(sanitize.collect_tokens("www.company.com.pcap"),
                         {"www.company.com": "domain"})

    def test_plain_text_has_no_tokens(self):
        """普通文本/版本号不产生 token（避免自检误报）。"""
        self.assertEqual(sanitize.collect_tokens("faults_demo.json 版本 1.2.3 port=8080"), {})


class MACMaskTests(unittest.TestCase):
    def test_colon_mac_tail_masked(self):
        """MAC 前 3 字节保留（厂商标识），尾 3 字节 ``**`` + 稳定伪名。"""
        out = sanitize.mask_text("网卡 aa:bb:cc:dd:ee:ff 断开")
        self.assertIn(f"aa:bb:cc:**:**:**#{_hash4('aa:bb:cc:dd:ee:ff')}", out)
        self.assertNotIn("dd:ee:ff", out)

    def test_hyphen_mac_masked(self):
        """Windows 常见 ``AA-BB-CC-DD-EE-FF`` 写法同样处理，分隔符不变。"""
        out = sanitize.mask_text("AA-BB-CC-DD-EE-FF")
        self.assertEqual(out, f"AA-BB-CC-**-**-**#{_hash4('AA-BB-CC-DD-EE-FF')}")

    def test_uuid_not_mistaken_for_mac(self):
        """UUID（8-4-4-4-12）不是 MAC，不许动。"""
        uuid = "123e4567-e89b-12d3-a456-426614174000"
        self.assertEqual(sanitize.mask_text(uuid), uuid)


class CombinedMaskTests(unittest.TestCase):
    def test_all_five_examples_together_and_idempotent(self):
        """SPEC V4 的五个原例一起上：全部消失、形态正确、再跑一遍不变。"""
        text = (
            "peer=192.168.1.100 dns=8.8.8.8 host=www.company.com "
            r"log=C:\Users\alice\x.log mac=aa:bb:cc:dd:ee:ff"
        )
        out = sanitize.mask_text(text)
        for original in ("192.168.1.100", "8.8.8.8", "www.company.com",
                         r"C:\Users\alice", "aa:bb:cc:dd:ee:ff"):
            with self.subTest(original=original):
                self.assertNotIn(original, out)
        self.assertIn(f"192.168.1.***#{_hash4('192.168.1.100')}", out)
        self.assertIn(f"8.8.***.***#{_hash4('8.8.8.8')}", out)
        self.assertIn(f"w**.c******.com#{_hash4('www.company.com')}", out)
        self.assertIn(r"C:\Users\<user>\x.log", out)
        self.assertIn(f"aa:bb:cc:**:**:**#{_hash4('aa:bb:cc:dd:ee:ff')}", out)
        self.assertEqual(sanitize.mask_text(out), out, "脱敏不幂等，会二次打码")

    def test_empty_text(self):
        """空串原样返回（不抛异常）。"""
        self.assertEqual(sanitize.mask_text(""), "")


class MaskObjTests(unittest.TestCase):
    def test_nested_json_values_are_masked(self):
        """``mask_obj`` 递归处理 dict/list/tuple 里的字符串值。"""
        payload = {
            "target": "192.168.1.100",
            "nested": {"domain": "www.company.com", "n": 3, "ok": True},
            "items": [r"C:\Users\alice\x.log", "aa:bb:cc:dd:ee:ff", None],
        }
        out = sanitize.mask_obj(payload)
        self.assertIn(f"192.168.1.***#{_hash4('192.168.1.100')}", out["target"])
        self.assertIn(f"w**.c******.com#{_hash4('www.company.com')}", out["nested"]["domain"])
        self.assertEqual(out["nested"]["n"], 3)
        self.assertIs(out["nested"]["ok"], True)
        self.assertIn("aa:bb:cc:**:**:**", out["items"][1])
        self.assertIsNone(out["items"][2])
        self.assertIsInstance(out["items"], list)

    def test_input_is_not_mutated(self):
        """返回新对象：调用方还能拿原始对象做判断。"""
        payload = {"target": "192.168.1.100"}
        sanitize.mask_obj(payload)
        self.assertEqual(payload["target"], "192.168.1.100")


class NoNetworkImportTests(unittest.TestCase):
    def test_sanitize_source_has_no_network_import(self):
        """``sanitize.py`` 源码里不出现任何网络模块 import（SPEC V8）。"""
        source = (ROOT / "core" / "sanitize.py").read_text(encoding="utf-8")
        for module in NETWORK_MODULES:
            pattern = rf"(?m)^\s*(?:import|from)\s+{re.escape(module)}\b"
            self.assertIsNone(re.search(pattern, source), f"sanitize.py 竟然 import 了 {module}")

    def test_mask_text_works_with_connect_blocked(self):
        """把 ``socket.socket.connect`` 换成抛异常：脱敏照常工作（证明没有网络调用）。"""

        def _boom(*_args, **_kwargs):
            raise RuntimeError("禁止联网")

        with mock.patch.object(socket.socket, "connect", _boom):
            out = sanitize.mask_text("8.8.8.8 www.company.com")
        self.assertNotIn("8.8.8.8", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
