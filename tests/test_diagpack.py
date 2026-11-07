"""``core/diagpack.py`` 的回归测试：诊断包结构、脱敏、护栏与三个入口（M2 · V1~V9）。

所有用例都把 ``NETDIAG_LOG_DIR`` 指到临时目录（SPEC 陷阱 8），**绝不写仓库 logs/**。
需要 tshark 的地方都用 mock 或直接写文件，CI 的干净 checkout 也能跑。
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import diagnose   # noqa: E402
import diagpack   # noqa: E402
import logstore   # noqa: E402
import server     # noqa: E402

BAT = ROOT / "导出诊断包.bat"
UI = ROOT / "ui" / "index.html"
NAME_RE = re.compile(r"^NetDiag-diag-[0-9a-f]{8}-\d{8}-\d{4}(?:-\d+)?\.zip$")
NETWORK_MODULES = ("socket", "urllib", "http", "ftplib", "smtplib", "telnetlib",
                   "xmlrpc", "requests", "asyncio", "ssl")
#: 验收用的五个原值（SPEC V4）。
SECRETS = ("192.168.1.100", "8.8.8.8", "www.company.com",
           r"C:\Users\alice\x.log", "aa:bb:cc:dd:ee:ff")


def _sensitive_line() -> str:
    """一行同时包含五类敏感对象（与验收用例一致）。"""
    return ("peer=192.168.1.100 dns=8.8.8.8 host=www.company.com "
            r"log=C:\Users\alice\x.log mac=aa:bb:cc:dd:ee:ff")


def _write(path: Path, text: str) -> Path:
    """写 UTF-8 文本文件并建好父目录。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _set_age(path: Path, minutes: float) -> None:
    """把 mtime 调成 ``minutes`` 分钟前（负值表示未来），用于排序/30 天过滤。"""
    stamp = time.time() - minutes * 60
    os.utime(path, (stamp, stamp))


def _seed(root: Path, runs: int = 2, crashes: int = 1) -> None:
    """造一份最小日志现场：env + 日文件 + runs + crashes（内容含五类敏感对象）。"""
    _write(root / "env.json", json.dumps({
        "version": "0.1.0",
        "tshark_path": r"D:\builds\agent-7\NetDiag\tools\WiresharkPortable"
                       r"\App\Wireshark\tshark.exe",
        "entry": "test",
    }, ensure_ascii=False, indent=2))
    _write(root / "diag-20261107.log", f"[20:00:00] [INFO] {_sensitive_line()}\n")
    for index in range(runs):
        path = _write(root / "runs" / f"2026010{index}-000000-abcdef0{index}.json",
                      json.dumps({"mode": "offline", "ok": True,
                                  "params": {"target": "192.168.1.100",
                                             "pcap": "faults_demo.pcap"}},
                                 ensure_ascii=False))
        _set_age(path, 10 - index)
    for index in range(crashes):
        path = _write(root / "crashes" / f"2026010{index}-000000-1-2-abcd.txt",
                      f"消息: {_sensitive_line()}\n")
        _set_age(path, 10 - index)


def _zip_text(path: Path) -> tuple[list[str], dict[str, str]]:
    """返回 ``(文件名列表, {文件名: UTF-8 文本})``。"""
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        texts = {name: zf.read(name).decode("utf-8", "replace") for name in names}
    return names, texts


class _TempLogCase(unittest.TestCase):
    """公共夹具：日志根目录注入临时目录，跑完关句柄再清理（Windows 才能删）。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="netdiag_pack_")
        self.root = Path(self._tmp.name) / "logs"
        self.root.mkdir(parents=True)
        self._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(self.root)})
        self._env.start()
        logstore.close_streams()

    def tearDown(self) -> None:
        logstore.close_streams()
        self._env.stop()
        self._tmp.cleanup()


class BuildLayoutTests(_TempLogCase):
    def test_default_output_dir_and_filename(self):
        """默认写 ``<日志根目录>/exports/``，文件名符合 SPEC V2。"""
        _seed(self.root, runs=0, crashes=0)
        path = diagpack.build()
        self.assertIsInstance(path, Path)
        self.assertEqual(path.parent, self.root / "exports")
        self.assertRegex(path.name, NAME_RE)
        self.assertTrue(path.is_file())
        self.assertNotIn("desktop", path.name.lower(), "文件名不许出现真实机器名")

    def test_out_dir_override_creates_nested(self):
        """``out_dir`` 可覆盖输出目录，多级新目录自动创建。"""
        _seed(self.root, runs=0, crashes=0)
        out = Path(self._tmp.name) / "custom" / "nested"
        path = diagpack.build(out_dir=out)
        self.assertEqual(path.parent, out)
        self.assertTrue(path.is_file())

    def test_collision_appends_sequence(self):
        """同一分钟连续导出两次：第二次加 ``-2``，不覆盖第一个包（SPEC 陷阱 1）。"""
        _seed(self.root, runs=0, crashes=0)
        first = diagpack.build()
        second = diagpack.build()
        self.assertTrue(first.is_file() and second.is_file())
        self.assertNotEqual(first, second)
        self.assertTrue(second.name.endswith("-2.zip"), second.name)

    def test_structure_env_logs_runs_crashes_readme(self):
        """包内结构：env.json + logs/*.log + runs/*.json + crashes/*.txt + README.txt。"""
        _seed(self.root, runs=2, crashes=1)
        names, _texts = _zip_text(diagpack.build())
        self.assertIn("README.txt", names)
        self.assertIn("env.json", names)
        diag_logs = [n for n in names if n.startswith("logs/") and n.endswith(".log")]
        runs = [n for n in names if n.startswith("runs/") and n.endswith(".json")]
        crashes = [n for n in names if n.startswith("crashes/") and n.endswith(".txt")]
        self.assertTrue(diag_logs, names)
        self.assertEqual(len(runs), 2)
        self.assertEqual(len(crashes), 1)

    def test_limits_30_days_20_runs_10_crashes(self):
        """日志只收最近 30 天；runs 最多 20 条；crashes 最多 10 份（SPEC V3）。"""
        old = _write(self.root / "diag-20200101.log", "old\n")
        _set_age(old, 60 * 24 * 40)  # 40 天前
        _write(self.root / "diag-20261107.log", "new\n")
        for index in range(25):
            path = _write(self.root / "runs" / f"20260101-0000{index:02d}-abcdef{index:02d}.json",
                          "{}")
            _set_age(path, 100 - index)
        for index in range(12):
            path = _write(self.root / "crashes" / f"20260101-0000{index:02d}-1-2-abcd.txt", "x")
            _set_age(path, 100 - index)
        names, _ = _zip_text(diagpack.build())
        logs = [n for n in names if n.startswith("logs/")]
        runs = [n for n in names if n.startswith("runs/")]
        crashes = [n for n in names if n.startswith("crashes/")]
        self.assertNotIn("logs/diag-20200101.log", logs, "超过 30 天的日志不该进包")
        self.assertEqual(len(logs), 1)
        self.assertEqual(len(runs), 20)
        self.assertEqual(len(crashes), 10)
        # 留下的是最新 20 条（文件名尾号 05..24）
        self.assertIn("runs/20260101-000024-abcdef24.json", runs)
        self.assertNotIn("runs/20260101-000004-abcdef04.json", runs)

    def test_include_reports_adds_latest_three_pairs(self):
        """``include_reports=True``：最近 3 份报告，同名 ``.md`` / ``.json`` 成对收录。"""
        _seed(self.root, runs=0, crashes=0)
        reports = Path(self._tmp.name) / "reports"
        reports.mkdir()
        for index in range(5):
            _write(reports / f"r{index}.md", f"# report {index} {_sensitive_line()}\n")
            path = _write(reports / f"r{index}.json", json.dumps({"peer": "192.168.1.100"}))
            _set_age(path, 50 - index)
            _set_age(reports / f"r{index}.md", 50 - index)
        with mock.patch.object(diagpack, "REPORTS", reports):
            names, texts = _zip_text(diagpack.build(include_reports=True))
        report_names = sorted(n for n in names if n.startswith("reports/"))
        self.assertEqual(report_names, [
            "reports/r2.json", "reports/r2.md",
            "reports/r3.json", "reports/r3.md",
            "reports/r4.json", "reports/r4.md",
        ])
        joined = "\n".join(texts[n] for n in report_names)
        self.assertNotIn("192.168.1.100", joined, "报告正文也必须脱敏")

    def test_reports_absent_by_default(self):
        """不加 ``--include-reports`` 时包里没有 reports/。"""
        _seed(self.root, runs=0, crashes=0)
        names, _ = _zip_text(diagpack.build())
        self.assertFalse([n for n in names if n.startswith("reports/")])


class SanitizeInPackageTests(_TempLogCase):
    def test_five_secrets_masked_everywhere(self):
        """五个原值在包内**逐个搜不到**，且同一 IP 各处伪名一致（SPEC V4 / 验收 1）。"""
        _seed(self.root, runs=2, crashes=1)
        reports = Path(self._tmp.name) / "reports"
        _write(reports / "demo.md", f"# demo\n{_sensitive_line()}\n")
        with mock.patch.object(diagpack, "REPORTS", reports):
            names, texts = _zip_text(diagpack.build(include_reports=True))
        joined = "\n".join(texts.values())
        for secret in SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, joined, f"zip 内仍能搜到原值：{secret}")
        # 同一 IP 在所有文件里的脱敏串必须完全一致
        masked = set(re.findall(r"192\.168\.1\.\*\*\*#[0-9a-f]{4}", joined))
        self.assertEqual(len(masked), 1, f"同一 IP 出现多个伪名：{masked}")
        self.assertIn("8.8.***.***#", joined)
        self.assertIn("w**.c******.com#", joined)
        self.assertIn(r"C:\Users\<user>\x.log", joined)
        self.assertIn("aa:bb:cc:**:**:**#", joined)

    def test_env_absolute_paths_become_root_relative(self):
        """``env.json`` 的 ``tshark_path`` 绝对路径变 ``<root>\\...``（SPEC 陷阱 3）。"""
        _seed(self.root, runs=0, crashes=0)
        _names, texts = _zip_text(diagpack.build())
        env = json.loads(texts["env.json"])
        self.assertTrue(env["tshark_path"].startswith("<root>\\"), env["tshark_path"])
        self.assertNotIn("D:", texts["env.json"])
        self.assertNotIn("agent-7", texts["env.json"])
        self.assertIn("tshark.exe", env["tshark_path"])

    def test_readme_explains_masked_no_pcap_no_upload(self):
        """README.txt 必须说清：是什么、已脱敏、不含 pcap、工具不上传（SPEC V5）。"""
        _seed(self.root, runs=0, crashes=0)
        _names, texts = _zip_text(diagpack.build())
        readme = texts["README.txt"]
        self.assertIn("已脱敏", readme)
        self.assertIn("pcap", readme)
        self.assertIn("不含 pcap", readme)
        self.assertIn("不上传任何数据", readme)
        self.assertIn("怎么发回", readme)
        self.assertIn("logs/", readme)

    def test_raw_keeps_values_and_readme_warns(self):
        """``raw=True``：保留原值，但 README 必须警告「未脱敏」（SPEC V6）。"""
        _seed(self.root, runs=0, crashes=0)
        _names, texts = _zip_text(diagpack.build(raw=True))
        joined = "\n".join(texts.values())
        self.assertIn("192.168.1.100", joined)
        self.assertIn("未脱敏", texts["README.txt"])
        self.assertIn("已保留原值", texts["README.txt"])


class FilenameLeakTests(_TempLogCase):
    """审查阻塞 ①：pcap / 报告文件名本身就是 IP / 域名时，包内名字与内容都不能带原值。"""

    def test_sensitive_filenames_masked_in_names_and_contents(self):
        """``192.168.1.100.pcap`` / ``www.company.com.md`` / ``MAIL.Corp.Example.COM`` 全链路。"""
        _seed(self.root, runs=0, crashes=0)
        _write(self.root / "192.168.1.100.log", "peer=192.168.1.100\n")
        for index, pcap_name in enumerate(
                ("192.168.1.100.pcap", "www.company.com.pcap", "MAIL.Corp.Example.COM.md")):
            _write(self.root / "runs" / f"20260101-00000{index}-abcdef0{index}.json",
                   json.dumps({"mode": "offline", "params": {"pcap": pcap_name}}))
        reports = Path(self._tmp.name) / "reports"
        for index, stem in enumerate(
                ("192.168.1.100", "www.company.com", "MAIL.Corp.Example.COM")):
            _write(reports / f"{stem}.md", f"# {stem}.pcap\npeer=192.168.1.100\n")
            _set_age(reports / f"{stem}.md", 10 - index)
        with mock.patch.object(diagpack, "REPORTS", reports):
            path = diagpack.build(include_reports=True)
        names, texts = _zip_text(path)
        blob = "\n".join(names) + "\n" + "\n".join(texts.values())
        for secret in ("192.168.1.100", "www.company.com", "MAIL.Corp.Example.COM"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, blob, f"包内仍能搜到原值：{secret}")
        for name in names:
            with self.subTest(name=name):
                self.assertIsNone(re.search(r'[<>:"|?*]', name),
                                  f"zip 条目名含 Windows 非法字符，解压会失败：{name}")

    def test_oversized_sensitive_filename_masked_in_readme(self):
        """被跳过的文件名也要脱敏后才写进 README（不能从跳过清单泄露）。"""
        _seed(self.root, runs=0, crashes=0)
        big = _write(self.root / "192.168.1.100.log", _sensitive_line() + "\n" * 300)
        self.assertGreater(big.stat().st_size, 500)
        with mock.patch.object(diagpack, "MAX_FILE_BYTES", 500):
            _names, texts = _zip_text(diagpack.build())
        readme = texts["README.txt"]
        self.assertNotIn("192.168.1.100", readme)
        self.assertIn("192.168.1.___#25c9", readme)


class LeakSelfCheckTests(_TempLogCase):
    """验收 3：默认拒绝的泄漏自检 —— 命中即抛异常、不产生 zip、错误信息不含原值。"""

    def test_verify_no_leaks_direct(self):
        """独立函数可单测：名字命中、内容命中都会抛；干净条目放行。"""
        with self.assertRaises(RuntimeError) as ctx:
            diagpack._verify_no_leaks(
                [("192.168.1.100.pcap", b"clean")], {"192.168.1.100": "ipv4"})
        self.assertIn("ipv4", str(ctx.exception))
        self.assertNotIn("192.168.1.100", str(ctx.exception))
        with self.assertRaises(RuntimeError) as ctx:
            diagpack._verify_no_leaks(
                [("clean.txt", b"peer=www.company.com")], {"www.company.com": "domain"})
        self.assertIn("域名", str(ctx.exception))
        self.assertNotIn("www.company.com", str(ctx.exception))
        # MAC 出现在文件名里（后跟 .pcap）也要能命中，不能被边界漏掉
        with self.assertRaises(RuntimeError) as ctx:
            diagpack._verify_no_leaks(
                [("aa:bb:cc:dd:ee:ff.pcap", b"clean")],
                {"aa:bb:cc:dd:ee:ff": "mac"})
        self.assertIn("MAC", str(ctx.exception))
        diagpack._verify_no_leaks(
            [("192.168.1.___#25c9.pcap", b"peer=192.168.1.***#25c9")],
            {"192.168.1.100": "ipv4"})

    def test_build_aborts_and_writes_no_zip_when_mask_rule_neutralized(self):
        """把域名规则“关掉”（替换函数退化为原样返回）→ build 必须抛异常且不写 zip。"""
        _seed(self.root, runs=0, crashes=0)  # 日志/崩溃快照里含 www.company.com
        out = Path(self._tmp.name) / "mut-out"
        with mock.patch.object(diagpack.sanitize, "_mask_domain",
                               lambda match: match.group(0)):
            with self.assertRaises(RuntimeError) as ctx:
                diagpack.build(out_dir=out)
        message = str(ctx.exception)
        self.assertIn("域名", message)
        self.assertNotIn("www.company.com", message, "错误信息不许打印原值")
        self.assertEqual(list(out.glob("*.zip")), [], "自检失败后不许留下 zip")
        # 恢复规则后正常导出
        path = diagpack.build(out_dir=out)
        self.assertTrue(path.is_file())
        _names, texts = _zip_text(path)
        self.assertNotIn("www.company.com", "\n".join(texts.values()))


class GuardrailTests(_TempLogCase):
    def test_oversized_file_skipped_and_noted(self):
        """单文件超过上限 → 跳过并写进 README，原值不会以任何形式进包（SPEC V9）。"""
        _seed(self.root, runs=0, crashes=0)
        big = _write(self.root / "diag-big.log", _sensitive_line() + "\n" * 300)
        self.assertGreater(big.stat().st_size, 500)
        with mock.patch.object(diagpack, "MAX_FILE_BYTES", 500):
            names, texts = _zip_text(diagpack.build())
        self.assertNotIn("logs/diag-big.log", names)
        self.assertIn("diag-big.log", texts["README.txt"])
        self.assertIn("超过单文件", texts["README.txt"])
        self.assertNotIn("192.168.1.100", "\n".join(texts.values()))

    def test_total_limit_skips_remaining(self):
        """包内总量很小 → 所有文件都跳过并写进 README，仍然产出一个只有 README 的包。"""
        _seed(self.root, runs=1, crashes=1)
        with mock.patch.object(diagpack, "MAX_TOTAL_BYTES", 1):
            names, texts = _zip_text(diagpack.build())
        self.assertEqual(names, ["README.txt"])
        self.assertIn("超过包内总量", texts["README.txt"])

    def test_mask_failure_skips_file_never_exports_raw(self):
        """脱敏抛异常 → 跳过该文件（宁可少一个，不可导出原文，SPEC 红线 4）。"""
        _seed(self.root, runs=0, crashes=0)
        with mock.patch.object(diagpack.sanitize, "mask_text",
                               side_effect=RuntimeError("boom")):
            names, texts = _zip_text(diagpack.build())
        self.assertEqual(names, ["README.txt"], names)
        self.assertIn("脱敏失败", texts["README.txt"])
        self.assertNotIn("192.168.1.100", "\n".join(texts.values()))

    def test_build_works_with_socket_connect_blocked(self):
        """把 socket 连接换成抛异常，导出照常成功（SPEC V8：绝不联网）。"""

        def _boom(*_args, **_kwargs):
            raise RuntimeError("禁止联网")

        _seed(self.root, runs=0, crashes=0)
        with mock.patch.object(socket.socket, "connect", _boom):
            path = diagpack.build()
        self.assertTrue(path.is_file())

    def test_source_has_no_network_import(self):
        """``diagpack.py`` / ``sanitize.py`` 源码里没有任何网络模块 import（SPEC V8）。"""
        for name in ("diagpack.py", "sanitize.py"):
            source = (ROOT / "core" / name).read_text(encoding="utf-8")
            for module in NETWORK_MODULES:
                pattern = rf"(?m)^\s*(?:import|from)\s+{re.escape(module)}\b"
                self.assertIsNone(re.search(pattern, source),
                                  f"{name} 竟然 import 了 {module}")


class EntryPointTests(_TempLogCase):
    def test_cli_export_diag(self):
        """入口①：``diagnose.py --export-diag`` 进程内实跑，返回 0 且写出 zip。"""
        _seed(self.root, runs=0, crashes=0)
        out = Path(self._tmp.name) / "cli-out"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = diagnose.main(["--export-diag", "--out", str(out)])
        self.assertEqual(rc, 0, stdout.getvalue()[-800:])
        files = list(out.glob("*.zip"))
        self.assertEqual(len(files), 1)
        self.assertIn("诊断包已生成", stdout.getvalue())
        self.assertIn("已脱敏", stdout.getvalue())

    def test_cli_raw_prints_warning_on_console(self):
        """入口① ``--raw``：控制台必须警告（SPEC V6 双警告之一）。"""
        _seed(self.root, runs=0, crashes=0)
        out = Path(self._tmp.name) / "cli-raw"
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(stderr):
            rc = diagnose.main(["--export-diag", "--raw", "--out", str(out)])
        self.assertEqual(rc, 0)
        self.assertIn("--raw", stderr.getvalue())
        self.assertIn("未脱敏", stderr.getvalue())

    def test_bat_entry_contract(self):
        """入口②：根目录 ``导出诊断包.bat`` 存在且调用 ``--export-diag``（双击即用）。"""
        self.assertTrue(BAT.is_file(), "缺少 导出诊断包.bat")
        text = BAT.read_text(encoding="utf-8")
        self.assertIn("core\\diagnose.py", text)
        self.assertIn("--export-diag", text)
        self.assertIn("tools\\python\\python.exe", text)
        self.assertIn("pause", text, "双击运行结束后窗口会一闪而过，需要 pause")

    def test_ui_has_diagpack_button_and_handler(self):
        """入口③：UI 顶部有 ``#diagpack`` 按钮，点击 POST ``/api/diagpack``。"""
        text = UI.read_text(encoding="utf-8")
        self.assertIn('id="diagpack"', text)
        self.assertIn("导出诊断包", text)
        self.assertIn("/api/diagpack", text)
        self.assertIn('$("#diagpack").onclick', text)
        # 不许碰坏既有按钮
        self.assertIn('id="ai-open"', text)
        self.assertIn('id="quit-app"', text)
        self.assertIn('$("#quit-app").onclick = quitApp;', text)

    def test_http_endpoint_returns_ok_path_size_entries(self):
        """入口③ HTTP 实跑：``POST /api/diagpack`` 返回 ok + path + size + entries。"""
        _seed(self.root, runs=0, crashes=0)
        httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/diagpack", data=b"{}", method="POST",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=60) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertTrue(data.get("ok"), data)
        path = Path(data["path"])
        self.assertTrue(path.is_file())
        self.assertEqual(path.parent, self.root / "exports")
        self.assertGreater(data["size"], 0)
        self.assertGreaterEqual(data["entries"], 3)  # env + log + README
        _names, texts = _zip_text(path)
        self.assertNotIn("192.168.1.100", "\n".join(texts.values()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
