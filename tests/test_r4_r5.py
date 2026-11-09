"""R4/R5 回归测试：保存手填组件路径 + 日志列表/正文接口。

R4 —— ``POST /api/selfcheck/path``（契约以 v2 前端 api.js 已定的调用为准）：

* ``{key: python|tshark, path: <绝对路径>}``；scapy / npcap 不能靠路径指定 → 400
  ``unsupported_key``；
* 校验三关（存在 / 是文件 / 可执行），失败分别 ``not_found`` / ``not_a_file`` /
  ``not_executable``；
* 校验通过写 ``config/paths.json``（与 ai-config 同一类本地 config，不写 .env、
  不把绝对路径提交进仓库），返回 ``{ok, key, path, item, preflight}``；
* 保存后强制重检，preflight 反映新状态（tshark 项 ok=True）。

R5 —— ``GET /api/logs`` + ``GET /api/log?name=``（契约以 logs.js/api.js 为准）：

* ``/api/logs`` 返回 ``{files:[{name, kind, size, mtime, epoch}]}``，只列 logs/
  直属的 app / diag / startup 三类；
* ``/api/log?name=`` 返回 JSON ``{ok, name, text, size, truncated, lines}``；
  ``&lines=N`` 取尾部 N 行（上限 5000）；``&download=1`` 改回 text/plain +
  ``Content-Disposition: attachment``；
* 安全：严格白名单 + 拒绝 ``../`` 穿越与符号链接；非法/不存在一律 404。

测试把 ``logstore.log_root()`` 指到临时目录（``NETDIAG_LOG_DIR``），不碰真实 logs/。
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import logstore  # noqa: E402
import server  # noqa: E402
import selfcheck  # noqa: E402


def _snapshot() -> dict:
    """构造一份与 selfcheck.collect() 同结构的缓存值（六项，含 fix 字段）。"""
    keys = ["python", "tshark", "npcap", "scapy", "port", "admin"]
    checks = [{
        "key": k, "name": k, "ok": True, "detail": f"{k} detail",
        "fix_kind": "none", "fix_url": "", "fix_command": "",
        "impact": f"{k} impact", "doc_url": "docs/startup.md",
    } for k in keys]
    return {
        "ok": True, "version": "9.9.9", "first_run": False, "checks": checks,
        "capabilities": {"probe": True, "offline": True, "live": True,
                         "passive": True, "reports": True, "settings": True,
                         "path_probe": True, "mtr_engine": "tracert",
                         "missing": {}, "scapy": True},
        "ui_copy": {"startup": {"panel_title": "准备检查"}},
    }


# ---------------------------------------------------------------- R4 纯函数

class ValidateComponentPathTest(unittest.TestCase):
    """``validate_component_path`` 三关校验 + key 白名单由调用方负责。"""

    def _mock_run(self, rc: int = 0, err: str = ""):
        return mock.patch.object(server.tshark, "run",
                                 return_value=(rc, "", err))

    def test_valid_python_file_passes(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_r4_") as tmp:
            exe = Path(tmp) / "python.exe"
            exe.write_bytes(b"")
            with self._mock_run(rc=0):
                ok, code, err = server.validate_component_path("python", str(exe))
        self.assertTrue(ok, err)
        self.assertEqual(code, "")

    def test_nonexistent_path(self):
        ok, code, err = server.validate_component_path(
            "tshark", r"C:\definitely\not\here\tshark.exe")
        self.assertFalse(ok)
        self.assertEqual(code, "not_found")
        self.assertIn("不存在", err)

    def test_directory_is_not_a_file(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_r4_") as tmp:
            ok, code, err = server.validate_component_path("tshark", tmp)
        self.assertFalse(ok)
        self.assertEqual(code, "not_a_file")
        self.assertIn("不是文件", err)

    def test_not_executable(self):
        with tempfile.TemporaryDirectory(prefix="netdiag_r4_") as tmp:
            exe = Path(tmp) / "tshark.exe"
            exe.write_bytes(b"")
            with self._mock_run(rc=1, err="bad command"):
                ok, code, err = server.validate_component_path("tshark", str(exe))
        self.assertFalse(ok)
        self.assertEqual(code, "not_executable")

    def test_empty_path(self):
        ok, code, _ = server.validate_component_path("tshark", "  ")
        self.assertFalse(ok)
        self.assertEqual(code, "empty")


class LogHelperTest(unittest.TestCase):
    """``log_files`` / ``_log_kind`` / ``resolve_log_file`` 的白名单与穿越。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="netdiag_r5_")
        self.logdir = Path(self._tmp.name) / "logs"
        self.logdir.mkdir()
        (self.logdir / "app-20261109.log").write_bytes(b"app line\n")
        (self.logdir / "diag-20261109.log").write_bytes(b"diag line\n")
        (self.logdir / "startup.log").write_bytes(b"startup line\n")
        (self.logdir / "env.json").write_bytes(b"{}")
        (self.logdir / "netdiag.pid").write_bytes(b"123")
        (self.logdir / "secret.txt").write_bytes(b"nope")
        sub = self.logdir / "runs"
        sub.mkdir()
        (sub / "x.json").write_bytes(b"{}")
        self._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(self.logdir)})
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    def test_log_files_lists_only_app_diag_startup(self):
        files = server.log_files()
        names = {f["name"] for f in files}
        self.assertEqual(names, {"app-20261109.log", "diag-20261109.log",
                                 "startup.log"})
        for f in files:
            self.assertIn(f["kind"], ("app", "diag", "startup"))
            self.assertIn("size", f)
            self.assertIn("mtime", f)
            self.assertIn("epoch", f)

    def test_log_kind_matches_prefix_forms(self):
        self.assertEqual(server._log_kind("app-20261109.log"), "app")
        self.assertEqual(server._log_kind("diag.log"), "diag")
        self.assertEqual(server._log_kind("startup-1.log"), "startup")
        for bad in ("env.json", "netdiag.pid", "secret.txt", "app-20261109.log.bak",
                    "../app.log", "app/../../x", "diag-20261109"):
            self.assertIsNone(server._log_kind(bad), bad)

    def test_resolve_log_file_rejects_traversal_and_non_whitelist(self):
        for name in ("../core/server.py", "..\\..\\core\\server.py",
                     "%2e%2e/app-20261109.log", "secret.txt", "env.json",
                     "runs/x.json", "app-20261109.log/../diag-20261109.log"):
            with self.subTest(name=name):
                self.assertIsNone(server.resolve_log_file(name), name)

    def test_resolve_log_file_returns_file_for_valid_name(self):
        p = server.resolve_log_file("diag-20261109.log")
        self.assertIsNotNone(p)
        self.assertEqual(p.name, "diag-20261109.log")

    def test_resolve_log_file_rejects_symlink(self):
        # 符号链接穿越：logs 下放一个指向外部文件的链接，resolve 后跑出 logs/。
        outside = self._tmp.name and Path(self._tmp.name) / "outside.txt"
        outside.write_bytes(b"secret")
        link = self.logdir / "app-link.log"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("本机不支持符号链接，跳过")
        self.assertIsNone(server.resolve_log_file("app-link.log"))


# ---------------------------------------------------------------- 真实 HTTP 路由

class R4R5RouteTest(unittest.TestCase):
    """真实 DiagServer（端口 0），日志目录与 config/paths.json 都指到临时目录。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="netdiag_r4r5_")
        cls.logdir = Path(cls._tmp.name) / "logs"
        cls.logdir.mkdir()
        (cls.logdir / "app-20261109.log").write_bytes(b"a1\na2\na3\na4\na5\n")
        (cls.logdir / "diag-20261109.log").write_bytes(b"d1\nd2\nd3\n")
        cls._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(cls.logdir)})
        cls._env.start()
        cls._paths_patch = mock.patch(
            "core.config.PATHS_CONFIG",
            Path(cls._tmp.name) / "config" / "paths.json")
        cls._paths_patch.start()
        # 隔离 UI 入口 config，避免读到真实 ui-version.json
        cls._uicfg = mock.patch.object(
            server, "UI_VERSION_CONFIG",
            Path(cls._tmp.name) / "config" / "ui-version.json")
        cls._uicfg.start()
        cls.httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._uicfg.stop()
        cls._paths_patch.stop()
        cls._env.stop()
        cls._tmp.cleanup()

    def _req(self, method: str, path: str, body: bytes | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body,
                         headers={"Content-Type": "application/json"} if body else {})
            resp = conn.getresponse()
            return (resp.status, resp.getheader("Content-Type") or "",
                    resp.getheader("Content-Disposition") or "",
                    resp.read())
        finally:
            conn.close()

    def _post_json(self, path: str, payload: dict):
        return self._req("POST", path, json.dumps(payload).encode("utf-8"))

    # ---- R4 路由
    def test_save_path_scapy_is_unsupported(self):
        status, _, _, raw = self._post_json(
            "/api/selfcheck/path", {"key": "scapy", "path": r"C:\x\scapy.py"})
        self.assertEqual(status, 200)  # 业务错误仍走 JSON 200，code 区分
        data = json.loads(raw)
        self.assertFalse(data["ok"])
        self.assertEqual(data["code"], "unsupported_key")

    def test_save_path_npcap_is_unsupported(self):
        status, _, _, raw = self._post_json(
            "/api/selfcheck/path", {"key": "npcap", "path": r"C:\x\npcap.exe"})
        data = json.loads(raw)
        self.assertFalse(data["ok"])
        self.assertEqual(data["code"], "unsupported_key")

    def test_save_path_not_found(self):
        status, _, _, raw = self._post_json(
            "/api/selfcheck/path",
            {"key": "tshark", "path": r"C:\definitely\missing\tshark.exe"})
        data = json.loads(raw)
        self.assertFalse(data["ok"])
        self.assertEqual(data["code"], "not_found")

    def test_save_path_invalid_json(self):
        # 非法 JSON：_read_json 回落到 {}，key 为空 → unsupported_key（安全兜底）。
        status, _, _, raw = self._req("POST", "/api/selfcheck/path", b"{not json")
        data = json.loads(raw)
        self.assertFalse(data["ok"])
        self.assertEqual(data["code"], "unsupported_key")

    def test_save_valid_python_path_writes_and_rechecks(self):
        exe = Path(self._tmp.name) / "python.exe"
        exe.write_bytes(b"")
        snap = _snapshot()
        with mock.patch.object(server.tshark, "run", return_value=(0, "Python 3.11.9", "")), \
                mock.patch.object(server.selfcheck, "collect_cached",
                                  return_value=snap) as collect:
            status, _, _, raw = self._post_json(
                "/api/selfcheck/path", {"key": "python", "path": str(exe)})
        self.assertEqual(status, 200)
        data = json.loads(raw)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["key"], "python")
        self.assertEqual(data["path"], str(exe))
        self.assertIn("item", data)
        self.assertIn("preflight", data)
        # 保存后必须强制重检（force=True），并拿到整体 preflight。
        collect.assert_called()
        # config/paths.json 已写入（临时目录），不碰真实 config。
        cfg = Path(self._tmp.name) / "config" / "paths.json"
        self.assertTrue(cfg.is_file())
        saved = json.loads(cfg.read_text(encoding="utf-8"))
        self.assertEqual(saved["python_path"], str(exe))

    def test_save_valid_tshark_path_writes(self):
        exe = Path(self._tmp.name) / "tshark.exe"
        exe.write_bytes(b"")
        snap = _snapshot()
        with mock.patch.object(server.tshark, "run", return_value=(0, "TShark 4.7.4", "")), \
                mock.patch.object(server.selfcheck, "collect_cached",
                                  return_value=snap):
            status, _, _, raw = self._post_json(
                "/api/selfcheck/path", {"key": "tshark", "path": str(exe)})
        data = json.loads(raw)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["key"], "tshark")
        cfg = Path(self._tmp.name) / "config" / "paths.json"
        saved = json.loads(cfg.read_text(encoding="utf-8"))
        self.assertEqual(saved["tshark_path"], str(exe))

    # ---- R5 路由
    def test_logs_list_fields_complete(self):
        status, ctype, _, raw = self._req("GET", "/api/logs")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ctype)
        data = json.loads(raw)
        self.assertTrue(data["ok"])
        names = {f["name"] for f in data["files"]}
        self.assertEqual(names, {"app-20261109.log", "diag-20261109.log"})
        for f in data["files"]:
            for field in ("name", "kind", "size", "mtime", "epoch"):
                self.assertIn(field, f, f"{field} 缺失")

    def test_log_reads_full_text(self):
        status, _, _, raw = self._req("GET", "/api/log?name=app-20261109.log")
        self.assertEqual(status, 200)
        data = json.loads(raw)
        self.assertEqual(data["text"], "a1\na2\na3\na4\na5\n")
        self.assertFalse(data["truncated"])
        self.assertEqual(data["name"], "app-20261109.log")

    def test_log_lines_truncates_to_tail(self):
        status, _, _, raw = self._req(
            "GET", "/api/log?name=app-20261109.log&lines=2")
        data = json.loads(raw)
        self.assertEqual(data["text"], "a4\na5\n")
        self.assertTrue(data["truncated"])

    def test_log_download_has_attachment_header(self):
        status, ctype, disp, body = self._req(
            "GET", "/api/log?name=diag-20261109.log&download=1")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "text/plain; charset=utf-8")
        self.assertIn("attachment", disp)
        self.assertIn("diag-20261109.log", disp)
        self.assertEqual(body, b"d1\nd2\nd3\n")

    def test_log_invalid_name_404(self):
        for name in ("../core/server.py", "secret.txt", "env.json",
                     "runs/x.json", "app-20261109.log.bak"):
            with self.subTest(name=name):
                status, _, _, raw = self._req(
                    "GET", "/api/log?name=" + urllib.parse.quote(name))
                self.assertEqual(status, 404, f"{name} 必须 404：{raw[:80]!r}")

    def test_log_missing_file_404(self):
        status, _, _, _ = self._req("GET", "/api/log?name=app-20200101.log")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
