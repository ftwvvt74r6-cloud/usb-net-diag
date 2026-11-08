"""H6 统一 preflight：``GET /api/preflight`` 与 ``/api/selfcheck`` 同源。

这个文件回答三个问题：

1. **字段一致**：两个接口的 ``checks`` / ``capabilities`` / ``ui_copy`` 必须逐键相同
   （launcher 的 splash 与 UI 首屏读同一份后端数据，不许出现第二套判定）；
2. **无 first_run / ack 语义**：preflight 是「现在能不能用」，不承担首屏一次性的
   「首次运行」提醒，也不写标记；
3. **缓存单飞**：连续调用 preflight + selfcheck 只跑一次 ``selfcheck.collect``；
   路由内部只调 ``collect_cached``，不复制六项检查逻辑。

测试用真实 DiagServer + mock 掉六项检查的落点，不依赖 tshark / Npcap / 管理员，
CI 两端行为一致；不写仓库 ``config/``。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import selfcheck  # noqa: E402
import server  # noqa: E402

EXPECTED_KEYS = ["python", "tshark", "npcap", "scapy", "port", "admin"]


def _http(port: int, method: str, path: str, body: bytes | None = None,
          timeout: int = 15) -> tuple[int, str]:
    """本机 HTTP 请求；HTTPError 也当响应返回（同 test_selfcheck 的口径）。"""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _checks(tshark_ok: bool = True, npcap_ok: bool = True) -> list[dict]:
    """构造六项固定结构（含 fix_url / impact，模拟 collect() 的真实输出）。"""
    fix_urls = {
        "tshark": "https://www.wireshark.org/download.html",
        "npcap": "https://npcap.com/#download",
        "python": "https://www.python.org/downloads/windows/",
    }
    ok_map = {"python": True, "tshark": tshark_ok, "npcap": npcap_ok,
              "scapy": False, "port": True, "admin": False}
    out = []
    for key in EXPECTED_KEYS:
        ok = ok_map[key]
        item = {
            "key": key, "name": key, "ok": ok, "detail": f"{key} detail",
            "fix_kind": "url" if (not ok and key in fix_urls) else "none",
            "fix_url": "" if ok else fix_urls.get(key, ""),
            "fix_command": "", "impact": f"{key} impact",
            "doc_url": "docs/startup.md",
        }
        if key == "python":
            # S7 变异锚点：**通过项也带非空 fix_url**。实现若不过滤 ok，
            # 全绿时 fix_urls 就不再是空字典，下面的断言会直接红。
            item["fix_url"] = fix_urls["python"]
        out.append(item)
    return out


def _snapshot(*, first_run: bool = True, tshark_ok: bool = True,
              npcap_ok: bool = True) -> dict:
    """构造一份与 selfcheck.collect() 同结构的缓存值。"""
    checks = _checks(tshark_ok=tshark_ok, npcap_ok=npcap_ok)
    return {
        "ok": all(item["ok"] for item in checks),
        "version": "9.9.9",
        "first_run": first_run,
        "checks": checks,
        "capabilities": {
            "probe": True, "offline": tshark_ok, "live": tshark_ok and npcap_ok,
            "passive": npcap_ok, "reports": True, "settings": True,
            "path_probe": True, "mtr_engine": "tracert", "missing": {},
            "scapy": False,
        },
        "ui_copy": {"startup": {"panel_title": "准备检查", "fix_tshark": "安装 Wireshark"}},
    }


class PreflightPayloadTest(unittest.TestCase):
    """``preflight_payload()`` 只做「同源投影」：不新增判定、不带 first_run。"""

    def setUp(self) -> None:
        selfcheck.invalidate_cache()

    def tearDown(self) -> None:
        selfcheck.invalidate_cache()

    def test_payload_reuses_collect_cached_and_matches_selfcheck(self):
        snap = _snapshot()
        with mock.patch.object(server.selfcheck, "collect_cached",
                               return_value=snap) as collect:
            payload = server.preflight_payload()
            again = server.preflight_payload()
        self.assertEqual(collect.call_count, 2, "每次调用都走 collect_cached（缓存负责单飞）")
        self.assertEqual(payload, again)
        self.assertEqual([item["key"] for item in payload["checks"]], EXPECTED_KEYS)
        self.assertEqual(payload["capabilities"], snap["capabilities"])
        self.assertEqual(payload["ui_copy"], snap["ui_copy"])
        self.assertEqual(payload["version"], "9.9.9")
        self.assertEqual(payload["source"], "selfcheck", "必须显式标注同源")
        self.assertNotIn("first_run", payload,
                         "preflight 不承担首屏「首次运行」语义")
        self.assertNotIn("ack", payload)
        self.assertEqual(payload["fix_urls"], {},
                         "全部通过时修复索引为空（只有失败项才给官网链接）")

    def test_payload_fix_urls_include_only_failed_installable_checks(self):
        snap = _snapshot(tshark_ok=False, npcap_ok=False)
        with mock.patch.object(server.selfcheck, "collect_cached",
                               return_value=snap):
            payload = server.preflight_payload()
        self.assertEqual(payload["fix_urls"]["tshark"],
                         "https://www.wireshark.org/download.html")
        self.assertEqual(payload["fix_urls"]["npcap"], "https://npcap.com/#download")
        self.assertNotIn("python", payload["fix_urls"],
                         "通过项即使带 fix_url 也不该出现在修复索引里")

    def test_payload_does_not_call_individual_check_functions(self):
        """变异锚点：preflight 若自己复制一套判定（直接调 check_*）必须红。"""
        with mock.patch.object(server.selfcheck, "collect_cached",
                               return_value=_snapshot()) as collect, \
                mock.patch.object(server.selfcheck, "check_tshark",
                                  side_effect=AssertionError("不许复制检查逻辑")), \
                mock.patch.object(server.selfcheck, "check_npcap",
                                  side_effect=AssertionError("不许复制检查逻辑")):
            server.preflight_payload()
        collect.assert_called_once()


class PreflightRouteTest(unittest.TestCase):
    """真实 HTTP 路由：preflight / selfcheck 字段一致，缓存只跑一次。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._env = mock.patch.dict(
            os.environ, {"NETDIAG_LOG_DIR": str(Path(tempfile.gettempdir()) /
                                               "netdiag_preflight_logs")})
        cls._env.start()
        cls.httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._env.stop()

    def setUp(self) -> None:
        selfcheck.invalidate_cache()

    def tearDown(self) -> None:
        selfcheck.invalidate_cache()

    def test_preflight_and_selfcheck_share_checks_and_capabilities(self):
        with mock.patch.object(server.selfcheck, "collect",
                               return_value=_snapshot()) as collect:
            code_p, text_p = _http(self.port, "GET", "/api/preflight")
            code_s, text_s = _http(self.port, "GET", "/api/selfcheck")
        self.assertEqual(code_p, 200, text_p[:300])
        self.assertEqual(code_s, 200, text_s[:300])
        preflight = json.loads(text_p)
        selfcheck_data = json.loads(text_s)
        self.assertEqual(preflight["checks"], selfcheck_data["checks"])
        self.assertEqual(preflight["capabilities"], selfcheck_data["capabilities"])
        self.assertEqual(preflight["ui_copy"], selfcheck_data["ui_copy"])
        self.assertEqual(collect.call_count, 1,
                         "两次接口请求必须共用同一份缓存（单飞）")
        self.assertNotIn("first_run", preflight)
        self.assertIn("first_run", selfcheck_data, "旧 selfcheck 契约不许被改坏")
        self.assertIn("ok", selfcheck_data)
        self.assertIn("version", selfcheck_data)

    def test_preflight_fix_urls_are_derived_from_same_checks(self):
        snap = _snapshot(tshark_ok=False, npcap_ok=False)
        with mock.patch.object(server.selfcheck, "collect_cached",
                               return_value=snap):
            code, text = _http(self.port, "GET", "/api/preflight")
        self.assertEqual(code, 200, text[:300])
        data = json.loads(text)
        by_key = {item["key"]: item for item in data["checks"]}
        self.assertFalse(by_key["tshark"]["ok"])
        self.assertFalse(by_key["npcap"]["ok"])
        self.assertEqual(data["fix_urls"]["tshark"], by_key["tshark"]["fix_url"])
        self.assertEqual(data["fix_urls"]["npcap"], by_key["npcap"]["fix_url"])
        self.assertFalse(data["ok"])

    def test_preflight_has_no_ack_side_effect(self):
        """preflight 不能写首次运行标记（GET 只读；POST 路由不存在）。"""
        with mock.patch.object(server.selfcheck, "collect_cached",
                               return_value=_snapshot()), \
                mock.patch.object(server.selfcheck, "ack_first_run") as ack:
            code, _text = _http(self.port, "GET", "/api/preflight")
            code_post, _ = _http(self.port, "POST", "/api/preflight", b"{}")
        self.assertEqual(code, 200)
        self.assertEqual(code_post, 404, "preflight 不提供 ack 语义")
        ack.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
