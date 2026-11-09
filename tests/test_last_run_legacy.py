"""last-run/result 旧记录（legacy）判定回归测试。

issue：``/api/last-run/result`` 恢复旧记录时会用 ``_attach_conclusion`` 现算一份
conclusion 补进去；前端如果只看 conclusion 是否存在，就会把这份「补出来」的
conclusion 当成新结果，渲染四层「未知」卡（而不是「旧版本结果」横幅）。

守的口径：

1. legacy 判定依据是「记录是否带 ``record_schema``」或「verdict 是否含
   ``basis`` / ``coverage`` / ``not_covered``」，**不能只看 conclusion 是否存在**；
2. ``/api/last-run/result`` 返回时带 ``legacy``（顶层 + result 内）与
   ``legacy_reason`` 原因说明；
3. 前端 ``conclusionData`` 优先信服务端下发的 ``legacy`` 标记。

变异（mutation）：把 ``_is_legacy_result`` 的判定改成「只看 conclusion 是否存在」，
本文件的 legacy 用例必须变红（因为 ``_attach_conclusion`` 会把 conclusion 补上）。
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

import logstore  # noqa: E402
import server  # noqa: E402
import verdict  # noqa: E402

HOST = "127.0.0.1"


def _old_payload() -> dict:
    """构造 E1 之前的旧 payload：无 record_schema、verdict 无边界字段、无 conclusion。"""
    result = {
        "ok": True,
        "meta": {
            "pcap_name": "legacy_sample.pcap", "packets": 20, "duration": 10.0,
            "interface": "test0", "bpf": "",
        },
        "rows": [],
        "metrics": {},
        "summary": {"target": "192.0.2.20", "critical_count": 0, "warning_count": 0},
    }
    result["verdict"] = verdict.build(result)  # verdict.build 不含 basis/coverage/not_covered
    return result


def _reset_last_run() -> None:
    server.LAST_RUN.update({"summary": None, "result": None, "cleared_at": 0.0})


class IsLegacyResultTest(unittest.TestCase):
    """纯函数 ``_is_legacy_result`` 的判定依据。"""

    def test_old_payload_is_legacy(self):
        legacy, reason = server._is_legacy_result(_old_payload())
        self.assertTrue(legacy)
        self.assertTrue(reason, "legacy 必须带原因说明")

    def test_record_schema_marks_not_legacy(self):
        payload = _old_payload()
        payload["record_schema"] = 2
        legacy, reason = server._is_legacy_result(payload)
        self.assertFalse(legacy)
        self.assertEqual(reason, "")

    def test_ui_contract_version_marks_not_legacy(self):
        payload = _old_payload()
        payload["ui_contract_version"] = "2"
        legacy, _ = server._is_legacy_result(payload)
        self.assertFalse(legacy)

    def test_verdict_boundary_fields_mark_not_legacy(self):
        payload = _old_payload()
        payload["verdict"]["basis"] = ["依据"]
        legacy, _ = server._is_legacy_result(payload)
        self.assertFalse(legacy)

    def test_conclusion_alone_does_not_mark_not_legacy(self):
        # 关键变异点：只补 conclusion（无 record_schema、verdict 无边界字段）仍是 legacy。
        payload = _old_payload()
        payload["conclusion"] = {"conclusion": "一句话结论", "basis": [], "coverage": [],
                                 "not_covered": []}
        legacy, _ = server._is_legacy_result(payload)
        self.assertTrue(legacy, "只看 conclusion 存在会把旧结果误判成新结果")

    def test_none_is_legacy(self):
        legacy, _ = server._is_legacy_result(None)
        self.assertTrue(legacy)


class LastRunResultLegacyHttpTest(unittest.TestCase):
    """``/api/last-run/result`` 对旧记录返回 legacy 标记。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: cls.tmp.name})
        cls._env.start()
        logstore.close_streams()
        _reset_last_run()
        cls.httpd = server.DiagServer((HOST, 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.15)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls._env.stop()
        logstore.close_streams()
        cls.tmp.cleanup()

    def setUp(self) -> None:
        _reset_last_run()

    def _get(self, path: str) -> tuple[int, dict]:
        try:
            with urllib.request.urlopen(
                    f"http://{HOST}:{self.port}{path}", timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_old_payload_returns_legacy_true(self):
        # 直接把 E1 之前的旧 payload 塞进内存（模拟旧版本进程留下的结果），
        # 不经过 _remember_last_run（那个入口现在会打 record_schema 标记）。
        with server.LOCK:
            server.LAST_RUN["result"] = _old_payload()
        status, body = self._get("/api/last-run/result")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertTrue(body.get("legacy"), "旧记录必须返回 legacy=true")
        self.assertIn("legacy_reason", body)
        self.assertTrue(body["result"].get("legacy"), "result 内也要带 legacy 标记")
        # _attach_conclusion 会补 conclusion，但 legacy 仍应为 true ——
        # 这正是「不能只看 conclusion 存在」要防的场景。
        self.assertIn("conclusion", body["result"])

    def test_fresh_result_returns_legacy_false(self):
        # 正常入口（_remember_last_run）会打 record_schema，判定非 legacy。
        server._remember_last_run("live", "example.com", time.time() - 1, _old_payload())
        status, body = self._get("/api/last-run/result")
        self.assertEqual(status, 200)
        self.assertFalse(body.get("legacy"), "带 record_schema 的新结果不应 legacy")

    def test_remember_last_run_stamps_record_schema(self):
        server._remember_last_run("live", "example.com", time.time() - 1, _old_payload())
        stored = server._last_run_result()
        self.assertEqual(stored.get("record_schema"), server.diagnose.RUN_RECORD_SCHEMA)

    def test_remember_last_run_does_not_pollute_payload(self):
        # 打标记必须走浅拷贝，不能污染传入的 payload（否则会污染 JOB["result"] 与报告）。
        payload = _old_payload()
        server._remember_last_run("live", "example.com", time.time() - 1, payload)
        self.assertNotIn("record_schema", payload,
                         "打标记不得回写原 payload（会污染报告快照）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
