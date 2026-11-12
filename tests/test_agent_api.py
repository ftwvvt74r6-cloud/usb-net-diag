"""P0-2 契约测试：``/api/agent/*`` 与 ``/api/monitor`` —— 设置页在真机上「全是未开启」。

**钉的是什么**
--------------
设置页那三行字（装没装 / 在不在跑 / 最近一次采样）以前是**猜**的：后端没有接口，
前端只能按「拿不到 = 没开」渲染。这一组用例钉住三件事：

1. **事实来源**：装没装只认计划任务 ``NetDiag Agent``（``schtasks /query`` 的退出码），
   在不在跑 = 任务在跑 **或** ``logs/agent.pid`` 里的进程还活着（单看任一个都会被
   单点骗），采到什么时候 = ``logs/history/YYYY-MM-DD.jsonl`` 的**最后一行**
   （不是 mtime —— 文件刚打开还没写完时 mtime 会撒谎）。
2. **同源**：``/api/monitor`` 的阈值与目标就是 ``config/agent.json``，也正是
   ``/api/agent/status`` 回的那一份。界面上的阈值虚线（history.js）与采集判事件
   用的阈值必须是**同一个数**，否则「图上是 88ms、判定按 120ms」永远说不清。
3. **不静默**：间隔不在 5/10/30/60 → 400 且文件不改；``schtasks`` 失败 → 把原文
   回给界面。全部用例注入假 runner，**绝不真的去建计划任务**。
"""
from __future__ import annotations

import datetime as dt
import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import agent_ctl  # noqa: E402  扁平导入 = server 里用的那一份
import history as history_mod  # noqa: E402
import logstore  # noqa: E402
import server  # noqa: E402
from core import config as config_mod  # noqa: E402  config 走包相对导入，只能这么导


class FakeSchTasks:
    """假的 ``schtasks``：记录每条命令，按子命令回预设结果。"""

    def __init__(self, *, query=(1, "ERROR: The system cannot find the file specified."),
                 create=(0, "SUCCESS: The scheduled task was successfully created."),
                 delete=(0, "SUCCESS: The scheduled task was successfully deleted.")):
        self.calls: list[list[str]] = []
        self.query = query
        self.create = create
        self.delete = delete

    def __call__(self, cmd):
        self.calls.append([str(part) for part in cmd])
        verb = cmd[1] if len(cmd) > 1 else ""
        if verb == "/query":
            return self.query
        if verb == "/create":
            return self.create
        if verb == "/delete":
            return self.delete
        return 1, "unexpected"

    @property
    def verbs(self) -> list[str]:
        return [call[1] for call in self.calls if len(call) > 1]

    def last(self, verb: str) -> list[str]:
        for call in reversed(self.calls):
            if len(call) > 1 and call[1] == verb:
                return call
        raise AssertionError(f"没有发过 {verb}：{self.calls}")


#: 计划任务查询的两种真实输出（英文系统 / 中文系统各一份，字段名不同、取值相同）。
TASK_RUNNING_EN = (
    "HostName:            DESKTOP-1\r\n"
    "TaskName:            \\NetDiag Agent\r\n"
    "Status:              Running\r\n"
    "Last Run Time:       2026/11/12 9:00:00\r\n"
)
TASK_RUNNING_ZH = (
    "主机名:             DESKTOP-1\r\n"
    "任务名:             \\NetDiag Agent\r\n"
    "状态:               正在运行\r\n"
)
TASK_READY_EN = (
    "HostName:            DESKTOP-1\r\n"
    "TaskName:            \\NetDiag Agent\r\n"
    "Status:              Ready\r\n"
)
TASK_DISABLED_EN = (
    "TaskName:            \\NetDiag Agent\r\n"
    "Status:              Disabled\r\n"
)
TASK_MISSING = (1, "ERROR: The system cannot find the file specified.")


class _AgentCase(unittest.TestCase):
    """把日志根与 agent 配置都指到临时目录；默认把 schtasks 换成假的。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.logs = self.tmp / "logs"
        self.hist = self.logs / "history"
        self.hist.mkdir(parents=True)
        self.cfg_file = self.tmp / "agent.json"
        self._env = mock.patch.dict(os.environ, {
            logstore.ENV_LOG_DIR: str(self.logs),
            "NETDIAG_AGENT_CONFIG": str(self.cfg_file),
        })
        self._env.start()
        self.fake = FakeSchTasks()
        self._runner = mock.patch.object(agent_ctl, "_default_runner", self.fake)
        self._runner.start()
        # 固定基准：2026-11-11 10:00:00 本地时间（比「现在」早一天，stale_s 为正）
        self.base = dt.datetime(2026, 11, 11, 10, 0, 0).timestamp()
        self.day = history_mod.iso(self.base)[:10]

    def tearDown(self) -> None:
        self._runner.stop()
        self._env.stop()
        logstore.close_streams()          # Windows 上不关句柄临时目录删不掉
        self._tmp.cleanup()

    # ---- 造数据

    def sample_epoch(self, epoch: float) -> dict:
        return {
            "t": history_mod.iso(epoch),
            "epoch": round(epoch, 3),
            "interval_s": 10,
            "gateway": {"rtt_ms": 5.0, "loss_pct": 0.0, "jitter_ms": 1.0,
                        "method": "icmp"},
            "dns": {"rtt_ms": 9.0, "loss_pct": 0.0, "jitter_ms": 2.0, "method": "icmp"},
            "targets": [{"key": "baidu", "rtt_ms": 20.0, "loss_pct": 0.0,
                         "jitter_ms": 3.0, "method": "icmp"}],
            "wlan": {"ssid": "Home-5G", "bssid": "aa:bb:cc:00:00:01",
                     "rssi_dbm": -55, "rx_mbps": 300, "tx_mbps": 200,
                     "band": "5G", "channel": 36},
        }

    def sample(self, offset: float) -> dict:
        """造一条样本：``offset`` 是相对基准时间的秒数。"""
        return self.sample_epoch(self.base + float(offset))

    def write_samples(self, records, name: str | None = None) -> Path:
        path = self.hist / (name or f"{self.day}.jsonl")
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return path

    def write_pid(self, pid: int) -> None:
        (self.logs / "agent.pid").write_text(str(pid), encoding="utf-8")

    def write_agent_config(self, body: dict) -> None:
        self.cfg_file.write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")

    def read_agent_config(self) -> dict:
        return json.loads(self.cfg_file.read_text(encoding="utf-8"))


# ====================================================================== 任务状态

class TaskQueryTest(_AgentCase):
    """``query_task``：只认 ``schtasks`` 的退出码与状态值关键词。"""

    def test_running_task_english_output(self):
        self.fake.query = (0, TASK_RUNNING_EN)
        out = agent_ctl.query_task()
        self.assertTrue(out["installed"])
        self.assertTrue(out["running"])
        self.assertEqual(out["state"], "running")

    def test_running_task_chinese_output(self):
        # 中文系统的字段名是「状态」，值里的「正在运行」才是稳定指纹
        self.fake.query = (0, TASK_RUNNING_ZH)
        out = agent_ctl.query_task()
        self.assertTrue(out["running"])
        self.assertEqual(out["state"], "running")

    def test_installed_but_idle_is_stopped(self):
        self.fake.query = (0, TASK_READY_EN)
        out = agent_ctl.query_task()
        self.assertTrue(out["installed"])
        self.assertFalse(out["running"])
        self.assertEqual(out["state"], "stopped")

    def test_disabled_task_is_error_not_running(self):
        self.fake.query = (0, TASK_DISABLED_EN)
        out = agent_ctl.query_task()
        self.assertTrue(out["installed"])
        self.assertFalse(out["running"])
        self.assertEqual(out["state"], "error")

    def test_missing_task_is_not_installed_and_says_nothing_extra(self):
        self.fake.query = TASK_MISSING
        out = agent_ctl.query_task()
        self.assertFalse(out["installed"])
        self.assertFalse(out["running"])
        self.assertEqual(out["state"], "stopped")
        # 没装不是错误：界面据此显示「安装」，不需要红字
        self.assertEqual(out["last_error"], "")

    def test_query_command_is_the_task_the_bats_create(self):
        self.fake.query = (0, TASK_READY_EN)
        agent_ctl.query_task()
        self.assertEqual(self.fake.last("/query"),
                         ["schtasks", "/query", "/tn", "NetDiag Agent", "/fo", "LIST", "/v"])

    def test_task_name_matches_the_bat_files(self):
        # 与 install-agent.bat / uninstall-agent.bat 里的任务名必须逐字一致，
        # 否则界面查的是另一个任务，永远「未安装」。
        self.assertEqual(agent_ctl.TASK_NAME, "NetDiag Agent")
        for name in ("install-agent.bat", "uninstall-agent.bat"):
            path = ROOT / name
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="replace")
                self.assertIn(agent_ctl.TASK_NAME, text, name)


# ====================================================================== 安装卸载

class InstallUninstallTest(_AgentCase):
    """``install`` / ``uninstall``：参数与 bat 一致，失败要回原文，卸载幂等。"""

    def test_install_command_matches_the_bat(self):
        out = agent_ctl.install()
        self.assertTrue(out["ok"])
        cmd = self.fake.last("/create")
        self.assertIn("/create", cmd)
        self.assertIn("NetDiag Agent", cmd)
        self.assertEqual(cmd[cmd.index("/sc") + 1], "onlogon")
        self.assertEqual(cmd[cmd.index("/delay") + 1], "0001:00")
        self.assertEqual(cmd[cmd.index("/rl") + 1], "limited")
        self.assertIn("/f", cmd)
        # 登录触发 + 延迟 1 分钟：不建「开机就起」的任务（那时网络还没就绪）
        self.assertIn("--daemon", " ".join(cmd))

    def test_install_failure_returns_the_original_text(self):
        self.fake.create = (1, "ERROR: Access is denied.")
        out = agent_ctl.install()
        self.assertFalse(out["ok"])
        self.assertIn("Access is denied", out["error"])

    def test_uninstall_deletes_the_task(self):
        out = agent_ctl.uninstall()
        self.assertTrue(out["ok"])
        self.assertEqual(self.fake.last("/delete")[:4],
                         ["schtasks", "/delete", "/tn", "NetDiag Agent"])
        self.assertIn("/f", self.fake.last("/delete"))

    def test_uninstall_missing_task_is_still_ok(self):
        # 连点两次「卸载」不该弹红字：任务不存在 = 目标状态已达成
        self.fake.delete = (1, "ERROR: The system cannot find the file specified.")
        out = agent_ctl.uninstall()
        self.assertTrue(out["ok"])
        self.assertEqual(out["error"], "")

    def test_uninstall_other_failure_is_reported(self):
        self.fake.delete = (1, "ERROR: Access is denied.")
        out = agent_ctl.uninstall()
        self.assertFalse(out["ok"])
        self.assertIn("Access is denied", out["error"])


# ====================================================================== 采样落盘

class LastSampleTest(_AgentCase):
    """``last_sample``：最后一行、只认样本分片、没样本就是没样本。"""

    def test_reads_the_last_line_not_the_first(self):
        self.write_samples([self.sample(0), self.sample(10), self.sample(20)])
        out = agent_ctl.last_sample(today=dt.date(2026, 11, 11))
        self.assertEqual(out["last_sample_at"], history_mod.iso(self.base + 20))
        self.assertEqual(out["last_sample_epoch"], round(self.base + 20, 3))
        self.assertEqual(out["history_file"], f"{self.day}.jsonl")
        self.assertEqual(out["samples_today"], 3)

    def test_file_bytes_is_the_real_size(self):
        path = self.write_samples([self.sample(0), self.sample(10)])
        self.assertEqual(agent_ctl.last_sample()["history_file_bytes"],
                         path.stat().st_size)

    def test_events_and_marks_are_not_samples(self):
        # events.jsonl / marks.jsonl 与样本混在同一目录：拿它们当「最近采样」
        # 会让设置页的时间跳到一个跟样本无关的时刻。
        self.write_samples([self.sample(0)])
        (self.hist / "events.jsonl").write_text(
            json.dumps({"t": "2026-11-11T23:59:59+08:00", "epoch": self.base + 50000}) + "\n",
            encoding="utf-8")
        (self.hist / "marks.jsonl").write_text(
            json.dumps({"t": "2026-11-11T23:59:59+08:00", "epoch": self.base + 60000}) + "\n",
            encoding="utf-8")
        (self.hist / f"{self.day}.jsonl.tmp").write_text("{}\n", encoding="utf-8")
        out = agent_ctl.last_sample()
        self.assertEqual(out["history_file"], f"{self.day}.jsonl")
        self.assertEqual(out["last_sample_at"], history_mod.iso(self.base))

    def test_rolled_shard_keeps_the_main_file_as_newest(self):
        """滚动后「最新的一片」是**没有序号**的那个 —— 序号最大的反而最老。

        采集侧滚动 = 把写满的 ``.jsonl`` 改名成 ``.1.jsonl``，再新建一个空的
        ``.jsonl`` 继续写。按文件名排序取最后一片会拿到 `.1`（最老的），
        于是设置页会把「最近采样时间」显示成半小时前。
        """
        base_file = self.write_samples([self.sample(0)], name=f"{self.day}.jsonl")
        rolled = base_file.with_name(f"{self.day}.1.jsonl")
        base_file.rename(rolled)
        self.write_samples([self.sample(60), self.sample(70)], name=f"{self.day}.jsonl")
        out = agent_ctl.last_sample(today=dt.date(2026, 11, 11))
        self.assertEqual(out["history_file"], f"{self.day}.jsonl")
        self.assertEqual(out["last_sample_epoch"], round(self.base + 70, 3))
        # 今天一共 3 条（两片加一起），不是「最新那片的 2 条」
        self.assertEqual(out["samples_today"], 3)

    def test_samples_today_counts_only_todays_shards(self):
        # 昨天一整天的样本不该被算进「今天采了多少」——那会让首页样本数与
        # 设置页状态对不上（一个按区间、一个按日期）。
        self.write_samples([self.sample(-86400)], name="2026-11-10.jsonl")
        self.write_samples([self.sample(0), self.sample(10)], name=f"{self.day}.jsonl")
        out = agent_ctl.last_sample(today=dt.date(2026, 11, 11))
        self.assertEqual(out["samples_today"], 2)

    def test_no_samples_is_empty_not_zero_seconds(self):
        out = agent_ctl.last_sample()
        self.assertEqual(out["last_sample_at"], "")
        self.assertIsNone(out["last_sample_epoch"])
        self.assertEqual(out["history_file"], "")
        self.assertEqual(out["history_file_bytes"], 0)
        self.assertEqual(out["samples_today"], 0)

    def test_half_written_line_is_skipped(self):
        path = self.hist / f"{self.day}.jsonl"
        path.write_text(json.dumps(self.sample(0), ensure_ascii=False) + "\n{\"t\": \"2026-11",
                        encoding="utf-8")
        out = agent_ctl.last_sample()
        self.assertEqual(out["last_sample_at"], history_mod.iso(self.base))


# ====================================================================== 汇总状态

class StatusTest(_AgentCase):
    """``status``：三源合一 + 与采集同源的配置。"""

    def test_task_running_means_running(self):
        self.fake.query = (0, TASK_RUNNING_EN)
        self.write_samples([self.sample(0)])
        out = agent_ctl.status(now=self.base + 30)
        self.assertTrue(out["installed"])
        self.assertTrue(out["running"])
        self.assertEqual(out["state"], "running")
        self.assertEqual(out["stale_s"], 30.0)

    def test_alive_pid_running_even_if_task_not_started(self):
        # 手动 `python core/agent.py --daemon` 起过：任务还是 Ready，进程却在跑
        self.fake.query = (0, TASK_READY_EN)
        self.write_pid(os.getpid())
        out = agent_ctl.status()
        self.assertTrue(out["running"])
        self.assertEqual(out["state"], "running")

    def test_dead_pid_does_not_fake_running(self):
        # 任务被手动停了、PID 文件还留着：绝不能因为「文件里有数字」就说在跑
        self.fake.query = (0, TASK_READY_EN)
        proc = subprocess.run([sys.executable, "-c", "import os;print(os.getpid())"],
                              capture_output=True, text=True)
        dead = int(proc.stdout.strip())
        self.assertFalse(agent_ctl._pid_alive(dead), "取到的 PID 还活着，用例失效")
        self.write_pid(dead)
        out = agent_ctl.status()
        self.assertFalse(out["running"])
        self.assertEqual(out["state"], "stopped")

    def test_no_samples_gives_stale_none(self):
        self.fake.query = (0, TASK_READY_EN)
        out = agent_ctl.status(now=self.base)
        self.assertIsNone(out["stale_s"])
        self.assertEqual(out["last_sample_at"], "")

    def test_interval_targets_thresholds_come_from_the_agent_config(self):
        # 设置页与采集共用 config/agent.json：界面回显的就是采集正在用的值
        self.write_agent_config({
            "interval_s": 30,
            "targets": [{"key": "baidu", "host": "www.baidu.com", "port": 443}],
            "thresholds": {"rtt_ms": 88, "jitter_ms": 25, "loss_pct": 3},
        })
        self.fake.query = (0, TASK_READY_EN)
        out = agent_ctl.status()
        self.assertEqual(out["interval_s"], 30)
        self.assertEqual(out["targets"], [{"key": "baidu", "host": "www.baidu.com",
                                           "port": 443}])
        self.assertEqual(out["thresholds"], {"rtt_ms": 88.0, "jitter_ms": 25.0,
                                             "loss_pct": 3.0})

    def test_schtasks_never_called_for_config_only(self):
        # 读配置不该顺手建任务：verbs 里只允许 query
        agent_ctl.status()
        self.assertEqual(set(self.fake.verbs), {"/query"})


# ====================================================================== 监测配置

class MonitorConfigTest(_AgentCase):
    """``monitor_config`` / ``save_monitor`` / ``save_config``：同源、可写、不静默。"""

    def test_defaults_are_the_agent_defaults(self):
        out = agent_ctl.monitor_config()
        self.assertEqual(out["thresholds"], {"rtt_ms": 120.0, "jitter_ms": 40.0,
                                             "loss_pct": 2.0})
        self.assertEqual(out["targets"], [])
        self.assertEqual(out["interval_s"], 10)

    def test_thresholds_written_once_are_read_back(self):
        agent_ctl.save_monitor({"thresholds": {"rtt_ms": 88}})
        self.assertEqual(agent_ctl.monitor_config()["thresholds"]["rtt_ms"], 88.0)
        # 写的是 config/agent.json 本身，不是第二份内存默认值
        self.assertEqual(self.read_agent_config()["thresholds"]["rtt_ms"], 88.0)

    def test_targets_are_normalized_and_capped(self):
        agent_ctl.save_monitor({"targets": [{"host": "a.com"}, {"host": "b.com"},
                                           {"host": "c.com"}, {"host": "d.com"}]})
        self.assertEqual(len(agent_ctl.monitor_config()["targets"]), 3)

    def test_interval_change_persists(self):
        out = agent_ctl.save_config({"interval_s": 60})
        self.assertTrue(out["ok"])
        self.assertEqual(out["interval_s"], 60)
        self.assertEqual(config_mod.load_agent()["interval_s"], 60)

    def test_illegal_interval_raises_instead_of_falling_back(self):
        agent_ctl.save_config({"interval_s": 30})
        with self.assertRaises(ValueError):
            agent_ctl.save_config({"interval_s": 7})
        # 失败不该改动已有值（「我改成 7 却还是 10」比报错更难查）
        self.assertEqual(config_mod.load_agent()["interval_s"], 30)

    def test_unknown_keys_are_dropped(self):
        agent_ctl.save_config({"interval_s": 30, "evil": {"x": 1}})
        stored = self.read_agent_config()
        self.assertNotIn("evil", stored)


# ====================================================================== 路由

class AgentHttpTest(_AgentCase):
    """真起 ``DiagServer``（端口 0），按 settings.js / history.js 的调法走一遍。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = server.DiagServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _json(self, path: str, *, body: dict | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            if body is None:
                conn.request("GET", path)
            else:
                conn.request("POST", path, body=json.dumps(body).encode("utf-8"),
                             headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, json.loads(raw.decode("utf-8"))
        finally:
            conn.close()

    # ---- /api/agent/status

    def test_status_route_exists_and_has_the_fields_settings_js_reads(self):
        self.fake.query = (0, TASK_RUNNING_EN)
        self.write_samples([self.sample(0)])
        status, data = self._json("/api/agent/status")
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"])
        # settings.js::paintAgent 只读这几个键，缺一个就会渲染成「未开启」
        for key in ("installed", "running", "state", "interval_s",
                    "last_sample_at", "last_error"):
            self.assertIn(key, data)
        self.assertTrue(data["installed"])
        self.assertTrue(data["running"])
        self.assertEqual(data["last_sample_at"], history_mod.iso(self.base))

    def test_status_is_not_a_404(self):
        # 这条是给「真机上全是未开启」兜底的回归：接口不存在时前端会写「未开启」
        status, _ = self._json("/api/agent/status")
        self.assertEqual(status, 200)

    def test_status_when_nothing_installed(self):
        status, data = self._json("/api/agent/status")
        self.assertEqual(status, 200)
        self.assertFalse(data["installed"])
        self.assertFalse(data["running"])
        self.assertEqual(data["last_sample_at"], "")
        # 没装 ≠ 出错：界面按 installed 渲染「安装」，不该走红字分支
        self.assertEqual(data["state"], "stopped")

    # ---- 安装 / 卸载

    def test_install_then_status_says_installed(self):
        self.fake.create = (0, "SUCCESS")
        status, data = self._json("/api/agent/install", body={})
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"])
        self.assertEqual(self.fake.verbs, ["/create", "/query"])
        # 装完再查：任务已在（fake 的 query 还是「找不到」，这里只验命令真的发了）
        self.assertIn("NetDiag Agent", self.fake.last("/create"))

    def test_install_failure_surfaces_the_reason(self):
        self.fake.create = (1, "ERROR: Access is denied.")
        status, data = self._json("/api/agent/install", body={})
        self.assertEqual(status, 500)
        self.assertFalse(data["ok"])
        self.assertIn("Access is denied", data["error"])

    def test_uninstall_route_is_idempotent(self):
        self.fake.delete = (1, "ERROR: The system cannot find the file specified.")
        status, data = self._json("/api/agent/uninstall", body={})
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])

    # ---- /api/agent/config

    def test_config_post_writes_interval_and_keeps_it(self):
        status, data = self._json("/api/agent/config", body={"interval_s": 30})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["interval_s"], 30)
        # 再读一遍：真的落盘了，不是只回显
        _, again = self._json("/api/monitor")
        self.assertEqual(again["interval_s"], 30)
        self.assertEqual(self.read_agent_config()["interval_s"], 30)

    def test_config_post_rejects_illegal_interval_with_400(self):
        status, data = self._json("/api/agent/config", body={"interval_s": 7})
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])
        self.assertIn("7", data["error"])
        self.assertEqual(config_mod.load_agent()["interval_s"], 10)

    # ---- /api/monitor

    def test_monitor_get_matches_agent_defaults(self):
        status, data = self._json("/api/monitor")
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"])
        self.assertEqual(data["thresholds"]["rtt_ms"], 120.0)
        self.assertIsInstance(data["targets"], list)

    def test_monitor_post_threshold_is_the_same_number_the_agent_uses(self):
        # 首页趋势图的阈值虚线读 /api/monitor，采集判事件读 config/agent.json：
        # 两处必须是同一个数，否则「图上 88ms、判定按 120ms」永远解释不清。
        status, data = self._json("/api/monitor", body={"thresholds": {"rtt_ms": 88}})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["thresholds"]["rtt_ms"], 88.0)
        self.assertEqual(config_mod.load_agent()["thresholds"]["rtt_ms"], 88.0)
        _, agent = self._json("/api/agent/status")
        self.assertEqual(agent["thresholds"]["rtt_ms"], 88.0)

    def test_monitor_post_targets_show_up_in_agent_status(self):
        status, data = self._json("/api/monitor",
                                  body={"targets": [{"host": "www.baidu.com", "port": 443}]})
        self.assertEqual(status, 200, data)
        self.assertEqual(len(data["targets"]), 1)
        self.assertEqual(data["targets"][0]["host"], "www.baidu.com")
        _, agent = self._json("/api/agent/status")
        self.assertEqual(agent["targets"], data["targets"])

    def test_monitor_post_ignores_unknown_keys(self):
        status, data = self._json("/api/monitor", body={"nonsense": [1, 2, 3]})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["thresholds"]["rtt_ms"], 120.0)

    # ---- 同一时刻：首页样本数 == 设置页状态

    def test_home_sample_count_equals_settings_samples_today(self):
        """交付证据的核心断言：同一秒里「首页样本数」与「设置页状态」对得上。

        首页读 ``/api/history``（区间内样本数），设置页读
        ``/api/agent/status.samples_today``（今天分片的总行数）。样本都落在今天
        同一区间里时两个数必须相等 —— 以前设置页没有接口，这个数只能是 0。
        """
        now = time.time()
        day = dt.date.today().isoformat()
        self.write_samples([self.sample_epoch(now - 30), self.sample_epoch(now - 20),
                            self.sample_epoch(now - 10)], name=f"{day}.jsonl")
        self.fake.query = (0, TASK_RUNNING_EN)
        _, hist = self._json(f"/api/history?from={int(now) - 60}"
                             f"&to={int(now) + 1}&bucket=1m")
        _, st = self._json("/api/agent/status")
        self.assertEqual(hist["samples"], 3)
        self.assertEqual(st["samples_today"], hist["samples"])
        self.assertEqual(st["last_sample_at"], history_mod.iso(now - 10))
        self.assertGreater(st["stale_s"], -1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
