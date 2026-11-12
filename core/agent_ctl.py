"""常驻采集的「装没装 / 在不在跑 / 最近采到什么时候」与监测配置的**唯一出口**。

**解决什么问题**
----------------
设置页要回答三个问题，而它们来自三个互不相干的地方：

* **装没装** —— Windows 计划任务 ``NetDiag Agent`` 是否存在（``install-agent.bat``
  建的就是这一个任务）；
* **在不在跑** —— 同一任务的运行状态 + ``logs/agent.pid`` 单实例锁里的 PID 是否
  还活着（计划任务显示「正在运行」但进程已被杀的情况真的会发生）；
* **采到什么时候** —— ``logs/history/YYYY-MM-DD.jsonl`` 的最后一行与文件大小。

以前这三件事只写在 ``install-agent.bat`` / ``uninstall-agent.bat`` 里，界面拿不到，
于是设置页整块显示「未开启」——那是在猜。本模块把「事实」集中到一个可注入外部
命令的实现里：计划任务查询/创建/删除全部走 ``schtasks``，测试注入假 runner 即可，
**不 mock 系统**。

**不做什么**
------------
* 不自己起进程、不写计划任务以外的东西（历史数据归 :mod:`core.agent`）；
* 不改采集行为：阈值与监测目标读写 ``config/agent.json``，与采集侧**同源**
  （``config.load_agent`` / ``save_agent``），否则界面改了阈值、采集还按旧值判；
* 非 Windows 平台一律返回「不支持」，绝不假装查到了。
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any, Callable, Mapping

#: 既能被 ``import agent_ctl``（server 的扁平导入）加载，也能被
#: ``from core import agent_ctl``（测试）加载。``config`` 内部走包相对导入
#: （``from .platform import paths``），所以仓库根必须在 ``sys.path`` 上；
#: ``logstore`` 则与 server / history 一样用扁平导入，保证是**同一份**日志根。
_CORE_DIR = pathlib.Path(__file__).resolve().parent
_ROOT_DIR = _CORE_DIR.parent
for _p in (str(_CORE_DIR), str(_ROOT_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import logstore  # noqa: E402  唯一日志根（跟随 NETDIAG_LOG_DIR）
from core import config as config_mod  # noqa: E402  配置读写的唯一实现

#: 计划任务名：与 ``install-agent.bat`` / ``uninstall-agent.bat`` 必须逐字一致。
TASK_NAME = "NetDiag Agent"

#: ``schtasks`` 单次调用的超时（秒）。查询卡住时不能让整个 HTTP 请求挂死。
SCHTASKS_TIMEOUT_S = 8.0

#: 计划任务状态里表示「正在运行」的片段：英文系统 ``Running``，中文系统 ``正在运行``。
RUNNING_MARKS = ("running", "正在运行")

#: 运行期的错误标记：任务被禁用 / 上次结果非 0 时置 ``state="error"``。
ERROR_MARKS = ("disabled", "已禁用", "could not", "失败")

#: 样本分片文件名：``YYYY-MM-DD.jsonl`` 或滚动后的 ``YYYY-MM-DD.N.jsonl``。
#: 与 :data:`core.agent.DAY_FILE_RE` 同构；这里重新声明是为了不 import 采集侧
#: （采集侧一导入就会拉起 wlan / probe 的重量级依赖）。
_SHARD_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.jsonl$")


# ---------------------------------------------------------------- 外部命令

def _run(cmd: list[str]) -> tuple[int, str]:
    """跑一个系统命令并返回 ``(退出码, 输出)``；任何异常都折成退出码 1。

    Args:
        cmd: 命令行参数列表（不经过 shell，避免引号与注入问题）。

    Returns:
        tuple[int, str]: 退出码与合并后的输出；命令不存在 / 超时都返回 ``1``
            与可读原因 —— 调用方按「没装上」处理，不抛异常。
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=SCHTASKS_TIMEOUT_S,
                              encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return 1, "schtasks 不可用"
    except subprocess.TimeoutExpired:
        return 1, "schtasks 超时"
    except OSError as exc:
        return 1, f"{type(exc).__name__}: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _default_runner(cmd: list[str]) -> tuple[int, str]:
    """默认 runner（真实执行）。测试注入同名函数替换它。"""
    return _run(cmd)


def _query_cmd() -> list[str]:
    """查询计划任务的命令（``/fo LIST /v`` 带状态与上次结果）。"""
    return ["schtasks", "/query", "/tn", TASK_NAME, "/fo", "LIST", "/v"]


def _status_from_text(text: str) -> tuple[bool, bool]:
    """从 ``schtasks`` 输出里判 ``(running, error)``。

    只认**状态值**里的关键词，不去解析本地化字段名（中文系统是「状态」、
    英文是 ``Status``）—— 字段名会随语言变，取值里的 ``Running`` / ``正在运行``
    却是稳定指纹。

    Args:
        text: 命令输出全文。

    Returns:
        tuple[bool, bool]: ``(是否正在运行, 是否处于错误/禁用状态)``。
    """
    low = text.lower()
    running = any(mark in low for mark in RUNNING_MARKS)
    error = any(mark in low for mark in ERROR_MARKS) and not running
    return running, error


def query_task(runner: Callable[[list[str]], tuple[int, str]] | None = None) -> dict:
    """查询计划任务是否安装、是否在跑。

    Args:
        runner: 命令执行器（测试注入）；省略时真的调 ``schtasks``。

    Returns:
        dict: ``{"installed": bool, "running": bool, "state": str,
        "last_error": str}``；``state`` ∈ ``running`` / ``stopped`` / ``error``。
        查询失败（命令不存在等）按「未安装」处理，原因写进 ``last_error``。
    """
    run = runner or _default_runner
    code, text = run(_query_cmd())
    if code != 0:
        return {"installed": False, "running": False, "state": "stopped",
                "last_error": ""}
    running, error = _status_from_text(text)
    state = "running" if running else ("error" if error else "stopped")
    return {"installed": True, "running": running, "state": state, "last_error": ""}


# ---------------------------------------------------------------- 安装 / 卸载

def _install_cmd() -> list[str]:
    """创建计划任务的命令（登录触发 + 1 分钟延迟，普通权限）。

    与 ``install-agent.bat`` 同一套参数：**一个**任务、登录后 1 分钟、``/rl limited``
    （不弹 UAC）。可执行文件优先用 ``NetDiag-agent.exe``，没有则回落到便携包
    ``tools/python/pythonw.exe core/agent.py``。
    """
    root = pathlib.Path(__file__).resolve().parents[1]
    exe = root / "NetDiag-agent.exe"
    if exe.is_file():
        target = f'"{exe}" --daemon'
    else:
        pythonw = root / "tools" / "python" / "pythonw.exe"
        target = f'"{pythonw}" "{root / "core" / "agent.py"}" --daemon'
    return ["schtasks", "/create", "/tn", TASK_NAME, "/sc", "onlogon",
            "/delay", "0001:00", "/tr", target, "/rl", "limited", "/f"]


def install(runner: Callable[[list[str]], tuple[int, str]] | None = None) -> dict:
    """安装常驻采集（创建计划任务）。

    Args:
        runner: 命令执行器（测试注入）。

    Returns:
        dict: ``{"ok": bool, "error": str}``；``ok=False`` 时 ``error`` 是
            ``schtasks`` 的原文片段（给人看的失败原因，不吞掉）。
    """
    code, text = (runner or _default_runner)(_install_cmd())
    if code == 0:
        return {"ok": True, "error": ""}
    return {"ok": False, "error": (text or "").strip()[:400] or "schtasks 创建任务失败"}


def uninstall(runner: Callable[[list[str]], tuple[int, str]] | None = None) -> dict:
    """卸载常驻采集（删除计划任务）。已运行中的 agent 会在注销后停止。

    Args:
        runner: 命令执行器（测试注入）。

    Returns:
        dict: ``{"ok": bool, "error": str}``；任务本来就不存在也算成功
            （幂等：界面连点两次不该报错）。
    """
    run = runner or _default_runner
    code, text = run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"])
    if code == 0:
        return {"ok": True, "error": ""}
    low = text.lower()
    if "cannot find" in low or "找不到" in text or "does not exist" in low:
        return {"ok": True, "error": ""}
    return {"ok": False, "error": (text or "").strip()[:400] or "schtasks 删除任务失败"}


# ---------------------------------------------------------------- 采样落盘

def _history_dir() -> pathlib.Path:
    """历史样本目录（跟随 ``NETDIAG_LOG_DIR``，与采集侧同一套约定）。"""
    return logstore.log_root() / "history"


def _sample_files(directory: pathlib.Path) -> list[pathlib.Path]:
    """列出**样本**分片（排除 ``events.jsonl`` / ``marks.jsonl`` 与滚动临时文件）。

    Returns:
        list[pathlib.Path]: 按「日期 + 滚动序号」自然排序。滚动分片是
            ``2026-11-11.1.jsonl``，按纯字符串比会排在 ``2026-11-11.jsonl``
            **前面**（``.`` < ``j``），所以这里显式取序号比。
    """
    if not directory.is_dir():
        return []
    out: list[tuple[str, int, pathlib.Path]] = []
    for path in directory.glob("*.jsonl"):
        match = _SHARD_RE.match(path.name)
        if not match:
            continue                      # events.jsonl / marks.jsonl / *.jsonl.tmp
        index = int(match.group(2)) if match.group(2) else 0
        out.append((match.group(1), index, path))
    out.sort(key=lambda item: (item[0], item[1]))
    return [path for _, _, path in out]


def _newest_file(files: list[pathlib.Path]) -> pathlib.Path:
    """正在被写的那一片：取 mtime 最大的分片。

    文件名序号**不能**用来挑最新：采集侧滚动时把满的 ``.jsonl`` 改名成 ``.1``，
    再新建一个空的 ``.jsonl`` 继续写 —— 序号最大的是**最老**的一片，最新的
    恰恰是没有序号的那个。mtime 才是「谁刚被写过」的真实指纹。
    """
    def key(path: pathlib.Path) -> tuple[float, str]:
        try:
            return (path.stat().st_mtime, path.name)
        except OSError:
            return (0.0, path.name)

    return max(files, key=key)


def last_sample(directory: pathlib.Path | None = None,
                today: dt.date | None = None) -> dict:
    """取「最近一次采样」的时间、文件与大小，以及今天一共采了多少条。

    读取**最后一行**而不是文件 mtime：文件可能刚被打开还没写完，mtime 给不出
    「最后一次真的采到数据」是什么时候（那是 P0-2 要回答的问题本身）。

    Args:
        directory: 覆盖历史目录（测试用）；省略时用 :func:`_history_dir`。
        today: 覆盖「今天」的判定（测试用，跨日边界不必等真到零点）。

    Returns:
        dict: ``{"last_sample_at": str, "last_sample_epoch": float|None,
        "history_file": str, "history_file_bytes": int, "samples_today": int}``。
        没有任何样本时时间与 epoch 为空串 / ``None``，文件为 ``""``、大小为 0
        —— **不写「0 秒前」**，没有样本就是没有样本。

        ``samples_today`` 是**今天所有分片**的有效行数（滚动后不止一个文件），
        与首页趋势图同一区间的样本数是同一个口径。
    """
    folder = pathlib.Path(directory) if directory is not None else _history_dir()
    files = _sample_files(folder)
    empty = {"last_sample_at": "", "last_sample_epoch": None,
             "history_file": "", "history_file_bytes": 0, "samples_today": 0}
    if not files:
        return empty
    newest = _newest_file(files)
    try:
        size = newest.stat().st_size
    except OSError:
        size = 0
    day = (today or dt.date.today()).isoformat()
    samples_today = 0
    for path in files:
        match = _SHARD_RE.match(path.name)
        if not match or match.group(1) != day:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        samples_today += sum(1 for line in text.splitlines() if line.strip())
    try:
        text = newest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    last_at = ""
    last_epoch = None
    for line in reversed(text.splitlines()):
        payload = line.strip()
        if not payload:
            continue
        try:
            record = json.loads(payload)
        except ValueError:
            continue
        if isinstance(record, Mapping):
            last_at = str(record.get("t") or "")
            try:
                last_epoch = float(record.get("epoch"))
            except (TypeError, ValueError):
                last_epoch = None
        break
    return {"last_sample_at": last_at, "last_sample_epoch": last_epoch,
            "history_file": newest.name, "history_file_bytes": size,
            "samples_today": samples_today}


# ---------------------------------------------------------------- 汇总状态

def _pid_alive(pid: int) -> bool:
    """进程是否还活着（Windows 用 ``OpenProcess``；其它平台用 ``kill 0``）。

    Args:
        pid: 进程号。

    Returns:
        bool: 存在且未退出为 True；权限不足 / 查询失败按「不在」处理。
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, int(pid))
            if not handle:
                return False
            try:
                code = ctypes.c_ulong(0)
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return False
                return code.value == 259        # STILL_ACTIVE
            finally:
                kernel32.CloseHandle(handle)
        except Exception:                        # noqa: BLE001  查不了就当没有
            return False
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def _agent_pid() -> int:
    """读 ``logs/agent.pid`` 里的 PID；没有 / 不可解析时返回 0。"""
    path = logstore.log_root() / "agent.pid"
    try:
        return int((path.read_text(encoding="utf-8").strip() or "0"))
    except (OSError, ValueError):
        return 0


def status(runner: Callable[[list[str]], tuple[int, str]] | None = None,
           directory: pathlib.Path | None = None,
           now: float | None = None,
           today: dt.date | None = None) -> dict:
    """设置页要的完整状态（界面字段与采集配置**同源**）。

    ``running`` 的口径是「**计划任务在跑** 或 **单实例锁里的 PID 还活着**」：
    只看任务状态会在「刚手动启动、还没被任务拉起」时误报未运行；只看 PID 会在
    「任务已装好、agent 刚崩、PID 残留」时误报运行 —— 两个都看才不会被单点骗。

    Args:
        runner: 命令执行器（测试注入）。
        directory: 覆盖历史目录（测试用）。
        now: 当前 epoch 秒（测试注入，供 ``stale_s`` 计算）。
        today: 覆盖「今天」的判定（测试注入，跨日边界不必等真到零点）。

    Returns:
        dict: ``{"installed", "running", "state", "last_error", "interval_s",
        "targets", "thresholds", "last_sample_at", "last_sample_epoch",
        "history_file", "history_file_bytes", "samples_today", "stale_s"}``。
        ``stale_s`` 是「距上次采样多少秒」；没有样本时为 ``None``（界面显示「未采到」）。
    """
    cfg = config_mod.load_agent()
    task = query_task(runner)
    pid = _agent_pid()
    pid_running = _pid_alive(pid)
    sample = last_sample(directory, today)
    stamp = time.time() if now is None else float(now)
    stale = (round(max(0.0, stamp - sample["last_sample_epoch"]), 1)
             if sample["last_sample_epoch"] else None)
    running = bool(task["running"] or pid_running)
    state = "running" if running else task["state"]
    return {
        "installed": bool(task["installed"]),
        "running": running,
        "state": state,
        "last_error": task["last_error"],
        "interval_s": int(cfg["interval_s"]),
        "targets": list(cfg["targets"]),
        "thresholds": dict(cfg["thresholds"]),
        "last_sample_at": sample["last_sample_at"],
        "last_sample_epoch": sample["last_sample_epoch"],
        "history_file": sample["history_file"],
        "history_file_bytes": sample["history_file_bytes"],
        "samples_today": sample["samples_today"],
        "stale_s": stale,
    }


# ---------------------------------------------------------------- 监测配置

def monitor_config() -> dict:
    """监测目标与告警阈值（``/api/monitor`` GET）。

    Returns:
        dict: ``{"targets": [{"key", "host", "port"?}], "thresholds":
        {"rtt_ms", "jitter_ms", "loss_pct"}}``。与采集侧同源，**不留第二份默认值**：
        界面上的阈值线就是 agent 判事件用的那条线。
    """
    cfg = config_mod.load_agent()
    return {"targets": list(cfg["targets"]),
            "thresholds": dict(cfg["thresholds"]),
            "interval_s": int(cfg["interval_s"])}


def save_monitor(patch: Mapping[str, Any] | None) -> dict:
    """写入监测目标 / 阈值（``/api/monitor`` POST）。

    只接受 ``targets`` 与 ``thresholds`` 两个键（其余忽略，避免前端写脏配置）。

    Args:
        patch: ``{"targets": [...]}`` 与/或 ``{"thresholds": {...}}``。

    Returns:
        dict: 与 :func:`monitor_config` 同构的**写回后**配置。

    Raises:
        OSError: 配置文件不可写。
    """
    body = dict(patch or {})
    keep = {key: body[key] for key in ("targets", "thresholds") if key in body}
    if not keep:
        return monitor_config()
    config_mod.save_agent(keep)
    return monitor_config()


def save_config(patch: Mapping[str, Any] | None) -> dict:
    """写入常驻采集自身的配置（``POST /api/agent/config``）。

    设置页只发 ``{"interval_s": 30}``，但同一个入口也允许带 ``targets`` /
    ``thresholds`` —— 与 ``/api/monitor`` 是**同一份** ``config/agent.json``，
    不存在「界面一个值、采集另一个值」。

    Args:
        patch: ``{"interval_s"?, "targets"?, "thresholds"?}``；其余键忽略。

    Returns:
        dict: ``{"ok": True, "interval_s", "targets", "thresholds"}``（写回后的值）。

    Raises:
        ValueError: 间隔不在 5/10/30/60 里（**不静默改成默认值**：
            「我改成 7 却还是 10」比报错更难查）。
        OSError: 配置文件不可写。
    """
    body = dict(patch or {})
    keep = {key: body[key] for key in ("interval_s", "targets", "thresholds")
            if key in body and body[key] is not None}
    if keep:
        config_mod.save_agent(keep)
    cfg = config_mod.load_agent()
    return {"ok": True,
            "interval_s": int(cfg["interval_s"]),
            "targets": list(cfg["targets"]),
            "thresholds": dict(cfg["thresholds"])}


__all__ = [
    "TASK_NAME",
    "query_task",
    "install",
    "uninstall",
    "last_sample",
    "status",
    "monitor_config",
    "save_monitor",
    "save_config",
]
