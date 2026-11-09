"""本地 Web UI + HTTP API（仅监听 127.0.0.1，不对外暴露）。

API:
  GET  /                    诊断界面
  GET  /api/status          任务状态 / 日志 / 结果
  GET  /api/interfaces      可用网卡
  GET  /api/captures        已有抓包文件
  GET  /api/reports         历史报告列表（报告与导出 → 历史报告）
  POST /api/scan            启动诊断 {mode,target,duration,interface,pcap,shadow}
  POST /api/elevate         非管理员一键请求 UAC 提权重启
  POST /api/upload?name=x   上传 pcap 后分析抓包文件
  GET  /api/report?path=    读取报告文件
  GET  /api/evidence        通用取证请求单（?full=0|1&fmt=md|txt，纯计算不写文件）
  GET  /api/doctor          环境自检
  GET  /api/preflight       启动器/首屏共用能力快照（与 /api/selfcheck 同源，无 first_run）
  GET  /api/selfcheck       首屏准备检查（六项只读环境检查 + 首次运行标记）
  POST /api/selfcheck/ack   记下「首次运行检查已看过」（写失败不阻塞界面）
  GET  /api/last-run        上次运行摘要（内存优先；进程重启后用 runs/ 历史兜底）
  GET  /api/last-run/result 上次运行的完整结果（只在内存里；没有时返回 404 JSON）
  POST /api/last-run/clear  清空内存里的上次结果（runs/ 历史记录保留）
  GET  /api/ai              AI 模型配置（Key 已脱敏）
  POST /api/ai              保存 AI 配置（局部更新，即时生效）
  POST /api/ai/test         用当前或临时参数测试连通性
  POST /api/ai/analyze      对最近一次诊断结果做 AI 解读
  GET/POST /api/probe       连通与速度测试（链路体检，分段测 DNS/TCP/TLS/首字节；
                            ``path`` 开关默认开 = 体检后补一次逐跳路径探测）
  POST /api/passive         启动通信观察（被动监听）{interface,duration,target,engine}
  GET  /api/passive         通信观察状态与结果
  POST /api/passive/stop    提前结束通信观察
  GET  /api/ping            存活探测（单实例判断）
  GET  /api/app             应用信息（版本/端口/PID/是否静默模式）
  POST /api/diagpack        导出脱敏诊断包（zip），返回 path / size / entries
  POST /api/quit            优雅退出（界面右上角「退出」调用）
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import threading
import time
import traceback
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# 请求体上限：JSON 配置类请求 8MB 足够；上传抓包单独放宽到 2GB
MAX_JSON_BODY = 8 << 20
MAX_UPLOAD = 2 << 30
MAX_CONCURRENT_PROBE = 3  # 体检会发真实报文，限制并发避免把目标打挂
#: ``/api/probe?path=true`` 的逐跳时间预算（秒）。
#: 体检是同步 HTTP 请求，不能等满 tracert 的 60s 硬上限（S6）：到点后停止发新探测，
#: 保留已拿到的跳并标 ``completed=False``，报告写「探测未完成…以上是已完成的跳」。
PROBE_PATH_BUDGET_S = 20.0

CORE = Path(__file__).resolve().parent
ROOT = CORE.parent
sys.path.insert(0, str(CORE))

import ai  # noqa: E402
# H1：浏览器打开权的唯一判定（browser_disabled）与唯一打开入口（open_browser）
# 都在 app 里；server 不再直接碰 webbrowser，避免第二套逻辑。
import app  # noqa: E402
import bootstrap  # noqa: E402
import conclusion  # noqa: E402
import copytext  # noqa: E402
import diagnose  # noqa: E402
import diagpack  # noqa: E402
import evidence  # noqa: E402
import logstore  # noqa: E402
import passive  # noqa: E402
import pathprobe  # noqa: E402
import probe  # noqa: E402
import report  # noqa: E402
import selfcheck  # noqa: E402
import tshark  # noqa: E402
import verdict  # noqa: E402
import version  # noqa: E402

UI_DIR = ROOT / "ui"
CAPTURES = ROOT / "captures"
REPORTS = ROOT / "reports"

#: 前端静态资源的 MIME 表（键是小写扩展名，值是完整的 ``Content-Type``）。
#:
#: 为什么不用 ``mimetypes.guess_type``：Windows 上它会读注册表，``.js`` 常被猜成
#: ``text/plain``；浏览器拿到 ``text/plain`` 的脚本会拒绝执行（控制台报
#: 「MIME type ... is not executable」），现场表现就是白屏。显式表不受宿主环境影响。
STATIC_MIME = {
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}


def static_asset(path: str):
    """把请求路径解析成 ``ui/`` 下可安全读取的白名单文件。

    Args:
        path: ``urlparse`` 得到的原始 path（可能含 ``%2e`` / ``%2f`` 之类编码）。

    Returns:
        Path | None: 通过全部检查的文件；不合法一律返回 ``None``，由调用方回 404
        —— 刻意不回 403，以免告诉探测者「这个路径存在」。

        Note:
        四道关，缺一不可：

        1. 先 ``unquote`` 解码**再**判断 —— 不先解码就挡不住 ``%2e%2e``；
        2. 逐段拒绝 ``..`` / ``.`` / 反斜杠 / NUL。反斜杠在 POSIX 语义里不是分隔符，
           但在 Windows 上是，``\\..\\`` 会变成真实穿越；
        3. 白名单：
           * v1：只认 ``/app.css`` 与 ``/js/<名字>.js``，``ui/`` 下其余文件不开放；
           * v2（ui/v2/**）：段数 2 或 3；``parts[0] == "v2"``；3 段时
             ``parts[1]`` 必须是 ``css`` / ``js`` / ``img`` 之一。扩展名必须已在
             :data:`STATIC_MIME`（不新增扩展名）。
        4. ``resolve()`` 后 ``relative_to(UI_DIR)`` 二次校验，挡符号链接与
           「解析后跑出 ui/」的边界情况。

        不做内容缓存：本地环回上每次只是几 KB 读盘，而开发期改完样式刷新即见，
        比多一层失效逻辑更省心。
    """
    raw = urllib.parse.unquote(path or "")
    if "\x00" in raw or "\\" in raw or not raw.startswith("/"):
        return None
    parts = [seg for seg in raw.split("/") if seg]
    if not parts or any(seg in (".", "..") for seg in parts):
        return None
    if parts == ["app.css"]:
        candidate = UI_DIR / "app.css"
    elif len(parts) == 2 and parts[0] == "js" and parts[1].endswith(".js"):
        candidate = UI_DIR / "js" / parts[1]
    elif 2 <= len(parts) <= 3 and parts[0] == "v2":
        # v2 子目录：/v2/index.html 由入口路由（_route_get）单独处理，这里只管
        # 静态子资源。段数 2 时是 /v2/<file>（img/favicon 等），3 时是
        # /v2/<css|js|img>/<file>。
        if len(parts) == 3 and parts[1] not in ("css", "js", "img"):
            return None
        candidate = UI_DIR / "v2" / Path(*parts[1:])
    else:
        return None
    try:
        resolved = candidate.resolve()
        resolved.relative_to(UI_DIR.resolve())
    except (OSError, ValueError):
        return None
    # 扩展名必须已在 STATIC_MIME：v2 的 index.html / secret.txt 这类非静态
    # 子资源，宁可在这里返回 None（404），也不交给调用方猜一个 MIME 出去。
    if resolved.suffix.lower() not in STATIC_MIME:
        return None
    return resolved if resolved.is_file() else None

#: 入口版本 → 入口 HTML 的相对路径（相对 ``UI_DIR``）。
#: 用映射而非 if/elif 硬编码，是为了以后加 v3 只改这里一处。
UI_ENTRY = {
    "v1": "index.html",
    "v2": "v2/index.html",
}

#: 版本选择的 Cookie 名（?ui= 命中时回写，之后无参访问仍保持同版本）。
UI_COOKIE = "nd_ui"

#: 版本选择的 config 文件（一键回滚脚本写它；缺省时回内置 v1）。
UI_VERSION_CONFIG = ROOT / "config" / "ui-version.json"


def ui_entry(parsed, cookie: str | None) -> str:
    """按优先级决定本次请求用哪个入口版本（返回 ``"v1"`` 或 ``"v2"``）。

    优先级（高 → 低）：

    1. ``?ui=v1|v2`` 查询参数；
    2. Cookie ``nd_ui``（上次 ``?ui=`` 回写的选择）；
    3. ``config/ui-version.json`` 的 ``.default``；
    4. 内置 ``"v1"``。

    这是纯函数：只做字符串判断，不碰文件、不抛异常、不读全局 —— 方便单测。

    Args:
        parsed: ``urllib.parse.urlparse(self.path)`` 的返回值。
        cookie: ``Cookie`` 请求头里 ``nd_ui`` 的值（已由调用方解析，可为 ``None``）。

    Returns:
        str: ``"v1"`` 或 ``"v2"``；任何非法值都回落，绝不返回白名单外的东西。
    """
    q = urllib.parse.parse_qs(parsed.query)
    want = (q.get("ui") or [None])[0]
    if want in ("v1", "v2"):
        return want
    if cookie in ("v1", "v2"):
        return cookie
    try:
        if UI_VERSION_CONFIG.is_file():
            cfg = json.loads(UI_VERSION_CONFIG.read_text(encoding="utf-8"))
            default = cfg.get("default")
            if default in ("v1", "v2"):
                return default
    except (OSError, ValueError):
        pass
    return "v1"


def _parse_ui_cookie(headers) -> str | None:
    """从请求头里取 ``nd_ui`` 的值（不存在/非法一律 ``None``）。

    Args:
        headers: ``BaseHTTPRequestHandler.headers``（``email.message`` 风格）。

    Returns:
        str | None: 白名单内的 ``"v1"`` / ``"v2"``，否则 ``None``。
    """
    raw = headers.get("Cookie") or ""
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        if k.strip() == UI_COOKIE and v.strip() in ("v1", "v2"):
            return v.strip()
    return None


LOCK = threading.Lock()
JOB = {
    "state": "idle",      # idle | running | done | error
    "mode": "",
    "target": "",
    "duration": 0,        # 用户请求的抓包秒数（分析抓包文件为 0，进度条据此算倒计时）
    "started_at": 0.0,
    "finished_at": 0.0,
    "logs": [],
    "result": None,
    "error": "",
    "error_code": "",     # 稳定错误码（E_NO_NPCAP / E_NO_ADMIN / E_BAD_PCAP ...）
    "error_detail": None,  # 失败时的可诊断性字段（stage / pcap_path / pcap_exists / ...）
}

# 通信观察（被动监听）单独一个任务槽，避免和诊断任务互相覆盖
PJOB = {
    "state": "idle",      # idle | running | done | error
    "duration": 0,
    "started_at": 0.0,
    "finished_at": 0.0,
    "result": None,
    "error": "",
    "engine": "auto",
    "stop": False,
}
ENGINE_CACHE: dict = {}
DOCTOR_CACHE: dict = {"at": 0.0, "data": None}
PROBE_SEM = threading.Semaphore(MAX_CONCURRENT_PROBE)

# ---- 上次结果（G5）：页面刷新/重开时明确告诉用户「这是上次的结果」 ----
#: 内存只保留最近一次分析：新运行覆盖，进程退出即失（不落盘、不联网）。
LAST_RUN = {"summary": None, "result": None, "cleared_at": 0.0}
#: 完整结果的内存上限（**序列化后的 UTF-8 字节数**，不是字符数）；超过时只留摘要
#: （``full_result=False``），避免大结果长期占内存。
LAST_RUN_MAX_BYTES = 8 << 20
#: runs/*.json 兜底只认诊断类记录（probe / passive 没有 render() 可恢复的完整结果）。
LAST_RUN_FALLBACK_MODES = ("live", "scan", "offline")

# ---- 应用生命周期：单实例、优雅退出、空闲自动释放 ----
APP_NAME = "USBNetDiag"


def _read_version(root: Path = ROOT) -> str:
    """读产品版本号（薄包装，实现见 :func:`version.read_version`）。

    ``APP_VERSION`` 与既有用例都通过它取值，所以保留入口；真正读文件、
    剥 UTF-8 BOM 的逻辑只在 :mod:`core.version` 一处（L 轮补丁）。

    Args:
        root: 仓库根目录，默认即 ``core/`` 的上一级。

    Returns:
        str: 形如 ``0.2.0`` 的版本号；读不到时是 ``0.0.0``。
    """
    return version.read_version(root)


#: 产品版本的唯一来源是仓库根 ``VERSION``（启动横幅 / ``/api/ping`` / ``/api/app`` 共用）。
APP_VERSION = _read_version()
QUIT = threading.Event()            # 置位后主循环退出
SERVER: dict = {"httpd": None}      # 当前监听实例，供 /api/quit 关停
LAST_HIT = {"t": time.time()}       # 最后一次有人访问界面的时间
PID_FILE = ROOT / "logs" / "netdiag.pid"


def touch() -> None:
    """记录一次界面访问，空闲计时据此重置。"""
    LAST_HIT["t"] = time.time()


def request_quit(reason: str = "") -> None:
    """请求服务退出：先让 HTTP 响应发出去，再关监听。

    Args:
        reason: 退出原因，会写进运行日志（便于事后回答「它怎么就没了」）。
            留空表示人工触发。

    Returns:
        None: 不阻塞调用方。真正关监听在后台线程里做，延迟 0.3 秒 ——
            否则 200 响应还没写回浏览器端口就被关掉，前端只会看到「连接被重置」。
    """
    if QUIT.is_set():
        return
    if reason:
        log(reason)
    QUIT.set()

    def _close() -> None:
        time.sleep(0.3)  # 留出时间把 200 响应写回浏览器
        srv = SERVER.get("httpd")
        if srv is not None:
            try:
                srv.shutdown()
            except Exception:  # noqa: BLE001
                pass

    threading.Thread(target=_close, daemon=True).start()


def _idle_watchdog(minutes: int) -> None:
    """静默模式下，浏览器关掉后没人访问就自动退出，避免残留后台进程。"""
    while not QUIT.wait(20):
        if JOB["state"] == "running" or PJOB["state"] == "running":
            LAST_HIT["t"] = time.time()
            continue
        if time.time() - LAST_HIT["t"] > minutes * 60:
            request_quit(f"已 {minutes} 分钟无人访问界面，自动退出并释放端口。")
            return


def _write_pid() -> None:
    try:
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    except OSError:
        pass


def cleanup_pid() -> None:
    """只删自己的 PID 文件，避免误删新实例的。"""
    try:
        if PID_FILE.is_file() and PID_FILE.read_text(encoding="utf-8").strip() == str(os.getpid()):
            PID_FILE.unlink()
    except OSError:
        pass



class BodyTooLarge(Exception):
    """请求体超过上限；携带 status 供路由层返回 413。"""

    status = 413


def _to_int(v, default, lo: int, hi: int) -> int | None:
    """把查询串/JSON 里的值安全转成限定范围的整数，非法值回落到 default。"""
    if v in (None, "", 0, "0"):
        return default
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return default
    return max(lo, min(n, hi))


def _to_float(v, default: float, lo: float, hi: float) -> float:
    try:
        n = float(str(v).strip())
    except (TypeError, ValueError):
        return default
    if n != n or n in (float("inf"), float("-inf")):  # NaN / Inf
        return default
    return max(lo, min(n, hi))


_ATTEMPT_RE = re.compile(r"第\s*(\d+)\s*/\s*(\d+)\s*块")


def _job_phase(state: str, logs: list[dict]) -> str:
    """从任务状态与日志关键字推断当前阶段（给进度条显示）。

    日志是采集层写的唯一事实来源；与其在抓包线程里到处埋状态，不如由查询接口
    统一解析 —— 这样老的 ``/api/status`` 字段完全不变，只做加法。

    Args:
        state: :data:`JOB` 的 ``state``。
        logs: :data:`JOB` 的日志列表（每项含 ``t`` / ``m``）。

    Returns:
        str: ``空闲`` / ``准备中`` / ``探测网卡`` / ``抓包中`` / ``分析中`` /
            ``完成`` / ``失败`` 之一。
    """
    if state == "idle":
        return "空闲"
    if state == "done":
        return "完成"
    if state == "error":
        return "失败"
    messages = [str(row.get("m") or "") for row in (logs or [])]
    if any("报告已生成" in m for m in messages):
        return "完成"
    if any("开始分析报文" in m or "连通与速度测试" in m for m in messages):
        return "分析中"
    if any("开始抓包" in m for m in messages):
        return "抓包中"
    if any("探测网卡" in m for m in messages):
        return "探测网卡"
    return "准备中"


def _job_attempt(logs: list[dict]) -> tuple[int, int]:
    """从「第 2/3 块」日志里取最近一次换卡重试的进度。

    Args:
        logs: :data:`JOB` 的日志列表。

    Returns:
        tuple[int, int]: ``(当前块, 总块数)``；没有换卡日志时返回 ``(0, 0)``。
    """
    attempt = total = 0
    for row in logs or []:
        match = _ATTEMPT_RE.search(str(row.get("m") or ""))
        if match:
            attempt, total = int(match.group(1)), int(match.group(2))
    return attempt, total


def doctor_cached(ttl: int = 60) -> dict:
    """环境自检（带缓存）。

    自检要跑 ``tshark -v`` / ``tshark -D``，一次 1~2 秒；首屏每次刷新都跑会让界面明显卡顿，
    所以缓存 :data:`ttl` 秒。用户装完 Npcap 想立刻看到变化时，刷一次缓存过期即可。

    Args:
        ttl: 缓存有效期（秒）。传 0 表示强制重跑。

    Returns:
        dict: ``bootstrap.check(verbose=False)`` 的结果，键含
            ``ok`` / ``tshark`` / ``npcap`` / ``admin`` / ``python`` / ``interfaces`` 等。
    """
    now = time.time()
    if DOCTOR_CACHE["data"] and now - DOCTOR_CACHE["at"] < ttl:
        return DOCTOR_CACHE["data"]
    data = bootstrap.check(verbose=False)
    DOCTOR_CACHE.update({"at": now, "data": data})
    return data


def _probe_guarded(target: str, port, count, timeout, proto,
                   path: bool = False) -> dict:
    """体检会向目标发真实报文，加并发闸门，避免被误用成压测工具。

    「逐跳路径」开关打开且体检成功时，在本函数里补一次 MTR（``pathprobe.run``），
    把结果附到 ``path_profile``。路径探测失败/超时**只降级**：返回的体检结论与
    记录一条 run 的行为都不变，最多少一个 ``path_profile`` 键。

    Args:
        target: 目标主机/URL。
        port: 端口；``None`` 表示按协议画像自动选。
        count: 探测次数。
        timeout: 单次超时秒数；假值回落到 3.0。
        proto: 强制协议（``http``/``tls``/``smb``/...），``None`` 表示自动识别。
        path: 是否在体检之后做逐跳路径探测（默认 ``False``；HTTP 路由缺省传
            ``True``，与「旧载荷默认开」的兼容口径一致）。

    Returns:
        dict: ``probe.run()`` 的结果（``path=True`` 且拿到逐跳数据时多一个
            ``path_profile`` 与 ``ui_copy.path``）；并发超限时
            ``{"ok": False, "error": ...}``（不记 run，因为这次体检根本没执行）。
    """
    if not PROBE_SEM.acquire(blocking=False):
        return {"ok": False,
                "error": f"同时进行的体检已达 {MAX_CONCURRENT_PROBE} 个，请等待前一个结束"}
    started = time.monotonic()
    params = {"target": (target or "")[:300], "port": port or "",
              "count": count, "proto": proto or "", "path": bool(path)}
    try:
        try:
            res = probe.run(target, port=port, count=count,
                            timeout=timeout if timeout else 3.0, proto=proto)
        finally:
            PROBE_SEM.release()
    except Exception:
        _record_ui_run("probe", params, started, {"ok": False})
        raise
    if path and isinstance(res, dict) and res.get("ok"):
        profile = _probe_path_profile(target, port)
        if profile is not None:
            res = dict(res)
            res["path_profile"] = profile
            res["ui_copy"] = {"path": _path_ui_copy()}
    _record_ui_run("probe", params, started, res)
    return res


def _probe_path_profile(target: str, port,
                        budget_s: float = PROBE_PATH_BUDGET_S) -> dict | None:
    """体检成功后补跑一次 MTR，返回 ``path_profile``（失败只降级为 ``None``）。

    同步 HTTP 请求必须有自己的时间预算（S6）：到 ``budget_s`` 后通过
    ``should_stop`` 让 ``pathprobe.run`` 停止发新探测（tracert 会在 100ms 内 kill），
    保留已完成的跳并让结果带 ``completed=False``；**不抛异常、不拖死请求**。

    Args:
        target: 目标（域名或 IP；域名由 ``pathprobe.run`` 自己解析）。
        port: 体检用的端口；``None`` 时路径探测按 443/80 判断可达性。
        budget_s: 本次逐跳探测的时间预算（秒）；默认
            :data:`PROBE_PATH_BUDGET_S`，小于 1 秒按 1 秒处理。

    Returns:
        dict | None: 有逐跳数据时是 ``PathProbeResult.to_dict()``（另加
            ``excluded_icmp=0`` —— 体检不抓包，没有可排除的包）；解析失败 /
            探测不可用 / 零跳时返回 ``None``（界面上不显示该区块）。
    """
    try:
        budget = max(1.0, float(budget_s))
    except (TypeError, ValueError):
        budget = PROBE_PATH_BUDGET_S
    deadline = time.monotonic() + budget

    def _budget_exhausted() -> bool:
        """到点即停：pathprobe 每批发包前 / tracert 每 100ms 检查一次。"""
        return time.monotonic() >= deadline

    try:
        result = pathprobe.run(target, port=port, logger=log,
                               should_stop=_budget_exhausted)
    except Exception as exc:                       # noqa: BLE001  路径探测失败只降级
        log(f"[提示] 逐跳路径探测不可用（不影响体检结论）："
            f"{type(exc).__name__}: {exc}")
        return None
    if not result.hops:
        log(f"[提示] 逐跳路径探测没有可用数据：{result.error or '零跳'}")
        return None
    if result.error:
        log(f"[提示] 逐跳路径探测部分降级（结果仍可用）：{result.error}")
    if not result.completed:
        log(f"[提示] 逐跳路径探测未跑完（时间预算 {budget:g}s 或取消），"
            f"保留已完成的 {len(result.hops)} 跳（结果标记未完成）")
    profile = result.to_dict()
    profile["excluded_icmp"] = 0
    return profile


def log(msg: str) -> None:
    """写一条运行日志：同时进内存环形缓冲与磁盘日志。

    Args:
        msg: 日志正文。不需要自己带时间戳，这里会补 ``HH:MM:SS``。

    Returns:
        None: 内存里最多保留 400 条（超出丢最早的 100 条），界面靠轮询取增量；
            磁盘那份委托给 :func:`logstore.diag_log`（``logs/diag-YYYYMMDD.log``），
            供事后排障。
    """
    with LOCK:
        JOB["logs"].append({"t": time.strftime("%H:%M:%S"), "m": str(msg)})
        if len(JOB["logs"]) > 400:
            del JOB["logs"][:100]
    logstore.diag_log(str(msg))


def _record_ui_run(mode: str, params: dict, started: float, result: dict) -> None:
    """记录一次 UI 触发的通信观察 / 连通与速度测试（诊断任务由 ``diagnose.run_scan`` 自记）。

    Args:
        mode: ``passive`` 或 ``probe``。
        params: 本次参数（只留模式/目标/时长等，不写绝对路径）。
        started: ``time.monotonic()`` 起点。
        result: ``passive.run()`` / ``probe.run()`` 的结果。

    Returns:
        None: 写盘失败静默忽略（日志不影响体检/监听）。
    """
    try:
        result = result or {}
        ok = bool(result.get("ok"))
        logstore.record_run({
            "mode": mode,
            "params": dict(params or {}),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "level": str(result.get("level") or ""),
            "critical": 0,
            "warning": 0,
            "sufficiency_ok": ok,
            "error_code": "" if ok else "E_INTERNAL",
            "tshark_version": tshark.version(),
            "ok": ok,
        })
    except Exception:  # noqa: BLE001
        pass


def _probe_ui_copy() -> dict:
    """影子探测结果块的界面文案（唯一来源：``core/copy/zh-CN.json`` 的 ``probe``）。

    只把这一节随 ``/api/status`` 的结果下发，前端不另存一份中文文案：
    ``ui/index.html`` 的行为「搬文案」而不是「写文案」。文案表损坏时返回空表，
    前端在缺文案时不渲染该区块（不影响主结果）。

    Returns:
        dict: ``probe`` section 的字符串映射；读取失败时返回 ``{}``。
    """
    try:
        return copytext.section(copytext.load_table(), "probe")
    except Exception:                              # noqa: BLE001  文案缺失不拖垮状态接口
        return {}


def _path_ui_copy() -> dict:
    """路径剖面结果块的界面文案（唯一来源：``core/copy/zh-CN.json`` 的 ``path``）。

    与 :func:`_probe_ui_copy` 同一套做法：中文只在 copy 表里，页面只负责排版。
    文案表损坏时返回空表，前端在缺文案时不渲染该区块。

    Returns:
        dict: ``path`` section 的字符串映射；读取失败时返回 ``{}``。
    """
    try:
        return copytext.section(copytext.load_table(), "path")
    except Exception:                              # noqa: BLE001  文案缺失不拖垮状态接口
        return {}


def _evidence_ui_copy() -> dict:
    """取证请求单结果块的界面文案（唯一来源：``core/copy/zh-CN.json`` 的
    ``evidence_checklist``）。

    清单正文来自 ``core/copy/evidence_checklist.json``（后端算好随结果下发），
    页面只负责排版与按钮，不另存一份中文标签。

    Returns:
        dict: ``evidence_checklist`` section 的字符串映射；读取失败时返回 ``{}``。
    """
    try:
        return copytext.section(copytext.load_table(), "evidence_checklist")
    except Exception:                              # noqa: BLE001  文案缺失不拖垮状态接口
        return {}


def evidence_payload(result: dict | None, full: bool = False, fmt: str = "md") -> dict:
    """生成 ``/api/evidence`` 的响应体（纯计算，不写文件、不联网）。

    ``full=True`` 是**通用空白版**：不依赖 ``JOB["result"]``，还没有诊断结果时
    也返回全 7 维（``result=None`` 等价于空结果）。``full=False`` 才要求最近一次
    诊断结果，并按结论挑相关维度。

    为避免 ``dimensions_for`` 在缺 ``verdict`` 时回退去 ``verdict.build``（会读
    copy 表），这里先把判定算好再显式传给 ``build_checklist``；已有
    ``result["verdict"]`` 时直接复用，不重复计算。

    Args:
        result: 最近一次诊断结果（``JOB["result"]``）；``None`` 表示还没有结果。
        full: ``True`` 输出覆盖 7 维的通用空白版；``False`` 按本次结论取相关维度。
        fmt: ``"md"``（报告内区块同款 Markdown）或 ``"txt"``（纯文本，供复制）。
            其它值由路由层拒绝；这里按 ``md`` 兜底。

    Returns:
        dict: 成功 ``{"ok": True, "fmt", "full", "dimensions": [维度机器码],
        "content": str}``；``full=False`` 且没有结果 / 本次不需要取证时
        ``{"ok": False, "error": "..."}``（错误可直接展示给用户）。
    """
    has_result = isinstance(result, dict) and bool(result)
    if not has_result and not full:
        return {"ok": False, "error": "还没有可用的诊断结果，请先完成一次诊断"}
    payload_result = result if has_result else {}
    if full:
        # 通用空白版不需要结论；只借用已有的判定做展示，不重新计算。
        stored = payload_result.get("verdict")
        verdict_obj = stored if isinstance(stored, dict) else {}
        checklist = evidence.build_checklist(payload_result, full=True,
                                             verdict=verdict_obj)
    else:
        stored = payload_result.get("verdict")
        verdict_obj = stored if isinstance(stored, dict) else verdict.build(payload_result)
        checklist = evidence.build_checklist(payload_result, full=False,
                                             verdict=verdict_obj)
    dims = [dim.get("key", "") for dim in checklist.get("dimensions") or []]
    content = (evidence.render_checklist_text(checklist) if fmt == "txt"
               else evidence.render_checklist_markdown(checklist))
    if not content:
        return {"ok": False,
                "error": "本次结论不需要外部取证（可用 full=1 获取通用空白版）"}
    return {"ok": True, "fmt": "txt" if fmt == "txt" else "md",
            "full": bool(full), "dimensions": dims, "content": content}



def _attach_probe_ui_copy(result: dict | None) -> dict | None:
    """给带探针基线 / 路径剖面 / 取证清单的结果补界面文案（不原地改 JOB 里的结果）。

    取证清单（``evidence_checklist``）是**只进状态响应**的加法字段：它由
    最近一次结果现算，不写进报告 JSON，所以 20 产物快照不受影响。

    Args:
        result: ``JOB["result"]``；三个区块都没有时原样返回。

    Returns:
        dict | None: 有 ``meta.probe_baseline`` / ``meta.path_profile`` 或本次
            需要外部取证时返回浅拷贝 + ``ui_copy``（键 ``probe`` / ``path`` /
            ``evidence``），需要取证时另加 ``evidence_checklist``；否则返回原对象
            （离线路径 / 正常结果零改动）。
    """
    if not isinstance(result, dict):
        return result
    meta = result.get("meta") or {}
    payload = {}
    if isinstance(meta.get("probe_baseline"), dict):
        payload["probe"] = _probe_ui_copy()
    if isinstance(meta.get("path_profile"), dict):
        payload["path"] = _path_ui_copy()
    stored_verdict = result.get("verdict")
    checklist = evidence.build_checklist(
        result, verdict=stored_verdict if isinstance(stored_verdict, dict) else None)
    if checklist.get("dimensions"):
        payload["evidence"] = _evidence_ui_copy()
    if not payload:
        return result
    enriched = dict(result)
    if checklist.get("dimensions"):
        enriched["evidence_checklist"] = checklist
    enriched["ui_copy"] = payload
    return enriched


def _conclusion_ui_copy() -> dict:
    """结论卡片的界面文案（唯一来源：``core/copy/zh-CN.json`` 的 ``conclusion``）。

    页面上的标题、按钮、旧数据降级文案都从这里取；前端不另存一份中文。
    文案表损坏时返回空表，前端使用内置最小回退（仍然不会空白）。

    Returns:
        dict: ``conclusion`` section 的字符串/列表映射；读取失败时返回 ``{}``。
    """
    try:
        return copytext.section(copytext.load_table(), "conclusion")
    except Exception:                              # noqa: BLE001  文案缺失不拖垮状态接口
        return {}


def _conclusion_verdict(result: dict) -> dict:
    """为结论渲染挑一个可用的判定对象（旧/降级结果没有 ``verdict`` 时补标题）。

    正常结果直接用 ``result["verdict"]``；0 包降级结果没有 verdict，但仍有
    ``headline`` / ``card_title``。此时只补一个最小 ``{"headline": ...}``，让结论句
    不至于变成「标题缺失」，置信度仍由 :func:`core.conclusion.build_conclusion`
    按「无有效样本」自动降为低 —— **不伪造 level / points**。

    Args:
        result: 诊断结果字典。

    Returns:
        dict: 判定对象；两处都没有标题时返回 ``{}``（渲染器会显式降级为「未知」）。
    """
    stored = result.get("verdict")
    if isinstance(stored, dict) and stored:
        return stored
    for key in ("headline", "card_title", "plain"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return {"headline": value.strip()}
    return {}


def conclusion_report_id(result: dict) -> str:
    """生成给人看的「报告标识」（复制给协作方 / 导出时用于追溯）。

    优先用真实落盘文件名（``.md`` / ``.json``），退化为抓包文件名 + 生成时间；
    都没有时返回「本次诊断（未落盘报告）」。只在状态响应/导出里出现，不写进报告。

    Args:
        result: 诊断结果字典（读 ``report`` / ``meta``）。

    Returns:
        str: 非空标识，如 ``faults_demo.md / faults_demo.json · 2026-11-07 21:49:03``。
    """
    report_files = result.get("report")
    report_files = report_files if isinstance(report_files, dict) else {}
    names = []
    for key in ("markdown", "json"):
        raw = report_files.get(key)
        if raw:
            name = Path(str(raw)).name
            if name and name not in names:
                names.append(name)
    meta = result.get("meta")
    meta = meta if isinstance(meta, dict) else {}
    parts = [" / ".join(names) if names else
             str(meta.get("pcap_name") or "本次诊断（未落盘报告）")]
    generated = str(meta.get("generated_at") or "").strip()
    if generated:
        parts.append(generated)
    return " · ".join(parts)


def build_status_conclusion(result: dict) -> dict:
    """为 ``/api/status`` 构造结论边界对象（与 CLI/报告/MCP 同一 ``build_conclusion``）。

    Args:
        result: ``JOB["result"]``（正常或 0 包降级结果）。

    Returns:
        dict: :func:`core.conclusion.build_conclusion` 的 7 键对象；任何字段填充
            失败都由渲染器显式降级为「未知（原因：…）」+ 低置信，不返回空块。
    """
    return conclusion.build_conclusion(result, _conclusion_verdict(result))


def _attach_conclusion(result: dict | None, block: dict | None = None) -> dict | None:
    """给结果补结论对象与「复制/导出」预渲染文本（只进状态响应，不写报告）。

    为什么把渲染好的文本也下发：UI 的「复制给协作方」「导出 .md」必须与
    :func:`core.conclusion.render_conclusion_text` / ``render_conclusion_markdown``
    逐字一致。让服务端渲染一次，前端只负责放进剪贴板/Blob，避免第三份手写格式化。
    ``conclusion_export`` 则是「CLI ``--json`` 的 conclusion 对象 + 元信息」的
    固定结构，`.json` 导出直接序列化它。

    Args:
        result: 诊断结果字典；非字典原样返回。
        block: 已算好的结论对象；省略时现算 :func:`build_status_conclusion`。

    Returns:
        dict | None: 浅拷贝 + ``conclusion`` / ``conclusion_text`` /
            ``conclusion_markdown`` / ``conclusion_export``，并把同一份界面文案
            并入 ``ui_copy.conclusion``；``result`` 非字典时原样返回。
    """
    if not isinstance(result, dict):
        return result
    block = block if isinstance(block, dict) else build_status_conclusion(result)
    report_id = conclusion_report_id(result)
    enriched = dict(result)
    enriched["conclusion"] = block
    enriched["conclusion_text"] = conclusion.render_conclusion_text(block, report_id)
    enriched["conclusion_markdown"] = conclusion.render_conclusion_markdown(
        block, report_id)
    meta = result.get("meta")
    meta = meta if isinstance(meta, dict) else {}
    report_files = result.get("report")
    report_files = report_files if isinstance(report_files, dict) else {}
    report_names = {
        key: Path(str(value)).name
        for key, value in report_files.items()
        if value and key in ("markdown", "json")
    }
    enriched["conclusion_export"] = {
        "meta": {
            "report_id": report_id,
            "generated_at": meta.get("generated_at", ""),
            "pcap_name": meta.get("pcap_name", ""),
            "report": report_names,
        },
        "conclusion": block,
    }
    ui_copy = dict(enriched.get("ui_copy") or {})
    ui_copy["conclusion"] = _conclusion_ui_copy()
    enriched["ui_copy"] = ui_copy
    return enriched



def _now_iso(epoch: float | None = None) -> str:
    """把时间转成本机时区的 ISO 8601 字符串（带时区偏移）。

    Args:
        epoch: Unix 秒；``None`` 表示当前时间。

    Returns:
        str: 形如 ``2026-11-09T01:23:45+08:00`` 的秒级时间戳。前端按本地时区
            渲染成「今天 14:32」这类人类可读文本，服务端不写死时区。
    """
    stamp = time.time() if epoch is None else float(epoch)
    return dt.datetime.fromtimestamp(stamp).astimezone().isoformat(timespec="seconds")


def _last_run_target(mode: str, target: str, pcap: str | None) -> str:
    """上次结果摘要里的「目标」：保留用户当时填的值（离线模式退化为 pcap 文件名）。

    Args:
        mode: 用户选择的模式（``scan`` / ``live`` / ``offline``）。
        target: 用户填写并提交的目标；全网体检允许为空。
        pcap: 离线模式选中的抓包文件（只取文件名，不写绝对路径）。

    Returns:
        str: 目标文本；全网体检返回空串，由界面按 copy 表回退成「全网」。
    """
    text = (target or "").strip()
    if not text and mode == "offline" and pcap:
        text = Path(str(pcap)).name
    return text


def _remember_last_run(mode: str, target: str, started_at: float,
                       result: dict | None) -> None:
    """记住最近一次分析（内存单槽；新运行覆盖，进程退出即失）。

    只保存**摘要 + 可选完整结果**：摘要供 ``/api/last-run`` 渲染提示条，完整结果供
    ``/api/last-run/result`` 恢复结果区。完整结果超过 :data:`LAST_RUN_MAX_BYTES` 时
    丢弃完整结果、只留摘要（``full_result=False``），内存占用有上限。

    上限按**序列化后的 UTF-8 字节数**（``json.dumps(..., ensure_ascii=False).encode``）
    计算，不按字符数：一个中文字符通常占 3 字节，按字符数会让实际内存到约 3 倍上限。

    Args:
        mode: 用户选择的模式（``scan`` / ``live`` / ``offline``）。
        target: 摘要里的目标文本（见 :func:`_last_run_target`）。
        started_at: 任务开始时间（Unix 秒，``start_job`` 记录的 ``JOB["started_at"]``）。
        result: 本次分析结果；失败时可以是 ``{"ok": False, ...}``。

    Returns:
        None: 只更新模块级 :data:`LAST_RUN`，不写文件、不抛业务异常。

    Note:
        完整结果里的 ``meta.pcap_file`` 可能是本机绝对路径，``rows`` 也可能含目标
        IP / 域名 / URL。这些**只留在本进程内存**（单槽，进程退出即失），不落盘、
        不联网、不导出；``/api/last-run/result`` 只在 127.0.0.1 上本机可读。
        这里不做脱敏，因为前端「查看上次结果」要按原样渲染既有字段。
    """
    now = time.time()
    payload = result if isinstance(result, dict) else {}
    ok = bool(payload.get("ok"))
    verdict_data = payload.get("verdict")
    level = ""
    if ok and isinstance(verdict_data, dict):
        level = str(verdict_data.get("level") or "")
    summary_data = payload.get("summary")
    summary_data = summary_data if isinstance(summary_data, dict) else {}
    summary = {
        "time": _now_iso(now),
        "epoch": int(now),
        "mode": str(mode or ""),
        "target": (target or "").strip(),
        "level": level,
        "ok": ok,
        "duration_ms": max(0, int((now - float(started_at or now)) * 1000)),
        "critical": max(0, int(summary_data.get("critical_count") or 0)),
        "warning": max(0, int(summary_data.get("warning_count") or 0)),
        "full_result": False,
        "source": "memory",
    }
    full = None
    if ok and payload:
        try:
            size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError):
            size = LAST_RUN_MAX_BYTES + 1
        if size <= LAST_RUN_MAX_BYTES:
            # 打上 schema 版本标记再入内存（浅拷贝，不污染 payload 引用）：
            # /api/last-run/result 恢复时据此判定是否 legacy，而不是靠
            # conclusion 是否存在（后者会被 _attach_conclusion 现算补齐，误判）。
            full = dict(payload)
            full["record_schema"] = diagnose.RUN_RECORD_SCHEMA
        else:
            summary["trimmed"] = True
    summary["full_result"] = full is not None
    with LOCK:
        LAST_RUN.update({"summary": summary, "result": full, "cleared_at": 0.0})


def _last_run_from_runs(limit: int = 50) -> dict | None:
    """用 ``logs/runs/*.json`` 最近一条诊断记录兜底生成摘要（完整结果不可恢复）。

    Args:
        limit: 最多检查多少个最新的记录文件（``runs/`` 目录本身最多保留
            ``logstore.KEEP_RUNS`` 条）。

    Returns:
        dict | None: 摘要（``source="runs"``、``full_result=False``）；没有可用的
            诊断记录时返回 ``None``。单个文件读取/解析失败只跳过，不抛异常。
    """
    runs_dir = logstore.log_root() / "runs"
    try:
        files = [p for p in runs_dir.glob("*.json") if p.is_file()]
    except OSError:
        return None

    def _mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    files.sort(key=_mtime, reverse=True)
    for path in files[: max(1, int(limit))]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        mode = str(data.get("mode") or "").strip().lower()
        if mode not in LAST_RUN_FALLBACK_MODES:
            continue
        params = data.get("params")
        params = params if isinstance(params, dict) else {}
        target = str(params.get("target") or "").strip()
        if not target and mode == "offline":
            target = str(params.get("pcap") or "").strip()
        epoch = _mtime(path)
        # 旧记录兼容：没有 schema 版本字段的历史记录标记 legacy，前端据此只显示
        # 「旧版本结果」横幅、禁用导出，而不是渲染四层「未知」卡。
        legacy = not (
            isinstance(params.get("record_schema"), int)
            or isinstance(params.get("ui_contract_version"), str)
        )
        return {
            "time": _now_iso(epoch),
            "epoch": int(epoch),
            "mode": mode,
            "target": target,
            "level": str(data.get("level") or ""),
            "ok": bool(data.get("ok")),
            "duration_ms": max(0, int(data.get("duration_ms") or 0)),
            "critical": max(0, int(data.get("critical") or 0)),
            "warning": max(0, int(data.get("warning") or 0)),
            "full_result": False,
            "source": "runs",
            "legacy": legacy,
        }
    return None


def _last_run_view() -> dict | None:
    """返回「上次结果」摘要：内存优先，其次用 runs 文件兜底，都没有则 ``None``。

    Returns:
        dict | None: 摘要，键 ``time`` / ``epoch`` / ``mode`` / ``target`` /
            ``level`` / ``ok`` / ``duration_ms`` / ``critical`` / ``warning`` /
            ``full_result`` / ``source``。用户在本进程点过「开始新任务」
            （``cleared_at`` 非 0）后不再用历史记录兜底，避免刚清空又冒出来。
    """
    with LOCK:
        summary = LAST_RUN.get("summary")
        cleared_at = float(LAST_RUN.get("cleared_at") or 0.0)
    if isinstance(summary, dict) and summary:
        return dict(summary)
    if cleared_at:
        return None
    return _last_run_from_runs()


def _is_legacy_result(result: dict | None) -> tuple[bool, str]:
    """判定一份诊断结果是否「旧版本」：缺结论边界信息，UI 只能显示横幅。

    依据（任一满足即**非** legacy）：

    1. 结果带 ``record_schema``（int）或 ``ui_contract_version``（str）—— 新版本
       的 run 结果会被打上这两个版本标记；
    2. ``verdict`` 里含 ``basis`` / ``coverage`` / ``not_covered`` 任一边界字段。

    **刻意不看 ``conclusion`` 是否存在**：``/api/last-run/result`` 恢复时会用
    :func:`_attach_conclusion` 现算一份 conclusion 补进去，旧结果因此也会「有
    conclusion」。只看 conclusion 会把旧结果误判成新结果，前端据此渲染四层
    「未知」卡（issue: last-run/result 旧记录兼容）。

    Args:
        result: 待判定的诊断结果字典；``None`` / 非 dict 一律按 legacy。

    Returns:
        tuple[bool, str]: ``(是否 legacy, 原因说明)``。非 legacy 时原因为空串。
    """
    if not isinstance(result, dict):
        return True, "结果缺失或不是对象"
    if (isinstance(result.get("record_schema"), int)
            or isinstance(result.get("ui_contract_version"), str)):
        return False, ""
    verdict_data = result.get("verdict")
    if isinstance(verdict_data, dict) and any(
            key in verdict_data for key in ("basis", "coverage", "not_covered")):
        return False, ""
    return True, "记录缺少 record_schema 版本标记，且 verdict 无结论边界字段"


def _last_run_result() -> dict | None:
    """返回内存里的完整结果（没有时 ``None``；调用方不得据此抛异常）。

    Returns:
        dict | None: 最近一次成功分析的完整结果；进程重启、结果被清空或超过
            内存上限时返回 ``None``。
    """
    with LOCK:
        stored = LAST_RUN.get("result")
    return dict(stored) if isinstance(stored, dict) and stored else None


def _last_run_ui_copy() -> dict:
    """上次结果提示条的界面文案（唯一来源：``copy/zh-CN.json`` 的 ``last_run``）。

    Returns:
        dict: ``last_run`` section 的字符串映射；读取失败时返回 ``{}``
            （前端用内置最小回退，仍然不会空白）。
    """
    try:
        return copytext.section(copytext.load_table(), "last_run")
    except Exception:                              # noqa: BLE001  文案缺失不拖垮状态接口
        return {}


def _settings_ui_copy() -> dict:
    """设置页运行状态文案（唯一来源：``copy/zh-CN.json`` 的 ``settings``）。

    Returns:
        dict: ``settings`` section 的字符串映射；读取失败时返回 ``{}``。
    """
    try:
        return copytext.section(copytext.load_table(), "settings")
    except Exception:                              # noqa: BLE001  文案缺失不拖垮状态接口
        return {}


def _error_detail_from(res: dict) -> dict | None:
    """从失败结果里提取「可诊断性」字段，供 UI 错误卡渲染（不返回本地日志专用字段）。

    失败结果可能是 ``diagnose._pcap_error_card`` 的产物（带 ``pcap_path`` /
    ``pcap_exists`` / ``pcap_size`` / ``stage`` / ``reasons`` / ``re_capture``），
    也可能是普通 ``{"ok": False, "error": "..."}``（无这些字段）。这里只挑出
    UI 需要的白名单字段，``_log`` 这类本地日志字段绝不外发。

    Args:
        res: 失败结果字典。

    Returns:
        dict | None: 白名单字段的浅拷贝（``stage`` / ``pcap_path`` / ``pcap_name`` /
            ``pcap_exists`` / ``pcap_size`` / ``reasons`` / ``re_capture``）；
            结果里一个相关字段都没有时返回 ``None``（UI 走普通失败卡）。
    """
    if not isinstance(res, dict):
        return None
    keys = ("stage", "pcap_path", "pcap_name", "pcap_exists", "pcap_size",
            "reasons", "re_capture")
    detail = {key: res[key] for key in keys if key in res}
    return detail or None


def _worker(mode: str, target: str, duration: int, interface: str | None, pcap: str | None,
            shadow: bool = False) -> None:
    # run 记录由 diagnose.run_scan() 统一写（UI 的 /api/scan 也走它），
    # 这里不再重复 record_run —— 否则同一次分析会出现两条记录。
    started_at = float(JOB.get("started_at") or 0.0) or time.time()
    try:
        if mode == "offline":
            res = diagnose.run_scan(target=target, pcap=pcap, logger=log)
        else:
            res = diagnose.run_scan(target=target, duration=duration,
                                    interface=interface, logger=log, shadow=shadow)
            if not res.get("ok") and res.get("empty_capture"):
                # 0 包不直接判失败：自动做一次连通与速度测试（目标 → 默认网关），
                # 拿到时延/抖动/丢包就降级成中性结论；拿不到才走红色失败。
                fallback = diagnose.degraded_empty_capture_result(
                    target=target, duration=duration,
                    interface=res.get("interface") or interface,
                    capture_error=res.get("error", ""),
                    bpf=res.get("bpf", ""), logger=log)
                if fallback is not None:
                    # 降级卡也必须落盘（复审遗留 #7）：历史报告/导出里要能查到。
                    # 只落「真实卡片」：没有 kind/card_title 的结构不是本函数的产物
                    # （测试替身 / 上游改动），写出去只会得到一份空报告污染 reports/。
                    if isinstance(fallback, dict) and (
                            fallback.get("kind") or fallback.get("card_title")):
                        try:
                            fallback["report"] = report.save_degraded(fallback, REPORTS)
                            log(f"[提示] 降级结论报告已生成："
                                f"{fallback['report']['markdown']}")
                        except Exception as exc:  # noqa: BLE001 落盘失败不改变降级结论
                            log(f"[警告] 降级结论报告落盘失败：{type(exc).__name__}: {exc}")
                    else:
                        log("[提示] 降级结论结构不完整，跳过落盘（界面结论不受影响）")
                    res = fallback
        with LOCK:
            if res.get("ok"):
                JOB["state"] = "done"
                JOB["result"] = res
                JOB["error"] = ""
                JOB["error_code"] = ""
                JOB["error_detail"] = None
            else:
                JOB["state"] = "error"
                JOB["error"] = res.get("error", "未知错误")
                JOB["error_code"] = res.get("code") or diagnose._error_code(res)
                JOB["error_detail"] = _error_detail_from(res)
                JOB["result"] = None
            JOB["finished_at"] = time.time()
        # G5：把本次分析记进内存，供刷新/重开页面时提示「上次结果」。放在状态更新之后，
        # 保证前端一看到 done 就能查到对应摘要。
        _remember_last_run(mode, _last_run_target(mode, target, pcap),
                           started_at, res)
    except Exception as exc:  # noqa: BLE001
        diagnose._log_to_file(traceback.format_exc())
        with LOCK:
            JOB["state"] = "error"
            JOB["error"] = f"{type(exc).__name__}: {exc}"
            JOB["error_code"] = "E_INTERNAL"
            JOB["error_detail"] = None
            JOB["finished_at"] = time.time()
        _remember_last_run(mode, _last_run_target(mode, target, pcap),
                           started_at, {"ok": False, "error": str(exc)})


def _to_bool(value, default: bool = True) -> bool:
    """把请求体里的布尔开关解析成 ``bool``（缺省 / 脏值回退默认值）。

    Args:
        value: 原始值（``True``/``False``/``0``/``1``/``"false"``/``None`` 等）。
        default: 缺省时的返回值；影子探测要求默认 **开**。

    Returns:
        bool: 解析结果；``None`` / 无法识别时返回 ``default``。
    """
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return default


def start_job(payload: dict) -> dict:
    """启动一次诊断任务（全网体检 / 单目标诊断 / 分析抓包文件）。

    Args:
        payload: 前端提交的原始 JSON，键：
            ``mode``（``live`` / ``scan`` / ``offline``，非法值回落 ``live``）、
            ``target``（目标 IP/网段/域名，最多 300 字符）、
            ``duration``（秒，夹在 3 ~ ``max_duration`` 之间）、
            ``interface``（网卡序号，可空=自动挑）、
            ``pcap``（仅离线模式；**只接受 captures/ 下的文件名**，防任意文件读取）、
            ``shadow``（可选 bool，默认 ``True``：实时抓包同时做影子探测**与路径
            剖面（MTR）**；离线忽略；MTR 只在有目标时跑）。
            旧版前端不传 ``shadow`` 时按默认开处理，行为兼容。

    Returns:
        dict: 成功 ``{"ok": True}``；已在跑或参数不合法时 ``{"ok": False, "error": "..."}``。
            任务本身在后台线程执行，进度请轮询 ``/api/status``。
    """
    cfg = diagnose.load_config()
    shadow = _to_bool(payload.get("shadow"), True)
    with LOCK:
        if JOB["state"] == "running":
            return {"ok": False, "error": "已有诊断任务在执行，请等待完成"}
        mode = str(payload.get("mode") or "live").strip().lower()
        if mode not in ("live", "scan", "offline"):
            mode = "live"
        target = (payload.get("target") or "").strip()[:300]
        ignored_target = ""
        if mode == "scan" and target:
            # 全网体检（全网扫描）的语义是「不设过滤、抓本机全部流量」。历史上前端仍显示目标框，
            # 用户填了就被当成 host 过滤导致 0 包；这里做后端兜底：忽略并记日志。
            ignored_target, target = target, ""
        duration = _to_int(payload.get("duration"), int(cfg.get("default_duration", 30)),
                           3, int(cfg.get("max_duration", 180)))
        interface = payload.get("interface") or None
        pcap = payload.get("pcap") or None
        if mode == "offline":
            if not pcap:
                return {"ok": False, "error_code": "E_BAD_PCAP", "error": "分析抓包文件需要指定 pcap 文件"}
            # 只允许 captures/ 下的文件：防止通过接口去读任意本地文件
            name = Path(str(pcap)).name
            cand = CAPTURES / name
            if not cand.is_file():
                return {"ok": False, "error_code": "E_BAD_PCAP",
                        "error": f"抓包文件不存在：{name}（请先在界面里上传到 captures/）"}
            pcap = str(cand)

        JOB.update({"state": "running", "mode": mode, "target": target or "全网",
                    "duration": duration if mode != "offline" else 0,
                    "started_at": time.time(), "finished_at": 0, "logs": [],
                    "result": None, "error": "", "error_code": "", "error_detail": None})
    if ignored_target:
        log(f"[提示] 全网体检（全网扫描）模式忽略目标 {ignored_target}，抓取全部流量")
    log(f"任务已启动：模式={mode}，目标={target or '全网'}，时长={duration}s"
        f"{'' if mode == 'offline' else ('，探针基线/路径剖面=' + ('开' if shadow else '关'))}")
    threading.Thread(target=_worker,
                     args=(mode, target, duration, interface, pcap),
                     kwargs={"shadow": shadow}, daemon=True).start()
    return {"ok": True}


def report_index(limit: int = 50) -> list[dict]:
    """列出 ``reports/`` 下的历史报告（界面「报告与导出 → 历史报告」用）。

    只读目录，不生成、不修改任何报告；按修改时间倒序，最多 ``limit`` 条。

    Args:
        limit: 最多返回多少条（正数；调用方负责上限）。

    Returns:
        list[dict]: 每项键 ``name``（.md 文件名）/ ``size``（字节）/
            ``mtime``（``YYYY-MM-DD HH:MM``）/ ``json``（同名 .json 存在时为文件名，
            否则空串）。目录不可读时返回空列表，不抛异常。
    """
    try:
        paths = sorted(REPORTS.glob("*.md"), key=lambda p: p.stat().st_mtime,
                       reverse=True)
    except OSError:
        return []
    out: list[dict] = []
    for path in paths[:max(0, int(limit))]:
        try:
            stat = path.stat()
        except OSError:
            continue
        sidecar = path.with_suffix(".json")
        out.append({
            "name": path.name,
            "size": stat.st_size,
            "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime)),
            "json": sidecar.name if sidecar.is_file() else "",
        })
    return out


def request_elevation() -> dict:
    """UI「以管理员身份重启」：调用启动器已有的 UAC 提权路径。

    提权本身是 Windows 的安全桌面确认，做不到静默；这里只负责发起请求：

    * 已是管理员 → 直接返回 ``already_admin``，不重复弹 UAC；
    * 用户点「是」→ 新进程以管理员权限启动（``core/app.py --elevated`` 会等旧实例
      释放端口后再监听，避免两个实例抢同一个端口），随后旧服务退出；
    * 用户点「否」/ 被组策略禁止 → 返回 ``ok: False``，旧服务继续跑，
      分析抓包文件与连通与速度测试不受影响。

    返回值是结构化契约（UI 只读这几个键，不要再让路由层猜）：

    Returns:
        dict: 成功 ``{"ok": True, "restarted": True, "message": ...}``；
            本来就有权限 ``{"ok": True, "restarted": False, "already_admin": True,
            "message": ...}``；失败 ``{"ok": False, "restarted": False,
            "error": "..."}`` —— 失败**不抛异常、不杀当前进程**。
    """
    if tshark.is_admin():
        return {"ok": True, "restarted": False, "already_admin": True,
                "message": "当前已是管理员权限"}
    try:
        import app  # noqa: PLC0415  延迟导入：只有提权时才需要启动器模块
        started = app.relaunch_as_admin()
    except Exception as exc:  # noqa: BLE001  提权失败只回可读错误，不影响服务
        return {"ok": False, "restarted": False,
                "error": f"提权请求失败：{type(exc).__name__}: {exc}"}
    if not started:
        return {"ok": False, "restarted": False,
                "error": "未获得管理员权限（已取消，或被系统策略禁止）。"
                         "仍可继续使用分析抓包文件与连通与速度测试。"}
    log("[提示] 已请求以管理员身份重启，等待 Windows 授权…")
    threading.Timer(0.8, lambda: request_quit("正在以管理员权限重启，服务即将退出…")
                    ).start()
    return {"ok": True, "restarted": True, "message": "已请求管理员权限，服务将重启"}


def preflight_payload() -> dict:
    """启动器与界面共用的能力快照（H6：``GET /api/preflight``）。

    与 ``GET /api/selfcheck`` **同源**：内部只调 :func:`selfcheck.collect_cached`，
    不复制任何判定逻辑。唯一的语义差别是 preflight 不带 ``first_run`` / ack ——
    那是首屏面板的一次性提醒，不是「这台机器现在能不能用」的一部分。

    为什么让启动器也读这个接口（而不是自己再实现一套 Python/tshark/Npcap 判断）：
    C# 里重复判定迟早和 Python 分叉（版本号解析、scapy 可选、端口语义都会漂移）。
    启动器在服务未起时只显示 Python/端口两个本地占位，服务起来后以本接口为准。

    Returns:
        dict: 键 ``ok``（六项是否全过）/ ``version`` / ``checks``（固定 6 项，字段与
            selfcheck 完全一致，含 ``fix_kind`` / ``fix_url`` / ``fix_command`` /
            ``impact``）/ ``capabilities``（能力矩阵）/ ``ui_copy``（``{"startup": {...}}``
            文案）/ ``fix_urls``（**仅未通过**且带官网链接的项 → URL，启动器按钮
            直接取用；全绿时为空）/ ``source``（固定 ``"selfcheck"``，明示同源）。

    Example:
        >>> payload = preflight_payload()
        >>> [item["key"] for item in payload["checks"]][:2]
        ['python', 'tshark']
    """
    snap = selfcheck.collect_cached()
    checks = snap.get("checks") or []
    # S7：修复索引只收**未通过**的检查项。通过的项即使带 fix_url（历史数据/未来
    # 增加「查看官网」等字段）也不该被启动器当成「需要修复」，否则全绿时按钮仍亮。
    fix_urls = {
        str(item.get("key")): str(item.get("fix_url"))
        for item in checks
        if isinstance(item, dict) and item.get("fix_url") and not item.get("ok")
    }
    return {
        "ok": bool(snap.get("ok")),
        "version": snap.get("version", ""),
        "checks": checks,
        "capabilities": snap.get("capabilities") or {},
        "ui_copy": snap.get("ui_copy") or {},
        "fix_urls": fix_urls,
        "source": "selfcheck",
    }


# ---------------------------------------------------------------- 通信观察
def engine_info() -> dict:
    """当前可用的采集引擎（第一步就告诉用户「能不能用 Scapy」）。

    导入 Scapy 约 2 秒，所以结果进程内缓存一次，不在每次探测时重来。

    Returns:
        dict: 键 ``engine``（``scapy`` / ``tshark``）、``scapy``（bool）、
            可选 ``error``（Scapy 不可用时的原因，如 Npcap 缺失）。
    """
    if not ENGINE_CACHE:
        try:
            ENGINE_CACHE.update(passive.engine_status())
        except Exception as exc:  # noqa: BLE001
            ENGINE_CACHE.update({"engine": "tshark", "scapy": False, "error": str(exc)[:120]})
    return ENGINE_CACHE


def _passive_worker(interface: str | None, duration: int, target: str, engine: str) -> None:
    started = time.monotonic()
    params = {"interface": str(interface or ""), "duration": int(duration or 0),
              "target": (target or "")[:300], "engine": engine}
    try:
        res = passive.run(interface=interface, duration=duration, target=target,
                          engine=engine, logger=log,
                          should_stop=lambda: bool(PJOB.get("stop")))
        _record_ui_run("passive", params, started, res)
        with LOCK:
            if res.get("ok"):
                PJOB["state"] = "done"
                PJOB["result"] = res
            else:
                PJOB["state"] = "error"
                PJOB["error"] = res.get("error", "未知错误")
            PJOB["finished_at"] = time.time()
    except Exception as exc:  # noqa: BLE001
        _record_ui_run("passive", params, started, {"ok": False})
        diagnose._log_to_file(traceback.format_exc())
        with LOCK:
            PJOB["state"] = "error"
            PJOB["error"] = f"{type(exc).__name__}: {exc}"
            PJOB["finished_at"] = time.time()


def passive_start(payload: dict) -> dict:
    """启动通信观察（被动监听，只听不发）。

    Args:
        payload: 键 ``interface``（网卡序号，空=自动挑）、``duration``（秒，夹在 3~300）、
            ``target``（只保留与该目标相关的会话，空=全部流量）、
            ``engine``（``auto`` / ``scapy`` / ``tshark``，非法值回落 ``auto``）。

    Returns:
        dict: 成功 ``{"ok": True, "engine": "<实际使用的引擎>"}``；
            已有监听在跑时 ``{"ok": False, "error": "..."}``。
    """
    with LOCK:
        if PJOB["state"] == "running":
            return {"ok": False, "error": "已有监听任务在执行，请先停止或等待结束"}
    interface = payload.get("interface") or None
    try:
        duration = max(3, min(int(payload.get("duration") or 20), 300))
    except (TypeError, ValueError):
        duration = 20
    target = (payload.get("target") or "").strip()
    engine = (payload.get("engine") or "auto").lower()
    if engine not in ("auto", "scapy", "tshark"):
        engine = "auto"
    with LOCK:
        PJOB.update({"state": "running", "error": "", "result": None, "engine": engine,
                     "duration": duration, "started_at": time.time(),
                     "finished_at": 0, "stop": False})
    log(f"通信观察（被动监听）启动：网卡 {interface or '自动选择'}，{duration}s，"
        f"目标 {target or '全部流量'}，引擎 {engine}")
    threading.Thread(target=_passive_worker,
                     args=(interface, duration, target, engine), daemon=True).start()
    return {"ok": True, "engine": engine}


def passive_status() -> dict:
    """通信观察的当前状态与结果（界面每秒轮询它）。

    Returns:
        dict: 键 ``ok`` / ``state``（``idle``/``running``/``done``/``error``）/
            ``result``（完成后是 ``passive.run()`` 的结果，运行中为 ``None``）/
            ``error`` / ``engine`` / ``engine_info`` / ``elapsed``（已运行秒数）。
    """
    with LOCK:
        snap = {k: PJOB[k] for k in ("state", "result", "error", "engine",
                                     "started_at", "finished_at", "duration")}
        running = PJOB["state"] == "running"
    snap["ok"] = True
    snap["engine_info"] = engine_info()
    snap["elapsed"] = round(time.time() - snap["started_at"], 1) if running and snap["started_at"] else 0
    if running:
        # 监听中 → 汇总中：最后 1 秒留给会话汇总，别让用户以为卡在 0 秒不动。
        snap["phase"] = "监听中" if snap["elapsed"] < max(1, snap["duration"] - 1) else "汇总中"
    else:
        snap["phase"] = {"done": "完成", "error": "失败"}.get(snap["state"], "空闲")
    return snap


# ---------------------------------------------------------------- 结果页联动
#: 默认网关缓存：``/api/status`` 每 0.5 秒被轮询一次，GetBestRoute 虽快也没必要每次问。
GATEWAY_CACHE: dict = {"at": 0.0, "value": ""}


def _gateway_now(ttl: float = 30.0) -> str:
    """取默认网关（缓存 ``ttl`` 秒）；取不到返回空串，绝不影响状态接口。"""
    now = time.time()
    if now - float(GATEWAY_CACHE.get("at") or 0) > ttl:
        try:
            GATEWAY_CACHE["value"] = diagnose.winapi.default_gateway()
        except Exception:  # noqa: BLE001  取网关失败只让按钮消失，不影响结果
            GATEWAY_CACHE["value"] = ""
        GATEWAY_CACHE["at"] = now
    return str(GATEWAY_CACHE.get("value") or "")


def _peer_from_streams(streams: list[dict]) -> tuple[str, int] | None:
    """从 ``meta.streams_top`` 里挑一个最值得复测的服务端对端。

    优先带「无响应 / 重传 / RST」标记的会话，其次是重传次数多、报文多的；
    本机回环地址直接跳过（对它们做实时抓包没有意义）。返回
    ``(host, port)``；没有合法对端时返回 ``None``。
    """
    best: tuple[str, int] | None = None
    best_score = -1
    for item in streams or []:
        if not isinstance(item, dict):
            continue
        host = str(item.get("server") or "").strip()
        if not host or host in ("-", "0.0.0.0", "::", "::1"):
            continue
        if host.startswith("127.") or host == "localhost":
            continue
        try:
            port = int(item.get("dport") or 0)
        except (TypeError, ValueError):
            port = 0
        if not 1 <= port <= 65535:
            port = 0
        flags = " ".join(str(f) for f in (item.get("flags") or []))
        score = 0
        if any(k in flags for k in ("无响应", "重传", "RST")):
            score += 100
        score += int(item.get("retrans") or 0) * 10
        score += min(int(item.get("packets") or 0), 50)
        if score > best_score:
            best, best_score = (host, port), score
    return best


def link_actions(result: dict | None, gateway: str = "") -> list[dict]:
    """生成结果页「接下来怎么做」里的一键复测按钮参数（只描述，不执行）。

    这是**加法字段**：只进 ``/api/status`` 的响应，不写进报告 JSON / Markdown，
    因此不会改变 ``reports/`` 快照。前端拿到后负责弹确认框、切模式、预填表单。

    Args:
        result: ``JOB["result"]``（正常结果或 0 包降级结果）；空 / 非 dict 时返回 ``[]``。
        gateway: 默认网关（调用方查好传入，便于单测不碰系统 API）；空串时若降级
            结果里的 ``link.via == "gateway"`` 会用 ``link.host`` 兜底。

    Returns:
        list[dict]: 每项键 ``kind``（``live`` / ``probe``）/ ``mode``（前端模式名）/
            ``label``（按钮文案）/ ``target`` / ``port``（live 为端口，probe 为 ``None``）/
            ``display``（确认框里的 ``IP:端口``）/ ``confirm``（确认文案）。
            ``live`` 只在结果里有合法 Stream 对端时出现，``probe`` 只在知道网关时出现；
            两者都没有时返回 ``[]``（结果页不显示空的按钮区）。
    """
    if not isinstance(result, dict):
        return []
    actions: list[dict] = []
    meta = result.get("meta") or {}
    peer = _peer_from_streams(meta.get("streams_top") or [])
    if peer:
        host, port = peer
        display = f"{host}:{port}" if port else host
        actions.append({
            "kind": "live", "mode": "live", "needs_admin": True,
            "label": "用单目标诊断复测对端",
            "target": host, "port": port, "display": display,
            "confirm": f"将切换到『单目标诊断』并预填 {display}，是否继续？",
        })
    gw = str(gateway or "").strip()
    if not gw and result.get("degraded"):
        link = result.get("link") or {}
        if str(link.get("via") or "") == "gateway":
            gw = str(link.get("host") or "").strip()
    if gw:
        actions.append({
            "kind": "probe", "mode": "probe", "needs_admin": False,
            "label": "用连通与速度测试复测网关",
            "target": gw, "port": None, "display": gw,
            "confirm": f"将切换到『连通与速度测试』并预填网关 {gw}，是否继续？",
        })
    return actions


#: 客户端提前断开（关标签页 / 取消请求 / 浏览器 RST）时抛的异常类型。
#: 这些不是服务故障：浏览器不再需要响应，打印整段 traceback 只会污染日志。
CONNECTION_NOISE = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


def _log_connection_noise(exc: BaseException, where: str = "请求处理") -> None:
    """把「客户端提前断开」降级为**一行** debug 日志（不写 traceback、不显示给用户）。

    Args:
        exc: 捕获到的连接异常。
        where: 发生位置（``请求处理`` / ``响应发送`` / ``服务端``），便于排障时区分。

    Returns:
        None: 日志写盘失败也不抛异常（连接噪音处理本身不许再制造噪音）。

    Note:
        日志里用中文类别描述，不写 ``ConnectionResetError`` 这类 Python 类名：
        G4/B1 的磁盘日志验收明确要求 ``diag-*.log`` 不出现 ``Traceback`` /
        ``ConnectionResetError``——类名会把一次正常的关页面渲染成服务故障。
    """
    reasons = {
        ConnectionResetError: "连接被重置",
        ConnectionAbortedError: "连接被中止",
        BrokenPipeError: "管道已断开",
    }
    reason = reasons.get(type(exc), "连接异常")
    try:
        logstore.diag_log(
            f"[debug] {where}：客户端提前断开（{reason}）；"
            "不写 traceback，服务继续")
    except Exception:                              # noqa: BLE001  日志失败不阻塞服务
        pass


class Handler(BaseHTTPRequestHandler):
    """本地 Web UI 与 API 的请求处理器。

    安全边界（都在这层落实，下游模块不需要重复做）：
        * **Host 校验**：只接受 ``127.0.0.1`` / ``localhost``，挡住 DNS 重绑定；
        * **Origin 校验**：写操作要求同源，挡住跨站请求伪造；
        * **统一响应头**：CSP / ``X-Frame-Options`` / ``nosniff`` 见 :data:`SECURITY_HEADERS`；
        * **异常兜底**：任何未捕获异常都转成 500 JSON，不把栈信息漏给浏览器。
    """
    server_version = "USBNetDiag/1.1"
    protocol_version = "HTTP/1.1"

    # 只允许本机页面加载资源，禁止被其他站点内嵌或注入脚本
    SECURITY_HEADERS = (
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
        ("Content-Security-Policy",
         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
         "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
         "connect-src 'self'; base-uri 'none'; form-action 'none'; "
         "frame-ancestors 'none'; object-src 'none'"),
    )

    # ---------- helpers ----------
    def handle_one_request(self) -> None:
        """包住基类：客户端提前断开只记一行 debug，绝不打印 traceback。

        浏览器关标签页 / 取消请求时，服务端可能正在读请求行、读 body 或写响应，
        对应 ``ConnectionResetError``（WinError 10054）/ ``ConnectionAbortedError`` /
        ``BrokenPipeError``。这些是正常的客户端行为，不是服务故障；不拦就会由
        ``socketserver`` 打印整段 traceback（G4 真机噪音）。
        """
        try:
            super().handle_one_request()
        except CONNECTION_NOISE as exc:
            # 连接已经不可复用：置位让 handle() 循环退出，不再读下一条请求。
            self.close_connection = True
            _log_connection_noise(exc)

    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8",
              extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        """写一个完整响应；客户端提前断开在这里降级，**绝不**把栈冒到调用方。

        整个「状态行 + 头 + body」必须放在同一个 ``try`` 里：``end_headers()``
        会把头部缓冲真正写进 socket，大响应（``GET /``）时客户端 RST 恰好落在这里
        —— 只包 ``wfile.write(body)`` 会漏掉 ``end_headers``，异常冒到
        ``do_GET`` 的宽泛 ``except`` 就会先写一整段 traceback（B1 真机复现）。

        Args:
            extra_headers: 追加的头（``(名字, 值)`` 二元组序列）。向后兼容：旧调用
                不传即不加任何头；入口路由用它在 ``?ui=`` 命中时回写 ``Set-Cookie``。
        """
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            if self.close_connection:
                # 早退 body 超过丢弃上限/分块传输时由 _discard_body 置位：
                # 必须明确告诉客户端不再复用连接，否则 keep-alive 会读到残留字节。
                self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-store")
            for k, v in self.SECURITY_HEADERS:
                self.send_header(k, v)
            for k, v in extra_headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except CONNECTION_NOISE as exc:
            # 客户端已经走了：响应没人收是正常现象。置位关闭连接，让 handle()
            # 循环退出；只记一行 debug（B1：这里不许再写 traceback）。
            self.close_connection = True
            _log_connection_noise(exc, "响应发送")

    def _json(self, data, code: int = 200) -> None:
        self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def log_message(self, fmt, *args):  # 静音，避免刷屏
        """屏蔽默认访问日志（每个请求打一行会把控制台刷爆）。

        Args:
            fmt: ``BaseHTTPRequestHandler`` 传来的格式化模板，这里不用。
            *args: 模板参数，同样不用。

        Returns:
            None: 有意为空实现。需要看请求时请用 ``log()`` 写业务日志。
        """
        return

    def _declared_body_length(self) -> int:
        """当前请求声明的 ``Content-Length``（缺失或非法按 0）。

        Returns:
            int: 非负字节数；解析失败不抛异常。
        """
        try:
            return max(0, int(self.headers.get("Content-Length") or 0))
        except ValueError:
            return 0

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0:
            return {}
        if length > MAX_JSON_BODY:
            # 必须把已声明的 body 读干净再回错误，否则客户端还在写、
            # 连接会被 RST，浏览器只能看到「连接被重置」而不是明确的提示。
            self._drain(length)
            raise BodyTooLarge(f"请求体 {length} 字节，超过 {MAX_JSON_BODY // (1 << 20)}MB 上限")
        try:
            raw = self.rfile.read(length)
            self._body_left = max(0, getattr(self, "_body_left", length) - len(raw))
            if not raw:
                return {}
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (ValueError, OSError, UnicodeDecodeError):
            return {}

    def _discard_body(self) -> None:
        """丢弃本请求尚未读取的 body，防止残留字节被当成下一条请求执行。

        早退（403 / 扩展名不符等）不读 body 时，``BaseHTTPRequestHandler`` 会把
        残留字节解析成下一条 HTTP 请求（keep-alive 请求走私 / CSRF 绕过），所以
        任何提前返回前都必须调用本方法。只消费 :meth:`_drain` 的有界上限；
        body 过大或分块传输时强制关闭连接。

        Returns:
            None: 已读完或读失败都直接返回，不抛异常。
        """
        # 分块传输没有可靠的 Content-Length，无法安全 drain。**必须**在 ``left <= 0``
        # 早返回之前判断 ``Transfer-Encoding``：否则 chunked 请求（无 Content-Length）
        # 会既不 drain 也不 close，残留 body 被当成下一条请求执行（审查实测可走私
        # ``POST /api/passive/stop`` 并绕过 ``_guard`` 的 Origin 校验）。
        if (self.headers.get("Transfer-Encoding") or "").strip():
            self._body_left = 0
            self.close_connection = True
            return
        left = getattr(self, "_body_left", 0)
        if left <= 0:
            return
        self._body_left = 0
        self._drain(left)

    def _drain(self, length: int) -> None:
        """丢弃剩余请求体，最多 64MB；超限或对端提前断开则关闭连接。"""
        left = min(max(0, length), 64 << 20)
        try:
            while left > 0:
                chunk = self.rfile.read(min(1 << 20, left))
                if not chunk:
                    self.close_connection = True
                    break
                left -= len(chunk)
        except OSError:
            self.close_connection = True
        self._body_left = 0
        if length > 64 << 20:
            self.close_connection = True

    def _guard(self) -> bool:
        """只接受本机页面/本机程序，挡住恶意网页跨站调用与 DNS 重绑定。"""
        raw = (self.headers.get("Host") or "").strip().lower()
        if raw.startswith("["):
            host = raw[1:raw.find("]")] if "]" in raw else raw
        else:
            host = raw.split(":")[0]
        if host and host not in ("127.0.0.1", "localhost", "::1"):
            return False
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return True  # 本机程序、命令行工具不带 Origin
        try:
            o = urllib.parse.urlparse(origin)
        except ValueError:
            return False
        return (o.hostname or "").lower() in ("127.0.0.1", "localhost", "::1")

    def _ai_analyze(self, payload: dict) -> None:
        """对诊断结果做 AI 解读，并把结论落到 reports/<stem>.ai.md。"""
        result = payload.get("result")
        if not isinstance(result, dict) or not result:
            with LOCK:
                result = JOB.get("result")
        if not result:
            return self._json({"ok": False, "error": "暂无可解读的诊断结果，请先执行一次诊断"})
        try:
            out = ai.analyze_result(result, question=str(payload.get("question") or ""))
        except ai.AIError as exc:
            return self._json({"ok": False, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            return self._json({"ok": False, "error": f"{type(exc).__name__}: {exc}"})

        try:
            stem = Path((result.get("meta") or {}).get("pcap_name") or "report").stem
            REPORTS.mkdir(parents=True, exist_ok=True)
            path = REPORTS / f"{stem}.ai.md"
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            path.write_text(
                f"# AI 解读 · {stem}\n\n"
                f"> 模型：`{out.get('model', '-')}` · 生成时间：{stamp} · "
                f"耗时 {out.get('latency_ms', 0) / 1000:.1f}s\n\n"
                f"{out['analysis']}\n",
                encoding="utf-8",
            )
            out["markdown"] = path.name
        except OSError:
            pass
        log(f"AI 解读完成（{out.get('model')}，{out.get('latency_ms', 0) / 1000:.1f}s）")
        return self._json(out)

    # ---------- routes ----------
    def do_GET(self):
        """处理 GET：静态页 + 只读 API。

        Returns:
            None: 响应直接写入 socket。失败路径固定三种 ——
                403（来源不合法）、404（路径不存在）、500（内部错误，栈只进日志）。
        """
        try:
            self._body_left = self._declared_body_length()
            self._discard_body()  # GET 不需要 body；有也必须丢弃，防请求走私
            self._route_get()
        except BodyTooLarge as exc:
            self._json({"ok": False, "error": str(exc)}, 413)
        except CONNECTION_NOISE as exc:
            # 连接类异常必须排在宽泛 except 之前：宽泛分支会先写一整段 traceback
            # （B1）。这里交给统一降级——一行 debug + 关闭连接，不响应。
            self.close_connection = True
            _log_connection_noise(exc)
        except Exception as exc:  # noqa: BLE001
            diagnose._log_to_file(traceback.format_exc())
            self._json({"ok": False, "error": f"服务内部错误：{type(exc).__name__}: {exc}"}, 500)

    def do_POST(self):
        """处理 POST：启动任务、上传、配置、退出等有副作用的操作。

        Returns:
            None: 响应直接写入 socket。请求体超过 :data:`MAX_JSON_BODY` 时返回 413，
                并且会把剩余字节读完再关 —— 否则客户端只会看到「连接被重置」。
        """
        try:
            self._body_left = self._declared_body_length()
            self._route_post()
        except BodyTooLarge as exc:
            self._json({"ok": False, "error": str(exc)}, 413)
        except CONNECTION_NOISE as exc:
            # 同 do_GET：连接类异常先降级，禁止落到下面写 traceback 的分支。
            self.close_connection = True
            _log_connection_noise(exc)
        except Exception as exc:  # noqa: BLE001
            diagnose._log_to_file(traceback.format_exc())
            self._json({"ok": False, "error": f"服务内部错误：{type(exc).__name__}: {exc}"}, 500)
        finally:
            # 兜底：任何没读完 body 的返回路径都不许把残留字节留给下一条请求。
            self._discard_body()

    def _route_get(self):
        touch()
        if not self._guard():
            return self._json({"ok": False, "error": "禁止外部页面访问本机服务"}, 403)
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/ping":
            # 单实例探测用：前端也用它确认后端是否还活着
            return self._json({"ok": True, "app": APP_NAME, "version": APP_VERSION,
                               "pid": os.getpid(), "url": SERVER.get("url", ""),
                               "started_at": SERVER.get("started_at", 0)})
        if path == "/api/app":
            cfg = diagnose.load_config()
            # 首屏会先要 /api/app：这里复用 selfcheck 的短 TTL 结果，别把
            # 六项检查（tshark 版本 / 端口 / scapy 导入）再跑一遍。
            snap = selfcheck.collect_cached()
            # 文案随应用信息一起下发（前端不另存中文）：startup 是首屏检查，
            # last_run / settings 是 G5 的提示条与设置页文案（加法字段）。
            ui_copy = dict(snap.get("ui_copy") or {})
            ui_copy["last_run"] = _last_run_ui_copy()
            ui_copy["settings"] = _settings_ui_copy()
            return self._json({"ok": True, "app": APP_NAME, "version": APP_VERSION,
                               "pid": os.getpid(), "port": SERVER.get("port", 0),
                               "url": SERVER.get("url", ""),
                               "idle_exit_min": SERVER.get("idle_exit_min", 0),
                               "auto_quit": bool(SERVER.get("idle_exit_min", 0)),
                               "admin": tshark.is_admin(),
                               # 加法字段：首屏自检与权限卡文案随应用信息一起下发，
                               # 前端不另存一份中文（文案唯一来源仍是 copy/zh-CN.json）。
                               "first_run": snap["first_run"],
                               "ui_copy": ui_copy,
                               # 加法字段：首屏不用等 /api/selfcheck 就能先按能力置灰；
                               # checks 同批下发，UI 首屏可直接画面板、不再跑第二次全套检查。
                               "checks": snap["checks"],
                               "capabilities": snap["capabilities"],
                               "auto_open_browser": bool(cfg.get("auto_open_browser", True))})
        if path in ("/", "/index.html", "/v2/", "/v2/index.html"):
            # 入口路由：按 ui_entry() 的优先级决定发 v1 还是 v2 的 index.html。
            # 覆盖四个入口别名（v1 的 /、/index.html；v2 的 /v2/、/v2/index.html），
            # 但发出去的始终是 ui_entry 选定的那份 HTML（不按 URL 别名各自固定）。
            version = ui_entry(parsed, _parse_ui_cookie(self.headers))
            rel = UI_ENTRY.get(version, UI_ENTRY["v1"])
            f = UI_DIR / rel
            if not f.is_file():
                # 目标入口文件缺失：宁可 500 并写明缺哪个文件，绝不静默回退到另一版。
                return self._send(500, f"ui/{rel} missing".encode("utf-8"),
                                  "text/plain; charset=utf-8")
            extra = ()
            q = urllib.parse.parse_qs(parsed.query)
            if (q.get("ui") or [None])[0] in ("v1", "v2"):
                # ?ui= 命中时回写 Cookie，之后无参访问仍保持该版本。
                extra = (("Set-Cookie", f"{UI_COOKIE}={version}; Path=/; SameSite=Lax"),)
            return self._send(200, f.read_bytes(), "text/html; charset=utf-8", extra)

        if path == "/api/status":
            with LOCK:
                data = dict(JOB)
            data["elapsed"] = round((data["finished_at"] or time.time()) - data["started_at"], 1) \
                if data["state"] in ("running", "done", "error") and data["started_at"] else 0
            # 加法字段：老前端不读也不受影响；新前端据此画进度条 / 倒计时 / 阶段。
            data["phase"] = _job_phase(data["state"], data.get("logs") or [])
            attempt, attempts = _job_attempt(data.get("logs") or [])
            data["attempt"] = attempt
            data["attempts"] = attempts
            # 加法字段：结果页「接下来怎么做」的一键复测按钮参数。
            # 只进状态响应，不进报告，所以 faults_demo 快照不受影响。
            if data["state"] == "done" and isinstance(data.get("result"), dict):
                data["link_actions"] = link_actions(data["result"], _gateway_now())
                data["result"] = _attach_probe_ui_copy(data["result"])
                # E2：结论与边界作为**加法字段**随状态下发。同一 build_conclusion
                # 产物 + 服务端预渲染文本，UI 只负责排版/复制/下载，不另写格式化。
                data["conclusion"] = build_status_conclusion(data["result"])
                data["result"] = _attach_conclusion(data["result"], data["conclusion"])
            # 结论卡文案即使没有结果也要下发（失败/降级页也要显示边界卡）；
            # 旧前端不读 ui_copy.conclusion，不受影响。
            data["ui_copy"] = {"conclusion": _conclusion_ui_copy()}
            return self._json(data)
        if path == "/api/last-run":
            # 加法接口（G5）：页面加载 / bfcache 还原 / 分析完成后都来问一次。
            # 没有记录时 last=null（前端必须不渲染提示条，不能误报）。
            return self._json({"ok": True, "last": _last_run_view(),
                               "ui_copy": {"last_run": _last_run_ui_copy()}})
        if path == "/api/last-run/result":
            # 完整结果只在内存里；进程重启 / 用户点过「开始新任务」后返回 404 JSON，
            # 界面据此禁用「查看」并说明只能看摘要（不抛异常、不吐栈）。
            stored = _last_run_result()
            if stored is None:
                return self._json(
                    {"ok": False,
                     "error": "内存里没有上次的完整结果（服务可能已重启，或只有历史摘要）"},
                    404)
            # 旧记录兼容：判定依据是 record_schema / verdict 边界字段，而不是
            # conclusion 是否存在（_attach_conclusion 会现算补齐，只看它会误判）。
            legacy, legacy_reason = _is_legacy_result(stored)
            enriched = _attach_probe_ui_copy(stored)
            block = build_status_conclusion(enriched)
            enriched = _attach_conclusion(enriched, block)
            # 把 legacy 标记一并下发：前端据此只渲染「旧版本结果」横幅 + 重新诊断，
            # 不渲染四层「未知」卡、不给导出按钮。原因说明随响应返回便于排查。
            enriched["legacy"] = legacy
            enriched["legacy_reason"] = legacy_reason
            return self._json({"ok": True, "result": enriched,
                               "summary": _last_run_view(),
                               "legacy": legacy,
                               "legacy_reason": legacy_reason,
                               "link_actions": link_actions(enriched, _gateway_now())})
        if path == "/api/interfaces":
            ifaces = [{**i, "short": tshark.short_name(i["name"])} for i in tshark.list_interfaces()]
            return self._json({"interfaces": ifaces, "admin": tshark.is_admin(),
                               "npcap": tshark.npcap_installed()})
        if path == "/api/captures":
            files = sorted(CAPTURES.glob("*.pcap*"), key=lambda p: p.stat().st_mtime, reverse=True)
            return self._json({"files": [{"name": p.name, "size": p.stat().st_size,
                                          "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))}
                                         for p in files[:50]]})
        if path == "/api/reports":
            return self._json({"ok": True, "files": report_index()})
        if path == "/api/report":
            q = urllib.parse.parse_qs(parsed.query)
            name = (q.get("path") or [""])[0]
            target = (REPORTS / Path(name).name)
            if not target.is_file():
                return self._send(404, b"report not found", "text/plain; charset=utf-8")
            ctype = "text/markdown; charset=utf-8" if target.suffix == ".md" else "application/json; charset=utf-8"
            return self._send(200, target.read_bytes(), ctype)
        if path == "/api/evidence":
            # 纯计算：只读最近一次诊断结果，不写文件、不联网。
            q = urllib.parse.parse_qs(parsed.query)
            full = _to_bool((q.get("full") or [None])[0], False)
            fmt = ((q.get("fmt") or ["md"])[0] or "md").strip().lower()
            if fmt not in ("md", "txt"):
                return self._json({"ok": False, "error": "fmt 只支持 md / txt"})
            with LOCK:
                latest = JOB.get("result")
            return self._json(evidence_payload(latest, full=full, fmt=fmt))
        if path == "/api/doctor":
            return self._json(doctor_cached())
        if path == "/api/preflight":
            # H6：启动器 splash 与 UI 首屏共用这一份（同一 collect_cached 缓存），
            # 不带 first_run/ack 语义；旧前端继续用 /api/selfcheck 也仍然同源。
            return self._json(preflight_payload())
        if path == "/api/selfcheck":
            # 纯读环境：不写文件、不触发 UAC、不启动抓包子进程；短 TTL 缓存
            # 让紧接着的 /api/app 或「重新检测」复用同一份结果。
            return self._json(selfcheck.collect_cached())
        if path == "/api/passive":
            return self._json(passive_status())
        if path == "/api/ai":
            return self._json(ai.public_config())
        if path == "/api/probe":
            q = urllib.parse.parse_qs(parsed.query)
            target = (q.get("target") or [""])[0].strip()
            if not target:
                return self._json({"ok": False, "error": "请提供 target 参数，例如 /api/probe?target=example.com"})
            port = _to_int((q.get("port") or [None])[0], None, 1, 65535)
            count = _to_int((q.get("count") or ["4"])[0], 4, 1, 10)
            proto = (q.get("proto") or [None])[0]
            # 加法字段：旧前端不传 path 时按「开」处理（与 /api/scan 的 shadow 同口径）。
            want_path = _to_bool((q.get("path") or [None])[0], True)
            return self._json(_probe_guarded(target, port, count, None, proto,
                                             path=want_path))
        # 前端静态资源：样式/脚本拆成独立文件后浏览器会以子资源方式请求它们。
        # 位置必须在所有 /api/* 之后、404 兜底之前 —— 静态路由不许抢 API 的路径。
        asset = static_asset(path)
        if asset is not None:
            ctype = STATIC_MIME.get(asset.suffix.lower())
            if ctype is None:
                # 白名单里冒出未登记扩展名：宁可 404，也不猜一个 MIME 出去。
                return self._send(404, b"not found", "text/plain; charset=utf-8")
            return self._send(200, asset.read_bytes(), ctype)
        return self._send(404, b"not found", "text/plain; charset=utf-8")

    def _route_post(self):
        touch()
        if not self._guard():
            self._discard_body()  # 403 也要读掉 body，否则会被当成下一条请求
            return self._json({"ok": False, "error": "禁止外部页面访问本机服务"}, 403)
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/quit":
            # S4：这个端点会真的停掉本机服务，和所有 POST 一样必须先过 _route_post
            # 顶部的 _guard()（Host + Origin 同源），拒绝外部网页 CSRF / DNS rebinding。
            # 不再加一次性 token：本机同用户进程本来就能结束进程，token 挡不住它们，
            # 反而会破坏「界面右上角退出 / 空闲自动退出」两条既有链路。
            self._discard_body()
            request_quit("收到界面退出指令，正在停止本地服务…")
            return self._json({"ok": True, "message": "服务已停止，可以关闭本页面了"})
        if parsed.path == "/api/last-run/clear":
            # 只清内存（以及本进程的 runs 兜底开关），不删 logs/runs 历史记录：
            # 清空后再查 /api/last-run 必须是 null（刷新也不该再冒出来）。
            # 同时把已完成/失败的 JOB 展示槽归零：否则刷新后 /api/status 会把旧结果
            # 重新渲染回来，用户会以为「开始新任务」没生效。运行中的任务不动。
            self._discard_body()
            with LOCK:
                LAST_RUN.update({"summary": None, "result": None,
                                 "cleared_at": time.time()})
                if JOB.get("state") in ("done", "error"):
                    JOB.update({"state": "idle", "mode": "", "target": "",
                                "duration": 0, "started_at": 0.0,
                                "finished_at": 0.0, "logs": [], "result": None,
                                "error": "", "error_code": ""})
            log("已清空「上次结果」的内存记录（runs/ 历史记录保留）。")
            return self._json({"ok": True})
        if parsed.path == "/api/elevate":
            self._discard_body()
            return self._json(request_elevation())
        if parsed.path == "/api/selfcheck/ack":
            self._discard_body()
            # 写失败（U 盘只读 / 目录被锁）返回 ok:false 但绝不阻塞界面。
            result = selfcheck.ack_first_run()
            # ack 改了 first_run：缓存里的旧载荷必须作废，否则 TTL 内
            # 下一次 /api/selfcheck 还会把「首次运行」下发一遍。
            selfcheck.invalidate_cache()
            return self._json(result)

        if parsed.path == "/api/ai":
            payload = self._read_json()
            try:
                cfg = ai.save_config(payload)
            except ValueError as exc:
                return self._json({"ok": False, "error": str(exc)})
            log(f"AI 配置已更新：{cfg.get('model')} @ {cfg.get('base_url')}")
            return self._json({"ok": True, "config": ai.public_config(cfg)})
        if parsed.path == "/api/ai/test":
            payload = self._read_json()
            overrides = payload.get("overrides") if isinstance(payload.get("overrides"), dict) else payload
            return self._json(ai.test_connection(overrides or None))
        if parsed.path == "/api/ai/analyze":
            return self._ai_analyze(self._read_json())
        if parsed.path == "/api/passive":
            return self._json(passive_start(self._read_json()))
        if parsed.path == "/api/passive/stop":
            self._discard_body()
            with LOCK:
                PJOB["stop"] = True
            log("通信观察：收到停止指令，正在收尾…")
            return self._json({"ok": True})
        if parsed.path == "/api/probe":
            payload = self._read_json()
            target = (payload.get("target") or "").strip()
            if not target:
                return self._json({"ok": False, "error": "请填写要诊断的域名或 IP"})
            port = _to_int(payload.get("port"), None, 1, 65535)
            count = _to_int(payload.get("count"), 4, 1, 10)
            timeout = _to_float(payload.get("timeout"), 3.0, 0.5, 10.0)
            # 「逐跳路径」开关（默认开，加法字段）：关闭时不发任何 MTR 探测包。
            want_path = _to_bool(payload.get("path"), True)
            log(f"连通与速度测试（链路体检）：{target}:{port or '默认端口'}"
                f"（逐跳路径={'开' if want_path else '关'}）")
            return self._json(_probe_guarded(target, port, count, timeout,
                                             payload.get("proto") or None,
                                             path=want_path))
        if parsed.path == "/api/scan":
            payload = self._read_json()
            return self._json(start_job(payload))
        if parsed.path == "/api/diagpack":
            # 前端顶部「导出诊断包」按钮：默认脱敏，不联网，产物落在 logs/exports/。
            payload = self._read_json()
            raw = bool(payload.get("raw"))
            include_reports = bool(payload.get("include_reports"))
            try:
                path = diagpack.build(include_reports=include_reports, raw=raw)
                with zipfile.ZipFile(path) as zf:
                    entries = len(zf.namelist())
                size = path.stat().st_size
            except Exception as exc:  # noqa: BLE001  导出失败只回错误，不吐栈给浏览器
                diagnose._log_to_file(traceback.format_exc())
                return self._json({"ok": False,
                                   "error": f"导出诊断包失败：{type(exc).__name__}: {exc}"})
            if raw:
                log("[警告] 诊断包 --raw 未脱敏：包含原始 IP/域名/用户名/MAC")
            log(f"诊断包已导出：{path}（{size / 1024:.0f} KB，{entries} 个条目）")
            return self._json({"ok": True, "path": str(path), "size": size,
                               "entries": entries})
        if parsed.path == "/api/upload":
            q = urllib.parse.parse_qs(parsed.query)
            raw_name = Path((q.get("name") or ["upload.pcapng"])[0]).name
            safe = "".join(c for c in raw_name if c.isalnum() or c in "._-") or "upload.pcapng"
            if not safe.lower().endswith((".pcap", ".pcapng", ".cap")):
                self._discard_body()
                return self._json({"ok": False, "error": "只接受 .pcap / .pcapng / .cap 文件"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0:
                return self._json({"ok": False, "error": "空文件"})
            if length > MAX_UPLOAD:
                # 2GB 量级读完不现实：直接关连接，keep-alive 不再复用（防走私）。
                self._body_left = 0
                self.close_connection = True
                return self._json({"ok": False,
                                   "error": f"文件超过 {MAX_UPLOAD // (1 << 30)}GB 上限"}, 413)
            CAPTURES.mkdir(parents=True, exist_ok=True)
            dest = CAPTURES / f"upload_{time.strftime('%Y%m%d_%H%M%S')}_{safe}"
            remaining = length
            written = 0
            try:
                with dest.open("wb") as fh:
                    while remaining > 0:
                        chunk = self.rfile.read(min(1 << 20, remaining))
                        if not chunk:
                            break
                        fh.write(chunk)
                        written += len(chunk)
                        remaining -= len(chunk)
                        self._body_left = max(0, getattr(self, "_body_left", 0) - len(chunk))
            except OSError:
                dest.unlink(missing_ok=True)
                raise
            if written == 0:
                dest.unlink(missing_ok=True)
                self._discard_body()
                return self._json({"ok": False, "error": "上传中断，未收到数据"})
            return self._json({"ok": True, "file": dest.name, "size": dest.stat().st_size})
        self._discard_body()
        return self._send(404, b"not found", "text/plain; charset=utf-8")


class DiagServer(ThreadingHTTPServer):
    """daemon_threads：关闭时不被长连接拖住。

    allow_reuse_address 必须为 False：Windows 上 SO_REUSEADDR 语义与 Unix 不同，
    置 True 会让两个进程同时绑上 8787，旧进程继续响应，改了代码却看不到效果。
    端口被占时由 create_server() 顺延到下一个端口。
    """

    daemon_threads = True
    allow_reuse_address = False

    def handle_error(self, request, client_address) -> None:
        """兜底：连接类异常只写一行 debug；其他异常保留「类型 + 原因」一行可诊断信息。

        ``Handler.handle_one_request`` 已经拦住绝大多数连接重置；这里覆盖
        ``socketserver`` 的默认实现，避免漏网的 ``BrokenPipeError`` 又打印整段
        traceback。**不吞所有异常**：非连接异常仍写一行 error（类型 + 原因），
        只是不再把栈直接刷到 stderr。

        Args:
            request: 触发异常的套接字（``socketserver`` 传入，这里不使用）。
            client_address: 客户端地址（这里不使用；日志不含敏感信息）。

        Returns:
            None: 只写日志，不向客户端发送任何内容（连接可能已断开）。
        """
        exc = sys.exc_info()[1]
        if exc is not None and isinstance(exc, CONNECTION_NOISE):
            _log_connection_noise(exc, "服务端")
            return
        try:
            name = type(exc).__name__ if exc is not None else "UnknownError"
            reason = str(exc or "")[:300]
            logstore.diag_log(f"[错误] 请求处理异常：{name}: {reason}"
                              if reason else f"[错误] 请求处理异常：{name}")
        except Exception:                          # noqa: BLE001  日志失败不阻塞服务
            pass


def create_server(port: int = 8787, idle_exit_min: int = 0,
                  quiet: bool = False, register_pid: bool = True) -> tuple[DiagServer | None, str]:
    """建监听。端口被占用时顺延最多 10 个。

    Args:
        port: 起始端口（默认 8787）。
        idle_exit_min: 无人访问多少分钟后自动退出；0 表示常驻不退出。
        quiet: True 时不打印启动横幅（静默启动用）。
        register_pid: 是否写 ``logs/netdiag.pid``。自测传 False，
            避免测试实例覆盖正在运行的应用的 PID 文件。

    Returns:
        tuple[DiagServer | None, str]: ``(实例, 访问地址)``；10 个端口都被占用时返回 ``(None, "")``。

    Note:
        ``allow_reuse_address`` 必须是 **False**。Windows 上它等价于 ``SO_REUSEADDR``，
        会让两个进程同时绑同一端口，旧进程继续响应新请求 —— 这正是曾经
        「改了代码却没生效」的根因。
    """
    httpd = None
    url = ""
    bound = port
    for p in range(port, port + 10):
        try:
            httpd = DiagServer(("127.0.0.1", p), Handler)
            url = f"http://127.0.0.1:{p}/"
            bound = p
            break
        except OSError:
            continue
    if httpd is None:
        return None, ""
    SERVER.update({"httpd": httpd, "port": bound, "url": url,
                   "idle_exit_min": idle_exit_min, "started_at": time.time()})
    if register_pid:
        _write_pid()
    if idle_exit_min > 0:
        threading.Thread(target=_idle_watchdog, args=(idle_exit_min,), daemon=True).start()
    if not quiet:
        print("=" * 62)
        print(f"  NetDiag · 网络矩阵 已启动（v{APP_VERSION}）")
        print(f"  浏览器界面：{url}")
        print("  界面右上角「退出」可停止服务；关闭此窗口也会停止")
        print("=" * 62)
    return httpd, url


def main() -> int:
    """命令行入口：读配置 → 建监听 → 开浏览器 → 阻塞服务。

    Returns:
        int: 进程退出码。0 正常退出；1 端口全被占用。
    """
    # 日志基建（每次启动一次）：目录 → 裁剪 → 环境快照 → 崩溃钩子。
    logstore.ensure_dirs()
    logstore.prune()
    logstore.write_env_snapshot({"entry": "server"})
    logstore.install_excepthooks()
    cfg = diagnose.load_config()
    bootstrap.gen_configs()
    port = int(cfg.get("server_port", 8787))
    httpd, url = create_server(port)
    if httpd is None:
        print("[错误] 端口被占用，无法启动本地服务", file=sys.stderr)
        return 1
    if cfg.get("auto_open_browser", True) and not app.browser_disabled():
        # H1/S2：走 app.open_browser() 这一受控入口（内部再判一次 env），
        # 不再直接调 webbrowser.open —— 否则「所有打开点都走这里」就有第二套逻辑。
        threading.Timer(0.8, lambda: app.open_browser(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        httpd.server_close()
        cleanup_pid()
    return 0



if __name__ == "__main__":
    sys.exit(main())
