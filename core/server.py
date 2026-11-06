"""本地 Web UI + HTTP API（仅监听 127.0.0.1，不对外暴露）。

API:
  GET  /                    诊断界面
  GET  /api/status          任务状态 / 日志 / 结果
  GET  /api/interfaces      可用网卡
  GET  /api/captures        已有抓包文件
  POST /api/scan            启动诊断 {mode,target,duration,interface,pcap}
  POST /api/upload?name=x   上传 pcap 后离线分析
  GET  /api/report?path=    读取报告文件
  GET  /api/doctor          环境自检
  GET  /api/ai              AI 模型配置（Key 已脱敏）
  POST /api/ai              保存 AI 配置（局部更新，即时生效）
  POST /api/ai/test         用当前或临时参数测试连通性
  POST /api/ai/analyze      对最近一次诊断结果做 AI 解读
  GET/POST /api/probe       链路体检（分段测 DNS/TCP/TLS/首字节，按协议自适应）
  POST /api/passive         启动被动监听 {interface,duration,target,engine}
  GET  /api/passive         被动监听状态与结果
  POST /api/passive/stop    提前结束被动监听
  GET  /api/ping            存活探测（单实例判断）
  GET  /api/app             应用信息（版本/端口/PID/是否静默模式）
  POST /api/quit            优雅退出（界面右上角「退出」调用）
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# 请求体上限：JSON 配置类请求 8MB 足够；上传抓包单独放宽到 2GB
MAX_JSON_BODY = 8 << 20
MAX_UPLOAD = 2 << 30
MAX_CONCURRENT_PROBE = 3  # 体检会发真实报文，限制并发避免把目标打挂

CORE = Path(__file__).resolve().parent
ROOT = CORE.parent
sys.path.insert(0, str(CORE))

import ai  # noqa: E402
import bootstrap  # noqa: E402
import diagnose  # noqa: E402
import passive  # noqa: E402
import probe  # noqa: E402
import tshark  # noqa: E402

UI_DIR = ROOT / "ui"
CAPTURES = ROOT / "captures"
REPORTS = ROOT / "reports"

LOCK = threading.Lock()
JOB = {
    "state": "idle",      # idle | running | done | error
    "mode": "",
    "target": "",
    "started_at": 0.0,
    "finished_at": 0.0,
    "logs": [],
    "result": None,
    "error": "",
}

# 被动监听单独一个任务槽，避免和诊断任务互相覆盖
PJOB = {
    "state": "idle",      # idle | running | done | error
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

# ---- 应用生命周期：单实例、优雅退出、空闲自动释放 ----
APP_NAME = "USBNetDiag"
APP_VERSION = "1.2"
QUIT = threading.Event()            # 置位后主循环退出
SERVER: dict = {"httpd": None}      # 当前监听实例，供 /api/quit 关停
LAST_HIT = {"t": time.time()}       # 最后一次有人访问界面的时间
PID_FILE = ROOT / "logs" / "netdiag.pid"


def touch() -> None:
    """记录一次界面访问，空闲计时据此重置。"""
    LAST_HIT["t"] = time.time()


def request_quit(reason: str = "") -> None:
    """请求服务退出：先让 HTTP 响应发出去，再关监听。"""
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


def doctor_cached(ttl: int = 60) -> dict:
    """环境自检要跑 tshark -v / -D，较慢；缓存 60 秒，避免首屏卡顿。"""
    now = time.time()
    if DOCTOR_CACHE["data"] and now - DOCTOR_CACHE["at"] < ttl:
        return DOCTOR_CACHE["data"]
    data = bootstrap.check(verbose=False)
    DOCTOR_CACHE.update({"at": now, "data": data})
    return data


def _probe_guarded(target: str, port, count, timeout, proto) -> dict:
    """体检会向目标发真实报文，加并发闸门，避免被误用成压测工具。"""
    if not PROBE_SEM.acquire(blocking=False):
        return {"ok": False,
                "error": f"同时进行的体检已达 {MAX_CONCURRENT_PROBE} 个，请等待前一个结束"}
    try:
        return probe.run(target, port=port, count=count,
                         timeout=timeout if timeout else 3.0, proto=proto)
    finally:
        PROBE_SEM.release()


def log(msg: str) -> None:
    with LOCK:
        JOB["logs"].append({"t": time.strftime("%H:%M:%S"), "m": str(msg)})
        if len(JOB["logs"]) > 400:
            del JOB["logs"][:100]
    diagnose._log_to_file(str(msg))


def _worker(mode: str, target: str, duration: int, interface: str | None, pcap: str | None) -> None:
    try:
        if mode == "offline":
            res = diagnose.run_scan(target=target, pcap=pcap, logger=log)
        else:
            res = diagnose.run_scan(target=target, duration=duration, interface=interface, logger=log)
        with LOCK:
            if res.get("ok"):
                JOB["state"] = "done"
                JOB["result"] = res
            else:
                JOB["state"] = "error"
                JOB["error"] = res.get("error", "未知错误")
                JOB["result"] = None
            JOB["finished_at"] = time.time()
    except Exception as exc:  # noqa: BLE001
        diagnose._log_to_file(traceback.format_exc())
        with LOCK:
            JOB["state"] = "error"
            JOB["error"] = f"{type(exc).__name__}: {exc}"
            JOB["finished_at"] = time.time()


def start_job(payload: dict) -> dict:
    cfg = diagnose.load_config()
    with LOCK:
        if JOB["state"] == "running":
            return {"ok": False, "error": "已有诊断任务在执行，请等待完成"}
        mode = str(payload.get("mode") or "live").strip().lower()
        if mode not in ("live", "scan", "offline"):
            mode = "live"
        target = (payload.get("target") or "").strip()[:300]
        duration = _to_int(payload.get("duration"), int(cfg.get("default_duration", 30)),
                           3, int(cfg.get("max_duration", 180)))
        interface = payload.get("interface") or None
        pcap = payload.get("pcap") or None
        if mode == "offline":
            if not pcap:
                return {"ok": False, "error": "离线分析需要指定抓包文件"}
            # 只允许 captures/ 下的文件：防止通过接口去读任意本地文件
            name = Path(str(pcap)).name
            cand = CAPTURES / name
            if not cand.is_file():
                return {"ok": False,
                        "error": f"抓包文件不存在：{name}（请先在界面里上传到 captures/）"}
            pcap = str(cand)

        JOB.update({"state": "running", "mode": mode, "target": target or "全网",
                    "started_at": time.time(), "finished_at": 0, "logs": [],
                    "result": None, "error": ""})
    log(f"任务已启动：模式={mode}，目标={target or '全网'}，时长={duration}s")
    threading.Thread(target=_worker, args=(mode, target, duration, interface, pcap), daemon=True).start()
    return {"ok": True}


# ---------------------------------------------------------------- 被动监听
def engine_info() -> dict:
    """缓存采集引擎信息（scapy 导入要 2s，不必每次探测）。"""
    if not ENGINE_CACHE:
        try:
            ENGINE_CACHE.update(passive.engine_status())
        except Exception as exc:  # noqa: BLE001
            ENGINE_CACHE.update({"engine": "tshark", "scapy": False, "error": str(exc)[:120]})
    return ENGINE_CACHE


def _passive_worker(interface: str | None, duration: int, target: str, engine: str) -> None:
    try:
        res = passive.run(interface=interface, duration=duration, target=target,
                          engine=engine, logger=log,
                          should_stop=lambda: bool(PJOB.get("stop")))
        with LOCK:
            if res.get("ok"):
                PJOB["state"] = "done"
                PJOB["result"] = res
            else:
                PJOB["state"] = "error"
                PJOB["error"] = res.get("error", "未知错误")
            PJOB["finished_at"] = time.time()
    except Exception as exc:  # noqa: BLE001
        diagnose._log_to_file(traceback.format_exc())
        with LOCK:
            PJOB["state"] = "error"
            PJOB["error"] = f"{type(exc).__name__}: {exc}"
            PJOB["finished_at"] = time.time()


def passive_start(payload: dict) -> dict:
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
                     "started_at": time.time(), "finished_at": 0, "stop": False})
    log(f"被动监听启动：网卡 {interface or '自动选择'}，{duration}s，"
        f"目标 {target or '全部流量'}，引擎 {engine}")
    threading.Thread(target=_passive_worker,
                     args=(interface, duration, target, engine), daemon=True).start()
    return {"ok": True, "engine": engine}


def passive_status() -> dict:
    with LOCK:
        snap = {k: PJOB[k] for k in ("state", "result", "error", "engine",
                                     "started_at", "finished_at")}
        running = PJOB["state"] == "running"
    snap["ok"] = True
    snap["engine_info"] = engine_info()
    snap["elapsed"] = round(time.time() - snap["started_at"], 1) if running and snap["started_at"] else 0
    return snap


class Handler(BaseHTTPRequestHandler):
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
    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in self.SECURITY_HEADERS:
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, data, code: int = 200) -> None:
        self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def log_message(self, fmt, *args):  # 静音，避免刷屏
        return

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
            if not raw:
                return {}
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (ValueError, OSError, UnicodeDecodeError):
            return {}

    def _drain(self, length: int) -> None:
        """丢弃剩余请求体，最多 64MB，超出直接断开。"""
        left = min(length, 64 << 20)
        try:
            while left > 0:
                chunk = self.rfile.read(min(1 << 20, left))
                if not chunk:
                    break
                left -= len(chunk)
        except OSError:
            pass
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
        try:
            self._route_get()
        except BodyTooLarge as exc:
            self._json({"ok": False, "error": str(exc)}, 413)
        except Exception as exc:  # noqa: BLE001
            diagnose._log_to_file(traceback.format_exc())
            self._json({"ok": False, "error": f"服务内部错误：{type(exc).__name__}: {exc}"}, 500)

    def do_POST(self):
        try:
            self._route_post()
        except BodyTooLarge as exc:
            self._json({"ok": False, "error": str(exc)}, 413)
        except Exception as exc:  # noqa: BLE001
            diagnose._log_to_file(traceback.format_exc())
            self._json({"ok": False, "error": f"服务内部错误：{type(exc).__name__}: {exc}"}, 500)

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
            return self._json({"ok": True, "app": APP_NAME, "version": APP_VERSION,
                               "pid": os.getpid(), "port": SERVER.get("port", 0),
                               "url": SERVER.get("url", ""),
                               "idle_exit_min": SERVER.get("idle_exit_min", 0),
                               "auto_quit": bool(SERVER.get("idle_exit_min", 0)),
                               "admin": tshark.is_admin(),
                               "auto_open_browser": bool(cfg.get("auto_open_browser", True))})
        if path in ("/", "/index.html"):
            f = UI_DIR / "index.html"
            if not f.is_file():
                return self._send(500, b"ui/index.html missing", "text/plain; charset=utf-8")
            return self._send(200, f.read_bytes(), "text/html; charset=utf-8")

        if path == "/api/status":
            with LOCK:
                data = dict(JOB)
            data["elapsed"] = round((data["finished_at"] or time.time()) - data["started_at"], 1) \
                if data["state"] in ("running", "done", "error") and data["started_at"] else 0
            return self._json(data)
        if path == "/api/interfaces":
            ifaces = [{**i, "short": tshark.short_name(i["name"])} for i in tshark.list_interfaces()]
            return self._json({"interfaces": ifaces, "admin": tshark.is_admin(),
                               "npcap": tshark.npcap_installed()})
        if path == "/api/captures":
            files = sorted(CAPTURES.glob("*.pcap*"), key=lambda p: p.stat().st_mtime, reverse=True)
            return self._json({"files": [{"name": p.name, "size": p.stat().st_size,
                                          "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))}
                                         for p in files[:50]]})
        if path == "/api/report":
            q = urllib.parse.parse_qs(parsed.query)
            name = (q.get("path") or [""])[0]
            target = (REPORTS / Path(name).name)
            if not target.is_file():
                return self._send(404, b"report not found", "text/plain; charset=utf-8")
            ctype = "text/markdown; charset=utf-8" if target.suffix == ".md" else "application/json; charset=utf-8"
            return self._send(200, target.read_bytes(), ctype)
        if path == "/api/doctor":
            return self._json(doctor_cached())
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
            return self._json(_probe_guarded(target, port, count, None, proto))
        return self._send(404, b"not found", "text/plain; charset=utf-8")

    def _route_post(self):
        touch()
        if not self._guard():
            return self._json({"ok": False, "error": "禁止外部页面访问本机服务"}, 403)
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/quit":
            request_quit("收到界面退出指令，正在停止本地服务…")
            return self._json({"ok": True, "message": "服务已停止，可以关闭本页面了"})

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
            with LOCK:
                PJOB["stop"] = True
            log("被动监听：收到停止指令，正在收尾…")
            return self._json({"ok": True})
        if parsed.path == "/api/probe":
            payload = self._read_json()
            target = (payload.get("target") or "").strip()
            if not target:
                return self._json({"ok": False, "error": "请填写要诊断的域名或 IP"})
            port = _to_int(payload.get("port"), None, 1, 65535)
            count = _to_int(payload.get("count"), 4, 1, 10)
            timeout = _to_float(payload.get("timeout"), 3.0, 0.5, 10.0)
            log(f"链路体检：{target}:{port or '默认端口'}")
            return self._json(_probe_guarded(target, port, count, timeout,
                                             payload.get("proto") or None))
        if parsed.path == "/api/scan":
            payload = self._read_json()
            return self._json(start_job(payload))
        if parsed.path == "/api/upload":
            q = urllib.parse.parse_qs(parsed.query)
            raw_name = Path((q.get("name") or ["upload.pcapng"])[0]).name
            safe = "".join(c for c in raw_name if c.isalnum() or c in "._-") or "upload.pcapng"
            if not safe.lower().endswith((".pcap", ".pcapng", ".cap")):
                return self._json({"ok": False, "error": "只接受 .pcap / .pcapng / .cap 文件"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0:
                return self._json({"ok": False, "error": "空文件"})
            if length > MAX_UPLOAD:
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
            except OSError:
                dest.unlink(missing_ok=True)
                raise
            if written == 0:
                dest.unlink(missing_ok=True)
                return self._json({"ok": False, "error": "上传中断，未收到数据"})
            return self._json({"ok": True, "file": dest.name, "size": dest.stat().st_size})
        return self._send(404, b"not found", "text/plain; charset=utf-8")


class DiagServer(ThreadingHTTPServer):
    """daemon_threads：关闭时不被长连接拖住。

    allow_reuse_address 必须为 False：Windows 上 SO_REUSEADDR 语义与 Unix 不同，
    置 True 会让两个进程同时绑上 8787，旧进程继续响应，改了代码却看不到效果。
    端口被占时由 create_server() 顺延到下一个端口。
    """

    daemon_threads = True
    allow_reuse_address = False


def create_server(port: int = 8787, idle_exit_min: int = 0,
                  quiet: bool = False, register_pid: bool = True) -> tuple[DiagServer | None, str]:
    """建监听。端口被占用时顺延最多 10 个，返回 (实例, 访问地址)。

    register_pid=False 供自测使用：避免测试实例覆盖正在运行的应用的 PID 文件。
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
        print(f"  USB-Net-Diag 已启动（v{APP_VERSION}）")
        print(f"  浏览器界面：{url}")
        print("  界面右上角「退出」可停止服务；关闭此窗口也会停止")
        print("=" * 62)
    return httpd, url


def main() -> int:
    cfg = diagnose.load_config()
    bootstrap.gen_configs()
    port = int(cfg.get("server_port", 8787))
    httpd, url = create_server(port)
    if httpd is None:
        print("[错误] 端口被占用，无法启动本地服务", file=sys.stderr)
        return 1
    if cfg.get("auto_open_browser", True):
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
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
