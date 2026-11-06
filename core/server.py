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
"""
from __future__ import annotations

import json
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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
    with LOCK:
        if JOB["state"] == "running":
            return {"ok": False, "error": "已有诊断任务在执行，请等待完成"}
        mode = payload.get("mode") or "live"
        target = (payload.get("target") or "").strip()
        duration = int(payload.get("duration") or 30)
        interface = payload.get("interface") or None
        pcap = payload.get("pcap") or None
        if mode == "offline" and not pcap:
            return {"ok": False, "error": "离线分析需要指定抓包文件"}

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
    server_version = "USBNetDiag/0.1.0"

    # ---------- helpers ----------
    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
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
            if length <= 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, OSError):
            return {}

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
        if not self._guard():
            return self._json({"ok": False, "error": "禁止外部页面访问本机服务"}, 403)
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
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
            return self._json(bootstrap.check(verbose=False))
        if path == "/api/passive":
            return self._json(passive_status())
        if path == "/api/ai":
            return self._json(ai.public_config())
        if path == "/api/probe":
            q = urllib.parse.parse_qs(parsed.query)
            target = (q.get("target") or [""])[0].strip()
            if not target:
                return self._json({"ok": False, "error": "请提供 target 参数，例如 /api/probe?target=example.com"})
            port = (q.get("port") or [None])[0]
            return self._json(probe.run(
                target,
                port=int(port) if port and port.isdigit() else None,
                count=int((q.get("count") or ["4"])[0] or 4),
                proto=(q.get("proto") or [None])[0],
            ))
        return self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if not self._guard():
            return self._json({"ok": False, "error": "禁止外部页面访问本机服务"}, 403)
        parsed = urllib.parse.urlparse(self.path)
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
            port = payload.get("port")
            try:
                port = int(port) if port not in (None, "", 0, "0") else None
            except (TypeError, ValueError):
                port = None
            log(f"链路体检：{target}:{port or '默认端口'}")
            return self._json(probe.run(
                target, port=port,
                count=max(1, min(int(payload.get("count") or 4), 10)),
                timeout=max(0.5, min(float(payload.get("timeout") or 3), 10)),
                proto=(payload.get("proto") or None),
            ))
        if parsed.path == "/api/scan":
            payload = self._read_json()
            return self._json(start_job(payload))
        if parsed.path == "/api/upload":
            q = urllib.parse.parse_qs(parsed.query)
            raw_name = Path((q.get("name") or ["upload.pcapng"])[0]).name
            safe = "".join(c for c in raw_name if c.isalnum() or c in "._-") or "upload.pcapng"
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return self._json({"ok": False, "error": "空文件"})
            CAPTURES.mkdir(parents=True, exist_ok=True)
            dest = CAPTURES / f"upload_{time.strftime('%Y%m%d_%H%M%S')}_{safe}"
            remaining = length
            with dest.open("wb") as fh:
                while remaining > 0:
                    chunk = self.rfile.read(min(1 << 20, remaining))
                    if not chunk:
                        break
                    fh.write(chunk)
                    remaining -= len(chunk)
            return self._json({"ok": True, "file": dest.name, "size": dest.stat().st_size})
        return self._send(404, b"not found", "text/plain; charset=utf-8")


def main() -> int:
    cfg = diagnose.load_config()
    bootstrap.gen_configs()
    port = int(cfg.get("server_port", 8787))
    url = f"http://127.0.0.1:{port}/"

    httpd = None
    for p in range(port, port + 10):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            url = f"http://127.0.0.1:{p}/"
            break
        except OSError:
            continue
    if httpd is None:
        print("[错误] 端口被占用，无法启动本地服务", file=sys.stderr)
        return 1

    print("=" * 62)
    print("  USB-Net-Diag 已启动")
    print(f"  浏览器界面：{url}")
    print("  关闭此窗口即停止服务")
    print("=" * 62)
    if cfg.get("auto_open_browser", True):
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
