"""USB-Net-Diag 采集与诊断主流程（CLI 入口）。

用法：
  python diagnose.py --target 192.168.1.10 --duration 30
  python diagnose.py --pcap captures/diag_x.pcapng --target 192.168.1.10
  python diagnose.py --interfaces
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path

CORE = Path(__file__).resolve().parent
ROOT = CORE.parent
sys.path.insert(0, str(CORE))

import analyzer  # noqa: E402
import report  # noqa: E402
import tshark  # noqa: E402
import verdict  # noqa: E402

CAPTURES = ROOT / "captures"
REPORTS = ROOT / "reports"
LOGS = ROOT / "logs"
CONFIG = ROOT / "config" / "app-config.json"

DEFAULT_CONFIG = {
    "server_port": 8787,
    "default_duration": 30,
    "max_duration": 180,
    "threat_intel_key": "",
    "auto_open_browser": True,
    # 静默启动（NetDiag.vbs）时，界面超过这么多分钟没人访问就自动退出；
    # 设为 0 表示常驻不退（需自己结束进程）
    "idle_exit_min": 30,
}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        if CONFIG.is_file():
            cfg.update(json.loads(CONFIG.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return cfg


def _stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def _log_to_file(line: str) -> None:
    try:
        LOGS.mkdir(parents=True, exist_ok=True)
        with (LOGS / f"diag_{dt.date.today():%Y%m%d}.log").open("a", encoding="utf-8") as fh:
            fh.write(f"[{dt.datetime.now():%H:%M:%S}] {line}\n")
    except OSError:
        pass


def log(msg: str) -> None:
    print(msg, flush=True)
    _log_to_file(msg)


def bpf_for(target: str) -> str:
    """把目标转成 BPF 过滤器。只接受 IP / CIDR / 域名，避免把任意表达式喂给抓包器。"""
    t = (target or "").strip()
    if not t:
        return ""
    if len(t) > 200:
        raise ValueError("目标过长")
    if not all(c.isalnum() or c in ".:/-_" for c in t):
        raise ValueError("目标只能是 IP、网段(CIDR) 或域名，不要带空格与特殊符号")
    # 支持 CIDR 段
    if "/" in t:
        return f"net {t}"
    return f"host {t}"


def capture_live(target: str = "", duration: int = 30, interface: str | None = None,
                 logger=log) -> dict:
    """实时抓包，返回 {ok, pcap, interface, bpf} 或 {ok:False, error, degraded}。"""
    ts = tshark.find_tshark()
    if not ts:
        return {
            "ok": False,
            "degraded": True,
            "error": "未找到 tshark。请确认 tools/WiresharkPortable/App/Wireshark/tshark.exe 是否存在。",
        }
    if not tshark.npcap_installed():
        return {
            "ok": False,
            "degraded": True,
            "error": "Npcap 未安装或未生效，实时抓包不可用。请以管理员身份运行 start.bat 完成安装，"
                     "或改用“离线分析”上传已有 pcap 文件。",
        }

    interfaces = tshark.list_interfaces(ts)
    if not interfaces:
        return {"ok": False, "degraded": True,
                "error": "未枚举到可用网卡，请确认 Npcap 已安装且 tshark -D 可正常输出。"}

    iface = None
    if interface:
        if interface.isdigit():
            iface = next((i for i in interfaces if i["index"] == int(interface)), None)
        else:
            iface = next((i for i in interfaces if interface.lower() in i["name"].lower()), None)
    if not iface:
        picked = tshark.pick_interface(interfaces)
        ordered = ([picked] if picked else []) + [i for i in interfaces if i is not picked]
        logger("探测网卡流量（每块 2 秒），自动选择有流量的网卡 ...")
        iface = tshark.probe_interface(ts, ordered) or picked

    CAPTURES.mkdir(parents=True, exist_ok=True)
    pcap = CAPTURES / f"diag_{_stamp()}.pcapng"
    try:
        bpf = bpf_for(target)
    except ValueError as exc:
        return {"ok": False, "error": f"目标不合法：{exc}"}
    duration = max(3, min(int(duration or 30), 180))

    cmd = [str(ts), "-i", str(iface["index"]), "-w", str(pcap), "-a", f"duration:{duration}", "-q"]
    if bpf:
        cmd += ["-f", bpf]

    logger(f"开始抓包：网卡[{iface['index']}] {tshark.short_name(iface['name'])}，时长 {duration}s，过滤器 `{bpf or '无（全网）'}`")
    rc, out, err = tshark.run(cmd, timeout=duration + 120)

    msg = (err or "") + (out or "")
    if not pcap.exists() or pcap.stat().st_size == 0:
        low = msg.lower()
        if "permission" in low or "access is denied" in low or "not permitted" in low or "admin" in low:
            return {"ok": False, "degraded": True,
                    "error": "抓包权限不足（需要管理员权限 + Npcap 驱动）。请右键以管理员身份运行 start.bat，"
                             "或使用离线分析已有 pcap 文件。"}
        return {"ok": False, "degraded": True, "error": f"抓包失败(rc={rc}): {msg.strip()[:400]}"}

    logger(f"抓包完成：{pcap.name}（{pcap.stat().st_size / 1024:.0f} KB）")

    # tshark 退出 ≠ 数据已经全部落盘（杀软扫描 / 大文件缓存回写会滞后）。
    # 若此时立刻分析，tshark 会以 rc=14「cut short」读到一个残缺文件，
    # 结论随抓包尾部是否已落地而变——这就是「同一文件两次结论不同」的来源。
    if _wait_file_stable(pcap):
        logger("抓包文件已落盘稳定，开始分析")
    else:
        logger("[提示] 抓包文件 3 秒内仍在变化，分析可能读到不完整内容")

    return {"ok": True, "pcap": str(pcap), "interface": tshark.short_name(iface["name"]),
            "interface_index": iface["index"], "bpf": bpf or "无（全网）", "duration": duration}


def _wait_file_stable(path: Path, timeout: float = 3.0) -> bool:
    """等文件大小连续两次采样不变，确认写盘结束。

    Args:
        path: 要观察的文件；不存在时直接返回 False。
        timeout: 最长等待秒数，默认 3.0（抓包刚结束时通常 0.2s 内就稳定）。

    Returns:
        True 表示已稳定（或本来就是静默的只读文件）；False 表示超时仍在变化。

    Raises:
        不抛异常。读不到文件（盘符消失、权限不足）按「未稳定」处理。
    """
    deadline = time.monotonic() + timeout
    last = -1
    while time.monotonic() < deadline:
        try:
            size = path.stat().st_size
        except OSError:
            return False
        if size == last:
            return True
        last = size
        time.sleep(0.15)
    return False



def run_scan(target: str = "", duration: int = 30, interface: str | None = None,
             pcap: str | None = None, logger=log) -> dict:
    """完整诊断：抓包(或复用) → 分析 → 落盘报告。"""
    cfg = load_config()
    cap: dict = {"ok": True, "bpf": "离线分析", "interface": "-", "duration": 0}
    if pcap:
        p = Path(pcap)
        # 支持 U 盘盘符变化：只给文件名时回落到 captures/
        if not p.is_absolute() and not p.exists():
            p = CAPTURES / p.name
        if not p.is_file():
            return {"ok": False, "error": f"抓包文件不存在: {pcap}"}
        cap["pcap"] = str(p)
    else:
        cap = capture_live(target, duration, interface, logger=logger)
        if not cap.get("ok"):
            return {"ok": False, "error": cap.get("error", "抓包失败"), "degraded": cap.get("degraded", False)}

    logger("开始分析报文 ...")
    result = analyzer.analyze(cap["pcap"], target=target, ti_key=cfg.get("threat_intel_key", ""), log=logger)
    if not result.get("ok"):
        return result

    result["meta"]["interface"] = cap.get("interface", "-")
    result["meta"]["bpf"] = cap.get("bpf", "-")
    result["meta"]["capture_duration"] = cap.get("duration", 0)

    if result["meta"]["packets"] == 0:
        result["rows"].insert(0, {
            "category": "采集有效性",
            "finding": "抓包周期内未捕获任何报文，可能选错网卡或过滤器过严",
            "severity": "警告",
            "evidence": f"网卡 {result['meta']['interface']}，过滤器 {result['meta']['bpf']}",
            "advice": "在网卡下拉框中手动切换有业务流量的网卡后重试",
        })
        result["summary"]["warning_count"] = sum(1 for r in result["rows"] if r["severity"] == "警告")
        result["summary"]["critical_count"] = sum(1 for r in result["rows"] if r["severity"] == "严重")

    result["verdict"] = verdict.build(result)
    paths = report.save(result, REPORTS)
    result["report"] = paths
    logger(f"报告已生成：{paths['markdown']}")

    c = result["summary"]["critical_count"]
    w = result["summary"]["warning_count"]
    logger(f"诊断完成：严重 {c} 项，警告 {w} 项")
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="USB-Net-Diag 网络诊断")
    ap.add_argument("--target", default="", help="目标 IP 或 CIDR 网段，留空表示全网扫描")
    ap.add_argument("--duration", type=int, default=load_config()["default_duration"])
    ap.add_argument("--interface", default=None, help="网卡序号或名称关键字")
    ap.add_argument("--pcap", default=None, help="离线分析指定 pcap 文件")
    ap.add_argument("--interfaces", action="store_true", help="列出可用网卡")
    ap.add_argument("--json", action="store_true", help="仅输出 JSON 摘要")
    args = ap.parse_args(argv)

    if args.interfaces:
        for i in tshark.list_interfaces():
            print(f"{i['index']}. {i['name']}")
        print(f"\ntshark: {tshark.version()}")
        return 0

    res = run_scan(args.target, args.duration, args.interface, args.pcap)
    if not res.get("ok"):
        print(f"[错误] {res.get('error')}", file=sys.stderr)
        if res.get("degraded"):
            print("[降级] 可执行：python diagnose.py --pcap <已有抓包文件> 进行离线分析", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(res["summary"], ensure_ascii=False))
    else:
        print("\n" + report.render_markdown(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
