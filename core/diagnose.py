"""NetDiag（网络矩阵）采集与诊断主流程（CLI 入口）。

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
import diagpack  # noqa: E402
import logstore  # noqa: E402
import report  # noqa: E402
import tshark  # noqa: E402
import verdict  # noqa: E402

CAPTURES = ROOT / "captures"
REPORTS = ROOT / "reports"
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
    """读 ``config/app-config.json``（本模块自带的极简版本）。

    Returns:
        dict: 默认值叠加文件内容。与 :func:`core.config.load_app` 的区别是不做类型收敛 ——
            这是历史入口，收敛逻辑在新模块里（两者结果在正常配置下一致）。
    """
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
    """把一行日志交给 :mod:`logstore`（保留旧调用方，签名不变）。

    Args:
        line: 日志正文；多行（traceback）会逐行加时间前缀。

    Returns:
        None: 写盘失败只影响日志，不影响诊断。
    """
    logstore.diag_log(line)


def log(msg: str) -> None:
    """默认日志回调：打印到控制台，同时追加到 ``logs/diag-YYYYMMDD.log``。

    Args:
        msg: 日志正文。

    Returns:
        None: 写盘失败只影响日志，不影响诊断。
    """
    print(msg, flush=True)
    _log_to_file(msg)


def bpf_for(target: str) -> str:
    """把目标转成 BPF 过滤器表达式。

    只接受 IP / CIDR / 域名，其它字符一律拒绝 —— 过滤器最终会进 tshark 命令行，
    放任任意表达式等于把抓包器变成可编程工具。

    Args:
        target: 用户输入的目标，如 ``192.168.1.10`` / ``10.0.0.0/24`` / ``example.com``。

    Returns:
        str: 可用的 BPF 串；空目标返回空串（表示抓全网）。

    Raises:
        ValueError: 目标含非法字符，或长度超过 200 个字符（由调用方转成可展示的错误）。
    """
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


def _capture_candidates(chosen: dict, ordered: list[dict], limit: int = 3) -> list[dict]:
    """给出「首选网卡 + 后续候选」的尝试顺序（按网卡序号去重）。

    Args:
        chosen: 首选网卡（探测命中的那块，或 ``pick_interface`` 的兜底结果）。
        ordered: :func:`tshark.order_interfaces` 的候选顺序（物理优先、虚拟靠后）。
        limit: 最多尝试几块，默认 3（首次 + 最多两次换卡重试）。

    Returns:
        list[dict]: 首项必为 ``chosen``，其余按 ``ordered`` 顺序补齐；
            按 ``index`` 去重后截断到 ``limit``。
    """
    plan = [chosen]
    seen = {chosen.get("index")}
    for item in ordered:
        if len(plan) >= limit:
            break
        index = item.get("index")
        if index in seen:
            continue
        plan.append(item)
        seen.add(index)
    return plan


def _pcap_has_packets(ts: Path, pcap: Path) -> bool:
    """判断刚抓完的 pcap 里到底有没有报文（0 包和 0 字节都算空）。

    抓包进程正常退出、文件也有几 KB，不代表抓到了流量：tshark 对 0 包也会写
    pcapng 文件头（约 444 B）。所以不能只看文件大小，要真的读一帧出来。

    Args:
        ts: tshark 可执行文件路径。
        pcap: 待检查的抓包文件。

    Returns:
        bool: 文件不存在、0 字节或读不出第一帧时返回 ``False``；只读第一帧
            （``-c 1``），大文件也不会被整份读进内存。
    """
    try:
        if pcap.stat().st_size <= 0:
            return False
    except OSError:
        return False
    rc, out, _ = tshark.run(
        [str(ts), "-r", str(pcap), "-c", "1", "-T", "fields", "-e", "frame.number"],
        timeout=60,
    )
    return rc == 0 and bool((out or "").strip())


def _capture_empty_error(plan: list[dict], duration: int, bpf: str) -> str:
    """构造「候选网卡全都没抓到包」的错误文案（可直接照着操作）。

    Args:
        plan: 本轮实际尝试过的网卡列表。
        duration: 每块网卡抓了多少秒。
        bpf: 本次使用的 BPF 过滤器；空串表示全网。

    Returns:
        str: 中文错误说明，含 ``--interfaces`` / ``--interface`` 自助命令，
            以及「网卡未连接」和「流量走了 VPN 虚拟网卡」两类常见原因。
    """
    names = "、".join(f"{tshark.short_name(i['name'])}[{i['index']}]" for i in plan)
    if len(plan) == 1:
        lead = f"网卡 {names} 在 {duration} 秒内没有捕获到任何报文"
    else:
        lead = (f"连续 {len(plan)} 块候选网卡（{names}）在 {duration} 秒内都没有"
                "捕获到任何报文")
    reasons = ("常见原因：1) 选中的网卡未连接或没有业务流量（例如已断开的以太网口）；"
               "2) 流量走了 VPN / 代理的虚拟网卡（如 mihomo(Clash Meta) 的 Meta/TUN 网卡），"
               "物理网卡上可能看不到业务报文。")
    hint = ("请运行 `python core\\diagnose.py --interfaces` 查看网卡列表，"
            "再用 `--interface <序号>` 指定真正有流量的网卡后重试。")
    if bpf:
        hint += f" 当前还设置了过滤器 `{bpf}`，可先去掉 `--target` 抓全网确认网卡是否选对。"
    return f"{lead}。{reasons}{hint}"


def capture_live(target: str = "", duration: int = 30, interface: str | None = None,
                 logger=log) -> dict:
    """实时抓包并落盘到 ``captures/``。

    Args:
        target: 抓包目标（转成 BPF）；空表示全网。
        duration: 抓包秒数。
        interface: 网卡序号或名称关键字；空则按 :func:`tshark.order_interfaces`
            的候选顺序逐块探测（每块 2 秒、最多 5 块），取第一块真有流量的；
            全都没流量再用 :func:`tshark.pick_interface` 兜底。显式指定时先抓该网卡，
            若它 0 包仍会按候选顺序换卡重试。
        logger: 日志回调。

    Returns:
        dict: 成功 ``{"ok": True, "pcap": str, "interface": str, "interface_index": int,
            "bpf": str, "duration": int}``；失败 ``{"ok": False, "error": str,
            "degraded": bool}``，``degraded=True`` 表示「缺 tshark/Npcap/提权」这类
            环境问题，前端据此提示改用离线分析。抓满 0 包/0 字节时不直接失败，
            会按候选顺序自动换卡重试（最多 3 块）；全失败时错误里带
            ``--interfaces`` / ``--interface`` 指引与常见原因。

    Note:
        返回前会等文件大小稳定（最多 3 秒）。tshark 进程退出 ≠ 数据已落盘，
        在写盘窗口期就开始分析会读到半份数据，进而产生幻影告警（T00）。
        0 包的空抓包文件会被删除，避免在 ``captures/`` 留下无法分析的垃圾。
    """
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

    ordered = tshark.order_interfaces(interfaces)
    iface = None
    if interface:
        if interface.isdigit():
            iface = next((i for i in interfaces if i["index"] == int(interface)), None)
        else:
            iface = next((i for i in interfaces if interface.lower() in i["name"].lower()), None)
    if not iface:
        # 先按候选顺序真实抓 2 秒；名字只能猜（以太网可能没插网线），流量不会说谎。
        logger("探测网卡流量（每块 2 秒，最多 5 块），自动选择有流量的网卡 ...")
        iface = tshark.probe_interface(ts, ordered) or tshark.pick_interface(interfaces)
    if iface is None:
        return {"ok": False, "degraded": True, "error": "未枚举到可用网卡。"}

    try:
        bpf = bpf_for(target)
    except ValueError as exc:
        return {"ok": False, "error": f"目标不合法：{exc}"}
    duration = max(3, min(int(duration or 30), 180))
    CAPTURES.mkdir(parents=True, exist_ok=True)

    plan = _capture_candidates(iface, ordered, limit=3)
    failures: list[str] = []
    for attempt, cand in enumerate(plan, 1):
        pcap = CAPTURES / f"diag_{_stamp()}.pcapng"
        cmd = [str(ts), "-i", str(cand["index"]), "-w", str(pcap),
               "-a", f"duration:{duration}", "-q"]
        if bpf:
            cmd += ["-f", bpf]

        prefix = f"（第 {attempt}/{len(plan)} 块）" if len(plan) > 1 else ""
        logger(f"开始抓包{prefix}：网卡[{cand['index']}] "
               f"{tshark.short_name(cand['name'])}，时长 {duration}s，"
               f"过滤器 `{bpf or '无（全网）'}`")
        rc, out, err = tshark.run(cmd, timeout=duration + 120)
        msg = (err or "") + (out or "")

        try:
            size = pcap.stat().st_size
        except OSError:
            size = 0
        if size == 0:
            low = msg.lower()
            if ("permission" in low or "access is denied" in low
                    or "not permitted" in low or "admin" in low):
                return {"ok": False, "degraded": True,
                        "error": "抓包权限不足（需要管理员权限 + Npcap 驱动）。请右键以管理员身份运行 start.bat，"
                                 "或使用离线分析已有 pcap 文件。"}
            failures.append(f"{tshark.short_name(cand['name'])}[{cand['index']}] 0 字节(rc={rc})")
            logger(f"[提示] 网卡[{cand['index']}] 没有生成有效抓包（rc={rc}），"
                   "自动换下一块候选网卡重试 ...")
            continue

        # tshark 退出 ≠ 数据已经全部落盘（杀软扫描 / 大文件缓存回写会滞后）。
        # 若此时立刻分析，tshark 会以 rc=14「cut short」读到一个残缺文件，
        # 结论随抓包尾部是否已落地而变——这就是「同一文件两次结论不同」的来源。
        stable = _wait_file_stable(pcap)
        # 0 包也会写 ~444 B 的 pcapng 头：文件非空不代表抓到了流量，必须真读一帧。
        if not _pcap_has_packets(ts, pcap):
            failures.append(f"{tshark.short_name(cand['name'])}[{cand['index']}] 0 包")
            logger(f"[提示] 网卡[{cand['index']}] {tshark.short_name(cand['name'])} "
                   f"在 {duration} 秒内未捕获到报文，自动换下一块候选网卡重试 ...")
            try:
                pcap.unlink()
            except OSError:
                pass
            continue

        logger(f"抓包完成：{pcap.name}（{size / 1024:.0f} KB）")
        if stable:
            logger("抓包文件已落盘稳定，开始分析")
        else:
            logger("[提示] 抓包文件 3 秒内仍在变化，分析可能读到不完整内容")

        return {"ok": True, "pcap": str(pcap), "interface": tshark.short_name(cand["name"]),
                "interface_index": cand["index"], "bpf": bpf or "无（全网）",
                "duration": duration}

    error = _capture_empty_error(plan, duration, bpf)
    if failures:
        error += f"（各网卡结果：{'；'.join(failures)}）"
    return {"ok": False, "degraded": True, "error": error}


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
             pcap: str | None = None, logger=log,
             report_dir: str | Path | None = None) -> dict:
    """完整诊断：抓包（或复用已有 pcap）→ 分析 → 落盘报告 → 记一条 run。

    Args:
        target: 目标 IP/网段/域名；空表示全网。
        duration: 实时抓包秒数（仅无 ``pcap`` 时生效）。
        interface: 网卡序号或名称关键字。
        pcap: 离线分析的抓包路径。只给文件名时会到 ``captures/`` 下找
            （兼容 U 盘盘符变化）。
        logger: 日志回调。
        report_dir: 报告输出目录；``None``（默认）写 ``reports/``，与历史行为一致。
            给定时只写该目录（目录不存在会自动创建），文件名清洗仍由
            :func:`report.save` 负责。

    Returns:
        dict: ``analyzer.analyze()`` 的结果，另加 ``report``（``.md``/``.json`` 落盘路径）
            与 ``capture``（本次采集参数）。失败时 ``{"ok": False, "error": "..."}``。

    Note:
        无论成功、失败还是抛异常，都会调用一次 :func:`logstore.record_run`
        （``mode`` 为 ``offline`` / ``live``）。UI 的 ``/api/scan`` 也走本函数，
        所以两个入口共用同一个记录点，一次分析只有一条记录。
    """
    started = time.monotonic()
    mode = "offline" if pcap else "live"
    params = _run_params(target, duration, interface, pcap)
    try:
        result = _run_scan(target=target, duration=duration, interface=interface,
                           pcap=pcap, logger=logger, report_dir=report_dir)
    except Exception:
        _record_run(mode, params, started, {"ok": False}, error_code="E_INTERNAL")
        raise
    _record_run(mode, params, started, result)
    return result


def _run_params(target: str, duration: int, interface: str | None,
                pcap: str | None) -> dict:
    """组装 run 记录里的 ``params``：只留目标/时长/网卡与 pcap 文件名，不写绝对路径。"""
    params = {
        "target": (target or "")[:300],
        "duration": int(duration or 0),
        "interface": str(interface)[:120] if interface else "",
    }
    if pcap:
        params["pcap"] = Path(str(pcap)).name
    return params


def _tshark_version() -> str:
    """取本次运行使用的 tshark 版本串（找不到时返回提示语）。"""
    try:
        return tshark.version()
    except Exception:  # noqa: BLE001
        return ""


def _error_code(result: dict) -> str:
    """把失败结果归类成稳定错误码（写进 run 记录的 ``error_code``）。"""
    message = str(result.get("error") or "")
    lowered = message.lower()
    if "未找到 tshark" in message:
        return "E_NO_TSHARK"
    if "npcap" in lowered:
        return "E_NO_NPCAP"
    if "权限不足" in message or "permission" in lowered or "access is denied" in lowered:
        return "E_NO_ADMIN"
    if "网卡" in message and result.get("degraded"):
        return "E_NO_INTERFACE"
    if "不存在" in message or "not found" in lowered:
        return "E_BAD_PCAP"
    return "E_INTERNAL"


def _record_run(mode: str, params: dict, started: float, result: dict,
                error_code: str | None = None) -> None:
    """把一次分析的结果写成 ``runs/*.json``；任何失败都吞掉（日志不影响业务）。"""
    try:
        result = result or {}
        ok = bool(result.get("ok"))
        summary = result.get("summary") or {}
        verdict_data = result.get("verdict") or {}
        sufficiency = (verdict_data.get("sufficiency")
                       if isinstance(verdict_data, dict) else None)
        record = {
            "mode": mode,
            "params": dict(params or {}),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "level": str(verdict_data.get("level") or "") if ok else "",
            "critical": int(summary.get("critical_count") or 0),
            "warning": int(summary.get("warning_count") or 0),
            "sufficiency_ok": bool(sufficiency.get("ok"))
            if isinstance(sufficiency, dict) else False,
            "error_code": (error_code if error_code is not None
                           else ("" if ok else _error_code(result))),
            "tshark_version": _tshark_version(),
            "ok": ok,
        }
        logstore.record_run(record)
    except Exception:  # noqa: BLE001
        pass


def _run_scan(target: str = "", duration: int = 30, interface: str | None = None,
              pcap: str | None = None, logger=log,
              report_dir: str | Path | None = None) -> dict:
    """``run_scan`` 的实现体（拆出来是为了让记录逻辑只包一层、不散落在每个 return）。"""
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
    out_dir = Path(report_dir) if report_dir else REPORTS
    paths = report.save(result, out_dir)
    result["report"] = paths
    logger(f"报告已生成：{paths['markdown']}")

    c = result["summary"]["critical_count"]
    w = result["summary"]["warning_count"]
    logger(f"诊断完成：严重 {c} 项，警告 {w} 项")
    return result


def _export_diag(args) -> int:
    """导出诊断包并打印结果（``--export-diag`` 的实现体）。

    Args:
        args: ``argparse`` 解析结果，读取 ``out`` / ``include_reports`` / ``raw``。

    Returns:
        int: 0 表示成功；1 表示输出目录不可写等失败（错误信息写 stderr）。
    """
    try:
        path = diagpack.build(out_dir=args.out, include_reports=args.include_reports,
                              raw=args.raw)
    except Exception as exc:  # noqa: BLE001  命令行入口只报错，不吐栈
        print(f"[错误] 导出诊断包失败：{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"诊断包已生成：{path}")
    try:
        print(f"包体积：{path.stat().st_size / 1024:.0f} KB")
    except OSError:
        pass
    if args.raw:
        # SPEC V6：--raw 必须控制台 + README 双警告，不能只在包里写。
        print("[警告] --raw 已生效：本包未脱敏，含原始 IP/域名/用户名/MAC，"
              "只允许发给可信任的维护者！", file=sys.stderr)
    else:
        print("已脱敏：包内 IP/域名/用户名/MAC 均替换为不可还原的伪名。")
    print("请把这个文件发回给维护者（工具不会自动上传任何数据）。")
    return 0


def main(argv: list[str] | None = None) -> int:
    """``diagnose.py`` 的命令行入口（不开界面也能出报告）。

    Args:
        argv: 参数列表；省略时取 ``sys.argv[1:]``。支持 ``--target`` / ``--duration`` /
            ``--interface`` / ``--pcap`` / ``--interfaces``（只列网卡）/ ``--json``（只打摘要）/
            ``--report-out``（把完整报告**只**写指定目录、**不再写** ``reports/``；
            省略时仍写 ``reports/``）/ ``--export-diag``（导出脱敏诊断包后退出，
            可配 ``--include-reports`` / ``--raw`` / ``--out``）。

    Returns:
        int: 0 成功；2 分析失败（如抓包文件不完整）；其它非 0 表示环境问题。
    """
    ap = argparse.ArgumentParser(description="NetDiag 网络诊断")
    ap.add_argument("--target", default="", help="目标 IP 或 CIDR 网段，留空表示全网扫描")
    ap.add_argument("--duration", type=int, default=load_config()["default_duration"])
    ap.add_argument("--interface", default=None, help="网卡序号或名称关键字")
    ap.add_argument("--pcap", default=None, help="离线分析指定 pcap 文件")
    ap.add_argument("--interfaces", action="store_true", help="列出可用网卡")
    ap.add_argument("--json", action="store_true", help="仅输出 JSON 摘要")
    ap.add_argument("--report-out", default=None, metavar="DIR",
                    help="只写该目录（不再写 reports/）：把完整报告 .md/.json "
                         "导出到指定目录；省略时仍写 reports/")
    ap.add_argument("--export-diag", action="store_true",
                    help="导出诊断包（zip）后退出，不执行抓包/分析；默认脱敏")
    ap.add_argument("--include-reports", action="store_true",
                    help="诊断包内附最近 3 份报告（.md/.json）")
    ap.add_argument("--raw", action="store_true",
                    help="诊断包不做脱敏（危险：保留原始 IP/域名/用户名/MAC）")
    ap.add_argument("--out", default=None, metavar="DIR",
                    help="诊断包输出目录；省略时写 logs/exports/")
    args = ap.parse_args(argv)

    # 日志基建（CLI 也是一次「启动」）：目录 → 裁剪 → 环境快照 → 崩溃钩子。
    # 放在 parse_args 之后：--help 不该在仓库里留下日志。
    logstore.ensure_dirs()
    logstore.prune()
    logstore.write_env_snapshot({"entry": "diagnose"})
    logstore.install_excepthooks()

    if args.export_diag:
        return _export_diag(args)

    if args.interfaces:
        for i in tshark.list_interfaces():
            print(f"{i['index']}. {i['name']}")
        print(f"\ntshark: {tshark.version()}")
        return 0

    res = run_scan(args.target, args.duration, args.interface, args.pcap,
                   report_dir=args.report_out)
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
