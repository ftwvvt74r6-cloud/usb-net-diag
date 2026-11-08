"""NetDiag（网络矩阵）采集与诊断主流程（CLI 入口）。

用法：
  python diagnose.py --target 192.168.1.10 --duration 30
  python diagnose.py --pcap captures/diag_x.pcapng --target 192.168.1.10
  python diagnose.py --interfaces
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import socket
import sys
import time
from pathlib import Path

CORE = Path(__file__).resolve().parent
ROOT = CORE.parent
sys.path.insert(0, str(CORE))
sys.path.insert(0, str(ROOT))

from core.platform import winapi  # noqa: E402

import analyzer  # noqa: E402
import diagpack  # noqa: E402
import logstore  # noqa: E402
import pathprobe  # noqa: E402
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


def _harden_console() -> None:
    """让 CLI 在 cp936(GBK) 等窄编码控制台下「编不出也不崩」（只改 errors）。

    中文 Windows 控制台默认 cp936，而报告里的 ``❌`` / ``✅`` 不在 GBK 字符集里：
    :func:`main` 打印完整报告时会抛 ``UnicodeEncodeError``，把一次已经成功、
    报告也已落盘的诊断变成 exit 1。这里在打印任何内容之前把 ``errors`` 改成
    ``backslashreplace``：能编码的中文照旧按原编码输出，编不出的 emoji 变成
    ``\\u274c`` 这样的可见转义——不丢字符、不误导，也不抛异常。

    选 ``backslashreplace`` 而不是 ``replace``：前者保留了「哪个字符没编出来」的
    信息（可检索、可反查），后者只剩 ``?``，排障时分不清丢的是 emoji 还是别的
    字符。两者都不会崩，但前者的证据更完整，也符合本任务「emoji 可显示为
    ``\\u274c``」的验收口径。

    Note:
        只改 ``errors``、不传 ``encoding``，保留控制台当前编码（cp936 下中文照常
        显示）。没有 ``reconfigure`` 的流（测试的 ``StringIO``、重定向包装器）直接
        跳过；流为 ``None``（pythonw / VBS 无控制台）或重配置失败也只跳过——兜底
        逻辑本身绝不能在入口抛错。报告文件仍由 :func:`report.save` 以 UTF-8 原文
        落盘，不受这里影响。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="backslashreplace")
        except Exception:  # noqa: BLE001  入口兜底失败只能跳过，不能反过来崩
            continue


def log(msg: str) -> None:
    """默认日志回调：打印到控制台，同时追加到 ``logs/diag-YYYYMMDD.log``。

    Args:
        msg: 日志正文。

    Returns:
        None: 写盘失败只影响日志，不影响诊断。
    """
    print(msg, flush=True)
    _log_to_file(msg)


# 抓包阶段**不能**当作公网地址的网段。198.18.0.0/15 必须单列：mihomo/Clash
# 的 fake-ip 就落在这里，它只是域名在代理里的假地址，拿它做 host 过滤必然 0 包。
_NON_PUBLIC_NETS = [
    (ipaddress.ip_network("0.0.0.0/8"), "无效地址"),
    (ipaddress.ip_network("10.0.0.0/8"), "私网地址"),
    (ipaddress.ip_network("100.64.0.0/10"), "运营商级 NAT 地址"),
    (ipaddress.ip_network("127.0.0.0/8"), "回环地址"),
    (ipaddress.ip_network("169.254.0.0/16"), "链路本地地址"),
    (ipaddress.ip_network("172.16.0.0/12"), "私网地址"),
    (ipaddress.ip_network("192.0.0.0/24"), "保留地址"),
    (ipaddress.ip_network("192.0.2.0/24"), "文档示例地址"),
    (ipaddress.ip_network("192.168.0.0/16"), "私网地址"),
    (ipaddress.ip_network("198.18.0.0/15"), "代理假 IP 段"),
    (ipaddress.ip_network("198.51.100.0/24"), "文档示例地址"),
    (ipaddress.ip_network("203.0.113.0/24"), "文档示例地址"),
    (ipaddress.ip_network("224.0.0.0/4"), "组播地址"),
    (ipaddress.ip_network("240.0.0.0/4"), "保留地址"),
    (ipaddress.ip_network("::/128"), "未指定地址"),
    (ipaddress.ip_network("::1/128"), "回环地址"),
    (ipaddress.ip_network("fc00::/7"), "IPv6 唯一本地地址(ULA)"),
    (ipaddress.ip_network("fe80::/10"), "IPv6 链路本地地址"),
    (ipaddress.ip_network("ff00::/8"), "IPv6 组播地址"),
    (ipaddress.ip_network("2001:db8::/32"), "文档示例地址"),
]


def _non_public_reason(ip: str) -> str:
    """判断一个 IP 为什么不能作为抓包阶段的 host 目标。

    Args:
        ip: 待判断的 IPv4/IPv6 字符串。

    Returns:
        str: 非公网原因（如 ``代理假 IP 段`` / ``私网地址``）；公网地址返回空串。
            解析不了的值返回 ``不是有效 IP``。
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return "不是有效 IP"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    for net, label in _NON_PUBLIC_NETS:
        if addr.version == net.version and addr in net:
            return label
    return ""


def _network_non_public_reason(
        net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    """判断一个网段为什么不能整段作为抓包过滤器。

    抓包阶段的 ``net`` 过滤只对**公网 CIDR** 有意义；私网 / fake-ip / 回环等
    网段一旦下过滤，很可能只抓到噪声（甚至 0 包）。这类目标改为抓全网，分析
    阶段再按用户目标筛选 —— 与「尽量抓到东西」的目标一致。

    Args:
        net: :mod:`ipaddress` 的网络对象（IPv4 或 IPv6）。

    Returns:
        str: 非公网原因（如 ``私网地址`` / ``代理假 IP 段``）；整段都是公网时返回空串。
    """
    for bad, label in _NON_PUBLIC_NETS:
        if net.version == bad.version and net.overlaps(bad):
            return label
    return ""


def _resolve_ips(host: str) -> list[str]:
    """把域名解析成去重后的 IP 列表（IPv4 在前）。

    单独抽成函数是为了让单测能替换 DNS（不联网也能覆盖 fake-ip/私网/公网分支）。

    Args:
        host: 域名，如 ``baidu.com``。

    Returns:
        list[str]: 去重后的 IP 字符串；解析失败返回 ``[]``（不抛异常）。
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    ips: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in ips:
            ips.append(ip)
    # IPv4 优先：代理环境里 AAAA 常被丢弃，先尝试 IPv4 更接近真实业务流量。
    ips.sort(key=lambda value: 0 if ":" not in value else 1)
    return ips


def capture_filter_for(target: str, logger=None) -> dict:
    """决定「单目标诊断（定向抓包）」阶段到底用不用 BPF 过滤器。

    路测根因：``-f "host baidu.com"`` 在 tshark 里会先把域名解析成 IP，而 mihomo
    的 fake-ip（198.18.0.0/15）并不是真实业务地址，过滤后 0 包。因此只有**解析
    结果全部是公网地址**时才用 ``host <ip>``；fake-ip / 私网 / 解析失败 / 无法
    表达的目标一律不加抓包过滤器（抓全网），分析阶段仍按用户目标筛选。

    Args:
        target: 用户输入的目标，如 ``192.168.1.10`` / ``192.168.1.0/24`` /
            ``baidu.com``；空串表示全网。
        logger: 日志回调；省略时不打印。

    Returns:
        dict: 键 ``bpf``（最终过滤器，空串=无过滤）/ ``kind``（``none`` /
            ``ip`` / ``cidr`` / ``domain``）/ ``resolved``（域名解析出的 IP 列表）/
            ``reason``（决策原因）。只有**公网** IP、域名、CIDR 才会下过滤器；
            私网 / fake-ip / 回环等目标一律抓全网，分析阶段再按目标筛。
    """
    log = logger or (lambda _message: None)
    t = (target or "").strip()
    if not t:
        return {"bpf": "", "kind": "none", "resolved": [], "reason": "未指定目标"}
    if len(t) > 200:
        raise ValueError("目标过长")
    if not all(c.isalnum() or c in ".:/-_" for c in t):
        raise ValueError("目标只能是 IP、网段(CIDR) 或域名，不要带空格与特殊符号")

    # 1) 纯 IP：只有公网地址才下 host 过滤。私网 / fake-ip / 回环等目标在代理或
    #    TUN 环境里经常对不上真实流量，下了过滤反而 0 包 —— 抓全网，分析阶段筛。
    try:
        addr = ipaddress.ip_address(t)
    except ValueError:
        addr = None
    if addr is not None:
        non_public = _non_public_reason(str(addr))
        if non_public:
            log(f"[提示] 目标 {t} 是{non_public}，抓包阶段不做 host 过滤（抓全网），"
                "分析阶段再按目标筛选")
            return {"bpf": "", "kind": "ip", "resolved": [str(addr)],
                    "reason": f"{non_public}，抓全网分析阶段筛选"}
        bpf = f"host {addr}"
        log(f"[提示] 目标 {t} 是公网 IP 地址，抓包阶段使用 {bpf}")
        return {"bpf": bpf, "kind": "ip", "resolved": [str(addr)], "reason": "公网 IP"}

    # 2) CIDR：只有公网网段才用 net 过滤；私网 / fake-ip 网段抓全网再筛。
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError as exc:
            log(f"[提示] 目标 {t} 的网段写法无法解析（{exc}），抓包阶段不做过滤，"
                "分析阶段再按目标筛选")
            return {"bpf": "", "kind": "cidr", "resolved": [], "reason": "网段无法解析"}
        non_public = _network_non_public_reason(net)
        if non_public:
            log(f"[提示] 目标 {t} 是{non_public}网段，抓包阶段不做 net 过滤（抓全网），"
                "分析阶段再按目标筛选")
            return {"bpf": "", "kind": "cidr", "resolved": [],
                    "reason": f"{non_public}网段，抓全网分析阶段筛选"}
        bpf = f"net {net.with_prefixlen}"
        note = "（已按网络地址规范化）" if t != net.with_prefixlen else ""
        log(f"[提示] 目标 {t} 是公网网段，抓包阶段使用 {bpf}{note}")
        return {"bpf": bpf, "kind": "cidr", "resolved": [], "reason": "公网网段"}

    # 3) 域名：解析 → 只接受全公网结果；其余情况明确降级为「抓全网」。
    ips = _resolve_ips(t)
    if not ips:
        log(f"[提示] 目标 {t} 解析失败（DNS 无结果），抓包阶段不做 host 过滤，"
            "分析阶段再按目标筛选")
        return {"bpf": "", "kind": "domain", "resolved": [], "reason": "域名解析失败"}
    bad = [(ip, _non_public_reason(ip)) for ip in ips]
    bad = [(ip, reason) for ip, reason in bad if reason]
    if bad:
        detail = "、".join(f"{ip}（{reason}）" for ip, reason in bad)
        log(f"[提示] 目标 {t} 解析到 {detail}，抓包阶段不做 host 过滤，"
            "分析阶段再按目标筛选")
        return {"bpf": "", "kind": "domain", "resolved": ips,
                "reason": f"解析结果含非公网地址：{bad[0][1]}"}
    chosen = ips[:4]
    if len(ips) > len(chosen):
        log(f"[提示] 目标 {t} 解析到 {len(ips)} 个公网地址，过滤器只取前 {len(chosen)} 个")
    bpf = " or ".join(f"host {ip}" for ip in chosen)
    log(f"[提示] 目标 {t} 解析到 {'、'.join(chosen)}（公网地址），抓包阶段使用 {bpf}")
    return {"bpf": bpf, "kind": "domain", "resolved": ips, "reason": "解析结果为公网地址"}


def bpf_for(target: str) -> str:
    """把目标转成实时抓包用的 BPF 过滤器（兼容旧调用方）。

    只保留「能安全进 tshark 命令行」的写法，真正的取舍在
    :func:`capture_filter_for`：域名解析到 fake-ip/私网/失败时返回空串（抓全网）。

    Args:
        target: 用户输入的目标，如 ``192.168.1.10`` / ``10.0.0.0/24`` / ``example.com``。

    Returns:
        str: BPF 串；空串表示抓全网（空目标、解析失败、fake-ip/私网域名、
            私网 IP / 私网 CIDR 等）。

    Raises:
        ValueError: 目标含非法字符，或长度超过 200 个字符（由调用方转成可展示的错误）。
    """
    return capture_filter_for(target)["bpf"]


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


def _capture_empty_error(plan: list[dict], durations: list[int], bpf: str) -> str:
    """构造「候选网卡全都没抓到包」的错误文案（可直接照着操作）。

    Args:
        plan: 本轮实际尝试过的网卡列表。
        durations: 与 ``plan`` 一一对应的实际抓包秒数。换卡重试会把后几块缩短到
            ``min(用户时长, 10)``，文案必须写真实序列（如 ``30s→10s→10s``），
            不能只写用户请求的 30s。
        bpf: 本次使用的 BPF 过滤器；空串表示全网。

    Returns:
        str: 中文错误说明，含实际时长序列、``--interfaces`` / ``--interface``
            自助命令，以及「网卡未连接」和「流量走了 VPN 虚拟网卡」两类常见原因。
    """
    names = "、".join(f"{tshark.short_name(i['name'])}[{i['index']}]" for i in plan)
    if len(plan) == 1:
        lead = f"网卡 {names} 在 {durations[0] if durations else 0} 秒内没有捕获到任何报文"
    else:
        seq = "→".join(f"{d}s" for d in durations)
        lead = (f"连续 {len(plan)} 块候选网卡（{names}）在 {seq} 内都没有"
                "捕获到任何报文")
    reasons = ("常见原因：1) 选中的网卡未连接或没有业务流量（例如已断开的以太网口）；"
               "2) 流量走了 VPN / 代理的虚拟网卡（如 mihomo(Clash Meta) 的 Meta/TUN 网卡），"
               "物理网卡上可能看不到业务报文。")
    hint = ("请运行 `python core\\diagnose.py --interfaces` 查看网卡列表，"
            "再用 `--interface <序号>` 指定真正有流量的网卡后重试。")
    if bpf:
        hint += f" 当前还设置了过滤器 `{bpf}`，可先去掉 `--target` 抓全网确认网卡是否选对。"
    return f"{lead}。{reasons}{hint}"


def _probe_traffic_candidates(ts: Path, candidates: list[dict],
                              seconds: int = 2) -> list[dict]:
    """探测候选网卡里哪些真有流量（**只用于提示，绝不用于换卡**）。

    显式指定网卡的抓包失败后，用户需要知道「哪块有流量」才知道下一步选谁；
    这里把候选里真有流量的都列出来（最多 5 块，每块试 ``seconds`` 秒），
    但不拿它们继续抓包——显式选择必须被尊重。

    Args:
        ts: tshark 可执行文件路径。
        candidates: 候选网卡列表（调用方已按优先级排序、并剔除刚失败的显式网卡）。
        seconds: 每块网卡试抓的秒数。

    Returns:
        list[dict]: 有流量的候选网卡项（保持传入顺序）；一块都没有时返回 ``[]``。
    """
    hits: list[dict] = []
    for cand in candidates[:5]:
        _rc, out, _err = tshark.run(
            [str(ts), "-i", str(cand["index"]), "-a", f"duration:{seconds}",
             "-c", "20", "-T", "fields", "-e", "frame.number"],
            timeout=seconds + 15,
        )
        if any(line.strip() for line in (out or "").splitlines()):
            hits.append(cand)
    return hits


def _explicit_empty_error(iface: dict, duration: int, bpf: str,
                          traffic: list[dict]) -> str:
    """构造「用户显式指定的网卡没抓到包」的错误文案。

    与 :func:`_capture_empty_error` 的关键差别：这里**不会换卡**，所以文案必须
    先说明「停在你指定的网卡」，再给出本次探测发现有流量的候选，让用户自己决定
    是否改指定或改用自动选择。

    Args:
        iface: 用户显式指定的网卡（``index`` / ``name``）。
        duration: 在这块网卡上抓了多少秒。
        bpf: 本次使用的 BPF 过滤器；空串表示全网。
        traffic: :func:`_probe_traffic_candidates` 探测到有流量的候选网卡。

    Returns:
        str: 中文错误说明，含 ``--interfaces`` 与「不指定 --interface」两条命令；
            有流量候选时逐个列出（形如 ``#5 WLAN、#10 Meta``）。
    """
    name = tshark.short_name(iface["name"])
    lead = f"你指定的网卡 #{iface['index']} {name} 在 {duration} 秒内没抓到任何包。"
    lead += "已按显式指定停在这块网卡，不会自动换卡。"
    if traffic:
        found = "、".join(f"#{i['index']} {tshark.short_name(i['name'])}" for i in traffic)
        body = f"本次探测发现有流量的候选网卡：{found}，可供参考。"
    else:
        body = "本次探测也没有发现其它有流量的候选网卡。"
    hint = ("请运行 `python core\\diagnose.py --interfaces` 查看完整网卡清单；"
            "或不指定 `--interface`、让程序自动选择有流量的网卡重试："
            f"`python core\\diagnose.py --duration {duration}`。")
    if bpf:
        hint += f" 当前还设置了过滤器 `{bpf}`，可先去掉 `--target` 抓全网确认网卡是否选对。"
    return f"{lead}{body}{hint}"


def _explicit_empty_result(ts: Path, iface: dict, ordered: list[dict], duration: int,
                           bpf: str, logger) -> dict:
    """显式指定网卡抓空后的返回值：只探测提示、绝不换卡。

    Args:
        ts: tshark 可执行文件路径。
        iface: 用户显式指定的网卡。
        ordered: 全部网卡的候选顺序（用于挑出「其它」网卡去探测）。
        duration: 在这块网卡上抓了多少秒（写进错误信息）。
        bpf: 本次使用的 BPF 过滤器。
        logger: 日志回调。

    Returns:
        dict: ``{"ok": False, "degraded": True, "empty": True,
            "interface": 网卡名, "bpf": 过滤器, "error": 可操作错误文案}``；
            错误里列出本次探测发现有流量的候选网卡（不会用它们继续抓包）。
    """
    others = [i for i in ordered if i["index"] != iface["index"]]
    logger(f"[提示] 显式指定网卡[{iface['index']}] 抓包为空，按指定不换卡；"
           "正在探测其它候选网卡是否有流量（仅用于提示）...")
    traffic = _probe_traffic_candidates(ts, others)
    return {"ok": False, "degraded": True, "empty": True,
            "interface": tshark.short_name(iface["name"]), "bpf": bpf,
            "error": _explicit_empty_error(iface, duration, bpf, traffic)}


def _shadow_prober_for(target: str, duration: int, logger) -> "pathprobe.ShadowProber | None":
    """构造影子探针（任何失败都只降级为「探针不可用」，绝不打断抓包）。

    Args:
        target: 抓包目标；用于发现业务对端（IP/CIDR/域名）。
        duration: 抓包秒数，决定探针最多跑几轮（封顶 38 包/目标）。
        logger: 日志回调。

    Returns:
        pathprobe.ShadowProber | None: 有可用目标时返回已构造但**未启动**的探针；
            网关/目标都拿不到、或平台 API 抛异常时返回 ``None``（本次不做探针）。
    """
    try:
        targets = pathprobe.discover_targets(target=target)
        specs = pathprobe.shadow_specs(targets)
        if not specs:
            logger("[提示] 影子探测：没有可用目标（网关与业务目标都没拿到），本次跳过")
            return None
        if targets.get("dns_skip") == "loopback":
            logger("[提示] 影子探测：DNS 服务器是本机回环地址，跳过 DNS 角色"
                   "（探它等于探自己，测不出路径好坏）")
        elif targets.get("dns_skip"):
            logger("[提示] 影子探测：DNS 服务器地址不可用于探测，跳过 DNS 角色")
        prober = pathprobe.ShadowProber(
            specs, interval_s=pathprobe.PROBE_INTERVAL_S,
            max_rounds=pathprobe.rounds_for(duration))
        logger(f"[提示] 影子探测已启用：每 {pathprobe.PROBE_INTERVAL_S:g} 秒 1 轮，"
               f"{len(specs)} 个目标（{'、'.join(s.role for s in specs)}），"
               f"最多约 {pathprobe.probe_len(specs) * prober.max_rounds} 个探测包")
        return prober
    except Exception as exc:                       # noqa: BLE001  探针失败只降级
        logger(f"[提示] 影子探测不可用，已跳过（不影响诊断）："
               f"{type(exc).__name__}: {exc}")
        return None


def _path_profiler_for(target: str, duration: int, logger) -> "pathprobe.PathProfiler | None":
    """构造路径探测（MTR）后台任务（任何失败都只降级为「路径不可用」）。

    只有**有目标**才跑：全网体检（``target`` 为空）没有对端，逐跳没有意义。
    时间预算 = 抓包时长 + 5 秒（SPEC V9）；超时后 :func:`pathprobe.run` 返回已
    完成的跳，绝不把抓包主流程拖住。

    Args:
        target: 抓包目标（IP / 域名 / CIDR）；空表示全网体检 → 不跑 MTR。
        duration: 抓包秒数，用于算时间预算。
        logger: 日志回调。

    Returns:
        pathprobe.PathProfiler | None: 已构造但**未启动**的后台任务；无目标或
            构造失败时返回 ``None``（本次不做路径探测）。
    """
    if not str(target or "").strip():
        return None
    try:
        budget = max(8.0, float(duration or 0) + 5.0)
        profiler = pathprobe.PathProfiler(
            target, port=None, max_hops=pathprobe.PATH_DEFAULT_MAX_HOPS,
            samples=3, timeout_s=0.8, budget_s=budget)
        logger(f"[提示] 路径探测（MTR）已启用：最多 {profiler.max_hops} 跳 × "
               f"{profiler.samples} 样本，时间预算 {profiler.budget_s:g}s"
               f"（抓包时长 + 5s）")
        return profiler
    except Exception as exc:                       # noqa: BLE001  路径探测失败只降级
        logger(f"[提示] 路径探测不可用，已跳过（不影响诊断）："
               f"{type(exc).__name__}: {exc}")
        return None


def _merge_probe_filter(bpf: str, prober, path_kinds=()) -> str:
    """把探针排除式合并进用户抓包过滤器（``AND`` 语义，用户串必须加括号）。

    MTR 与影子探测共用同一套标记（ICMP id / TCP 源端口段），但**即使影子探测
    没有任何目标**，只要有诊断目标就会发 MTR 包 —— 所以排除式的协议集合必须把
    ``path_kinds`` 并进去，否则「没有网关目标」那一次会把 MTR 包抓进业务统计。

    Args:
        bpf: 用户过滤器；空串表示抓全网。
        prober: 已构造的影子探针；``None`` 时只按 ``path_kinds`` 合并。
        path_kinds: MTR 可能发出的探针协议机器码（``icmp`` / ``tcp_syn``）。

    Returns:
        str: 合并后的 BPF；没有探针/排除式时与入参相同。
    """
    kinds = {str(kind) for kind in (path_kinds or ())}
    if prober is not None:
        kinds |= ({kind.value for kind in prober.ledger.kinds()}
                  or {spec.kind.value for spec in prober.specs})
    if not kinds:
        return bpf
    exclusion = pathprobe.exclusion_bpf(kinds)
    if not exclusion:
        return bpf
    return f"({bpf}) and ({exclusion})" if bpf else exclusion


def _merge_display_filters(*filters: str) -> str:
    """把多个 tshark ``-Y`` 显示过滤用 ``AND`` 连起来（空串自动跳过）。

    Args:
        *filters: 显示过滤串；空串代表「这一项不需要过滤」。

    Returns:
        str: 合并后的过滤串；全部为空时返回空串（调用方传 ``None`` 表示不过滤）。
    """
    parts = [str(item).strip() for item in filters if str(item or "").strip()]
    return " and ".join(parts)


def capture_live(target: str = "", duration: int = 30, interface: str | None = None,
                 logger=log, shadow: bool = False) -> dict:
    """实时抓包并落盘到 ``captures/``。

    Args:
        target: 抓包目标；空表示全网。实际过滤器由 :func:`capture_filter_for`
            决定：域名只有解析结果全是公网地址时才用 ``host <ip>``，fake-ip/
            私网/解析失败一律不加过滤器（分析阶段仍按目标筛选）。
        duration: 首块网卡的抓包秒数；换卡重试时每块缩短为 ``min(duration, 10)``。
        interface: 网卡序号或名称关键字；空则按 :func:`tshark.order_interfaces`
            的候选顺序逐块探测（每块 2 秒、最多 5 块），取第一块真有流量的；
            全都没流量再用 :func:`tshark.pick_interface` 兜底。显式指定时**只抓该网卡**：
            抓到 0 包/0 字节也不换卡（尊重用户选择，避免「指定 Meta 却静默换到 WLAN」
            给出错误结论），直接返回带候选网卡与自助命令的错误。
        logger: 日志回调。
        shadow: 是否在抓包同时启动影子探测与路径探测（MTR）。默认 ``False``；
            ``run_scan``/UI 传 ``True``。两类探针的抓包排除式都会**合并进 BPF**
            （第一道隔离），账本/路径结果随成功结果分别以 ``probe`` / ``path``
            键返回（``run_scan`` 据此注入基线/路径剖面）。**MTR 只在有目标时启动**：
            全网体检没有对端，逐跳没有意义。

    Returns:
        dict: 成功 ``{"ok": True, "pcap": str, "interface": str, "interface_index": int,
            "bpf": str, "duration": int}``（``shadow=True`` 且确实发出探针时再加
            ``"probe"``：账本 + 聚合基线 + 三种过滤串；MTR 产出了逐跳数据时再加
            ``"path"``：路径剖面 + 两种过滤串）；失败 ``{"ok": False,
            "error": str, "degraded": bool, "empty": bool, "interface": str,
            "bpf": str}``。
            **所有**返回路径都带 ``interface`` / ``bpf``（没有可用值时为 ``""``），
            供降级卡与 ``degraded_*`` 报告写「最终网卡 / 实际过滤器」；``empty=True``
            表示抓包窗口内 0 包（可走 0 包降级），``degraded=True`` 表示
            「缺 tshark/Npcap/提权」这类环境问题，前端据此提示改用分析抓包文件。
            自动选择模式下抓满 0 包/0 字节时不直接失败，会按候选顺序自动换卡重试
            （最多 3 块）；全失败时 ``interface`` 是最后尝试的那块，错误里带
            ``--interfaces`` / ``--interface`` 指引与常见原因。显式指定模式 0 包时
            不换卡，错误里列出本次探测发现有流量的候选网卡和两条自助命令。

    Note:
        返回前会等文件大小稳定（最多 3 秒）。tshark 进程退出 ≠ 数据已落盘，
        在写盘窗口期就开始分析会读到半份数据，进而产生幻影告警（T00）。
        0 包的空抓包文件会被删除（日志写一行「已删除空抓包」），避免在
        ``captures/`` 留下无法分析的垃圾。

        影子探测的线程收尾放在 ``finally``：抓包成功/失败/抛异常都会
        ``stop()`` + ``join(3)``；探针自身异常只写进账本 ``error``，不影响
        本函数返回值与主诊断退出码。路径探测同理：线程异常只写进 ``path.error``，
        时间预算（抓包时长 + 5s）用完就返回已完成的跳，绝不阻塞抓包。
    """
    ts = tshark.find_tshark()
    if not ts:
        return {
            "ok": False,
            "degraded": True,
            "interface": "",
            "bpf": "",
            "error": "未找到 tshark。请确认 tools/WiresharkPortable/App/Wireshark/tshark.exe 是否存在。",
        }
    if not tshark.npcap_installed():
        return {
            "ok": False,
            "degraded": True,
            "interface": "",
            "bpf": "",
            "error": "Npcap 未安装或未生效，实时抓包不可用。请以管理员身份运行 start.bat 完成安装，"
                     "或改用「分析抓包文件」上传已有 pcap 文件。",
        }

    interfaces = tshark.list_interfaces(ts)
    if not interfaces:
        return {"ok": False, "degraded": True, "interface": "", "bpf": "",
                "error": "未枚举到可用网卡，请确认 Npcap 已安装且 tshark -D 可正常输出。"}

    ordered = tshark.order_interfaces(interfaces)
    iface = None
    if interface:
        if interface.isdigit():
            iface = next((i for i in interfaces if i["index"] == int(interface)), None)
        else:
            iface = next((i for i in interfaces if interface.lower() in i["name"].lower()), None)
    # 显式指定的网卡必须被尊重：0 包时停在原地报错，不静默换到别的网卡。
    explicit = iface is not None
    if not iface:
        # 先按候选顺序真实抓 2 秒；名字只能猜（以太网可能没插网线），流量不会说谎。
        logger("探测网卡流量（每块 2 秒，最多 5 块），自动选择有流量的网卡 ...")
        iface = tshark.probe_interface(ts, ordered) or tshark.pick_interface(interfaces)
    if iface is None:
        return {"ok": False, "degraded": True, "interface": "", "bpf": "",
                "error": "未枚举到可用网卡。"}

    try:
        decision = capture_filter_for(target, logger=logger)
    except ValueError as exc:
        return {"ok": False, "interface": tshark.short_name(iface["name"]),
                "bpf": "", "error": f"目标不合法：{exc}"}
    bpf = decision["bpf"]
    logger(f"[提示] 最终使用的抓包过滤器：{bpf or '无（全网）'}")
    duration = max(3, min(int(duration or 30), 180))
    CAPTURES.mkdir(parents=True, exist_ok=True)

    # 影子探测必须在 tshark 启动**之前**构造：排除式要合并进 capture filter，
    # 而 filter 一旦交给 tshark 就不能再改（账本随抓包增长，BPF 不能）。
    prober = _shadow_prober_for(target, duration, logger) if shadow else None
    # 路径探测（MTR）与抓包并存：有目标才跑（全网体检没有对端，逐跳无意义）。
    profiler = _path_profiler_for(target, duration, logger) if shadow else None
    if prober is not None or profiler is not None:
        path_kinds = (tuple(profiler.snapshot()["planned_kinds"])
                      if profiler is not None else ())
        merged = _merge_probe_filter(bpf, prober, path_kinds)
        if merged != bpf:
            bpf = merged
            logger("[提示] 影子探测/路径探测：抓包过滤器已 AND 合并探针排除式"
                   "（第一道隔离）")
    for worker, name in ((prober, "影子探测"), (profiler, "路径探测")):
        if worker is None:
            continue
        try:
            worker.start()
        except Exception as exc:                   # noqa: BLE001  探针起不来不拦诊断
            logger(f"[提示] {name}线程启动失败，已跳过：{type(exc).__name__}: {exc}")
            if worker is prober:
                prober = None
            else:
                profiler = None

    # 显式指定只抓这一块；自动模式才允许「0 包换下一块」重试（最多 3 块）。
    plan = [iface] if explicit else _capture_candidates(iface, ordered, limit=3)

    def _attempts() -> dict:
        """按候选网卡逐块抓包（内嵌函数：让探针的启动/收尾只有一对入口/出口）。"""
        failures: list[str] = []
        for attempt, cand in enumerate(plan, 1):
            # 换卡重试用短时长：3 块 × 用户时长会让失败路径拖到 90s；重试只值 10s。
            attempt_duration = duration if attempt == 1 else min(duration, 10)
            pcap = CAPTURES / f"diag_{_stamp()}.pcapng"
            cmd = [str(ts), "-i", str(cand["index"]), "-w", str(pcap),
                   "-a", f"duration:{attempt_duration}", "-q"]
            if bpf:
                cmd += ["-f", bpf]

            prefix = f"（第 {attempt}/{len(plan)} 块）" if len(plan) > 1 else ""
            shorten = (f"（重试缩短时长，原 {duration}s）"
                       if attempt_duration < duration else "")
            logger(f"开始抓包{prefix}：网卡[{cand['index']}] "
                   f"{tshark.short_name(cand['name'])}，时长 {attempt_duration}s{shorten}，"
                   f"过滤器 `{bpf or '无（全网）'}`")
            rc, out, err = tshark.run(cmd, timeout=attempt_duration + 120)
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
                            "interface": tshark.short_name(cand["name"]),
                            "bpf": bpf or "无（全网）",
                            "error": "抓包权限不足（需要管理员权限 + Npcap 驱动）。请右键以管理员身份运行 start.bat，"
                                     "或使用「分析抓包文件」分析已有 pcap。"}
                failures.append(f"{tshark.short_name(cand['name'])}[{cand['index']}] 0 字节(rc={rc})")
                if explicit:
                    return _explicit_empty_result(ts, iface, ordered, duration, bpf, logger)
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
                try:
                    pcap.unlink()
                    logger(f"[提示] 已删除空抓包：{pcap.name}")
                except OSError:
                    pass
                if explicit:
                    return _explicit_empty_result(ts, iface, ordered, duration, bpf, logger)
                logger(f"[提示] 网卡[{cand['index']}] {tshark.short_name(cand['name'])} "
                       f"在 {attempt_duration} 秒内未捕获到报文，自动换下一块候选网卡重试 ...")
                continue

            logger(f"抓包完成：{pcap.name}（{size / 1024:.0f} KB）")
            if stable:
                logger("抓包文件已落盘稳定，开始分析")
            else:
                logger("[提示] 抓包文件 3 秒内仍在变化，分析可能读到不完整内容")

            return {"ok": True, "pcap": str(pcap), "interface": tshark.short_name(cand["name"]),
                    "interface_index": cand["index"], "bpf": bpf or "无（全网）",
                    "duration": attempt_duration}

        durations = [duration if attempt == 1 else min(duration, 10)
                     for attempt, _cand in enumerate(plan, 1)]
        error = _capture_empty_error(plan, durations, bpf)
        if failures:
            error += f"（各网卡结果：{'；'.join(failures)}）"
        # 复审阻塞 1：全失败也要交代「最终用的是哪块卡、哪个过滤器」，否则
        # server 的降级卡与 degraded_* 报告只能填「自动选择 / 无（全网）」，
        # 把实际用过的公网过滤器误报成没过滤。
        last = plan[-1] if plan else iface
        return {"ok": False, "degraded": True, "empty": True,
                "interface": tshark.short_name(last["name"]),
                "interface_index": last["index"],
                "bpf": bpf or "无（全网）",
                "error": error}

    try:
        result = _attempts()
    finally:
        for worker, name in ((prober, "影子探测"), (profiler, "路径探测")):
            if worker is None:
                continue
            worker.stop()
            if not worker.join(3.0):
                logger(f"[提示] {name}线程 3 秒内未退出；它是 daemon 线程，不阻塞进程退出")
    if prober is not None:
        if prober.sent_count:
            result["probe"] = prober.snapshot()
            logger(f"影子探测结束：共发 {prober.sent_count} 个探针包")
        else:
            logger("[提示] 影子探测没有发出任何探针，本次不注入探针基线")
    if profiler is not None:
        profile = profiler.result
        if profile is not None and profile.hops:
            result["path"] = profiler.snapshot()
            if profile.degraded_ttl is not None:
                detail = f"第 {profile.degraded_ttl} 跳开始劣化"
            elif profile.middle_loss_suspected:
                detail = ("中间跳有丢包但未持续到目标（疑似 ICMP 限速/策略过滤，"
                          f"第 {'、'.join(str(ttl) for ttl in profile.middle_loss_ttls)} 跳）")
            else:
                detail = "未发现持续劣化"
            logger(f"路径探测结束：{len(profile.hops)} 跳，结论 {profile.verdict_key}，"
                   f"{detail}")
        else:
            reason = profiler.error or (profile.error if profile is not None else "")
            logger("[提示] 路径探测没有产生可用数据，本次不注入路径剖面"
                   f"（不影响诊断）{('：' + reason) if reason else ''}")
    return result


def _fmt_ms(value: float) -> str:
    """把毫秒数写成给人看的短串：不足 1ms 写 ``<1``，其余去掉多余的 0。"""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "-"
    if number < 1:
        return "<1"
    return f"{number:g}"


def _link_stats(host: str) -> dict:
    """对单个地址做一次轻量 ICMP 体检（薄包装，测试可替换）。

    Args:
        host: IPv4 字面量。

    Returns:
        dict: :func:`core.platform.winapi.icmp_stats` 的结果；调用异常时退回
            ``{"ok": False, ...}``，绝不让降级路径因探测失败而崩。
    """
    try:
        return winapi.icmp_stats(host, count=4, timeout_ms=800)
    except Exception as exc:  # noqa: BLE001  探测失败只表示「拿不到降级信息」
        return {"ok": False, "host": host, "sent": 4, "recv": 0, "loss_pct": 100.0,
                "avg_ms": 0.0, "jitter_ms": 0.0,
                "error": f"{type(exc).__name__}: {exc}"}


def degraded_empty_capture_result(target: str = "", duration: int = 0,
                                  interface: str | None = None,
                                  capture_error: str = "", bpf: str = "",
                                  logger=log) -> dict | None:
    """0 包优雅降级：抓包窗口没有业务报文时，用链路可达性代替「红色失败」。

    路测反馈：网卡选错、流量走 VPN/TUN、或目标本来就没流量时，三块网卡 0 包直接
    判「诊断失败」会让人以为工具坏了。这里自动对「目标 → 默认网关」做一次 ICMP
    体检，只要拿到时延/抖动/丢包就返回中性降级结论；只有连这组信息都拿不到
    （如 Npcap 不可用、网卡打不开）时才让调用方报错。

    Args:
        target: 用户填的目标；空表示全网体检（不设过滤，抓本机全部流量）。
        duration: 本次抓包时长（秒），写进结论。
        interface: 用户显式选择的网卡；空表示自动选择。
        capture_error: 抓包阶段的原始错误文案（放进「为什么」供排障）。
        bpf: 本次实际使用的 BPF 过滤器；空串表示全网。
        logger: 日志回调。

    Returns:
        dict | None: 成功时 ``{"ok": True, "degraded": True, "headline",
            "plain", "link": {...}, "reasons": [...], "next_steps": [...],
            "capture": {...}}``；目标与默认网关都测不到时返回 ``None``
            （调用方应按真正的失败处理）。
    """
    link: dict | None = None
    via = ""
    host = ""
    probe_host = ""
    target_stats: dict | None = None
    if target:
        # 域名先解析成 IP 再探测；10.255.255.1 这类 IP 直接探。
        probe_host = target
        try:
            ipaddress.ip_address(target)
        except ValueError:
            resolved = _resolve_ips(target)
            probe_host = resolved[0] if resolved else ""
        if probe_host:
            target_stats = _link_stats(probe_host)
            if target_stats.get("ok"):
                link, via, host = target_stats, "target", target
    target_probe = probe_host
    gateway = ""
    if link is None:
        gateway = winapi.default_gateway()
        if gateway:
            stats = _link_stats(gateway)
            if stats.get("ok"):
                link, via, host = stats, "gateway", gateway
    if link is None:
        return None
    if via == "gateway":
        probe_host = host

    # 目标明确 ping 不通 → 「目标不可达」；其余 0 包 → 「未观察到任何 TCP/IP 会话」。
    kind = ("target_unreachable"
            if target and not (target_stats or {}).get("ok") else "empty_sessions")
    card_title = ("目标不可达" if kind == "target_unreachable"
                  else "未观察到任何 TCP/IP 会话")

    avg = _fmt_ms(link.get("avg_ms", 0))
    jitter = _fmt_ms(link.get("jitter_ms", 0))
    loss = link.get("loss_pct", 100.0)
    metrics = (f"RTT 平均 {avg} ms / 抖动 {jitter} ms / 丢包 {loss:g}%")
    if via == "target":
        headline = "未捕获业务报文，但链路可达"
        plain = (f"抓包窗口内没有业务报文；对目标 {target} 的探测显示链路可达："
                 f"{metrics}。")
    else:
        headline = "未捕获业务报文，但本地链路可达"
        if target:
            plain = (f"抓包窗口内没有业务报文；目标 {target} 当前没有响应，"
                     f"但本机到默认网关 {host} 的链路可达：{metrics}。")
        else:
            plain = (f"抓包窗口内没有业务报文；本机到默认网关 {host} 的链路可达："
                     f"{metrics}。")

    if kind == "empty_sessions":
        reasons = [
            "抓包点可能看不到业务流量：VPN / 代理 / TUN 虚拟网卡（如 mihomo 的 Meta）"
            "会改写路由，物理网卡上可能没有业务报文。",
            "该目标在抓包窗口内本来就没有流量（例如只发了一次请求，或目标不在线）。",
            "对方可能只响应 ICMP（例如只开 ping 的网关/设备），没有可观察的 TCP/UDP 服务交互。",
        ]
    else:
        reasons = [
            f"目标 {target} 对 ICMP 探测没有响应：可能目标离线、路由不通，"
            "或被中间防火墙 / 安全组拦截。",
            "抓包点可能看不到业务流量：VPN / 代理 / TUN 虚拟网卡会改写路由，"
            "物理网卡上可能没有业务报文。",
            "抓包窗口内没有与该目标的 TCP/UDP 交互；也可能目标只提供 UDP 服务，"
            "ICMP 被单独禁用。",
        ]
    if via == "gateway" and target and kind == "target_unreachable":
        reasons.append("目标本身不可达；先用「连通与速度测试」测目标与网关，"
                       "确认是本地链路问题还是对端问题。")
    if kind == "target_unreachable":
        next_steps = [
            "先查路由：确认本机到目标网段有可用路由，默认网关是否正确。",
            "检查目标侧防火墙 / 安全组是否放行，以及目标主机是否在线。",
            "用「连通与速度测试」测目标的常见端口（如 443），区分「主机不通」"
            "还是「端口/服务不通」。",
        ]
    else:
        next_steps = [
            "换一块有流量的网卡（或保持「自动选择」）再抓一次。",
            "把抓包时长调到 30~60 秒；仍为空可先用「全网体检」确认本机有没有业务流量。",
            "如果走代理 / VPN，优先在 TUN 虚拟网卡（如 Meta）上抓包。",
        ]
    if via == "gateway" and target and kind == "empty_sessions":
        next_steps.insert(0, f"目标 {target} 当前没有响应：先查路由 / 防火墙，"
                             "或用「连通与速度测试」确认目标端口是否在监听。")

    logger(f"[提示] 未捕获业务报文，已自动做连通与速度测试：{metrics}"
           f"（{'目标' if via == 'target' else '默认网关'} {host}），"
           f"按「{card_title}」降级，不判为失败")
    return {
        "ok": True,
        "degraded": True,
        "degraded_reason": "empty_capture",
        "kind": kind,
        "card_title": card_title,
        "headline": headline,
        "plain": plain,
        "link": {"via": via, "host": host, "probe_host": probe_host or host,
                 "avg_ms": link.get("avg_ms", 0.0),
                 "jitter_ms": link.get("jitter_ms", 0.0),
                 "loss_pct": link.get("loss_pct", 100.0),
                 "recv": link.get("recv", 0), "sent": link.get("sent", 0),
                 "target": {
                     "host": target_probe or target,
                     "ok": bool((target_stats or {}).get("ok")),
                     "avg_ms": (target_stats or {}).get("avg_ms", 0.0),
                     "loss_pct": (target_stats or {}).get("loss_pct", 100.0),
                 }},
        "reasons": reasons,
        "next_steps": next_steps,
        "capture": {
            "target": target or "全网",
            "interface": interface or "自动选择",
            "duration": int(duration or 0),
            "bpf": bpf or "无（全网）",
            "error": capture_error,
        },
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


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
             report_dir: str | Path | None = None,
             shadow: bool = False) -> dict:
    """完整诊断：抓包（或复用已有 pcap）→ 分析 → 落盘报告 → 记一条 run。

    Args:
        target: 目标 IP/网段/域名；空表示全网。
        duration: 实时抓包秒数（仅无 ``pcap`` 时生效）。
        interface: 网卡序号或名称关键字。
        pcap: 分析抓包文件的路径。只给文件名时会到 ``captures/`` 下找
            （兼容 U 盘盘符变化）。
        logger: 日志回调。
        report_dir: 报告输出目录；``None``（默认）写 ``reports/``，与历史行为一致。
            给定时只写该目录（目录不存在会自动创建），文件名清洗仍由
            :func:`report.save` 负责。
        shadow: 实时抓包时是否同时做影子探测**与路径探测（MTR）**。**产品入口默认开**
            （CLI 不传 ``--no-shadow`` 即开、UI 默认勾选、``/api/scan`` 缺省
            ``true``）；本函数作为库入口默认 ``False``，保证旧调用方行为不变。
            **离线路径（``pcap`` 非空）恒不启动探针**——用户可能只是在分析别人
            给的抓包文件。MTR 只在有目标时启动（全网体检没有对端）。

    Returns:
        dict: ``analyzer.analyze()`` 的结果，另加 ``report``（``.md``/``.json`` 落盘路径）
            与 ``capture``（本次采集参数）；有探针数据时 ``meta["probe_baseline"]``
            里带「探针基线」、有逐跳数据时 ``meta["path_profile"]`` 里带「路径剖面」
            （无数据时这两个键都不存在，输出与 main 逐字节一致）。
            失败时 ``{"ok": False, "error": "..."}``。

    Note:
        无论成功、失败还是抛异常，都会调用一次 :func:`logstore.record_run`
        （``mode`` 为 ``offline`` / ``live``）。UI 的 ``/api/scan`` 也走本函数，
        所以两个入口共用同一个记录点，一次分析只有一条记录。

        影子探测的三层隔离都在本函数/``capture_live`` 内完成：抓包 BPF 合并、
        分析阶段 ``-Y`` 显示过滤、报告里写「已排除 N 个探针包」；任何一步失败
        都只降级为「探针不可用」，不改变主诊断结论与退出码。路径探测同理，并且
        多一条：ICMP type 11（TTL 超时）整类从**显示过滤**排除，排除数量写进报告。
    """
    started = time.monotonic()
    mode = "offline" if pcap else "live"
    params = _run_params(target, duration, interface, pcap)
    try:
        result = _run_scan(target=target, duration=duration, interface=interface,
                           pcap=pcap, logger=logger, report_dir=report_dir,
                           shadow=shadow)
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
    if ("npcap 未安装" in lowered or "npcap 未就绪" in lowered
            or "缺少抓包驱动" in message):
        return "E_NO_NPCAP"
    if "权限不足" in message or "permission" in lowered or "access is denied" in lowered:
        return "E_NO_ADMIN"
    if ("未枚举到可用网卡" in message or "device is being used" in lowered
            or "could not be initiated" in lowered or "adapter" in lowered):
        return "E_NO_INTERFACE"
    if ("解析失败" in message or "不完整" in message or "cut short" in lowered
            or "capture file" in lowered or "pcap" in lowered):
        return "E_BAD_PCAP"
    if "npcap" in lowered:
        return "E_NO_NPCAP"
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
              report_dir: str | Path | None = None,
              shadow: bool = False) -> dict:
    """``run_scan`` 的实现体（拆出来是为了让记录逻辑只包一层、不散落在每个 return）。"""
    cfg = load_config()
    cap: dict = {"ok": True, "bpf": verdict.OFFLINE_BPF, "interface": "-", "duration": 0}
    if pcap:
        p = Path(pcap)
        # 支持 U 盘盘符变化：只给文件名时回落到 captures/
        if not p.is_absolute() and not p.exists():
            p = CAPTURES / p.name
        if not p.is_file():
            return {"ok": False, "error": f"抓包文件不存在: {pcap}"}
        cap["pcap"] = str(p)
    else:
        # 离线路径（上面的分支）恒不启动探针：用户可能只是在分析别人的 pcap。
        cap = capture_live(target, duration, interface, logger=logger, shadow=shadow)
        if not cap.get("ok"):
            return {"ok": False, "error": cap.get("error", "抓包失败"),
                    "degraded": cap.get("degraded", False),
                    "empty_capture": bool(cap.get("empty")),
                    "bpf": cap.get("bpf", ""),
                    "interface": cap.get("interface", "")}

    probe = cap.get("probe") or {}
    path = cap.get("path") or {}
    # 两道防御层合并：影子探针（按标记）+ 路径探测（按标记 + 整类 ICMP type 11）。
    # 用 AND 连接：任意一项为空就等价于另一项。
    display_filter = _merge_display_filters(
        str(probe.get("exclusion_display_filter") or ""),
        str(path.get("exclusion_display_filter") or ""))
    logger("开始分析报文 ...")
    result = analyzer.analyze(cap["pcap"], target=target,
                              ti_key=cfg.get("threat_intel_key", ""), log=logger,
                              display_filter=display_filter or None)
    if not result.get("ok") and display_filter:
        # 显示过滤属于「防御层」：无论失败原因是不是 filter（未知字段报
        # '"bogus.field" is not a valid protocol'、语法错误报 'Unexpected end of
        # filter expression' …），都**无条件**重试一次未过滤分析，保证诊断能出结论。
        # 只重试一次（不再检查错误文案、不循环），并明确告知结果可能含探针流量。
        logger("[警告] 探针隔离显示过滤不可用，已退回未过滤分析；"
               "本次统计可能包含探针流量")
        result = analyzer.analyze(cap["pcap"], target=target,
                                  ti_key=cfg.get("threat_intel_key", ""), log=logger)
    if not result.get("ok"):
        return result

    result["meta"]["interface"] = cap.get("interface", "-")
    result["meta"]["bpf"] = cap.get("bpf", "-")
    result["meta"]["capture_duration"] = cap.get("duration", 0)

    # 探针基线只「有数据才注入」：没有探针记录时一个键都不加，保证离线路径与
    # main 的 20 个产物逐字节一致（V11 红线；单测另有钉死）。
    baseline = probe.get("baseline")
    if isinstance(baseline, dict) and int(baseline.get("probe_count") or 0) > 0:
        kinds = []
        for item in probe.get("planned") or []:
            try:
                kinds.append(pathprobe.ProbeKind(str(item.get("kind"))))
            except ValueError:
                continue
        excluded = 0
        try:
            ts = tshark.find_tshark()
            if ts:
                excluded = pathprobe.count_marked_packets(ts, cap["pcap"], kinds)
        except Exception as exc:                   # noqa: BLE001  统计失败只影响说明数字
            logger(f"[提示] 统计探针包数失败（不影响结论）：{type(exc).__name__}: {exc}")
        baseline = dict(baseline)
        baseline["excluded_packets"] = excluded
        result["meta"]["probe_baseline"] = baseline
        logger(f"探针基线：发出 {baseline.get('sent', 0)} 个、收到 "
               f"{baseline.get('recv', 0)} 个；已从业务统计排除 {excluded} 个标记探针包"
               f"（ICMP 超时包另计）")

    # 路径剖面同样只「有数据才注入」：离线路径没有 cap["path"]，一个键都不加。
    profile = path.get("profile")
    if isinstance(profile, dict) and profile.get("hops"):
        excluded_icmp = 0
        try:
            ts = tshark.find_tshark()
            if ts:
                excluded_icmp = pathprobe.count_time_exceeded_packets(ts, cap["pcap"])
        except Exception as exc:                   # noqa: BLE001  统计失败只影响说明数字
            logger(f"[提示] 统计 ICMP 超时包数失败（不影响结论）："
                   f"{type(exc).__name__}: {exc}")
        profile = dict(profile)
        profile["excluded_icmp"] = excluded_icmp
        result["meta"]["path_profile"] = profile
        if profile.get("degraded_ttl") is not None:
            degraded_text = f"第 {profile.get('degraded_ttl')} 跳开始劣化"
        elif profile.get("middle_loss_suspected"):
            degraded_text = ("中间跳有丢包但未持续到目标（疑似 ICMP 限速/策略过滤，"
                             f"第 {'、'.join(str(ttl) for ttl in profile.get('middle_loss_ttls') or [])} 跳）")
        else:
            degraded_text = "未发现持续劣化"
        logger(f"路径剖面：{len(profile.get('hops') or [])} 跳（方式 {profile.get('method')}），"
               f"{degraded_text}；"
               f"已从业务统计剔除 {excluded_icmp} 个 ICMP 超时包"
               f"（含非探针流量，{excluded_icmp} 为上限）——这些包未计入业务统计")

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
            可配 ``--include-reports`` / ``--raw`` / ``--out``）/ ``--no-shadow``
            （实时抓包时关闭影子探测；默认开，离线分析恒不发探针）。

    Returns:
        int: 0 成功；2 分析失败（如抓包文件不完整）；其它非 0 表示环境问题。

    Note:
        入口第一件事是 :func:`_harden_console`：cp936 控制台下把编不出的 emoji
        转义成 ``\\u274c``，避免「报告已落盘、打印时却 exit 1」。只影响控制台
        显示，``.md`` / ``.json`` 报告内容不变。
    """
    _harden_console()
    ap = argparse.ArgumentParser(description="NetDiag 网络诊断")
    ap.add_argument("--target", default="", help="目标 IP 或 CIDR 网段，留空表示全网体检（不设过滤）")
    ap.add_argument("--duration", type=int, default=load_config()["default_duration"])
    ap.add_argument("--interface", default=None, help="网卡序号或名称关键字")
    ap.add_argument("--pcap", default=None, help="分析抓包文件：指定 pcap 文件")
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
    ap.add_argument("--no-shadow", action="store_true",
                    help="实时抓包时不发影子探测包（默认开：每 5 秒一轮、每目标 1 包，"
                         "已从诊断统计里排除；离线分析恒不发）")
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
                   report_dir=args.report_out, shadow=not args.no_shadow)
    if not res.get("ok"):
        print(f"[错误] {res.get('error')}", file=sys.stderr)
        if res.get("degraded"):
            print("[降级] 可执行：python diagnose.py --pcap <已有抓包文件> 分析抓包文件", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(res["summary"], ensure_ascii=False))
    else:
        print("\n" + report.render_markdown(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
