"""tshark / dumpcap 定位与执行封装（纯标准库，适配便携 Python）。"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def _tool_names(base: str):
    return (base + ".exe", base) if os.name == "nt" else (base,)


def _candidate_dirs() -> list[Path]:
    return [
        ROOT / "tools" / "WiresharkPortable" / "App" / "Wireshark",
        ROOT / "tools" / "Wireshark",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark",
    ]


def _find(base: str) -> Path | None:
    env = os.environ.get(f"{base.upper()}_PATH")
    if env:
        p = Path(env)
        if p.is_file():
            return p
    for d in _candidate_dirs():
        for name in _tool_names(base):
            p = d / name
            if p.is_file():
                return p
    hit = shutil.which(base)
    return Path(hit) if hit else None


def short_name(name: str) -> str:
    """把 ``tshark -D`` 的长设备名精简成括号里的网卡别名。

    Args:
        name: 形如 ``1. \\Device\\NPF_{GUID} (以太网)`` 的原始串。

    Returns:
        str: 括号内的可读名（``以太网``）；不含括号时原样返回。
    """
    m = re.search(r"\(([^()]*)\)\s*$", name or "")
    return m.group(1).strip() if m else (name or "")


def find_tshark() -> Path | None:
    """定位 ``tshark.exe``。

    Returns:
        Path | None: 按「环境变量 ``TSHARK_PATH`` → 便携目录 → 系统安装目录 → PATH」
            的顺序找；都没找到返回 ``None``（调用方据此报 ``E_NO_TSHARK``）。
    """
    return _find("tshark")


def find_dumpcap() -> Path | None:
    """定位 ``dumpcap.exe``（长时间抓包用它比 tshark 更省资源）。

    Returns:
        Path | None: 找不到时返回 ``None``。
    """
    return _find("dumpcap")


def find_npcap_installer() -> Path | None:
    """在 ``tools/`` 下找 Npcap 离线安装包。

    Returns:
        Path | None: 匹配 ``npcap-*.exe`` 的第一个；没有则 ``None``
            （此时前端提示用户自己去装）。
    """
    for p in (ROOT / "tools").glob("npcap-*.exe"):
        return p
    for p in ROOT.glob("tools/npcap*.exe"):
        return p
    return None


def _env() -> dict:
    """让 Wireshark 把个人配置写回 U 盘，避免污染目标机器。"""
    env = os.environ.copy()
    data = ROOT / "tools" / "WiresharkPortable" / "Data" / "settings"
    try:
        if (ROOT / "tools" / "WiresharkPortable").is_dir():
            data.mkdir(parents=True, exist_ok=True)
            env.setdefault("WIRESHARK_CONFIG_DIR", str(data))
    except OSError:
        pass
    return env


def run(args: list[str], timeout: int = 180) -> tuple[int, str, str]:
    """跑一个子进程并收集输出。**不抛异常**，一切失败都折成返回码。

    Args:
        args: 完整命令行（argv 列表，不经 shell，因此目标串里的特殊字符不会被解释）。
        timeout: 超时秒数，超时后子进程被杀。

    Returns:
        tuple[int, str, str]: ``(returncode, stdout, stderr)``。约定返回码：
            正常为子进程自身退出码；``-9`` 超时；``-2`` 找不到可执行文件；``-3`` 其它 OS 错误。
            因此调用方判断失败**不要**只看 ``rc != 0``，要区分这几个负数。
    """
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
            env=_env(),
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -9, "", f"命令超时（{timeout}s）: {' '.join(args[:3])} ..."
    except FileNotFoundError:
        return -2, "", f"找不到可执行文件: {args[0]}"
    except OSError as exc:
        return -3, "", f"执行失败: {exc}"


def iter_lines(args: list[str], timeout: int = 900, sink: dict | None = None):
    """流式读取子进程 stdout，逐行 yield。

    大 pcap 的 ``-T fields`` 输出可能有几十万行，整份读进内存会撑爆便携环境，
    所以边读边吐。

    Args:
        args: 完整命令行（argv 列表）。
        timeout: 超时秒数；到点直接 kill 子进程（其余行不再产出）。
        sink: 可选字典，函数结束前会写入 ``{"rc": 退出码, "stderr": 错误输出}``。
            调用方**必须**检查它 —— tshark 对不完整文件返回 14、
            被杀返回负数，只凭「有没有收到行」无法区分「读完了」和「读到一半」。

    Yields:
        str: 一行输出（已去掉行尾换行符）。

    Note:
        这是生成器：不把 ``sink`` 传进去就永远拿不到退出码，
        会把「解析中断」误当成「解析完成」（T00 的根因）。
    """
    import threading

    proc = None
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1 << 20,
            creationflags=CREATE_NO_WINDOW,
            env=_env(),
        )
        killer = threading.Timer(timeout, proc.kill)
        killer.daemon = True
        killer.start()
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                yield line.rstrip("\r\n")
        finally:
            killer.cancel()
            try:
                proc.stdout.close()  # type: ignore[union-attr]
            except Exception:
                pass
            err = ""
            try:
                err = (proc.stderr.read() or "")  # type: ignore[union-attr]
            except Exception:
                pass
            proc.wait()
            # stderr 也必须显式关闭：只 read() 不 close() 会让 TextIOWrapper 活到 GC，
            # 在 Windows 上表现为 ResourceWarning + 短暂占用管道句柄。
            try:
                proc.stderr.close()  # type: ignore[union-attr]
            except Exception:
                pass
            if sink is not None:
                sink["rc"] = proc.returncode
                sink["stderr"] = err
    except FileNotFoundError:
        if sink is not None:
            sink.update({"rc": -2, "stderr": f"找不到可执行文件: {args[0]}"})
    except OSError as exc:
        if sink is not None:
            sink.update({"rc": -3, "stderr": f"执行失败: {exc}"})
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass


def version(tshark: Path | None = None) -> str:
    """取 tshark 版本串。

    Args:
        tshark: 可执行文件路径；省略时自动查找。

    Returns:
        str: 版本首行，如 ``"TShark (Wireshark) 4.7.4 ..."``；
            找不到时返回 ``"未找到 tshark"``，取不到版本时返回 ``"tshark 版本未知 (rc=N)"``。
    """
    tshark = tshark or find_tshark()
    if not tshark:
        return "未找到 tshark"
    rc, out, err = run([str(tshark), "-v"], timeout=30)
    for line in (out or err).splitlines():
        line = line.strip()
        if line:
            return line
    return f"tshark 版本未知 (rc={rc})"


def list_interfaces(tshark: Path | None = None) -> list[dict]:
    """列出可用于抓包的网卡（解析 ``tshark -D``）。

    Args:
        tshark: 可执行文件路径；省略时自动查找。

    Returns:
        list[dict]: 每项 ``{"index": int, "name": str, "raw": str}``。
            ``name`` 保留原串（含括号别名），展示前请过 ``short_name()``；
            找不到 tshark 或没有网卡时返回空列表。
    """
    tshark = tshark or find_tshark()
    if not tshark:
        return []
    rc, out, err = run([str(tshark), "-D"], timeout=45)
    if rc != 0 and not out:
        # 部分环境下 -D 会把列表写到 stderr
        out = err
    items: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "." not in line:
            continue
        idx, _, name = line.partition(".")
        idx = idx.strip()
        if not idx.isdigit():
            continue
        items.append({"index": int(idx), "name": name.strip(), "raw": line})
    return items


# 只用来给候选**排优先级**，绝不从列表里删：VPN 虚拟网卡可能恰好是唯一通路，
# 删掉它们会让用户彻底抓不到包。命中这些词的网卡排到物理网卡后面。
SKIP_HINTS = (
    "loopback", "npf_loopback", "npcap loopback", "adapter for loopback", "回环",
    "本地连接*", "local area connection*", "蓝牙", "bluetooth",
    "vmware", "virtualbox", "vbox", "vmnet", "hyper-v", "vethernet",
    "meta", "tun", "tap", "docker", "wsl",
    "teredo", "isatap", "tunnel", "虚拟",
    # tshark 的 extcap 伪接口（远程抓包 / 随机包生成器），不是网卡，排到最后。
    "ciscodump", "etwdump", "randpkt", "sshdump", "udpdump", "wifidump",
    "remote capture",
)

PREFER_HINTS = ("以太网", "ethernet", "wlan", "wi-fi", "wireless", "无线")

# 虚拟网卡内部再分一层：VPN/TUN 可能正是用户唯一的上网通路，排在蓝牙、回环、
# tshark extcap 伪接口前面；但仍整体排在物理网卡后面。
LATE_PREFER_HINTS = ("meta", "tun", "tap", "wireguard", "vpn", "clash", "wintun")


def _candidate_rank(item: dict) -> tuple[int, int, int]:
    """给一块网卡算排序键：物理网卡在前，虚拟/外设网卡在后。

    ``index`` 只做同类兜底，保证 ``tshark -D`` 的原顺序在排序后仍然稳定。
    """
    name = str(item.get("name") or "").lower()
    index = int(item.get("index") or 0)
    if any(hint in name for hint in SKIP_HINTS):
        # 已被判为虚拟/外设的网卡不再按「Wi-Fi」等好名字插队；但 VPN/TUN 要
        # 排在其他虚拟网卡前面——它很可能就是默认路由，而蓝牙/回环几乎不会。
        late = 0 if any(hint in name for hint in LATE_PREFER_HINTS) else 1
        return (1, late, index)
    preferred = next((n for n, hint in enumerate(PREFER_HINTS) if hint in name),
                     len(PREFER_HINTS))
    return (0, preferred, index)


def order_interfaces(interfaces: list[dict]) -> list[dict]:
    """按候选优先级排序（物理优先、虚拟靠后），**不删除**任何网卡。

    用户机器上常同时有 WLAN、断开的以太网、Clash/Meta TUN、VMware、蓝牙、
    Wi-Fi Direct 等一堆网卡；名字看不出哪块通外网，但「物理网卡优先」能先把
    最可能通外网的那块排前面，再交给 :func:`probe_interface` 用真实流量验证。

    Args:
        interfaces: ``list_interfaces()`` 的返回值。

    Returns:
        list[dict]: 新列表，顺序为「以太网/WLAN 等物理网卡 → 其它未命中
            :data:`SKIP_HINTS` 的网卡 → Meta/TUN 等 VPN 虚拟网卡 → VMware/蓝牙/
            回环/extcap 伪接口」。同类内按 :data:`PREFER_HINTS` 与 ``index``
            稳定排序；输入为空返回 ``[]``。
    """
    return sorted(interfaces, key=_candidate_rank)


def pick_interface(interfaces: list[dict]) -> dict | None:
    """挑一块「像样」的默认网卡（按名字猜，不验证是否有流量）。

    按业务优先级：先按 :data:`PREFER_HINTS` 找物理网卡（以太网/Wi-Fi），
    再用 :data:`SKIP_HINTS` 把回环、蓝牙、虚拟网卡（VMware/Meta/Hyper-V 等）
    降到后面。**只排序不删除**：虚拟网卡全被跳过时会退回完整列表，
    避免「唯一可用的就是 VPN 网卡」时返回 ``None``。

    注意：本函数只看名字，断开的以太网也会被选中；要真正选到有流量的网卡，
    调用方应先用 :func:`probe_interface` 按 :func:`order_interfaces` 的顺序探测。

    Args:
        interfaces: ``list_interfaces()`` 的返回值。

    Returns:
        dict | None: 选中的那一项；输入为空时返回 ``None``。
    """
    if not interfaces:
        return None
    good = [i for i in interfaces if not any(s in i["name"].lower() for s in SKIP_HINTS)]
    # 没有物理网卡时按候选顺序兜底：VPN/TUN 排在蓝牙/回环前面，仍绝不返回 None。
    pool = good or order_interfaces(interfaces)
    for hint in PREFER_HINTS:
        for i in pool:
            if hint in i["name"].lower():
                return i
    return pool[0]


def probe_interface(tshark_path: Path, candidates: list[dict], seconds: int = 2) -> dict | None:
    """逐个网卡试抓几秒，返回第一个真有流量的。

    用户机器上常有一堆虚拟网卡（VPN、Docker、VMware），名字看不出哪个通外网；
    用「抓两秒看有没有包」比猜名字可靠。

    Args:
        tshark_path: tshark 可执行文件路径。
        candidates: 候选网卡列表（最多试前 5 个，避免启动时等太久）。
        seconds: 每个网卡试抓的秒数。

    Returns:
        dict | None: 第一个抓到包的网卡项；都没流量返回 ``None``。
    """
    for i in candidates[:5]:
        rc, out, err = run(
            [str(tshark_path), "-i", str(i["index"]), "-a", f"duration:{seconds}",
             "-c", "20", "-T", "fields", "-e", "frame.number"],
            timeout=seconds + 15,
        )
        if len([ln for ln in (out or "").splitlines() if ln.strip()]):
            return i
    return None


def is_admin() -> bool:
    """当前进程是否管理员。

    Returns:
        bool: Windows 上问 ``IsUserAnAdmin()``；非 Windows 看 ``geteuid()==0``。
            查不到时返回 ``False``（保守：宁可提示「可能抓不了包」）。
    """
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else True
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def npcap_installed() -> bool:
    """检测 Npcap 是否就绪（优先看文件，最后才问服务状态）。

    只查文件系统是毫秒级；``sc query`` 在受限环境里可能卡住，因此放最后、
    超时压到 5 秒，且不再把它的输出当唯一判据（服务名可能是 ``npcap`` 或 ``npf``，
    输出还是本地化的）。

    Returns:
        bool: 命中安装目录 / ``wpcap.dll`` / ``drivers/npcap.sys`` / ``Packet.dll``
            任一即 True；非 Windows 恒 True。
    """
    if os.name != "nt":
        return True
    sysroot = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    for probe in (
        sysroot / "System32" / "Npcap",              # Npcap 安装目录
        sysroot / "System32" / "wpcap.dll",          # WinPcap 兼容 DLL
        sysroot / "System32" / "drivers" / "npcap.sys",
        sysroot / "System32" / "Packet.dll",
    ):
        try:
            if probe.exists():
                return True
        except OSError:
            continue
    rc, out, _ = run(["sc", "query", "npcap"], timeout=5)
    if rc != 0:
        return False
    text = (out or "").upper()
    return "RUNNING" in text or "STOPPED" in text
