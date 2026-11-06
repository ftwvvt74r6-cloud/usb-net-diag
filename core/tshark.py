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
    """把 tshark -D 的长设备名精简为括号内的网卡别名。"""
    m = re.search(r"\(([^()]*)\)\s*$", name or "")
    return m.group(1).strip() if m else (name or "")


def find_tshark() -> Path | None:
    return _find("tshark")


def find_dumpcap() -> Path | None:
    return _find("dumpcap")


def find_npcap_installer() -> Path | None:
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
    """执行子进程，返回 (returncode, stdout, stderr)。不抛异常。"""
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
    """流式读取子进程 stdout，逐行 yield，避免大 pcap 的输出整份进内存。

    结束时把 {"rc": 返回码, "stderr": 错误输出} 写回 sink。
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
    """解析 `tshark -D`，返回 [{'index':1,'name':'以太网','raw':'...'}]"""
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


SKIP_HINTS = (
    "loopback", "npf_loopback", "adapter for loopback", "回环",
    "本地连接*", "local area connection*", "蓝牙", "bluetooth",
    "vmware", "virtualbox", "vmnet", "hyper-v", "vethernet",
    "teredo", "isatap", "tunnel", "tap-", "虚拟",
)

PREFER_HINTS = ("以太网", "ethernet", "wlan", "wi-fi", "wireless", "无线")


def pick_interface(interfaces: list[dict]) -> dict | None:
    """挑选默认网卡：按业务优先级排序，跳过回环/虚拟/蓝牙适配器。"""
    if not interfaces:
        return None
    good = [i for i in interfaces if not any(s in i["name"].lower() for s in SKIP_HINTS)]
    pool = good or interfaces
    for hint in PREFER_HINTS:
        for i in pool:
            if hint in i["name"].lower():
                return i
    return pool[0]


def probe_interface(tshark_path: Path, candidates: list[dict], seconds: int = 2) -> dict | None:
    """逐个网卡试抓 2 秒，返回第一个有流量的网卡。"""
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
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else True
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def npcap_installed() -> bool:
    """检测 Npcap 是否安装（服务或驱动目录）。"""
    if os.name != "nt":
        return True
    if Path(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap").is_dir():
        return True
    if Path(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wpcap.dll").exists():
        return True
    rc, out, _ = run(["sc", "query", "npcap"], timeout=20)
    return rc == 0 and "RUNNING" in out.upper() or (rc == 0 and "STOPPED" in out.upper())
