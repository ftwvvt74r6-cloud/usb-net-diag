"""无线链路与主机网络参数采集（``GET /api/wifi`` 的数据源）。

模块职责
--------
把「本机无线链路 + 主机网络 + 网关实测」三类参数整理成一份可展示的快照，供界面用
**一张表**呈现。对标网络工程师在 AC/无线控制器后台能看到的字段，但**只使用本机就能
拿到的数据**，拿不到的字段显式标记为「需网络后台」，不做编造。

数据来源
--------
1. ``netsh wlan show interfaces``：SSID / BSSID / 频段 / 信道 / 协议 / 信号 / RSSI /
   协商速率 / 加密方式（键名中英双份，兼容中英文系统）；
2. :func:`core.platform.winapi.default_gateway`：默认网关；
3. ``ping`` 网关 4 次：RTT 均值 / 抖动 / 丢包（解析 ``time=``/``时间=`` 数字，不依赖界面语言）。

不做什么
--------
* 不调用厂商 AC API（各厂商不统一，且需要凭据）；
* 不估算空口时延、不伪造 SNR —— SNR 按「RSSI − 噪声底(-95 dBm)」给出并**标注为估算**；
* 不读注册表、不改系统设置、不联网。
"""

from __future__ import annotations

import pathlib
import re
import socket
import statistics
import subprocess
import sys
import time

_CORE_DIR = pathlib.Path(__file__).resolve().parent
_ROOT_DIR = _CORE_DIR.parent
for _p in (str(_ROOT_DIR), str(_CORE_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
try:  # 正常布局：ROOT 在 sys.path 上，core 是可导入的包
    from core.platform import winapi  # type: ignore
except ImportError:  # 扁平布局：CORE 在 sys.path 上，platform 是包
    from platform import winapi  # type: ignore

#: 缓存秒数：界面每次进首页都会取一次，netsh 启动约 100ms，短缓存避免抖动。
CACHE_TTL_S = 15.0
_CACHE: dict = {"at": 0.0, "value": None}

#: 噪声底假设（dBm）。仅用于把 RSSI 折算成「估计信噪比」，界面必须标注是估算。
NOISE_FLOOR_DBM = -95

#: ``netsh wlan show interfaces`` 的已知键名（中英）；值一律先 strip。
_KEYS = {
    "name": ("名称", "Name"),
    "description": ("描述", "Description"),
    "guid": ("GUID",),
    "state": ("状态", "State"),
    "ssid": ("SSID",),
    "bssid": ("AP BSSID", "BSSID"),
    "band": ("频段", "Band"),
    "channel": ("信道", "Channel"),
    "radio": ("无线电类型", "Radio type"),
    "auth": ("身份验证", "Authentication"),
    "cipher": ("密码", "Cipher"),
    "rx_mbps": ("接收速率(Mbps)", "Receive rate (Mbps)", "接收速率", "Receive rate"),
    "tx_mbps": ("传输速率(Mbps)", "Transmit rate (Mbps)", "传输速率", "Transmit rate"),
    "signal_pct": ("信号", "Signal"),
    "rssi_dbm": ("Rssi", "RSSI"),
}


def _num(text: str):
    """从字符串里取出第一个数字（``-54`` / ``99%`` / ``433.3`` 都能取到）。"""
    if text is None:
        return None
    m = re.search(r"-?\d+(?:\.\d+)?", str(text))
    if not m:
        return None
    val = float(m.group(0))
    return int(val) if val.is_integer() else val


def parse_netsh_interfaces(text: str) -> dict:
    """解析 ``netsh wlan show interfaces`` 的输出，返回一份无线链路字典。

    Args:
        text: ``netsh wlan show interfaces`` 的完整输出（中文或英文系统均可）。

    Returns:
        dict: 已知字段按 :data:`_KEYS` 归一化后的字典；解析不到关键字段（如
        ``SSID``）时返回空字典，由调用方判定为「当前无无线连接/无法解析」。

    Raises:
        无。输入为空串时返回 ``{}``，不抛异常。

    Example:
        >>> parse_netsh_interfaces("    SSID                   : RR\\n    Rssi : -54")
        {'ssid': 'RR', 'rssi_dbm': -54}
    """
    if not text:
        return {}
    out: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        for field, names in _KEYS.items():
            if field in out:
                continue
            for name in names:
                if key == name or key.lower() == name.lower():
                    if field in ("rx_mbps", "tx_mbps", "signal_pct", "rssi_dbm", "channel"):
                        out[field] = _num(value)
                    else:
                        out[field] = value
                    break
    if not out.get("ssid"):
        return {}
    # 派生字段：估计信噪比（标注估算），供界面原样展示
    rssi = out.get("rssi_dbm")
    if isinstance(rssi, (int, float)):
        out["snr_est_db"] = int(rssi - NOISE_FLOOR_DBM)
    return out


def _run_netsh() -> str:
    """执行 ``netsh wlan show interfaces`` 并返回文本（失败返回空串）。"""
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    raw = proc.stdout or b""
    for enc in ("utf-8", "mbcs", "gbk"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def _ping_gateway(gateway: str, count: int = 4) -> dict:
    """ping 网关 ``count`` 次，返回 RTT 均值/抖动/丢包。

    Args:
        gateway: 网关 IPv4 地址；空串时直接返回空结果。
        count: 发包数，默认 4（总计约 4 秒）。

    Returns:
        dict: ``{"rtt_ms": float|None, "jitter_ms": float|None, "loss_pct": int|None,
        "sent": int, "recv": int}``；全部失败时各数值为 ``None``。

    Example:
        >>> _ping_gateway("") == {}
        True
    """
    if not gateway:
        return {}
    try:
        proc = subprocess.run(
            ["ping", "-n", str(count), "-w", "1000", gateway],
            capture_output=True,
            timeout=count * 2 + 5,
        )
        text = (proc.stdout or b"").decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return {}
    rtts = [float(m) for m in re.findall(r"(?:time|时间)[=<]([\d.]+)\s*ms", text, re.IGNORECASE)]
    rtts = [v for v in rtts if v >= 0]
    if not rtts:
        return {"rtt_ms": None, "jitter_ms": None, "loss_pct": 100, "sent": count, "recv": 0}
    return {
        "rtt_ms": round(statistics.mean(rtts), 1),
        "jitter_ms": round(max(rtts) - min(rtts), 1),
        "loss_pct": int(round((1 - len(rtts) / count) * 100)),
        "sent": count,
        "recv": len(rtts),
    }


def link_info() -> dict:
    """只取无线链路本身（``netsh`` 一次解析），**不 ping、不缓存**。

    与 :func:`collect` 的区别：``collect`` 会顺带 ping 网关（约 4 秒），常驻采集
    agent 每 10 秒跑一轮时不能接受这个开销 —— 它自己有网关测量通路，只需要
    SSID / BSSID / 信号这一组链路字段。

    Returns:
        dict: 同 :func:`parse_netsh_interfaces` 的结果；无无线连接时 ``{}``。

    Example:
        >>> isinstance(link_info(), dict)
        True
    """
    return parse_netsh_interfaces(_run_netsh())


def _local_ip() -> str:
    """取本机对外 IPv4（UDP connect 技巧，不实际发包；失败返回空串）。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return ""


def collect() -> dict:
    """采集一份完整快照（不做缓存）。

    Returns:
        dict: ``{"ok": bool, "available": bool, "wlan": {...}, "host": {...},
        "probe": {...}, "external": [...]}``。

        * ``available``：是否有可用的无线连接信息；
        * ``external``：本机拿不到、需要网络后台（AC）才能补的字段清单，界面直接展示为「需网络后台」。

    Example:
        >>> snap = collect()
        >>> snap["ok"]
        True
    """
    wlan = link_info()
    gateway = ""
    try:
        gateway = winapi.default_gateway() or ""
    except Exception:  # noqa: BLE001  网关拿不到不影响其它字段
        gateway = ""
    probe = _ping_gateway(gateway)
    external = [
        {"key": "air_latency", "label": "空口时延", "hint": "需从无线控制器（AC）用户详情页读取"},
        {"key": "ap_name", "label": "AP 名称 / AP ID", "hint": "需网络后台：接入 AP 的标识"},
        {"key": "roaming", "label": "漫游轨迹", "hint": "需网络后台：最近几次 AP 切换记录"},
        {"key": "channel_util", "label": "信道利用率 / 干扰", "hint": "需网络后台或抓包点统计"},
    ]
    return {
        "ok": True,
        "available": bool(wlan),
        "wlan": wlan,
        "host": {
            "local_ip": _local_ip(),
            "gateway": gateway,
        },
        "probe": probe,
        "external": external,
        "noise_floor_dbm": NOISE_FLOOR_DBM,
    }


def snapshot(force: bool = False) -> dict:
    """带短缓存的快照（界面用）。

    Args:
        force: ``True`` 时忽略缓存立即重采（「刷新参数」按钮用）。

    Returns:
        dict: 同 :func:`collect` 的结构，另含 ``cached``/``age_s`` 便于界面显示数据新鲜度。

    Raises:
        无。采集异常也会返回 ``{"ok": False, "error": "..."}``，不向上抛。

    Example:
        >>> snapshot(force=True)["ok"]
        True
    """
    now = time.time()
    if not force and _CACHE["value"] is not None and now - _CACHE["at"] <= CACHE_TTL_S:
        value = dict(_CACHE["value"])
        value["cached"] = True
        value["age_s"] = round(now - _CACHE["at"], 1)
        return value
    try:
        value = collect()
    except Exception as exc:  # noqa: BLE001  采集失败也要给界面一个可读结果
        value = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    _CACHE["value"] = value
    _CACHE["at"] = now
    out = dict(value)
    out["cached"] = False
    out["age_s"] = 0.0
    return out
