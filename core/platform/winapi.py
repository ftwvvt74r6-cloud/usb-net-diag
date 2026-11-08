"""Windows 平台能力：管理员、Npcap、网卡、网关、DNS。

**唯一原则：不解析本地化 CLI 文本。** 现有实现靠 ``sc query`` / ``ipconfig`` /
``tracert`` 的输出子串判断，在中文 Windows、不同 Windows 版本、不同区域设置下
会静默失效（评审第 4 步）。这里改为：

* 能用 ``ctypes`` 调 API 的，一律调 API（``GetAdaptersAddresses`` / ``GetIpForwardTable2``）；
* 退而求其次是查注册表/文件系统（``npcap_installed``）；
* 实在要用命令行时，**只判断返回码**，不判断文本。

本文件只放骨架：``is_admin`` / ``npcap_installed`` / ``default_gateway`` /
``icmp_stats`` / ``dns_servers`` 已可用；``adapters`` 现在借 ``tshark -D`` 的网卡名，
``interface_index_map`` 仍是签名占位（建议真机调通后再落地）。
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------- 只读网络 API
class _MIB_IPFORWARDROW(ctypes.Structure):
    """``GetBestRoute`` 的返回结构（14 个 DWORD，Windows SDK 原样映射）。

    ``dwForwardNextHop`` 就是默认路由的下一跳（即默认网关）；用 API 而不是解析
    ``ipconfig``/``route print``，避免中文/英文系统的本地化文本差异。
    """

    _fields_ = [
        ("dwForwardDest", ctypes.c_uint32),
        ("dwForwardMask", ctypes.c_uint32),
        ("dwForwardPolicy", ctypes.c_uint32),
        ("dwForwardNextHop", ctypes.c_uint32),
        ("dwForwardIfIndex", ctypes.c_uint32),
        ("dwForwardType", ctypes.c_uint32),
        ("dwForwardProto", ctypes.c_uint32),
        ("dwForwardAge", ctypes.c_uint32),
        ("dwForwardNextHopAS", ctypes.c_uint32),
    ] + [(f"dwForwardMetric{i}", ctypes.c_uint32) for i in range(1, 6)]


class _IP_OPTION_INFORMATION(ctypes.Structure):
    """``IcmpSendEcho`` 的可选 IP 头参数（这里全部留空 = 系统默认）。"""

    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    """``IcmpSendEcho`` 的回复头；``RoundTripTime`` 单位毫秒。"""

    _fields_ = [
        ("Address", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", _IP_OPTION_INFORMATION),
    ]


# ---------------------------------------------------------------- 权限 / 驱动


def is_admin() -> bool:
    """当前进程是否具备管理员权限（实时抓包的前提）。

    Returns:
        bool: Windows 上问 ``IsUserAnAdmin()``；非 Windows 看 ``geteuid()==0``。
            调用失败返回 ``False``（保守：宁可提示可能抓不了包）。
    """
    if not IS_WINDOWS:
        return bool(getattr(os, "geteuid", lambda: 0)() == 0)
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def npcap_installed() -> bool:
    """Npcap 是否就绪。

    判定顺序（从便宜到贵）：驱动目录 → ``wpcap.dll`` → 服务注册表键。
    **不判断服务状态文本** —— 服务名可能是 ``npcap`` 或 ``npf``，
    ``sc query`` 的输出还是本地化的，靠文本匹配会在中文/英文系统上表现不一致。

    Returns:
        bool: 任一证据命中即 True；非 Windows 恒 True。
    """
    if not IS_WINDOWS:
        return True
    sysroot = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    if (sysroot / "System32" / "Npcap").is_dir():
        return True
    if (sysroot / "System32" / "wpcap.dll").is_file():
        return True
    try:
        import winreg  # noqa: PLC0415  仅 Windows 可用

        for key in (r"SYSTEM\CurrentControlSet\Services\npcap",
                    r"SYSTEM\CurrentControlSet\Services\npf"):
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key).Close()
                return True
            except OSError:
                continue
    except ImportError:
        pass
    return False


# ---------------------------------------------------------------- 网络配置（骨架）


@dataclass(frozen=True)
class Adapter:
    """一块网卡及其地址。

    字段：
        name: 友好名（``以太网`` / ``WLAN``），给用户看。
        description: 原始设备串（``tshark -D`` 的整行），排障时用于确认是哪块卡。
        mac: MAC 地址；临时实现下为空。
        ipv4 / gateway / dns: 地址、网关、DNS 列表；临时实现下为空元组。
        is_up: 是否已连接。
    """
    name: str
    description: str
    mac: str
    ipv4: tuple[str, ...] = ()
    gateway: tuple[str, ...] = ()
    dns: tuple[str, ...] = ()
    is_up: bool = True


def _legacy_tshark():
    """拿到现有的 ``core/tshark`` 模块，包内导入与扁平导入两种方式都试。

    Returns:
        模块对象；拿不到时返回 ``None``（调用方据此降级）。

    Note:
        这里用延迟导入而不是模块级导入，是因为 ``platform`` 是底层包，
        import 期再去拉起 tshark 会让「只想读配置」的调用方也付出进程开销。
    """
    try:                                   # 场景一：core 是包（from core.platform import winapi）
        from .. import tshark as mod        # type: ignore[import-not-found]
        return mod
    except Exception:
        pass
    try:                                   # 场景二：core 在 sys.path 上（脚本方式运行）
        import tshark as mod                # type: ignore[import-not-found]
        return mod
    except Exception:
        return None


def adapters() -> tuple[Adapter, ...]:
    """枚举网卡与地址（替代 ``ipconfig`` 文本解析）。

    当前为**临时实现**：转发到 ``tshark -D``，只提供网卡序号与友好名，
    ``ipv4`` / ``gateway`` / ``dns`` / ``mac`` 均为空 —— 因为 ``-D`` 不带地址信息。
    第 4 阶段（T13 路径探测）会换成 ``GetAdaptersAddresses`` 的 ctypes 实现，
    届时这几个字段才有真实值。

    实现要点（真机调试用）::

        GetAdaptersAddresses(
            Family=AF_UNSPEC,
            Flags=GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
            Reserved=None, SizePointer=byref(size), Addresses=buf)

    先用 ``size=0`` 调一次拿 ``ERROR_BUFFER_OVERFLOW`` 的所需长度，
    再分配缓冲区二次调用。字段：``FriendlyName`` / ``PhysicalAddress`` /
    ``FirstUnicastAddress`` / ``FirstGatewayAddress`` / ``FirstDnsServerAddress``。

    Returns:
        按 ``tshark -D`` 顺序排列的 :class:`Adapter` 元组；找不到 tshark 时返回空元组
        （**不抛异常**，让上层用「无网卡」的正常分支处理）。
    """
    mod = _legacy_tshark()
    if mod is None:
        return ()
    try:
        items = mod.list_interfaces() or []
    except Exception:
        return ()
    out: list[Adapter] = []
    for item in items:
        raw = str(item.get("raw") or item.get("name") or "")
        name = str(item.get("name") or "")
        # ``tshark -D`` 的形态是 ``1. \Device\NPF_{GUID} (以太网)``：括号里才是人看的名字
        friendly = name
        if "(" in name and name.endswith(")"):
            friendly = name[name.rfind("(") + 1:-1].strip() or name
        out.append(Adapter(name=friendly, description=raw, mac=""))
    return tuple(out)


def default_gateway(dest: str = "8.8.8.8") -> str:
    """默认网关地址（路径探测 / 0 包降级时判断「本地链路是否可达」）。

    调 ``iphlpapi.GetBestRoute`` 查「去往 ``dest`` 的最优路由」的下一跳，**不解析
    任何本地化命令行输出**。没有默认路由（如断网、只有直连网段）时返回空串。

    Args:
        dest: 查询目的地址（IPv4 字面量），默认 ``8.8.8.8``，即走默认路由。

    Returns:
        str: 网关 IPv4 地址；非 Windows、无默认路由或 API 调用失败时返回 ``""``。
    """
    if not IS_WINDOWS:
        return ""
    try:
        packed = socket.inet_aton(str(dest))
    except OSError:
        return ""
    row = _MIB_IPFORWARDROW()
    try:
        rc = ctypes.windll.iphlpapi.GetBestRoute(  # type: ignore[attr-defined]
            struct.unpack("<I", packed)[0], 0, ctypes.byref(row))
    except Exception:  # noqa: BLE001  API 缺失/权限异常都按「没网关」处理
        return ""
    if rc != 0 or row.dwForwardNextHop == 0:
        return ""
    return socket.inet_ntoa(struct.pack("<I", row.dwForwardNextHop))


def icmp_stats(host: str, count: int = 4, timeout_ms: int = 800) -> dict:
    """用 Windows ``IcmpSendEcho`` 测一个地址的 RTT / 抖动 / 丢包（非管理员可用）。

    0 包优雅降级需要一组「链路是否可达」的数字，但抓包可能根本看不到业务报文；
    这里用系统 ICMP 回显做一次轻量探测。用 API 而不是解析 ``ping`` 文本：中文 /
    英文系统的输出格式不同，做文本匹配会在别的机器上静默失效。

    Args:
        host: IPv4 字面量（域名请先解析；本函数不联网查 DNS）。
        count: 探测次数，夹在 1~10；默认 4。
        timeout_ms: 单次等待毫秒数，夹在 100~5000；默认 800。

    Returns:
        dict: 键 ``ok``（至少收到 1 个回复）/ ``host`` / ``sent`` / ``recv`` /
            ``loss_pct``（0~100，1 位小数）/ ``avg_ms`` / ``jitter_ms``（RTT 总体
            标准差，1 位小数）/ ``error``（失败原因，成功为空串）。非 Windows、
            非 IPv4、API 不可用时 ``ok=False`` 且 ``error`` 说明原因，不抛异常。
    """
    host = str(host or "").strip()
    count = max(1, min(int(count or 4), 10))
    timeout_ms = max(100, min(int(timeout_ms or 800), 5000))
    empty = {"ok": False, "host": host, "sent": count, "recv": 0,
             "loss_pct": 100.0, "avg_ms": 0.0, "jitter_ms": 0.0}
    if not IS_WINDOWS:
        return {**empty, "error": "仅 Windows 支持 ICMP 探测"}
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return {**empty, "error": "不是合法 IPv4 地址"}
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi")
        iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
        iphlpapi.IcmpSendEcho.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_ushort,
            ctypes.POINTER(_IP_OPTION_INFORMATION), ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_uint32,
        ]
        iphlpapi.IcmpSendEcho.restype = ctypes.c_uint32
        iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        handle = iphlpapi.IcmpCreateFile()
    except Exception as exc:  # noqa: BLE001  API 不可用只降级，不影响主流程
        return {**empty, "error": f"ICMP API 不可用：{type(exc).__name__}: {exc}"}
    if not handle or handle == ctypes.c_void_p(-1).value:
        return {**empty, "error": "IcmpCreateFile 失败"}
    payload = ctypes.create_string_buffer(b"netdiag-probe")
    reply = ctypes.create_string_buffer(ctypes.sizeof(_ICMP_ECHO_REPLY) + 256)
    dest = struct.unpack("<I", packed)[0]
    samples: list[float] = []
    last_error = ""
    try:
        for _ in range(count):
            n = iphlpapi.IcmpSendEcho(
                handle, dest, payload, len(payload.raw),
                None, reply, ctypes.sizeof(reply), timeout_ms)
            row = _ICMP_ECHO_REPLY.from_buffer(reply)
            if n >= 1 and row.Status == 0:
                samples.append(float(row.RoundTripTime))
            elif n == 0:
                last_error = "超时或无回复"
            else:
                last_error = f"ICMP 状态 {row.Status}"
    except Exception as exc:  # noqa: BLE001  探测异常按丢包处理
        last_error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            iphlpapi.IcmpCloseHandle(handle)
        except Exception:  # noqa: BLE001  关闭句柄失败不影响结果
            pass

    recv = len(samples)
    if recv == 0:
        return {**empty, "error": last_error or "没有收到 ICMP 回复"}
    avg = sum(samples) / recv
    jitter = (sum((x - avg) ** 2 for x in samples) / recv) ** 0.5
    return {
        "ok": True,
        "host": host,
        "sent": count,
        "recv": recv,
        "loss_pct": round((count - recv) / count * 100.0, 1),
        "avg_ms": round(avg, 1),
        "jitter_ms": round(jitter, 1),
        "error": "",
    }


def _registry_dns_values() -> list[str]:
    """从注册表读出「配置过的 DNS 服务器」原始字符串（内部函数）。

    只读两条来源，**不解析任何本地化 CLI 文本**：

    1. 每块网卡的 ``Tcpip\\Parameters\\Interfaces\\{GUID}`` 下的
       ``NameServer``（静态配置）与 ``DhcpNameServer``（DHCP 下发）；
    2. 全局 ``Tcpip\\Parameters`` 下的同名值（组策略/旧配置可能只写这里）。

    网络适配器键名是 GUID（与语言无关），所以这条路在中文/英文系统上行为一致。

    Returns:
        list[str]: 原始值（可能含空格/逗号分隔的多个地址、``0.0.0.0`` 与 IPv6）；
            非 Windows、注册表不可读时返回空列表（不抛异常）。
    """
    if not IS_WINDOWS:
        return []
    try:
        import winreg  # noqa: PLC0415  仅 Windows 可用
    except ImportError:
        return []
    base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    values: list[str] = []

    def _read(handle) -> None:
        for name in ("NameServer", "DhcpNameServer"):
            try:
                value, _kind = winreg.QueryValueEx(handle, name)
            except OSError:
                continue
            if isinstance(value, str) and value.strip():
                values.append(value)

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root:
            _read(root)
            try:
                interfaces = winreg.OpenKey(root, "Interfaces")
            except OSError:
                interfaces = None
            if interfaces is not None:
                with interfaces:
                    index = 0
                    while True:
                        try:
                            guid = winreg.EnumKey(interfaces, index)
                        except OSError:
                            break
                        index += 1
                        try:
                            with winreg.OpenKey(interfaces, guid) as card:
                                _read(card)
                        except OSError:
                            continue
    except OSError:
        return values
    return values


def _parse_dns_list(values) -> tuple[str, ...]:
    """把注册表原始值拆成「有效 IPv4 列表」（纯函数，去重保序）。

    Args:
        values: 原始字符串集合（单个值里可能有空格/逗号/分号分隔的多个地址）。

    Returns:
        tuple[str, ...]: 规范化后的 IPv4 地址；跳过空串、``0.0.0.0``、组播、
            IPv6（带 ``%`` 的链路本地地址也跳过）。顺序按出现顺序。
    """
    out: list[str] = []
    for raw in values or ():
        text = str(raw or "").replace(";", " ").replace(",", " ")
        for part in text.split():
            try:
                address = ipaddress.ip_address(part.strip())
            except ValueError:
                continue
            if address.version != 4 or address.is_unspecified or address.is_multicast:
                continue
            normalized = str(address)
            if normalized not in out:
                out.append(normalized)
    return tuple(out)


def dns_servers() -> tuple[str, ...]:
    """当前生效的 DNS 服务器列表（只读注册表，不解析本地化 CLI 文本）。

    注意 DNS 可能来自 DHCP / 组策略 / 每网卡独立配置，开了 DoH（DNS over HTTPS）
    之后注册表里的地址与真正发查询的地址还可能不一致 —— 报告里必须标注这一
    不确定性：探 DNS 服务器只能证明「这台机器到该地址的 UDP/53 通不通」。

    Returns:
        tuple[str, ...]: 去重后的 IPv4 地址（静态配置优先于 DHCP 下发，网卡顺序按
        注册表枚举顺序）；非 Windows、注册表不可读、没有任何有效地址时返回
        ``()`` —— **不抛异常**（探针拿不到 DNS 角色只会少一行，不该拖垮诊断）。

    Example:
        >>> dns_servers()  # doctest: +SKIP
        ('192.0.2.53',)
    """
    try:
        return _parse_dns_list(_registry_dns_values())
    except Exception:  # noqa: BLE001  注册表读取失败只按「没有 DNS 角色」降级
        return ()


def interface_index_map() -> dict[str, int]:
    """网卡友好名 → tshark ``-i`` 序号。

    现状靠正则从 ``tshark -D`` 的括号别名里抠（见 ``tshark.short_name``）；
    更稳的做法是用 ``GetIfEntry2`` 的 ``InterfaceIndex`` 对齐。

    Returns:
        dict[str, int]: 友好名到序号的映射。

    Raises:
        NotImplementedError: 本阶段未实现。
    """
    raise NotImplementedError("interface_index_map(): 见 docstring")


__all__ = [
    "IS_WINDOWS", "is_admin", "npcap_installed", "Adapter",
    "adapters", "default_gateway", "icmp_stats", "dns_servers",
    "interface_index_map",
]
