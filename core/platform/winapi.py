"""Windows 平台能力：管理员、Npcap、网卡、网关、DNS。

**唯一原则：不解析本地化 CLI 文本。** 现有实现靠 ``sc query`` / ``ipconfig`` /
``tracert`` 的输出子串判断，在中文 Windows、不同 Windows 版本、不同区域设置下
会静默失效（评审第 4 步）。这里改为：

* 能用 ``ctypes`` 调 API 的，一律调 API（``GetAdaptersAddresses`` / ``GetIpForwardTable2``）；
* 退而求其次是查注册表/文件系统（``npcap_installed``）；
* 实在要用命令行时，**只判断返回码**，不判断文本。

本文件只放骨架：``is_admin`` / ``npcap_installed`` 可直接用，网络配置查询给了签名
与实现要点（结构体较长，建议真机调通后再落地）。
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path

IS_WINDOWS = os.name == "nt"


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


def default_gateway() -> str:
    """默认网关地址（路径探测的第 1 跳）。

    Returns:
        str: 网关 IP。

    Raises:
        NotImplementedError: 本阶段未实现。落地方案见 docstring 正文
            （``GetBestRoute2`` 或内置 Scapy 的 ``conf.route.default_gateway()``）。
    """
    raise NotImplementedError("default_gateway(): 见 docstring")


def dns_servers() -> tuple[str, ...]:
    """当前生效的 DNS 服务器列表。

    注意 DNS 可能来自 DHCP / 组策略 / 每网卡独立配置，开了 DoH 之后
    注册表里的地址与真正发查询的地址还可能不一致 —— 报告里必须标注这一不确定性。

    Returns:
        tuple[str, ...]: DNS 服务器地址。

    Raises:
        NotImplementedError: 本阶段未实现（随 ``adapters()`` 一起落地）。
    """
    raise NotImplementedError("dns_servers(): 见 adapters() 的 FirstDnsServerAddress")


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
    "adapters", "default_gateway", "dns_servers", "interface_index_map",
]
