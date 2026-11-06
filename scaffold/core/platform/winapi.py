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
    """当前进程是否具备管理员权限（实时抓包的前提）。"""
    if not IS_WINDOWS:
        return bool(getattr(os, "geteuid", lambda: 0)() == 0)
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def npcap_installed() -> bool:
    """Npcap 是否就绪。

    判定顺序（从便宜到贵）：驱动目录 → wpcap.dll → 服务注册表键存在。
    **不判断服务状态文本**：Npcap 的服务名可能是 ``npcap`` 或 ``npf``，
    且 ``sc query`` 的输出是本地化的。
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
    name: str
    description: str
    mac: str
    ipv4: tuple[str, ...] = ()
    gateway: tuple[str, ...] = ()
    dns: tuple[str, ...] = ()
    is_up: bool = True


def adapters() -> tuple[Adapter, ...]:
    """枚举网卡与地址（替代 ``ipconfig`` 文本解析）。

    实现要点（真机调试用）::

        GetAdaptersAddresses(
            Family=AF_UNSPEC,
            Flags=GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
            Reserved=None, SizePointer=byref(size), Addresses=buf)

    先用 ``size=0`` 调一次拿 ``ERROR_BUFFER_OVERFLOW`` 的所需长度，
    再分配缓冲区二次调用。字段：``FriendlyName`` / ``PhysicalAddress`` /
    ``FirstUnicastAddress`` / ``FirstGatewayAddress`` / ``FirstDnsServerAddress``。

    TODO: 落地时替换为真实 ctypes 实现；在此之前可临时调用现有
    ``core/tshark.py:list_interfaces()``（只看 ``-D`` 的序号与别名）。
    """
    raise NotImplementedError("adapters(): 见本函数 docstring 的 GetAdaptersAddresses 实现要点")


def default_gateway() -> str:
    """默认网关地址（路径探测第 1 跳）。

    可选的更简路径：``scapy.all.conf.route.default_gateway()``（内置 scapy 2.8 已有），
    或 ``GetBestRoute2(interfaceLuid=0, ...)``。
    """
    raise NotImplementedError("default_gateway(): 见 docstring")


def dns_servers() -> tuple[str, ...]:
    """当前生效的 DNS 服务器列表。

    注意：DNS 可能来自 DHCP / 组策略 / 每网卡独立配置，且 DoH 开启后
    注册表里的地址可能与实际查询走的不一致——报告里要标注这一不确定性。
    """
    raise NotImplementedError("dns_servers(): 见 adapters() 的 FirstDnsServerAddress")


def interface_index_map() -> dict[str, int]:
    """网卡友好名 → tshark ``-i`` 序号。

    现状：``tshark.list_interfaces()`` 返回的 ``name`` 里带 ``(中文别名)``，
    用正则抠出来（``tshark.short_name``）。更稳的做法是 ``tshark -D`` +
    ``GetIfEntry2`` 的 ``InterfaceIndex`` 对齐。
    """
    raise NotImplementedError("interface_index_map(): 见 docstring")


__all__ = [
    "IS_WINDOWS", "is_admin", "npcap_installed", "Adapter",
    "adapters", "default_gateway", "dns_servers", "interface_index_map",
]
