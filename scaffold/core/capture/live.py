"""抓包编排：策略选择 → 网卡选择 → 抓包 → 降级。

现有 ``core/diagnose.py:capture_live()`` 已经把这套踩通了（提权、Npcap 兜底、
自动选网卡、失败降级提示）。这里只把它拆成「计划（可序列化）+ 执行」两段，
好处是**抓包参数能进报告**，复现时不用猜当时用的什么过滤器和网卡。

关键约束（不要退化）：

* 抓包失败必须返回 ``degraded=True`` 并给出「改用离线分析」的提示，**不能抛异常**；
* 探针一旦启用，``bpf`` 必须并入 ``ProbeLedger.exclusion_bpf()``；
* ``duration`` 上限读配置（默认 180s），不要硬编码在调用点。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ..platform.paths import PATHS


@dataclass(frozen=True)
class CapturePlan:
    mode: str = "live"                 # live | offline
    interface_index: int | None = None
    interface_name: str = ""
    target: str = ""
    duration_s: int = 30
    bpf: str = ""
    out_dir: Path = PATHS.captures
    pcap: str = ""                     # offline 时的输入

    def bpf_for(self) -> str:
        """按目标生成 BPF：``host <ip>`` / ``net <cidr>``；空目标 = 全部流量。"""
        target = (self.target or "").strip()
        if not target:
            return self.bpf
        base = f"net {target}" if "/" in target else f"host {target}"
        return f"({base}) and ({self.bpf})" if self.bpf else base


@dataclass(frozen=True)
class CaptureOutcome:
    ok: bool
    pcap: str = ""
    interface: str = ""
    bpf: str = ""
    duration_s: int = 0
    error: str = ""
    degraded: bool = False


def capture(plan: CapturePlan, log=None) -> CaptureOutcome:
    """执行抓包。

    TODO(迁移)：平移 ``core/diagnose.py:capture_live()``。检查顺序不要变：

    1. ``TsharkAdapter.discover().available`` → 否则 ``degraded`` + 「未找到 tshark」；
    2. ``winapi.is_admin()`` / ``winapi.npcap_installed()`` → 否则 ``degraded``；
    3. 网卡：显式指定 → 名称关键字 → 自动挑（跳过回环/虚拟/蓝牙）→ 试抓 2s 找有流量的；
    4. 组装 ``-i <idx> -w <pcap> -a duration:<n> -q [-f <bpf>]``；
    5. 输出为空/报错时的**错误分类**（权限 vs 其他）要保留，文案见 ``errors.HINTS``。

    探针模式下在第 4 步把 ``plan.bpf + ProbeLedger.exclusion_bpf()`` 一起传给 ``-f``。
    """
    raise NotImplementedError("capture(): 见 docstring 的检查顺序")


def resolve_interface(interfaces: list[Mapping], spec: str | int | None) -> Mapping | None:
    """按序号或名称关键字挑网卡（已实现：纯函数，便于单测）。"""
    if not interfaces:
        return None
    if spec in (None, "", 0, "0"):
        return None
    text = str(spec).strip()
    if text.isdigit():
        wanted = int(text)
        return next((i for i in interfaces if int(i.get("index", -1)) == wanted), None)
    lowered = text.lower()
    return next((i for i in interfaces if lowered in str(i.get("name", "")).lower()), None)


__all__ = ["CapturePlan", "CaptureOutcome", "capture", "resolve_interface"]
