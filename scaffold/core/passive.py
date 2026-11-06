"""被动监听（迁移占位）。

现有 ``core/passive.py``（483 行）可用，且是 scapy 2.8 的唯一使用者。
迁移时保持三点不变：

1. **引擎自动回落**：scapy 失败 → tshark，输出格式必须完全一致；
2. **不发任何报文**（这是它与 probe 的核心区别，也是合规卖点）；
3. ``Unknown TCP/UDP`` 只表示「没识别出来」，**不代表故障**——报告必须写这句，
   否则一线会把「未知」当「异常」上报。

返回值建议改为 ``contracts.PassiveResult``。
"""

from __future__ import annotations

from typing import Any

from .contracts import PassiveResult


def run(interface: str | None = None, duration: int = 20, target: str = "",
        max_packets: int = 20000, engine: str = "auto", logger=None,
        should_stop=None) -> dict[str, Any]:
    """监听网卡 ``duration`` 秒，返回会话表 + 汇总。

    TODO(迁移)：转调现有 ``core/passive.py:run()``。
    ``should_stop`` 必须真正生效——它对应 ``POST /api/v1/jobs/{id}/cancel``。
    """
    raise NotImplementedError("passive.run(): 见 docstring 的迁移说明")


def engine_status() -> dict[str, Any]:
    """返回当前可用引擎（``scapy`` / ``tshark``）与版本，供 UI 显示。"""
    raise NotImplementedError("passive.engine_status(): 转调现有实现")


def to_contract(raw: dict[str, Any]) -> PassiveResult:
    return PassiveResult(
        interface=str(raw.get("interface", "")),
        duration_s=float(raw.get("duration") or 0.0),
        engine=str(raw.get("engine", "")),
        bpf=str(raw.get("bpf", "")),
        flows=tuple(raw.get("flows") or ()),
        summary=raw.get("summary") or {},
    )


__all__ = ["run", "engine_status", "to_contract"]
