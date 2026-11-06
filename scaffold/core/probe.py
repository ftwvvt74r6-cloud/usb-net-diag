"""协议自适应体检（迁移占位）。

现有 ``core/probe.py``（946 行）已经是全项目最具差异化的部分，**不要重写**，
只做两件事：

1. 返回值改成 ``contracts.ProbeResult``（或保留 dict，由适配函数转换）；
2. 每个结论带上 ``evidence_kind``：``TLS 握手失败`` 是实测，
   ``「443 上跑明文 HTTP」`` 也是实测，但 ``「大概是中间设备拦截」`` 是推断。

迁移步骤：``git mv core/probe.py core/probe_legacy.py`` → 本文件转调，
或直接把函数搬进来并把 ``sys.path`` 依赖去掉（改为 ``from .capture.tshark``）。
"""

from __future__ import annotations

from typing import Any

from .contracts import ProbeResult


def run(target: str, port: int | None = None, count: int = 4,
        timeout: float = 3.0, proto: str | None = None) -> dict[str, Any]:
    """执行一次分段体检，返回 ``ProbeResult.to_dict()`` 形态。

    TODO(迁移)：转调现有 ``core/probe.py:run()``，或把实现搬进来。
    注意保持以下**已承诺**的对外行为（README 与 SKILL.md 都写了）：

    * ``proto`` 可选值：``http|tls|smb|rdp|ssh|opaque``；
    * 认不出协议时降级 Opaque TCP，**只报建连延迟、不下应用层结论**；
    * 443 上返回明文 HTTP 时，结论改为「该端口不是 HTTPS」；
    * 分段结果 ``segments[]`` 里每段都要有 ``status`` 与 ``note``。
    """
    raise NotImplementedError("probe.run(): 见 docstring 的迁移说明")


def to_contract(raw: dict[str, Any]) -> ProbeResult:
    """把现有 dict 结果转成契约对象（迁移期适配层）。"""
    return ProbeResult(
        target=str(raw.get("target", "")),
        port=raw.get("port"),
        ip=str(raw.get("ip", "")),
        protocol=str(raw.get("protocol", "")),
        segments=tuple(raw.get("segments") or ()),
        total_ms=float(raw.get("total_ms") or 0.0),
    )


__all__ = ["run", "to_contract"]
