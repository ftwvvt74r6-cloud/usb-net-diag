"""探测结果「为什么没响应」的唯一判定器（纯逻辑，不发包、不读配置）。

**解决什么问题**
----------------
ICMP 只丢不回有两种完全不同的原因，而它们的处置方式相反：

* **链路真的丢包**：网关/中间跳也丢，TCP 侧同样劣化 —— 该找运营商；
* **目标不响应 ICMP**：公网上大量服务器与云安全组直接丢弃 echo request，
  但 443/80 的 TCP 握手完全正常 —— 这时拿「8 发 0 收 = 丢包 100%」去判
  「承载网故障」是**把对端策略当成链路劣化**（真机证据：目标 ICMP 全丢，
  TCP RTT 27.7ms、重传 3.06% 都正常，结论却写「运营商·承载网」）。

本模块只做一件事：**给定「ICMP 收发」与「同一目标的 TCP 侧证据」，给出一个
可枚举的原因**。所有探测方（影子探针 / 路径探测 / 常驻 agent）都调这里，
不许各自写一套 if —— 否则口径迟早分叉。

**四个原因**（同时也是 ``reason`` 字段的取值域）
------------------------------------------------
``ok``
    有响应。**部分丢包也算 ok**：丢包率是「量」，不是「无响应的原因」，
    部分丢包仍然可以判承载网（见 :data:`REASON_OK` 的说明）。
``icmp_filtered``
    ICMP 一个都没回，但同一目标的 TCP 探测**连上了** —— 目标活着，
    只是不理 ICMP。不得作为丢包/承载网证据。
``refused``
    ICMP 一个都没回（或没发 ICMP），而 TCP 收到 RST —— 主机在、端口没开。
    同样**不是**链路丢包（这条路上有包能到对端并能回来）。
``timeout``
    ICMP 与 TCP 都没有任何响应 —— 这才是「可能真的不通」。

**边界**
--------
不判断「丢多少算异常」（那是 verdict/规则层的事），不碰网络、不读文件。
"""
from __future__ import annotations

#: 有响应（含部分丢包）。
REASON_OK = "ok"
#: ICMP 全丢，但 TCP 侧证明目标可达 —— 目标不响应 ICMP（服务器侧策略常见）。
REASON_ICMP_FILTERED = "icmp_filtered"
#: TCP 被对端 RST 拒绝 —— 主机在、端口没开，链路本身有去有回。
REASON_REFUSED = "refused"
#: ICMP 与 TCP 都没有响应 —— 可能真的不可达。
REASON_TIMEOUT = "timeout"

#: ``reason`` 的合法取值域（顺序固定，供契约校验与文档枚举）。
PROBE_REASONS: tuple[str, ...] = (
    REASON_OK,
    REASON_ICMP_FILTERED,
    REASON_REFUSED,
    REASON_TIMEOUT,
)

#: 「目标其实活着，只是我们没拿到 ICMP 回应」的原因集合。
#: 判定层遇到这两类时**不得**把它们当成丢包证据（不判承载网）。
TARGET_ALIVE_REASONS: tuple[str, ...] = (REASON_ICMP_FILTERED, REASON_REFUSED)

#: TCP 侧证据的合法取值（``""`` 表示没有 TCP 证据，例如只探 ICMP 的端点）。
TCP_OK = "ok"
TCP_REFUSED = "refused"
TCP_TIMEOUT = "timeout"
TCP_UNREACHABLE = "unreachable"
TCP_EVIDENCES: tuple[str, ...] = ("", TCP_OK, TCP_REFUSED, TCP_TIMEOUT, TCP_UNREACHABLE)


def normalize(reason: str) -> str:
    """把任意输入收敛成 :data:`PROBE_REASONS` 里的一个值。

    旧报告 / 第三方写入的数据可能没有 ``reason``，也可能写了别的字符串。
    判定层不能因为一个陌生字符串就崩掉或静默当成 ``ok``，统一收敛到
    ``timeout``（最保守：既不宣称正常，也不宣称被过滤）。

    Args:
        reason: 任意原因串（可能为空、``None``、大小写混乱）。

    Returns:
        str: :data:`PROBE_REASONS` 中的一个；无法识别时为 :data:`REASON_TIMEOUT`。

    Example:
        >>> normalize("OK")
        'ok'
        >>> normalize("whatever")
        'timeout'
    """
    text = str(reason or "").strip().lower()
    return text if text in PROBE_REASONS else REASON_TIMEOUT


def is_target_alive(reason: str) -> bool:
    """该原因是否意味着「目标其实活着，只是 ICMP 没回」。

    Args:
        reason: ``reason`` 字段（任意值，内部先 :func:`normalize`）。

    Returns:
        bool: ``icmp_filtered`` / ``refused`` 为 True；``ok`` / ``timeout`` 为 False。

    Example:
        >>> is_target_alive("icmp_filtered")
        True
        >>> is_target_alive("timeout")
        False
    """
    return normalize(reason) in TARGET_ALIVE_REASONS


def endpoint_reason(*, icmp_sent: int = 0, icmp_recv: int = 0,
                    tcp: str = "") -> str:
    """按「ICMP 收发 + TCP 证据」定一个原因。

    判定顺序（先看 ICMP 有没有回，再看 TCP 能不能证明目标活着）：

    1. ``icmp_sent <= 0``：本次没发 ICMP（只探 TCP 的端点）→ 直接按 ``tcp`` 定；
    2. ``icmp_recv > 0``：有回应 → ``ok``（**部分丢包仍是 ok**，丢多少交给阈值层）；
    3. ICMP 一个都没回：TCP 连上 → ``icmp_filtered``；TCP 被 RST → ``refused``；
       其余（超时 / 不可达 / 没测）→ ``timeout``。

    Args:
        icmp_sent: 发出的 ICMP 探测包数（``0`` 表示没发）。
        icmp_recv: 收到回应的 ICMP 包数。
        tcp: TCP 侧证据，取 :data:`TCP_EVIDENCES`；``""`` 表示没测。

    Returns:
        str: :data:`PROBE_REASONS` 之一。

    Example:
        >>> endpoint_reason(icmp_sent=8, icmp_recv=0, tcp="ok")
        'icmp_filtered'
        >>> endpoint_reason(icmp_sent=8, icmp_recv=0, tcp="refused")
        'refused'
        >>> endpoint_reason(icmp_sent=8, icmp_recv=0, tcp="timeout")
        'timeout'
        >>> endpoint_reason(icmp_sent=4, icmp_recv=3, tcp="")
        'ok'
        >>> endpoint_reason(icmp_sent=0, icmp_recv=0, tcp="ok")
        'ok'
    """
    try:
        sent = int(icmp_sent or 0)
        recv = int(icmp_recv or 0)
    except (TypeError, ValueError):
        sent, recv = 0, 0
    if sent <= 0:
        # 没发 ICMP：TCP 是唯一证据源。
        if tcp == TCP_OK:
            return REASON_OK
        if tcp == TCP_REFUSED:
            return REASON_REFUSED
        return REASON_TIMEOUT
    if recv > 0:
        return REASON_OK
    if tcp == TCP_OK:
        return REASON_ICMP_FILTERED
    if tcp == TCP_REFUSED:
        return REASON_REFUSED
    return REASON_TIMEOUT


__all__ = [
    "REASON_OK",
    "REASON_ICMP_FILTERED",
    "REASON_REFUSED",
    "REASON_TIMEOUT",
    "PROBE_REASONS",
    "TARGET_ALIVE_REASONS",
    "TCP_OK",
    "TCP_REFUSED",
    "TCP_TIMEOUT",
    "TCP_UNREACHABLE",
    "TCP_EVIDENCES",
    "normalize",
    "is_target_alive",
    "endpoint_reason",
]
