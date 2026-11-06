"""路径探测（MTR）+ 影子探测（Shadow Probing）—— 规划第 4、6 步合并实现。

**为什么合并**：两步的技术难点完全相同（目标发现、探针识别、时钟对齐、
ICMP 被过滤的第四态），分开写就会把同一批坑踩两遍。

**为什么不用 tracert**（评审第 4 步）：

* Windows 没有 mtr；
* ``tracert`` 每跳只探 3 次、不输出丢包率，拿不到「第几跳开始丢」的统计量；
* 输出是**本地化文本**（中文 Windows 是「请求超时」），解析极脆；
* 企业网常对 ICMP 限速/禁 ping，会把「被过滤」误判成「链路故障」。

**怎么实现**：用已内置的 scapy 2.8 自己发 TTL 递增探测：

    pkt = IP(dst=target, ttl=ttl) / ICMP(id=PROBE_ID, seq=n)     # ICMP 探测
    pkt = IP(dst=target, ttl=ttl) / TCP(dport=port, flags="S")   # TCP 探测（穿 ICMP 过滤）
    ans, unans = sr(pkt, timeout=1, verbose=0)

每跳采 N 次 → 丢包率 + RTT + 抖动，才有资格叫「定界」。

**三个必须做对的细节**：

1. **探针不能污染诊断**：``exclusion_bpf()`` 产出抓包过滤表达式；
   或在 analyzer 侧按账本五元组+时间窗排除。否则探针自己会造出
   ICMP 超时、额外 TCP 会话、甚至 RST，让工具变成误报机器。
2. **探针要能被认出来是自己发的**：固定 ``PROBE_ID``（ICMP id）、
   固定源端口段、固定 payload 标记，全部写进账本。
3. **时钟对齐**：pcap 用系统时钟（``frame.time_epoch``），探测用
   ``time.monotonic()``；两者有偏移。要么记录 ``clock_offset_ms`` 做校准，
   要么只做「区间归属」而不做逐包对齐。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, Sequence

#: ICMP 探测用的固定 id，便于在抓包里认出来。
PROBE_ID = 0x4E44  # "ND"
#: TCP 探测固定使用的源端口段（避开普通业务端口）。
PROBE_SRC_PORT_RANGE = (39000, 39999)


class ProbeKind(str, Enum):
    ICMP = "icmp"
    TCP_SYN = "tcp_syn"
    UDP = "udp"


class HopStatus(str, Enum):
    OK = "ok"
    LOSS = "loss"
    FILTERED = "filtered"      # 不回 ICMP，但目标端口可达 → 被策略过滤，不是故障
    UNREACHABLE = "unreachable"
    NO_TARGET = "no_target"


@dataclass(frozen=True)
class ProbeSpec:
    kind: ProbeKind
    target: str
    ttl: int = 64
    port: int | None = None
    samples: int = 5
    timeout_s: float = 1.0
    interval_s: float = 0.2
    role: str = ""             # gateway / dns / vdi / target

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ProbeKind(self.kind))


@dataclass(frozen=True)
class ProbeRecord:
    """一次探测的实际结果。**必须带时间戳**，否则无法与抓包对齐。"""

    spec: ProbeSpec
    sent_monotonic: float
    sent_epoch: float
    rtt_ms: float | None = None
    responded: bool = False
    responder: str = ""
    error: str = ""
    seq: int = 0


@dataclass
class ProbeLedger:
    """探测账本：既用于**排除**探针流量，也用于报告复现。"""

    records: list[ProbeRecord] = field(default_factory=list)
    started_epoch: float = 0.0
    finished_epoch: float = 0.0
    clock_offset_ms: float = 0.0

    # ---- 排除用 ----
    def ports(self) -> set[int]:
        return {r.spec.port for r in self.records if r.spec.port}

    def targets(self) -> set[str]:
        return {r.spec.target for r in self.records if r.spec.target}

    def has_icmp(self) -> bool:
        return any(r.spec.kind is ProbeKind.ICMP for r in self.records)

    def exclusion_bpf(self, ignore_icmp: bool = True) -> str:
        """把探针流量从抓包里排除掉的 BPF 表达式。

        ``ignore_icmp=True`` 时直接排除全部 ICMP：影子探测每 5 秒一发，
        量虽小但会让 ``icmp_unreach``/``icmp_timeout`` 计数失真。
        """
        parts: list[str] = []
        if ignore_icmp and self.has_icmp():
            parts.append("not icmp")
        for target in sorted(self.targets()):
            parts.append(f"not (host {target})")
        return " and ".join(parts)

    def window(self) -> tuple[float, float]:
        return self.started_epoch, self.finished_epoch

    def to_dict(self) -> dict:
        return {
            "started_epoch": self.started_epoch,
            "finished_epoch": self.finished_epoch,
            "clock_offset_ms": self.clock_offset_ms,
            "probe_count": len(self.records),
            "targets": sorted(self.targets()),
            "ports": sorted(self.ports()),
            "exclusion_bpf": self.exclusion_bpf(),
        }


@dataclass(frozen=True)
class HopStat:
    ttl: int
    ip: str = ""
    sent: int = 0
    lost: int = 0
    rtt_min_ms: float | None = None
    rtt_avg_ms: float | None = None
    status: HopStatus = HopStatus.OK

    @property
    def loss_pct(self) -> float:
        return round(self.lost / self.sent * 100.0, 1) if self.sent else 0.0


@dataclass(frozen=True)
class PathProbeResult:
    target: str = ""
    hops: tuple[HopStat, ...] = ()
    verdict_key: str = ""
    icmp_filtered: bool = False
    target_port_reachable: bool | None = None
    ledger: Mapping | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "verdict_key": self.verdict_key,
            "icmp_filtered": self.icmp_filtered,
            "target_port_reachable": self.target_port_reachable,
            "hops": [{"ttl": h.ttl, "ip": h.ip, "sent": h.sent, "lost": h.lost,
                      "loss_pct": h.loss_pct,
                      "rtt_avg_ms": h.rtt_avg_ms, "status": h.status.value}
                     for h in self.hops],
            "ledger": dict(self.ledger or {}),
        }


# ---------------------------------------------------------------- 定界判定


def classify(hops: Sequence[HopStat],
             target_port_reachable: bool | None = None) -> tuple[str, bool]:
    """把逐跳统计翻成「该找谁」。

    返回 ``(verdict_key, icmp_filtered)``。四态的关键是**最后一种**：
    全部都丢但目标端口 TCP 可通 → 这不是故障，是 ICMP 被策略过滤。
    """
    if not hops:
        return "PATH.NO_DATA", False

    losing = [h for h in hops if h.status is HopStatus.LOSS or h.loss_pct >= 20.0]
    if not losing:
        return "PATH.OK", False

    # ICMP 全丢但 TCP 可达 → 过滤
    if target_port_reachable and all(h.loss_pct >= 90.0 for h in hops):
        return "PATH.ICMP_FILTERED", True

    first = hops[0]
    last = hops[-1]
    if first.loss_pct >= 20.0:
        return "PATH.LOCAL_SIDE", False       # 终端侧 / 接入层
    if last.loss_pct >= 20.0 and len(losing) == 1:
        return "PATH.SERVER_EDGE", False      # 仅末跳丢 → 服务端接入链路
    return "PATH.TRANSPORT_NET", False        # 中间跳丢 → 承载网 / 运营商


# ---------------------------------------------------------------- 目标发现


def discover_targets(vdi_hint: str = "") -> dict[str, str]:
    """发现网关 / DNS / 业务目标。

    不要解析 ``ipconfig`` 文本（本地化 + 版本差异）；用
    ``core.platform.winapi.adapters()``（``GetAdaptersAddresses``）或
    ``scapy.all.conf.route.default_gateway()``。

    TODO(迁移)：接入 winapi 后返回
    ``{"gateway": "192.168.1.1", "dns": "10.0.0.53", "vdi": vdi_hint}``。
    """
    raise NotImplementedError("discover_targets(): 见 docstring")


def plan(targets: Mapping[str, str], samples: int = 5) -> tuple[ProbeSpec, ...]:
    """按角色生成探测计划：网关用 ICMP，DNS 用 UDP/53，业务目标用 TCP SYN。"""
    out: list[ProbeSpec] = []
    if g := targets.get("gateway"):
        out.append(ProbeSpec(ProbeKind.ICMP, g, samples=samples, role="gateway"))
    if d := targets.get("dns"):
        out.append(ProbeSpec(ProbeKind.UDP, d, port=53, samples=max(3, samples // 2), role="dns"))
    if v := targets.get("vdi"):
        out.append(ProbeSpec(ProbeKind.TCP_SYN, v, port=int(targets.get("vdi_port", 443)),
                             samples=samples, role="target"))
    return tuple(out)


# ---------------------------------------------------------------- 执行（占位）


def run(target: str, port: int | None = None, max_hops: int = 16,
        samples: int = 5, timeout_s: float = 1.0) -> PathProbeResult:
    """TTL 递增探测。

    TODO(迁移)：用 scapy 实现::

        from scapy.all import IP, ICMP, TCP, sr, conf

        conf.verb = 0
        for ttl in range(1, max_hops + 1):
            pkts = [IP(dst=target, ttl=ttl) / ICMP(id=PROBE_ID, seq=i)
                    for i in range(samples)]
            answered, _ = sr(pkts, timeout=timeout_s, inter=0.05)
            # 注意：scapy 需要 Npcap + 管理员权限；失败要降级为「无法探测」
            #      而不是抛异常打断整个诊断。

    另外两件必做的事：

    1. 抓包侧同时生效 ``ledger.exclusion_bpf()``（否则探针污染诊断）；
    2. 探测前先测一次目标端口的 TCP 连通性（``probe_link``），
       用于判定「ICMP 被过滤」而不是「链路故障」。
    """
    raise NotImplementedError("run(): 见 docstring 的 scapy 实现要点")


def shadow_specs(targets: Mapping[str, str], interval_s: float = 5.0) -> tuple[ProbeSpec, ...]:
    """影子探测计划：每 ``interval_s`` 秒一轮，量很小（1 包/目标/轮）。"""
    base = plan(targets, samples=1)
    return tuple(
        ProbeSpec(spec.kind, spec.target, ttl=spec.ttl, port=spec.port,
                  samples=1, timeout_s=min(1.0, interval_s / 2), interval_s=interval_s,
                  role=spec.role)
        for spec in base
    )


def probe_len(specs: Iterable[ProbeSpec]) -> int:
    """预估探针报文数，用于给用户提示「本次会额外发多少包」。"""
    return sum(max(1, s.samples) for s in specs)


__all__ = [
    "PROBE_ID", "PROBE_SRC_PORT_RANGE",
    "ProbeKind", "HopStatus", "ProbeSpec", "ProbeRecord", "ProbeLedger",
    "HopStat", "PathProbeResult",
    "classify", "discover_targets", "plan", "shadow_specs", "probe_len", "run",
]
