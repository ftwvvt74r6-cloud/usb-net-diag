"""影子探测（Shadow Probing）+ 路径探测（MTR）—— D 批次实现。

**解决什么问题**：实时抓包（全网体检 / 单目标诊断）期间，业务报文可能一个都没有
（选错网卡、流量走 VPN、目标本来就没流量）。这时报告只能写「无样本」，答不出
「是本地出口丢包，还是对端不回」。本模块提供两类主动探测：

* **影子探测**：每约 5 秒发一轮**极轻量**探针（网关 ICMP、目标端口 TCP SYN、
  DNS 服务器 UDP/53），把「RTT / 丢包基线」变成事实，并作为方向判定的
  **两侧对照证据**；
* **路径探测（MTR）**：TTL 从 1 递增、每批一次 ``sr()`` 批量收发，得到逐跳
  ``ttl / ip / sent / lost / loss_pct / rtt_min·avg·max / jitter / status``，
  再判定「第几跳开始劣化」与「本地出口 / 承载网 / 对端侧 / ICMP 被过滤 / 证据不足」；
  ICMP 被策略过滤（全丢但目标端口 TCP 可达）时自动降级为 **TCP SYN 逐跳**并在
  结果里标 ``icmp_filtered=True`` / ``method="tcp"``。

**谁调用它**：:mod:`core.diagnose` 的实时抓包路径（``capture_live`` / ``run_scan``）
构造 :class:`ShadowProber` / :class:`PathProfiler` 并按抓包时长启停；
:mod:`core.server` 的 ``/api/probe`` 在「逐跳路径」开关打开时直接调 :func:`run`；
:mod:`core.verdict` 只读 ``meta["probe_baseline"]``（由 ``run_scan`` 注入），
:mod:`core.report` 只读 ``meta["path_profile"]``，都不直接 import 本模块。

**不做什么**：

* 不发「业务请求」：探针只发 1 个 ICMP / TCP SYN / 最小 DNS 查询，不建连、不传数据；
* 不做 IPv6 逐跳（本批只做 IPv4，遇到 IPv6 目标返回 ``error`` 不抛异常）；
* 不调用 ``tracert`` / 不解析任何本地化 CLI 文本（AGENTS.md 硬约束）；
* 不联网上报：探测结果只进本地报告；
* 离线分析 / 被动监听路径**绝不**构造本模块的探针（见 tests/test_shadow_probe.py）。

**输入输出**：输入是探针规格 :class:`ProbeSpec`（目标 / 端口 / 角色）与抓包时长；
输出是一份 :class:`ProbeLedger` 账本（逐条记录 + 聚合基线）或一份
:class:`PathProbeResult` 路径剖面（逐跳 + 结论机器码，可 JSON）。账本同时承担
**排除**职责：``exclusion_bpf()`` / ``exclusion_display_filter()`` 把探针流量从
抓包与统计里剔除，避免「探针自己造出 ICMP 超时 / 额外 TCP 会话」的误报。

**四个必须做对的细节**（评审第 6 步的踩坑记录）：

1. **探针不能污染诊断**：抓包阶段用 BPF 排除（ICMP echo 的固定 id、TCP/UDP 的
   固定源端口段），分析阶段再用 tshark ``-Y`` 显示过滤做防御层 —— 只做 BPF 不够，
   探针的**回复**（echo-reply / SYN-ACK / RST）方向端口是反的，BPF 漏了它就会
   变成「额外 TCP 会话」。
2. **探针要能被认出来是自己发的**：固定 :data:`PROBE_ID`、固定源端口段
   :data:`PROBE_SRC_PORT_RANGE`、固定 payload :data:`PROBE_PAYLOAD`，全部写进账本。
3. **ICMP time-exceeded 无法按 id 认领**：路径上设备回的 ICMP type 11 里，外层
   ICMP 的 ident 不是我们的 :data:`PROBE_ID`（原始 id 埋在「原始 IP 头 + 8 字节」
   里）。所以 MTR 期间在**显示过滤**追加 ``not (icmp.type == 11)``，并用
   :func:`count_time_exceeded_packets` 把「被排除的路径探测相关 ICMP 数」写进报告。
   残余风险（同一窗口其它流量的 TTL 超时也会被一起排除）写在 ``docs/path-probe.md``。
4. **时钟对齐**：pcap 用系统时钟（``frame.time_epoch``），探测用
   ``time.monotonic()``；两者有偏移。所以只记 ``sent_epoch`` 做区间归属，
   不逐包对齐；逐跳 RTT 用 scapy 自己的 ``sent_time`` 与收包时间之差。
"""
from __future__ import annotations

import ipaddress
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

#: ICMP 探测用的固定 id，便于在抓包里认出来（"ND" = NetDiag）。
PROBE_ID = 0x4E44
#: TCP / UDP 探测固定使用的源端口段（避开普通业务端口）。
PROBE_SRC_PORT_RANGE = (39000, 39999)
#: 探针 payload 固定前缀；即使 id/端口被中间设备改写，也能在原始字节里认出。
PROBE_PAYLOAD = b"NetDiag-shadow-probe"
#: UDP DNS 探针查询的域名：``.example`` 是 RFC 2606 保留的示例 TLD，
#: 必然得到 NXDOMAIN —— 拿到响应就证明「DNS 服务器可达」，且不依赖真实域名。
PROBE_DNS_NAME = "netdiag-probe.example"
#: 影子探测默认轮询间隔（秒）。
PROBE_INTERVAL_S = 5.0
#: 单次探针默认等待上限（秒）；影子探测按 V3 要求压到 1s 以内。
PROBE_TIMEOUT_S = 1.0
#: 单个目标在单次诊断里允许发出的探针上限（duration=180s、5s 一轮 ≈ 37 包）。
PROBE_MAX_PACKETS_PER_TARGET = 38
#: 角色展示顺序：网关 → DNS → 业务目标（报告与聚合都按它排）。
PROBE_ROLES = ("gateway", "dns", "target")

# ---------------------------------------------------------------- 路径探测参数

#: 路径探测（MTR）默认最大跳数；调用方可给 1..32。
PATH_DEFAULT_MAX_HOPS = 16
#: ``max_hops`` 的安全夹取范围（防止被当成压测工具）。
PATH_MAX_HOPS_RANGE = (1, 32)
#: 路径探测默认每跳采样数；调用方可给 1..10。
PATH_DEFAULT_SAMPLES = 5
#: ``samples`` 的安全夹取范围。
PATH_SAMPLES_RANGE = (1, 10)
#: 单包等待上限的安全夹取范围（秒）；低于 0.2 会大面积误判丢包。
PATH_TIMEOUT_RANGE = (0.2, 3.0)
#: 每批 ``sr()`` 同时发出的跳数：16 跳 ≈ 4 批 × 单包超时，live 抓包 3~6 秒可完成。
PATH_BATCH_HOPS = 4
#: 判定「劣化」的丢包率阈值（百分比）：≥ 20% 视为这一跳开始坏。
PATH_LOSS_DEGRADED_PCT = 20.0
#: 判定「RTT 突增」的倍数阈值：当前跳平均 RTT ≥ 基线 × 3……
PATH_RTT_SPIKE_FACTOR = 3.0
#: ……且绝对增量 ≥ 50ms（两个条件都满足才算突增，避免 1ms→3ms 这种噪声）。
PATH_RTT_SPIKE_DELTA_MS = 50.0
#: 「ICMP 被过滤」的判定：整条路径每一跳的丢包率都 ≥ 这个值，且目标端口 TCP 可达。
PATH_ICMP_FILTER_LOSS_PCT = 90.0
#: 未显式给端口时，判断目标侧 TCP 可达性依次尝试的端口。
PATH_FALLBACK_PORTS = (443, 80)
#: TCP 可达性单次连接超时（秒）；MTR 只做一次探路，不重试。
PATH_TCP_CHECK_TIMEOUT_S = 1.0
#: 逐跳判定结论的机器码（渲染层负责翻成中文；不在本模块写中文长文案）。
PATH_OK = "PATH.OK"
PATH_LOCAL_SIDE = "PATH.LOCAL_SIDE"
PATH_TRANSPORT_NET = "PATH.TRANSPORT_NET"
PATH_SERVER_EDGE = "PATH.SERVER_EDGE"
PATH_ICMP_FILTERED = "PATH.ICMP_FILTERED"
PATH_NO_DATA = "PATH.NO_DATA"
#: MTR 期间要排除的 ICMP 类型：11 = time-exceeded（TTL 耗尽）。
ICMP_TIME_EXCEEDED = 11

class ProbeKind(str, Enum):
    """探针协议类型（同时是账本 / 统计里的机器码）。"""

    ICMP = "icmp"
    TCP_SYN = "tcp_syn"
    UDP = "udp"


class HopStatus(str, Enum):
    """路径探测（MTR）单跳的状态机；本批只用 ``classify()`` 的判定口径。"""

    OK = "ok"
    LOSS = "loss"
    FILTERED = "filtered"      # 不回 ICMP，但目标端口可达 → 被策略过滤，不是故障
    UNREACHABLE = "unreachable"
    NO_TARGET = "no_target"


@dataclass(frozen=True)
class ProbeSpec:
    """一次探针的规格（发什么、发给谁、算哪个角色）。

    Attributes:
        kind: 探针协议（ICMP / TCP SYN / UDP）。
        target: 目标 IPv4 字面量（域名在 :func:`discover_targets` 里已解析）。
        ttl: IP TTL，影子探测固定 64；路径探测（后续 PR）用递增 TTL。
        port: TCP / UDP 目的端口；ICMP 探针为 ``None``。
        samples: 计划采样数；影子探测固定 1（每轮每目标 1 包）。
        timeout_s: 单包等待上限（秒），上限 1s。
        interval_s: 轮询间隔（秒），影子探测固定 5s。
        role: 角色机器码：``gateway`` / ``dns`` / ``target``。
    """

    kind: ProbeKind
    target: str
    ttl: int = 64
    port: int | None = None
    samples: int = 5
    timeout_s: float = 1.0
    interval_s: float = 0.2
    role: str = ""             # gateway / dns / target

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ProbeKind(self.kind))

    def to_dict(self) -> dict:
        """把规格转成可 JSON 序列化的字典（账本落进结果时用）。

        Returns:
            dict: 键 ``kind``（机器码）/``target``/``ttl``/``port``/``samples``/
                ``timeout_s``/``interval_s``/``role``。
        """
        return {
            "kind": self.kind.value,
            "target": self.target,
            "ttl": int(self.ttl),
            "port": self.port,
            "samples": int(self.samples),
            "timeout_s": float(self.timeout_s),
            "interval_s": float(self.interval_s),
            "role": self.role,
        }


#: 探针发送器签名：``(spec, seq) -> (responded, rtt_ms, responder, error)``。
#: 抽成可注入参数，单测不依赖 scapy / 网卡 / 管理员权限。
ProbeSender = Callable[[ProbeSpec, int], tuple[bool, float | None, str, str]]


@dataclass(frozen=True)
class ProbeRecord:
    """一次探测的实际结果。**必须带时间戳**，否则无法与抓包对齐。

    Attributes:
        spec: 本次探针规格。
        sent_monotonic: 发送时刻的 ``time.monotonic()``（算 RTT 用）。
        sent_epoch: 发送时刻的系统时钟（与 pcap 的 ``frame.time_epoch`` 同源，
            只做「区间归属」，不逐包对齐）。
        rtt_ms: 往返时延（毫秒）；没有响应时为 ``None``（**不许用 0.0 冒充**）。
        responded: 是否收到可判「通」的响应。
        responder: 响应方 IP；无响应时为空串。
        error: 失败原因（``timeout`` / ``scapy 不可用`` ……）；成功为空串。
        seq: 全局递增序号（ICMP seq / 源端口分配都从它派生）。
    """

    spec: ProbeSpec
    sent_monotonic: float
    sent_epoch: float
    rtt_ms: float | None = None
    responded: bool = False
    responder: str = ""
    error: str = ""
    seq: int = 0

    def to_dict(self) -> dict:
        """把一条记录转成可 JSON 序列化的字典。

        Returns:
            dict: 键 ``spec``（:meth:`ProbeSpec.to_dict`）/``sent_monotonic``/
                ``sent_epoch``/``rtt_ms``/``responded``/``responder``/``error``/
                ``seq``；``rtt_ms`` 无样本时保持 ``None``。
        """
        return {
            "spec": self.spec.to_dict(),
            "sent_monotonic": float(self.sent_monotonic),
            "sent_epoch": float(self.sent_epoch),
            "rtt_ms": self.rtt_ms,
            "responded": bool(self.responded),
            "responder": self.responder,
            "error": self.error,
            "seq": int(self.seq),
        }


@dataclass
class ProbeLedger:
    """探测账本：既用于**排除**探针流量，也用于报告复现。

    Attributes:
        records: 逐条探测记录（按发送顺序）。
        started_epoch: 探针线程启动时刻（系统时钟）。
        finished_epoch: 探针线程收尾时刻（系统时钟）。
        clock_offset_ms: 预留的时钟偏移校准值；本批不做逐包对齐，固定 0。
    """

    records: list[ProbeRecord] = field(default_factory=list)
    started_epoch: float = 0.0
    finished_epoch: float = 0.0
    clock_offset_ms: float = 0.0

    # ---- 排除用 ----
    def ports(self) -> set[int]:
        """账本里出现过的探针目的端口集合。

        Returns:
            set[int]: TCP/UDP 探针的目的端口；ICMP 记录不贡献端口。
        """
        return {r.spec.port for r in self.records if r.spec.port}

    def targets(self) -> set[str]:
        """账本里出现过的探针目标地址集合。

        Returns:
            set[str]: 去重后的目标 IP 字符串。
        """
        return {r.spec.target for r in self.records if r.spec.target}

    def kinds(self) -> set[ProbeKind]:
        """账本里实际出现过的探针协议集合。

        Returns:
            set[ProbeKind]: 例如 ``{ProbeKind.ICMP, ProbeKind.TCP_SYN}``。
        """
        return {r.spec.kind for r in self.records}

    def has_icmp(self) -> bool:
        """账本里是否有 ICMP 探针（决定是否需要排除 echo 请求/回复）。

        Returns:
            bool: 存在 ICMP 记录时为 True。
        """
        return ProbeKind.ICMP in self.kinds()

    def exclusion_bpf(self, ignore_icmp: bool = True) -> str:
        """把探针流量从**抓包**里排除掉的 BPF 表达式。

        只排除「我们自己发的」那部分：ICMP echo 的固定 id、TCP/UDP 的固定源端口段，
        并且端口段同时匹配源/目的 —— 探针的回复方向端口是反的，只排源端口会漏掉
        SYN-ACK / RST / DNS 响应（这正是「只做 BPF 不够」的原因之一）。

        Args:
            ignore_icmp: 是否把 ICMP echo 探针也排除；``False`` 时只给端口段条件
                （保留给「想单独看 ICMP」的调试场景）。

        Returns:
            str: BPF 串；空账本返回空串（调用方据此判断「无需合并过滤」）。
        """
        kinds = self.kinds()
        if not ignore_icmp:
            kinds = {kind for kind in kinds if kind is not ProbeKind.ICMP}
        return exclusion_bpf(kinds)

    def exclusion_display_filter(self) -> str:
        """把探针流量从**分析**里排除掉的 tshark ``-Y`` 表达式（防御层）。

        Returns:
            str: 显示过滤串；空账本返回空串。
        """
        return exclusion_display_filter(self.kinds())

    def window(self) -> tuple[float, float]:
        """探针线程的活动时间窗（系统时钟秒）。

        Returns:
            tuple[float, float]: ``(started_epoch, finished_epoch)``；未启动时都是 0。
        """
        return self.started_epoch, self.finished_epoch

    def baseline(self) -> dict:
        """按角色聚合出「探针基线」（报告 / 方向对照消费的数据）。

        Returns:
            dict: 键 ``probe_count``（记录总数）/``sent``/``recv``/``window``/
                ``roles``（:func:`aggregate_records` 的结果）；``excluded_packets``
                固定 0，由调用方在分析前用 ``count_marked_packets`` 回填。
                没有 RTT 样本的角色 ``n=0`` 且 ``rtt_*`` 为 ``None`` —— 不是 0.0。
        """
        roles = aggregate_records(self.records)
        sent = sum(int(item["sent"]) for item in roles)
        recv = sum(int(item["recv"]) for item in roles)
        started, finished = self.window()
        return {
            "probe_count": len(self.records),
            "sent": sent,
            "recv": recv,
            "window": {"started_epoch": started, "finished_epoch": finished},
            "roles": roles,
            "excluded_packets": 0,
        }

    def to_dict(self) -> dict:
        """把账本转成可 JSON 序列化的字典（结果里 ``meta.probe_baseline`` 的底稿）。

        Returns:
            dict: 键 ``started_epoch``/``finished_epoch``/``clock_offset_ms``/
                ``probe_count``/``targets``/``ports``/``kinds``/``exclusion_bpf``/
                ``exclusion_display_filter``/``records``（逐条记录）。
        """
        return {
            "started_epoch": self.started_epoch,
            "finished_epoch": self.finished_epoch,
            "clock_offset_ms": self.clock_offset_ms,
            "probe_count": len(self.records),
            "targets": sorted(self.targets()),
            "ports": sorted(self.ports()),
            "kinds": sorted(kind.value for kind in self.kinds()),
            "exclusion_bpf": self.exclusion_bpf(),
            "exclusion_display_filter": self.exclusion_display_filter(),
            "records": [record.to_dict() for record in self.records],
        }


@dataclass(frozen=True)
class HopStat:
    """路径探测（MTR）的单跳统计。

    ``sent`` / ``lost`` 表达「有没有样本」（``sent=0`` = 这一跳根本没探），
    ``rtt_n`` 表达「有没有 RTT 样本」（回了包但拿不到时间戳时为 0）；
    RTT 三个值 + 抖动在 ``rtt_n=0`` 时是 ``None``，**不许用 0.0 冒充**。
    """

    ttl: int
    ip: str = ""
    sent: int = 0
    lost: int = 0
    rtt_min_ms: float | None = None
    rtt_avg_ms: float | None = None
    status: HopStatus = HopStatus.OK
    rtt_max_ms: float | None = None
    jitter_ms: float | None = None
    rtt_n: int = 0

    @property
    def loss_pct(self) -> float:
        """单跳丢包率（百分比，1 位小数）。

        Returns:
            float: ``lost / sent * 100``；``sent == 0``（无样本）时返回 0.0。
                「有没有样本」由 ``sent`` / ``rtt_n`` 表达，不要只看这个比例。
        """
        return round(self.lost / self.sent * 100.0, 1) if self.sent else 0.0

    def to_dict(self) -> dict:
        """把单跳统计转成可 JSON 序列化的字典（报告 / ``meta.path_profile`` 用）。

        Returns:
            dict: 键 ``ttl``/``ip``/``sent``/``lost``/``loss_pct``/
                ``rtt_min_ms``/``rtt_avg_ms``/``rtt_max_ms``/``jitter_ms``/
                ``rtt_n``/``status``（机器码）；没有 RTT 样本时三个 RTT 与抖动
                都是 ``None``。
        """
        return {
            "ttl": int(self.ttl),
            "ip": self.ip,
            "sent": int(self.sent),
            "lost": int(self.lost),
            "loss_pct": self.loss_pct,
            "rtt_min_ms": self.rtt_min_ms,
            "rtt_avg_ms": self.rtt_avg_ms,
            "rtt_max_ms": self.rtt_max_ms,
            "jitter_ms": self.jitter_ms,
            "rtt_n": int(self.rtt_n),
            "status": self.status.value,
        }


@dataclass(frozen=True)
class PathProbeResult:
    """路径探测（MTR）结果：逐跳数据 + 结论机器码 + 方法/降级标注。

    ``verdict_key`` 只用 :data:`PATH_OK` 等 6 个机器码；``unreachable`` 是附加
    布尔（ICMP 与 TCP 都没响应时，渲染层据此写「目标不可达」而不是「正常」）。
    """

    target: str = ""
    hops: tuple[HopStat, ...] = ()
    verdict_key: str = ""
    icmp_filtered: bool = False
    target_port_reachable: bool | None = None
    ledger: Mapping | None = None
    target_ip: str = ""
    method: str = "icmp"
    degraded_ttl: int | None = None
    baseline_ms: float | None = None
    reached_target: bool = False
    completed: bool = True
    tun_suspected: bool = False
    unreachable: bool = False
    max_hops: int = 0
    samples: int = 0
    timeout_s: float = 0.0
    probes_sent: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        """把路径探测结果转成可 JSON 序列化的字典（``meta.path_profile`` 的底稿）。

        Returns:
            dict: 键 ``target``/``target_ip``/``verdict_key``/``degraded_ttl``/
                ``baseline_ms``/``icmp_filtered``/``target_port_reachable``/
                ``method``/``reached_target``/``completed``/``tun_suspected``/
                ``unreachable``/``max_hops``/``samples``/``timeout_s``/
                ``probes_sent``/``error``/``hops``（逐跳）/``ledger``。
        """
        return {
            "target": self.target,
            "target_ip": self.target_ip,
            "verdict_key": self.verdict_key,
            "degraded_ttl": self.degraded_ttl,
            "baseline_ms": self.baseline_ms,
            "icmp_filtered": self.icmp_filtered,
            "target_port_reachable": self.target_port_reachable,
            "method": self.method,
            "reached_target": self.reached_target,
            "completed": self.completed,
            "tun_suspected": self.tun_suspected,
            "unreachable": self.unreachable,
            "max_hops": int(self.max_hops),
            "samples": int(self.samples),
            "timeout_s": float(self.timeout_s),
            "probes_sent": int(self.probes_sent),
            "error": self.error,
            "hops": [hop.to_dict() for hop in self.hops],
            "ledger": dict(self.ledger or {}),
        }


# ---------------------------------------------------------------- 定界判定


def classify(hops: Sequence[HopStat],
             target_port_reachable: bool | None = None) -> tuple[str, bool]:
    """把逐跳统计翻成「该找谁」。

    四态的关键是**最后一种**：全部都丢但目标端口 TCP 可通 → 这不是故障，是
    ICMP 被策略过滤（企业网常见），不能把「被过滤」误判成「链路故障」。

    Args:
        hops: 逐跳统计（按 TTL 顺序）。
        target_port_reachable: 目标端口 TCP 是否可达；``None`` 表示没测。

    Returns:
        tuple[str, bool]: ``(verdict_key, icmp_filtered)``。``verdict_key`` 是机器码
        （``PATH.OK`` / ``PATH.LOCAL_SIDE`` / ``PATH.SERVER_EDGE`` /
        ``PATH.TRANSPORT_NET`` / ``PATH.ICMP_FILTERED`` / ``PATH.NO_DATA``），
        由渲染层负责翻成中文。
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


# ---------------------------------------------------------------- 路径剖面判定


def clamp_path_options(max_hops: int = PATH_DEFAULT_MAX_HOPS,
                       samples: int = PATH_DEFAULT_SAMPLES,
                       timeout_s: float = 1.0) -> tuple[int, int, float]:
    """把路径探测的三个参数夹到安全范围（纯函数，调用方/测试共用）。

    「MTR 长什么样」不设上限的话，一次 32 跳 × 10 样本 × 3 秒能把网卡打满，
    也能把一次实时抓包拖到几分钟 —— 所以参数一律先夹取再使用。

    Args:
        max_hops: 请求的最大跳数；夹到 :data:`PATH_MAX_HOPS_RANGE`。
        samples: 请求的每跳采样数；夹到 :data:`PATH_SAMPLES_RANGE`。
        timeout_s: 请求的单包等待上限（秒）；夹到 :data:`PATH_TIMEOUT_RANGE`。

    Returns:
        tuple[int, int, float]: ``(max_hops, samples, timeout_s)``；脏值（``None`` /
            非数字）回落默认值而不是抛异常。

    Example:
        >>> clamp_path_options(999, 0, 99)
        (32, 1, 3.0)
    """
    low_hops, high_hops = PATH_MAX_HOPS_RANGE
    low_samples, high_samples = PATH_SAMPLES_RANGE
    low_timeout, high_timeout = PATH_TIMEOUT_RANGE
    try:
        hops = int(max_hops)
    except (TypeError, ValueError):
        hops = PATH_DEFAULT_MAX_HOPS
    try:
        count = int(samples)
    except (TypeError, ValueError):
        count = PATH_DEFAULT_SAMPLES
    try:
        timeout = float(timeout_s)
    except (TypeError, ValueError):
        timeout = 1.0
    return (max(low_hops, min(hops, high_hops)),
            max(low_samples, min(count, high_samples)),
            max(low_timeout, min(timeout, high_timeout)))


def build_hop_stats(rows: Iterable[Mapping]) -> tuple[HopStat, ...]:
    """把原始采样记录聚合成逐跳统计（纯函数，MTR 与单测共用）。

    每条原始记录键：``ttl``（整数）、``responded``（布尔）、``rtt_ms``
    （浮点或 ``None``）、``responder``（响应方 IP，空串表示没响应）。

    Args:
        rows: 原始采样记录（顺序无关，内部按 ``ttl`` 排序输出）。

    Returns:
        tuple[HopStat, ...]: 按 TTL 升序的逐跳统计。``sent`` 是该 TTL 的采样数，
        ``lost`` 是没响应的采样数；``ip`` 取该跳出现过的非空响应方（取第一个），
        ``rtt_n`` 是真正拿到 RTT 的样本数，``rtt_min_ms``/``rtt_avg_ms``/
        ``rtt_max_ms``/``jitter_ms`` 在 ``rtt_n=0`` 时是 ``None``；
        ``jitter_ms`` 用总体标准差（与 :func:`aggregate_records` 口径一致）。

    Example:
        >>> [h.ttl for h in build_hop_stats([{"ttl": 2}, {"ttl": 1}])]
        [1, 2]
    """
    grouped: dict[int, list[Mapping]] = {}
    for row in rows:
        try:
            ttl = int(row.get("ttl"))
        except (TypeError, ValueError):
            continue
        grouped.setdefault(ttl, []).append(row)

    out: list[HopStat] = []
    for ttl in sorted(grouped):
        samples = grouped[ttl]
        sent = len(samples)
        responders = [str(item.get("responder") or "") for item in samples
                      if item.get("responded")]
        ip = next((value for value in responders if value), "")
        rtts = [float(item["rtt_ms"]) for item in samples
                if item.get("responded") and item.get("rtt_ms") is not None]
        lost = sent - sum(1 for item in samples if item.get("responded"))
        hop = HopStat(ttl=ttl, ip=ip, sent=sent, lost=lost, rtt_n=len(rtts),
                      status=HopStatus.LOSS if sent and lost == sent
                      else HopStatus.OK)
        if rtts:
            avg = sum(rtts) / len(rtts)
            jitter = (sum((value - avg) ** 2 for value in rtts) / len(rtts)) ** 0.5
            hop = HopStat(ttl=ttl, ip=ip, sent=sent, lost=lost,
                          rtt_min_ms=round(min(rtts), 1),
                          rtt_avg_ms=round(avg, 1),
                          status=hop.status,
                          rtt_max_ms=round(max(rtts), 1),
                          jitter_ms=round(jitter, 1), rtt_n=len(rtts))
        out.append(hop)
    return tuple(out)


def degraded_hops(hops: Sequence[HopStat]) -> tuple[int, ...]:
    """列出「已经劣化」的跳（纯函数，阈值全部来自模块常量）。

    两条判据，任一命中即算劣化：

    1. **丢包**：``loss_pct >= PATH_LOSS_DEGRADED_PCT``（默认 20%）；
    2. **RTT 突增**：当前跳平均 RTT ≥ 基线 × :data:`PATH_RTT_SPIKE_FACTOR`
       且绝对增量 ≥ :data:`PATH_RTT_SPIKE_DELTA_MS`。基线取「已响应跳里最小的
       平均 RTT」（首跳自身不参与比较，避免把第一跳的正常抖动当成突增）。

    Args:
        hops: 逐跳统计（顺序无关，内部按 ttl 排序）。

    Returns:
        tuple[int, ...]: 劣化跳的 TTL（升序）；没有劣化时是空元组。
    """
    baseline: float | None = None
    flagged: list[int] = []
    for hop in sorted(hops, key=lambda item: item.ttl):
        if hop.sent <= 0:
            continue
        if hop.loss_pct >= PATH_LOSS_DEGRADED_PCT:
            flagged.append(hop.ttl)
        elif (hop.rtt_avg_ms is not None and baseline is not None
              and hop.rtt_avg_ms >= baseline * PATH_RTT_SPIKE_FACTOR
              and (hop.rtt_avg_ms - baseline) >= PATH_RTT_SPIKE_DELTA_MS):
            flagged.append(hop.ttl)
        if hop.rtt_avg_ms is not None:
            baseline = (hop.rtt_avg_ms if baseline is None
                        else min(baseline, hop.rtt_avg_ms))
    return tuple(flagged)


def first_degraded_hop(hops: Sequence[HopStat]) -> int | None:
    """「第几跳开始劣化」——第一条命中 :func:`degraded_hops` 判据的 TTL。

    Args:
        hops: 逐跳统计。

    Returns:
        int | None: 劣化跳的 TTL；全部正常或没有任何样本时返回 ``None``。
            **没有样本 ≠ 正常**：调用方必须再看 ``sent`` / ``rtt_n`` 才能下结论
            （见 :func:`summarize_path` 的 ``PATH.NO_DATA``）。

    Example:
        >>> first_degraded_hop(()) is None
        True
    """
    flagged = degraded_hops(hops)
    return flagged[0] if flagged else None


def looks_like_tun(hops: Sequence[HopStat], target_ip: str = "") -> bool:
    """猜「本次逐跳走的是代理/TUN 的虚拟路径」。

    **唯一可靠证据**是 ``198.18.0.0/15`` 出现在路径的关键位置。这段是 RFC 2544
    的基准测试网段，mihomo / Clash 等 TUN 代理默认拿它做 fake-ip：

    1. 目标解析到该网段（fake-ip 直接命中，逐跳探到的是代理的虚拟路径）；
    2. 任一**有响应**的跳的 IP 落在该网段（TUN 虚拟网关在代为应答）。

    **为什么不用跳数判断**：on-link 目标（同网段主机、本机物理网关）正常就只有
    1 跳；ICMP 被过滤时也可能只看到 1~2 跳响应。把「有响应的最大 TTL ≤ 2」当成
    代理证据，会把物理网关误报成 TUN（D+ 增量 2.5 的路测缺陷：对物理网关提示
    「当前流量可能走代理」）。漏报只是少一句建议，误报会诱导用户去关代理，
    所以**证据不足一律返回 False**（宁可不提示，不可误报）。

    Args:
        hops: 逐跳统计。
        target_ip: 本次探测的目标 IP 字面量；空串表示不知道。

    Returns:
        bool: 目标或任一有响应的跳落在 ``198.18.0.0/15`` 时为 True；其余情况
            （hop ip 为空 / 解析失败 / 全部丢包 / on-link LAN 目标 / 物理网关 /
            普通多跳公网）恒为 False。

    Example:
        >>> looks_like_tun((), "198.18.0.2")
        True
    """
    bench = ipaddress.ip_network("198.18.0.0/15")

    def _is_fake_ip(value: str) -> bool:
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            return False
        return address.version == 4 and address in bench

    if target_ip and _is_fake_ip(target_ip):
        return True
    for hop in hops:
        # 「有响应」= 有 RTT 样本，或至少有一个采样回了包；全丢的 hop 不算证据。
        responded = hop.rtt_n > 0 or (hop.sent > 0 and hop.loss_pct < 100.0)
        if responded and hop.ip and _is_fake_ip(hop.ip):
            return True
    return False


def summarize_path(hops: Sequence[HopStat],
                   target_port_reachable: bool | None = None,
                   method: str = "icmp",
                   target_ip: str = "") -> dict:
    """把逐跳统计翻成「第几跳开始劣化 + 该找谁」（纯函数，无中文长文案）。

    与 :func:`classify` 的区别：这里同时看**丢包**与 **RTT 突增**，并且把
    「没有样本」「ICMP 被过滤」「目标不可达」明确分开 —— 三者都不许落成「正常」。

    Args:
        hops: 逐跳统计。
        target_port_reachable: 目标端口 TCP 是否可达；``None`` 表示没测。
        method: ``"icmp"`` / ``"tcp"``；只有 ICMP 方法才可能判定「被过滤」。
        target_ip: 目标 IP 字面量，用于判断「是否已探到目标」与 TUN 提示。

    Returns:
        dict: 键 ``verdict_key``（:data:`PATH_OK` 等 6 个机器码）/
            ``degraded_ttl``（第几跳开始劣化，无则 ``None``）/``baseline_ms``
            （基线平均 RTT，无样本 ``None``）/``icmp_filtered``/``unreachable``/
            ``reached_target``/``tun_suspected``。没有样本时恒为 ``PATH.NO_DATA``，
            绝不返回 ``PATH.OK``。

    Example:
        >>> summarize_path(())["verdict_key"]
        'PATH.NO_DATA'
    """
    hops = tuple(hops)
    has_samples = any(hop.sent > 0 for hop in hops)
    if not hops or not has_samples:
        return {"verdict_key": PATH_NO_DATA, "degraded_ttl": None,
                "baseline_ms": None, "icmp_filtered": False,
                "unreachable": False, "reached_target": False,
                "tun_suspected": False}

    responded = [hop for hop in hops if hop.rtt_n > 0 or hop.loss_pct < 100.0]
    if not responded:
        # 整条路径一个响应都没有：要么被过滤（TCP 可达），要么目标/链路不可达。
        if method == "icmp" and target_port_reachable:
            return {"verdict_key": PATH_ICMP_FILTERED, "degraded_ttl": None,
                    "baseline_ms": None, "icmp_filtered": True,
                    "unreachable": False, "reached_target": False,
                    "tun_suspected": looks_like_tun(hops, target_ip)}
        return {"verdict_key": PATH_NO_DATA, "degraded_ttl": None,
                "baseline_ms": None, "icmp_filtered": False,
                "unreachable": bool(target_port_reachable is False),
                "reached_target": False,
                "tun_suspected": looks_like_tun(hops, target_ip)}

    flagged = degraded_hops(hops)
    degraded_ttl = flagged[0] if flagged else None
    if degraded_ttl is None:
        verdict = PATH_OK
    elif degraded_ttl == hops[0].ttl:
        verdict = PATH_LOCAL_SIDE            # 第一跳就坏 → 终端/接入侧
    elif len(flagged) == 1 and degraded_ttl == hops[-1].ttl:
        verdict = PATH_SERVER_EDGE           # 只有末跳坏 → 对端侧
    else:
        verdict = PATH_TRANSPORT_NET         # 中间跳坏 → 承载网 / 运营商

    rtts = [hop.rtt_avg_ms for hop in hops if hop.rtt_avg_ms is not None]
    reached = bool(target_ip) and any(hop.ip == target_ip for hop in hops)
    return {"verdict_key": verdict, "degraded_ttl": degraded_ttl,
            "baseline_ms": round(min(rtts), 1) if rtts else None,
            "icmp_filtered": False, "unreachable": False,
            "reached_target": reached,
            "tun_suspected": looks_like_tun(hops, target_ip)}


# ---------------------------------------------------------------- 隔离表达式


def _port_range_bpf(proto: str) -> str:
    """生成「源或目的端口落在探针段」的 BPF 片段（内部函数）。"""
    low, high = PROBE_SRC_PORT_RANGE
    return (f"not ({proto} src portrange {low}-{high} or "
            f"{proto} dst portrange {low}-{high})")


def _port_range_display(proto: str) -> str:
    """生成「源或目的端口落在探针段」的显示过滤片段（内部函数）。"""
    low, high = PROBE_SRC_PORT_RANGE
    return (f"not (({proto}.srcport >= {low} and {proto}.srcport <= {high}) or "
            f"({proto}.dstport >= {low} and {proto}.dstport <= {high}))")


def exclusion_bpf(kinds: Iterable[ProbeKind]) -> str:
    """按探针协议生成抓包排除表达式（纯函数，供账本与预规划共用）。

    ICMP 用固定 id（请求 + 回复两种 type）；TCP/UDP 用固定源端口段并同时匹配
    源/目的（回复方向端口是反的）。组合用 ``and``，空集合返回空串。

    Args:
        kinds: 本次会发出的探针协议集合（``ProbeKind`` 或同值字符串）。

    Returns:
        str: BPF 串；``kinds`` 为空时返回空串（= 不需要合并过滤）。
    """
    kinds = {ProbeKind(kind) for kind in kinds}
    parts: list[str] = []
    if ProbeKind.ICMP in kinds:
        parts.append(f"not (icmp[icmptype] == 8 and icmp[4:2] == {PROBE_ID:#06x})")
        parts.append(f"not (icmp[icmptype] == 0 and icmp[4:2] == {PROBE_ID:#06x})")
    if ProbeKind.TCP_SYN in kinds:
        parts.append(_port_range_bpf("tcp"))
    if ProbeKind.UDP in kinds:
        parts.append(_port_range_bpf("udp"))
    return " and ".join(parts)


def exclusion_display_filter(kinds: Iterable[ProbeKind]) -> str:
    """按探针协议生成 tshark ``-Y`` 排除表达式（纯函数，分析阶段防御层）。

    Args:
        kinds: 本次会发出的探针协议集合。

    Returns:
        str: 显示过滤串；``kinds`` 为空时返回空串。
    """
    kinds = {ProbeKind(kind) for kind in kinds}
    parts: list[str] = []
    if ProbeKind.ICMP in kinds:
        parts.append(f"not ((icmp.type == 8 or icmp.type == 0) "
                     f"and icmp.ident == {PROBE_ID:#06x})")
    if ProbeKind.TCP_SYN in kinds:
        parts.append(_port_range_display("tcp"))
    if ProbeKind.UDP in kinds:
        parts.append(_port_range_display("udp"))
    return " and ".join(parts)


def probe_marker_display_filter(kinds: Iterable[ProbeKind]) -> str:
    """生成「只匹配探针报文」的显示过滤（用于统计 pcap 里混进了多少探针包）。

    Args:
        kinds: 本次会发出的探针协议集合。

    Returns:
        str: 显示过滤串；``kinds`` 为空时返回空串（调用方应跳过统计）。
    """
    kinds = {ProbeKind(kind) for kind in kinds}
    parts: list[str] = []
    if ProbeKind.ICMP in kinds:
        parts.append(f"((icmp.type == 8 or icmp.type == 0) "
                     f"and icmp.ident == {PROBE_ID:#06x})")
    if ProbeKind.TCP_SYN in kinds:
        low, high = PROBE_SRC_PORT_RANGE
        parts.append(f"((tcp.srcport >= {low} and tcp.srcport <= {high}) or "
                     f"(tcp.dstport >= {low} and tcp.dstport <= {high}))")
    if ProbeKind.UDP in kinds:
        low, high = PROBE_SRC_PORT_RANGE
        parts.append(f"((udp.srcport >= {low} and udp.srcport <= {high}) or "
                     f"(udp.dstport >= {low} and udp.dstport <= {high}))")
    return " or ".join(parts)


def path_exclusion_display_filter(
        kinds: Iterable[ProbeKind] = (ProbeKind.ICMP, ProbeKind.TCP_SYN)) -> str:
    """MTR 期间的显示过滤：探针标记 + 排除 ICMP time-exceeded（type 11）。

    为什么必须多排一条：路径上设备回的 ``ICMP type 11`` 外层 ident 不是
    :data:`PROBE_ID`（我们的 id 埋在「原始 IP 头 + 8 字节」里），按 id/端口认不出来；
    而分析层会把 type 11 计入 ``icmp_timeout``，不排就会凭空多出「TTL 耗尽」故障。

    Args:
        kinds: MTR 可能发出的探针协议；默认 ICMP + TCP SYN（TCP 降级用）。

    Returns:
        str: tshark ``-Y`` 串；``kinds`` 为空时也会返回 ``not (icmp.type == 11)``
            （只要 MTR 跑过，这一步就必须有）。

    Example:
        >>> path_exclusion_display_filter([])
        'not (icmp.type == 11)'
    """
    kinds = {ProbeKind(kind) for kind in kinds}
    base = exclusion_display_filter(kinds)
    extra = f"not (icmp.type == {ICMP_TIME_EXCEEDED})"
    return f"{base} and {extra}" if base else extra


# ---------------------------------------------------------------- 目标发现


def _winapi():
    """惰性加载 ``core.platform.winapi``（模块导入零副作用）。

    Returns:
        module: 平台适配模块；导入失败时抛 ``ImportError``（由调用方兜底）。
    """
    root = str(Path(__file__).resolve().parents[1])
    if root not in sys.path:
        sys.path.insert(0, root)
    from core.platform import winapi

    return winapi


def _probeable_ip(value: str) -> str:
    """把候选目标规范成可探测的 IPv4/IPv6 字面量（内部函数）。

    Args:
        value: IP / CIDR / 域名字符串。

    Returns:
        str: 规范化后的 IP；``0.0.0.0`` / 组播 / 无法解析时返回空串。
    """
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            addr = next(net.hosts(), None) or net.network_address
        else:
            addr = ipaddress.ip_address(text)
    except ValueError:
        try:
            infos = socket.getaddrinfo(text, None, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError):
            return ""
        addr = None
        for info in infos:
            try:
                candidate = ipaddress.ip_address(str(info[4][0]))
            except ValueError:
                continue
            if not (candidate.is_unspecified or candidate.is_multicast):
                return str(candidate)
        return ""
    if addr.is_unspecified or addr.is_multicast:
        return ""
    return str(addr)


def discover_targets(vdi_hint: str = "", target: str = "") -> dict[str, str]:
    """发现网关 / DNS / 业务目标（**绝不抛异常**，拿不到就不返回该键）。

    平台能力复用 :mod:`core.platform.winapi`：``default_gateway()`` 走
    ``GetBestRoute``、``dns_servers()`` 读注册表（都不解析本地化 CLI 文本）。
    业务目标来自抓包目标（IP / CIDR 取第一个主机 / 域名先解析）。

    DNS 角色有一条「优雅跳过」规则：DNS 服务器是 ``127.0.0.0/8`` / ``::1`` 时
    探针发出去只会打到自己（本地 stub 解析器），不产生任何有效对照，所以跳过并在
    返回值里用 ``dns_skip`` 说明原因 —— 调用方据此在日志里交代一句，而不是发无效探针。

    Args:
        vdi_hint: 调用方显式给的业务目标提示（优先于 ``target``）。
        target: 用户填写的诊断目标；空表示全网体检（没有业务目标角色）。

    Returns:
        dict[str, str]: 可能含 ``gateway`` / ``dns`` / ``vdi`` / ``vdi_port``；
            出现但不可用时含 ``dns_skip``（``loopback`` / ``unusable``）。
            键缺失表示该角色这次不可用；不抛异常、不写文件。

    Example:
        >>> discover_targets(target="192.0.2.10").get("vdi")
        '192.0.2.10'
    """
    found: dict[str, str] = {}
    try:
        gateway = str(_winapi().default_gateway() or "").strip()
    except Exception:                              # noqa: BLE001  平台 API 失败只降级
        gateway = ""
    gateway_ip = _probeable_ip(gateway) if gateway else ""
    if gateway_ip:
        found["gateway"] = gateway_ip
    try:
        servers = _winapi().dns_servers()
    except Exception:                              # noqa: BLE001  未实现 / 无权限都按缺项
        servers = ()
    saw_server = False
    for server in servers or ():
        server = str(server or "").strip()
        if server:
            saw_server = True
        dns_ip = _probeable_ip(server)
        if not dns_ip:
            continue
        try:
            address = ipaddress.ip_address(dns_ip)
        except ValueError:
            found.setdefault("dns_skip", "unusable")
            continue
        if address.is_loopback or address.is_unspecified:
            # 本机回环上的 DNS stub：探它等于探自己，测不出路径好坏。
            found["dns_skip"] = "loopback"
            continue
        found["dns"] = dns_ip
        found.pop("dns_skip", None)
        break
    if saw_server and "dns" not in found and "dns_skip" not in found:
        found["dns_skip"] = "unusable"
    candidate = _probeable_ip(vdi_hint or target)
    if candidate:
        found["vdi"] = candidate
        found["vdi_port"] = "443"
    return found


def plan(targets: Mapping[str, str], samples: int = 5) -> tuple[ProbeSpec, ...]:
    """按角色生成探测计划：网关用 ICMP，DNS 用 UDP/53，业务目标用 TCP SYN。

    Args:
        targets: :func:`discover_targets` 的结果；缺哪个角色就跳过哪个。
        samples: 每个目标的计划采样数（影子探测传 1）。

    Returns:
        tuple[ProbeSpec, ...]: 探针规格；没有可用目标时是空元组。
    """
    out: list[ProbeSpec] = []
    if g := targets.get("gateway"):
        out.append(ProbeSpec(ProbeKind.ICMP, g, samples=samples, role="gateway"))
    if d := targets.get("dns"):
        out.append(ProbeSpec(ProbeKind.UDP, d, port=53,
                             samples=max(3, samples // 2), role="dns"))
    if v := targets.get("vdi"):
        try:
            port = int(targets.get("vdi_port") or 443)
        except (TypeError, ValueError):
            port = 443
        out.append(ProbeSpec(ProbeKind.TCP_SYN, v, port=port,
                             samples=samples, role="target"))
    return tuple(out)


def shadow_specs(targets: Mapping[str, str],
                 interval_s: float = PROBE_INTERVAL_S) -> tuple[ProbeSpec, ...]:
    """影子探测计划：每 ``interval_s`` 秒一轮，量很小（1 包/目标/轮）。

    Args:
        targets: :func:`discover_targets` 的结果。
        interval_s: 轮询间隔（秒），默认 :data:`PROBE_INTERVAL_S`。

    Returns:
        tuple[ProbeSpec, ...]: 每目标 1 个规格，``samples=1``、``timeout_s<=1``、
        ``interval_s`` 写成实际轮询间隔。
    """
    base = plan(targets, samples=1)
    return tuple(
        ProbeSpec(spec.kind, spec.target, ttl=spec.ttl, port=spec.port,
                  samples=1, timeout_s=min(PROBE_TIMEOUT_S, interval_s / 2),
                  interval_s=interval_s, role=spec.role)
        for spec in base
    )


def rounds_for(duration: int | float,
               interval_s: float = PROBE_INTERVAL_S) -> int:
    """按抓包时长算探针最多跑几轮（首轮立即发，之后每 ``interval_s`` 一轮）。

    Args:
        duration: 抓包时长（秒）。
        interval_s: 轮询间隔（秒）。

    Returns:
        int: 轮数，至少 1；上限 :data:`PROBE_MAX_PACKETS_PER_TARGET`（单目标包数
        上限，180s → 37 轮）。
    """
    interval = max(0.5, float(interval_s or PROBE_INTERVAL_S))
    rounds = int(float(duration or 0) // interval) + 1
    return max(1, min(rounds, PROBE_MAX_PACKETS_PER_TARGET))


def probe_len(specs: Iterable[ProbeSpec]) -> int:
    """预估探针报文数，用于给用户提示「本次会额外发多少包」。

    Args:
        specs: 探针规格集合。

    Returns:
        int: 每个规格至少 1 包的报文总数。
    """
    return sum(max(1, s.samples) for s in specs)


def probe_src_port(seq: int) -> int:
    """按序号在固定端口段里分配源端口（纯函数，便于复现账本）。

    Args:
        seq: 全局递增序号（从 1 开始）。

    Returns:
        int: 落在 :data:`PROBE_SRC_PORT_RANGE` 内的源端口。
    """
    low, high = PROBE_SRC_PORT_RANGE
    span = high - low + 1
    return low + (max(1, int(seq)) - 1) % span


# ---------------------------------------------------------------- 探针发送


def send_probe(spec: ProbeSpec, seq: int,
               timeout_s: float | None = None) -> tuple[bool, float | None, str, str]:
    """发出一个探针并判定「通 / 丢」（scapy 收发；依赖 Npcap，失败只降级）。

    判定口径（SPEC V5）：ICMP 收到 echo-reply = 通、超时 = 丢；TCP 收到
    SYN-ACK 或 RST = 通（网络可达）；UDP 收到任意响应、或 ICMP port-unreachable
    = 通（主机可达，端口没开）；全部超时 = 丢。

    Args:
        spec: 探针规格。
        seq: 全局序号（ICMP seq / 源端口都从它派生）。
        timeout_s: 覆盖规格里的等待上限；``None`` 时用 ``spec.timeout_s``。

    Returns:
        tuple[bool, float | None, str, str]: ``(responded, rtt_ms, responder, error)``。
        失败时 ``rtt_ms`` 为 ``None``、``error`` 写原因（不含敏感信息）；本函数
        **不抛异常**（scapy 缺失 / 权限不足 / 网卡打不开都转成 error）。
    """
    try:
        from scapy.all import (conf, sr1, DNS, DNSQR, ICMP, IP, TCP,  # noqa: E402
                               UDP)
    except Exception as exc:                       # noqa: BLE001  scapy 是可选依赖
        return False, None, "", f"scapy 不可用：{type(exc).__name__}: {exc}"
    conf.verb = 0
    timeout = max(0.1, min(float(timeout_s if timeout_s is not None
                                 else spec.timeout_s or PROBE_TIMEOUT_S), 2.0))
    sport = probe_src_port(seq)
    try:
        if spec.kind is ProbeKind.ICMP:
            packet = (IP(dst=spec.target) /
                      ICMP(id=PROBE_ID, seq=int(seq) % 0x10000) / PROBE_PAYLOAD)
        elif spec.kind is ProbeKind.TCP_SYN:
            packet = (IP(dst=spec.target) /
                      TCP(sport=sport, dport=int(spec.port or 443), flags="S",
                          seq=int(seq) % 0xFFFFFFFF))
        else:
            packet = (IP(dst=spec.target) /
                      UDP(sport=sport, dport=int(spec.port or 53)) /
                      DNS(rd=1, qd=DNSQR(qname=PROBE_DNS_NAME)))
        started = time.monotonic()
        answer = sr1(packet, timeout=timeout, verbose=0)
        rtt_ms = round((time.monotonic() - started) * 1000.0, 1)
    except Exception as exc:                       # noqa: BLE001  探针失败只降级
        return False, None, "", f"{type(exc).__name__}: {exc}"
    if answer is None:
        return False, None, "", "timeout"
    responder = ""
    try:
        responder = str(answer[IP].src)
    except Exception:                              # noqa: BLE001  无 IP 层不影响判定
        responder = ""
    try:
        if spec.kind is ProbeKind.ICMP:
            if answer.haslayer(ICMP) and int(answer[ICMP].type) == 0:
                ident = int(getattr(answer[ICMP], "id", -1))
                return ident == PROBE_ID, rtt_ms if ident == PROBE_ID else None, \
                    responder, "" if ident == PROBE_ID else "icmp_id_mismatch"
            return False, None, responder, "icmp_unreachable"
        if spec.kind is ProbeKind.TCP_SYN:
            if answer.haslayer(TCP):
                return True, rtt_ms, responder, ""
            return False, None, responder, "unexpected_reply"
        if answer.haslayer(DNS) or answer.haslayer(UDP):
            return True, rtt_ms, responder, ""
        if answer.haslayer(ICMP):
            icmp = answer[ICMP]
            if int(getattr(icmp, "type", -1)) == 3 and int(getattr(icmp, "code", -1)) == 3:
                return True, rtt_ms, responder, "icmp_port_unreachable"
            return False, None, responder, f"icmp_type_{getattr(icmp, 'type', '?')}"
    except Exception as exc:                       # noqa: BLE001  解析失败按未响应
        return False, None, responder, f"{type(exc).__name__}: {exc}"
    return False, None, responder, "unexpected_reply"


# ---------------------------------------------------------------- 调度


class ShadowProber:
    """后台影子探测线程：首轮立即发，之后每 ``interval_s`` 秒一轮，按轮数封顶。

    生命周期（SPEC V3）：``start()`` 启动 daemon 线程并立刻发第一轮；``stop()``
    置取消位，``join(timeout=3)`` 最多等 3 秒。探针异常在 :meth:`run_round`
    内部吞掉并记进 ``error``，**绝不影响主诊断**。

    Attributes:
        specs: 探针规格元组。
        ledger: :class:`ProbeLedger` 账本（线程安全地追加记录）。
    """

    def __init__(self, specs: Iterable[ProbeSpec],
                 interval_s: float = PROBE_INTERVAL_S,
                 max_rounds: int | None = None,
                 sender: ProbeSender | None = None) -> None:
        self.specs = tuple(specs)
        self.interval_s = max(0.5, float(interval_s or PROBE_INTERVAL_S))
        self.max_rounds = max(1, int(max_rounds or rounds_for(
            180, self.interval_s)))
        self.ledger = ProbeLedger()
        self._sender = sender or send_probe
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._seq = 0

    def start(self) -> None:
        """启动后台探针线程（幂等：已在跑时直接返回；不发任何包在调用线程里）。"""
        if self._thread is not None and self._thread.is_alive():
            return
        self.ledger.started_epoch = time.time()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="shadow-prober", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """请求停止：置取消位，当前这一轮发完即收尾（不阻塞调用方）。"""
        self._stop.set()

    def join(self, timeout: float = 3.0) -> bool:
        """等探针线程退出（最多 ``timeout`` 秒）。

        Args:
            timeout: 最长等待秒数，默认 3（SPEC V3 要求 3s 内退出）。

        Returns:
            bool: 线程已退出返回 True；仍存活返回 False。
        """
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout=max(0.0, float(timeout)))
        return not thread.is_alive()

    def run_round(self) -> list[ProbeRecord]:
        """同步发一轮探针（每目标 1 包），返回本轮记录。

        Returns:
            list[ProbeRecord]: 本轮产生的记录；发送器抛异常时也会记一条带
                ``error`` 的记录（保证「账本有痕迹」）。
        """
        produced: list[ProbeRecord] = []
        for spec in self.specs:
            if self._stop.is_set():
                break
            with self._lock:
                self._seq += 1
                seq = self._seq
            sent_monotonic = time.monotonic()
            sent_epoch = time.time()
            try:
                responded, rtt_ms, responder, error = self._sender(spec, seq)
            except Exception as exc:               # noqa: BLE001  探针失败只降级
                responded, rtt_ms, responder, error = (
                    False, None, "", f"{type(exc).__name__}: {exc}")
            record = ProbeRecord(
                spec=spec, sent_monotonic=sent_monotonic, sent_epoch=sent_epoch,
                rtt_ms=rtt_ms, responded=bool(responded),
                responder=responder, error=error, seq=seq)
            with self._lock:
                self.ledger.records.append(record)
            produced.append(record)
        return produced

    def _loop(self) -> None:
        """线程主体：首轮立即、随后 ``wait(interval)``，最多 ``max_rounds`` 轮。"""
        try:
            for index in range(self.max_rounds):
                if self._stop.is_set():
                    break
                self.run_round()
                if index + 1 >= self.max_rounds:
                    break
                if self._stop.wait(self.interval_s):
                    break
        finally:
            self.ledger.finished_epoch = time.time()

    def exclusion_bpf(self) -> str:
        """抓包排除表达式：已发记录优先，未发时按计划规格预生成（抓包前用）。

        Returns:
            str: BPF 串；没有探针规格时返回空串。
        """
        kinds = self.ledger.kinds() or {spec.kind for spec in self.specs}
        return exclusion_bpf(kinds)

    def exclusion_display_filter(self) -> str:
        """分析阶段排除表达式（已发记录优先，未发时按计划规格预生成）。

        Returns:
            str: tshark ``-Y`` 串；没有探针规格时返回空串。
        """
        kinds = self.ledger.kinds() or {spec.kind for spec in self.specs}
        return exclusion_display_filter(kinds)

    def marker_display_filter(self) -> str:
        """只匹配探针报文的显示过滤（统计 pcap 里混入多少探针包）。

        Returns:
            str: tshark ``-Y`` 串；没有探针规格时返回空串。
        """
        kinds = self.ledger.kinds() or {spec.kind for spec in self.specs}
        return probe_marker_display_filter(kinds)

    @property
    def sent_count(self) -> int:
        """已写进账本的探针记录数（含发送失败的记录）。

        Returns:
            int: 记录条数。
        """
        with self._lock:
            return len(self.ledger.records)

    def snapshot(self) -> dict:
        """把「计划 + 账本 + 聚合基线 + 三种过滤串」打包成可 JSON 序列化的快照。

        Returns:
            dict: 键 ``planned``（规格列表）/``ledger``（:meth:`ProbeLedger.to_dict`）/
                ``baseline``（:meth:`ProbeLedger.baseline`）/``exclusion_bpf``/
                ``exclusion_display_filter``/``marker_display_filter``。
        """
        return {
            "planned": [spec.to_dict() for spec in self.specs],
            "ledger": self.ledger.to_dict(),
            "baseline": self.ledger.baseline(),
            "exclusion_bpf": self.exclusion_bpf(),
            "exclusion_display_filter": self.exclusion_display_filter(),
            "marker_display_filter": self.marker_display_filter(),
        }


# ---------------------------------------------------------------- 聚合 / 统计


def aggregate_records(records: Iterable[ProbeRecord]) -> list[dict]:
    """按 ``(role, target, kind)`` 聚合探针记录（纯函数，报告与方向对照共用）。

    Args:
        records: 逐条探针记录。

    Returns:
        list[dict]: 每个角色/目标一组，键 ``role``/``kind``/``target``/``sent``/
            ``recv``/``loss_pct``/``n``/``rtt_min_ms``/``rtt_avg_ms``/
            ``rtt_max_ms``/``jitter_ms``/``errors``。**没有 RTT 样本时**
            ``n=0`` 且 ``rtt_*`` 为 ``None``（不是 0.0）；``loss_pct`` 只在
            ``sent=0`` 时为 ``None``。分组按网关 → DNS → 业务目标排序。
    """
    groups: dict[tuple[str, str, str], dict] = {}
    for record in records:
        role = record.spec.role or "target"
        kind = record.spec.kind.value
        key = (role, str(record.spec.target), kind)
        item = groups.get(key)
        if item is None:
            item = groups[key] = {
                "role": role, "kind": kind, "target": str(record.spec.target),
                "sent": 0, "recv": 0, "loss_pct": None, "n": 0,
                "rtt_min_ms": None, "rtt_avg_ms": None, "rtt_max_ms": None,
                "jitter_ms": None, "_rtts": [], "errors": [],
            }
        item["sent"] += 1
        if record.responded:
            item["recv"] += 1
        if record.rtt_ms is not None:
            item["_rtts"].append(float(record.rtt_ms))
        if record.error and record.error not in item["errors"] and len(item["errors"]) < 3:
            item["errors"].append(record.error)

    role_rank = {role: index for index, role in enumerate(PROBE_ROLES)}
    out: list[dict] = []
    for item in sorted(groups.values(),
                       key=lambda value: (role_rank.get(value["role"], 9),
                                          value["target"], value["kind"])):
        rtts = item.pop("_rtts")
        n = len(rtts)
        item["n"] = n
        if n:
            avg = sum(rtts) / n
            jitter = (sum((value - avg) ** 2 for value in rtts) / n) ** 0.5
            item["rtt_min_ms"] = round(min(rtts), 1)
            item["rtt_avg_ms"] = round(avg, 1)
            item["rtt_max_ms"] = round(max(rtts), 1)
            item["jitter_ms"] = round(jitter, 1)
        item["loss_pct"] = (round((item["sent"] - item["recv"])
                                  / item["sent"] * 100.0, 1)
                            if item["sent"] else None)
        out.append(item)
    return out


def _tshark_module():
    """惰性加载 :mod:`core.tshark`（避免模块导入时拉起平台层）。"""
    try:
        import tshark as module
    except ModuleNotFoundError:
        root = str(Path(__file__).resolve().parents[1])
        if root not in sys.path:
            sys.path.insert(0, root)
        from core import tshark as module
    return module


def count_marked_packets(tshark_path, pcap, kinds: Iterable[ProbeKind]) -> int:
    """用 tshark 显示过滤统计 pcap 里混进了多少**探针报文**。

    这是「已排除 N 个探针包」这句报告文案的取数口：抓包 BPF 生效时应为 0；
    不为 0 说明 BPF 没盖住（例如抓的是 TUN 网卡），分析阶段的显示过滤会兜底。

    Args:
        tshark_path: tshark 可执行文件路径（``Path`` 或字符串）。
        pcap: 已抓好的抓包文件。
        kinds: 本次会发出的探针协议集合。

    Returns:
        int: 命中的探针报文条数；表达式为空 / tshark 失败 / 文件读不了都返回 0
            （统计失败不改变诊断结论）。
    """
    expression = probe_marker_display_filter(kinds)
    if not expression:
        return 0
    try:
        module = _tshark_module()
        rc, out, _err = module.run(
            [str(tshark_path), "-r", str(pcap), "-Y", expression,
             "-T", "fields", "-e", "frame.number"],
            timeout=120)
    except Exception:                              # noqa: BLE001  统计失败只影响说明数字
        return 0
    if rc != 0:
        return 0
    return len([line for line in (out or "").splitlines() if line.strip()])


def count_time_exceeded_packets(tshark_path, pcap) -> int:
    """统计 pcap 里的 ``ICMP type 11``（TTL 超时）报文数。

    MTR 期间设备回的 time-exceeded 认不出探针 id，只能整类排除；这个数字就是
    「已排除 N 个路径探测相关 ICMP」的取数口（同窗口其它流量的 TTL 超时也会被
    算进来 —— 这是残余风险，文档里写明）。

    Args:
        tshark_path: tshark 可执行文件路径（``Path`` 或字符串）。
        pcap: 已抓好的抓包文件。

    Returns:
        int: 命中的 type 11 报文数；tshark 失败 / 文件读不了返回 0
            （统计失败不改变诊断结论）。
    """
    try:
        module = _tshark_module()
        rc, out, _err = module.run(
            [str(tshark_path), "-r", str(pcap), "-Y",
             f"icmp.type == {ICMP_TIME_EXCEEDED}",
             "-T", "fields", "-e", "frame.number"],
            timeout=120)
    except Exception:                              # noqa: BLE001  统计失败只影响说明数字
        return 0
    if rc != 0:
        return 0
    return len([line for line in (out or "").splitlines() if line.strip()])


# ---------------------------------------------------------------- 路径探测执行


def _resolve_target_ip(target: str) -> tuple[str, str]:
    """把目标解析成 IPv4 字面量（内部函数，失败返回原因不抛异常）。

    Args:
        target: 目标 IP / 域名。

    Returns:
        tuple[str, str]: ``(ip, error)``；成功时 ``error`` 为空串，失败时 ``ip``
            为空串。IPv6 目标明确拒绝（本批只做 IPv4 逐跳）。
    """
    text = str(target or "").strip()
    if not text:
        return "", "目标为空"
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        try:
            infos = socket.getaddrinfo(text, None, socket.AF_INET,
                                       socket.SOCK_DGRAM)
        except (OSError, UnicodeError):
            return "", f"DNS 解析失败：{text}"
        for info in infos:
            try:
                address = ipaddress.ip_address(str(info[4][0]))
            except (ValueError, IndexError):
                continue
            if address.version == 4:
                return str(address), ""
        return "", f"DNS 解析失败：{text}"
    if address.version != 4:
        return "", "路径探测当前只支持 IPv4（IPv6 未实现）"
    return str(address), ""


def probe_tcp_reachable(ip: str, port: int, timeout_s: float = PATH_TCP_CHECK_TIMEOUT_S) -> bool:
    """用一次普通 TCP 连接判断「目标端口是否可达」（不发送任何数据）。

    判定口径与影子探针一致：**SYN-ACK（连上）或 RST（连接被拒）都算可达** ——
    两种都证明「去目标的那条路是通的」，这正是区分「ICMP 被过滤」与「链路故障」
    所需的证据；超时 / 网络不可达 / 参数非法都算不可达。

    Args:
        ip: 目标 IPv4 字面量。
        port: 目标端口。
        timeout_s: 单次连接超时（秒）。

    Returns:
        bool: 可达为 True；任何失败为 False（不抛异常）。
    """
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    if not (1 <= port <= 65535):
        return False
    timeout = max(0.1, min(float(timeout_s or PATH_TCP_CHECK_TIMEOUT_S), 3.0))
    try:
        sock = socket.create_connection((str(ip), port), timeout=timeout)
    except ConnectionRefusedError:
        return True                                # RST：主机在，端口没开，网络可达
    except (OSError, ValueError):
        return False
    try:
        sock.close()
    except OSError:
        pass
    return True


def check_target_port(ip: str, port: int | None = None,
                      timeout_s: float = PATH_TCP_CHECK_TIMEOUT_S,
                      checker: Callable[..., bool] | None = None
                      ) -> tuple[bool | None, int | None]:
    """判断目标端口可达性；未给端口时按 :data:`PATH_FALLBACK_PORTS` 依次尝试。

    Args:
        ip: 目标 IPv4 字面量。
        port: 显式端口；``None`` 时尝试 443 → 80。
        timeout_s: 单次连接超时（秒）。
        checker: 可注入的单端口判定函数；省略时用 :func:`probe_tcp_reachable`
            （单测用，避免真连网）。

    Returns:
        tuple[bool | None, int | None]: ``(reachable, port)``。``reachable`` 为
            ``None`` 表示根本没测（ip 为空）；``port`` 是实际测的那个端口
            （显式给的，或第一个可达的；都不可达时是第一个试的端口）。
    """
    if not ip:
        return None, None
    probe = checker or probe_tcp_reachable
    ports = [int(port)] if port else list(PATH_FALLBACK_PORTS)
    for candidate in ports:
        try:
            if probe(ip, candidate, timeout_s):
                return True, candidate
        except Exception:                          # noqa: BLE001  判定失败只当不可达
            continue
    return False, ports[0] if ports else None


#: 一批探测的发送器签名：``(ip, method, probes, timeout_s, port) -> rows``。
#: ``probes`` 是 ``[{"ttl": int, "seq": int}, ...]``；``rows`` 每项的键是
#: ``ttl`` / ``seq`` / ``responded`` / ``rtt_ms`` / ``responder`` / ``error``。
#: 抽成可注入参数，单测不依赖 scapy / 网卡 / 管理员权限。
PathSender = Callable[[str, str, Sequence[Mapping], float, "int | None"], list[dict]]


def _scapy_send_batch(ip: str, method: str, probes: Sequence[Mapping],
                      timeout_s: float, port: int | None = None) -> list[dict]:
    """用 scapy ``sr()`` 批量发一批 TTL 探测并回收（内部函数，可被注入替换）。

    一批只调一次 ``sr()``：scapy 会把 ICMP time-exceeded / echo-reply / SYN-ACK /
    RST 按「原始 IP 头 + 8 字节」匹配回对应的发送包，因此能一次拿到「哪个 TTL
    被谁回应、RTT 多少」。逐跳串行 ``sr1()`` 会把 16 跳拖到 80 秒，实时抓包期间
    根本来不及。

    Args:
        ip: 目标 IPv4 字面量。
        method: ``"icmp"`` 或 ``"tcp"``。
        probes: ``[{"ttl": int, "seq": int}, ...]``。
        timeout_s: 整批等待上限（秒）。
        port: TCP 方法的目的端口；ICMP 方法忽略。

    Returns:
        list[dict]: 每个 probe 一条记录（键 ``ttl``/``seq``/``responded``/
            ``rtt_ms``/``responder``/``error``），顺序与 ``probes`` 一致。
            scapy 不可用或发送失败时抛异常（由 :func:`_scan_hops` 兜底降级）。
    """
    from scapy.all import ICMP, IP, TCP, conf, sr  # noqa: PLC0415  scapy 是可选依赖

    conf.verb = 0
    packets = []
    keyed: list[tuple[int, int]] = []
    for probe in probes:
        ttl = int(probe["ttl"])
        seq = int(probe["seq"])
        if method == "tcp":
            packet = (IP(dst=ip, ttl=ttl) /
                      TCP(sport=probe_src_port(seq), dport=int(port or 443),
                          flags="S", seq=seq % 0xFFFFFFFF))
        else:
            packet = (IP(dst=ip, ttl=ttl) /
                      ICMP(id=PROBE_ID, seq=seq % 0x10000) / PROBE_PAYLOAD)
        packets.append(packet)
        keyed.append((ttl, seq))
    answers, _unanswered = sr(packets, timeout=timeout_s, verbose=0)

    rows: dict[tuple[int, int], dict] = {
        key: {"ttl": key[0], "seq": key[1], "responded": False,
              "rtt_ms": None, "responder": "", "error": "timeout"}
        for key in keyed}
    for sent, received in answers:
        try:
            ttl = int(sent[IP].ttl)
            if method == "tcp":
                seq = int(sent[TCP].seq)
            else:
                seq = int(sent[ICMP].seq)
        except Exception:                          # noqa: BLE001  解析失败只跳过这一包
            continue
        key = (ttl, seq)
        row = rows.get(key)
        if row is None:
            # ICMP seq 会被截到 16 位、TCP seq 截到 32 位：按截断值回查一次。
            match = next((candidate for candidate in keyed
                          if candidate[0] == ttl
                          and (candidate[1] % (0x10000 if method != "tcp"
                                               else 0xFFFFFFFF)) == seq),
                         None)
            if match is None:
                continue
            row = rows[match]
        responder = ""
        try:
            responder = str(received[IP].src)
        except Exception:                          # noqa: BLE001  无 IP 层不影响可达性
            responder = ""
        rtt_ms = None
        sent_time = getattr(sent, "sent_time", None)
        received_time = getattr(received, "time", None)
        if sent_time and received_time:
            rtt_ms = round(max(0.0, (received_time - sent_time) * 1000.0), 1)
        row.update({"responded": True, "rtt_ms": rtt_ms,
                    "responder": responder, "error": ""})
    return [rows[key] for key in keyed]


def _truncate_at_target(rows: Sequence[Mapping], ip: str) -> list[dict]:
    """只保留「到目标为止」的跳（内部函数）。

    一批里会同时发多个 TTL：目标在第 2 跳时，同一批的第 3、4 跳包也已经发出，
    而且目标对更大 TTL 的请求同样会回 echo-reply（TTL 只在转发时递减，到达目的地
    后不再生效）。不截断就会把目标重复算成好几跳，结论跟着变形。

    Args:
        rows: 原始采样记录。
        ip: 目标 IPv4 字面量。

    Returns:
        list[dict]: ``ttl <= 首次探到目标的 ttl`` 的记录；没探到目标时原样返回。
    """
    first: int | None = None
    for row in rows:
        if row.get("responded") and str(row.get("responder")) == ip:
            try:
                ttl = int(row.get("ttl"))
            except (TypeError, ValueError):
                continue
            if first is None or ttl < first:
                first = ttl
    if first is None:
        return list(rows)
    kept: list[dict] = []
    for row in rows:
        try:
            if int(row.get("ttl")) <= first:
                kept.append(dict(row))
        except (TypeError, ValueError):
            continue
    return kept


def _scan_hops(ip: str, method: str, max_hops: int, samples: int,
               timeout_s: float, port: int | None,
               should_stop: Callable[[], bool] | None,
               sender: PathSender) -> tuple[list[dict], bool, str]:
    """按批扫 TTL 1..max_hops（内部函数）：到目标即停、可取消、失败只降级。

    Args:
        ip: 目标 IPv4 字面量。
        method: ``"icmp"`` / ``"tcp"``。
        max_hops: 已夹取的最大跳数。
        samples: 已夹取的每跳采样数。
        timeout_s: 已夹取的单批等待上限（秒）。
        port: TCP 方法的目的端口。
        should_stop: 取消判定（返回 True 就收尾）；``None`` 表示不取消。
        sender: 批量发送器。

    Returns:
        tuple[list[dict], bool, str]: ``(rows, completed, error)``。``completed``
            为 False 表示被取消/预算耗尽；``error`` 非空表示整条路径探测不可用
            （每批都抛异常，例如 scapy 未安装）—— 此时 ``rows`` 为空，调用方
            不应把「没发出包」当成「全部丢包」。
    """
    rows: list[dict] = []
    errors: list[str] = []
    batches = 0
    failed = 0
    completed = True
    seq = 0
    for start in range(1, max_hops + 1, PATH_BATCH_HOPS):
        ttls = list(range(start, min(start + PATH_BATCH_HOPS, max_hops + 1)))
        probes = []
        for ttl in ttls:
            for _ in range(samples):
                seq += 1
                probes.append({"ttl": ttl, "seq": seq})
        if should_stop is not None and should_stop():
            completed = False
            break
        batches += 1
        try:
            got = sender(ip, method, probes, timeout_s, port)
        except Exception as exc:                   # noqa: BLE001  探测失败只降级
            failed += 1
            errors.append(f"{type(exc).__name__}: {exc}")
            continue
        rows.extend(got)
        reached = any(item.get("responded") and str(item.get("responder")) == ip
                      for item in got)
        if reached:
            break
    if batches and failed == batches:
        return [], False, (errors[0] if errors else "路径探测不可用")
    return rows, completed, ""


def run(target: str, port: int | None = None, max_hops: int = PATH_DEFAULT_MAX_HOPS,
        samples: int = PATH_DEFAULT_SAMPLES, timeout_s: float = 1.0, *,
        should_stop: Callable[[], bool] | None = None,
        sender: PathSender | None = None,
        tcp_checker: Callable[..., bool] | None = None) -> PathProbeResult:
    """TTL 递增路径探测（MTR）：逐跳 RTT/丢包/抖动 + 劣化判定 + ICMP→TCP 降级。

    流程（全部在 IPv4 上）：

    1. 目标解析（域名先解析；IPv6 明确拒绝）；
    2. 先测一次目标端口 TCP 可达性（``port`` 未给时试 443/80），留作「ICMP 被过滤」
       的判据；
    3. **ICMP 逐跳**：TTL 1..max_hops 按 :data:`PATH_BATCH_HOPS` 分批，每批一次
       ``sr()``；收到目标自己的回复即停；
    4. 若 ICMP **一个响应都没有**而目标端口 TCP 可达 → 判定 ICMP 被策略过滤，
       改用 **TCP SYN 逐跳**重扫（样本减半），结果带 ``icmp_filtered=True`` /
       ``method="tcp"``；TCP 也不可达 → ``PATH.NO_DATA`` + ``unreachable=True``；
    5. :func:`summarize_path` 给出「第几跳开始劣化 + 该找谁」，TUN/代理再给提示。

    Args:
        target: 目标 IP / 域名。
        port: 目标端口；``None`` 时用 443/80 做可达性判断，TCP 降级时也用它。
        max_hops: 最大跳数，夹到 :data:`PATH_MAX_HOPS_RANGE`。
        samples: 每跳采样数，夹到 :data:`PATH_SAMPLES_RANGE`。
        timeout_s: 单批等待上限（秒），夹到 :data:`PATH_TIMEOUT_RANGE`。
        should_stop: 可选的取消判定；每批发包前调用一次，返回 True 就收尾并把
            ``completed`` 置 False（实时抓包取消/时间预算用）。
        sender: 可注入的批量发送器（单测用；省略时走 scapy）。
        tcp_checker: 可注入的可达性判定 ``(ip, port, timeout) -> bool``；省略时
            等价于 :func:`probe_tcp_reachable`（单测用，避免真连网）。

    Returns:
        :class:`PathProbeResult`: 逐跳统计 + ``verdict_key`` / ``degraded_ttl`` /
        ``method`` / ``icmp_filtered`` / ``tun_suspected`` 等；参数非法 / 解析失败 /
        scapy 不可用时也返回结果（``hops`` 为空、``error`` 写明原因），**不抛异常**
        —— 调用方（实时抓包 / 体检）绝不允许被路径探测拖垮。

    Note:
        本函数**不写文件、不读配置**；发出的每个包都带固定标记（ICMP id =
        :data:`PROBE_ID`、TCP 源端口 ∈ :data:`PROBE_SRC_PORT_RANGE`），抓包侧
        必须同时生效 :func:`exclusion_bpf` 与 :func:`path_exclusion_display_filter`。
        TCP 降级重扫失败时**保留** ICMP 的逐跳数据（「ICMP 全丢」本身已是结论），
        只把原因写进 ``error``，不会因此返回空路径。
    """
    max_hops, samples, timeout_s = clamp_path_options(max_hops, samples, timeout_s)
    original = str(target or "").strip()
    ip, error = _resolve_target_ip(original)
    ledger = {"probe_id": PROBE_ID,
              "src_port_range": list(PROBE_SRC_PORT_RANGE),
              "probes_sent": 0, "method": "icmp"}
    if not ip:
        return PathProbeResult(target=original, target_ip="", verdict_key=PATH_NO_DATA,
                               error=error, max_hops=max_hops, samples=samples,
                               timeout_s=timeout_s, ledger=ledger)

    check = tcp_checker or probe_tcp_reachable
    reachable: bool | None = None
    used_port: int | None = None
    if port:
        try:
            reachable = bool(check(ip, int(port), PATH_TCP_CHECK_TIMEOUT_S))
        except Exception:                          # noqa: BLE001  可达性判定失败只降级
            reachable = None
        used_port = int(port)
    else:
        try:
            reachable, used_port = check_target_port(
                ip, None, PATH_TCP_CHECK_TIMEOUT_S, checker=tcp_checker)
        except Exception:                          # noqa: BLE001  同上
            reachable, used_port = None, None

    send = sender or _scapy_send_batch
    rows, completed, scan_error = _scan_hops(
        ip, "icmp", max_hops, samples, timeout_s, None, should_stop, send)
    rows = _truncate_at_target(rows, ip)
    method = "icmp"
    icmp_filtered = False
    note = ""
    if not scan_error and rows:
        hops = build_hop_stats(rows)
        if not any(hop.rtt_n > 0 or hop.loss_pct < 100.0 for hop in hops) and reachable:
            # ICMP 全丢但目标端口 TCP 可达 → 被策略过滤，改用 TCP SYN 逐跳重扫。
            icmp_filtered = True
            tcp_samples = max(1, samples // 2)
            tcp_rows, tcp_completed, tcp_error = _scan_hops(
                ip, "tcp", max_hops, tcp_samples, timeout_s, used_port,
                should_stop, send)
            completed = completed and tcp_completed
            tcp_rows = _truncate_at_target(tcp_rows, ip)
            if tcp_rows:
                rows = tcp_rows
                samples = tcp_samples
                method = "tcp"
            else:
                # TCP 重扫失败不能把已经证明的「ICMP 全丢」丢掉：保留 ICMP 数据，
                # 把原因写进 error（非致命，报告里仍写「ICMP 被过滤」）。
                note = tcp_error or "TCP 探测没有响应"
    if scan_error:
        return PathProbeResult(target=original, target_ip=ip,
                               verdict_key=PATH_NO_DATA, icmp_filtered=icmp_filtered,
                               target_port_reachable=reachable, ledger=dict(
                                   ledger, probes_sent=len(rows)),
                               method=method, completed=completed,
                               max_hops=max_hops, samples=samples,
                               timeout_s=timeout_s, probes_sent=len(rows),
                               error=scan_error)

    hops = build_hop_stats(rows)
    summary = summarize_path(hops, reachable, method=method, target_ip=ip)
    result = PathProbeResult(
        target=original, target_ip=ip, hops=hops,
        verdict_key=str(summary["verdict_key"]),
        icmp_filtered=icmp_filtered,
        target_port_reachable=reachable,
        ledger=dict(ledger, probes_sent=len(rows), method=method),
        method=method,
        degraded_ttl=summary["degraded_ttl"],
        baseline_ms=summary["baseline_ms"],
        reached_target=bool(summary["reached_target"]),
        completed=completed,
        tun_suspected=bool(summary["tun_suspected"]),
        unreachable=bool(summary["unreachable"]),
        max_hops=max_hops, samples=samples, timeout_s=timeout_s,
        probes_sent=len(rows), error=note)
    return result


# ---------------------------------------------------------------- 路径探测调度


class PathProfiler:
    """后台路径探测线程：实时抓包同时跑 MTR，可取消、失败只降级。

    生命周期与 :class:`ShadowProber` 一致（daemon 线程 + ``Event`` 取消 +
    ``join(timeout)``），额外带**时间预算**：到点后 :func:`run` 在下一批发包前
    收尾并返回已完成的跳（``completed=False``），绝不把抓包主流程拖住。

    Attributes:
        target: 目标 IP / 域名。
        port: 目标端口（``None`` 表示按 443/80 判断）。
        max_hops / samples / timeout_s: 已夹取的探测参数。
        budget_s: 时间预算（秒），由抓包时长 + 5 秒得出。
        result: :class:`PathProbeResult`；线程未跑完时为 ``None``。
        error: 线程内异常（探针不可用）的描述，成功为空串。
    """

    def __init__(self, target: str, port: int | None = None,
                 max_hops: int = PATH_DEFAULT_MAX_HOPS,
                 samples: int = 3, timeout_s: float = 0.8,
                 budget_s: float = 35.0,
                 runner: Callable[..., PathProbeResult] | None = None) -> None:
        self.target = str(target or "").strip()
        self.port = port
        self.max_hops, self.samples, self.timeout_s = clamp_path_options(
            max_hops, samples, timeout_s)
        self.budget_s = max(3.0, float(budget_s or 35.0))
        self.result: PathProbeResult | None = None
        self.error = ""
        self.started_epoch = 0.0
        self.finished_epoch = 0.0
        self._runner = runner or run
        self._stop = threading.Event()
        self._deadline = 0.0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """启动后台线程（幂等：已在跑时直接返回）。"""
        if self._thread is not None and self._thread.is_alive():
            return
        self.started_epoch = time.time()
        self._deadline = time.monotonic() + self.budget_s
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="path-profiler",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """请求停止：置取消位，当前这一批发完即收尾（不阻塞调用方）。"""
        self._stop.set()

    def join(self, timeout: float = 3.0) -> bool:
        """等线程退出（最多 ``timeout`` 秒）。

        Args:
            timeout: 最长等待秒数。

        Returns:
            bool: 已退出返回 True；仍存活返回 False。
        """
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout=max(0.0, float(timeout)))
        return not thread.is_alive()

    def should_stop(self) -> bool:
        """取消判定：外部 ``stop()`` 或时间预算到点都算停。

        Returns:
            bool: 该收尾时为 True。
        """
        return self._stop.is_set() or time.monotonic() >= self._deadline

    def _loop(self) -> None:
        """线程主体：跑一次 :func:`run`，任何异常都只记进 ``error``。"""
        try:
            self.result = self._runner(
                self.target, port=self.port, max_hops=self.max_hops,
                samples=self.samples, timeout_s=self.timeout_s,
                should_stop=self.should_stop)
        except Exception as exc:                   # noqa: BLE001  路径探测失败只降级
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.finished_epoch = time.time()

    def snapshot(self) -> dict:
        """把「参数 + 结果 + 过滤串」打包成可 JSON 序列化的快照。

        Returns:
            dict: 键 ``profile``（:meth:`PathProbeResult.to_dict`；没有结果时
                ``None``）/``error``/``planned_kinds``/``started_epoch``/
                ``finished_epoch``/``budget_s``/``exclusion_bpf``/
                ``exclusion_display_filter``/``marker_display_filter``。
        """
        planned = [ProbeKind.ICMP.value, ProbeKind.TCP_SYN.value]
        kinds = [ProbeKind.ICMP, ProbeKind.TCP_SYN]
        return {
            "profile": self.result.to_dict() if self.result is not None else None,
            "error": self.error,
            "planned_kinds": planned,
            "started_epoch": self.started_epoch,
            "finished_epoch": self.finished_epoch,
            "budget_s": self.budget_s,
            "max_hops": self.max_hops,
            "samples": self.samples,
            "timeout_s": self.timeout_s,
            "exclusion_bpf": exclusion_bpf(kinds),
            "exclusion_display_filter": path_exclusion_display_filter(kinds),
            "marker_display_filter": probe_marker_display_filter(kinds),
        }


__all__ = [
    "PROBE_ID", "PROBE_SRC_PORT_RANGE", "PROBE_PAYLOAD", "PROBE_DNS_NAME",
    "PROBE_INTERVAL_S", "PROBE_TIMEOUT_S", "PROBE_MAX_PACKETS_PER_TARGET",
    "PROBE_ROLES", "ProbeSender", "PathSender",
    "PATH_DEFAULT_MAX_HOPS", "PATH_MAX_HOPS_RANGE", "PATH_DEFAULT_SAMPLES",
    "PATH_SAMPLES_RANGE", "PATH_TIMEOUT_RANGE", "PATH_BATCH_HOPS",
    "PATH_LOSS_DEGRADED_PCT", "PATH_RTT_SPIKE_FACTOR", "PATH_RTT_SPIKE_DELTA_MS",
    "PATH_ICMP_FILTER_LOSS_PCT", "PATH_FALLBACK_PORTS",
    "PATH_TCP_CHECK_TIMEOUT_S", "ICMP_TIME_EXCEEDED",
    "PATH_OK", "PATH_LOCAL_SIDE", "PATH_TRANSPORT_NET", "PATH_SERVER_EDGE",
    "PATH_ICMP_FILTERED", "PATH_NO_DATA",
    "ProbeKind", "HopStatus", "ProbeSpec", "ProbeRecord", "ProbeLedger",
    "HopStat", "PathProbeResult",
    "classify", "clamp_path_options", "build_hop_stats", "degraded_hops",
    "first_degraded_hop", "looks_like_tun", "summarize_path",
    "discover_targets", "plan", "shadow_specs", "rounds_for",
    "probe_len", "probe_src_port", "send_probe", "ShadowProber", "PathProfiler",
    "aggregate_records", "exclusion_bpf", "exclusion_display_filter",
    "path_exclusion_display_filter", "probe_marker_display_filter",
    "count_marked_packets", "count_time_exceeded_packets",
    "probe_tcp_reachable", "check_target_port", "run",
]
