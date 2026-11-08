"""影子探测（Shadow Probing）+ 路径探测（MTR）骨架 —— D 批次迁移落点。

**解决什么问题**：实时抓包（全网体检 / 单目标诊断）期间，业务报文可能一个都没有
（选错网卡、流量走 VPN、目标本来就没流量）。这时报告只能写「无样本」，答不出
「是本地出口丢包，还是对端不回」。本模块在抓包的同时，每约 5 秒发一轮**极轻量**
探针（网关 ICMP、目标端口 TCP SYN；DNS 服务器 UDP 待平台 API 落地后启用），
把「RTT / 丢包基线」变成事实，并作为方向判定的**两侧对照证据**。

**谁调用它**：:mod:`core.diagnose` 的实时抓包路径（``capture_live`` / ``run_scan``）
构造 :class:`ShadowProber` 并按抓包时长启停；:mod:`core.verdict` 只读
``meta["probe_baseline"]``（由 ``run_scan`` 注入），不直接 import 本模块。

**不做什么**：

* 不实现 MTR / TTL 逐跳：:func:`run` 保持 ``NotImplementedError``，留给后续 PR；
* 不发「业务请求」：探针只发 1 个 ICMP / TCP SYN / 最小 DNS 查询，不建连、不传数据；
* 不联网上报：探针结果只进本地报告；
* 离线分析 / 被动监听路径**绝不**构造本模块的探针（见 tests/test_shadow_probe.py）。

**输入输出**：输入是探针规格 :class:`ProbeSpec`（目标 / 端口 / 角色）与抓包时长；
输出是一份 :class:`ProbeLedger` 账本（逐条记录 + 聚合基线）。账本同时承担
**排除**职责：``exclusion_bpf()`` / ``exclusion_display_filter()`` 把探针流量从
抓包与统计里剔除，避免「探针自己造出 ICMP 超时 / 额外 TCP 会话」的误报。

**三个必须做对的细节**（评审第 6 步的踩坑记录）：

1. **探针不能污染诊断**：抓包阶段用 BPF 排除（ICMP echo 的固定 id、TCP/UDP 的
   固定源端口段），分析阶段再用 tshark ``-Y`` 显示过滤做防御层 —— 只做 BPF 不够，
   探针的**回复**（echo-reply / SYN-ACK / RST）方向端口是反的，BPF 漏了它就会
   变成「额外 TCP 会话」。
2. **探针要能被认出来是自己发的**：固定 :data:`PROBE_ID`、固定源端口段
   :data:`PROBE_SRC_PORT_RANGE`、固定 payload :data:`PROBE_PAYLOAD`，全部写进账本。
3. **时钟对齐**：pcap 用系统时钟（``frame.time_epoch``），探测用
   ``time.monotonic()``；两者有偏移。所以只记 ``sent_epoch`` 做区间归属，
   不逐包对齐。
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
    """路径探测（MTR，后续 PR）的单跳统计；本批只保留数据结构与 ``classify``。"""

    ttl: int
    ip: str = ""
    sent: int = 0
    lost: int = 0
    rtt_min_ms: float | None = None
    rtt_avg_ms: float | None = None
    status: HopStatus = HopStatus.OK

    @property
    def loss_pct(self) -> float:
        """单跳丢包率（百分比，1 位小数）。

        Returns:
            float: ``lost / sent * 100``；``sent == 0``（无样本）时返回 0.0。
                本批 MTR 未实现，``sent`` 本身承担「有没有样本」的表达。
        """
        return round(self.lost / self.sent * 100.0, 1) if self.sent else 0.0


@dataclass(frozen=True)
class PathProbeResult:
    """路径探测（MTR）结果；``run()`` 本批未实现，结构先冻结给后续 PR 用。"""

    target: str = ""
    hops: tuple[HopStat, ...] = ()
    verdict_key: str = ""
    icmp_filtered: bool = False
    target_port_reachable: bool | None = None
    ledger: Mapping | None = None

    def to_dict(self) -> dict:
        """把路径探测结果转成可 JSON 序列化的字典。

        Returns:
            dict: 键 ``target``/``verdict_key``/``icmp_filtered``/
                ``target_port_reachable``/``hops``（逐跳）/``ledger``。
        """
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
    ``GetBestRoute``（不解析本地化文本）；``dns_servers()`` 尚未实现时按「无 DNS
    角色」降级。业务目标来自抓包目标（IP / CIDR 取第一个主机 / 域名先解析）。

    Args:
        vdi_hint: 调用方显式给的业务目标提示（优先于 ``target``）。
        target: 用户填写的诊断目标；空表示全网体检（没有业务目标角色）。

    Returns:
        dict[str, str]: 可能含 ``gateway`` / ``dns`` / ``vdi`` / ``vdi_port``。
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
    for server in servers or ():
        dns_ip = _probeable_ip(server)
        if dns_ip:
            found["dns"] = dns_ip
            break
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


# ---------------------------------------------------------------- 执行（占位）


def run(target: str, port: int | None = None, max_hops: int = 16,
        samples: int = 5, timeout_s: float = 1.0) -> PathProbeResult:
    """TTL 递增路径探测（MTR）—— **本批不实现，后续 PR**。

    为什么不在本批做（SPEC §5）：本批只交付「影子探测」；MTR 需要逐跳 TTL
    递增、每跳采样与丢包率统计，属于另一个可独立验收的增量。这里保留 API 与
    数据结构，后续 PR 用 scapy 实现：

        pkt = IP(dst=target, ttl=ttl) / ICMP(id=PROBE_ID, seq=n)
        ans, unans = sr(pkt, timeout=timeout, verbose=0)

    另外两件必做的事（后续 PR 一起做）：

    1. 抓包侧同时生效 ``ledger.exclusion_bpf()``（否则探针污染诊断）；
    2. 探测前先测一次目标端口 TCP 连通性，用于判定「ICMP 被过滤」而不是「链路故障」。

    Args:
        target: 目标 IP / 域名。
        port: 目标端口；``None`` 时探测逻辑自行决定。
        max_hops: 最大跳数。
        samples: 每跳采样数。
        timeout_s: 单包等待上限（秒）。

    Returns:
        不返回：本批固定抛 :class:`NotImplementedError`。

    Raises:
        NotImplementedError: 恒抛，提示实现见本函数 docstring。
    """
    raise NotImplementedError(
        "pathprobe.run()（MTR TTL 逐跳）后续 PR 实现；本批只交付影子探测。"
        "抓包侧必须先合并 ledger.exclusion_bpf()，否则探针会污染诊断。")


__all__ = [
    "PROBE_ID", "PROBE_SRC_PORT_RANGE", "PROBE_PAYLOAD", "PROBE_DNS_NAME",
    "PROBE_INTERVAL_S", "PROBE_TIMEOUT_S", "PROBE_MAX_PACKETS_PER_TARGET",
    "PROBE_ROLES", "ProbeSender",
    "ProbeKind", "HopStatus", "ProbeSpec", "ProbeRecord", "ProbeLedger",
    "HopStat", "PathProbeResult",
    "classify", "discover_targets", "plan", "shadow_specs", "rounds_for",
    "probe_len", "probe_src_port", "send_probe", "ShadowProber",
    "aggregate_records", "exclusion_bpf", "exclusion_display_filter",
    "probe_marker_display_filter", "count_marked_packets", "run",
]
