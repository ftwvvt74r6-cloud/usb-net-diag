"""全项目唯一数据契约。

任何两个模块之间传递的数据，都必须在这里有定义。禁止再自造 dict 结构。

为什么要有这个文件（对应评审 P0-1）：

* 现状 ``rows[]`` 把 ``"L4 传输层"`` / ``"严重"`` 这类**中文文案**当接口值，
  UI、Markdown、JSON 报告、AI prompt、MCP 五个出口都靠字符串匹配消费；
  改一句文案就破一次接口，CI 也无法稳定断言。
* 这里把它们换成稳定机器码（``Layer`` / ``Severity`` / ``Category`` /
  ``Direction``），文案一律查 ``copy/zh-CN.json``。

字段设计要点：

* ``Finding.direction`` 与 ``Finding.evidence_kind`` 是相对现有实现的**关键增强**
  ——没有方向就无法实现规划第 5 步的「上行/下行丢包」「零窗口归属」；
  没有 ``MEASURED/INFERRED`` 区分，就会把「疑似」写成「确定」。
* ``Features.missing`` 让「特征缺失」和「特征为零」不再混为一谈（评审 P0-4/P1）。
* ``Provenance`` 让任何一份结论都能复现（评审 4.1 第 5 条）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

SCHEMA_VERSION = "2.0"

#: ``RULE_ID`` 形态：大写点分，如 ``L4.RETRANS.HIGH`` / ``L7.DNS.FAIL``。
RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(\.[A-Z0-9_]+)+$")


# ---------------------------------------------------------------- 枚举


class Layer(str, Enum):
    """OSI 分层。``SEC`` 是安全观察，不参与网络故障主判定。"""

    L2 = "L2"
    L3 = "L3"
    L4 = "L4"
    L7 = "L7"
    SEC = "SEC"

    @property
    def label_key(self) -> str:
        return f"layer.{self.value.lower()}"


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"
    NA = "na"  # 无样本 / 不适用


_SEV_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
    Severity.OK: 3,
    Severity.NA: 4,
}


class Direction(str, Enum):
    """数据流向（相对抓包点）。

    注意语义：``C2S`` 指「客户端 → 服务端」的**数据**方向。
    零窗口这类字段要记录**通告方**，见 ``Finding.metric["advertised_by"]``。
    """

    C2S = "c2s"
    S2C = "s2c"
    BIDIR = "bidir"


class EndpointKind(str, Enum):
    CLIENT = "client"
    SERVER = "server"
    GATEWAY = "gateway"
    DNS = "dns"
    VDI = "vdi"
    UNKNOWN = "unknown"


class EvidenceKind(str, Enum):
    """结论强度。``INFERRED`` 必须带 ``confidence < 1.0``。"""

    MEASURED = "measured"  # 直接观测到的数值
    INFERRED = "inferred"  # 推断（如「疑似上行丢包」）


class Category(str, Enum):
    """故障类别英文码（原实现里是中文串）。"""

    COLLECT = "collect"                    # 采集有效性
    L2_ARP = "l2_arp"                      # 本地可达性
    NET_UNREACH = "net_unreach"            # 网络可达性
    NET_LATENCY = "net_latency"            # 网络时延
    CONNECT = "connect"                    # 连接建立
    TRANSPORT = "transport"                # 传输质量
    DNS = "dns"
    APP = "app"                            # 应用响应
    TLS = "tls"
    SEC_EXFIL = "sec_exfil"                # 可疑外联
    SEC_SCAN = "sec_scan"                  # 端口扫描
    SEC_PLAINTEXT = "sec_plaintext"        # 明文凭证


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------- 序列化


def to_jsonable(value: Any) -> Any:
    """把契约对象递归转成可 JSON 序列化的结构。

    统一处理 ``Enum`` / ``dataclass`` / ``Mapping`` / ``tuple`` / ``frozenset``，
    避免每个类都写一遍 ``to_dict``。
    """
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in value]
    return value


# ---------------------------------------------------------------- 基础构件


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int | None = None
    kind: EndpointKind = EndpointKind.UNKNOWN
    label: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", EndpointKind(self.kind))

    def __str__(self) -> str:  # 给日志/报告用，不含脱敏逻辑
        return f"{self.ip}:{self.port}" if self.port is not None else self.ip

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass(frozen=True)
class Stats:
    """毫秒级统计。没有样本时 ``n == 0``，**不要**用 0 冒充「很快」。"""

    n: int = 0
    avg: float = 0.0
    p95: float = 0.0
    max: float = 0.0
    jitter: float = 0.0

    @classmethod
    def from_values(cls, values: Iterable[float]) -> "Stats":
        vals = sorted(float(v) for v in values)
        n = len(vals)
        if not n:
            return cls()
        avg = sum(vals) / n
        var = sum((x - avg) ** 2 for x in vals) / n
        p95 = vals[min(n - 1, int(round(0.95 * (n - 1))))]
        return cls(n=n, avg=round(avg, 1), p95=round(p95, 1),
                   max=round(vals[-1], 1), jitter=round(var ** 0.5, 1))

    @property
    def has_sample(self) -> bool:
        return self.n > 0

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass(frozen=True)
class DirStat:
    """**单个方向**的 TCP 统计 —— 评审 P0-2 的核心修复。

    现有实现把 retrans / dup_ack / zero_win 全部按流累加，导致：
    「客户端重传」既可能是上行丢包、也可能是下行 ACK 丢失，
    而「零窗口」甚至可能来自客户端自己（VDI 场景常见）。
    """

    direction: Direction
    packets: int = 0
    bytes: int = 0
    retrans: int = 0
    dup_ack: int = 0
    ooo: int = 0
    zero_win: int = 0
    win_full: int = 0
    rst: int = 0
    syn: int = 0
    data_packets: int = 0
    rtt: Stats = field(default_factory=Stats)

    def __post_init__(self) -> None:
        object.__setattr__(self, "direction", Direction(self.direction))

    def to_dict(self) -> dict:
        return to_jsonable(self)


# ---------------------------------------------------------------- 特征（extract 的输出）


@dataclass
class CaptureMeta:
    mode: str = "offline"          # live | offline
    pcap_file: str = ""
    pcap_name: str = ""
    packets: int = 0
    bytes: int = 0
    duration_s: float = 0.0
    interface: str = ""
    bpf: str = ""
    first_ts: float = 0.0
    last_ts: float = 0.0

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class StreamStat:
    stream: str
    client: Endpoint
    server: Endpoint
    app_hint: str = ""
    packets: int = 0
    bytes: int = 0
    handshake_ms: float | None = None
    think_ms: float | None = None
    state: str = ""
    frames: tuple[int, ...] = ()
    dirs: Mapping[Direction, DirStat] = field(default_factory=dict)

    def dir_of(self, direction: Direction) -> DirStat | None:
        return self.dirs.get(Direction(direction))

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class TcpFeatures:
    packets: int = 0
    bytes: int = 0
    streams: tuple[StreamStat, ...] = ()
    retrans_rate: float = 0.0
    dup_ack_rate: float = 0.0
    ooo_rate: float = 0.0
    rtt: Stats = field(default_factory=Stats)
    handshake: Stats = field(default_factory=Stats)
    conn_fail: int = 0
    conn_refused: int = 0
    #: 全量按方向汇总；键为 Direction.value，便于直接落 JSON。
    dir_totals: Mapping[str, DirStat] = field(default_factory=dict)

    def total(self, direction: Direction) -> DirStat:
        """取某方向的汇总；缺失时返回全零（调用方须先查 ``requires``）。"""
        key = Direction(direction).value
        return self.dir_totals.get(key) or DirStat(direction=direction)

    @property
    def has_streams(self) -> bool:
        return len(self.streams) > 0

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class Features:
    """``extract`` 层的唯一输出，可序列化为 ``features.json`` 供 CI 回放。

    有了它，规则测试不再需要 tshark（评审第 2 步）。
    """

    capture: CaptureMeta = field(default_factory=CaptureMeta)
    tcp: TcpFeatures = field(default_factory=TcpFeatures)
    dns: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    icmp: dict = field(default_factory=dict)
    arp: dict = field(default_factory=dict)
    tls: dict = field(default_factory=dict)
    app: dict = field(default_factory=dict)
    derived: dict = field(default_factory=dict)   # 时间分桶、峰值窗标记等
    #: 未能计算的特征键集合；``Rule.requires`` 与之比对，避免「没样本=正常」。
    missing: frozenset[str] = frozenset()

    def has(self, key: str) -> bool:
        return key not in self.missing

    def to_dict(self) -> dict:
        return to_jsonable(self)


# ---------------------------------------------------------------- 发现（规则输出）


@dataclass(frozen=True)
class Finding:
    """一条规则命中结果。**不含中文**，也不含建议文案。"""

    rule_id: str
    layer: Layer
    severity: Severity
    category: Category
    metric: Mapping[str, Any] = field(default_factory=dict)
    targets: tuple[Endpoint, ...] = ()
    frames: tuple[int, ...] = ()
    streams: tuple[str, ...] = ()
    direction: Direction | None = None
    confidence: float = 1.0
    evidence_kind: EvidenceKind = EvidenceKind.MEASURED
    advice_key: str = ""
    #: 结论标题的文案 key（不含 ``headline.`` 前缀）。留空时用 ``rule_id``。
    #: 需要按方向/归属给不同措辞的规则在这里指定，如 ``L4.RETRANS.HIGH.UP``。
    headline_key: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "layer", Layer(self.layer))
        object.__setattr__(self, "severity", Severity(self.severity))
        object.__setattr__(self, "category", Category(self.category))
        object.__setattr__(self, "evidence_kind", EvidenceKind(self.evidence_kind))
        if self.direction is not None:
            object.__setattr__(self, "direction", Direction(self.direction))
        object.__setattr__(self, "targets", tuple(self.targets))
        object.__setattr__(self, "frames", tuple(self.frames))
        object.__setattr__(self, "streams", tuple(self.streams))
        self.validate()

    def validate(self) -> None:
        if not RULE_ID_RE.match(self.rule_id):
            raise ValueError(f"rule_id 形态不合法（应形如 L4.RETRANS.HIGH）：{self.rule_id!r}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError(f"confidence 必须落在 [0,1]：{self.confidence!r}")
        if self.evidence_kind is EvidenceKind.INFERRED and self.confidence >= 1.0:
            raise ValueError(f"{self.rule_id}：推断类结论必须 confidence < 1.0")
        if self.severity is Severity.CRITICAL and not self.targets and not self.metric:
            raise ValueError(f"{self.rule_id}：严重级别必须给出 targets 或 metric，便于定位")

    @property
    def rank(self) -> int:
        return _SEV_RANK[self.severity]

    def to_dict(self) -> dict:
        return to_jsonable(self)


# ---------------------------------------------------------------- 充足性 / 分层 / 判定


@dataclass(frozen=True)
class Sufficiency:
    """证据充分性。``ok=False`` 时结论必须降级为「无法判定」（评审 P0-4）。"""

    ok: bool = True
    reasons: tuple[str, ...] = ()      # 如 ("duration_too_short",) —— copy 表里的 key
    needed: tuple[str, ...] = ()       # 如 ("collect_again",) —— next_step 表的 key
    #: reason key → 文案占位符实参，如 {"duration_too_short": {"actual": 8, "need": 10}}
    reason_args: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass(frozen=True)
class LayerStatus:
    layer: Layer
    severity: Severity
    detail_key: str = ""
    detail_args: Mapping[str, Any] = field(default_factory=dict)
    finding_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "layer", Layer(self.layer))
        object.__setattr__(self, "severity", Severity(self.severity))

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass(frozen=True)
class Verdict:
    level: Severity
    headline_key: str
    headline_args: Mapping[str, Any] = field(default_factory=dict)
    impact_key: str = ""
    layers: tuple[LayerStatus, ...] = ()
    finding_ids: tuple[str, ...] = ()
    next_step_keys: tuple[str, ...] = ()
    sufficiency: Sufficiency = field(default_factory=Sufficiency)

    def __post_init__(self) -> None:
        object.__setattr__(self, "level", Severity(self.level))
        object.__setattr__(self, "layers", tuple(self.layers))

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass(frozen=True)
class Provenance:
    """让一份结论可复现（评审 4.1 第 5 条）。"""

    app_version: str = ""
    schema_version: str = SCHEMA_VERSION
    tshark_version: str = ""
    rules_version: str = ""
    config_sha256: str = ""
    prompt_version: str = ""
    generated_at: str = ""

    def to_dict(self) -> dict:
        return to_jsonable(self)


# ---------------------------------------------------------------- 顶层结果


@dataclass
class AnalyzeResult:
    capture: CaptureMeta
    features: Features
    findings: tuple[Finding, ...] = ()
    metrics: Mapping[str, Any] = field(default_factory=dict)
    verdict: Verdict | None = None
    provenance: Provenance = field(default_factory=Provenance)
    schema_version: str = SCHEMA_VERSION

    def by_layer(self, layer: Layer) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.layer is Layer(layer))

    @property
    def worst(self) -> Finding | None:
        return min(self.findings, key=lambda f: f.rank, default=None)

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class ProbeResult:
    """``probe``（协议自适应体检）的结果。字段含义沿用现有实现。"""

    target: str = ""
    port: int | None = None
    ip: str = ""
    protocol: str = ""
    segments: tuple[Mapping[str, Any], ...] = ()
    total_ms: float = 0.0
    level: Severity = Severity.OK
    headline_key: str = ""
    evidence_kind: EvidenceKind = EvidenceKind.MEASURED

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass
class PassiveResult:
    """``passive``（通信观察 / 被动监听）的结果。"""

    interface: str = ""
    duration_s: float = 0.0
    engine: str = ""
    bpf: str = ""
    flows: tuple[Mapping[str, Any], ...] = ()
    summary: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return to_jsonable(self)


# ---------------------------------------------------------------- 任务


@dataclass
class Job:
    job_id: str
    kind: str
    state: JobState = JobState.QUEUED
    params: Mapping[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    started_at: float = 0.0
    finished_at: float = 0.0
    progress: float = 0.0
    error: Mapping[str, Any] | None = None
    result: Any = None
    result_ref: str = ""
    trace_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", JobState(self.state))

    @property
    def running(self) -> bool:
        return self.state in (JobState.QUEUED, JobState.RUNNING)

    def public(self) -> dict:
        """给 ``GET /api/v1/jobs/{id}`` 用的视图：**不带**完整 result。"""
        return {
            "job_id": self.job_id,
            "kind": self.kind,
            "state": self.state.value,
            "progress": round(self.progress, 3),
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": to_jsonable(self.error),
            "result_ref": self.result_ref,
            "trace_id": self.trace_id,
        }

    def to_dict(self) -> dict:
        return to_jsonable(self)


# ---------------------------------------------------------------- API envelope


def envelope_ok(data: Any, trace_id: str = "") -> dict:
    return {"schema_version": SCHEMA_VERSION, "ok": True, "data": to_jsonable(data),
            "error": None, "trace_id": trace_id}


def envelope_err(code: str, message: str, hint: str = "", trace_id: str = "",
                 **extra: Any) -> dict:
    err = {"code": code, "message": message, "hint": hint}
    if extra:
        err["detail"] = {k: to_jsonable(v) for k, v in extra.items()}
    return {"schema_version": SCHEMA_VERSION, "ok": False, "data": None,
            "error": err, "trace_id": trace_id}


__all__ = [
    "SCHEMA_VERSION", "RULE_ID_RE", "to_jsonable",
    "Layer", "Severity", "Direction", "EndpointKind", "EvidenceKind", "Category", "JobState",
    "Endpoint", "Stats", "DirStat", "CaptureMeta", "StreamStat", "TcpFeatures", "Features",
    "Finding", "Sufficiency", "LayerStatus", "Verdict", "Provenance",
    "AnalyzeResult", "ProbeResult", "PassiveResult", "Job",
    "envelope_ok", "envelope_err",
]
