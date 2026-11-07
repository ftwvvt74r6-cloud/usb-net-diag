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

SCHEMA_VERSION = "2.1"

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
        """``layer.l4`` 形式的文案 key（去 ``copy/zh-CN.json`` 查）。

        Returns:
            str: 小写前缀的 key，如 ``"layer.l4"``。

        Note:
            不直接返回 ``"L4 传输层"`` 是为了让改文案不动逻辑，
            也让 CI 断言 ``layer`` 时不会因为改字而变红。
        """
        return f"layer.{self.value.lower()}"


class Severity(str, Enum):
    """分级。用英文枚举而不是中文，是为了让 CI 断言不被文案改动影响。

    ``NA`` 与 ``OK`` 的区别很关键：``OK`` 是「测了，正常」，
    ``NA`` 是「没样本，测不了」—— 后者报成正常就是误报（评审 P0-4）。
    """
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
    """端点在会话里的角色。方向判定、零窗口归属、丢包归因都依赖它。"""
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
    """任务状态机：``QUEUED → RUNNING → (DONE | ERROR | CANCELLED)``。

    ``GET /api/v1/jobs/{id}`` 直接把 ``.value`` 下发给前端，
    前端据此决定「继续轮询 / 停止 / 取结果」。
    """
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------- 序列化


def to_jsonable(value: Any) -> Any:
    """把契约对象递归转成可 JSON 序列化的结构。

    统一处理 ``Enum`` / ``dataclass`` / ``Mapping`` / ``tuple`` / ``frozenset``，
    避免每个类都手写一遍 ``to_dict``。

    Args:
        value: 任意契约对象或普通容器。``Enum`` 取 ``.value``；dataclass 逐字段展开；
            ``Mapping`` 的键统一转 ``str``（JSON 只接受字符串键）。

    Returns:
        Any: 只含 dict / list / str / int / float / bool / None 的结构；
            传入已是标量时原样返回。
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
    """一个网络端点（IP + 可选端口 + 角色）。会话表、发现项、路径探测都用它说话。

    字段：
        ip: IPv4/IPv6 字面量，**不带**方括号（拼 URL 时由渲染层加）。
        port: 传输层端口；``None`` 表示「不知道或不适用」，如 ICMP 只剩 IP。
        kind: 角色（客户端/服务端/网关/DNS/VDI/未知），由 SYN 方向推断，不靠端口大小猜。
        label: 给报告用的可读名字（域名、SNI、资产名），可为空。
    """
    ip: str
    port: int | None = None
    kind: EndpointKind = EndpointKind.UNKNOWN
    label: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", EndpointKind(self.kind))

    def __str__(self) -> str:  # 给日志/报告用，不含脱敏逻辑
        return f"{self.ip}:{self.port}" if self.port is not None else self.ip

    def to_dict(self) -> dict:
        """转字典，供 JSON 下发。

        Returns:
            dict: 键 ``ip`` / ``port`` / ``kind`` / ``label``。
        """
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
        """从一组毫秒值算出 n / avg / p95 / max / jitter。

        ``p95`` 用最近秩法（取下标 ``round(0.95*(n-1))``），不做插值 ——
        样本少时插值会给出一个并不存在的值，运维按这个数去找包会找不到。

        Args:
            values: 任意可迭代的毫秒值（int/float 均可，内部统一转 float）。

        Returns:
            Stats: 空输入返回 ``n=0`` 的全零实例；调用方须先查 ``has_sample`` 再用。
        """
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
        """是否有样本。

        Returns:
            bool: ``n > 0``。为 False 时**不要**把 ``avg=0`` 当「很快」，应报「无样本」。
        """
        return self.n > 0

    def to_dict(self) -> dict:
        """转字典。

        Returns:
            dict: 键 ``n`` / ``avg`` / ``p95`` / ``max`` / ``jitter``，单位毫秒。
        """
        return to_jsonable(self)


@dataclass(frozen=True)
class DirStat:
    """**单个方向**的 TCP 统计 —— 评审 P0-2 的核心修复。

    现有实现把 retrans / dup_ack / zero_win 全部按流累加，导致：
    「客户端重传」既可能是上行丢包、也可能是下行 ACK 丢失，
    而「零窗口」甚至可能来自客户端自己（VDI 场景常见）。

    计数口径（三个字段容易混，必须分开记）：

    * ``retrans`` —— **数据**重传次数，**不含 SYN**（与 ``analyzer`` 里
      ``st["retrans"]`` 的口径一致，否则重传率会与现有报告对不上）。
    * ``syn`` —— 该方向 SYN 帧数（**含重传**）。
    * ``syn_retrans`` —— SYN 重传次数。SYN 重传说明「握手包在路上丢了」，
      是上行连通性信号，与数据重传是两种故障，不能并进 ``retrans``。
    """

    direction: Direction
    packets: int = 0
    bytes: int = 0
    retrans: int = 0
    syn_retrans: int = 0     #: 该方向 SYN 重传次数（上行连通性信号，不计入 retrans）
    dup_ack: int = 0
    ooo: int = 0
    zero_win: int = 0
    win_full: int = 0
    lost_seg: int = 0        #: ``tcp.analysis.lost_segment`` 命中数（对端宣告丢了段）
    rst: int = 0
    syn: int = 0
    data_packets: int = 0
    rtt: Stats = field(default_factory=Stats)

    def __post_init__(self) -> None:
        object.__setattr__(self, "direction", Direction(self.direction))

    def to_dict(self) -> dict:
        """转字典。

        Returns:
            dict: ``direction`` 是字符串；``rtt`` 是嵌套的 ``Stats.to_dict()``；
                其余是 12 个计数字段（packets/bytes/retrans/syn_retrans/dup_ack/
                ooo/zero_win/win_full/lost_seg/rst/syn/data_packets）。
        """
        return to_jsonable(self)


# ---------------------------------------------------------------- 特征（extract 的输出）


@dataclass
class CaptureMeta:
    """采集元信息 —— 回答「这份结论是从哪份数据、用什么参数算出来的」。

    字段：
        mode: ``live``（实时抓）或 ``offline``（分析抓包文件）。
        pcap_file / pcap_name: 绝对路径与文件名；报告命名用后者。
        packets / bytes / duration_s: 规模与时间跨度，判断证据是否充分的第一步。
        interface / bpf: 网卡与过滤器，复现同一份抓包时必需。
        first_ts / last_ts: 首末包的 epoch 秒，用于时间分桶与峰值窗标记。
    """
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
        """转字典。

        Returns:
            dict: 键同字段名，全部是标量（无嵌套、无 Enum）。
        """
        return to_jsonable(self)


@dataclass
class StreamStat:
    """一条 TCP 会话（``tcp.stream``）的统计与端点角色。

    字段：
        client / server: 谁是客户端由 SYN / SYN-ACK 方向推断，不靠端口大小猜。
        app_hint: 应用层线索（HTTP Host、TLS SNI、端口画像），用于「这条流是什么业务」。
        handshake_ms / think_ms: 握手耗时、服务端思考时间（收完请求到给出响应）。
        state: 结束方式（正常关闭 / RST / 无响应）。
        frames: 组成这条流的帧号，供报告跳转定位。
        dirs: 上下行各自的 ``DirStat``，键是 ``Direction``。
    """
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
        """取某个方向的统计。

        Args:
            direction: 想查的方向（``C2S`` / ``S2C``）；传字符串会被自动转成枚举。

        Returns:
            DirStat | None: 该方向没有数据时返回 ``None``（**不是**全零对象）。
                调用方据此区分「这个方向没抓到包」和「这个方向捕到包但计数为 0」。
        """
        return self.dirs.get(Direction(direction))

    def to_dict(self) -> dict:
        """转字典。

        Returns:
            dict: ``dirs`` 的键会转成 ``"c2s"`` / ``"s2c"`` 字符串，``frames`` 转列表。
        """
        return to_jsonable(self)


@dataclass
class TcpFeatures:
    """TCP 层的全部特征（``extract`` 阶段的输出）。

    字段：
        retrans_rate / dup_ack_rate / ooo_rate: 都是**百分比**（0~100），不是 0~1。
        rtt / handshake: ``Stats``，含 p95 与抖动。
        conn_fail / conn_refused: SYN 无应答 / 被对端 RST 的会话数。
        dir_totals: 按方向汇总的 ``DirStat``，键是 ``Direction.value``。
    """
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
        """取某方向的汇总。

        Args:
            direction: ``C2S`` / ``S2C`` / ``BIDIR``。

        Returns:
            DirStat: 该方向的汇总；缺失时返回全零实例（**不会**返回 ``None``）。

        Note:
            全零 ≠ 没样本。要判断有没有数据请先查 ``Features.missing``，
            否则会把「没抓到上行包」误报成「上行完全正常」。
        """
        key = Direction(direction).value
        return self.dir_totals.get(key) or DirStat(direction=direction)

    @property
    def has_streams(self) -> bool:
        """是否聚合出了会话。

        Returns:
            bool: 至少有一条 ``tcp.stream`` 才能做会话级判断（谁连谁、谁在重传）。
        """
        return len(self.streams) > 0

    def to_dict(self) -> dict:
        """转字典。

        Returns:
            dict: ``streams`` 是 ``StreamStat.to_dict()`` 的列表，
                ``dir_totals`` 是方向字符串到 ``DirStat.to_dict()`` 的映射。
        """
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
        """某个特征是否算出来了。

        Args:
            key: 特征键名，如 ``"tcp.rtt"`` / ``"dns.avg"``。

        Returns:
            bool: True 表示可用。False 时规则应当**跳过**，而不是判「正常」。
        """
        return key not in self.missing

    def to_dict(self) -> dict:
        """转字典，可序列化为 ``features.json`` 供 CI 回放。

        Returns:
            dict: 各特征块原样输出；``missing`` 转成排序后的列表，方便 diff。
        """
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
        """校验字段自洽性；不合法直接抛 —— 宁可启动就炸，也不要产出坏结论。

        Returns:
            None: 校验通过时无返回值。

        Raises:
            ValueError: ``rule_id`` 形态不符 ``RULE_ID_RE``、``confidence`` 越界、
                推断类（``INFERRED``）却给了 1.0 置信度、或者判了严重却没有任何
                ``targets`` / ``metric`` 可用于定位。
        """
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
        """严重度排序权重（越小越严重）。

        Returns:
            int: critical=0 / warning=1 / info=2 / ok=3 / na=4，用于 ``min()`` 找最坏项。
        """
        return _SEV_RANK[self.severity]

    def to_dict(self) -> dict:
        """转字典。

        Returns:
            dict: ``layer`` / ``severity`` / ``category`` / ``evidence_kind`` /
                ``direction`` 转成字符串，``targets`` / ``frames`` / ``streams`` 转列表。
        """
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
        """转字典。

        Returns:
            dict: 键 ``ok`` / ``reasons`` / ``needed`` / ``reason_args``。
                前三者的内容是 copy 表的 key（不是成句中文），渲染层负责翻译。
        """
        return to_jsonable(self)


@dataclass(frozen=True)
class LayerStatus:
    """某一层的汇总状态（给 UI 的四层状态条用）。

    字段：
        layer: 哪一层。
        severity: 该层最坏项的严重度。
        detail_key / detail_args: 「L4 有 2 条严重」这类描述的文案 key 与占位符实参。
        finding_ids: 归属这一层的 ``rule_id`` 列表。
    """
    layer: Layer
    severity: Severity
    detail_key: str = ""
    detail_args: Mapping[str, Any] = field(default_factory=dict)
    finding_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "layer", Layer(self.layer))
        object.__setattr__(self, "severity", Severity(self.severity))

    def to_dict(self) -> dict:
        """转字典。

        Returns:
            dict: ``layer`` / ``severity`` 是字符串，``finding_ids`` 是列表。
        """
        return to_jsonable(self)


@dataclass(frozen=True)
class Verdict:
    """最终判定 —— 一句话结论 + 四层状态 + 下一步做什么。

    字段：
        level: 总体严重度。
        headline_key / headline_args: 结论文案的 key 与占位符实参（**不含中文**）。
        impact_key: 「对用户意味着什么」的文案 key。
        next_step_keys: 处置建议的 key 列表，按优先级排列。
        sufficiency: 证据是否够；``ok=False`` 时 ``level`` 必须是降级后的结论
            （见 ``VERDICT.INSUFFICIENT``），不能拿「没样本」当「正常」。
    """
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
        """转字典。

        Returns:
            dict: ``layers`` 是 ``LayerStatus.to_dict()`` 的列表，
                ``sufficiency`` 是 ``Sufficiency.to_dict()``。
        """
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
        """转字典。

        Returns:
            dict: 键 ``app_version`` / ``schema_version`` / ``tshark_version`` /
                ``rules_version`` / ``config_sha256`` / ``prompt_version`` / ``generated_at``。
                任一来源取不到时该键是空串而非 ``None``，方便直接拼进报告表头。
        """
        return to_jsonable(self)


# ---------------------------------------------------------------- 顶层结果


@dataclass
class AnalyzeResult:
    """一次离线/实时分析的完整结果（顶层对象）。

    字段：
        capture: 采集元信息。
        features: 提取出的全部特征（``extract`` 的输出）。
        findings: 规则命中的结论，已按严重度排序。
        metrics: 给报告用的扁平指标表（含百分比、均值），保留旧字段名。
        verdict: 判定结果；``None`` 表示还没算。
        provenance: 可复现信息。
    """
    capture: CaptureMeta
    features: Features
    findings: tuple[Finding, ...] = ()
    metrics: Mapping[str, Any] = field(default_factory=dict)
    verdict: Verdict | None = None
    provenance: Provenance = field(default_factory=Provenance)
    schema_version: str = SCHEMA_VERSION

    def by_layer(self, layer: Layer) -> tuple[Finding, ...]:
        """取某一层的全部发现。

        Args:
            layer: 目标层（``Layer`` 枚举或其字符串值）。

        Returns:
            tuple[Finding, ...]: 该层的发现，保持原有排序；无命中时是空元组而非 ``None``。
        """
        return tuple(f for f in self.findings if f.layer is Layer(layer))

    @property
    def worst(self) -> Finding | None:
        """最严重的那一条发现。

        Returns:
            Finding | None: 没有任何发现时返回 ``None``。
                注意 ``None`` 只表示「没命中规则」，**不代表**证据充分 ——
                那个要看 ``verdict.sufficiency.ok``。
        """
        return min(self.findings, key=lambda f: f.rank, default=None)

    def to_dict(self) -> dict:
        """转字典，作为 ``/api/v1/analyze`` 的响应体。

        Returns:
            dict: 嵌套的 ``features`` / ``findings`` / ``verdict`` 已递归转成基本类型。
        """
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
        """转字典。

        Returns:
            dict: ``segments`` 是分段计时列表，每段含 ``phase`` / ``ms`` / ``ok``；
                ``level`` 与 ``evidence_kind`` 转成字符串。
        """
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
        """转字典。

        Returns:
            dict: ``flows`` 是会话列表；``summary`` 含计数、协议分布与扇出（fanout）提示。
        """
        return to_jsonable(self)


# ---------------------------------------------------------------- 任务


@dataclass
class Job:
    """一个后台任务。抓包、分析抓包文件、通信观察都走它。

    字段：
        job_id: 短随机串，用作 API 路径参数。
        params: 启动参数原样保存，便于「按上次参数重跑」。
        progress: 0.0~1.0；无法估算进度时保持 0，前端显示为「进行中」而不是假的百分比。
        error: 失败时的 ``DiagError.to_dict()``。
        result_ref: 结果落盘路径；大结果不塞进内存，避免轮询把内存打满。
        trace_id: 关联日志，便于前端报错对上后端记录。
    """
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
        """是否还在执行。

        Returns:
            bool: ``QUEUED`` 或 ``RUNNING`` 时为 True。
        """
        return self.state in (JobState.QUEUED, JobState.RUNNING)

    def public(self) -> dict:
        """给 ``GET /api/v1/jobs/{id}`` 用的视图。

        Returns:
            dict: 10 个字段（``job_id`` / ``kind`` / ``state`` / ``progress`` /
                ``created_at`` / ``started_at`` / ``finished_at`` / ``error`` /
                ``result_ref`` / ``trace_id``）。**不含**完整 ``result`` ——
                否则前端每次轮询都要拉几 MB 的结论。
        """
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
        """转字典（含完整 ``result``，用于落盘存档）。

        Returns:
            dict: 全部字段；``state`` 已转成字符串。
        """
        return to_jsonable(self)


# ---------------------------------------------------------------- API envelope


def envelope_ok(data: Any, trace_id: str = "") -> dict:
    """成功响应信封。所有 ``/api/v1/*`` 的成功返回都套这一层。

    Args:
        data: 业务数据，任意契约对象（内部会 ``to_jsonable``）。
        trace_id: 请求追踪号，用于把前端报错对上后端日志。

    Returns:
        dict: 键 ``schema_version`` / ``ok``(True) / ``data`` / ``error``(None) / ``trace_id``。
    """
    return {"schema_version": SCHEMA_VERSION, "ok": True, "data": to_jsonable(data),
            "error": None, "trace_id": trace_id}


def envelope_err(code: str, message: str, hint: str = "", trace_id: str = "",
                 **extra: Any) -> dict:
    """失败响应信封。**所有**可预期失败都应走这里，不要混用纯文本 404。

    Args:
        code: ``ErrorCode.value``，如 ``"E_NO_TSHARK"``。
        message: 面向用户的说明，一句话说清发生了什么。
        hint: 下一步怎么办；留空时由调用方从 ``errors.HINTS`` 取该 code 的默认提示。
        trace_id: 请求追踪号。
        **extra: 附加诊断信息，会被放进 ``error["detail"]``。

    Returns:
        dict: 键 ``schema_version`` / ``ok``(False) / ``data``(None) / ``error`` / ``trace_id``；
            ``error`` 内含 ``code`` / ``message`` / ``hint``（有 extra 时加 ``detail``）。
    """
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
