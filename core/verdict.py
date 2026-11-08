"""把结构化分析结果翻译成「故障定位结论」。

输出目标（对齐一线运维的真实用法）：
  1. 先回答：问题在哪一层、哪个协议、哪个对端 —— 一句话说清
  2. 再回答：这一层坏了会看到什么现象、影响什么业务
  3. 最后给：按顺序可执行的处置动作

本模块不调用网络与模型，纯规则推导，离线可用。
专业明细（帧号、IP、端口、Stream、原始指标）全部保留在 proof 与 rows 中。
"""
from __future__ import annotations

import sys
from pathlib import Path

try:                                    # 扁平导入：core/ 在 sys.path 上（report.py / diagnose.py）
    from contracts import Sufficiency
except ImportError:                     # 包导入：仓库根在 sys.path 上（tests / core.rules）
    from core.contracts import Sufficiency

try:                                    # 扁平导入：core/ 在 sys.path 上（report.py / diagnose.py）
    from copytext import get as _copy_get
except ModuleNotFoundError:             # 包导入：仓库根在 sys.path 上（tests / core.rules）
    from core.copytext import get as _copy_get

#: 仓库根：copy 文案表按「仓库根在 sys.path 上」的包导入方式读取（与 analyzer 同款）。
_ROOT = Path(__file__).resolve().parents[1]

#: 严重度排序。``"na"`` 排最后不是「最轻」，而是「最没有信息量」：
#: 一层里只要有任何真实样本（哪怕是「测了正常」的 ``"—"``），就以样本为准；
#: 全都是 ``"na"`` 时才会落到 ``"na"``，表示「这一层这次没数据可判」。
SEV_ORDER = {"严重": 0, "警告": 1, "提示": 2, "—": 3, "na": 4}

#: 算作「问题」的严重度。``"—"``（正常）与 ``"na"``（没样本）都不是问题：
#: 前者判过了没问题，后者根本没有数据可判。两者都不得进 bad / sec_bad，
#: 也不得影响 ``flags.network_ok`` 与 ``summary`` 的计数。
PROBLEM_SEVERITIES = ("严重", "警告")

#: 算作「该层有真实样本」的严重度：``"—"`` 表示测了正常（见 analyzer.NEUTRAL_SEVERITY），
#: 其余三种表示真判出了东西。只有 ``"na"``（没样本，见 analyzer.NO_SAMPLE_SEVERITY）
#: 不算样本 —— 证据不足时正是这些层必须显示成 ``na``，而不是 ``ok``。
SAMPLE_SEVERITIES = ("严重", "警告", "提示", "—")

# ---------- 证据充分性：判「有没有可判定的维度」，不判「报文总数」 ----------
#
# 为什么没有「报文总数 < N」或「抓包时长 < N 秒」这类总闸：
# captures 里的 arp_no_reply 只有 5 个包，却抓到了「同一目标 3 次请求无应答」的真故障；
# icmp_unreachable 也只有 5 个包，判出了严重。用总包数卡，会把已经成立的结论埋掉。
#
# 所以阈值全部落在**单个维度**上：每个维度各自回答「这类样本够不够对应规则跑出结论」。
# 例如 TCP 维度要求 ≥ 5 个 TCP 报文（或至少 1 条完整会话）—— 少于这个数连重传率、
# 握手都拼不出来；ARP 维度要求**同一目标** ≥ 2 次请求，因为 ARP 规则本身就要
# 「同一目标 ≥ 2 次请求且无应答」才判得出「无应答」。这些是单维度的最小条件，
# 不是全局的报文数阈值。
MIN_TCP_PACKETS = 5      # TCP 的结论依赖重传率/握手，太少连会话都拼不完整
MIN_TCP_STREAMS = 1      # 有完整会话也算有 TCP 样本（兜住「报文少但会话成立」）
MIN_DNS_QUERIES = 1
MIN_HTTP_REQUESTS = 1
MIN_ICMP_ERRORS = 1      # ICMP 只判错误报文（不可达/超时），echo 本身不是结论
MIN_ARP_REQUESTS = 2     # ARP 规则本身要「同一目标 ≥ 2 次请求」才判得出无应答

#: 证据不足时给的两条可执行建议（在线抓包场景）；是 copy 表缺失时的回退常量。
INSUFFICIENT_STEPS = (
    "把抓包时长加长（建议 30 秒以上），并换成实际在用的网卡再抓一次。",
    "确认目标流量真的经过本机：换个位置抓（如交换机镜像口），或先在体检页直接测一次目标端口。",
)

#: 离线（上传 pcap 分析）场景的第一条建议：没有网卡可换，重抓要借助外部工具。
INSUFFICIENT_STEPS_OFFLINE = (
    "把抓包时长加长（建议 30 秒以上），用 Wireshark 等工具重新抓一次再上传分析。",
    INSUFFICIENT_STEPS[1],
)

#: 证据不足时的 ``needed`` key（查 ``copy/zh-CN.json`` 的 ``next_step``）。
#: 这是**在线**场景的 pair；离线时第一条换成 ``collect_longer_offline``。
INSUFFICIENT_NEEDED = ("collect_longer", "confirm_traffic_path")

#: 证据不足时的 ``reasons`` key（查 ``copy/zh-CN.json`` 的 ``insufficient``）。
INSUFFICIENT_REASON = "no_decidable_dimension"

#: 落盘报告里 tshark 路径的占位：绝对路径是机器相关键，换机器重跑会产生脏 diff。
TSHARK_PATH_PLACEHOLDER = "<TSHARK_PATH>"

#: 分析抓包文件（``run_scan --pcap``）时写进 ``meta.bpf`` 的模式标记。
#: 它同时会显示在报告的「网卡 / 过滤器」一行，所以必须是用户可见的新模式名。
OFFLINE_BPF = "分析抓包文件"

#: 旧版写进报告的模式标记；只用于兼容历史报告 / 旧调用方，不再新写。
_OFFLINE_BPF_LEGACY = "离线分析"

# 排查顺序：自下而上。同严重度时，越底层越优先（先查链路再查应用）
LAYER_RANK = {"L2 本地链路": 0, "L3 网络层": 1, "L4 传输层": 2, "L7 应用层": 3, "安全观察": 9}
CAT_RANK = {
    "本地可达性": 0, "网络可达性": 1, "网络时延": 2, "连接建立": 3, "传输质量": 4,
    "域名解析": 5, "应用响应": 6, "可疑外联": 7, "端口扫描": 7, "明文凭证": 8,
}

#: 层 id → copy 表 ``verdict.layer_name`` / ``layer_protocol`` 的键。
_LAYER_COPY_KEYS = (("L2", "l2"), ("L3", "l3"), ("L4", "l4"), ("L7", "l7"))

#: 故障类别（中文，同时是 ``rows[].category`` 的结构化取值）→ copy 表 key 后缀。
#: 类别中文值本身是数据契约（verdict 的排序表、legacy_map 的匹配模式都用它），
#: 不迁进 copy 表；这里只维护「类别 → 文案 key」的映射。
_CAT_KEYS = {
    "连接建立": "connect", "传输质量": "transport", "网络时延": "latency",
    "网络可达性": "unreach", "域名解析": "dns", "TLS 会话": "tls", "应用响应": "app",
    "本地可达性": "arp", "可疑外联": "exfil", "端口扫描": "scan", "明文凭证": "plaintext",
}


def _t(section: str, key: str, **args) -> str:
    """从 copy 表取文案（走本模块校验过的 :func:`_load_copy`）。

    Args:
        section: copy 表 section 名（支持 ``verdict.titles`` 这类点号路径）。
        key: section 内的键。
        **args: ``{name}`` 占位符实参。

    Returns:
        str: 可直接展示的文案。缺 key / 缺实参时回退成 key 或原文，不抛异常。
    """
    raw = _copy_get(_load_copy(), section, key)
    if raw is None:
        return key
    if not args:
        return raw
    try:
        return raw.format(**args)
    except (KeyError, IndexError, ValueError):
        return raw


def _title(cat: str, rst: bool = False) -> str:
    """类别的标题文案（``copy.verdict.titles``）。

    Args:
        cat: ``rows[].category`` 的中文值。
        rst: 是否「被对端 RST 拒绝」变体（仅「连接建立」有单独标题）。

    Returns:
        str: 标题；未知类别回退成类别名本身。
    """
    if cat == "连接建立" and rst:
        return _t("verdict.titles", "connect_rst")
    key = _CAT_KEYS.get(cat)
    return _t("verdict.titles", key) if key else cat


def _explain(cat: str, rst: bool = False) -> str:
    """类别的现象解释（``copy.verdict.explain`` / ``copy.verdict.rst_explain``）。

    Args:
        cat: ``rows[].category`` 的中文值。
        rst: 是否「被对端 RST 拒绝」变体。

    Returns:
        str: 白话解释；未知类别返回空串。
    """
    if cat == "连接建立" and rst:
        return _t("verdict", "rst_explain")
    key = _CAT_KEYS.get(cat)
    return _t("verdict.explain", key) if key else ""


def _layer_defs() -> list[dict]:
    """四层的展示定义（层名与协议文案来自 copy 表）。

    Returns:
        list[dict]: 每项 ``{"id", "name", "protocol"}``，供 :func:`compute_layers` 使用。
    """
    return [{"id": lid,
             "name": _t("verdict.layer_name", key),
             "protocol": _t("layer_protocol", key)}
            for lid, key in _LAYER_COPY_KEYS]


def _worst(rows: list[dict]) -> str:
    """一层里最「重」的严重度；空列表返回 ``"—"``。

    Args:
        rows: 该层的行（已排除安全观察行）。

    Returns:
        str: ``"严重"/"警告"/"提示"/"—"/"na"``。``"na"`` 只在**整层都没有真实样本**时
            返回（排序见 :data:`SEV_ORDER`）：只要有一条测过的行，就以那条为准。
    """
    if not rows:
        return "—"
    return min((r.get("severity", "—") for r in rows), key=lambda s: SEV_ORDER.get(s, 9))


def _sort_key(r: dict) -> tuple:
    return (SEV_ORDER.get(r.get("severity"), 9),
            LAYER_RANK.get(r.get("layer"), 8),
            CAT_RANK.get(r.get("category"), 9))


def compute_layers(rows: list[dict], meta: dict, metrics: dict,
                   sufficient: bool = True) -> list[dict]:
    """为每一层算一个状态块（UI 用横条展示「哪一层红了」）。

    Args:
        rows: 旧 ``rows[]``；安全观察行**不参与**主判定。
        meta: 采集元信息；``L4`` 在没有 TCP 报文时标为 ``na``（没样本，别报正常）。
        metrics: 指标表，供状态块填明细。
        sufficient: 证据是否充分（即 ``verdict.sufficiency.ok``）。为 ``False`` 时，
            **没有真实样本行的层**一律置为 ``na``：否则会出现「结论是证据不足、
            分层表却显示 ✅ 正常」的自相矛盾。有样本行（含 ``"—"``=测了正常）的层
            仍按样本判定，保持 ``ok``。例外是 L3 的兜底中性行：它没有 ICMP/RTT
            样本时也会写「三层转发正常」，这种行不算样本。

    Returns:
        list[dict]: 每项 ``{"id", "name", "protocol", "status"（ok/warn/bad/na）,
            "severity", "detail", "count"}``。
    """
    out: list[dict] = []
    for d in _layer_defs():
        mine = [r for r in rows if r.get("layer", "").startswith(d["id"])]
        net = [r for r in mine if r.get("category") != "安全观察"]
        status = _worst(net)
        # "na" 是第三态：不是「正常」，是「这次没样本，判不了」。
        # 早先只有 ok/warn/bad 三态，没样本的行 severity 写成 "—"，
        # 于是「未检测到 DNS 报文」在 UI 上是一块绿色 —— 用户会以为验过了。
        state = {"严重": "bad", "警告": "warn", "提示": "warn",
                 "—": "ok", "na": "na"}.get(status, "ok")
        if d["id"] == "L4" and not meta.get("tcp_packets"):
            state = "na"
        else:
            # 该层有没有真实样本行：``"—"``（测了正常）与三种发现都算，只有 ``"na"`` 不算。
            has_sample = any(r.get("severity") in SAMPLE_SEVERITIES for r in net)
            # L3 的「未收到 ICMP 不可达/超时，三层转发正常」是 analyzer **无条件**产出的
            # 兜底行：一个 ICMP / RTT 样本都没有时它照样写「正常」。这种行不能算样本，
            # 否则空抓包（empty_capture：ARP×1 + ICMP echo×1 + UDP×1）的 L3 仍会 ✅。
            if d["id"] == "L3":
                has_sample = has_sample and bool(
                    _int(meta.get("icmp_unreach")) + _int(meta.get("icmp_timeout"))
                    or _int(metrics.get("rtt_samples")))
            # 证据不足时「—」不再自动等于 ok：没样本的层必须显示第三态。
            # 判定层已经说「无法判断」，分层表就不能再给绿色勾 —— 这是 T06
            # 要根除的「没抓到=没问题」。
            if not sufficient and not has_sample:
                state = "na"
        out.append({
            "id": d["id"], "name": d["name"], "protocol": d["protocol"],
            "status": state, "severity": status,
            "detail": _layer_note(d["id"], meta, metrics, state),
        })
    return out


def _layer_note(lid: str, meta: dict, m: dict, status: str = "ok") -> str:
    """层状态块的关键指标短语（文案来自 copy 表 ``layer_note``）。

    Args:
        lid: 层 id（``L2``/``L3``/``L4``/``L7``）。
        meta: 采集元信息。
        m: 指标表。
        status: 该层状态（``ok``/``warn``/``bad``/``na``）。

    Returns:
        str: 可直接展示的指标短语。

    Note:
        B1：层状态是 ``na``（这次没样本）时，旧实现让 L2 输出
        「同网段地址解析正常」——没测过却报正常。现在 na 一律走
        ``layer_note.<层>.na`` 的「无样本」文案，不再出现「…正常」的肯定句。
        L3/L4/L7 的 na 文案与它们的「无样本」短语同值（``本次无 TCP 流量`` 这类
        本来就是否定式陈述），所以只有 L2 的那句可见文字会变。
    """
    if status == "na":
        return _t("layer_note", f"{lid.lower()}.na")
    if lid == "L2":
        n = meta.get("arp_no_reply") or 0
        return _t("layer_note", "l2.arp", count=n) if n else _t("layer_note", "l2.ok")
    if lid == "L3":
        if not m.get("rtt_samples"):
            return _t("layer_note", "l3.no_sample")
        parts = [_t("layer_note", "l3.rtt_avg", avg=m.get("rtt_avg_ms", 0))]
        if m.get("rtt_jitter_ms"):
            parts.append(_t("layer_note", "l3.jitter", jitter=m["rtt_jitter_ms"]))
        if m.get("icmp_unreach") or m.get("icmp_timeout"):
            parts.append(_t("layer_note", "l3.icmp_err",
                            count=m.get("icmp_unreach", 0) + m.get("icmp_timeout", 0)))
        return "，".join(parts)
    if lid == "L4":
        if not meta.get("tcp_packets"):
            return _t("layer_note", "l4.no_tcp")
        parts = [_t("layer_note", "l4.retrans", rate=m.get("retrans_rate", 0))]
        if m.get("conn_fail"):
            parts.append(_t("layer_note", "l4.conn_fail", count=m["conn_fail"]))
        if m.get("conn_refused", 0) >= 2:
            parts.append(_t("layer_note", "l4.refused", count=m["conn_refused"]))
        if m.get("hs_samples"):
            parts.append(_t("layer_note", "l4.handshake", avg=m["hs_avg_ms"]))
        return "，".join(parts)
    parts = []
    if m.get("dns_samples"):
        parts.append(_t("layer_note", "l7.dns", avg=m.get("dns_avg_ms", 0)))
    if m.get("http_samples"):
        parts.append(_t("layer_note", "l7.http", avg=m.get("http_avg_ms", 0)))
    return "，".join(parts) or _t("layer_note", "l7.none")


def _headline(main: dict, meta: dict, m: dict) -> str:
    """一句话结论文案（全部来自 copy 表 ``verdict.headline``）。

    Args:
        main: 主判定行（``bad[0]``）。
        meta: 采集元信息（``zero_win`` 等计数在这里）。
        m: 指标表。

    Returns:
        str: 一句话结论；未知类别回退成 finding 前 48 字或「未发现明显故障」。
    """
    cat = main.get("category")
    f = main.get("finding", "")
    if cat == "连接建立":
        if m.get("conn_fail"):
            return _t("verdict.headline", "connect.no_response", count=m["conn_fail"])
        if m.get("conn_refused"):
            return _t("verdict.headline", "connect.refused", count=m["conn_refused"])
        return _t("verdict.headline", "connect.slow", avg=m.get("hs_avg_ms", 0))
    if cat == "传输质量":
        # 零窗口看的是「接收方缓冲区被塞满」，不是链路丢包 —— 这两个结论的
        # 排查方向完全相反（查接收端应用 vs 查网络）。
        # 计数在 meta["zero_win"]，metrics 里没有这个键：早先读 m 的那版
        # 永远取到默认值 0，分支从不成立，零窗口场景会被误报成「链路上在丢包」。
        if meta.get("zero_win", 0) >= 3 and m.get("retrans_rate", 0) < 2:
            return _t("verdict.headline", "transport.zero_win")
        return _t("verdict.headline", "transport.loss", rate=m.get("retrans_rate", 0))
    if cat == "网络时延":
        return _t("verdict.headline", "latency", avg=m.get("rtt_avg_ms", 0),
                  jitter=m.get("rtt_jitter_ms", 0))
    if cat == "网络可达性":
        return _t("verdict.headline", "unreach")
    if cat == "域名解析":
        if (m.get("dns_fail_rate") or 0) >= 20:
            return _t("verdict.headline", "dns.fail", rate=m["dns_fail_rate"])
        if m.get("dns_timeouts", 0) >= 3:
            return _t("verdict.headline", "dns.timeout", count=m["dns_timeouts"])
        return _t("verdict.headline", "dns.slow", avg=m.get("dns_avg_ms", 0))
    if cat == "应用响应":
        if m.get("http_err5"):
            return _t("verdict.headline", "app.5xx", count=m["http_err5"])
        return _t("verdict.headline", "app.slow", avg=m.get("http_avg_ms", 0))
    if cat == "本地可达性":
        return _t("verdict.headline", "arp.no_reply")
    if cat in ("可疑外联", "端口扫描", "明文凭证"):
        return _t("verdict.headline", "security")
    return f[:48] if f else _t("verdict.headline", "fallback")


def _int(v) -> int:
    """把 meta 里的计数值安全转成 ``int``（缺键 / ``None`` / 脏值一律当 0）。"""
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


#: 本模块消费、且值必须是「字符串键 → 字符串值」映射的 copy section。
_STRING_SECTIONS = ("next_step", "insufficient", "impact", "layer_note", "layer_protocol")


def _is_str_map(value) -> bool:
    """判断一个 section 是否是「字符串键 → 字符串值」的映射。

    Args:
        value: 待校验的 section 值。

    Returns:
        bool: 是合法字符串映射时为 True。
    """
    return isinstance(value, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items())


def _load_copy() -> dict:
    """读 ``core/copy/zh-CN.json`` 文案表。

    Returns:
        dict: 文案表。以下任一情况都返回空表、**不抛异常**，由调用方回退成 key：
            文件缺失 / 包导入失败 / **结构不合法**（顶层不是对象，或本模块消费的
            section 形状不对）。

    Note:
        copy 表是本 PR 的唯一文案来源（以前 copy 无人在报告链路消费，畸形表不会
        有人崩；现在 ``{"next_step": []}`` 会让 ``verdict.build`` 抛
        ``AttributeError``，``{"insufficient": {"no_decidable_dimension": {...}}}``
        会抛 ``'dict' object has no attribute 'format'``）。所以「读不到」与
        「读到了但形状不对」走同一条回退路径，绝不让报告渲染崩在文案表上。

        ⚠️ 本模块消费的 section 必须列进白名单（``_STRING_SECTIONS`` 以及
        ``verdict`` 的每个子表）。漏列时畸形表会被当成可用表，逐 key 取到非字符串，
        症状是「文案悄悄回退成 key、你以为改了」。
    """
    try:
        if str(_ROOT) not in sys.path:
            sys.path.insert(0, str(_ROOT))
        from core.config import load_copy
        table = load_copy() or {}
    except Exception:                              # noqa: BLE001
        return {}
    if not isinstance(table, dict):
        return {}
    for name in _STRING_SECTIONS:
        if not _is_str_map(table.get(name, {})):
            return {}
    nested = table.get("verdict", {})
    if not isinstance(nested, dict):
        return {}
    for _key, sub in nested.items():
        if isinstance(sub, str):
            continue
        if not _is_str_map(sub):
            return {}
    return table


def _is_offline(meta: dict) -> bool:
    """分析抓包文件标记：``run_scan`` 走 ``--pcap`` 路径时把 bpf 写成 :data:`OFFLINE_BPF`。

    旧报告 / 旧调用方写的是「离线分析」；两个都认，避免历史数据被当成在线抓包，
    给出「换一块网卡再抓」这种做不到的建议。
    """
    return meta.get("bpf") in (OFFLINE_BPF, _OFFLINE_BPF_LEGACY)


def _insufficient_steps(meta: dict) -> list[str]:
    """证据不足时的两条处置建议；copy 表优先，缺失回退内联常量。

    Args:
        meta: 采集元信息；``bpf`` 是分析抓包文件标记（:data:`OFFLINE_BPF`，兼容旧值
            「离线分析」）时第一条建议换成离线版本。

    Returns:
        list[str]: 两条建议文案（可直接展示的成句中文）。
    """
    ns = _load_copy().get("next_step", {})
    offline = _is_offline(meta)
    first_key = "collect_longer_offline" if offline else "collect_longer"
    first = ns.get(first_key) or (INSUFFICIENT_STEPS_OFFLINE[0] if offline else INSUFFICIENT_STEPS[0])
    second = ns.get("confirm_traffic_path") or INSUFFICIENT_STEPS[1]
    return [first, second]


def _insufficient_reason_args(meta: dict, packets: int) -> dict:
    """``no_decidable_dimension`` 模板的占位符实参（key 与 copy 表一一对应）。"""
    return {
        "packets": _int(packets),
        "tcp_packets": _int(meta.get("tcp_packets")),
        "dns_total": _int(meta.get("dns_total")),
        "http_req": _int(meta.get("http_req")),
        "icmp_err": _int(meta.get("icmp_unreach")) + _int(meta.get("icmp_timeout")),
        "arp_req": _int(meta.get("arp_req")),
        "arp_req_max": _int(meta.get("arp_req_max")),
    }


def _insufficient_proof(meta: dict, packets: int) -> str:
    """证据不足点的 proof 文案：copy 模板优先，缺失/缺占位符时回退内联。

    两份文案共用同一组占位符，改一边必须同步另一边；copy 表可用时以它为准
    （tests 用自定义表断言输出跟着 copy 表变，不是断言两份「逐字相等」）。
    """
    args = _insufficient_reason_args(meta, packets)
    tpl = _load_copy().get("insufficient", {}).get(INSUFFICIENT_REASON)
    if tpl:
        try:
            return tpl.format(**args)
        except (KeyError, IndexError, ValueError):
            pass
    return ("没有一个可判定的维度：报文 {packets} 个 —— TCP {tcp_packets} 个、"
            "DNS {dns_total} 次、HTTP {http_req} 个、ICMP 错误 {icmp_err} 条、"
            "ARP {arp_req} 次（同一目标最多 {arp_req_max} 次）").format(**args)


def _sufficiency(meta: dict, net_rows: list[dict]) -> Sufficiency:
    """判断这次抓包「有没有可判定的维度」。

    判定顺序（先有证据，再看维度）：

    1. 存在任何故障行（严重/警告）→ ``ok=True``。已经判出故障就说明证据链成立，
       此时再去数报文多少是多余的，甚至有害（5 个包的 ARP 样本就是真故障）。
    2. 否则任一维度有样本 → ``ok=True``。
    3. 全都没有 → ``ok=False``，``reasons`` / ``needed`` 给出 key 与可执行建议。

    Args:
        meta: 采集元信息。只读**真实存在**的键：``tcp_packets`` / ``streams_total`` /
            ``dns_total`` / ``http_req`` / ``icmp_unreach`` / ``icmp_timeout`` /
            ``arp_req`` / ``arp_req_max``。
        net_rows: 已排除安全观察行的 ``rows[]``。

    Returns:
        Sufficiency: ``ok=False`` 时 ``reasons`` 含 :data:`INSUFFICIENT_REASON`，
            ``reason_args`` 带上本次的报文数与各维度计数，便于报告直出原因。

    Note:
        这是**采集有效性**闸门：判的是「每个维度有没有能支撑对应规则的样本」。
        阈值是**单维度的最小条件**，不是全局的报文总数阈值 —— 参见模块头的
        「证据充分性」注释段。

        维度口径贴的是「对应规则能不能判」，不是「有没有这类包」：
        ICMP 只算错误报文（echo request 不构成结论）；ARP 要求**同一目标** ≥ 2 次
        请求（``arp_req_max``），两个不同目标各 1 次时规则一条也判不出来，
        所以总请求数（``arp_req``）达标也不算维度成立。
    """
    if any(r.get("severity") in PROBLEM_SEVERITIES for r in net_rows):
        return Sufficiency(ok=True)

    dims = {
        "tcp": (_int(meta.get("tcp_packets")) >= MIN_TCP_PACKETS
                or _int(meta.get("streams_total")) >= MIN_TCP_STREAMS),
        "dns": _int(meta.get("dns_total")) >= MIN_DNS_QUERIES,
        "http": _int(meta.get("http_req")) >= MIN_HTTP_REQUESTS,
        "icmp": (_int(meta.get("icmp_unreach")) + _int(meta.get("icmp_timeout"))
                 >= MIN_ICMP_ERRORS),
        "arp": _int(meta.get("arp_req_max")) >= MIN_ARP_REQUESTS,
    }
    if any(dims.values()):
        return Sufficiency(ok=True)

    needed = (("collect_longer_offline", INSUFFICIENT_NEEDED[1])
              if _is_offline(meta) else INSUFFICIENT_NEEDED)
    return Sufficiency(
        ok=False,
        reasons=(INSUFFICIENT_REASON,),
        needed=needed,
        reason_args={INSUFFICIENT_REASON: _insufficient_reason_args(
            meta, _int(meta.get("packets")))},
    )


def build(result: dict) -> dict:
    """生成最终判定：一句话结论 + 分层状态 + 处置建议。

    Args:
        result: 诊断结果字典（``meta`` / ``rows`` / ``metrics`` / ``summary``）。

    Returns:
        dict: 键 ``level``（严重/警告/提示/正常/证据不足）/ ``headline``（一句话结论）/
            ``plain``（白话解释）/ ``impact``（对业务意味着什么）/ ``layer``（问题所在层）/
            ``layers``（四层状态）/ ``points``（问题明细）/
            ``next_steps``（按优先级排序的处置建议）/ ``metrics`` / ``flags`` /
            ``sufficiency``（:meth:`contracts.Sufficiency.to_dict` 的结果）。

    Note:
        两道闸门拦「没抓到 = 没问题」：

        1. 抓空包（``packets == 0``）先返回「无法定位」而不是「各层正常」。
        2. 抓到了包但**没有任何可判定维度**时，``level`` 是「证据不足」而不是「正常」。
           见 :func:`_sufficiency`：判的是「每个维度有没有能支撑规则的样本」，
           不是全局的报文总数。

        本函数只做路由与拼装：用户可见文案全部来自 ``core/copy/zh-CN.json``，
        字典里的 ``level`` / ``layer`` / ``category`` 等是机器侧的结构化标识。
    """
    result = result or {}
    meta = result.get("meta") or {}
    rows = result.get("rows") or []
    m = result.get("metrics") or {}
    packets = int(meta.get("packets") or 0)

    # ---------- 抓空包：先别下结论 ----------
    if packets == 0:
        return {
            "level": "警告",
            "headline": _t("verdict.headline", "empty"),
            "plain": _t("verdict.plain", "empty"),
            "impact": _t("impact", "empty"),
            "layer": "—",
            # 空包是「证据不足」的极端情形：四层都没有样本，不许显示成 ✅ 正常。
            "layers": compute_layers([], meta, m, sufficient=False),
            "points": [{
                "severity": "警告", "layer": "—", "protocol": "—", "category": "采集有效性",
                "title": _t("verdict.plain", "collect_empty_title"),
                "plain": _t("verdict.plain", "collect_empty_plain"),
                "proof": _t("verdict.plain", "collect_empty_proof",
                            iface=meta.get("interface", "-"), bpf=meta.get("bpf", "-")),
                "action": _t("verdict.plain", "collect_empty_action"),
            }],
            "next_steps": [_t("next_step", "collect_again")],
            "metrics": m,
            "flags": {"network_ok": None, "security_ok": None},
            # 空包是「证据不足」的极端情形：连一个维度都没有样本。
            "sufficiency": Sufficiency(
                ok=False, reasons=("packets_zero",), needed=("collect_again",),
            ).to_dict(),
        }

    net_rows = [r for r in rows if r.get("layer") != "安全观察"]
    sec_bad = [r for r in rows if r.get("layer") == "安全观察"
               and r.get("severity") in PROBLEM_SEVERITIES]
    # "na"（没样本）既不进 bad 也不进 sec_bad：没有数据不能算问题，
    # 算进去会让「什么都没抓到」变成一条故障，把 level 拉成警告。
    bad = sorted([r for r in net_rows if r.get("severity") in PROBLEM_SEVERITIES], key=_sort_key)
    hints = [r for r in net_rows if r.get("severity") == "提示"]

    # 证据充分性：没有任何可判定维度时，后面的「正常」就是没有依据的正常。
    suff = _sufficiency(meta, net_rows)

    points: list[dict] = []
    for r in (bad + hints)[:6]:
        cat = r.get("category", "")
        finding = r.get("finding") or ""
        # 与旧实现逐字等价：类别 + finding 里含协议缩写 RST + 不含中文「无响应」。
        # 「无响应」守卫不是装饰：copy 文案若同时含 RST 与「无响应」（例如写成
        # 「未收到 SYN-ACK/RST」），没有它会误判成「被拒」并把结论讲反。
        # 彻底机制化需要给 rows[] 加机器标记（会改报告 JSON 形状）→ 登记 BACKLOG。
        is_rst = (cat == "连接建立" and "RST" in finding
                  and "无响应" not in finding)
        plain_txt = _explain(cat, is_rst) + _t("verdict.plain", "explain_join") + finding
        points.append({
            "severity": r.get("severity"),
            "layer": r.get("layer", "—"),
            "protocol": r.get("protocol", "—"),
            "category": cat,
            "title": _title(cat, is_rst),
            "plain": plain_txt,
            "proof": finding + _t("verdict.plain", "proof_join") + str(r.get("evidence", "-")),
            "action": r.get("advice", ""),
        })

    # 安全项单独放最后，明确标注「非本次主线」
    for r in sec_bad[:2]:
        cat = r.get("category", "")
        finding = r.get("finding") or ""
        points.append({
            "severity": r.get("severity"), "layer": "安全观察", "protocol": r.get("protocol", "—"),
            "category": cat, "title": _title(cat),
            "plain": _explain(cat) + _t("verdict.plain", "explain_join") + finding,
            "proof": finding + _t("verdict.plain", "proof_join") + str(r.get("evidence", "-")),
            "action": r.get("advice", ""),
        })

    # ---------- 主判定 ----------
    if not suff.ok:
        # 抓到了包，但没有一个维度有样本可判。这时候说「正常」等于凭空断言：
        # 「什么都没测到」和「测了没问题」是两件事，结论必须是「无法判断」。
        level = "证据不足"
        headline = _t("verdict.headline", "insufficient")
        plain = _t("verdict.plain", "insufficient")
        impact = _t("impact", "insufficient")
        layer = "—"
        ins_steps = _insufficient_steps(meta)
        # 追加而不是覆盖：前面已构好的安全观察/提示明细是**已经成立的结论**，
        # 覆盖会让「有安全隐患」这条信息在报告里消失（机器侧 security_ok 却还是 False）。
        points = [{
            "severity": "提示",
            "layer": "—",
            "protocol": "—",
            "category": "采集有效性",
            "title": _t("verdict.plain", "collect_insufficient_title"),
            "plain": _t("verdict.plain", "collect_insufficient_plain"),
            "proof": _insufficient_proof(meta, packets),
            "action": ins_steps[0],
        }] + points
    elif bad:
        main = bad[0]
        level = "严重" if main.get("severity") == "严重" else "警告"
        headline = _headline(main, meta, m)
        plain = (_explain(main.get("category")) +
                 _t("verdict.plain", "locate_prefix") + (main.get("finding") or ""))
        impact = _impact(main, m)
        layer = f"{main.get('layer')}｜{main.get('protocol')}"
    elif sec_bad:
        level = "警告"
        headline = _t("verdict.headline", "sec_only")
        plain = _t("verdict.plain", "sec_only")
        impact = _t("impact", "sec_only")
        layer = "安全观察"
    else:
        level = "正常"
        headline = _t("verdict.headline", "normal")
        facts = []
        if m.get("rtt_samples"):
            facts.append(_t("verdict.fact", "rtt", avg=m["rtt_avg_ms"]))
        facts.append(_t("verdict.fact", "retrans", rate=m.get("retrans_rate", 0)))
        if m.get("dns_samples"):
            facts.append(_t("verdict.fact", "dns", avg=m["dns_avg_ms"]))
        if m.get("http_samples"):
            facts.append(_t("verdict.fact", "http", avg=m["http_avg_ms"]))
        if m.get("hs_samples"):
            facts.append(_t("verdict.fact", "handshake", avg=m["hs_avg_ms"]))
        plain = (_t("verdict.plain", "normal_prefix") + "、".join(facts)
                 + _t("verdict.plain", "normal_suffix"))
        impact = _t("impact", "ok")
        layer = "—"

    # ---------- 处置顺序：按排查优先级，底层先动 ----------
    steps: list[str] = []
    if not suff.ok:
        # 证据不足时，处置建议是「怎么重新采到能判的样本」，不是「怎么修网络」。
        steps = _insufficient_steps(meta)
    else:
        for r in bad:
            adv = (r.get("advice") or "").strip()
            if adv and adv not in steps:
                steps.append(adv)
        if not steps:
            steps = [_t("next_step", "baseline")]

    return {
        "level": level,
        "headline": headline,
        "plain": plain,
        "impact": impact,
        "layer": layer,
        # 证据不足时没有样本的层要显示成 na（见 compute_layers 的 sufficient 参数）。
        "layers": compute_layers(rows, meta, m, sufficient=suff.ok),
        "points": points,
        "next_steps": steps[:6],
        "metrics": m,
        "flags": {
            # 「证据不足」= 网络是否正常无从判断，与空包分支的 None 对齐；
            # 不能因为 bad 为空就写 True（那等于拿「没测到」当「正常」）。
            "network_ok": None if not suff.ok else not bool(bad),
            "security_ok": not bool(sec_bad),
        },
        "sufficiency": suff.to_dict(),
    }


def _impact(main: dict, m: dict) -> str:
    """「对业务意味着什么」的文案（来自 copy 表 ``impact``）。

    Args:
        main: 主判定行。
        m: 指标表。

    Returns:
        str: 影响描述；未知类别回退成 ``impact.default``。
    """
    cat = main.get("category")
    if cat == "连接建立":
        if not m.get("conn_fail"):
            return _t("impact", "connect_refused")
        return _t("impact", "connect")
    if cat == "传输质量":
        return _t("impact", "transport", rate=m.get("retrans_rate", 0))
    if cat == "网络时延":
        return _t("impact", "net_latency")
    if cat == "网络可达性":
        return _t("impact", "net_unreach")
    if cat == "域名解析":
        return _t("impact", "dns")
    if cat == "应用响应":
        return _t("impact", "app")
    if cat == "本地可达性":
        return _t("impact", "l2_arp")
    return _t("impact", "default")
