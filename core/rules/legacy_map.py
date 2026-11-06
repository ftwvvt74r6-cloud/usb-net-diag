"""旧 ``rows[]`` → 新 ``Finding`` 的迁移桥（**临时件，T05 完成后可删**）。

为什么需要它（对应评审 T03）：

* 现有 ``analyzer.build_findings()`` 产出的 ``rows[]`` 是「中文字段 + 自由文本证据」
  的隐式结构，被 UI / Markdown / AI / MCP 四处消费，**一次改完风险极高**。
* 所以第一刀不改 ``rows``，而是**再加一份** ``findings[]``：
  映射表在本文里，旧的照旧输出，新的逐步接管。
* 映射表同时是一份**迁移清单**：``missing_from_registry()`` 会告诉你
  哪些 ``rule_id`` 还只在旧代码里有、``core/rules/`` 里还没实现。

三条纪律：

1. **不丢信息**：旧 ``advice`` 文本暂时塞进 ``metric["advice_raw"]``，
   只为了让迁移期的报告不至于没有处置建议；T05 之后必须改成 ``copy`` 表的 key。
2. **不猜方向**：旧数据没有方向，一律 ``direction=None``；
   零窗口这种「方向决定结论」的规则给 ``confidence=0.5 / INFERRED``。
3. **不匹配就报**：``find_unmatched()`` 必须能在 CI 里断言「映射无漏项」，
   否则规则一改、映射静默漏掉，迁移就永远做不完。

用法::

    from core.rules.legacy_map import map_rows, find_unmatched
    findings = map_rows(result["rows"])       # 加到 result["findings_v2"]
    assert not find_unmatched(result["rows"]), "有 row 没被映射，补 legacy_map"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from ..contracts import (
    Category,
    EvidenceKind,
    Finding,
    Layer,
    Severity,
)

#: 旧 severity 中文 → 枚举。
#:
#: ``"—"`` 是「测了，正常」，``"na"`` 是「没样本，测不了」—— 两者都不产出 Finding，
#: 但**不能混成同一个值**：混了以后就没法回答「这次到底验没验过」，
#: 而「没样本报成正常」正是评审 P0-4 要修的那类误报。
SEVERITY_MAP: dict[str, Severity] = {
    "严重": Severity.CRITICAL,
    "警告": Severity.WARNING,
    "提示": Severity.INFO,
    "—": Severity.OK,
    "-": Severity.OK,
    "": Severity.OK,
    "na": Severity.NA,
}

#: 出现这些词的行表示「这一层正常/没样本」，不产出 Finding。
NORMAL_HINTS: tuple[str, ...] = (
    "正常", "未检测到", "未收到", "未发现", "无需处理", "三层转发正常",
)


@dataclass(frozen=True)
class LegacyPattern:
    """一条映射规则。匹配条件 = 层 + 类别 + 关键词（空 = 该层该类别的异常行）。"""

    layer_cn: str
    category_cn: str
    keyword: str
    rule_id: str
    category: Category
    confidence: float = 1.0
    evidence_kind: EvidenceKind = EvidenceKind.MEASURED
    advice_key: str = ""
    note: str = ""


#: 顺序敏感：**先匹配先返回**，所以更具体的 keyword 要放前面。
PATTERNS: tuple[LegacyPattern, ...] = (
    # ---------------- L2 ----------------
    LegacyPattern("L2 本地链路", "本地可达性", "", "L2.ARP.NO_REPLY",
                  Category.L2_ARP, advice_key="L2.ARP.ADVICE",
                  note="请求次数阈值在 thresholds.l2.arp.min_requests"),

    # ---------------- L3 ----------------
    LegacyPattern("L3 网络层", "网络可达性", "ICMP", "L3.ICMP.UNREACH",
                  Category.NET_UNREACH, advice_key="L3.ICMP.ADVICE",
                  note="含「需要分片」时由规则升级为 critical，映射层不判严重度"),
    LegacyPattern("L3 网络层", "网络时延", "", "L3.RTT.HIGH",
                  Category.NET_LATENCY, advice_key="L3.RTT.ADVICE",
                  note="注意：旧实现的 RTT 来自 tcp.analysis.ack_rtt，含延迟 ACK/应用等待"),

    # ---------------- L4 ----------------
    LegacyPattern("L4 传输层", "连接建立", "没有收到回应", "L4.CONNECT.NO_RESPONSE",
                  Category.CONNECT, advice_key="L4.CONNECT.ADVICE",
                  note="SYN 无应答，旧实现计为「建连失败」"),
    LegacyPattern("L4 传输层", "连接建立", "RST 重置", "L4.CONNECT.RST",
                  Category.CONNECT, confidence=0.8, advice_key="L4.CONNECT.ADVICE",
                  note="旧实现用「流里出现过 RST」判定，会把正常关闭的 RST 也算进来（T07 要修）"),
    LegacyPattern("L4 传输层", "连接建立", "握手", "L4.CONNECT.SLOW_HANDSHAKE",
                  Category.CONNECT, advice_key="L4.CONNECT.ADVICE"),
    LegacyPattern("L4 传输层", "传输质量", "重传率", "L4.RETRANS.HIGH",
                  Category.TRANSPORT, advice_key="L4.RETRANS.ADVICE",
                  note=("旧数据无方向 → direction 留空、confidence 降到 0.6；"
                        "方向要靠 extract 层的 c2s/s2c 拆分（T04）才能给出")),
    LegacyPattern("L4 传输层", "传输质量", "零窗口", "L4.ZEROWIN.SIDE",
                  Category.TRANSPORT, confidence=0.5, evidence_kind=EvidenceKind.INFERRED,
                  advice_key="L4.ZEROWIN.ADVICE",
                  note="旧实现只统计总数、不知道谁通告 → 无法归属客户端/服务端"),

    # ---------------- L7 ----------------
    LegacyPattern("L7 应用层", "域名解析", "失败率", "L7.DNS.FAIL",
                  Category.DNS, advice_key="L7.DNS.ADVICE"),
    LegacyPattern("L7 应用层", "域名解析", "没有收到响应", "L7.DNS.TIMEOUT",
                  Category.DNS, advice_key="L7.DNS.ADVICE",
                  note="旧实现用「查询数-响应数」估算，T07 要改成按 txid 配对"),
    LegacyPattern("L7 应用层", "域名解析", "响应平均", "L7.DNS.SLOW",
                  Category.DNS, advice_key="L7.DNS.ADVICE"),
    LegacyPattern("L7 应用层", "应用响应", "5xx", "L7.HTTP.5XX",
                  Category.APP, advice_key="L7.HTTP.ADVICE"),
    LegacyPattern("L7 应用层", "应用响应", "4xx", "L7.HTTP.4XX",
                  Category.APP, advice_key="L7.HTTP.ADVICE"),
    LegacyPattern("L7 应用层", "应用响应", "响应平均", "L7.HTTP.SLOW",
                  Category.APP, advice_key="L7.HTTP.ADVICE"),
    LegacyPattern("L7 应用层", "TLS 会话", "", "L7.TLS.ALERTS",
                  Category.TLS, confidence=0.6, advice_key="L7.TLS.ADVICE",
                  note="少量 TLS 告警多为正常关闭通知，别当故障"),

    # ---------------- 安全观察（不参与主判定） ----------------
    LegacyPattern("安全观察", "可疑外联", "", "SEC.EXFIL",
                  Category.SEC_EXFIL, advice_key="SEC.EXFIL.ADVICE"),
    LegacyPattern("安全观察", "端口扫描", "", "SEC.SCAN",
                  Category.SEC_SCAN, advice_key="SEC.SCAN.ADVICE"),
    LegacyPattern("安全观察", "明文凭证", "", "SEC.PLAINTEXT",
                  Category.SEC_PLAINTEXT, advice_key="SEC.PLAINTEXT.ADVICE"),
)

#: 层中文 → Layer 枚举。
LAYER_MAP: dict[str, Layer] = {
    "L2 本地链路": Layer.L2,
    "L3 网络层": Layer.L3,
    "L4 传输层": Layer.L4,
    "L7 应用层": Layer.L7,
    "安全观察": Layer.SEC,
}

#: 从旧 finding 文本里抠数字，喂给文案模板（抠不到就不放，模板会优雅降级）。
_NUM_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"重传率\s*([\d.]+)%", "retrans_rate"),
    (r"失败率\s*([\d.]+)%", "rate"),
    (r"(\d+)\s*个请求返回 5xx.*?占\s*([\d.]+)%", "err5_rate"),   # 特殊：两个组
    (r"(\d+)\s*个请求返回 5xx", "err5"),
    (r"(\d+)\s*个请求返回 4xx", "err4"),
    (r"(\d+)\s*个同网段地址", "count"),
    (r"收到\s*(\d+)\s*条 ICMP", "count"),
    (r"RTT 平均\s*([\d.]+)ms", "rtt_avg_ms"),
    (r"抖动\s*([\d.]+)ms", "rtt_jitter_ms"),
    (r"握手平均\s*([\d.]+)ms", "hs_avg_ms"),
    (r"零窗口\s*(\d+)\s*次", "zero_win"),
    (r"(\d+)\s*个连接发出 SYN", "conn_fail"),
    (r"(\d+)\s*个连接被对端 RST", "conn_refused"),
    (r"DNS 响应平均\s*([\d.]+)ms", "avg_ms"),
    (r"HTTP 响应平均\s*([\d.]+)ms", "avg_ms"),
    (r"(\d+)\s*次查询没有收到响应", "timeouts"),
    (r"（(\d+) 个 SNI", "sni_count"),
    (r"(\d+)\s*个会话", "streams_total"),
)


def _numbers(text: str) -> dict:
    out: dict[str, object] = {}
    for pattern, key in _NUM_PATTERNS:
        match = re.search(pattern, text)
        if not match:
            continue
        if key == "err5_rate" and match.lastindex and match.lastindex >= 2:
            out["err5"] = int(match.group(1))
            out["err5_rate"] = float(match.group(2))
            continue
        raw = match.group(1)
        try:
            out[key] = float(raw) if "." in raw else int(raw)
        except (TypeError, ValueError):
            continue
    return out


def match(row: Mapping) -> LegacyPattern | None:
    """按「层 + 类别 + 关键词」找第一条匹配的映射规则。

    Args:
        row: 旧结构的一行，需含 ``layer`` / ``category`` / ``finding``。

    Returns:
        LegacyPattern | None: 命中的规则；返回 ``None`` 表示「新规则还没覆盖到」，
            调用方应把它记进未匹配清单（CI 里断言为空）。

    Note:
        顺序敏感：``PATTERNS`` 里更具体的 ``keyword`` 必须排在前面，
        否则「连接建立」的三个模式会互相吃掉。
    """
    layer_cn = str(row.get("layer", "")).strip()
    category_cn = str(row.get("category", "")).strip()
    text = str(row.get("finding", ""))
    for pattern in PATTERNS:
        if pattern.layer_cn != layer_cn or pattern.category_cn != category_cn:
            continue
        if pattern.keyword and pattern.keyword not in text:
            continue
        return pattern
    return None


def is_normal(row: Mapping) -> bool:
    """判断这一行是不是「正常 / 无样本」的陈述（不该产出 Finding）。

    Args:
        row: 旧结构的一行。

    Returns:
        bool: 严重度为 ``"—"``（测了，正常）时为 True；``"na"``（没样本）不再
            走严重度分支，而是**按文案**判（「未检测到…」这类陈述同样不产出 Finding）。

    Note:
        为什么 ``"na"`` 不算 normal：它是第三种状态，回答的是「没测到」而不是「没问题」。
        ``SEVERITY_MAP`` 里两者已经分开（``Severity.OK`` vs ``Severity.NA``），
        这里也必须分开，否则下游想统计「有多少项真验过」时会把它算进去。

        ⚠️ 副作用：``"na"`` 行现在靠 ``NORMAL_HINTS``（「未检测到」等词）兜住。
        哪天文案改成「无样本」而不含这些词，这些行会立刻变成 ``find_unmatched``
        的漏项 —— 改文案（PR F）时必须同步往 ``NORMAL_HINTS`` 里加词。
    """
    severity = str(row.get("severity", "—")).strip()
    if SEVERITY_MAP.get(severity, Severity.OK) is Severity.OK:
        return True
    text = str(row.get("finding", ""))
    return any(hint in text for hint in NORMAL_HINTS)


def to_finding(row: Mapping, index: int = 0) -> Finding | None:
    """把一行旧 ``row`` 转成结构化 ``Finding``。

    Args:
        row: 旧结构的一行。
        index: 该行在原 ``rows[]`` 里的下标，写进 ``metric["legacy_index"]`` 便于回溯。

    Returns:
        Finding | None: 正常行、或没有任何模式匹配时返回 ``None``。

    Note:
        旧数据没有方向，所以 ``direction`` 一律为 ``None``；依赖方向才能定性的规则
        （重传、零窗口）会把置信度压到 0.6 并标成 ``INFERRED`` ——
        宁可写「疑似」，也不要给出确定结论。
    """
    if is_normal(row):
        return None
    pattern = match(row)
    if pattern is None:
        return None

    severity = SEVERITY_MAP.get(str(row.get("severity", "")).strip(), Severity.WARNING)
    layer = LAYER_MAP.get(pattern.layer_cn, Layer.L4)
    text = str(row.get("finding", ""))

    metric: dict[str, object] = {
        "legacy_index": index,
        "finding_raw": text,
        # ⚠️ 迁移期专用：旧建议文案没有 key，只能原文带过来。
        # T05 完成后必须删除本字段，改用 advice_key → copy 表。
        "advice_raw": str(row.get("advice", "")),
        "evidence_raw": str(row.get("evidence", "")),
    }
    metric.update(_numbers(text))

    confidence = pattern.confidence
    # 旧数据没有方向：靠方向判定的规则再降一档，别让下游当成结论
    if pattern.rule_id in ("L4.RETRANS.HIGH", "L4.ZEROWIN.SIDE"):
        confidence = min(confidence, 0.6)
    if confidence >= 1.0:
        evidence_kind = pattern.evidence_kind
    else:
        evidence_kind = (pattern.evidence_kind if pattern.evidence_kind is EvidenceKind.INFERRED
                         else EvidenceKind.INFERRED)

    return Finding(
        rule_id=pattern.rule_id,
        layer=layer,
        severity=severity,
        category=pattern.category,
        metric=metric,
        targets=(),          # 旧 evidence 是自由文本，解析不可靠 → 宁可空着
        frames=(),
        streams=(),
        direction=None,      # 旧数据无方向，见上面的 note
        confidence=round(confidence, 2),
        evidence_kind=evidence_kind,
        advice_key=pattern.advice_key,
        headline_key=pattern.rule_id,
    )


def map_rows(rows: Iterable[Mapping]) -> list[Finding]:
    """批量转换，保持原顺序。

    Args:
        rows: 旧 ``rows[]`` 列表。

    Returns:
        list[Finding]: 只含有结论的行；正常行与未匹配行被跳过。
    """
    out: list[Finding] = []
    for index, row in enumerate(rows or ()):
        finding = to_finding(row, index)
        if finding is not None:
            out.append(finding)
    return out


def find_unmatched(rows: Iterable[Mapping]) -> list[Mapping]:
    """找出「既不是正常行、也没有匹配到模式」的行。

    Args:
        rows: 旧 ``rows[]`` 列表。

    Returns:
        list[Mapping]: 漏映射的行。**CI 里应断言为空** ——
            非空意味着有人加了新规则却忘了补映射，迁移会静默漏项。
    """
    return [row for row in (rows or ())
            if not is_normal(row) and match(row) is None]


def coverage(rows: Sequence[Mapping]) -> dict:
    """迁移进度报告。

    Args:
        rows: 旧 ``rows[]`` 列表。

    Returns:
        dict: 键 ``total``（总行数）/ ``mapped``（已映射）/ ``normal``（正常行）/
            ``unmatched``（漏映射数）/ ``unmatched_rows``（漏映射行的摘要，便于直接看）。
    """
    rows = list(rows or ())
    mapped = [r for r in rows if to_finding(r) is not None]
    normal = [r for r in rows if is_normal(r)]
    unmatched = find_unmatched(rows)
    return {
        "total": len(rows),
        "mapped": len(mapped),
        "normal": len(normal),
        "unmatched": len(unmatched),
        "unmatched_rows": [{"layer": r.get("layer"), "category": r.get("category"),
                            "finding": str(r.get("finding", ""))[:80]} for r in unmatched],
    }


def mapped_rule_ids() -> tuple[str, ...]:
    """本映射表能产出的全部 ``rule_id``。

    Returns:
        tuple[str, ...]: 去重且保序的 ``rule_id`` 列表。
    """
    seen: dict[str, None] = {}
    for pattern in PATTERNS:
        seen.setdefault(pattern.rule_id, None)
    return tuple(seen)


def missing_from_registry() -> tuple[str, ...]:
    """已能映射、但 ``core/rules/`` 还没实现的 ``rule_id`` —— 这就是 T05 的待办清单。

    Returns:
        tuple[str, ...]: 尚未被新规则引擎接管的 ``rule_id``。
            返回空元组说明新引擎已吃下全部旧能力，本文件可以删了。
    """
    try:
        from .base import registry  # 延迟导入：base 会反向导入 l2..l7
    except Exception:  # noqa: BLE001  包结构未就绪时不该让调用方崩
        return mapped_rule_ids()
    implemented = {rule.id for rule in registry()}
    return tuple(rule_id for rule_id in mapped_rule_ids() if rule_id not in implemented)


__all__ = [
    "SEVERITY_MAP", "NORMAL_HINTS", "LAYER_MAP", "LegacyPattern", "PATTERNS",
    "match", "is_normal", "to_finding", "map_rows",
    "find_unmatched", "coverage", "mapped_rule_ids", "missing_from_registry",
]
