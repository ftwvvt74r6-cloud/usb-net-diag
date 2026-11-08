"""结论边界结构化渲染器：把一次诊断的「结论 + 依据 + 覆盖 / 未覆盖 + 置信」做成一份对象。

**解决什么问题**：以前的结论只有一个 ``headline``。它被口头转述或复制到工单时，
「基于哪些样本」「哪些路径没测」「最关键的边界是什么」会全部丢失，协作方只能把
「未发现异常」误读成「网络没问题」。本模块把结论与边界绑成同一个结构化对象，
六个出口（报告 / CLI / 诊断包 / 取证单 / UI / MCP，后两者在 E2 接入）都消费它。

**谁调用它**：:func:`core.report.render_markdown` 与 ``report.save``、
``core/diagnose.py`` 的 ``--json``、:mod:`core.evidence` 的取证单、后续的
UI / MCP。所有出口只允许调用 :func:`build_conclusion`，禁止各自拼一份文案。

**不做什么**：不读时钟、不联网、不读本次结果之外的任何可变状态；不把
``confidence_level`` / ``key_limit`` 写进契约或报告 JSON（它们只是在渲染期由
``confidence`` 与 copy 表派生）。本模块允许使用 ``copytext`` 的进程级**文案表**
缓存，但绝不缓存任何「本次运行事实」—— 同一进程连续渲染两条结果必须互不串味。

**输入输出**：
    * :func:`derive_confidence`：``result`` → ``float``（0.9 / 0.65 / 0.3 三档）。
    * :func:`build_conclusion`：``(result, verdict)`` → 键
      ``conclusion`` / ``basis`` / ``coverage`` / ``not_covered`` /
      ``confidence`` / ``confidence_level`` / ``key_limit``。
    * :func:`render_conclusion_markdown` / :func:`render_conclusion_text`：
      上述对象 → 给人看的整块文本（报告 / 复制给协作方）。

**降级规则**：任何一个占位符填充失败，该项输出「未知（原因：…）」并把结论级
``confidence`` 降为 :data:`CONFIDENCE_INDIRECT`（等级「低」）；**禁止空串、禁止
吞异常**。copy 表整体损坏时同样走这条路径，绝不让渲染崩在文案表上。
"""
from __future__ import annotations

from typing import Any

try:                                    # 扁平导入：core/ 在 sys.path 上（report / diagnose）
    from copytext import get as _copy_get, load_table as _load_table
except ModuleNotFoundError:             # 包导入：仓库根在 sys.path 上（tests / core.*）
    from core.copytext import get as _copy_get, load_table as _load_table

try:                                    # 扁平导入
    from contracts import (
        CONFIDENCE_HIGH_MIN,
        CONFIDENCE_MEDIUM_MIN,
        confidence_level_of,
    )
except ModuleNotFoundError:             # 包导入
    from core.contracts import (
        CONFIDENCE_HIGH_MIN,
        CONFIDENCE_MEDIUM_MIN,
        confidence_level_of,
    )

try:                                    # 扁平导入：借用同一套「可判定维度」闸门
    import verdict as _verdict_mod
except ModuleNotFoundError:             # 包导入
    from core import verdict as _verdict_mod

#: 有对照组（网关 + 对端双侧探测）且两侧结论一致时的置信度。
CONFIDENCE_CONTRAST = 0.9
#: 仅单侧证据（只有抓包无对照 / 只有一侧探针）时的置信度。
CONFIDENCE_SINGLE_SIDE = 0.65
#: 仅间接线索（无样本 / 证据不足 / ICMP 超时 / 采样异常 / 填充失败）时的置信度。
CONFIDENCE_INDIRECT = 0.3

#: 对照组每侧至少要有几个 RTT/探针样本，样本太少谈不上「两侧一致」。
CONTRAST_MIN_SAMPLES = 2
#: 单侧丢包达到这个百分比就不算「两侧都正常」，不能给高置信。
PROBE_LOSS_HIGH_PCT = 20.0

#: ``confidence_level`` → copy 表 ``conclusion.key_limit`` 的键。
#: 这个映射本身就是「等级→边界」的唯一出处；删掉它，低/中/高三条文案就取不到。
KEY_LIMIT_KEYS = {"高": "high", "中": "medium", "低": "low"}

#: ``basis`` 子模板的展示顺序（固定，便于逐字节断言）。
_BASIS_ORDER = ("capture", "target", "probe", "path", "findings")

#: 禁止出现在结论/边界里的绝对化措辞（用户定稿：没有依据的「正常」不算结论）。
ABSOLUTE_WORDING = ("链路正常", "链路未见异常", "完全没有问题", "一切正常")

#: 视为「已知」的探针角色；用于计算「本次未覆盖的探针角色」。
_KNOWN_ROLES = ("gateway", "target")

#: copy 表缺失时的最小标签回退（只兜排版，不兜结论事实）。
_LABEL_FALLBACK = {
    "section_title": "### 结论与边界",
    "conclusion_label": "**结论**：",
    "basis_heading": "**依据**",
    "coverage_heading": "**本次覆盖**",
    "not_covered_heading": "**明确未覆盖**",
    "confidence_line": "**置信度**：{level}（{confidence:.2f}）　**关键边界**：{key_limit}",
    "text_title": "结论与边界",
    "text_conclusion": "结论：{conclusion}",
    "text_basis": "依据：",
    "text_coverage": "本次覆盖：",
    "text_not_covered": "明确未覆盖：",
    "text_confidence": "置信度：{level}（{confidence:.2f}）",
    "text_key_limit": "关键边界：{key_limit}",
    "unknown": "未知（原因：{reason}）",
}


class _FillError(Exception):
    """内部信号：某个模板/占位符填充失败（必须转成「未知（原因：…）」，不许吞掉）。"""


# ---------------------------------------------------------------- copy 表访问


def _raw(section: str, key: str) -> str | None:
    """读 copy 表里的一个字符串模板（缺失 / 类型不对返回 ``None``）。

    Args:
        section: section 点号路径，如 ``conclusion`` / ``conclusion.key_limit``。
        key: section 内的键。

    Returns:
        str | None: 命中的字符串模板；缺失或不是字符串时返回 ``None``。
    """
    try:
        value = _copy_get(_load_table(), section, key)
    except Exception:                          # noqa: BLE001  文案表问题走降级，不拖垮渲染
        return None
    return value if isinstance(value, str) else None


def _raw_section(section: str) -> dict:
    """读 copy 表里的一个对象 section（如 ``conclusion.basis``）。

    Args:
        section: section 点号路径。

    Returns:
        dict: 命中的对象；缺失或不是对象时返回空字典。
    """
    try:
        node: Any = _load_table()
        for part in section.split("."):
            if not isinstance(node, dict):
                return {}
            node = node.get(part, {})
    except Exception:                          # noqa: BLE001
        return {}
    return node if isinstance(node, dict) else {}


def _unknown(reason: str) -> str:
    """把失败原因渲染成用户可见的「未知（原因：…）」。

    Args:
        reason: 非空的失败原因（异常类型 + 摘要，或「模板缺失」这类说明）。

    Returns:
        str: copy 表 ``conclusion.unknown`` 模板的填充结果；模板缺失时用最小的
            中文回退，保证**永远不返回空串**。
    """
    text = str(reason or "").strip() or "未提供原因"
    raw = _raw("conclusion", "unknown") or _LABEL_FALLBACK["unknown"]
    try:
        rendered = raw.format(reason=text)
    except (KeyError, IndexError, ValueError):
        return f"未知（原因：{text}）"
    return rendered if rendered.strip() else f"未知（原因：{text}）"


def _reason_of(exc: BaseException, label: str = "") -> str:
    """把异常整理成短原因（异常类型 + 摘要，去换行、截断）。

    Args:
        exc: 捕获到的异常。
        label: 可选的模板定位信息（如 ``conclusion.basis_short``）。

    Returns:
        str: 非空原因串，可直接放进「未知（原因：…）」。
    """
    detail = " ".join(str(exc or "").split())[:120]
    head = f"{type(exc).__name__}: {detail}".strip(": ")
    return f"{label}（{head}）" if label else head


def _render_template(raw: str | None, facts: dict, label: str) -> str:
    """严格渲染一个占位符模板：任何失败都抛 :class:`_FillError`（不返回空串）。

    Args:
        raw: copy 表里的模板；``None`` 表示缺失。
        facts: 占位符实参（运行时事实）。
        label: 失败时写进原因的定位名。

    Returns:
        str: 去首尾空白的填充结果，保证非空。

    Raises:
        _FillError: 模板缺失、占位符缺失、格式化失败或填充结果为空。
    """
    if not isinstance(raw, str) or not raw.strip():
        raise _FillError(f"{label}: 模板缺失")
    try:
        rendered = raw.format(**facts)
    except Exception as exc:                   # noqa: BLE001  所有填充失败都必须显式降级
        raise _FillError(_reason_of(exc, label)) from exc
    if not isinstance(rendered, str) or not rendered.strip():
        raise _FillError(f"{label}: 填充结果为空")
    return rendered.strip()


# ---------------------------------------------------------------- 运行时事实


def _int(value: Any) -> int:
    """把计数安全转成 ``int``（缺键 / ``None`` / 脏值一律当 0）。"""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _num(value: Any) -> str:
    """把数值格式化成短串（整数不带 ``.0``；缺失返回 ``-``）。"""
    if value is None:
        return "-"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "-"
    if not number:
        return "0"
    return f"{number:g}"


def _text(value: Any, default: str = "-") -> str:
    """把任意值转成非空短串（布尔 / 空串按默认值处理）。"""
    if value is None or value == "":
        return default
    return str(value)


def _role_items(baseline: dict) -> dict[str, dict]:
    """把探针基线按角色归并（同角色重复时取第一条，与 verdict 的方向对照同口径）。

    Args:
        baseline: ``meta.probe_baseline`` 对象。

    Returns:
        dict[str, dict]: 角色机器码 → 该角色的聚合项；坏数据跳过。
    """
    by_role: dict[str, dict] = {}
    for item in baseline.get("roles") or []:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "")
        if role and role not in by_role:
            by_role[role] = item
    return by_role


def _role_label(role: str) -> str:
    """探针角色机器码 → 中文名（复用 ``copy.probe.role_*``）。"""
    text = _raw("probe", f"role_{role}")
    return text if text else role


def _probe_facts(baseline: dict | None) -> dict:
    """从探针基线里取展示/置信用的事实（缺失时返回「未启用」形态）。

    Args:
        baseline: ``meta.probe_baseline``；``None`` 表示本次没发探针。

    Returns:
        dict: 键 ``probe_present`` / ``probe_roles`` / ``probe_kinds`` /
            ``probe_sent`` / ``probe_recv`` / ``probe_loss`` / ``missing_roles``。
            数值统一成短字符串，模板里用 ``{probe_sent}`` 直接填。
    """
    if not isinstance(baseline, dict):
        return {
            "probe_present": False,
            "probe_roles": "无",
            "probe_kinds": "无",
            "probe_sent": "0",
            "probe_recv": "0",
            "probe_loss": "-",
            "missing_roles": "、".join(_role_label(role) for role in _KNOWN_ROLES),
        }
    by_role = _role_items(baseline)
    roles = list(by_role)
    labels = [_role_label(role) for role in roles] or ["无"]
    kinds: list[str] = []
    for item in by_role.values():
        kind = str(item.get("kind") or "")
        if kind and kind not in kinds:
            kinds.append(kind)
    kind_labels = []
    for kind in kinds:
        text = _raw("conclusion", f"probe_kind_{kind}")
        kind_labels.append(text if text else kind)
    missing = [role for role in _KNOWN_ROLES if role not in by_role]
    sent = _int(baseline.get("sent"))
    recv = _int(baseline.get("recv"))
    if not sent:
        sent = sum(_int(item.get("sent")) for item in by_role.values())
        recv = sum(_int(item.get("recv")) for item in by_role.values())
    loss = round((sent - recv) / sent * 100.0, 1) if sent else None
    return {
        "probe_present": bool(by_role),
        "probe_roles": "、".join(labels),
        "probe_kinds": "、".join(kind_labels) or "无",
        "probe_sent": str(sent),
        "probe_recv": str(recv),
        "probe_loss": _num(loss),
        "missing_roles": "、".join(_role_label(role) for role in missing) or "无",
    }


def _path_facts(profile: dict | None) -> dict:
    """从路径剖面里取展示用的事实（缺失时返回「未探测」形态）。

    Args:
        profile: ``meta.path_profile``；``None`` 表示本次没做逐跳探测。

    Returns:
        dict: 键 ``path_present`` / ``path_hops`` / ``path_degraded``。
    """
    if not isinstance(profile, dict):
        return {"path_present": False, "path_hops": "0", "path_degraded": "未探测"}
    hops = profile.get("hops") or []
    degraded = profile.get("degraded_ttl")
    return {
        "path_present": bool(hops),
        "path_hops": str(len(hops)),
        "path_degraded": "无" if degraded is None else f"第 {degraded} 跳",
    }


def _ports_text(meta: dict) -> str:
    """从会话明细里取本次涉及的端口（最多 6 个，保持出现顺序）。"""
    ports: list[str] = []
    for stream in meta.get("streams_top") or []:
        if not isinstance(stream, dict):
            continue
        port = stream.get("dport")
        if port in (None, ""):
            continue
        text = str(port)
        if text not in ports:
            ports.append(text)
        if len(ports) >= 6:
            break
    return "、".join(ports) if ports else "-"


def _finding_counts(rows: list, summary: dict) -> tuple[int, int, int]:
    """统计本次判定计数（行优先，行缺失时回退 summary 的聚合计数）。"""
    if rows:
        critical = sum(1 for row in rows
                       if isinstance(row, dict) and row.get("severity") == "严重")
        warning = sum(1 for row in rows
                      if isinstance(row, dict) and row.get("severity") == "警告")
        info = sum(1 for row in rows
                   if isinstance(row, dict) and row.get("severity") == "提示")
        return critical, warning, info
    return (_int(summary.get("critical_count")), _int(summary.get("warning_count")), 0)


def _runtime_facts(result: dict) -> dict:
    """汇总本次运行的可填事实（**只来自入参**，绝不写进任何模块级缓存）。

    Args:
        result: 诊断结果字典（``meta`` / ``summary`` / ``rows``）。

    Returns:
        dict: 模板占位符实参：采样窗口、报文/会话数、目标与端口、探针事实、
            路径事实与判定计数。所有值都是非空短字符串或布尔。
    """
    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    rows = result.get("rows") if isinstance(result.get("rows"), list) else []
    critical, warning, info = _finding_counts(rows, summary)
    target = summary.get("target") or meta.get("target") or "全网"
    facts = {
        "packets": _num(meta.get("packets")),
        "streams": _num(meta.get("streams_total")),
        "duration": _num(meta.get("duration")),
        "target": _text(target, "全网"),
        "ports": _ports_text(meta),
        "finding_count": str(critical + warning + info),
        "critical": str(critical),
        "warning": str(warning),
        "info": str(info),
    }
    facts.update(_probe_facts(meta.get("probe_baseline")))
    facts.update(_path_facts(meta.get("path_profile")))
    return facts


# ---------------------------------------------------------------- 置信度推导


def _sufficiency_ok(result: dict, verdict_data: dict | None = None) -> bool:
    """本次结果有没有至少一个「可判定维度」（优先读已算好的 verdict）。

    Args:
        result: 诊断结果字典。
        verdict_data: 调用方已算好的判定；``None`` 时读 ``result["verdict"]``。

    Returns:
        bool: ``verdict.sufficiency.ok``；没有现成 verdict 时用
            :func:`core.verdict._sufficiency` 现算（纯函数，不读 copy / 网络）。
            拿不到时按 **False**（证据不足）处理，绝不乐观地给「高」。
    """
    if not isinstance(verdict_data, dict):
        stored = result.get("verdict")
        verdict_data = stored if isinstance(stored, dict) else None
    if isinstance(verdict_data, dict):
        sufficiency = verdict_data.get("sufficiency")
        if isinstance(sufficiency, dict) and "ok" in sufficiency:
            return bool(sufficiency.get("ok"))
    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    rows = result.get("rows") if isinstance(result.get("rows"), list) else []
    net_rows = [row for row in rows
                if isinstance(row, dict) and row.get("layer") != "安全观察"]
    try:
        return bool(_verdict_mod._sufficiency(meta, net_rows).ok)
    except Exception:                          # noqa: BLE001  判不了就按证据不足
        return False


def _sampling_anomaly(meta: dict) -> bool:
    """采样异常：没抓到包，或窗口长度非法（``<=0``）。

    Args:
        meta: 采集元信息。

    Returns:
        bool: True 表示本次采样不能支撑任何置信度。
    """
    if _int(meta.get("packets")) <= 0:
        return True
    duration = meta.get("duration")
    if duration is None:
        return False
    try:
        return float(duration) <= 0
    except (TypeError, ValueError):
        return True


def _only_icmp_timeout(meta: dict) -> bool:
    """是否「只有 ICMP 超时」这类间接线索（其他维度都没有可判样本）。

    Args:
        meta: 采集元信息。

    Returns:
        bool: 有 ICMP 超时、且 TCP / DNS / HTTP / ARP 四个维度都不成立时为 True。
    """
    if _int(meta.get("icmp_timeout")) <= 0:
        return False
    return (_int(meta.get("tcp_packets")) < getattr(_verdict_mod, "MIN_TCP_PACKETS", 5)
            and _int(meta.get("streams_total")) < getattr(_verdict_mod, "MIN_TCP_STREAMS", 1)
            and _int(meta.get("dns_total")) < getattr(_verdict_mod, "MIN_DNS_QUERIES", 1)
            and _int(meta.get("http_req")) < getattr(_verdict_mod, "MIN_HTTP_REQUESTS", 1)
            and _int(meta.get("arp_req_max")) < getattr(_verdict_mod, "MIN_ARP_REQUESTS", 2))


def _contrast_consistent(result: dict, meta: dict,
                         verdict_data: dict | None = None) -> bool:
    """是否满足「有对照组且结论一致」的高置信条件。

    条件全部可机械计算：``probe_baseline.roles`` 同时含 ``gateway`` 与
    ``target``、两侧 RTT/探针样本各 ≥ :data:`CONTRAST_MIN_SAMPLES`、两侧丢包率
    都低于 :data:`PROBE_LOSS_HIGH_PCT`，且方向对照没有指向对端。

    Args:
        result: 诊断结果字典（读 ``verdict.probe_contrast``）。
        meta: 采集元信息（读 ``probe_baseline``）。
        verdict_data: 调用方已算好的判定；``None`` 时读 ``result["verdict"]``。

    Returns:
        bool: 满足条件时为 True（→ :data:`CONFIDENCE_CONTRAST`）。
    """
    baseline = meta.get("probe_baseline")
    if not isinstance(baseline, dict):
        return False
    by_role = _role_items(baseline)
    gateway = by_role.get("gateway")
    target = by_role.get("target")
    if gateway is None or target is None:
        return False
    for item in (gateway, target):
        if _int(item.get("n")) < CONTRAST_MIN_SAMPLES:
            return False
        loss = item.get("loss_pct")
        if loss is None:
            return False
        try:
            if float(loss) >= PROBE_LOSS_HIGH_PCT:
                return False
        except (TypeError, ValueError):
            return False
    if not isinstance(verdict_data, dict):
        stored = result.get("verdict")
        verdict_data = stored if isinstance(stored, dict) else None
    contrast = verdict_data.get("probe_contrast") if isinstance(
        verdict_data, dict) else None
    if isinstance(contrast, dict) and str(contrast.get("code") or "") == (
            "PROBE.CONTRAST.TARGET_SIDE"):
        return False
    return True


def _derive_confidence(result: dict, verdict_data: dict | None = None) -> float:
    """三档推导的实现体（显式接收已算好的 verdict，避免读过期副本）。"""
    if not isinstance(result, dict):
        return CONFIDENCE_INDIRECT
    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    if _contrast_consistent(result, meta, verdict_data):
        return CONFIDENCE_CONTRAST
    if (_sampling_anomaly(meta) or not _sufficiency_ok(result, verdict_data)
            or _only_icmp_timeout(meta)):
        return CONFIDENCE_INDIRECT
    return CONFIDENCE_SINGLE_SIDE


def derive_confidence(result: dict) -> float:
    """由证据形态自动推导结论级置信度（纯函数，不允许人工填写）。

    三档映射（用户 2026-11-08 定稿）：

    * :data:`CONFIDENCE_CONTRAST`（0.9，高）：有对照组（网关 vs 对端双侧探测）
      且两侧结论一致；
    * :data:`CONFIDENCE_SINGLE_SIDE`（0.65，中）：仅单侧证据（只测目标 / 只有抓包
      无对照 / 只有一侧探针）；
    * :data:`CONFIDENCE_INDIRECT`（0.3，低）：仅间接线索（无样本 / 证据不足 /
      ICMP 超时 / 采样异常）。

    Args:
        result: 诊断结果字典（读 ``meta`` / ``rows`` / 可选 ``verdict``）。

    Returns:
        float: 0.9 / 0.65 / 0.3 之一；``result`` 不是对象时按 0.3（证据不足）。
    """
    if not isinstance(result, dict):
        return CONFIDENCE_INDIRECT
    stored = result.get("verdict")
    return _derive_confidence(result, stored if isinstance(stored, dict) else None)


# ---------------------------------------------------------------- 边界构造


def _key_limit(level: str) -> tuple[str, str]:
    """按置信等级从 copy 表选「最关键一条边界」。

    Args:
        level: ``"高"`` / ``"中"`` / ``"低"``。

    Returns:
        tuple[str, str]: ``(文案, 失败原因)``；成功时原因为空串。等级→key 的映射
            缺项、copy 缺 key 或填充失败时文案为空串、原因非空（调用方据此降级）。
    """
    key = KEY_LIMIT_KEYS.get(level)
    if not key:
        return "", f"等级→key_limit 映射缺失：{level!r}"
    try:
        return _render_template(_raw("conclusion.key_limit", key), {},
                                f"conclusion.key_limit.{key}"), ""
    except _FillError as exc:
        return "", str(exc)


def _static_items(key: str, reasons: list[str]) -> list[str]:
    """读一组静态覆盖/未覆盖项；缺失或结构不对时记原因并返回「未知」。

    Args:
        key: ``coverage_static`` / ``not_covered_static`` 等 section 内的键。
        reasons: 失败原因收集列表（原地追加）。

    Returns:
        list[str]: 非空的静态条目；整体缺失时返回单条「未知（原因：…）」。
    """
    value = _raw_section("conclusion").get(key)
    if not isinstance(value, list):
        reason = f"conclusion.{key}: 模板缺失或不是列表"
        reasons.append(reason)
        return [_unknown(reason)]
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            reason = f"conclusion.{key}[{index}]: 不是非空字符串"
            reasons.append(reason)
            items.append(_unknown(reason))
            continue
        items.append(item.strip())
    return items or [_unknown(f"conclusion.{key}: 列表为空")]


def _runtime_items(facts: dict, reasons: list[str]) -> list[str]:
    """读并渲染 coverage 的运行时模板（每个占位符独立降级，不因一条失败丢整块）。"""
    table = _raw_section("conclusion")
    templates = table.get("coverage_runtime")
    if not isinstance(templates, list):
        reason = "conclusion.coverage_runtime: 模板缺失或不是列表"
        reasons.append(reason)
        return [_unknown(reason)]
    items: list[str] = []
    for index, template in enumerate(templates):
        try:
            items.append(_render_template(template, facts,
                                          f"conclusion.coverage_runtime[{index}]"))
        except _FillError as exc:
            reasons.append(str(exc))
            items.append(_unknown(str(exc)))
    if facts.get("probe_present"):
        key = "coverage_runtime_probe"
    else:
        key = "coverage_runtime_no_probe"
    try:
        items.append(_render_template(table.get(key), facts, f"conclusion.{key}"))
    except _FillError as exc:
        reasons.append(str(exc))
        items.append(_unknown(str(exc)))
    return items


def _not_covered_runtime(facts: dict, reasons: list[str]) -> list[str]:
    """渲染「明确未覆盖」里由本次事实决定的部分。"""
    table = _raw_section("conclusion")
    try:
        return [_render_template(table.get("not_covered_runtime"), facts,
                                 "conclusion.not_covered_runtime")]
    except _FillError as exc:
        reasons.append(str(exc))
        return [_unknown(str(exc))]


def _basis_items(facts: dict, reasons: list[str]) -> list[str]:
    """按固定顺序渲染「依据」明细（探针/路径没有数据时不出现对应条目）。"""
    table = _raw_section("conclusion").get("basis")
    if not isinstance(table, dict):
        reason = "conclusion.basis: 模板缺失或不是对象"
        reasons.append(reason)
        return [_unknown(reason)]
    items: list[str] = []
    for key in _BASIS_ORDER:
        if key == "probe" and not facts.get("probe_present"):
            continue
        if key == "path" and not facts.get("path_present"):
            continue
        try:
            items.append(_render_template(table.get(key), facts,
                                          f"conclusion.basis.{key}"))
        except _FillError as exc:
            reasons.append(str(exc))
            items.append(_unknown(str(exc)))
    return items


def build_conclusion(result: dict, verdict: dict | None = None) -> dict:
    """构造结论边界对象（六出口的唯一出处）。

    处理顺序：推导 ``confidence`` → 派生 ``confidence_level`` → 按等级取
    ``key_limit`` → 用 copy 模板填 ``basis`` / ``coverage`` / ``not_covered`` →
    渲染 conclusion 句。**任何一项填充失败**都会把该项替换成「未知（原因：…）」，
    并把最终 ``confidence`` 降为 :data:`CONFIDENCE_INDIRECT`（等级「低」）。

    Args:
        result: 诊断结果字典（``meta`` / ``rows`` / ``summary`` / 可选 ``verdict``）。
        verdict: 已算好的判定字典；省略时读 ``result["verdict"]``。只读
            ``headline`` 与 ``probe_contrast``，不调用 ``verdict.build``。

    Returns:
        dict: 键 ``conclusion``（str）/ ``basis`` / ``coverage`` /
            ``not_covered``（``list[str]``，保证非空、无空串）/
            ``confidence``（float）/ ``confidence_level``（高|中|低）/
            ``key_limit``（str）。**不含**任何缓存或本次结果以外的事实。
    """
    result = result if isinstance(result, dict) else {}
    vd = verdict if isinstance(verdict, dict) else {}
    if not vd:
        stored = result.get("verdict")
        vd = stored if isinstance(stored, dict) else {}
    facts = _runtime_facts(result)
    reasons: list[str] = []

    confidence = _derive_confidence(result, vd)
    level = confidence_level_of(confidence)
    key_limit, failure = _key_limit(level)
    if failure:
        reasons.append(failure)

    headline = vd.get("headline")
    if not isinstance(headline, str) or not headline.strip():
        reason = "结论标题缺失（verdict.headline 为空）"
        reasons.append(reason)
        headline = _unknown(reason)
    else:
        headline = headline.strip()

    basis = _basis_items(facts, reasons)
    coverage = _static_items("coverage_static", reasons) + _runtime_items(facts, reasons)
    not_covered = (_static_items("not_covered_static", reasons)
                   + _not_covered_runtime(facts, reasons))

    try:
        basis_short = _render_template(_raw("conclusion", "basis_short"), facts,
                                       "conclusion.basis_short")
    except _FillError as exc:
        reasons.append(str(exc))
        basis_short = _unknown(str(exc))

    if reasons:
        confidence = CONFIDENCE_INDIRECT
        level = confidence_level_of(confidence)
        low_limit, low_failure = _key_limit(level)
        if low_failure:
            reasons.append(low_failure)
            key_limit = _unknown(low_failure)
        else:
            key_limit = low_limit
    else:
        key_limit = key_limit or _unknown("key_limit 为空")

    try:
        conclusion = _render_template(
            _raw("conclusion", "template"),
            {"headline": headline, "basis_short": basis_short, "key_limit": key_limit},
            "conclusion.template")
    except _FillError as exc:
        reasons.append(str(exc))
        conclusion = _unknown(str(exc))
        confidence = CONFIDENCE_INDIRECT
        level = confidence_level_of(confidence)

    return {
        "conclusion": conclusion,
        "basis": basis,
        "coverage": coverage,
        "not_covered": not_covered,
        "confidence": confidence,
        "confidence_level": level,
        "key_limit": key_limit,
    }


# ---------------------------------------------------------------- 渲染


def _label(key: str) -> str:
    """取 copy 表 ``conclusion`` section 的展示标签（缺失时用最小回退）。"""
    return _raw("conclusion", key) or _LABEL_FALLBACK[key]


def _as_text_list(value: Any, reason: str) -> list[str]:
    """把对象里的列表字段规整成非空字符串列表（坏数据 → 一条「未知」）。"""
    if not isinstance(value, (list, tuple)) or not value:
        return [_unknown(reason)]
    items = [str(item).strip() for item in value if isinstance(item, str) and item.strip()]
    return items or [_unknown(reason)]


def _normalized(block: dict) -> dict:
    """把任意输入规整成可渲染的边界对象（缺项用「未知」补齐，绝不返回空块）。"""
    source = block if isinstance(block, dict) else {}
    reason = "结论对象缺失" if not source else "结论对象字段缺失"
    confidence = source.get("confidence")
    try:
        confidence_value = float(confidence)
        if not 0.0 <= confidence_value <= 1.0:
            raise ValueError
    except (TypeError, ValueError):
        confidence_value = CONFIDENCE_INDIRECT
    level = source.get("confidence_level")
    if level not in ("高", "中", "低"):
        level = confidence_level_of(confidence_value)
    return {
        "conclusion": (str(source.get("conclusion")).strip()
                       if isinstance(source.get("conclusion"), str)
                       and str(source.get("conclusion")).strip() else _unknown(reason)),
        "basis": _as_text_list(source.get("basis"), f"{reason}: basis"),
        "coverage": _as_text_list(source.get("coverage"), f"{reason}: coverage"),
        "not_covered": _as_text_list(source.get("not_covered"), f"{reason}: not_covered"),
        "confidence": confidence_value,
        "confidence_level": level,
        "key_limit": (str(source.get("key_limit")).strip()
                      if isinstance(source.get("key_limit"), str)
                      and str(source.get("key_limit")).strip()
                      else _unknown(f"{reason}: key_limit")),
    }


def _report_line(report_id: str | None) -> str:
    """渲染「报告标识」尾注（只给导出/复制用；报告正文不传，保持逐字节不变）。

    Args:
        report_id: 报告文件名 + 生成时间等可追溯标识；空值表示不追加。

    Returns:
        str: 非空时返回 copy 表 ``conclusion.report_line`` 的填充结果，否则空串。
    """
    text = str(report_id or "").strip()
    if not text:
        return ""
    raw = _raw("conclusion", "report_line") or "报告标识：{report_id}"
    try:
        return raw.format(report_id=text).strip()
    except (KeyError, IndexError, ValueError):
        return f"报告标识：{text}"


def render_conclusion_markdown(block: dict, report_id: str | None = None) -> str:
    """把结论边界对象渲染成 Markdown 整块（报告 / 取证单 / 导出共用）。

    输出固定包含：结论句、依据、本次覆盖、明确未覆盖、置信等级/关键边界。
    任何字段缺失都会补「未知」；函数**永远不返回空串**。

    Args:
        block: :func:`build_conclusion` 的返回值（或结构相同的对象）。
        report_id: 可选的报告标识（文件名 + 生成时间）。省略时不追加任何行 ——
            报告正文必须保持逐字节不变，只有复制/导出才带上标识。

    Returns:
        str: 以 ``### 结论与边界`` 开头、以单个换行结尾的 Markdown 文本。
    """
    data = _normalized(block)
    lines = [_label("section_title"), ""]
    lines.append(_label("conclusion_label") + data["conclusion"])
    lines.append("")
    lines.append(_label("basis_heading"))
    lines += [f"- {item}" for item in data["basis"]]
    lines.append("")
    lines.append(_label("coverage_heading"))
    lines += [f"- {item}" for item in data["coverage"]]
    lines.append("")
    lines.append(_label("not_covered_heading"))
    lines += [f"- {item}" for item in data["not_covered"]]
    lines.append("")
    try:
        tail = _label("confidence_line").format(
            level=data["confidence_level"], confidence=data["confidence"],
            key_limit=data["key_limit"])
    except (KeyError, IndexError, ValueError):
        tail = (f"**置信度**：{data['confidence_level']}"
                f"（{data['confidence']:.2f}）　**关键边界**：{data['key_limit']}")
    lines.append(tail)
    extra = _report_line(report_id)
    if extra:
        lines.append(extra)
    return "\n".join(lines) + "\n"


def render_conclusion_text(block: dict, report_id: str | None = None) -> str:
    """把结论边界对象渲染成纯文本整块（复制给协作方 / 发微信 / 工单）。

    与 :func:`render_conclusion_markdown` 同源，但不含 Markdown 符号
    （无 ``#`` 标题、无 ``|`` 表格），并显式列出「结论 + 依据 + 本次覆盖 +
    明确未覆盖 + 置信等级/关键边界」。传 ``report_id`` 时在末尾追加报告标识，
    让协作方能手查到对应的 `.md` / `.json` 报告。

    Args:
        block: :func:`build_conclusion` 的返回值（或结构相同的对象）。
        report_id: 可选的报告标识（文件名 + 生成时间）；省略时不追加。

    Returns:
        str: 纯文本整块（以单个换行结尾，保证非空）。
    """
    data = _normalized(block)
    lines = [_label("text_title"), ""]
    try:
        lines.append(_label("text_conclusion").format(conclusion=data["conclusion"]))
    except (KeyError, IndexError, ValueError):
        lines.append("结论：" + data["conclusion"])
    lines.append("")
    lines.append(_label("text_basis"))
    lines += [f"{index}. {item}" for index, item in enumerate(data["basis"], 1)]
    lines.append("")
    lines.append(_label("text_coverage"))
    lines += [f"{index}. {item}" for index, item in enumerate(data["coverage"], 1)]
    lines.append("")
    lines.append(_label("text_not_covered"))
    lines += [f"{index}. {item}" for index, item in enumerate(data["not_covered"], 1)]
    lines.append("")
    try:
        lines.append(_label("text_confidence").format(
            level=data["confidence_level"], confidence=data["confidence"]))
    except (KeyError, IndexError, ValueError):
        lines.append(f"置信度：{data['confidence_level']}（{data['confidence']:.2f}）")
    try:
        lines.append(_label("text_key_limit").format(key_limit=data["key_limit"]))
    except (KeyError, IndexError, ValueError):
        lines.append("关键边界：" + data["key_limit"])
    extra = _report_line(report_id)
    if extra:
        lines.append(extra)
    return "\n".join(lines) + "\n"


__all__ = [
    "CONFIDENCE_CONTRAST",
    "CONFIDENCE_SINGLE_SIDE",
    "CONFIDENCE_INDIRECT",
    "CONFIDENCE_HIGH_MIN",
    "CONFIDENCE_MEDIUM_MIN",
    "CONTRAST_MIN_SAMPLES",
    "PROBE_LOSS_HIGH_PCT",
    "KEY_LIMIT_KEYS",
    "ABSOLUTE_WORDING",
    "derive_confidence",
    "build_conclusion",
    "render_conclusion_markdown",
    "render_conclusion_text",
]
