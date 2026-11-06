"""AI 出口：**只接受已脱敏 payload**，并要求结构化输出。

与现有 ``core/ai.py`` 的三个差别（评审 4.6）：

1. **脱敏在构造消息的同一处完成**，不靠调用方记得先脱敏；
2. 要求模型返回**固定 JSON**，本地校验失败就重试一次，仍失败则**只出 L1 结论**
   —— 永不因为 AI 挂了而丢诊断；
3. **provenance 里记 ``prompt_version``**，模型换版本时能定位「结论为什么变了」。

传输层（urllib / 超时 / 错误映射）建议直接沿用现有 ``core/ai.py``，
本文件只负责「说什么」和「怎么验」，不负责「怎么连」。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from ..contracts import AnalyzeResult, Severity, to_jsonable
from ..errors import DiagError, ErrorCode
from .sanitize import Ledger, Policy, Profile, sanitize

#: 改 prompt 必须同时改这个号，并写进 Provenance。
PROMPT_VERSION = "2026.11.1"

SYSTEM_PROMPT = """你是资深网络排障工程师，读者是一线桌面运维：懂电脑、会看日志，但不熟网络协议。
唯一目标：让他读完就知道「哪一层坏了、哪个协议、哪个对端、下一步做什么」。

硬性要求：
1. 只能引用给定数据里的 IP 记号、端口、数值、帧号，禁止编造。
2. 数据里的 <ip:lan-1> / <host:a1b2>.corp.example.com 是**脱敏后的占位符**，
   原样引用，不要试图还原。
3. 区分「网络慢」和「服务端慢」：RTT/握手小但首字节或服务端等待大 = 服务端问题；
   两者都大 = 链路问题；有建连失败 = 网络或防火墙问题。
4. 只给 1~3 个最可能的成因，按可能性排序，不要罗列所有可能。
5. 证据不足时写「需补充证据」，并说明下一步抓什么、加什么过滤条件。
6. 只输出 JSON，不要 markdown 代码块，不要解释。

输出结构（严格遵守）：
{"headline": "60 字以内一句话结论",
 "points": [{"layer": "L2|L3|L4|L7|SEC", "protocol": "", "target": "",
             "evidence": "", "action": "", "confidence": 0.0}],
 "steps": ["按执行顺序排列的可落地动作"],
 "needs_more_data": false}
"""


@dataclass
class AIPayload:
    """待发送内容 + 脱敏账本。账本留在本地，**不进请求体**。"""

    messages: list[dict]
    ledger: Ledger
    model: str = ""
    prompt_version: str = PROMPT_VERSION

    def estimated_chars(self) -> int:
        return sum(len(m.get("content", "")) for m in self.messages)


# ---------------------------------------------------------------- 构造消息


def _finding_line(f: Any) -> str:
    direction = getattr(getattr(f, "direction", None), "value", "-")
    kind = getattr(getattr(f, "evidence_kind", None), "value", "-")
    metric = ", ".join(f"{k}={v}" for k, v in (f.metric or {}).items())
    targets = "; ".join(str(t) for t in (f.targets or ()))
    return (f"- {f.rule_id}｜{f.layer.value}｜{f.category.value}｜{f.severity.value}"
            f"｜方向 {direction}｜置信度 {f.confidence}（{kind}）"
            f"｜目标 {targets or '-'}｜指标 {metric or '-'}"
            f"｜帧 {','.join(str(x) for x in f.frames[:6]) or '-'}")


def render_brief(result: AnalyzeResult) -> str:
    """把结果压成一份**信息完整但无冗余**的纯文本，给模型看。

    刻意只给 findings / 指标 / 分层状态，**不给**原始 URI、Header、payload
    ——那些既不必要，又是泄露面。
    """
    cap = result.capture
    lines = [
        "【采集概况】",
        f"模式 {cap.mode}｜报文 {cap.packets} 个｜时长 {cap.duration_s}s"
        f"｜网卡 {cap.interface or '-'}｜过滤器 {cap.bpf or '-'}",
        "",
        "【分层状态】（规则引擎判定，severity 为枚举值）",
    ]
    verdict = result.verdict
    if verdict is not None:
        for layer in verdict.layers:
            lines.append(f"- {layer.layer.value}：{layer.severity.value}"
                         f"（{layer.detail_key or '-'}）")
        if verdict.sufficiency and not verdict.sufficiency.ok:
            lines.append("")
            lines.append("【证据充分性】不足：" + ", ".join(verdict.sufficiency.reasons))
            lines.append("提示：结论应表述为「证据不足」，不要给出确定结论。")
    lines += ["", "【规则命中】"]
    if result.findings:
        lines.extend(_finding_line(f) for f in result.findings)
    else:
        lines.append("- 无命中（各层指标在阈值内）")

    metrics = result.metrics or {}
    if metrics:
        lines += ["", "【关键指标】"]
        lines.append(", ".join(f"{k}={v}" for k, v in metrics.items()))
    return "\n".join(lines)


def build_payload(result: AnalyzeResult, policy: Policy | Profile | str | None = None,
                  question: str = "", model: str = "") -> AIPayload:
    """构造已脱敏的请求体。这是**唯一**构造 AI 请求的入口。"""
    brief = render_brief(result)
    if question.strip():
        brief += "\n\n另外请重点回答这个问题：" + question.strip()

    safe_text, ledger = sanitize(brief, policy or Profile.CLOUD_MASK)
    return AIPayload(
        messages=[{"role": "system", "content": SYSTEM_PROMPT},
                  {"role": "user", "content": str(safe_text)}],
        ledger=ledger,
        model=model,
    )


# ---------------------------------------------------------------- 校验输出


_REQUIRED_KEYS = ("headline", "points", "steps")

#: 用于「不许编造」校验的 IP[:端口] 形态。
_IP_PORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b")


def validate_output(text: str) -> dict:
    """解析并校验模型输出。失败抛 ``DiagError(AI_BAD_OUTPUT)``。

    校验点：必须是 JSON 对象、必填键齐全、``points`` 是列表、
    ``headline`` 不超过 120 字（防止模型写小作文）。
    """
    raw = (text or "").strip()
    if raw.startswith("```"):                      # 容忍模型加代码块
        raw = raw.strip("`")
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise DiagError(ErrorCode.AI_BAD_OUTPUT, f"模型输出不是 JSON：{raw[:120]!r}") from exc
    if not isinstance(data, dict):
        raise DiagError(ErrorCode.AI_BAD_OUTPUT, "模型输出不是 JSON 对象")
    missing = [k for k in _REQUIRED_KEYS if k not in data]
    if missing:
        raise DiagError(ErrorCode.AI_BAD_OUTPUT, f"模型输出缺字段：{missing}")
    if not isinstance(data.get("points"), list):
        raise DiagError(ErrorCode.AI_BAD_OUTPUT, "points 必须是数组")
    headline = str(data.get("headline") or "")
    if len(headline) > 120:
        raise DiagError(ErrorCode.AI_BAD_OUTPUT, f"headline 过长（{len(headline)} 字）")
    data["_prompt_version"] = PROMPT_VERSION
    return data


def guard_no_new_facts(ai_output: Mapping[str, Any], findings: Any) -> list[str]:
    """粗略的「不许编造」校验：模型提到的 IP:端口 必须出现在 findings 里。

    返回可疑条目（空 = 通过）。落地时可放宽为「警告而非拒绝」，
    但**必须**在报告里标注「AI 输出含未在数据中出现的目标」。
    """
    known: set[str] = set()
    for f in findings:
        for t in getattr(f, "targets", ()) or ():
            known.add(str(t))
            if getattr(t, "ip", ""):
                known.add(str(t.ip))
    blob = json.dumps(to_jsonable(ai_output), ensure_ascii=False)
    suspects: list[str] = []
    for match in _IP_PORT_RE.finditer(blob):
        candidate = match.group(0)
        if candidate not in known and match.group(1) not in known:
            suspects.append(candidate)
    return suspects


# ---------------------------------------------------------------- 调用（占位）


def analyze(result: AnalyzeResult, question: str = "",
            policy: Policy | Profile | str | None = None) -> dict:
    """调模型。传输层复用现有 ``core/ai.py``：

    TODO(迁移)：``from ..legacy.ai import chat`` 或直接把 ``chat()`` 搬进本包，
    然后::

        payload = build_payload(result, policy, question, model=cfg["model"])
        for attempt in (1, 2):
            text = chat(payload.messages, model=payload.model)
            try:
                return {"ok": True, "data": validate_output(text),
                        "prompt_version": PROMPT_VERSION,
                        "ledger_count": payload.ledger.count}
            except DiagError:
                continue
        # 两次都失败 → 只出 L1 结论，不让诊断失败
        raise DiagError(ErrorCode.AI_BAD_OUTPUT,
                        "AI 输出未通过校验，请查看本地规则结论")

    注意：``payload.ledger`` 必须留在本地（写进 reports/<stem>.ledger.json，可选），
    绝不随请求外发。
    """
    raise NotImplementedError("analyze(): 见本函数 docstring 的迁移说明")


def fallback_summary(result: AnalyzeResult) -> str:
    """AI 不可用时的降级文案：直接用 L1 结论，不额外编造。"""
    verdict = result.verdict
    if verdict is None:
        return ""
    if verdict.sufficiency and not verdict.sufficiency.ok:
        return "证据不足，本次无法判定；请按提示补采后再试。"
    worst = result.worst
    if worst is None:
        return "各层指标在阈值内，未发现网络故障。"
    return f"命中 {worst.rule_id}（{worst.severity.value}）：{worst.category.value}"


__all__ = [
    "PROMPT_VERSION", "SYSTEM_PROMPT", "AIPayload",
    "render_brief", "build_payload", "validate_output", "guard_no_new_facts",
    "analyze", "fallback_summary",
]
