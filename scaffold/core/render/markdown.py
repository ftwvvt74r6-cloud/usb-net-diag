"""Markdown 报告渲染（最小可用版）。

只做「把契约渲染成人话」，**不含任何判断逻辑**——判断已经在 verdict 里做完了。
完整版（会话明细、DNS 逐条、HTTP 逐条、ICMP 明细、机器摘要）迁移
现有 ``core/report.py`` 即可，接口不变：``render(result, copy) -> str``。

命名策略（评审 P1「报告覆盖写」）：

* 渲染只产出字符串，**不落盘**；
* 落盘由 ``json_report.save()`` 负责，文件名带时间戳，永不覆盖历史。
"""

from __future__ import annotations

from typing import Mapping

from ..contracts import AnalyzeResult, Layer, Severity
from .text import CopyTable

STATUS_MARK = {
    Severity.CRITICAL: "❌",
    Severity.WARNING: "⚠️",
    Severity.INFO: "•",
    Severity.OK: "✅",
    Severity.NA: "—",
}


def _esc(value: object) -> str:
    return str("" if value is None else value).replace("|", "\\|").replace("\n", " ").strip()


def _table(head: list[str], body: list[list]) -> str:
    out = ["| " + " | ".join(head) + " |",
           "|" + "|".join(["---"] * len(head)) + "|"]
    out += ["| " + " | ".join(_esc(c) for c in row) + " |" for row in body]
    return "\n".join(out)


def render(result: AnalyzeResult, copy: CopyTable | Mapping | None = None) -> str:
    copy = copy if isinstance(copy, CopyTable) else CopyTable.load()
    cap = result.capture
    verdict = result.verdict
    lines: list[str] = ["# 网络故障诊断报告", ""]

    lines.append(f"- 抓包文件：`{cap.pcap_name or '-'}`　模式：{cap.mode}"
                 f"　报文 {cap.packets} 个　时长 {cap.duration_s}s")
    lines.append(f"- 采集网卡：{cap.interface or '-'}　过滤器：`{cap.bpf or '无'}`")
    prov = result.provenance
    if prov.generated_at:
        lines.append(f"- 生成时间：{prov.generated_at}　规则版本：{prov.rules_version or '-'}"
                     f"　配置指纹：`{prov.config_sha256 or '-'}`")
    lines.append("")
    lines.append("> 阅读顺序：先看一、结论，再看二、分层状态，三、问题详解照着做即可。")
    lines.append("")

    # ---- 一、结论 ----
    lines += ["## 一、结论", ""]
    if verdict is None:
        lines += ["（无判定结果：verdict 未生成，请检查管线）", ""]
    else:
        mark = STATUS_MARK.get(verdict.level, "")
        lines += [f"### {mark} {copy.headline(verdict)}", ""]
        lines.append(f"**影响**：{copy.impact(verdict)}")
        lines.append("")
        # 证据充分性单独一节，避免被读者忽略
        if verdict.sufficiency and not verdict.sufficiency.ok:
            lines += ["**证据不足，本结论仅供参考：**", ""]
            lines += [f"- {x}" for x in copy.insufficient(verdict.sufficiency)]
            lines += ["", "建议补采：" + "、".join(
                copy.next_step(k) for k in verdict.sufficiency.needed) if verdict.sufficiency.needed else ""]
            lines.append("")

    # ---- 二、分层状态 ----
    lines += ["## 二、分层状态", ""]
    if verdict is not None and verdict.layers:
        body: list[list] = []
        for status in verdict.layers:
            body.append([
                copy.label("layer", status.layer.value),
                copy.label("layer_protocol", status.layer.value),
                f"{STATUS_MARK.get(status.severity, '')} "
                f"{copy.label('severity', status.severity.value)}",
                copy.layer_detail(status) or "-",
            ])
        lines += [_table(["层次", "协议", "状态", "关键指标"], body), ""]
    else:
        lines += ["（无分层数据）", ""]

    # ---- 三、问题详解 ----
    lines += ["## 三、问题详解", ""]
    findings = [f for f in result.findings if f.layer is not Layer.SEC]
    if not findings:
        lines += ["本次没有命中任何规则。若业务仍有异常，请在复现问题时重新抓包。", ""]
    for idx, f in enumerate(findings, 1):
        title = copy.text(f"headline.{f.headline_key or f.rule_id}", f.metric,
                          default=f"{f.rule_id}（{f.category.value}）")
        lines += [f"### {idx}. {title}", ""]
        lines.append(f"- **所在层 / 协议 / 方向**："
                     f"{copy.label('layer', f.layer.value)}｜{f.category.value}"
                     f"｜{copy.label('direction', f.direction.value) if f.direction else '-'}")
        lines.append(f"- **严重程度**：{copy.label('severity', f.severity.value)}"
                     f"（置信度 {f.confidence:.2f}，"
                     f"{'推断' if f.evidence_kind.value == 'inferred' else '实测'}）")
        if f.targets:
            lines.append("- **对端**：" + "、".join(f"`{t}`" for t in f.targets))
        if f.frames:
            lines.append("- **证据帧**：" + "、".join(f"#{x}" for x in f.frames))
        if f.metric:
            lines.append("- **关键指标**：" + "、".join(f"{k}={v}" for k, v in f.metric.items()))
        advice = copy.advice(f.advice_key)
        if advice:
            lines.append(f"- **怎么处理**：{advice}")
        lines.append("")

    # ---- 四、下一步 ----
    if verdict is not None and verdict.next_step_keys:
        lines += ["## 四、下一步", ""]
        for key in verdict.next_step_keys:
            lines.append(f"- {copy.next_step(key)}")
        lines.append("")

    # ---- 五、安全观察（附带项，放最后） ----
    sec = [f for f in result.findings
           if f.layer is Layer.SEC and f.severity in (Severity.CRITICAL, Severity.WARNING)]
    if sec:
        lines += ["## 五、安全观察（附带项，非主线）", ""]
        for f in sec:
            lines += [f"- **{f.rule_id}**：{f.metric.get('count', 0)} 项；"
                      f"类型 {f.metric.get('by_type', {})}", ""]

    lines.append("---")
    lines.append(f"*schema {result.schema_version} · 报告由本地规则引擎生成，"
                 f"AI 解读为可选增强*")
    return "\n".join(x for x in lines if x is not None)


__all__ = ["render", "STATUS_MARK"]
