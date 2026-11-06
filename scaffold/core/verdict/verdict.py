"""把 findings 汇总成「一句话结论 + 四层状态 + 下一步」。

纯函数：不读文件、不联网、不看时钟（时间由调用方传）。所以在 CI 里可以直接
喂 ``features.json`` + 期望的 ``finding`` 列表做快照测试。

与现有 ``core/verdict.py`` 的差别：

* 输入从「中文 rows」变成「``Finding`` 列表」——文案不再参与判断；
* 多一道**证据充分性闸门**（``assess_sufficiency``）：样本不足时结论降级为
  「证据不足，无法判定」，而不是报「各层正常」（评审 P0-4）；
* 输出只有**文案 key + 实参**，中文由 ``copy/zh-CN.json`` 渲染。
"""

from __future__ import annotations

from typing import Mapping

from ..contracts import (
    Category,
    Features,
    Finding,
    Layer,
    LayerStatus,
    Severity,
    Sufficiency,
    Verdict,
)
from ..rules.base import LAYER_ORDER, Thresholds

#: 参与主判定的层（安全观察不抢主线）。
NET_LAYERS: tuple[Layer, ...] = (Layer.L2, Layer.L3, Layer.L4, Layer.L7)

#: 命中某条规则后建议的下一步（next_step 表的 key）。
RULE_NEXT_STEPS: dict[str, tuple[str, ...]] = {
    "L4.RETRANS.HIGH": ("path_probe", "check_switch"),
    "L4.ZEROWIN.CLIENT": ("check_local_app",),
    "L4.ZEROWIN.SERVER": ("check_server_app",),
    "L4.CONNECT.NO_RESPONSE": ("probe_link",),
    "L4.CONNECT.RST": ("probe_link",),
    "L2.ARP.NO_REPLY": ("check_switch",),
    "L3.ICMP.UNREACH": ("path_probe",),
    "L3.RTT.HIGH": ("path_probe",),
    "L7.DNS.FAIL": ("probe_link",),
    "L7.DNS.SLOW": ("probe_link",),
    "L7.HTTP.5XX": ("baseline",),
}


# ---------------------------------------------------------------- 充足性闸门


def assess_sufficiency(features: Features, cfg: Mapping | None = None) -> Sufficiency:
    """样本够不够下结论。

    这是本模块最重要的一段：**宁可说「不知道」，也不能说「没问题」**。
    1 KB 的空抓包被报成「各层指标正常」，是一线运维最不能接受的行为。
    """
    suff_cfg = dict((cfg or {}).get("sufficiency") or {})
    min_dur = float(suff_cfg.get("min_duration_s", 10))
    min_streams = int(suff_cfg.get("min_tcp_streams", 3))
    min_rtt = int(suff_cfg.get("min_rtt_samples", 5))

    cap, tcp = features.capture, features.tcp
    reasons: list[str] = []
    args: dict[str, dict] = {}
    needed: list[str] = []

    if cap.packets == 0:
        reasons.append("packets_zero")
        needed.append("collect_again")
        return Sufficiency(ok=False, reasons=tuple(reasons),
                           needed=tuple(dict.fromkeys(needed)), reason_args=args)

    if cap.duration_s and cap.duration_s < min_dur:
        reasons.append("duration_too_short")
        args["duration_too_short"] = {"actual": round(float(cap.duration_s), 1), "need": min_dur}
        needed.append("collect_again")

    if 0 < len(tcp.streams) < min_streams:
        reasons.append("too_few_streams")
        args["too_few_streams"] = {"actual": len(tcp.streams), "need": min_streams}
        needed.append("collect_again")

    if 0 < tcp.rtt.n < min_rtt:
        reasons.append("too_few_rtt")
        args["too_few_rtt"] = {"actual": tcp.rtt.n, "need": min_rtt}
        needed.append("probe_link")

    dns_samples = int((features.dns or {}).get("samples", 0))
    http_requests = int((features.http or {}).get("requests", 0))
    if dns_samples == 0 and http_requests == 0:
        reasons.append("no_app_sample")
        needed.append("probe_link")

    # 「no_app_sample」本身不致命（很多内网场景确实没有 DNS/HTTP），
    # 但「时长不够」和「会话太少」会让任何结论都不可靠。
    fatal = {"packets_zero", "duration_too_short", "too_few_streams"}
    return Sufficiency(
        ok=not any(r in fatal for r in reasons),
        reasons=tuple(reasons),
        needed=tuple(dict.fromkeys(needed)),
        reason_args=args,
    )


# ---------------------------------------------------------------- 分层状态


def _layer_severity(layer: Layer, findings: tuple[Finding, ...]) -> Severity:
    rel = [f.severity for f in findings if f.layer is layer]
    if not rel:
        return Severity.NA
    return min(rel, key=lambda s: {"critical": 0, "warning": 1, "info": 2, "ok": 3, "na": 4}[s.value])


def _measured(layer: Layer, features: Features) -> bool:
    """这一层**有没有样本**。有样本且无命中 → OK；无样本 → NA。

    这一步是「证据充分性」落到每一层的关键：不能让「没测」显示成「正常」。
    """
    tcp = features.tcp
    if layer is Layer.L2:
        return features.has("arp.no_reply")
    if layer is Layer.L3:
        return tcp.rtt.has_sample or features.has("icmp.unreach")
    if layer is Layer.L4:
        return tcp.packets > 0 and tcp.has_streams
    if layer is Layer.L7:
        dns = features.dns or {}
        http = features.http or {}
        return bool(dns.get("samples")) or bool(http.get("requests"))
    return False


def _layer_detail(layer: Layer, features: Features) -> tuple[str, dict]:
    tcp = features.tcp
    if layer is Layer.L2:
        arp = features.arp or {}
        count = len(arp.get("no_reply") or [])
        return ("layer_detail.l2.arp", {"count": count}) if count else ("layer_detail.l2.ok", {})
    if layer is Layer.L3:
        if not tcp.rtt.has_sample:
            return "layer_detail.l3.no_sample", {}
        return "layer_detail.l3.rtt", {"avg": tcp.rtt.avg, "jitter": tcp.rtt.jitter}
    if layer is Layer.L4:
        if tcp.packets == 0:
            return "layer_detail.l4.no_tcp", {}
        if not tcp.has_streams:
            return "layer_detail.l4.insufficient", {"streams": 0}
        return "layer_detail.l4.retrans", {"rate": tcp.retrans_rate}
    if layer is Layer.L7:
        dns = features.dns or {}
        http = features.http or {}
        if not dns.get("samples") and not http.get("requests"):
            return "layer_detail.l7.no_sample", {}
        return "", {}
    return "", {}


def build_layers(features: Features, findings: tuple[Finding, ...],
                 sufficiency: Sufficiency) -> tuple[LayerStatus, ...]:
    out: list[LayerStatus] = []
    for layer in NET_LAYERS:
        severity = _layer_severity(layer, findings)
        if severity is Severity.NA:
            # 没有命中：有样本才算「正常」，没样本就是「无结论」
            severity = Severity.OK if _measured(layer, features) else Severity.NA
        key, args = _layer_detail(layer, features)
        out.append(LayerStatus(
            layer=layer,
            severity=severity,
            detail_key=key,
            detail_args=args,
            finding_ids=tuple(f.rule_id for f in findings if f.layer is layer),
        ))
    return tuple(out)


# ---------------------------------------------------------------- 主判定


def _pick_main(findings: tuple[Finding, ...]) -> Finding | None:
    bad = [f for f in findings
           if f.layer is not Layer.SEC and f.severity in (Severity.CRITICAL, Severity.WARNING)]
    return min(bad, key=lambda f: (f.rank, LAYER_ORDER.get(f.layer, 8), f.rule_id),
               default=None)


def _next_steps(main: Finding | None, sufficiency: Sufficiency,
                has_findings: bool) -> tuple[str, ...]:
    steps: list[str] = []
    steps.extend(sufficiency.needed)
    if main is not None:
        steps.extend(RULE_NEXT_STEPS.get(main.rule_id, ("probe_link",)))
    if not has_findings:
        steps.append("baseline")
    return tuple(dict.fromkeys(steps))


def build(features: Features, findings: tuple[Finding, ...] | list[Finding],
          thresholds: Thresholds | None = None,
          cfg: Mapping | None = None) -> Verdict:
    """汇总。调用方应传**已排序**的 findings（``run_rules`` 已排好）。

    ``thresholds`` 目前只用于未来「按阈值写进 metric」的需求，保留参数以免
    签名再变；``cfg`` 用于读取 ``sufficiency`` 配置。
    """
    findings = tuple(findings)
    sufficiency = assess_sufficiency(features, cfg)
    layers = build_layers(features, findings, sufficiency)
    main = _pick_main(findings)
    sec_hit = any(f.layer is Layer.SEC and f.severity in (Severity.CRITICAL, Severity.WARNING)
                  for f in findings)

    if features.capture.packets == 0:
        level = Severity.NA
        headline_key = "VERDICT.EMPTY"
        args: dict = {}
        impact_key = "impact.collect"
    elif main is not None:
        level = main.severity
        headline_key = f"headline.{main.headline_key or main.rule_id}"
        args = dict(main.metric)
        impact_key = f"impact.{main.category.value}"
    elif sec_hit:
        level = Severity.WARNING
        headline_key = "VERDICT.SEC_ONLY"
        args = {}
        impact_key = "impact.sec_plaintext"
    elif not sufficiency.ok:
        level = Severity.NA
        headline_key = "VERDICT.INSUFFICIENT"
        args = {}
        impact_key = "impact.default"
    else:
        level = Severity.OK
        headline_key = "VERDICT.OK"
        args = {}
        impact_key = "impact.ok"

    return Verdict(
        level=level,
        headline_key=headline_key,
        headline_args=args,
        impact_key=impact_key,
        layers=layers,
        finding_ids=tuple(f.rule_id for f in findings),
        next_step_keys=_next_steps(main, sufficiency, bool(findings)),
        sufficiency=sufficiency,
    )


__all__ = ["NET_LAYERS", "RULE_NEXT_STEPS", "assess_sufficiency",
           "build_layers", "build"]
