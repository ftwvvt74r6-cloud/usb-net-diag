"""报告渲染：分层故障定位（主）+ 完整技术明细（辅）。

排版顺序刻意做成「由浅入深」：
  1 结论        —— 哪一层、哪个协议、多严重，一句话
  2 分层定位表  —— L2/L3/L4/L7 四层的状态与关键指标
  3 问题详解    —— 每条故障：现象 → 影响 → 证据 → 处置
  4 处置步骤    —— 按排查顺序可执行
  5 会话与请求  —— 慢会话、慢请求、DNS 明细，一线可直接定位对端
  6 技术明细    —— 原始观测值，供专业复核

所有静态中文（标题、表头、参考值说明、脚注）都来自 ``core/copy/zh-CN.json``
的 ``report`` / ``state`` section；本模块只保留排版与取数逻辑。
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import verdict as verdict_mod
import evidence as evidence_mod
import conclusion as conclusion_mod

try:                                    # 扁平导入：core/ 在 sys.path 上（runtime / 测试）
    from copytext import text as _copy_text
except ModuleNotFoundError:             # 包导入：仓库根在 sys.path 上
    from core.copytext import text as _copy_text

STATUS_MARK = {"ok": "✅", "warn": "⚠️", "bad": "❌", "na": "—", "insufficient": "❓"}


def _t(key: str, **args) -> str:
    """取报告静态文案（``copy.report`` section）。

    Args:
        key: ``report`` section 内的键。
        **args: ``{name}`` 占位符实参。

    Returns:
        str: 可直接展示的文案；缺 key 时回退成 key 本身。
    """
    return _copy_text("report", key, **args)


def _d(key: str, **args) -> str:
    """取降级结论报告的静态文案（``copy.degraded_report`` section）。

    Args:
        key: ``degraded_report`` section 内的键。
        **args: ``{name}`` 占位符实参。

    Returns:
        str: 可直接展示的文案；缺 key 时回退成 key 本身（绝不抛异常）。
    """
    return _copy_text("degraded_report", key, **args)


def _p(key: str, **args) -> str:
    """取影子探测（探针基线）的静态文案（``copy.probe`` section）。

    Args:
        key: ``probe`` section 内的键。
        **args: ``{name}`` 占位符实参。

    Returns:
        str: 可直接展示的文案；缺 key 时回退成 key 本身或空串。
    """
    return _copy_text("probe", key, default="", **args)


def _pa(key: str, **args) -> str:
    """取路径剖面（MTR）的静态文案（``copy.path`` section）。

    Args:
        key: ``path`` section 内的键。
        **args: ``{name}`` 占位符实参。

    Returns:
        str: 可直接展示的文案；缺 key 时回退成 key 本身或空串。
    """
    return _copy_text("path", key, default="", **args)


def _path_verdict_text(profile: dict) -> str:
    """把路径结论机器码翻成一句中文（``copy.path.verdict_*``）。

    Args:
        profile: ``meta["path_profile"]``；读 ``verdict_key``、``unreachable`` 与
            ``method``。tracert 降级时没有 TCP 重扫，``PATH.ICMP_FILTERED`` 要用
            单独的文案，不能写「本次已改用 TCP 探测」。

    Returns:
        str: 结论句；未知机器码返回空串（渲染层不猜）。
    """
    code = str(profile.get("verdict_key") or "")
    keys = {
        "PATH.OK": "verdict_ok",
        "PATH.LOCAL_SIDE": "verdict_local_side",
        "PATH.TRANSPORT_NET": "verdict_transport_net",
        "PATH.SERVER_EDGE": "verdict_server_edge",
        "PATH.ICMP_FILTERED": "verdict_icmp_filtered",
        "PATH.NO_DATA": ("verdict_unreachable" if profile.get("unreachable")
                         else "verdict_no_data"),
    }
    key = keys.get(code)
    if key == "verdict_icmp_filtered" and str(profile.get("method") or "icmp") == "tracert":
        key = "verdict_icmp_filtered_tracert"
    return _pa(key) if key else ""


def _path_method_text(profile: dict) -> str:
    """探测方式标注：scapy ICMP / TCP 降级 / 系统 tracert。

    Args:
        profile: ``meta["path_profile"]``；读 ``method`` / ``icmp_filtered``。

    Returns:
        str: 可直接展示的一行。``method == "tracert"`` 时优先写「基于系统 tracert，
            样本数 3」——即使同时判定 ICMP 被过滤，数据源仍是 tracert，不能写成
            「改用 TCP 探测」（tracert 降级下没有 TCP 重扫）。
    """
    method = str(profile.get("method") or "icmp")
    if method == "tracert":
        return _pa("method_tracert")
    if method == "tcp" or profile.get("icmp_filtered"):
        return _pa("method_tcp")
    return _pa("method_icmp")


def _path_status_text(status: str) -> str:
    """单跳状态机器码（ok/degraded/loss/...）→ 中文文案。

    Args:
        status: ``HopStatus`` 的机器码（``ok`` / ``degraded`` / ``loss`` ……）。

    Returns:
        str: 可直接展示的状态名；未知值原样返回。
    """
    key = "status_" + str(status or "")
    text = _pa(key)
    return text or str(status or "-")


def _render_path_profile(profile: dict) -> list[str]:
    """渲染「路径剖面」区块（只在 ``meta.path_profile`` 有逐跳数据时调用）。

    区块放在「探针基线」之后：先看探针的两侧对照，再看「路径上第几跳开始坏」。
    没有 RTT 样本的跳写「未探到」，**不写 0ms**；``completed=False``（时间预算
    用完/被抓包取消）必须明说「探测未完成」，不能让人把残缺路径当完整结论。

    Args:
        profile: ``meta["path_profile"]``。

    Returns:
        list[str]: 报告行（已含结尾空行）；没有逐跳数据时返回空列表（不输出空区块）。
    """
    hops = profile.get("hops") or []
    if not hops:
        return []
    lines = [_pa("section_title"), ""]
    rows = []
    template = _pa("rtt_value")
    if "{" not in template:
        template = "{min}/{avg}/{max} ms"
    for hop in hops:
        n = int(hop.get("rtt_n") or 0)
        if n > 0:
            try:
                rtt = template.format(min=hop.get("rtt_min_ms"),
                                      avg=hop.get("rtt_avg_ms"),
                                      max=hop.get("rtt_max_ms"))
            except (KeyError, IndexError, ValueError):
                rtt = template
            jitter = f"{hop.get('jitter_ms')}ms"
        else:
            rtt = _pa("no_sample")
            jitter = _pa("no_sample")
        loss = hop.get("loss_pct")
        rows.append([
            hop.get("ttl", "-"),
            hop.get("ip") or _pa("ip_unknown"),
            hop.get("sent", 0),
            hop.get("lost", 0),
            "-" if loss is None else f"{loss:g}%",
            rtt,
            jitter,
            _path_status_text(str(hop.get("status") or "")),
        ])
    lines.append(_table(
        [_pa("th_ttl"), _pa("th_ip"), _pa("th_sent"), _pa("th_lost"),
         _pa("th_loss"), _pa("th_rtt"), _pa("th_jitter"), _pa("th_status")],
        rows))
    lines.append("")
    lines.append(_pa("target_line", target=profile.get("target", "-"),
                     ip=profile.get("target_ip", "-"),
                     probes=profile.get("probes_sent", 0)))
    lines.append(_path_method_text(profile))
    verdict = _path_verdict_text(profile)
    if verdict:
        lines.append(verdict)
    # R5：中间跳有丢包/RTT 异常，但劣化没有持续到目标或最后响应跳。企业网里路由
    # 设备常对 TTL 回复限速，单看中间跳直接断言「承载网故障」会误报 —— 该提示只在
    # 没有持续劣化段（degraded_ttl 为空）时出现，和有劣化结论的路径不混着说。
    middle_ttls = list(profile.get("middle_loss_ttls") or [])
    if profile.get("middle_loss_suspected") and profile.get("degraded_ttl") is None:
        lines.append(_pa("middle_loss_hint",
                         ttls="、".join(str(ttl) for ttl in middle_ttls) or "-"))
    if profile.get("degraded_ttl") is not None:
        lines.append(_pa("degraded_line", ttl=profile.get("degraded_ttl")))
        if profile.get("baseline_ms") is not None:
            lines.append(_pa("baseline_line", ms=profile.get("baseline_ms")))
    if profile.get("reached_target"):
        reached_ttl = next((hop.get("ttl") for hop in hops
                            if hop.get("ip") == profile.get("target_ip")), "-")
        lines.append(_pa("reached_line", ttl=reached_ttl))
    if not profile.get("completed", True):
        lines.append(_pa("not_completed_line"))
    lines.append(_pa("excluded_icmp", count=profile.get("excluded_icmp", 0)))
    if profile.get("tun_suspected"):
        lines.append(_pa("tun_hint"))
    lines.append("")
    return lines


def _state_text(status: str) -> str:
    """层状态机器码（ok/warn/bad/na/insufficient）→ 中文文案。"""
    return _copy_text("state", status, default=status)


def _esc(v) -> str:
    s = "" if v is None else str(v)
    return s.replace("|", "\\|").replace("\n", " ").strip()


def _table(head: list[str], body: list[list]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    for row in body:
        out.append("| " + " | ".join(_esc(c) for c in row) + " |")
    return "\n".join(out)


def _ms(v) -> str:
    try:
        return f"{float(v):.0f}ms"
    except (TypeError, ValueError):
        return "-"


def _opt(v, has: bool) -> str:
    """没有样本时显示 -，避免把「没测到」误读成「0ms 很快」。"""
    return _ms(v) if has else "-"


def _probe_role_text(role: str) -> str:
    """把探针角色机器码（gateway/dns/target）翻成中文（``copy.probe.role_*``）。

    Args:
        role: 角色机器码。

    Returns:
        str: 可直接展示的角色名；文案缺失时回退成 key（与全项目文案约定一致）。
    """
    return _p("role_" + str(role or "target"))


def _probe_rtt_text(item: dict) -> str:
    """探针 RTT 单元格：有样本写「最小/平均/最大」，没有样本写「未探到」。

    Args:
        item: :func:`core.pathprobe.aggregate_records` 产出的单个角色聚合项。

    Returns:
        str: 可直接展示的 RTT 短语；``n == 0`` 时绝不写 0ms（没有样本 ≠ 很快）。
    """
    if int(item.get("n") or 0) <= 0:
        return _p("no_sample")
    template = _p("rtt_value")
    if "{" not in template:
        template = "{min}/{avg}/{max} ms"
    try:
        return template.format(min=item.get("rtt_min_ms"),
                               avg=item.get("rtt_avg_ms"),
                               max=item.get("rtt_max_ms"))
    except (KeyError, IndexError, ValueError):
        return template


def _probe_contrast_text(contrast: dict) -> str:
    """方向对照一句话（机器码 → copy.probe.contrast_* 文案）。

    Args:
        contrast: ``verdict.probe_contrast``；含 ``code`` / ``gateway_loss_pct`` /
            ``target_loss_pct`` / ``confidence``。

    Returns:
        str: 可直接展示的中文（措辞含「疑似」由 copy 表保证）；未知 code 返回空串。
            ``loss_pct`` 为 ``None``（该侧没有探针样本）时显示 ``-``，不写 ``None``。
    """
    code = str(contrast.get("code") or "")
    keys = {
        "PROBE.CONTRAST.LOCAL_SIDE": "contrast_local_side",
        "PROBE.CONTRAST.TARGET_SIDE": "contrast_target_side",
        "PROBE.CONTRAST.BOTH_SIDES": "contrast_both_sides",
        "PROBE.CONTRAST.INSUFFICIENT": "contrast_insufficient",
    }
    key = keys.get(code)
    if not key:
        return ""
    gateway = contrast.get("gateway_loss_pct")
    target = contrast.get("target_loss_pct")
    return _p(key, gateway="-" if gateway is None else gateway,
              target="-" if target is None else target,
              confidence=contrast.get("confidence", "-"))


def _render_probe_baseline(baseline: dict, vd: dict) -> list[str]:
    """渲染「探针基线」区块（只在 ``meta.probe_baseline`` 存在时调用）。

    区块头在报告「关键指标」之后：先看业务指标，再看「探针自己的对照基线」。
    0 个 RTT 样本的角色写「未探到」，绝不写 0ms / 正常。收发计数是**模块自记**：
    固定写「发出 / 收到 / 超时」三值；「已从业务统计排除 N 个标记探针包」只在
    N>0 时出现 —— 抓包过滤器正常生效时 N 恒为 0，打印「排除 0」没有信息量。

    Args:
        baseline: ``meta["probe_baseline"]``。
        vd: 判定结果（读可选的 ``probe_contrast``）。

    Returns:
        list[str]: 报告行（已含结尾空行）；空数据时返回空列表。
    """
    roles = baseline.get("roles") or []
    if not roles:
        return []
    lines = [_p("section_title"), ""]
    rows = []
    for item in roles:
        jitter = (f"{item.get('jitter_ms')}ms" if int(item.get("n") or 0) > 0
                  else _p("no_sample"))
        loss = item.get("loss_pct")
        rows.append([
            _probe_role_text(item.get("role", "")),
            item.get("target", "-"),
            item.get("sent", 0),
            item.get("recv", 0),
            "-" if loss is None else f"{loss:g}%",
            _probe_rtt_text(item),
            jitter,
        ])
    lines.append(_table(
        [_p("th_role"), _p("th_target"), _p("th_sent"), _p("th_recv"),
         _p("th_loss"), _p("th_rtt"), _p("th_jitter")],
        rows))
    lines.append("")
    sent = int(baseline.get("sent") or 0)
    recv = int(baseline.get("recv") or 0)
    try:
        timeout = int(baseline.get("timeout"))
    except (TypeError, ValueError):
        # 旧载荷没有 timeout 键：用模块自记的同一口径推出来（sent - recv）。
        timeout = max(0, sent - recv)
    lines.append(_p("summary_line", sent=sent, recv=recv, timeout=timeout))
    excluded = int(baseline.get("excluded_packets") or 0)
    if excluded > 0:
        lines.append(_p("excluded", count=excluded))
    contrast = vd.get("probe_contrast") if isinstance(vd, dict) else None
    if isinstance(contrast, dict):
        text = _probe_contrast_text(contrast)
        if text:
            lines.append(text)
    lines.append("")
    return lines


def render_markdown(result: dict, vd: dict | None = None) -> str:
    """把一次诊断结果渲染成 Markdown 报告。

    Args:
        result: ``analyze()``/``run_scan()`` 的结果字典。
        vd: 判定结果；省略时现场 ``verdict.build(result)`` 算一遍（避免调用方重复计算）。

    Returns:
        str: 完整 Markdown 正文 —— 结论段、分层定位、问题清单（现象/处理/依据）、
            会话表与技术明细。
    """
    vd = vd or result.get("verdict") or verdict_mod.build(result)
    meta = result.get("meta", {})
    rows = result.get("rows", [])
    m = result.get("metrics") or {}
    summary = result.get("summary", {})
    target = summary.get("target", _t("all_network"))

    L: list[str] = [
        _t("doc_title"),
        "",
        _t("target_line", target=target, pcap=meta.get("pcap_name", "")),
        _t("duration_line", duration=meta.get("duration", 0), packets=meta.get("packets", 0),
           streams=meta.get("streams_total", 0)),
        _t("generated_line", generated=meta.get("generated_at", ""),
           iface=meta.get("interface", "-")),
        "",
        _t("reading_order"),
        _t("layer_order"),
        "",
    ]

    # ---------------- 一、故障定位 ----------------
    # 「证据不足」必须显示成独立档（❓），不能落进 ✅/「正常」：判定层已经把
    # 「没样本」和「没问题」分开，渲染层再把它们盖回绿色勾，等于白做。
    level_key = {"严重": "bad", "警告": "warn", "正常": "ok",
                 "证据不足": "insufficient"}.get(vd.get("level", ""), "ok")
    L += [_t("section_verdict"), "", f"### {STATUS_MARK.get(level_key, '')} {vd['headline']}", ""]
    # E1：结论句 + 依据 + 本次覆盖 / 明确未覆盖 + 置信等级/关键边界，紧跟在标题之后。
    # 只**追加行**、不改上面任何一行：红线要求「去掉新增行后与基线逐字节相等」。
    conclusion_block = conclusion_mod.build_conclusion(result, vd)
    rendered_conclusion = conclusion_mod.render_conclusion_markdown(conclusion_block)
    if rendered_conclusion.strip():
        L += rendered_conclusion.rstrip("\n").split("\n")
        L.append("")
    L.append(_t("fault_layer_line", layer=vd.get("layer", "—"),
                impact=vd.get("impact", "—")))
    L.append("")
    for line in (vd.get("plain") or "").split("\n"):
        if line.strip():
            L.append(line.strip())
    L.append("")

    L += [_t("layers_heading"), ""]
    L.append(_table(
        [_t("th_layer"), _t("th_protocol"), _t("th_state"), _t("th_metric")],
        [[f"{x['id']} {x['name']}", x["protocol"],
          f"{STATUS_MARK.get(x['status'], '')} {_state_text(x['status'])}",
          x["detail"]] for x in vd.get("layers", [])]))
    L.append("")

    L += [_t("metrics_heading"), ""]
    L.append(_table(
        [_t("th_name"), _t("th_value"), _t("th_ref"), _t("th_desc")],
        [
            [_t("m_conn_fail_name"),
             _t("m_conn_fail_value", count=m.get("conn_fail", 0)),
             "0", _t("m_conn_fail_desc")],
            [_t("m_hs_name"),
             _opt(m.get("hs_avg_ms"), m.get("hs_samples", 0) > 0),
             _t("m_hs_ref"), _t("m_hs_desc")],
            [_t("m_rtt_name"),
             f"{_opt(m.get('rtt_avg_ms'), m.get('rtt_samples', 0) > 0)} / P95 "
             f"{_opt(m.get('rtt_p95_ms'), m.get('rtt_samples', 0) > 0)}",
             _t("m_rtt_ref"), _t("m_rtt_desc", samples=m.get("rtt_samples", 0))],
            [_t("m_jitter_name"),
             _opt(m.get("rtt_jitter_ms"), m.get("rtt_samples", 0) > 0),
             "< 30ms", _t("m_jitter_desc")],
            [_t("m_retrans_name"), f"{m.get('retrans_rate', 0):.2f}%",
             "< 0.5%", _t("m_retrans_desc")],
            [_t("m_ooo_name"),
             f"{m.get('ooo_rate', 0):.2f}% / {m.get('dup_ack_rate', 0):.2f}%",
             "< 0.5%", _t("m_ooo_desc")],
            [_t("m_dns_name"),
             _t("m_dns_value",
                latency=_opt(m.get("dns_avg_ms"), m.get("dns_samples", 0) > 0),
                rate=m.get("dns_fail_rate", 0)),
             _t("m_dns_ref"), _t("m_dns_desc", samples=m.get("dns_samples", 0))],
            [_t("m_http_name"),
             f"{_opt(m.get('http_avg_ms'), m.get('http_samples', 0) > 0)} / P95 "
             f"{_opt(m.get('http_p95_ms'), m.get('http_samples', 0) > 0)}",
             "< 800ms", _t("m_http_desc")],
            [_t("m_tput_name"), f"{m.get('throughput_mbps', 0):.2f} Mbps",
             _t("m_tput_ref"), _t("m_tput_desc")],
        ]))
    L.append("")

    # ---------------- 影子探测基线（只有实时 + 开了探针才出现） ----------------
    # 离线分析 / 关闭探针时 meta 里没有这个键 → 一行都不加，保证 20 产物逐字节不变。
    baseline = meta.get("probe_baseline")
    if isinstance(baseline, dict):
        L += _render_probe_baseline(baseline, vd)

    # ---------------- 路径剖面（只有实时 + 有目标 + MTR 有数据才出现） ----------------
    # 与「探针基线」同一口径：没有 meta.path_profile 就一行不加（离线 20 产物红线）。
    path_profile = meta.get("path_profile")
    if isinstance(path_profile, dict):
        L += _render_path_profile(path_profile)

    # ---------------- 二、问题详解 ----------------
    L += [_t("section_points"), ""]
    if not vd.get("points"):
        L += [_t("no_points"), ""]
    for i, p in enumerate(vd.get("points", []), 1):
        L.append(f"### {i}. {p['title']}（{p['severity']}）")
        L.append("")
        L.append(_t("point_layer", layer=p["layer"], protocol=p["protocol"]))
        L.append(_t("point_plain", plain=p["plain"]))
        L.append(_t("point_proof", proof=p["proof"]))
        L.append(_t("point_action", action=p["action"]))
        L.append("")

    # ---------------- 三、处置步骤 ----------------
    L += [_t("section_steps"), ""]
    for i, s in enumerate(vd.get("next_steps") or [], 1):
        L.append(f"{i}. {s}")
    L.append("")

    # ---------------- 四、会话明细 ----------------
    streams = meta.get("streams_top") or []
    L += [_t("section_streams"), ""]
    if streams:
        L.append(_table(
            ["Stream", _t("th_client"), _t("th_server"), _t("th_proto"),
             _t("th_pkt_bytes"), _t("th_handshake"), _t("th_rtt"), _t("th_retrans"),
             _t("th_think"), _t("th_flags"), _t("th_frame")],
            [[f"#{s['stream']}", f"{s['client']}:{s['sport']}", f"{s['server']}:{s['dport']}",
              s.get("app", "-"), f"{s['packets']} / {s['bytes']}",
              _ms(s.get("handshake_ms")) if s.get("handshake_ms") is not None else "-",
              _ms(s.get("rtt_avg")) if s.get("rtt_avg") else "-",
              s.get("retrans", 0),
              _ms(s.get("think_ms")) if s.get("think_ms") else "-",
              "、".join(s.get("flags") or []) or "—",
              ",".join(f"#{f}" for f in (s.get("frames") or [])[:2]) or "-"]
             for s in streams]))
    else:
        L.append(_t("no_tcp"))
    L.append("")

    # ---------------- 五、慢请求与解析明细 ----------------
    L += [_t("section_app"), ""]
    dns_detail = meta.get("dns_detail") or []
    http_slow = meta.get("http_slow") or []
    if dns_detail:
        L += [_t("h_dns"), ""]
        L.append(_table([_t("th_domain"), _t("th_dns_time"), _t("th_rcode"),
                         _t("th_dns_server"), _t("th_frame")],
                        [[d["name"], _ms(d["ms"]), _rcode_text(d["rcode"]),
                          d.get("server", "-"), f"#{d['frame']}"] for d in dns_detail[:10]]))
        L.append("")
        if meta.get("dns_servers"):
            L.append(_t("dns_servers_prefix") + "，".join(
                _t("dns_servers_item", ip=ip, count=n) for ip, n in meta["dns_servers"]))
            L.append("")
    if http_slow:
        L += [_t("h_http"), ""]
        L.append(_table([_t("th_method"), "Host", "URI", _t("th_status"), _t("th_cost"),
                         "Stream", _t("th_frame")],
                        [[h.get("method", "-"), h["host"], h["uri"] or "/", h["code"],
                          _ms(h["ms"]), f"#{h['stream']}", f"#{h['frame']}"] for h in http_slow]))
        L.append("")
    if meta.get("icmp_detail"):
        L += [_t("h_icmp"), ""]
        L.append(_table([_t("th_type"), _t("th_meaning"), _t("th_from_to"), _t("th_frame")],
                        [[f"type {i['type']}/code {i['code']}", i["desc"],
                          f"{i['src']} → {i['dst']}", f"#{i['frame']}"]
                         for i in meta["icmp_detail"]]))
        L.append("")
    if not (dns_detail or http_slow or meta.get("icmp_detail")):
        L += [_t("no_app_detail"), ""]

    # ---------------- 六、安全观察 ----------------
    sec_rows = [r for r in rows if r.get("layer") == "安全观察"
                and r.get("severity") in ("严重", "警告", "提示")]
    if sec_rows:
        L += [_t("section_security"), "", _t("note_security"), ""]
        L.append(_table([_t("th_category"), _t("th_finding"), _t("th_severity"),
                         _t("th_evidence"), _t("th_advice")],
                        [[r["category"], r["finding"], r["severity"], r["evidence"], r["advice"]]
                         for r in sec_rows]))
        L.append("")
    else:
        L += [_t("section_security"), "", _t("no_security"), ""]

    # ---------------- 七、技术明细 ----------------
    L += [_t("section_tech"), "", _t("h_overview"), ""]
    L.append(_table([_t("th_item"), _t("th_val")], [
        [_t("tech_pcap"), meta.get("pcap_name", "")],
        [_t("tech_iface"), f"{meta.get('interface', '-')} / {meta.get('bpf', '-')}"],
        [_t("tech_bytes"), f"{meta.get('packets', 0)} / {meta.get('bytes', 0)}"],
        [_t("tech_duration"), _t("tech_duration_value", seconds=meta.get("duration", 0))],
        [_t("tech_tcp"), f"{meta.get('tcp_packets', 0)} / {meta.get('tcp_data_packets', 0)}"],
        [_t("tech_streams"), meta.get("streams_total", 0)],
        ["SYN / SYN-ACK", f"{meta.get('syn', 0)} / {meta.get('synack', 0)}"],
        [_t("tech_retrans"), f"{meta.get('retrans', 0)} / {meta.get('ooo', 0)} / "
                             f"{meta.get('dup_ack', 0)}"],
        [_t("tech_window"), f"{meta.get('rst', 0)} / {meta.get('zero_win', 0)}"],
        [_t("tech_dns"),
         f"{meta.get('dns_total', 0)} / {meta.get('dns_resp', 0)} / {meta.get('nxdomain', 0)}"],
        [_t("tech_http"), f"{meta.get('http_req', 0)} / {meta.get('http_err5', 0)}"],
        [_t("tech_external"), meta.get("external_ips", 0)],
        ["tshark", meta.get("tshark_path", "")],
    ]))
    L.append("")

    if meta.get("proto_mix"):
        L += [_t("h_proto_mix"), ""]
        L.append(_table([_t("th_protocol"), _t("th_packets")],
                        [[x["proto"], x["count"]] for x in meta["proto_mix"]]))
        L.append("")

    if meta.get("dns_top"):
        L += [_t("h_dns_top"), ""]
        nx = dict(meta.get("nx_top") or [])
        L.append(_table([_t("th_domain"), _t("th_queries"), _t("th_failed")],
                        [[n, c, nx.get(n, 0)] for n, c in meta["dns_top"]]))
        L.append("")

    if meta.get("http_codes"):
        L += [_t("h_http_codes"), ""]
        L.append(_table([_t("th_status"), _t("th_count")],
                        [[c, n] for c, n in meta["http_codes"]]))
        L.append("")

    if meta.get("ext_detail"):
        L += [_t("h_external"), ""]
        L.append(_table([_t("th_external_ip"), _t("th_packets"), _t("th_ports"),
                         _t("th_risk_ports")],
                        [[e["ip"], e["packets"], ",".join(str(p) for p in e.get("ports", [])) or "-",
                          ",".join(str(p) for p in e.get("risk_ports", [])) or "-"]
                         for e in meta["ext_detail"]]))
        L.append("")

    if meta.get("cred_events"):
        L += [_t("h_credentials"), ""]
        L.append(_table([_t("th_cred_type"), _t("th_where"), _t("th_detail"), _t("th_frame_no")],
                        [[c["type"], c["where"], c["detail"], f"#{c['frame']}"]
                         for c in meta["cred_events"]]))
        L.append("")

    # ---------------- 八、机器摘要 ----------------
    L += [_t("section_machine"), "",
          _t("summary_line", critical=summary.get("critical_count", 0),
             warning=summary.get("warning_count", 0)),
          "", "```json", json.dumps(summary, ensure_ascii=False, indent=2), "```", ""]
    # ---------------- 九、取证请求单（结论驱动） ----------------
    # 只有「有相关维度」时才追加；「正常且没有问题」不输出（UI 仍提供通用空白版）。
    # 这是本批唯一会改变离线报告的区块（用户已定稿的声明例外）：它**追加在全文末尾**，
    # 因此旧内容逐字节不变——去掉「空行 + 区块」即与 main 的报告逐字节相等。
    checklist = evidence_mod.build_checklist(result, verdict=vd)
    evidence_block = evidence_mod.render_checklist_markdown(checklist)
    if evidence_block:
        L += ["", evidence_block.rstrip("\n")]
    # 与 main 的报告保持一致：输出总以单个 \n 结尾（追加区块后尤其容易漏，
    # 会让 git diff 出现 "\ No newline at end of file" 的额外噪声）。
    text = "\n".join(L)
    return text if text.endswith("\n") else text + "\n"


def _rcode_text(code: str) -> str:
    """DNS 响应码 → 中文说明（文案来自 copy 表 ``report.rcode_*``）。"""
    key = {"0": "rcode_ok", "2": "rcode_servfail", "3": "rcode_nxdomain",
           "5": "rcode_refused", "1": "rcode_format"}.get(str(code))
    return _t(key) if key else f"rcode {code}"


def save(result: dict, out_dir: Path) -> dict:
    """把报告写成 ``.md`` 与 ``.json`` 两份。

    Args:
        result: 诊断结果字典。
        out_dir: 输出目录（通常是 ``reports/``）。

    Returns:
        dict: 键 ``md`` / ``json``（绝对路径字符串）。

    Note:
        JSON 侧**只挑** ``summary`` / ``meta`` / ``metrics`` / ``rows`` / ``verdict`` 五块写盘，
        因此新增的 ``findings_v2`` / ``provenance`` 不会改变已提交的报告快照。
        E1 起 ``verdict`` 块新增 ``confidence`` / ``basis`` / ``coverage`` /
        ``not_covered`` 四个键（声明例外）；``confidence_level`` / ``key_limit``
        只在渲染层出现，**不落库**。
        文件名取自抓包文件名，并过滤掉路径分隔符等危险字符。

        落盘前把 ``meta.tshark_path`` 替换成固定占位：绝对路径是机器相关键，
        换机器重跑会让 ``git diff reports/`` 一直脏（``analyze()`` 的原值不动，
        只在落盘时替换）。
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # 浅拷贝 result 与 meta 再归一化：render_markdown / verdict.build 消费的都是归一化后的值。
    result = dict(result)
    meta = dict(result.get("meta") or {})
    meta["tshark_path"] = verdict_mod.TSHARK_PATH_PLACEHOLDER
    result["meta"] = meta
    raw = Path(str(meta.get("pcap_name") or "report")).stem
    # 文件名来自抓包文件名，可能是上传的任意名字：过滤掉路径分隔符等危险字符
    stem = "".join(c for c in raw if c.isalnum() or c in "._-") or "report"
    md_path = out_dir / f"{stem}.md"
    json_path = out_dir / f"{stem}.json"
    md_path.write_text(render_markdown(result), encoding="utf-8")
    verdict_data = verdict_mod.build(result)
    conclusion_block = conclusion_mod.build_conclusion(result, verdict_data)
    # E1：verdict 块只新增 confidence / basis / coverage / not_covered 四键。
    # confidence_level 与 key_limit 是渲染期派生值，**不许落库**（E-IMPL-SPEC §1）。
    verdict_data["confidence"] = conclusion_block["confidence"]
    verdict_data["basis"] = conclusion_block["basis"]
    verdict_data["coverage"] = conclusion_block["coverage"]
    verdict_data["not_covered"] = conclusion_block["not_covered"]
    json_path.write_text(
        json.dumps(
            {
                "summary": result.get("summary", {}),
                "meta": result.get("meta", {}),
                "metrics": result.get("metrics", {}),
                "rows": result.get("rows", []),
                "verdict": verdict_data,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"markdown": str(md_path), "json": str(json_path)}


def _degraded_conclusion(result: dict) -> dict:
    """为 0 包降级结果构造结论边界对象（B1：降级导出也必须带边界/置信）。

    降级结果没有 ``meta`` / ``rows`` / ``verdict``，不能直接喂给
    :func:`core.conclusion.build_conclusion`；这里用 ``capture`` / ``target`` /
    ``link`` / ``duration`` 已有事实拼一个最小输入，标题取 ``card_title``
    （没有时退 ``headline``）。

    ``meta.packets`` 固定为 **0**：降级 = 没有有效样本，置信度由同一个推导器
    自动落到 0.3（低），**不手工写置信度**。也正因如此，这里绝不伪造
    ``probe_baseline``——真实数据都没有，不能凭空造出「高置信」的对照条件。

    Args:
        result: :func:`diagnose.degraded_empty_capture_result` 的返回值。

    Returns:
        dict: :func:`core.conclusion.build_conclusion` 的 7 键对象；结果不是
            字典或字段缺失时同样返回可渲染对象（缺项由渲染器降级为「未知」）。
    """
    result = result if isinstance(result, dict) else {}
    cap = result.get("capture")
    cap = cap if isinstance(cap, dict) else {}
    link = result.get("link")
    link = link if isinstance(link, dict) else {}
    target = str(cap.get("target") or "").strip() or "全网"
    duration = cap.get("duration") or 0
    headline = str(result.get("card_title") or result.get("headline") or "").strip()
    minimal = {
        "meta": {
            "packets": 0,
            "streams_total": 0,
            "duration": duration,
            "target": target,
        },
        "summary": {"target": target},
        "rows": [],
        # 保留降级特有事实（链路探测）：当前结论模板只消费 meta，但把
        # capture/link 一起传入，避免将来扩展依据时又出现第二个取数出处。
        "capture": dict(cap),
        "link": dict(link),
    }
    return conclusion_mod.build_conclusion(minimal, {"headline": headline})


def render_degraded(result: dict) -> str:
    """把 0 包降级结论渲染成 Markdown（结论 + 边界 + 事实 + 原因 + 建议）。

    与正常诊断报告分开渲染：降级结果没有 ``rows`` / ``verdict``，强行套用
    :func:`render_markdown` 会出现空章节，反而又变成「结果区没有内容」。

    B1 起在同一节里输出统一的「结论与边界」整块（结论 / 依据 / 本次覆盖 /
    明确未覆盖 / 置信等级+关键边界）：降级报告也是可下载、可归档的导出路径，
    按 E-SPEC §1-四不能只给结论不给边界。原有一、二、三、四节的字段含义与
    顺序不变，结论块是纯插入。

    Args:
        result: :func:`diagnose.degraded_empty_capture_result` 的返回值，键含
            ``card_title`` / ``headline`` / ``plain`` / ``link`` / ``capture`` /
            ``reasons`` / ``next_steps`` / ``at``。

    Returns:
        str: Markdown 正文（UTF-8 文本，LF 换行），含同一渲染器生成的
            「### 结论与边界」整块。
    """
    link = result.get("link") or {}
    cap = result.get("capture") or {}
    via = str(link.get("via") or "")
    if via == "target":
        link_text = _d("link_target", host=str(link.get("host") or "-"))
    elif via == "gateway":
        link_text = _d("link_gateway", host=str(link.get("host") or "-"))
    else:
        link_text = "-"
    if link.get("avg_ms") is not None:
        link_text += (f"；RTT 平均 {link.get('avg_ms')} ms / 抖动 "
                      f"{link.get('jitter_ms')} ms / {_d('field_loss')} "
                      f"{link.get('loss_pct')}%")
    reasons = [f"{i}. {r}" for i, r in enumerate(result.get("reasons") or [], 1)]
    steps = [f"{i}. {s}" for i, s in enumerate(result.get("next_steps") or [], 1)]
    # F1：0 包降级路径的 capture.target 用「全网」表示没设目标（见 diagnose 降级卡），
    # 非空 ≠ 单目标。旧实现只判真值，把全网体检误写成「单目标诊断」。
    target_text = str(cap.get("target") or "").strip()
    degraded_mode = ("单目标诊断" if target_text and target_text != "全网" else "全网体检")
    # B1：与正常报告/UI/MCP 同一 build_conclusion + 同一渲染器。降级结果没有
    # verdict/rows，用 capture/target/link/duration 拼最小输入，置信度自动 0.3/低。
    conclusion_block = conclusion_mod.render_conclusion_markdown(
        _degraded_conclusion(result)).rstrip("\n")
    lines = [
        _d("title"),
        "",
        _d("meta_line", mode=degraded_mode, at=result.get("at") or "-"),
        "",
        _d("section_conclusion"),
        "",
        f"**{result.get('card_title') or result.get('headline') or '降级'}**",
        "",
        str(result.get("plain") or result.get("headline") or ""),
        "",
        conclusion_block,
        "",
        _d("section_facts"),
        "",
        f"- {_d('field_target')}：{cap.get('target') or '全网'}",
        f"- {_d('field_interface')}：{cap.get('interface') or '-'}",
        f"- {_d('field_duration')}：{cap.get('duration') or 0} 秒",
        f"- {_d('field_bpf')}：`{cap.get('bpf') or '无（全网）'}`",
        f"- {_d('field_link')}：{link_text}",
        "",
        _d("section_reasons"),
        "",
        *(reasons or ["-"]),
        "",
        _d("section_steps"),
        "",
        *(steps or ["-"]),
        "",
        _d("footer"),
        "",
    ]
    return "\n".join(lines)


def save_degraded(result: dict, out_dir: Path) -> dict:
    """把 0 包降级结论落盘成 ``.md`` + ``.json``（复审遗留 #7）。

    路测要求：降级卡不能只活在界面上，历史报告 / 导出诊断包里也要能查到这次
    结论。文件名带时间戳，不覆盖任何既有报告。

    B1 起 JSON 与 md 同步携带同一结论边界对象（``conclusion`` / ``basis`` /
    ``coverage`` / ``not_covered`` / ``confidence`` / ``confidence_level`` /
    ``key_limit``）。这是**独立导出**，允许出现渲染期派生字段；普通
    :func:`save` 的五块报告 JSON 约定不变（仍不写 ``confidence_level`` /
    ``key_limit``）。

    Args:
        result: :func:`diagnose.degraded_empty_capture_result` 的返回值。
        out_dir: 输出目录（通常是 ``reports/``）。

    Returns:
        dict: 键 ``markdown`` / ``json``（绝对路径字符串）。
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    md_path = out_dir / f"degraded_{stamp}.md"
    json_path = out_dir / f"degraded_{stamp}.json"
    md_path.write_text(render_degraded(result), encoding="utf-8")
    block = _degraded_conclusion(result)
    payload = {
        "kind": result.get("kind", ""),
        "card_title": result.get("card_title", ""),
        "headline": result.get("headline", ""),
        "plain": result.get("plain", ""),
        "capture": result.get("capture", {}),
        "link": result.get("link", {}),
        "reasons": result.get("reasons", []),
        "next_steps": result.get("next_steps", []),
        "generated_at": result.get("at", ""),
        # B1：降级导出与 md 用同一结论对象；字段含义与 CLI/UI 的 7 键一致。
        "conclusion": block["conclusion"],
        "basis": block["basis"],
        "coverage": block["coverage"],
        "not_covered": block["not_covered"],
        "confidence": block["confidence"],
        "confidence_level": block["confidence_level"],
        "key_limit": block["key_limit"],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                         encoding="utf-8")
    return {"markdown": str(md_path), "json": str(json_path)}
