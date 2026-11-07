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
    return "\n".join(L)


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
    json_path.write_text(
        json.dumps(
            {
                "summary": result.get("summary", {}),
                "meta": result.get("meta", {}),
                "metrics": result.get("metrics", {}),
                "rows": result.get("rows", []),
                "verdict": verdict_mod.build(result),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"markdown": str(md_path), "json": str(json_path)}


def render_degraded(result: dict) -> str:
    """把 0 包降级结论渲染成 Markdown（结论 + 事实 + 原因 + 建议）。

    与正常诊断报告分开渲染：降级结果没有 ``rows`` / ``verdict``，强行套用
    :func:`render_markdown` 会出现空章节，反而又变成「结果区没有内容」。

    Args:
        result: :func:`diagnose.degraded_empty_capture_result` 的返回值，键含
            ``card_title`` / ``headline`` / ``plain`` / ``link`` / ``capture`` /
            ``reasons`` / ``next_steps`` / ``at``。

    Returns:
        str: Markdown 正文（UTF-8 文本，LF 换行）。
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
    lines = [
        _d("title"),
        "",
        _d("meta_line", mode="单目标诊断（定向抓包）" if cap.get("target")
           else "全网体检（全网扫描）", at=result.get("at") or "-"),
        "",
        _d("section_conclusion"),
        "",
        f"**{result.get('card_title') or result.get('headline') or '降级'}**",
        "",
        str(result.get("plain") or result.get("headline") or ""),
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
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                         encoding="utf-8")
    return {"markdown": str(md_path), "json": str(json_path)}
