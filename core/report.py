"""报告渲染：分层故障定位（主）+ 完整技术明细（辅）。

排版顺序刻意做成「由浅入深」：
  1 结论        —— 哪一层、哪个协议、多严重，一句话
  2 分层定位表  —— L2/L3/L4/L7 四层的状态与关键指标
  3 问题详解    —— 每条故障：现象 → 影响 → 证据 → 处置
  4 处置步骤    —— 按排查顺序可执行
  5 会话与请求  —— 慢会话、慢请求、DNS 明细，一线可直接定位对端
  6 技术明细    —— 原始观测值，供专业复核
"""
from __future__ import annotations

import json
from pathlib import Path

import verdict as verdict_mod

STATUS_TEXT = {"ok": "正常", "warn": "注意", "bad": "异常", "na": "无样本",
               "insufficient": "证据不足"}
STATUS_MARK = {"ok": "✅", "warn": "⚠️", "bad": "❌", "na": "—", "insufficient": "❓"}


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
    target = summary.get("target", "全网")

    L: list[str] = [
        "# 网络故障诊断报告",
        "",
        f"- 诊断目标：`{target}`　抓包文件：`{meta.get('pcap_name', '')}`",
        f"- 抓包时长：{meta.get('duration', 0)} 秒　报文 {meta.get('packets', 0)} 个　"
        f"TCP 会话 {meta.get('streams_total', 0)} 个",
        f"- 生成时间：{meta.get('generated_at', '')}　采集网卡：{meta.get('interface', '-')}",
        "",
        "> 阅读顺序：先看第一节的定位结论，再看第二节确认现象，第三节照着做即可。",
        "> 报告按 L2 链路 → L3 网络 → L4 传输 → L7 应用 的顺序判断，故障先从底层查起。",
        "",
    ]

    # ---------------- 一、故障定位 ----------------
    # 「证据不足」必须显示成独立档（❓），不能落进 ✅/「正常」：判定层已经把
    # 「没样本」和「没问题」分开，渲染层再把它们盖回绿色勾，等于白做。
    level_key = {"严重": "bad", "警告": "warn", "正常": "ok",
                 "证据不足": "insufficient"}.get(vd.get("level", ""), "ok")
    L += ["## 一、故障定位", "", f"### {STATUS_MARK.get(level_key, '')} {vd['headline']}", ""]
    L.append(f"**故障层**：{vd.get('layer', '—')}　**影响**：{vd.get('impact', '—')}")
    L.append("")
    for line in (vd.get("plain") or "").split("\n"):
        if line.strip():
            L.append(line.strip())
    L.append("")

    L += ["### 分层定位", ""]
    L.append(_table(
        ["层次", "协议", "状态", "关键指标"],
        [[f"{x['id']} {x['name']}", x["protocol"],
          f"{STATUS_MARK.get(x['status'], '')} {STATUS_TEXT.get(x['status'], x['status'])}",
          x["detail"]] for x in vd.get("layers", [])]))
    L.append("")

    L += ["### 关键指标", ""]
    L.append(_table(
        ["指标", "实测值", "正常参考", "说明"],
        [
            ["建连失败", f"{m.get('conn_fail', 0)} 个", "0", "SYN 发出后无任何回应，业务直接不可用"],
            ["TCP 握手时延", _opt(m.get("hs_avg_ms"), m.get("hs_samples", 0) > 0), "< 100ms（同城）", "建连一次的往返耗时"],
            ["RTT 往返时延",
             f"{_opt(m.get('rtt_avg_ms'), m.get('rtt_samples', 0) > 0)} / P95 "
             f"{_opt(m.get('rtt_p95_ms'), m.get('rtt_samples', 0) > 0)}",
             "< 50ms（内网）", f"基于 {m.get('rtt_samples', 0)} 个 ACK 采样"],
            ["RTT 抖动", _opt(m.get("rtt_jitter_ms"), m.get("rtt_samples", 0) > 0),
             "< 30ms", "时延忽大忽小，无线/拥塞的典型特征"],
            ["TCP 重传率", f"{m.get('retrans_rate', 0):.2f}%", "< 0.5%", "等于丢包率，超过 2% 用户能明显感知"],
            ["乱序 / 重复 ACK", f"{m.get('ooo_rate', 0):.2f}% / {m.get('dup_ack_rate', 0):.2f}%",
             "< 0.5%", "多路径或链路质量问题"],
            ["DNS 解析",
             f"{_opt(m.get('dns_avg_ms'), m.get('dns_samples', 0) > 0)}"
             f"（失败 {m.get('dns_fail_rate', 0):.0f}%）",
             "< 100ms，失败率 0", f"基于 {m.get('dns_samples', 0)} 个响应样本"],
            ["HTTP 响应",
             f"{_opt(m.get('http_avg_ms'), m.get('http_samples', 0) > 0)} / P95 "
             f"{_opt(m.get('http_p95_ms'), m.get('http_samples', 0) > 0)}",
             "< 800ms", "含服务端处理时间，需与 RTT 对比区分"],
            ["吞吐", f"{m.get('throughput_mbps', 0):.2f} Mbps", "视带宽而定", "抓包周期内平均"],
        ]))
    L.append("")

    # ---------------- 二、问题详解 ----------------
    L += ["## 二、问题详解", ""]
    if not vd.get("points"):
        L += ["本次没有命中任何异常阈值，无需逐条处理。", ""]
    for i, p in enumerate(vd.get("points", []), 1):
        L.append(f"### {i}. {p['title']}（{p['severity']}）")
        L.append("")
        L.append(f"- **所在层**：{p['layer']}　**协议**：{p['protocol']}")
        L.append(f"- **看到的现象**：{p['plain']}")
        L.append(f"- **专业依据**：{p['proof']}")
        L.append(f"- **怎么处理**：{p['action']}")
        L.append("")

    # ---------------- 三、处置步骤 ----------------
    L += ["## 三、处置步骤（按顺序执行）", ""]
    for i, s in enumerate(vd.get("next_steps") or [], 1):
        L.append(f"{i}. {s}")
    L.append("")

    # ---------------- 四、会话明细 ----------------
    streams = meta.get("streams_top") or []
    L += ["## 四、会话明细（按问题严重度排序）", ""]
    if streams:
        L.append(_table(
            ["Stream", "客户端", "服务端", "协议", "包/字节", "握手", "RTT 均值", "重传",
             "服务端等待", "标记", "帧"],
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
        L.append("无 TCP 会话。")
    L.append("")

    # ---------------- 五、慢请求与解析明细 ----------------
    L += ["## 五、应用层明细", ""]
    dns_detail = meta.get("dns_detail") or []
    http_slow = meta.get("http_slow") or []
    if dns_detail:
        L += ["### 5.1 DNS 解析（按耗时降序）", ""]
        L.append(_table(["域名", "响应耗时", "响应码", "DNS 服务器", "帧"],
                        [[d["name"], _ms(d["ms"]), _rcode_text(d["rcode"]),
                          d.get("server", "-"), f"#{d['frame']}"] for d in dns_detail[:10]]))
        L.append("")
        if meta.get("dns_servers"):
            L.append("- 使用的 DNS 服务器：" + "，".join(
                f"`{ip}`（{n} 次响应）" for ip, n in meta["dns_servers"]))
            L.append("")
    if http_slow:
        L += ["### 5.2 HTTP 慢请求（按耗时降序）", ""]
        L.append(_table(["方法", "Host", "URI", "状态码", "耗时", "Stream", "帧"],
                        [[h.get("method", "-"), h["host"], h["uri"] or "/", h["code"],
                          _ms(h["ms"]), f"#{h['stream']}", f"#{h['frame']}"] for h in http_slow]))
        L.append("")
    if meta.get("icmp_detail"):
        L += ["### 5.3 ICMP 异常报文", ""]
        L.append(_table(["类型", "含义", "来源 → 目的", "帧"],
                        [[f"type {i['type']}/code {i['code']}", i["desc"],
                          f"{i['src']} → {i['dst']}", f"#{i['frame']}"]
                         for i in meta["icmp_detail"]]))
        L.append("")
    if not (dns_detail or http_slow or meta.get("icmp_detail")):
        L += ["本次没有应用层明细可展示。", ""]

    # ---------------- 六、安全观察 ----------------
    sec_rows = [r for r in rows if r.get("layer") == "安全观察"
                and r.get("severity") in ("严重", "警告", "提示")]
    if sec_rows:
        L += ["## 六、安全观察（附带项，非本工具主线）", "",
              "> 以下内容是抓包时顺带发现的安全隐患，与本次网络故障无直接关系。", ""]
        L.append(_table(["类别", "发现", "程度", "证据", "建议"],
                        [[r["category"], r["finding"], r["severity"], r["evidence"], r["advice"]]
                         for r in sec_rows]))
        L.append("")
    else:
        L += ["## 六、安全观察（附带项，非本工具主线）", "",
              "本次未发现可疑外联与明文认证。该项不影响上面的故障定位结论。", ""]

    # ---------------- 七、技术明细 ----------------
    L += ["## 七、技术明细（供专业复核）", "", "### 7.1 采集概况", ""]
    L.append(_table(["项目", "值"], [
        ["抓包文件", meta.get("pcap_name", "")],
        ["网卡 / 过滤器", f"{meta.get('interface', '-')} / {meta.get('bpf', '-')}"],
        ["报文总数 / 字节", f"{meta.get('packets', 0)} / {meta.get('bytes', 0)}"],
        ["抓包时长", f"{meta.get('duration', 0)} 秒"],
        ["TCP 报文 / 数据报文", f"{meta.get('tcp_packets', 0)} / {meta.get('tcp_data_packets', 0)}"],
        ["TCP 会话数", meta.get("streams_total", 0)],
        ["SYN / SYN-ACK", f"{meta.get('syn', 0)} / {meta.get('synack', 0)}"],
        ["重传 / 乱序 / 重复 ACK", f"{meta.get('retrans', 0)} / {meta.get('ooo', 0)} / {meta.get('dup_ack', 0)}"],
        ["RST / 零窗口", f"{meta.get('rst', 0)} / {meta.get('zero_win', 0)}"],
        ["DNS 查询 / 响应 / NXDOMAIN",
         f"{meta.get('dns_total', 0)} / {meta.get('dns_resp', 0)} / {meta.get('nxdomain', 0)}"],
        ["HTTP 请求 / 5xx", f"{meta.get('http_req', 0)} / {meta.get('http_err5', 0)}"],
        ["外部目标 IP", meta.get("external_ips", 0)],
        ["tshark", meta.get("tshark_path", "")],
    ]))
    L.append("")

    if meta.get("proto_mix"):
        L += ["### 7.2 协议分布", ""]
        L.append(_table(["协议", "报文数"], [[x["proto"], x["count"]] for x in meta["proto_mix"]]))
        L.append("")

    if meta.get("dns_top"):
        L += ["### 7.3 域名解析次数 Top", ""]
        nx = dict(meta.get("nx_top") or [])
        L.append(_table(["域名", "查询次数", "其中失败"],
                        [[n, c, nx.get(n, 0)] for n, c in meta["dns_top"]]))
        L.append("")

    if meta.get("http_codes"):
        L += ["### 7.4 HTTP 状态码分布", ""]
        L.append(_table(["状态码", "次数"], [[c, n] for c, n in meta["http_codes"]]))
        L.append("")

    if meta.get("ext_detail"):
        L += ["### 7.5 外部目标与端口", ""]
        L.append(_table(["外部 IP", "报文数", "涉及端口", "高危端口"],
                        [[e["ip"], e["packets"], ",".join(str(p) for p in e.get("ports", [])) or "-",
                          ",".join(str(p) for p in e.get("risk_ports", [])) or "-"]
                         for e in meta["ext_detail"]]))
        L.append("")

    if meta.get("cred_events"):
        L += ["### 7.6 明文凭证事件（口令已脱敏）", ""]
        L.append(_table(["类型", "位置", "说明", "帧号"],
                        [[c["type"], c["where"], c["detail"], f"#{c['frame']}"]
                         for c in meta["cred_events"]]))
        L.append("")

    # ---------------- 八、机器摘要 ----------------
    L += ["## 八、机器摘要", "",
          f"严重 {summary.get('critical_count', 0)} 项，警告 {summary.get('warning_count', 0)} 项。",
          "", "```json", json.dumps(summary, ensure_ascii=False, indent=2), "```", ""]
    return "\n".join(L)


def _rcode_text(code: str) -> str:
    return {"0": "成功", "2": "SERVFAIL(服务器失败)", "3": "NXDOMAIN(域名不存在)",
            "5": "REFUSED(被拒绝)", "1": "格式错误"}.get(str(code), f"rcode {code}")


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
