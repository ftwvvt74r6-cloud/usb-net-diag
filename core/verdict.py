"""把结构化分析结果翻译成「故障定位结论」。

输出目标（对齐一线运维的真实用法）：
  1. 先回答：问题在哪一层、哪个协议、哪个对端 —— 一句话说清
  2. 再回答：这一层坏了会看到什么现象、影响什么业务
  3. 最后给：按顺序可执行的处置动作

本模块不调用网络与模型，纯规则推导，离线可用。
专业明细（帧号、IP、端口、Stream、原始指标）全部保留在 proof 与 rows 中。
"""
from __future__ import annotations

try:                                    # 扁平导入：core/ 在 sys.path 上（report.py / diagnose.py）
    from contracts import Sufficiency
except ImportError:                     # 包导入：仓库根在 sys.path 上（tests / core.rules）
    from core.contracts import Sufficiency

#: 严重度排序。``"na"`` 排最后不是「最轻」，而是「最没有信息量」：
#: 一层里只要有任何真实样本（哪怕是「测了正常」的 ``"—"``），就以样本为准；
#: 全都是 ``"na"`` 时才会落到 ``"na"``，表示「这一层这次没数据可判」。
SEV_ORDER = {"严重": 0, "警告": 1, "提示": 2, "—": 3, "na": 4}

#: 算作「问题」的严重度。``"—"``（正常）与 ``"na"``（没样本）都不是问题：
#: 前者判过了没问题，后者根本没有数据可判。两者都不得进 bad / sec_bad，
#: 也不得影响 ``flags.network_ok`` 与 ``summary`` 的计数。
PROBLEM_SEVERITIES = ("严重", "警告")

# ---------- 证据充分性：判「有没有可判定的维度」，不判「报文够不够多」 ----------
#
# 为什么不按报文数卡：captures 里的 arp_no_reply 只有 5 个包，却抓到了
# 「同一目标 3 次请求无应答」的真故障；icmp_unreachable 也只有 5 个包，判出了严重。
# 用「包太少 = 证据不足」这种阈值，会把已经成立的结论埋掉 —— 那是比误报更糟的漏报。
#
# 为什么没有「抓包时长 < N 秒」：现有确定性样本的 duration 都是 1~3 秒，
# 一加就集体误判成证据不足。时长阈值要等真实抓包数据校准，本 PR 不做。
MIN_TCP_PACKETS = 5      # TCP 的结论依赖重传率/握手，太少连会话都拼不完整
MIN_TCP_STREAMS = 1      # 有完整会话也算有 TCP 样本（兜住「报文少但会话成立」）
MIN_DNS_QUERIES = 1
MIN_HTTP_REQUESTS = 1
MIN_ICMP_ERRORS = 1      # ICMP 只判错误报文（不可达/超时），echo 本身不是结论
MIN_ARP_REQUESTS = 2     # ARP 规则本身要「同一目标 ≥ 2 次请求」才判得出无应答

#: 证据不足时给的两条可执行建议；与 :data:`INSUFFICIENT_NEEDED` 一一对应。
INSUFFICIENT_STEPS = (
    "把抓包时长加长（建议 30 秒以上），并换成实际在用的网卡再抓一次。",
    "确认目标流量真的经过本机：换个位置抓（如交换机镜像口），或先在体检页直接测一次目标端口。",
)

#: 证据不足时的 ``needed`` key（查 ``copy/zh-CN.json`` 的 ``next_step``）。
INSUFFICIENT_NEEDED = ("collect_longer", "confirm_traffic_path")

#: 证据不足时的 ``reasons`` key（查 ``copy/zh-CN.json`` 的 ``insufficient``）。
INSUFFICIENT_REASON = "no_decidable_dimension"

# 排查顺序：自下而上。同严重度时，越底层越优先（先查链路再查应用）
LAYER_RANK = {"L2 本地链路": 0, "L3 网络层": 1, "L4 传输层": 2, "L7 应用层": 3, "安全观察": 9}
CAT_RANK = {
    "本地可达性": 0, "网络可达性": 1, "网络时延": 2, "连接建立": 3, "传输质量": 4,
    "域名解析": 5, "应用响应": 6, "可疑外联": 7, "端口扫描": 7, "明文凭证": 8,
}

LAYERS = [
    {"id": "L2", "name": "本地链路", "protocol": "ARP / 以太网"},
    {"id": "L3", "name": "网络层", "protocol": "IP / ICMP"},
    {"id": "L4", "name": "传输层", "protocol": "TCP / UDP"},
    {"id": "L7", "name": "应用层", "protocol": "DNS / HTTP / TLS"},
]

# 每一类故障：现象解释（说给不懂协议的人听）
EXPLAIN = {
    "连接建立": ("表现是：访问这个地址时一直转圈，最后提示「无法连接」或连接超时。"
                 "网络本身可能是通的，卡在「建立连接」这一步 —— 要么对方端口没有服务在听，"
                 "要么中间的防火墙/安全组把包丢了。"),
    "传输质量": ("表现是：网页加载到一半卡住、远程桌面一顿一顿、文件传输速度上不去。"
                 "数据发出去没被对方确认，只能重发；重发越多，有效速度越低。这是链路质量问题，不是应用问题。"),
    "网络时延": ("表现是：每个操作都要等一会儿才有反应，但最终能成功，就是慢。"
                 "时延大而稳定多半是物理距离或运营商路径绕行；时延忽大忽小则是链路拥塞或无线不稳。"),
    "网络可达性": ("表现是：某个网段或某台主机完全连不上。"
                   "ICMP 的提示直接指明了原因：端口不可达=服务没起，主机不可达=路由/防火墙拦了，"
                   "需要分片=路径 MTU 不匹配。"),
    "域名解析": ("表现是：网址打不开，但直接用 IP 能打开；或者每次打开网页前都要愣几秒。"
                 "这一步是上网的第一跳，DNS 慢会让所有网站都显得慢。"),
    "TLS 会话": ("表现是：HTTPS 站点证书报错、握手失败，或提示「连接不安全」。"
                 "少量告警多为正常的关闭通知，不用处理；成片告警才是证书或协议问题。"),
    "应用响应": ("表现是：网页能打开，但很慢，或者直接报 500/502。"
                 "网络是通的，问题在服务端处理或应用本身。"),
    "本地可达性": ("表现是：同一个网段内的设备互相访问不了。"
                   "二层地址解析都没有回应，说明对方没开机、IP 冲突，或者被划到了不同 VLAN。"),
    "可疑外联": ("与网络故障无关，是顺带发现的安全隐患，优先级低于上面的连通性问题。"),
    "端口扫描": ("与网络故障无关，是顺带发现的安全观察项。"),
    "明文凭证": ("与网络故障无关，是顺带发现的安全隐患，建议单独处理。"),
}

# 每一类故障的标题（不带数字，数字由 finding 提供）
TITLES = {
    "连接建立": "建立 TCP 连接这一步失败或偏慢",
    "连接建立-RST": "对方明确拒绝了连接（端口没开）",
    "传输质量": "链路上在丢包，实际速度被拖慢",
    "网络时延": "网络往返时延偏大",
    "网络可达性": "网络层不通，被设备拦截",
    "域名解析": "域名解析（DNS）出了问题",
    "TLS 会话": "TLS 会话有告警",
    "应用响应": "服务端响应异常",
    "本地可达性": "同网段内找不到对方（ARP 无应答）",
    "可疑外联": "发现可疑的外联端口",
    "端口扫描": "发现疑似端口扫描行为",
    "明文凭证": "发现明文传输的账号口令",
}


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


def compute_layers(rows: list[dict], meta: dict, metrics: dict) -> list[dict]:
    """为每一层算一个状态块（UI 用横条展示「哪一层红了」）。

    Args:
        rows: 旧 ``rows[]``；安全观察行**不参与**主判定。
        meta: 采集元信息；``L4`` 在没有 TCP 报文时标为 ``na``（没样本，别报正常）。
        metrics: 指标表，供状态块填明细。

    Returns:
        list[dict]: 每项 ``{"id", "name", "protocol", "status"（ok/warn/bad/na）,
            "severity", "detail", "count"}``。
    """
    out: list[dict] = []
    for d in LAYERS:
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
        out.append({
            "id": d["id"], "name": d["name"], "protocol": d["protocol"],
            "status": state, "severity": status,
            "detail": _layer_note(d["id"], meta, metrics),
        })
    return out


def _layer_note(lid: str, meta: dict, m: dict) -> str:
    if lid == "L2":
        n = meta.get("arp_no_reply") or 0
        return f"ARP 无应答 {n} 个地址" if n else "同网段地址解析正常"
    if lid == "L3":
        if not m.get("rtt_samples"):
            return "本次无 RTT 采样（纯 UDP/短连接）"
        parts = [f"RTT 均值 {m.get('rtt_avg_ms', 0):.0f}ms"]
        if m.get("rtt_jitter_ms"):
            parts.append(f"抖动 {m['rtt_jitter_ms']:.0f}ms")
        if m.get("icmp_unreach") or m.get("icmp_timeout"):
            parts.append(f"ICMP 异常 {m.get('icmp_unreach', 0) + m.get('icmp_timeout', 0)} 条")
        return "，".join(parts)
    if lid == "L4":
        if not meta.get("tcp_packets"):
            return "本次无 TCP 流量"
        parts = [f"重传率 {m.get('retrans_rate', 0):.2f}%"]
        if m.get("conn_fail"):
            parts.append(f"建连失败 {m['conn_fail']}")
        if m.get("conn_refused", 0) >= 2:
            parts.append(f"被拒绝 {m['conn_refused']}")
        if m.get("hs_samples"):
            parts.append(f"握手均值 {m['hs_avg_ms']:.0f}ms")
        return "，".join(parts)
    parts = []
    if m.get("dns_samples"):
        parts.append(f"DNS 均值 {m.get('dns_avg_ms', 0):.0f}ms")
    if m.get("http_samples"):
        parts.append(f"HTTP 均值 {m.get('http_avg_ms', 0):.0f}ms")
    return "，".join(parts) or "本次无应用层样本"


def _headline(main: dict, meta: dict, m: dict) -> str:
    cat = main.get("category")
    f = main.get("finding", "")
    if cat == "连接建立":
        if m.get("conn_fail"):
            return f"{m['conn_fail']} 个目标端口完全连不上：TCP 握手没有回应"
        if m.get("conn_refused"):
            return f"{m['conn_refused']} 个连接被对方拒绝（RST）"
        return f"建立连接偏慢：TCP 握手平均 {m.get('hs_avg_ms', 0):.0f}ms"
    if cat == "传输质量":
        # 零窗口看的是「接收方缓冲区被塞满」，不是链路丢包 —— 这两个结论的
        # 排查方向完全相反（查接收端应用 vs 查网络）。
        # 计数在 meta["zero_win"]，metrics 里没有这个键：早先读 m 的那版
        # 永远取到默认值 0，分支从不成立，零窗口场景会被误报成「链路上在丢包」。
        if meta.get("zero_win", 0) >= 3 and m.get("retrans_rate", 0) < 2:
            return "接收端处理不过来：出现 TCP 零窗口（接收缓冲区已满），不是网络慢"
        return f"链路上在丢包：TCP 重传率 {m.get('retrans_rate', 0):.2f}%"
    if cat == "网络时延":
        return (f"网络往返偏慢：RTT 平均 {m.get('rtt_avg_ms', 0):.0f}ms、"
                f"抖动 {m.get('rtt_jitter_ms', 0):.0f}ms")
    if cat == "网络可达性":
        return "网络层被拦截：收到 ICMP 不可达/超时"
    if cat == "域名解析":
        if (m.get("dns_fail_rate") or 0) >= 20:
            return f"域名解析出问题：失败率 {m['dns_fail_rate']:.0f}%"
        if m.get("dns_timeouts", 0) >= 3:
            return f"DNS 查询有 {m['dns_timeouts']} 次没有响应"
        return f"DNS 解析偏慢：平均 {m.get('dns_avg_ms', 0):.0f}ms"
    if cat == "应用响应":
        if m.get("http_err5"):
            return f"服务端报错：{m['http_err5']} 个请求返回 5xx"
        return f"服务端响应慢：HTTP 平均 {m.get('http_avg_ms', 0):.0f}ms"
    if cat == "本地可达性":
        return "本地网段内找不到对方：ARP 请求没有应答"
    if cat in ("可疑外联", "端口扫描", "明文凭证"):
        return "网络连通性正常，但发现了安全隐患"
    return f[:48] if f else "未发现明显故障"


def _int(v) -> int:
    """把 meta 里的计数值安全转成 ``int``（缺键 / ``None`` / 脏值一律当 0）。"""
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _sufficiency(meta: dict, net_rows: list[dict]) -> Sufficiency:
    """判断这次抓包「有没有可判定的维度」。

    判定顺序（先有证据，再看维度）：

    1. 存在任何故障行（严重/警告）→ ``ok=True``。已经判出故障就说明证据链成立，
       此时再去数报文多少是多余的，甚至有害（5 个包的 ARP 样本就是真故障）。
    2. 否则任一维度有样本 → ``ok=True``。
    3. 全都没有 → ``ok=False``，``reasons`` / ``needed`` 给出 key 与可执行建议。

    Args:
        meta: 采集元信息。只读**真实存在**的键：``tcp_packets`` / ``streams_total`` /
            ``dns_total`` / ``http_req`` / ``icmp_unreach`` / ``icmp_timeout`` / ``arp_req``。
        net_rows: 已排除安全观察行的 ``rows[]``。

    Returns:
        Sufficiency: ``ok=False`` 时 ``reasons`` 含 :data:`INSUFFICIENT_REASON`，
            ``reason_args`` 带上本次的报文数与「哪个维度没样本」，便于报告直出原因。

    Note:
        这是**采集有效性**闸门，不是**样本量**闸门：它只回答「测没测到」，
        不回答「测得够不够多」。后者需要真实抓包校准的阈值，不在本 PR 范围。

        维度口径贴的是「对应规则能不能判」，不是「有没有这类包」：
        ICMP 只算错误报文（echo request 不构成结论），ARP 要求 ≥ 2 次请求
        （ARP 规则自身就要 ≥ 2 次才判无应答），单次请求属于「无从判断」。
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
        "arp": _int(meta.get("arp_req")) >= MIN_ARP_REQUESTS,
    }
    if any(dims.values()):
        return Sufficiency(ok=True)

    return Sufficiency(
        ok=False,
        reasons=(INSUFFICIENT_REASON,),
        needed=INSUFFICIENT_NEEDED,
        reason_args={INSUFFICIENT_REASON: {
            "tcp_packets": _int(meta.get("tcp_packets")),
            "dns_total": _int(meta.get("dns_total")),
            "http_req": _int(meta.get("http_req")),
            "icmp_err": _int(meta.get("icmp_unreach")) + _int(meta.get("icmp_timeout")),
            "arp_req": _int(meta.get("arp_req")),
        }},
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
           见 :func:`_sufficiency`：判的是「有没有样本可判」，不是「报文够不够多」。
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
            "headline": "这次没抓到任何报文，无法定位",
            "plain": ("抓包文件是空的，可能是网卡选错、过滤器写得太窄，或者开始抓包后没有任何流量。"
                      "请重新抓一次再判断。"),
            "layer": "—",
            "layers": compute_layers([], meta, m),
            "points": [{
                "severity": "警告", "layer": "—", "protocol": "—", "category": "采集有效性",
                "title": "本次采集没有数据",
                "plain": "抓包文件为空，所有指标都不可信。",
                "proof": f"报文数 0，网卡 {meta.get('interface', '-')}，过滤器 {meta.get('bpf', '-')}",
                "action": "换网卡重抓，或把过滤器清空后再试一次。",
            }],
            "next_steps": ["在界面上把「网卡」改成实际在用的那块，目标留空抓 30 秒。"],
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
        is_rst = cat == "连接建立" and "RST" in finding and "无响应" not in finding
        plain_txt = (RST_EXPLAIN if is_rst else EXPLAIN.get(cat, "")) + "具体：" + finding
        points.append({
            "severity": r.get("severity"),
            "layer": r.get("layer", "—"),
            "protocol": r.get("protocol", "—"),
            "category": cat,
            "title": TITLES.get(cat + "-RST" if is_rst else cat, cat),
            "plain": plain_txt,
            "proof": f"{finding}｜证据：{r.get('evidence', '-')}",
            "action": r.get("advice", ""),
        })

    # 安全项单独放最后，明确标注「非本次主线」
    for r in sec_bad[:2]:
        cat = r.get("category", "")
        points.append({
            "severity": r.get("severity"), "layer": "安全观察", "protocol": r.get("protocol", "—"),
            "category": cat, "title": TITLES.get(cat, cat),
            "plain": EXPLAIN.get(cat, "") + "具体：" + (r.get("finding") or ""),
            "proof": f"{r.get('finding', '')}｜证据：{r.get('evidence', '-')}",
            "action": r.get("advice", ""),
        })

    # ---------- 主判定 ----------
    if not suff.ok:
        # 抓到了包，但没有一个维度有样本可判。这时候说「正常」等于凭空断言：
        # 「什么都没测到」和「测了没问题」是两件事，结论必须是「无法判断」。
        level = "证据不足"
        headline = "这次抓包没有可判定的流量，不能下「正常」的结论"
        plain = ("没有一个维度能判：没有 TCP 流量（报文不足或没有会话），"
                 "没有 DNS 查询、没有 HTTP 请求，没有 ICMP 错误报文，"
                 "ARP 请求也不足以判「无应答」（规则要求同一目标至少 2 次）。\n\n"
                 "「没抓到」不等于「没问题」——每个维度都无从判断，"
                 "所以本次结论是**无法判断**，而不是网络正常。")
        impact = "无法判断（不代表网络正常）"
        layer = "—"
        points = [{
            "severity": "提示",
            "layer": "—",
            "protocol": "—",
            "category": "采集有效性",
            "title": "本次采集没有可判定的流量",
            "plain": ("抓到的报文不构成任何一个可判定维度，"
                      "任何「正常」的说法都缺证据。"),
            "proof": (f"报文 {packets} 个：TCP {_int(meta.get('tcp_packets'))} 个、"
                      f"DNS 查询 {_int(meta.get('dns_total'))} 次、"
                      f"HTTP 请求 {_int(meta.get('http_req'))} 个、"
                      f"ICMP 错误 {_int(meta.get('icmp_unreach')) + _int(meta.get('icmp_timeout'))} 条、"
                      f"ARP 请求 {_int(meta.get('arp_req'))} 次"),
            "action": INSUFFICIENT_STEPS[0],
        }]
    elif bad:
        main = bad[0]
        level = "严重" if main.get("severity") == "严重" else "警告"
        headline = _headline(main, meta, m)
        plain = (EXPLAIN.get(main.get("category"), "") +
                 "\n\n定位：" + (main.get("finding") or ""))
        impact = _impact(main, m)
        layer = f"{main.get('layer')}｜{main.get('protocol')}"
    elif sec_bad:
        level = "警告"
        headline = "网络连通性正常，但发现了安全隐患"
        plain = ("所有网络性能指标都在正常范围，问题不在链路。"
                 "附带的安全观察有命中项，建议单独处理（不影响本次故障排查结论）。")
        impact = "网络正常，存在安全隐患"
        layer = "安全观察"
    else:
        level = "正常"
        headline = "各层指标正常，本次未发现网络故障"
        facts = []
        if m.get("rtt_samples"):
            facts.append(f"RTT 均值 {m['rtt_avg_ms']:.0f}ms")
        facts.append(f"重传率 {m.get('retrans_rate', 0):.2f}%")
        if m.get("dns_samples"):
            facts.append(f"DNS 均值 {m['dns_avg_ms']:.0f}ms")
        if m.get("http_samples"):
            facts.append(f"HTTP 均值 {m['http_avg_ms']:.0f}ms")
        if m.get("hs_samples"):
            facts.append(f"握手均值 {m['hs_avg_ms']:.0f}ms")
        plain = ("从链路、网络、传输到应用层都没有命中异常阈值（" + "、".join(facts) + "）。"
                 "如果用户仍反馈卡顿，说明问题不在本次抓包的时段或不在本机侧，"
                 "建议在复现卡顿的同时开启抓包，或直接用「链路体检」分段测一次。")
        impact = "未见异常"
        layer = "—"

    # ---------- 处置顺序：按排查优先级，底层先动 ----------
    steps: list[str] = []
    if not suff.ok:
        # 证据不足时，处置建议是「怎么重新采到能判的样本」，不是「怎么修网络」。
        steps = list(INSUFFICIENT_STEPS)
    else:
        for r in bad:
            adv = (r.get("advice") or "").strip()
            if adv and adv not in steps:
                steps.append(adv)
        if not steps:
            steps = ["本次无需处理，保留报告作为基线；下次出现卡顿时再抓一次对比指标变化。"]

    return {
        "level": level,
        "headline": headline,
        "plain": plain,
        "impact": impact,
        "layer": layer,
        "layers": compute_layers(rows, meta, m),
        "points": points,
        "next_steps": steps[:6],
        "metrics": m,
        "flags": {
            "network_ok": not bool(bad),
            "security_ok": not bool(sec_bad),
        },
        "sufficiency": suff.to_dict(),
    }


RST_EXPLAIN = ("表现是：只有个别地址/端口连不上，其余访问正常，提示「连接被重置」。"
               "这是对方主机明确拒绝，说明网络是通的，问题在目标端口没有服务在监听，"
               "或被 ACL / 限流主动拒绝。")


def _impact(main: dict, m: dict) -> str:
    cat = main.get("category")
    if cat == "连接建立":
        if not m.get("conn_fail"):
            return "个别连接被拒绝，其余业务正常"
        return "业务不可用：相关服务连不上"
    if cat == "传输质量":
        rate = m.get("retrans_rate", 0)
        return f"体验变差：速度下降、卡顿（重传 {rate:.1f}%）"
    if cat == "网络时延":
        return "操作变慢：每次交互都要多等几十到几百毫秒"
    if cat == "网络可达性":
        return "部分业务不通：特定网段/主机访问失败"
    if cat == "域名解析":
        return "上网变慢或打不开：所有依赖域名的访问都受影响"
    if cat == "应用响应":
        return "业务报错或明显变慢：问题在服务端"
    if cat == "本地可达性":
        return "同网段互访失败：可能整段网络中断"
    return "需关注"
