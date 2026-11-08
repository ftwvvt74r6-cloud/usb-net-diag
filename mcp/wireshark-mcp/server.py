"""wireshark-mcp：基于 tshark 的 MCP 服务器（stdio 传输，零第三方依赖）。

工具：
  list_interfaces        列出可用网卡
  capture_live_packets   按目标 IP 实时抓包并诊断
  scan_network_threats   不带目标的全网段威胁扫描
  analyze_pcap           分析抓包文件（离线分析已有 pcap）
  probe_link             连通与速度测试（分段链路体检：TLS / HTTP / SMB / Banner / Opaque）
  listen_flows           通信观察（被动监听网卡），输出会话表（源/目标/协议/包长/连接状态）
  doctor                 环境自检

启动：python server.py   （由 MCP 客户端配置 command/args 拉起）
环境变量：TSHARK_PATH 指向便携 tshark.exe；USB_NET_DIAG_ROOT 指向项目根目录
"""
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

import bootstrap  # noqa: E402
import diagnose  # noqa: E402
import passive  # noqa: E402
import probe  # noqa: E402
import report  # noqa: E402
import tshark  # noqa: E402

SERVER_INFO = {"name": "wireshark-mcp", "version": "1.0.0"}
PROTOCOL = "2024-11-05"

TOOLS = [
    {
        "name": "list_interfaces",
        "description": "列出本机可用于抓包的网络接口，返回序号与名称。",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "capture_live_packets",
        "description": ("对指定目标实时抓包并做分层故障定位：L2 链路 / L3 网络 / L4 传输 / L7 应用，"
                        "给出「哪一层、哪个协议、哪个对端、怎么处理」的 Markdown 报告。"
                        "target_ip 为空时抓全网。"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_ip": {"type": "string", "description": "目标 IP 或 CIDR，如 192.168.1.10；留空表示全网"},
                "duration": {"type": "integer", "description": "抓包秒数，默认 30，最大 180", "default": 30},
                "interface": {"type": "string", "description": "网卡序号或名称关键字，省略则自动选择"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "scan_network_threats",
        "description": "不做目标过滤，抓取本机网卡全部流量并做分层故障定位（延迟/丢包/解析/服务响应）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "duration": {"type": "integer", "description": "扫描秒数，默认 60，最大 180", "default": 60},
                "interface": {"type": "string", "description": "网卡序号或名称关键字"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "analyze_pcap",
        "description": "分析抓包文件（离线分析已有 pcap/pcapng），输出同样格式的诊断报告。权限受限无法实时抓包时使用。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pcap_file": {"type": "string", "description": "抓包文件绝对路径或 captures 目录下的文件名"},
                "target": {"type": "string", "description": "报告中的目标标识，可留空"},
            },
            "required": ["pcap_file"],
            "additionalProperties": False,
        },
    },
    {
        "name": "probe_link",
        "description": ("不抓包，直接对目标做一次分段体检，并按协议自适应选择探测方式："
                        "先读服务端首包（Banner）识别协议，TLS/HTTPS 走 DNS→TCP→TLS→首字节，"
                        "HTTP 走 DNS→TCP→首字节，SMB 走 TCP→SMB 协商，SSH 等看 TCP→Banner，"
                        "认不出的端口降级为 Opaque TCP 只报建连延迟。"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "域名或 IP，可带端口，如 10.0.0.5:445"},
                "port": {"type": "integer", "description": "端口，留空按协议自动（443/80）"},
                "count": {"type": "integer", "description": "TCP 探测次数，默认 4，用于估算丢包与抖动"},
                "proto": {"type": "string",
                          "description": "强制协议：http/tls/smb/rdp/ssh/opaque；留空自动识别"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "listen_flows",
        "description": ("通信观察（被动监听网卡，只读不发包），把流量聚合成会话表：源 IP:端口、目标 IP:端口、"
                        "协议（按端口 + 首包特征识别，认不出显示 Unknown TCP/UDP）、包数、"
                        "平均包长、总流量、连接状态（ESTABLISHED / SYN 无响应 / RST 重置 / FIN 关闭）。"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "只监听该 IP / CIDR，留空=全部流量"},
                "duration": {"type": "integer", "description": "监听秒数，默认 20，最大 300", "default": 20},
                "interface": {"type": "string", "description": "网卡序号或名称关键字"},
                "engine": {"type": "string", "description": "auto（默认，优先 scapy）| scapy | tshark"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "doctor",
        "description": "检查 tshark / Npcap / 管理员权限 / 网卡是否就绪。",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def _text(payload) -> dict:
    if isinstance(payload, str):
        return {"content": [{"type": "text", "text": payload}], "isError": False}
    return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
            "isError": False}


def _num(v, default: int, lo: int, hi: int) -> int:
    """模型给的参数可能是字符串/越界值：统一收敛到安全区间，避免一次调用卡死几十秒。"""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(n, hi))


def _err(msg: str) -> dict:
    return {"content": [{"type": "text", "text": f"错误：{msg}"}], "isError": True}


def _flows_markdown(res: dict) -> str:
    """把会话表转成适合直接读的 Markdown。"""
    s = res["summary"]
    head = (f"## 通信观察（被动监听）（{res['interface']} / {res['duration']}s / 引擎 {res['engine']}）\n\n"
            f"- 会话 {s['flows']} 条，报文 {s['packets']} 个，流量 {s['bytes'] / 1024:.1f} KB\n"
            f"- 未识别 {s['unknown']} 条，RST 重置 {s['rst']} 条，SYN 无响应 {s['syn_no_reply']} 条\n"
            f"- 过滤器：`{res['bpf'] or '全部流量'}`\n\n"
            f"**结论**：{res['headline']}\n\n{res['advice']}\n\n"
            "| 源 | 目标 | 协议 | 包数 | 平均包长 | 总流量 | 状态 |\n"
            "|---|---|---|---|---|---|---|\n")
    rows = [f"| {f['src']} | {f['dst']} | {f['proto']} | {f['packets']} | "
            f"{f['avg_size']} B | {f['bytes'] / 1024:.1f} KB | {f['state']} |"
            for f in res["flows"][:50]]
    return head + "\n".join(rows)


def call_tool(name: str, args: dict) -> dict:
    """执行一个 MCP 工具调用。

    Args:
        name: 工具名，见本文件 ``TOOLS`` 定义
            （``list_interfaces`` / ``doctor`` / ``capture_live_packets`` /
            ``analyze_pcap`` / ``probe_target`` / ``capture_passive`` 等）。
        args: 工具参数；数值类参数统一过 ``_num()`` 夹紧，
            防止模型给个 ``99999`` 把一次调用拖成几分钟。

    Returns:
        dict: MCP 结果对象 ``{"content": [{"type": "text", "text": ...}], "isError": bool}``。
            未知工具或参数错误时返回 ``isError=True`` 的文本，不抛异常 ——
            抛异常会让整轮工具调用失败，模型拿不到任何可读信息。
    """
    if name == "list_interfaces":
        items = tshark.list_interfaces()
        lines = [f"{i['index']}. {i['name']}" for i in items] or ["未枚举到网卡"]
        return _text({"interfaces": items, "text": "\n".join(lines)})

    if name == "doctor":
        return _text(bootstrap.check(verbose=False))

    if name == "capture_live_packets":
        target = (args.get("target_ip") or "").strip()
        res = diagnose.run_scan(target=target,
                                duration=_num(args.get("duration") or 30, 30, 5, 180),
                                interface=args.get("interface"), logger=lambda m: None)
        if not res.get("ok"):
            hint = " 可改用 analyze_pcap 分析抓包文件。" if res.get("degraded") else ""
            return _err(res.get("error", "抓包失败") + hint)
        return _text(report.render_markdown(res))

    if name == "scan_network_threats":
        res = diagnose.run_scan(target="",
                                duration=_num(args.get("duration") or 60, 60, 5, 180),
                                interface=args.get("interface"), logger=lambda m: None)
        if not res.get("ok"):
            hint = " 可改用 analyze_pcap 分析抓包文件。" if res.get("degraded") else ""
            return _err(res.get("error", "扫描失败") + hint)
        return _text(report.render_markdown(res))

    if name == "probe_link":
        target = (args.get("target") or "").strip()
        if not target:
            return _err("缺少 target 参数")
        port = args.get("port")
        return _text(probe.run(target, port=_num(port, 0, 1, 65535) or None,
                               count=_num(args.get("count") or 4, 4, 1, 10),
                               proto=(args.get("proto") or None)))

    if name == "listen_flows":
        res = passive.run(interface=args.get("interface"),
                          duration=_num(args.get("duration") or 20, 20, 3, 300),
                          target=(args.get("target") or "").strip(),
                          engine=(args.get("engine") or "auto"),
                          logger=lambda m: None)
        if not res.get("ok"):
            return _err(res.get("error", "通信观察失败"))
        return _text(_flows_markdown(res))

    if name == "analyze_pcap":
        pcap = args.get("pcap_file") or ""
        if not pcap:
            return _err("缺少 pcap_file 参数")
        res = diagnose.run_scan(target=args.get("target", ""), pcap=pcap, logger=lambda m: None)
        if not res.get("ok"):
            return _err(res.get("error", "分析失败"))
        return _text(report.render_markdown(res))

    return _err(f"未知工具: {name}")


def handle(msg: dict) -> dict | None:
    """分发一条 JSON-RPC 消息。

    Args:
        msg: 已解析的请求对象，需含 ``method``；``id`` 存在时表示要回包。

    Returns:
        dict | None: 要回给客户端的 JSON-RPC 响应；
            对通知类消息（``notifications/initialized`` 等）返回 ``None``，表示不回包。
    """
    method = msg.get("method", "")
    mid = msg.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
        }}
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            result = call_tool(name, arguments)
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc(file=sys.stderr)
            result = _err(f"{type(exc).__name__}: {exc}")
        return {"jsonrpc": "2.0", "id": mid, "result": result}
    if mid is None:
        return None
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": f"Method not found: {method}"}}


def main() -> int:
    """stdio 主循环：按行读 JSON-RPC → 分发 → 按行写回。

    为什么是一行一条：MCP 的 stdio 传输用换行分隔消息，不能用「读满缓冲区」的方式。

    Returns:
        int: 进程退出码。0 = stdin 关闭（客户端主动断开），属正常结束。
    """
    for line in sys.stdin.buffer:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line.decode("utf-8"))
        except ValueError:
            continue
        try:
            resp = handle(msg)
        except Exception:  # noqa: BLE001
            traceback.print_exc(file=sys.stderr)
            continue
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
