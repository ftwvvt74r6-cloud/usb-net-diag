"""确定性生成 pcap 故障样本（**纯标准库，不依赖 scapy / tshark**）。

为什么要有这个文件（对应评审第 2 步）：

* `*.pcap` 被 `.gitignore` 全局忽略，只有 `!captures/faults_demo.pcap` 例外。
  所以把样本提交到 `tests/pcap_samples/` 会被**静默忽略**，CI 里文件不存在、
  测试静默跳过 —— 这是「绿着但什么都没测」的经典坑。
* 提交二进制样本还有三个问题：不可 review、不可造边界值（丢 1 包 vs 丢 30%）、
  含真实拓扑信息。
* 脚本生成则：无二进制、可 diff、可造任意边界、且**确定性**（同版本永远产出同一字节），
  于是可以用 sha256 断言「样本没被人偷偷改过」。

用法::

    python gen_pcap.py --list                     # 看样本清单与期望结论
    python gen_pcap.py --out pcap_samples          # 生成 8 个样本 + expected.json
    python gen_pcap.py --out . --only dns_timeout  # 只生成一个
    python gen_pcap.py --out . --verify --tshark ..\\..\\tools\\WiresharkPortable\\App\\Wireshark\\tshark.exe

`expected.json` 是**契约**：每个样本声明它应该命中哪些 `rule_id`、不应该命中哪些、
以及关键指标的期望值。CI 只读这个 json，不 import 生成器。

设计约束（不要改）：

1. **确定性**：时间戳固定从 `BASE_EPOCH` 起算，不使用 `time.time()`、不使用随机数。
2. **可读**：每个样本一个函数，包序列像剧本一样从上往下读。
3. **自洽**：TCP 的 seq/ack 必须自洽，否则 tshark 不会给出
   `tcp.analysis.retransmission` / `duplicate_ack` / `zero_window` 这些派生字段，
   样本就白造了（本文件的期望值已在真实 tshark 4.7.4 上核对过）。
4. **不含真实资产**：IP 固定用 192.168.1.0/24 与 10.0.0.0/24 的示例段，
   域名用 `.corp.local` / `.example.com`。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Callable, Iterable, Sequence

# ---------------------------------------------------------------- 常量

BASE_EPOCH = 1735689600  # 2025-01-01T00:00:00Z，固定值保证确定性

CLIENT_IP, CLIENT_MAC = "192.168.1.100", "00:11:22:33:44:55"
SERVER_IP, SERVER_MAC = "10.0.0.5", "66:77:88:99:aa:bb"
GATEWAY_IP, GATEWAY_MAC = "192.168.1.1", "52:54:00:12:34:56"
DNS_IP = "192.168.1.53"
NEIGHBOR_IP, NEIGHBOR_MAC = "192.168.1.50", "aa:bb:cc:dd:ee:ff"

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

PCAP_MAGIC = 0xA1B2C3D4
PCAP_LINKTYPE_ETHERNET = 1
SNAP_LEN = 65535


# ---------------------------------------------------------------- 低层编码


def _mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", "").replace("-", ""))


def _ip(text: str) -> bytes:
    parts = text.split(".")
    if len(parts) != 4:
        raise ValueError(f"不是合法 IPv4：{text}")
    return bytes(int(p) for p in parts)


def _checksum(data: bytes) -> int:
    """RFC 1071 反码求和（IP / TCP / UDP / ICMP 通用）。"""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth(src_mac: str, dst_mac: str, payload: bytes, ethertype: int = ETH_P_IP) -> bytes:
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64,
         ident: int = 0) -> bytes:
    total_len = 20 + len(payload)
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000,
                       ttl, proto, 0, _ip(src), _ip(dst))
    chk = _checksum(head)
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000,
                       ttl, proto, chk, _ip(src), _ip(dst))
    return head + payload


_FLAGS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10}


def _flag_bits(flags: str) -> int:
    bits = 0
    for ch in flags.upper():
        if ch not in _FLAGS:
            raise ValueError(f"未知 TCP flag：{ch}")
        bits |= _FLAGS[ch]
    return bits


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
        flags: str = "A", win: int = 64240, payload: bytes = b"") -> bytes:
    offset = 5 << 4  # 无选项
    head = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                       offset, _flag_bits(flags), win, 0, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, IPPROTO_TCP,
                                               len(head) + len(payload))
    chk = _checksum(pseudo + head + payload)
    head = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                       offset, _flag_bits(flags), win, chk, 0)
    return head + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    head = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, IPPROTO_UDP, length)
    chk = _checksum(pseudo + head + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, chk) + payload


def icmp(type_: int, code: int, payload: bytes = b"", rest: bytes = b"\x00\x00\x00\x00") -> bytes:
    head = struct.pack("!BBH", type_, code, 0) + rest
    chk = _checksum(head + payload)
    return struct.pack("!BBH", type_, code, chk) + rest + payload


def arp(op: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    return struct.pack("!HHBBH6s4s6s4s", 1, ETH_P_IP, 6, 4, op,
                       _mac(sender_mac), _ip(sender_ip),
                       _mac(target_mac), _ip(target_ip))


# ---------------------------------------------------------------- 应用层报文


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError(f"非法 DNS 标签：{label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_query(txid: int, name: str) -> bytes:
    return (struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            + dns_name(name) + struct.pack("!HH", 1, 1))


def dns_response(txid: int, name: str, rcode: int = 0, address: str | None = None) -> bytes:
    """rcode: 0=NOERROR(带 A 记录) / 3=NXDOMAIN。"""
    flags = 0x8180 | (rcode & 0x0F)
    ancount = 1 if address else 0
    body = dns_name(name) + struct.pack("!HH", 1, 1)
    answer = b""
    if address:
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + _ip(address))
    return struct.pack("!HHHHHH", txid, flags, 1, ancount, 0, 0) + body + answer


def http_request(host: str, path: str = "/", method: str = "GET") -> bytes:
    return (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: usb-net-diag-fixture\r\nAccept: */*\r\n\r\n").encode("ascii")


def http_response(code: int, reason: str, body: str = "",
                  ctype: str = "text/plain") -> bytes:
    raw = body.encode("utf-8")
    head = (f"HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(raw)}\r\nConnection: close\r\n\r\n")
    return head.encode("ascii") + raw


# ---------------------------------------------------------------- pcap 写出


def write_pcap(path: Path, frames: Sequence[tuple[float, bytes]]) -> int:
    """frames = [(相对秒, 以太网帧字节)]。返回文件字节数。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, SNAP_LEN,
                             PCAP_LINKTYPE_ETHERNET))
        for offset, frame in frames:
            stamp = BASE_EPOCH + float(offset)
            sec = int(stamp)
            usec = int(round((stamp - sec) * 1_000_000))
            if usec >= 1_000_000:      # 极少数浮点进位
                sec, usec = sec + 1, usec - 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)
    return path.stat().st_size


# ---------------------------------------------------------------- 会话辅助


class Flow:
    """一条 TCP 会话的 seq/ack 记账器，避免手写序号时算错。

    规则：SYN 占 1 个序号，数据占 len(payload)，纯 ACK 不占。
    """

    def __init__(self, client_port: int = 51515, server_port: int = 8080,
                 client_ip: str = CLIENT_IP, server_ip: str = SERVER_IP,
                 client_isn: int = 1000, server_isn: int = 5000) -> None:
        self.c_ip, self.s_ip = client_ip, server_ip
        self.c_mac, self.s_mac = CLIENT_MAC, SERVER_MAC
        self.c_port, self.s_port = client_port, server_port
        self.c_isn, self.s_isn = client_isn, server_isn
        self.c_next = client_isn + 1
        self.s_next = server_isn + 1

    # ---- 两个方向的封装 ----
    def _c2s(self, seq: int, ack: int, flags: str, win: int, payload: bytes) -> bytes:
        return eth(self.c_mac, self.s_mac,
                   ipv4(self.c_ip, self.s_ip, IPPROTO_TCP,
                        tcp(self.c_ip, self.s_ip, self.c_port, self.s_port,
                            seq, ack, flags, win, payload)))

    def _s2c(self, seq: int, ack: int, flags: str, win: int, payload: bytes) -> bytes:
        return eth(self.s_mac, self.c_mac,
                   ipv4(self.s_ip, self.c_ip, IPPROTO_TCP,
                        tcp(self.s_ip, self.c_ip, self.s_port, self.c_port,
                            seq, ack, flags, win, payload)))

    # ---- 剧本原语 ----
    def syn(self, win: int = 64240) -> bytes:
        return self._c2s(self.c_isn, 0, "S", win, b"")

    def synack(self, win: int = 65535) -> bytes:
        return self._s2c(self.s_isn, self.c_isn + 1, "SA", win, b"")

    def ack_c(self, win: int = 64240, ack: int | None = None) -> bytes:
        return self._c2s(self.c_next, ack if ack is not None else self.s_next, "A", win, b"")

    def data_c(self, payload: bytes, win: int = 64240, ack: int | None = None) -> bytes:
        seq = self.c_next
        frame = self._c2s(seq, ack if ack is not None else self.s_next, "PA", win, payload)
        self.c_next += len(payload)
        return frame

    def data_s(self, payload: bytes, win: int = 65535) -> bytes:
        seq = self.s_next
        frame = self._s2c(seq, self.c_next, "PA", win, payload)
        self.s_next += len(payload)
        return frame

    def ack_s(self, win: int = 65535, ack: int | None = None) -> bytes:
        return self._s2c(self.s_next, ack if ack is not None else self.c_next, "A", win, b"")

    def retrans_c(self, payload: bytes, seq: int) -> bytes:
        """重传：**不推进** c_next，序号由调用方指定。"""
        return self._c2s(seq, self.s_next, "PA", 64240, payload)

    def fin_c(self) -> bytes:
        frame = self._c2s(self.c_next, self.s_next, "FA", 64240, b"")
        self.c_next += 1
        return frame


# ---------------------------------------------------------------- 样本


def case_arp_no_reply() -> list[tuple[float, bytes]]:
    """L2：网关 ARP 请求 3 次无应答；同网段邻居正常应答（作为对照）。

    期望：L2.ARP.NO_REPLY；arp_no_reply == 1（只有网关）
    """
    frames: list[tuple[float, bytes]] = []
    for i in range(3):
        frames.append((i * 1.0, eth(CLIENT_MAC, "ff:ff:ff:ff:ff:ff",
                                    arp(1, CLIENT_MAC, CLIENT_IP, "00:00:00:00:00:00",
                                        GATEWAY_IP), ETH_P_ARP)))
    frames.append((3.0, eth(CLIENT_MAC, "ff:ff:ff:ff:ff:ff",
                            arp(1, CLIENT_MAC, CLIENT_IP, "00:00:00:00:00:00",
                                NEIGHBOR_IP), ETH_P_ARP)))
    frames.append((3.1, eth(NEIGHBOR_MAC, CLIENT_MAC,
                            arp(2, NEIGHBOR_MAC, NEIGHBOR_IP, CLIENT_MAC, CLIENT_IP),
                            ETH_P_ARP)))
    return frames


def case_dns_timeout() -> list[tuple[float, bytes]]:
    """L7：4 次查询，只有第 1 次回了 NXDOMAIN，后 3 次完全没响应。

    期望：L7.DNS.FAIL（失败率 25% → 警告）；dns 超时 3 次
    注意：响应必须带同一 txid 才会被 tshark 算出 dns.time。
    """
    names = ["app.corp.local", "api.corp.local", "db.corp.local", "mail.corp.local"]
    frames: list[tuple[float, bytes]] = []
    t = 0.0
    for i, name in enumerate(names):
        frames.append((t, eth(CLIENT_MAC, GATEWAY_MAC,
                              ipv4(CLIENT_IP, DNS_IP, IPPROTO_UDP,
                                   udp(CLIENT_IP, DNS_IP, 51000 + i, 53,
                                       dns_query(0x1000 + i, name))))))
        if i == 0:  # 只有第一条有响应，而且是 NXDOMAIN
            frames.append((t + 0.385, eth(SERVER_MAC, CLIENT_MAC,
                                          ipv4(DNS_IP, CLIENT_IP, IPPROTO_UDP,
                                               udp(DNS_IP, CLIENT_IP, 53, 51000 + i,
                                                   dns_response(0x1000 + i, name, rcode=3))))))
        t += 1.5
    return frames


def case_tcp_retransmission() -> list[tuple[float, bytes]]:
    """L4：客户端第 2 个数据段丢失（未出现在抓包里），服务端连续 dup-ACK，
    客户端重传该段 → 典型「上行丢包」签名。

    期望：L4.RETRANS.HIGH + direction=c2s + 严重（重传率 1/11 ≈ 9.1%）
    """
    flow = Flow(client_port=51516, server_port=8080)
    seg_a, seg_b, seg_c = b"A" * 300, b"B" * 300, b"C" * 300

    frames: list[tuple[float, bytes]] = []
    t = 0.0
    frames.append((t, flow.syn())); t += 0.025
    frames.append((t, flow.synack())); t += 0.001
    frames.append((t, flow.ack_c())); t += 0.001

    # 段 A 正常送达
    frames.append((t, flow.data_c(seg_a))); t += 0.001        # c_next: 1001 → 1301
    frames.append((t, flow.ack_s())); t += 0.001              # ack 1301

    # 段 B **丢失**：不写出。它的序号就是此刻的 c_next（1301）
    seq_b = flow.c_next
    flow.c_next += len(seg_b)                                 # 视为 B 已发但没抓到 → 1601
    seq_c = flow.c_next

    frames.append((t, flow.data_c(seg_c))); t += 0.001        # seq 1601（缺口在 1301）
    frames.append((t, flow.ack_s(ack=seq_b))); t += 0.001     # dup-ACK #1（还是 1301）
    frames.append((t, flow.data_c(b"D" * 300))); t += 0.001
    frames.append((t, flow.ack_s(ack=seq_b))); t += 0.001     # dup-ACK #2

    # 超时重传段 B（seq 回到 1301，不推进 c_next）
    frames.append((t, flow.retrans_c(seg_b, seq_b))); t += 0.001
    frames.append((t, flow.ack_s(ack=seq_c + 300))); t += 0.001
    return frames


def case_udp_no_response() -> list[tuple[float, bytes]]:
    """负向对照（**不许误报**）：UDP 媒体流（RTP 序号缺第 6 个）+ 一次正常 DNS。

    UDP 没有 TCP 那样的重传/dup-ACK 信号，单点抓包**无法**直接测丢包率。
    本样本的用途是「证明工具不会因为 UDP 缺口就乱报 L4 问题」。

    期望：没有任何 L4/L7 故障；must_not 含 L4.RETRANS.HIGH / L7.DNS.FAIL
    """
    frames: list[tuple[float, bytes]] = []
    t = 0.0
    for seq in (1, 2, 3, 4, 5, 7, 8, 9, 10):   # 故意缺 6
        rtp = struct.pack("!BBHII", 0x80, 96, seq, seq * 160, 0x00000001) + b"V" * 160
        frames.append((t, eth(CLIENT_MAC, SERVER_MAC,
                              ipv4(CLIENT_IP, "10.0.1.20", IPPROTO_UDP,
                                   udp(CLIENT_IP, "10.0.1.20", 40000 + seq, 5004, rtp)))))
        t += 0.02

    frames.append((t, eth(CLIENT_MAC, GATEWAY_MAC,
                          ipv4(CLIENT_IP, DNS_IP, IPPROTO_UDP,
                               udp(CLIENT_IP, DNS_IP, 51100, 53,
                                   dns_query(0x2000, "app.corp.local"))))))
    frames.append((t + 0.042, eth(SERVER_MAC, CLIENT_MAC,
                                  ipv4(DNS_IP, CLIENT_IP, IPPROTO_UDP,
                                       udp(DNS_IP, CLIENT_IP, 53, 51100,
                                           dns_response(0x2000, "app.corp.local",
                                                        address="10.0.0.9"))))))
    return frames


def case_zero_window_client() -> list[tuple[float, bytes]]:
    """L4：**客户端**通告零窗口（它在下载、消费不过来）。

    期望：L4.ZEROWIN.CLIENT + metric.bottleneck_side == "client" + direction == s2c
    这是评审 3.2 的修正点：旧实现只统计总数，会把结论错写成「服务端慢」。
    """
    flow = Flow(client_port=51517, server_port=445)
    frames: list[tuple[float, bytes]] = []
    t = 0.0
    frames.append((t, flow.syn())); t += 0.02
    frames.append((t, flow.synack())); t += 0.001
    frames.append((t, flow.ack_c(win=0))); t += 0.001        # 一上来就零窗口

    for _ in range(4):
        frames.append((t, flow.data_s(b"X" * 1400))); t += 0.05
        frames.append((t, flow.ack_c(win=0))); t += 0.05     # 继续零窗口 ×4
    return frames


def case_http_500() -> list[tuple[float, bytes]]:
    """L7：一次 200、一次 500。5xx 占比 50% → 严重。

    期望：L7.HTTP.5XX；must_not 含 L4.RETRANS.HIGH（网络没问题，别再甩锅给链路）
    """
    flow = Flow(client_port=51518, server_port=80)
    frames: list[tuple[float, bytes]] = []
    t = 0.0
    frames.append((t, flow.syn())); t += 0.018
    frames.append((t, flow.synack())); t += 0.001
    frames.append((t, flow.ack_c())); t += 0.001

    frames.append((t, flow.data_c(http_request("app.corp.local", "/api/health")))); t += 0.001
    frames.append((t, flow.ack_s())); t += 0.001
    frames.append((t, flow.data_s(http_response(200, "OK", '{"ok":true}', "application/json"))))
    t += 0.002
    frames.append((t, flow.ack_c()))     # 立刻 ACK：否则 ack_rtt 会把「应用等待」算成网络时延
    t += 0.900

    frames.append((t, flow.data_c(http_request("app.corp.local", "/api/orders")))); t += 0.001
    frames.append((t, flow.ack_s())); t += 0.001
    frames.append((t, flow.data_s(http_response(500, "Internal Server Error",
                                                "upstream timeout"))))
    t += 0.002
    frames.append((t, flow.ack_c()))
    return frames


def case_http_404() -> list[tuple[float, bytes]]:
    """L7：404（客户端/路径问题）→ 只应给「提示」，不许升级为严重。

    期望：L7.HTTP.4XX；severity == info
    """
    flow = Flow(client_port=51519, server_port=80)
    frames: list[tuple[float, bytes]] = []
    t = 0.0
    frames.append((t, flow.syn())); t += 0.02
    frames.append((t, flow.synack())); t += 0.001
    frames.append((t, flow.ack_c())); t += 0.001
    frames.append((t, flow.data_c(http_request("app.corp.local", "/missing")))); t += 0.001
    frames.append((t, flow.ack_s())); t += 0.001
    frames.append((t, flow.data_s(http_response(404, "Not Found", "no such path"))))
    t += 0.002
    frames.append((t, flow.ack_c()))
    return frames


def case_icmp_unreachable() -> list[tuple[float, bytes]]:
    """L3：端口不可达 ×2 + 「需要分片」×1。

    期望：L3.ICMP.UNREACH + 严重（含 MTU/分片 → 升级）
    """
    frames: list[tuple[float, bytes]] = []
    t = 0.0
    echo = icmp(8, 0, b"ping" * 4, rest=struct.pack("!HH", 0x1234, 1))
    for i in range(2):
        frames.append((t, eth(CLIENT_MAC, SERVER_MAC,
                              ipv4(CLIENT_IP, "10.0.0.7", IPPROTO_ICMP, echo))))
        t += 0.5
        frames.append((t, eth(SERVER_MAC, CLIENT_MAC,
                              ipv4("10.0.0.7", CLIENT_IP, IPPROTO_ICMP,
                                   icmp(3, 3, echo[:8])))))     # 端口不可达
        t += 0.5
    frames.append((t, eth(SERVER_MAC, CLIENT_MAC,
                          ipv4("10.0.0.7", CLIENT_IP, IPPROTO_ICMP,
                               icmp(3, 4, echo[:8])))))         # 需要分片
    return frames


# ---------------------------------------------------------------- 注册表

CaseFn = Callable[[], list[tuple[float, bytes]]]


class Case:
    def __init__(self, filename: str, fn: CaseFn, title: str,
                 expect_rule_ids: Iterable[str], must_not: Iterable[str] = (),
                 expect_metrics: dict | None = None, severity: str = "",
                 note: str = "") -> None:
        self.filename = filename
        self.fn = fn
        self.title = title
        self.expect_rule_ids = tuple(expect_rule_ids)
        self.must_not = tuple(must_not)
        self.expect_metrics = dict(expect_metrics or {})
        self.severity = severity
        self.note = note


CASES: tuple[Case, ...] = (
    Case("arp_no_reply.pcap", case_arp_no_reply,
         "同网段 ARP 无应答（网关），邻居正常作对照",
         ["L2.ARP.NO_REPLY"], ["L4.RETRANS.HIGH", "L7.DNS.FAIL"],
         {"arp_no_reply": 1}, "warning",
         note="邻居 192.168.1.50 有应答，用来证明「只报真无应答的那个」，不是整段报。"),
    Case("icmp_unreachable.pcap", case_icmp_unreachable,
         "ICMP 端口不可达 + 需要分片（路径 MTU）",
         ["L3.ICMP.UNREACH"], ["L7.HTTP.5XX"],
         {"icmp_unreach": 3, "icmp_timeout": 0}, "critical",
         note="含 type 3 code 4（需要分片）→ 严重度必须升级到 critical。"),
    Case("dns_timeout.pcap", case_dns_timeout,
         "DNS 3 次超时 + 1 次 NXDOMAIN（失败率 25%）",
         ["L7.DNS.FAIL", "L7.DNS.SLOW"], ["L4.RETRANS.HIGH", "L7.HTTP.5XX"],
         {"dns_fail_rate": 25.0, "dns_timeouts": 3, "dns_avg_ms": 385.0}, "warning",
         note="响应延迟 385ms 同时触发 DNS 慢（≥300ms），两条规则都应命中。"),
    Case("tcp_retransmission.pcap", case_tcp_retransmission,
         "客户端段丢失 → 服务端 dup-ACK → 客户端重传（上行丢包签名）",
         ["L4.RETRANS.HIGH"], ["L7.DNS.FAIL"],
         {"retrans_rate": 9.09, "direction": "c2s", "c2s_retrans": 1, "s2c_dup_ack": 2},
         "critical",
         note=("方向判定依赖 dup-ACK。**当前代码恒报「重复 ACK 0.00%」**："
               "tshark 对 tcp.analysis.duplicate_ack 输出的是 \"1,1\"（两次出现），"
               "而 analyzer._flag() 只认 \"1\"，所以永远判 False（见 code-index #28）。"
               "这条修好之后，L4.RETRANS.HIGH 才可能给出 direction=c2s。")),
    Case("zero_window_client.pcap", case_zero_window_client,
         "客户端通告零窗口（客户端消费不过来，不是服务端慢）",
         ["L4.ZEROWIN.CLIENT"], ["L4.RETRANS.HIGH"],
         {"advertised_by": "client", "bottleneck_side": "client", "zero_win": 5}, "warning",
         note="旧实现只统计总数（5 次），无法归属到客户端；新规则必须判 CLIENT。"),
    Case("http_500.pcap", case_http_500,
         "HTTP 500 占 50%（服务端错误，网络不背锅）",
         ["L7.HTTP.5XX"], ["L4.RETRANS.HIGH", "L7.DNS.FAIL", "L3.RTT.HIGH"],
         {"http_err5": 1, "http_err5_rate": 50.0}, "critical",
         note=("每个响应都在 2ms 内被 ACK —— 否则 tcp.analysis.ack_rtt 会把"
               "「应用等待」算成网络 RTT，L3 误报时延（见 code-index #27）。")),
    Case("404_error.pcap", case_http_404,
         "HTTP 404（客户端/路径问题，只给提示）",
         ["L7.HTTP.4XX"], ["L7.HTTP.5XX", "L3.RTT.HIGH"],
         {"http_err4": 1}, "info",
         note=("**当前代码会同时输出「4xx 提示」和「HTTP 响应正常」**（自相矛盾）："
               "「正常」行的抑制条件只检查 严重/警告，漏了 提示（见 code-index #29）。"
               "迁移后同一类别只允许一条结论。")),
    Case("udp_no_response.pcap", case_udp_no_response,
         "负向对照：UDP 序号缺 1 个 + 正常 DNS，**不许**误报丢包",
         [], ["L4.RETRANS.HIGH", "L7.DNS.FAIL", "L4.CONNECT.NO_RESPONSE", "L3.RTT.HIGH"],
         {}, "ok",
         note=("UDP 无序号语义，单点抓包不能据此判丢包。本样本专门守「不误报」："
               "RTP 序号故意缺第 6 个，工具也不许报 L4 传输问题。")),
)

BY_NAME = {Path(c.filename).stem: c for c in CASES}


# ---------------------------------------------------------------- 输出


def generate(out_dir: Path, only: Sequence[str] = (), manifest: bool = True) -> dict:
    """生成样本。返回 manifest 字典（同时写入 expected.json）。"""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    selected = [c for c in CASES if not only or Path(c.filename).stem in only]
    if not selected:
        raise SystemExit(f"没有匹配的样本：{list(only)}；可用：{sorted(BY_NAME)}")

    entries: list[dict] = []
    for case in selected:
        frames = case.fn()
        path = out_dir / case.filename
        size = write_pcap(path, frames)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append({
            "file": case.filename,
            "title": case.title,
            "packets": len(frames),
            "bytes": size,
            "sha256": digest,
            "expect": {},
            "severity": case.severity,
            "note": case.note,
        })
        # 期望值单独放，避免「生成器自证」的嫌疑；CI 只读 expected.json
        entries[-1]["expect"] = {"rule_ids": list(case.expect_rule_ids)}
        if case.must_not:
            entries[-1]["expect"]["must_not"] = list(case.must_not)
        if case.expect_metrics:
            entries[-1]["expect"]["metrics"] = case.expect_metrics
        print(f"  {case.filename:<28} {len(frames):>3} 包  {size:>5} B  {digest[:12]}")

    doc = {
        "schema_version": "1.0",
        "generated_by": "tests/fixtures/gen_pcap.py",
        "base_epoch": BASE_EPOCH,
        "note": ("确定性命中；同版本重跑 sha256 必须一致。"
                 "CI 用法：先跑生成器，再比对 sha256，再跑规则断言。"),
        "cases": entries,
    }
    if manifest:
        (out_dir / "expected.json").write_text(
            json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return doc


def verify_with_tshark(out_dir: Path, tshark: str | None) -> int:
    """可选：用真实 tshark 检查「派生字段」是否出现（形状自检，不是 CI 依赖）。

    逐样本打印关键字段计数：retransmission / duplicate_ack / zero_window /
    dns.time / http.response.code / arp.opcode。
    """
    import shutil
    import subprocess

    exe = tshark or shutil.which("tshark")
    if not exe:
        print("[跳过] 没找到 tshark（可用 --tshark <path> 指定）")
        return 0

    checks = {
        "tcp_retransmission.pcap": ["tcp.analysis.retransmission", "tcp.analysis.duplicate_ack"],
        "zero_window_client.pcap": ["tcp.analysis.zero_window"],
        "dns_timeout.pcap": ["dns.time", "dns.flags.rcode"],
        "http_500.pcap": ["http.response.code", "http.time"],
        "404_error.pcap": ["http.response.code"],
        "arp_no_reply.pcap": ["arp.opcode"],
        "icmp_unreachable.pcap": ["icmp.type"],
        "udp_no_response.pcap": ["udp.dstport"],
    }
    rc_all = 0
    for case in CASES:
        fields = checks.get(case.filename, [])
        if not fields:
            continue
        args = [exe, "-r", str(out_dir / case.filename), "-n", "-T", "fields"]
        for field in fields:
            args += ["-e", field]
        proc = subprocess.run(args, capture_output=True, text=True, errors="replace")
        if proc.returncode != 0:
            print(f"[失败] {case.filename}: {proc.stderr.strip()[:120]}")
            rc_all = 1
            continue
        hits = {}
        for field in fields:
            hits[field] = 0
        for line in proc.stdout.splitlines():
            cells = line.split("\t") if "\t" in line else line.split(",")
            for field, cell in zip(fields, cells):
                if cell.strip():
                    hits[field] += 1
        summary = "  ".join(f"{k}={v}" for k, v in hits.items())
        print(f"  {case.filename:<28} {summary}")
    return rc_all


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="确定性生成 pcap 故障样本")
    ap.add_argument("--out", default="pcap_samples", help="输出目录（默认 pcap_samples）")
    ap.add_argument("--only", nargs="*", default=[], help="只生成指定样本（文件名去扩展名）")
    ap.add_argument("--list", action="store_true", help="列出样本与期望结论")
    ap.add_argument("--no-manifest", action="store_true", help="不写 expected.json")
    ap.add_argument("--verify", action="store_true", help="用 tshark 检查派生字段")
    ap.add_argument("--tshark", default=None, help="tshark 可执行文件路径")
    args = ap.parse_args(argv)

    if args.list:
        print(f"共 {len(CASES)} 个样本：\n")
        for case in CASES:
            print(f"{case.filename:<28} {case.severity:<9} {case.title}")
            print(f"{'':<28} 期望命中：{', '.join(case.expect_rule_ids) or '（无，负向对照）'}")
            if case.must_not:
                print(f"{'':<28} 不许命中：{', '.join(case.must_not)}")
        return 0

    out = Path(args.out)
    print(f"生成到 {out.resolve()}")
    generate(out, args.only, manifest=not args.no_manifest)
    if args.verify:
        print("\ntshark 派生字段自检：")
        return verify_with_tshark(out, args.tshark)
    return 0


if __name__ == "__main__":
    sys.exit(main())
