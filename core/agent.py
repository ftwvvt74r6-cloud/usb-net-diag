"""常驻采集 agent：后台按固定间隔采样网关 / DNS / 监测目标 / 无线链路。

模块职责
--------
把「网络现在怎么样」按时间轴连续记录下来，供历史接口（``/api/history``）与未来的
AP 热力图使用。**只采样、不判定**：阈值判断只用来决定「要不要落一条事件」，
健康度结论仍然由 ``analyzer`` + ``verdict`` 给。

采样对象
--------
1. **网关**：默认路由的下一跳（``GetBestRoute``，不解析本地化文本）；
2. **DNS**：当前生效的第一个 DNS 服务器（注册表读取，见 ``winapi.dns_servers``）；
3. **监测目标**：最多 3 个，域名或 IP + 可选端口。有端口走 TCP，没端口走 ICMP；
   ICMP 被禁（全丢）时自动降级 TCP 443/80/53 并打 ``degraded`` 标记。

数据落盘
--------
``logs/history/YYYY-MM-DD.jsonl`` 一天一个文件，单行一条样本；单文件超
:data:`MAX_FILE_BYTES` 滚动成 ``YYYY-MM-DD.1.jsonl``。保留 7 天，启动时清旧分片。
事件另存 ``logs/history/events.jsonl``（保留 30 天）。

不做什么
--------
* 不监听任何端口、不开窗口（配合 ``pythonw`` 走 ``--daemon``）；
* 不写 ``reports/``（那是「一次分析的快照」，历史是「连续的时序」，两者不能混）；
* 不做 AP 热力图：样本里已经留全 ``wlan`` 的 7 个字段，热力图将来直接现算。

命令行
------
``python core/agent.py --daemon`` 常驻；``--once`` 采一轮打印；``--status`` 看配置与
落盘情况；``--interval 30`` 改间隔（下一轮生效）。安装/卸载见 ``docs/agent.md``。
"""

from __future__ import annotations

import ctypes
import datetime as dt
import ipaddress
import json
import os
import pathlib
import re
import socket
import sys
import threading
import time
from typing import Any, Callable, Iterable, Mapping

_CORE_DIR = pathlib.Path(__file__).resolve().parent
_ROOT_DIR = _CORE_DIR.parent
#: 以 ``python core/agent.py`` 方式运行时，``sys.path[0]`` 是 ``core/``，
#: 此时 ``from core import ...`` 找不到包 —— 把仓库根补进去（幂等）。
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

from core import config as config_mod  # noqa: E402
from core import logstore  # noqa: E402
from core import probe_reason  # noqa: E402
from core import wlan  # noqa: E402
from core.platform import winapi  # noqa: E402

#: 单文件滚动阈值：5 MB。按 10 秒一轮、每行约 400 字节估算，约 5 天才会到。
MAX_FILE_BYTES = 5 << 20

#: 历史样本保留天数（含今天）。7 天足够回答「昨天下午是不是也这样」。
RETENTION_DAYS = 7

#: 事件保留天数。
EVENT_RETENTION_DAYS = 30

#: 连续多少次超阈值才落事件。1 次会把单点抖动误判成故障，3 次又太迟钝。
CONSECUTIVE_HITS = 2

#: 同类告警的最小间隔（秒）：网络断了每轮都失败，不能每 10 秒刷一行日志。
WARN_EVERY_S = 60.0

#: ICMP 不通时依次尝试的 TCP 端口（先 443 再 80，最后 53 —— DNS 服务器也要能探）。
DEGRADE_TCP_PORTS: tuple[int, ...] = (443, 80, 53)

#: 样本里 ``wlan`` 块的固定字段。**必须齐**：缺键会让热力图没法对齐时间轴，
#: 取不到的值写 ``None`` 而不是删键。
WLAN_FIELDS: tuple[str, ...] = (
    "ssid", "bssid", "rssi_dbm", "rx_mbps", "tx_mbps", "band", "channel")

#: 事件类型 → (样本里的字段, 阈值键)。
EVENT_TYPES: tuple[tuple[str, str, str], ...] = (
    ("rtt", "rtt_ms", "rtt_ms"),
    ("jitter", "jitter_ms", "jitter_ms"),
    ("loss", "loss_pct", "loss_pct"),
)

#: 历史分片文件名：``YYYY-MM-DD.jsonl`` 或滚动后的 ``YYYY-MM-DD.N.jsonl``。
DAY_FILE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.jsonl$")

#: 单实例锁文件名（与 ``logs/netdiag.pid`` 同一目录）。
INSTANCE_FILE = "agent.pid"

#: 域名 → IPv4 的缓存 TTL。每 10 秒解析 3 个域名会把本机 DNS 打成压测。
IP_CACHE_TTL_S = 300.0

_IP_CACHE: dict[str, tuple[float, str]] = {}


# ------------------------------------------------------------------ 小工具

def _emit(text: str) -> None:
    """打印到控制台；``pythonw`` 下 ``sys.stdout`` 是 ``None``，静默跳过。"""
    stream = sys.stdout
    if stream is None:
        return
    try:
        stream.write(text if text.endswith("\n") else text + "\n")
        stream.flush()
    except (OSError, ValueError):
        pass


def _log_line(msg: str) -> None:
    """写一条 agent 日志到 ``logs/app-YYYYMMDD.log``（不抛异常）。"""
    try:
        logstore.app_log(f"[agent] {msg}")
    except Exception:  # noqa: BLE001  日志失败绝不影响采集
        pass


def _local(when: float) -> dt.datetime:
    """epoch 秒 → **带本地时区**的 aware ``datetime``。

    用 ``fromtimestamp(ts, tz=utc).astimezone()`` 而不是
    ``fromtimestamp(ts).astimezone()``：后者在 Windows 上对 1970 年初的时间戳会抛
    ``OSError: [Errno 22]``（naive datetime 转带时区要过 ``mktime``，超出 CRT 的
    可表示范围）。测试要注入固定 epoch，不能踩这个坑。

    Args:
        when: Unix 时间戳（秒）。

    Returns:
        datetime: 带本地时区偏移的 aware 对象。

    Example:
        >>> _local(0).utcoffset() is not None
        True
    """
    return dt.datetime.fromtimestamp(float(when), tz=dt.timezone.utc).astimezone()


def _iso(epoch: float) -> str:
    """把 epoch 秒转成本地时区带偏移的 ISO 字符串（如 ``2026-11-11T16:50:01+08:00``）。

    Args:
        epoch: Unix 时间戳（秒）。

    Returns:
        str: 精确到秒、带时区偏移的时间串。带偏移是为了让跨时区导出的 CSV 不会被
            误读成本地时间。
    """
    return _local(epoch).isoformat(timespec="seconds")


def _day(epoch: float | None = None) -> str:
    """返回 ``YYYY-MM-DD``（本地日期），用作分片文件名。"""
    when = time.time() if epoch is None else float(epoch)
    return _local(when).strftime("%Y-%m-%d")


def _stats(samples: Iterable[float]) -> dict:
    """把一组 RTT 采样算成 ``avg`` / ``max`` / ``min`` / ``jitter``。

    Args:
        samples: RTT 毫秒列表（可以是空列表）。

    Returns:
        dict: ``{"n", "avg", "max", "min", "jitter"}``；没有样本时除 ``n`` 外全为
            ``None`` —— **不写 0**，0 会被下游当成「极快」。
    """
    vals = [float(v) for v in samples]
    n = len(vals)
    if not n:
        return {"n": 0, "avg": None, "max": None, "min": None, "jitter": None}
    avg = sum(vals) / n
    var = sum((v - avg) ** 2 for v in vals) / n
    return {"n": n, "avg": round(avg, 1), "max": round(max(vals), 1),
            "min": round(min(vals), 1), "jitter": round(var ** 0.5, 1)}


def _endpoint(method: str, *, rtt=None, loss=None, jitter=None, reason: str = "",
              **extra) -> dict:
    """构造一个「端点测量块」，五个契约字段一定在。

    Args:
        method: ``icmp`` / ``tcp`` / ``none``。
        rtt: 平均 RTT 毫秒；``None`` 表示没测到。
        loss: 丢包百分比；``None`` 表示「这一项不存在」（如目标为空）。
        jitter: RTT 标准差毫秒。
        reason: 「为什么没响应」，取值见 :mod:`core.probe_reason`
            （``ok`` / ``icmp_filtered`` / ``refused`` / ``timeout``）。默认按
            ``loss`` 推：有回包（``loss < 100``）→ ``ok``，否则 ``timeout``。
        **extra: 附加字段（``ip`` / ``port`` / ``ok`` / ``error`` / ``degraded``…），
            值为 ``None`` 或空串时不写入，避免样本里出现一堆 null 噪声。

    Returns:
        dict: ``{"rtt_ms", "loss_pct", "jitter_ms", "method", "reason", ...}``。
    """
    if not reason:
        # 没有更细的证据时按「有没有回包」给一个最保守的原因：部分丢包仍是 ok
        # （丢多少是阈值层的事），全丢才是 timeout。
        reason = (probe_reason.REASON_OK
                  if loss is not None and float(loss) < 100.0
                  else probe_reason.REASON_TIMEOUT)
    out: dict[str, Any] = {"rtt_ms": rtt, "loss_pct": loss,
                           "jitter_ms": jitter, "method": method, "reason": reason}
    for key, value in extra.items():
        if value is None or value == "":
            continue
        out[key] = value
    return out


# ------------------------------------------------------------------ 历史目录

def history_dir() -> pathlib.Path:
    """历史样本目录（``logs/history``）。

    Returns:
        Path: 跟随 ``NETDIAG_LOG_DIR``，测试可把整个日志根指到临时目录。
    """
    return logstore.log_root() / "history"


def day_file(day: str | None = None) -> pathlib.Path:
    """当天的样本分片路径。

    Args:
        day: ``YYYY-MM-DD``；省略时取今天。

    Returns:
        Path: ``<logs>/history/YYYY-MM-DD.jsonl``。
    """
    return history_dir() / f"{day or _day()}.jsonl"


def events_path() -> pathlib.Path:
    """事件文件路径。

    Returns:
        Path: ``<logs>/history/events.jsonl``（每次调用重新解析，跟随 ``NETDIAG_LOG_DIR``）。
    """
    return history_dir() / "events.jsonl"


def marks_path() -> pathlib.Path:
    """人工标记文件路径（``POST /api/history/mark`` 写入）。

    Returns:
        Path: ``<logs>/history/marks.jsonl``。
    """
    return history_dir() / "marks.jsonl"


# ------------------------------------------------------------------ 地址解析

def resolve_ip(host: str, *, ttl_s: float = IP_CACHE_TTL_S,
               now: float | None = None) -> str:
    """把监测目标解析成 IPv4 字面量（带缓存）。

    ``winapi.icmp_stats`` 只接受 IPv4 字面量，所以域名必须先解析。解析结果缓存
    :data:`IP_CACHE_TTL_S` 秒：既避免每轮都查 DNS，又能在切换网络后 5 分钟内
    重新解析。

    Args:
        host: 域名或 IP 字符串。
        ttl_s: 缓存有效期秒数。
        now: 当前时间（测试注入）；省略时取 ``time.time()``。

    Returns:
        str: IPv4 字面量；解析失败、空串、IPv6 字面量时返回 ``""``
            （ICMP 探不了 IPv6，宁可显式「测不到」也不冒充成 100% 丢包）。
    """
    text = (host or "").strip()
    if not text:
        return ""
    try:
        ipaddress.IPv4Address(text)
        return text
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(text)
        return ""          # IPv6 字面量交给 TCP 分支，不走 ICMP
    except ValueError:
        pass
    stamp = time.time() if now is None else float(now)
    hit = _IP_CACHE.get(text)
    if hit is not None and stamp - hit[0] <= ttl_s:
        return hit[1]
    try:
        infos = socket.getaddrinfo(text, None, socket.AF_INET)
    except OSError:
        return ""
    ip = infos[0][4][0] if infos else ""
    if ip:
        _IP_CACHE[text] = (stamp, ip)
    return ip


# ------------------------------------------------------------------ 测量

def _connect_ms(ip: str, port: int, timeout_s: float) -> tuple[float | None, str]:
    """建一次 TCP 连接并记下耗时（内部函数，测试直接打桩）。

    Args:
        ip: 目标 IPv4/域名。
        port: 目标端口。
        timeout_s: 建连超时秒数。

    Returns:
        tuple: ``(毫秒, 错误文本)``；成功时错误文本为空串，失败时毫秒为 ``None``。
    """
    started = time.perf_counter()
    try:
        sock = socket.create_connection((ip, int(port)), timeout=float(timeout_s))
    except OSError as exc:
        return None, f"{type(exc).__name__}: {exc}"
    elapsed = (time.perf_counter() - started) * 1000.0
    try:
        sock.close()
    except OSError:
        pass
    return round(max(0.0, elapsed), 1), ""


def measure_icmp(host: str, count: int = 2, timeout_ms: int = 800) -> dict:
    """对目标做一组 ICMP 回显，返回 RTT / 抖动 / 丢包。

    走 ``winapi.icmp_stats``（``IcmpSendEcho``），**不解析 ``ping`` 文本** ——
    中文/英文系统的输出格式不同，做文本匹配会在别的机器上静默失效。

    Args:
        host: 域名或 IPv4 字面量。
        count: 发包数（内部夹到 1~10）。
        timeout_ms: 单包等待毫秒（内部夹到 100~5000）。

    Returns:
        dict: :func:`_endpoint` 结构，另含 ``ip`` / ``ok`` / ``error``。
            解析失败时 ``loss_pct = 100.0`` 且 ``error`` 说明原因。
    """
    ip = resolve_ip(host)
    if not ip:
        return _endpoint("icmp", rtt=None, loss=100.0, jitter=None,
                         ok=False, error="DNS 解析失败或非 IPv4 地址")
    stats = winapi.icmp_stats(ip, count=count, timeout_ms=timeout_ms)
    ok = bool(stats.get("ok"))
    return _endpoint(
        "icmp",
        rtt=float(stats["avg_ms"]) if ok else None,
        loss=float(stats.get("loss_pct", 100.0)),
        jitter=float(stats["jitter_ms"]) if ok else None,
        ip=ip, ok=ok, error=stats.get("error") or "",
    )


def _tcp_reason(error: str) -> str:
    """把建连失败的错误文本收敛成 ``reason``（``refused`` / ``timeout``）。

    只做字符串分类，不解析平台错误码：Windows 与 Linux 的错误文本都含
    ``refused`` / ``timed out`` 这类关键词，够用来区分「主机在但端口没开」与
    「根本没有响应」—— 这两件事在判定层的处理完全相反。

    Args:
        error: :func:`_connect_ms` 返回的错误文本（``"ConnectionRefusedError: ..."``）。

    Returns:
        str: :data:`core.probe_reason.TCP_REFUSED` 或 ``TCP_TIMEOUT``。
    """
    low = str(error or "").lower()
    if "refused" in low or "10061" in low:
        return probe_reason.TCP_REFUSED
    return probe_reason.TCP_TIMEOUT


def measure_tcp(host: str, port: int, count: int = 2,
                timeout_s: float = 1.5) -> dict:
    """连续建 ``count`` 次 TCP 连接，用建连耗时当作 RTT。

    Args:
        host: 域名或 IP。
        port: 目标端口。
        count: 建连次数。
        timeout_s: 单次建连超时秒数。

    Returns:
        dict: :func:`_endpoint` 结构（``method="tcp"``），另含 ``ip`` / ``port`` /
            ``ok`` / ``error``。全部失败时 ``rtt_ms`` 为 ``None``、``loss_pct = 100.0``，
            ``reason`` 区分 ``refused``（RST，主机在）与 ``timeout``（无响应）。
    """
    ip = resolve_ip(host) or host
    samples: list[float] = []
    fails = 0
    last_error = ""
    for _ in range(max(1, int(count))):
        ms, err = _connect_ms(ip, port, timeout_s)
        if ms is None:
            fails += 1
            last_error = err
        else:
            samples.append(ms)
    st = _stats(samples)
    tried = len(samples) + fails
    return _endpoint(
        "tcp",
        rtt=st["avg"],
        loss=round(fails / tried * 100.0, 1) if tried else 100.0,
        jitter=st["jitter"],
        reason=probe_reason.REASON_OK if samples else _tcp_reason(last_error),
        ip=ip, port=int(port), ok=bool(samples),
        error="" if samples else (last_error or "连接超时"),
    )


def probe_endpoint(key: str, host: str, port: int | None = None, *,
                   count: int = 2, icmp_timeout_ms: int = 800,
                   tcp_timeout_s: float = 1.5) -> dict:
    """测一个端点：有端口走 TCP，没端口走 ICMP，ICMP 不通自动降级 TCP。

    「ICMP 被禁」在公网上很常见（很多边界设备直接丢弃 echo request），此时
    100% 丢包并不代表目标不可达。降级顺序是 :data:`DEGRADE_TCP_PORTS`，
    命中即用，并在结果里打 ``degraded=true`` / ``method_note="icmp_blocked"``，
    让下游知道**这条 RTT 是建连时间，不是 ICMP 往返**。

    Args:
        key: 目标标识（写进样本的 ``key``，用于事件归属）。
        host: 域名或 IP；空串直接返回 ``method="none"``。
        port: 端口；``None`` 表示走 ICMP。
        count: 探测次数。
        icmp_timeout_ms: ICMP 单包超时。
        tcp_timeout_s: TCP 建连超时。

    Returns:
        dict: ``{"key", "rtt_ms", "loss_pct", "jitter_ms", "method", ...}``。
    """
    if not host:
        return {"key": key, **_endpoint("none", rtt=None, loss=None, jitter=None,
                                        reason=probe_reason.REASON_TIMEOUT,
                                        error="目标为空")}
    if port:
        return {"key": key, **measure_tcp(host, port, count=count,
                                          timeout_s=tcp_timeout_s)}
    out = measure_icmp(host, count=count, timeout_ms=icmp_timeout_ms)
    if not out.get("ok"):
        for candidate in DEGRADE_TCP_PORTS:
            alt = measure_tcp(host, candidate, count=count, timeout_s=tcp_timeout_s)
            if alt.get("ok"):
                alt["degraded"] = True
                alt["method_note"] = "icmp_blocked"
                # ICMP 全丢但 TCP 连上了：不是丢包，是目标不理 ICMP。
                # 这样下游（历史趋势 / 事件 / 报告）不会把 100% 丢包当真相。
                alt["reason"] = probe_reason.REASON_ICMP_FILTERED
                alt["icmp_loss_pct"] = out.get("loss_pct")
                return {"key": key, **alt}
        out["tried_tcp_ports"] = list(DEGRADE_TCP_PORTS)
    return {"key": key, **out}


def wlan_block() -> dict:
    """取无线链路 7 个字段（取不到写 ``None``，**不删键**）。

    Returns:
        dict: 键恒为 :data:`WLAN_FIELDS`。没有无线连接（有线 / 未连）时全部 ``None``。
    """
    try:
        info = wlan.link_info()
    except Exception:  # noqa: BLE001  netsh 挂了不该让整轮采样失败
        info = {}
    if not isinstance(info, Mapping):
        info = {}
    return {field: info.get(field) for field in WLAN_FIELDS}


def _first_dns() -> str:
    """当前生效的第一个 DNS 服务器地址；没有则空串。"""
    try:
        servers = winapi.dns_servers()
    except Exception:  # noqa: BLE001  注册表不可读只按「没有 DNS 角色」降级
        return ""
    return servers[0] if servers else ""


def _gateway() -> str:
    """默认网关地址；没有默认路由时空串。"""
    try:
        return winapi.default_gateway() or ""
    except Exception:  # noqa: BLE001  同上
        return ""


def _without_key(block: Mapping[str, Any] | None) -> dict | None:
    """去掉测量块里的 ``key``（网关 / DNS 不需要自报家门）。"""
    if block is None:
        return None
    return {k: v for k, v in block.items() if k != "key"}


def collect_sample(cfg: Mapping[str, Any] | None = None, *,
                   now: float | None = None) -> dict:
    """采一轮样本。

    Args:
        cfg: 已归一化的 agent 配置（见 :func:`core.config.load_agent`）；
            省略时现读 ``config/agent.json``。
        now: 当前 epoch 秒（测试注入）；省略时取 ``time.time()``。

    Returns:
        dict: 一条样本记录，字段为 ``t`` / ``epoch`` / ``interval_s`` /
            ``gateway`` / ``dns`` / ``targets`` / ``wlan``。

        * ``gateway`` / ``dns``：测量块；**拿不到该角色时为 ``None``**
          （没有默认路由 / 没有配置 DNS）——这是「没采样」，不是「0 丢包」；
        * ``targets``：每个配置目标一项，顺序与配置一致；
        * ``wlan``：7 个字段恒在。
    """
    conf = cfg if cfg is not None else config_mod.load_agent()
    epoch = float(time.time() if now is None else now)
    count = int(conf.get("icmp_count") or 2)
    icmp_timeout = int(float(conf.get("icmp_timeout_ms") or 800))
    tcp_timeout = float(conf.get("tcp_timeout_s") or 1.5)

    gateway_ip = _gateway()
    gateway = _without_key(probe_endpoint(
        "gateway", gateway_ip, None, count=count,
        icmp_timeout_ms=icmp_timeout, tcp_timeout_s=tcp_timeout)) if gateway_ip else None

    dns_ip = _first_dns()
    dns = _without_key(probe_endpoint(
        "dns", dns_ip, None, count=count,
        icmp_timeout_ms=icmp_timeout, tcp_timeout_s=tcp_timeout)) if dns_ip else None

    targets = [
        probe_endpoint(str(item.get("key") or "target"), str(item.get("host") or ""),
                       item.get("port"), count=count,
                       icmp_timeout_ms=icmp_timeout, tcp_timeout_s=tcp_timeout)
        for item in (conf.get("targets") or [])
    ]

    return {
        "t": _iso(epoch),
        "epoch": round(epoch, 3),
        "interval_s": int(conf.get("interval_s") or 10),
        "gateway": gateway,
        "dns": dns,
        "targets": targets,
        "wlan": wlan_block(),
    }


# ------------------------------------------------------------------ 事件检测

class EventTracker:
    """把连续样本变成事件：**连续 N 次**超阈值才算一次，同一次故障只落一条。

    为什么不是「一超就报」：单次 200ms 的 RTT 尖刺是常态（路由器排队、无线重传），
    报出来会让事件列表全是噪声。连续 2 次才报，等价于「持续了至少一个采样间隔」。

    为什么同一次故障只落一条：事件是给人看的列表，不是采样日志。只要条件没恢复，
    就不该每 10 秒再写一条；恢复后再次越线才算新事件。

    Args:
        thresholds: ``{"rtt_ms": 120, "jitter_ms": 40, "loss_pct": 2}``；缺键用默认值。
        consecutive: 连续命中次数，默认 2。
    """

    def __init__(self, thresholds: Mapping[str, Any] | None = None,
                 consecutive: int = CONSECUTIVE_HITS) -> None:
        default = dict(config_mod.AGENT_DEFAULTS["thresholds"])
        if thresholds:
            for key, value in thresholds.items():
                if key in default:
                    try:
                        default[key] = float(value)
                    except (TypeError, ValueError):
                        continue
        self.thresholds: dict[str, float] = default
        self.consecutive = max(1, int(consecutive))
        self._state: dict[tuple[str, str], dict] = {}

    def reset(self) -> None:
        """清空连续计数（配置变更 / 手动重置时调用）。"""
        self._state.clear()

    @staticmethod
    def _series(record: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
        """从样本里抽出所有「被监测的序列」：(序列名, 测量块)。"""
        out: list[tuple[str, Mapping[str, Any]]] = []
        for name in ("gateway", "dns"):
            block = record.get(name)
            if isinstance(block, Mapping):
                out.append((name, block))
        for item in record.get("targets") or []:
            if isinstance(item, Mapping):
                out.append((str(item.get("key") or "target"), item))
        return out

    def observe(self, record: Mapping[str, Any]) -> list[dict]:
        """吃进一条样本，返回**本条样本触发的新事件**（可能为空）。

        Args:
            record: :func:`collect_sample` 的产物。

        Returns:
            list[dict]: 每个事件形如
                ``{"t","epoch","target","type","value","threshold","duration_s",
                "bssid","rssi_dbm"}``。``type`` 取 ``rtt`` / ``jitter`` / ``loss``。
        """
        now = float(record.get("epoch") or time.time())
        link = record.get("wlan") or {}
        if not isinstance(link, Mapping):
            link = {}
        fired: list[dict] = []
        for series, block in self._series(record):
            for etype, field, tkey in EVENT_TYPES:
                state_key = (series, etype)
                value = block.get(field)
                limit = self.thresholds.get(tkey)
                if value is None or limit is None:
                    self._state.pop(state_key, None)
                    continue
                try:
                    numeric = float(value)
                except (TypeError, ValueError):
                    self._state.pop(state_key, None)
                    continue
                if numeric <= float(limit):
                    self._state.pop(state_key, None)      # 恢复 → 重新武装
                    continue
                state = self._state.get(state_key)
                if state is None:
                    state = self._state[state_key] = {"count": 0, "since": now,
                                                      "fired": False}
                state["count"] += 1
                if state["count"] >= self.consecutive and not state["fired"]:
                    state["fired"] = True
                    fired.append({
                        "t": record.get("t") or _iso(now),
                        "epoch": round(now, 3),
                        "target": series,
                        "type": etype,
                        "value": round(numeric, 1),
                        "threshold": float(limit),
                        "duration_s": round(max(0.0, now - float(state["since"])), 1),
                        "bssid": link.get("bssid"),
                        "rssi_dbm": link.get("rssi_dbm"),
                    })
        return fired


# ------------------------------------------------------------------ 落盘

def _roll(path: pathlib.Path) -> pathlib.Path:
    """把超限分片改名成 ``YYYY-MM-DD.N.jsonl``，返回新的可写路径。"""
    match = DAY_FILE_RE.match(path.name)
    stem = match.group(1) if match else path.stem
    index = 1
    while True:
        candidate = path.with_name(f"{stem}.{index}.jsonl")
        if not candidate.exists():
            return candidate
        index += 1


def append_record(record: Mapping[str, Any], *, directory: pathlib.Path | None = None,
                  max_bytes: int = MAX_FILE_BYTES,
                  epoch: float | None = None) -> pathlib.Path:
    """把一条样本追加进当天分片（超限先滚动）。

    Args:
        record: 样本记录。
        directory: 覆盖历史目录（测试用）；省略时用 :func:`history_dir`。
        max_bytes: 单文件字节上限，超过就先滚动到 ``.N`` 分片。
        epoch: 用于决定分片日期的时间戳；省略时取 ``record["epoch"]``。

    Returns:
        Path: 实际写入的文件路径。

    Raises:
        OSError: 目录不可写（调用方按「单次失败不退出」处理）。
    """
    target_dir = pathlib.Path(directory) if directory is not None else history_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    when = epoch if epoch is not None else record.get("epoch")
    path = target_dir / f"{_day(when)}.jsonl"
    try:
        if path.exists() and path.stat().st_size >= int(max_bytes):
            path = _roll(path)
    except OSError:
        pass
    line = json.dumps(dict(record), ensure_ascii=False, separators=(",", ":")) + "\n"
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line)
    return path


def append_event(event: Mapping[str, Any],
                 path: pathlib.Path | None = None) -> pathlib.Path:
    """追加一条事件到 ``events.jsonl``。

    Args:
        event: :meth:`EventTracker.observe` 产出的事件。
        path: 覆盖事件文件路径（测试用）。

    Returns:
        Path: 实际写入的文件路径。
    """
    target = pathlib.Path(path) if path is not None else events_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(dict(event), ensure_ascii=False, separators=(",", ":")) + "\n"
    with open(target, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line)
    return target


def prune_history(*, retain_days: int = RETENTION_DAYS,
                  directory: pathlib.Path | None = None,
                  today: dt.date | None = None) -> list[str]:
    """删除超过保留期的样本分片（只在启动 / 跨天时调用）。

    Args:
        retain_days: 保留天数（含今天）。``7`` 表示留今天与之前 6 天。
        directory: 覆盖历史目录（测试用）。
        today: 参考日期（测试注入）。

    Returns:
        list[str]: 被删除的文件名（按名字排序）。
    """
    target_dir = pathlib.Path(directory) if directory is not None else history_dir()
    if not target_dir.is_dir():
        return []
    anchor = today or dt.date.today()
    cutoff = anchor - dt.timedelta(days=max(1, int(retain_days)) - 1)
    removed: list[str] = []
    for path in sorted(target_dir.glob("*.jsonl")):
        match = DAY_FILE_RE.match(path.name)
        if not match:
            continue
        try:
            day = dt.date.fromisoformat(match.group(1))
        except ValueError:
            continue
        if day >= cutoff:
            continue
        try:
            path.unlink()
            removed.append(path.name)
        except OSError:
            continue
    return removed


def prune_events(*, retain_days: int = EVENT_RETENTION_DAYS,
                 path: pathlib.Path | None = None,
                 now: float | None = None) -> int:
    """把超过保留期的事件从 ``events.jsonl`` 里剔掉（整文件重写，原子替换）。

    Args:
        retain_days: 保留天数。
        path: 覆盖事件文件路径（测试用）。
        now: 当前 epoch 秒（测试注入）。

    Returns:
        int: 被剔除的事件条数（含解析失败的行）。
    """
    target = pathlib.Path(path) if path is not None else events_path()
    if not target.is_file():
        return 0
    stamp = float(time.time() if now is None else now)
    cutoff = stamp - max(1, int(retain_days)) * 86400.0
    kept: list[str] = []
    dropped = 0
    try:
        raw = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    for line in raw.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            obj = json.loads(text)
        except ValueError:
            dropped += 1
            continue
        try:
            epoch = float(obj.get("epoch") or 0)
        except (TypeError, ValueError):
            epoch = 0.0
        if epoch and epoch < cutoff:
            dropped += 1
            continue
        kept.append(text)
    if dropped:
        tmp = target.with_name(target.name + ".tmp")
        try:
            tmp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            os.replace(tmp, target)
        except OSError:
            return 0
    return dropped


# ------------------------------------------------------------------ 告警节流

class WarnGate:
    """把「同类告警」压到每分钟最多一条。

    网络一断，每一轮采样都会失败；若每轮写一行 WARN，``app-*.log`` 一天就能被
    撑爆，反而盖住了真正的问题。这里只放行第一条，被压掉的条数在下一次放行时
    合并成一句「另有 N 条同类告警」。

    Args:
        every_s: 最小间隔秒数，默认 :data:`WARN_EVERY_S`。
        clock: 时间源（测试注入）。
        sink: 落日志的函数，默认写 ``app`` 日志；接收已带 ``WARN`` 前缀的文本。
    """

    def __init__(self, every_s: float = WARN_EVERY_S, *,
                 clock: Callable[[], float] = time.time,
                 sink: Callable[[str], None] | None = None) -> None:
        self.every_s = float(every_s)
        self.clock = clock
        self.sink = sink or _log_line
        self.suppressed = 0
        self._last: float | None = None

    def warn(self, msg: str) -> bool:
        """尝试写一条告警。

        Args:
            msg: 告警正文。

        Returns:
            bool: ``True`` 表示真的写下去了；``False`` 表示被节流吞掉。
        """
        now = self.clock()
        if self._last is not None and now - self._last < self.every_s:
            self.suppressed += 1
            return False
        self._last = now
        text = f"WARN {msg}"
        if self.suppressed:
            text += f"（另有 {self.suppressed} 条同类告警被省略）"
            self.suppressed = 0
        self.sink(text)
        return True


# ------------------------------------------------------------------ 单实例

def instance_path() -> pathlib.Path:
    """单实例锁文件路径。

    Returns:
        Path: ``<logs>/agent.pid``。
    """
    return logstore.log_root() / INSTANCE_FILE


def _pid_alive(pid: int) -> bool:
    """判断进程是否还活着（Windows 用 ``OpenProcess`` + ``GetExitCodeProcess``）。

    Args:
        pid: 进程号。

    Returns:
        bool: 进程存在且未退出为 ``True``；权限不足 / 查询失败按「不在」处理。
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, int(pid))  # QUERY_LIMITED_INFORMATION
            if not handle:
                return False
            try:
                code = ctypes.c_ulong(0)
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return False
                return code.value == 259      # STILL_ACTIVE
            finally:
                kernel32.CloseHandle(handle)
        except Exception:  # noqa: BLE001  查不了就当没有实例
            return False
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def acquire_instance(path: pathlib.Path | None = None) -> bool:
    """抢占单实例锁。

    两个 agent 同时跑会把每条样本写两遍、事件也翻倍。锁文件里只有 PID：
    文件存在且那个 PID 还活着就拒绝启动；PID 已死（上次崩溃/拔盘）视为残留并覆盖。

    Args:
        path: 覆盖锁文件路径（测试用）。

    Returns:
        bool: ``True`` 表示抢到（可以继续启动）；``False`` 表示已有实例在跑。
    """
    target = pathlib.Path(path) if path is not None else instance_path()
    try:
        if target.is_file():
            raw = target.read_text(encoding="utf-8").strip()
            try:
                other = int(raw or 0)
            except ValueError:
                other = 0
            if other and other != os.getpid() and _pid_alive(other):
                return False
    except OSError:
        pass
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(os.getpid()), encoding="utf-8")
    except OSError:
        pass
    return True


def release_instance(path: pathlib.Path | None = None) -> None:
    """释放单实例锁（只删自己写的那个）。

    Args:
        path: 覆盖锁文件路径（测试用）；省略时用 :func:`instance_path`。

    Returns:
        None: 文件不存在 / 不是本进程的 / 删不掉都静默忽略。
    """
    target = pathlib.Path(path) if path is not None else instance_path()
    try:
        if target.is_file() and target.read_text(encoding="utf-8").strip() == str(os.getpid()):
            target.unlink()
    except OSError:
        pass


# ------------------------------------------------------------------ 主循环

def _startup_maintenance() -> None:
    """启动维护：建目录 → 清旧分片 → 剔过期事件 → 记一行启动日志。"""
    try:
        logstore.ensure_dirs()
    except Exception:  # noqa: BLE001  建目录失败也要继续（写盘会再报一次）
        pass
    cfg = config_mod.load_agent()
    try:
        removed = prune_history(retain_days=int(cfg["retain_days"]))
        dropped = prune_events(retain_days=int(cfg["event_retain_days"]))
        if removed or dropped:
            _log_line(f"启动清理：删除分片 {len(removed)} 个、过期事件 {dropped} 条")
    except Exception as exc:  # noqa: BLE001  清理失败不该阻止采集
        _log_line(f"启动清理失败（继续采集）：{type(exc).__name__}: {exc}")
    _log_line(
        f"agent 启动：间隔 {cfg['interval_s']}s，目标 {len(cfg['targets'])} 个，"
        f"历史目录 {history_dir()}")


class Agent:
    """采样主循环。所有外部依赖都可注入，测试不需要真网络与真等待。

    Args:
        config_loader: 返回归一化配置的函数，默认 :func:`core.config.load_agent`。
        sampler: 采样函数，签名 ``(cfg) -> record``，默认 :func:`collect_sample`。
        record_writer: 样本落盘函数，默认 :func:`append_record`。
        event_writer: 事件落盘函数，默认 :func:`append_event`。
        tracker: 事件检测器；``None`` 表示不检测（只记录，不判定）。
        clock: 时间源（秒）。
        sleeper: 等待函数，签名 ``(seconds) -> None``。
        warner: 告警节流器，默认 :class:`WarnGate`。

    Attributes:
        interval_s: 当前生效的采样间隔；``None`` 表示还没跑过。
        last_record: 最近一条样本。
        cycles: 已完成的采样轮数。
    """

    def __init__(self, *, config_loader: Callable[[], dict] | None = None,
                 sampler: Callable[[Mapping[str, Any]], dict] | None = None,
                 record_writer: Callable[[Mapping[str, Any]], Any] | None = None,
                 event_writer: Callable[[Mapping[str, Any]], Any] | None = None,
                 tracker: EventTracker | None = None,
                 clock: Callable[[], float] = time.time,
                 sleeper: Callable[[float], None] | None = None,
                 warner: WarnGate | None = None) -> None:
        self.config_loader = config_loader or config_mod.load_agent
        self.sampler = sampler or collect_sample
        self.record_writer = record_writer or append_record
        self.event_writer = event_writer or append_event
        self.tracker = tracker
        self.clock = clock
        self.sleeper = sleeper or time.sleep
        self.warner = warner or WarnGate(clock=clock)
        self.interval_s: int | None = None
        self.last_record: dict | None = None
        self.cycles = 0

    def cycle(self) -> dict:
        """跑一轮：读配置 → 采样 → 落盘 → 事件检测。

        配置**每轮重读**，所以界面上把间隔从 10 改成 30 后不必重启进程，
        下一轮自然按新间隔走（并记一行「间隔变更」日志）。

        Returns:
            dict: 本轮样本。

        Raises:
            Exception: 采样 / 写盘异常原样抛出，由 :meth:`run` 记告警后继续。
        """
        cfg = self.config_loader()
        interval = int(cfg.get("interval_s") or 10)
        if self.interval_s is not None and interval != self.interval_s:
            _log_line(f"采样间隔 {self.interval_s}s → {interval}s，下一轮生效")
        # 先记下间隔：即使采样抛异常，下一轮也该按新间隔等，不能退回 10 秒猛试
        self.interval_s = interval
        record = self.sampler(cfg)
        self.record_writer(record)
        if self.tracker is not None:
            for event in self.tracker.observe(record):
                self.event_writer(event)
        self.last_record = record
        self.cycles += 1
        return record

    def _wait(self, seconds: float, stop_event: threading.Event | None) -> None:
        """等下一轮；有 stop_event 时用 ``wait`` 以便及时响应停止。"""
        if seconds <= 0:
            return
        if stop_event is not None:
            stop_event.wait(seconds)
        else:
            self.sleeper(seconds)

    def run(self, *, stop_event: threading.Event | None = None,
            max_cycles: int | None = None, guard_instance: bool = True) -> int:
        """阻塞运行主循环。

        Args:
            stop_event: 置位后退出；省略时只能靠 ``max_cycles`` 或 Ctrl+C 结束。
            max_cycles: 最多跑几轮（测试 / ``--once`` 用）；``None`` 表示无限。
            guard_instance: 是否抢单实例锁（测试用 ``False``）。

        Returns:
            int: 退出码。0 = 正常退出（含「已有实例」）；不会因采样失败返回非 0。
        """
        acquired = False
        if guard_instance:
            if not acquire_instance():
                _log_line("已有 agent 实例在运行，本次不重复启动")
                return 0
            acquired = True
        try:
            _startup_maintenance()
            attempts = 0
            while True:
                if stop_event is not None and stop_event.is_set():
                    break
                started = self.clock()
                try:
                    self.cycle()
                except Exception as exc:  # noqa: BLE001  单次失败不退出
                    self.warner.warn(f"采样失败 {type(exc).__name__}: {exc}")
                attempts += 1
                if max_cycles is not None and attempts >= max_cycles:
                    break
                budget = float(self.interval_s or 10)
                self._wait(max(0.0, budget - max(0.0, self.clock() - started)), stop_event)
            return 0
        finally:
            if acquired:
                release_instance()


# ------------------------------------------------------------------ 命令行

USAGE = """NetDiag 常驻采集 agent

用法：
  python core/agent.py --daemon            常驻采集（用 pythonw 启动即无窗口）
  python core/agent.py --once              只采一轮并打印 JSON（自检用）
  python core/agent.py --status            打印配置与历史落盘情况
  python core/agent.py --interval 30       修改采样间隔（5/10/30/60，下一轮生效）

配置文件：config/agent.json（也可用环境变量 NETDIAG_AGENT_CONFIG 指定）
历史目录：logs/history/（样本 YYYY-MM-DD.jsonl / 事件 events.jsonl）
"""


def build_agent() -> Agent:
    """按当前配置装配一个「采样 + 事件检测」的 Agent（``--daemon`` 用）。

    阈值必须从 ``config/agent.json`` 读，不能用模块默认值 —— 否则用户把
    ``rtt_ms`` 从 120 改成 300，事件判定还是按 120 报，界面上改的阈值等于没生效。

    Returns:
        Agent: 已挂好 :class:`EventTracker` 的实例。
    """
    cfg = config_mod.load_agent()
    return Agent(tracker=EventTracker(cfg.get("thresholds")))


def _cmd_once() -> int:
    """采一轮并打印 JSON（不落盘），用于验收与排障。"""
    record = collect_sample()
    _emit(json.dumps(record, ensure_ascii=False, indent=2))
    return 0


def _cmd_status() -> int:
    """打印配置与历史落盘概况。"""
    cfg = config_mod.load_agent()
    directory = history_dir()
    rows = []
    total = 0
    if directory.is_dir():
        for path in sorted(directory.glob("*.jsonl")):
            if path.name in ("events.jsonl", "marks.jsonl"):
                continue
            try:
                count = sum(1 for line in
                            path.read_text(encoding="utf-8", errors="replace").splitlines()
                            if line.strip())
            except OSError:
                count = 0
            total += count
            rows.append(f"  {path.name}  {count} 条  {path.stat().st_size} B")
    events = 0
    if events_path().is_file():
        try:
            events = sum(1 for line in
                         events_path().read_text(encoding="utf-8", errors="replace").splitlines()
                         if line.strip())
        except OSError:
            events = 0
    payload = {
        "config": cfg,
        "history_dir": str(directory),
        "samples_total": total,
        "events_total": events,
        "instance_running": instance_path().is_file(),
    }
    _emit(json.dumps(payload, ensure_ascii=False, indent=2))
    if rows:
        _emit("分片：\n" + "\n".join(rows))
    return 0


def _cmd_interval(argv: list[str]) -> int:
    """处理 ``--interval N``（写配置，立即返回，不等下一轮）。"""
    try:
        index = argv.index("--interval")
        value = argv[index + 1]
    except (ValueError, IndexError):
        _emit("用法：--interval 5|10|30|60")
        return 2
    try:
        cfg = config_mod.save_agent({"interval_s": value})
    except ValueError as exc:
        _emit(f"[错误] {exc}")
        return 2
    except OSError as exc:
        _emit(f"[错误] 写配置失败：{exc}")
        return 1
    _emit(f"采样间隔已设为 {cfg['interval_s']}s（正在运行的 agent 下一轮生效）")
    return 0


def main(argv: list[str] | None = None) -> int:
    """命令行入口。

    Args:
        argv: 参数列表；省略时取 ``sys.argv[1:]``。

    Returns:
        int: 退出码。0 正常；2 参数错误；1 写配置失败。
    """
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if "--daemon" in args:
            try:
                logstore.ensure_dirs()
                logstore.install_excepthooks()
            except Exception:  # noqa: BLE001  日志基建失败不阻止采集
                pass
            return build_agent().run()
        if "--once" in args:
            return _cmd_once()
        if "--status" in args:
            return _cmd_status()
        if "--interval" in args:
            return _cmd_interval(args)
        _emit(USAGE)
        return 0 if ("--help" in args or "-h" in args) else 2
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
