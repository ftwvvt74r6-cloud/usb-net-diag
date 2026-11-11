"""历史样本的读取 / 聚合 / 导出（``/api/history*`` 的数据层）。

为什么单独一层
--------------
界面画图要的是「按桶聚合后的序列」，导出 CSV 要的是「逐样本逐目标的行」，
排查要的是「这段到底有没有数据」。三者对同一份 JSONL 的读法不同，但**口径必须
一致**（同一个缺口不能一处算 3 分钟、一处算 5 分钟）。所以读取、分桶、覆盖率的
判定都收在这一个模块里，``server`` 只做参数解析与响应封装。

三条硬口径
----------
1. **不填 0**：某个样本没测到网关 RTT，就是 ``None``（JSON ``null``）。聚合时
   ``rtt_ms.avg`` 也是 ``None`` —— 0 会被读成「0 毫秒，网络极好」，与事实相反。
2. **缺口必须显式**：没有数据的桶不出现在 ``series`` 里（不画成 0 的平线），
   而是计入 ``coverage.gaps``（缺失桶数）+ ``coverage.gap_ranges``（每段的真实
   起止时间）。宁可让图断开，也不许连一条假线过去；空区间同样要给缺口，
   不许返回 ``gaps=0`` 让人读成「采齐了」。
3. **时间带时区**：对外一律 ``2026-11-11T10:00:00+08:00``。跨时区导出、跨机汇总
   时，没有偏移的字符串会被当成本地时间，差 8 小时没人看得出来。

为什么自己留一份 ``_local`` / ``_iso``
--------------------------------------
``core/agent.py`` 里有一模一样的两行，但 import 它会连带拉起 ``config`` /
``wlan`` / ``winapi``（注册表、netsh、ctypes）。历史查询是**只读**路径，不该因为
看一条曲线而加载采集侧的全部依赖，所以这里独立实现（语义与 agent 完全一致）。
"""
from __future__ import annotations

import datetime as dt
import json
import math
import pathlib
import re
import sys
import time
from typing import Any, Iterable, Mapping, Sequence

_CORE_DIR = pathlib.Path(__file__).resolve().parent
_ROOT_DIR = _CORE_DIR.parent
#: 既能被 ``import history``（server 的扁平导入）加载，也能被
#: ``from core import history``（测试）加载 —— 两种方式都要能找到 ``logstore``。
for _p in (str(_CORE_DIR), str(_ROOT_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import logstore  # noqa: E402  唯一日志根（跟随 NETDIAG_LOG_DIR）

#: 分桶档位 → 秒。只提供这三档：更细的桶在 7 天数据上会画出几万个点，
#: 更粗的桶会把一次 1 分钟的抖动抹平。
BUCKET_CHOICES: dict[str, int] = {"1m": 60, "5m": 300, "1h": 3600}

#: 默认桶。
DEFAULT_BUCKET = "1m"

#: 默认查询区间（秒）：不带 ``from`` 时看最近一小时。
DEFAULT_RANGE_S = 3600

#: 历史分片文件名：``YYYY-MM-DD.jsonl`` 或滚动后的 ``YYYY-MM-DD.N.jsonl``。
#: 与 ``core/agent.py`` 的 ``DAY_FILE_RE`` 同构；这里重新声明是为了不 import 采集侧。
SHARD_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.jsonl$")

#: 单条人工标记的上限字数。超过就拒，避免有人把整篇说明贴进 marks。
MAX_MARK_CHARS = 500

#: 缺口判定的容差（相对采样间隔的倍数）。
#:
#: 一轮采样本身要花几百毫秒到几秒（ICMP 2 次 + TCP 建连），实际间隔略大于
#: ``interval_s`` 是常态。小于 1.5 倍就当「按时采到了」，不然每轮都会算出一个假缺口。
GAP_TOLERANCE = 1.5

#: CSV 列头。**固定**：列序是给 Excel / 脚本用的契约，改列序等于让别人的公式全错。
CSV_COLUMNS: tuple[str, ...] = (
    "time", "interval_s",
    "gateway_rtt_ms", "gateway_loss_pct", "gateway_jitter_ms",
    "dns_rtt_ms",
    "target_key", "target_rtt_ms", "target_loss_pct",
    "bssid", "rssi_dbm", "rx_mbps", "band", "channel",
)


# ------------------------------------------------------------------ 时间

def _local(when: float) -> dt.datetime:
    """epoch 秒 → 带本地时区的 aware ``datetime``。

    Args:
        when: Unix 时间戳（秒）。

    Returns:
        datetime: 带本地时区偏移的对象。

        Note:
        必须走 ``fromtimestamp(ts, tz=utc).astimezone()``：naive → aware 的
        ``fromtimestamp(ts).astimezone()`` 在 Windows 上对 1970 年前后的时间戳会抛
        ``OSError: [Errno 22]``，测试注入固定 epoch 时会踩到。
    """
    return dt.datetime.fromtimestamp(float(when), tz=dt.timezone.utc).astimezone()


def iso(when: float) -> str:
    """epoch 秒 → 本地时区带偏移的 ISO 字符串。

    Args:
        when: Unix 时间戳（秒）。

    Returns:
        str: 精确到秒，如 ``2026-11-11T16:50:01+08:00``。
    """
    return _local(when).isoformat(timespec="seconds")


def _day(when: float) -> str:
    """epoch 秒 → 本地日期 ``YYYY-MM-DD``（用于挑分片）。"""
    return _local(when).strftime("%Y-%m-%d")


def parse_time(value: Any, *, default: float) -> float:
    """把查询参数解析成 epoch 秒。

    Args:
        value: ``None`` / 空串 / epoch 秒（数字或数字串）/ ISO 8601 字符串
            （``2026-11-11``、``2026-11-11 10:00``、``2026-11-11T10:00:00+08:00``、
            结尾 ``Z`` 的 UTC 写法）。
        default: 值为空时返回的默认 epoch。

    Returns:
        float: epoch 秒。无时区的字符串按**本地时间**解释（与界面显示一致）。

    Raises:
        ValueError: 给了值但既不是数字也不是 ISO 时间；调用方据此回 400。
    """
    if value is None:
        return float(default)
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return float(default)
    try:
        return float(text)
    except ValueError:
        pass
    literal = text[:-1] + "+00:00" if text[-1] in ("Z", "z") else text
    try:
        parsed = dt.datetime.fromisoformat(literal)
    except ValueError as exc:
        raise ValueError(
            f"时间格式无法识别：{text!r}（支持 epoch 秒或 ISO 8601，如 2026-11-11T10:00:00+08:00）"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()      # naive 一律按本地时间，不按 UTC 猜
    return parsed.timestamp()


def parse_range(from_value: Any = None, to_value: Any = None, *,
                now: float | None = None) -> tuple[float, float]:
    """解析 ``from`` / ``to`` 两个查询参数。

    Args:
        from_value: 起始时间（见 :func:`parse_time`）；省略时取 ``to - 1 小时``。
        to_value: 结束时间；省略时取当前时间。
        now: 当前 epoch（测试注入）。

    Returns:
        tuple[float, float]: ``(start, end)``，闭区间。

    Raises:
        ValueError: 格式非法，或 ``from`` 晚于 ``to``。
    """
    stamp = time.time() if now is None else float(now)
    end = parse_time(to_value, default=stamp)
    start = parse_time(from_value, default=end - DEFAULT_RANGE_S)
    if start > end:
        raise ValueError(
            f"from（{iso(start)}）晚于 to（{iso(end)}），区间为空")
    return start, end


def bucket_seconds(name: Any) -> tuple[str, int]:
    """把 ``bucket`` 参数解析成秒数。

    Args:
        name: ``1m`` / ``5m`` / ``1h``；空值时用 :data:`DEFAULT_BUCKET`。

    Returns:
        tuple[str, int]: ``(归一化档位名, 秒数)``。

    Raises:
        ValueError: 不在三档之内。
    """
    text = str(name or "").strip().lower() or DEFAULT_BUCKET
    if text not in BUCKET_CHOICES:
        raise ValueError(
            f"bucket 只支持 {' / '.join(BUCKET_CHOICES)}，收到 {text!r}")
    return text, BUCKET_CHOICES[text]


def bucket_start(epoch: float, seconds: int) -> float:
    """求某个时间戳所属桶的起点。

    Args:
        epoch: Unix 时间戳（秒）。
        seconds: 桶宽（60 / 300 / 3600）。

    Returns:
        float: 桶起点 epoch。**按本地时区对齐**：1h 桶落在整点、5m 桶落在
            ``:00/:05/:10…``，这样图上刻度与人对表的方式一致（按 UTC 对齐的话，
            UTC+8 看到的是 ``:00`` 对应的本地 ``08:00``，但 5m 桶会整体偏移，
            凌晨的桶还会跨到前一天）。

        Note:
        有夏令时的时区里，一天可能有 23 或 25 小时，``replace()`` 理论上会撞到
        不存在的本地时间。中国无夏令时，先按此实现；真有该需求时再按 UTC 桶对齐。
    """
    local = _local(epoch)
    if seconds >= 3600:
        aligned = local.replace(minute=0, second=0, microsecond=0)
    else:
        step_min = max(1, seconds // 60)
        aligned = local.replace(minute=local.minute - local.minute % step_min,
                                second=0, microsecond=0)
    return aligned.timestamp()


# ------------------------------------------------------------------ 读盘

def history_dir() -> pathlib.Path:
    """历史样本目录（``<日志根>/history``，跟随 ``NETDIAG_LOG_DIR``）。

    Returns:
        Path: 目录路径（不保证存在）。
    """
    return logstore.log_root() / "history"


def shards(start: float, end: float) -> list[pathlib.Path]:
    """列出与 ``[start, end]`` 有交集的分片文件（含滚动分片）。

    Args:
        start: 区间起点 epoch。
        end: 区间终点 epoch。

    Returns:
        list[Path]: 按文件名排序；目录不存在时返回空表。**只按文件名挑日期**，
            不做全目录扫描式读取 —— 7 天数据最多十几个分片。
    """
    folder = history_dir()
    if not folder.is_dir():
        return []
    first, last = _day(start), _day(end)
    picked: list[pathlib.Path] = []
    for path in sorted(folder.iterdir()):
        match = SHARD_RE.match(path.name)
        if not match:
            continue                      # events.jsonl / marks.jsonl 等不是样本分片
        if first <= match.group(1) <= last:
            picked.append(path)
    return picked


def _iter_jsonl(path: pathlib.Path) -> Iterable[dict]:
    """逐行读 JSONL，坏行/空行静默跳过。

    Args:
        path: 文件路径。

    Yields:
        dict: 每一行的对象。**半行截断**（采集进程被杀）只会损失那一行，
            不会让整段历史读不出来。
    """
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                item = json.loads(text)
            except ValueError:
                continue
            if isinstance(item, dict):
                yield item


def _epoch_of(item: Mapping[str, Any]) -> float | None:
    """取记录里的 ``epoch``；缺失/非法返回 ``None``。"""
    try:
        return float(item.get("epoch"))
    except (TypeError, ValueError):
        return None


def read_samples(start: float, end: float) -> list[dict]:
    """读取 ``[start, end]`` 内的样本，按时间升序。

    Args:
        start: 区间起点 epoch（闭）。
        end: 区间终点 epoch（闭）。

    Returns:
        list[dict]: 样本记录。跨分片合并后**按 epoch 重排**：滚动分片
            （``YYYY-MM-DD.1.jsonl``）与当天主分片之间没有文件名顺序关系，
            只能靠时间戳排。
    """
    out: list[dict] = []
    for path in shards(start, end):
        for item in _iter_jsonl(path):
            stamp = _epoch_of(item)
            if stamp is None or stamp < start or stamp > end:
                continue
            out.append(item)
    out.sort(key=lambda rec: float(rec.get("epoch") or 0))
    return out


def read_events(start: float, end: float) -> list[dict]:
    """读取 ``[start, end]`` 内的事件。

    Args:
        start: 区间起点 epoch（闭）。
        end: 区间终点 epoch（闭）。

    Returns:
        list[dict]: 事件记录（``t`` / ``epoch`` / ``target`` / ``type`` / ``value``
            / ``threshold`` / ``duration_s`` …），按时间升序。
    """
    path = history_dir() / "events.jsonl"
    out: list[dict] = []
    for item in _iter_jsonl(path):
        stamp = _epoch_of(item)
        if stamp is None or stamp < start or stamp > end:
            continue
        out.append(item)
    out.sort(key=lambda rec: float(rec.get("epoch") or 0))
    return out


def read_marks(start: float, end: float) -> list[dict]:
    """读取 ``[start, end]`` 内的人工标记。

    Args:
        start: 区间起点 epoch（闭）。
        end: 区间终点 epoch（闭）。

    Returns:
        list[dict]: 形如 ``{"t","epoch","note"}``，按时间升序。
    """
    path = history_dir() / "marks.jsonl"
    out: list[dict] = []
    for item in _iter_jsonl(path):
        stamp = _epoch_of(item)
        if stamp is None or stamp < start or stamp > end:
            continue
        out.append(item)
    out.sort(key=lambda rec: float(rec.get("epoch") or 0))
    return out


def add_mark(note: str, *, now: float | None = None) -> dict:
    """追加一条人工标记（「这台机器 15:20 换过 AP」这类上下文）。

    Args:
        note: 标记正文（去首尾空白后不能为空，最长 :data:`MAX_MARK_CHARS` 字）。
        now: 时间（测试注入）；省略取当前。

    Returns:
        dict: 落盘的那条记录 ``{"t","epoch","note"}``。

    Raises:
        ValueError: 正文为空或过长。
        OSError: 目录/文件不可写（U 盘只读、被占用）。
    """
    text = " ".join(str(note or "").split())
    if not text:
        raise ValueError("note 不能为空")
    if len(text) > MAX_MARK_CHARS:
        raise ValueError(f"note 最长 {MAX_MARK_CHARS} 字，收到 {len(text)} 字")
    stamp = float(time.time() if now is None else now)
    record = {"t": iso(stamp), "epoch": round(stamp, 3), "note": text}
    folder = history_dir()
    folder.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with open(folder / "marks.jsonl", "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line)
    return record


# ------------------------------------------------------------------ 聚合

def _blocks(sample: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    """抽出一条样本里所有「被监测的序列」。

    Args:
        sample: 一条样本记录。

    Returns:
        list[tuple[str, Mapping]]: ``(序列 key, 测量块)``，顺序固定为
        ``gateway`` → ``dns`` → 各目标。目标用 ``target:<key>`` 前缀 ——
        用户可以把目标命名为 ``gateway``，不带前缀就会和网关序列撞名。
    """
    out: list[tuple[str, Mapping[str, Any]]] = []
    for name in ("gateway", "dns"):
        block = sample.get(name)
        if isinstance(block, Mapping):
            out.append((name, block))
    for item in sample.get("targets") or []:
        if not isinstance(item, Mapping):
            continue
        out.append((f"target:{item.get('key') or 'target'}", item))
    return out


def _match(key: str, wanted: str) -> bool:
    """序列 key 是否匹配用户给的 ``target`` 参数（``target:<key>`` 可省前缀）。"""
    return key == wanted or key.split(":", 1)[-1] == wanted


def series_keys(samples: Sequence[Mapping[str, Any]]) -> list[str]:
    """区间内出现过的序列 key（按首次出现排序）。

    Args:
        samples: 区间内的样本。

    Returns:
        list[str]: 如 ``["gateway", "dns", "target:公司官网"]``。给 ``target``
            参数写错时拼错误提示用 —— 让人一眼看到可选值，比回一个空图强。
    """
    seen: list[str] = []
    for sample in samples:
        for key, _ in _blocks(sample):
            if key not in seen:
                seen.append(key)
    return seen



def _mean(values: Sequence[float]) -> float | None:
    """一组数值的均值（保留 1 位小数）；**空列表返回 ``None``**。

    Args:
        values: 数值列表。

    Returns:
        float | None: ``None`` 表示「这段没测到」—— 写 0 会被读成
            「0 毫秒，网络极好」，图上是一条贴着横轴的完美直线。
    """
    if not values:
        return None
    return round(sum(values) / len(values), 1)


def _peak(values: Sequence[float]) -> float | None:
    """一组数值的最大值（保留 1 位小数）；空列表返回 ``None``。

    Args:
        values: 数值列表。

    Returns:
        float | None: 丢包按桶取**最差**那一笔 —— 一桶里 5 个样本有 1 个丢 20%，
            平均值（4%）会把这次断流抹平。
    """
    if not values:
        return None
    return round(max(values), 1)


def _mode(values: Iterable[Any]) -> Any:
    """出现次数最多的非空值；全空返回 ``None``。

    Args:
        values: 任意可哈希值序列（``bssid`` 之类）。

    Returns:
        Any: 众数。平票时取**先出现**的（拿到第一个就不换），保证同一份数据
            多次查询结果一致。
    """
    counts: dict[Any, int] = {}
    first: dict[Any, int] = {}
    for index, value in enumerate(values):
        if value in (None, ""):
            continue
        counts[value] = counts.get(value, 0) + 1
        first.setdefault(value, index)
    if not counts:
        return None
    best = max(counts, key=lambda key: (counts[key], -first[key]))
    return best


def pick_block(sample: Mapping[str, Any],
               target: str | None = None) -> Mapping[str, Any] | None:
    """选出一条样本里「这条曲线看哪一段测量」。

    默认顺序：**配置里的第一个目标** → DNS → 网关。

    为什么不把三条平均成一条：网关 1 ms 与公网目标 30 ms 平均出 15 ms，
    这个数不代表任何一台设备，图上还会随着「网关抖一下」上下跳 —— 读的人只会
    更糊涂。画一条就必须说清是哪条，所以 ``/api/history`` 的响应里带 ``target``
    说明当前曲线是什么，并支持 ``?target=`` 显式切换。

    Args:
        sample: 一条样本记录。
        target: 指定序列：``gateway`` / ``dns`` / ``target:<key>`` / ``<key>``；
            ``None`` 按上面的默认顺序。

    Returns:
        Mapping | None: 测量块；该样本没有对应测量时 ``None``。
    """
    blocks = _blocks(sample)
    if not blocks:
        return None
    if target:
        wanted = str(target).strip()
        for key, block in blocks:
            if _match(key, wanted):
                return block
        return None
    for key, block in blocks:
        if key.startswith("target:"):
            return block
    by_key = dict(blocks)
    return by_key.get("dns") or by_key.get("gateway")


def primary_key(samples: Sequence[Mapping[str, Any]], target: str | None = None) -> str:
    """算出「这条曲线实际画的是哪条序列」的 key。

    Args:
        samples: 区间内的样本（按时间升序）。
        target: 用户指定的 ``target`` 参数。

    Returns:
        str: 序列 key（如 ``target:公司官网``）；区间内没有任何测量时为空串。
            与 :func:`pick_block` 的选法必须同源，否则图上的线与响应里的
            ``target`` 会对不上。
    """
    for sample in samples:
        block = pick_block(sample, target)
        if block is None:
            continue
        wanted = str(target).strip() if target else ""
        for key, candidate in _blocks(sample):
            if candidate is block and (not wanted or _match(key, wanted)):
                return key
    return ""


def aggregate_points(samples: Sequence[Mapping[str, Any]], seconds: int,
                     target: str | None = None) -> list[dict]:
    """按桶聚合出一条扁平的时间轴（界面的折线/色块直接用这个）。

    Args:
        samples: :func:`read_samples` 的产物（按时间升序）。
        seconds: 桶宽（见 :func:`bucket_seconds`）。
        target: 看哪条序列，见 :func:`pick_block`。

    Returns:
        list[dict]: 每个**有数据的桶**一项::

            {"t": 1762833600.0, "ts": "2026-11-11T10:00:00+08:00", "n": 6,
             "rtt_ms": 12.3, "loss_pct": 0.0, "jitter_ms": 1.2,
             "rssi_dbm": -55.0, "rx_mbps": 300.0, "bssid": "aa:bb:cc:dd:ee:ff"}

        聚合口径（前端直接画，不再二次加工）：

        * ``rtt_ms`` / ``jitter_ms`` / ``rssi_dbm`` / ``rx_mbps``：桶内**均值**；
        * ``loss_pct``：桶内**最大值**（最差那一笔）；
        * ``bssid``：桶内**样本数最多**的那个（主 AP）。

        **没有数据的桶不出现**：不补 0、也不补 ``null`` 占位 —— 补点会让
        「没采到」和「采到了但数值是 0」在图上长得一样。缺口由
        :func:`bucket_coverage` 单独说。``t`` 是 epoch 秒（前端用它画横轴），
        ``ts`` 是给人看的带时区文本。
    """
    #: 桶起点 → 该桶的累加槽
    slots: dict[float, dict] = {}
    for sample in samples:
        stamp = _epoch_of(sample)
        if stamp is None:
            continue
        block = pick_block(sample, target)
        if not isinstance(block, Mapping):
            continue          # 这条样本没测到该序列 → 这个桶不算「有数据」
        link = sample.get("wlan") if isinstance(sample.get("wlan"), Mapping) else {}
        slot = slots.setdefault(bucket_start(stamp, seconds), {
            "rtt": [], "loss": [], "jitter": [], "rssi": [], "rx": [],
            "bssid": [], "n": 0})
        slot["n"] += 1
        slot["bssid"].append(link.get("bssid"))
        for field, bucket_name in (("rtt_ms", "rtt"), ("loss_pct", "loss"),
                                   ("jitter_ms", "jitter"), ("rssi_dbm", "rssi"),
                                   ("rx_mbps", "rx")):
            value = block.get(field) if field in block else link.get(field)
            if value is None:
                continue          # 没测到就不进样本，绝不当 0
            try:
                slot[bucket_name].append(float(value))
            except (TypeError, ValueError):
                continue

    points: list[dict] = []
    for key_ts in sorted(slots):
        slot = slots[key_ts]
        points.append({
            "t": round(key_ts, 3),
            "ts": iso(key_ts),
            "n": slot["n"],
            "rtt_ms": _mean(slot["rtt"]),
            "loss_pct": _peak(slot["loss"]),
            "jitter_ms": _mean(slot["jitter"]),
            "rssi_dbm": _mean(slot["rssi"]),
            "rx_mbps": _mean(slot["rx"]),
            "bssid": _mode(slot["bssid"]),
        })
    return points



def _interval_of(samples: Sequence[Mapping[str, Any]]) -> int:
    """样本里最常见的 ``interval_s``；没有样本时按默认 10 秒。"""
    counts: dict[int, int] = {}
    for sample in samples:
        try:
            value = int(sample.get("interval_s"))
        except (TypeError, ValueError):
            continue
        counts[value] = counts.get(value, 0) + 1
    if not counts:
        return 10
    return max(counts, key=lambda key: counts[key])


def sample_coverage(samples: Sequence[Mapping[str, Any]], start: float, end: float,
                    interval_s: int | None = None) -> dict:
    """算区间内的**样本级**覆盖率与缺口（导出摘要用）。

    Args:
        samples: 区间内的样本（按时间升序）。
        start: 区间起点 epoch。
        end: 区间终点 epoch。
        interval_s: 采样间隔；省略时取样本里的众数。

    Returns:
        dict: ``{"samples", "expected", "ratio", "interval_s", "gaps": [...]}``。

        * ``expected``：``(end-start)/interval_s`` 的向上取整，估算值（闭区间两端
          各算一个样本会让 1 小时 10 秒间隔算出 361，读起来别扭，这里只用长度估）；
        * ``ratio``：``samples/expected``，保留 3 位；``expected`` 为 0 时是 ``None``
          （不写 0，避免「覆盖率 0%」被当成「一条也没采到」）；
        * ``gaps``：每段 ``{"from","to","seconds","missing"}``。**空区间也照样给
          一段缺口**（覆盖整个查询区间）——「这段没数据」必须说出来，不能返回
          一个空数组让人误以为「一切正常」。

        Note:
        相邻样本间隔小于 ``interval_s * 1.5`` 视为「按时采到」：一轮采样本身要花
        几百毫秒到几秒，严格按 ``interval_s`` 判会每桶都多出一个假缺口。
        这是**导出报告**用的口径（一次 21 秒的断档也要列出来）；界面画图用的是
        :func:`bucket_coverage`（按桶算，桶内有样本即算「有线」）。
    """
    step = max(1, int(interval_s if interval_s is not None else _interval_of(samples)))
    span = max(0.0, float(end) - float(start))
    expected = int(math.ceil(span / step)) if span > 0 else 0
    stamps = [stamp for stamp in (_epoch_of(item) for item in samples)
              if stamp is not None]

    gaps: list[dict] = []
    limit = step * GAP_TOLERANCE

    def _gap(gap_from: float, gap_to: float, *, inner: bool) -> dict:
        seconds = max(0, int(round(gap_to - gap_from)))
        # inner=True 表示两端都有样本，缺的是中间那几个（减掉端点本身）
        slots = max(1, int(round((gap_to - gap_from) / step)))
        missing = max(1, slots - 1) if inner else max(1, slots)
        return {"from": iso(gap_from), "to": iso(gap_to),
                "seconds": seconds, "missing": missing}

    if not stamps:
        gaps.append(_gap(float(start), float(end), inner=False))
    else:
        if stamps[0] - start > limit:
            gaps.append(_gap(float(start), stamps[0], inner=False))
        for prev, cur in zip(stamps, stamps[1:]):
            if cur - prev > limit:
                gaps.append(_gap(prev, cur, inner=True))
        if end - stamps[-1] > limit:
            gaps.append(_gap(stamps[-1], float(end), inner=False))

    return {
        "samples": len(stamps),
        "expected": expected,
        "ratio": round(len(stamps) / expected, 3) if expected else None,
        "interval_s": step,
        "gaps": gaps,
    }


def bucket_coverage(points: Sequence[Mapping[str, Any]], start: float, end: float,
                    seconds: int, *, samples: int = 0) -> dict:
    """算区间内的**桶级**覆盖率与缺口（界面断线用）。

    Args:
        points: :func:`aggregate_points` 的产物（有数据的桶）。
        start: 区间起点 epoch。
        end: 区间终点 epoch。
        seconds: 桶宽。
        samples: 原始样本条数（原样回填到响应里）。

    Returns:
        dict: ``{"from","to","samples","gaps","expected","ratio","bucket_s",
        "gap_ranges"}``。

        * ``gaps``：**缺失的桶数**（界面契约）。区间内一条数据都没有时，
          它等于全部桶数 —— **不会填 0**，否则前端会显示「0 个缺口」；
        * ``gap_ranges``：每段 ``{"from","to","seconds","missing"}``，``missing``
          是这段缺了几个桶。图上的断线要靠它说清「断的是 10:03 那一分钟」；
        * ``ratio``：有数据的桶 / 应有桶数，保留 3 位。

        Note:
        桶按**本地时区**对齐后逐个累加求边界，不用 ``epoch // seconds``：
        UTC+5:30 这类时区的本地整点落在 ``:30``，整除会整体错位。
    """
    present = {int(round(float(point.get("t") or 0))) for point in points}
    first = bucket_start(start, seconds)
    last = bucket_start(end, seconds)

    expected = 0
    runs: list[dict] = []
    run: dict | None = None
    cursor = first
    while cursor <= last + 0.5:
        expected += 1
        if int(round(cursor)) in present:
            if run is not None:
                runs.append(run)
                run = None
        elif run is None:
            run = {"start": cursor, "count": 1}
        else:
            run["count"] += 1
        cursor += seconds
    if run is not None:
        runs.append(run)

    ranges = [{"from": iso(item["start"]),
               "to": iso(item["start"] + item["count"] * seconds),
               "seconds": int(item["count"] * seconds),
               "missing": int(item["count"])} for item in runs]
    missing = sum(item["missing"] for item in ranges)
    return {
        "from": iso(start),
        "to": iso(end),
        "samples": int(samples),
        "gaps": missing,
        "expected": expected,
        "ratio": round(len(present) / expected, 3) if expected else None,
        "bucket_s": int(seconds),
        "gap_ranges": ranges,
    }


def event_type_name(kind: Any) -> str:
    """事件类型改成界面契约的写法：``rtt`` → ``latency``。

    Args:
        kind: 采样侧的类型（``rtt`` / ``jitter`` / ``loss``）。

    Returns:
        str: ``latency`` / ``jitter`` / ``loss``。``rtt`` 在界面文案里叫
        「时延」，契约里写 ``latency``；两者指同一个测量，改名只是为了和前端
        的 ``type`` 枚举对齐（未识别的类型原样透传，不吞数据）。
    """
    text = str(kind or "").strip()
    return "latency" if text == "rtt" else text


def _number(value: Any) -> float | None:
    """数值化；``None`` / 空串 / 非数字一律 ``None``（**不写 0**）。"""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def event_view(event: Mapping[str, Any]) -> dict:
    """把 ``events.jsonl`` 的一条事件整理成界面契约的形状。

    Args:
        event: :func:`read_events` 的一条记录。

    Returns:
        dict: ``{"t","ts","target","type","value","threshold","duration_s",
        "bssid","rssi_dbm"}``。``t`` 是 epoch 秒（前端按它画竖线），``ts`` 是
        带时区的可读时间。缺字段一律 ``None``，不补 0。
    """
    stamp = _epoch_of(event)
    return {
        "t": round(stamp, 3) if stamp is not None else None,
        "ts": str(event.get("t") or (iso(stamp) if stamp is not None else "")),
        "target": str(event.get("target") or ""),
        "type": event_type_name(event.get("type")),
        "value": _number(event.get("value")),
        "threshold": _number(event.get("threshold")),
        "duration_s": _number(event.get("duration_s")),
        "bssid": event.get("bssid") or None,
        "rssi_dbm": _number(event.get("rssi_dbm")),
    }


def mark_view(mark: Mapping[str, Any]) -> dict:
    """把一条人工标记整理成界面契约的形状（``{"t","ts","note"}``）。

    Args:
        mark: :func:`read_marks` 的一条记录。

    Returns:
        dict: ``t`` 是 epoch 秒 —— 界面用它算横坐标，传 ISO 字符串会在
        ``Number(...)`` 里变成 ``NaN``，标记就整条画不出来。
    """
    stamp = _epoch_of(mark)
    return {
        "t": round(stamp, 3) if stamp is not None else None,
        "ts": str(mark.get("t") or (iso(stamp) if stamp is not None else "")),
        "note": str(mark.get("note") or ""),
    }


def build_history(from_value: Any = None, to_value: Any = None,
                  bucket: Any = None, target: Any = None, *,
                  now: float | None = None) -> dict:
    """``GET /api/history`` 的完整载荷。

    Args:
        from_value: 起始时间（epoch 秒或 ISO 8601）。
        to_value: 结束时间。
        bucket: ``1m`` / ``5m`` / ``1h``。
        target: 看哪条序列（``gateway`` / ``dns`` / ``<目标 key>``）；省略时按
            「第一个目标 → DNS → 网关」的默认顺序。
        now: 当前 epoch（测试注入）。

    Returns:
        dict: ``{"ok","from","to","from_epoch","to_epoch","bucket","bucket_s",
        "target","targets","samples","series","marks","coverage"}``。

        * ``series``：**扁平**的一串桶，一个桶一项（见 :func:`aggregate_points`）；
        * ``target``：这条曲线实际画的是哪条序列（空区间时是空串）；
        * ``targets``：区间内可选的序列清单 —— 让调用方知道还能切什么；
        * ``coverage.gaps``：缺失桶数；``coverage.gap_ranges``：缺口的真实起止。

    Raises:
        ValueError: 参数非法（时间格式 / ``from`` 晚于 ``to`` / ``bucket``
            越界 / ``target`` 在该区间的样本里不存在）。
    """
    name, seconds = bucket_seconds(bucket)
    start, end = parse_range(from_value, to_value, now=now)
    samples = read_samples(start, end)

    wanted = str(target).strip() if target else ""
    available = series_keys(samples)
    # 只有「区间里明明有数据，但都不是要的那条」才算参数错：区间整个没数据时
    # 回 400 会把「agent 还没跑」误报成「你参数写错了」，那是另一码事。
    if wanted and available and not any(_match(key, wanted) for key in available):
        raise ValueError(
            f"target 不在本区间的样本里：{wanted!r}（可选：{', '.join(available)}）")

    points = aggregate_points(samples, seconds, wanted or None)
    return {
        "ok": True,
        "from": iso(start),
        "to": iso(end),
        "from_epoch": round(start, 3),
        "to_epoch": round(end, 3),
        "bucket": name,
        "bucket_s": seconds,
        "target": primary_key(samples, wanted or None).split(":", 1)[-1],
        "targets": available,
        "samples": len(samples),
        "series": points,
        "marks": [mark_view(item) for item in read_marks(start, end)],
        "coverage": bucket_coverage(points, start, end, seconds,
                                    samples=len(samples)),
    }


# ------------------------------------------------------------------ 导出

def _cell(value: Any) -> str:
    """数值 → CSV 单元格文本；``None`` 一律空串。

    Args:
        value: 数值或其他标量。

    Returns:
        str: ``12.0`` → ``12``，``0.0`` → ``0``，``None`` → ``""``。

        Note:
        缺失必须留空而不是写 0：CSV 可能被直接喂给 Excel 画图，0 会让曲线
        在断网的那一分钟贴着横轴画过去。
    """
    if value is None or value == "":
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return f"{float(value):g}"
    return str(value)


def export_csv(samples: Sequence[Mapping[str, Any]]) -> str:
    """把样本导成逐行 CSV（一行 = 一个样本 × 一个目标）。

    Args:
        samples: 区间内的样本（按时间升序）。

    Returns:
        str: 含表头、以 ``\\n`` 结尾（每行都以 ``\\n`` 结束）的文本。列头固定为
        :data:`CSV_COLUMNS`；网关/DNS 列在不同目标行里重复出现（宽表，方便直接
        在 Excel 里按目标筛选）。

        Note:
        没有配置目标时每个样本仍出一行，``target_*`` 三列留空 —— 这样「有采集
        但没有目标」与「完全没有采集」在 CSV 里能分开。
    """
    lines = [",".join(CSV_COLUMNS)]
    for sample in samples:
        stamp = _epoch_of(sample)
        when = sample.get("t") or (iso(stamp) if stamp is not None else "")
        interval = _cell(sample.get("interval_s"))
        gateway = sample.get("gateway") if isinstance(sample.get("gateway"), Mapping) else {}
        dns = sample.get("dns") if isinstance(sample.get("dns"), Mapping) else {}
        link = sample.get("wlan") if isinstance(sample.get("wlan"), Mapping) else {}
        targets = [item for item in (sample.get("targets") or [])
                   if isinstance(item, Mapping)] or [None]
        for target in targets:
            block = target or {}
            row = (
                _cell(when), interval,
                _cell(gateway.get("rtt_ms")), _cell(gateway.get("loss_pct")),
                _cell(gateway.get("jitter_ms")),
                _cell(dns.get("rtt_ms")),
                _cell(block.get("key")), _cell(block.get("rtt_ms")),
                _cell(block.get("loss_pct")),
                _cell(link.get("bssid")), _cell(link.get("rssi_dbm")),
                _cell(link.get("rx_mbps")), _cell(link.get("band")),
                _cell(link.get("channel")),
            )
            lines.append(",".join(_quote(cell) for cell in row))
    return "\n".join(lines) + "\n"


def _quote(text: str) -> str:
    """CSV 单格转义：含逗号/引号/换行时加双引号并把内部引号翻倍。"""
    if any(ch in text for ch in (",", '"', "\n", "\r")):
        return '"' + text.replace('"', '""') + '"'
    return text


def _nearest(samples: Sequence[Mapping[str, Any]], stamp: float
             ) -> Mapping[str, Any] | None:
    """找出时间上最接近 ``stamp`` 的样本（用于给事件补当时的 AP 与信号）。"""
    best: Mapping[str, Any] | None = None
    best_delta = float("inf")
    for sample in samples:
        value = _epoch_of(sample)
        if value is None:
            continue
        delta = abs(value - stamp)
        if delta < best_delta:
            best, best_delta = sample, delta
    return best


def _duration(seconds: int) -> str:
    """把秒数写成人读时长（``45 秒`` / ``3 分 20 秒`` / ``2 小时 5 分``）。

    Args:
        seconds: 时长（秒）。

    Returns:
        str: 展示用文本。不足 1 分钟**不写成「0 分钟」** —— 一次 21 秒的断档
        写成 0 分钟会被读成「没有缺口」。
    """
    total = max(0, int(seconds))
    if total < 60:
        return f"{total} 秒"
    if total < 3600:
        return f"{total // 60} 分 {total % 60} 秒" if total % 60 else f"{total // 60} 分"
    hours, rest = divmod(total, 3600)
    return f"{hours} 小时 {rest // 60} 分" if rest // 60 else f"{hours} 小时"


def _event_rank(event: Mapping[str, Any]) -> float:
    """事件的「严重程度」：实测值超出阈值的倍数，越大越靠前。"""
    try:
        value = float(event.get("value"))
        limit = float(event.get("threshold"))
    except (TypeError, ValueError):
        return 0.0
    if limit <= 0:
        return value
    return value / limit


def export_markdown(samples: Sequence[Mapping[str, Any]], start: float, end: float,
                    events: Sequence[Mapping[str, Any]] | None = None,
                    *, top: int = 5) -> str:
    """生成人读的历史摘要（时段 / 样本数 / 覆盖率 / 异常 Top5）。

    Args:
        samples: 区间内的样本（按时间升序）。
        start: 区间起点 epoch。
        end: 区间终点 epoch。
        events: 区间内的事件（``None`` 时按区间现读 ``events.jsonl``）。
        top: 异常列几条。

    Returns:
        str: Markdown 文本（``\\n`` 换行）。每条异常带**当时**的 AP 与信号：
        用户看到「15:20 丢包 30%」时，下一个问题一定是「那会儿是不是换 AP 了」。
    """
    if events is None:
        events = read_events(start, end)
    cover = sample_coverage(samples, start, end)
    lines = [
        "# 网络历史摘要",
        "",
        f"- 时段：{iso(start)} → {iso(end)}",
        f"- 样本数：{cover['samples']}（按 {cover['interval_s']}s 间隔估算应采 "
        f"{cover['expected']} 条）",
        f"- 覆盖率：{'-' if cover['ratio'] is None else f'{cover["ratio"] * 100:.1f}%'}",
        f"- 数据缺口：{len(cover['gaps'])} 段",
    ]
    if cover["gaps"]:
        longest = max(cover["gaps"], key=lambda gap: gap["seconds"])
        lines.append(f"- 最长缺口：{longest['from']} → {longest['to']}"
                     f"（{_duration(longest['seconds'])}）")
    lines.append("")

    ranked = sorted(events, key=_event_rank, reverse=True)[:max(0, int(top))]
    lines.append(f"## 异常 Top{max(0, int(top))}")
    lines.append("")
    if not ranked:
        lines.append("无（区间内没有连续超阈值的事件）。")
    else:
        lines.append("| # | 时间 | 目标 | 类型 | 实测 | 阈值 | 当时 AP | 信号 |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for index, event in enumerate(ranked, 1):
            stamp = _epoch_of(event) or float(start)
            sample = _nearest(samples, stamp)
            link = sample.get("wlan") if sample and isinstance(sample.get("wlan"),
                                                              Mapping) else {}
            bssid = (link or {}).get("bssid") or "-"
            ssid = (link or {}).get("ssid") or ""
            ap = f"{ssid}（{bssid}）" if ssid else str(bssid)
            rssi = (link or {}).get("rssi_dbm")
            lines.append(
                f"| {index} | {event.get('t') or iso(stamp)} "
                f"| {event.get('target') or '-'} | {event.get('type') or '-'} "
                f"| {_cell(event.get('value'))} | {_cell(event.get('threshold'))} "
                f"| {ap} | {'-' if rssi is None else f'{_cell(rssi)} dBm'} |")
    lines.append("")
    if cover["gaps"]:
        lines.append("## 缺口明细")
        lines.append("")
        lines.append("| 从 | 到 | 时长 | 缺失样本 |")
        lines.append("|---|---|---|---|")
        for gap in cover["gaps"][:20]:
            lines.append(f"| {gap['from']} | {gap['to']} "
                         f"| {_duration(gap['seconds'])} "
                         f"| {gap['missing']} |")
        if len(cover["gaps"]) > 20:
            lines.append(f"| … | 共 {len(cover['gaps'])} 段 | | |")
        lines.append("")
    lines.append("> 缺口表示这段时间**没有采集数据**（agent 未运行 / 机器休眠），"
                 "不是「丢包 0」。")
    return "\n".join(lines) + "\n"


def export_document(fmt: str, from_value: Any = None, to_value: Any = None,
                    *, now: float | None = None) -> tuple[str, str, str]:
    """按格式生成导出内容。

    Args:
        fmt: ``csv`` / ``md``。
        from_value: 起始时间。
        to_value: 结束时间。
        now: 当前 epoch（测试注入）。

    Returns:
        tuple[str, str, str]: ``(内容, Content-Type, 建议文件名)``。

    Raises:
        ValueError: 格式不支持或时间非法。
    """
    kind = str(fmt or "csv").strip().lower()
    if kind not in ("csv", "md"):
        raise ValueError(f"format 只支持 csv / md，收到 {kind!r}")
    start, end = parse_range(from_value, to_value, now=now)
    samples = read_samples(start, end)
    if kind == "csv":
        body = export_csv(samples)
        ctype = "text/csv; charset=utf-8"
    else:
        body = export_markdown(samples, start, end, read_events(start, end))
        ctype = "text/markdown; charset=utf-8"
    name = f"netdiag-history-{_local(end).strftime('%Y%m%d-%H%M')}.{kind}"
    return body, ctype, name
