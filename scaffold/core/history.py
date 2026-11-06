"""历史基线库（sqlite3）。

**这是规划里完全缺失的一层。** 没有它，以下三件事永远做不到：

1. 「高峰期拥塞」——单次抓包无法定义「高峰」，必须和历史同一时段比；
2. 「比昨天更差吗」——需要同一目标的纵向对比；
3. 「这条规则误报率多少」——需要记录「命中之后现场是否真的有问题」。

便携 Python 已内置 ``_sqlite3.pyd`` 与 ``sqlite3.dll``，无需 pip。

表结构刻意很窄（只存结论与关键指标），原始 pcap 不进库：

    case(id, ts, target, profile, level, rules_hit, metrics_json, provenance_json, note)

查询示例（给 verdict/AI 用）::

    base = baseline("/app/health")     # 该目标最近 N 次的指标中位数
    if today_retrans > base["retrans_rate"] * 2: ...
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .contracts import AnalyzeResult, to_jsonable
from .platform.paths import PATHS

SCHEMA = """
CREATE TABLE IF NOT EXISTS case (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             REAL    NOT NULL,
    target         TEXT    NOT NULL DEFAULT '',
    profile        TEXT    NOT NULL DEFAULT '',
    level          TEXT    NOT NULL DEFAULT '',
    rules_hit      TEXT    NOT NULL DEFAULT '',
    metrics_json   TEXT    NOT NULL DEFAULT '{}',
    provenance_json TEXT   NOT NULL DEFAULT '{}',
    note           TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_case_target_ts ON case(target, ts);
CREATE INDEX IF NOT EXISTS idx_case_ts        ON case(ts);
"""


@dataclass(frozen=True)
class Baseline:
    """某目标的纵向基线：取窗口内指标的中位数。"""

    target: str
    samples: int
    metrics: Mapping[str, float]
    last_ts: float = 0.0

    def ratio(self, key: str, value: float) -> float | None:
        """返回相对基线的倍数；基线缺失或为 0 时返回 None（**不要用 0 做除数**）。"""
        base = self.metrics.get(key)
        if not base:
            return None
        return value / base


def db_path(path: Path | str | None = None) -> Path:
    if path:
        return Path(path)
    PATHS.data.mkdir(parents=True, exist_ok=True)
    return PATHS.data / "history.db"


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path(path)), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def record(result: AnalyzeResult, target: str = "", profile: str = "",
           note: str = "", path: Path | str | None = None) -> int:
    """写入一条诊断结论，返回行 id。"""
    verdict = result.verdict
    level = getattr(getattr(verdict, "level", None), "value", "")
    rules = ",".join(f.rule_id for f in result.findings)
    with connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO case(ts,target,profile,level,rules_hit,metrics_json,"
            "provenance_json,note) VALUES(?,?,?,?,?,?,?,?)",
            (time.time(), target or result.capture.pcap_name, profile, level, rules,
             json.dumps(to_jsonable(result.metrics), ensure_ascii=False),
             json.dumps(to_jsonable(result.provenance), ensure_ascii=False), note),
        )
        return int(cur.lastrowid or 0)


def history(target: str = "", limit: int = 20,
            path: Path | str | None = None) -> list[dict]:
    sql = "SELECT * FROM case"
    args: list[Any] = []
    if target:
        sql += " WHERE target = ?"
        args.append(target)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(max(1, int(limit)))
    with connect(path) as conn:
        rows = conn.execute(sql, args).fetchall()
    return [dict(r) for r in rows]


def baseline(target: str, window: int = 20, keys: Iterable[str] = (),
             path: Path | str | None = None) -> Baseline:
    """取窗口内**每个指标的中位数**作为基线。

    用中位数而不是平均值：网络指标的长尾很重，平均值会被一次异常拉偏。
    """
    rows = history(target, limit=window, path=path)
    if not rows:
        return Baseline(target=target, samples=0, metrics={})

    wanted = list(keys) or []
    buckets: dict[str, list[float]] = {}
    for row in rows:
        try:
            metrics = json.loads(row.get("metrics_json") or "{}")
        except ValueError:
            continue
        for key, value in metrics.items():
            if wanted and key not in wanted:
                continue
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                buckets.setdefault(key, []).append(float(value))

    medians: dict[str, float] = {}
    for key, values in buckets.items():
        values.sort()
        mid = len(values) // 2
        medians[key] = (values[mid] if len(values) % 2
                        else round((values[mid - 1] + values[mid]) / 2, 3))
    return Baseline(target=target, samples=len(rows), metrics=medians,
                    last_ts=float(rows[0].get("ts") or 0.0))


def hourly_profile(target: str, days: int = 7, path: Path | str | None = None) -> dict[int, int]:
    """按小时统计命中次数，用来粗判「是否集中在业务高峰」。

    注意：这只能给「倾向性」提示，不能单独作为「高峰期拥塞」的结论
    （评审 3.3：单点抓包无法直接证明 UDP 丢包与高峰相关）。
    """
    since = time.time() - max(1, int(days)) * 86400
    sql = ("SELECT CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER) AS h, "
           "COUNT(*) AS n FROM case WHERE ts >= ?")
    args: list[Any] = [since]
    if target:
        sql += " AND target = ?"
        args.append(target)
    sql += " GROUP BY h"
    with connect(path) as conn:
        rows = conn.execute(sql, args).fetchall()
    return {int(r["h"]): int(r["n"]) for r in rows}


__all__ = ["SCHEMA", "Baseline", "db_path", "connect", "record",
           "history", "baseline", "hourly_profile"]
