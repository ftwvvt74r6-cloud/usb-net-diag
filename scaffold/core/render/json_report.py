"""JSON 报告 + 落盘命名策略。

修的是现有实现的一个隐患（评审 P1）：``reports/<pcap 名>.md`` 直接覆盖写，
同一份 pcap 分析两次，前一份报告就没了。诊断报告属于「审计证据」，
**不应该被后来的结论覆盖**。

命名：``<stem>.<YYYYmmdd-HHMMSS>.<schema>.json``，冲突再追加 ``-2``。
解析用的「最新一份」由 mtime 或历史库决定，不靠文件名排序。
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..contracts import SCHEMA_VERSION, AnalyzeResult, to_jsonable
from .markdown import render
from .text import CopyTable


def to_document(result: AnalyzeResult) -> dict:
    """机器可读报告：只保留有长期价值的部分（不含内存态字段）。"""
    doc = {
        "schema_version": result.schema_version or SCHEMA_VERSION,
        "capture": to_jsonable(result.capture),
        "metrics": to_jsonable(result.metrics),
        "findings": to_jsonable(result.findings),
        "verdict": to_jsonable(result.verdict),
        "provenance": to_jsonable(result.provenance),
    }
    return doc


def dumps(result: AnalyzeResult) -> str:
    return json.dumps(to_document(result), ensure_ascii=False, indent=2)


def _unique(path: Path) -> Path:
    if not path.exists():
        return path
    for i in range(2, 1000):
        candidate = path.with_name(f"{path.stem}-{i}{path.suffix}")
        if not candidate.exists():
            return candidate
    return path


def save(result: AnalyzeResult, out_dir: Path | str,
         copy: CopyTable | None = None, now: datetime | None = None) -> dict:
    """写出 ``.json`` 与 ``.md``，返回两份路径。**永不覆盖**已有报告。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    stem = Path(result.capture.pcap_name or "report").stem or "report"
    base = f"{stem}.{stamp}"

    json_path = _unique(out / f"{base}.json")
    json_path.write_text(dumps(result), encoding="utf-8")

    md_path = _unique(out / f"{base}.md")
    md_path.write_text(render(result, copy), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def load(path: Path | str) -> dict:
    """读回一份 JSON 报告（给基线对比 / 快照测试用）。"""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def normalize(doc: dict) -> dict:
    """快照测试用：抹掉时间戳等易变字段，只比「结论」。"""
    doc = json.loads(json.dumps(doc, ensure_ascii=False))
    prov = doc.get("provenance") or {}
    for volatile in ("generated_at", "tshark_version", "config_sha256"):
        prov.pop(volatile, None)
    cap = doc.get("capture") or {}
    for volatile in ("pcap_file", "first_ts", "last_ts"):
        cap.pop(volatile, None)
    return doc


__all__ = ["to_document", "dumps", "save", "load", "normalize"]
