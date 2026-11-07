"""把一份 pcap 的抽取值落盘成 ``features.json``，供规则测试回放。

用途：T05 的规则单测**不需要 tshark**。CI 里直接读
``tests/fixtures/faults_features.json``，跑的是同一份特征，
不会因为「没装 Wireshark」而 skip 掉整条判断链路。

用法（在仓库根目录）::

    python scripts/dump_features.py --pcap captures/faults_demo.pcap \
        --out tests/fixtures/faults_features.json

输出结构：``Features.to_dict()`` 的全部键，外加四个顶层元信息 ——
``schema_version`` / ``source_pcap``（只留文件名）/ ``generated_at``（UTC）/
``tshark_version``（当前 tshark 版本首行）。

``tshark_version`` 是给 golden 比对用的：不同版本对同一份 pcap 的字段解析可能不同，
数字对不上时先看版本，比逐个排查口径快。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.contracts import SCHEMA_VERSION                        # noqa: E402
from core.extract import FIELDS, build_features, parse_rows      # noqa: E402
from core.tshark import find_tshark, iter_lines, version         # noqa: E402


def make_args(tshark: Path, pcap: Path) -> list[str]:
    """构造读 pcap 的 tshark 命令行。

    ``occurrence=a`` + ``aggregator=,`` 是现有口径的前提：一个帧里出现两次
    同一字段（如 duplicate_ack）会拼成 ``"1,1"``，解析层依赖这个行为。

    Args:
        tshark: tshark 可执行文件路径。
        pcap: 待解析的抓包文件。

    Returns:
        list[str]: 可直接交给 ``subprocess`` 的 argv。
    """
    args = [str(tshark), "-r", str(pcap), "-n", "-T", "fields",
            "-E", "header=y", "-E", "separator=|", "-E", "quote=d",
            "-E", "aggregator=,", "-E", "occurrence=a"]
    for field in FIELDS:
        args += ["-e", field]
    return args


def main(argv: list[str] | None = None) -> int:
    """命令行入口。

    Args:
        argv: 参数列表；省略时取 ``sys.argv[1:]``。

    Returns:
        int: 0 成功；2 表示找不到 tshark 或 tshark 解析失败。
    """
    ap = argparse.ArgumentParser(description="导出 pcap 的 Features JSON")
    ap.add_argument("--pcap", required=True, help="抓包文件路径")
    ap.add_argument("--out", required=True, help="输出 JSON 路径")
    ap.add_argument("--tshark", default="", help="手动指定 tshark.exe（可选）")
    args = ap.parse_args(argv)

    pcap = Path(args.pcap)
    if not pcap.is_file():
        print(f"[错误] 抓包文件不存在：{pcap}", file=sys.stderr)
        return 2

    tshark = Path(args.tshark) if args.tshark else find_tshark()
    if not tshark:
        print("[错误] 找不到 tshark（既不在 tools/ 也不在 PATH）", file=sys.stderr)
        return 2

    sink: dict = {}
    lines = iter_lines(make_args(tshark, pcap), timeout=1800, sink=sink)
    try:
        rows = parse_rows(lines)
    finally:
        lines.close()

    if not rows:
        err = (sink.get("stderr") or "").strip()
        print(f"[错误] 没解析到任何报文（rc={sink.get('rc')}）：{err[:300]}", file=sys.stderr)
        return 2

    feats = build_features(
        rows,
        meta={"pcap_file": pcap.name, "pcap_name": pcap.name, "mode": "offline"},
    )

    data = feats.to_dict()
    data["schema_version"] = SCHEMA_VERSION
    data["source_pcap"] = pcap.name
    data["tshark_version"] = version(tshark)
    data["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8", newline="\n")

    print(f"已写 {out}｜报文 {len(rows)} 个｜TCP 会话 {len(feats.tcp.streams)} 条"
          f"｜schema {SCHEMA_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
