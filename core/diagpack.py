"""诊断包导出：把 ``logs/`` 里能回答「出了什么问题」的现场打成一个**已脱敏**的 zip。

为什么要有这一层（M2）：软件不联网上报，同事出问题时只能把现场带回来。本模块负责
一键收集、默认脱敏、加体积护栏、写包内 ``README.txt``，最后返回 zip 的绝对路径。

包内结构（SPEC V3）::

    NetDiag-diag-<机器名哈希8位>-<YYYYmmdd-HHMM>.zip
    ├─ README.txt          本包是什么 / 是否脱敏 / 怎么发回 / 不含 pcap
    ├─ env.json            环境快照（绝对路径已脱敏）
    ├─ logs/*.log          最近 30 天的启动 / 诊断日志
    ├─ runs/*.json         最近 20 次分析记录
    ├─ crashes/*.txt       最近 10 份崩溃快照
    └─ reports/*.md|.json  仅 ``include_reports=True``：最近 3 份报告

三条硬约束：

1. **默认脱敏**（:mod:`core.sanitize`）；任何文件脱敏失败 → **跳过并写进 README**，
   绝不静默导出原文（SPEC 红线 4）。``raw=True`` 才保留原值，且 README 与控制台都会警告。
2. **绝不联网**：本模块只 import 标准库的 ``zipfile`` / ``hashlib`` / ``json`` / ``platform``
   与项目内的 ``logstore`` / ``sanitize``，没有任何 socket / urllib / http。
3. **护栏**：单文件 > 10 MB 跳过；包内总量 > 100 MB 的后续文件跳过；两者都写进 README。

输出目录默认 ``<日志根目录>/exports/``（``NETDIAG_LOG_DIR`` 注入时随之变化），
同名 zip 已存在时在文件名后加 ``-2`` / ``-3``，不静默覆盖。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
import zipfile
from pathlib import Path

import logstore
import sanitize

ROOT = Path(__file__).resolve().parents[1]
#: 报告目录；测试可整体替换（避免读仓库里的历史报告）。
REPORTS = ROOT / "reports"

#: 只收集最近这么多天的 ``logs/*.log``。
LOG_DAYS = 30
#: ``runs/`` 收录条数。
KEEP_RUNS = 20
#: ``crashes/`` 收录份数（只收 ``*.txt``，不含 faulthandler 的 ``fatal-*.log``）。
KEEP_CRASHES = 10
#: ``--include-reports`` 收录的报告份数（同名 ``.md`` / ``.json`` 算一份）。
KEEP_REPORTS = 3
#: 单文件上限（字节）。超过就跳过并写进 README（SPEC V9）。
MAX_FILE_BYTES = 10 << 20
#: 包内文件总量上限（字节）。超过后按收集顺序跳过后面的文件。
MAX_TOTAL_BYTES = 100 << 20

README_NAME = "README.txt"
_KB = 1024.0
_MB = 1024.0 * 1024.0


def build(out_dir=None, include_reports: bool = False, raw: bool = False) -> Path:
    """收集现场 → 脱敏 → 写 zip，返回诊断包路径（唯一公开入口，SPEC V1）。

    Args:
        out_dir: 输出目录；``None`` 表示默认的 ``<日志根目录>/exports/``。
            相对路径按当前工作目录解析，不存在会自动创建。
        include_reports: 是否附上 ``reports/`` 里最近 3 份报告（``.md`` / ``.json``）。
        raw: ``True`` 表示**不脱敏**、保留原始 IP/域名/用户名/MAC；默认 ``False``。
            控制台警告由调用方（CLI / 服务端）打印，包内 README 也会写醒目警告。

    Returns:
        Path: 新生成的 zip 的绝对路径。同名文件已存在时会顺延 ``-2`` / ``-3``，
            不会覆盖旧包。

    Raises:
        OSError: 输出目录不可写、zip 写盘失败（半成品会被删除后重新抛出）。
            单个源文件读不到或脱敏失败不算错误，只会跳过并写进 README。
    """
    root = logstore.log_root()
    out = Path(out_dir) if out_dir else root / "exports"
    out.mkdir(parents=True, exist_ok=True)

    skipped: list[str] = []
    entries: list[tuple[str, bytes]] = []
    _collect_env(root, raw, entries, skipped)
    _collect_logs(root, raw, entries, skipped)
    _collect_runs(root, raw, entries, skipped)
    _collect_crashes(root, raw, entries, skipped)
    if include_reports:
        _collect_reports(raw, entries, skipped)

    entries = _fit_total(entries, skipped)
    target = _unique_path(out)
    readme = _render_readme(entries, skipped, raw, include_reports)
    try:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            for arcname, data in entries:
                zf.writestr(arcname, data)
            zf.writestr(README_NAME, readme.encode("utf-8"))
    except Exception:  # noqa: BLE001  写一半的包不能留下，否则看起来像“成功”
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return target


# ---------------------------------------------------------------- 收集
def _collect_env(root: Path, raw: bool, entries: list, skipped: list) -> None:
    """收录 ``env.json``：解析成对象后递归脱敏（绝对路径 → ``<root>`` 形式）。"""
    path = root / "env.json"
    if not path.is_file():
        skipped.append("env.json（本次启动还没写过环境快照）")
        return
    _add_file("env.json", path, raw, entries, skipped, as_json=True)


def _collect_logs(root: Path, raw: bool, entries: list, skipped: list) -> None:
    """收录日志根目录下最近 :data:`LOG_DAYS` 天的 ``*.log``（历史命名也收）。"""
    cutoff = dt.datetime.now().timestamp() - LOG_DAYS * 86400
    paths = []
    try:
        candidates = sorted(root.glob("*.log"))
    except OSError:
        candidates = []
    for path in candidates:
        try:
            if path.is_file() and path.stat().st_mtime >= cutoff:
                paths.append(path)
        except OSError:
            continue
    if not paths:
        skipped.append(f"logs/*.log（最近 {LOG_DAYS} 天没有日志文件）")
    for path in paths:
        _add_file(f"logs/{path.name}", path, raw, entries, skipped)


def _collect_runs(root: Path, raw: bool, entries: list, skipped: list) -> None:
    """收录 ``runs/`` 里最近的 :data:`KEEP_RUNS` 条分析记录（JSON 逐字段脱敏）。"""
    paths = _recent(root / "runs", "*.json", KEEP_RUNS)
    if not paths:
        skipped.append("runs/*.json（没有分析记录）")
    for path in paths:
        _add_file(f"runs/{path.name}", path, raw, entries, skipped, as_json=True)


def _collect_crashes(root: Path, raw: bool, entries: list, skipped: list) -> None:
    """收录 ``crashes/`` 里最近的 :data:`KEEP_CRASHES` 份 ``*.txt`` 崩溃快照。"""
    paths = _recent(root / "crashes", "*.txt", KEEP_CRASHES)
    if not paths:
        skipped.append("crashes/*.txt（没有崩溃快照）")
    for path in paths:
        _add_file(f"crashes/{path.name}", path, raw, entries, skipped)


def _collect_reports(raw: bool, entries: list, skipped: list) -> None:
    """收录 ``reports/`` 最近 :data:`KEEP_REPORTS` 份报告（同名 `.md` / `.json` 成对收）。"""
    try:
        files = [p for p in REPORTS.iterdir()
                 if p.is_file() and p.suffix.lower() in (".md", ".json")]
    except OSError:
        files = []
    groups: dict[str, list[Path]] = {}
    for path in files:
        groups.setdefault(path.stem, []).append(path)
    if not groups:
        skipped.append("reports/（没有报告文件）")
        return
    stems = sorted(groups, key=lambda stem: (max(_mtime(p) for p in groups[stem]), stem),
                   reverse=True)[:KEEP_REPORTS]
    for stem in stems:
        for path in sorted(groups[stem], key=lambda p: p.name):
            _add_file(f"reports/{path.name}", path, raw, entries, skipped,
                      as_json=path.suffix.lower() == ".json")


def _recent(directory: Path, pattern: str, limit: int) -> list[Path]:
    """目录内按 mtime 倒序取最新 ``limit`` 个文件；目录不存在返回空列表。"""
    try:
        paths = [p for p in directory.glob(pattern) if p.is_file()]
    except OSError:
        return []
    paths.sort(key=lambda p: (_mtime(p), p.name), reverse=True)
    return paths[:max(0, int(limit))]


def _mtime(path: Path) -> int:
    """取 mtime（纳秒）；读不到按 0 处理（排到最旧）。"""
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def _add_file(arcname: str, path: Path, raw: bool, entries: list, skipped: list,
              as_json: bool = False) -> None:
    """读一个文件 → 脱敏 → 放进待写列表；读/脱敏失败只记入 ``skipped``，不抛异常。"""
    try:
        size = path.stat().st_size
    except OSError:
        skipped.append(f"{arcname}（读不到文件信息）")
        return
    if size > MAX_FILE_BYTES:
        skipped.append(f"{arcname}（{_human_size(size)}，超过单文件 "
                       f"{_human_size(MAX_FILE_BYTES)} 上限）")
        return
    try:
        data = path.read_bytes()
        if not raw:
            data = _mask_json_bytes(data) if as_json else _mask_text_bytes(data)
    except Exception:  # noqa: BLE001  脱敏失败宁可少一个文件，不可导出原文（SPEC 红线 4）
        skipped.append(f"{arcname}（脱敏失败，已跳过，未导出原文）")
        return
    if len(data) > MAX_FILE_BYTES:
        skipped.append(f"{arcname}（脱敏后 {_human_size(len(data))}，超过单文件上限）")
        return
    entries.append((arcname, data))


def _fit_total(entries: list, skipped: list) -> list:
    """包内总量护栏：按收集顺序累加，超 :data:`MAX_TOTAL_BYTES` 的后续文件跳过。"""
    kept: list[tuple[str, bytes]] = []
    total = 0
    for arcname, data in entries:
        if total + len(data) > MAX_TOTAL_BYTES:
            skipped.append(f"{arcname}（{_human_size(len(data))}，超过包内总量 "
                           f"{_human_size(MAX_TOTAL_BYTES)} 上限）")
            continue
        kept.append((arcname, data))
        total += len(data)
    return kept


# ---------------------------------------------------------------- 脱敏
def _mask_text_bytes(data: bytes) -> bytes:
    """字节流转文本脱敏再转回 UTF-8（日志是 UTF-8；坏字节用替换符，不泄露原文）。"""
    return sanitize.mask_text(data.decode("utf-8", "replace")).encode("utf-8")


def _mask_json_bytes(data: bytes) -> bytes:
    """JSON 文件：先解析再 ``mask_obj``，保持结构可读；解析失败退化为纯文本脱敏。"""
    text = data.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        return sanitize.mask_text(text).encode("utf-8")
    return (json.dumps(sanitize.mask_obj(payload), ensure_ascii=False, indent=2)
            + "\n").encode("utf-8")


# ---------------------------------------------------------------- 输出
def _machine_hash() -> str:
    """机器名哈希：``sha1(platform.node())`` 前 8 位 —— 文件名里**不许**出现真实机器名。"""
    return hashlib.sha1(platform.node().encode("utf-8")).hexdigest()[:8]


def _unique_path(out: Path) -> Path:
    """生成 ``NetDiag-diag-<hash>-<YYYYmmdd-HHMM>.zip``；重名顺延 ``-2`` / ``-3``。"""
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    base = f"NetDiag-diag-{_machine_hash()}-{stamp}"
    candidate = out / f"{base}.zip"
    sequence = 2
    while candidate.exists():
        candidate = out / f"{base}-{sequence}.zip"
        sequence += 1
    return candidate


def _human_size(size: int) -> str:
    """把字节数变成 ``1.2 MB`` / ``340 KB`` 这类人读格式。"""
    value = float(size)
    if value >= _MB:
        return f"{value / _MB:.1f} MB"
    if value >= _KB:
        return f"{value / _KB:.1f} KB"
    return f"{int(value)} B"


def _version() -> str:
    """读仓库 ``VERSION``；读不到返回空串（README 里只是装饰信息）。"""
    try:
        return (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _render_readme(entries: list, skipped: list, raw: bool, include_reports: bool) -> str:
    """拼包内 ``README.txt``：是什么 / 是否脱敏 / 怎么发回 / 不含 pcap / 不上传。"""
    stamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    total = sum(len(data) for _, data in entries)
    lines = [
        "=" * 64,
        "USB-Net-Diag 诊断包",
        "=" * 64,
        "",
        f"生成时间: {stamp}",
        f"工具版本: {_version() or '未知'}",
        f"机器标识: {_machine_hash()}（机器名 SHA1 前 8 位，只用于区分机器，不可反推）",
        "",
    ]
    if raw:
        lines += [
            "【脱敏状态】⚠ 未脱敏（--raw）：已保留原值",
            "本包含有原始 IP / 域名 / 用户名 / MAC！只允许通过可信渠道发给维护者，",
            "不要上传到公开位置、不要贴到工单系统。",
        ]
    else:
        lines += [
            "【脱敏状态】已脱敏",
            "IP / 域名 / 用户名 / MAC 均已替换为不可还原的伪名：",
            "  · 私有 IP 保留网段、尾段变 ***；公网 IP 保留前两段，后两段变 ***。",
            "  · 域名保留首字符与顶级域，中间变 *（例如 w**.c******.com）。",
            r"  · C:\Users\<用户名> 变 C:\Users\<user>。",
            "  · MAC 保留前 3 字节，尾 3 字节变 **。",
            "  · 每个对象带 #xxxx 伪名后缀：同一对端出现多次时后缀相同，便于统计次数。",
            "  · 端口、协议、错误码、版本号保持原样（排障必需）。",
        ]
    lines += [
        "",
        "【包里有什么】",
        "  README.txt     本说明",
        "  env.json       环境快照（版本/系统/tshark/是否管理员/配置指纹）",
        f"  logs/*.log     最近 {LOG_DAYS} 天的启动与诊断日志",
        f"  runs/*.json    最近 {KEEP_RUNS} 次分析记录",
        f"  crashes/*.txt  最近 {KEEP_CRASHES} 份崩溃快照",
    ]
    if include_reports:
        lines.append(f"  reports/       最近 {KEEP_REPORTS} 份报告（.md / .json）")
    lines += [
        "",
        f"实际收录 {len(entries)} 个文件，合计 {_human_size(total)}：",
    ]
    for arcname, data in entries:
        lines.append(f"  - {arcname}  ({_human_size(len(data))})")
    if not entries:
        lines.append("  （没有可收录的文件）")
    lines += ["", "【没有收录 / 被跳过的文件】"]
    if skipped:
        lines += [f"  - {item}" for item in skipped]
    else:
        lines.append("  无")
    lines += [
        "",
        "【包里没有的东西】",
        "  · 不含 pcap / pcapng 抓包文件，也不含任何报文载荷（体积大且可能带业务数据）。",
        "  · 不含 AI Key 与 config/*.json 的配置值（env.json 只保留 config_sha256 指纹）。",
        "  · 本工具不联网、不上传任何数据；这个 zip 只在本机生成。",
        "",
        "【怎么发回】",
        "  把整个 zip 原样发回给维护者（IM / 邮件均可）。不用解压、不用改名。",
        "  聊天软件里请选「发送文件」，不要截图。",
        "",
    ]
    return "\n".join(lines)
