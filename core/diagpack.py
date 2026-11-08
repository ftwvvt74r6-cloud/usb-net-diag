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
   文件名（zip 条目名）与文件内容走**同一套**脱敏；``*`` 是 Windows 非法文件名字符，
   条目名里的 ``*`` / ``<`` / ``>`` 等统一换成 ``_``（例如
   ``192.168.1.***#25c9.pcap`` → ``192.168.1.___#25c9.pcap``），保证能正常解压。
2. **绝不联网**：本模块只 import 标准库的 ``zipfile`` / ``hashlib`` / ``json`` /
   ``platform`` / ``re`` 与项目内的 ``logstore`` / ``sanitize``，没有任何 socket / urllib / http。
3. **护栏**：单文件 > 10 MB 跳过；包内总量 > 100 MB 的后续文件跳过；两者都写进 README。
4. **默认拒绝的泄漏自检**：脱敏时收集所有被替换的原值 token；写 zip **之前**逐个扫描
   条目的名字与内容，只要仍出现任何一个 → 抛异常、**不写 zip**。错误信息只报类别，
   不打印原值（宁可导出失败，不可泄露）。

输出目录默认 ``<日志根目录>/exports/``（``NETDIAG_LOG_DIR`` 注入时随之变化），
同名 zip 已存在时在文件名后加 ``-2`` / ``-3``，不静默覆盖。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
import re
import zipfile
from pathlib import Path

import logstore
import sanitize
from version import read_version

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
        RuntimeError: 泄漏自检发现仍有原值残留；此时**不会生成 zip**，错误信息只报
            token 类别、不含原值（默认拒绝：宁可导出失败，不可泄露）。

    Note:
        自检只在默认（非 ``raw``）模式执行；``raw=True`` 按设计保留原值。
    """
    root = logstore.log_root()
    out = Path(out_dir) if out_dir else root / "exports"
    out.mkdir(parents=True, exist_ok=True)

    skipped: list[str] = []
    entries: list[tuple[str, bytes]] = []
    tokens: dict[str, str] = {}
    _collect_env(root, raw, entries, skipped, tokens)
    _collect_logs(root, raw, entries, skipped, tokens)
    _collect_runs(root, raw, entries, skipped, tokens)
    _collect_crashes(root, raw, entries, skipped, tokens)
    if include_reports:
        _collect_reports(raw, entries, skipped, tokens)

    entries = _fit_total(entries, skipped)
    readme_bytes = _render_readme(entries, skipped, raw, include_reports).encode("utf-8")
    if not raw:
        # 默认拒绝：写 zip 之前，条目名 + 内容 + README 全部过一遍；命中即中止。
        _verify_no_leaks(entries + [(README_NAME, readme_bytes)], tokens)
    target = _unique_path(out)
    try:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            for arcname, data in entries:
                zf.writestr(arcname, data)
            zf.writestr(README_NAME, readme_bytes)
    except Exception:  # noqa: BLE001  写一半的包不能留下，否则看起来像“成功”
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return target


# ---------------------------------------------------------------- 收集
def _collect_env(root: Path, raw: bool, entries: list, skipped: list,
                 tokens: dict) -> None:
    """收录 ``env.json``：解析成对象后递归脱敏（绝对路径 → ``<root>`` 形式）。"""
    path = root / "env.json"
    if not path.is_file():
        skipped.append("env.json（本次启动还没写过环境快照）")
        return
    _add_file("env.json", path, raw, entries, skipped, tokens, as_json=True)


def _collect_logs(root: Path, raw: bool, entries: list, skipped: list,
                  tokens: dict) -> None:
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
        _add_file(f"logs/{path.name}", path, raw, entries, skipped, tokens)


def _collect_runs(root: Path, raw: bool, entries: list, skipped: list,
                  tokens: dict) -> None:
    """收录 ``runs/`` 里最近的 :data:`KEEP_RUNS` 条分析记录（JSON 逐字段脱敏）。"""
    paths = _recent(root / "runs", "*.json", KEEP_RUNS)
    if not paths:
        skipped.append("runs/*.json（没有分析记录）")
    for path in paths:
        _add_file(f"runs/{path.name}", path, raw, entries, skipped, tokens, as_json=True)


def _collect_crashes(root: Path, raw: bool, entries: list, skipped: list,
                     tokens: dict) -> None:
    """收录 ``crashes/`` 里最近的 :data:`KEEP_CRASHES` 份 ``*.txt`` 崩溃快照。"""
    paths = _recent(root / "crashes", "*.txt", KEEP_CRASHES)
    if not paths:
        skipped.append("crashes/*.txt（没有崩溃快照）")
    for path in paths:
        _add_file(f"crashes/{path.name}", path, raw, entries, skipped, tokens)


def _collect_reports(raw: bool, entries: list, skipped: list, tokens: dict) -> None:
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
            _add_file(f"reports/{path.name}", path, raw, entries, skipped, tokens,
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


#: Windows 文件名非法字符（``*`` 来自 ``***`` 打码，``<>`` 来自 ``<user>`` 等占位符）。
_ILLEGAL_ARCNAME = re.compile(r'[<>:"|?*\x00-\x1f]')


def _fs_safe_arcname(name: str) -> str:
    """把脱敏后的名字变成 Windows 可解压的条目名（非法字符 → ``_``）。

    只是**展示层**兼容：``192.168.1.***#25c9.pcap`` → ``192.168.1.___#25c9.pcap``；
    脱敏本身仍用同一套 :func:`core.sanitize.mask_text`，原值同样搜不到。
    """
    parts = []
    for part in name.split("/"):
        part = _ILLEGAL_ARCNAME.sub("_", part).rstrip(" .")
        parts.append(part or "_")
    return "/".join(parts)


def _mask_arcname(name: str, raw: bool) -> tuple[str, dict[str, str]]:
    """给 zip 条目名脱敏并返回收集到的 token；``raw=True`` 原样保留。"""
    if raw:
        return name, {}
    tokens: dict[str, str] = {}
    return _fs_safe_arcname(sanitize.mask_text(name, tokens)), tokens


def _add_file(arcname_raw: str, path: Path, raw: bool, entries: list, skipped: list,
              tokens: dict, as_json: bool = False) -> None:
    """读一个文件 → 脱敏 → 放进待写列表；读/脱敏失败只记入 ``skipped``，不抛异常。"""
    try:
        arcname, name_tokens = _mask_arcname(arcname_raw, raw)
    except Exception:  # noqa: BLE001  名字都脱敏不了，连名字都不能写进 README
        skipped.append("某个文件（文件名脱敏失败，已跳过，未导出原文）")
        return
    tokens.update(name_tokens)
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
            data = (_mask_json_bytes(data, tokens) if as_json
                    else _mask_text_bytes(data, tokens))
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
def _mask_text_bytes(data: bytes, tokens: dict) -> bytes:
    """字节流转文本脱敏再转回 UTF-8（日志是 UTF-8；坏字节用替换符，不泄露原文）。"""
    return sanitize.mask_text(data.decode("utf-8", "replace"), tokens).encode("utf-8")


def _mask_json_bytes(data: bytes, tokens: dict) -> bytes:
    """JSON 文件：先解析再 ``mask_obj``，保持结构可读；解析失败退化为纯文本脱敏。"""
    text = data.decode("utf-8", "replace")
    # 原文也扫一遍：键名/转义形式（如 JSON 里的 \\\\host）里的敏感串同样要进自检清单。
    tokens.update(sanitize.collect_tokens(text))
    try:
        payload = json.loads(text)
    except ValueError:
        return sanitize.mask_text(text, tokens).encode("utf-8")
    return (json.dumps(sanitize.mask_obj(payload, tokens), ensure_ascii=False, indent=2)
            + "\n").encode("utf-8")


#: 自检时各类 token 的边界：避免 ``110.0.0.1`` 里的 ``10.0.0.1``、``digital`` 里的
#: ``git`` 这种子串误报，同时保证 ``192.168.1.100.pcap`` / ``\\Users\\alice\\`` 这类
#: **真实泄漏形态**一定能命中。
_LEAK_BOUNDARY = {
    "ipv4": (r"(?<![\d.])", r"(?!\d|\.\d)"),
    "ipv6": (r"(?<![0-9A-Za-z:])", r"(?![0-9A-Za-z:])"),
    "domain": (r"(?<![A-Za-z0-9-])", r"(?![A-Za-z0-9-])"),
    "mac": (r"(?<![0-9A-Fa-f:.-])", r"(?![0-9A-Fa-f:-])"),
    "user": (r"(?<![A-Za-z0-9_])", r"(?![A-Za-z0-9_])"),
    "host": (r"(?<![A-Za-z0-9_.-])", r"(?![A-Za-z0-9_-])"),
}
_DEFAULT_LEAK_BOUNDARY = (r"(?<![A-Za-z0-9_.-])", r"(?![A-Za-z0-9_.-])")

#: 脱敏占位符（``<user>`` / ``<host>`` …）。它们不是原值，自检前先挖掉。
_PLACEHOLDER_RE = re.compile(r"<(?:user|host|root|home|ipv6)>", re.IGNORECASE)

#: 错误信息里只出现类别名，绝不出现原值（审查要求：不许打印原值）。
_LEAK_LABELS = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "domain": "域名",
    "mac": "MAC",
    "user": "用户名",
    "host": "主机名",
}


def _verify_no_leaks(entries: list[tuple[str, bytes]], tokens: dict[str, str]) -> None:
    """默认拒绝的泄漏自检：条目**名字 + 内容**里只要还有原值 token 就抛异常。

    在 :func:`build` 写 zip **之前**调用；抛异常时调用方不会生成 zip（宁可导出失败，
    不可泄露）。错误信息只报命中类别（如 ``IPv4(ipv4)``），**不打印原值或文件名**。

    Args:
        entries: ``(zip 条目名, 内容字节)`` 列表；调用方应把 README 也算进去。
        tokens: ``{原始 token: 类别}``，来自 :func:`core.sanitize.collect_tokens`。

    Raises:
        RuntimeError: 任一 token 仍出现在条目名或 UTF-8 文本内容里。异常信息只含类别。
    """
    if not tokens:
        return
    patterns: list[tuple[str, str, re.Pattern[str]]] = []
    for token, category in tokens.items():
        left, right = _LEAK_BOUNDARY.get(category, _DEFAULT_LEAK_BOUNDARY)
        patterns.append((token.lower(), category,
                         re.compile(left + re.escape(token.lower()) + right)))
    hits: set[str] = set()
    for arcname, data in entries:
        # 占位符 <user>/<root> 等不是原值；先挖掉。lower() 让后面的子串预筛和
        # 边界正则都只处理小写，避免对每个 token 重复做大小写转换。
        haystacks = [
            _PLACEHOLDER_RE.sub(" ", arcname).lower(),
            _PLACEHOLDER_RE.sub(" ", data.decode("utf-8", "replace")).lower(),
        ]
        for token, category, pattern in patterns:
            if category in hits:
                continue
            for haystack in haystacks:
                # 先用 C 实现的子串查找预筛；绝大多数 token 根本不在文本里。
                if token in haystack and pattern.search(haystack):
                    hits.add(category)
                    break
    if hits:
        labels = "、".join(f"{_LEAK_LABELS.get(key, key)}({key})" for key in sorted(hits))
        raise RuntimeError(
            f"诊断包泄漏自检失败：检出 {labels} 类原值残留，已中止导出（未生成 zip）")


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
    """读仓库 ``VERSION``（剥 UTF-8 BOM）；读不到回退 ``0.0.0``。"""
    return read_version(ROOT)


def _render_readme(entries: list, skipped: list, raw: bool, include_reports: bool) -> str:
    """拼包内 ``README.txt``：是什么 / 是否脱敏 / 怎么发回 / 不含 pcap / 不上传。"""
    stamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    total = sum(len(data) for _, data in entries)
    lines = [
        "=" * 64,
        "NetDiag · 网络矩阵 诊断包",
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
            r"  · C:\Users\<用户名> 变 C:\Users\<user>；%USERPROFILE% 变 <home>；",
            r"    \\主机名\共享 的主机名变 <host>。",
            "  · 文件名里的 IP / 域名也会脱敏，只保留扩展名",
            "    （例如抓包名的主机段 → 192.168.1.***#25c9.pcap）。",
            "  · zip 条目名里的 * / < / > 会换成 _（Windows 解压不允许这些字符），脱敏效果不变。",
            "  · MAC 保留前 3 字节，尾 3 字节变 **。",
            "  · 每个对象带 #xxxx 伪名后缀：同一对端出现多次时后缀相同，便于统计次数。",
            "  · 端口、协议、错误码、版本号保持原样（排障必需）。",
            "  · 导出前还会做一次泄漏自检：只要仍有原值残留就中止，不会生成 zip。",
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
        "  · 不含 AI Key；env.json 只保留 config_sha256 指纹，不写 config/*.json 的配置值。",
        "  · 诊断日志里若出现 AI 模型/地址，其中的域名与 IP 同样会被脱敏。",
        "  · 本工具不联网、不上传任何数据；这个 zip 只在本机生成。",
        "",
        "【怎么发回】",
        "  把整个 zip 原样发回给维护者（IM / 邮件均可）。不用解压、不用改名。",
        "  聊天软件里请选「发送文件」，不要截图。",
        "",
        "【阅读报告】",
        "  报告结论含边界字段（依据 / 本次覆盖 / 明确未覆盖 / 置信度 / 关键边界），",
        "  请整块阅读，不要只看一句话结论；单独转述结论会丢失覆盖范围。",
        "",
    ]
    return "\n".join(lines)
