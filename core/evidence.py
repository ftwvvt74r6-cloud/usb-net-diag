"""通用「取证请求单」：把本次诊断结论翻译成一张可直接转发的取证清单。

**解决什么问题**：诊断只能看到终端这一侧。当结论指向无线、接入交换机、出口、
DNS、代理或服务端时，使用者需要向对应部门要证据，但往往说不清「要什么、为什么、
在哪看、多少算正常」。本模块把「还需要谁提供什么」变成一页可转发的清单。

**谁调用它**：:func:`core.report.render_markdown`（报告内区块）、
:mod:`core.server`（``/api/evidence`` 与 ``/api/status`` 的加法字段）、
``ui/index.html``（结果页区块与复制/导出按钮）。

**不做什么**：不联网、不写文件、不读时钟、不做回填；不按厂商或产品组织维度；
不在本模块硬编码清单中文正文（正文只在 ``core/copy/evidence_checklist.json``）。

**输入输出**：``result``（:func:`core.analyzer.analyze` / :func:`core.verdict.build`
的结果）→ 清单字典（``{"full", "level", "layer", "dimensions"}``）→
Markdown（报告）或纯文本（复制到微信/工单）。

7 个维度按**证据来源方**划分：终端侧 / 无线接入侧 / 有线接入侧 / 承载与出口侧 /
名称解析与地址 / 加密与代理 / 服务侧。维度机器码见 :data:`DIMENSION_KEYS`，
中文名、说明与条目全部来自模板 JSON。
"""
from __future__ import annotations

import json
from pathlib import Path

try:                                    # 扁平导入：core/ 在 sys.path 上（report/server）
    from copytext import text as _copy_text
except ModuleNotFoundError:             # 包导入：仓库根在 sys.path 上（tests）
    from core.copytext import text as _copy_text

try:                                    # 判定结果缺失时按需现算（纯函数，不联网）
    import verdict as _verdict_mod
except ModuleNotFoundError:             # 包导入
    from core import verdict as _verdict_mod

try:                                    # 结论边界块（E1：取证单前置「结论+边界」）
    import conclusion as _conclusion_mod
except ModuleNotFoundError:             # 包导入
    from core import conclusion as _conclusion_mod

#: 清单模板的唯一位置（清单正文只在这里维护）。
_TEMPLATE_PATH = Path(__file__).resolve().parent / "copy" / "evidence_checklist.json"

#: 7 个「证据来源方」维度的机器码，顺序即报告/界面里的展示顺序。
#: 不允许按厂商/产品增加维度 —— 换一家厂商不该换一张清单。
DIMENSION_KEYS = (
    "terminal",        # 终端侧（工具自采，声明「已具备」）
    "wireless",        # 无线接入侧（无线控制器/AP 管理后台）
    "wired",           # 有线接入侧（接入交换机）
    "transport",       # 承载与出口侧（网关/防火墙/VPN/专线）
    "naming",          # 名称解析与地址（DNS/DHCP）
    "crypto_proxy",    # 加密与代理（TLS/证书/代理）
    "service",         # 服务侧（应用/服务端监控）
)

#: 每个清单项恰好包含的四个字段，顺序即渲染顺序。
ITEM_FIELDS = ("field", "why", "where", "criteria")

#: 视为「有问题」的行严重度（用来判断结果里是否真的有故障需要取证）。
_PROBLEM_SEVERITIES = ("严重", "警告", "提示")

#: 本模块输出里只认这几种「机器侧类别」，其余类别走兜底规则。
_L2_CATEGORIES = ("本地可达性",)
_L3_CATEGORIES = ("网络可达性", "网络时延")
_L4_CATEGORIES = ("连接建立", "传输质量")


def validate_template(template: dict) -> list[str]:
    """校验清单模板结构，返回问题列表（空列表 = 合法）。

    只校验**结构**，不校验措辞；厂商名由测试用 ``-F`` 扫描，避免把「一家厂商
    改个名」这种文案变化误判成结构错误。

    Args:
        template: 从 ``core/copy/evidence_checklist.json`` 读出的对象。

    Returns:
        list[str]: 人类可读的问题列表；模板合法时为空列表。检查项：
            7 个维度键齐全且无多余键、每维 ``name``/``note`` 为非空字符串、
            ``items`` 为列表、每项恰好含 :data:`ITEM_FIELDS` 四键且值为非空字符串。
    """
    problems: list[str] = []
    if not isinstance(template, dict):
        return ["模板顶层必须是对象"]
    dimensions = template.get("dimensions")
    if not isinstance(dimensions, dict):
        return ["模板缺少 dimensions 对象"]
    keys = set(dimensions)
    expected = set(DIMENSION_KEYS)
    if keys != expected:
        problems.append(
            f"维度集合不符：缺少 {sorted(expected - keys)}，多出 {sorted(keys - expected)}")
    for key in DIMENSION_KEYS:
        dim = dimensions.get(key)
        if not isinstance(dim, dict):
            problems.append(f"{key}: 维度必须是对象")
            continue
        for field in ("name", "note"):
            value = dim.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{key}.{field}: 必须是非空字符串")
        items = dim.get("items")
        if not isinstance(items, list):
            problems.append(f"{key}.items: 必须是列表")
            continue
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                problems.append(f"{key}.items[{index}]: 必须是对象")
                continue
            if set(item) != set(ITEM_FIELDS):
                problems.append(
                    f"{key}.items[{index}]: 字段必须恰好是 {list(ITEM_FIELDS)}")
                continue
            for field in ITEM_FIELDS:
                value = item.get(field)
                if not isinstance(value, str) or not value.strip():
                    problems.append(f"{key}.items[{index}].{field}: 必须是非空字符串")
    return problems


def load_template(path: Path | str | None = None) -> dict:
    """读取并校验清单模板（显式 loader，便于测试注入与变异）。

    Args:
        path: 模板文件路径；省略时读仓库内的
            ``core/copy/evidence_checklist.json``。

    Returns:
        dict: 已通过 :func:`validate_template` 的模板对象。

    Raises:
        OSError: 文件不存在或不可读。
        json.JSONDecodeError: 文件不是合法 JSON。
        ValueError: JSON 合法但结构不符（缺维度、缺字段等），消息含前几条问题。
    """
    target = Path(path) if path is not None else _TEMPLATE_PATH
    data = json.loads(target.read_text(encoding="utf-8"))
    problems = validate_template(data)
    if problems:
        raise ValueError("取证清单模板不合法：" + "；".join(problems[:5]))
    return data


def _load_template_or_empty() -> dict:
    """导入期加载模板；文件缺失/损坏时返回空表（报告宁可少区块也不许崩）。

    Returns:
        dict: 合法模板；失败时 ``{}``。
    """
    try:
        return load_template()
    except (OSError, ValueError):
        # JSONDecodeError 是 ValueError 的子类；U 盘被拔/文件截断都走这里。
        return {}


#: 导入时加载一次：纯函数只读这份内存数据，不再碰磁盘（实现「纯函数不读文件」）。
_TEMPLATE: dict = _load_template_or_empty()


def _e(key: str, **args) -> str:
    """取「取证请求单」的静态标签（``copy.evidence_checklist`` section）。

    Args:
        key: ``evidence_checklist`` section 内的键。
        **args: ``{name}`` 占位符实参。

    Returns:
        str: 可直接展示的标签；缺 key 时按全项目约定回退成 key 本身。
    """
    return _copy_text("evidence_checklist", key, **args)


def _verdict_of(result: dict, verdict: dict | None) -> dict:
    """取判定结果：优先显式传入，其次 ``result["verdict"]``，最后现算一次。

    Args:
        result: 诊断结果；允许为空字典（此时现算会降级为空判定）。
        verdict: 调用方已算好的判定，可省一次 ``verdict.build``。

    Returns:
        dict: 判定结果；实在拿不到时返回 ``{}``（调用方按「无结论」处理）。
    """
    if isinstance(verdict, dict):
        return verdict
    found = result.get("verdict") if isinstance(result, dict) else None
    if isinstance(found, dict):
        return found
    try:
        return _verdict_mod.build(result if isinstance(result, dict) else {})
    except Exception:  # noqa: BLE001  没有判定也不能让取证单/报告崩掉
        return {}


def _dims_for_row(layer: str, category: str) -> tuple[str, ...]:
    """单条「层 + 类别」→ 相关维度（纯函数，规则集中在这里）。

    Args:
        layer: ``rows[].layer`` / ``points[].layer``（如 ``L2 本地链路``）。
        category: ``rows[].category``（如 ``本地可达性``）。

    Returns:
        tuple[str, ...]: 维度机器码；安全观察与未知类别返回空元组（由调用方兜底）。
    """
    layer = str(layer or "")
    category = str(category or "")
    if layer.startswith("安全观察") or category == "安全观察":
        return ()
    if category == "采集有效性":
        return DIMENSION_KEYS
    if layer.startswith("L2") or category in _L2_CATEGORIES:
        # L2/ARP 在无线与有线接入上都可能发生，工具侧无法区分 → 两个接入侧都问。
        return ("wireless", "wired")
    if layer.startswith("L3") or category in _L3_CATEGORIES:
        return ("transport",)
    if layer.startswith("L4") or category in _L4_CATEGORIES:
        return ("transport",)
    if category == "域名解析":
        return ("naming",)
    if category == "TLS 会话":
        return ("crypto_proxy", "service")
    if category == "应用响应":
        return ("service",)
    if layer.startswith("L7"):
        return ("service",)
    return ()


def _dimensions_for(verdict: dict, rows: list[dict]) -> list[str]:
    """结论 → 维度集合（内部实现，规则见 :func:`dimensions_for` 的 docstring）。

    Args:
        verdict: 判定结果字典。
        rows: ``result["rows"]``；只把真实问题行（严重/警告/提示）计入映射。

    Returns:
        list[str]: 按 :data:`DIMENSION_KEYS` 顺序排列的维度机器码。
    """
    level = str(verdict.get("level") or "")
    points = [p for p in (verdict.get("points") or []) if isinstance(p, dict)]
    problem_rows = [r for r in (rows or [])
                    if isinstance(r, dict)
                    and r.get("severity") in _PROBLEM_SEVERITIES
                    and not str(r.get("layer") or "").startswith("安全观察")]
    sufficiency = verdict.get("sufficiency")
    insufficient = level == "证据不足"
    if isinstance(sufficiency, dict) and sufficiency.get("ok") is False:
        insufficient = True
    # 「采集有效性」= 没抓到/没测到，任何单一维度都给不出结论 → 通用空白版。
    if insufficient or any(p.get("category") == "采集有效性" for p in points):
        return list(DIMENSION_KEYS)
    # 「正常」且没有任何问题条目 = 本次不需要向外部取证 → 报告不出现区块。
    if level == "正常" and not points:
        return []

    chosen: set[str] = {"terminal"}       # 工具自己就是终端侧，恒声明「已具备」
    mapped_any = False
    for item in points + problem_rows:
        dims = _dims_for_row(item.get("layer", ""), item.get("category", ""))
        if dims:
            mapped_any = True
            chosen.update(dims)

    contrast = verdict.get("probe_contrast")
    if isinstance(contrast, dict):
        code = str(contrast.get("code") or "")
        if code == "PROBE.CONTRAST.TARGET_SIDE":
            chosen.add("service")         # 对照指向对端 → 服务侧需要自证
            mapped_any = True
        elif code == "PROBE.CONTRAST.LOCAL_SIDE":
            chosen.add("wired")           # 对照指向本地出口 → 接入/出口侧要看
            mapped_any = True

    # 有故障但类别无法识别：保守落到「承载与出口侧」——它是路径上最通用的一侧，
    # 总比只给一个「终端侧已具备」的空清单强（宁可多要一份证据，不可漏问）。
    if not mapped_any and (points or problem_rows):
        chosen.add("transport")
    return [key for key in DIMENSION_KEYS if key in chosen]


def dimensions_for(result: dict, verdict: dict | None = None) -> list[str]:
    """把「本次结论」映射成相关维度集合（纯函数、可测试、可变异）。

    规则（按顺序短路，命中即返回）：

    1. 判定为「证据不足」或 ``verdict.sufficiency.ok is False`` 或存在
       ``category == "采集有效性"`` 的条目 → 返回**全部 7 维**（通用空白版）。
    2. 判定为「正常」且没有任何 ``points`` → 返回空列表（报告不出现区块）。
    3. 其余情况按问题条目逐条映射，并**始终包含** ``terminal``（工具自己已采，
       列出来是为了声明「这一侧不需要再要」）：

       - ``L2`` / ``本地可达性``（ARP、本地链路）→ ``wireless`` + ``wired``；
       - ``L3`` / ``网络可达性`` / ``网络时延``（含 ICMP 不可达）→ ``transport``；
       - ``L4`` / ``连接建立`` / ``传输质量``（重传、建连失败、零窗口）→ ``transport``；
       - ``L7`` / ``域名解析`` → ``naming``；``TLS 会话`` → ``crypto_proxy`` + ``service``；
         ``应用响应`` 或其它 L7 类别 → ``service``；
       - ``verdict.probe_contrast`` 指向对端（``TARGET_SIDE``）→ 追加 ``service``；
         指向本地（``LOCAL_SIDE``）→ 追加 ``wired``；
       - 安全观察行不参与映射；类别无法识别但有故障 → 兜底 ``transport``。

    返回顺序固定为 :data:`DIMENSION_KEYS` 的顺序，便于逐字节断言。

    Args:
        result: 诊断结果字典（读 ``verdict`` 与 ``rows``；缺 ``verdict`` 时现算）。
        verdict: 可选的已算好判定（报告渲染路径传入，避免重复计算）。

    Returns:
        list[str]: 维度机器码列表；空列表表示本次不需要外部取证。
    """
    result = result if isinstance(result, dict) else {}
    vd = _verdict_of(result, verdict)
    rows = result.get("rows") or []
    if not vd and not rows:
        return []
    return _dimensions_for(vd, rows)


def _select_dimensions(template: dict, keys: list[str]) -> list[dict]:
    """按维度机器码从模板里取维度与条目（结构不合法时跳过，不抛异常）。

    Args:
        template: 模板对象（通常是 :data:`_TEMPLATE`）。
        keys: 要输出的维度机器码（已按展示顺序排好）。

    Returns:
        list[dict]: 每项 ``{"key", "name", "note", "items"}``；``items`` 只保留
            四字段齐全的条目（坏数据降级成缺条目，而不是让整份报告报错）。
    """
    source = template.get("dimensions") if isinstance(template, dict) else None
    if not isinstance(source, dict):
        return []
    selected: list[dict] = []
    for key in keys:
        dim = source.get(key)
        if not isinstance(dim, dict):
            continue
        items: list[dict] = []
        for item in dim.get("items") or []:
            if not isinstance(item, dict):
                continue
            if not all(isinstance(item.get(field), str) and item.get(field).strip()
                       for field in ITEM_FIELDS):
                continue
            items.append({field: item[field] for field in ITEM_FIELDS})
        selected.append({
            "key": key,
            "name": str(dim.get("name") or ""),
            "note": str(dim.get("note") or ""),
            "items": items,
        })
    return selected


def build_checklist(result: dict, full: bool = False, verdict: dict | None = None,
                    template: dict | None = None,
                    conclusion: dict | None = None) -> dict:
    """按本次结论生成清单；``full=True`` 生成覆盖 7 维的通用空白版。

    ``full=True`` 时**不依赖 ``result`` 与结论**：``result={}`` 也能返回完整的
    7 维（界面「复制通用空白版」在还没有诊断结果时也必须是可达的）。

    Args:
        result: 诊断结果字典（``verdict`` / ``rows`` 决定相关维度）。
        full: 为 ``True`` 时忽略结论、输出全部 7 维（界面「复制通用空白版」用）。
        verdict: 可选的已算好判定；报告渲染/接口传入同一个判定，避免重复计算。
        template: 可选的模板对象（测试注入/变异用）；省略时用导入期加载的模板。
        conclusion: 可选的已算好结论边界对象（E1）。报告/接口可传入同一个
            :func:`core.conclusion.build_conclusion` 产物；省略且 ``full=False``
            时按本次 ``result`` + ``verdict`` 现算一次，保证取证单与报告同源。

    Returns:
        dict: ``{"full": bool, "level": str, "layer": str, "dimensions": [...]}``；
            ``dimensions`` 每项 ``{"key", "name", "note", "items"}``，``items``
            每项恰好 ``field/why/where/criteria`` 四键。E1 起加法键
            ``conclusion``（结论边界对象，``full=True`` 时为通用空白版不加）；
            模板不可用时返回空 ``dimensions``（调用方据此不渲染区块）。
    """
    result = result if isinstance(result, dict) else {}
    chosen_template = template if isinstance(template, dict) else _TEMPLATE
    if full:
        # 通用空白版**不依赖本次结论**：没有结果（``{}``）也能生成全 7 维，
        # 因此不调用 verdict.build，也不经 copy 表回退。有已算好/已附带的判定时
        # 只借用 level/layer 做展示，不重新计算。
        vd = verdict if isinstance(verdict, dict) else None
        if vd is None:
            found = result.get("verdict")
            vd = found if isinstance(found, dict) else {}
        keys = list(DIMENSION_KEYS)
    else:
        vd = _verdict_of(result, verdict)
        keys = dimensions_for(result, verdict=vd)
    conclusion_block = conclusion if isinstance(conclusion, dict) else None
    if conclusion_block is None and not full:
        # 取证单/复制/导出路径也必须带边界；与报告调用同一 build_conclusion。
        conclusion_block = _conclusion_mod.build_conclusion(result, vd)
    payload = {
        "full": bool(full),
        "level": str(vd.get("level") or ""),
        "layer": str(vd.get("layer") or ""),
        "dimensions": _select_dimensions(chosen_template, keys),
    }
    if conclusion_block is not None:
        payload["conclusion"] = conclusion_block
    return payload


def _esc(value) -> str:
    """Markdown 表格单元格转义：竖线转义、换行压成空格。

    Args:
        value: 任意单元格值。

    Returns:
        str: 可直接放进 Markdown 表格的文本。
    """
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _table(head: list[str], rows: list[list]) -> str:
    """拼一张 Markdown 表格（与 ``core.report._table`` 同形，避免循环导入）。

    Args:
        head: 表头单元格。
        rows: 数据行；每行长度应与表头一致。

    Returns:
        str: 多行 Markdown 表格。
    """
    out = ["| " + " | ".join(head) + " |",
           "|" + "|".join(["---"] * len(head)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(_esc(cell) for cell in row) + " |")
    return "\n".join(out)


def render_checklist_markdown(checklist: dict, include_conclusion: bool = True) -> str:
    """把清单渲染成报告内 Markdown 区块（维度小标题 + 四列表格）。

    维度与条目文字来自模板 JSON，标题/表头等标签来自 ``copy.evidence_checklist``；
    没有维度时返回空串（调用方据此不追加区块）。E1 起若 ``checklist`` 带
    ``conclusion`` 边界对象，则在清单**之前**输出同一结论+边界块（与报告同源），
    保证「任何只给结论不给边界的导出路径」不成立。

    Args:
        checklist: :func:`build_checklist` 的返回值。
        include_conclusion: 是否在清单前输出结论边界块；报告正文第一节已经
            输出过同一块时也**保留**（报告末尾的取证单是「整块可转发」的副本，
            复制给协作方时结论和边界不会丢）。

    Returns:
        str: 以 ``copy.evidence_checklist.section_title`` 开头、以换行结尾的 Markdown；
            无维度时返回 ``""``。
    """
    dims = checklist.get("dimensions") if isinstance(checklist, dict) else None
    if not dims:
        return ""
    prefix = ""
    if include_conclusion and isinstance(checklist.get("conclusion"), dict):
        prefix = _conclusion_mod.render_conclusion_markdown(
            checklist["conclusion"]) + "\n"
    if checklist.get("full"):
        intro = _e("intro_full")
    else:
        intro = _e("intro", level=checklist.get("level") or "-",
                   layer=checklist.get("layer") or "-")
    lines = [_e("section_title"), "", intro, ""]
    for index, dim in enumerate(dims, 1):
        lines.append(_e("dim_title", index=index, name=dim.get("name") or ""))
        lines.append("")
        if dim.get("note"):
            lines += [dim["note"], ""]
        items = dim.get("items") or []
        if items:
            lines.append(_table(
                [_e("th_field"), _e("th_why"), _e("th_where"), _e("th_criteria")],
                [[item.get("field", ""), item.get("why", ""),
                  item.get("where", ""), item.get("criteria", "")] for item in items]))
            lines.append("")
    lines += [_e("footer"), ""]
    return prefix + "\n".join(lines)


def render_checklist_text(checklist: dict, include_conclusion: bool = True) -> str:
    """把清单渲染成纯文本（方便直接发微信/工单，不含 Markdown 表格符号）。

    E1 起若 ``checklist`` 带 ``conclusion`` 边界对象，则在清单前输出同一结论+
    边界块的**纯文本版**（复制给协作方时结论与边界一起走）。

    Args:
        checklist: :func:`build_checklist` 的返回值。
        include_conclusion: 是否在清单前输出结论边界块；默认输出。

    Returns:
        str: 纯文本清单；无维度时返回 ``""``。正文不含 ``|`` 与 ``#`` 标题符号，
            每项四字段各占一行并缩进。
    """
    dims = checklist.get("dimensions") if isinstance(checklist, dict) else None
    if not dims:
        return ""
    prefix = ""
    if include_conclusion and isinstance(checklist.get("conclusion"), dict):
        prefix = _conclusion_mod.render_conclusion_text(checklist["conclusion"]) + "\n"
    if checklist.get("full"):
        intro = _e("text_intro_full")
    else:
        intro = _e("text_intro", level=checklist.get("level") or "-",
                   layer=checklist.get("layer") or "-")
    lines = [_e("text_title"), "", intro, ""]
    for index, dim in enumerate(dims, 1):
        lines.append(_e("text_dim", index=index, name=dim.get("name") or ""))
        if dim.get("note"):
            lines.append("  " + _e("text_note", value=dim["note"]))
        for item in dim.get("items") or []:
            lines.append("  · " + _e("text_field", value=item.get("field", "")))
            lines.append("    " + _e("text_why", value=item.get("why", "")))
            lines.append("    " + _e("text_where", value=item.get("where", "")))
            lines.append("    " + _e("text_criteria", value=item.get("criteria", "")))
        lines.append("")
    lines += [_e("text_footer"), ""]
    return prefix + "\n".join(lines)


__all__ = [
    "DIMENSION_KEYS",
    "ITEM_FIELDS",
    "load_template",
    "validate_template",
    "dimensions_for",
    "build_checklist",
    "render_checklist_markdown",
    "render_checklist_text",
]
