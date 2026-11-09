"""UI 源码统一读取器（R3，为 S4 多入口做准备）。

之前测试各自直接 ``(ROOT / "ui" / "index.html").read_text()`` /
``(ROOT / "ui" / "app.css").read_text()``，把「v1 只有一个 HTML + 一个 CSS」的
事实写死在每个测试里。S4 引入 ``ui/v2/**`` 后（一个 HTML + 多个 CSS/JS），这些
读点要能按 ``ND_UI_BUNDLE`` 切包，否则 v2 一上线，23 处读点要么读错文件要么漏读
子资源。

这里提供四个函数，统一从「入口 HTML」解析 ``<link rel="stylesheet">`` 与
``<script src>``，按文档顺序拼出内容：

* :func:`html` —— 入口 HTML 全文（``ui/index.html`` 或 ``ui/v2/index.html``）；
* :func:`css` —— 所有样式表 ``<link>`` 的内容**按顺序拼接**；
* :func:`js` —— 所有 ``<script src>`` 的内容**按顺序拼接**；
* :func:`text` —— ``html + css + js`` 拼接（整份 UI 源码视图，供「某 token 是否
  在界面任何地方出现」这类跨文件断言）。

选包：环境变量 ``ND_UI_BUNDLE=v1|v2``，默认 ``v1``。**v1 下四个函数返回的字节与
改造前测试直接读文件完全一致**（v1 恰好只有一个 HTML + 一个 CSS、没有外链 JS），
所以默认跑测试，断言强度与行为零变化 —— 这是 R3 的红线。

注意：本模块只读仓库 ``ui/`` 下的静态源文件，不 import 被测代码、不联网、不写盘；
任何文件缺失都显式抛 ``FileNotFoundError``（宁可失败，不让测试在漏读子资源时静默通过）。
"""
from __future__ import annotations

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI_DIR = ROOT / "ui"

#: 入口 HTML 相对 ``ui/`` 的路径（与 ``core/server.py`` 的 ``UI_ENTRY`` 保持一致）。
_ENTRY = {
    "v1": "index.html",
    "v2": "v2/index.html",
}

#: 匹配 ``<link rel="stylesheet" ...>`` 整条标签（属性顺序、单双引号都不敏感；
#: 无捕获组，``findall`` 返回完整标签串）。
_LINK_RE = re.compile(
    r'<link\b[^>]*\brel=["\']?stylesheet["\']?[^>]*>', re.IGNORECASE)
#: 从 ``<link>`` 里抽 ``href``。
_HREF_RE = re.compile(r'\bhref=["\']([^"\']+)["\']', re.IGNORECASE)
#: 匹配 ``<script ... src="...">`` 整条标签（无捕获组）。
_SCRIPT_RE = re.compile(r'<script\b[^>]*\bsrc=["\'][^"\']+["\'][^>]*>', re.IGNORECASE)
#: 从 ``<script>`` 里抽 ``src``。
_SRC_RE = re.compile(r'\bsrc=["\']([^"\']+)["\']', re.IGNORECASE)


def _bundle() -> str:
    """当前选包：``ND_UI_BUNDLE`` 里的 ``v1``/``v2``，其它值/缺省都回 ``v1``。"""
    bundle = (os.environ.get("ND_UI_BUNDLE") or "v1").strip().lower()
    return bundle if bundle in _ENTRY else "v1"


def _entry_html() -> Path:
    """入口 HTML 的绝对路径（缺文件时由调用方 ``read_text`` 抛错）。"""
    return UI_DIR / _ENTRY[_bundle()]


def _resolve_asset(href: str, entry: Path) -> Path:
    """把 ``href``（形如 ``/app.css`` / ``/v2/css/tokens.css``）映到磁盘文件。

    href 都是「以 ``/`` 开头的站点绝对路径」，相对 ``ui/`` 根；去掉前导 ``/``
    拼到 ``UI_DIR`` 下。带 ``../`` 或反斜杠的非法引用直接抛错（测试不该被坑）。
    """
    raw = href.strip()
    if not raw.startswith("/") or "\\" in raw or ".." in raw:
        raise ValueError(f"非法资源引用：{href!r}（须为 / 开头的站点内路径）")
    return UI_DIR / raw.lstrip("/")


def _linked_content(pattern_re, href_re, entry: Path) -> str:
    """解析入口 HTML 里的一类外链（link/script），按序读回并拼接。

    Args:
        pattern_re: 匹配整条标签的正则（``<link ...>`` / ``<script ...>``）。
        href_re: 从标签里抽 ``href``/``src`` 的正则。
        entry: 入口 HTML 路径（仅用于报错信息）。

    Returns:
        str: 所有外链文件内容按出现顺序拼接；没有外链返回空串。
    """
    html_text = entry.read_text(encoding="utf-8")
    chunks: list[str] = []
    for tag in pattern_re.findall(html_text):
        m = href_re.search(tag)
        if not m:
            continue
        path = _resolve_asset(m.group(1), entry)
        chunks.append(path.read_text(encoding="utf-8"))
    return "".join(chunks)


def html() -> str:
    """入口 HTML 全文（``utf-8``）。"""
    return _entry_html().read_text(encoding="utf-8")


def css() -> str:
    """所有 ``<link rel="stylesheet">`` 的内容按文档顺序拼接。"""
    return _linked_content(_LINK_RE, _HREF_RE, _entry_html())


def js() -> str:
    """所有 ``<script src>`` 的内容按文档顺序拼接。"""
    return _linked_content(_SCRIPT_RE, _SRC_RE, _entry_html())


def text() -> str:
    """整份 UI 源码视图：HTML + 样式 + 脚本拼接（跨文件断言的统一来源）。"""
    return html() + css() + js()
