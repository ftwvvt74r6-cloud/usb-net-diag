"""G1 守门：用户可见文案不再出现「一线 / 二线 / 同事」，防止改回去。

扫描范围（``G-SPEC`` G1 / V1；S1 复审后扩大到**全部用户可见**）：

* ``core/copy/*.json``：遍历**所有字符串值**（不只 ``zh-CN.json``，也不只原文 grep；
  ``evidence_checklist.json`` 等文案表同样属于用户可见）；
* ``ui/index.html``（三个模式示例、结论复制按钮、设置 / 退出文案）；
* ``README.md``、``AGENTS.md``；
* ``docs/**/*.md``（含由 docstring 生成的 ``docs/api-reference.md``）；
* ``CHANGELOG.md``：历史条目**允许保留原文**，但同一行必须带
  「历史称谓；v0.3.2 起…」注记（否则算回退）。

不在范围（内部说明，不是给使用者看的）：``tests/``、``scaffold/``、
``tasks/tasks.json``、``scripts/``、``LICENSE``（法务原文照旧保留）。
grep 语义与 ``git grep -F`` 一致：纯子串匹配，不解释正则。
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _uisrc  # noqa: E402

COPY_DIR = ROOT / "core" / "copy"
COPY_PATH = COPY_DIR / "zh-CN.json"
COPY = json.loads(COPY_PATH.read_text(encoding="utf-8"))
HTML = _uisrc.html()

#: 行业内部称谓：用户可见范围必须为 0（``-F`` 纯子串）。
LEGACY_TERMS = ("一线", "二线", "同事")
#: CHANGELOG 历史行允许保留旧称谓的唯一条件。
HISTORY_MARKER = "历史称谓"

#: 需要扫描的用户可见文件（相对路径固定，避免目录重构后范围悄悄缩小）。
REQUIRED_FILES = (
    "core/copy/zh-CN.json",
    "ui/index.html",
    "README.md",
    "AGENTS.md",
    "docs/api-reference.md",
    "docs/conclusion-boundary.md",
    "docs/log-collection.md",
    "docs/licensing.md",
    "docs/build.md",
)

#: 允许保留旧称谓（且必须带历史注记）的唯一文件；与分类表一致。
ALLOWED_LEGACY_FILES = ("CHANGELOG.md",)

CONFIG_RE = re.compile(
    r'<script type="application/json" id="ui-config">(.*?)</script>', re.S)


def _copy_json_files() -> list[Path]:
    """``core/copy/*.json`` 全量（新增文案表自动纳入守门，不用改清单）。"""
    return sorted(COPY_DIR.glob("*.json"))


def _iter_strings(node, prefix: str = "") -> list[tuple[str, str]]:
    """深度遍历 JSON，返回 ``[(点分路径, 字符串值)]``（只关心字符串值）。"""
    out: list[tuple[str, str]] = []
    if isinstance(node, str):
        out.append((prefix or "<root>", node))
    elif isinstance(node, dict):
        for key, value in node.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            out.extend(_iter_strings(value, child))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            out.extend(_iter_strings(value, f"{prefix}[{index}]"))
    return out


def _user_visible_files() -> list[Path]:
    """用户可见文件清单：固定文件 + ``docs/`` 下全部 Markdown。"""
    files = [ROOT / rel for rel in REQUIRED_FILES]
    files.extend(sorted((ROOT / "docs").rglob("*.md")))
    seen: list[Path] = []
    for path in files:
        if path not in seen:
            seen.append(path)
    return seen


def _ui_config() -> dict:
    """解析页面里的 UI 配置块（模式示例从配置里取，不靠 grep 片段）。"""
    match = CONFIG_RE.search(HTML)
    if match is None:
        raise AssertionError("ui/index.html 缺少 id=ui-config 的 JSON 配置块")
    return json.loads(match.group(1))


class UserVisibleNoLegacyRolesTest(unittest.TestCase):
    """用户可见范围三类词命中 = 0。"""

    def test_every_required_file_is_scanned(self):
        names = {p.relative_to(ROOT).as_posix() for p in _user_visible_files()}
        for rel in REQUIRED_FILES:
            with self.subTest(file=rel):
                self.assertIn(rel, names, "扫描范围不能悄悄漏掉用户可见文件")

    def test_copy_scope_covers_every_json_table(self):
        """S1：扫整个 ``core/copy/*.json``，不只 ``zh-CN.json``。"""
        names = {p.relative_to(ROOT).as_posix() for p in _copy_json_files()}
        self.assertIn("core/copy/zh-CN.json", names)
        self.assertIn("core/copy/evidence_checklist.json", names,
                      "新增文案表必须自动纳入守门范围")

    def test_copy_table_has_no_legacy_roles(self):
        """遍历所有 copy JSON 的**字符串值**（键名不算用户可见文案）。"""
        for path in _copy_json_files():
            data = json.loads(path.read_text(encoding="utf-8"))
            for dotted, value in _iter_strings(data):
                for term in LEGACY_TERMS:
                    with self.subTest(file=path.name, key=dotted, term=term):
                        self.assertNotIn(
                            term, value,
                            f"{path.name}:{dotted} 仍含旧称谓 {term!r}（用户可见）")

    def test_ui_has_no_legacy_roles(self):
        for term in LEGACY_TERMS:
            with self.subTest(term=term):
                self.assertNotIn(term, HTML, f"ui/index.html 仍含旧称谓 {term!r}")

    def test_readme_and_agents_have_no_legacy_roles(self):
        for rel in ("README.md", "AGENTS.md"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            for term in LEGACY_TERMS:
                with self.subTest(file=rel, term=term):
                    self.assertNotIn(term, text, f"{rel} 仍含旧称谓 {term!r}")

    def test_docs_have_no_legacy_roles(self):
        for path in sorted((ROOT / "docs").rglob("*.md")):
            text = path.read_text(encoding="utf-8")
            for term in LEGACY_TERMS:
                with self.subTest(file=path.relative_to(ROOT).as_posix(), term=term):
                    self.assertNotIn(
                        term, text,
                        f"{path.relative_to(ROOT).as_posix()} 仍含旧称谓 {term!r}")

    def test_changelog_history_is_kept_with_annotation_only(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        hits = []
        for lineno, line in enumerate(text.splitlines(), 1):
            if any(term in line for term in LEGACY_TERMS):
                hits.append((lineno, line))
                self.assertIn(HISTORY_MARKER, line,
                              f"CHANGELOG.md:{lineno} 旧称谓必须带历史注记")
                self.assertIn("v0.3.2", line,
                              f"CHANGELOG.md:{lineno} 注记要写明从哪个版本起改名")
                self.assertIn("协作方", line)
        self.assertTrue(hits, "历史条目应保留原文（加注即可，不许改掉历史）")


class GeneralizedCopyTest(unittest.TestCase):
    """G1 的四个具体落点：AI 提示词、复制按钮、三模式示例、README/文档口径。"""

    def test_ai_prompt_addresses_general_users(self):
        prompt = COPY["prompt"]["system"]
        self.assertIn("普通使用者", prompt)
        self.assertIn("不熟网络协议", prompt)
        self.assertNotIn("桌面运维", prompt)
        self.assertNotIn("一线", prompt)

    def test_copy_button_says_collaborator(self):
        self.assertEqual(COPY["conclusion"]["btn_copy"], "复制给协作方")
        self.assertIn("复制给协作方", HTML, "前端兜底文案也必须同步")

    def test_three_mode_examples_are_generalized(self):
        modes = _ui_config()["modes"]
        for mode in ("scan", "live", "offline"):
            example = modes[mode]["example"]
            with self.subTest(mode=mode):
                self.assertTrue(example.strip())
                for term in LEGACY_TERMS:
                    self.assertNotIn(term, example)
        self.assertIn("用户反馈", modes["scan"]["example"])
        self.assertIn("用户反馈", modes["live"]["example"])
        self.assertIn("对方", modes["offline"]["example"])

    def test_readme_and_boundary_doc_use_collaborator(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        doc = (ROOT / "docs" / "conclusion-boundary.md").read_text(encoding="utf-8")
        self.assertIn("复制给协作方", readme)
        self.assertIn("复制给协作方", doc)
        self.assertIn("### 4.3 复制给协作方", doc)

    def test_generated_api_reference_has_no_legacy_roles(self):
        text = (ROOT / "docs" / "api-reference.md").read_text(encoding="utf-8")
        for term in LEGACY_TERMS:
            with self.subTest(term=term):
                self.assertNotIn(term, text,
                                 "docstring 渲染物由 gen_api_doc.py 生成：先改源码再重跑")

    def test_scan_scope_excludes_internal_only_files(self):
        """内部说明（tests/scaffold/tasks/scripts）不是用户可见，明确排除。"""
        names = [p.relative_to(ROOT).as_posix() for p in _user_visible_files()]
        for internal in ("tests", "scaffold", "tasks/tasks.json", "scripts"):
            prefix = internal.rstrip("/")
            with self.subTest(internal=internal):
                self.assertFalse(
                    any(name == prefix or name.startswith(prefix + "/")
                        for name in names),
                    f"{internal} 是内部文件，不属于用户可见扫描范围")
        self.assertFalse(any(name == "LICENSE" for name in names))

    def test_allowlist_matches_classification_table(self):
        """允许保留旧称谓的文件只有 CHANGELOG（且必须带历史注记），别处一律 0。"""
        self.assertEqual(ALLOWED_LEGACY_FILES, ("CHANGELOG.md",))
        names = {p.relative_to(ROOT).as_posix() for p in _user_visible_files()}
        self.assertNotIn("CHANGELOG.md", names,
                         "CHANGELOG 走历史注记专用规则，不混进普通扫描")
        docs = {p.relative_to(ROOT).as_posix()
                for p in (ROOT / "docs").rglob("*.md")}
        self.assertTrue(docs <= names, "docs/** 必须全部在用户可见扫描范围")
        copy_names = {p.relative_to(ROOT).as_posix() for p in _copy_json_files()}
        self.assertTrue(copy_names, "core/copy 下必须有文案表")


if __name__ == "__main__":
    unittest.main(verbosity=2)
