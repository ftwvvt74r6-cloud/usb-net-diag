"""G1 守门：用户可见文案不再出现「一线 / 二线 / 同事」，防止改回去。

扫描范围（``G-SPEC`` G1 / V1）：

* ``core/copy/zh-CN.json``（用户可见文案 + AI 提示词）
* ``ui/index.html``（三个模式示例、结论复制按钮、设置 / 退出文案）
* ``README.md``、``AGENTS.md``
* ``docs/**/*.md``（含由 docstring 生成的 ``docs/api-reference.md``）
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
COPY_PATH = ROOT / "core" / "copy" / "zh-CN.json"
UI_PATH = ROOT / "ui" / "index.html"
COPY = json.loads(COPY_PATH.read_text(encoding="utf-8"))
HTML = UI_PATH.read_text(encoding="utf-8")

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

CONFIG_RE = re.compile(
    r'<script type="application/json" id="ui-config">(.*?)</script>', re.S)


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

    def test_copy_table_has_no_legacy_roles(self):
        text = COPY_PATH.read_text(encoding="utf-8")
        for term in LEGACY_TERMS:
            with self.subTest(term=term):
                self.assertNotIn(term, text,
                                 f"copy/zh-CN.json 仍含旧称谓 {term!r}（用户可见）")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
