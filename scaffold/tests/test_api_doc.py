"""接口文档生成器的自检。

为什么要给它写测试：这个脚本的输出会被当成「文档」交给人和 AI，
一旦解析错了（比如签名拼错、把私有函数算成公开、`self` 被当成参数），
生成的文档就是**错的但看起来很正式**——比没有文档更糟。
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCAFFOLD = Path(__file__).resolve().parent.parent

_GEN = SCAFFOLD / "tools" / "gen_api_doc.py"
if not _GEN.is_file():
    raise AssertionError(
        f"缺少生成器：{_GEN}\n"
        "多半是 .gitignore 把 scaffold/tools/ 当成运行环境 tools/ 忽略了；\n"
        "检查 .gitignore 里是否是 /tools/（带前导斜杠）。")

spec = importlib.util.spec_from_file_location("gen_api_doc", _GEN)
gad = importlib.util.module_from_spec(spec)
# 必须先注册到 sys.modules：gen_api_doc 用了 `from __future__ import annotations`，
# dataclass 处理字符串注解时要按 cls.__module__ 回查模块，缺了会抛
# AttributeError: 'NoneType' object has no attribute '__dict__'
sys.modules["gen_api_doc"] = gad
spec.loader.exec_module(gad)          # type: ignore[union-attr]

SAMPLE = '''"""示例模块：用来测解析。"""


def good(alpha: int, beta: str = "x", *args, gamma=1, **kwargs) -> bool:
    """做一件明确的事。

    Args:
        alpha: 数量。
        beta: 名字。

    Returns:
        是否成功。

    Raises:
        不抛异常。
    """
    return True


def bare(pcap, log=None) -> tuple:
    """只有一句话，没有参数说明。"""
    return (), ""


def _private():
    """私有函数不该出现在文档里。"""


class Widget:
    """一个类。

    Args:
        无。

    Returns:
        实例。
    """

    def method(self) -> int:
        """只要 self，不算缺参数。"""
        return 1

    def needs_args(self, value: int) -> int:
        """有真参数但没写 Args。"""
        return value

    def _hidden(self) -> None:
        """私有方法。"""
'''


def _write(tmp: str, name: str, text: str) -> Path:
    path = Path(tmp) / name
    path.write_text(text, encoding="utf-8")
    return path


class SignatureTests(unittest.TestCase):
    def test_full_signature_round_trip(self):
        import ast

        tree = ast.parse(SAMPLE)
        fn = next(n for n in tree.body
                  if isinstance(n, ast.FunctionDef) and n.name == "good")
        sig = gad.render_signature(fn)
        self.assertIn("alpha: int", sig)
        self.assertIn("beta: str", sig)
        self.assertIn("*args", sig)
        self.assertIn("gamma=1", sig)
        self.assertIn("**kwargs", sig)
        self.assertTrue(sig.endswith("-> bool"))

    def test_annotation_free_signature(self):
        import ast

        tree = ast.parse("def f(a, b=2):\n    pass\n")
        self.assertEqual(gad.render_signature(tree.body[0]), "def f(a, b=2)")

    def test_default_rendering_has_no_spaces_around_equal(self):
        """签名按 PEP 8 渲染（`b=2`），与源码里的主流写法一致。"""
        import ast

        tree = ast.parse(SAMPLE)
        fn = next(n for n in tree.body
                  if isinstance(n, ast.FunctionDef) and n.name == "good")
        sig = gad.render_signature(fn)
        self.assertIn("beta: str='x'", sig)
        self.assertIn("gamma=1", sig)
        self.assertNotIn(" = ", sig)


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=SCAFFOLD)
        self.root = Path(self.tmp.name)
        _write(self.tmp.name, "sample.py", SAMPLE)
        self.doc = gad.analyze_file(self.root / "sample.py", self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_module_docstring_captured(self):
        self.assertIn("示例模块", self.doc.summary)

    def test_public_private_split(self):
        names = [s.qualname for s in self.doc.symbols]
        self.assertIn("good", names)
        self.assertIn("_private", names)          # 解析出来
        self.assertNotIn("_private", [s.qualname for s in self.doc.public])  # 但不进文档
        self.assertIn("Widget", [s.qualname for s in self.doc.public])
        self.assertIn("Widget.method", [s.qualname for s in self.doc.public])
        self.assertNotIn("Widget._hidden", [s.qualname for s in self.doc.public])

    def test_fully_documented_symbol_passes(self):
        good = next(s for s in self.doc.public if s.qualname == "good")
        self.assertEqual(good.missing, [])
        self.assertTrue(good.has_args)
        self.assertTrue(good.has_returns)

    def test_one_liner_is_flagged_for_missing_args(self):
        bare = next(s for s in self.doc.public if s.qualname == "bare")
        self.assertIn("缺参数说明", bare.missing)
        self.assertIn("缺返回值说明", bare.missing)

    def test_self_only_method_is_not_penalized(self):
        """`def method(self) -> int` 只有一个 self —— 不该判「缺参数说明」。"""
        method = next(s for s in self.doc.public if s.qualname == "Widget.method")
        self.assertNotIn("缺参数说明", method.missing)

    def test_real_args_without_section_is_flagged(self):
        method = next(s for s in self.doc.public if s.qualname == "Widget.needs_args")
        self.assertIn("缺参数说明", method.missing)

    def test_no_docstring_is_flagged(self):
        with tempfile.TemporaryDirectory(dir=SCAFFOLD) as tmp:
            root = Path(tmp)
            _write(tmp, "x.py", "def f(a):\n    return a\n")
            doc = gad.analyze_file(root / "x.py", root)
            self.assertEqual(doc.public[0].missing, ["无 docstring"])
            self.assertEqual(doc.coverage, 0.0)


class CoverageTests(unittest.TestCase):
    def test_coverage_math(self):
        docs = [
            gad.ModuleDoc(path="a.py", docstring="模块 A", symbols=[
                gad.Symbol(kind="function", name="ok", qualname="ok",
                           signature="def ok()", docstring="做一件事。"),
                gad.Symbol(kind="function", name="bad", qualname="bad",
                           signature="def bad(x)", docstring=""),
            ]),
        ]
        stats = gad.coverage(docs)
        self.assertEqual(stats["symbols"], 2)
        self.assertEqual(stats["symbols_ok"], 1)
        self.assertAlmostEqual(stats["coverage"], 0.5)
        self.assertEqual(len(stats["gaps"]), 1)

    def test_scan_skips_pycache_and_reports_errors(self):
        with tempfile.TemporaryDirectory(dir=SCAFFOLD) as tmp:
            root = Path(tmp)
            (root / "pkg" / "__pycache__").mkdir(parents=True)
            (root / "pkg" / "__pycache__" / "x.py").write_text("x = 1\n", encoding="utf-8")
            (root / "pkg" / "good.py").write_text('"""ok"""\n', encoding="utf-8")
            (root / "pkg" / "broken.py").write_text("def f(:\n", encoding="utf-8")
            docs = gad.scan(root, ["pkg"])
            paths = [d.path for d in docs]
            self.assertEqual(len(paths), 2, "应忽略 __pycache__，只扫 2 个")
            self.assertTrue(any(d.error for d in docs), "语法错误要记进 error，不能崩")

    def test_scan_scaffold_itself(self):
        """扫自己的 core/：要能跑通、有符号、无解析失败。"""
        docs = gad.scan(SCAFFOLD, ["core"])
        stats = gad.coverage(docs)
        self.assertGreaterEqual(stats["symbols"], 40)
        self.assertEqual(stats["errors"], [])
        self.assertGreaterEqual(stats["module_coverage"], 0.9)


if __name__ == "__main__":
    unittest.main(verbosity=2)
