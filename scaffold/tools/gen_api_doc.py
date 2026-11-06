"""从源码自动生成接口文档 + 注释覆盖率报告（纯标准库，不 import 被测代码）。

**为什么用生成而不是手写**（对应 T16）：

* 手写的「所有接口清单」一定会过期。代码改名了、加了参数，文档不会自己醒过来。
* 用 AST 解析生成，签名永远是真的；人只需要写「这个接口为什么存在、怎么用」。
* 覆盖率可以算，于是「完整代码注释」从口号变成**可以进 CI 的指标**：
  ``--check 0.95`` 不达标就退出码 1。

用法（在仓库根目录）::

    python scripts/gen_api_doc.py                       # 生成 docs/api-reference.md + docs/docstring-gaps.md
    python scripts/gen_api_doc.py --check 0.95           # 覆盖率不足 95% 就失败（CI 用）
    python scripts/gen_api_doc.py --include core mcp     # 只扫指定目录
    python scripts/gen_api_doc.py --stdout               # 打到屏幕，不写文件

设计约定：

1. **只读不写源码**：只解析 AST，绝不修改被测文件。
2. **公开符号**：名字不以 ``_`` 开头（类里的 dunder 也跳过）。
3. **不做解释**：模块/函数原有的 docstring 原样搬进文档；缺的就是缺的，列在 gaps 里，
   **不替作者编**。这样「文档写了什么」永远是作者的责任。
4. **输出固定 LF**：产物必须能跨平台逐字节复现 —— 否则 Windows 写 CRLF、
   Linux 写 LF，doc-sync 闸门就变成与平台相关的。
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

DEFAULT_INCLUDE = ("core", "mcp")
DEFAULT_DOC = "docs/api-reference.md"
DEFAULT_GAPS = "docs/docstring-gaps.md"

#: 判断 docstring 是否写了某一节（中英混排都能认）。
ARGS_HINTS = ("Args:", "Arguments:", "Parameters:", "参数：", "参数:", ":param")
RETURNS_HINTS = ("Returns:", "Return:", "Yields:", "返回：", "返回:", ":return")
RAISES_HINTS = ("Raises:", "Raises", "异常：", "抛：", ":raises", "抛出")


@dataclass
class Symbol:
    """一个公开符号（模块级函数 / 类 / 类方法）。"""

    kind: str                  # function | class | method
    name: str
    qualname: str              # Class.method
    signature: str
    decorators: tuple[str, ...] = ()
    docstring: str = ""
    lineno: int = 0
    is_public: bool = True

    @property
    def summary(self) -> str:
        """docstring 的第一行（非空、去句号）。"""
        for line in (self.docstring or "").splitlines():
            text = line.strip()
            if text:
                return text
        return ""

    @property
    def has_args(self) -> bool:
        return any(h in (self.docstring or "") for h in ARGS_HINTS)

    @property
    def has_returns(self) -> bool:
        return any(h in (self.docstring or "") for h in RETURNS_HINTS)

    @property
    def has_raises(self) -> bool:
        return any(h in (self.docstring or "") for h in RAISES_HINTS)

    @property
    def missing(self) -> list[str]:
        """缺什么。空列表 = 合格。"""
        gaps: list[str] = []
        if not self.summary:
            gaps.append("无 docstring")
            return gaps
        if self.kind in ("function", "method") and "(" in self.signature:
            inner = self.signature.split("(", 1)[1].split(")", 1)[0]
            # self / cls 不算参数：否则每个方法都被判「缺参数说明」
            inner = inner.replace("self", "").replace("cls", "").strip(" ,*/")
            if inner and not self.has_args:
                gaps.append("缺参数说明")
        if "->" in self.signature and self.signature.split("->")[-1].strip() not in ("None", ""):
            if not self.has_returns:
                gaps.append("缺返回值说明")
        return gaps


@dataclass
class ModuleDoc:
    path: str
    docstring: str = ""
    symbols: list[Symbol] = field(default_factory=list)
    error: str = ""

    @property
    def summary(self) -> str:
        for line in (self.docstring or "").splitlines():
            text = line.strip()
            if text:
                return text
        return ""

    @property
    def public(self) -> list[Symbol]:
        return [s for s in self.symbols if s.is_public]

    @property
    def coverage(self) -> float:
        """合格符号占比（无符号时算 100%）。"""
        pub = self.public
        if not pub:
            return 1.0
        ok = sum(1 for s in pub if not s.missing)
        return ok / len(pub)


# ---------------------------------------------------------------- 解析


def _unparse(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001  极端语法下别让整个工具挂掉
        return ""


def render_signature(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """手工拼签名（``ast.unparse(fn)`` 会把函数体一起带出来）。"""
    a = fn.args
    parts: list[str] = []

    pos = list(getattr(a, "posonlyargs", [])) + list(a.args)
    defaults: list[ast.expr | None] = [None] * (len(pos) - len(a.defaults)) + list(a.defaults)
    for arg, default in zip(pos, defaults):
        text = arg.arg
        if arg.annotation is not None:
            text += f": {_unparse(arg.annotation)}"
        if default is not None:
            text += f"={_unparse(default)}"
        parts.append(text)
    if getattr(a, "posonlyargs", []):
        parts.insert(len(a.posonlyargs), "/")

    if a.vararg is not None:
        parts.append(f"*{a.vararg.arg}")
    elif a.kwonlyargs:
        parts.append("*")
    for arg, default in zip(a.kwonlyargs, a.kw_defaults):
        text = arg.arg
        if arg.annotation is not None:
            text += f": {_unparse(arg.annotation)}"
        if default is not None:
            text += f"={_unparse(default)}"
        parts.append(text)
    if a.kwarg is not None:
        parts.append(f"**{a.kwarg.arg}")

    ret = f" -> {_unparse(fn.returns)}" if fn.returns is not None else ""
    prefix = "async def " if isinstance(fn, ast.AsyncFunctionDef) else "def "
    return f"{prefix}{fn.name}({', '.join(parts)}){ret}"


def _collect(node: ast.ClassDef, out: list[Symbol]) -> None:
    for child in node.body:
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        out.append(Symbol(
            kind="method",
            name=child.name,
            qualname=f"{node.name}.{child.name}",
            signature=render_signature(child),
            decorators=tuple(_unparse(d) for d in child.decorator_list),
            docstring=ast.get_docstring(child) or "",
            lineno=child.lineno,
            is_public=not child.name.startswith("_"),
        ))


def analyze_file(path: Path, root: Path) -> ModuleDoc:
    rel = str(path.relative_to(root)).replace("\\", "/")
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError) as exc:
        return ModuleDoc(path=rel, error=f"{type(exc).__name__}: {exc}")

    doc = ModuleDoc(path=rel, docstring=ast.get_docstring(tree) or "")
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            doc.symbols.append(Symbol(
                kind="function",
                name=node.name,
                qualname=node.name,
                signature=render_signature(node),
                decorators=tuple(_unparse(d) for d in node.decorator_list),
                docstring=ast.get_docstring(node) or "",
                lineno=node.lineno,
                is_public=not node.name.startswith("_"),
            ))
        elif isinstance(node, ast.ClassDef):
            doc.symbols.append(Symbol(
                kind="class",
                name=node.name,
                qualname=node.name,
                signature=f"class {node.name}",
                decorators=tuple(_unparse(d) for d in node.decorator_list),
                docstring=ast.get_docstring(node) or "",
                lineno=node.lineno,
                is_public=not node.name.startswith("_"),
            ))
            _collect(node, doc.symbols)
    return doc


def scan(root: Path, include: Sequence[str]) -> list[ModuleDoc]:
    docs: list[ModuleDoc] = []
    for entry in include:
        base = root / entry
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            docs.append(analyze_file(path, root))
    return docs


# ---------------------------------------------------------------- 统计


def coverage(docs: Iterable[ModuleDoc]) -> dict:
    docs = list(docs)
    symbols = [s for d in docs for s in d.public]
    ok = [s for s in symbols if not s.missing]
    with_doc = [s for s in symbols if s.summary]
    modules_ok = [d for d in docs if d.summary]
    return {
        "modules": len(docs),
        "modules_with_doc": len(modules_ok),
        "module_coverage": round(len(modules_ok) / len(docs), 3) if docs else 1.0,
        "symbols": len(symbols),
        "symbols_with_doc": len(with_doc),
        "symbols_ok": len(ok),
        "coverage": round(len(ok) / len(symbols), 3) if symbols else 1.0,
        "gaps": [s for s in symbols if s.missing],
        "errors": [d for d in docs if d.error],
    }


# ---------------------------------------------------------------- 输出


def render_reference(docs: Sequence[ModuleDoc], stats: dict) -> str:
    lines = [
        "# 接口参考（自动生成）",
        "",
        "> 本文件由 `scripts/gen_api_doc.py` 从 AST 生成，**签名永远与代码一致**。",
        "> 不要手改签名；要改内容就改源码里的 docstring，然后重跑：",
        ">",
        "> ```bat",
        "> tools\\python\\python.exe scripts\\gen_api_doc.py",
        "> ```",
        "",
        f"- 扫描模块：**{stats['modules']}** 个（有模块说明 {stats['modules_with_doc']} 个）",
        f"- 公开符号：**{stats['symbols']}** 个（有 docstring {stats['symbols_with_doc']} 个，"
        f"合格 {stats['symbols_ok']} 个）",
        f"- 合格率：**{stats['coverage'] * 100:.1f}%**（目标 ≥ 95%，见 `docs/api-style.md`）",
        "",
        "阅读顺序建议：先看 `docs/overview.md`（一页看懂项目）→ 本文件的「按模块」→ 具体源码。",
        "",
        "---",
        "",
    ]

    for doc in docs:
        if doc.error:
            lines += [f"## `{doc.path}`", "", f"> ⚠️ 解析失败：{doc.error}", ""]
            continue
        lines += [f"## `{doc.path}`", ""]
        if doc.summary:
            lines += [f"**职责**：{doc.summary}", ""]
        else:
            lines += ["> ⚠️ 本模块**没有模块级 docstring**（不知道它为什么存在）。", ""]

        pub = doc.public
        if not pub:
            lines += ["_（无公开符号）_", ""]
            continue

        lines += ["| 符号 | 类型 | 行 | docstring |", "|---|---|---|---|"]
        for sym in pub:
            flag = "✅" if not sym.missing else "⚠️ " + "、".join(sym.missing)
            lines.append(f"| `{sym.qualname}` | {sym.kind} | {sym.lineno} | {flag} |")
        lines.append("")

        for sym in pub:
            title = f"### `{sym.qualname}`" + (f"  ({sym.kind})" if sym.kind != "function" else "")
            lines += [title, "", "```python"]
            if sym.decorators:
                lines += [f"@{d}" for d in sym.decorators]
            lines.append(sym.signature)
            lines += ["```", ""]
            if sym.docstring:
                body = sym.docstring.strip()
                lines += ["```text", body, "```", ""]
            else:
                lines += ["> ⚠️ 缺少 docstring。", ""]
    return "\n".join(lines) + "\n"


def render_gaps(docs: Sequence[ModuleDoc], stats: dict) -> str:
    lines = [
        "# 注释缺口清单（自动生成）",
        "",
        "> 由 `scripts/gen_api_doc.py` 生成。**这张表就是「补注释」的待办**：",
        "> 一行修完就少一行，`--check` 通过就说明达标了。",
        "",
        f"- 合格率：**{stats['coverage'] * 100:.1f}%**（{stats['symbols_ok']}/{stats['symbols']}）",
        f"- 模块说明：{stats['modules_with_doc']}/{stats['modules']}",
        "",
        "## 按文件汇总",
        "",
        "| 文件 | 公开符号 | 有 docstring | 合格 | 合格率 |",
        "|---|---|---|---|---|",
    ]
    for doc in docs:
        if doc.error:
            lines.append(f"| `{doc.path}` | - | - | - | 解析失败 |")
            continue
        pub = doc.public
        with_doc = sum(1 for s in pub if s.summary)
        ok = sum(1 for s in pub if not s.missing)
        lines.append(f"| `{doc.path}` | {len(pub)} | {with_doc} | {ok} | "
                     f"{doc.coverage * 100:.0f}% |")
    lines.append("")

    lines += ["## 待补清单", "", "| 文件:行 | 符号 | 缺什么 |", "|---|---|---|"]
    for doc in docs:
        for sym in doc.symbols:
            if sym.is_public and sym.missing:
                lines.append(f"| `{doc.path}:{sym.lineno}` | `{sym.qualname}` | "
                             f"{'、'.join(sym.missing)} |")
    for doc in docs:
        if not doc.error and not doc.summary:
            lines.append(f"| `{doc.path}:1` | （模块级） | 缺模块说明 |")
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="生成接口文档与注释覆盖率报告")
    ap.add_argument("--root", default=".", help="仓库根目录（默认当前目录）")
    ap.add_argument("--include", nargs="*", default=list(DEFAULT_INCLUDE),
                    help=f"要扫描的目录（默认 {DEFAULT_INCLUDE}）")
    ap.add_argument("--out", default=DEFAULT_DOC, help=f"接口文档输出路径（默认 {DEFAULT_DOC}）")
    ap.add_argument("--gaps", default=DEFAULT_GAPS, help=f"缺口清单输出路径（默认 {DEFAULT_GAPS}）")
    ap.add_argument("--check", type=float, default=None,
                    help="合格率门槛（0~1）；低于它就返回码 1，CI 用")
    ap.add_argument("--stdout", action="store_true", help="只打屏幕，不写文件")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    docs = scan(root, args.include)
    if not docs:
        print(f"[错误] 在 {root} 下没找到可扫描的 .py（include={args.include}）。\n"
              f"        请在**仓库根目录**运行（那里才有 core/ 和 mcp/）；\n"
              f"        或者用 --include 指定目录，例如 --include scaffold/core。",
              file=sys.stderr)
        return 2

    stats = coverage(docs)
    reference = render_reference(docs, stats)
    gaps = render_gaps(docs, stats)

    if args.stdout:
        print(reference)
        return 0

    (root / args.out).parent.mkdir(parents=True, exist_ok=True)
    (root / args.out).write_text(reference, encoding="utf-8", newline="\n")
    (root / args.gaps).parent.mkdir(parents=True, exist_ok=True)
    (root / args.gaps).write_text(gaps,     encoding="utf-8", newline="\n")

    print(f"模块 {stats['modules']} 个（有说明 {stats['modules_with_doc']}）"
          f"｜公开符号 {stats['symbols']} 个（合格 {stats['symbols_ok']}）"
          f"｜合格率 {stats['coverage'] * 100:.1f}%")
    print(f"已写：{args.out} 与 {args.gaps}")
    if stats["gaps"]:
        print(f"待补 {len(stats['gaps'])} 个符号 —— 明细见 {args.gaps}")
    for doc in stats["errors"]:
        print(f"[解析失败] {doc.path}: {doc.error}", file=sys.stderr)

    if args.check is not None and stats["coverage"] < args.check:
        print(f"[不达标] 合格率 {stats['coverage'] * 100:.1f}% < 门槛 "
              f"{args.check * 100:.1f}%", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
