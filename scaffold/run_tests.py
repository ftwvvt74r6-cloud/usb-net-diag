"""骨架自检入口。

**为什么需要这个文件**：项目自带的便携 Python 用了 ``python311._pth``，
它把 ``sys.path`` 固定成三行（``python311.zip`` / ``.`` / ``Lib\\site-packages``），
**不会把当前工作目录加进去**，所以直接 ``python -m unittest discover`` 会
``ImportError: No module named core``。

这里显式把 ``scaffold/`` 加到 ``sys.path[0]``，于是项目便携 Python、
系统 Python、CI 上的 Python 三处行为一致。

用法::

    ..\\tools\\python\\python.exe run_tests.py          # 项目便携 Python
    python run_tests.py                                # 系统 Python 3.11+
    python run_tests.py -v                             # 详细模式（默认就是 verbose）
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main(verbosity: int = 2) -> int:
    # 1) 让 `import core...` 可用（便携 Python 的关键补丁）
    sys.path.insert(0, str(ROOT))
    # 2) 别在可移动盘/只读盘上留 __pycache__
    sys.dont_write_bytecode = True

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(ROOT / "tests"), top_level_dir=str(ROOT))
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    print()
    print(f"用例 {result.testsRun} 个｜失败 {len(result.failures)}｜"
          f"错误 {len(result.errors)}｜跳过 {len(result.skipped)}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
