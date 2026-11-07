"""整套测试的兜底断言：跑完全套后仓库 ``logs/`` 零新增（SPEC V7）。

为什么叫 ``test_zz_``：``unittest discover`` 按文件名排序**导入全部模块**再执行用例，
本模块是最后一个被导入、也是最后一个执行的。模块导入时先抓一份仓库 ``logs/`` 快照
（此时所有用例都还没跑），用例执行时再比一次 —— 等价于「整套跑完」的 before/after。
单跑本模块时它是恒真自检；真正的主证据是 WRITER.md 里整套 before/after 的计数。

本文件不 import 任何项目模块：它只观察文件系统，避免自己把日志写进去。
"""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_LOGS = ROOT / "logs"


def _dir_state(path: Path) -> tuple:
    """目录内每个文件的 ``(名字, 大小, mtime_ns)``。"""
    if not path.is_dir():
        return ()
    return tuple(
        (p.name, p.stat().st_size, p.stat().st_mtime_ns)
        for p in sorted(path.iterdir()) if p.is_file()
    )


_IMPORT_STATE = _dir_state(REPO_LOGS)


class RepoLogsUntouchedBySuiteTest(unittest.TestCase):
    def test_repo_logs_unchanged_after_full_suite(self):
        """整套用例（导入快照 → 全部跑完）没有往仓库 ``logs/`` 写任何文件。"""
        self.assertEqual(
            _dir_state(REPO_LOGS), _IMPORT_STATE,
            "跑完全套后仓库 logs/ 有新增/改动：测试必须用 NETDIAG_LOG_DIR 注入临时目录",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
