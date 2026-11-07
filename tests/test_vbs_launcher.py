"""VBS 静默启动器契约测试。

目的：``NetDiag.vbs`` / ``NetDiag-stop.vbs`` 是普通用户唯一会双击的两个文件，
但它们不是 Python —— 没有 import 检查、没有类型提示，跑不起来也不会在 CI 里报错。
一旦里面写死的相对路径、端口号，或停止器依赖的两个约定（``/api/quit``、
``netdiag.pid``）跟源码脱节，表现就是「双击没反应」，
而这类故障恰恰最难从日志里看出来（日志压根没生成）。

所以这里把 vbs 里的事实当契约断言：只读文本 + 查磁盘，
不 import 任何项目模块，不依赖 tshark / scapy / 网络。
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VBS = ROOT / "NetDiag.vbs"
STOP_VBS = ROOT / "NetDiag-stop.vbs"
ICO = ROOT / "NetDiag.ico"

# 便携运行环境不进仓库，CI 的干净 checkout 里没有这两个目录，
# 不能拿磁盘存在性去校验（与 tests/test_launcher_contract.py 保持同一约定）。
SKIP_PREFIX = ("tools", "harness")

# NetDiag.vbs 的写法：pyw = root & "\tools\python\pythonw.exe"
# 抓 root & "\xxx" 里的相对路径，交给磁盘校验。
REF_PATTERN = re.compile(r'root\s*&\s*"\\([^"]+)"')

# NetDiag-stop.vbs 的写法：port = 8787
PORT_PATTERN = re.compile(r"^\s*port\s*=\s*(\d+)\s*$", re.MULTILINE)

# core/config.py 的 DEFAULTS 里： "server_port": 8787
CONFIG_PORT_PATTERN = re.compile(r'"server_port"\s*:\s*(\d+)')


def _read(path: Path) -> str:
    """读文本，兼容 WSH 的 UTF-16 LE BOM 与普通 UTF-8；坏字节替换掉。"""
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8", errors="replace")


class VbsLauncherContract(unittest.TestCase):
    def test_vbs_launcher_contract(self):
        """四个契约一起验；任一段失败会指出是哪一段。"""

        # ---- 1. 三个入口文件必须都在 ----
        with self.subTest("入口文件存在"):
            for path in (VBS, STOP_VBS, ICO):
                self.assertTrue(path.is_file(), f"启动器资产缺失：{path.name}")

        # ---- 2. vbs 里写死的相对路径必须能在磁盘上落地 ----
        with self.subTest("vbs 引用路径与磁盘一致"):
            self.assertTrue(
                VBS.read_bytes().startswith(b"\xff\xfe"),
                "NetDiag.vbs 必须保存为 UTF-16 LE BOM：WSH 在中文系统上按 ANSI "
                "读取无 BOM 的 UTF-8 会报“未结束的字符串常量”",
            )
            refs = REF_PATTERN.findall(_read(VBS))
            self.assertGreaterEqual(
                len(refs), 2,
                "没能从 NetDiag.vbs 解析出入口路径，脚本格式可能被整体改写了",
            )
            for ref in refs:
                if ref.split("\\")[0].lower() in SKIP_PREFIX:
                    continue      # 便携运行环境不进仓库，CI 里无法校验
                target = ROOT.joinpath(*ref.split("\\"))
                self.assertTrue(
                    target.is_file(),
                    f"NetDiag.vbs 引用了不存在的路径：{ref}（双击后会静默失败）",
                )
            # 上面跳过了 tools/，这里用纯文本断言补住这个盲区：
            # 不需要磁盘上有该文件，只要求 vbs 仍然优先指向便携 Python 的 pythonw.exe，
            # 且保留系统 python / py -3 的回退链（lite 环境没有 tools/）。
            vbs = _read(VBS)
            self.assertIn(
                "tools\\python\\pythonw.exe", vbs,
                "NetDiag.vbs 不再指向便携 Python 的 pythonw.exe",
            )
            markers = [
                "tools\\python\\pythonw.exe",
                'cmd = "python """',
                'cmd = "py -3 """',
                "https://www.python.org/downloads/windows/",
            ]
            positions = []
            for marker in markers:
                idx = vbs.find(marker)
                with self.subTest(marker=marker):
                    self.assertGreaterEqual(
                        idx, 0, f"NetDiag.vbs 缺少 Python 回退契约：{marker}")
                positions.append(idx)
            self.assertEqual(
                positions, sorted(positions),
                "NetDiag.vbs 的 Python 回退顺序不是 包内 pythonw -> python -> py -3")
            self.assertIn("sys.version_info", vbs,
                          "NetDiag.vbs 的回退没有校验 Python 3.11+")

        # ---- 3. 停止器依赖的两个约定 ----
        with self.subTest("server.py 保留 /api/quit 与 netdiag.pid"):
            src = _read(ROOT / "core" / "server.py")
            self.assertIn(
                "/api/quit", src,
                "server.py 不再暴露 /api/quit，停止器的第 1 条退出路径会失效",
            )
            self.assertIn(
                "netdiag.pid", src,
                "server.py 不再写 logs/netdiag.pid，停止器的兜底强杀会失效",
            )

        # ---- 4. 停止器端口必须等于 config 默认端口 ----
        with self.subTest("停止器端口与 config 默认端口一致"):
            match = PORT_PATTERN.search(_read(STOP_VBS))
            self.assertIsNotNone(match, "没能从 NetDiag-stop.vbs 解析出 port 赋值")
            assert match is not None
            cfg_match = CONFIG_PORT_PATTERN.search(_read(ROOT / "core" / "config.py"))
            self.assertIsNotNone(cfg_match, "没能从 core/config.py 解析出 server_port 默认值")
            assert cfg_match is not None
            self.assertEqual(
                int(match.group(1)), int(cfg_match.group(1)),
                "NetDiag-stop.vbs 的端口与 config 默认 server_port 脱节，"
                "停止器会一直打到错端口、只能靠强杀兜底",
            )


class StopLauncherEncodingTest(unittest.TestCase):
    """``NetDiag-stop.vbs`` 与主启动器同源同坑：必须 UTF-16 LE BOM + CRLF。

    背景（R 轮复审 B1）：两个 VBS 原本都是 UTF-8 无 BOM，中文系统 WSH(ACP936) 会报
    「未结束的字符串常量 / 语句未结束」，双击等于坏文件。主启动器已在 R 轮修好，
    停止器漏了 —— 而 UI 上「退出」按钮正是提示用户双击它。
    """

    def test_stop_vbs_is_utf16_bom_crlf(self) -> None:
        raw = STOP_VBS.read_bytes()
        self.assertTrue(raw.startswith(b"\xff\xfe"),
                        "NetDiag-stop.vbs 必须保存为 UTF-16 LE BOM（中文系统 WSH 才认）")
        text = raw.decode("utf-16")
        self.assertIn("\r\n", text, "NetDiag-stop.vbs 必须用 CRLF 换行（cmd/wscript 兼容）")
        self.assertIn("port = 8787", text, "停止器应保留默认端口契约")

    def test_main_vbs_has_no_dead_py_branch(self) -> None:
        """``py`` 从未赋值，``FileExists(py)`` 是死分支，必须删掉。"""
        text = VBS.read_bytes().decode("utf-16")
        self.assertNotIn("fso.FileExists(py)", text,
                         "NetDiag.vbs 里 FileExists(py) 是死分支（py 从未赋值）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
