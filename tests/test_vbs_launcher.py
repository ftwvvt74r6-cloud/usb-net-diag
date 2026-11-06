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

# NetDiag.vbs 的写法：pyw = root & "\tools\python\pythonw.exe"
# 抓 root & "\xxx" 里的相对路径，交给磁盘校验。
REF_PATTERN = re.compile(r'root\s*&\s*"\\([^"]+)"')

# NetDiag-stop.vbs 的写法：port = 8787
PORT_PATTERN = re.compile(r"^\s*port\s*=\s*(\d+)\s*$", re.MULTILINE)

# core/config.py 的 DEFAULTS 里： "server_port": 8787
CONFIG_PORT_PATTERN = re.compile(r'"server_port"\s*:\s*(\d+)')


def _read(path: Path) -> str:
    """读文本，坏字节替换掉 —— 契约检查不该因为一个乱码字符而崩。"""
    return path.read_text(encoding="utf-8", errors="replace")


class VbsLauncherContract(unittest.TestCase):
    def test_vbs_launcher_contract(self):
        """四个契约一起验；任一段失败会指出是哪一段。"""

        # ---- 1. 三个入口文件必须都在 ----
        with self.subTest("入口文件存在"):
            for path in (VBS, STOP_VBS, ICO):
                self.assertTrue(path.is_file(), f"启动器资产缺失：{path.name}")

        # ---- 2. vbs 里写死的相对路径必须能在磁盘上落地 ----
        with self.subTest("vbs 引用路径与磁盘一致"):
            refs = REF_PATTERN.findall(_read(VBS))
            self.assertGreaterEqual(
                len(refs), 2,
                "没能从 NetDiag.vbs 解析出入口路径，脚本格式可能被整体改写了",
            )
            for ref in refs:
                target = ROOT.joinpath(*ref.split("\\"))
                self.assertTrue(
                    target.is_file(),
                    f"NetDiag.vbs 引用了不存在的路径：{ref}（双击后会静默失败）",
                )

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
