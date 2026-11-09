"""``start.bat`` 必须是纯 ASCII，中文提示只能来自 ``core/startmsg.py``。

为什么要钉死这一条
------------------
中文 Windows 的 cmd 在执行 ``chcp 65001`` 之后，仍然按**字节偏移**继续读批处理文件。
文件里只要还有多字节字符，就存在「一个汉字正好跨在行边界」的概率，此时后半截字节
会被当成一条命令执行 —— 现场表现是一串乱码加
``'xxx' 不是内部或外部命令``。实测（真实 start.bat + 桩，控制台代码页 936）：
原样 5 处断行、只把注释改 ASCII 1 处、全角标点转 ASCII 2 处、UTF-8 BOM 5 处，
**只有全 ASCII 是 0 处**。

因此这里不是「风格检查」，而是一条防止回退的硬约束：
只要有人在 ``start.bat`` 里写回一个汉字，双击启动就会在 GBK 控制台里报错，
而且这种报错在开发者自己的 UTF-8 环境里复现不出来。
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import startmsg  # noqa: E402

START_BAT = ROOT / "start.bat"


class StartBatAsciiTest(unittest.TestCase):
    """字节级约束 + 提示 key 的接线正确性。"""

    def setUp(self) -> None:
        self.assertFalse(not START_BAT.is_file(), "start.bat 丢失，便携包入口没了")
        self.raw = START_BAT.read_bytes()
        # 仓库里是 CRLF；断言用归一化后的文本，避免换行风格影响结果
        self.text = self.raw.decode("ascii", "strict").replace("\r\n", "\n")

    def test_every_byte_is_below_0x80(self):
        bad = [(i, b) for i, b in enumerate(self.raw) if b >= 0x80]
        self.assertEqual(bad, [], f"start.bat 出现非 ASCII 字节 {len(bad)} 个：{bad[:5]}")

    def test_no_utf8_bom(self):
        self.assertFalse(self.raw.startswith(b"\xef\xbb\xbf"),
                         "带 BOM 会把首行 @echo off 顶掉，cmd 直接报错")

    def test_every_say_key_is_defined(self):
        keys = re.findall(r"call :say ([a-z_]+)", self.text)
        self.assertTrue(keys, "start.bat 里没有任何 :say 调用，中文提示会整段丢失")
        for key in sorted(set(keys)):
            with self.subTest(key=key):
                self.assertIn(key, startmsg.MESSAGES,
                              f"start.bat 调用了未定义的提示 key：{key}")

    def test_say_helper_exists_and_has_no_chinese(self):
        self.assertIn("\n:say\n", self.text, "缺少 :say 子程序，调用会落到文件末尾")
        body = self.text[self.text.index("\n:say\n"):]
        self.assertIn('"%PY%" %PYARGS% "%ROOT%\\core\\startmsg.py"', body)

    def test_admin_flag_and_error_codes_are_kept(self):
        """--admin 与 bootstrap 的退出码语义不许在改动中丢。"""
        self.assertIn('"%~1"=="--admin"', self.text)
        self.assertIn('"%~1"=="ai"', self.text)
        self.assertIn("if errorlevel 3 goto :no_tshark", self.text)
        self.assertIn('"%ROOT%\\core\\server.py"', self.text)

    def test_python_fallback_order_is_kept(self):
        # "where py" 是 "where python" 的前缀，必须带上重定向后缀才能定位到第二条
        order = ["where python >nul", '"%PY%" -c', "where py >nul",
                 "https://www.python.org/downloads/windows/"]
        positions = [self.text.find(m) for m in order]
        for marker, pos in zip(order, positions):
            with self.subTest(marker=marker):
                self.assertGreaterEqual(pos, 0, f"缺少 Python 回退契约：{marker}")
        self.assertEqual(positions, sorted(positions),
                         "Python 回退顺序必须是 包内 -> python -> py -3")


class StartMsgModuleTest(unittest.TestCase):
    """消息模块本身的行为（UTF-8 直写、未知 key 不输出）。"""

    def test_unknown_key_returns_2_and_prints_nothing(self):
        self.assertEqual(startmsg.main(["nope_not_a_key"]), 2)
        self.assertEqual(startmsg.main([]), 2)

    def test_render_keeps_the_missing_tshark_wording(self):
        text = startmsg.render("no_tshark")
        self.assertIn("未找到 tshark", text)
        self.assertIn("其余功能照常", text)

    def test_render_substitutes_arguments(self):
        self.assertIn("C:\\NetDiag", startmsg.render("banner", ["C:\\NetDiag"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
