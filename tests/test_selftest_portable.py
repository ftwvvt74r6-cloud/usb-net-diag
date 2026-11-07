"""把 ``tests/selftest.py`` 里**机器无关**的段接进 unittest / CI（PR G · V1）。

背景：``selftest.py`` 是人工跑的自检脚本，断言用 ``check(name, cond)`` 记账 ——
**不抛异常**。``unittest discover`` 不会收集它，所以 §1 输入校验这类纯逻辑回归
在 CI 里一直是盲区；就算有人把整段塞进用例，不接管 ``check`` 也永远是绿的。

做法：

* 每个用例把 ``selftest.check`` / ``selftest.skip`` 换成自己的记账函数，
  ``cond=False`` 收进失败清单，段跑完 ``assertEqual(失败清单, [])``；
  同时统计 ``check`` 被调用了几次，防止「这一段根本没跑」也变绿。
* 只纳入在**干净 checkout**（无 ``tools/``、非管理员、无 scapy、无 tshark）里
  实测能过的段：§1 输入校验、§2/§2b 本地 mock 体检、§5/§6 本地 HTTP API。
  实测数据：§1 18 项、§2 13 项、§5 12 项、§6 4 项全过；§2b 因本机无 openssl
  由 selftest 自己 skip。这些段只绑 ``127.0.0.1``，不访问外网、不依赖 ``tools/``。
* §3 被动监听依赖**固定网卡序号 + 管理员 + Npcap + 真实流量**，不是机器无关的，
  在 wrapper 里登记 ``selftest.skip``（人工自检仍用 ``tests/selftest.py --fast``）。
* §4 离线分析只需要 tshark：有 tshark 就真跑，没有就 ``selftest.skip`` ——
  绝不让内部 ``check`` 变红。因此本文件在干净 checkout 里是 **OK 且不 skip**
  （unittest 层面），而 §3/§4 的检查项以 ``[SKIP]`` 出现在日志里。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import selftest  # noqa: E402


class _SelftestCase(unittest.TestCase):
    """公共夹具：接管 ``selftest`` 的 check/skip 记账，跑完恢复原函数。"""

    def setUp(self) -> None:
        self.failures: list[str] = []
        self.skips: list[tuple[str, str]] = []
        self.checked = 0
        self._orig_check = selftest.check
        self._orig_skip = selftest.skip
        self._orig_section = selftest.section
        selftest.check = self._check
        selftest.skip = self._skip
        # selftest 的段标题是中文，且用 ``print`` 写 stdout。CI 的 Windows 控制台
        # 是 cp1252 且 stdout 为 strict，直接打印会 UnicodeEncodeError（实测踩过）。
        # 段标题对 unittest 没有价值，直接静音。
        selftest.section = lambda title: None

    def tearDown(self) -> None:
        selftest.check = self._orig_check
        selftest.skip = self._orig_skip
        selftest.section = self._orig_section

    def _check(self, name: str, cond: bool, detail: str = "") -> None:
        self.checked += 1
        if not cond:
            self.failures.append(f"{name} — {detail}" if detail else name)

    def _skip(self, name: str, why: str) -> None:
        self.skips.append((name, why))
        # 走 stderr：Python 的 stderr 默认是 backslashreplace，cp1252 控制台也能安全打印；
        # stdout 是 strict，中文会直接炸掉整个用例。
        print(f"  [SKIP] {name} — {why}", file=sys.stderr, flush=True)

    def assert_section_clean(self, section: str) -> None:
        """断言某一段没有 ``cond=False`` 的项。"""
        self.assertEqual(
            self.failures, [],
            f"{section} 有失败项：\n" + "\n".join(f"  - {x}" for x in self.failures),
        )

    def assert_checks_ran(self, minimum: int = 1) -> None:
        """断言这一段真的调用了 ``check``（防「段体被跳过也全绿」）。"""
        self.assertGreaterEqual(
            self.checked, minimum,
            f"这一段只跑了 {self.checked} 个 check，疑似段体没被执行",
        )


class ValidationSectionTest(_SelftestCase):
    """§1 输入校验与边界：纯逻辑，任何机器都必须全过。"""

    def test_validation_section_passes(self):
        """过滤器注入、端口越界、布尔字符串、IPv6 字面量都不能回归。"""
        selftest.test_validation()
        self.assert_section_clean("§1 输入校验与边界")
        self.assert_checks_ran(10)


class ProbeSectionTest(_SelftestCase):
    """§2 协议自适应体检：只绑 127.0.0.1 的 mock 服务，不需要 tshark。"""

    def test_probe_section_passes(self):
        """明文 HTTP / SMB / SSH banner / 无 banner / 端口不通的判定不能回归。"""
        selftest.test_probe()
        selftest.test_probe_tls()   # 没有 openssl 时由 selftest 自己 skip，不算失败
        self.assert_section_clean("§2 协议自适应体检")
        self.assert_checks_ran(10)


class ApiSectionTest(_SelftestCase):
    """§5/§6 本地 HTTP API 与生命周期：起在 127.0.0.1，不需要 tools/。"""

    def test_api_section_passes(self):
        """Host 校验 / 请求体上限 / 上传类型 / 报告路径穿越 / 安全响应头。"""
        selftest.test_api()
        self.assert_section_clean("§5 HTTP API 加固")
        self.assert_checks_ran(10)

    def test_lifecycle_section_passes(self):
        """探活 / 应用信息 / 优雅退出后端口释放。"""
        selftest.test_lifecycle()
        self.assert_section_clean("§6 应用生命周期")
        self.assert_checks_ran(3)


class EnvironmentDependentSectionTest(_SelftestCase):
    """§3/§4 依赖机器环境：缺前提时必须 skip，不能把内部 ``check`` 变成失败。"""

    def test_passive_section_is_skipped(self):
        """§3 永不进 CI：固定网卡序号 + 管理员 + Npcap + 真实流量，只能人工跑。

        ``test_passive`` 里 ``passive.run("6", ...)`` 的网卡序号是写死的，
        换台机器结论就变；把它塞进自动化等于给 CI 埋一颗随机红的雷。
        """
        selftest.skip(
            "§3 被动监听（需要管理员 + Npcap + 真实流量）",
            "固定网卡序号/实时抓包依赖具体机器，保留给人工自检 tests/selftest.py --fast",
        )
        self.assert_section_clean("§3 被动监听")
        self.assertEqual(len(self.skips), 1, "§3 应登记 1 条 skip")
        self.assertIn("被动监听", self.skips[0][0])

    def test_offline_section_skips_without_tshark(self):
        """§4 有 tshark 就真跑；干净 checkout（CI）里没有，必须 skip 而不是失败。"""
        if selftest.diagnose.tshark.find_tshark() is None:
            selftest.skip("§4 离线分析（需要 tshark）", "未找到 tshark")
            self.assertEqual(len(self.skips), 1, "§4 应登记 1 条 skip")
            self.assertIn("离线分析", self.skips[0][0])
        else:
            selftest.test_offline()
            self.assert_checks_ran(4)
        self.assert_section_clean("§4 离线分析")


if __name__ == "__main__":
    unittest.main(verbosity=2)
