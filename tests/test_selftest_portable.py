"""把 ``tests/selftest.py`` 里**机器无关**的段接进 unittest / CI（PR G · V1）。

背景：``selftest.py`` 是人工跑的自检脚本，断言用 ``check(name, cond)`` 记账 ——
**不抛异常**。``unittest discover`` 不会收集它，所以 §1 输入校验这类纯逻辑回归
在 CI 里一直是盲区；就算有人把整段塞进用例，不接管 ``check`` 也永远是绿的。

做法：

* 每个用例把 ``selftest.check`` / ``selftest.skip`` 换成自己的记账函数，
  ``cond=False`` 收进失败清单，段跑完 ``assertEqual(失败清单, [])``；
  同时统计 ``check`` 被调用了几次，防止「这一段根本没跑」也变绿。
* **段级 skip 必须传播成 unittest skip**（B2）：段执行期间只要登记过 ``skip``，
  用例就 ``self.skipTest(reason)`` —— 不许「静默少了几个 check 还绿」，
  也不许变成红。端口被占（8080/8088/8090/8000 或 8790-8799 / 8801-8810）、
  没有 tshark、没有 openssl 都走这条路。
* ``assert_checks_ran`` 的阈值按**实际子段**收紧（C2）：§1=18、§2=13、§2b=3、
  §5=12、§6=4、§4=6；阈值只在「没有任何 skip」时才校验，避免环境缺能力时误红。
* 只纳入在**干净 checkout**（无 ``tools/``、非管理员、无 scapy、无 tshark）里
  实测能过的段：§1 输入校验、§2 本地 mock 体检、§5/§6 本地 HTTP API。
  这些段只绑 ``127.0.0.1``，不访问外网、不依赖 ``tools/``。
* §3 被动监听依赖**固定网卡序号 + 管理员 + Npcap + 真实流量**，不是机器无关的；
  用例只验证 skip 登记并传播（人工自检仍用 ``tests/selftest.py --fast``）。
* §4 离线分析有 tshark 就真跑，没有就 skip；§2b TLS 有 openssl 就真跑，没有就 skip。
* 测试**不写仓库 ``logs/``**（B3）：``setUp`` 把 ``NETDIAG_LOG_DIR`` 指到临时目录
  （``logstore.log_root()`` 每次读环境变量），``tearDown`` 再用「目录文件列表 before/after」
  证明仓库 ``logs/`` 一个文件都没多。
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import selftest  # noqa: E402
import logstore  # noqa: E402

diagnose = selftest.diagnose
REPO_LOGS = ROOT / "logs"


def _dir_state(path: Path) -> tuple:
    """目录内每个文件的 ``(名字, 大小, mtime_ns)``；用来证明「没有新增/改动」。"""
    if not path.is_dir():
        return ()
    return tuple(
        (p.name, p.stat().st_size, p.stat().st_mtime_ns)
        for p in sorted(path.iterdir()) if p.is_file()
    )


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

        # B3：磁盘日志改道临时目录。所有日志出口（server.log → logstore.diag_log、
        # diagnose 的 run 记录、崩溃快照）都读 NETDIAG_LOG_DIR，所以改环境变量一次就够。
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(
            os.environ, {logstore.ENV_LOG_DIR: str(Path(self._tmp.name) / "logs")})
        self._env.start()
        logstore.close_streams()
        self._repo_logs_before = _dir_state(REPO_LOGS)

    def tearDown(self) -> None:
        try:
            self.assertEqual(
                _dir_state(REPO_LOGS), self._repo_logs_before,
                "测试往仓库 logs/ 写了文件：应把 NETDIAG_LOG_DIR 指向临时目录",
            )
        finally:
            logstore.close_streams()
            self._env.stop()
            selftest.check = self._orig_check
            selftest.skip = self._orig_skip
            selftest.section = self._orig_section
            self._tmp.cleanup()

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

    def assert_checks_ran(self, minimum: int) -> None:
        """断言这一段真的调用了 ``check``（防「段体被跳过也全绿」）。"""
        self.assertGreaterEqual(
            self.checked, minimum,
            f"这一段只跑了 {self.checked} 个 check（应至少 {minimum} 个），"
            "疑似子段没被执行",
        )

    def finish_section(self, section: str, minimum: int) -> None:
        """段跑完后的统一判定。

        失败清单优先（有失败就是红，不能被 skip 掩盖）；有段级 skip 就传播成
        unittest skip；两者都没有才校验「至少跑了 N 个 check」。

        Args:
            section: 段名，用于失败信息。
            minimum: 该段在「无 skip」时应执行的 check 数（按实际子段收紧）。
        """
        self.assert_section_clean(section)
        if self.skips:
            detail = "；".join(f"{name} — {why}" for name, why in self.skips)
            self.skipTest(f"{section} 有子段跳过：{detail}")
        self.assert_checks_ran(minimum)


class ValidationSectionTest(_SelftestCase):
    """§1 输入校验与边界：纯逻辑，任何机器都必须全过（18 项）。"""

    def test_validation_section_passes(self):
        """过滤器注入、端口越界、布尔字符串、IPv6 字面量都不能回归。"""
        selftest.test_validation()
        self.finish_section("§1 输入校验与边界", 18)


class ProbeSectionTest(_SelftestCase):
    """§2 协议自适应体检：只绑 127.0.0.1 的 mock 服务，不需要 tshark（13 项）。"""

    def test_probe_section_passes(self):
        """明文 HTTP / SMB / SSH banner / 无 banner / 端口不通的判定不能回归。

        8080/8088/8090/8000 全被占时 selftest 会登记段级 skip，这里传播成
        unittest skip —— 不探别人的服务，也不静默变绿。
        """
        selftest.test_probe()
        self.finish_section("§2 协议自适应体检", 13)


class TlsSectionTest(_SelftestCase):
    """§2b TLS 体检：有 openssl 才真跑（3 项），没有就整段 skip。"""

    def test_tls_section_passes_or_skips(self):
        """自签证书握手 / 版本号 / 不误判故障；无 openssl 时 skip 而不是伪装通过。"""
        selftest.test_probe_tls()
        self.finish_section("§2b TLS 体检", 3)


class ApiSectionTest(_SelftestCase):
    """§5/§6 本地 HTTP API 与生命周期：起在 127.0.0.1，不需要 tools/。"""

    def test_api_section_passes(self):
        """Host 校验 / 请求体上限 / 上传类型 / 报告路径穿越 / 安全响应头（12 项）。"""
        selftest.test_api()
        self.finish_section("§5 HTTP API 加固", 12)

    def test_lifecycle_section_passes(self):
        """探活 / 应用信息 / 优雅退出后端口释放（4 项）。

        这条会走 ``POST /api/quit`` → ``server.log`` → ``logstore.diag_log``，
        是 B3 里唯一真正会写 ``logs/`` 的路径；``setUp`` 已把
        ``NETDIAG_LOG_DIR`` 改道临时目录。
        """
        selftest.test_lifecycle()
        self.finish_section("§6 应用生命周期", 4)


class EnvironmentDependentSectionTest(_SelftestCase):
    """§3/§4 依赖机器环境：缺前提时必须 skip，不能把内部 ``check`` 变成失败。"""

    def test_passive_section_is_skipped(self):
        """§3 永不进 CI：固定网卡序号 + 管理员 + Npcap + 真实流量，只能人工跑。

        ``test_passive`` 里 ``passive.run("6", ...)`` 的网卡序号是写死的，
        换台机器结论就变；把它塞进自动化等于给 CI 埋一颗随机红的雷。
        """
        selftest.skip(
            "§3 被动监听（需要管理员 + Npcap + 真实流量）",
            "固定网卡序号/实时抓包依赖具体机器；需管理员 + Npcap，由人工自检覆盖"
            "（tests/selftest.py --fast）",
        )
        self.assertEqual(self.failures, [])
        self.assertEqual(len(self.skips), 1, "§3 应登记 1 条 skip")
        name, why = self.skips[0]
        self.assertIn("被动监听", name)
        # C1：skip 原因必须说清前提与替代路径，不能只写「依赖机器」。
        self.assertIn("管理员", why)
        self.assertIn("Npcap", why)
        self.assertIn("人工自检", why)
        self.finish_section("§3 被动监听", 0)      # 段级 skip → unittest skip

    def test_offline_section_skips_without_tshark(self):
        """§4 有 tshark 就真跑；干净 checkout（CI）里没有，必须 skip 而不是失败。"""
        if selftest.diagnose.tshark.find_tshark() is None:
            selftest.skip("§4 离线分析（需要 tshark）", "未找到 tshark")
            self.assertEqual(len(self.skips), 1, "§4 应登记 1 条 skip")
            self.assertIn("离线分析", self.skips[0][0])
            self.finish_section("§4 离线分析", 0)  # 段级 skip → unittest skip
        else:
            selftest.test_offline()
            self.finish_section("§4 离线分析", 6)


if __name__ == "__main__":
    unittest.main(verbosity=2)
