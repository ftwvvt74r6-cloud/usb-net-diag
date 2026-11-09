"""``NetDiag.exe`` 启动器与「启动不提权」的契约测试。

这个文件回答三类问题（也是 C1 的验收点）：

1. **源码/构建契约**：``scripts/build_launcher.py --check`` 在没有 csc 的
   ubuntu CI 上也能跑；manifest 必须是 ``asInvoker``，启动器源码里不许出现
   ``runas`` / ``requireAdministrator``。
2. **真实产物**：有系统 csc 时（本机 / windows CI）实际编译到临时目录，
   断言 exe > 8KB；再把它放进一个**假根目录**跑 ``--dry-run --report``，
   证明它只定位 Python、不启动服务、不开浏览器。假根目录里的 ``pythonw.exe``
   是一个「被启动就写标记文件」的替身 —— 万一 --dry-run 真的启动 app，
   标记文件会暴露它，而不需要等 30 秒轮询或弹真实消息框。
3. **静态回归钉**：``core/app.py`` 的 ``main()`` 启动路径不再调用
   ``relaunch_as_admin()``；``start.bat`` 默认路径不自动 RunAs（只有
   ``--admin`` 条件分支允许）；Npcap 安装不再带 ``/S`` 静默参数。

不启动可见浏览器、不请求 UAC、不写仓库 ``logs/``：所有产物都在临时目录。
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_PY = ROOT / "core" / "app.py"
START_BAT = ROOT / "start.bat"
LAUNCHER_SRC = ROOT / "launcher" / "NetDiagLauncher.cs"
LAUNCHER_MANIFEST = ROOT / "launcher" / "NetDiag.exe.manifest"
BUILD_LAUNCHER = ROOT / "scripts" / "build_launcher.py"
BUILD_RELEASE = ROOT / "scripts" / "build_release.py"
LAUNCHER_EXE = "NetDiag.exe"

sys.path.insert(0, str(ROOT / "scripts"))
import build_launcher  # noqa: E402  复用同一套 csc 探测/结构校验

#: 8787~8796 是 core/server.py 与启动器共用的端口区间。
PORTS = range(8787, 8797)

FAKE_PYTHON_SOURCE = r"""
using System;
using System.IO;
using System.Threading;

internal static class FakePython
{
    // 被启动就留下标记；然后睡一会儿，模拟一个「服务没就绪」的进程。
    private static int Main(string[] args)
    {
        try
        {
            File.WriteAllText(
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "fake-python-launched.txt"),
                string.Join(" ", args));
        }
        catch (Exception) { }
        Thread.Sleep(30000);
        return 0;
    }
}
"""


def _env(**updates: str) -> dict:
    """子进程环境：强制 UTF-8 输出，避免中文 Windows 管道编码差异。"""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(updates)
    return env


def _run(cmd: list[str], timeout: int = 60, env: dict | None = None) -> subprocess.CompletedProcess:
    """跑子进程（UTF-8 解码；失败时调用方断言 returncode）。"""
    return subprocess.run(
        cmd, cwd=str(ROOT), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout, env=env or _env(),
    )


def _listening_ports() -> set[int]:
    """探测 8787~8796 里当前能连上的端口（用于比较前后没有新增监听）。"""
    found: set[int] = set()
    for port in PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.05)
        try:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                found.add(port)
        finally:
            sock.close()
    return found


class LauncherSourceContractTest(unittest.TestCase):
    """不依赖 csc：源码结构 + 启动不提权的静态回归钉。"""

    def test_build_launcher_check_runs_everywhere(self):
        proc = _run([sys.executable, str(BUILD_LAUNCHER), "--check"], timeout=60)
        self.assertEqual(proc.returncode, 0,
                         f"--check 失败：\nstdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("LAUNCHER CHECK OK", proc.stdout)

    def test_manifest_is_as_invoker(self):
        text = LAUNCHER_MANIFEST.read_text(encoding="utf-8")
        self.assertIn('level="asInvoker"', text,
                      "manifest 必须是 asInvoker：双击启动不能请求提权")
        self.assertNotIn('level="requireAdministrator"', text,
                         "manifest 改成了 requireAdministrator：启动会弹 UAC")
        self.assertIn("requestedExecutionLevel", text)

    def test_source_detection_order_and_no_elevation(self):
        source = LAUNCHER_SRC.read_text(encoding="utf-8")
        self.assertNotIn("runas", source.lower(),
                         "启动器自身不许请求提权（runas 只属于界面按需提权）")
        self.assertNotIn("requireAdministrator", source)
        self.assertIn("--no-elevate", source,
                      "启动器拉起 core\\app.py 时必须带 --no-elevate")
        self.assertIn("CreateNoWindow = true", source,
                      "启动器必须隐藏窗口启动 python")
        self.assertIn("UseShellExecute = false", source,
                      "隐藏启动必须 UseShellExecute=false（否则会弹控制台/走 shell）")

        # 只切 FindPython 函数体：NoPythonMessage 里也会出现这些词，不能拿全文定位。
        start = source.index("private static PythonCandidate FindPython()")
        end = source.index("private static string[] SplitPath", start)
        body = source[start:end]
        pythonw = body.index('"pythonw.exe"')
        python = body.index('"python.exe"')
        path_python = body.index("Path.Combine(dirs[i], \"python.exe\")")
        py_launcher = body.index('"py.exe"')
        self.assertLess(pythonw, python, "定位顺序必须是 pythonw.exe -> python.exe")
        self.assertLess(python, path_python, "定位顺序必须是包内 Python -> 系统 PATH")
        self.assertLess(path_python, py_launcher, "定位顺序必须是系统 python -> py -3")

    def test_app_main_never_relaunches_as_admin(self):
        source = APP_PY.read_text(encoding="utf-8")
        main_start = source.index("def main()")
        main_body = source[main_start:source.index('if __name__ == "__main__"', main_start)]
        self.assertNotIn("relaunch_as_admin(", main_body,
                         "core/app.py 的启动路径又调用了 relaunch_as_admin()：双击会弹 UAC")
        self.assertIn("--no-elevate", source,
                      "core/app.py 必须接受启动器传入的 --no-elevate")
        self.assertIn("启动不提权", source,
                      "启动日志缺少「启动不提权」说明")

    def test_no_python_copy_is_friendly_and_has_no_local_path(self):
        """缺 Python 的 MessageBox 文案面向一线：现象 + 安装指引 + 文档，不拼本机路径。"""
        source = LAUNCHER_SRC.read_text(encoding="utf-8")
        start = source.index("private static string NoPythonMessage()")
        end = source.index("private static void WriteDryRunReport", start)
        body = source[start:end]
        self.assertIn("Python 3.11", body)
        self.assertIn("python.org", body)
        self.assertIn("docs/startup.md", body)
        self.assertNotIn("Path.Combine", body,
                         "缺 Python 文案不许运行时拼接本机绝对路径")
        self.assertNotIn("C:\\\\", body)

    def test_dry_run_missing_python_is_structured_and_never_shows_msgbox(self):
        """--dry-run 缺 Python 只写 ok:false/error + exit 2，绝不弹框。"""
        source = LAUNCHER_SRC.read_text(encoding="utf-8")
        start = source.index("private static int RunDryRun")
        end = source.index("private static PythonCandidate FindPython()", start)
        body = source[start:end]
        self.assertIn('error = NoPythonMessage();', body)
        self.assertIn("WriteDryRunReport", body)
        self.assertIn("ExitNoPython", body)
        self.assertNotIn("ShowError", body,
                         "--dry-run 缺 Python 不许弹 MessageBox（自动化会挂住）")
        self.assertNotIn("MessageBoxW", body)

    def test_start_bat_default_does_not_runas(self):
        text = START_BAT.read_text(encoding="utf-8")
        occurrences = text.count("-Verb RunAs")
        self.assertEqual(occurrences, 1,
                         "-Verb RunAs 只允许出现在 --admin 条件分支里一次")
        index = text.index("-Verb RunAs")
        guard = text[max(0, index - 500):index]
        self.assertIn('"%~1"=="--admin"', guard,
                      "RunAs 不在 --admin 条件分支里：默认启动会弹 UAC")
        self.assertNotIn("start /wait \"\" \"%%~f\" /S", text,
                         "Npcap 安装又带上了 /S（免费版立刻失败）")
        self.assertIn('start /wait "" "%%~f"', text,
                      "Npcap 安装应改为交互式 start /wait")
        # P1 起 start.bat 必须纯 ASCII，中文提示在 core/startmsg.py；
        # 这里钉住「安装前必须提示走向导」这条语义仍然存在。
        self.assertIn("call :say npcap_hint", text,
                      "Npcap 交互式安装缺少「请在向导里完成安装」提示")
        msg = (ROOT / "core" / "startmsg.py").read_text(encoding="utf-8")
        self.assertIn("请在向导里完成安装", msg,
                      "Npcap 交互式安装缺少「请在向导里完成安装」提示")


@unittest.skipUnless(os.name == "nt", "启动器只能在 Windows 上真实编译/运行")
class LauncherBinaryTest(unittest.TestCase):
    """有 csc 时实际编译 exe，并跑 --dry-run 证明「只定位、不启动」。"""

    tmp: Path
    exe: Path
    fake_python: Path
    csc: Path | None

    @classmethod
    def setUpClass(cls) -> None:
        cls.csc = build_launcher.find_csc()
        if cls.csc is None:
            raise unittest.SkipTest("本机没有 csc.exe，跳过编译/运行用例")
        cls.tmp = Path(tempfile.mkdtemp(prefix="netdiag_launcher_"))
        out = cls.tmp / "bin"
        proc = _run([sys.executable, str(BUILD_LAUNCHER), "--out", str(out)], timeout=180)
        if proc.returncode != 0:
            raise AssertionError(f"编译启动器失败：\n{proc.stdout}\n{proc.stderr}")
        cls.exe = out / LAUNCHER_EXE
        if not cls.exe.is_file() or cls.exe.stat().st_size < 8 * 1024:
            raise AssertionError(f"启动器产物缺失或过小：{cls.exe}")
        cls.fake_python = cls.tmp / "fake_python.exe"
        fake_src = cls.tmp / "FakePython.cs"
        fake_src.write_text(FAKE_PYTHON_SOURCE, encoding="utf-8")
        compile_proc = _run([
            str(cls.csc), "/nologo", "/target:exe", "/codepage:65001",
            f"/out:{cls.fake_python}", str(fake_src),
        ], timeout=120)
        if compile_proc.returncode != 0:
            raise AssertionError(f"编译假 Python 失败：\n{compile_proc.stdout}\n{compile_proc.stderr}")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def _make_root(self, name: str, with_bundled_python: bool) -> Path:
        """造一个假项目根：NetDiag.exe + core/app.py +（可选）pythonw 替身。"""
        root = self.tmp / name
        (root / "core").mkdir(parents=True)
        (root / "core" / "app.py").write_text("# fake app\n", encoding="utf-8")
        shutil.copy2(self.exe, root / LAUNCHER_EXE)
        if with_bundled_python:
            target = root / "tools" / "python"
            target.mkdir(parents=True)
            shutil.copy2(self.fake_python, target / "pythonw.exe")
        return root

    def _dry_run(self, root: Path, report: Path, path_env: str | None = None,
                 timeout: int = 10) -> subprocess.CompletedProcess:
        env = _env()
        if path_env is not None:
            env["PATH"] = path_env
        try:
            return subprocess.run(
                [str(root / LAUNCHER_EXE), "--dry-run", "--report", str(report)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, env=env,
            )
        except subprocess.TimeoutExpired:
            self.fail("--dry-run 超过 10 秒：疑似启动了服务并进入 30 秒轮询")

    def _assert_no_new_listeners(self, before: set[int]) -> None:
        after = _listening_ports()
        self.assertEqual(after, before,
                         f"--dry-run 不应启动服务、不应新增监听端口：{sorted(after - before)}")

    # -------------------------------------------------------------- tests
    def test_compiled_exe_size(self):
        self.assertGreater(self.exe.stat().st_size, 8 * 1024)
        self.assertEqual(self.exe.read_bytes()[:2], b"MZ", "产物不是 Windows PE")

    def test_dry_run_uses_bundled_python_and_starts_nothing(self):
        root = self._make_root("bundled", with_bundled_python=True)
        report = self.tmp / "report-bundled.json"
        marker = root / "tools" / "python" / "fake-python-launched.txt"
        before = _listening_ports()
        proc = self._dry_run(root, report)
        self.assertEqual(proc.returncode, 0,
                         f"--dry-run 退出码不对：{proc.returncode}\n{proc.stdout}\n{proc.stderr}")
        data = json.loads(report.read_text(encoding="utf-8"))
        self.assertTrue(data["ok"], data)
        self.assertEqual(Path(data["python"]), root / "tools" / "python" / "pythonw.exe",
                         "启动器没有优先使用包内 pythonw.exe")
        self.assertEqual(data["python_kind"], "bundled-pythonw")
        self.assertFalse(data["started"], "--dry-run 报告里 started 必须为 false")
        self.assertFalse(data["browser_opened"], "--dry-run 不许开浏览器")
        self.assertFalse(marker.exists(), "--dry-run 真的启动了 python（标记文件出现）")
        self._assert_no_new_listeners(before)

    def test_dry_run_finds_python_on_path(self):
        root = self._make_root("pathpython", with_bundled_python=False)
        path_dir = self.tmp / "pathdir"
        path_dir.mkdir()
        shutil.copy2(self.fake_python, path_dir / "python.exe")
        report = self.tmp / "report-path.json"
        proc = self._dry_run(root, report, path_env=str(path_dir))
        self.assertEqual(proc.returncode, 0, f"{proc.stdout}\n{proc.stderr}")
        data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(data["python_kind"], "system-python")
        self.assertEqual(Path(data["python"]), path_dir / "python.exe")
        self.assertFalse((path_dir / "fake-python-launched.txt").exists(),
                         "--dry-run 真的执行了 PATH 里的 python")

    def test_dry_run_without_python_exits_2(self):
        root = self._make_root("nopython", with_bundled_python=False)
        report = self.tmp / "report-nopython.json"
        proc = self._dry_run(root, report, path_env="")
        self.assertEqual(proc.returncode, 2,
                         f"找不到 Python 应退出 2，实际 {proc.returncode}")
        data = json.loads(report.read_text(encoding="utf-8"))
        self.assertFalse(data["ok"])
        self.assertIn("Python", data["error"])
        self.assertIn("3.11", data["error"])
        self.assertIn("docs/startup.md", data["error"])
        self.assertEqual(data["python"], "")
        self.assertTrue(data["dry_run"])
        self.assertFalse(data["started"], "--dry-run 缺 Python 不许启动 app")
        self.assertFalse(data["browser_opened"], "--dry-run 缺 Python 不许开浏览器")

    @unittest.skipUnless(shutil.which("git") and (ROOT / ".git").exists(),
                         "需要 git 工作区（发布包解压目录里没有 .git）")
    def test_lite_release_contains_launcher_exe(self):
        """真实走一遍 lite 打包：zip 根必须有 NetDiag.exe，且无 tools/Npcap/Wireshark。

        这是变异锚点「build_release 不再放 NetDiag.exe 进 lite zip」的判别用例：
        去掉 build_release.main 里的 launcher 构建调用，本用例会红。
        """
        out = self.tmp / "dist"
        out.mkdir()
        proc = _run([
            sys.executable, str(BUILD_RELEASE),
            "--out", str(out), "--skip-verify", "--allow-dirty",
        ], timeout=300)
        self.assertEqual(proc.returncode, 0,
                         f"lite 构建失败：\n{proc.stdout}\n{proc.stderr}")
        zips = list(out.glob("NetDiag-*-lite.zip"))
        self.assertEqual(len(zips), 1, f"没有找到 lite zip：{list(out.iterdir())}")

        import zipfile
        with zipfile.ZipFile(zips[0]) as zf:
            names = zf.namelist()
            self.assertEqual({n.split("/")[0] for n in names}, {"NetDiag"},
                             "zip 顶层只允许 NetDiag/（编译临时目录不许漏进包）")
            exe_info = zf.getinfo("NetDiag/NetDiag.exe")
            self.assertGreater(exe_info.file_size, 8 * 1024,
                               "zip 里的 NetDiag.exe 是空壳")
            self.assertFalse([n for n in names if n.startswith("NetDiag/tools/")],
                             "lite 包里不允许出现 tools/")
            self.assertFalse([n for n in names if "npcap-" in n.lower()],
                             "lite 包里不允许出现 Npcap 安装包")
            self.assertFalse([
                n for n in names
                if n.lower().endswith((".exe", ".dll"))
                and ("wireshark" in n.lower() or "tshark" in n.lower())
            ], "lite 包里不允许出现 Wireshark/tshark 二进制")


if __name__ == "__main__":
    unittest.main(verbosity=2)
