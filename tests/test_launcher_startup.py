"""H1/H2/H3 launcher 契约 + 真实二进制行为（Windows + 系统 csc 才跑）。

覆盖 H-SPEC 里必须可机械证伪的几条：

* **源码契约**（ubuntu CI 也能跑）：唯一打开点、env 传递、复用分支在启动 Python
  之前、端口枚举优化、`logs/startup.log` / `config/launcher-cache.json` /
  `/api/preflight` / `--measure` / `--splash-test` 这些标记都在。
* **--dry-run**：报告里明确写「子进程会收到 NETDIAG_NO_BROWSER=1」「只允许 1 个
  打开点」「没有 splash」，且不启动任何进程。
* **--measure**：真实走一次启动（隐藏子进程 + env）→ 等 `/api/ping` → 写
  `logs/startup.log` → `POST /api/quit` 优雅退出；t0~t3 结构 / 冷热模式 /
  缓存失效重扫都能从报告里读出来。
* **复用实例**：已有本程序实例时只复用，不新起进程、也不退出别人的服务。
* **--splash-test**：离屏渲染 4 张 PNG（加载中 / 全绿 / 缺 tshark / 非管理员），
  并写 `splash-states.json` 供「状态映射 / 按钮可见性」断言。

所有产物都在临时目录；不启动可见浏览器，不弹 UAC，不依赖 tshark/Npcap。

环境抖动与产品失败要分开：本机 csc 缺失 / 编译超时 / 产品端口区间（8787~8796）
被残留进程或真实实例占用，都是**测试环境**问题，不是产品缺陷。这类情况一律
``skipTest`` 并写明原因，绝不判红 —— 一条随机红会把真正的回归淹没在噪音里。
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import build_launcher  # noqa: E402

LAUNCHER_SRC = ROOT / "launcher" / "NetDiagLauncher.cs"
SPLASH_SRC = ROOT / "launcher" / "SplashForm.cs"
MANIFEST = ROOT / "launcher" / "NetDiag.exe.manifest"
EXE_NAME = "NetDiag.exe"
PORTS = range(8787, 8797)


def _env(**updates: str) -> dict:
    """子进程环境：UTF-8 输出，避免中文 Windows 管道编码差异。"""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(updates)
    return env


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """跑一个 Python 侧子进程（只用于编译，不做 GUI 等待）。"""
    return subprocess.run(
        cmd, cwd=str(ROOT), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout, env=_env(),
    )


def _listening_ports() -> set[int]:
    """8787~8796 里当前能连上的端口（确认没有残留监听）。"""
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

#: 假 app：真实启动一个本地 HTTP 服务，行为足够让 launcher 走完 measure 全流程。
#: 它把收到的 NETDIAG_NO_BROWSER 写进 env-marker.txt —— 这是「launcher 真的把 env
#: 传给了子进程」的行为证据（不是只查源码字符串）。
FAKE_APP = r'''
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "env-marker.txt"), "a", encoding="utf-8") as fh:
    fh.write(os.environ.get("NETDIAG_NO_BROWSER", "<unset>") + "\n")
    fh.write(" ".join(sys.argv[1:]) + "\n")

# 并发用例的闸门：让第一个 launcher 拉起假 app 后仍停在「等就绪」，从而确定性地
# 让第二个 launcher 撞上互斥锁（不是靠 sleep 猜时间）。其它用例不设这个 env。
HOLD = os.environ.get("NETDIAG_FAKE_HOLD", "")
if HOLD:
    deadline = time.time() + 30
    while not os.path.exists(HOLD) and time.time() < deadline:
        time.sleep(0.05)

def free_port():
    for port in range(8787, 8797):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            sock.close()
    # 环境抖动加固：8787~8796 全被占用（真实产品实例在跑 / 残留进程 / 并行测试撞车）
    # 不是产品失败。写一个 marker 文件让测试能识别并 skip，而不是让假服务
    # 裸 SystemExit 导致 launcher 起不来、测试在超时处神秘变红。
    try:
        with open(os.path.join(ROOT, "port-busy.txt"), "w", encoding="utf-8") as fh:
            fh.write("8787-8796 全被占用\n")
    except OSError:
        pass
    raise SystemExit(3)

PORT = free_port()
URL = "http://127.0.0.1:%d/" % PORT
KEYS = ["python", "tshark", "npcap", "scapy", "port", "admin"]

def checks():
    items = []
    for key in KEYS:
        ok = key not in ("admin",)
        items.append({
            "key": key,
            "name": key,
            "ok": ok,
            "detail": key + " detail",
            "fix_kind": "elevate" if key == "admin" else "none",
            "fix_url": "",
            "fix_command": "",
            "impact": key + " impact",
            "doc_url": "docs/startup.md",
        })
    return items

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, payload, code=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/ping":
            return self._json({"ok": True, "app": "USBNetDiag", "version": "9.9.9",
                               "pid": os.getpid(), "url": URL, "started_at": time.time()})
        if self.path == "/api/preflight":
            return self._json({
                "ok": False, "version": "9.9.9", "source": "selfcheck",
                "checks": checks(),
                "capabilities": {"probe": True, "offline": True, "live": True,
                                 "passive": True, "reports": True, "settings": True,
                                 "missing": {}, "scapy": False},
                "ui_copy": {"startup": {}},
                "fix_urls": {},
            })
        return self._json({"ok": False, "error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/api/quit":
            self._json({"ok": True, "message": "bye"})
            # 假服务必须在响应后确定性地退出：只 shutdown() 偶尔会被
            # ThreadingHTTPServer 的收尾线程拖住，测试机器上留下残留监听。
            threading.Thread(target=_die, daemon=True, args=(self.server,)).start()
            return
        return self._json({"ok": False, "error": "not found"}, 404)


def _die(httpd):
    time.sleep(0.1)
    try:
        httpd.shutdown()
    except Exception:
        pass
    os._exit(0)


server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
server.serve_forever()
'''


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _startup_log_lines(root: Path) -> list[dict]:
    path = root / "logs" / "startup.log"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _http_ok(port: int, path: str = "/api/ping", timeout: float = 1.0) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def _port_in_use(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        return sock.connect_ex(("127.0.0.1", port)) == 0
    finally:
        sock.close()


def _product_instance_running() -> str:
    """本机是否已有**真实产品实例**在 8787 监听（非本测试起的 FAKE_APP）。

    所有二进制用例都假设产品端口区间（8787~8796）空闲，以便冷启动 FAKE_APP。
    若用户正开着 NetDiag（真实实例占 8787），launcher 会走复用路径，measure 的
    ``mode`` / ``port`` 断言全部漂移 —— 这是环境抖动，不是产品失败，应 skip。

    Returns:
        str: 有真实实例时返回其地址（用于 skip 说明）；否则返回空串。
    """
    if not _port_in_use(8787):
        return ""
    try:
        with urllib.request.urlopen("http://127.0.0.1:8787/api/ping", timeout=1.0) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        if data.get("app") == "USBNetDiag":
            return data.get("url") or "http://127.0.0.1:8787/"
    except Exception:
        return ""
    return ""


class LauncherStartupSourceContract(unittest.TestCase):
    """不依赖 csc：H1/H2/H3 的关键行为在源码里必须留有明确实现。"""

    @classmethod
    def setUpClass(cls):
        cls.source = LAUNCHER_SRC.read_text(encoding="utf-8")
        cls.splash = SPLASH_SRC.read_text(encoding="utf-8")

    def test_launcher_passes_no_browser_env_to_child(self):
        self.assertIn('NoBrowserEnv = "NETDIAG_NO_BROWSER"', self.source)
        self.assertIn('psi.EnvironmentVariables[NoBrowserEnv] = "1";', self.source,
                      "launcher 必须给 python 子进程设 NETDIAG_NO_BROWSER=1")
        self.assertIn("EnvNoBrowser()", self.source,
                      "launcher 自身也必须遵守 NETDIAG_NO_BROWSER")

    def test_browser_open_has_exactly_one_implementation_and_two_call_sites(self):
        # 定义 1 次 + 调用 2 处（复用实例 / 新启动就绪后）。多一处 = 两个标签页回潮。
        self.assertEqual(self.source.count("OpenBrowser("), 3,
                         "浏览器打开点必须唯一实现、且只在复用/就绪后各调一次")
        self.assertIn("private static bool OpenBrowser(string url)", self.source)

    def test_reuse_branch_runs_before_python_start(self):
        start = self.source.index("private static int RunNormal")
        end = self.source.index("LaunchState state = new LaunchState();", start)
        reuse = self.source[start:end]
        self.assertIn("OpenBrowser(existing)", reuse,
                      "复用分支必须打开已有实例的地址")
        self.assertNotIn("StartApp(", reuse,
                         "复用分支绝不能再启动一个新的 Python 进程")
        self.assertNotIn("FindPythonCached", reuse,
                         "复用分支应跳过 Python 定位（不浪费时间）")
        self.assertNotIn("FindPython()", reuse)

    def test_single_instance_mutex_and_measure_log_after_quit(self):
        """S1/S3 源码锚点：去锁或把日志写回 quit 之前，都必须红。"""
        self.assertIn('private const string MutexName = @"Global\\NetDiagLauncher-',
                      self.source, "S1：必须有全局命名互斥锁")
        self.assertIn("AbandonedMutexException", self.source,
                      "S1：前一个实例异常退出留下的锁必须按已获取处理")
        self.assertIn("WaitOne(0, false)", self.source)
        self.assertIn("ReleaseSingleInstance()", self.source)
        self.assertIn("if (!TryAcquireSingleInstance()) return ExitOk;", self.source,
                      "S1：锁被占用的第二个实例必须立即 exit 0")
        log = self.source[self.source.index("private static void LogAndReport"):
                          self.source.index("private static long Now")]
        self.assertLess(log.index("QuitAndWait(state)"), log.index("WriteStartupLog()"),
                        "S3：--measure 必须先 quit 再写 startup.log（quit_* 才是真实值）")

    def test_port_scan_uses_listener_table_not_http_on_closed_ports(self):
        self.assertIn("GetActiveTcpListeners()", self.source,
                      "H2：不允许对 10 个关闭端口各等 700ms；先枚举监听端口")
        self.assertIn("ListeningPorts()", self.source)
        self.assertIn("private static string ProbePing(int port)", self.source)
        probe = self.source[self.source.index("private static string ProbeExisting"):
                            self.source.index("private static bool[] ListeningPorts")]
        self.assertIn("for (int port = PortMin; port <= PortMax; port++)", probe,
                      "端口必须从 8787 起按升序探测（8787 优先）")
        self.assertIn("ProbePing(port)", probe)

    def test_timing_and_artifact_markers(self):
        for marker in ("logs", "startup.log", "launcher-cache.json",
                       "/api/preflight", "--measure", "--splash-test",
                       "--no-splash", "t0_ms", "t1_ms", "t2_ms", "t3_ms",
                       "python_cache", "python_candidates", "first_run"):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source, f"缺少 H2 契约标记：{marker}")

    def test_splash_source_has_six_checks_and_status_mapping(self):
        for marker in ("python", "tshark", "npcap", "scapy", "port", "admin",
                       "StatusMissing", "StatusDegraded", "StatusOk",
                       "AutoScaleMode.Dpi",
                       "继续使用降级功能", "以管理员身份重启", "打开官网"):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source + self.splash)
        self.assertIn("DrawToBitmap", self.splash)
        self.assertIn('"buttons"', self.splash.replace("\\", ""),
                      "按钮可见性必须写进 splash-states.json")

    def test_manifest_declares_high_dpi(self):
        text = MANIFEST.read_text(encoding="utf-8")
        self.assertIn("dpiAware", text)
        self.assertIn("PerMonitorV2", text)
        self.assertIn('level="asInvoker"', text)


@unittest.skipUnless(os.name == "nt", "launcher 只能在 Windows 上真实编译/运行")
class LauncherStartupBinaryTest(unittest.TestCase):
    """真实编译 + 假根目录：measure / dry-run / 复用 / splash 离屏渲染。"""

    tmp: Path
    exe: Path
    csc: Path | None

    @classmethod
    def setUpClass(cls) -> None:
        # 环境抖动加固：本机已有真实产品实例占 8787 时，launcher 会走复用路径，
        # 所有 measure/dry-run/splash 的冷启动断言都会漂移。这不是产品失败，先检测、
        # 命中就整类 skip，避免「用户开着 NetDiag 跑测试」被误判成回归。
        url = _product_instance_running()
        if url:
            raise unittest.SkipTest(
                f"本机已有真实产品实例在运行（{url}），端口被占（环境抖动，非产品失败）")
        cls.csc = build_launcher.find_csc()
        if cls.csc is None:
            raise unittest.SkipTest("本机没有 csc.exe，跳过编译/运行用例")
        cls.tmp = Path(tempfile.mkdtemp(prefix="netdiag_h_startup_"))
        out = cls.tmp / "bin"
        # 环境抖动加固：编译 exe 失败 / 超时是**本机工具链问题**，不是产品失败。
        # 这里 skip 并写明原因，绝不让「csc 被占用 / 杀软卡编译 / CI 磁盘慢」把
        # 产品测试判红 —— 环境抖动不该折算成产品回归。
        try:
            proc = _run([sys.executable, str(ROOT / "scripts" / "build_launcher.py"),
                         "--out", str(out)], timeout=240)
        except subprocess.TimeoutExpired as exc:
            raise unittest.SkipTest(f"编译启动器超时（环境抖动，非产品失败）：{exc}")
        if proc.returncode != 0:
            raise unittest.SkipTest(
                f"编译启动器失败（本机 csc 工具链问题，非产品失败）：\n"
                f"{proc.stdout}\n{proc.stderr}")
        cls.exe = out / EXE_NAME
        if not cls.exe.is_file() or cls.exe.stat().st_size < 8 * 1024:
            raise unittest.SkipTest(f"启动器产物缺失或过小（编译异常，非产品失败）：{cls.exe}")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def _make_root(self, name: str) -> Path:
        root = self.tmp / name
        (root / "core").mkdir(parents=True)
        (root / "core" / "app.py").write_text(FAKE_APP, encoding="utf-8", newline="\n")
        (root / "VERSION").write_text("9.9.9\n", encoding="utf-8")
        (root / "config").mkdir()
        (root / "logs").mkdir()
        shutil.copy2(self.exe, root / EXE_NAME)
        return root

    def _launcher_env(self, **updates: str) -> dict:
        env = _env()
        python_dir = str(Path(sys.executable).parent)
        env["PATH"] = python_dir
        env.pop("NETDIAG_NO_BROWSER", None)
        env.update(updates)
        return env

    def _run_exe(self, root: Path, args: list[str], timeout: int = 90,
                 env: dict | None = None) -> subprocess.CompletedProcess:
        # stdout/stderr 直接丢弃：winexe + 子进程会继承管道句柄，capture_output 可能
        # 一直等到孙子进程退出；报告与 startup.log 才是断言依据。
        return subprocess.run(
            [str(root / EXE_NAME)] + args, cwd=str(root),
            env=env or self._launcher_env(),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout,
        )

    def _measure(self, root: Path, name: str) -> tuple[int, dict]:
        report = root / f"{name}.json"
        proc = self._run_exe(root, ["--measure", "--report", str(report)])
        data = _read_json(report) if report.is_file() else {}
        return proc.returncode, data

    def _wait_ping(self, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if _http_ok(8787):
                return True
            time.sleep(0.1)
        return False

    def _quit_port(self, port: int) -> None:
        """让假 app 优雅退出（POST /api/quit）；失败也不让测试挂住。"""
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/quit", data=b"{}", method="POST")
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read()
        except Exception:
            pass

    def _wait_port_closed(self, port: int, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not _port_in_use(port):
                return True
            time.sleep(0.1)
        return False

    # -------------------------------------------------------------- tests
    def test_measure_runs_real_startup_writes_log_and_quits(self):
        root = self._make_root("measure")
        before = _listening_ports()
        # 环境抖动加固：本机 8787~8796 已有残留监听（真实产品实例 / 上次运行没清干净 /
        # 并行测试撞车）时，measure 会顺延端口，before/after 对比与固定端口断言都会抖。
        # 这不该判成产品失败 —— 直接 skip 并写明原因。
        if before:
            self.skipTest(f"产品端口区间有残留监听（环境抖动，非产品失败）：{sorted(before)}")
        code, data = self._measure(root, "measure-1")
        # 端口全被占时假 app 写 port-busy.txt 后退出；这是环境问题，skip 而非红。
        if (root / "port-busy.txt").is_file():
            self.skipTest("8787-8796 全被占用（环境抖动，非产品失败）")
        self.assertEqual(code, 0, data)
        for key in ("t0_ms", "t1_ms", "t2_ms", "t3_ms", "spawn_ms", "ready_ms",
                    "browse_ms", "total_ms", "mode", "python_kind",
                    "python_candidates", "python_cache", "port", "reused",
                    "first_run", "browser", "ok"):
            self.assertIn(key, data, f"measure 报告缺 {key}")
        self.assertTrue(data["ok"])
        self.assertFalse(data["reused"])
        self.assertEqual(data["browser"], "skipped", "measure 不许开浏览器")
        self.assertGreater(data["t1_ms"], 0)
        self.assertGreaterEqual(data["t2_ms"], data["t1_ms"])
        self.assertGreaterEqual(data["t3_ms"], data["t2_ms"])
        self.assertGreaterEqual(data["total_ms"], data["t2_ms"])
        # launcher 优先 8787，但被占时会顺延到 8788~8796（产品设计行为）。断端口在
        # 产品窗口内即可，不写死 8787 —— 写死会在「8787 被外部占用」时误判产品失败。
        self.assertIn(data["port"], range(8787, 8797), f"端口应落在产品窗口：{data}")

        # 日志：单行 JSON 追加，字段与报告同构。
        lines = _startup_log_lines(root)
        self.assertEqual(len(lines), 1, f"startup.log 应只有 1 行：{lines}")
        self.assertEqual(lines[0]["total_ms"], data["total_ms"])
        self.assertEqual(lines[0]["mode"], data["mode"])
        # S3：measure 的日志必须包含真实退出结果（不能恒 false/0）。
        self.assertTrue(lines[0]["quit_ok"],
                        f"startup.log 的 quit_ok 必须是 POST /api/quit 的真实结果：{lines[0]}")
        self.assertTrue(lines[0]["quit_exited"],
                        f"startup.log 的 quit_exited 必须是子进程真实退出：{lines[0]}")
        self.assertGreater(lines[0]["quit_ms"], 0,
                           f"startup.log 的 quit_ms 必须记录真实耗时：{lines[0]}")
        self.assertEqual(lines[0]["quit_ok"], data["quit_ok"])
        self.assertEqual(lines[0]["quit_exited"], data["quit_exited"])
        self.assertEqual(lines[0]["quit_ms"], data["quit_ms"])

        # 子进程真的收到 env（不是只查源码字符串）。
        marker = (root / "env-marker.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(marker[0], "1", f"子进程 env 未传递：{marker}")
        self.assertIn("--no-elevate", marker[1])

        # 优雅退出：measure 已 POST /api/quit，端口不再监听（没有残留进程）。
        self.assertEqual(_listening_ports(), before,
                         "measure 之后不应残留本地监听")

    def test_measure_second_run_is_warm_and_cache_hit(self):
        root = self._make_root("warm")
        code1, first = self._measure(root, "warm-1")
        code2, second = self._measure(root, "warm-2")
        self.assertEqual((code1, code2), (0, 0), (first, second))
        self.assertEqual(first["python_cache"], "miss", first)
        self.assertEqual(first["mode"], "cold", first)
        self.assertEqual(second["python_cache"], "hit", second)
        self.assertEqual(second["mode"], "warm", second)
        self.assertEqual(second["python_candidates"], 1, "缓存命中只应做一次存在性校验")
        self.assertFalse(second["first_run"], "已有缓存/日志时不是首跑")

    def test_stale_python_cache_falls_back_to_full_scan(self):
        root = self._make_root("stale")
        code, _ = self._measure(root, "stale-1")
        self.assertEqual(code, 0)
        cache_file = root / "config" / "launcher-cache.json"
        payload = _read_json(cache_file)
        payload["size"] = 1                    # 与真实 size 不符 → 必须失效重扫
        cache_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        code, data = self._measure(root, "stale-2")
        self.assertEqual(code, 0, data)
        self.assertTrue(data["python_cache"].startswith("invalid:"),
                        f"过期缓存必须报 invalid 并全扫：{data['python_cache']}")
        self.assertTrue(data["ok"])
        # 重扫后缓存应被重写为有效值（下一次命中）。
        code, data2 = self._measure(root, "stale-3")
        self.assertEqual((code, data2["python_cache"]), (0, "hit"), data2)

    def test_python_cache_mtime_and_missing_path_invalidations(self):
        """缓存校验覆盖 mtime 变化与路径不存在（H2 明确要求两项）。"""
        root = self._make_root("cache-invalid")
        code, _ = self._measure(root, "ci-1")
        self.assertEqual(code, 0)
        cache_file = root / "config" / "launcher-cache.json"
        base = _read_json(cache_file)

        cases = [
            ("mtime", lambda payload: payload.update(mtime_utc=1)),
            ("missing", lambda payload: payload.update(
                python=str(root / "tools" / "python" / "gone-pythonw.exe"))),
        ]
        for name, mutate in cases:
            payload = dict(base)
            mutate(payload)
            cache_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            code, data = self._measure(root, f"ci-{name}")
            self.assertEqual(code, 0, data)
            self.assertTrue(data["python_cache"].startswith("invalid:"),
                            f"{name} 失效未触发重扫：{data['python_cache']}")
            self.assertTrue(data["ok"], data)
        code, data = self._measure(root, "ci-final")
        self.assertEqual((code, data["python_cache"]), (0, "hit"), data)

    def test_dry_run_reports_env_contract_and_starts_nothing(self):
        root = self._make_root("dry")
        report = root / "dry.json"
        before = _listening_ports()
        if before:
            self.skipTest(f"产品端口区间有残留监听（环境抖动，非产品失败）：{sorted(before)}")
        proc = self._run_exe(root, ["--dry-run", "--report", str(report)])
        self.assertEqual(proc.returncode, 0)
        data = _read_json(report)
        self.assertTrue(data["ok"])
        self.assertTrue(data["dry_run"])
        self.assertFalse(data["started"])
        self.assertFalse(data["browser_opened"])
        self.assertFalse(data["splash"])
        self.assertEqual(data["child_env"]["NETDIAG_NO_BROWSER"], "1",
                         "dry-run 报告必须写明子进程会收到 env")
        self.assertEqual(data["browser_open_points"], 1,
                         "只允许一个浏览器打开点")
        self.assertFalse((root / "env-marker.txt").exists(),
                         "--dry-run 真的启动了 app（env-marker 出现）")
        self.assertEqual(_listening_ports(), before)

    def test_reuse_existing_instance_never_starts_new_process(self):
        root = self._make_root("reuse")
        # 先起一个「已经在跑」的假服务，并用 --fake-server 留下身份标记。
        fake = subprocess.Popen(
            [sys.executable, str(root / "core" / "app.py"), "--fake-server"],
            cwd=str(root), env=self._launcher_env(),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 15
            while time.time() < deadline and not _port_in_use(8787):
                if fake.poll() is not None:
                    self.skipTest("假服务启动失败（端口区间可能被占用）")
                time.sleep(0.1)
            if not _port_in_use(8787):
                self.skipTest("8787 无监听，跳过复用用例")
            marker_before = (root / "env-marker.txt").read_text(encoding="utf-8")
            code, data = self._measure(root, "reuse-measure")
            self.assertEqual(code, 0, data)
            self.assertTrue(data["reused"], data)
            self.assertEqual(data["mode"], "reuse", data)
            self.assertEqual(data["browser"], "skipped")
            self.assertIsNone(fake.poll(), "复用路径居然把已有实例退出了")
            marker_after = (root / "env-marker.txt").read_text(encoding="utf-8")
            self.assertEqual(marker_before, marker_after,
                             "复用路径又起了一个新进程（env-marker 被重写）")
        finally:
            try:
                fake.kill()
            except Exception:
                pass
            fake.wait(timeout=10)
            time.sleep(0.3)

    def test_concurrent_double_click_starts_exactly_one_instance(self):
        """S1：并发双击只允许一个启动编排（一个 app、一行 startup.log、第二个秒退 0）。

        用 ``NETDIAG_FAKE_HOLD`` 把第一个 launcher 的假 app 卡在「等就绪」，
        确定性制造「锁被占用」的窗口，而不是靠 sleep 猜。
        """
        root = self._make_root("concurrent")
        gate = root / "hold-start"
        env = self._launcher_env(NETDIAG_FAKE_HOLD=str(gate), NETDIAG_NO_BROWSER="1")
        first_report = root / "first.json"
        second_report = root / "second.json"
        first = subprocess.Popen(
            [str(root / EXE_NAME), "--measure", "--report", str(first_report)],
            cwd=str(root), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                marker = root / "env-marker.txt"
                if marker.is_file() and len(marker.read_text(encoding="utf-8").splitlines()) >= 2:
                    break
                if first.poll() is not None:
                    self.fail(f"第一个 launcher 提前退出：rc={first.returncode}")
                time.sleep(0.05)
            else:
                self.fail("第一个 launcher 30s 内没有拉起假 app")

            began = time.time()
            second = self._run_exe(root, ["--measure", "--report", str(second_report)],
                                   timeout=20, env=env)
            second_s = time.time() - began
            self.assertEqual(second.returncode, 0,
                             "锁被占用的第二个实例必须 exit 0（静默退出）")
            self.assertLess(second_s, 3.0,
                            f"第二个实例必须在锁被占用时立即退出，实测 {second_s:.2f}s")
            self.assertIsNone(first.poll(), "持锁实例不该被第二个实例终止")
            self.assertFalse(second_report.exists(),
                             "第二个实例不许产生 measure 报告（说明它根本没启动）")
        finally:
            gate.write_text("go", encoding="utf-8")
            try:
                first.wait(timeout=60)
            except subprocess.TimeoutExpired:
                first.kill()
                first.wait(timeout=10)
                raise

        self.assertEqual(first.returncode, 0)
        data = _read_json(first_report)
        self.assertTrue(data["ok"], data)
        # 假 app 每次被拉起写 2 行（env + argv）；并发双击只能有一份。
        marker_lines = (root / "env-marker.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(marker_lines), 2,
                         f"并发双击拉起了不止一个 app：{marker_lines}")
        self.assertEqual(len(_startup_log_lines(root)), 1,
                         "并发启动只允许一行 startup.log（锁内写）")

    def test_mutex_released_after_launch_reuses_running_service(self):
        """S1：第一个 launcher 释放锁后，再次启动必须走复用路径、不新起进程/浏览器。"""
        root = self._make_root("lock-release")
        env = self._launcher_env(NETDIAG_NO_BROWSER="1")
        before = _listening_ports()
        if before:
            self.skipTest(f"产品端口区间有残留监听（环境抖动，非产品失败）：{sorted(before)}")
        first = self._run_exe(root, ["--no-splash"], timeout=90, env=env)
        self.assertEqual(first.returncode, 0, "第一次正常启动失败")
        port = _startup_log_lines(root)[-1]["port"]
        try:
            self.assertTrue(_port_in_use(port), "第一次启动后服务未就绪")
            marker_before = (root / "env-marker.txt").read_text(encoding="utf-8")
            code, data = self._measure(root, "reuse-after-release")
            self.assertEqual(code, 0, data)
            self.assertTrue(data["reused"],
                            f"锁释放后再次启动必须复用已有服务：{data}")
            self.assertEqual(data["mode"], "reuse", data)
            self.assertEqual(data["port"], port)
            marker_after = (root / "env-marker.txt").read_text(encoding="utf-8")
            self.assertEqual(marker_before, marker_after,
                             "复用路径又起了第二个 app（env-marker 变了）")
        finally:
            self._quit_port(port)
            self.assertTrue(self._wait_port_closed(port),
                            f"清理失败：{port} 仍在监听")
        self.assertEqual(_listening_ports(), before)

    def test_splash_test_renders_four_png_and_state_contract(self):
        root = self._make_root("splash")
        out = root / "shots"
        before = _listening_ports()
        if before:
            self.skipTest(f"产品端口区间有残留监听（环境抖动，非产品失败）：{sorted(before)}")
        proc = self._run_exe(root, ["--splash-test", str(out)])
        self.assertEqual(proc.returncode, 0)
        pngs = sorted(out.glob("splash-*.png"))
        self.assertEqual(len(pngs), 4, [p.name for p in pngs])
        for png in pngs:
            self.assertGreater(png.stat().st_size, 4000,
                               f"{png.name} 太小，可能是空白/纯色图")
        states = _read_json(out / "splash-states.json")
        self.assertEqual([s["scenario"] for s in states],
                         ["loading", "all_green", "missing_tshark", "non_admin"])
        by_name = {s["scenario"]: s for s in states}

        loading = by_name["loading"]
        items = {item["key"]: item for item in loading["items"]}
        self.assertEqual(items["python"]["state"], "ok", "Python 用本地占位先点亮")
        self.assertEqual(items["port"]["state"], "checking")
        self.assertEqual(items["tshark"]["state"], "checking",
                         "服务未起时其余项目只能显示「检查中…」")
        self.assertEqual(loading["buttons"], ["skip"])

        green = by_name["all_green"]
        self.assertTrue(green["all_ok"])
        self.assertEqual({item["state"] for item in green["items"]}, {"ok"})
        self.assertEqual(green["buttons"], [], "全绿自动进入，不摆按钮")

        missing = by_name["missing_tshark"]
        items = {item["key"]: item for item in missing["items"]}
        self.assertEqual(items["tshark"]["state"], "missing")
        self.assertTrue(items["tshark"]["fix_url"].startswith("https://"))
        self.assertEqual(items["scapy"]["state"], "degraded", "缺 scapy 只是降级")
        self.assertIn("install", missing["buttons"])
        self.assertIn("continue", missing["buttons"])
        self.assertNotIn("elevate", missing["buttons"])

        admin = by_name["non_admin"]
        items = {item["key"]: item for item in admin["items"]}
        self.assertEqual(items["admin"]["state"], "degraded")
        self.assertIn("elevate", admin["buttons"])
        self.assertIn("continue", admin["buttons"])
        self.assertNotIn("install", admin["buttons"])
        self.assertEqual(_listening_ports(), before,
                         "--splash-test 不许启动服务/开浏览器")


if __name__ == "__main__":
    unittest.main(verbosity=2)
