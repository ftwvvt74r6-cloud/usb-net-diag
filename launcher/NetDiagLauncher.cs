// ============================================================================
// NetDiag · 网络矩阵 —— Windows 图形启动器（系统自带 .NET Framework，无第三方依赖）
//
// 为什么需要它：
//   1. .vbs 不支持右键「以管理员身份运行 / 以其他用户运行」，也容易被脚本宿主
//      策略拦下。exe 是 Windows 原生入口，右键两项是系统能力，不需要注册表。
//   2. 启动慢的主因之一是旧 core/app.py 启动即请求 UAC。本启动器以 asInvoker
//      运行，双击**不提权**；需要管理员的功能由界面按需请求。
//   3. pythonw 起来后没有提示，用户不知道在等什么。这里用 WinForms 等待窗口
//      显示六项检查进度，就绪后再开浏览器；失败给可操作出口。
//
// H1 单次打开浏览器（本文件的硬约束）：
//   * 启动器是**唯一**打开浏览器的地方；给子进程设 NETDIAG_NO_BROWSER=1，
//     app.py / server.py 就不会再各开一个标签页。
//   * launcher 自己遵守 NETDIAG_NO_BROWSER=1（或 --no-browser）：测量/测试安全。
//   * 已有实例 → 直接复用，**绝不**再起第二个 Python 进程。
//   * 并发双击 → 命名互斥锁只放行一个启动编排；第二个立即退出（exit 0），
//     不显示 splash、不新起进程、不开浏览器（S1）。
//
// H2 启动计时：t0 Main 进入 → t1 Python spawn → t2 /api/ping 首次成功 →
//   t3 打开浏览器（env=1 时为跳过），单行 JSON 追加到 logs/startup.log；
//   --measure 走真实启动、等就绪、POST /api/quit 后写日志/报告再退出
//   （S3：quit 结果必须在写 startup.log 之前拿到）。
//
// 只做：探测已有实例 → 定位 Python（带缓存）→ 隐藏启动 core\app.py → 等就绪 →
//       （可选 splash）→ 打开浏览器一次。
// 不做：注册表、开机自启、访问 127.0.0.1 以外网络、安装 Python、启动时提权。
// 编译：scripts/build_launcher.py（csc /target:winexe，+ SplashForm.cs）。
// 退出码：0 成功 / 2 找不到 Python / 3 等待超时 / 4 启动失败。
// ============================================================================

using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace NetDiag
{
    internal static class Launcher
    {
        // 与 core/server.py 的端口区间、轮询节奏保持一致。写死常量而不是读配置：
        // 启动器要在 Python 起来之前工作，此时读不到 app-config.json。
        private const int PortMin = 8787;
        private const int PortMax = 8796;

        //: 服务写下的**真实**监听端口（JSON）。8787~8796 全被占时服务会绑端口 0 由系统
        //: 分配，那种实例按固定区间永远扫不到 —— 先读这个文件才知道该去敲哪个端口。
        private const string PortFileRel = @"logs\netdiag.port";
        private const int PollIntervalMs = 200;
        private const int ReadyTimeoutMs = 30000;
        private const int PingTimeoutMs = 700;
        private const int PyProbeTimeoutMs = 5000;
        private const int PreflightTimeoutMs = 20000;

        private const int ExitOk = 0;
        private const int ExitNoPython = 2;
        private const int ExitWaitTimeout = 3;
        private const int ExitLaunchFailed = 4;

        private const string Caption = "NetDiag · 网络矩阵";
        private const string AppMarker = "NetDiag";
        private const string PythonDownloadUrl = "https://www.python.org/downloads/windows/";

        //: 浏览器打开权归属的环境变量（与 core/app.py 的 NO_BROWSER_ENV 同一个名字）。
        private const string NoBrowserEnv = "NETDIAG_NO_BROWSER";

        //: 启动编排期的单实例锁名（S1）。Global 命名空间：跨会话/跨用户也只放行一个，
        //: 因为端口 8787~8796 是整机资源。产品名进锁名，避免和其它程序撞名。
        private const string MutexName = @"Global\NetDiagLauncher-NetDiag";

        /// <summary>持锁期间要防止 Mutex 被 GC 回收，所以放静态字段；未持有时为 null。</summary>
        private static Mutex _instanceLock;
        private static bool _instanceLockOwned;

        /// <summary>进程启动即开始走的单调时钟；t0 就是它第一次被读到的时刻。</summary>
        private static readonly Stopwatch Clock = Stopwatch.StartNew();

        private static string _root = "";
        private static bool _noBrowser;      // launcher 自己不开浏览器（env 或 --no-browser）
        private static bool _noSplash;       // --no-splash / --measure / --dry-run
        private static bool _measureMode;    // --measure：真实启动 + 计时 + 优雅退出
        private static StartupMetrics _metrics = new StartupMetrics();

        [STAThread]
        private static int Main(string[] args)
        {
            // t0：Main 进入。之后所有时间点都相对这里，日志里 t0_ms 恒为 0。
            long ignored = Clock.ElapsedMilliseconds;
            GC.KeepAlive(ignored);

            bool dryRun = false;
            string reportPath = null;
            string splashTestDir = null;

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (string.Equals(arg, "--dry-run", StringComparison.OrdinalIgnoreCase)) dryRun = true;
                else if (string.Equals(arg, "--measure", StringComparison.OrdinalIgnoreCase)) _measureMode = true;
                else if (string.Equals(arg, "--no-browser", StringComparison.OrdinalIgnoreCase)) _noBrowser = true;
                else if (string.Equals(arg, "--no-splash", StringComparison.OrdinalIgnoreCase)) _noSplash = true;
                else if (string.Equals(arg, "--report", StringComparison.OrdinalIgnoreCase)
                         && i + 1 < args.Length) reportPath = args[++i];
                else if (string.Equals(arg, "--splash-test", StringComparison.OrdinalIgnoreCase)
                         && i + 1 < args.Length) splashTestDir = args[++i];
            }

            // 根目录 = exe 所在目录。发布包里 NetDiag.exe 与 core\ 同级；双击时
            // 当前工作目录不可靠，所以不用 cwd。
            _root = ResolveRoot();
            _metrics = new StartupMetrics();

            // 先建 WinForms 视觉样式再建任何窗口（--splash-test 的截图也走这里，
            // 保证证据和真实运行时同一套主题）。
            try
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
            }
            catch (Exception) { }

            if (splashTestDir != null)
            {
                _noSplash = true;
                return RunSplashTest(splashTestDir);
            }

            // launcher 自身也遵守 env：NETDIAG_NO_BROWSER=1 时只启动服务、不开浏览器，
            // 供自动化测量与 CI 测试安全使用。
            _noBrowser = _noBrowser || EnvNoBrowser();
            _metrics.NoBrowser = _noBrowser;

            if (dryRun)
            {
                _noSplash = true;
                return RunDryRun(reportPath);
            }
            if (_measureMode)
            {
                // 测量模式：不显示 splash、不开浏览器，完整走真实启动后优雅退出。
                _noSplash = true;
                _noBrowser = true;
                _metrics.NoBrowser = true;
                _metrics.Measure = true;
            }

            // S1：并发双击只放行一个 launcher 做启动编排（探测/spawn/就绪/浏览器/日志）。
            // 锁被占用 = 另一个 launcher 正在启动：立即退出 0，不显示 splash、不
            // 启动 python、不开浏览器（服务与标签页都由持锁实例负责）。
            if (!TryAcquireSingleInstance()) return ExitOk;
            try
            {
                int code;
                try { code = RunNormal(reportPath); }
                catch (Exception ex)
                {
                    _metrics.Error = ex.GetType().Name + ": " + ex.Message;
                    WriteStartupLog();
                    ShowError("启动器内部错误：" + ex.GetType().Name + ": " + ex.Message);
                    code = ExitLaunchFailed;
                }
                return code;
            }
            finally
            {
                ReleaseSingleInstance();
            }
        }

        // ------------------------------------------------------------ 主流程
        private static string ResolveRoot()
        {
            try
            {
                string dir = AppDomain.CurrentDomain.BaseDirectory;
                if (!string.IsNullOrEmpty(dir)) return dir.TrimEnd('\\', '/');
            }
            catch (Exception) { }
            try { return Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName); }
            catch (Exception) { return ""; }
        }

        private static bool EnvNoBrowser()
        {
            try
            {
                string raw = (Environment.GetEnvironmentVariable(NoBrowserEnv) ?? "").Trim().ToLowerInvariant();
                return raw == "1" || raw == "true" || raw == "yes" || raw == "on";
            }
            catch (Exception) { return false; }
        }

        // --------------------------------------------------- 单实例准入（S1）
        /// <summary>
        /// 尝试取启动器单实例锁；false = 另一个 launcher 正在启动，调用方应立即 exit 0。
        ///
        /// 为什么需要：两个 launcher 同时启动会各自 spawn 一个 pythonw，抢到 8787/8788，
        /// 各开一次浏览器（两个标签页），并并发追加 startup.log（丢行）。锁覆盖整个
        /// **启动编排**（探测→spawn→就绪→浏览器→写日志），不覆盖服务运行期：服务活着
        /// 时靠 /api/ping 复用，本来就不会起第二个进程。
        ///
        /// Returns:
        /// bool: true = 已持锁（含上一个实例异常退出留下的 AbandonedMutex）；
        ///       false = 锁被另一个存活实例持有，本次必须静默退出。
        /// </summary>
        private static bool TryAcquireSingleInstance()
        {
            try
            {
                Mutex mutex = new Mutex(false, MutexName);
                try
                {
                    if (!mutex.WaitOne(0, false))
                    {
                        mutex.Dispose();
                        return false;
                    }
                }
                catch (AbandonedMutexException)
                {
                    // 上一个实例在持锁期间崩溃/被强杀：WaitOne 已把所有权交给本进程，
                    // 按成功处理；否则一次崩溃会永久挡住后续双击。
                }
                _instanceLock = mutex;
                _instanceLockOwned = true;
                return true;
            }
            catch (Exception)
            {
                // 极老系统 / 受限会话创建命名互斥锁失败：退化为不互斥。
                // 宁可极端情况下重复启动，也不能让用户双击没反应。
                return true;
            }
        }

        /// <summary>释放启动编排锁；未持有时是空操作（含创建失败退化的路径）。</summary>
        private static void ReleaseSingleInstance()
        {
            try
            {
                if (_instanceLockOwned && _instanceLock != null) _instanceLock.ReleaseMutex();
            }
            catch (Exception) { }
            finally
            {
                _instanceLockOwned = false;
                try { if (_instanceLock != null) _instanceLock.Dispose(); }
                catch (Exception) { }
                _instanceLock = null;
            }
        }

        private static int RunNormal(string reportPath)
        {
            _metrics.Action = _measureMode ? "measure" : "launch";
            _metrics.FirstRun = IsFirstRun();

            // 双保险：已有实例就直接开浏览器，不再起第二个进程抢端口。
            // 8787 优先（最常见），未命中再 8788~8796；命中即停，不做无谓全扫。
            string existing = ProbeExisting();
            if (!string.IsNullOrEmpty(existing))
            {
                _metrics.Reused = true;
                _metrics.Mode = "reuse";
                _metrics.T2 = Now();
                _metrics.Port = ParsePort(existing);
                SplashForm reuseSplash = null;
                if (!_noSplash && !_measureMode)
                {
                    reuseSplash = new SplashForm(false, Now());
                    reuseSplash.ShowReuse(existing);
                    reuseSplash.Show();
                    Pump(120);
                }
                bool reuseOpened = OpenBrowser(existing);
                _metrics.T3 = Now();
                _metrics.Browser = _noBrowser ? "skipped" : (reuseOpened ? "opened" : "failed");
                _metrics.Ok = _noBrowser || reuseOpened;
                if (!_noBrowser && !reuseOpened)
                    ShowError("检测到已运行的 NetDiag，但打开浏览器失败。\n\n请手动访问：" + existing);                if (reuseSplash != null)
                {
                    FadeOutAndClose(reuseSplash);
                    reuseSplash.Dispose();
                }
                LogAndReport(reportPath, null);
                return _metrics.Ok ? ExitOk : ExitLaunchFailed;
            }

            LaunchState state = new LaunchState();
            SplashForm splash = null;
            if (!_noSplash)
            {
                splash = new SplashForm(!HasStartupArtifacts(), Now());
                splash.Show();
                Pump(30);
            }

            Thread worker = new Thread(delegate() { LaunchWorker(state, splash); });
            worker.IsBackground = true;
            worker.Start();

            if (splash == null)
            {
                worker.Join();
            }
            else
            {
                // 主线程只做消息泵 + 用户选择；耗时工作全部在 worker 里。
                while (state.Working
                       || (state.NeedUserChoice && !state.AllowProceed && !splash.ProceedRequested))
                {
                    Application.DoEvents();
                    if (splash.CloseRequested) break;
                    if (!state.Working && splash.ElevateRequested)
                    {
                        splash.ElevateRequested = false;
                        HandleElevate(splash, state);
                    }
                    Thread.Sleep(20);
                }
            }

            if (splash == null)
            {
                if (!string.IsNullOrEmpty(state.Fatal))
                {
                    _metrics.Error = state.FatalCode;
                    _metrics.Ok = false;
                    LogAndReport(reportPath, state);
                    // 测量/自动化绝不能弹会阻塞的消息框（无桌面时会永久挂住）。
                    if (!_measureMode) ShowError(state.Fatal);
                    return state.ExitCode;
                }
                return FinishAndOpen(state, reportPath, null);
            }

            if (!string.IsNullOrEmpty(state.Fatal))
            {
                splash.SetFatal(state.Fatal, state.InstallUrl, state.InstallLabel);
                while (!splash.CloseRequested)
                {
                    Application.DoEvents();
                    Thread.Sleep(20);
                }
                FadeOutAndClose(splash);
                splash.Dispose();
                _metrics.Error = state.FatalCode;
                _metrics.Ok = false;
                LogAndReport(reportPath, state);
                return state.ExitCode;
            }

            int result = FinishAndOpen(state, reportPath, splash);
            FadeOutAndClose(splash);
            splash.Dispose();
            return result;
        }

        /// <summary>就绪后收尾：开一次浏览器（受 env 控制）→ 记录 t3 → 写日志/报告。</summary>
        private static int FinishAndOpen(LaunchState state, string reportPath, SplashForm splash)
        {
            if (splash != null) splash.SetSubtitle("正在打开界面…");
            bool opened = OpenBrowser(state.Url);
            _metrics.T3 = Now();
            _metrics.Browser = _noBrowser ? "skipped" : (opened ? "opened" : "failed");
            _metrics.Ok = _noBrowser || opened;
            if (!_noBrowser && !opened)
                ShowError("本地服务已就绪，但打开浏览器失败。\n\n请手动访问：" + state.Url);
            LogAndReport(reportPath, state);
            return _metrics.Ok ? ExitOk : ExitLaunchFailed;
        }

        /// <summary>后台启动流程：定位 Python（缓存）→ spawn → 等 /api/ping → 取 preflight。</summary>
        private static void LaunchWorker(LaunchState state, SplashForm splash)
        {
            try
            {
                Post(splash, delegate { splash.SetSubtitle("正在定位 Python…"); });
                PythonLookup lookup = FindPythonCached();
                state.Lookup = lookup;
                _metrics.Cache = lookup.Cache;
                _metrics.Candidates = lookup.Candidates;
                _metrics.PythonKind = lookup.Python != null ? lookup.Python.Kind : "";
                // 缓存命中 = 热启动；首跑/缓存失效 = 冷启动（写进 startup.log 便于对比）。
                _metrics.Mode = lookup.Cache == "hit" ? "warm" : "cold";

                if (lookup.Python == null)
                {
                    state.Fatal = NoPythonMessage();
                    state.FatalCode = "no-python";
                    state.InstallUrl = PythonDownloadUrl;
                    state.InstallLabel = "打开 Python 官网";
                    state.ExitCode = ExitNoPython;
                    Post(splash, delegate
                    {
                        splash.SetItem("python", CheckState.Missing, "没有可用的 Python 3.11+");
                        splash.SetSubtitle("没有找到可用的 Python");
                    });
                    return;
                }
                PythonCandidate python = lookup.Python;
                Post(splash, delegate
                {
                    splash.SetItem("python", CheckState.Ok, "已找到 " + python.Kind);
                    splash.SetSubtitle("正在启动本地服务…");
                });

                string script = Path.Combine(_root, "core", "app.py");
                if (!File.Exists(script))
                {
                    state.Fatal = "项目目录不完整：找不到\n" + script + "\n\n"
                                  + "请确认 NetDiag.exe 与 core\\ 目录在同一层（解压时不要只拖 exe 出来）。";
                    state.FatalCode = "missing-app";
                    state.ExitCode = ExitLaunchFailed;
                    return;
                }

                Process proc = StartApp(python, script);
                if (proc == null)
                {
                    state.Fatal = "无法启动 core\\app.py。\n\n请检查 Python 是否可用："
                                  + python.Exe + "\n并查看日志："
                                  + Path.Combine(_root, "logs") + "\\app-*.log";
                    state.FatalCode = "spawn-failed";
                    state.ExitCode = ExitLaunchFailed;
                    return;
                }
                state.Proc = proc;
                _metrics.T1 = Now();

                int failureExit, pythonExit;
                string url = WaitForReady(proc, out failureExit, out pythonExit, splash);
                if (string.IsNullOrEmpty(url))
                {
                    state.ExitCode = failureExit;
                    if (failureExit == ExitLaunchFailed)
                    {
                        state.Fatal = "启动失败：Python 进程已退出（退出码 "
                                      + pythonExit.ToString(CultureInfo.InvariantCulture) + "）。\n\n"
                                      + "请查看日志：" + Path.Combine(_root, "logs") + "\\app-*.log\n\n"
                                      + "常见原因：Python 版本低于 3.11、缺少项目文件、依赖导入失败。";
                        state.FatalCode = "python-exited";
                    }
                    else
                    {
                        state.Fatal = "启动超时：30 秒内本地服务没有就绪。\n\n"
                                      + "请查看日志：" + Path.Combine(_root, "logs") + "\\app-*.log\n\n"
                                      + "常见原因：\n  - Npcap / 安全软件拦截了 Python\n"
                                      + "  - Python 缺少运行所需的模块\n"
                                      + "  - 本机端口一个都绑不上（罕见，重启电脑后再试）";
                        state.FatalCode = "wait-timeout";
                    }
                    return;
                }

                state.Url = url;
                _metrics.T2 = Now();
                _metrics.Port = ParsePort(url);
                Post(splash, delegate
                {
                    splash.SetItem("port", CheckState.Ok, "本地服务已就绪：" + url);
                    splash.SetSubtitle("正在读取环境检查结果…");
                });

                if (_measureMode)
                {
                    state.AllowProceed = true;
                    return;
                }
                // 用户已经点了「跳过检查」/ESC：不再等 preflight，直接进界面，
                // 检查结果由 UI 首屏自检显示。
                if (splash != null && splash.ProceedRequested)
                {
                    state.AllowProceed = true;
                    return;
                }

                PreflightData data = FetchPreflight(url, PreflightTimeoutMs);
                if (data == null || data.Items.Count == 0)
                {
                    Post(splash, delegate
                    {
                        splash.SetSubtitle("环境检查超时，可直接进入界面");
                        splash.SetMessage("本地服务已就绪；检查结果会在界面首屏显示，不影响继续使用。");
                    });
                    state.AllowProceed = true;
                    return;
                }
                state.Preflight = data;
                Post(splash, delegate { splash.ApplyPreflight(data); });
                if (data.Ok) state.AllowProceed = true;
                else state.NeedUserChoice = true;
            }
            catch (Exception ex)
            {
                state.Fatal = "启动器内部错误：" + ex.GetType().Name + ": " + ex.Message
                              + "\n\n请查看日志目录：" + Path.Combine(_root, "logs");
                state.FatalCode = "exception";
                state.ExitCode = ExitLaunchFailed;
            }
            finally
            {
                state.Working = false;
            }
        }

        /// <summary>用户点「以管理员身份重启」：复用 /api/elevate，等新实例后重读 preflight。</summary>
        private static void HandleElevate(SplashForm splash, LaunchState state)
        {
            splash.SetMessage("已请求管理员权限，请在系统窗口中确认…");
            string response = HttpPost(JoinUrl(state.Url, "api/elevate"), "{}", 5000);
            bool restarted = response != null && JsonTrue(response, "restarted");
            if (!restarted)
            {
                splash.SetMessage("未获得管理员权限（已取消或被系统策略禁止）。"
                                  + "仍可继续使用分析抓包文件与连通与速度测试。");
                return;
            }
            int oldPid = GetPid(state.Url);
            int deadline = Environment.TickCount + 30000;
            string newUrl = "";
            while (Environment.TickCount < deadline)
            {
                newUrl = ProbeExisting();
                if (!string.IsNullOrEmpty(newUrl))
                {
                    int pid = GetPid(newUrl);
                    if (oldPid <= 0 || (pid > 0 && pid != oldPid)) break;
                }
                Application.DoEvents();
                Thread.Sleep(200);
            }
            if (string.IsNullOrEmpty(newUrl))
            {
                splash.SetMessage("等待以管理员权限重启超时，可继续使用降级功能。");
                return;
            }
            state.Url = newUrl;
            _metrics.Port = ParsePort(newUrl);
            PreflightData data = FetchPreflight(newUrl, 8000);
            if (data != null && data.Items.Count > 0)
            {
                state.Preflight = data;
                splash.ApplyPreflight(data);
                state.AllowProceed = data.Ok;
                splash.SetMessage(data.Ok ? "已以管理员权限重启。"
                                           : "已以管理员权限重启，其余检查结果如上。");
            }
            else
            {
                splash.SetMessage("已以管理员权限重启。");
                state.AllowProceed = true;
            }
        }

        // ------------------------------------------------------------ 测量模式
        /// <summary>--measure 的优雅退出：POST /api/quit，最多等 8 秒（超时才强杀自启实例）。</summary>
        private static void QuitAndWait(LaunchState state)
        {
            long start = Now();
            if (state != null && !string.IsNullOrEmpty(state.Url))
            {
                string response = HttpPost(JoinUrl(state.Url, "api/quit"), "{}", 5000);
                _metrics.QuitOk = response != null && JsonTrue(response, "ok");
            }
            if (state != null && state.Proc != null)
            {
                try
                {
                    // 启动超时（还没拿到 URL）时只给 1.5s 收尾，避免测量永久等待。
                    int waitMs = string.IsNullOrEmpty(state.Url) ? 1500 : 8000;
                    _metrics.QuitExited = state.Proc.WaitForExit(waitMs);
                    if (!_metrics.QuitExited)
                    {
                        try { state.Proc.Kill(); } catch (Exception) { }
                    }
                }
                catch (Exception) { }
            }
            _metrics.QuitMs = (int)(Now() - start);
        }

        // ------------------------------------------------------------ 日志/报告
        private static void LogAndReport(string reportPath, LaunchState state)
        {
            // S3：--measure 的 quit 结果必须写进 startup.log，所以先 quit 再写日志。
            // 非 measure 行没有退出动作，quit_* 保持 false/0（字段存在只为同一 schema）。
            if (_measureMode)
            {
                if (!_metrics.Reused) QuitAndWait(state);
                WriteStartupLog();
                WriteMeasureReport(reportPath);
                return;
            }
            WriteStartupLog();
        }

        private static long Now()
        {
            return Clock.ElapsedMilliseconds;
        }

        private static string StartupLogPath()
        {
            return Path.Combine(_root, "logs", "startup.log");
        }

        private static string CachePath()
        {
            return Path.Combine(_root, "config", "launcher-cache.json");
        }

        /// <summary>首次 = 没有 Python 缓存且没有 startup.log（splash 的「首次可能较慢」提示）。</summary>
        private static bool HasStartupArtifacts()
        {
            try { return File.Exists(CachePath()) || File.Exists(StartupLogPath()); }
            catch (Exception) { return true; }
        }

        private static bool IsFirstRun()
        {
            return !HasStartupArtifacts();
        }

        private static void WriteStartupLog()
        {
            try
            {
                string path = StartupLogPath();
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                File.AppendAllText(path, _metrics.ToJsonLine(_root) + "\n", new UTF8Encoding(false));
            }
            catch (Exception) { }   // U 盘只读 / 安全软件锁目录：日志失败绝不影响启动
        }

        private static void WriteMeasureReport(string reportPath)
        {
            string json = _metrics.ToJsonLine(_root);
            if (string.IsNullOrEmpty(reportPath))
            {
                TryAttachConsole();
                try { Console.WriteLine(json); } catch (Exception) { }
                return;
            }
            try
            {
                WriteTextFile(reportPath, json + "\n");
            }
            catch (Exception ex)
            {
                TryAttachConsole();
                try { Console.Error.WriteLine("写 --report 失败：" + ex.Message); } catch (Exception) { }
            }
        }

        private static void WriteTextFile(string path, string text)
        {
            string full = Path.GetFullPath(path);
            string parent = Path.GetDirectoryName(full);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
            File.WriteAllText(full, text, new UTF8Encoding(false));
        }

        // ------------------------------------------------------- --dry-run
        /// <summary>--dry-run：只定位 Python 并写结果，不启动、不轮询、不开浏览器、不显示 splash。</summary>
        private static int RunDryRun(string reportPath)
        {
            // winexe 没有控制台；从命令行运行时挂到父进程控制台，方便直接看结果。
            // 自动化一律读 --report（stdout 在无控制台时不可依赖）。
            TryAttachConsole();
            PythonCandidate python = FindPython();
            string error = "";
            if (python == null)
            {
                error = NoPythonMessage();
                Console.Error.WriteLine(error);
            }
            else
            {
                Console.WriteLine("python : " + python.Exe);
                Console.WriteLine("kind   : " + python.Kind);
                Console.WriteLine("root   : " + _root);
            }
            if (!string.IsNullOrEmpty(reportPath))
            {
                try { WriteDryRunReport(Path.GetFullPath(reportPath), python, error); }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("写 --report 失败：" + ex.Message);
                    return ExitLaunchFailed;
                }
            }
            return python != null ? ExitOk : ExitNoPython;
        }

        // --------------------------------------------------------- Python 定位
        /// <summary>
        /// 按「包内 pythonw → 包内 python → PATH 里的 python → py -3」定位。
        /// 不解析 `python --version` 等本地化 CLI 文本：中文系统输出是中文，
        /// 解析既不可靠也违背项目「不用本地化 CLI 文本做判断」的约束。
        /// 命中即停（H2）；实际检查过的候选位置记在 _pythonCandidates 里。
        /// </summary>
        private static PythonCandidate FindPython()
        {
            _pythonCandidates = 0;
            string bundled = Path.Combine(_root, "tools", "python");
            string pythonw = Path.Combine(bundled, "pythonw.exe");
            _pythonCandidates++;
            if (File.Exists(pythonw)) return new PythonCandidate(pythonw, "bundled-pythonw", null);
            string python = Path.Combine(bundled, "python.exe");
            _pythonCandidates++;
            if (File.Exists(python)) return new PythonCandidate(python, "bundled-python", null);

            // 自己遍历 PATH，而不是 `where python`：where 的输出格式/退出码在
            // 受限环境里并不稳定，且 where 本身也可能不在 PATH。
            string[] dirs = SplitPath(Environment.GetEnvironmentVariable("PATH"));
            for (int i = 0; i < dirs.Length; i++)
            {
                string candidate = Path.Combine(dirs[i], "python.exe");
                _pythonCandidates++;
                if (File.Exists(candidate)) return new PythonCandidate(candidate, "system-python", null);
            }

            // py -3：只有真的能跑且版本 >= 3.11 才采用；只看退出码，不看输出文本。
            for (int i = 0; i < dirs.Length; i++)
            {
                string py = Path.Combine(dirs[i], "py.exe");
                _pythonCandidates++;
                if (File.Exists(py) && ProbePythonLauncher(py))
                    return new PythonCandidate(py, "py-launcher", new string[] { "-3" });
            }
            return null;
        }

        private static int _pythonCandidates;

        private static string[] SplitPath(string pathEnv)
        {
            if (string.IsNullOrEmpty(pathEnv)) return new string[0];
            string[] raw = pathEnv.Split(';');
            System.Collections.Generic.List<string> dirs = new System.Collections.Generic.List<string>();
            for (int i = 0; i < raw.Length; i++)
            {
                string dir = raw[i].Trim().Trim('"');
                if (dir.Length > 0) dirs.Add(dir);
            }
            return dirs.ToArray();
        }

        private static bool ProbePythonLauncher(string pyExe)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(pyExe,
                    "-3 -c \"import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)\"");
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process probe = Process.Start(psi))
                {
                    if (probe == null) return false;
                    if (!probe.WaitForExit(PyProbeTimeoutMs))
                    {
                        try { probe.Kill(); } catch (Exception) { }
                        return false;
                    }
                    return probe.ExitCode == 0;
                }
            }
            catch (Exception) { return false; }
        }

        // --------------------------------------------------- Python 结果缓存（H2）
        /// <summary>
        /// 带缓存的 Python 定位：cache 命中也要校验「文件存在 + size/mtime + 版本」，
        /// 任一不符就回退全扫（缓存只省扫描，不省存在性检查）。
        /// </summary>
        private static PythonLookup FindPythonCached()
        {
            PythonLookup lookup = new PythonLookup();
            string path = CachePath();
            PythonCandidate cached;
            string reason;
            if (TryReadPythonCache(path, out cached, out reason))
            {
                lookup.Python = cached;
                lookup.Candidates = 1;          // 缓存命中 = 只做了 1 次存在性校验
                lookup.Cache = "hit";
                return lookup;
            }
            lookup.Cache = File.Exists(path) ? ("invalid:" + reason) : "miss";
            PythonCandidate python = FindPython();
            lookup.Python = python;
            lookup.Candidates = _pythonCandidates;
            if (python != null) TryWritePythonCache(path, python);
            return lookup;
        }

        private static bool TryReadPythonCache(string path, out PythonCandidate python, out string reason)
        {
            python = null;
            reason = "missing";
            try
            {
                if (!File.Exists(path)) return false;
                string text = File.ReadAllText(path, Encoding.UTF8);
                if (JsonNumber(text, "format") != "1") { reason = "format"; return false; }
                string version = JsonString(text, "app_version");
                if (!string.IsNullOrEmpty(version) && version != ReadVersion()) { reason = "version"; return false; }
                string exe = JsonString(text, "python");
                if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) { reason = "missing-file"; return false; }
                string kind = JsonString(text, "python_kind");
                FileInfo info = new FileInfo(exe);
                string size = JsonNumber(text, "size");
                string mtime = JsonNumber(text, "mtime_utc");
                if (size != info.Length.ToString(CultureInfo.InvariantCulture)
                    || mtime != info.LastWriteTimeUtc.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture))
                {
                    reason = "stale";
                    return false;
                }
                string prefix = JsonString(text, "prefix_args");
                string[] prefixArgs = string.IsNullOrEmpty(prefix) ? null : prefix.Split(' ');
                python = new PythonCandidate(exe, string.IsNullOrEmpty(kind) ? "cache" : kind, prefixArgs);
                reason = "";
                return true;
            }
            catch (Exception)
            {
                reason = "unreadable";
                return false;
            }
        }

        private static void TryWritePythonCache(string path, PythonCandidate python)
        {
            try
            {
                FileInfo info = new FileInfo(python.Exe);
                string prefix = python.PrefixArgs == null ? "" : string.Join(" ", python.PrefixArgs);
                StringBuilder sb = new StringBuilder();
                sb.Append("{\"format\":1,\"app\":\"NetDiag\"");
                sb.Append(",\"app_version\":\"").Append(JsonEscape(ReadVersion())).Append('"');
                sb.Append(",\"python\":\"").Append(JsonEscape(python.Exe)).Append('"');
                sb.Append(",\"python_kind\":\"").Append(JsonEscape(python.Kind)).Append('"');
                sb.Append(",\"prefix_args\":\"").Append(JsonEscape(prefix)).Append('"');
                sb.Append(",\"size\":").Append(info.Length.ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"mtime_utc\":").Append(info.LastWriteTimeUtc.ToFileTimeUtc()
                                                       .ToString(CultureInfo.InvariantCulture));
                sb.Append('}').Append('\n');
                string parent = Path.GetDirectoryName(Path.GetFullPath(path));
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
            }
            catch (Exception) { }   // 写保护/目录被锁：缓存写失败只影响下次速度，不影响启动
        }

        private static string ReadVersion()
        {
            try { return File.ReadAllText(Path.Combine(_root, "VERSION"), Encoding.UTF8).Trim(); }
            catch (Exception) { return ""; }
        }

        private static Process StartApp(PythonCandidate python, string script)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = python.Exe;
                psi.Arguments = BuildAppArguments(python, script);
                psi.WorkingDirectory = _root;   // core/app.py 依赖相对路径找 config/ 与 ui/
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                // H1：启动器是唯一打开浏览器的地方；子进程一律不自己开。
                // 提权重启路径（Python 的 /api/elevate）也会继承这个 env，不会多弹一个标签页。
                psi.EnvironmentVariables[NoBrowserEnv] = "1";
                return Process.Start(psi);
            }
            catch (Exception) { return null; }
        }

        private static string BuildAppArguments(PythonCandidate python, string script)
        {
            StringBuilder sb = new StringBuilder();
            if (python.PrefixArgs != null)
                for (int i = 0; i < python.PrefixArgs.Length; i++) sb.Append(python.PrefixArgs[i]).Append(' ');
            // --no-elevate 是双保险：即使以后 core/app.py 又长回启动提权逻辑，
            // 启动器拉起的这份也明确声明「本次不请求提权」。
            return sb.Append('"').Append(script).Append("\" --no-elevate").ToString();
        }

        // --------------------------------------------------------- 就绪探测
        /// <summary>
        /// 找本程序已在运行的实例：先读端口文件，再扫 8787..8796；都没有返回 null。
        ///
        /// 为什么先读文件：端口 8787~8796 全被别的程序占满时，服务会绑端口 0 由系统
        /// 分配（core/server.py::create_server），那种实例在固定区间里**永远扫不到**。
        /// 服务把真实端口写进 logs\netdiag.port，这里读一眼就知道该敲哪个端口 ——
        /// 顺带把「端口 0 启动」的冷启动也变快（不用扫 10 个端口）。
        ///
        /// H2 实测发现的最大浪费：对**没人监听**的端口发 HttpWebRequest，.NET 会
        /// 等满 700ms 超时才失败；10 个端口 = 7 秒，占了冷启动一半时间。所以先用
        /// ``GetActiveTcpListeners()``（一次系统调用，约 10ms）拿到本机监听端口表，
        /// 只对真正在监听的端口发 HTTP 探查；8787 优先，命中即停。
        /// 枚举失败（极老系统/被安全软件拦）时退回逐个 HTTP 探查。
        /// </summary>
        private static string ProbeExisting()
        {
            string fromFile = ProbePortFile();
            if (!string.IsNullOrEmpty(fromFile)) return fromFile;
            bool[] listening = ListeningPorts();
            for (int port = PortMin; port <= PortMax; port++)
            {
                if (listening != null && !listening[port - PortMin]) continue;
                string url = ProbePing(port);
                if (!string.IsNullOrEmpty(url)) return url;
            }
            return null;
        }

        /// <summary>
        /// 读 logs\netdiag.port 里的真实端口，敲一次 /api/ping；对不上返回 null。
        ///
        /// 文件读不到、JSON 坏、端口越界、进程已死（端口没人应答）都返回 null ——
        /// 调用方会退回按区间扫，所以这里的失败一律不是错误。
        /// </summary>
        private static string ProbePortFile()
        {
            try
            {
                string path = Path.Combine(_root, PortFileRel);
                if (!File.Exists(path)) return null;
                string body = File.ReadAllText(path, Encoding.UTF8);
                string raw = JsonNumber(body, "port");
                if (string.IsNullOrEmpty(raw)) return null;
                int port;
                if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture,
                                  out port)) return null;
                if (port <= 0 || port > 65535) return null;
                return ProbePing(port);
            }
            catch (Exception) { return null; }
        }

        /// <summary>本机 8787~8796 的监听位图；枚举失败返回 null（调用方退回 HTTP 逐端口探查）。</summary>
        private static bool[] ListeningPorts()
        {
            try
            {
                bool[] map = new bool[PortMax - PortMin + 1];
                IPEndPoint[] listeners = IPGlobalProperties.GetIPGlobalProperties()
                                                          .GetActiveTcpListeners();
                for (int i = 0; i < listeners.Length; i++)
                {
                    int port = listeners[i].Port;
                    if (port >= PortMin && port <= PortMax) map[port - PortMin] = true;
                }
                return map;
            }
            catch (Exception) { return null; }
        }

        /// <summary>对一个端口做一次 /api/ping；确认是本程序才返回界面地址。</summary>
        private static string ProbePing(int port)
        {
            string url = "http://127.0.0.1:"
                         + port.ToString(CultureInfo.InvariantCulture) + "/api/ping";
            string body = HttpGet(url, PingTimeoutMs);
            if (body == null) return null;
            // 只认本程序的应答：别的服务也可能占着 8787 并回 200。
            string app = JsonString(body, "app");
            if (!JsonTrue(body, "ok") || string.IsNullOrEmpty(app)
                || app.IndexOf(AppMarker, StringComparison.OrdinalIgnoreCase) < 0) return null;
            string served = JsonString(body, "url");
            return string.IsNullOrEmpty(served)
                ? "http://127.0.0.1:" + port.ToString(CultureInfo.InvariantCulture) + "/"
                : served;
        }

        private static string WaitForReady(Process proc, out int failureExit, out int pythonExit,
                                           SplashForm splash)
        {
            failureExit = ExitWaitTimeout;
            pythonExit = 0;
            int deadline = Environment.TickCount + ReadyTimeoutMs;
            int lastUpdate = 0;
            while (Environment.TickCount < deadline)
            {
                string url = ProbeExisting();
                if (!string.IsNullOrEmpty(url)) return url;
                if (proc != null && proc.HasExited)
                {
                    // app.py 可能发现已有实例、开窗后退出；再探一次，别把成功误判成失败。
                    url = ProbeExisting();
                    if (!string.IsNullOrEmpty(url)) return url;
                    failureExit = ExitLaunchFailed;
                    try { pythonExit = proc.ExitCode; } catch (Exception) { pythonExit = -1; }
                    return null;
                }
                int elapsed = (int)Now();
                if (splash != null && elapsed - lastUpdate >= 500)
                {
                    lastUpdate = elapsed;
                    Post(splash, delegate { splash.SetItem("port", CheckState.Checking, "等待本地服务就绪…"); });
                }
                Thread.Sleep(PollIntervalMs);
            }
            return null;
        }

        /// <summary>GET 一个本地 URL；超时/非 200 都返回 null（探测失败不是异常）。</summary>
        private static string HttpGet(string url, int timeoutMs)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "GET";
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                req.Proxy = null;   // 只访问 127.0.0.1，系统代理不该参与
                using (WebResponse resp = req.GetResponse())
                using (Stream stream = resp.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
                    return reader.ReadToEnd();
            }
            catch (Exception) { return null; }
        }

        /// <summary>POST 一个本地 URL（空 JSON 体）；失败返回 null。</summary>
        private static string HttpPost(string url, string body, int timeoutMs)
        {
            try
            {
                byte[] payload = Encoding.UTF8.GetBytes(body ?? "{}");
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "POST";
                req.ContentType = "application/json; charset=utf-8";
                req.ContentLength = payload.Length;
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                req.Proxy = null;
                using (Stream stream = req.GetRequestStream()) stream.Write(payload, 0, payload.Length);
                using (WebResponse resp = req.GetResponse())
                using (Stream stream = resp.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
                    return reader.ReadToEnd();
            }
            catch (Exception) { return null; }
        }

        /// <summary>轮询 /api/preflight 直到拿到 6 项检查；总超时后返回 null。</summary>
        private static PreflightData FetchPreflight(string baseUrl, int timeoutMs)
        {
            string url = JoinUrl(baseUrl, "api/preflight");
            int deadline = Environment.TickCount + timeoutMs;
            while (Environment.TickCount < deadline)
            {
                string body = HttpGet(url, 2000);
                if (!string.IsNullOrEmpty(body))
                {
                    PreflightData data = PreflightData.Parse(body);
                    if (data.Items.Count > 0) return data;
                }
                Thread.Sleep(300);
            }
            return null;
        }

        private static string JoinUrl(string baseUrl, string relative)
        {
            if (string.IsNullOrEmpty(baseUrl)) return relative;
            return baseUrl.EndsWith("/", StringComparison.Ordinal) ? baseUrl + relative : baseUrl + "/" + relative;
        }

        private static int ParsePort(string url)
        {
            try
            {
                Uri uri = new Uri(url);
                return uri.Port;
            }
            catch (Exception) { return PortMin; }
        }

        private static int GetPid(string url)
        {
            string body = HttpGet(JoinUrl(url, "api/ping"), 1500);
            if (string.IsNullOrEmpty(body)) return 0;
            Match match = Regex.Match(body, "\"pid\"\\s*:\\s*(\\d+)");
            if (!match.Success) return 0;
            int pid;
            return int.TryParse(match.Groups[1].Value, NumberStyles.Integer,
                                CultureInfo.InvariantCulture, out pid) ? pid : 0;
        }

        // --------------------------------------------------------- 开浏览器
        /// <summary>
        /// 唯一打开浏览器的实现。受 NETDIAG_NO_BROWSER=1 / --no-browser 控制：
        /// 测量与自动化场景下返回 false 但不算失败（调用方用 _noBrowser 判定）。
        /// </summary>
        private static bool OpenBrowser(string url)
        {
            if (_noBrowser || string.IsNullOrEmpty(url)) return false;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(url);
                psi.UseShellExecute = true;   // 交给系统默认浏览器
                Process.Start(psi);
                return true;
            }
            catch (Exception) { return false; }
        }

        // ------------------------------------------------------------ 小工具
        private static string NoPythonMessage()
        {
            return "这台电脑还没有可用的 Python 3.11+，NetDiag 无法启动本地界面。\n\n"
                   + "请安装 Python 3.11 或更高版本（安装时勾选 Add python.exe to PATH），"
                   + "然后重新双击 NetDiag.exe：\n"
                   + "https://www.python.org/downloads/windows/\n\n"
                   + "如果用的是内部完整包，请确认包内 tools\\python 目录存在；"
                   + "更多排查见 docs/startup.md。";
        }

        private static void Post(SplashForm form, Action action)
        {
            if (form == null || action == null) return;
            try
            {
                if (form.IsHandleCreated && !form.IsDisposed) form.BeginInvoke(action);
                else action();
            }
            catch (Exception) { }
        }

        /// <summary>在 splash 存续期间泵消息（Timer/按钮/重绘都要靠它）。</summary>
        private static void Pump(int milliseconds)
        {
            int deadline = Environment.TickCount + Math.Max(0, milliseconds);
            while (Environment.TickCount < deadline)
            {
                Application.DoEvents();
                Thread.Sleep(10);
            }
        }

        /// <summary>200~400ms 淡出（Timer 间接调 Opacity），避免窗口「啪」地消失。</summary>
        private static void FadeOutAndClose(SplashForm form)
        {
            try
            {
                for (int step = 9; step >= 0; step--)
                {
                    form.Opacity = step / 10.0;
                    Pump(30);
                }
                form.Hide();
            }
            catch (Exception) { }
        }

        private static void WriteDryRunReport(string path, PythonCandidate python, string error)
        {
            string parent = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
            string script = Path.Combine(_root, "core", "app.py");
            StringBuilder sb = new StringBuilder();
            sb.Append("{\"ok\":").Append(python != null ? "true" : "false");
            sb.Append(",\"dry_run\":true,\"app\":\"NetDiag\"");
            sb.Append(",\"root\":\"").Append(JsonEscape(_root)).Append('"');
            sb.Append(",\"python\":\"").Append(JsonEscape(python != null ? python.Exe : "")).Append('"');
            sb.Append(",\"python_kind\":\"").Append(JsonEscape(python != null ? python.Kind : "")).Append('"');
            sb.Append(",\"app_script\":\"").Append(JsonEscape(script)).Append('"');
            sb.Append(",\"app_script_exists\":").Append(File.Exists(script) ? "true" : "false");
            // 明确写 false：测试用它证明 --dry-run 没有偷偷启动服务/开浏览器。
            sb.Append(",\"started\":false,\"browser_opened\":false,\"splash\":false");
            // H1 契约：launcher 会把 NETDIAG_NO_BROWSER=1 传给子进程；dry-run 本身
            // 也遵守 env（有该变量时不打开浏览器）。
            sb.Append(",\"no_browser_env\":\"").Append(JsonEscape(Environment.GetEnvironmentVariable(NoBrowserEnv) ?? ""))
              .Append("\",\"launcher_no_browser\":").Append(_noBrowser ? "true" : "false");
            sb.Append(",\"child_env\":{\"").Append(NoBrowserEnv).Append("\":\"1\"}");
            sb.Append(",\"browser_open_points\":1");
            sb.Append(",\"error\":\"").Append(JsonEscape(error)).Append('"').Append('}').Append('\n');
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        }

        // ---------------------------------------------------- --splash-test
        /// <summary>
        /// --splash-test DIR：离屏渲染 4 种 splash 状态（加载中/全绿/缺 tshark/非管理员）。
        /// 不 Show 窗口、不启动服务、不开浏览器；同时写 splash-states.json 供契约测试
        /// 断言「状态映射 / 按钮可见性」，而不是靠肉眼看 PNG。
        /// </summary>
        private static int RunSplashTest(string outDir)
        {
            TryAttachConsole();
            try
            {
                Directory.CreateDirectory(outDir);
                string[] scenarios = { "loading", "all_green", "missing_tshark", "non_admin" };
                string[] files = { "splash-1-loading", "splash-2-all-green",
                                   "splash-3-missing-tshark", "splash-4-non-admin" };
                long[] elapsed = { 1200, 2600, 3100, 2400 };
                StringBuilder json = new StringBuilder();
                json.Append('[');
                for (int i = 0; i < scenarios.Length; i++)
                {
                    using (SplashForm form = new SplashForm(scenarios[i] == "loading",
                                                            elapsed[i] - 500))
                    {
                        form.ApplyScenario(scenarios[i], elapsed[i]);
                        string png = Path.Combine(outDir, files[i] + ".png");
                        form.RenderToBitmap(png);
                        if (i > 0) json.Append(',');
                        json.Append(form.StateJson());
                    }
                }
                json.Append(']').Append('\n');
                File.WriteAllText(Path.Combine(outDir, "splash-states.json"), json.ToString(),
                                  new UTF8Encoding(false));
                Console.WriteLine("SPLASH TEST OK: 4 png + splash-states.json -> " + outDir);
                return ExitOk;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("SPLASH TEST FAILED: " + ex.GetType().Name + ": " + ex.Message);
                return ExitLaunchFailed;
            }
        }

        // ------------------------------------------------------------ 小工具
        private static string JsonEscape(string text)
        {
            return SplashLogic.JsonEscape(text);
        }

        private static void TryAttachConsole()
        {
            try
            {
                if (!AttachConsole(ATTACH_PARENT_PROCESS)) return;
                StreamWriter stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false));
                stdout.AutoFlush = true;
                Console.SetOut(stdout);
                StreamWriter stderr = new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false));
                stderr.AutoFlush = true;
                Console.SetError(stderr);
            }
            catch (Exception) { }   // 没有控制台就只靠 --report / MessageBox
        }

        private static void ShowError(string text)
        {
            try { MessageBoxW(IntPtr.Zero, text, Caption, MB_OK | MB_ICONERROR | MB_TOPMOST); }
            catch (Exception) { }   // 极端环境（无窗口站）弹不出也不能让启动器崩掉
        }

        // ------------------------------------------------------- 控制台/消息框
        private const uint ATTACH_PARENT_PROCESS = 0xFFFFFFFF;
        private const uint MB_OK = 0x00000000;
        private const uint MB_ICONERROR = 0x00000010;
        private const uint MB_TOPMOST = 0x00040000;

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(uint dwProcessId);

        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

        /// <summary>极简 JSON 取值：服务端输出固定，只取顶层 ok/app/url/pid 等键。</summary>
        private static string JsonString(string json, string key)
        {
            if (string.IsNullOrEmpty(json)) return null;
            Match m = Regex.Match(json, "\"" + Regex.Escape(key)
                                      + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
            return m.Success ? Regex.Unescape(m.Groups[1].Value) : null;
        }

        private static bool JsonTrue(string json, string key)
        {
            return !string.IsNullOrEmpty(json) && Regex.IsMatch(json,
                "\"" + Regex.Escape(key) + "\"\\s*:\\s*true");
        }

        private static string JsonNumber(string json, string key)
        {
            if (string.IsNullOrEmpty(json)) return null;
            Match m = Regex.Match(json, "\"" + Regex.Escape(key) + "\"\\s*:\\s*(\\d+)");
            return m.Success ? m.Groups[1].Value : null;
        }

        // ------------------------------------------------------------ 数据类
        private sealed class PythonCandidate
        {
            public readonly string Exe;
            public readonly string Kind;
            public readonly string[] PrefixArgs;
            public PythonCandidate(string exe, string kind, string[] prefixArgs)
            {
                Exe = exe;
                Kind = kind;
                PrefixArgs = prefixArgs;
            }
        }

        private sealed class PythonLookup
        {
            public PythonCandidate Python;
            public int Candidates;
            public string Cache = "miss";
        }

        private sealed class LaunchState
        {
            public volatile bool Working = true;
            public bool NeedUserChoice;
            public bool AllowProceed;
            public string Url = "";
            public string Fatal = "";
            public string FatalCode = "";
            public string InstallUrl = "";
            public string InstallLabel = "";
            public int ExitCode = ExitLaunchFailed;
            public Process Proc;
            public PreflightData Preflight;
            public PythonLookup Lookup;
        }

        /// <summary>H2 的计时/模式记录；一行 JSON 追加到 logs/startup.log。</summary>
        private sealed class StartupMetrics
        {
            public string Action = "launch";
            public string Mode = "cold";
            public bool Measure;
            public bool NoBrowser;
            public bool Reused;
            public bool FirstRun;
            public bool Ok;
            public string Error = "";
            public long T1, T2, T3;        // t0 恒为 0（进程启动 = 时钟起点）
            public int Port;
            public int Candidates;
            public string PythonKind = "";
            public string Cache = "none";
            public string Browser = "none";   // opened / skipped / failed
            public bool QuitOk;
            public bool QuitExited;
            public int QuitMs;

            public string ToJsonLine(string root)
            {
                long t1 = T1, t2 = T2, t3 = T3;
                long total = t3 > 0 ? t3 : (t2 > 0 ? t2 : (t1 > 0 ? t1 : 0));
                StringBuilder sb = new StringBuilder();
                sb.Append("{\"ts\":\"").Append(JsonEscape(DateTimeOffset.Now.ToString(
                    "yyyy-MM-dd'T'HH:mm:sszzz", CultureInfo.InvariantCulture))).Append('"');
                sb.Append(",\"action\":\"").Append(JsonEscape(Action)).Append('"');
                sb.Append(",\"mode\":\"").Append(JsonEscape(Mode)).Append('"');
                sb.Append(",\"t0_ms\":0");
                sb.Append(",\"t1_ms\":").Append(t1.ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"t2_ms\":").Append(t2.ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"t3_ms\":").Append(t3.ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"spawn_ms\":").Append((t1 > 0 ? t1 : 0).ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"ready_ms\":").Append((t2 > 0 ? Math.Max(0, t2 - (t1 > 0 ? t1 : t2)) : 0)
                    .ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"browse_ms\":").Append((t3 > 0 && t2 > 0 ? Math.Max(0, t3 - t2) : 0)
                    .ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"total_ms\":").Append(total.ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"python_kind\":\"").Append(JsonEscape(PythonKind)).Append('"');
                sb.Append(",\"python_candidates\":").Append(Candidates.ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"python_cache\":\"").Append(JsonEscape(Cache)).Append('"');
                sb.Append(",\"port\":").Append(Port.ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"reused\":").Append(Reused ? "true" : "false");
                sb.Append(",\"first_run\":").Append(FirstRun ? "true" : "false");
                sb.Append(",\"browser\":\"").Append(JsonEscape(Browser)).Append('"');
                sb.Append(",\"no_browser\":").Append(NoBrowser ? "true" : "false");
                sb.Append(",\"measure\":").Append(Measure ? "true" : "false");
                sb.Append(",\"quit_ok\":").Append(QuitOk ? "true" : "false");
                sb.Append(",\"quit_exited\":").Append(QuitExited ? "true" : "false");
                sb.Append(",\"quit_ms\":").Append(QuitMs.ToString(CultureInfo.InvariantCulture));
                sb.Append(",\"ok\":").Append(Ok ? "true" : "false");
                sb.Append(",\"error\":\"").Append(JsonEscape(Error)).Append('"');
                sb.Append(",\"root\":\"").Append(JsonEscape(root)).Append('"');
                sb.Append('}');
                return sb.ToString();
            }
        }
    }
}
