// ============================================================================
// NetDiag · 网络矩阵 —— Windows 图形启动器（系统自带 .NET Framework，无第三方依赖）
//
// 为什么需要它：
//   1. .vbs 不支持右键「以管理员身份运行 / 以其他用户运行」，也容易被脚本宿主
//      策略拦下。exe 是 Windows 原生入口，右键两项是系统能力，不需要注册表。
//   2. 启动慢的主因之一是旧 core/app.py 启动即请求 UAC。本启动器以 asInvoker
//      运行，双击**不提权**；需要管理员的功能由界面按需请求。
//   3. pythonw 起来后没有提示，用户不知道在等什么。这里轮询 /api/ping，
//      就绪才开浏览器；失败时用 MessageBox 给出可操作下一步。
//
// 只做四件事：探测已有实例 → 定位 Python → 隐藏启动 core\app.py → 等就绪开浏览器。
// 不做：提权、注册表、开机自启、访问 127.0.0.1 以外网络、安装 Python。
// 编译：scripts/build_launcher.py（csc /target:winexe）。
// 退出码：0 成功 / 2 找不到 Python / 3 等待超时 / 4 启动失败。
// ============================================================================

using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace NetDiag
{
    internal static class Launcher
    {
        // 与 core/server.py 的端口区间、轮询节奏保持一致。写死常量而不是读配置：
        // 启动器要在 Python 起来之前工作，此时读不到 app-config.json。
        private const int PortMin = 8787;
        private const int PortMax = 8796;
        private const int PollIntervalMs = 200;
        private const int ReadyTimeoutMs = 30000;
        private const int PingTimeoutMs = 700;
        private const int PyProbeTimeoutMs = 5000;

        private const int ExitOk = 0;
        private const int ExitNoPython = 2;
        private const int ExitWaitTimeout = 3;
        private const int ExitLaunchFailed = 4;

        private const string Caption = "NetDiag · 网络矩阵";
        private const string AppMarker = "NetDiag";
        private static string _root = "";

        [STAThread]
        private static int Main(string[] args)
        {
            bool dryRun = false;
            string reportPath = null;
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], "--dry-run", StringComparison.OrdinalIgnoreCase)) dryRun = true;
                else if (string.Equals(args[i], "--report", StringComparison.OrdinalIgnoreCase)
                         && i + 1 < args.Length) reportPath = args[++i];
            }

            // 根目录 = exe 所在目录。发布包里 NetDiag.exe 与 core\ 同级；双击时
            // 当前工作目录不可靠，所以不用 cwd。
            _root = ResolveRoot();
            return dryRun ? RunDryRun(reportPath) : RunNormal();
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

        private static int RunNormal()
        {
            // 双保险：已有实例就直接开浏览器，不再起第二个进程抢端口。
            string existing = ProbeExisting();
            if (!string.IsNullOrEmpty(existing))
                return OpenBrowser(existing) ? ExitOk : ExitLaunchFailed;

            PythonCandidate python = FindPython();
            if (python == null)
            {
                ShowError(NoPythonMessage());
                return ExitNoPython;
            }

            string script = Path.Combine(_root, "core", "app.py");
            if (!File.Exists(script))
            {
                ShowError("项目目录不完整：找不到\n" + script + "\n\n"
                          + "请确认 NetDiag.exe 与 core\\ 目录在同一层（解压时不要只拖 exe 出来）。");
                return ExitLaunchFailed;
            }

            Process proc = StartApp(python, script);
            if (proc == null)
            {
                ShowError("无法启动 core\\app.py。\n\n请检查 Python 是否可用："
                          + python.Exe + "\n并查看日志："
                          + Path.Combine(_root, "logs") + "\\app-*.log");
                return ExitLaunchFailed;
            }

            int failureExit, pythonExit;
            string url = WaitForReady(proc, out failureExit, out pythonExit);
            if (string.IsNullOrEmpty(url))
            {
                if (failureExit == ExitLaunchFailed)
                    ShowError("启动失败：Python 进程已退出（退出码 "
                              + pythonExit.ToString(CultureInfo.InvariantCulture) + "）。\n\n"
                              + "请查看日志：" + Path.Combine(_root, "logs") + "\\app-*.log\n\n"
                              + "常见原因：Python 版本低于 3.11、缺少项目文件、依赖导入失败。");
                else
                    ShowError("启动超时：30 秒内本地服务没有就绪。\n\n"
                              + "请查看日志：" + Path.Combine(_root, "logs") + "\\app-*.log\n\n"
                              + "常见原因：\n  - 端口 8787-8796 全被占用\n"
                              + "  - Npcap / 安全软件拦截了 Python\n"
                              + "  - Python 缺少运行所需的模块");
                return failureExit;
            }
            return OpenBrowser(url) ? ExitOk : ExitLaunchFailed;
        }

        /// <summary>--dry-run：只定位 Python 并写结果，不启动、不轮询、不开浏览器。</summary>
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
        /// </summary>
        private static PythonCandidate FindPython()
        {
            string bundled = Path.Combine(_root, "tools", "python");
            string pythonw = Path.Combine(bundled, "pythonw.exe");
            if (File.Exists(pythonw)) return new PythonCandidate(pythonw, "bundled-pythonw", null);
            string python = Path.Combine(bundled, "python.exe");
            if (File.Exists(python)) return new PythonCandidate(python, "bundled-python", null);

            // 自己遍历 PATH，而不是 `where python`：where 的输出格式/退出码在
            // 受限环境里并不稳定，且 where 本身也可能不在 PATH。
            string[] dirs = SplitPath(Environment.GetEnvironmentVariable("PATH"));
            for (int i = 0; i < dirs.Length; i++)
            {
                string candidate = Path.Combine(dirs[i], "python.exe");
                if (File.Exists(candidate)) return new PythonCandidate(candidate, "system-python", null);
            }

            // py -3：只有真的能跑且版本 >= 3.11 才采用；只看退出码，不看输出文本。
            for (int i = 0; i < dirs.Length; i++)
            {
                string py = Path.Combine(dirs[i], "py.exe");
                if (File.Exists(py) && ProbePythonLauncher(py))
                    return new PythonCandidate(py, "py-launcher", new string[] { "-3" });
            }
            return null;
        }

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
        /// <summary>扫描 8787..8796，返回本程序的界面地址；没有就返回 null。</summary>
        private static string ProbeExisting()
        {
            for (int port = PortMin; port <= PortMax; port++)
            {
                string url = "http://127.0.0.1:"
                             + port.ToString(CultureInfo.InvariantCulture) + "/api/ping";
                string body = HttpGet(url, PingTimeoutMs);
                if (body == null) continue;
                // 只认本程序的应答：别的服务也可能占着 8787 并回 200。
                string app = JsonString(body, "app");
                if (!JsonTrue(body, "ok") || string.IsNullOrEmpty(app)
                    || app.IndexOf(AppMarker, StringComparison.OrdinalIgnoreCase) < 0) continue;
                string served = JsonString(body, "url");
                return string.IsNullOrEmpty(served)
                    ? "http://127.0.0.1:" + port.ToString(CultureInfo.InvariantCulture) + "/"
                    : served;
            }
            return null;
        }

        private static string WaitForReady(Process proc, out int failureExit, out int pythonExit)
        {
            failureExit = ExitWaitTimeout;
            pythonExit = 0;
            int deadline = Environment.TickCount + ReadyTimeoutMs;
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

        // --------------------------------------------------------- 开浏览器
        private static bool OpenBrowser(string url)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(url);
                psi.UseShellExecute = true;   // 交给系统默认浏览器
                Process.Start(psi);
                return true;
            }
            catch (Exception ex)
            {
                ShowError("本地服务已就绪，但打开浏览器失败。\n\n请手动访问：" + url
                          + "\n\n系统返回：" + ex.Message);
                return false;
            }
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
            sb.Append(",\"started\":false,\"browser_opened\":false");
            sb.Append(",\"error\":\"").Append(JsonEscape(error)).Append('"').Append('}').Append('\n');
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        }

        private static string JsonEscape(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            StringBuilder sb = new StringBuilder(text.Length + 16);
            foreach (char c in text)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < ' ') sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        /// <summary>极简 JSON 取值：服务端输出固定，只取顶层 ok/app/url 三个键。</summary>
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

        // ------------------------------------------------------- 控制台/消息框
        private const uint ATTACH_PARENT_PROCESS = 0xFFFFFFFF;
        private const uint MB_OK = 0x00000000;
        private const uint MB_ICONERROR = 0x00000010;
        private const uint MB_TOPMOST = 0x00040000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(uint dwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

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
    }
}
