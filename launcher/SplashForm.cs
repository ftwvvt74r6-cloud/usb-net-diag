// ============================================================================
// NetDiag · 网络矩阵 —— 启动等待窗口（WinForms，系统自带组件，无第三方依赖）
//
// 为什么需要它（H3）：
//   双击 NetDiag.exe 后要定位 Python、拉起本地服务、等 8787 端口就绪。这段
//   时间以前只有一个「什么都不显示」的黑屏空档，用户会怀疑程序没反应。这里给
//   一个屏幕正中的无边框小窗：产品名 + 六项检查逐条点亮 + 已用时，失败时直接
//   给安装/提权/继续三个出口。
//
// 边界（刻意不做的事）：
//   * **不复制后端判定**：六项检查的结果全部来自 GET /api/preflight（H6 与
//     /api/selfcheck 同源）；本文件只做「机器码 → ✓/⚠/✗ + 文案」的展示映射。
//   * 服务没起时不猜结果：Python / 端口显示本地占位（启动器确实知道这两个），
//     其余一律「检查中…」，等接口回来再点亮。
//   * 不阻塞：所有耗时操作都在 NetDiagLauncher 的后台线程里，UI 线程只画；
//     本文件只暴露状态更新、按钮标记与离屏渲染接口。
//   * 离屏截图（--splash-test）用 Form.DrawToBitmap，不 Show() 可见窗口，
//     因此 CI / 自动化里不会闪窗。
//
// 编译：scripts/build_launcher.py（csc /target:winexe，引用 System.Windows.Forms
//       / System.Drawing 两个系统程序集）。
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace NetDiag
{
    /// <summary>单项检查的展示状态。Checking 只用于「服务未起、结果未到」。</summary>
    internal enum CheckState
    {
        Checking = 0,
        Ok = 1,
        Degraded = 2,
        Missing = 3,
    }

    /// <summary>preflight 的一项检查（字段与后端 /api/preflight 的 checks 一致）。</summary>
    internal sealed class SplashItem
    {
        public string Key = "";
        public string Name = "";
        public CheckState State = CheckState.Checking;
        public string Detail = "";
        public string Impact = "";
        public string FixKind = "";
        public string FixUrl = "";
        public string FixCommand = "";

        /// <summary>界面上显示的一行摘要：通过显示 detail，失败/降级显示 impact（更短、说后果）。</summary>
        public string Summary
        {
            get
            {
                if (State == CheckState.Checking) return "检查中…";
                if (State == CheckState.Ok) return string.IsNullOrEmpty(Detail) ? "可用" : Detail;
                string consequence = string.IsNullOrEmpty(Impact) ? Detail : Impact;
                return string.IsNullOrEmpty(consequence) ? "不可用" : consequence;
            }
        }
    }

    /// <summary>后端 GET /api/preflight 的最小投影（只保留 splash 需要的字段）。</summary>
    internal sealed class PreflightData
    {
        public bool Ok;
        public string Version = "";
        public string Source = "";
        public string Error = "";
        public readonly List<SplashItem> Items = new List<SplashItem>();
        public readonly Dictionary<string, string> FixUrls =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>按固定顺序取一项；没有该项时返回 null（不抛异常）。</summary>
        public SplashItem Get(string key)
        {
            for (int i = 0; i < Items.Count; i++)
                if (string.Equals(Items[i].Key, key, StringComparison.OrdinalIgnoreCase))
                    return Items[i];
            return null;
        }

        /// <summary>解析 /api/preflight 的 JSON；解析失败不抛，返回带 Error 的空对象。</summary>
        public static PreflightData Parse(string json)
        {
            PreflightData data = new PreflightData();
            if (string.IsNullOrEmpty(json))
            {
                data.Error = "empty response";
                return data;
            }
            try
            {
                Dictionary<string, object> root = MiniJson.AsObject(MiniJson.Parse(json));
                data.Ok = MiniJson.GetBool(root, "ok", false);
                data.Version = MiniJson.GetString(root, "version", "");
                data.Source = MiniJson.GetString(root, "source", "");
                List<object> checks = MiniJson.GetArray(root, "checks");
                for (int i = 0; i < checks.Count; i++)
                {
                    Dictionary<string, object> raw = MiniJson.AsObject(checks[i]);
                    if (raw == null) continue;
                    SplashItem item = new SplashItem();
                    item.Key = MiniJson.GetString(raw, "key", "");
                    item.Name = MiniJson.GetString(raw, "name", item.Key);
                    item.Detail = MiniJson.GetString(raw, "detail", "");
                    item.Impact = MiniJson.GetString(raw, "impact", "");
                    item.FixKind = MiniJson.GetString(raw, "fix_kind", "");
                    item.FixUrl = MiniJson.GetString(raw, "fix_url", "");
                    item.FixCommand = MiniJson.GetString(raw, "fix_command", "");
                    if (string.IsNullOrEmpty(item.Key)) continue;
                    // 状态映射只在这里做一次：C# 不复制「什么算可用」的后端判定，
                    // 只决定 ok=false 时是「降级(⚠)」还是「不可用(✗)」的展示语义。
                    item.State = SplashLogic.MapStatus(item.Key,
                        MiniJson.GetBool(raw, "ok", false));
                    data.Items.Add(item);
                }
                Dictionary<string, object> fixes = MiniJson.GetObject(root, "fix_urls");
                if (fixes != null)
                {
                    foreach (KeyValuePair<string, object> pair in fixes)
                    {
                        string url = pair.Value as string;
                        if (!string.IsNullOrEmpty(url)) data.FixUrls[pair.Key] = url;
                    }
                }
                if (data.Items.Count == 0) data.Error = "no checks in payload";
            }
            catch (Exception ex)
            {
                data.Error = ex.GetType().Name + ": " + ex.Message;
            }
            return data;
        }
    }

    /// <summary>纯展示逻辑：状态映射 / 按钮可见性 / 状态 JSON（--splash-test 断言用）。</summary>
    internal static class SplashLogic
    {
        /// <summary>六项固定顺序（与 core/selfcheck.py 的 CHECK_KEYS 一致）。</summary>
        public static readonly string[] CheckOrder =
            { "python", "tshark", "npcap", "scapy", "port", "admin" };

        public const string StatusOk = "✓ 可用";
        public const string StatusDegraded = "⚠ 可用但降级";
        public const string StatusMissing = "✗ 不可用";
        public const string StatusChecking = "检查中…";

        /// <summary>
        /// ok=false 时的展示分级：scapy 缺了只是逐跳降级，admin 缺了只是不能实时抓包
        /// （离线分析与体检仍可用），二者都不算「不可用」；tshark / Npcap / Python /
        /// 端口缺失才会挡住主流程，按 ✗ 显示后果。
        /// </summary>
        public static CheckState MapStatus(string key, bool ok)
        {
            if (ok) return CheckState.Ok;
            if (string.Equals(key, "scapy", StringComparison.OrdinalIgnoreCase)
                || string.Equals(key, "admin", StringComparison.OrdinalIgnoreCase))
                return CheckState.Degraded;
            return CheckState.Missing;
        }

        /// <summary>状态对应的界面文案（✓/⚠/✗ 三个符号必须同时出现在源码里，测试按它断言）。</summary>
        public static string StatusText(CheckState state)
        {
            switch (state)
            {
                case CheckState.Ok: return StatusOk;
                case CheckState.Degraded: return StatusDegraded;
                case CheckState.Missing: return StatusMissing;
                default: return StatusChecking;
            }
        }

        /// <summary>状态颜色：绿 / 琥珀 / 红 / 灰（仅展示用）。</summary>
        public static Color StatusColor(CheckState state)
        {
            switch (state)
            {
                case CheckState.Ok: return Color.FromArgb(21, 128, 61);
                case CheckState.Degraded: return Color.FromArgb(180, 83, 9);
                case CheckState.Missing: return Color.FromArgb(185, 28, 28);
                default: return Color.FromArgb(107, 114, 128);
            }
        }

        /// <summary>是否需要「以管理员身份重启」：权限项已确认不是 ✓（检查中不算）。</summary>
        public static bool ShowElevate(PreflightData data)
        {
            if (data == null) return false;
            SplashItem admin = data.Get("admin");
            return admin != null
                && (admin.State == CheckState.Degraded || admin.State == CheckState.Missing);
        }

        /// <summary>是否需要「继续使用降级功能」：任何一项已确认不是 ✓ 都需要给这个出口。</summary>
        public static bool ShowContinue(PreflightData data)
        {
            if (data == null) return false;
            for (int i = 0; i < data.Items.Count; i++)
            {
                CheckState state = data.Items[i].State;
                if (state == CheckState.Degraded || state == CheckState.Missing) return true;
            }
            return false;
        }

        /// <summary>
        /// 「打开官网」按钮的目标：按固定顺序取第一个带修复 URL 的失败项。
        /// 只认后端下发的 fix_url（不在 C# 里写死官网地址）。
        /// </summary>
        public static string InstallUrl(PreflightData data)
        {
            if (data == null) return "";
            for (int i = 0; i < CheckOrder.Length; i++)
            {
                SplashItem item = data.Get(CheckOrder[i]);
                if (item == null || item.State == CheckState.Ok) continue;
                if (!string.IsNullOrEmpty(item.FixUrl)) return item.FixUrl;
            }
            foreach (KeyValuePair<string, string> pair in data.FixUrls)
                if (!string.IsNullOrEmpty(pair.Value)) return pair.Value;
            return "";
        }

        /// <summary>「打开官网」按钮文案：尽量说清打开谁的官网。</summary>
        public static string InstallLabel(PreflightData data)
        {
            if (data == null) return "打开官网";
            SplashItem item = data.Get("tshark");
            if (item != null && item.State == CheckState.Missing
                && !string.IsNullOrEmpty(item.FixUrl)) return "打开 Wireshark 官网";
            item = data.Get("npcap");
            if (item != null && item.State == CheckState.Missing
                && !string.IsNullOrEmpty(item.FixUrl)) return "打开 Npcap 官网";
            item = data.Get("python");
            if (item != null && item.State == CheckState.Missing
                && !string.IsNullOrEmpty(item.FixUrl)) return "打开 Python 官网";
            return "打开官网";
        }

        /// <summary>把一项的界面状态写成 JSON（--splash-test 产出，Python 测试据此断言映射）。</summary>
        public static string ItemJson(SplashItem item)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("{\"key\":\"").Append(JsonEscape(item.Key)).Append('"');
            sb.Append(",\"name\":\"").Append(JsonEscape(item.Name)).Append('"');
            sb.Append(",\"state\":\"").Append(StateCode(item.State)).Append('"');
            sb.Append(",\"status\":\"").Append(JsonEscape(StatusText(item.State))).Append('"');
            sb.Append(",\"summary\":\"").Append(JsonEscape(item.Summary)).Append('"');
            sb.Append(",\"fix_url\":\"").Append(JsonEscape(item.FixUrl)).Append('"').Append('}');
            return sb.ToString();
        }

        /// <summary>机器可读状态码：ok / degraded / missing / checking（tests 用）。</summary>
        public static string StateCode(CheckState state)
        {
            switch (state)
            {
                case CheckState.Ok: return "ok";
                case CheckState.Degraded: return "degraded";
                case CheckState.Missing: return "missing";
                default: return "checking";
            }
        }

        /// <summary>构造 --splash-test 的四种场景数据（只在测试/截图路径使用）。</summary>
        public static PreflightData Scenario(string name)
        {
            PreflightData data = new PreflightData();
            data.Version = "-";
            data.Source = "selfcheck";
            for (int i = 0; i < CheckOrder.Length; i++)
            {
                SplashItem item = new SplashItem();
                item.Key = CheckOrder[i];
                item.Name = DisplayName(item.Key);
                item.State = CheckState.Ok;
                item.Detail = OkText(item.Key);
                item.Impact = ImpactText(item.Key);
                data.Items.Add(item);
            }
            if (name == "loading")
            {
                data = new PreflightData();
                data.Version = "-";
                // 服务未起：只填启动器本地确实知道的两项，其余显示「检查中…」。
                SplashItem python = new SplashItem();
                python.Key = "python"; python.Name = DisplayName("python");
                python.State = CheckState.Ok; python.Detail = "已定位 Python，正在启动本地服务";
                data.Items.Add(python);
                SplashItem port = new SplashItem();
                port.Key = "port"; port.Name = DisplayName("port");
                port.State = CheckState.Checking;
                data.Items.Add(port);
                for (int i = 0; i < CheckOrder.Length; i++)
                {
                    if (CheckOrder[i] == "python" || CheckOrder[i] == "port") continue;
                    SplashItem item = new SplashItem();
                    item.Key = CheckOrder[i]; item.Name = DisplayName(item.Key);
                    item.State = CheckState.Checking;
                    data.Items.Add(item);
                }
                // 顺序统一成 CHECK_KEYS，界面不因构造顺序跳动。
                data.Items.Sort(delegate(SplashItem a, SplashItem b)
                {
                    return Array.IndexOf(CheckOrder, a.Key).CompareTo(Array.IndexOf(CheckOrder, b.Key));
                });
                data.Ok = false;
                return data;
            }
            if (name == "missing_tshark")
            {
                Set(data, "tshark", false, "未找到 tshark：实时抓包 / 通信观察 / 分析抓包文件不可用",
                    "实时抓包、通信观察、分析抓包文件不可用", "url",
                    "https://www.wireshark.org/download.html");
                Set(data, "scapy", false, "没有内置 scapy：逐跳自动降级为系统 tracert",
                    "逐跳样本更少、精度降低（仍可用）", "none", "");
                data.Ok = false;
            }
            else if (name == "non_admin")
            {
                Set(data, "admin", false, "当前不是管理员：实时抓包与通信观察需要按需提权",
                    "实时抓包 / 通信观察需要管理员权限；离线分析与体检可用", "elevate", "");
                data.Ok = false;
            }
            return data;
        }

        private static void Set(PreflightData data, string key, bool ok, string detail,
                                string impact, string fixKind, string fixUrl)
        {
            SplashItem item = data.Get(key);
            if (item == null) return;
            item.State = MapStatus(key, ok);
            item.Detail = detail;
            item.Impact = impact;
            item.FixKind = fixKind;
            item.FixUrl = fixUrl;
            if (!string.IsNullOrEmpty(fixUrl)) data.FixUrls[key] = fixUrl;
            data.Ok = false;
        }

        /// <summary>六项的中文名（与 copy/zh-CN.json 的 startup.check_* 同口径）。</summary>
        public static string DisplayName(string key)
        {
            switch (key)
            {
                case "python": return "Python";
                case "tshark": return "tshark（Wireshark）";
                case "npcap": return "Npcap 抓包驱动";
                case "scapy": return "scapy 逐跳引擎";
                case "port": return "本地端口 8787~8796";
                case "admin": return "管理员权限";
                default: return key;
            }
        }

        private static string OkText(string key)
        {
            switch (key)
            {
                case "python": return "已找到 Python 3.11+";
                case "tshark": return "已找到 tshark";
                case "npcap": return "Npcap 驱动已就绪";
                case "scapy": return "scapy 可用（逐跳更准）";
                case "port": return "本地端口可用";
                case "admin": return "当前以管理员权限运行";
                default: return "可用";
            }
        }

        private static string ImpactText(string key)
        {
            switch (key)
            {
                case "python": return "没有 Python 就无法启动本地界面";
                case "tshark": return "实时抓包 / 通信观察 / 分析抓包文件不可用";
                case "npcap": return "实时抓包与通信观察不可用（离线分析不需要）";
                case "scapy": return "逐跳自动降级为系统 tracert（仍然可用）";
                case "port": return "8787~8796 全被占用时界面打不开";
                case "admin": return "实时抓包 / 通信观察需按需提权；其余功能可用";
                default: return "";
            }
        }

        /// <summary>JSON 字符串转义（与 launcher 的写日志共用同一套规则）。</summary>
        public static string JsonEscape(string text)
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
    }

    /// <summary>
    /// 启动等待窗口。正常启动时由 NetDiagLauncher 创建并 Show()，后台线程通过
    /// <see cref="ApplyPreflight"/> 更新；--splash-test 时只创建、渲染、释放，不显示。
    /// </summary>
    internal sealed class SplashForm : Form
    {
        private const int FormWidth = 820;
        private const int FormHeight = 540;
        private const int MaxRows = 6;

        private readonly Label _title;
        private readonly Label _subtitle;
        private readonly ProgressBar _progress;
        private readonly Panel _accent;
        private readonly TableLayoutPanel _grid;
        private readonly Label _elapsed;
        private readonly Label _message;
        private readonly FlowLayoutPanel _actions;
        private readonly Button _skipButton;
        private readonly Button _continueButton;
        private readonly Button _installButton;
        private readonly Button _elevateButton;
        private readonly Button _closeButton;
        private readonly Timer _timer;
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private readonly Label[] _statusLabels = new Label[MaxRows];
        private readonly Label[] _nameLabels = new Label[MaxRows];
        private readonly Label[] _detailLabels = new Label[MaxRows];

        private PreflightData _data = new PreflightData();
        private long _elapsedOffsetMs;
        private long _frozenElapsedMs = -1;
        private bool _firstRunHint;
        private string _scenario = "";
        private string _fatalInstallUrl = "";

        // 由按钮直接置位；后台线程/主循环只读，volatile 足够（没有复合状态）。
        public volatile bool ProceedRequested;
        public volatile bool ElevateRequested;
        public volatile bool CloseRequested;

        public SplashForm(bool firstRunHint, long elapsedOffsetMs)
        {
            _firstRunHint = firstRunHint;
            _elapsedOffsetMs = Math.Max(0, elapsedOffsetMs);

            Text = "NetDiag · 网络矩阵";
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.White;
            ShowInTaskbar = true;
            MaximizeBox = false;
            MinimizeBox = false;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            ClientSize = new Size(FormWidth, FormHeight);
            DoubleBuffered = true;
            KeyPreview = true;

            _accent = new Panel();
            _accent.BackColor = Color.FromArgb(15, 118, 110);
            _accent.Bounds = new Rectangle(0, 0, FormWidth, 6);
            Controls.Add(_accent);

            _title = new Label();
            _title.Text = "NetDiag · 网络矩阵";
            _title.Font = new Font("Microsoft YaHei UI", 22F, FontStyle.Bold);
            _title.ForeColor = Color.FromArgb(17, 24, 39);
            _title.Bounds = new Rectangle(30, 22, 700, 42);
            Controls.Add(_title);

            _subtitle = new Label();
            _subtitle.Text = firstRunHint
                ? "正在加载组件（首次可能较慢）…"
                : "正在准备本地服务…";
            _subtitle.Font = new Font("Microsoft YaHei UI", 11F);
            _subtitle.ForeColor = Color.FromArgb(75, 85, 99);
            _subtitle.Bounds = new Rectangle(32, 66, 700, 26);
            Controls.Add(_subtitle);

            _progress = new ProgressBar();
            _progress.Style = ProgressBarStyle.Marquee;
            _progress.MarqueeAnimationSpeed = 30;
            _progress.Bounds = new Rectangle(32, 100, FormWidth - 64, 16);
            Controls.Add(_progress);

            _grid = new TableLayoutPanel();
            _grid.Bounds = new Rectangle(32, 132, FormWidth - 64, 6 * 34);
            _grid.ColumnCount = 3;
            _grid.RowCount = MaxRows;
            _grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 26F));
            _grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 214F));
            _grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            for (int i = 0; i < MaxRows; i++) _grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 34F));
            _grid.BackColor = Color.White;
            Controls.Add(_grid);

            Font rowFont = new Font("Microsoft YaHei UI", 10.5F);
            for (int i = 0; i < MaxRows; i++)
            {
                _statusLabels[i] = new Label();
                _statusLabels[i].Font = new Font("Microsoft YaHei UI", 11F, FontStyle.Bold);
                _statusLabels[i].AutoSize = false;
                _statusLabels[i].Dock = DockStyle.Fill;
                _statusLabels[i].TextAlign = ContentAlignment.MiddleLeft;
                _statusLabels[i].Text = "…";
                _grid.Controls.Add(_statusLabels[i], 0, i);

                _nameLabels[i] = new Label();
                _nameLabels[i].Font = rowFont;
                _nameLabels[i].ForeColor = Color.FromArgb(31, 41, 55);
                _nameLabels[i].AutoSize = false;
                _nameLabels[i].Dock = DockStyle.Fill;
                _nameLabels[i].TextAlign = ContentAlignment.MiddleLeft;
                _nameLabels[i].Text = SplashLogic.DisplayName(SplashLogic.CheckOrder[i]);
                _grid.Controls.Add(_nameLabels[i], 1, i);

                _detailLabels[i] = new Label();
                _detailLabels[i].Font = new Font("Microsoft YaHei UI", 9.5F);
                _detailLabels[i].ForeColor = Color.FromArgb(55, 65, 81);
                _detailLabels[i].AutoSize = false;
                _detailLabels[i].Dock = DockStyle.Fill;
                _detailLabels[i].TextAlign = ContentAlignment.MiddleLeft;
                _detailLabels[i].Text = "检查中…";
                _grid.Controls.Add(_detailLabels[i], 2, i);
            }

            _elapsed = new Label();
            _elapsed.Font = new Font("Microsoft YaHei UI", 10F);
            _elapsed.ForeColor = Color.FromArgb(107, 114, 128);
            _elapsed.Bounds = new Rectangle(32, 344, 360, 24);
            _elapsed.Text = "已用时 0.0s";
            Controls.Add(_elapsed);

            _message = new Label();
            _message.Font = new Font("Microsoft YaHei UI", 10F);
            _message.ForeColor = Color.FromArgb(180, 83, 9);
            _message.Bounds = new Rectangle(32, 372, FormWidth - 64, 44);
            _message.Text = "";
            Controls.Add(_message);

            _actions = new FlowLayoutPanel();
            _actions.FlowDirection = FlowDirection.RightToLeft;
            _actions.WrapContents = false;
            _actions.Bounds = new Rectangle(32, 438, FormWidth - 64, 46);
            _actions.BackColor = Color.White;
            Controls.Add(_actions);

            _skipButton = MakeButton("跳过检查");
            _skipButton.Click += delegate { ProceedRequested = true; };
            _actions.Controls.Add(_skipButton);

            _closeButton = MakeButton("关闭");
            ShowButton(_closeButton, false);
            _closeButton.Click += delegate { CloseRequested = true; ProceedRequested = true; };
            _actions.Controls.Add(_closeButton);

            _continueButton = MakeButton("继续使用降级功能");
            ShowButton(_continueButton, false);
            _continueButton.Click += delegate { ProceedRequested = true; };
            _actions.Controls.Add(_continueButton);

            _elevateButton = MakeButton("以管理员身份重启");
            ShowButton(_elevateButton, false);
            _elevateButton.Click += delegate { ElevateRequested = true; };
            _actions.Controls.Add(_elevateButton);

            _installButton = MakeButton("打开官网");
            ShowButton(_installButton, false);
            _installButton.Click += delegate
            {
                string url = !string.IsNullOrEmpty(_fatalInstallUrl)
                    ? _fatalInstallUrl
                    : SplashLogic.InstallUrl(_data);
                if (string.IsNullOrEmpty(url)) return;
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo(url);
                    psi.UseShellExecute = true;   // 用户主动点按钮才打开官网
                    Process.Start(psi);
                }
                catch (Exception) { }
            };
            _actions.Controls.Add(_installButton);

            _timer = new Timer();
            _timer.Interval = 100;
            _timer.Tick += delegate { UpdateElapsedLabel(); };
            _timer.Start();

            KeyDown += delegate(object sender, KeyEventArgs e)
            {
                // ESC 跳过检查，直接进 UI（检查结果由界面首屏自检显示）。
                if (e.KeyCode == Keys.Escape) ProceedRequested = true;
            };

            ApplyData(_data);   // 初始占位：全部「检查中…」+ Python 占位由 launcher 填入
        }

        public long ElapsedMs
        {
            get
            {
                if (_frozenElapsedMs >= 0) return _frozenElapsedMs;
                return _elapsedOffsetMs + _clock.ElapsedMilliseconds;
            }
        }

        private static Button MakeButton(string text)
        {
            Button button = new Button();
            button.Text = text;
            button.AutoSize = true;
            button.MinimumSize = new Size(108, 34);
            button.FlatStyle = FlatStyle.System;
            button.Font = new Font("Microsoft YaHei UI", 10F);
            button.Margin = new Padding(6, 0, 0, 0);
            // Tag 记「设计上的可见性」：窗体隐藏时 Control.Visible 会跟着变 false，
            // --splash-test 的状态 JSON 需要的是「用户看到时会不会有这个按钮」。
            button.Tag = "";
            return button;
        }

        /// <summary>设置按钮可见性并记录设计意图（StateJson 不依赖窗体当前是否显示）。</summary>
        private static void ShowButton(Button button, bool visible)
        {
            if (button == null) return;
            button.Visible = visible;
            button.Tag = visible ? "1" : "";
        }

        /// <summary>把当前数据画到六个固定行（缺项显示「检查中…」，不隐藏行以免跳动）。</summary>
        private void ApplyData(PreflightData data)
        {
            _data = data ?? new PreflightData();
            for (int i = 0; i < MaxRows; i++)
            {
                string key = SplashLogic.CheckOrder[i];
                SplashItem item = _data.Get(key);
                if (item == null)
                {
                    _statusLabels[i].Text = "…";
                    _statusLabels[i].ForeColor = Color.FromArgb(156, 163, 175);
                    _detailLabels[i].Text = "检查中…";
                }
                else
                {
                    _statusLabels[i].Text = StatusSymbol(item.State);
                    _statusLabels[i].ForeColor = SplashLogic.StatusColor(item.State);
                    _detailLabels[i].Text = item.Summary;
                    _detailLabels[i].ForeColor = item.State == CheckState.Missing
                        ? Color.FromArgb(153, 27, 27)
                        : Color.FromArgb(55, 65, 81);
                }
            }

            bool needContinue = SplashLogic.ShowContinue(_data);
            string installUrl = SplashLogic.InstallUrl(_data);
            ShowButton(_installButton, !string.IsNullOrEmpty(installUrl));
            _installButton.Text = SplashLogic.InstallLabel(_data);
            ShowButton(_elevateButton, SplashLogic.ShowElevate(_data));
            ShowButton(_continueButton, needContinue);
            // 全部 ✓ 时自动进界面，不再摆一个多余的「跳过检查」。
            ShowButton(_skipButton, !(_data != null && _data.Ok));
            // 只有失败/降级时才允许「关闭」；全绿自动进入，不给用户多一个选择。
            ShowButton(_closeButton, false);
            Invalidate();
        }

        private static string StatusSymbol(CheckState state)
        {
            switch (state)
            {
                case CheckState.Ok: return "✓";
                case CheckState.Degraded: return "⚠";
                case CheckState.Missing: return "✗";
                default: return "…";
            }
        }

        public void SetItem(string key, CheckState state, string detail)
        {
            PreflightData data = _data ?? new PreflightData();
            SplashItem item = data.Get(key);
            if (item == null)
            {
                item = new SplashItem();
                item.Key = key;
                item.Name = SplashLogic.DisplayName(key);
                item.Impact = "";
                data.Items.Add(item);
            }
            item.State = state;
            item.Detail = detail ?? "";
            data.Ok = false;
            ApplyData(data);
        }

        public void SetMessage(string message)
        {
            _message.Text = message ?? "";
        }

        public void SetSubtitle(string text)
        {
            _subtitle.Text = text ?? "";
        }

        public void ApplyPreflight(PreflightData data)
        {
            if (data == null) return;
            ApplyData(data);
            _progress.Style = data.Ok ? ProgressBarStyle.Blocks : ProgressBarStyle.Continuous;
            _progress.Value = 100;
            if (data.Ok)
            {
                SetSubtitle("准备完成，正在打开界面…");
            }
            else
            {
                int failures = 0, degraded = 0;
                for (int i = 0; i < data.Items.Count; i++)
                {
                    if (data.Items[i].State == CheckState.Missing) failures++;
                    else if (data.Items[i].State == CheckState.Degraded) degraded++;
                }
                if (failures > 0)
                    SetSubtitle("有 " + failures + " 项需要处理，可安装后重启，或继续使用可用功能");
                else if (degraded > 0)
                    SetSubtitle("部分功能降级（" + degraded + " 项），其余功能正常");
                else
                    SetSubtitle("检查完成");
                SetMessage("组件缺失或权限受限都不影响启动：界面里会显示同样的检查结果与修复入口。");
            }
        }

        /// <summary>复用已有实例：不跑检查，直接显示「复用已运行服务」。</summary>
        public void ShowReuse(string url)
        {
            _scenario = "reuse";
            _grid.Visible = false;
            _progress.Visible = false;
            _elapsed.Bounds = new Rectangle(32, 160, 360, 28);
            _message.Bounds = new Rectangle(32, 196, FormWidth - 64, 60);
            _subtitle.Text = "复用已运行服务";
            _message.Text = "已有 NetDiag 在运行：" + url + "\n不会重复启动新进程，直接打开界面。";
            _message.ForeColor = Color.FromArgb(15, 118, 110);
            ShowButton(_skipButton, false);
            ShowButton(_continueButton, false);
            ShowButton(_installButton, false);
            ShowButton(_elevateButton, false);
            ShowButton(_closeButton, false);
            _title.Text = "NetDiag · 网络矩阵";
        }

        /// <summary>启动失败（无 Python / 端口全占 / 服务未就绪）：只给安装与关闭两个出口。</summary>
        public void SetFatal(string message, string installUrl, string installLabel)
        {
            _scenario = "fatal";
            _grid.Visible = false;
            _progress.Style = ProgressBarStyle.Continuous;
            _progress.Value = 0;
            _subtitle.Text = "启动未完成";
            _subtitle.ForeColor = Color.FromArgb(185, 28, 28);
            _message.ForeColor = Color.FromArgb(153, 27, 27);
            _message.Text = message ?? "";
            ShowButton(_skipButton, false);
            ShowButton(_continueButton, false);
            ShowButton(_elevateButton, false);
            ShowButton(_installButton, !string.IsNullOrEmpty(installUrl));
            _installButton.Text = string.IsNullOrEmpty(installLabel) ? "打开官网" : installLabel;
            _fatalInstallUrl = installUrl ?? "";
            ShowButton(_closeButton, true);
        }

        private void UpdateElapsedLabel()
        {
            double seconds = ElapsedMs / 1000.0;
            _elapsed.Text = string.Format(CultureInfo.InvariantCulture, "已用时 {0:F1}s", seconds);
        }

        /// <summary>冻结已用时（--splash-test 截图用固定值，不依赖真实时钟）。</summary>
        public void FreezeElapsed(long milliseconds)
        {
            _frozenElapsedMs = Math.Max(0, milliseconds);
            UpdateElapsedLabel();
        }

        /// <summary>
        /// 离屏渲染成 PNG：供 --splash-test / 证据截图使用。
        ///
        /// WinForms 的 DrawToBitmap 对「从未显示过」的窗体只画背景（子控件没有
        /// 布局/绘制上下文）。这里把窗口短暂放到屏幕外 (-32000, -32000) 并
        /// ShowInTaskbar=false 后再渲染：用户看不到任何窗口，也不会闪屏；
        /// 渲染完立即 Hide 并恢复原位置。--splash-test 全程不打开浏览器。
        /// </summary>
        public void RenderToBitmap(string path)
        {
            bool alreadyVisible = Visible;
            bool oldTaskbar = ShowInTaskbar;
            FormStartPosition oldStart = StartPosition;
            Point oldLocation = Location;
            if (!alreadyVisible)
            {
                ShowInTaskbar = false;
                StartPosition = FormStartPosition.Manual;
                Location = new Point(-32000, -32000);
                Show();
                Application.DoEvents();
                PerformLayout();
                for (int i = 0; i < Controls.Count; i++) Controls[i].PerformLayout();
            }
            try
            {
                using (Bitmap bitmap = new Bitmap(Width, Height, PixelFormat.Format32bppArgb))
                {
                    DrawToBitmap(bitmap, new Rectangle(0, 0, Width, Height));
                    bitmap.Save(path, ImageFormat.Png);
                }
            }
            finally
            {
                if (!alreadyVisible)
                {
                    Hide();
                    ShowInTaskbar = oldTaskbar;
                    StartPosition = oldStart;
                    Location = oldLocation;
                }
            }
        }

        /// <summary>当前界面的机器可读状态（--splash-test 写入 splash-states.json）。</summary>
        public string StateJson()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("{\"scenario\":\"").Append(SplashLogic.JsonEscape(_scenario)).Append('"');
            sb.Append(",\"first_run_hint\":").Append(_firstRunHint ? "true" : "false");
            sb.Append(",\"elapsed_s\":")
              .Append((ElapsedMs / 1000.0).ToString("F2", CultureInfo.InvariantCulture));
            sb.Append(",\"subtitle\":\"").Append(SplashLogic.JsonEscape(_subtitle.Text)).Append('"');
            sb.Append(",\"message\":\"").Append(SplashLogic.JsonEscape(_message.Text)).Append('"');
            sb.Append(",\"all_ok\":").Append(_data != null && _data.Ok ? "true" : "false");
            sb.Append(",\"items\":[");
            for (int i = 0; i < (_data == null ? 0 : _data.Items.Count); i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(SplashLogic.ItemJson(_data.Items[i]));
            }
            sb.Append("],\"buttons\":[");
            bool first = true;
            AppendButton(sb, ref first, "skip", _skipButton);
            AppendButton(sb, ref first, "continue", _continueButton);
            AppendButton(sb, ref first, "install", _installButton);
            AppendButton(sb, ref first, "elevate", _elevateButton);
            AppendButton(sb, ref first, "close", _closeButton);
            sb.Append("]}");
            return sb.ToString();
        }

        private static void AppendButton(StringBuilder sb, ref bool first, string name, Button button)
        {
            if (button == null) return;
            string flag = button.Tag as string;
            if (flag != "1") return;
            if (!first) sb.Append(',');
            first = false;
            sb.Append('"').Append(name).Append('"');
        }

        /// <summary>--splash-test 场景设置：固定状态 + 冻结耗时，保证截图可复现。</summary>
        public void ApplyScenario(string name, long elapsedMs)
        {
            _scenario = name;
            FreezeElapsed(elapsedMs);
            PreflightData data = SplashLogic.Scenario(name);
            if (name == "loading")
            {
                ApplyData(data);
                SetSubtitle("正在加载组件（首次可能较慢）…");
                _message.Text = "启动器正在定位 Python 并等待本地服务就绪…";
                _message.ForeColor = Color.FromArgb(107, 114, 128);
                // 截图为可复现证据：用固定 30% 的进度代替运行时的 Marquee 动画，
                // 避免同一份证据每次渲染出不同的动画帧。
                _progress.Style = ProgressBarStyle.Continuous;
                _progress.Value = 30;
            }
            else if (name == "all_green")
            {
                ApplyData(data);
                data.Ok = true;
                ApplyPreflight(data);
            }
            else if (name == "missing_tshark")
            {
                ApplyPreflight(data);
            }
            else if (name == "non_admin")
            {
                ApplyPreflight(data);
            }
            else
            {
                ApplyData(data);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _timer.Stop();
                _timer.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// 极小 JSON 解析器。为什么不用第三方库：启动器只允许系统 .NET Framework
    /// 自带程序集（发布包不带 DLL）；为什么不用正则硬抠：preflight 的 detail
    /// 文案会变长、包含引号/转义，正则迟早抠错。这里只实现 RFC 8259 的子集：
    /// object / array / string / number / true / false / null，足够读本地接口。
    /// </summary>
    internal static class MiniJson
    {
        public static object Parse(string text)
        {
            if (text == null) throw new ArgumentNullException("text");
            int index = 0;
            object value = ParseValue(text, ref index);
            SkipWhitespace(text, ref index);
            if (index != text.Length)
                throw new FormatException("JSON 末尾有多余内容（位置 " + index + "）");
            return value;
        }

        private static object ParseValue(string text, ref int index)
        {
            SkipWhitespace(text, ref index);
            if (index >= text.Length) throw new FormatException("JSON 意外结束");
            char c = text[index];
            if (c == '{') return ParseObject(text, ref index);
            if (c == '[') return ParseArray(text, ref index);
            if (c == '"') return ParseString(text, ref index);
            if (c == 't') { Expect(text, ref index, "true"); return true; }
            if (c == 'f') { Expect(text, ref index, "false"); return false; }
            if (c == 'n') { Expect(text, ref index, "null"); return null; }
            if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber(text, ref index);
            throw new FormatException("JSON 非法字符 '" + c + "'（位置 " + index + "）");
        }

        private static Dictionary<string, object> ParseObject(string text, ref int index)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.Ordinal);
            index++; // {
            SkipWhitespace(text, ref index);
            if (index < text.Length && text[index] == '}') { index++; return result; }
            while (true)
            {
                SkipWhitespace(text, ref index);
                if (index >= text.Length || text[index] != '"')
                    throw new FormatException("JSON 对象键必须是字符串（位置 " + index + "）");
                string key = ParseString(text, ref index);
                SkipWhitespace(text, ref index);
                if (index >= text.Length || text[index] != ':')
                    throw new FormatException("JSON 对象缺少 ':'（位置 " + index + "）");
                index++;
                result[key] = ParseValue(text, ref index);
                SkipWhitespace(text, ref index);
                if (index >= text.Length) throw new FormatException("JSON 对象未闭合");
                if (text[index] == ',') { index++; continue; }
                if (text[index] == '}') { index++; return result; }
                throw new FormatException("JSON 对象非法分隔符（位置 " + index + "）");
            }
        }

        private static List<object> ParseArray(string text, ref int index)
        {
            List<object> result = new List<object>();
            index++; // [
            SkipWhitespace(text, ref index);
            if (index < text.Length && text[index] == ']') { index++; return result; }
            while (true)
            {
                result.Add(ParseValue(text, ref index));
                SkipWhitespace(text, ref index);
                if (index >= text.Length) throw new FormatException("JSON 数组未闭合");
                if (text[index] == ',') { index++; continue; }
                if (text[index] == ']') { index++; return result; }
                throw new FormatException("JSON 数组非法分隔符（位置 " + index + "）");
            }
        }

        private static string ParseString(string text, ref int index)
        {
            index++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (index < text.Length)
            {
                char c = text[index++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (index >= text.Length) throw new FormatException("JSON 字符串转义未完成");
                char esc = text[index++];
                switch (esc)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (index + 4 > text.Length) throw new FormatException("JSON \\u 转义不完整");
                        sb.Append((char)Convert.ToInt32(text.Substring(index, 4), 16));
                        index += 4;
                        break;
                    default: throw new FormatException("JSON 非法转义 \\" + esc);
                }
            }
            throw new FormatException("JSON 字符串未闭合");
        }

        private static double ParseNumber(string text, ref int index)
        {
            int start = index;
            if (index < text.Length && text[index] == '-') index++;
            while (index < text.Length && "0123456789.eE+-".IndexOf(text[index]) >= 0) index++;
            string raw = text.Substring(start, index - start);
            double value;
            if (!double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out value))
                throw new FormatException("JSON 数字非法：" + raw);
            return value;
        }

        private static void Expect(string text, ref int index, string token)
        {
            if (index + token.Length > text.Length
                || string.CompareOrdinal(text, index, token, 0, token.Length) != 0)
                throw new FormatException("JSON 期望 " + token + "（位置 " + index + "）");
            index += token.Length;
        }

        private static void SkipWhitespace(string text, ref int index)
        {
            while (index < text.Length)
            {
                char c = text[index];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') index++;
                else break;
            }
        }

        public static Dictionary<string, object> AsObject(object value)
        {
            return value as Dictionary<string, object>;
        }

        public static List<object> AsArray(object value)
        {
            return value as List<object>;
        }

        public static string GetString(Dictionary<string, object> obj, string key, string fallback)
        {
            if (obj == null) return fallback;
            object value;
            if (!obj.TryGetValue(key, out value) || value == null) return fallback;
            string text = value as string;
            return text ?? Convert.ToString(value, CultureInfo.InvariantCulture);
        }

        public static bool GetBool(Dictionary<string, object> obj, string key, bool fallback)
        {
            if (obj == null) return fallback;
            object value;
            if (!obj.TryGetValue(key, out value) || value == null) return fallback;
            if (value is bool) return (bool)value;
            string text = value as string;
            if (text != null) return text == "true" || text == "1";
            return fallback;
        }

        public static List<object> GetArray(Dictionary<string, object> obj, string key)
        {
            if (obj == null) return new List<object>();
            object value;
            if (!obj.TryGetValue(key, out value)) return new List<object>();
            return value as List<object> ?? new List<object>();
        }

        public static Dictionary<string, object> GetObject(Dictionary<string, object> obj, string key)
        {
            if (obj == null) return null;
            object value;
            if (!obj.TryGetValue(key, out value)) return null;
            return value as Dictionary<string, object>;
        }
    }
}
