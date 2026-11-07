# 日志与现场记录（M1 日志基建）

> 实现：`core/logstore.py` 是**唯一日志出口**。`core/app.py` 的 `redirect_output()`、
> `core/diagnose.py` 的 `_log_to_file()`、`core/server.py` 的 `log()` 都只做委托，
> 调用方的签名没有变。
>
> 为什么要这么做：程序分发出去后**不会联网上报**（用户明确要求）。排障只能靠
> 「把 `logs/` 带回来」，所以日志必须结构稳定、有上限、能回答
> 「谁在什么环境跑了什么」。

## 一、目录长什么样

启动（`app.py` / `server.py` / `diagnose.py`）时依次执行
`ensure_dirs() → prune() → write_env_snapshot() → install_excepthooks()`，
跑完一次分析后目录如下：

```
logs/
├─ app-YYYYMMDD.log    启动器日志：pythonw 下的 stdout/stderr（print 原样落盘）
├─ diag-YYYYMMDD.log   诊断/服务运行日志：diagnose.log()、server.log()、traceback
├─ env.json            本次启动的环境快照（覆盖写，只保留最近一次）
├─ runs/               每次分析一条 JSON：<ts>-<8位随机>.json
│   └─ 20261107-193245-a1b2c3d4.json
└─ crashes/            崩溃快照
    ├─ 20261107-193301.txt          Python 未捕获异常（主线程 / 子线程）
    └─ fatal-20261107-193200.log    faulthandler：进程级崩溃（段错误/栈溢出等）
```

时间标记统一：

| 位置 | 格式 | 例 |
|---|---|---|
| 日文件名 | `%Y%m%d` | `app-20261107.log` |
| `runs/` 文件名 | `%Y%m%d-%H%M%S` + 8 位随机十六进制 | `20261107-193245-a1b2c3d4.json` |
| `crashes/*.txt` | `%Y%m%d-%H%M%S`（同秒冲突时加 `-2`） | `20261107-193301.txt` |
| `crashes/fatal-*.log` | `fatal-%Y%m%d-%H%M%S.log` | `fatal-20261107-193200.log` |

日文件里的行格式固定为：

```
[HH:MM:SS] [INFO] 正文
```

多行内容（例如 traceback）逐行加前缀；**同一进程内日志句柄只打开一次**，
不会每次 `print` 都开文件。Windows 文件名里不会出现 `:`。

## 二、env.json：这台机器是什么环境

每次启动覆盖写，字段（缺一项都算 bug）：

```json
{
  "version": "0.1.0",
  "windows": "Windows-11-10.0.22631-SP0",
  "windows_version": "10.0.22631",
  "admin": true,
  "npcap": true,
  "tshark_version": "TShark (Wireshark) 4.7.4 (v4.7.4-0-g3261ea7f570f).",
  "tshark_path": "D:\\utest\\NetDiag\\tools\\WiresharkPortable\\App\\Wireshark\\tshark.exe",
  "python_version": "3.11.9",
  "console_encoding": "utf-8",
  "config_sha256": "…（app-config + 规则阈值的联合哈希，不含 AI Key）",
  "started_at": "2026-11-07T19:32:45+08:00",
  "entry": "server"
}
```

* `config_sha256` 用于回答「同一份抓包为什么两次结论不同」：先比配置指纹；
  它**不哈希 AI Key**（见 `core/config.py` 的 `config_sha256()`）。
* `entry` 是本次启动入口（`app` / `server` / `diagnose`），方便对账。
* 干净 checkout（没有 `tools/`）里 `tshark_version` 是 `未找到 tshark`，
  `tshark_path` 为空串 —— 这是合法快照，不是错误。

## 三、runs/：每次分析一条记录

触发点：

| mode | 入口 | 说明 |
|---|---|---|
| `live` | `diagnose.run_scan()`（无 `pcap`） | CLI 实时抓包；UI 的 `/api/scan`（live/scan）也走它 |
| `offline` | `diagnose.run_scan(pcap=...)` | CLI `--pcap` / UI 离线分析 / MCP `analyze_pcap` |
| `passive` | `server._passive_worker()` | UI 被动监听 |
| `probe` | `server._probe_guarded()` | UI 链路体检 |

**一次分析只写一条记录**：UI 的 `/api/scan` 经 `server._worker → diagnose.run_scan`，
记录在 `run_scan` 里统一产生，`_worker` 不再重复写。

示例（`runs/20261107-193245-a1b2c3d4.json`）：

```json
{
  "mode": "offline",
  "params": {
    "target": "192.168.1.10",
    "duration": 0,
    "interface": "",
    "pcap": "faults_demo.pcap"
  },
  "duration_ms": 842,
  "level": "警告",
  "critical": 3,
  "warning": 5,
  "sufficiency_ok": true,
  "error_code": "",
  "tshark_version": "TShark (Wireshark) 4.7.4 (v4.7.4-0-g3261ea7f570f).",
  "ok": true
}
```

字段含义：

| 字段 | 说明 |
|---|---|
| `mode` | `live` / `offline` / `passive` / `probe` |
| `params` | 本次参数。**只留目标、时长、网卡、pcap 文件名**；不写绝对路径（防隐私泄漏，M2 还会再脱敏） |
| `duration_ms` | 本次从开始到结束的毫秒数 |
| `level` | `verdict.level`（严重/警告/提示/正常/证据不足）；失败时为空串 |
| `critical` / `warning` | 报告里的严重/警告条数（被动监听与体检没有这两类计数，为 0） |
| `sufficiency_ok` | 证据是否充分（`verdict.sufficiency.ok`）；被动监听/体检按「本次是否成功」记 |
| `error_code` | 失败时的稳定错误码（`E_NO_TSHARK` / `E_NO_NPCAP` / `E_NO_ADMIN` / `E_NO_INTERFACE` / `E_BAD_PCAP` / `E_INTERNAL`），成功为空串 |
| `tshark_version` | 本次运行时的 tshark 版本首行 |
| `ok` | 附加布尔：本次是否成功（便于脚本筛失败记录） |

## 四、crashes/：崩了也要留证据

* `crashes/<ts>.txt`：`sys.excepthook`（主线程）与 `threading.excepthook`（子线程）
  捕获的未捕获异常。内容依次是：时间、异常类型、消息、完整 traceback、环境摘要
  （版本 / Python / 系统 / 管理员 / Npcap / tshark 版本与路径 / 控制台编码）。
* `crashes/fatal-<ts>.log`：`faulthandler.enable(file=...)` 的输出文件。Python 层
  捕获不到的错误（段错误、栈溢出、`os._exit` 之外的硬崩溃）会写在这里。
  文件对象在 `logstore` 里持有全局引用，**不能被 GC 回收**（否则崩溃时什么都写不出来）。

两个钩子都会在记录后调用原钩子，所以控制台/事件日志里的 traceback 不会消失。

## 五、保留与裁剪（prune）

启动时执行一次（`prune()`），也可以手动调：

| 规则 | 默认值 | 行为 |
|---|---|---|
| 单文件上限 | 5 MB | 超限时**只留尾部**（约一半、从行首开始），文件名不换、目录保持干净 |
| `runs/` | 最近 200 个 | 按文件名（时间戳）保留最新，删更旧的 |
| `crashes/` | 最近 50 个 | 同上（`fatal-*.log` 也计入） |
| `logs/` 总量 | 100 MB | 最旧优先删除；**跳过 `env.json`、`netdiag.pid` 与当天的日志** |

设计约束：

* **绝不删正在写的文件**：当天的 `app-*` / `diag-*` / `fatal-*` 在总量裁剪时被跳过；
  单文件超限只截尾不删除（截完文件仍存在）。
* 先按「最旧优先」再删；单个文件失败（被占用/权限不足）只跳过，不会中断其它裁剪。
* 测试通过环境变量注入小上限即可复现，不需要真的造 100 MB 文件（见下节）。

## 六、日志根目录可注入（测试隔离）

`logstore.log_root()` 每次调用都读环境变量：

| 环境变量 | 含义 |
|---|---|
| `NETDIAG_LOG_DIR` | 日志根目录。**测试必须指到临时目录**，禁止写仓库 `logs/` |

```powershell
# 手工验证：日志写到临时目录，仓库 logs/ 一个文件都不多
$env:NETDIAG_LOG_DIR = "$env:TEMP\netdiag-logs"
tools\python\python.exe core\diagnose.py --pcap captures\faults_demo.pcap --report-out "$env:TEMP\netdiag-report"
```

整套测试有两条防线：

1. 每个涉及日志的用例在 `setUp` 里把 `NETDIAG_LOG_DIR` 指到临时目录；
2. `tests/test_zz_no_repo_logs.py` 在**整套跑完**后对比仓库 `logs/` 的文件列表
   （导入时快照 vs 结束时），有新增即失败。

## 七、怎么读这些日志

```powershell
# 最近一次环境
Get-Content logs\env.json

# 最近 10 次分析（按文件名倒序 = 时间倒序）
Get-ChildItem logs\runs | Sort-Object Name -Descending | Select-Object -First 10 |
  ForEach-Object { Get-Content $_.FullName }

# 上一次崩溃的栈
Get-ChildItem logs\crashes\*.txt | Sort-Object LastWriteTime -Descending |
  Select-Object -First 1 | Get-Content

# 今天服务日志里的错误
Select-String -Path logs\diag-*.log -Pattern "Traceback|\[ERROR\]|失败"
```

排障顺序建议：`env.json`（环境对不对）→ `runs/`（跑没跑、成没成功、多久）→
`crashes/`（崩没崩）→ 日文件（过程）。M1 只做基建，**一键导出诊断包**与脱敏在 M2。

## 八、隐私说明

* 本工具**不联网、不上传任何日志**；`logs/` 只在本机，删掉即消失。
* 日志里会出现：目标 IP/域名、网卡名、抓包文件名、错误信息、tshark 版本、
  Windows 版本、是否管理员。这些都是排障必需的最小信息。
* **不会**写入：完整 pcap 内容、报文载荷、`config/ai-config.json` 里的 Key、
  `config/app-config.json` 里的任何值（只写 `config_sha256` 指纹）。
* `runs/*.json` 的 `params` 只留 pcap 文件名，不写 `D:\...` 这类绝对路径。
* 把日志发给别人前，建议先看一眼 `env.json` 与 `runs/`：如果机器名/路径敏感，
  删掉 `logs/` 里对应的行即可（M2 会提供自动脱敏的导出包）。
