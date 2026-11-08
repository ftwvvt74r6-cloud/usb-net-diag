# HANDOVER-AI —— NetDiag（网络矩阵）交接手册

> **写给谁**：接手本仓库的 AI 编码助手 / 新开发者。
> **对齐版本**：`VERSION` = `0.2.0`；写作基线 `main` = `d6a10c4`（PR #25 合并后）。
> **时效性**：文中数字是 2026-11-08 在本仓库实测的；合并新 PR 后 sha 会变，以
> `git log -1 --oneline` 与代码为准。**冲突时优先级：代码 > 本文件 > 其他文档。**
> **命令占位符**：`<python>` = 仓库自带 `tools\python\python.exe`（3.11.9）；
> fork 后没有 `tools/` 时，用系统 `python`（同样只用标准库）。

---

## 1. 这份文档怎么用

| 你的时间 | 读什么 | 目标 |
|---|---|---|
| 10 分钟 | §2、§12，然后跑一遍 §12 的 1~2 步 | 知道这工具能/不能干什么，确认环境没坏 |
| 1 小时 | §3、§4、§5、§8、§10 | 建立数据流与契约的心智模型，知道改哪里 |
| 要动手 | §6、§7、§11，再看目标模块的 docstring | 按仓库既有流程加功能，不踩已知坑 |

**维护纪律**：改了以下任意一项，必须在同一个 PR 里更新本文件对应数字 ——
`VERSION` / 路由数量或路径 / `tests/` 用例数 / `core/` 模块数 / CI job 名。
数字的取法（不要凭记忆）：

```powershell
<python> -m unittest discover -s tests          # 看 "Ran N tests" 与 "OK (skipped=N)"
<python> scripts\gen_api_doc.py --check 0.95    # 看 "模块 N 个｜公开符号 N 个"
git ls-files 'core/*.py'                        # 核心模块清单（注意用单引号，PowerShell 不吃双引号里的通配）
git grep -nF "/api/" -- core/server.py          # /api/ 相关行（宽口径，见下方说明）
```

> 注：最后一条 `git grep -nF "/api/"` 是**宽口径**统计 —— 当前 `core/server.py` 命中 **45 行**
> （含 docstring / 注释 / 示例 URL），**不等于路由数量**；精确路由清单看 **§4 的表**
> （10 个 POST + 2 个 GET = 12 个核心 API）。

> 仓库里有多份**历史文档**（`docs/START-HERE.md`、`docs/plan-review.md`、`docs/code-index.md`、
> `docs/t00-findings.md`、`docs/handoff-MANIFEST.json`）描述的是 v0.1.0 或目标架构，
> 数字与目录已经过期；不要拿它们当现状。现状看本文件 §2~§8。

---

## 2. 项目是什么 + 能力边界

**一句话**：放进 U 盘/任意目录就能跑的 Windows 便携网络诊断工具。插上 → 双击
`NetDiag.vbs`（或 `start.bat`）→ 浏览器打开 `127.0.0.1:8787`，把「慢、卡、丢包、连不上、
时通时不通」定位到 **L2 链路 → L3 网络 → L4 传输 → L7 应用** 的某一层，并回答四问：
**哪一层坏了 / 哪个协议 / 哪个对端 / 下一步做什么**。安全观察（明文凭证、可疑外联）
只是附带项，不参与主判定。

### 2.1 四个入口

| 入口 | 怎么进 | 前提 | 自动化覆盖 |
|---|---|---|---|
| **UI** | `NetDiag.vbs`（静默、自动提权）/ `start.bat`（带窗口）/ `core\server.py` | 便携 Python；实时抓包另需 Npcap + 管理员 | HTTP 路由有 `test_http_drain.py` 等；UI 本身无浏览器 E2E |
| **CLI** | `core\diagnose.py --pcap ...` | tshark（分析抓包文件也要） | `test_cli_report_out.py` 等 |
| **MCP** | `mcp\wireshark-mcp\server.py`（stdio）+ `config\mcp-wireshark.json` | 一个 MCP 客户端；实时能力同 UI | 只做「文件存在 + 可编译」契约检查，**无协议级测试** |
| **诊断包** | 界面按钮 / `导出诊断包.bat` / `diagnose.py --export-diag` | 无（纯本地打包） | `test_diagpack.py`、`test_sanitize.py` |

MCP 服务暴露 7 个工具：`list_interfaces`、`capture_live_packets`、`scan_network_threats`、
`analyze_pcap`、`probe_link`、`listen_flows`、`doctor`（见 `mcp/wireshark-mcp/server.py` 的 `TOOLS`）。

### 2.2 能测什么

| 层 | 能测 | 产出 |
|---|---|---|
| L2 | ARP 请求 ≥2 次仍无应答 | 警告（对方关机 / IP 冲突 / 跨 VLAN） |
| L3 | ICMP 不可达/超时、RTT、抖动 | 警告/严重 + 秒数 + 帧号 |
| L4 | TCP 建连无响应、握手期 RST、重传、乱序、零窗口/窗口满 | 严重/警告；重传方向需 dup-ACK 证据 |
| L7 | DNS 失败率/耗时、HTTP 5xx/耗时、TLS alert | 严重/警告；按「服务端慢 vs 网络慢」区分 |
| 观察 | 高危端口外联、明文凭证 | 只列事实，不抢主判定 |
| 基线 | 实时抓包时每 5 秒一轮轻量探针（网关 ICMP / DNS UDP / 目标 TCP SYN） | 「探针基线」区块 + 两侧对照；探针流量双过滤隔离（见 `docs/shadow-probe.md`） |
| 路径 | 实时抓包或有目标时跑一次 MTR（TTL 1..16 逐跳 RTT/丢包） | 「路径剖面」区块 + 第几跳开始劣化；ICMP 被过滤时降级 TCP 并标注（见 `docs/path-probe.md`） |

另有「通信观察（被动监听）」（Scapy/tshark 抓包 → 会话表）与「连通与速度测试（链路体检）」（对单个 TCP 目标按协议
自适应探测 DNS/TCP/TLS/HTTP/SMB/RDP/SSH/Opaque TCP 分段耗时）。

### 2.3 不能测什么（交接时必须说清楚）

| 限制 | 事实 / 原因 |
|---|---|
| **UDP 丢包率** | UDP 无序号，单点抓包算不出丢包率；只有 DNS 超时等协议感知信号，或主动探测能间接判断（`docs/plan-review.md` §3.3）；影子探测给的是「探针自己的丢包」不是业务 UDP 丢包 |
| **探针覆盖范围** | 探针测网关 / DNS / 业务目标三个角色；路径剖面测到目标的逐跳（IPv4，最多 32 跳、实时默认 16 跳）；**IPv6 逐跳未实现**；被动监听与离线分析**恒不发包** |
| **全网体检 / 单目标诊断** | 依赖 Npcap 驱动 + 管理员权限；未提权只能分析抓包文件（`start.bat` 会降级，不崩） |
| **通信观察（被动监听）** | 同上，且要有真实流量；CI/沙箱环境会 skip |
| **TLS 自检（selftest）** | 需要本机 `openssl` 生成自签证书；没有就 skip，不伪装通过 |
| **非 Windows** | `core/platform/winapi.py`、VBS、Npcap 都是 Windows 专属；CI 的 Ubuntu job 只跑文档检查 |
| **UDP / ICMP 体检** | `probe.py` 只建 TCP 连接（`SOCK_STREAM`），不能探 UDP 服务 |
| **持续监控 / 流量清洗 / 压测** | 产品明确不做；体检有并发闸门（3 个） |
| **AI 外发脱敏** | 当前没有 `core/egress/` 实现；点「AI 解读」会把结构化结果（含 IP/域名/URI）发到你配置的模型端点，只在允许外发的环境使用 |
| **MCP 协议行为** | 只有文件/语法契约测试；真实 MCP 交互需手工冒烟 |

> **最重要的一条业务边界**：**「没抓到样本」不等于「网络正常」**。`verdict.build()` 会在
> 证据不足时返回「证据不足」，四层状态里显示「无样本」；不要为了「好看」把它改成「正常」。

### 2.4 运行环境

- 仅标准库；唯一可选第三方是 `tools/python/Lib/site-packages` 里的 Scapy 2.8.0。
- tshark 4.7.4 由 `tools/WiresharkPortable/.../tshark.exe` 提供，也可用 `TSHARK_PATH` 指到别处。
- `tools/`、`harness/` 被 `.gitignore` 整体排除，**不在仓库里**；干净 checkout 跑测试会 skip 依赖它们的用例。
- `config/app-config.json`、`config/ai-config.json` 也是 ignored；缺省配置能跑（`core/config.py` 有默认值）。

---

## 3. 数据流与分层

### 3.1 当前真实运行路径（以代码为准）

```
pcap / 网卡
   │
   ▼
core/analyzer.py::collect()          # 一次 tshark -T fields，45 个字段，逐行流式解析
   │  st = {packets, streams, dns_*, http_*, arp_*, dir, ...}
   ▼
_metrics(st, streams)  +  _stream_rows(st)  +  build_findings(st, m, streams)
   │
   ├── meta / metrics              # 扁平指标 + 技术明细，报告直接消费
   ├── rows[]                      # 中文发现列表（legacy，但 UI/报告/AI 都在读）
   └── _build_findings_v2(rows)    # 经 core/rules/legacy_map.py → findings_v2（机器码）
   ▼
core/verdict.py::build(result)       # 只读 meta/rows/metrics/summary
   │  level / headline / plain / impact / layer / layers / points /
   │  next_steps / flags / sufficiency
   ▼
core/report.py::render_markdown() / save()      # Markdown + JSON（JSON 只写 5 块）
   │
   ├── UI（/api/status 返回 result）
   ├── AI 解读（core/ai.py::build_messages → OpenAI 兼容端点）
   ├── MCP（analyze_pcap 工具）
   └── 诊断包（只收日志/报告，不收 pcap）
```

**关键事实（不要想当然）**：

1. `verdict.build()` **不消费** `findings_v2`，仍然读 `rows[]`。`findings_v2` 是 T03 的
   过渡产物，目前没有运行时消费者；`rows[]` 的中文值仍是兼容面。
2. `extract` 层**不在** `analyze()` 的主路径上。它由 `scripts/dump_features.py` 与
   `tests/test_extract_features.py` 使用：tshark 行 → `parse_rows()` → `build_features()`
   → `Features`，用于把 pcap 回放成可比较的特征（`tests/fixtures/faults_features.json`）。
   目标架构图（`docs/overview.md` §2）画的是「extract → rules」，那是**目标**，不是现状。
3. `core/rules/` 目前只有 `legacy_map.py`（`rows[]` → `Finding` 的迁移桥）；
   `core/rules/thresholds.json` 不存在，`config.load_thresholds()` 返回 `{}`。
   规则阈值实际在 `analyzer.py` 常量与 `build_findings()` 里，改阈值要配样本回归。
4. 导入方式有两套：运行时靠 `sys.path.insert(0, 'core')` 做扁平导入（`import analyzer`）；
   测试/部分包模块用仓库根做包导入（`from core.version import read_version`）。
   `core/config.py` 用相对导入（`from .platform import paths`），只能包导入；
   新增模块要么同时兼容两套（参考 `analyzer.py` 顶部的 try/except），要么明确限制调用方式。
5. **影子探测 / 路径剖面只在实时路径**：`capture_live(shadow=True)` 起
   `ShadowProber` + `PathProfiler` 两个线程，`run_scan` 把账本聚合成
   `meta["probe_baseline"]`、把逐跳结果注入 `meta["path_profile"]`；离线分析
   （`--pcap`）与 `core/passive.py` **都不引用 `core/pathprobe.py` 的发送逻辑**。
   探针隔离靠「抓包 BPF + 分析 `-Y`」双过滤；MTR 还要在显示过滤里整类排除
   ICMP type 11（time-exceeded 认不出探针 id），细节见 `docs/shadow-probe.md`
   与 `docs/path-probe.md`。

### 3.2 契约：哪些是内部结构，哪些是对外契约

| 层 | 内容 | 稳定性 |
|---|---|---|
| **代码级契约** | `core/contracts.py` 的 dataclass/Enum、`SCHEMA_VERSION = "2.1"`、`to_jsonable()`、`envelope_ok/err()` | 改形状 = 升版本；`envelope` 是目前**未被 HTTP 层使用**的目标契约 |
| **对外 HTTP** | 各 `/api/*` 的请求键与响应键（见 §4） | 视为对外契约；改键名要同步 UI/测试/本文件 |
| **报告文件** | `reports/<stem>.md` 与 `.json`；JSON 顶层固定 5 块 | 对外；`reports/faults_demo.*` 是提交进仓库的快照 |
| **诊断包** | zip 内 `README.txt` / `env.json` / `logs/` / `runs/` / `crashes/`（可选 `reports/`） | 对外；`test_diagpack.py` 钉结构 |
| **MCP** | 7 个工具名与参数（`TOOLS`） | 对外；改已有工具名/参数算破坏 |
| **CLI** | `diagnose.py` 的参数（`--pcap` / `--duration` / `--report-out` / `--export-diag` 等） | 对外 |
| **内部** | `Features` / `Finding` / `st` / `findings_v2` / `meta` 的技术明细键 | 可重构，但 `rows[]`/UI 可能间接依赖，改前先 grep |

`SCHEMA_VERSION` 升级规则（现行做法）：

1. 改 `contracts.py` 的 dataclass 字段、Enum 取值，或 `Features` 的语义 → 升 `SCHEMA_VERSION`；
2. 同步 `tests/fixtures/faults_features.json` 的 `schema_version`（`test_extract_features.py`
   会断言 `"2.1"`，并比对特征数值）；
3. 报告 JSON 故意不写 `schema_version`（见 §4.4），所以升版本不会改已提交的报告快照；
4. `Provenance.schema_version` 会出现在 `analyze()` 结果里，供诊断包/排查用。

---

## 4. 对外 API（`core/server.py`）

服务只绑 **`127.0.0.1`**，起始端口 `config/app-config.json` 的 `server_port`（默认 8787），
被占则顺延最多 10 个端口。请求处理有三道边界：`Host` 只接受 `127.0.0.1`/`localhost`/`::1`；
写请求检查 `Origin`（无 Origin 的本机程序放行）；JSON body 上限 8 MB、上传上限 2 GB。

> **路由计数**：**核心 API = 10 个 POST + 2 个 GET**（`/api/ping`、`/api/app`）。
> `do_GET` 另外还服务 8 个只读端点与静态页，完整清单见 4.2/4.3。

### 4.1 响应信封的现状（重要）

`contracts.envelope_ok()` / `envelope_err()` 定义了标准信封：

```json
{"schema_version": "2.1", "ok": true, "data": {}, "error": null, "trace_id": ""}
```

但**当前 `core/server.py` 的路由还没有套这层信封**：成功响应是路由自己的
`{"ok": true, ...}`，失败多为 `{"ok": false, "error": "..."}`，未知路径是纯文本 404，
`/api/v1/*` 只存在于 `contracts.py` 的 docstring 里（未实现）。
新写接口时先决定是否启用信封；**不要假设现有响应带 `schema_version` 或 `trace_id`**。

### 4.2 10 个 POST 路由

| 路由 | 请求体 / 参数 | 成功响应（关键键） |
|---|---|---|
| `POST /api/quit` | 无 | `{ok: true, message}`；0.3s 后关监听并清理 `logs/netdiag.pid` |
| `POST /api/ai` | AI 配置局部更新：`provider/base_url/api_key/model/temperature/timeout/verify_ssl` | `{ok: true, config}`（Key 已脱敏） |
| `POST /api/ai/test` | 同配置，或 `{overrides: {...}}` | `test_connection()` 结果（连通性/模型/耗时） |
| `POST /api/ai/analyze` | `{result?, question?}`；省略 result 用最近一次 `JOB.result` | AI 结论 + `model` + `latency_ms` + 可选 `markdown`（写 `reports/<stem>.ai.md`） |
| `POST /api/passive` | `{interface?, duration, target?, engine?}`（`auto/scapy/tshark`） | `{ok: true, engine}`；后台跑，轮询 `GET /api/passive` |
| `POST /api/passive/stop` | 无 | `{ok: true}`（置停止标志，后台收尾） |
| `POST /api/probe` | `{target, port?, count?, timeout?, proto?}` | `probe.run()` 结果（分段耗时/协议/结论） |
| `POST /api/scan` | `{mode: live/scan/offline, target?, duration?, interface?, pcap?}`；offline 的 pcap 只接受 `captures/` 下文件名 | `{ok: true}`；后台任务，轮询 `/api/status` |
| `POST /api/diagpack` | `{raw?: bool, include_reports?: bool}` | `{ok: true, path, size, entries}`（默认脱敏） |
| `POST /api/upload` | 原始字节 + `?name=x.pcap`；只收 `.pcap/.pcapng/.cap` | `{ok: true, file, size}`（落到 `captures/`） |

### 4.3 GET 路由（2 个核心 + 8 个只读 + 静态页）

| 路由 | 用途 | 响应关键键 |
|---|---|---|
| `GET /api/ping` | 单实例/存活探测 | `ok/app/version/pid/url/started_at` |
| `GET /api/app` | 应用信息 | `ok/app/version/pid/port/url/idle_exit_min/auto_quit/admin/auto_open_browser` |
| `GET /`、`/index.html` | 单文件控制台 | `ui/index.html` |
| `GET /api/status` | 诊断任务状态 | `JOB` 全量快照 + `elapsed` |
| `GET /api/interfaces` | 网卡列表 | `interfaces[]/admin/npcap` |
| `GET /api/captures` | 已有抓包 | `files[{name,size,mtime}]`（最多 50） |
| `GET /api/report?path=` | 读报告 | 文件原文；只取 `Path(name).name`，防目录穿越 |
| `GET /api/doctor` | 环境自检（缓存 60s） | `bootstrap.check()` 结果 |
| `GET /api/passive` | 通信观察状态 | `state/result/error/engine/engine_info/elapsed` |
| `GET /api/ai` | AI 配置（Key 脱敏） | `public_config()` |
| `GET /api/probe?target=&port=&count=&proto=` | 连通与速度测试（链路体检，GET 便捷入口） | `probe.run()` 结果 |

注意 `/api/probe` 同时有 GET 与 POST；两者都受并发闸门 `MAX_CONCURRENT_PROBE = 3` 限制。

### 4.4 报告快照为什么只写 5 块

`report.save()` 的 JSON 顶层**固定只写** `summary` / `meta` / `metrics` / `rows` / `verdict`。
原因（`core/report.py:317` 的 docstring）：

- `reports/faults_demo.json` 是**提交进仓库的快照**，多写字段会让每次改内部结构都污染 diff；
- `findings_v2` / `provenance` 是后加的增量字段，故意不落 JSON，避免改迁移桥就改历史报告；
- 落盘前把 `meta.tshark_path` 归一成固定占位，避免换机器（`D:\...` vs `C:\...`）让 `git diff reports/` 常脏；
- `generated_at` 是真实运行时间，重跑快照会变；证明「判定未变」要用 demo+9 样本的
  `render_markdown()` 输出对比，不要拿 `report.save()` 直接 diff。

### 4.5 错误形态

- 可预期失败：HTTP 200 + `{ok: false, error: "中文说明"}`（多数路由如此）；
- body 超限：413；非法 Host/Origin：403；路由不存在：404（纯文本）；未捕获异常：500 JSON，
  栈只写日志、不回浏览器；
- `core/errors.py` 的 `ErrorCode` / `DiagError` / `HINTS` 已定义稳定错误码，但当前 HTTP 层
  **没有全面接入**；新代码若要接，先统一一层 envelope，别一半一半。

---

## 5. 不变量（红线）

以下每一条都对应一次真实踩坑，违反会让「判定可信度/可复现性」直接下降。

1. **demo + 9 个确定性样本 = 20 个产物逐字节不变**。基线样本：
   `captures/faults_demo.pcap` + `scaffold/tests/fixtures/gen_pcap.py` 生成的 9 个
   （`arp_no_reply` / `icmp_unreachable` / `dns_timeout` / `tcp_retransmission` /
   `zero_window_client` / `http_500` / `404_error` / `udp_no_response` / `empty_capture`）。
   当前 demo 期望：`verdict.level=严重`、`layer=L4 传输层｜TCP`、严重 3 / 警告 5。
2. **`reports/` 零改动**：`reports/faults_demo.md` 与 `.json` 是入库快照；测试/实验用
   `--report-out` 或临时目录，不要写仓库 `reports/`。
3. **测试只增不减**：当前 480 条；修 bug 不许删断言/放宽，新增行为必须有命中 + 不命中用例。
4. **自动生成的文档不许手改**：`docs/api-reference.md`、`docs/docstring-gaps.md` 由
   `scripts/gen_api_doc.py` 从源码生成，手改下次就被覆盖，CI 的 doc-sync 会红。
5. **文案单一来源**：用户可见中文一律 `core/copy/zh-CN.json`，代码里只留 key；
   `core/rules/**`、`core/verdict/**` 里不许写中文字符串。
6. **「没样本 ≠ 正常」**：证据不足必须走 `Sufficiency(ok=False)` → 「证据不足」/「无样本」；
   不允许静默吞异常后返回「正常」。
7. **方向判定只在有 dup-ACK 证据时给**：`_retrans_direction()` 要求
   「一侧 retrans > 0 且另一侧 dup_ack > 0」；只有重传没有 dup-ACK 时返回 `None`，
   退回通用重传行，不硬编「上行/下行丢包」。
8. **copytext 缓存纪律**：表按「文件 mtime/size」缓存；测试 monkeypatch
   `core.config.load_copy` 不改变文件，必须调 `copytext.reload()`，否则静默读到真表而假绿。
9. **诊断包默认拒绝泄漏**：`diagpack.build()` 默认脱敏；写 zip 前会收集被替换的原值并逐个
   扫描条目名/内容，只要还出现就抛异常、**不写 zip**；`--raw` 才保留原值且必须双警告。
10. **仓库纪律**：不 force push、不直推 `main`、不手改 `.github/**`（要单独评审）、
    不把 `tools/` / `harness/` / `*.pcap` / `logs/` / `reports/` / 真实 `config/*.json`
    加进 git；`git add` 必须写明确路径，禁止 `git add -A`。

---

## 6. 加新功能的标准流程（照抄本仓库实际做法）

> 先读 §5，再按下面顺序做。每一步都给了可直接复制的命令（PowerShell，仓库根执行）。
> 两个路径变量：

```powershell
$PY = ".\tools\python\python.exe"      # fork 无 tools 时改成 "python"
$BR = "feat/t07-example"                # 换成你的分支名
```

### 6.1 写清动机 + 开分支

```powershell
git switch main
git pull --ff-only
git switch -c $BR
```

在任务单/PR 描述里写：**对应哪个现象/rule_id、改哪一层、验收命令、回滚方式**。
不要从 UI 反推数据结构，也不要在规则里写死 IP/端口/域名。

### 6.2 测试先行（失败用例）

```powershell
$PY -m unittest discover -s tests -p "test_your_feature.py" -v
```

新规则至少两条用例：**命中**（构造 Features → 断言 `rule_id` + `severity` + `direction`）
与**不命中**（阈值下方 → 空列表）；推断类结论断言 `confidence < 1.0`。

### 6.3 改代码 + 文案表

- 用户可见文案 → `core/copy/zh-CN.json`，代码只留 key；
- 跨模块数据 → 先改 `core/contracts.py`（改形状就升 `SCHEMA_VERSION`）；
- 报告/UI 层只排版/展示，不在这里做判定；
- 不要引入 pip 依赖（唯一例外是内置 Scapy）。

### 6.4 变异验证（证明测试真能抓回归）

把刚修的那一行**故意改坏**，跑新用例，必须变红；再改回：

```powershell
# 例：把 core/version.py 的 lstrip("\ufeff") 删掉，BOM 用例应红
$PY -m unittest discover -s tests -p "test_app_version.py" -v
git checkout -- core/version.py
```

「新用例绿了」不等于「测试有效」；本仓库要求至少做一次变异验证并写进 PR。

### 6.5 全套 + 干净 checkout 四件套

```powershell
$PY -m unittest discover -s tests
```

然后在**没有 `tools/`** 的干净 checkout 里跑（CI 形态）：

```powershell
git worktree remove --force .ci-check 2>$null
git worktree add --detach .ci-check HEAD
Set-Location .ci-check
& $PY -m compileall -q core mcp tests
& $PY -m unittest discover -s tests
& $PY scripts\gen_api_doc.py --check 0.95
& $PY scripts\gen_api_doc.py
git -c safe.directory=* diff --exit-code docs/api-reference.md docs/docstring-gaps.md
Set-Location ..
git worktree remove --force .ci-check
```

> 干净 checkout 没有 `tools/`、`config/app-config.json`、历史 `logs/`，所以：
> 测试数为 480，但 **skip 数会变成 27**（本机完整环境是 skipped=2）。这是正常现象，不是失败。

### 6.6 改了 `core/` 就重生成文档

```powershell
$PY scripts\gen_api_doc.py
git diff --stat docs\api-reference.md docs\docstring-gaps.md
```

行号/注释变了一定会产生 diff；**把生成结果一起提交**，不要手改。

### 6.7 精确提交 → push → PR

```powershell
git add core/your_module.py tests/test_your_feature.py docs/api-reference.md docs/docstring-gaps.md
git status --short          # 逐条看过；不要出现 tools/、logs/、reports/
git commit -m "feat(scope): 中文摘要"
git push -u origin HEAD
gh pr create --base main --head $BR --title "..." --body-file pr-body.md
```

PR 必须包含：动机、改了哪些层、验收命令与输出、回滚方式。
**只有 Lead 可以合并 PR**；写窗口自己不许点 Merge。

### 6.8 CI 与审查

```powershell
gh pr checks --watch                 # 可能 GraphQL EOF；失败时改用 REST：
gh api repos/<owner>/<repo>/actions/runs?branch=$BR
```

CI 双绿 + 独立审查无阻塞后，才进入合并队列。

---

## 7. CI 工作流（`.github/workflows/smoke.yml`）

触发：`push` 到 `main`、所有 `pull_request`、`workflow_dispatch`。两个 job：

### 7.1 `syntax-and-contract`（Windows，分支保护依赖这个 job 名）

| 步骤 | 命令 | 作用 |
|---|---|---|
| Python 语法编译 | `python -m compileall -q core mcp tests` | 全量语法检查 |
| 启动器契约测试 | `python -m unittest discover -s tests -v` | 全套 480 条（按环境 skip） |
| 密钥泄露扫描 | `git grep -nEI 'sk-...|r8_...|gh[opsu]_...'` | 防止把 Key 提交进 public 仓库 |

### 7.2 `api-docs`（Ubuntu，最便宜）

| 步骤 | 命令 | 作用 |
|---|---|---|
| 注释覆盖率 ≥ 95% | `python scripts/gen_api_doc.py --check 0.95` | 当前 257/257 = 100.0%（30 模块） |
| 文档与源码同步 | `python scripts/gen_api_doc.py` + `git diff --exit-code docs/api-reference.md docs/docstring-gaps.md` | 禁止手改生成文档 |

### 7.3 CI 里会 skip 什么

CI **没有 tshark、没有管理员/Npcap、没有仓库 `tools/`**：

| 缺失 | 影响 |
|---|---|
| tshark | 需要真 pcap 的用例 `skipUnless`；干净 checkout 共 19 skip |
| 管理员 + Npcap + 真实流量 | `tests/selftest.py` §3 通信观察（被动监听） → unittest 里只验证 skip 传播 |
| openssl | selftest §2b TLS 自检 → skip（Windows runner 可能自带 openssl，skip 数会少 1，以日志为准） |
| Linux 换行 | 生成器固定写 LF；不要用 `os.linesep`/平台默认编码生成文档 |

### 7.4 本地复现 CI

就是 §6.5 的 worktree 四件套；注意 `git -c safe.directory=*` 是 Windows worktree 的
所有权兜底。改 `.github/**` 属于改闸门，必须单独评审，不要顺手动。

---

## 8. 代码地图（`core/` 29 个 .py + 外围）

> 每个文件一句话职责。行数/签名细节看 `docs/api-reference.md`（自动生成，签名永远是真的）。

### 8.1 入口与启动

| 文件 | 职责 |
|---|---|
| `NetDiag.vbs` | 日常静默入口：`pythonw` 拉起、自动提权、单实例、打开浏览器 |
| `NetDiag-stop.vbs` | 界面点不了时的兜底：先 `/api/quit`，失败按 `logs/netdiag.pid` 强杀 |
| `start.bat` | 带窗口入口：提权 → bootstrap 自检 → Npcap 兜底 → 起 `core/server.py`（`start.bat ai` 可选拉 Harness） |
| `doctor.bat` | 只做环境自检，不起服务 |
| `导出诊断包.bat` | 双击导出脱敏诊断包（优先便携 Python，回落系统 Python） |

### 8.2 `core/` 逐个文件

| 文件 | 一句话职责 |
|---|---|
| `core/__init__.py` | 包标记 + 目标架构不变量；`__version__` 写死 `"0.2.0"`（升级时与 `VERSION` 同步） |
| `core/analyzer.py` | 抓包分析引擎：一次 tshark 流式解析 → `meta/metrics/rows` + `findings_v2` + `provenance` |
| `core/app.py` | 静默启动器：pythonw、单实例探测、UAC 提权、空闲退出、错误弹窗 |
| `core/bootstrap.py` | 盘符自适应：按当前路径重写 MCP/Harness 配置 + 环境自检（`--check`/`--npcap`） |
| `core/config.py` | 统一配置加载：app/ai/thresholds/copy + `config_sha256()` |
| `core/contracts.py` | 唯一数据契约：Enum/dataclass、`SCHEMA_VERSION=2.1`、`to_jsonable`、envelope |
| `core/copytext.py` | 文案表唯一读取入口：mtime/size 缓存、`reload()`、缺 key 回退 key |
| `core/diagnose.py` | CLI 主流程：采集/分析抓包文件、`run_scan()`、报告落盘、`--export-diag` |
| `core/diagpack.py` | 诊断包：收集 logs/runs/crashes/reports → 脱敏 → 泄漏自检 → zip |
| `core/errors.py` | 稳定错误码 `ErrorCode`、可展示异常 `DiagError`、默认 `HINTS` |
| `core/extract/__init__.py` | extract 包出口：`FIELDS` / `parse_rows` / `build_features` / 状态常量 |
| `core/extract/fields.py` | tshark 字段清单 + 原始字符串 → Python 值（`"1,1"`、`True`、空串） |
| `core/extract/aggregate.py` | 逐行聚合 → `Features`（纯函数，不 import analyzer） |
| `core/logstore.py` | 唯一日志出口：日文件、裁剪、`env.json`、`runs/`、`crashes/`、异常钩子 |
| `core/passive.py` | 通信观察（被动监听）：Scapy 优先/tshark 兜底，按会话聚合 + 端口/首包识别协议（**只听不发**） |
| `core/pathprobe.py` | 影子探测 + 路径剖面：目标发现（网关/DNS/目标）、探针收发（scapy）、账本、排除 BPF/显示过滤、按角色聚合基线；`run()` MTR（批量 sr、劣化判定、ICMP→TCP 降级、`PathProfiler` 线程）、time-exceeded 整类排除与计数 |
| `core/platform/__init__.py` | 平台适配层包标记（只做 OS 交互，不含业务判断） |
| `core/platform/paths.py` | 目录约定与根目录探测（`Paths`） |
| `core/platform/winapi.py` | Windows 能力：管理员、Npcap、网卡、默认网关、DNS |
| `core/probe.py` | 连通与速度测试（链路体检）：TCP 建连 + Banner 识别 + 按协议分段计时（HTTP/TLS/SMB/RDP/SSH/Opaque） |
| `core/report.py` | 报告渲染：Markdown + JSON 5 块；`tshark_path` 归一 |
| `core/rules/__init__.py` | 规则包标记（渐进迁移中） |
| `core/rules/legacy_map.py` | 旧 `rows[]` → `Finding` 的迁移桥（临时件；当前唯一规则相关实现） |
| `core/sanitize.py` | 诊断包脱敏：IP/域名/用户名/MAC/路径 → 不可还原伪名（幂等） |
| `core/server.py` | 本地 Web UI + HTTP API：路由、Host/Origin 校验、任务槽、单实例、退出 |
| `core/tshark.py` | tshark/dumpcap 定位与执行封装（`TSHARK_PATH`、便携路径、网卡探测） |
| `core/verdict.py` | 判定：`rows/meta/metrics/summary` → level/四层状态/问题明细/证据充分性 |
| `core/version.py` | 产品版本号唯一读取点：`VERSION`，剥 BOM 与空白，缺失回退 `0.0.0` |
| `core/ai.py` | AI 结论生成：构造 prompt、调用外部模型接口；**无 Key 时不可用，且不参与任何判定** |

### 8.3 外围

| 路径 | 职责 |
|---|---|
| `mcp/wireshark-mcp/server.py` | MCP stdio 服务：7 个工具，零第三方依赖，JSON-RPC |
| `scripts/gen_api_doc.py` | AST 扫 `core/` + `mcp/` → `api-reference.md` / `docstring-gaps.md`；`--check 0.95` |
| `scripts/dump_features.py` | pcap → `Features` fixture（`tests/fixtures/faults_features.json`） |
| `scripts/make_icon.py` | 生成 `NetDiag.ico` 与 `docs/assets/logo-*.png`（不依赖第三方库） |
| `ui/index.html` | 单文件控制台（1,451 行；无构建链、无前端框架） |
| `tests/` | 27 个 `test_*.py`（480 条）+ `tests/selftest.py` 人工自检脚本 |
| `scaffold/` | v0.1.0 时期的迁移骨架/历史资料；**不要整体覆盖 `core/`**，其中 `gen_pcap.py` 可生成 9 个样本 |

> 目标架构里的 `core/capture/`、`core/egress/`、`core/render/`、`core/api/`、`core/history.py`
> **当前都不存在**。`AGENTS.md` 的目录职责表部分写的是目标形态，改代码前以磁盘为准。

---

## 9. 文档体系索引

| 文档 | 作用 | 新鲜度 |
|---|---|---|
| **`docs/HANDOVER-AI.md`（本文件）** | 现状、数据流、API、红线、流程、坑、验收 | ✅ 权威（随代码更新） |
| `AGENTS.md` | 硬约束清单（不推 main、不改模块边界等） | ⚠️ 部分目录表是目标架构 |
| `docs/api-reference.md` | 自动生成的公开符号与签名 | ✅ 自动生成，禁止手改 |
| `docs/docstring-gaps.md` | 自动生成的注释缺口清单（当前 0 缺口） | ✅ 自动生成 |
| `docs/api-style.md` | 注释标准（模块头四问 / Args-Returns-Raises / 术语） | ⚠️ §0 基线是 v0.1.0（11 模块/55 符号），当前 30/257 |
| `docs/logging.md` | `logs/` 目录、字段、裁剪规则 | ✅ 当前 |
| `docs/shadow-probe.md` | 影子探测：目标发现、双过滤隔离、探针基线/方向对照、明确不做的边界 | ✅ 当前（D 批次） |
| `docs/path-probe.md` | 路径剖面（MTR）：逐跳表怎么读、劣化阈值、ICMP→TCP 降级、TUN 限制、time-exceeded 隔离与残余风险、DNS 角色 | ✅ 当前（D+ 增量 2） |
| `docs/log-collection.md` | 诊断包三个入口、脱敏、raw 警告 | ✅ 当前 |
| `docs/overview.md` | 一页看懂产品与**目标**分层 | ⚠️ §2 数据流是目标架构，不是 `analyze()` 现状 |
| `docs/START-HERE.md` | v0.1.0 的历史交接包（54 用例/骨架/COPY-MAP） | ❌ 历史，数字已过期 |
| `docs/plan-review.md` | v0.1.0 的完整评审与设计理由 | ❌ 历史；引用行号会漂 |
| `docs/code-index.md` | v0.1.0 的「文件:行」问题索引 | ❌ 历史；行号已漂，用函数名搜 |
| `docs/t00-findings.md` | v0.1.0 的只读扫描发现 | ❌ 历史 |
| `docs/handoff-MANIFEST.json` | 历史交接包清单（v1.2.0，repo 0.1.0） | ❌ 历史 |
| `docs/git-setup.md` | Git 接管操作手册（已去个人化，含 `<owner>/<repo>` 占位符） | ✅ 可用；示例数字偏旧 |
| `docs/assets/` | 图标/Logo | ✅ |

---

## 10. 复刻到新仓库（fork 清单）

### 10.1 真正需要改的只有两个占位符

| 占位符 | 出现位置 | 改成 |
|---|---|---|
| `<owner>` | `docs/git-setup.md`（7 处 URL） | 你的 GitHub 账号/组织 |
| `<repo>` | 同上 | 你的仓库名 |

文档里另有 `<你的工作目录>`（本机路径示例；`git grep -nF` 当前 **18 行命中**），按自己的目录替换即可；
它不影响代码运行。**没有别的写死用户名/盘符/邮箱。**
（核对方法：`git grep -nF "<你的工作目录>"`、`git grep -nF "<工作区目录>"`；
另用 `-F` 搜自己的账号名/用户目录确认为 0 —— **必须 `-F`**，正则转义写错会得到假 0。）

### 10.2 步骤

```powershell
# 1) fork / clone
git clone https://github.com/<owner>/<repo>.git
Set-Location <repo>

# 2) 改 origin（如果你是在别人的仓库上复刻）
git remote set-url origin https://github.com/<your-owner>/<your-repo>.git

# 3) 自备可选运行环境（不进 git；不装也能跑测试）
#    tools\python\  + tools\WiresharkPortable\ + tools\npcap-*.exe
#    或设 $env:TSHARK_PATH 指向已有 tshark

# 4) 不配置、不装依赖，直接跑
python -m unittest discover -s tests        # 期望 480 条，OK (skipped=27)

# 5) 要发版再改版本号
#    VERSION（唯一权威）与 core/__init__.py 的 __version__ 两处同步
```

### 10.3 fork 后自检

- [ ] 干净目录（无 `tools/`、无 `config/app-config.json`）跑测试 → `OK (skipped=19)`
- [ ] **有 tshark 时**（系统安装或 `tools/` + `TSHARK_PATH`）：
      `python core/diagnose.py --pcap captures/faults_demo.pcap --report-out <tmp>` 能出报告
      （**没有 tshark 时这条会以「未找到 tshark」退出，属预期，不是 bug**）
- [ ] `python core/diagnose.py --export-diag --out <tmp>` 能出 zip，README 写「已脱敏」
- [ ] 全仓搜索自己的**私有标记**（原仓库所有者账号、本机盘符路径、`C:\Users\<你的名字>`）在自己的改动里为 0
- [ ] CI 两个 job 绿（fork 的 Actions 默认可能关闭，需要手动启用）

> 不要把 `tools/`、`harness/`、`config/ai-config.json`、抓包/日志提交进仓库；
> 它们已被 `.gitignore` 排除，`git add -f` 只会制造噪声。

---

## 11. 常见坑 TOP 10（都是本项目真实修过的）

1. **把中文文案当判定键**
   现象：改一句「严重」→ UI/测试/AI 全挂。
   做法：断言 `rule_id` / `severity` / `layer` 等机器码，不匹配中文；文案只进
   `core/copy/zh-CN.json`。当前 `rows[]` 仍带中文（历史兼容），新代码走 `findings_v2`。

2. **`"1,1"` 聚合值**
   现象：`tcp.analysis.duplicate_ack` 同一帧出现两次，tshark 输出 `"1,1"`；
   旧的 `float()`/`== "1"` 解析会抛异常或把 dup-ACK 永远算 0。
   做法：用 `extract.fields.parse_flag/parse_num`（按逗号拆分，任一为真）；
   参考 `tests/test_direction_signals.py`。

3. **没样本当正常**
   现象：1 KB 空抓包也报「各层正常」。
   做法：`Sufficiency(ok=False)` + `Severity.NA`；判「每个维度有没有样本」，
   不是只看 `packets`。改判定必须跑 `tests/test_sufficiency.py`。

4. **手改自动生成文档**
   现象：本地改了 `docs/api-reference.md`，CI doc-sync 红；下次生成又被覆盖。
   做法：改源码 docstring → `python scripts/gen_api_doc.py` → 提交生成结果。

5. **行号位移导致 doc-sync 红**
   现象：只加了几行注释，`docs/api-reference.md` 大量行号 diff。
   做法：这是预期的；重跑生成器并提交，不要手改行号，也不要忽略 diff。

6. **端口被占导致假红**
   现象：旧进程还占着 8787/8801，新测试连到旧服务；或 `SO_REUSEADDR` 让两个进程
   同时绑同一端口，「改了代码却没生效」。
   做法：`DiagServer.allow_reuse_address = False`；测试用端口 0 或 `create_server()` 顺延；
   先 `Get-NetTCPConnection -LocalPort 8787` 查占用。

7. **测试写仓库共享路径**
   现象：跑一次测试，仓库 `logs/` / `reports/` 变脏。
   做法：`NETDIAG_LOG_DIR` 指临时目录；报告用 `--report-out`；
   `tests/test_zz_no_repo_logs.py` 会在全套跑完后检查 `logs/` 没变。

8. **`git add -f` 绕过 `.gitignore`**
   现象：把 `tools/`（约 360 MB）或生成物塞进 git。
   做法：生成器放 `scripts/`（不要在 ignored 的 `tools/` 里）；`git add` 只写明确路径；
   提交前 `git status --short` 逐条看。

9. **报告快照 5 块**
   现象：给 JSON 加 `findings_v2`/`provenance`，`reports/faults_demo.json` 全变。
   做法：`report.save()` 只写 `summary/meta/metrics/rows/verdict`；新增字段留在
   `analyze()` 返回值里，不入报告。测试见 `tests/test_report_shape.py`。

10. **copytext 缓存与 monkeypatch**
    现象：测试 patch 了文案来源，结果仍读到旧表 → 假绿。
    做法：patch 前后调 `core.copytext.reload()`；缓存键是 `(mtime_ns, size)`，
    文件没变就不会自动失效。参考 `tests/test_copy_source.py::_patched_copy`。

**另外三个当前落差（不是 bug，但会误导接手者）**：

- `/api/v1/*` 与标准 envelope **未实现**；`contracts.py` 里只是定义。
- `core/rules/thresholds.json` **不存在**；`load_thresholds()` 返回 `{}`，阈值实际在代码里。
- `core/__init__.py::__version__` 是写死的 `"0.2.0"`，与 `VERSION` 两处需同步。

---

## 12. 交接成功判定（10 分钟 checklist）

> 在**空目录/fork 的干净 checkout**里做（没有 `tools/`、没有 `config/app-config.json`）。
> `<python>` 用仓库自带 `tools\python\python.exe`，或系统 Python 3.11+。
>
> **前置条件**：只有 **第 2 步（出 demo 报告）需要 tshark**；其余步骤（测试 / 日志 / 诊断包 / UI）都不需要。
> 没有 tshark 时第 2 步会以「未找到 tshark」退出（exit 2）—— **这是预期行为，不是 bug**，跳过它继续。

### 12.1 五分钟内必须绿

```powershell
# 1) 全套测试（干净环境；不需要 tshark）
<python> -m unittest discover -s tests
# 期望：Ran 480 tests ... OK (skipped=27)

# 2) demo 报告（需要 tshark；没有就跳过这一步）
#    有 tools\ 时先指路：
$env:TSHARK_PATH = "$PWD\tools\WiresharkPortable\App\Wireshark\tshark.exe"
<python> core\diagnose.py --pcap captures\faults_demo.pcap --report-out "$env:TEMP\netdiag-demo"
# 期望：故障层 L4 传输层｜TCP；严重 3 / 警告 5；报告写到临时目录
# 没有 tshark 时的实际表现：exit 2 + 「未找到 tshark」，不产生报告

# 3) 日志现场
Get-Content logs\env.json | Select-String '"version"|"tshark_version"|"admin"'
Get-ChildItem logs\runs | Select-Object -Last 1
# 期望：version=0.2.0；runs/ 有本次分析记录；不联网、不上传

# 4) 诊断包
<python> core\diagnose.py --export-diag --out "$env:TEMP\netdiag-diag"
Get-ChildItem "$env:TEMP\netdiag-diag\NetDiag-diag-*.zip" |
  Expand-Archive -DestinationPath "$env:TEMP\netdiag-unzip" -Force
Get-Content "$env:TEMP\netdiag-unzip\README.txt"
# 期望：zip 可解压；README 写明已脱敏；包里没有 pcap
```

### 12.2 最后五分钟看 UI

```powershell
<python> core\server.py
# 另一个窗口：
curl.exe http://127.0.0.1:8787/api/ping
curl.exe http://127.0.0.1:8787/api/app
# 期望：{"ok":true,"app":"USBNetDiag","version":"0.2.0",...}
#       浏览器打开 http://127.0.0.1:8787/ 能看到控制台
curl.exe -X POST http://127.0.0.1:8787/api/quit
```

### 12.3 判定

| 结果 | 结论 |
|---|---|
| **已执行的步骤**全绿，UI 能开、`/api/ping` 返回 0.2.0 | ✅ 交接成功（无 tshark 时第 2 步跳过；此时第 3 步可能没有 `logs/env.json` —— 该文件由分析入口写，没跑分析就不会生成，可先跑任一分析或直接看 `start.bat` 启动后的 `logs/app-*.log`） |
| 测试绿但 UI 打不开 | 看 `logs/app-*.log` / `logs/diag-*.log`，先查端口占用与 `ui/index.html` |
| demo 报告层/计数不对 | 先确认 `captures/faults_demo.pcap` 未被改（sha256 应与入库一致），再看 `rows[]` |
| 诊断包解压乱码/缺 README | 看 `core/diagpack.py` 的 `README_NAME` 与 zip 条目名脱敏（`*` → `_`） |
| 干净环境 skip 不是 19 | 说明环境里多了/少了 tshark、openssl 或 tools；不是代码问题 |

---

*本文件只描述现状与规则，不改产品行为。发现文档与代码不一致时，以代码为准并在同一个 PR 修正本文件。*
