# USB-Net-Diag

放进 U 盘的 Windows 网络诊断工具链。插到目标电脑，双击 `start.bat`，浏览器打开控制台。

**主线是网络故障排查**：慢、卡、丢包、连不上、时通时不通。工具把问题按
**L2 链路 → L3 网络 → L4 传输 → L7 应用** 四层定位，直接告诉你：
**哪一层坏了、哪个协议、哪个对端、下一步做什么**。
安全检测（明文凭证、可疑外联）只是附带项，不抢主线。

> **本仓库只包含源码**：`core/`、`ui/`、`mcp/`、`skills/`、配置模板与示例报告。
> 便携运行环境 `tools/`（约 360 MB：Python 3.11 + Wireshark + Npcap）和
> `harness/`（约 540 MB，可选 Agent 底座）体积过大未纳入版本库，
> 需要按「运行环境准备」一节自行放置，或直接使用完整便携包。
>
> 当前版本：**v0.1.0（测试版）**，详见 [CHANGELOG.md](CHANGELOG.md)。


```
USB-Net-Diag/
├── start.bat                     # 总入口：提权 → 环境自检 → Npcap 兜底 → 启动 UI
├── doctor.bat                    # 只做环境自检，不启动服务
├── config/
│   ├── app-config.json           # 端口 / 时长 / 威胁情报 Key（可改）
│   ├── ai-config.json            # AI 模型地址与 Key（界面里改，也可手改）
│   ├── harness-config.json       # 启动时按当前盘符自动生成
│   └── mcp-wireshark.json        # MCP 客户端配置，按当前盘符自动生成
├── core/
│   ├── bootstrap.py              # 盘符自适应 + 环境自检
│   ├── tshark.py                 # tshark 定位/执行/网卡探测
│   ├── analyzer.py               # 流式解析 + 分层指标/会话聚合
│   ├── verdict.py                # 分层故障定位与白话结论
│   ├── report.py                 # 分层报告渲染（Markdown + JSON）
│   ├── probe.py                  # 链路体检：先识别协议，再按协议分段计时
│   ├── passive.py                # 被动监听：Scapy/tshark 抓包 → 会话表 + 协议指纹
│   ├── ai.py                     # AI 模型配置 + OpenAI 兼容调用
│   ├── diagnose.py               # CLI 主流程
│   └── server.py                 # 本地 Web UI + HTTP API（127.0.0.1）
├── mcp/wireshark-mcp/server.py   # MCP stdio 服务器（零第三方依赖）
├── skills/network-diagnose/SKILL.md
├── ui/index.html                 # 单文件控制台
├── harness/                      # DeepSeek Harness 便携版 0.2.0-rc.2（Agent 底座，可选）
├── tools/
│   ├── python/                   # 便携 Python 3.11（Embedded，内含 Scapy 2.8.0）
│   ├── WiresharkPortable/        # 便携 Wireshark 4.7.4（含 tshark）
│   └── npcap-1.79.exe            # Npcap 离线安装包
├── captures/                     # 抓包落盘
├── reports/                      # 报告落盘（.md / .json）
└── logs/                         # 运行日志
```

## 运行环境准备（使用裸仓库时）

仓库不含便携环境，需要自己补齐 `tools/`。程序按固定相对路径找依赖：

```
tools/
├── python/
│   ├── python.exe                             # 便携 Python 3.11（Embedded 64-bit）
│   └── Lib/site-packages/scapy/               # 可选：被动监听用，缺失则回落 tshark
├── WiresharkPortable/
│   └── App/Wireshark/tshark.exe               # 必需：抓包与离线分析都靠它
└── npcap-1.79.exe                             # 可选：缺失时实时抓包不可用，离线分析不受影响
```

步骤：

1. **Python**：取 [Windows embeddable package (64-bit) 3.11](https://www.python.org/downloads/windows/)，
   解压到 `tools/python/`，并在该目录放一个 `python311._pth`：
   ```
   python311.zip
   .
   Lib\site-packages
   ```
2. **scapy（可选）**：
   ```bat
   tools\python\python.exe -m pip install --no-warn-script-location ^
        --target tools\python\Lib\site-packages scapy==2.8.0
   ```
3. **Wireshark**：取 [Wireshark Portable](https://www.wireshark.org/download.html) 解压到
   `tools/WiresharkPortable/`，确认 `tshark.exe` 落在 `App/Wireshark/` 下。
4. **Npcap（可选）**：取 [Npcap](https://npcap.com/#download) 安装包放入 `tools/`，
   命名保持 `npcap-*.exe`，`start.bat` 会自动识别并静默安装。
5. **配置**：把 `config/app-config.example.json`、`config/ai-config.example.json`
   复制成同名不带 `.example` 的文件即可（缺失时程序走内置默认值；
   `mcp-wireshark.json` 与 `harness-config.json` 由 `bootstrap.py` 每次启动自动生成）。
6. **自检**：运行 `doctor.bat`，等价于 `tools\python\python.exe core\bootstrap.py --check`。

> 嫌麻烦就直接用完整便携包：把 `tools/`、`harness/` 拷进仓库目录，
> 在这个仓库里 `git status` 依然干净（两者都已被 `.gitignore` 忽略）。

## 使用

1. 双击 `start.bat`（UAC 弹窗点“是”；拒绝提权也能用离线分析）。
2. 浏览器自动打开 `http://127.0.0.1:8787/`。
3. 选模式：

| 模式 | 说明 | 产出 |
|---|---|---|
| 定向抓包 | 输入目标 IP/CIDR，自动构造 BPF `host <IP>` / `net <CIDR>` | 只分析该目标的流量 |
| 全网扫描 | 目标留空，抓本机网卡全部流量 | 覆盖所有会话，建议 60s+ |
| 被动监听 | 只监听不发包，按会话聚合 | 会话表：源/目标/协议/包长/连接状态 |
| 离线分析 | 上传/选择已有 pcap、pcapng | 不依赖 Npcap 与管理员权限 |

4. 结果按「由浅入深」四段呈现：

   | 区块 | 内容 |
   |---|---|
   | **故障定位卡** | 一句话结论（哪一层+哪个协议+哪个对端+要不要立刻处理）、四层状态条、关键指标 |
   | **问题详解** | 每条：所在层 / 协议 → 用户看到的现象 → 专业依据（数值+帧号+Stream）→ 怎么处理 |
   | **会话明细** | 每个 TCP 会话的对端、包数、握手时延、RTT、重传、服务端等待、问题标记、帧号 |
   | **技术明细** | 采集概况、协议分布、DNS 逐条耗时、HTTP 逐条状态码与耗时、ICMP 明细（默认折叠） |

   同样内容落盘到 `reports/*.md`，结构为：故障定位 → 分层定位 → 问题详解 → 处置步骤 →
   会话明细 → 应用层明细 → 技术明细 → JSON 摘要。

> 首次试跑：在「离线分析」里选择 `captures/faults_demo.pcap`。这是一份人工构造的故障样本，
> 同时包含 ARP 无应答、DNS 慢解析与 NXDOMAIN、TCP 建连无响应、重传、HTTP 500 与 2.4 秒慢响应、
> ICMP 端口不可达。预期结果：**故障层 L4，严重 3 项 / 警告 5 项**，四个层次全部有内容可看。

## 链路体检（不抓包，按协议自适应）

不再是「假定目标是网站」。建连后先**不发数据**，用 `MSG_PEEK` 读服务端首包（Banner），
结合端口画像判断协议，然后**只发这个协议该发的报文**：

```
DNS 解析 → TCP 建连 → 协议识别 → 该协议自己的握手/首包阶段
```

| 识别结果 | 后续动作 | 阶段条 |
|---|---|---|
| `0x16 0x03` / 443 且握手成功 | TLS ClientHello | DNS → TCP → 协议识别 → TLS 握手 → HTTP 首字节 |
| `HTTP/`、`GET ` | 发 HTTP GET | DNS → TCP → 协议识别 → HTTP 首字节 |
| `\xfeSMB` / `\xffSMB`、445/139 | SMB2 NEGOTIATE（只协商，不认证） | DNS → TCP → 协议识别 → SMB 协商 |
| `SSH-`、`220 `、`+OK`、MySQL 握手包 | 只读 banner，不再发任何报文 | DNS → TCP → 协议识别（含 banner 耗时） |
| `\x03\x00\x00`、3389 | X.224 连接请求 | DNS → TCP → 协议识别 → RDP 响应 |
| 都没有 | 降级 Opaque TCP | DNS → TCP → 协议识别 → 响应延迟（跳过） |

关键点：

- **非 Web 协议不会再误报 TLS 失败**：给 445 做体检走 SMB 协商，返回 `NT_STATUS_OK`
  或具体的权限/共享错误，而不是「TLS 握手失败」。
- **TLS 端口跑明文**会自动识别：443 上如果对明文 GET 回了 `HTTP/200`，结论改成
  「这个端口是明文 HTTP，不是 HTTPS」。
- **认不出就只说认不出**：Opaque TCP 只报建连延迟，不硬套 Web 结论，也不报错。
- 端口不常见时可以手动指定协议（界面「协议」下拉，或 API 的 `proto=http|tls|smb|rdp|ssh|opaque`）。

结果给出每段耗时和条形图，并直接判定瓶颈：

| 现象 | 判定 |
|---|---|
| DNS 段最长 | DNS 服务器慢或配错 |
| TCP 段最长 / 有失败 | 链路 RTT 大、丢包，或端口/防火墙不通 |
| 协议识别段有 banner 但不通 | 服务在，但应用层拒绝（如 SMB 权限） |
| TLS 段失败 | 证书、协议版本或中间设备拦截 |
| 前几段都快、首字节慢 | 网络没问题，是服务端处理慢 |

命令行/接口同样可用：

```bat
curl "http://127.0.0.1:8787/api/probe?target=example.com&port=443"
curl "http://127.0.0.1:8787/api/probe?target=10.0.0.5&port=445"
```

```bat
tools\python\python.exe -c "import sys;sys.path.insert(0,'core');import probe,json;print(json.dumps(probe.run('example.com',443),ensure_ascii=False,indent=2))"
```

## 被动监听（Scapy / tshark，看「谁在跟谁通信」）

左侧模式切到 **被动监听**，选网卡和时长即可。它跟「定向抓包」的区别是**不落 pcap、不做四层诊断，
而是把流量按会话聚合成一张表**，适合回答「这台机器现在到底在跑什么协议」。

采集引擎自动选择：

| 引擎 | 说明 |
|---|---|
| **Scapy 2.8.0**（默认） | 已内置在 `tools/python/Lib/site-packages`，纯 Python 逐包解析，能直接读 payload，识别最准 |
| tshark | 兜底：Scapy 导入失败或抓包异常时自动回落，输出格式完全一致 |

界面/接口展示字段：

| 字段 | 含义 |
|---|---|
| 源 IP:端口 / 目标 IP:端口 | 按 SYN 方向、知名端口、临时端口三级规则判定客户端/服务端 |
| 协议 | 先看首包特征（`0x16 0x03`=TLS、`GET `/`HTTP/`=HTTP、`\xfeSMB`=SMB、`SSH-`=SSH…），再看端口画像；都没有显示 **Unknown TCP / Unknown UDP** |
| 包数 / 平均包长 / 总流量 | 双向累计，字节含帧头 |
| 连接状态 | `ESTABLISHED`（有 SYN+ACK 或 3 个以上带 ACK 的包）、`SYN 无响应`（等够 1.5s 仍无回应）、`SYN 已发`、`RST 重置`、`FIN 关闭`、`活跃`、`无连接`（UDP） |
| 识别依据 | 例如「服务端首包：首包以 0x16 0x03 开头」或「端口画像（445）」 |

`Unknown TCP / Unknown UDP` 只表示「没有首包特征 + 端口不在常见画像里」，**不代表故障**；
可以拿这个 IP 去上面的「链路体检」手动指定协议再探一次。

接口：

```bat
curl -X POST http://127.0.0.1:8787/api/passive -H "Content-Type: application/json" ^
     -d "{\"duration\":20,\"target\":\"\",\"interface\":\"6\",\"engine\":\"auto\"}"
curl http://127.0.0.1:8787/api/passive
curl -X POST http://127.0.0.1:8787/api/passive/stop
```

命令行（不开界面）：

```bat
tools\python\python.exe -c "import sys;sys.path.insert(0,'core');import passive,json;print(json.dumps(passive.run(duration=10),ensure_ascii=False,indent=2))"
```

> 注意：被动监听需要管理员权限 + Npcap（Scapy 走 Npcap 的 wpcap 驱动）。
> 非管理员只能看到空结果或直接报错，此时请改用离线分析。

同时启动 Agent 底座（可选）：

```bat
start.bat ai
```

`harness/` 内已放入 DeepSeek Harness 便携版（默认 3081 端口）；不带 `ai` 参数时只起诊断 UI，
不占用额外内存。

命令行同样可用：

```bat
tools\python\python.exe core\diagnose.py --duration 30
tools\python\python.exe core\diagnose.py --target 192.168.1.10 --duration 30
tools\python\python.exe core\diagnose.py --pcap captures\diag_xxx.pcapng
tools\python\python.exe core\diagnose.py --interfaces
```

## AI 模型配置（可选，全部在界面里完成）

抓包分析本身是本地规则引擎，不联网也能跑。配好大模型后，结果页会多一个「AI 解读」：
把结构化结果交给模型，输出一句话结论、风险排序和处置建议，同时存一份 `reports/<抓包名>.ai.md`。

**不需要启动 Harness、也不需要另开配置页**，在诊断控制台里就能改：

1. 打开 `http://127.0.0.1:8787/`，点右上角 **AI 设置**。
2. 选服务商预置（DeepSeek / 通义千问 / Kimi / 智谱 / OpenAI / 自定义），
   接口地址与模型名自动填好，仍可继续手改。
3. 粘贴 API Key → 点 **测试连接** → 通过后点 **保存并启用**。
4. 回到诊断结果，点 **AI 解读**。

保存后即刻生效：下一次调用就用新参数，不用重启服务、不用重开浏览器。
顶部按钮会显示当前模型名，并带一个状态点（绿=已配置可用，红=未配置）。

支持任意 OpenAI 兼容端点，本地模型填 `http://127.0.0.1:11434/v1`（Ollama）或
`http://127.0.0.1:8000/v1`（vLLM）即可。

Key 以明文存在 `config/ai-config.json`，只在本机 U 盘内，不上传；界面上只回显脱敏值
（如 `sk-a******3456`），「清除 Key」可随时抹掉。换电脑/换盘符不受影响。

| 报错 | 处理 |
|---|---|
| `401 ... invalid` | Key 填错或已失效，重新复制 |
| `404 ... not found` | Base URL 层级不对，DeepSeek 应为 `https://api.deepseek.com/v1` |
| `无法连接 ...` | 检查网络或代理；内网自签证书把 `ai-config.json` 的 `verify_ssl` 改 `false` |
| `请求超时` | 调大设置里的「超时秒数」，或换响应更快的模型 |

> `harness/` 是另一套独立的 Agent 底座（自带界面与自己的 Key 管理），与本工具的 AI 解读互不影响；
> 只用诊断 + AI 解读的话，不必启动它。

## 分层诊断规则

| 层 | 指标 | 判定阈值 | 说明 |
|---|---|---|---|
| L2 链路 | ARP 无应答地址数 | ≥1 个（且请求 ≥2 次）→ 警告 | 对方关机、IP 冲突、跨 VLAN |
| L3 网络 | RTT / 抖动 / ICMP | RTT ≥300ms 或抖动 ≥80ms → 警告；ICMP 不可达/超时 → 警告；含「需要分片」→ 严重 | 区分链路时延与丢包 |
| L4 传输 | 建连失败（SYN 无响应） | ≥1 → 严重 | 端口未监听或防火墙丢包 |
| L4 传输 | 被 RST | ≥1 → 警告 | 对端明确拒绝，服务没起 |
| L4 传输 | 重传率 | ≥5% 严重 / ≥2% 警告 / ≥0.5% 提示 | SYN 重发不计入重传率，单独归为建连问题 |
| L4 传输 | 零窗口 / 窗口满 | 零窗口 ≥3 或窗口满 ≥10 → 警告 | 接收端应用处理不过来，不是网络慢 |
| L7 应用 | DNS 失败率 | ≥50% 严重 / ≥20% 警告 | 域名配错、DNS 劫持、恶意程序 |
| L7 应用 | DNS 耗时 | ≥300ms 警告 / ≥800ms 严重 | 打开网页前的第一跳等待 |
| L7 应用 | HTTP 5xx | ≥10% 严重 / 有则警告 | 服务端错误，网络不背锅 |
| L7 应用 | HTTP 耗时 | ≥1s 或 P95 ≥3s → 警告 | 需与 RTT 对比区分服务端慢 |
| 安全观察 | 高危端口外联 / 明文凭证 | 仅作附带项 | 不参与主判定 |

判定优先级：**自下而上**。同为「严重」时，先报底层（L2 → L3 → L4 → L7），
因为底层故障会连带影响上层指标。

威胁情报为可选增强：在 `config/app-config.json` 填 `threat_intel_key`（AbuseIPDB）即启用，
留空则跳过，全程离线可用。

## 权限与降级

实时抓包在 Windows 上依赖 **Npcap 驱动 + 管理员权限**，这是系统约束，无法绕过：

- `start.bat` 会先尝试 UAC 提权，未提权则继续以普通权限启动；
- Npcap 缺失时自动静默安装 `tools\npcap-*.exe`（`/S /winpcap_mode=no /loopback_support=yes`）；
- 抓包因权限/驱动失败时，工具直接返回降级提示，不中断流程；
- 降级路径：把目标机器上的 pcap 拖进「离线分析」，分析能力完全一致。

## 盘符自适应

U 盘盘符在不同机器上会变（F:、G:、H:…）。`bootstrap.py` 每次启动都用当前真实路径
重写 `config/mcp-wireshark.json` 与 `config/harness-config.json`，因此不需要手工改盘符。

## 接入 MCP / Agent

- MCP 配置：`config/mcp-wireshark.json`（`command` 指向盘内便携 Python，`TSHARK_PATH` 指向盘内 tshark）。
- 工具：`probe_link`（协议自适应体检）、`listen_flows`（被动监听会话表）、`list_interfaces`、
  `capture_live_packets`、`scan_network_threats`、`analyze_pcap`、`doctor`。
- 手工冒烟：

```bat
tools\python\python.exe -c "print('{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}')" | tools\python\python.exe mcp\wireshark-mcp\server.py
```

- 工作流固化在 `skills/network-diagnose/SKILL.md`，含固定输出格式与降级分支。
- `harness/` 已内置 DeepSeek Harness 便携版（0.2.0-rc.2，默认 3081 端口），
  用 `start.bat ai` 会连同诊断 UI 一起拉起；不启动它时工具链完全独立可用。

## 故障排查

| 现象 | 处理 |
|---|---|
| 提示「未找到 tshark」 | 确认 `tools\WiresharkPortable\App\Wireshark\tshark.exe` 存在 |
| 抓包 0 报文 | 工具会自动探测网卡；仍为 0 时在界面下拉框手动指定网卡 |
| 抓包报权限不足 | 右键 `start.bat` → 以管理员身份运行；或改用离线分析 |
| 端口 8787 被占用 | 自动顺延到 8788-8797；也可改 `config/app-config.json` 的 `server_port` |
| 报告里没有威胁情报 | 未配置 `threat_intel_key`，属正常 |
| 报告显示 RTT 为「-」 | 本次抓包没有 ACK 采样（纯 UDP 或短连接），用链路体检补测 |
| 体检显示「连不上」 | 先用 `telnet IP 端口` 或 `Test-NetConnection` 复核，再查防火墙/安全组 |

## 版本

- **应用版本：v0.1.0（测试版）**，见 `VERSION`；变更记录见 [CHANGELOG.md](CHANGELOG.md)
- 便携 Python 3.11.9（Embedded amd64）
- Wireshark Portable 4.7.4（tshark 4.7.4，通过 MSI 管理安装解出）
- Npcap 1.79 离线安装包
- DeepSeek Harness Portable 0.2.0-rc.2（`harness/`，内置 Node 运行时）
- 仅使用 Python 标准库，无 pip 依赖，离线可跑
