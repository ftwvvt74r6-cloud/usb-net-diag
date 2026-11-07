# 一页看懂 NetDiag（网络矩阵）

> 这份文档写给「第一次打开仓库的人」，也写给「三个月后回来改代码的自己」。
> 目标是 5 分钟建立正确的心智模型，不涉及实现细节。实现细节看
> [`api-reference.md`](./api-reference.md)（自动生成，签名永远是真的）。

## 1. 这工具是干什么的

一句话：**把「网慢/卡/连不上/时通时不通」定位到具体一层、具体对端、具体下一步。**

主线是故障排查，安全检测只是附带观察，不抢主线：

| 工作区 | 回答什么问题 | 输入 |
|---|---|---|
| 单目标诊断（定向抓包）/ 全网体检（全网扫描） | 这段时间网络上到底发生了什么 | 网卡 + 目标 + 时长 |
| 通信观察（被动监听） | 现在正在连谁、用什么协议、有没有扇出（P2P/云盘） | 网卡 + 时长 |
| 分析抓包文件（离线分析） | 别人给我的 pcap 里有什么问题 | pcap 文件 |
| 连通与速度测试（链路体检） | 到某个目标，慢在哪一段（DNS/TCP/TLS/应用） | 目标地址 |

它**不做什么**：不做持续监控、不做流量清洗、不当压测工具（体检有并发闸门）、
不改目标机器的任何配置。

## 2. 一次诊断的数据流

```
  网卡 / pcap
      │
      ▼
 ① 采集 capture      tshark -T fields 一次取全字段，按行流式读
      │              （大文件不进内存；必须检查退出码，见下）
      ▼
 ② 提取 extract      逐行聚合成 counters / streams / flows
      │              输出：Features（含 missing 集合）
      ▼
 ③ 规则 rules        features → findings（rule_id + 指标 + 证据，**不含中文**）
      │              requires 未满足 → 跳过 + 记进 skipped
      ▼
 ④ 判定 verdict      分层状态 + 证据充分性 → 一句话结论 + 下一步
      │
      ▼
 ⑤ 出口 render       Markdown / JSON / UI / AI prompt / MCP
                     （**脱敏只在这里做**，规则层必须看得到真实 IP）
```

关键约束：**只有 ① 能调用 tshark/scapy；只有 ⑤ 能对外发送。**
中间三层是纯函数，可拿 `features.json` 回放，测试不需要抓包。

## 3. 五个必须先懂的概念

### 3.1 分层定位（L2 → L3 → L4 → L7）

ARP 不通是 L2；ICMP 不可达是 L3；SYN 没回应、重传是 L4；DNS/HTTP/TLS 是 L7。
**报「网络慢」是没用的**，报「L4 重传 5.6%，集中在 3 条会话」才能干活。

### 3.2 证据充分性（`Sufficiency`）

「没抓到样本」和「样本为 0」是两件完全不同的事。
1 KB 的空抓包必须报「无法判定」，不能报「各层正常」——
这是评审里被判为 P0 的误报来源。

代码里的体现：`Features.missing` 记录「哪些特征没算出来」，
规则声明 `requires`，缺了就跳过而不是判 0。

### 3.3 方向（`Direction`）

抓包点在本机。看到「客户端重传」既可能是上行丢包，也可能是下行 ACK 丢了。
所以统计必须拆成 `c2s` / `s2c` 两份（`DirStat`），
零窗口这类字段还要记录**通告方是谁** —— 对方通告窗口为 0 是对方慢（VDI 常见），
我方通告窗口为 0 才是我方慢。

### 3.4 实测 vs 推断（`EvidenceKind`）

`MEASURED`：直接观测到的数值。
`INFERRED`：推断，**必须**带 `confidence < 1.0`，界面上写「疑似」。

这条是硬约束（`Finding.validate()` 会抛异常），目的是不让「疑似上行丢包」
被写成「上行丢包」传到工单里。

### 3.5 文案与逻辑分离

`core/rules/**` 里**禁止写中文**。规则只产出 `rule_id` + 指标 + 证据，
中文一律查 `core/copy/zh-CN.json`。

好处：改文案不动逻辑；CI 断言 `rule_id` 不会因为改字而红；多语言只是加一份 json。

## 4. 目录约定

```
core/            纯逻辑（不碰网络/时钟的地方尽量纯）
  contracts.py   全项目唯一数据契约（Layer/Severity/Finding/Features...）
  config.py      配置加载（用户可改的 app-config 与随代码走的 thresholds 分开）
  platform/      平台适配（管理员、Npcap、网卡、网关）—— 只这一层碰操作系统
  rules/         规则与迁移映射表
  capture/       唯一允许调 tshark/scapy 的地方
  egress/        唯一的对外出口（脱敏在这里）
  render/        Markdown / JSON 渲染
  api/           HTTP 路由（/api/v1/*，旧 /api/* 保留别名）
ui/index.html    单文件前端（无构建链）
mcp/             MCP stdio 服务端（零第三方依赖）
tests/           单元与回归用例
scripts/         gen_api_doc.py（文档生成，进 CI）
tools/           便携 Python / Wireshark / Npcap（**不入库**）
```

## 5. 常用命令

```bat
:: 起界面（静默，无黑窗）
NetDiag.vbs

:: 只做环境自检
tools\python\python.exe core\bootstrap.py --check

:: 命令行分析一个抓包文件
tools\python\python.exe core\diagnose.py --pcap captures\faults_demo.pcap --json

:: 全量自检（含真实抓包，约 40 秒）
tools\python\python.exe tests\selftest.py

:: 单元测试 / 契约测试
tools\python\python.exe -m unittest discover -s tests -v

:: 重新生成接口文档 + 检查注释覆盖率
tools\python\python.exe scripts\gen_api_doc.py
tools\python\python.exe scripts\gen_api_doc.py --check 0.95
```

## 6. 三个必读文档

| 文档 | 什么时候看 |
|---|---|
| [`api-reference.md`](./api-reference.md) | 要知道某个函数**收什么、返回什么、会抛什么**。自动生成，禁止手改 |
| [`api-style.md`](./api-style.md) | 要写新函数、补注释。规定了 Args/Returns/Raises 的三层写法 |
| [`docstring-gaps.md`](./docstring-gaps.md) | 想知道「还有哪些接口没写清」。是待办清单，通过 `--check` 后为空 |

## 7. 两个容易踩的坑（血泪版）

1. **tshark 退出码不能忽略。** 对不完整文件它返回 14 并只输出一半报文；
   只判断「有没有解析到包」会把半份数据当完整结论，产出幻影告警。
   详见 [`t00-findings.md`](./t00-findings.md)。
2. **`core/` 会遮住标准库。** 入口把 `core/` 加进 `sys.path`，
   所以 `core/platform/` 会遮住标准库 `platform`（Scapy 因此报
   `module 'platform' has no attribute 'release'`）。
   目前靠 `core/platform/__init__.py` 顶部的自愈垫片解决，
   目录收敛后应删除该垫片。
