# USB-Net-Diag 方案评审与架构改造建议

> 对象：`规划.docx`（usb-net-diag 项目迭代与工程化落地行动指南，7 步）
> 方式：**只读审查**本地工作区源码（未修改任何既有文件），逐条判断可行性并给出改造建议
> 评审版本：`v0.1.0`（`VERSION` = `0.1.0`），单一提交 `0bd5dbf`
> 结论摘要：方向可行，约 60% 可直接执行；**第 5 步的 3 条规则判据必须改**，第 2/3/4 步的实施方式需重写
> **历史文档说明**：本文件保留 v0.1.0 时期的模式旧名（被动监听 / 链路体检 / 定向抓包等）；
> 2026-11 改名后的对照表见 `CHANGELOG.md` 顶部，当前产品文案一律用新名。

---

## 目录

1. [项目现状体检](#1-项目现状体检)
2. [七步方案逐条评审](#2-七步方案逐条评审)
3. [三处必须修正的技术判断](#3-三处必须修正的技术判断)
4. [架构与接口定义](#4-架构与接口定义)
5. [落地风险清单](#5-落地风险清单)
6. [建议执行顺序](#6-建议执行顺序)
7. [附录 A：运行环境下载清单](#附录-a运行环境下载清单)
8. [附录 B：本次审查已核实的事实](#附录-b本次审查已核实的事实)
9. [附录 C：GitHub 与本地源码的工作方式](#附录-cgithub-与本地源码的工作方式)

配套骨架代码见 `scaffold/`，说明见 `scaffold/README.md`。

---

## 1. 项目现状体检

### 1.1 规模与结构

| 项 | 实测 |
|---|---|
| 入库文件 | 27 个（`git ls-files`） |
| Python | `core/` 约 4.4k 行 + `mcp/` 262 行 + `tests/` 88 行 |
| 前端 | `ui/index.html` 单文件约 58 KB（1300+ 行） |
| 提交历史 | 1 个（`0bd5dbf feat: USB-Net-Diag v0.1.0 …`） |
| CI | `.github/workflows/smoke.yml`：`compileall` + 契约测试 + 密钥扫描 |
| 依赖 | 纯标准库 + tshark + 可选 scapy |

### 1.2 值得保留的设计（改架构时不要动）

| 设计 | 位置 | 价值 |
|---|---|---|
| 四层模型 + 「自下而上」判定优先级 | `core/verdict.py` `LAYER_RANK` | 产品的核心资产 |
| 单次 tshark 全字段扫描 + 边读边聚合 | `core/analyzer.py` `collect()` | 大 pcap 不炸内存 |
| 完整降级链路（无 tshark → 离线；无 Npcap → 上传 pcap） | `core/diagnose.py` `capture_live()` | 落地性最关键的一环 |
| 「协议自适应体检」而非硬套 HTTP/TLS | `core/probe.py` `_identify()` | 全项目最具差异化的部分 |
| 服务只绑 `127.0.0.1` + Host/Origin 校验 | `core/server.py` `_guard()` | 基本安全面 |
| 「没样本显示 `-` 而不是 0ms」 | `core/report.py` `_opt()` | 细节正确性，商业工具常做错 |

### 1.3 问题清单

#### P0-1　数据契约缺失：中文文案就是接口

`rows[]` 的 `layer` / `category` / `severity` 直接是中文串（`"L4 传输层"`、`"严重"`），被 UI、Markdown、JSON 报告、AI prompt、MCP 五个出口消费。

后果：

- 改一句文案 = 破一次接口；
- 规划第 2 步「断言输出包含 L4 和 重传」本质是在断言**中文文案**，CI 会被文案锁死；
- 没有稳定机器码 → 无法做规则级回归、无法统计规则命中率；
- `evidence` 是「人话 + 帧号 + Stream」混合的自由文本，不可结构化校验。

> **这是全项目最该先动的地方**，优先级高于架构图。

#### P0-2　TCP 指标全部「无方向」

`core/analyzer.py` 中 `retrans` / `dup_ack` / `ooo` / `zero_win` / `lost` 均为**流级累加**，不区分 `c2s` / `s2c`。
直接导致规划第 5 步的三条规则**在现有特征上无法正确实现**（详见第 3 节）。

#### P0-3　AI 外发边界不存在，且已有真实泄露路径

`core/ai.py` `build_messages()` 实际外发内容清单：

| 类别 | 具体内容 |
|---|---|
| 私网 IP | `streams_top[].client` / `.server`（如 `192.168.1.100`） |
| 公网 IP | `top_external`、`ext_detail` |
| DNS 服务器 IP | `dns_detail[].server`、`dns_servers` |
| 主机名 / 域名 | `http_hosts`、`tls_sni`、`dns_top` |
| URI | `http_slow[].uri`、`dns_detail` 相关字段 |
| 帧号 | 全文（`帧 #35`） |
| 资产画像 | 协议分布、网段结构、会话数 |

更具体的泄露路径：`core/analyzer.py` 把 `uri_secret` 的 URI **前 50 字符**拼进 `finding`，而 `finding` 会同时进入**报告、AI prompt、MCP 返回**。
若 URL 为 `?password=Abc12345&user=zhang`，50 字符足够带走口令。

此外 MCP 出口把**完整 Markdown 报告**交给 Agent（`mcp/wireshark-mcp/server.py`），与 AI 属同一信任域——规划第 3 步漏掉了这个出口。

#### P0-4　缺「证据充分性」闸门 → 会给出危险的「正常」

只有 `packets == 0` 才提示采集无效（`core/diagnose.py`）。实测日志：

```
[15:17:06] 抓包完成：diag_20261106_151636.pcapng（1 KB）
[15:17:07] 诊断完成：严重 0 项，警告 0 项
```

1 KB 的包 + `host 172.19.4.189` 过滤 → 结论「各层指标正常」。
一线运维最不能接受「工具说正常、业务不能登录」。

**建议**：加入样本充分性判定（`duration < 10s` / `tcp_streams < 3` / `rtt_samples < 5` / `dns_samples == 0`），不满足时结论降级为「**证据不足，无法判定**」，并明确写出缺什么、怎么补采。此项成本最低、收益最高。

#### P0-5　可复现性存疑（CI 的前提）

同一份 pcap 三次分析，结论不一致：

```
[16:06:36] 解析 diag_20261106_160617.pcapng → 严重 0 项，警告 2 项
[16:07:35] 解析 diag_20261106_160617.pcapng → 严重 0 项，警告 0 项
[16:07:45] 解析 diag_20261106_160617.pcapng → 严重 0 项，警告 0 项
```

按代码读不应有差异（`build_findings` 不消费 `meta`）。最可能：首次分析时抓包文件尚未写完，或同名文件被覆盖。
**必须先复现清楚**——规划第 2 步的全部价值建立在「同一输入 → 同一结论」上。

#### P1　其他问题

| 问题 | 位置 | 影响 |
|---|---|---|
| 单例任务槽，无 `job_id` / 无取消 / 无幂等 | `server.py` `JOB` | 无法并发、无法追溯「哪次诊断」 |
| `/api/status` 每 1.2 s 回传**全量 result** | `server.py` `do_GET` | 大 pcap 时 UI 卡顿 |
| 上传无大小上限、无 Content-Type 校验、无分片 | `server.py` `/api/upload` | 本机磁盘 DoS |
| 无静态资源路由，只回 `/` 与 `/index.html` | `server.py` `do_GET` | **这才是 UI 只能单文件的真正原因** |
| `sys.path.insert` + 扁平 import（`from tshark import`） | `diagnose.py`、`analyzer.py` | `python -m core.analyzer` 直接失败；命名冲突风险 |
| `conn_refused` 用「流里有 RST」计数 | `analyzer.py` `_metrics()` | 正常关闭后的 RST 被误判成「端口没开」 |
| `dns_timeouts = 查询数 − 响应数` | `analyzer.py` `_metrics()` | 重传查询 / 多响应时失真 |
| 报告按 pcap 文件名覆盖写 | `report.py` `save()` | 同文件多次诊断互相覆盖，无审计价值 |
| `verdict.build()` 被调用两次 | `report.py` `save()` | 有状态化隐患 |
| 死代码：`analyzer.SEV_ORDER`；`compute_layers` 的 `category != "安全观察"` 永不命中 | `analyzer.py` / `verdict.py` | 安全项其实靠 `layer` 排除，易被后来者改错 |
| MCP 工具参数命名不一致 | `target_ip` vs `target` | Agent 侧易错 |

---

## 2. 七步方案逐条评审

| 步骤 | 判定 | 必须改的点 |
|---|---|---|
| 0 Git 接管 | ✅ 可行 | `.gitignore` 事实有误；SSH 22 可能被封；补 `AGENTS.md` + 分支保护 |
| 1 架构图 | ✅ 该做 | 先定契约再画图；图要画出 3 个边界 |
| 2 CI 回归 | ⚠️ 方向对，**实施方式必须改** | 不依赖 tshark；断言机器码；样本被 gitignore 挡住 |
| 3 脱敏 | ⚠️ 必要，**位置与策略都要改** | 放在外发边界；用伪名化而非全掩码 |
| 4 MTR | ⚠️ 半可行 | Windows 无 mtr；别解析本地化 `tracert`；用内置 scapy |
| 5 规则增强 | ❌ **3 条判据里 2 条方向错、1 条数据上不成立** | 见第 3 节 |
| 6 影子探测 | ✅ 性价比最高 | 必须先解决「探针污染诊断」 |
| 7 服务端探针 | ✅ 暂缓正确 | 现在就要预留「双侧对比」数据模型 |

### 第 0 步：可行，但有 3 处事实偏差

1. **`.gitignore` 现状与规划描述不同**：没有 `*.exe` 规则（`tools/`、`harness/` 目录规则顺带覆盖）；`*.pcap` 全局忽略 + `!captures/faults_demo.pcap` 例外，所以 `captures/faults_demo.pcap` **已入库**，而 `tests/pcap_samples/*.pcap` **会被静默忽略**——直接卡住第 2 步。
2. 公司网络常封 22 端口。备选：`ssh -T -p 443 git@ssh.github.com`，或退回 HTTPS + PAT。建议写进文档避免现场卡住。
3. 「新建 `test_git.txt` 验证推送」太弱。更好的验证是**让 `smoke.yml` 跑绿一次**。

补充：仓库的 `.gitignore` 已把 `tools/`、`harness/` 排除，**这与你「U 盘里有 exe 但仓库没有」的情况一致，是正确做法**，不要为了「仓库完整」把 900 MB 二进制塞进去。

### 第 1 步：该做，但顺序与内容要调整

规划的数据流图写的是 `pcap → analyzer → 脱敏 → verdict → AI → 报告`。
**这个顺序是错的**：脱敏放在 verdict 之前，规则引擎就看不到 IP，无法回答「哪个对端」——而这是 README 承诺的第一性价值。

正确的图应体现 **3 个边界**：

```
        采集边界              规则边界                外发边界
pcap/live ──► Features ──► Findings ──► Verdict ──┬──► Markdown/JSON（本地）
                                                   ├──► AI 请求（云）    ← 脱敏
                                                   ├──► 日志 / 导出      ← 脱敏
                                                   └──► MCP 返回（Agent）← 脱敏
```

建议产出 3 份文档而非 1 份：

| 文档 | 内容 |
|---|---|
| `docs/architecture.md` | 模块与依赖、3 个边界 |
| `docs/data-contract.md` | 契约定义、`schema_version`、兼容策略 |
| `docs/rules.md` | 规则表：`rule_id`/层/阈值/证据/建议/置信度 |

第三份是「改需求」时最常改的文件，也是 AI 最需要读的输入。

### 第 2 步：CI 方向对，但有 4 个坑

1. **别在 CI 里装 tshark 才能测规则**。当前 `analyzer.collect()` 把「tshark 适配 + 字段解析 + 聚合」揉在一起，规则测试被迫依赖外部二进制。拆开后规则测试是纯 Python，可跑 `ubuntu-latest`（快 3 倍、便宜 10 倍），只有抓包相关才上 Windows。
2. **断言机器码，不要断言中文**。`input=TCP重传 → 必须包含 "L4" 和 "重传"` 这种断言改一次文案红一片，最后团队会去改测试而不是改代码。应断言 `finding.rule_id == "L4.RETRANS.HIGH"`、`layer == L4`。
3. **pcap 样本别提交二进制**。`faults_demo.pcap` 仅 54 个包 / 8.6 KB，说明样本可生成。建议 `tests/fixtures/gen_pcap.py` 确定性生成（裸 pcap 写入，不依赖 scapy）→ 无二进制、可 review、可造边界样本（丢 1 包 vs 丢 30%）。若坚持提交，必须加 `!tests/pcap_samples/*.pcap`，否则 CI 拿不到文件、测试静默跳过——**最容易「绿着但什么都没测」的坑**。
4. 补两样：`golden` 快照（result JSON 归一化后 diff）+ 反向断言（「不得出现」比「必须出现」更能防 AI 改坏）。

现有 CI 的密钥扫描很好，建议再加一条**敏感数据扫描**：禁止真实内网网段/主机名进入 `docs/`、`reports/`、测试期望值。

### 第 3 步：脱敏必要，但位置与策略都要改

**位置错**：不是「送进 `ai.py` 之前」，而是**每个外发出口各拦一次**（AI / 报告文件 / 日志 / MCP / 导出）。规则与 verdict 必须看真值。

**策略建议改为「可逆伪名化」而非全掩码**：

| 对象 | 规划方案 | 建议 |
|---|---|---|
| 私网 IP | `[INTERNAL_IP_MASKED]` | `<ip:lan-1>`，**保留端口与方向**；映射表只存本地（可关）。理由：报告要给人回查，全掩码后运维没法照着去 ping |
| 公网 IP | 同上 | 保留，或按 profile 只保留 /24 |
| 域名 / SNI | 未提 | 保留 TLD + 二级域名短哈希：`a1b2.corp.example.com`。**全抹会让模型误判因果**（它靠域名区分「同一站点」还是「到处都慢」） |
| Cookie / Authorization | `[COOKIE_MASKED]` | **不采集**比采集后脱敏彻底（当前没采 Cookie，`http.authorization` 只进内存，但一加字段就漏） |
| 帧号 | 未提 | 换成相对序号（`#3/54`），保留定位能力、去掉环境指纹 |

**关键认知**：影响 AI 判断的特征是**方向、端口、时序、flags、窗口、重传位置**——都不在 IP 字符串里。所以「保留协议特征」不等于「只 mask IP」，而是**别 mask 端口和方向**。

**验收测试要双断言**：

- 正向：输出不含原 IP / 原 Cookie / 原 URI；
- 反向：**脱敏前后对同一 pcap 的 `findings[].rule_id + severity` 完全一致**。这条才真正证明「脱敏不影响判断」。

最后：**区分两个信任域**。本地 `logs/` 保留明文（排障需要），但①标注含敏感信息 ②提供一键清理 ③导出/分享时强制脱敏。一刀切全脱敏会让工具自己无法排障。

### 第 4 步：MTR 半可行，实现方式要换

三个硬约束：

1. **Windows 没有 mtr**，只有 `tracert`。每跳仅 3 次探测、**不输出丢包率**，拿不到「第几跳开始丢」所需的统计量。
2. `tracert` 输出**本地化**（中文 Windows 是「请求超时」「目标不可达」），文本解析极脆弱，且与本项目「纯标准库、稳健」的定位冲突。
3. 企业网常在核心/防火墙**对 ICMP 限速或禁 ping**，会出现「中间跳全丢、最后一跳可达」，直接误判成运营商故障。

**建议实现**：用已内置的 **scapy 2.8**（现仅 `passive.py` 使用）实现 TTL 递增探测：每跳 N 次采样 → 丢包率 + RTT + 抖动。
网关 / DNS 服务器**不要解析 `ipconfig` 文本**，用 `ctypes` 调 `GetAdaptersAddresses` / `GetIpForwardTable2`，或 scapy 的 `conf.route.default_gateway`。

定界判据要加「ICMP 被过滤」第四态：

```
逐跳都丢，但目标端口 TCP 可通    → 判定为 ICMP 被策略过滤，不下故障结论
第 1 跳即丢，且 TCP 也不通       → 终端侧 / 接入层
中间跳开始丢且持续到末跳         → 承载网 / 运营商
仅末跳丢（前序 0%）             → 服务端接入链路
```

还要**防抖与冷却**：不能「重传率 ≥ 5% 就 traceroute」。建议「同一目标 ≥ 2 次采样 + 间隔 ≥ 10 s + 冷却 ≥ 60 s」，并把探测账本写入 result 以便复现。

### 第 6 步：影子探测性价比最高，但有 4 个必须补的设计

1. **探针不能污染诊断**（最关键）。探针产生的 ICMP 超时会被计成 L3 故障，SYN 会变成额外 stream 甚至 RST。必须二选一：抓包 BPF 排除（`not icmp and not (tcp and host <probe_target>)`），或把探针账本传进 analyzer 按五元组 + 时间窗排除。**不做这条，功能一上线就会把工具变成误报机器。**
2. **探针必须可识别为自己发的**：固定源端口段 / 自定义 payload 标记 / 固定 TTL，写进账本。
3. **时钟对齐**：pcap 用系统时钟（`frame.time_epoch`），探针用 `time.monotonic()`，两者有偏移。要么做偏移校准，要么只做「区间归属」不做逐包对齐。
4. **三态结论**：通 / 不通 / **被过滤**。ICMP 不回 ≠ 丢包。

建议把第 4、6 步**合并为同一个模块** `pathprobe.py`，共用「目标发现 → 探测 → 账本 → 结论」四段，避免重复踩同样的坑。

### 第 7 步：暂缓正确，但现在就要留好数据模型

最小预留（缺一则「二分法定位」以后要重做）：

```python
CaptureSide = Literal["client", "server"]

@dataclass
class EndpointObservation:
    case_id: str                        # 同一次业务复现的标识（双侧共用）
    capture_id: str
    side: CaptureSide
    clock_offset_ms: float              # 与 case 基准时钟的偏移
    five_tuple: tuple[str, int, str, int, str]
    seq_ranges: list[tuple[int, int]]   # 收到/发出的序号区间
```

---

## 3. 三处必须修正的技术判断

这是整份规划里**技术上最需要改**的一节。

### 3.1 「上行丢包推断：重传率高 + RTT 稳定 → 大概率服务端未收到数据」

**问题**：抓包点在本机。「客户端重传同一 seq」只证明「客户端发了两次、没收到 ACK」，可能是：

| 实际原因 | 与规划假设 | 说明 |
|---|---|---|
| (a) 上行丢包 | ✅ 一致 | 服务端确实没收到 |
| (b) 下行丢包 | ❌ 反了 | 服务端收到了，但 ACK 在回程丢了 |
| (c) 服务端未处理 | ❌ 完全不同 | 收到了但应用/窗口没响应 |

而「RTT 稳定」只能排除「拥塞导致 RTT 膨胀」，**不能定位方向**。

**正确判据**（需先补方向特征）：

| 观察 | 推断 | 置信度 |
|---|---|---|
| 客户端重传 + 服务端持续 **dup-ACK** | 上行丢包（服务端见到后续包、缺一段） | 高 |
| 客户端重传 + 服务端**无 dup-ACK**、RTT 稳定 | 上行丢包**或**对端未处理 | 中 |
| 双向都有重传 + dup-ACK 双向都有 | 双向 / 中间设备劣化 | 高 |
| 服务端重传 + 客户端 dup-ACK | 下行丢包 | 高 |
| 出现 **DSACK / spurious retransmission** | 其实没丢，是超时误判 | 排他 |

结论必须写成「**疑似**上行丢包（置信度中），证据：…」，并给出证伪方法（例如影子探测同时段测网关与对端端口：两侧同丢 → 上行；只对端丢 → 对端侧）。原写法会给出过于确定的错话，在客户现场直接引发扯皮。

### 3.2 「检测到 TCP ZeroWindow → 服务端处理能力不足」

**方向可能完全反了**。零窗口由**接收方**通告，而当前代码只累加总数，无法归属。

| 通告方 | 含义 | 结论 |
|---|---|---|
| 服务端通告 | 客户端在上传，服务端应用读不过来 | 服务端瓶颈 ✅（规划说法） |
| 客户端通告 | 客户端在下载，客户端应用消费不过来 | **客户端瓶颈**（VDI 极常见：渲染卡、磁盘满、杀软扫描） |

注意 `core/verdict.py` 现有文案其实是对的（「接收端处理不过来」），**规划反而把它写错了方向**。必须按通告方归属，并区分 `c2s` / `s2c`。

### 3.3 「UDP 丢包（VDI 常见）提取时间戳 → 推断高峰期拥塞」

**在单点抓包路径上不成立**。UDP 无序号，无法从一份 pcap 直接算丢包率。当前**可测**的只有：

- RTP 序号缺口（VDI 语音/视频）
- DNS 查询无响应
- ICMP 端口不可达
- QUIC 包号缺口
- **主动探测**的丢包（第 4/6 步的产物）

且「高峰期」需要**历史基线**——现在每次诊断一次性、报告还覆盖写，无法回答「比昨天更差吗」。

### 3.4 规划缺失的一层：持久化与基线

> 用内置 `sqlite3`（便携 Python 已带 `_sqlite3.pyd` + `sqlite3.dll`）建 `data/history.db`：
> `case(id, ts, target, profile, level, metrics_json, rules_hit)`。

有了它才可能：① 高峰期 vs 平时对比 ② 同目标前后对比 ③ 规则误报率统计 ④ 给 AI 一个「基线」而不是让它猜。

**这是从「一次性工具」走向「成熟产品」的分水岭**，成本却很低。骨架见 `scaffold/core/history.py`。

---

## 4. 架构与接口定义

### 4.1 五条不变量（先定这个，再定目录）

1. **纯核心**：`findings = rules(features)` 必须是纯函数，不碰文件、网络、时钟。
2. **单一边界**：只有 `capture/` 能调用 tshark/scapy；只有 `egress/` 能对外发送。
3. **契约先行**：所有跨模块数据必须有 `schema_version`，且可序列化为 JSON。
4. **文案与逻辑分离**：规则只产出 `rule_id + 指标 + 证据`；中文标题/解释/建议查表得到。
5. **可复现**：任何 result 必须带 `provenance`（tshark 版本、规则版本、配置哈希、prompt 版本）。

### 4.2 目标模块树

```
core/
├── contracts.py        # 契约：Finding / Features / Verdict / Result（唯一真相）
├── errors.py           # 错误码 + 可展示异常
├── config.py           # 统一配置加载 + schema 校验 + config_sha256
├── copy/zh-CN.json     # 中文文案表（headline/impact/advice/labels）
├── platform/
│   ├── paths.py        # 根目录探测（标记文件，不靠固定层级）+ 目录约定
│   └── winapi.py       # 管理员、Npcap、网卡、路由表（ctypes，不解析本地化文本）
├── capture/
│   ├── tshark.py       # 唯一 tshark 适配器
│   └── live.py         # 抓包编排 + 降级
├── extract/
│   ├── fields.py       # FIELDS 定义 + -T fields 解析
│   └── aggregate.py    # 流级聚合，含 per-direction
├── rules/
│   ├── base.py         # Rule 协议 + registry + requires
│   ├── thresholds.json # 阈值外置
│   └── l2.py l3.py l4.py l7.py security.py
├── verdict/verdict.py  # findings → 主判定（纯函数）
├── pathprobe.py        # MTR + 影子探测（合并第 4、6 步）
├── probe.py            # 协议自适应体检
├── passive.py          # 被动监听
├── egress/
│   ├── sanitize.py     # 脱敏（AI / 报告 / 日志 / MCP / 导出）
│   └── ai.py           # 模型调用（只接受已脱敏 payload）
├── render/             # markdown.py / json_report.py
├── api/
│   ├── app.py          # 路由 + envelope
│   └── jobs.py         # JobStore（job_id / 取消 / 并发上限）
└── history.py          # 基线（sqlite3）
```

**迁移策略**（关键）：不要一次重构。保留现有 `core/*.py` 作为薄壳转发，`start.bat`、`config/mcp-wireshark.json`、README 的相对路径全部不动，3 个 PR 内完成，每步可回滚。

### 4.3 数据契约样例

完整实现见 `scaffold/core/contracts.py`。核心：

```python
SCHEMA_VERSION = "2.0"

class Layer(str, Enum):     L2, L3, L4, L7, SEC
class Severity(str, Enum):  CRITICAL, WARNING, INFO, OK, NA
class Direction(str, Enum): C2S, S2C, BIDIR
class EvidenceKind(str, Enum): MEASURED, INFERRED   # 推断类结论必须带这个标记

@dataclass(frozen=True)
class Finding:
    rule_id: str                  # "L4.RETRANS.HIGH" —— CI 只断言这个
    layer: Layer
    severity: Severity
    category: str                 # 英文码，非中文
    metric: dict                  # {"retrans_rate": 5.56, "retrans": 2, ...}
    targets: list[Endpoint]
    frames: list[int]             # 相对序号
    streams: list[int]
    direction: Direction | None   # ← 规划第 5 步全部依赖这个字段
    confidence: float             # 0~1；INFERRED 必须 < 1.0
    evidence_kind: EvidenceKind
    advice_key: str               # "L4.RETRANS.ADVICE"
```

配一张文案表 `core/copy/zh-CN.json`，中文标题/解释只在那里。这一条同时解决：CI 锁死文案、多语言、AI prompt 措辞一致性。

### 4.4 规则注册表（让第 5 步变得安全）

```python
@dataclass(frozen=True)
class Rule:
    id: str
    layer: Layer
    requires: frozenset[str]      # 依赖的特征键，缺失时 CI 报错而非静默返回 0
    version: int
    fn: Callable[[RuleContext], list[Finding]]

RULES = (ARP_NO_REPLY, TCP_RETRANS_HIGH, TCP_ZERO_WINDOW_SIDE,
         DNS_FAIL_HIGH, HTTP_5XX, ICMP_UNREACH, ...)
```

`requires` 是解药：现在「没样本 → 指标 0 → 显示正常」这个歧义，本质是**特征缺失与特征为零无法区分**。有了 `requires`，规则可显式返回「证据不足」。

### 4.5 HTTP API v1

现在的问题不是「不好看」，而是**无法追溯**：单例 `JOB`、无 id、无取消、错误格式三套（`{"ok":false}` / 纯文本 404 / 500）。

```
统一 envelope
{ "schema_version":"2.0", "ok":true,  "data":{...}, "error":null, "trace_id":"..." }
{ "schema_version":"2.0", "ok":false, "data":null,
  "error":{"code":"E_NO_TSHARK","message":"…","hint":"装 Npcap 或改用离线分析"},
  "trace_id":"..." }

POST   /api/v1/jobs            {kind:"scan|passive|probe|pathprobe", params:{…}} → 202 {job_id}
GET    /api/v1/jobs/{id}       → {state, progress_pct, logs_tail, error, result_ref}
GET    /api/v1/jobs/{id}/result?since=<seq>   → 增量，避免全量轮询
POST   /api/v1/jobs/{id}/cancel
GET    /api/v1/captures
POST   /api/v1/uploads?chunk=<n>&of=<m>       → 分片 + 上限
POST   /api/v1/ai/analyze      {job_id, question} → {text, model, prompt_sha}
```

旧路由保留为别名（1 个版本后删）。`X-Request-Id` 进日志，`trace_id` 进 result——同一份报告能直接对着日志查。

### 4.6 AI 层怎么变「成熟」

当前 `ai.py` 是自由文本输出，模型换版本结论就漂。建议：

1. **结构化输出 + 校验**：要求返回固定 JSON（`headline/layers[]/points[]/steps[]`），本地 schema 校验，失败重试 1 次，仍失败则**只出 L1 结果**（永不因 AI 失败而丢诊断）。
2. **prompt 版本化**：带 `prompt_version`，写进 report 的 provenance。
3. **L1 优先**：AI 只能「解释」和「排序」，不能**新增**未出现在 findings 里的事实。把 findings 的 IP/端口/数字抽出来做后置校验，出现未授权 IP 就整段降级为「AI 输出未通过校验」。
4. API Key 目前明文存 `config/ai-config.json`（已 gitignore）。可选增强：Windows DPAPI（`CryptProtectData`，ctypes 即可）绑定当前用户加密；U 盘跨机器会失效 → 做成可选开关，默认明文但界面明确提示。别为了安全把便携性做没了。

### 4.7 UI 的必然改动

`server.py` 没有静态路由，所以 `ui/index.html` 只能单文件。加上 `GET /static/*`（带 `Cache-Control` + 内容哈希）之后，才能拆成 `ui/app.js` + `ui/views/*.js`（原生 ES module，不需要打包器）。不急，但**不拆永远无法协作**——58 KB 单文件是 AI 最容易改崩的地方。

---

## 5. 落地风险清单

以下几条建议在写第一行新代码前先验证；任一不成立，整个方案的优先级都要重排。

| 风险 | 为什么是 P0 | 怎么验证 |
|---|---|---|
| **公司电脑拿不到管理员权限 / EDR 拦 Npcap 驱动安装** | 拿不到 = 实时抓包全废，「U 盘插上就能诊断」的核心卖点没了 | 第一天找目标机型实际装一次，跑通 `doctor.bat` |
| **Wireshark(GPL-2.0) + Npcap 的再分发合规** | 随 U 盘在公司内分发二进制属再分发行为，需确认义务 | 让法务/IT 过一遍；备选：改为「检测本机已有 tshark」 |
| **抓包内容的合规与伦理** | 抓的是本机网卡全部流量，可能包含同事数据；报告会落盘并被带出 | 明确「最小化采集 + 告知 + 留存期限 + 一键清除」 |
| **U 盘写保护 / 杀软扫描 / 只读盘符** | 多处直接 `write_text`，只读盘会静默失败或崩 | 启动时写权限探测 + 只读模式 |
| **大 pcap（>1 GB）** | 单次全字段扫描耗时线性拉长，UI 无法显示进度 | 时间窗/采样 + 进度回调（`-a duration` 或 `editcap` 切片） |
| **「同一 pcap 结论不一致」** | 直接摧毁 CI 与客户信任 | 先复现 P0-5 |

> 关于许可：Wireshark 采用 GPL-2.0，再分发二进制通常需要随附许可证并提供对应源码获取方式；Npcap 的免费版与 OEM 授权条款不同，商业分发需单独确认。**具体义务以官方许可条款为准，此处仅提示需在落地前确认。**

---

## 6. 建议执行顺序

原 0→7 的顺序有个根本问题：**第 2 步的 CI 建立在契约稳定之上，而契约要到第 3 步才被动到**。建议重排：

### 第 0 阶段（1~2 天）：先验证能不能落地
- 管理员权限 + Npcap 在目标机型上跑通（`doctor.bat`）
- 复现 P0-5 的非确定性
- 确认 Wireshark / Npcap 再分发的合规口径

### 第 1 阶段（3~5 天）：契约 + 方向性 + 证据闸门
- `contracts.py`（含 `direction`、`confidence`、`rule_id`、`provenance`）
- `extract/` 拆出纯特征层 + `features.json` 可落盘
- 补 `c2s/s2c` 双向统计 —— **第 5 步三条规则的前置条件**
- 加「证据充分性」闸门（P0-4）
- 修 `conn_refused` / `dns_timeouts` / 死代码

### 第 2 阶段（2~3 天）：CI 才真正开始有价值
- 脚本化生成 pcap 样本（或加 gitignore 例外）
- 规则单测（喂 `features.json`，不依赖 tshark）
- 机器码断言 + golden 快照 + 反向断言
- 分支保护 + `AGENTS.md`

### 第 3 阶段（3~4 天）：外发边界
- `egress/sanitize.py` + 三种 profile
- 修 `uri_secret` 泄露路径
- 双断言测试（结论不变 + 原值不出现）
- MCP 出口一起走

### 第 4 阶段（4~6 天）：路径探测 + 影子探测（合并）
- `pathprobe.py`（scapy TTL 探测 + 探针账本 + 过滤）
- 先做「探针不污染诊断」，再做探测本身

### 第 5 阶段：历史基线 + API v1 + 前端拆分（可与上并行）

### 第 6 阶段：第 7 步服务端探针的接口预留（只写契约，不实现）

---

## 附录 A：运行环境下载清单

> 仓库不含 `tools/`、`harness/`（`.gitignore` 已排除，这是正确的）。使用者需自行补齐。
> ⚠️ 下列为官方稳定入口。评审时机器已可通过代理访问 GitHub（`git ls-remote`、raw、API 均实测可用），
> 但**未逐一实测每个下载链接**，下载前请以官网为准。

### A.1 必需组件

| 组件 | 建议版本 | 官方地址 | 落位（仓库内） |
|---|---|---|---|
| Git for Windows | 最新 | <https://git-scm.com/download/win> | 系统安装（非仓库） |
| Python（Windows embeddable, 64-bit） | 3.11.9 | <https://www.python.org/downloads/windows/> → 直链 <https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip> | 解压到 `tools/python/` |
| Wireshark（含 tshark） | 4.7.x | <https://www.wireshark.org/download.html>　win64 列表：<https://www.wireshark.org/download/win64/> | 解出 `tshark.exe` 到 `tools/WiresharkPortable/App/Wireshark/` |
| Npcap（离线安装包，实时抓包必需） | 1.7x | <https://npcap.com/#download>　镜像：<https://nmap.org/npcap/> | `tools/npcap-1.79.exe`（`start.bat` 按 `npcap-*.exe` 通配匹配，版本号可改） |

### A.2 可选组件

| 组件 | 用途 | 官方地址 | 落位 |
|---|---|---|---|
| scapy | 被动监听（默认引擎）、**路径探测/影子探测建议也走它** | <https://pypi.org/project/scapy/>　文档：<https://scapy.net/> | `tools/python/Lib/site-packages/scapy/`（见下方命令） |
| Wireshark Portable（PortableApps） | 免 MSI 安装，直接解压 | <https://portableapps.com/apps/development/wireshark_portable> | 覆盖到 `tools/WiresharkPortable/` |
| Wireshark Portable（portapps） | 备选便携封装 | <https://github.com/portapps/wireshark-portable/releases> | 同上 |
| DeepSeek Harness 便携版 | Agent 底座（`start.bat ai`） | ⚠️ **无公开下载地址**，需向提供方获取；本仓库不含 | `harness/` |
| 7-Zip | 解压/提取 MSI 内容 | <https://www.7-zip.org/> | 系统安装 |

装 scapy 到内置 Python 的命令（PowerShell，在仓库根目录执行）：

```powershell
.\tools\python\python.exe -m pip install --no-warn-script-location `
    --target .\tools\python\Lib\site-packages scapy==2.8.0
```

### A.3 CI 用（不需要下载到 U 盘）

| 用途 | 方式 |
|---|---|
| Windows runner 装 tshark | `choco install wireshark --params "/NoNpcap"`（<https://community.chocolatey.org/packages/wireshark>）或 `winget install WiresharkFoundation.Wireshark` |

> 建议：**规则测试不要依赖 tshark**（见第 2 步），只有端到端的抓包测试才需要它。

### A.4 `tools/python/python311._pth` 内容

```
python311.zip
.
Lib\site-packages
```

### A.5 自检

```bat
doctor.bat
REM 等价于：tools\python\python.exe core\bootstrap.py --check
```

---

## 附录 B：本次审查已核实的事实

便于后续对照，避免以讹传讹：

| 事实 | 核实方式 |
|---|---|
| 工作区原本干净（`git status` 无输出），评审未改任何既有文件 | `git status --short` |
| 仓库 27 个入库文件、1 个提交、`origin` 为 HTTPS | `git ls-files`、`git log`、`git remote -v` |
| `captures/faults_demo.pcap` **已入库**（`.gitignore` 有 `!` 例外） | `git ls-files` |
| `.gitignore` 中**没有** `*.exe` 规则 | 通读 `.gitignore` |
| `tests/pcap_samples/*.pcap` 会被现有规则忽略 | 同上（`*.pcap` 全局忽略，无该类例外） |
| 内置 Python 为 3.11 且**带 `_sqlite3.pyd` + `sqlite3.dll`** | `tools/python/` 文件列表 → `history.py` 方案可行 |
| 内置 scapy 为 **2.8.0** | `tools/python/Lib/site-packages/scapy-2.8.0.dist-info` |
| tshark 实际版本 4.7.4 | README + `logs/` |
| 曾用 mock 模型（`127.0.0.1:8899`）测试 AI 调用 | `logs/diag_20261106.log` |
| 1 KB 抓包被判定为「严重 0 / 警告 0」 | `logs/diag_20261106.log` 15:17 |
| 同一 pcap 三次分析出现 2 → 0 → 0 警告 | `logs/diag_20261106.log` 16:06–16:07 |
| 本机经代理**可访问 GitHub**：`git ls-remote`、`raw.githubusercontent.com`、`api.github.com` 均实测可用 | 本次实测 |
| 远端 `main` = 本地 `HEAD` = `0bd5dbf63a0673243fcb10335bd7977557aa7c6e`（内容逐字一致） | `git rev-parse` + GitHub refs API |
| 仓库为 **public**、115 KB、单 commit、无其他分支 | GitHub API |
| 工作区所在卷 **G: 为 exFAT**（不支持硬链接） | `fsutil fsinfo volumeinfo G:` |

---

## 附录 C：GitHub 与本地源码的工作方式

### C.1 结论：以本地工作区为唯一可信源

| 视角 | 内容 | 是否完整 |
|---|---|---|
| 本地工作区（`<工作区目录>`） | 源码 + `tools/`（约 360 MB）+ `harness/`（约 540 MB）+ 真实 `config/*.json` + `captures/` + `logs/` + `reports/` | ✅ 完整 |
| GitHub 仓库 | 仅 27 个源码/配置模板文件（`tools/`、`harness/`、真实配置、抓包、日志、报告全部被忽略） | ❌ 缺运行依赖与真实配置 |

**原因**：

1. **仓库里没有 exe 和 `tools/`**，从 GitHub 看无法验证「tshark 是否找得到」「便携 Python 是否带 sqlite3/scapy」「网卡枚举是否正常」——而这些恰恰是评审的重点。
2. 仓库里没有真实 `config/ai-config.json`、`config/app-config.json`，看不到实际阈值与 Key 配置状态。
3. 仓库里没有 `logs/`、`reports/`、`captures/`（除 demo），看不到真实运行表现与结论分布。
4. 评审时 **Git 与 HTTP 两个通道都已打通**（已实测 `git ls-remote`、`raw.githubusercontent.com`、`api.github.com`），
   所以「读不读得到 GitHub」已不是问题；仍然读不到的，是被 `.gitignore` 排除的内容：
   `tools/`、`harness/`、真实 `config/*.json`、`logs/`、`reports/`、`captures/`。
   也就是说：**代码能对上，运行证据对不上**。而本次评审最有价值的两条结论
   （1 KB 空抓包被判「各层正常」、同一 pcap 两次结论不一致）恰恰来自 `logs/`。

### C.2 建议的协作方式

```
日常开发：本地 U 盘 / 公司电脑上的 clone  →  我直接读本地文件（默认）
版本对照：只在我需要「对比某次已推送的版本」时，你把 clone 目录告诉我路径
历史追溯：需要「这个文件上周长什么样」时，用 git 命令（我可以读 .git 里的对象）
```

具体规则：

- **我默认只看本地目录**，不看 GitHub；如果两者不一致，以本地为准，并**主动提醒你「本地与远端可能不同步」**。
- 判断是否同步**不需要联网**：`git status` + `git rev-parse HEAD` vs `git rev-parse origin/main` 就够。
- 若你要我评审「已推送到 GitHub 的版本」，**最省事的方式**是：`git clone` 到另一个本地目录（如 `<另一个本地目录>`），把这个路径告诉我，我在那里做只读审查。
- **CI 相关的判断**（Actions 是否绿、哪个 step 失败）我看不到，需要你把日志贴过来，或允许我用 `git log` / 本地复跑测试的方式间接验证。

### C.2.1 闭环工作流（配套「我审计 → 出文档 → 你交给公司 AI 实现」）

```
① 你发想法/需求（文字即可，不需要先写代码）
② 我读本地源码 + docs/code-index.md 定位，必要时 git diff 看上次交付后的改动
③ 我输出：评审结论 + 任务卡（id / steps / acceptance）+ 需要新增的文件清单
④ 公司 AI 按任务卡实现 → 提交 → 推送 main
⑤ 你告诉我「推完了」，我 git fetch origin → git log --oneline origin/main
   → git diff <上次sha>..origin/main，**只审 diff，不重读全仓**
⑥ 复核结论直接进下一轮任务卡
```

第 ⑤ 步是这套流程真正的价值：**审计可以增量做**，不必每次重读 4700 行。
唯一前提：**每次合并都要进 `main`**，否则我 `fetch` 不到你的分支。

### C.3 关于 `.gitignore` 的一个建议

保持现状（`tools/`、`harness/` 不进库）是对的。但建议增加两条，防止「体积失控」与「敏感数据入库」：

```gitignore
# 便携运行环境中的可执行文件，任何位置都不入库
*.exe
*.msi
*.dll

# 真实配置与抓包（已有规则，补充显式例外说明）
# tests/pcap_samples/*.pcap 若确需入库，必须在此处加 ! 例外
```

> 注意：`*.exe` 一旦加入，`captures/` 下的 demo 规则不受影响；但若将来要提交任何 exe（例如 CI 用的 stub），需显式 `!` 例外。

---

*本文档由只读评审生成，未修改仓库任何既有文件。骨架代码见 `scaffold/`，不参与现有构建。*
