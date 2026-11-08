# 路径剖面（MTR 逐跳）

> 对应批次：**D+ 增量 2**（`feat/d-shadow-probe`，PR #26）+ **G2 降级**（G 批次，
> `feat/g-generalize`）。目标：回答「问题出在**路径上的哪一跳**」——本地出口 /
> 承载网 / 对端侧 / ICMP 被过滤。有 scapy 用 MTR；没有 scapy 自动降级系统
> `tracert`（见第 4 节），不再把「没装 scapy」变成「路径探测不可用」。
>
> 一句话：**逐跳 RTT 与丢包不是地图，而是「从第几跳开始变坏」的坐标。**

本文只讲现状（代码以 `core/pathprobe.py` 为准），不写未来计划。

---

## 1. 它解决什么问题

「ping 网关丢包、ping 对端也丢包」不足以定位是本地接入、运营商还是对端。
MTR 逐跳在**同一条路径**上按 TTL 1..16 逐跳探测，得到每一跳的 RTT 与丢包，
再判断**第几跳开始劣化**：

```
第 1 跳就丢/慢，且持续到目标/最后响应跳 → 本地出口（终端 / 接入链路 / 网关）
中间某跳开始丢/慢，且持续到目标/最后响应跳 → 承载网（运营商 / 中间设备）
只有目标 / 最后一跳丢/慢               → 对端侧（服务端接入链路 / 对端主机）
中间跳丢/慢、后续跳与目标正常          → 疑似 ICMP 限速/策略过滤（不判承载网）
ICMP 全丢/TCP 可达                     → ICMP 被策略过滤（不是故障）
一个样本都没有                         → 证据不足（不判正常）
```

**「劣化」必须持续到目标或最后一个有响应的跳**：中间跳不回 ICMP、而后续跳/目标
正常，是路由器对 TTL 回复限速的常见形态，不能据此判承载网故障（R5）。

和「探针基线」（`docs/shadow-probe.md`）的关系：探针基线回答「网关 vs 对端谁更差」，
路径剖面回答「差在路径的哪一段」。两个区块都只**增加证据**，不改变主判定等级。

---

## 2. 怎么用

### 2.1 连通与速度测试页（手动）

1. 左侧切到「连通与速度测试」，填目标与端口；
2. 「逐跳路径（MTR / tracert）」默认勾选；取消勾选则完全不发逐跳探测包；
   有 scapy 时用 MTR，没有 scapy 时自动改用系统 `tracert`（每跳 3 次探测），
   界面上会提示「已降级」；
3. 结果区在体检结论下方出现逐跳表格 + 结论（探测方式行会写明 scapy / tracert）。

请求体是加法字段 `path: true|false`；旧版前端不传时后端按 **开** 处理。

同步 HTTP 入口有 **20 秒时间预算**（`core/server.py` 的 `PROBE_PATH_BUDGET_S`）：
体检本身测完后才补逐跳，到点停止发新探测、保留已完成的跳，结果标
`completed=false`，报告写「探测未完成（到达时间预算或被抓包取消）：以上是已完成的跳」。
不引入异步任务，也不会让浏览器请求干等 tracert 的 60 秒硬上限。

### 2.2 实时抓包（自动）

「全网体检 / 单目标诊断」页的开关文案是
**「抓包同时做路径剖面与探针基线（每 5 秒，少量探测包）」**，默认勾选：

* 打开时：影子探针（每 5 秒一轮）+ 路径探测（有目标才跑）一起启动；
* **全网体检没有目标 → 不跑 MTR**（没有对端，逐跳没有意义）；
* 关闭时：两类探测都不发，报告里也没有这两个区块；
* 被动监听 / 分析抓包文件**恒不发包**（产品承诺与用户预期）。

MTR 的时间预算 = **抓包时长 + 5 秒**：到点或收到取消就返回已完成的跳，并在报告里
写「探测未完成」。抓包、分析、主结论、退出码都不受 MTR 成败影响。

CLI：

```bat
python core\diagnose.py --duration 30 --target 203.0.113.9   REM 抓包 + 探针 + 路径剖面
python core\diagnose.py --duration 30 --no-shadow             REM 全关（两类探测都不发）
python core\diagnose.py --pcap x.pcap                         REM 离线分析：恒不发包
```

---

## 3. 逐跳表怎么读

报告（和界面）里的列：

| 列 | 含义 | 读法 |
|---|---|---|
| TTL | 第几跳（TTL 从 1 递增） | 第 1 跳是网关，往后是运营商/中间设备 |
| 地址 | 该跳响应方 IP | 空 = 这一跳没回（超时或过滤），不代表断 |
| 发出 / 丢失 | 该跳发出的采样数 / 超时数 | 每跳默认 3 个样本（手动体检 5 个；tracert 降级固定 3 个） |
| 丢包 | `丢失/发出` 的百分比 | ≥ 20% 且异常**持续到目标/最后响应跳**才算劣化；被后续跳打断时只提示疑似限速 |
| RTT 最小/平均/最大 | 该跳**成功样本**的往返时延 | 没有样本显示「未探到」，**不显示 0ms** |
| 抖动 | RTT 总体标准差 | 突增往往比平均值更早暴露拥塞 |
| 状态 | 正常 / 劣化 / 疑似限速 / 超时 / 被过滤 / 不可达 | 见下方状态口径 |

状态与劣化判定**同源**（`build_hop_stats()` 直接按判定阈值落状态）：

| 状态机器码 | 显示 | 何时出现 |
|---|---|---|
| `ok` | 正常 | 丢包 < 20%，且相对基线没有 RTT 突增 |
| `degraded` | 劣化 | 丢包 ≥ 20% 或 RTT 突增，**且该异常持续到目标或最后响应跳** |
| `rate_limited` | 疑似限速 | 单跳有丢包/RTT 异常，但后面的跳或目标已恢复正常（不判承载网） |
| `loss` | 超时 | 该跳所有样本都没有响应（100% 丢包） |
| `filtered` / `unreachable` / `no_target` | 被过滤 / 不可达 / 无目标 | 保留机器码：当前由结论句与「探测方式」表达，尚未逐跳赋值 |

「报告表格写正常、结论却说这一跳开始劣化」是自相矛盾的；所以只要命中劣化判据，
状态就不再是「正常」。反过来，限速中间跳也不会被标成「劣化」：它的状态是
「疑似限速」，`degraded_hops` / `first_degraded_hop` 都不会把它算进劣化段。

**「第几跳开始劣化」的判定（R5，`degraded_hops` / `first_degraded_hop` 同源）**：

1. 单跳丢包 ≥ 20% 或 RTT 突增只是**候选异常**；
2. 从某一跳开始的异常必须**连续延续到终点**才算劣化 —— 终点是「探到目标时的目标跳」，
   目标没探到时取「最后一个有响应的跳」；若路径末尾是 100% 不回包的黑洞，则终点
   取最后一个有采样的跳（不能拿更早的正常跳把尾部黑洞当「已恢复」）；
3. 中间跳 100% 不回、后续跳/目标正常 → `degraded_ttl` 为空、结论 `PATH.OK`，
   报告额外提示「中间跳未响应/丢包，疑似 ICMP 限速/策略过滤；后续跳与目标正常，
   不能据此判承载网故障」；
4. 若异常确实持续到目标（含目标自身丢包 ≥ 阈值 / RTT 突增）或持续到最后一个
   响应跳，则仍按既有口径判 `PATH.LOCAL_SIDE` / `PATH.TRANSPORT_NET` /
   `PATH.SERVER_EDGE`，`first_degraded_hop` 取**持续劣化段的第一跳**；
5. 单跳（目标 = 第 1 跳）行为不变；全丢/证据不足仍是 `PATH.NO_DATA`，不判正常。

报告里的「共发出 N 个探测包」来自**独立发送计数器** `probes_sent`：按实际交给发送器
的包数累计，包含到目标后同批多发的 TTL、以及 ICMP 被过滤时的 TCP 回退包，**不是**
截断后的表格行数。

判定阈值（集中在 `core/pathprobe.py`，可单测、可变异）：

* **丢包劣化**：`loss_pct >= PATH_LOSS_DEGRADED_PCT`（20%），**且异常持续到
  目标/最后响应跳**（见上面的 R5 判定）；
* **RTT 突增**：当前跳平均 RTT ≥ 基线 × `PATH_RTT_SPIKE_FACTOR`（3 倍）
  **且** 比基线高 ≥ `PATH_RTT_SPIKE_DELTA_MS`（50ms），同样要持续到终点。
  基线取「已响应跳里最小的平均 RTT」，所以 5ms → 15ms 这种噪声不会被误报；
* 结论机器码只有 6 个：`PATH.OK` / `PATH.LOCAL_SIDE` / `PATH.TRANSPORT_NET` /
  `PATH.SERVER_EDGE` / `PATH.ICMP_FILTERED` / `PATH.NO_DATA`。

**没有样本 ≠ 正常**：整条路径一个响应都没有时结论是
「证据不足（PATH.NO_DATA）」或「目标不可达」，绝不会写成「路径正常」。

---

## 4. 两条实现路径：scapy / 系统 tracert（G2）

lite 包与系统 Python **不带 scapy**。旧实现直接 `import scapy`，路径探测会报
`ModuleNotFoundError`，逐跳与路径剖面整块消失。现在按可用性自动选引擎：
**没有 scapy 不等于路径探测不可用**。

| 引擎 | 何时使用 | 命令 / 实现 | 每跳样本 | 精度 |
|---|---|---|---|---|
| `scapy`（首选） | `import scapy.all` 成功 | TTL 递增 + 批量 `sr()`；ICMP 全丢且目标端口 TCP 可达时改用 TCP SYN 重扫 | 手填 1..10（实时 3 / 手动 5） | 高：精确 RTT、TCP 回退、逐跳状态 |
| `tracert`（降级） | scapy 不可导入，且系统有 `tracert` | `tracert -d -h <max_hops≤16> -w <timeout_ms> <目标>`（列表参数，`CREATE_NO_WINDOW`） | **固定 3** | 中：系统命令每跳 3 次探测；只能按输出结构解析 RTT / `*` |

行为约定：

* 目标先解析成 IPv4 再交给 tracert（`-d` 不做反向解析，也不让命令行解析域名）；
* `-h` 固定夹到 16，`-w` 复用 `PATH_TIMEOUT_RANGE`（200~3000ms），整体等待有
  60s 硬上限；到点 kill 命令并保留已解析的跳（`completed=false`），不会卡死抓包；
* 解析**只认结构**：行首跳号 + 1~3 个 `*` / `<1` / 数字 + 行尾 IPv4；超时行看
  「前 3 个字段全 `*`」。不依赖「请求超时 / Request timed out」等本地化关键词；
  `<1` 记为 0.5ms（只影响显示，不影响判定）；有 RTT 但没有响应方 IP 的行按结构
  不完整跳过；
* 行结构不完整（命令被杀、最后一行没写完）不伪造数据；**整条输出没有可识别跳行
  或命令不可用**时明确返回 `error="tracert 解析失败/不可用：…"`，结论仍是
  `PATH.NO_DATA`，绝不静默返回「全是 0」；
* R5 判定完全复用 `build_hop_stats()` / `summarize_path()` / `degraded_hops()`：
  tracert 中途丢包但目标正常 → 仍 `PATH.OK + middle_loss_suspected`；只有持续
  到目标 / 最后响应跳的异常才判劣化；
* 日志由 `run(logger=...)` 写一行：`路径剖面：使用 scapy 逐跳` 或
  `路径剖面：scapy 不可用，使用系统 tracert 降级（每跳 3 次探测）`；
* 报告 / 结果区的「探测方式」：`icmp` / `tcp` / `tracert` 三种各自有文案；
  tracert 会标注「基于系统 tracert，样本数 3（每跳 3 次探测）」，**不**写成
  「ICMP 被过滤，改用 TCP 探测」；
* 引擎选择与 `capabilities.path_probe` / `mtr_engine` 同源：有 scapy →
  `scapy`；无 scapy 有 tracert → `tracert`（逐跳**不置灰**）；两者都无 →
  `path_probe=false`（UI 才置灰并说明）。

**AGENTS.md §3-11 声明例外**：该条款禁止「用本地化 CLI 文本做平台判断」。
本处的 tracert **仅作无 scapy 时的逐跳数据源**：`-d` 只解析数字 / IP 结构，
不依赖任何本地化关键词做平台 / 版本判断；解析失败明确报「tracert 解析失败 /
不可用」，绝不静默伪造数据。此为本批次**声明例外**（PR 描述与本文件同步记录）。

---

## 5. ICMP 被过滤 → TCP 降级

企业网/防火墙经常只放行业务端口、丢弃 ICMP。这时**不能**把「16 跳全丢」判成故障。
探测流程因此是两段的（**仅 scapy 引擎**；tracert 降级只能给 ICMP 逐跳，不会假装
做过 TCP 重扫）：

```
ICMP 逐跳（TTL 1..16，每批 4 跳一次 sr()）
   └─ 有响应 → 直接出结论
   └─ 一个响应都没有
        ├─ 先用一次普通 TCP 连接判断目标端口是否可达（port 参数；未给时试 443 / 80）
        │     · 连上（SYN-ACK）或连接被拒（RST）都算「网络可达」
        │     · 超时 / 不可达 → 结论「目标不可达 / 证据不足」
        └─ 可达 → 改用 TCP SYN 逐跳重扫（样本减半）
              · 结果 method="tcp"、icmp_filtered=true
              · verdict_key 固定为 PATH.ICMP_FILTERED（TCP 有响应只证明端口可达，
                不能反推「ICMP 路径正常」）
              · 报告与界面明确写「ICMP 被过滤，改用 TCP 探测」
```

**结论句不会自相矛盾**：TCP 回退成功时报告不会再写「整条路径未观察到劣化」；
若 TCP 路径本身也有劣化跳，仍保留「第几跳开始劣化」的数据行供参考。

TCP 重扫失败（例如 scapy 发送异常）时**保留** ICMP 的逐跳数据，只把原因写进
`error` —— 「ICMP 全丢但 TCP 可达」本身已经是结论。

方法标注始终出现在报告与结果区：看到 TCP 就说明这一份逐跳是用 TCP SYN 探的，
中间设备对 TCP 的响应策略与 ICMP 不同，**不能**按 ICMP 的丢包语义直接套用。

---

## 6. TUN / 代理的限制（必须如实说明）

本机可能跑着代理 / TUN（例如把默认路由劫持到 `198.18.0.0/15` 的 fake-ip 网段）。
这时逐跳看到的是**代理的虚拟路径**，不是物理链路。

TUN 判定**只认 fake-ip / `198.18.0.0/15` 证据，不按跳数推断**：

* 目标解析到 `198.18.0.0/15` → 判定「疑似走代理/TUN」（fake-ip 直接命中）；
* 任一**有响应**的跳的 IP 落在 `198.18.0.0/15` → 同样判定（TUN 虚拟网关代答）；
* 其余情况一律**不提示**：on-link 目标 / 本机物理网关只有 1 跳响应、ICMP 被过滤
  时只看到 1~2 跳、普通多跳公网都不是代理证据。**on-link 目标 1 跳即到达是正常
  现象**，`192.0.2.1` 这类物理网关不该被提示成 TUN。
* 报告固定提示：「当前流量可能走代理/TUN，逐跳反映的是代理路径；如需物理路径请
  关闭代理后复测。」

为什么删掉旧规则：D+ 增量 2 曾把「有响应的最大 TTL ≤ 2」也当成 TUN 信号，但
on-link 本来就只有 1 跳，结果所有物理网关/同网段主机都被误报成代理（D+ 增量 2.5
修复）。漏报一个提示只是少一句建议，误报会诱导用户去关代理，所以**证据不足时
宁可不提示**。

`discover_targets()` **不写死物理网关**：网关来自系统路由表（`GetBestRoute`），
宿主机换了网段/代理也不会给出错误常量。

---

## 7. 探针隔离与残余风险

MTR 的探测包与它诱发的 ICMP 都会进入自己的抓包，必须隔离，否则会伪造出
「TTL 耗尽 / 额外 TCP 会话」的假故障。

| 层次 | 做法 |
|---|---|
| 抓包 BPF | 与影子探针同一套标记：ICMP id = `PROBE_ID`（0x4E44）、TCP 源端口 ∈ `PROBE_SRC_PORT_RANGE`（39000-39999）。**有目标就合并**，即使影子探针没有目标 |
| 分析 `-Y` | `path_exclusion_display_filter()` = 探针标记排除 **+ `not (icmp.type == 11)`** |
| 计数（互斥） | `count_time_exceeded_packets()` 统计**全部** ICMP type 11（含非探针流量，N 是上限）；`count_marked_packets()` 统计标记探针包并**显式排除 type 11**；两个数字互不重叠，都写进报告 |

**为什么 time-exceeded 要整类排除**：路径设备回的 ICMP type 11 外层 ident 不是我们的
`PROBE_ID`（原始 id 埋在「原始 IP 头 + 8 字节」里），按外层标记认不出来；而分析层会把
type 11 计入 `icmp_timeout`，不排就会凭空多出「TTL 耗尽」故障。踩坑记录：

* Wireshark 的 `icmp.ident` 对 ICMP 错误报文会命中**内嵌的原始报文**，所以我们的
  time-exceeded 也会被「标记探针」表达式命中；
* 为了避免同一个包既算「标记探针包」又算「ICMP 超时包」，`probe_marker_display_filter()`
  显式排除 type 11，两处计数口径**互斥**；
* 真正需要整类排除的是**同一抓包窗口里别人的 TTL 超时**（共享口 / 镜像口 / TUN
  上很常见）—— 合成 pcap 测试专门造了这种包来证明这条过滤是必要的。

**残余风险（如实写）**：

1. `not (icmp.type == 11)` 会连同窗口内**其它流量**的 TTL 超时一起排除，所以
   报告写的是「本窗口内已从业务统计中剔除 N 个 ICMP 超时包（含非探针流量；N 为
   上限）——这些包未计入业务统计」：N 不是精确归因，而且这些包**不进入业务统计**
   （不是仍然计入、也不是只做展示）；
2. 抓在 TUN 网卡上时，探针可能根本不出物理网卡，BPF 看不到也排不掉；分析阶段
   的显示过滤仍会兜住，但计数会偏小；
3. 我们没有排除 ICMP unreachable（type 3）—— TCP 探针正常会收到 RST/SYN-ACK，
   极少诱发 type 3；若真出现，会被当成业务 ICMP 计入（已知边界）；
4. **tracert 降级的探测包不在本模块标记体系里**：系统命令的 ICMP echo 使用 OS
   自己的标识，BPF/显示过滤无法按 `PROBE_ID` 认领；仍能整类排除 ICMP type 11
   （TTL 超时），echo 请求/回复只会让抓包报文计数略增，不会伪造 `icmp_timeout`
   或链路故障。这是 lite 降级路径的已知边界，报告只影响本次抓包的统计口径。

合成 pcap 回归：`tests/test_mtr.py::PathIsolationSyntheticTest`
——「业务 + MTR 探针 + time-exceeded + 旁路 TTL 超时」pcap 带完整过滤分析与纯净业务
pcap **逐字段相同**；只排标记不排 type 11 时统计不同（证明该条必要）。

---

## 8. DNS 角色（W1 遗留补全）

影子探针的角色从两个变三个：**网关（ICMP）→ DNS（UDP/53）→ 业务目标（TCP SYN）**。

DNS 服务器来自注册表（`core/platform/winapi.py::dns_servers()`，**不解析**
`ipconfig` 这类本地化 CLI 文本）：

```
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}
    NameServer      （静态配置）
    DhcpNameServer  （DHCP 下发）
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
    NameServer / DhcpNameServer（组策略或旧配置可能只写这里）
```

* 只取合法 IPv4，去重、保序；跳过 `0.0.0.0` / 组播 / IPv6；
* 读不到 / 非 Windows / 注册表不可读 → 返回 `()`，**不抛异常**（少一行 DNS 而已）；
* **环回 DNS 优雅跳过**：`127.0.0.0/8`、`::1` 上的 DNS 通常是本机 stub，
  探它等于探自己，日志会写「DNS 服务器是本机回环地址，跳过 DNS 角色」；
* 开了 DoH 时注册表地址与真正发查询的地址可能不一致 —— 探针只能证明
  「本机到该地址的 UDP/53 通不通」，报告不把它当 DNS 解析质量的唯一证据。

---

## 9. 明确不做 / 已知边界

* **IPv6 逐跳**：本批只做 IPv4；IPv6 目标返回 `error`（不抛异常），不做半成品；
* **有 scapy 时不调用 tracert**：tracert 只是 lite 环境（无 scapy）的降级数据源，
  且只解析数字 / IP 结构；声明例外与失败形态见第 4 节；
* **被动监听期间的路径探测**：「只听不发」是产品承诺，`core/passive.py` 不引用本模块；
* **离线分析的路径探测**：`--pcap` 路径恒不启动（用户可能只在分析别人的抓包）；
* **服务端探针 / 双侧抓包**：规划第 7 步，本批不实现；
* **探针结果联网上报**：本工具不联网，逐跳数据只进本地报告；
* **探测包上限**：单次最多 32 跳 × 10 样本（scapy 路径夹取），实时抓包用 16 跳 ×
  3 样本、预算 = 抓包时长 + 5 秒；tracert 固定 `-h 16`、每跳 3 次、整体 60s 上限；
  不做持续 MTR。

---

## 10. 相关文件

| 文件 | 作用 |
|---|---|
| `core/pathprobe.py` | 全部实现：`run()`、`clamp_path_options`、`build_hop_stats`、`first_degraded_hop`、`summarize_path`、`PathProfiler`、隔离过滤串、`count_time_exceeded_packets` |
| `core/diagnose.py` | `capture_live()` 起停 MTR、BPF/显示过滤合并、`meta.path_profile` 注入 |
| `core/selfcheck.py` | 首屏第 4 项 `scapy` + `capabilities.path_probe` / `mtr_engine`（逐跳是否置灰的唯一依据） |
| `core/report.py` | 报告「路径剖面」区块（文案在 `core/copy/zh-CN.json` 的 `path` section；`method=tracert` 有独立文案） |
| `core/server.py` | `/api/probe` 的 `path` 开关；`/api/status` 下发 `ui_copy.path`；引擎日志 |
| `ui/index.html` | 连通与速度测试页「逐跳路径」开关 + 降级提示；结果页路径剖面区块 |
| `tests/test_mtr.py` | V6~V10 + tracert 解析/降级 + 隔离合成 pcap + DNS 角色 |
| `core/platform/winapi.py` | `dns_servers()` 注册表实现（`_registry_dns_values` / `_parse_dns_list`） |
