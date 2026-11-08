# 路径剖面（MTR 逐跳）

> 对应批次：**D+ 增量 2**（`feat/d-shadow-probe`，PR #26）。目标：回答「问题出在
> **路径上的哪一跳**」——本地出口 / 承载网 / 对端侧 / ICMP 被过滤。
>
> 一句话：**逐跳 RTT 与丢包不是地图，而是「从第几跳开始变坏」的坐标。**

本文只讲现状（代码以 `core/pathprobe.py` 为准），不写未来计划。

---

## 1. 它解决什么问题

「ping 网关丢包、ping 对端也丢包」不足以定位是本地接入、运营商还是对端。
MTR 逐跳在**同一条路径**上按 TTL 1..16 逐跳探测，得到每一跳的 RTT 与丢包，
再判断**第几跳开始劣化**：

```
第 1 跳就丢/慢        → 本地出口（终端 / 接入链路 / 网关）
中间某一跳开始丢/慢    → 承载网（运营商 / 中间设备）
只有最后一跳丢/慢      → 对端侧（服务端接入链路 / 对端主机）
ICMP 全丢/TCP 可达     → ICMP 被策略过滤（不是故障）
一个样本都没有         → 证据不足（不判正常）
```

和「探针基线」（`docs/shadow-probe.md`）的关系：探针基线回答「网关 vs 对端谁更差」，
路径剖面回答「差在路径的哪一段」。两个区块都只**增加证据**，不改变主判定等级。

---

## 2. 怎么用

### 2.1 连通与速度测试页（手动）

1. 左侧切到「连通与速度测试」，填目标与端口；
2. 「逐跳路径（MTR）」默认勾选；取消勾选则完全不发逐跳探测包；
3. 结果区在体检结论下方出现逐跳表格 + 结论。

请求体是加法字段 `path: true|false`；旧版前端不传时后端按 **开** 处理。

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
| 发出 / 丢失 | 该跳发出的采样数 / 超时数 | 每跳默认 3 个样本（手动体检 5 个） |
| 丢包 | `丢失/发出` 的百分比 | ≥ 20% 视为这一跳开始劣化 |
| RTT 最小/平均/最大 | 该跳**成功样本**的往返时延 | 没有样本显示「未探到」，**不显示 0ms** |
| 抖动 | RTT 总体标准差 | 突增往往比平均值更早暴露拥塞 |
| 状态 | 正常 / 超时 / 被过滤 / 不可达 | 机读码在 `HopStat.status`，文案走 copy 表 |

判定阈值（集中在 `core/pathprobe.py`，可单测、可变异）：

* **丢包劣化**：`loss_pct >= PATH_LOSS_DEGRADED_PCT`（20%）；
* **RTT 突增**：当前跳平均 RTT ≥ 基线 × `PATH_RTT_SPIKE_FACTOR`（3 倍）
  **且** 比基线高 ≥ `PATH_RTT_SPIKE_DELTA_MS`（50ms）。
  基线取「已响应跳里最小的平均 RTT」，所以 5ms → 15ms 这种噪声不会被误报；
* 结论机器码只有 6 个：`PATH.OK` / `PATH.LOCAL_SIDE` / `PATH.TRANSPORT_NET` /
  `PATH.SERVER_EDGE` / `PATH.ICMP_FILTERED` / `PATH.NO_DATA`。

**没有样本 ≠ 正常**：整条路径一个响应都没有时结论是
「证据不足（PATH.NO_DATA）」或「目标不可达」，绝不会写成「路径正常」。

---

## 4. ICMP 被过滤 → TCP 降级

企业网/防火墙经常只放行业务端口、丢弃 ICMP。这时**不能**把「16 跳全丢」判成故障。
探测流程因此是两段的：

```
ICMP 逐跳（TTL 1..16，每批 4 跳一次 sr()）
   └─ 有响应 → 直接出结论
   └─ 一个响应都没有
        ├─ 先用一次普通 TCP 连接判断目标端口是否可达（port 参数；未给时试 443 / 80）
        │     · 连上（SYN-ACK）或连接被拒（RST）都算「网络可达」
        │     · 超时 / 不可达 → 结论「目标不可达 / 证据不足」
        └─ 可达 → 改用 TCP SYN 逐跳重扫（样本减半）
              · 结果 method="tcp"、icmp_filtered=true
              · 报告与界面明确写「ICMP 被过滤，改用 TCP 探测」
```

TCP 重扫失败（例如 scapy 发送异常）时**保留** ICMP 的逐跳数据，只把原因写进
`error` —— 「ICMP 全丢但 TCP 可达」本身已经是结论。

方法标注始终出现在报告与结果区：看到 TCP 就说明这一份逐跳是用 TCP SYN 探的，
中间设备对 TCP 的响应策略与 ICMP 不同，**不能**按 ICMP 的丢包语义直接套用。

---

## 5. TUN / 代理的限制（必须如实说明）

本机可能跑着代理 / TUN（例如把默认路由劫持到 `198.18.0.0/15` 的 fake-ip 网段）。
这时逐跳看到的是**代理的虚拟路径**，不是物理链路：

* 目标解析到 `198.18.0.0/15` → 直接判定「疑似走代理/TUN」；
* 有响应的跳最多只到 1~2 跳 → 同样提示（目标与你同网段时属正常，文案里已注明）；
* 报告固定提示：「当前流量可能走代理/TUN，逐跳反映的是代理路径；如需物理路径请
  关闭代理后复测。」

`discover_targets()` **不写死物理网关**：网关来自系统路由表（`GetBestRoute`），
宿主机换了网段/代理也不会给出错误常量。

---

## 6. 探针隔离与残余风险

MTR 的探测包与它诱发的 ICMP 都会进入自己的抓包，必须隔离，否则会伪造出
「TTL 耗尽 / 额外 TCP 会话」的假故障。

| 层次 | 做法 |
|---|---|
| 抓包 BPF | 与影子探针同一套标记：ICMP id = `PROBE_ID`（0x4E44）、TCP 源端口 ∈ `PROBE_SRC_PORT_RANGE`（39000-39999）。**有目标就合并**，即使影子探针没有目标 |
| 分析 `-Y` | `path_exclusion_display_filter()` = 探针标记排除 **+ `not (icmp.type == 11)`** |
| 计数 | `count_time_exceeded_packets()` 统计被排除的 ICMP 超时包；`count_marked_packets()` 统计标记探针包；两个数字都写进报告 |

**为什么 time-exceeded 要整类排除**：路径设备回的 ICMP type 11 外层 ident 不是我们的
`PROBE_ID`（原始 id 埋在「原始 IP 头 + 8 字节」里），按标记认不出来；而分析层会把
type 11 计入 `icmp_timeout`，不排就会凭空多出「TTL 耗尽」故障。踩坑记录：

* Wireshark 的 `icmp.type` / `icmp.ident` 对 ICMP 错误报文会命中**内嵌的原始报文**，
  所以我们自己的 time-exceeded 其实也能被标记串排掉；
* 真正需要整类排除的是**同一抓包窗口里别人的 TTL 超时**（共享口 / 镜像口 / TUN
  上很常见）—— 合成 pcap 测试专门造了这种包来证明这条过滤是必要的。

**残余风险（如实写）**：

1. `not (icmp.type == 11)` 会连同窗口内**其它流量**的 TTL 超时一起排除，所以
   「已排除 N 个路径探测相关 ICMP」里的 N 是上限，不是精确归因；
2. 抓在 TUN 网卡上时，探针可能根本不出物理网卡，BPF 看不到也排不掉；分析阶段
   的显示过滤仍会兜住，但计数会偏小；
3. 我们没有排除 ICMP unreachable（type 3）—— TCP 探针正常会收到 RST/SYN-ACK，
   极少诱发 type 3；若真出现，会被当成业务 ICMP 计入（已知边界）。

合成 pcap 回归：`tests/test_mtr.py::PathIsolationSyntheticTest`
——「业务 + MTR 探针 + time-exceeded + 旁路 TTL 超时」pcap 带完整过滤分析与纯净业务
pcap **逐字段相同**；只排标记不排 type 11 时统计不同（证明该条必要）。

---

## 7. DNS 角色（W1 遗留补全）

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

## 8. 明确不做 / 已知边界

* **IPv6 逐跳**：本批只做 IPv4；IPv6 目标返回 `error`（不抛异常），不做半成品；
* **tracert / 本地化 CLI 文本**：禁止；所有探测包自建；
* **被动监听期间的路径探测**：「只听不发」是产品承诺，`core/passive.py` 不引用本模块；
* **离线分析的路径探测**：`--pcap` 路径恒不启动（用户可能只在分析别人的抓包）；
* **服务端探针 / 双侧抓包**：规划第 7 步，本批不实现；
* **探针结果联网上报**：本工具不联网，逐跳数据只进本地报告；
* **探测包上限**：单次最多 32 跳 × 10 样本（夹取），实时抓包用 16 跳 × 3 样本、
  预算 = 抓包时长 + 5 秒；不做持续 MTR。

---

## 9. 相关文件

| 文件 | 作用 |
|---|---|
| `core/pathprobe.py` | 全部实现：`run()`、`clamp_path_options`、`build_hop_stats`、`first_degraded_hop`、`summarize_path`、`PathProfiler`、隔离过滤串、`count_time_exceeded_packets` |
| `core/diagnose.py` | `capture_live()` 起停 MTR、BPF/显示过滤合并、`meta.path_profile` 注入 |
| `core/report.py` | 报告「路径剖面」区块（文案在 `core/copy/zh-CN.json` 的 `path` section） |
| `core/server.py` | `/api/probe` 的 `path` 开关；`/api/status` 下发 `ui_copy.path` |
| `ui/index.html` | 连通与速度测试页「逐跳路径」开关 + 逐跳表格；结果页路径剖面区块 |
| `tests/test_mtr.py` | V6~V10 + 隔离合成 pcap + DNS 角色 |
| `core/platform/winapi.py` | `dns_servers()` 注册表实现（`_registry_dns_values` / `_parse_dns_list`） |
