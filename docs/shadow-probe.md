# 影子探测（Shadow Probing）

> 对应批次：**D**（`feat/d-shadow-probe`）。目标：实时抓包期间用极轻量探针给任何结局
> 一个**可量化的对照基线**，同时证明终端侧清白；探针流量必须从诊断统计里**完全隔离**。
>
> 一句话：**「没抓到业务报文」不再等于「没有数据」——至少还有一组网关/对端的 RTT 与丢包。**

本文只讲现状（代码以 `core/pathprobe.py` 为准），不写未来计划。

---

## 1. 它解决什么问题

实时抓包有两类「空结果」：

1. **真的 0 包**（选错网卡 / 流量走 VPN / 目标本来没流量）；
2. **抓到包但没有任何可判定维度**（只有 ARP 广播、只有零星 UDP）。

这时报告只能写「证据不足」。影子探测在抓包的同时，每约 5 秒向 **网关**（ICMP）、
**业务目标**（TCP SYN）、**DNS 服务器**（UDP/53，平台 API 可用时）各发 **1 个探针包**，
记录 RTT / 丢包，作为方向判定的**两侧对照**：

```
网关丢包 40%  vs  对端丢包 0%   → 疑似本地侧/接入链路
网关丢包 0%   vs  对端丢包 40%  → 疑似对端侧
两边都拿不到 RTT               → 证据不足（不硬指一侧）
```

措辞固定是「疑似」，`confidence < 1.0`；探针数据**不参与**主判定等级
（`level` / `headline` / 四层状态），只在报告中新增一个区块。

---

## 2. 数据流

```
diagnose.run_scan(shadow=True)                 # 仅 live/scan；离线恒 false
   └─ capture_live(..., shadow=True)
        ├─ pathprobe.discover_targets(target)  # 网关 / DNS / 业务目标
        ├─ pathprobe.shadow_specs(...)         # 每目标 1 个 ProbeSpec
        ├─ ShadowProber(specs, max_rounds=rounds_for(duration))
        ├─ 抓包 BPF = 用户 BPF AND ledger.exclusion_bpf()      ← 第一道隔离
        ├─ prober.start()                      # 首轮立即发，之后每 5s 一轮
        ├─ tshark -i N -w pcap -a duration -f <合并后 BPF>
        └─ finally: prober.stop(); prober.join(3)              ← 3s 内退出
   └─ analyzer.analyze(pcap, display_filter=ledger.exclusion_display_filter())
                                               # 第二道隔离（防御层）
   └─ result["meta"]["probe_baseline"] = 聚合基线 + excluded_packets
   └─ verdict.build(result) → 可选 verdict["probe_contrast"]
   └─ report.save() → 报告「探针基线」区块（只在有数据时出现）
```

**没有探针数据时，`analyze()` / `verdict.build()` / `render_markdown()` 的输出与
无此功能时逐字节相同**（20 产物红线，见 `D-SPEC` V11）。

---

## 3. 隔离：两道过滤 + 一个计数

只做抓包 BPF 是**不够**的：探针的回复方向端口是反的（echo-reply / SYN-ACK / RST /
DNS 响应），只排「源端口」会漏。所以：

| 层次 | 位置 | 表达式（由账本生成，纯函数） |
|---|---|---|
| 抓包 BPF | `ProbeLedger.exclusion_bpf()` | ICMP 固定 id 的 type 8/0 + `tcp/udp src\|dst portrange 39000-39999` |
| 分析 `-Y` | `ProbeLedger.exclusion_display_filter()` | `icmp.type/icmp.ident` + `tcp/udp srcport/dstport` 判断 |
| 计数 | `pathprobe.count_marked_packets()` | 用「只匹配探针」的 `-Y` 统计 pcap 里混进多少探针包 |

报告里固定写「探针已从业务统计排除（N 包）」。**N=0 也是证据**：说明抓包 BPF 生效；
N>0 说明 BPF 没盖住（例如抓的是 TUN 网卡），分析阶段的显示过滤兜住了。

合成 pcap 回归测试：`tests/test_shadow_probe.py::ProbeIsolationSyntheticTest`
——「业务 + 探针」pcap 带过滤分析与纯净业务 pcap **逐字段相同**；不带过滤时统计不同
（证明测试本身有效）。

固定标记（写在 `core/pathprobe.py`）：

* ICMP id = `PROBE_ID`（`0x4E44`，ASCII "ND"）；
* TCP/UDP 源端口 ∈ `PROBE_SRC_PORT_RANGE`（39000-39999，按序号取模分配）；
* payload 前缀 `b"NetDiag-shadow-probe"`；
* DNS 查询名 `netdiag-probe.example`（RFC 2606 保留 TLD，必然 NXDOMAIN）。

---

## 4. 记录与统计

每条 `ProbeRecord`：`(spec, sent_monotonic, sent_epoch, rtt_ms, responded,
responder, error, seq)`。时钟口径：pcap 用系统时钟、探测用 `monotonic()`，只做
「区间归属」，不逐包对齐。

按 `(role, target, kind)` 聚合（角色顺序：网关 → DNS → 业务目标）：

| 字段 | 含义 |
|---|---|
| `sent` / `recv` | 发出 / 收到可判「通」的响应 |
| `loss_pct` | `(sent-recv)/sent*100`；`sent=0` 时为 `None` |
| `n` | **RTT 样本数**（有响应且拿到 RTT） |
| `rtt_min_ms` / `rtt_avg_ms` / `rtt_max_ms` | `n=0` 时全是 `None`，**不许用 0.0 冒充** |
| `jitter_ms` | RTT 总体标准差；`n=0` 时 `None` |
| `errors` | 最多 3 条去重错误（`timeout` / `icmp_unreachable` / scapy 不可用…） |

响应判定（SPEC V5）：

* ICMP：收到 echo-reply（id 匹配）= 通；超时 = 丢；
* TCP：SYN-ACK 或 RST = 通（网络可达）；超时 = 丢；
* UDP：任意响应，或 ICMP port-unreachable = 通（主机可达、端口没开）；全超时 = 丢。

数量上限：`rounds_for(duration)` = `duration/5 + 1` 轮（首轮立即），封顶
`PROBE_MAX_PACKETS_PER_TARGET = 38`；`duration=180` → 37 轮 → 37 包/目标。

---

## 5. 报告与界面

报告新增一节（位于「关键指标」之后，仅 `meta.probe_baseline` 存在时出现）：

```
### 探针基线（抓包同时发出的少量探测包）
| 角色 | 目标 | 发出 | 收到 | 丢包 | RTT 最小/平均/最大 | 抖动 |
| 网关 | 192.0.2.1 | 2 | 2 | 0% | 1.0/1.5/2.0 ms | 0.5ms |
| 对端目标 | 198.51.100.20 | 1 | 0 | 100% | 未探到 | 未探到 |
探针已从业务统计排除（4 包）。
方向对照：疑似对端侧丢包（网关丢包 0% vs 对端 40%，置信度 0.6）。
```

* 没有 RTT 样本 → 写「未探到」，不写 0ms / 正常；
* 方向对照只在「有基线 + 有方向类 finding（`传输质量` 严重/警告）」时出现；
* 中文文案全部来自 `core/copy/zh-CN.json` 的 `probe` section；`core/verdict.py`
  只产出机器码（`PROBE.CONTRAST.*`），不写中文长文案。

UI（`ui/index.html`）：

* 仅 **全网体检 / 单目标诊断** 显示开关 `抓包同时做探针基线（每 5 秒，少量探测包）`，
  **默认勾选**；被动监听 / 分析抓包文件不显示；
* 请求体带加法字段 `shadow: bool`；旧版前端不传时后端默认 `true`（兼容）；
* 结果页区块的文案不写死在页面里：随 `/api/status` 的 `ui_copy.probe` 下发
  （来源仍是 copy 表），页面只负责排版。

CLI：

```bat
python core\diagnose.py --duration 30              REM 默认开探针
python core\diagnose.py --duration 30 --no-shadow  REM 关闭
python core\diagnose.py --pcap x.pcap              REM 离线分析：恒不发探针
```

---

## 6. 明确不做 / 已知边界

* **MTR / TTL 逐跳**：`pathprobe.run()` 仍是 `NotImplementedError`，留给后续 PR；
* **被动监听期间探针**：「只听不发」是产品承诺，`core/passive.py` 不引用本模块；
* **离线分析探针**：用户可能只是在分析别人给的 pcap，`--pcap` 路径恒不启动；
* **服务端探针 / 双侧抓包**：只留数据模型文字说明，本批不实现；
* **探针结果联网上报**：本工具不联网，探针只进本地报告；
* **DNS 角色**：`winapi.dns_servers()` 尚未实现，拿不到 DNS 服务器时自动跳过该角色
  （不报错）；网关 / 业务目标两个角色足以做两侧对照；
* **探针诱发的 ICMP 不可达**：BPF/显示过滤只排除「带固定标记的探针报文」；路由器因探针
  回送的 ICMP unreachable 目前不在排除范围（TCP 探针正常会收到 RST/SYN-ACK，极少触发）。
  这是已知残余风险，后续若要收口，需按 ICMP 内嵌报文端口做过滤。
