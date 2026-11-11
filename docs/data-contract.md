# 结果数据契约（`result` / `meta` / API 加法字段）

本文只写**机器读得懂的字段**：哪些键一定有、取什么值、空值是什么意思。
给人看的文案（「网卡 / 过滤器」怎么显示）不在契约里，见文末「展示 vs 契约」。

诊断结果由 `core/analyzer.py::analyze()` 产出，`core/diagnose.py::run_scan()`
补上采集侧信息后交给报告、API、MCP 三条出口。

---

## 1. 顶层块

| 键 | 落进报告 | 说明 |
|---|---|---|
| `meta` | ✅ | 采集元信息 + 技术明细（见 §2） |
| `metrics` | ✅ | 派生指标（时延、重传率、DNS 失败率…） |
| `rows` | ✅ | 故障行（`layer` / `category` / `finding` / `severity` / `evidence` / `advice`） |
| `summary` | ✅ | 严重/警告计数 |
| `verdict` | ✅ | 判定块（`level` / `layers` / `points` / `sufficiency` / 边界四键） |
| `findings_v2` | ❌ | 结构化结论（T03），只走 API/MCP |
| `provenance` | ❌ | 复现信息（配置哈希、版本） |
| `l7_packets` | ❌ | **R8-1**，按报文数的 L7 分布，只走 API（见 §4） |

`reports/*.json` **只**序列化前五块（`core/report.py::save()` 显式列出键名）。
新增顶层键默认不会污染报告快照 —— 这是 `l7_packets` 选择放在顶层而不是 `meta` 的原因。

---

## 2. `meta` 中与采集方式相关的字段

| 键 | 类型 | 实时抓包 | 离线分析（`--pcap`） |
|---|---|---|---|
| `capture_mode` | `str` | `"live"` | `"offline"` |
| `interface` | `str` | 网卡名（如 `以太网`） | **`""`**（空串 = 本模式不适用） |
| `bpf` | `str` | 实际过滤器，全网时为 `无（全网）` | **`""`** |
| `capture_duration` | `int` | 抓包秒数 | `0` |
| `pcap_file` / `pcap_name` | `str` | 落盘路径 / 文件名 | 同左（这里才是「文件」该待的地方） |

### `capture_mode`（R6-5 新增，判定唯一依据）

取值只有三个，全部小写英文：

* `live` —— 本机实时抓包；
* `offline` —— 分析已保存的抓包文件；
* `passive` —— 通信观察（被动监听）。

**判定逻辑只认这个键**（`verdict._is_offline()`）；`interface` / `bpf` 不参与任何判定。

> 历史兼容：R6-5 之前的报告没有 `capture_mode`，而是把模式文案写进 `meta.bpf`
> （`分析抓包文件` / 更早的 `离线分析`）。`_is_offline()` 在缺 `capture_mode` 时
> 仍回落到这两个旧值，否则历史报告会被当成在线抓包，给出「换一块网卡再抓」
> 这种做不到的建议。

### 为什么 `interface` / `bpf` 在离线时必须是空串

修复前它们是 `"-"` 和 `"分析抓包文件"` —— 一个占位符 + 一段模式文案。后果是所有
消费方都得自己猜哪些值是垃圾：AI prompt 打印「网卡 -，过滤器 分析抓包文件」，
UI 的过滤器一栏既点不动也删不掉。空串是明确信号：**这次分析没有这个维度**。

---

## 3. `dns_truncated`（R8-2）

| 键 | 类型 | 出现条件 |
|---|---|---|
| `dns_truncated` | `bool`（恒 `true`） | 仅当 `meta.dns_resp > meta.dns_total` |

DNS 一问一答，`dns_resp` 不该大于 `dns_total`。反超说明抓包中途被截断（查询/响应
统计窗口不一致）或响应被重复计数。此时**不能**把两个数相除：会得到负数失败率或
>100% 的响应率，都是看不出来的错数。

**缺键 = 未触发**，不要写成 `false` 再判断存在性 —— 与 `probe_baseline` /
`path_profile` 的「有数据才注入」同一口径，这样既有报告快照才能逐字节不变。

---

## 4. `l7_packets`（R8-1，API 加法字段）

```json
{
  "basis": "packets",
  "total_packets": 36,
  "buckets": [
    {"key": "tls",   "packets": 16, "pct": 44.4},
    {"key": "http",  "packets": 20, "pct": 55.6},
    {"key": "other", "packets": 0,  "pct": 0.0}
  ],
  "complete": true
}
```

| 字段 | 说明 |
|---|---|
| `basis` | 固定 `"packets"`：这是**按报文数**的口径，与前端按会话数的口径并存 |
| `total_packets` | 参与统计的报文总数 = 三个桶之和（恒等，可断言） |
| `buckets[].key` | 固定三个：`tls` / `http` / `other`，顺序固定（tls → http → other） |
| `buckets[].pct` | 该桶占 `total_packets` 的百分比，保留 1 位小数；`total_packets` 为 0 时全为 `0.0` |
| `complete` | 恒 `true`：统计覆盖全部会话，不是 top-N 抽样 |

**为什么要有第二套口径**：会话数看不出流量结构。10 个 TLS 小流（各 2 包）+ 1 个
HTTP 大流（2000 包）按会话数是「TLS 91%」，按报文数才是「HTTP 99%」——
后者才是真正占了带宽的那个。前端现有的「应用层分布」用 `meta.streams_top` 数会话，
两套并存、互不替换。

**统计范围**：TCP 会话的报文（`st["streams"]`）。DNS/UDP 不进流表，因此不在分母里；
这一点与前端按会话数的实现完全相同，两套口径可直接对比。

**下发位置**：`/api/status`（结果体）、`/api/last-run`（`last.l7_packets`，需内存里
有完整结果）、`/api/last-run/result`（结果体）。**不写进 `reports/`**。

---

## 5. 展示 vs 契约

契约是空串的地方，人读的 Markdown 不能留空白。展示层统一走
`verdict.display_capture_fields(meta)`：

| 契约值 | md / 判定文案里的显示 |
|---|---|
| `interface = ""` | `-` |
| `bpf = ""` 且 `capture_mode = "offline"` | `分析抓包文件`（读报告的人要知道「不是没设过滤器，是这次没抓包」） |
| `bpf = ""` 且非离线 | `-` |

因此 R6-5 只改了 `reports/faults_demo.json` 的 3 个字段，`reports/faults_demo.md`
逐字节不变。

---

## 6. 不变量（改这三块前必须确认）

1. `buckets` 的 `packets` 之和恒等于 `total_packets`；`pct` 之和在 `total_packets > 0`
   时为 100（±0.3 的舍入误差）。
2. `dns_truncated` / `capture_mode` 之外，`meta` 不新增「重跑会变的键」——
   报告快照会跟着变。
3. `l7_packets` 一旦出现在 `reports/*.json` 里，说明有人改了 `report.save()` 的
   块清单，违反「只落五块」的约定。
