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

---

## 7. 历史接口（`/api/history*`，T2）

数据源是常驻 agent 写的 `logs/history/YYYY-MM-DD.jsonl`（字段见 `docs/agent.md` §4）。
读取、分桶、覆盖率、导出全部收在 `core/history.py` 一层里，`server` 只做参数解析 ——
同一个缺口不能一处算 3 分钟、另一处算 5 分钟。

### 7.1 `GET /api/history?from&to&bucket=1m|5m|1h`

```json
{
  "ok": true,
  "from": "2026-11-11T10:00:00+08:00",
  "to": "2026-11-11T11:00:00+08:00",
  "from_epoch": 1794362400.0,
  "to_epoch": 1794366000.0,
  "bucket": "1m",
  "bucket_s": 60,
  "samples": 355,
  "series": [
    {"key": "gateway", "kind": "gateway", "label": "网关",
     "points": [{"t": "2026-11-11T10:00:00+08:00", "epoch": 1794362400.0, "n": 6,
                 "rtt_ms": {"avg": 12.3, "max": 20.0, "min": 8.1},
                 "loss_pct": {"avg": 0.0, "max": 0.0, "min": 0.0},
                 "jitter_ms": {"avg": 2.1, "max": 5.0, "min": 0.5},
                 "bssid": "aa:bb:cc:00:00:01"}]}
  ],
  "marks": [{"t": "...", "epoch": 1794363000.0, "note": "换了 AP"}],
  "coverage": {
    "samples": 355, "expected": 360, "ratio": 0.986,
    "interval_s": 10,
    "gaps": [{"from": "...", "to": "...", "seconds": 300, "missing": 30}]
  }
}
```

| 字段 | 口径 |
|---|---|
| `series[].key` | `gateway` / `dns` / `target:<目标名>`。**目标带前缀**：用户可以把它命名为 `gateway`，不带前缀就和网关序列撞名 |
| `series[].kind` | `gateway` / `dns` / `target` |
| `points[].n` | 该桶里的样本条数（`n=1` 表示这一分钟只采到一次） |
| `points[].rtt_ms` | `avg` / `max` / `min`，1 位小数。**没测到就是 `null`** |
| `points[].bssid` | 该桶内出现次数最多的 BSSID（主 AP）；全空时 `null` |

### 7.2 `coverage.gaps`：缺口必须显式

三条规则，改之前先读完：

1. **没有数据的桶不出现在 `series` 里**，不补 0 点。补 0 会在图上画出一条贴着
   横轴的完美直线，看起来像「网络很好」，实际是「没采到」。
2. **`gaps` 为空数组只代表「这段采齐了」**，不代表「没采到所以没缺口」。
   空区间（一条样本都没有）也照样给一段覆盖整个查询区间的缺口。
3. `missing` 是「该有但没有」的样本数，恒 ≥ 1；`seconds` 是真实时长。

缺口判定容差是 `interval_s × 1.5`：一轮采样本身要花几百毫秒到几秒，严格按
`interval_s` 判会每轮都多出一个假缺口。

`expected` / `ratio` 是**估算**：`expected = ceil((to-from)/interval_s)`，
`ratio = samples / expected`（`expected = 0` 时 `ratio` 为 `null`）。区间长度不是
采样间隔整数倍时，`ratio` 会略大于 1，属于正常现象 —— 它表达的是「采到的条数 /
按长度该有的条数」，不是严格覆盖率。

### 7.3 `GET /api/history/export?format=csv|md&from&to`

CSV 列头**固定**（列序即契约，逐字符不得改）：

```text
time,interval_s,gateway_rtt_ms,gateway_loss_pct,gateway_jitter_ms,dns_rtt_ms,target_key,target_rtt_ms,target_loss_pct,bssid,rssi_dbm,rx_mbps,band,channel
```

| 规则 | 说明 |
|---|---|
| 行粒度 | 一行 = 一个样本 × 一个目标（宽表，方便在 Excel 里按目标筛选） |
| 没有目标 | 每个样本仍出一行，`target_*` 三列留空 |
| 缺失值 | **留空**，不写 `0`（同上：0 会在图上连出一条假线） |
| 编码 | UTF-8，**无 BOM**（列头逐字节可比）；`\n` 换行 |
| 转义 | 含逗号/引号/换行的格子加双引号，内部引号翻倍 |

`md` 是人读摘要：时段、样本数/期望、覆盖率、缺口段数与最长缺口、异常 Top5
（时间/目标/类型/实测/阈值/**当时 AP 与信号**）、缺口明细表。异常取 `events.jsonl`
里区间内的事件，按「实测/阈值」降序取前 5 —— 与「连续 2 次才落一条」的判定同源，
不另算一套阈值。

### 7.4 `POST /api/history/mark` / `GET /api/history/marks`

`{"note": "15:20 换了 AP"}` → 追加一行到 `logs/history/marks.jsonl`，
返回 `{"ok": true, "mark": {"t", "epoch", "note"}}`。正文去空白后不能为空、
最长 500 字（超出返回 400）。写盘失败返回 500 —— 不假装成功，否则下次查 marks
对不上会变成另一个谜。

### 7.5 错误码

| 情况 | 响应 |
|---|---|
| 时间格式无法识别 / `from` 晚于 `to` / `bucket` 不在三档内 / `format` 非 `csv|md` | `400` + `{"ok": false, "error": "..."}` |
| `/api/history/` 后接未知子路径 | `404` |
| 目录不存在 / 文件为空 | `200` + 空 `series` / 空 `events` + 一段显式缺口（**不是错误**） |

时间参数接受 epoch 秒（数字或数字串）与 ISO 8601（`2026-11-11`、`2026-11-11 10:00`、
`2026-11-11T10:00:00+08:00`、结尾 `Z` 的 UTC）。**无时区按本地时间**解释。
