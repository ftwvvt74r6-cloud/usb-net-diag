# 结论与边界（conclusion + boundary）

> 用户 2026-11-08 定稿（`review/E-SPEC.md` §1）的落地说明。一句话口径：
> **结论必须自带依据与边界；任何只给结论不给边界的展示/导出/复制都算缺陷。**
>
> 唯一实现出处：`core/conclusion.py`。本文件解释「字段是什么意思、等级怎么来、
> 六个出口怎么保证一致、旧数据/降级怎么办、0.3.x 不做什么」。

---

## 1. 为什么需要「边界」

旧版结果只有一个 `headline`（例如「1 个目标端口完全连不上：TCP 握手没有回应」）。
它被口头转述、复制到工单或截图发群时，下面这些信息会全部丢失：

- 这个结论基于哪段抓包、多少报文、多少会话；
- 本次到底覆盖了什么（终端侧 L2–L7、哪些协议、有没有探针对照）；
- **哪些东西明确没测**（对端主机内部、抓包窗口之外、业务 QoS/DSCP 路径）；
- 结论有多可信（有没有网关 + 对端双侧对照）；
- 最关键的一条边界是什么。

二线看到「未发现链路层异常」时，很容易误读成「网络没问题」。所以 E 批次把结论
升级成一个结构化对象，六个出口共用它：

| 出口 | 位置 | 形态 |
|---|---|---|
| UI | 结果页「结论与边界」卡 | 同卡片连续展示；复制/导出按钮 |
| CLI `--json` | `diagnose.py --json` | `{"summary", "conclusion", ...}` |
| CLI 人读 | `diagnose.py` 打印的报告 | 与报告 `.md` 同一份 |
| 报告 `.md` | `reports/<stem>.md` 第一节 | 结论块紧随 headline |
| 诊断包 | `--include-reports` 收进的报告 | 包内报告天然含结论块 |
| 取证单 | `core/evidence.py` 的 md/txt/API content | 清单前先放同一结论块 |
| MCP | `analyze_pcap` 等诊断工具的返回 | `{ok, conclusion, markdown, summary?}` |

> `listen_flows`（通信观察）与 `probe_link`（链路体检）**不产生**分层诊断结论，
> 它们的返回保持原样；MCP 不把这两个工具伪装成结论出口。通信观察是「谁在和谁
> 通信」的会话表，链路体检是「通不通、多快」的单次探测，二者都不做 L2–L7 判定。

---

## 2. 结论对象：7 个键

`build_conclusion(result, verdict)` 返回：

```json
{
  "conclusion": "……（基于 ……；……）",
  "basis": ["抓包窗口 16 秒，报文 54 个、TCP 会话 4 个", "..."],
  "coverage": ["终端侧抓包与 L2–L7 规则判定", "..."],
  "not_covered": ["业务流量 QoS/DSCP 路径未覆盖（理论边界）", "..."],
  "confidence": 0.65,
  "confidence_level": "中",
  "key_limit": "探测/逐跳基于 ICMP，不代表 TCP 路径"
}
```

字段语义：

| 字段 | 语义 | 是否落库 |
|---|---|---|
| `conclusion` | 一句话结论，模板 = `{headline}（基于 {basis_short}；{key_limit}）`。**不手写第三份文案**，必须同时含依据摘要与关键边界 | ✅ CLI/UI/MCP；报告正文以同一句式出现 |
| `basis` | **依据什么**：采样窗口、报文/会话数、目标与端口、探针 sent/recv/loss、逐跳、判定计数 | ✅ 报告 JSON 的 `verdict.basis` |
| `coverage` | **本次覆盖了什么**：静态能力项（L2–L7 / 协议统计 / 安全观察）+ 运行时事实（窗口、目标、判定数、探针类型/角色） | ✅ `verdict.coverage` |
| `not_covered` | **明确没覆盖什么**：QoS/DSCP 理论边界、抓包点以外链路、窗口外时段 + 本次缺失的探针角色 | ✅ `verdict.not_covered` |
| `confidence` | `[0,1]` 的结论级置信度，由证据形态自动推导（见 §3） | ✅ `verdict.confidence` |
| `confidence_level` | `高/中/低`，由阈值派生，**不落库**；不是 dataclass 字段，外部无法人工赋值 | ❌ 渲染期计算 |
| `key_limit` | 按等级从 copy 表选出的「最关键一条边界」，**不落库** | ❌ 渲染期计算 |

双轨约定：**静态部分只放 copy 表模板**（`core/copy/zh-CN.json::conclusion`），
**运行时事实由代码填**。copy 表里不允许写死「54 个报文 / 16 秒 / 192.168.…」这类
本次数据；两条不同结果渲染出的运行时项必须不同。

---

## 3. `confidence` 与 `confidence_level`

### 3.1 三档推导（`derive_confidence`）

| 档 | 常量 | 判定条件 |
|---|---|---|
| 高 | `CONFIDENCE_CONTRAST = 0.9` | `meta.probe_baseline.roles` 同时有 `gateway` 与 `target`；两侧样本各 ≥2；两侧丢包率都 <20%；`verdict.probe_contrast` 未指向对端 |
| 中 | `CONFIDENCE_SINGLE_SIDE = 0.65` | 仅单侧证据：只有抓包无对照 / 只有一侧探针 |
| 低 | `CONFIDENCE_INDIRECT = 0.3` | 无有效样本、`sufficiency.ok=False`、仅 ICMP 超时、采样异常（0 包或窗口 ≤0）、渲染填充失败 |

> **高置信 0.9 目前只有合成用例**：真实触发需要网关 + 对端**双侧探针**同时有样本
> （管理员权限 + Npcap，实时抓包路径）。当前真机/CI 未覆盖这条路径；本次验收的
> 20 个离线报告产物最高为 0.65（中，无对照组），0.9/高只由注入 `probe_baseline`
> 的单测验证。真机验证前，0.9 不得当作「已实测能力」对外宣称。

约束：

- **自动推导，不许人工填**。没有 `set_confidence` / `confidence_score` 之类入口；
  构造器不接受 `confidence_level`。
- 0.9 的「两侧结论一致」只认上面可机械计算的条件；不靠文案或人判断。
- `Finding.confidence` 是单条发现的置信度，**不是**结论级 `confidence`，不要混用。

### 3.2 等级阈值

```python
CONFIDENCE_HIGH_MIN = 0.85   # >=0.85 → 高
CONFIDENCE_MEDIUM_MIN = 0.5  # 0.5 <= conf < 0.85 → 中
                              # <0.5 或证据缺失 → 低
```

`confidence_level_of()` 是唯一阈值实现，契约与渲染器都调它。因此 0.9→高、
0.65→中、0.3→低，三档阈值都能被单测钉住。

### 3.3 `key_limit` 三档（渲染层按等级选）

| 等级 | 文案（与用户原文逐字一致） |
|---|---|
| 高 | 业务流量 QoS/DSCP 路径未覆盖（理论边界） |
| 中 | 探测/逐跳基于 ICMP，不代表 TCP 路径 |
| 低 | 本次无有效样本或采样异常 |

`key_limit` **不进契约、不进报告 JSON**；它只是渲染期由等级 + copy 表派生。
删掉「等级 → key_limit」映射，结论句会缺边界，单测必须变红。

---

## 4. 六出口一致性

### 4.1 同一出处

所有出口只允许调用 `build_conclusion` + `render_conclusion_markdown` /
`render_conclusion_text`：

- 报告 `core/report.py`：第一节 headline 之后追加结论块；
- CLI `--json`：`diagnose._cli_payload()` 直接放 `build_conclusion` 产物；
- CLI 人读：打印完整报告（同一 Markdown 渲染器）；
- 取证单 `core/evidence.py`：清单前前置同一块（md/txt/API content 同步）；
- 诊断包：收进的报告已含结论块，README 写明「请整块阅读」；
- 0 包降级报告 `reports/degraded_*.md|json`：md 插入同一块，json 带同一 7 键对象
  （B1：只给结论不给边界的导出路径已修掉）；
- UI：`/api/status` 下发 `conclusion` + 服务端预渲染的 `conclusion_text` /
  `conclusion_markdown` / `conclusion_export`，前端只排版/复制/下载；
- MCP：`build_diagnostic_payload()` 返回 `{ok, conclusion, markdown, summary}`，
  `basis/coverage/not_covered` 在输出 Schema 里是 **required**。

### 4.2 「整块阅读」与口头传达

结论句内嵌「依据摘要 + 最关键边界」只是为了**降低**转述损失，不是消除损失。

> **口头传达丢失不可避免**：只要人把结论复述给另一个人，依据、覆盖范围、
> 明确未覆盖项、置信等级和关键边界都可能被省略。工具能做的是：把边界和结论
> 绑在同一个对象、同一张卡、同一个复制块里，并在文档/按钮/工具描述里反复要求
> 「整块阅读」。任何只截取 `conclusion` 一句的二次传播，仍然视为误用。

### 4.3 复制给二线

UI「复制给二线」复制的是 `render_conclusion_text(block, report_id)` 整块：

```
结论与边界

结论：……
依据：
1. ……
本次覆盖：
1. ……
明确未覆盖：
1. ……
置信度：中（0.65）
关键边界：……
报告标识：faults_demo.md / faults_demo.json · 2026-11-08 21:00:00
```

不是只复制结论句；报告标识是**文件名 + 生成时间**，不含绝对路径。
`render_conclusion_text` 不传 `report_id` 时不会追加报告行（报告正文因此保持
逐字节不变）。

### 4.4 导出 `.md` / `.json`

| 按钮 | 内容 |
|---|---|
| 导出结论（含边界）（.md） | `render_conclusion_markdown(block, report_id)`：结论 + 依据 + 覆盖 + 未覆盖 + 置信/边界 + 报告标识 |
| 导出结论（含边界）（.json） | `{"meta": {"report_id", "generated_at", "pcap_name", "report"}, "conclusion": {7 键}}` |

`.json` 里的 `conclusion` 与 CLI `--json`、MCP 返回的 `conclusion` **逐键相同**；
`meta` 只补报告标识/生成时间/抓包文件名，不引入第二套结论字段。

---

## 5. UI：同帧、不可折叠

- 正常 / 故障结果：结论卡紧跟主结论卡，在「采集概况」之前；
- 0 包降级结果：结论卡在主卡之后（置信度自动为低）；
- 失败/无数据页：也显示一张降级结论卡（`未知（原因：旧数据缺少边界字段）` + 低），
  不允许结果区只有红字；
- 同一张卡内 DOM 顺序固定为：
  **结论 → 依据 → 本次覆盖 → 明确未覆盖 → 置信度/关键边界**；
- **禁止**放在 `<details>`、tooltip、悬浮层或默认隐藏的 tab 里；
- 卡片文案来自 `core/copy/zh-CN.json::conclusion`（`ui_title` / `ui_*_heading` /
  `btn_*` 等），页面不另存一份中文。

headless 证据（本机 Edge，独立 profile，用完即删）在
`review/e2-samples/after/ui-conclusion.png` 与 `ui-evidence.json`；断言包括
`[data-concl]` 顺序、`closest('details') === null`、可见性、复制内容四要素、
两个导出文件内容。

---

## 6. 旧数据与降级（绝不空白）

### 6.1 旧载荷（没有 `conclusion` 字段）

UI `conclusionData()` 返回：

- `conclusion` / `basis` / `coverage` / `not_covered` 全部显示
  `未知（原因：旧数据缺少边界字段）`；
- `confidence = 0.3` → `confidence_level = 低`；
- `key_limit = 本次无有效样本或采样异常`；
- 卡片带 `data-legacy="1"`，视觉上弱化但**仍然完整显示**。

### 6.2 运行时填充失败

`build_conclusion` 对每个模板单独 `try/except`：失败项替换为
`未知（原因：{异常类型}: {摘要}）`，并把最终 `confidence` 降为 `0.3`（低）。
禁止空串、禁止 `except: pass`。

### 6.3 0 包降级结果

降级结果没有 `verdict`，`build_status_conclusion()` 只补一个最小
`{"headline": <降级标题>}`，不伪造 level/points；置信度仍按「无有效样本」→
0.3/低，`key_limit` 取低档文案。

降级报告 `reports/degraded_*.md|json` 也走**同一个** `build_conclusion`：
`render_degraded` 用 `capture` / `target` / `link` / `duration` 拼最小输入
（标题取 `card_title`，没有时退 `headline`），md 在「一、结论」节内插入同一
「结论与边界」整块（结论/依据/本次覆盖/明确未覆盖/置信+关键边界，同帧连续），
json 增加同一 7 键对象（`conclusion/basis/coverage/not_covered/confidence/
confidence_level/key_limit`）。降级结果没有 `meta`/`rows`，因此最小输入把
`packets` 固定为 0，置信度由推导器自动落 0.3/低，**不手工写**；也绝不伪造
`probe_baseline`（否则 0 包也可能推出高置信）。普通报告 JSON 的五块约定不变。

### 6.4 报告 JSON 的兼容边界

报告 JSON 的 `verdict` 块只多 `confidence/basis/coverage/not_covered` 四个键，
不含 `confidence_level` / `key_limit` / `conclusion`。旧版阅读器忽略新键即可；
新阅读器对缺键按「未知 + 低」处理。

---

## 7. 0.3.x 边界（明确不做 / 暂不做）

- **TCP-SYN 逐跳**：0.3.x 只做「环境可行性评估」——先验证本机能否跑
  Windows `tracetcp` 或 WSL `traceroute -T`；能跑再做 1~2 次 ICMP vs TCP 对照；
  不能跑就登记「评估受阻」。**不自研**（自研 ≥1 天且含误判调试）。
- **DSCP/包长模仿、逐流 QoS 复现、多引擎统一抓包**：明确不做。
- **IPv6 逐跳**：未实现（路径剖面只有 IPv4）。
- **被动监听 / 离线分析**：恒不发探针，因此没有「网关 vs 对端」对照组，
  结论置信度最多为中（仅单侧证据），不会给高。
- **通信观察 / 链路体检**：不产生分层诊断结论，不纳入六出口结论一致性要求。

---

## 8. 测试与红线

- 单测：`tests/test_conclusion.py`（契约/推导/模板/报告/CLI/取证单/诊断包）、
  `tests/test_ui_conclusion.py`（状态加法字段/复制/导出/降级/UI 静态契约）、
  `tests/test_mcp_conclusion.py`（output schema/required/结构化返回/description/工具名回归）。
- 变异至少覆盖：删等级→key_limit 映射、confidence 写死、填充失败吞异常、
  copy 表写死运行时数据、模块级缓存串味、MCP 缺 required、UI 只复制结论句、
  导出只含结论、结论/边界分帧或折叠、某出口绕过 `build_conclusion`、
  MCP description 缺指定措辞。
- 红线：demo + 9 样本 20 个**报告五块载荷**产物，JSON 删新增四键（并归一
  `analyze.provenance.schema_version 2.1→2.2` 这一契约升级）后与 v0.3.0 基线
  `e3f2c97` 逐字节相等；MD 去掉新增行后逐字节相等。E2 只改 UI/MCP/文档，
  **不得再改变报告/判定输出**（复核仍为 20/20）。
