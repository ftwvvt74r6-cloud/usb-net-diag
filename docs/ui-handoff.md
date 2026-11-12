# UI 侧需求单（文案 / 接线）

**立场**：判定、报告 md、接口、测试归后端；`ui/v2/**` 归 A。以后 UI 侧要改什么，
一律写进本单 —— **文件路径 + key + 期望 + 验收**，我不再直接动 `ui/v2`。

本单只写「要什么」，不规定实现写法。A 可以换写法，但**验收那一步必须能过**。

---

## 0. 为什么忽然要有这张单

上一批 P0-1 / P0-2 我为了把真机问题闭环，直接改了 4 个 `ui/v2` 文件
（`copy.js` / `verdict.js` / `render.js` / `settings.js`）。与 A 的 S8 **文件不重叠**
（见 §1），但同一个视图层两个作者，迟早出现两种坏结果：

1. **两套判定**：我在 `verdict.js` 里判「目标不回 ICMP」，A 在 `history.js` 里另写一份，
   改口径时漏一处，页面和导出文件就开始互相打脸；
2. **一句话两个版本**：同一个 key 被两个人先后改文案，谁后改谁生效，历史无从追溯。

所以从这一单开始：UI 侧只提单，不代笔。

---

## 1. 与 A 的 S8 是否重复 —— 结论：不重复

**S8** = 分支 `fix/ui-v2-history-live`，提交 `b8c39e7`，改动 `ui/v2/js/history.js` +
`ui/v2/css/components.css`（+25/−6），主题是历史趋势卡真机联调。

**我这一轮改的 4 个文件**：`ui/v2/js/copy.js`、`ui/v2/js/render.js`、
`ui/v2/js/settings.js`、`ui/v2/js/verdict.js`。

| 检查项 | 方法 | 结论 |
|---|---|---|
| 文件级重叠 | 两边 `git diff --stat` 对比 | **0 个文件重合**（S8 动 history.js/components.css，我动 copy/render/settings/verdict） |
| 语义级重叠 | 全仓 grep `icmp_filtered` / `filtered` / `过滤` 扫一遍 `ui/v2/js/*.js` | 只有我这两处（`verdict.js` 的 `firstLoss`/`icmpFiltered`、`render.js` 的跳表与探针基线），**没有第二份实现** |
| 反向检查 | S8 报告里是否被我改坏 | S8 报告 §4-D 记录的两条 `404 /api/monitor`、`404 /api/agent/status` 正是 P0-2 补掉的后端；**S8 的 UI 断言一条没动**，但它的报告里「这两个接口 404」的描述从现在起已过期（历史记录，不必改） |
| 冲突风险 | `git log --oneline -- <4 个文件>` | 这 4 个文件上，A 的最后一个提交是 `5cef2fb`（T2 设置页），我的是 `c55736d`/`c21e175`，之后无人再动 → 无并行改写 |

**唯一「看起来重复」的地方**，是设置页那张「常驻采集」卡：

* A 在 S8 报告里如实写了「没有 `/api/agent/status`，状态只能显示『未开启』」；
* 我把后端补上，并顺手修了「进程在跑、却没装计划任务时，卡片一边『运行中』一边
  『采集未开启』」这个自相矛盾。

这是同一个问题的**两端**（前端如实降级 / 后端补能力），不是两份实现。那处前端修补
已并入 main，归口说明见 §3。

---

## 2. 需求单

优先级：R1–R3 属于**同一条口径**（ICMP 被过滤时，报告里的丢包率怎么读），
建议一起做；R4–R6 是设置页；R7 是防分叉的收口；R8 只是确认。

### R1 关键指标表的「丢包率」要认 `reason`（最高优先）

- **文件**：`ui/v2/js/metricstable.js`，`rows()` 里 `mLoss` 那一段（当前 183–193 行）
- **现状**：`loss = 1 - recv/sent`；`flag` 恒为 `RP.mLossProbe`（「探针」）；
  `state = grade(loss, 1, 3)` → 100% 直接标红
- **期望**：当「这次没收到不是链路丢包」成立时（判据见下），
  1. `flag` 换成新 key `report.mLossIcmpFiltered`（建议文案：
     `目标不回 ICMP，此数不代表链路丢包`）；
  2. `state` 改为 `""`（不染色）—— 页面和导出都不要把 100% 标红；
  3. **数值不变**（仍是 `100.0 %`）。丢的确实是 ICMP 的包，这个数没算错，
     错的是「怎么读」。
- **判据（任一成立）**：
  - `res.meta.probe_baseline.roles` 里 `role === "target"` 那项的 `reason`
    ∈ `"icmp_filtered"` / `"refused"`；
  - `res.meta.path_profile.target_icmp_filtered === true`。
- **为什么**：`metricstable.rows()` 是**三个出口的唯一来源** —— 页面 ③ 关键指标表、
  导出的 md、导出的 json 都吃它。改这一处，三处同时一致；反过来，漏了这一处，
  就是「结论说『目标不理 ICMP』、指标表写『丢包 100%』」的自相矛盾。
- **验收**：真机目标 8 发 0 收 + 同目标 TCP 通时，页面与导出都显示
  `100.0 %（目标不回 ICMP，此数不代表链路丢包）` 且**不标红**；
  把同一目标改成 50% 丢包（部分丢包）时，仍标红 —— 部分丢包是**真的**丢包。

### R2 导出的报告要带那句口径（与 R1 配套）

- **文件**：`ui/v2/js/reporter.js`，③ 关键指标表 `mdTable(...)` 之后（当前 334–344 行）
- **现状**：页面有 `report.metricsNote` 兜着（`report.js:156`），**导出的 md / json 没有**
- **期望**：R1 的判据成立时，表后追加一行引用：
  `> 口径：目标不响应 ICMP（探测侧已用 TCP 证明可达），丢包率只说明「目标不理 ICMP」，以 TCP 的 RTT 与重传为准。`
  新 key：`report.icmpFilteredNote`
- **为什么**：导出文件是**唯一会被转发出去**的那一份。别人只看到「丢包率 100%」，
  结论就会变成「运营商承载网故障」—— 这正是 P0-1 要消灭的误判。
- **验收**：`icmp_filtered` 场景导出 md，「## 2 关键指标」表后有此行；
  普通丢包场景没有这一行（不能无脑常驻）。

### R3 `copy.js` 补两个 key

- **文件**：`ui/v2/js/copy.js`，`report` 段（现在 `metricsNote` 在 639 行附近）
- **期望**：

  | key | 建议文案 |
  |---|---|
  | `report.mLossIcmpFiltered` | `目标不回 ICMP，此数不代表链路丢包` |
  | `report.icmpFilteredNote` | `口径：目标不响应 ICMP（探测侧已用 TCP 证明可达），丢包率只说明「目标不理 ICMP」，以 TCP 的 RTT 与重传为准。` |

- **为什么**：R1/R2 要用的两句话必须有 key。硬编码在 JS 里，下次改口径就得翻代码。
- **验收**：`grep -n "mLossIcmpFiltered\|icmpFilteredNote" ui/v2/js/copy.js` 命中，
  且 R1/R2 读的是这两个 key。

### R4 安装失败别把 `[WinError 5]` 直接甩给用户

- **文件**：`ui/v2/js/settings.js`，`install()` 的失败分支（当前 253 行
  `U.toast(U.why(res), "crit");`）
- **现状**：`U.why(res)` 返回 `res.error` 原文 → toast 里出现
  `PermissionError: [WinError 5] 拒绝访问。`（后端如实回原文，这是对的；错在直接展示）
- **期望**：`res.error` 命中 `/拒绝访问|Access is denied|WinError\s*5|0x80070005/i` 时，
  弹模态框（不是 toast）：
  - 标题：`settings.agentBlockedTitle`（建议：`安装被系统策略拦截`）
  - 正文：`settings.agentBlockedBody`，说清三件事 ——
    ① **不是权限不够**，用管理员运行也解不开（拦的是 `schtasks.exe` 这个程序）；
    ② **采集本身没坏**，可以手动启动；
    ③ 三条替代（手动建任务 / 启动文件夹 / 临时手动跑），并指向 `docs/agent.md` §2.1
  - 其他错误仍走原来那条 toast（**不要吞原文**）
- **为什么**：`docs/agent.md` §2.1 已经把「怎么区分两种装不上」「四条替代」写全了，
  界面却只回一个 Windows 错误码 —— 文档写了等于没写。
- **验收**：注入 `{ok:false,status:500,error:"PermissionError: [WinError 5] 拒绝访问。"}`
  → 弹人话模态框；注入 `error:"系统找不到指定的路径"` → 仍是原文 toast。

### R5 安装成功后卡片没重画（顺手修的 bug）

- **文件**：`ui/v2/js/settings.js`，`install()` 的成功分支（当前 246–251 行）
- **现状**：装成功只 `toast` + 拉一次 `agent()` 存进 `state`，**没有重画卡片**；
  而卸载路径有（272–277 行 `paintAgent(currentAgentCard())`）。结果：装完按钮还是
  「安装常驻采集」，得刷新页面才变
- **期望**：与卸载对齐，成功后 `paintAgent(currentAgentCard())`
- **验收**：点「安装常驻采集」→ 不刷新页面，卡片当场变成「已安装」态
  （按钮变「卸载」，采样间隔下拉出现）。**用假 runner 也能验**：接口返回 ok 即可。

### R6 `settings.agentInstallHint` 那句话要改

- **文件**：`ui/v2/js/copy.js`，`settings.agentInstallHint`（当前 190 行）
- **现状**：`安装包在工具目录内：双击 install-agent.bat 完成安装（需要管理员权限）。`
  —— 「需要管理员」是对的（创建 `onlogon` 任务要），但没解释**装完就不需要了**，
  也没给「管理员也装不上」的出路
- **期望**：改成三句话，例如：
  `安装包在工具目录内：以管理员身份运行 install-agent.bat（只在创建任务这一步需要管理员，装好后按普通权限运行）。若提示拒绝访问且 schtasks 也查不了，说明系统策略禁止了 schtasks.exe，见 docs/agent.md §2.1。`
- **验收**：卡片上的安装说明能回答「为什么要管理员」「装完还要不要」「装不上怎么办」。

### R7 把 `icmpFiltered` / `tcpBad` 导出来，别让第二个人再写一遍（防分叉）

- **文件**：`ui/v2/js/verdict.js` 末尾的导出对象（当前 `ND.verdict = { build, head, steps, owner, footer, copySummary }`）
- **现状**：`icmpFiltered(meta)` 与 `tcpBad(meta)` 在闭包里，只有本文件用；
  R1 要判同一件事，只能另写一份，两套判定迟早不同步
- **期望**：挂到导出上（不加参数、不改行为）：
  `ND.verdict.icmpFiltered(meta)`、`ND.verdict.tcpBad(meta)`；R1 直接复用
- **验收**：`node -e` 里 `ND.verdict.icmpFiltered` 是函数；`metricstable.js` 不再自带判据。

### R8 阈值来源确认（低优先，可能什么都不用改）

- **文件**：`ui/v2/js/history.js`（`ND.api.monitor()` 那两处，当前 213 / 247 行）
- **现状**：先读 `/api/monitor`，404 才回落 `localStorage`，再回落 120 ms
- **期望**：确认 404 分支现在只作**兜底**（后端 P0-2 已实现该接口）。只要不是
  「界面显示 88 ms，采集判事件用 120 ms」，就不用动
- **验收**：真服务下改一次阈值（`POST /api/monitor`），历史卡的虚线跟着动。

---

## 3. 本轮已并入 main 的 4 处（请复核归口，别回滚）

这 4 个文件我改了、也推了，撤不回来 —— 列在这里是为了让 A 知道**现在是什么状态**，
避免重复实现。

| 文件 | 改了什么 | 建议 |
|---|---|---|
| `ui/v2/js/copy.js` | 新增 9 个 key：`verdict.problemByKind.icmpFiltered`、`verdict.basis.icmpFiltered`、`verdict.steps.icmpFiltered`(3 条动作)、`owners.peer.byKind.icmpFiltered`、`tech.probeRoleFiltered`、`tech.hopFiltered`、`tech.reasonIcmpFiltered/Refused/Timeout`、`settings.agentManualTitle/Body`；`report.metricsNote` 补了「目标不响应 ICMP 时以 TCP 为准」一句 | 命名不合适的直接改 key，但**同步改调用点**；文案想改请回本单，别静默改 |
| `ui/v2/js/verdict.js` | `firstLoss()` 跳过 `reason==="icmp_filtered"`/`status==="filtered"` 的跳；新增 `icmpFiltered()`/`tcpBad()`；`blame()` 插入 `kind:"icmpFiltered"`（归 `peer`）；`basisText()`/`stepsOf()` 各加一个分支 | 归 A 维护；R7 建议把它们导出 |
| `ui/v2/js/render.js` | 探针基线行：`reason` 是 `icmp_filtered`/`refused` 时追加「目标不回 ICMP，不是链路丢包」；逐跳表丢包列：`filtered` 的跳显示「被过滤」而不是 `100%` | 同上；这两处是**展示**，判定在 verdict.js，不要在这里加判据 |
| `ui/v2/js/settings.js` | 卡片三种状态分开写（接口没有 / 进程在跑但没装任务 / 没装也没跑）；`running` 时也显示采样间隔 | R4/R5/R6 是同一张卡的后续，建议一并收口 |

**红线**（这 4 个文件的改动都没有越过）：没改后端字段取值、没改 `captures/` 与
`reports/`、没新增网络请求、没引入第三方库。

---

## 4. 以后怎么提（模板）

```
### R<n> <一句话说清要什么>

- 文件：ui/v2/js/<file>.js（能定位到函数/行就给）
- key / 函数：<copy key 路径 或 函数名>
- 现状：<现在是什么行为，最好带一句「为什么会这样」>
- 期望：<要变成什么，不要写「优化一下」这种>
- 为什么：<不改会出什么错；一句话，不要论证>
- 验收：<别人能照着做一步就判断过没过>
```

三条硬要求：**能定位**（文件+函数/key）· **可判定**（期望是行为，不是形容词）·
**能验收**（一步可执行）。缺任何一条，就是一句「你看着改」，等于没提。
