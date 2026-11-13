# 工作记录索引（Work Records Index）

> 原始验收报告与截图不入库（含环境信息、体积大），只登记索引。
> 默认位置：`%USERPROFILE%\NetDiag-progress\<轮次>\`；历史遗留位置在备注里注明。
> 交接时按此表可以找到每一轮「改了什么、为什么、验收证据在哪」。

| 日期 | 轮次 | 范围 | 结论/产出 | 位置（备注） |
|---|---|---|---|---|
| 2026-11-0x | S1–S3 | UI v2 骨架 / 首页 / 结论卡 | 骨架与三段雏形，默认不启用 | 历史桌面 `沟通\` 目录（已归档到个人盘） |
| 2026-11-09 | v0.3.3 | 修复真机事故（pcap 路径/旧记录/失败混入） | 发布 0.3.3，tag `v0.3.3` | `docs/release-v0.3.3.md` |
| 2026-11-10 | S4 | 一眼三层结论 + 专业数据上首页 | 结论横幅/3 步动作/4 格责任 + 专业面板 | 历史桌面目录 |
| 2026-11-10 | S5 | 报告三段结构 + 文案专业化 | 首页与五个模式页统一三段 | `progress\s5\` |
| 2026-11-11 | S6/T1-T5 | 报告可分析化、设置页、历史趋势、L7 报文口径、数据段收口 | 复制/导出含数值；历史卡三态 | `progress\s6\` |
| 2026-11-11 | R6/R8 | 离线 meta 契约（capture_mode）、l7_packets、dns_truncated | 快照仅三键例外 | `progress\polish\` |
| 2026-11-11 | agent T1 | 常驻采集：采样可调/目标/事件/JSONL/安装脚本 | 测试 1114→1191 | `progress\agent\` |
| 2026-11-12 | T2 | 历史接口（history/events/export/mark，epoch 秒） | 测试 1264 | `progress\agent\` |
| 2026-11-12 | T3 | 端口三级避让 + 端口文件贯通启动器/stop | 测试 1295 | `progress\agent\` |
| 2026-11-12 | S9-S10 | 事件线配色、CSV 落盘名、设置页真机联调 | 目标 key/间隔生效/阈值同源 | `progress\s9\`、`progress\s10\` |
| 2026-11-12 | S11 | ICMP 被过滤时指标表/导出不标红；安装提示人话化 | 真机 8787+baidu 抓包验证 | `progress\s11\` |
| 2026-11-13 | C-轮1 | 独立测试窗口（陌生环境，黑盒） | 26 项：21 PASS/3 FAIL/1 PARTIAL/1 SKIP；缺陷 DEF-01(P0)/02(P1)/03(P1)/04(P2)/05(P3) | `%USERPROFILE%\work\soak\20261113\`（缺陷六段式在 defects.md） |
| 2026-11-13 | 原件对照 | 抓包原件 vs 程序翻译件对照（demo pcap） | 每个派生数字可用 tshark 复算；重传 4 帧 vs 5.56% 口径解释 | 桌面 `NetDiag-原件对照\` |

## 使用说明

1. 新接手的模型/人：先读 `docs/START-HERE.md`、`docs/HANDOVER-AI.md`、`docs/process.md`、`docs/backlog.md`
2. 想追溯"为什么这么改"：查 `docs/decisions.md` 与对应轮次的 `records`（本表）
3. 想复现某一轮验收：按本表找目录；若目录已失，PR 描述与 `CHANGELOG` 有等价信息
