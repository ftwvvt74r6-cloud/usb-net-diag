# TASKS —— 人读版任务清单

机器可读版是 `tasks/tasks.json`（含每个任务的 `steps` / `acceptance` / `copy_from`）。
两版内容一致，**以 json 为准**；本文件只用于快速浏览与排期。

---

## 一、怎么用这张表

```
1. 看 phase 分组，同 phase 内的任务按 id 顺序做（T00 → T01 → T02 → T03 …）
2. 开工前检查 depends_on 全部完成
3. 一次只改一个任务；做完跑 acceptance，绿了再下一个
4. 每个 PR 结束后，按 START-HERE.md 第 5 节的 8 条做一次终验
```

---

## 二、任务总览

> **顺序**：T17（配 git）→ T00（验证落地前提）→ T01…（按 phase 走）。
> T16（接口文档）与 T01 同属 PR1，可以并行推进，但它最后一道门槛 `--check 0.95` 必须在合并前通过。

| ID | 优先级 | PR | 任务 | 关键文件 | 验收要点 |
|---|---|---|---|---|---|
| **T17** | P0 | PR0 | **接管 git 仓库**（身份/代理/认证/首次导入） | `docs/git-setup.md` `AGENTS.md` | 本地 sha = `origin/main`；`git status` 空；Actions 绿过一次 |
| **T00** | P0 | PR0 | 验证落地前提 + 复现「同一 pcap 结论不一致」 | `logs/diag_20261106.log` `doctor.bat` | 目标机 Npcap/管理员可用；同一 pcap 三次结论一致 |
| **T01** | P0 | PR1 | 落地数据契约 | `core/contracts.py` `core/__init__.py` | `SCHEMA_VERSION == "2.0"` |
| **T02** | P0 | PR1 | 错误码 / 配置 / 平台适配 / 文案表 | `core/errors.py` `core/config.py` `core/platform/` `core/copy/` | `PATHS.root` 指向仓库根；`config_sha256()` 16 位 |
| **T03** | P0 | PR1 | analyzer 增量产出 `findings_v2` + `provenance` | `core/analyzer.py` `core/rules/legacy_map.py` | `rows` 逐字不变 + 多出 `findings_v2` |
| **T16** | P0 | PR1 | **接口定义文档 + 全量注释**（小白可读） | `scripts/gen_api_doc.py` `docs/overview.md` `core/**/*.py` | `gen_api_doc.py --check 0.95` 通过；缺口清单为空 |
| **T04** | P0 | PR2 | 拆出 extract 层 + `features.json` 可回放 | `core/extract/` `core/analyzer.py` | `len(tcp.streams) == 4`、`retrans_rate ≈ 5.56`、`dir_totals` 有 c2s/s2c |
| **T05** | P0 | PR2 | `build_findings` 拆成独立 Rule + verdict 纯函数 | `core/rules/` `core/verdict/` | 规则数 ≥ 8；`faults_demo` 报告快照 diff 为空 |
| **T06** | P0 | PR2 | 证据充分性闸门 | `core/verdict/verdict.py` | 1 KB 空抓包 → `VERDICT.INSUFFICIENT`，不再报「正常」 |
| **T07** | P1 | PR2 | 修 `conn_refused` / `dns_timeouts` / 死代码 | `core/analyzer.py` `core/verdict.py` | 正常关闭后的 RST 不再算「端口没开」 |
| **T08** | P0 | PR3 | 接出口脱敏（AI）+ 双断言 | `core/egress/` `core/ai.py` | ①查不到原 IP/口令 ②脱敏前后 findings 一致 |
| **T09** | P0 | PR3 | 修 `uri_secret` 泄露路径 | `core/analyzer.py:362-364,766-770` | 含 `?password=X` 的请求，报告与 payload 都不含 `X` |
| **T10** | P1 | PR3 | MCP 出口同样脱敏 | `mcp/wireshark-mcp/server.py:168` | `tools/list` 仍返回 7 个工具，报告已脱敏 |
| **T11** | P1 | PR3 | 接 JobStore（job_id / 增量日志 / 取消） | `core/api/jobs.py` `core/server.py` | 路由不变，只多 `job_id`；可取消 |
| **T12** | P2 | PR3 | `/api/v1` + envelope + 静态路由 + 前端拆分 | `core/api/app.py` `ui/index.html` | `/api/v1/jobs` 返回 envelope；`/static/app.js` 200 |
| **T13** | P2 | PR4 | 路径探测 + 影子探测（含探针排除） | `core/pathprobe.py` `core/capture/live.py` | 开探测后抓包指标与不开时一致 |
| **T14** | P2 | PR4 | 历史基线库（sqlite3） | `core/history.py` | 跑两次后 `baseline().samples == 2` |
| **T15** | P1 | PR4 | AGENTS.md / 分支保护 / CI 三层 / pcap 样本 | `.github/workflows/smoke.yml` `AGENTS.md` | PR 未过 check 无法合并；规则测试不依赖 tshark |

图例：P0 = 不做就会持续造成误判或泄露；P1 = 影响可维护性；P2 = 能力扩展。

---

## 三、推荐排期（单人节奏，含验证时间）

| 阶段 | 内容 | 估时 | 里程碑 |
|---|---|---|---|
| PR0 | **T17** + T00 | 2~3 天 | git 能推能拉、CI 跑起来；确认「能不能在公司环境跑」 |
| PR1 | T01 T02 T03 **T16** | 3~5 天 | 契约落地 + 接口文档合格率 ≥95%，旧行为零变化（可安全合并） |
| PR2 | T04 T05 T06 T07 | 3~5 天 | 规则可单测；空抓包不再报正常 |
| PR3 | T08 T09 T10 T11 T12 | 3~5 天 | 脱敏生效；任务可追溯；报告不覆盖 |
| PR4 | T13 T14 T15 | 4~6 天 | 能定界到跳；有基线；CI 真守门 |

**关键依赖**：`T04` 是所有方向类规则的前提；`T01` 是所有任务的公共前提；
`T13` 依赖 `T04` 的 `dir_totals`（判断探针是否污染统计）；`T14` 依赖 `T05`（要有 `rule_id` 才能统计命中率）。

---

## 四、每个 PR 结束时的固定动作

```bat
REM 1. 语法
tools\python\python.exe -m compileall -q core mcp tests

REM 2. 单测
tools\python\python.exe -m unittest discover -s tests -v

REM 3. 骨架自检（迁移完成前一直保留，当前 54 用例）
cd scaffold && ..\tools\python\python.exe run_tests.py && cd ..

REM 4. 接口文档 + 注释达标（T16 之后每次都要跑）
tools\python\python.exe scripts\gen_api_doc.py --check 0.95

REM 5. 报告快照（改过 rows 或规则必做）
copy reports\faults_demo.md %TEMP%\baseline.md
tools\python\python.exe core\diagnose.py --pcap captures\faults_demo.pcap
REM 用编辑器比对 %TEMP%\baseline.md 与 reports\faults_demo.md，只允许时间戳不同

REM 6. 干净度
git status --short
REM 期望：只出现你本次有意新增/修改的源码文件，不出现 tools/ harness/ *.pcap logs/ reports/
```

---

## 五、不许自己给自己加戏

- 不要顺手重构 `core/probe.py` / `core/passive.py`（1400 行可用实现）。
- 不要顺手把 UI 换成 React/Vue（没有构建链，会毁掉便携性）。
- 不要顺手加依赖（`requests` / `pandas` / `loguru`）。
- 不要顺手改 `start.bat` 的流程（提权 → 自检 → Npcap → 起 UI 的顺序有原因）。
- 不要为了「测试好写」而改产品行为——测试是描述行为的，不是定义行为的。
