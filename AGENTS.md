# AGENTS.md —— AI 协作契约（建议提交到仓库根目录）

> **接手先读 [`docs/HANDOVER-AI.md`](docs/HANDOVER-AI.md)**：项目现状、数据流、对外 API、红线、
> CI 与加新功能流程以那份手册为准；本文件只列硬约束，且部分目录表描述的是目标架构，不是当前实现。

> 本文件是**给 AI 编码助手的约束文件**，优先级高于一般性建议。
> 现状：仓库还没有这个文件，所以「禁止 AI 直接推 main」只能靠人盯。
> 把本文件放进仓库根目录 + 打开 GitHub 分支保护，约束才真正生效。

---

## 1. 项目定位（一句话）

放进 U 盘的 Windows 便携网络诊断工具：插上 → 双击 `start.bat` → 浏览器打开 `127.0.0.1:8787`。
主线是**网络故障排查**（L2→L3→L4→L7 分层定位），安全检测只是附带项。

**第一性价值**：回答四个问题 —— 哪一层坏了 / 哪个协议 / 哪个对端 / 下一步做什么。
任何改动如果削弱这四问，即使「代码更漂亮」也不算改进。

---

## 2. 目录职责（改之前先确认改的是哪一层）

| 路径 | 职责 | 允许改什么 |
|---|---|---|
| `start.bat` `doctor.bat` | 启动器：提权、自检、Npcap 兜底、拉起 UI | 只允许**追加**步骤，不许改既有 `%ROOT%\...` 路径 |
| `core/bootstrap.py` | 盘符自适应 + 环境自检 | 可改 |
| `core/platform/` | OS 交互（管理员/Npcap/网卡/路由） | 新增；**不许出现业务判断** |
| `core/capture/` | **唯一**允许调 tshark / scapy 的地方 | 新增；其他模块不许直接 `subprocess` |
| `core/extract/` | `Record` → `Features`，纯函数、可落盘 | 新增 |
| `core/rules/` | 规则：`Features` → `Finding`，**纯函数、无中文** | 新增 |
| `core/verdict/` | `Finding[]` → `Verdict`，纯函数 | 新增 |
| `core/egress/` | **唯一**允许对外发送/落敏感内容的地方 | 新增 |
| `core/render/` | 契约 → Markdown / JSON，只排版不判断 | 新增 |
| `core/api/` | 路由 + envelope + JobStore | 新增 |
| `core/history.py` | sqlite3 基线库 | 新增 |
| `core/analyzer.py` | 现有采集+聚合+规则（待拆） | 只允许**新增**字段/函数，不许删 |
| `core/probe.py` | 协议自适应体检（946 行，核心差异化） | ⛔ 不许重写，只允许搬路径/加类型 |
| `core/passive.py` | 被动监听（483 行，scapy 唯一使用者） | ⛔ 同上 |
| `ui/index.html` | 单文件控制台 | 拆分前不要动结构 |
| `mcp/wireshark-mcp/server.py` | MCP stdio 服务 | 加工具可以，改已有工具名/参数名不行 |
| `skills/network-diagnose/SKILL.md` | 工作流固化 | 改流程要同步 `README.md` |
| `tests/` | 测试 | 只加不改（`test_launcher_contract.py` 是启动器契约，动它等于放行破坏启动） |

---

## 3. 硬约束（DO NOT）

1. ⛔ 不许直接推 `main`。必须：`feat/xxx` 分支 → PR → CI 绿 → 合并。
2. ⛔ 不许在 `core/rules/**`、`core/verdict/**` 里写中文字符串。
   （CI 可以加一条 40 行的守门测试：`re.search(r'[\u4e00-\u9fff]', source)` 应为 None）
3. ⛔ 不许改 `rows[]` 里 `layer` / `category` / `severity` 的**取值**。
   要引入机器码就走新字段 + 适配层，别动老字段。
4. ⛔ 不许引入 pip 依赖。唯一例外是已内置的 `scapy 2.8.0`
   （`tools/python/Lib/site-packages/scapy`）。
5. ⛔ 不许把 `tools/`、`harness/`、`*.exe`、`config/ai-config.json`、
   `config/app-config.json`、`captures/**`、`logs/**`、`reports/**` 加进 git。
6. ⛔ 不许把真实 IP、内网域名、API Key 写进任何文件（含注释/示例/测试期望值）。
7. ⛔ 不许改 `start.bat` 的 `%ROOT%\...` 引用路径（`tests/test_launcher_contract.py` 守着）。
8. ⛔ 不许把服务绑到 `0.0.0.0`。它必须只监听 `127.0.0.1`。
9. ⛔ 不许静默吞异常后返回「正常」。证据不足就必须说「证据不足」。
10. ⛔ 不许删 `captures/faults_demo.pcap`（README 首跑引导 + CI 金标准）。
11. ⛔ 不许用「本地化 CLI 文本解析」做平台判断（`ipconfig`/`tracert`/`sc query` 的输出是本地化的）。
12. ⛔ 不许在 `verdict` 之前脱敏（规则会看不到 IP，答不出「哪个对端」）。
13. ⛔ **不许手改 `docs/api-reference.md` / `docs/docstring-gaps.md`** —— 它们由
    `scripts/gen_api_doc.py` 生成，手改下次就被覆盖。要改内容 → 改源码 docstring。
14. ⛔ 不许 `git push -f`；不许把改动直推 `main`。
15. ⛔ 不许把 `scripts/gen_api_doc.py` 放进 `tools/` —— `tools/` 被 `.gitignore` 排除，
    放进去在 CI 里根本不存在。

---

## 4. 编码规范（MUST）

| 主题 | 规则 |
|---|---|
| 分层 | `capture → extract(features) → rules(findings) → verdict → render/egress`，每层只依赖前一层 |
| 纯函数 | `extract` / `rules` / `verdict` / `render` 不得读文件、读时钟、开 socket |
| 契约 | 跨模块数据只能用 `core/contracts.py` 里的类型；不许临时 dict |
| 版本 | 改契约 → 升 `SCHEMA_VERSION`；改阈值 → 升 `rules/thresholds.json` 的 `rules_version` |
| 文案 | 一律 `copy/zh-CN.json` + `rule_id` 作 key；渲染层 `str.format` 安全降级 |
| 数值 | 「没有样本」用 `Stats.n == 0` 表达，**不许**用 `0.0` 冒充 |
| 推断 | 推断类结论必须 `evidence_kind=INFERRED` 且 `confidence < 1.0` |
| 错误 | 可预期失败抛 `DiagError(code, message, hint)`；代码里不许出现裸 `except: pass` |
| 日志 | 结构化、单行；进 `logs/` 前过 `egress.sanitize_for_log()` |
| 注释 | 写「为什么」，不写「是什么」；引用 issue/任务号 |

---

## 4.1 文档与注释（可测量的硬要求）

详见 `docs/api-style.md`。要点：

| 层级 | 要求 | 检查方式 |
|---|---|---|
| 模块头 | 回答四问：解决什么问题 / 谁调用它 / 不做什么 / 输入输出 | 人工 + 覆盖率统计 |
| 公开函数 | `Args:` / `Returns:` / `Raises:` / `Example:` 四节齐全；**结构化返回值必须列键名** | `scripts/gen_api_doc.py --check` |
| 行内注释 | 只写「为什么」，禁止复述代码（`i += 1  # i 加一`） | 人工 review |
| 术语 | 首次出现就地给一句白话解释（见 api-style 的术语表） | 人工 review |

命令（CI 也用它，别再手写接口清单）：

```bat
tools\python\python.exe scripts\gen_api_doc.py              REM 生成 docs/api-reference.md + 缺口清单
tools\python\python.exe scripts\gen_api_doc.py --check 0.95  REM 合格率 <95% 直接失败
```

现状基线（`v0.1.0`）：模块说明 11/11，公开符号 55 个，**合格 1 个（1.8%）**。
目标：**≥ 95%**。这张表就是「补注释」的进度条，一行修完就少一行。

**写作纪律**：这条规范的目标是「让不懂网络的人读懂」，不是「让注释看起来很多」。
给私有函数堆废话注释来刷覆盖率，比不写更糟。

## 4.2 提交前必问：CI 环境里缺什么？

本地能跑 ≠ CI 能跑。这个项目已经因此红过两次（VBS 契约测试、docs 换行）。

| 本机有 | CI 没有 | 后果 |
|---|---|---|
| `tools/`（约 360MB 便携环境） | 不存在 | 任何断言 `tools/...` 存在或可执行的测试都会红 |
| `tshark.exe`（PATH 或 Program Files） | 未安装 Wireshark | 依赖真抓包的测试必须 `skipUnless`，否则红 |
| 管理员权限 + Npcap | 没有 | 实时抓包、被动监听不可用 |
| Windows + `core.autocrlf=true` | Linux，两端都是 LF | 生成脚本必须**固定写 LF**，否则产物不可复现 |
| `logs/` `reports/` `captures/` 历史产物 | 不存在 | 测试不要依赖历史文件 |

提交前用**干净 checkout** 自查（唯一可信的验证方式）：

```bat
git worktree add --detach .ci-check HEAD
cd .ci-check
<python> -m compileall -q core mcp tests
<python> -c "import sys;sys.path.insert(0,'.');import unittest;unittest.main(module=None,argv=['x','discover','-s','tests','-v'])"
<python> scripts/gen_api_doc.py --check 0.95
git -c safe.directory=* diff --exit-code docs/api-reference.md docs/docstring-gaps.md
cd ..
git worktree remove --force .ci-check
```

---

## 5. 提交与 PR

```
分支：feat/<task-id>-<slug>      例：feat/t05-rules-migration
提交：<type>(<scope>): <中文摘要>  例：feat(rules): 把 build_findings 拆成独立 Rule
      type ∈ feat|fix|refactor|test|docs|chore|perf
PR  ：必须包含
      1) 动机（对应哪个 rule_id / 哪个现象）
      2) 改了哪些层（勾选 capture/extract/rules/verdict/egress/render/api）
      3) 验收命令与输出（贴 CI 或本地输出）
      4) 回滚方式（一句）
```

**分支保护需要人工在 GitHub 设置里打开**（AI 改不了仓库设置）：

- `main`：Require PR、Require status checks（选 `smoke` 里的 `syntax-and-contract`）、
  Require linear history、禁止 force push。
- 加 `CODEOWNERS`：`core/capture/**`、`start.bat`、`tests/**` 归维护者。

---

## 6. 测试要求

新增/修改规则，**必须同时给**：

1. 一个**命中**用例（构造 `Features` → 断言 `rule_id` + `severity` + `direction`）；
2. 一个**不命中**用例（阈值下方 → 返回空列表）；
3. 若结论是推断，断言 `confidence < 1.0`；
4. 若涉及方向，断言 `direction`；
5. 改 `rows[]` 文案的 PR 必须附带 `faults_demo` 的**前后报告 diff**。

测试不许依赖 tshark / 网络 / 管理员权限。需要真 pcap 的放 `tests/e2e/` 并打 `@slow` 标记。

### 跑单个测试文件

`tests/` 不是 Python 包（没有 `__init__.py`），所以 `python -m unittest tests.test_xxx`
会报 `ModuleNotFoundError: No module named 'tests'`。用 discover + 文件名过滤：

```bat
python -m unittest discover -s tests -p "test_incomplete_input.py" -v
```

---

## 7. 已知陷阱（踩过一次就别再踩）

| 陷阱 | 事实 |
|---|---|
| `sys.path` | `tools/python/python311._pth` 固定 3 行路径，**不含 cwd、忽略 `PYTHONPATH`**。`python -m xxx` 找不到 `core`。入口必须显式 `sys.path.insert` |
| 模块名 | 现有代码是扁平 import（`from tshark import ...`），依赖 `sys.path.insert(0, 'core')`。改成包结构时**必须**同时改所有 import，否则运行期才炸 |
| `*.pcap` | `.gitignore` 全局忽略，只有 `!captures/faults_demo.pcap` 例外。新增样本目录必须加例外或脚本生成 |
| tshark 输出 | 部分环境 `-D` 把网卡列表输出到 **stderr**；`-T fields` 的重复字段用 `aggregate=,` 拼接 |
| 时间 | pcap 用系统时钟（`frame.time_epoch`），探测用 `time.monotonic()`，两者有偏移 |
| 探针污染 | 任何主动探测都会进入自己的抓包：必须用 BPF 排除或按账本过滤，否则伪造出故障 |
| U 盘 | 可能是 exFAT（无硬链接/无权限位）、可能写保护、可能被杀软挂起。写文件一律 try/except 并降级 |
| 中文编码 | 控制台是 GBK、源码是 UTF-8。写文件显式 `encoding="utf-8"`；打印不要假设终端能显示 |
| 报告覆盖 | 现有 `reports/<pcap名>.md` 是覆盖写。任何「审计」需求都要求带时间戳的新文件名 |

---

## 8. 需求变更的正确姿势

```
1. 先改文档：docs/rules.md（加规则）/ docs/data-contract.md（加字段）
2. 再改契约：core/contracts.py + SCHEMA_VERSION
3. 再改实现：rules → verdict → render → ui
4. 最后补测试与快照
```

**不许**从 UI 反推数据结构，也不许为了「先跑起来」在规则里写死 IP / 端口 / 域名。
