# START HERE —— 给接手这个仓库的 AI 的说明

> **接手先读 [`docs/HANDOVER-AI.md`](./HANDOVER-AI.md)**：这是 v0.2.0 之后的权威交接手册
> （现状、数据流、API、红线、CI、加新功能流程）。本文件是 v0.1.0 时期的历史交接包，
> 里面的 54 用例 / 11 模块 / 55 符号等数字已过期，以 HANDOVER-AI 与代码为准。

> 这是一个**交接包**，不是代码补丁。里面是「怎么把 `usb-net-diag` 从 v0.1.0 改到可落地的 v0.2」的
> 评审结论 + 目标架构骨架 + 可执行任务卡。**所有改动都由你（接手方 AI）来做**，
> 本包不含任何对既有文件的修改。

---

## 0. 先做这 3 件事（5 分钟）

> ⚠️ **如果这台电脑还没配过 git**：先做 `tasks.json` 里的 **T17**，
> 按 `docs/git-setup.md` 一步步来（身份 → 代理 → 认证 → clone 到本机 → 首次导入）。
> 没配好 git，后面所有任务都没法走 PR 流程。

```bat
cd /d <仓库根目录>
tools\python\python.exe -c "import sys;print(sys.version)"

REM 1) 现有程序是否还活着（不写任何文件，只读环境）
doctor.bat

REM 2) 骨架是否自洽（54 个用例，纯标准库，不碰 tshark、不联网）
cd scaffold
..\tools\python\python.exe run_tests.py

REM 3) 接口文档生成器是否可用（顺便量出现有注释覆盖率）
cd ..
tools\python\python.exe scripts\gen_api_doc.py
```

第 2 步的期望输出（**必须完全一致**，否则说明拷贝/环境有问题）：

```
Ran 54 tests in 4.7xs
OK
用例 54 个｜失败 0｜错误 0｜跳过 0
```

第 3 步的期望输出（现状基线，T16 要把它拉到 95%）：

```
模块 11 个（有说明 11）｜公开符号 55 个（合格 1）｜合格率 1.8%
已写：docs/api-reference.md 与 docs/docstring-gaps.md
待补 54 个符号 —— 明细见 docs/docstring-gaps.md
```

> ⚠️ **不要用 `python -m unittest discover` 跑骨架**：便携 Python 的
> `tools/python/python311._pth` 把 `sys.path` 固定成三行、不含当前目录，会报
> `No module named 'core'`。`scaffold/run_tests.py` 专门补了这个
> （`sys.path.insert(0, scaffold)` + `dont_write_bytecode`）。

---

## 1. 你能读什么（按上下文预算选）

| 你的预算 | 读这些 | 约多少字 |
|---|---|---|
| 紧（< 30k） | 本文件 + `tasks/tasks.json` + `scaffold/core/contracts.py` | 1.2 万 |
| 中（< 80k） | 上述 + `AGENTS.md` + `docs/code-index.md` + `docs/api-style.md` + `scaffold/README.md` + `scaffold/core/rules/l4.py` + `scaffold/core/rules/legacy_map.py` + `scaffold/core/egress/sanitize.py` | 6 万 |
| 宽 | 再加 `docs/plan-review.md`（完整评审与理由）+ `scaffold/` 全部 + `docs/api-reference.md` | 12 万 |

**不要**为了「了解全貌」去通读 `core/*.py`（4700 行）——`docs/code-index.md` 已把
每个要改的点定位到「文件:行」，直接跳过去看 30 行就够了。

---

## 2. 硬规则（违反任何一条都算失败）

1. **禁止整体覆盖**。⛔ 绝不能 `scaffold/core/*` → `core/*` 全量拷贝。
   必须按下面第 3 节的 COPY-MAP 逐文件来；标 ⛔ 的文件是**同名但语义不同**的。
2. **禁止动既有行为**：`start.bat` 里所有 `%ROOT%\...` 引用路径、
   `tests/test_launcher_contract.py`、`captures/faults_demo.pcap`、`.github/workflows/smoke.yml`
   的 job 名 `syntax-and-contract`（分支保护依赖它）。
3. **禁止在 `core/rules/**` 里写中文**。文案只能进 `core/copy/zh-CN.json`。
4. **禁止改动 `rows[]` 的文案**（第一、二阶段），UI 与 Markdown 报告都在消费它。
   新增内容走新字段（如 `findings_v2`），旧的保留。
5. **禁止把 `tools/`、`harness/`、`*.exe`、真实 `config/*.json`、抓包、日志加进 git**。
6. **禁止引入第三方依赖**（唯一例外：已内置的 scapy 2.8.0）。不装 pip 包、不加 node 构建链。
7. **禁止把真实 IP / Key / 内网域名写进任何文件**（含注释、测试期望值、文档示例）。
8. **一次只做一个任务**。做完跑该任务的 `acceptance`，绿了再下一个。
   `tasks.json` 里 `depends_on` 没满足的不许开工。
9. **不许自己发明枚举值或字段名**。机器码一律用 `scaffold/core/contracts.py` 里已有的。
10. **不许重写 `core/probe.py`（946 行）与 `core/passive.py`（483 行）**。只搬不改。
11. **不许手改 `docs/api-reference.md` / `docs/docstring-gaps.md`**：它们由
    `scripts/gen_api_doc.py` 从源码生成，手改下次就被覆盖。要改内容 → 改源码 docstring。
12. **每个公开函数必须有 `Args:` / `Returns:` / `Raises:`**（标准见 `docs/api-style.md`），
    结构化返回值要列键名。`scripts/gen_api_doc.py --check 0.95` 不通过不许合并。

---

## 3. COPY-MAP：骨架文件怎么搬进仓库

| 骨架文件 | 目标 | 动作 | 备注 |
|---|---|---|---|
| `scaffold/core/contracts.py` | `core/contracts.py` | ✅ 原样拷贝 | 之后它就是唯一契约 |
| `scaffold/core/errors.py` | `core/errors.py` | ✅ 原样拷贝 | |
| `scaffold/core/config.py` | `core/config.py` | ✅ 原样拷贝 | 路径依赖 `platform/paths.py` |
| `scaffold/core/platform/` | `core/platform/` | ✅ 整个目录 | 新增包 |
| `scaffold/core/copy/zh-CN.json` | `core/copy/zh-CN.json` | ✅ 原样拷贝 | 文案唯一来源 |
| `scaffold/core/rules/` | `core/rules/` | ✅ 整个目录 | 逐条把 `build_findings` 搬进来 |
| `scaffold/core/rules/legacy_map.py` | `core/rules/legacy_map.py` | ✅ 原样拷贝 | T03 直接用它产出 `findings_v2`；T05 搬完规则后删除 |
| `scaffold/core/extract/` | `core/extract/` | ✅ 整个目录 | 先把 `collect()` 拆成可回放的纯函数 |
| `scaffold/core/verdict/` | `core/verdict/` | ✅ 整个目录 | 旧 `core/verdict.py` 留薄壳 |
| `scaffold/core/egress/` | `core/egress/` | ✅ 整个目录 | |
| `scaffold/core/render/` | `core/render/` | ✅ 整个目录 | 旧 `core/report.py` 留薄壳 |
| `scaffold/core/api/` | `core/api/` | ✅ 整个目录 | 路由先别名兼容旧路径 |
| `scaffold/core/history.py` | `core/history.py` | ✅ 原样拷贝 | |
| `scaffold/core/pathprobe.py` | `core/pathprobe.py` | ✅ 原样拷贝 | 新能力（第 4 阶段再用） |
| `scaffold/core/probe.py` | — | ⛔ **不要覆盖** | 现有 `core/probe.py` 才是实现，骨架那份只是迁移占位 |
| `scaffold/core/passive.py` | — | ⛔ **不要覆盖** | 同上 |
| `scaffold/core/capture/tshark.py` | `core/capture/tshark.py` | ⚠️ 只取类骨架 | `run()` 已实现；`interfaces()`/`iter_fields()` 请把 `core/tshark.py` 的实现搬进来 |
| `scaffold/core/capture/live.py` | `core/capture/live.py` | ⚠️ 只取骨架 | 实现来自 `core/diagnose.py:capture_live()` |
| `scaffold/run_tests.py` | `tools/run_tests.py`（可选） | ⚠️ 按需 | 迁完测试后改成跑仓库 `tests/` |
| `scaffold/tests/` | `tests/` | ⚠️ 合并 | 与现有 `test_launcher_contract.py` 并存，不合并文件、只加新文件 |
| `scaffold/tests/fixtures/gen_pcap.py` | `tests/fixtures/gen_pcap.py` | ✅ 原样拷贝 | 生成 8 个 pcap 样本 + `expected.json`；**生成的 .pcap 不要提交** |
| `scaffold/tests/fixtures/__init__.py` | `tests/fixtures/__init__.py` | ✅ 原样拷贝 | 让测试能 `from tests.fixtures import gen_pcap` |
| `scaffold/tools/gen_api_doc.py` | **`scripts/gen_api_doc.py`** | ✅ 原样拷贝 | ⛔ **不要放 `tools/`** —— `tools/` 被 `.gitignore` 排除，放进去 CI 里根本不存在 |
| `docs/api-style.md` | `docs/api-style.md` | ✅ | 注释标准（小白可读的三层写法） |
| `docs/git-setup.md` | `docs/git-setup.md` | ✅ | 公司电脑的 git 接管手册（T17 全程照它做） |

**一句话**：`core/analyzer.py`、`core/verdict.py`、`core/report.py`、`core/server.py`、
`core/probe.py`、`core/passive.py`、`core/tshark.py`、`core/diagnose.py` 这些**运行中的文件一个都不许被覆盖**，
只能「新增文件 + 在原文件里加薄壳转调」。

---

## 4. 落地顺序（3 个 PR，每步可单独合并、可回滚）

| PR | 任务 | 目标 | 验收 |
|---|---|---|---|
| **PR 0**<br/>环境先行 | T17 T00 | git 接管 + 落地前提验证 | sha 本地=远端；Npcap/提权可用 |
| **PR 1**<br/>只加不改 | T01 T02 T03 **T16** | 契约落地，旧路径零变化；接口文档与注释补到 95% | 骨架 54 用例绿 + `diagnose.py` 输出**逐字一致** + `--check 0.95` 通过 |
| **PR 2**<br/>切规则引擎 | T04 T05 T06 T07 | 规则可测、样本不足不再报「正常」 | 新规则单测绿 + `faults_demo` 快照 diff 为空 |
| **PR 3**<br/>切出口与 API | T08 T09 T10 T11 T12 | 脱敏、job_id、报告不覆盖 | 脱敏双断言绿 + 旧 UI 不回退 |
| **PR 4**<br/>探测与基线 | T13 T14 T15 | 路径探测、历史基线、工程化 | 探针不污染诊断 + CI 三层绿 |

任务清单的机器可读版本：**`tasks/tasks.json`**（含每个任务的 `files`、`steps`、
`acceptance.command`、`expect`、`depends_on`）。人读版：`tasks/TASKS.md`。

---

## 5. 「完成」的标准

按顺序全部满足才算交付：

1. `tools\python\python.exe -m compileall -q core mcp tests` 无输出。
2. `python -m unittest discover -s tests -v` 全绿（含原 8 个契约用例 + 新增规则用例）。
3. `docs/rules.md` 里每条规则都能在 `core/rules/**` 找到同名 `rule_id`，反之亦然。
4. 同一份 pcap 连跑 3 次，`findings[].rule_id + severity` 完全一致（可复现）。
5. 1 KB 的空抓包不再报「各层正常」，而是 `VERDICT.INSUFFICIENT` / `VERDICT.EMPTY`。
6. AI 出口的 payload 用 `egress.sanitize` 处理后，`verify()` 查不到任何原始 IP / 口令，
   且脱敏前后 `findings` 的 `rule_id + severity` 不变（双断言）。
7. `/api/v1/jobs/{id}` 能拿到 `state`、增量日志、取消；旧 `/api/*` 仍可用。
8. `git status` 里不出现 `tools/`、`harness/`、`*.pcap`、`config/ai-config.json`。

---

## 6. 常见误解（防呆）

| ❌ 错误理解 | ✅ 正确理解 |
|---|---|
| 「骨架是重构后的代码，直接覆盖」 | 骨架里 `probe.py`/`passive.py`/`capture/*` 是**占位**，覆盖会丢 1400 行可用实现 |
| 「把中文枚举换成英文就得改 UI」 | UI 读的是 `rows[].severity` 等字段值；第一阶段**不动**这些值，只新增 `findings_v2` |
| 「脱敏放在 analyzer 后面就安全了」 | 脱敏放在 analyzer 后面会让规则看不到 IP，无法回答「哪个对端」。必须放**出口**（AI/日志/导出/MCP 各一次） |
| 「重传率高就是上行丢包」 | 抓包点在本机，客户端重传也可能只是 ACK 丢了。方向必须靠**对端 dup-ACK** 判定，结论要写「疑似」+ 置信度 |
| 「零窗口 = 服务端慢」 | 零窗口由**接收方**通告。客户端通告 = 客户端慢（VDI 常见） |
| 「UDP 丢包可以抓包算出来」 | UDP 无序号。只有 RTP/DNS/QUIC 等协议感知的序号，或**主动探测**才能算 |
| 「tracert 结果解析一下就行」 | 输出本地化 + 只有 3 次探测、无丢包率 + 企业网 ICMP 常被过滤。要用内置 scapy 做 TTL 递增探测 |
| 「测试可以断言输出包含『重传』」 | 改文案就红。断言 `rule_id`，不要断言中文 |
| 「pcap 样本提交到 tests/ 就行」 | `.gitignore` 的 `*.pcap` 会吞掉它，CI 里文件不存在、测试静默跳过。要么脚本生成，要么加 `!` 例外 |
| 「改完跑一下 `python core/diagnose.py`」 | 先 `cd` 到仓库根、用 `tools\python\python.exe`；系统 Python 可能没有 scapy/tshark 路径 |

---

## 7. 出问题时

| 现象 | 处置 |
|---|---|
| 骨架测试报 `No module named 'core'` | 用 `run_tests.py`，不要用 `-m unittest`（见第 0 节） |
| 骨架测试报 `Start directory is not importable` | `scaffold/tests/__init__.py` 丢了 |
| `tshark 未找到` | 确认 `tools\WiresharkPortable\App\Wireshark\tshark.exe`；或设 `TSHARK_PATH` |
| 抓包 0 报文 | 用 `--interfaces` 看序号，`--interface 6` 显式指定；确认 Npcap 已装且已提权 |
| 报告里 RTT 是 `-` | 本次没有 ACK 采样（纯 UDP/短连接），不是 bug；用「连通与速度测试」补测 |
| 「同一 pcap 两次结论不同」 | 这是**已知未解问题**（T00），先解决再谈 CI |

---

*本包由只读评审生成：未修改仓库任何既有文件。`docs/` 与 `scaffold/` 均为新增目录。*
