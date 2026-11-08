# v0.3.2 发布记录（lite 源码包 · F / G / H 批次）

> 本文件记录 **2026-11-09 实际发布**的 v0.3.2 资产与构建证据；它**不随 zip 分发**
> （发布时该文件尚未创建；本 PR 起由 `scripts/build_release.py` 的 `PACKAGE_EXCLUDE`
> 显式排除，避免文档记录自己的哈希造成自指），只随仓库源码走。
> 构建/验包方法见 [`build.md`](build.md)，第三方许可边界见 [`licensing.md`](licensing.md)。
>
> v0.3.2 是正常功能发版，公开附件仍然**只发 lite 代码包**；不含 Wireshark / Npcap / `tools/`。

## 0. 这份记录怎么来的

- tag 与 Release 创建于 2026-11-09；本 PR（`docs/release-v0.3.2`）只做**发版记录回写**：
  按 `gh api` / zipfile 实测 / 真解压 / 干净 checkout 的值写文档，**不重新打包、
  不改 tag、不改 Release 资产**。
- 发布前 PR #37（`chore/release-v0.3.2`）只做版本进位与文档同步；本 PR 不改产品代码、
  测试与报告，只回写文档 + `scripts/build_release.py::PACKAGE_EXCLUDE`（1 个常量项）。

### 0.1 本版内容摘要（F / G / H）

- **启动 splash（H3）**：`NetDiag.exe` 显示无边框 WinForms 等待窗，逐项检查
  Python / tshark(Wireshark) / Npcap / scapy / 端口 / 权限六项，用 ✓ / ⚠ / ✗ 标注并写
  「缺了会怎样」；缺项时可打开官网、按需请求 UAC、或继续使用降级功能；支持 ESC / 跳过，
  完成后 300ms 淡出；`pythonw` + 隐藏窗口，全程无黑色控制台。
- **单浏览器（H1）**：浏览器打开点收敛到 launcher 唯一一处；launcher 给子进程设
  `NETDIAG_NO_BROWSER=1`；并发双击由命名互斥锁串行化，第二个实例直接退出，已有实例时复用、
  只开一个浏览器、不新起 Python 进程。
- **统一面板 / 左栏（H4 / H5）**：运行进度、剩余时间、阶段、实时日志与结束结果收进同一个白底
  `#workpanel`；左侧一级菜单精简为 4 项，设置移到右上角齿轮，二级菜单默认收起，1024px 无水平溢出。
- **缺组件不阻塞（F）**：缺 tshark / Npcap / scapy / 端口 / 管理员权限不再弹原生错误框退出；
  首屏「准备检查」扩为六项并给可操作指引；能力置灰由后端 `capabilities` 决定，
  连通与速度测试始终可用；**`GET /api/preflight` 与 `/api/selfcheck` 同源**
  （同一份 `selfcheck.collect_cached()`），splash 与首屏不写第二套判断。
- **文本通用化（G1）**：去掉行业内部称谓（旧称只保留在 CHANGELOG 历史条目里并加注），
  统一为「使用者 / 协作方 / 相关方」；界面复制按钮改为「复制给协作方」；AI 提示词读者改为
  「普通使用者（懂电脑、不熟网络协议）」；模式示例、界面文案、`docs/*`、`README.md`、
  `AGENTS.md` 同步。
- **逐跳降级（G2）**：没有 scapy 时逐跳自动改用系统 `tracert -d -h 16 -w <毫秒>`
  （每跳 3 次探测，按「行首跳号 + 数字 / `*` + IPv4」结构解析，不依赖本地化关键词），
  报告标注「基于系统 tracert，样本数 3」；有 scapy 时仍走 scapy MTR；解析失败明确报错。
- **探针计数（G3）**：探针基线改为模块自记的「发出 / 收到 / 超时」三值
  （`timeout = sent - recv`），不再由调用方从抓包统计反推；N=0 时不打印
  「排除 0 个标记探针包」。
- **连接重置（G4）**：浏览器提前断开（`ConnectionResetError` / `ConnectionAbortedError` /
  `BrokenPipeError`）降级为一行 debug 日志并关闭连接，不再打印整段 traceback。
- **页面状态（G5）**：新增 `GET /api/last-run`、`GET /api/last-run/result`、
  `POST /api/last-run/clear`；页面加载与 `pageshow` 查询上次结果，有则显示提示条、
  无记录不误报；设置页显示后台空闲退出时间与「立即退出后台」。

## 1. Release

| 项 | 值 |
|---|---|
| Release | <https://github.com/ftwvvt74r6-cloud/usb-net-diag/releases/tag/v0.3.2> |
| 标题 | NetDiag · 网络矩阵 v0.3.2（lite 源码包） |
| Tag | `v0.3.2`（annotated tag object `06c449ddcb86c64a1f3b7ee57148bea8e8c735fc`） |
| Tag 指向 | `e0004c9dbefdd77d78950b778fdfea59ef5c7e99`（`main` HEAD，PR #37 合并提交） |
| 发布时间 | **2026-11-09 04:55:09 +08:00**（UTC `2026-11-08T20:55:09Z`） |
| 发布件构建自 | `main` = `e0004c9`（干净工作区） |
| Release notes | `CHANGELOG.md` 的 `## v0.3.2` 段 + lite 包说明 + 4 条真机验收提示 |

## 2. 资产（只有 lite + SHA256SUMS）

| 文件 | 大小 | SHA-256 |
|---|---|---|
| `NetDiag-0.3.2-lite.zip` | **1,199,811 B**（1.14 MiB / 1.20 MB） | `da0c69b8b05eb52517c0550040cb5feef7d19b2580a335ed17a60f8a898e2e0e` |
| `SHA256SUMS.txt` | 89 B | — |

`SHA256SUMS.txt` 内容（LF，一行，`sha256sum` 兼容）：

```text
da0c69b8b05eb52517c0550040cb5feef7d19b2580a335ed17a60f8a898e2e0e  NetDiag-0.3.2-lite.zip
```

> 公开附件里**没有** `npcap-*.exe`、**没有** Wireshark、**没有** `tools/`。
> 核对命令：`gh api repos/ftwvvt74r6-cloud/usb-net-diag/releases/tags/v0.3.2 --jq '.assets[] | [.name,.size,.digest] | @tsv'`。
> 本机复核：Release 资产实测 `1,199,811 B`、SHA-256 与资产 `digest` 一致；`SHA256SUMS.txt`
> 逐行校验通过。

## 3. 包内容（lite）

| 项 | 值 |
|---|---|
| 顶层目录 | `NetDiag/`（单目录，不散落） |
| 文件数 | **187 个文件**（zip 条目 225 = 187 文件 + 38 目录条目） |
| 解压后大小 | **3,301,772 B**（3.15 MiB / 3.30 MB；zipfile 逐文件 `file_size` 求和，空目录不计字节） |
| zip 大小 | **1,199,811 B**（1.14 MiB / 1.20 MB） |
| `NetDiag/NetDiag.exe` | **70,144 B**；包内唯一 `.exe`，PE 头 `MZ`，manifest `asInvoker` |
| `tools/` | **不存在**（`tools_count=0`；`scaffold/tools/gen_api_doc.py` 只是 v0.1.0 迁移骨架的源码文件名） |
| Npcap 安装器 | **不存在**（`npcap` 0 命中） |
| Wireshark / tshark 二进制 | **不存在**（`.dll` 0 个；`tshark.exe` / `dumpcap.exe` / `wireshark.exe` 0 个；`mcp/wireshark-mcp/` 与 `core/tshark.py` 只是本仓库源码模块） |
| `reports/` | 只有 `faults_demo.md` / `faults_demo.json` |
| 禁入项 | `.git/`、`harness/`、`logs/` 文件、`config/ai-config.json`：**0 命中** |
| 发布记录 | `docs/release-v0.2.0.md`、`docs/release-v0.3.0.md`、`docs/release-v0.3.1.md` 不在包内；本 PR 起 `docs/release-v0.3.2.md` 也由 `PACKAGE_EXCLUDE` 排除 |
| `自检.bat` | 9,873 B，纯 ASCII + CRLF（269 个 CRLF，构建脚本断言） |

> 文件数交叉核对（`git ls-tree -r e0004c9` vs zip 清单）：发布时受控文件 **188** 个；
> 减去被排除的 3 份发布记录（`docs/release-v0.2.0.md`、`docs/release-v0.3.0.md`、
> `docs/release-v0.3.1.md`），加上构建生成的 `README.txt` 与 `NetDiag.exe`（2 个），
> 恰为 **187**；额外文件只有这 2 个，缺失文件只有这 3 个。

## 4. 构建自检（`build_release.py` 自动做，真解压真跑）

- 构建命令：`python scripts\build_release.py --out logs\dist\release-v032`（干净 `main` = `e0004c9`）；
- 打包：**187 files** → `NetDiag-0.3.2-lite.zip`（**1,199,811 B**，SHA-256 `da0c69b8…2e0e`）；
- 包内全套测试：**`Ran 955 tests ... OK (skipped=3)`**；
- 启动器契约：**`Ran 10 tests ... OK`**；
- 清单断言：`NetDiag.exe` 存在且 > 8 KB、`tools/` 不存在、`npcap-*.exe` 不存在、
  Wireshark/tshark 二进制不存在、`reports/` 只有两份示例、禁入项 0、`自检.bat` 纯 ASCII + CRLF；
- 最后一行 **`BUILD OK`**；
- 启动器大小：**70,144 B**（构建日志与包内 `NetDiag/NetDiag.exe` 实测一致）。

> `skipped=3` 是构建机自检解释器（带 scapy / tshark 条件）的结果；独立解压复跑时，
> 系统 Python 为 `skipped=28`，与构建解释器等价的 `tools\python` + `TSHARK_PATH` 为
> `skipped=3`，955 条仍然全过。skipped 数随环境变化，构建脚本只断言 `Ran N`
> 且 `N ≥ MIN_TEST_COUNT`，不把 skipped 写死（见 [`build.md`](build.md) §6）。

## 5. 独立解压验证（从 Release 重新下载，临时空目录，本 PR 人工复核）

| 检查 | 结果 |
|---|---|
| 下载 | `gh release download v0.3.2`：zip **1,199,811 B**、`SHA256SUMS.txt` **89 B** |
| zip 哈希 | 本机 sha256 = `da0c69b8b05eb52517c0550040cb5feef7d19b2580a335ed17a60f8a898e2e0e`，与 Release 资产一致 |
| `SHA256SUMS.txt` | 逐行校验通过（文件名 + 哈希 + 大小匹配） |
| 解压到空目录 | `NetDiag/` 单目录，**187 文件 / 3,301,772 B** |
| `NetDiag.exe --dry-run --report <临时文件>` | **exit 0**；JSON：`ok:true`、`dry_run:true`、`started:false`、`browser_opened:false`；定位到系统 Python 3.12.10（`python_kind=system-python`） |
| 系统 Python 全套测试 | **`Ran 955 tests ... OK (skipped=28)`**，rc=0（68.467 秒；本机系统 Python 无 `scapy`、未装 `tshark`） |
| 构建解释器全套测试 | `tools\python` + `TSHARK_PATH`：**`Ran 955 tests ... OK (skipped=3)`**，rc=0（111.823 秒） |
| 启动器契约 | **`Ran 10 tests ... OK`**，rc=0（系统 Python 与构建解释器一致） |
| 无 `tools/` / Npcap | `NetDiag/tools` 不存在；`npcap*` 0；`.dll` 0；`tshark.exe` / `dumpcap.exe` 0 |
| `reports/` | 只有 `faults_demo.md` / `faults_demo.json`；与仓库入库快照 SHA-256 一致 |

> 解压实测与 zip 清单一致：187 文件、3,301,772 B；解压后目录与包内 `VERSION` 均为 `0.3.2`。
> 包内 `reports/faults_demo.md` / `.json` 的 SHA-256 分别为
> `870E7E38…399E5` / `F545E70F…EDE7C`，与仓库 `reports/` 当前快照一致。

## 6. 红线

### 6.1 相对 v0.3.1（`d4b13dc`）：E 例外口径不变，本轮只有版本元数据

v0.3.1 已经声明过 E 批次例外：报告 JSON `verdict` 新增
`confidence` / `basis` / `coverage` / `not_covered` 四键、`SCHEMA_VERSION` 2.1→2.2、
报告 Markdown 追加「结论与边界」块（见 [`release-v0.3.1.md`](release-v0.3.1.md) §6.1）。
**本版没有新增报告结构例外**；相对 v0.3.1 的本轮差异只有版本元数据：

| 产物 | 差异 | 是否声明例外 |
|---|---|---|
| 10 个 `.md` 报告产物 | **10/10 逐字节相同** | — |
| 10 个 `.json` 报告产物 | **10/10 仅 `analyze.provenance.app_version` 0.3.1→0.3.2**；把该键归一后逐字节相同 | 是（版本元数据） |
| 合计 | **20/20 通过** | — |
| 入库 `reports/faults_demo.{md,json}` | `git diff d4b13dc..e0004c9 -- reports/` **零改动**；三处 blob 相同 | — |

> 口径：`captures/faults_demo.pcap` + `scaffold/tests/fixtures/gen_pcap.py` 生成的 9 个确定性样本，
> 各跑 `analyze → verdict.build → render_markdown`；两侧使用同一份 `config/app-config.json`
> 与本机 TShark 4.7.4，运行时字段归一后比较。E 批次的 4 键 / schema / md 结论边界属于
> v0.3.1 已声明例外，本版继续沿用，不重复计入“本版新增”。

### 6.2 相对版本进位前 `main`（`ec374a0`）：20 个报告产物不变

| 项 | 结果 |
|---|---|
| 同 config 口径（两侧同一份 `app-config.json` + 本机 TShark 4.7.4） | **归一 `app_version` 后 20/20 逐字节相同**（10 `.md` + 10 `.json`） |
| 原始快照（`ec374a0` `VERSION=0.3.1` vs `e0004c9` `VERSION=0.3.2`） | 10/10 `.md` 逐字节相同；`.json` 仅 `provenance.app_version`（0.3.1→0.3.2），判定 / 渲染 0 差异 |
| 入库 `reports/faults_demo.{md,json}` | `git diff ec374a0..e0004c9 -- reports/` **零改动** |
| 测试 | **955**（v0.3.1 基线 722，未减少） |
| 代码 / UI / 测试 / CI / 依赖 / scaffold | 本 PR 零改动；`scripts/build_release.py` 只改 `PACKAGE_EXCLUDE` 常量 |

> `ec374a0..e0004c9` 的差异只有 F / G / H 功能与版本进位 + 文档（CHANGELOG、README、build、
> HANDOVER）；报告相关代码的改动只影响实时路径（tracert 文案、探针自记计数），
> 不回写离线报告，因此本红线成立。

### 6.3 复审遗留（不阻塞发版，已记录）

- **高 DPI splash 未真机验收**：本机 96 DPI，125% / 150% 只做了静态确认
  （manifest PerMonitorV2、`AutoScaleMode.Dpi`、字号 ≥ 9pt），未在真机缩放桌面实跑。
- **热启动下界无 warm 样本支撑**：Release notes 写「热启动约 1.9~2.1s」，但现有 warm 样本为
  **2.085~2.119s**（2,085 / 2,087 / 2,089 / 2,096 / 2,099 / 2,100 / 2,103 / 2,108 / 2,115 / 2,119 ms）；
  1.9s 下界没有对应 warm 样本（1,982 ms 是冷启动端口回退样本）。冷启动实测 2.08~2.31s。

## 7. 干净 checkout（无 `tools/`、无 `harness/`）

工作树：`git worktree add --detach <tmp> docs/release-v0.3.2`；`python` = 系统 Python 3.12.10。

| 检查 | 结果 |
|---|---|
| `python -m compileall -q core mcp tests` | rc=0 |
| 全套 `unittest` | **`Ran 955 tests ... OK (skipped=27)`**，rc=0（干净口径） |
| `gen_api_doc.py --check 0.95` | 模块 **33** 个（有说明 33）｜公开符号 **314** 个（合格 314）｜**100.0%**，rc=0 |
| 重跑 `gen_api_doc.py` 后 `git diff --exit-code docs/api-reference.md docs/docstring-gaps.md` | rc=0（零 diff） |
| `git diff --check` | rc=0（无空白错误） |

## 8. 复现

```bat
git checkout e0004c9
python scripts\build_release.py --out logs\dist\release-v032
```

- 已发布的 zip 不再重建；上面的命令只用于在 `e0004c9` 上复现同一次构建流程。
- lite 自检用构建脚本所在解释器；带 `tools\python` 与系统 Python 的 skipped 数不同（见 §4 / §5）。
- 回写本记录的 PR 只改文档 + `PACKAGE_EXCLUDE`，不触碰任何代码/测试/报告。

## 9. 许可边界

- 本 Release **只发 lite 源码包**：不含 Wireshark / Npcap / Python / `tools/`；
  用户需自行安装 Python 3.11+、Wireshark（tshark）、Npcap。
- Npcap 免费版**不允许对外再分发**；商业使用 / 再分发前请阅读
  [`licensing.md`](licensing.md) §2 与 Npcap 官方许可，必要时购买商业许可。
- 内部 `--with-tools` / `--with-npcap` 包不在本 Release；见 [`build.md`](build.md) §1 / §11。
