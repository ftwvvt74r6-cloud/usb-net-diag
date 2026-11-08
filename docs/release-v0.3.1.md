# v0.3.1 发布记录（lite 源码包 · 结论与边界 / E 批次）

> 本文件记录 **2026-11-08 实际发布**的 v0.3.1 资产与构建证据；它**不随 zip 分发**
> （发布时该文件尚未创建；本 PR 起由 `scripts/build_release.py` 的 `PACKAGE_EXCLUDE`
> 显式排除，避免文档记录自己的哈希造成自指），只随仓库源码走。
> 构建/验包方法见 [`build.md`](build.md)，第三方许可边界见 [`licensing.md`](licensing.md)。
>
> v0.3.1 是正常功能发版，公开附件仍然**只发 lite 代码包**；不含 Wireshark / Npcap / `tools/`。

## 0. 这份记录怎么来的

- tag 与 Release 创建于 2026-11-08；本 PR（`docs/release-v0.3.1`）只做**发版记录回写**：
  按 `gh api` / zipfile 实测 / 真解压 / 干净 checkout 的值写文档，**不重新打包、
  不改 tag、不改 Release 资产**。
- 发布前 PR #32（`chore/release-v0.3.1`）只做版本进位与文档同步；本 PR 不改产品代码、
  测试与报告，只回写文档 + `scripts/build_release.py::PACKAGE_EXCLUDE`（1 个常量项）。

## 1. Release

| 项 | 值 |
|---|---|
| Release | <https://github.com/ftwvvt74r6-cloud/usb-net-diag/releases/tag/v0.3.1> |
| 标题 | NetDiag · 网络矩阵 v0.3.1（lite 源码包） |
| Tag | `v0.3.1`（annotated tag object `b15f592cb6195c79c3e12f407c86d1e5489337fb`） |
| Tag 指向 | `d4b13dcd1220e149b4f9283ce2930875dab4cfd5`（`main` HEAD，PR #32 合并提交） |
| 发布时间 | **2026-11-08 20:33:48 +08:00**（UTC `2026-11-08T12:33:48Z`） |
| 发布件构建自 | `main` = `d4b13dc`（干净工作区） |
| Release notes | `CHANGELOG.md` 的 `## v0.3.1` 段 + 「Python / Wireshark / Npcap 需自行安装」说明 + 3 条真机验收提示 |

## 2. 资产（只有 lite + SHA256SUMS）

| 文件 | 大小 | SHA-256 |
|---|---|---|
| `NetDiag-0.3.1-lite.zip` | **1,031,112 B**（0.98 MiB / 1.03 MB） | `09fc93f463c82724a6a1a5ceabe85ea76b438e3549eee2e51303a7bc87ac8d53` |
| `SHA256SUMS.txt` | 89 B | — |

`SHA256SUMS.txt` 内容（LF，一行，`sha256sum` 兼容）：

```text
09fc93f463c82724a6a1a5ceabe85ea76b438e3549eee2e51303a7bc87ac8d53  NetDiag-0.3.1-lite.zip
```

> 公开附件里**没有** `npcap-*.exe`、**没有** Wireshark、**没有** `tools/`。
> 核对命令：`gh api repos/ftwvvt74r6-cloud/usb-net-diag/releases/tags/v0.3.1 --jq '.assets[] | [.name,.size,.digest] | @tsv'`。
> 本机复核：zip 实测 `1,031,112 B`、SHA-256 与资产 `digest` 一致；`SHA256SUMS.txt` 校验通过。

## 3. 包内容（lite）

| 项 | 值 |
|---|---|
| 顶层目录 | `NetDiag/`（单目录，不散落） |
| 文件数 | **174 个文件**（zip 条目 212 = 174 文件 + 38 目录条目） |
| 解压后大小 | **2,771,469 B**（2.64 MiB / 2.77 MB；zipfile 逐文件 `file_size` 求和，空目录不计字节） |
| zip 大小 | **1,031,112 B**（0.98 MiB / 1.03 MB） |
| `NetDiag/NetDiag.exe` | **32,256 B**；包内唯一 `.exe`，PE 头 `MZ`，manifest `asInvoker` |
| `tools/` | **不存在**（`tools_count=0`；`scaffold/tools/gen_api_doc.py` 只是 v0.1.0 迁移骨架的源码文件名） |
| Npcap 安装器 | **不存在**（`npcap` 0 命中） |
| Wireshark / tshark 二进制 | **不存在**（`.dll` 0 个；`tshark.exe` / `dumpcap.exe` / `wireshark.exe` 0 个；`mcp/wireshark-mcp/` 与 `core/tshark.py` 只是本仓库源码模块） |
| `reports/` | 只有 `faults_demo.md` / `faults_demo.json` |
| 禁入项 | `.git/`、`harness/`、`logs/` 文件、`config/ai-config.json`：**0 命中** |
| 发布记录 | `docs/release-v0.2.0.md`、`docs/release-v0.3.0.md` 不在包内；本 PR 起 `docs/release-v0.3.1.md` 也由 `PACKAGE_EXCLUDE` 排除 |
| `自检.bat` | 9,873 B，纯 ASCII + CRLF（269 个 CRLF，构建脚本断言） |

> 文件数交叉核对（`git ls-tree -r d4b13dc` vs zip 清单）：发布时受控文件 **174** 个；
> 减去被排除的 `docs/release-v0.2.0.md`、`docs/release-v0.3.0.md`（2 个），加上构建生成的
> `README.txt` 与 `NetDiag.exe`（2 个），恰为 **174**；额外文件只有这 2 个，缺失文件只有这 2 个。

## 4. 构建自检（`build_release.py` 自动做，真解压真跑）

- 构建命令：`python scripts\build_release.py --out logs\dist\release-v031`（干净 `main` = `d4b13dc`）；
- 打包：**174 files** → `NetDiag-0.3.1-lite.zip`（**1,031,112 B**，SHA-256 `09fc93f4…8d53`）；
- 包内全套测试：**`Ran 722 tests ... OK (skipped=3)`**；
- 启动器契约：**`Ran 8 tests ... OK`**；
- 清单断言：`NetDiag.exe` 存在且 > 8 KB、`tools/` 不存在、`npcap-*.exe` 不存在、
  Wireshark/tshark 二进制不存在、`reports/` 只有两份示例、禁入项 0、`自检.bat` 纯 ASCII + CRLF；
- 最后一行 **`BUILD OK`**；
- 启动器大小：**32,256 B**（构建日志与包内 `NetDiag/NetDiag.exe` 实测一致）。

> `skipped=3` 是构建机自检解释器的结果；独立解压复跑（本机系统 Python 3.12.10，
> 无 `scapy` / 无 tshark）为 `skipped=28`，722 条仍然全过。skipped 数随环境变化，
> 构建脚本只断言 `Ran N` 且 `N ≥ MIN_TEST_COUNT`，不把 skipped 写死（见 [`build.md`](build.md) §6）。

## 5. 独立解压验证（临时空目录，本 PR 人工复核）

| 检查 | 结果 |
|---|---|
| 解压到空目录 | `NetDiag/` 单目录，**174 文件 / 2,771,469 B** |
| zip 哈希 | 本机 sha256 = `09fc93f463c82724a6a1a5ceabe85ea76b438e3549eee2e51303a7bc87ac8d53`，与 Release 资产一致 |
| `SHA256SUMS.txt` | 逐行校验通过（文件名 + 哈希匹配） |
| `NetDiag.exe --dry-run --report <临时文件>` | **exit 0**；JSON：`ok:true`、`dry_run:true`、`started:false`、`browser_opened:false`；定位到系统 Python 3.12.10（`python_kind=system-python`） |
| 系统 Python 全套测试 | **`Ran 722 tests ... OK (skipped=28)`**，rc=0（27.744 秒；本机系统 Python 无 `scapy`、未装 `tshark`） |
| 启动器契约 | **`Ran 8 tests ... OK`**，rc=0 |
| 无 `tools/` / Npcap | `NetDiag/tools` 不存在；`npcap*` 0；`.dll` 0；`tshark.exe` / `dumpcap.exe` 0 |
| `reports/` | 只有 `faults_demo.md` / `faults_demo.json` |

> 解压实测与 zip 清单一致：174 文件、2,771,469 B；解压后目录与包内 `VERSION` 均为 `0.3.1`。

## 6. 红线

### 6.1 相对 v0.3.0（`e3f2c97`）：只有 E 批次声明例外

`reports/faults_demo.{md,json}` 已随 E 批次重生成（`main` 上入库快照就是 E 之后的版本）。
把 v0.3.0 发布 commit `e3f2c97` 与 `d4b13dc` 的入库报告直接比较：

| 产物 | 差异 | 是否声明例外 |
|---|---|---|
| `reports/faults_demo.md` | **+52 行 / −0 行 / 0 个替换块**；两处插入均为「结论与边界」块（第一节标题后、取证请求单前），原有行逐字节不动 | 是（v0.3.1 E1 声明例外） |
| `reports/faults_demo.json` | 解析后结构差异**只有 4 个新增键**：`verdict.confidence` / `verdict.basis` / `verdict.coverage` / `verdict.not_covered`；无删除、无改值 | 是（v0.3.1 E1 声明例外） |
| 契约 `SCHEMA_VERSION` | `core/contracts.py` **2.1 → 2.2**；`tests/fixtures/faults_features.json` 同步 2.2 | 是（契约升级） |

> 说明：报告 JSON 文件本身不带 `schema_version` 字段（它在运行期 `analyze.provenance`
> 与 API envelope 里）；因此 schema 2.1→2.2 用契约源码与 fixture 证明，报告载荷差异
> 用上面 4 键证明。两条合起来即 E 批次声明的全部报告例外。

### 6.2 相对 E 合并后 `main`（`272ab0d`）：20 个报告产物不变

口径与既有发版一致：`captures/faults_demo.pcap` + `scaffold/tests/fixtures/gen_pcap.py`
生成的 9 个确定性样本，各跑 `analyze → verdict.build → render_markdown`，
运行时字段归一后比较（10 个 `.md` + 10 个 `.json`，共 **237,264 B**）。

| 项 | 结果 |
|---|---|
| 同版本标签 + 同本机 config 口径（`272ab0d` 的 `VERSION` 取 0.3.1 后重渲染） | **20/20 逐字节相同** |
| 原始 `272ab0d` 快照（`VERSION=0.3.0`、worktree 无本机 `config/app-config.json`） | 10/10 `.md` 逐字节相同；`.json` 仅 `provenance.app_version`（0.3.0→0.3.1）与 `provenance.config_sha256`（环境差异）两处，**判定/渲染 0 差异** |
| 入库 `reports/faults_demo.{md,json}` | `git diff 272ab0d..d4b13dc -- reports/` **零改动** |
| 测试 | **722**（v0.3.0 基线 620，未减少） |
| 代码 / UI / 测试 / CI / 依赖 / scaffold | 本 PR 零改动；`scripts/build_release.py` 只改 `PACKAGE_EXCLUDE` 常量 |

> `272ab0d..d4b13dc` 的仓库差异只有 `VERSION` / `core/__init__.py` 版本号 + 文档
> （CHANGELOG、README、build、HANDOVER），没有判定代码变化，因此本红线成立。

## 7. 干净 checkout（无 `tools/`、无 `harness/`）

工作树：`git worktree add --detach <tmp> docs/release-v0.3.1`；`python` = 系统 Python 3.12.10。

| 检查 | 结果 |
|---|---|
| `python -m compileall -q core mcp tests` | rc=0 |
| 全套 `unittest` | **`Ran 722 tests ... OK (skipped=27)`**，rc=0（干净口径） |
| `gen_api_doc.py --check 0.95` | 模块 **33** 个（有说明 33）｜公开符号 **302** 个（合格 302）｜**100.0%**，rc=0 |
| 重跑 `gen_api_doc.py` 后 `git diff --exit-code docs/api-reference.md docs/docstring-gaps.md` | rc=0（零 diff） |
| `git diff --check` | rc=0（无空白错误） |

## 8. 复现

```bat
git checkout d4b13dc
python scripts\build_release.py --out logs\dist\release-v031
```

- 已发布的 zip 不再重建；上面的命令只用于在 `d4b13dc` 上复现同一次构建流程。
- lite 自检用构建脚本所在解释器；带 `tools\python` 与系统 Python 的 skipped 数不同（见 §4）。
- 回写本记录的 PR 只改文档 + `PACKAGE_EXCLUDE`，不触碰任何代码/测试/报告。

## 9. 许可边界

- 本 Release **只发 lite 源码包**：不含 Wireshark / Npcap / Python / `tools/`；
  用户需自行安装 Python 3.11+、Wireshark（tshark）、Npcap。
- Npcap 免费版**不允许对外再分发**；商业使用 / 再分发前请阅读
  [`licensing.md`](licensing.md) §2 与 Npcap 官方许可，必要时购买商业许可。
- 内部 `--with-tools` / `--with-npcap` 包不在本 Release；见 [`build.md`](build.md) §1 / §11。
