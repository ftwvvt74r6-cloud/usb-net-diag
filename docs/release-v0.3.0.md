# v0.3.0 发布记录（lite 源码包 · UI 2.0 / B 批次 / D+ / C 启动体验）

> 本文件记录 **2026-11-08 实际发布**的 v0.3.0 资产与构建证据；它**不随 zip 分发**
> （发布时该文件尚未创建；PR-B 起由 `scripts/build_release.py` 的 `PACKAGE_EXCLUDE`
> 显式排除，避免文档记录自己的哈希造成自指），只随仓库源码走。
> 构建/验包方法见 [`build.md`](build.md)，第三方许可边界见 [`licensing.md`](licensing.md)。
>
> v0.3.0 是正常功能发版，不涉及 v0.2.0 那种「撤下含第三方二进制的公开包」的法务重发；
> 公开附件仍然**只发 lite 代码包**。

## 0. 这份记录怎么来的

- 发布前 PR #29（`chore/release-v0.3.0`）只做发版准备：同步文档、明确「包大小 / SHA-256 发布后补充」
  占位，**不预写**任何实际哈希。
- tag 与 Release 创建后，本 PR-B（`docs/release-v0.3.0`）按 `gh api` / 真解压 / 干净 checkout 的实测值回写；
  不重新打包、不改 tag、不改 Release 资产。

## 1. Release

| 项 | 值 |
|---|---|
| Release | <https://github.com/ftwvvt74r6-cloud/usb-net-diag/releases/tag/v0.3.0> |
| 标题 | NetDiag · 网络矩阵 v0.3.0（lite 源码包） |
| Tag | `v0.3.0`（annotated tag object `9563dbc54f734eecd0f7001986cb4001e3a07c50`） |
| Tag 指向 | `e3f2c974a3fbaa8e6f02222ab6d794f15ece84a4`（`main` HEAD，PR #29 合并提交） |
| 发布时间 | **2026-11-08 18:29:49 +08:00**（UTC `2026-11-08T10:29:49Z`） |
| 发布件构建自 | `main` = `e3f2c97`（干净工作区） |
| Release notes | `CHANGELOG.md` 的 `## v0.3.0` 段 + 「Python / Wireshark / Npcap 需自行安装」说明 + 3 条真机验收提示 |

## 2. 资产（只有 lite + SHA256SUMS）

| 文件 | 大小 | SHA-256 |
|---|---|---|
| `NetDiag-0.3.0-lite.zip` | **974,570 B**（0.93 MiB / 0.97 MB） | `c3687b917a331328a2e8ad45fa2291e9ac4a2e4f18eee157f0912c61ecdfd905` |
| `SHA256SUMS.txt` | 89 B | — |

`SHA256SUMS.txt` 内容（LF，一行，`sha256sum` 兼容）：

```text
c3687b917a331328a2e8ad45fa2291e9ac4a2e4f18eee157f0912c61ecdfd905  NetDiag-0.3.0-lite.zip
```

> 公开附件里**没有** `npcap-*.exe`、**没有** Wireshark、**没有** `tools/`。
> 核对命令：`gh api repos/ftwvvt74r6-cloud/usb-net-diag/releases/tags/v0.3.0 --jq '.assets[] | [.name,.size,.digest] | @tsv'`。

## 3. 包内容（lite）

| 项 | 值 |
|---|---|
| 顶层目录 | `NetDiag/`（单目录，不散落） |
| 文件数 | **169**（zip 条目 207 = 169 文件 + 38 目录条目） |
| 解压后大小 | **2,590,174 B**（2.47 MiB / 2.59 MB） |
| zip 大小 | **974,570 B**（0.93 MiB / 0.97 MB） |
| `NetDiag/NetDiag.exe` | **32,256 B**；包内唯一 `.exe`，PE 头 `MZ`，manifest `asInvoker` |
| `tools/` | **不存在**（包根没有 `NetDiag/tools/`；`scaffold/tools/gen_api_doc.py` 只是 v0.1.0 迁移骨架的源码文件名，不是运行时） |
| Npcap 安装器 | **不存在**（文件名 `npcap` 0 命中） |
| Wireshark / tshark 二进制 | **不存在**（`.dll` 0 个；`tshark.exe` / `dumpcap.exe` 0 个；`mcp/wireshark-mcp/` 与 `core/tshark.py` 只是本仓库源码模块） |
| `reports/` | 只有 `faults_demo.md` / `faults_demo.json` |
| 禁入项 | `.git/`、`harness/`、`logs/` 文件、`config/ai-config.json`：**0 命中** |
| 发布记录 | `docs/release-v0.2.0.md` 不在包内；PR-B 起 `docs/release-v0.3.0.md` 也由 `PACKAGE_EXCLUDE` 排除 |
| `自检.bat` | 纯 ASCII + CRLF（构建脚本断言） |

> 文件数交叉核对：发布时 `git ls-files` 共 168 个受控文件；减去被排除的
> `docs/release-v0.2.0.md`（1 个），加上构建生成的 `README.txt` 与 `NetDiag.exe`（2 个），
> 恰为 **169**。

## 4. 构建自检（`build_release.py` 自动做，真解压真跑）

- 构建命令：`python scripts\build_release.py --out logs\dist\release-v030`（干净 `main` = `e3f2c97`）；
- 打包：**169 files** → `NetDiag-0.3.0-lite.zip`（**974,570 B**，SHA-256 `c3687b91…d905`）；
- 包内全套测试：**`Ran 620 tests ... OK (skipped=3)`**；
- 启动器契约：**`Ran 8 tests ... OK`**；
- 清单断言：`NetDiag.exe` 存在且 > 8 KB、`tools/` 不存在、`npcap-*.exe` 不存在、
  Wireshark/tshark 二进制不存在、`reports/` 只有两份示例、禁入项 0、`自检.bat` 纯 ASCII + CRLF；
- 最后一行 **`BUILD OK`**；
- 启动器大小：**32,256 B**（构建日志与 `NetDiag/NetDiag.exe` 实测一致）。

> `skipped=3` 是构建机自检解释器的结果；独立解压复跑（本机系统 Python，无 `scapy` / `tshark`）
> 为 `skipped=28`，620 条仍然全过。skipped 数随环境变化，构建脚本只断言 `Ran N` 且 `N ≥ 235`，
> 不把 skipped 写死（见 [`build.md`](build.md) §6）。

## 5. 独立解压验证（临时空目录，本 PR-B 人工复核）

| 检查 | 结果 |
|---|---|
| 解压到空目录 | `NetDiag/` 单目录，**169 文件 / 2,590,174 B** |
| `NetDiag.exe --dry-run --report <临时文件>` | **exit 0**；JSON：`ok:true`、`dry_run:true`、`started:false`、`browser_opened:false`；定位到系统 Python 3.12.10 |
| 系统 Python 全套测试 | **`Ran 620 tests ... OK (skipped=28)`**，rc=0（本机系统 Python 无 `scapy`，也未装 `tshark`，故 skip 多于构建自检） |
| 启动器契约 | **`Ran 8 tests ... OK`**，rc=0 |
| 无 `tools/` / Npcap | `NetDiag/tools` 不存在；`npcap*` 0；`.dll` 0；`tshark.exe` / `dumpcap.exe` 0 |
| `reports/` | 只有 `faults_demo.md` / `faults_demo.json` |

> 解压实测与 zip 清单一致：169 文件、2,590,174 B；zip 的 SHA-256 为
> `c3687b91…d905`，与 Release 资产一致。

## 6. 红线（相对 `main` = `bbc7ecd`，PR #28 C 合并后）

| 项 | 结果 |
|---|---|
| demo + 9 样本 `analyze()` + `verdict.build()` + `render_markdown()` | **20/20 逐字节相同**（`faults_demo` + 9 个确定性样本 × `.md` / `.json`） |
| 20 个产物总字节 | **216,207 B**（base 与 head 相同） |
| `reports/faults_demo.md` / `.json` | `git diff --exit-code` = 0；两份入库快照零改动 |
| 测试 | **620**（未减少） |
| 代码 / UI / 测试 / CI | `core/`、`ui/`、`launcher/`、`tests/`、`mcp/`、`.github/**`、`.gitignore` 零改动；`scripts/build_release.py` 只改 `PACKAGE_EXCLUDE` 常量 |
| `.github/**` / `.gitignore` / 依赖 / `scaffold/` | 零改动 |

> 红线口径与既有发版一致：对 `faults_demo` + `scaffold/tests/fixtures/gen_pcap.py` 生成的 9 个
> 确定性样本，各跑 `analyzer.analyze → verdict.build → report.render_markdown`，把运行时字段
> `generated_at` / `tshark_path` 归一为占位符后逐字节比较（原样 CLI 报告含当前时间，不能直接比较）。

## 7. 干净 checkout（无 `tools/`、无 `harness/`）

工作树：`git worktree add --detach <tmp> <branch HEAD>`；`python` = 系统 Python 3.12.10。

| 检查 | 结果 |
|---|---|
| `python -m compileall -q core mcp tests` | rc=0 |
| 全套 `unittest` | **`Ran 620 tests ... OK (skipped=27)`**，rc=0（干净口径） |
| `gen_api_doc.py --check 0.95` | 模块 **32** 个（有说明 32）｜公开符号 **292** 个（合格 292）｜**100.0%**，rc=0 |
| 重跑 `gen_api_doc.py` 后 `git diff --exit-code docs/api-reference.md docs/docstring-gaps.md` | rc=0（零 diff） |
| `git diff --check` | rc=0（无空白错误） |

## 8. 复现

```bat
git checkout e3f2c97
python scripts\build_release.py --out logs\dist\release-v030
```

- 已发布的 zip 不再重建；上面的命令只用于在 `e3f2c97` 上复现同一次构建流程。
- lite 自检用构建脚本所在解释器；带 `tools\python` 与系统 Python 的 skipped 数不同（见 §4）。

## 9. 许可边界

- 本 Release **只发 lite 源码包**：不含 Wireshark / Npcap / Python / `tools/`；
  用户需自行安装 Python 3.11+、Wireshark（tshark）、Npcap。
- Npcap 免费版**不允许对外再分发**；商业使用 / 再分发前请阅读
  [`licensing.md`](licensing.md) §2 与 Npcap 官方许可，必要时购买商业许可。
- 内部 `--with-tools` / `--with-npcap` 包不在本 Release；见 [`build.md`](build.md) §1 / §11。
