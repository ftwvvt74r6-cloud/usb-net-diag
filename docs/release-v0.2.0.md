# v0.2.0 发布记录（lite 源码包 · 法务修正回合）

> 本文件记录 **2026-11-07 法务修正后实际发布**的资产与构建证据；它**不打进 zip**
> （`scripts/build_release.py` 显式排除，避免文档记录自己的哈希造成自指），只随仓库源码走。
> 构建/验包方法见 [`build.md`](build.md)，第三方许可边界见 [`licensing.md`](licensing.md)。

## 0. 为什么重发

- 2026-11-07 首次发布的 `NetDiag-0.2.0-portable.zip` **公开附带**了 `tools/npcap-1.79.exe`
  与 Wireshark 二进制。仓库是 PUBLIC，Npcap 免费版不允许对外再分发，Wireshark 公开分发
  还要承担 GPL 源码提供义务。
- 处置：`gh release delete v0.2.0 --cleanup-tag` 撤下旧 Release 和 tag；改为
  **公开只发 lite 代码包**，第三方二进制只进内部离线包。
- 证据与命令见 `review/chore-release-packaging-WRITER.md` 的「法务修正回合」。

## 1. Release

| 项 | 值 |
|---|---|
| Release | <https://github.com/ftwvvt74r6-cloud/usb-net-diag/releases/tag/v0.2.0> |
| 标题 | NetDiag · 网络矩阵 v0.2.0（lite 源码包） |
| Tag | `v0.2.0` |
| Tag 指向 | `601561426ffd8a4d569ec8b9e6242e1052df0ed5`（`main` HEAD） |
| 发布件构建自 | 分支 `chore/release-packaging` 的提交 `（构建后回填）`（产品代码与 `main` 相同） |
| Release notes | `CHANGELOG.md` 的 `## v0.2.0` 段 + 「Python / Wireshark / Npcap 需自行安装」说明 |

## 2. 资产（只有 lite + SHA256SUMS）

| 文件 | 大小 | SHA-256 |
|---|---|---|
| `NetDiag-0.2.0-lite.zip` | （构建后回填） | （构建后回填） |
| `SHA256SUMS.txt` | （构建后回填） | — |

> 公开附件里**没有** `npcap-*.exe`、**没有** `Wireshark`、**没有** `tools/`。
> 核对命令：`gh release view v0.2.0` +
> `gh api repos/ftwvvt74r6-cloud/usb-net-diag/releases/tags/v0.2.0 --jq '.assets[].name'`。

## 3. 包内容（lite）

| 项 | 值 |
|---|---|
| 顶层目录 | `NetDiag/`（单目录，不散落） |
| 文件数 | 约 **142** |
| 解压后大小 | 约 **1.5 MB** |
| `tools/` | **不存在**（构建脚本断言） |
| Npcap 安装器 | **不存在**（构建脚本断言） |
| `reports/` | 只有 `faults_demo.md` / `faults_demo.json` |
| 禁入项 | `.git/`、`harness/`、`logs/` 文件、`config/ai-config.json`：**0 命中** |

## 4. 构建自检（脚本自动做，真解压真跑）

- 自检 Python：**系统 Python**（lite 包不含运行时）；
- 全套测试：`Ran 235 tests ... OK (skipped=19)`；
- 启动器契约：`Ran 8 tests ... OK`；
- 清单断言：无 `tools/`、无 `npcap-*.exe`、禁入项 0、`reports/` 只有两份示例、
  `自检.bat` 纯 ASCII + CRLF；
- 最后一行 `BUILD OK`。

## 5. 独立解压验证（空目录，人工复核）

| 检查 | 结果 |
|---|---|
| 解压到空目录 | `NetDiag/` 单目录，约 142 文件 / 约 1.5 MB |
| `自检.bat --no-pause` | `PASS: 2  WARN: 5  FAIL: 0` → `RESULT: USABLE`，rc=0（本机无 tshark / Npcap / 未提权，故 5 个 WARN；Python 与源码导入 PASS） |
| 系统 Python 全套测试 | `Ran 235 tests ... OK (skipped=19)`，rc=0 |

## 6. 红线（相对 `main` = `6015614`）

| 项 | 结果 |
|---|---|
| demo + 9 样本 `analyze()+verdict.build()+render_markdown()` | **20/20 逐字节相同** |
| `reports/` | `git status` / `git diff` 均为空；两份示例 sha256 不变 |
| 测试 | 235（未减少） |
| `.github/**` / `.gitignore` / `core/**` / `ui/**` | 零改动 |

## 7. 干净 checkout（无 `tools/`、无 `harness/`）

| 检查 | 结果 |
|---|---|
| `compileall -q core mcp tests` | rc=0 |
| 全套 `unittest` | `Ran 235 tests ... OK (skipped=19)`，rc=0 |
| `gen_api_doc.py --check 0.95` | 模块 29 个 / 公开符号 204 个（合格 204），**100.0%**，rc=0 |
| `gen_api_doc.py` 后 `git diff --exit-code docs/api-reference.md docs/docstring-gaps.md` | rc=0（无 diff） |

## 8. 复现

```bat
git checkout <发布构建提交>
python scripts\build_release.py --out logs\dist\release
```

lite 包用系统 Python 自检（`skipped=19`）；内部包用包内 Python（`skipped=2`）。
原因见 [`build.md`](build.md) §6。
