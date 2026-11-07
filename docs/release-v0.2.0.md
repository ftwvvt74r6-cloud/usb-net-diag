# v0.2.0 发布记录（便携包）

> 本文件记录 **2026-11-07 实际发布**的资产与构建证据；它**不打进 zip**
> （避免文档记录自己的哈希造成自指），只随仓库源码走。
> 构建/验包方法见 [`build.md`](build.md)，第三方许可见 [`licensing.md`](licensing.md)。

## 1. Release

| 项 | 值 |
|---|---|
| Release | <https://github.com/ftwvvt74r6-cloud/usb-net-diag/releases/tag/v0.2.0> |
| 标题 | NetDiag · 网络矩阵 v0.2.0（Windows 便携包） |
| Tag | `v0.2.0` |
| Tag 指向 | `601561426ffd8a4d569ec8b9e6242e1052df0ed5`（发布时 `main` HEAD） |
| 发布件构建自 | 分支 `chore/release-packaging` 的提交 `174f652`（只含打包工程，产品代码与 `main` 相同） |
| Release notes | `CHANGELOG.md` 的 `## v0.2.0` 段（原样） |

## 2. 资产

| 文件 | 大小 | SHA-256 |
|---|---|---|
| `NetDiag-0.2.0-portable.zip` | **148,800,797 B**（141.9 MiB / 148.8 MB） | `7bd803abc998f1bfe92d9e9f028c9454a5219f7bbb43fa957413a5a4cbf39353` |
| `SHA256SUMS.txt` | 93 B | `90164fe9ba21b962773b4940560c8759e2e9803225e189021fa51caacac87dae` |

## 3. 包内容

| 项 | 值 |
|---|---|
| 顶层目录 | `NetDiag/`（单目录，不散落） |
| 解压后文件数 | **2057** |
| 解压后大小 | **381,762,414 B**（364.1 MiB / 381.8 MB） |
| `tools/` | **1915 文件 / 380,103,275 B**（362.5 MiB；Wireshark 未裁剪，只去掉 `__pycache__`/`*.pyc`） |
| `reports/` | 只有 `faults_demo.md` / `faults_demo.json` |
| 禁入项 | `.git/`、`harness/`、`logs/` 文件、`config/ai-config.json`：**0 命中** |
| Npcap 安装包 | `tools/npcap-1.79.exe`（再分发风险见 `licensing.md` §2） |

## 4. 构建自检（脚本自动做，真解压真跑）

```
[1/7] git archive HEAD (174f652) -> controlled files only
      141 controlled files
[2/7] copy tools/ as-is (no trimming) ...
      tools/: 1915 files, 380,103,275 B (362.5 MiB / 380.1 MB)
[4/7] build zip ...
      2057 files -> NetDiag-0.2.0-portable.zip (148,800,797 B ...)
[5/7] write SHA256SUMS.txt ...
      7bd803abc998f1bfe92d9e9f028c9454a5219f7bbb43fa957413a5a4cbf39353  NetDiag-0.2.0-portable.zip
[6/7] extract to a temp dir and run the packaged python ...
      package files=2057 tools=1915 reports=['faults_demo.json', 'faults_demo.md'] npcap=npcap-1.79.exe
  [verify] 235 tests OK (OK (skipped=2))
  [verify] 8 launcher-contract tests OK (OK)
...
BUILD OK
```

## 5. 独立解压验证（空目录，人工复核）

| 检查 | 结果 |
|---|---|
| 解压到空目录 | `NetDiag/` 单目录，2057 文件 / 381,762,414 B |
| 包内 Python 全套测试 | `Ran 235 tests ... OK (skipped=2)`，rc=0 |
| 包内 `自检.bat --no-pause` | `PASS: 4  WARN: 2  FAIL: 0` → `RESULT: USABLE`，rc=0（本机未装 Npcap/未提权，故 2 个 WARN；离线分析 PASS，demo 判定 `critical=3 warning=5`） |
| 自检后 `reports/` | 仍只有两份示例（自检报告写 `%TEMP%`） |

## 6. 红线（相对发布前 `main` = `6015614`）

| 项 | 结果 |
|---|---|
| demo + 9 样本 `analyze()+verdict.build()+render_markdown()` | **20/20 逐字节相同**（20 个文件、总字节数一致） |
| `reports/` | `git status` / `git diff` 均为空；`faults_demo.{md,json}` 与基线 sha256 一致 |
| 测试 | 235（未减少） |

> 说明：快照里的 `provenance.config_sha256` 会受本机 `config/app-config.json` 影响。
> 基线 worktree 原本没有这份被忽略的本地配置，比较前把**同一份** `app-config.json`
> 复制到基线侧，让两侧输入一致；这是运行元数据，不是产品代码差异。

## 7. 干净 checkout（无 `tools/`、无 `harness/`）

| 检查 | 结果 |
|---|---|
| `compileall -q core mcp tests` | rc=0 |
| 全套 `unittest` | `Ran 235 tests ... OK (skipped=19)`，rc=0 |
| `gen_api_doc.py --check 0.95` | 模块 29 个 / 公开符号 204 个（合格 204），**100.0%**，rc=0 |
| `gen_api_doc.py` 后 `git diff --exit-code docs/api-reference.md docs/docstring-gaps.md` | rc=0（无 diff） |

## 8. 复现

```bat
git checkout 174f652
tools\python\python.exe scripts\build_release.py
```

因为 zip 里含 `tools/`，包内测试是 `OK (skipped=2)`；没有 `tools/` 的干净 checkout
才是 `OK (skipped=19)`。两者都正常，原因见 `build.md` §5。
