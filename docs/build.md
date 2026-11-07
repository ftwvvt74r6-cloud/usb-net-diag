# 构建与发布（三种包：lite / 内部离线 / 内部离线+Npcap）

> 面向维护者。**公开件只发代码，内部件才带 tools** —— 这是 2026-11-07 法务修正后的硬边界。
> 许可依据见 [`licensing.md`](licensing.md) §0 / §2。
>
> 一条命令出包，脚本自己解压、用**包内或系统 Python** 真跑一遍测试，通过才说 `BUILD OK`。

---

## 1. 三种包一览

| 模式 | 命令（仓库根目录） | 产物 | zip 体积 | 解压后 | 包内第三方二进制 | 能发给谁 |
|---|---|---|---|---|---|---|
| **lite（默认）** | `python scripts\build_release.py` | `NetDiag-0.2.0-lite.zip` | 约 **0.7 MB** | 约 **1.7 MB** | **无** | **公开 Release / 任何人** |
| **内部离线** | `python scripts\build_release.py --with-tools` | `NetDiag-0.2.0-internal.zip` | 约 **147 MB** | 约 **363 MiB** | 便携 Python + Wireshark（**无 Npcap**） | 本组织内部，**不外传** |
| **内部离线 + Npcap** | `python scripts\build_release.py --with-npcap` | `NetDiag-0.2.0-internal-npcap.zip` | 约 **149 MB** | 约 **364 MiB** | 便携 Python + Wireshark + `npcap-1.79.exe` | **仅组织内部同事**，禁止公开 |

> 精确体积 / 条目数 / 是否含 Npcap 的实测见 §9。
> `--with-npcap` 隐含 `--with-tools`；构建时会在开始和结束各打印一次醒目警告。

---

## 2. 前置条件

| 项 | lite 构建 | `--with-tools` / `--with-npcap` 构建 |
|---|---|---|
| 系统 | Windows 10/11 | Windows 10/11 |
| Git | 能在仓库根目录执行 `git archive` | 同左 |
| Python | 系统 Python 3.9+（跑脚本）；**包内不带** | 系统 Python 3.9+ 或 `tools\python\python.exe` |
| `tools\` | **不需要** | **本机必须已有**（约 362.5 MiB，被 `.gitignore` 排除） |
| 磁盘 | ≥ 50 MB | ≥ 1.2 GB（暂存 + zip + 解压自检） |
| 工作区 | 已跟踪文件必须干净（`--allow-dirty` 仅本地调试） | 同左 |

`tools\` 的标准构成（仅内部包会复制）：

```
tools\
├── python\                                   # 便携 Python 3.11.9（含 Scapy 2.8.0）
├── WiresharkPortable\App\Wireshark\          # Wireshark 4.7.4，含 tshark.exe / dumpcap.exe
└── npcap-1.79.exe                            # Npcap 离线安装包（只在 --with-npcap 时进包）
```

---

## 3. 构建命令

```bat
REM 1) 公开 lite 包（默认，发布用）
python scripts\build_release.py

REM 2) 内部离线包（带便携 Python + Wireshark，不带 Npcap）
python scripts\build_release.py --with-tools

REM 3) 内部离线包（带 Npcap，仅内部分发）
python scripts\build_release.py --with-npcap
```

成功时最后一行是 **`BUILD OK`**，产物在 `logs\dist\`：

```
logs\dist\NetDiag-0.2.0-lite.zip
logs\dist\NetDiag-0.2.0-internal.zip
logs\dist\NetDiag-0.2.0-internal-npcap.zip
logs\dist\SHA256SUMS.txt          # 每次构建只记录本次产物，后构建会覆盖
```

> 为什么放 `logs\dist\`：`.gitignore` 里有 `/logs/*`，产物天然不入库；
> `dist\` 没有对应忽略规则，容易误提交。三种包可以指定不同 `--out` 避免互相覆盖：

```bat
python scripts\build_release.py --out logs\dist\release
python scripts\build_release.py --with-tools --out logs\dist\internal
python scripts\build_release.py --with-npcap --out logs\dist\internal-npcap
```

常用参数：

| 参数 | 作用 |
|---|---|
| `--out DIR` | 换产物目录（默认 `logs\dist`） |
| `--with-tools` | 内部离线包：复制 `tools\`，但**排除 `npcap-*.exe`** |
| `--with-npcap` | 内部离线包：复制 `tools\` 且**带上 `npcap-*.exe`**（禁止公开） |
| `--skip-verify` | 只出包，跳过解压自检（**发布前不要用**） |
| `--allow-dirty` | 允许已跟踪文件有未提交改动（只用于本地试跑） |
| `--keep` | 保留解压后的自检目录，便于人工复核 |

---

## 4. 脚本做了什么（7 步）

1. `git archive HEAD` → 暂存目录 `NetDiag\`：只含 **141 个受控文件**（约 1.5 MB，以 `git ls-files` 为准）。
   `.git`、`harness/`、`logs/`、`config/ai-config.json`、`reports/` 里非示例文件天然不在里面；
   `docs/release-v0.2.0.md`（发布记录，记录的是 zip 自己的哈希）被显式排除，避免自指。
2. **按模式处理 `tools\`**：
   - lite：**跳过**，包里没有任何第三方二进制；
   - `--with-tools`：原样复制，只跳过 `__pycache__` / `*.pyc`，并**排除 `npcap-*.exe`**；
   - `--with-npcap`：原样复制，**包含** `npcap-1.79.exe`，并打印醒目警告。
3. 生成包内 `README.txt`（按模式写清「要装什么 / 不要传什么」）；`自检.bat` 来自 git。
4. 打 `NetDiag-<VERSION>-<mode>.zip`（`ZIP_DEFLATED`，level 6，含目录条目，空目录 `logs\` 保留）。
5. 写 `SHA256SUMS.txt`（`sha256sum` 兼容：`<hash>  <文件名>`，LF 换行）。
6. **解压到临时目录**并做构建自检：
   - lite：用**系统 Python**；`--with-tools` / `--with-npcap`：用**包内便携 Python**；
   - 全套 `unittest`（235 条，见 §6 的 skipped 说明）；
   - 启动器契约（`test_launcher_contract.py`，8 tests）；
   - 清单断言（按模式）：禁入项为零、`reports/` 只有两份示例、必要入口齐全、
     `自检.bat` 纯 ASCII + CRLF；
   - **lite** 断言**没有** `tools/`、**没有** `npcap-*.exe`；
   - **`--with-tools`** 断言有 `tools/`、**没有** `npcap-*.exe`；
   - **`--with-npcap`** 断言有 `tools/`、**有** `npcap-*.exe`。
7. 打印 zip 路径 / 大小 / SHA-256 / 测试行，最后输出 `BUILD OK`；任一步失败退出码非 0。

---

## 5. 包内结构（顶层都是 `NetDiag\`）

### 5.1 lite（公开）

```
NetDiag\
├── 自检.bat / README.txt          # README.txt 构建时生成
├── start.bat / NetDiag.vbs / 导出诊断包.bat
├── VERSION / CHANGELOG.md / README.md / AGENTS.md
├── core\ ui\ mcp\ skills\ docs\ tests\ scaffold\ tasks\
├── config\*.example.json         # 只有示例；ai-config.json 绝不入包
├── captures\faults_demo.pcap
├── reports\faults_demo.{md,json} # 只保留这两份示例
└── logs\                          # 空目录（首次运行写入）
```

**没有 `tools\`**。lite 用系统 Python 启动：

```bat
python core\server.py
```

（`start.bat` / `NetDiag.vbs` 依赖 `tools\python`，只适用于内部离线包；
lite 用户请直接用 `python core\server.py`，或按 `docs\START-HERE.md` 的源码方式运行。）

### 5.2 `--with-tools` / `--with-npcap`（内部）

在 lite 结构基础上多一个 `tools\`：

```
tools\python\                               # 便携 Python 3.11.9
tools\WiresharkPortable\App\Wireshark\      # Wireshark 4.7.4（GPL，保留 COPYING.txt）
tools\npcap-1.79.exe                        # 仅 --with-npcap 有
```

`start.bat` / `NetDiag.vbs` 在内部包里可直接双击。

**绝不入包**（三种模式都断言）：`.git/`、`harness/`、`logs/` 里的文件、
`config/ai-config.json`、`reports/` 里除两份示例外的任何文件、`__pycache__/`、
`docs/release-v0.2.0.md`（发布记录不进包）。

---

## 6. 构建自检的通过标准

| 检查 | lite | `--with-tools` / `--with-npcap` |
|---|---|---|
| 自检 Python | **系统 Python**（构建脚本的解释器） | **包内** `tools\python\python.exe` |
| 全套测试 | `Ran 235 tests ... OK (skipped=19)` | `Ran 235 tests ... OK (skipped=2)` |
| 启动器契约 | `Ran 8 tests ... OK` | `Ran 8 tests ... OK` |
| `tools/` 断言 | 不存在 | 存在，≥1900 文件 / ≥350 MiB |
| Npcap 安装器 | 不存在 | `--with-tools`：不存在；`--with-npcap`：存在 |
| 包内 `自检.bat` | 纯 ASCII（0 个 >0x7F 字节）+ CRLF | 同左 |

> **skipped 为什么有两个数**：带 `tools/` 的包有 tshark + scapy，只跳过
> 「需要管理员 + Npcap 的真实抓包」和「需要本机 openssl 的 TLS 自检」= **2**；
> lite 没有 tshark / scapy，会多跳过 17 项 = **19**。两者都正常。
> 脚本只断言 `Ran N tests`（N ≥ 235）且结果为 `OK`，不把 skipped 数写死 ——
> 它随环境变化，写死会在别的机器误报。

---

## 7. 人工验收（发布前 10 分钟）

### 7.1 lite（必做）

```powershell
# 1) 解压到空目录
$dst = "$env:TEMP\netdiag-lite-verify"
Remove-Item $dst -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive logs\dist\NetDiag-0.2.0-lite.zip -DestinationPath $dst

# 2) 自检：无 tshark / 无 Npcap 时是 WARN，不是 FAIL
& "$dst\NetDiag\自检.bat" --no-pause
echo "exit=$LASTEXITCODE"
# 期望：RESULT: USABLE；WARN 提示装 Wireshark / Npcap，FAIL 0

# 3) 用系统 Python 跑全套测试
Push-Location "$dst\NetDiag"
$env:NETDIAG_LOG_DIR = "$env:TEMP\netdiag-lite-logs"
python -m unittest discover -s tests
Pop-Location
# 期望：Ran 235 tests ... OK (skipped=19)

# 4) 校验和
Get-FileHash logs\dist\NetDiag-0.2.0-lite.zip -Algorithm SHA256
Get-Content logs\dist\SHA256SUMS.txt
```

### 7.2 内部包（发布时不需要做，改了打包逻辑时做）

```powershell
$dst = "$env:TEMP\netdiag-internal-verify"
Remove-Item $dst -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive logs\dist\NetDiag-0.2.0-internal.zip -DestinationPath $dst
& "$dst\NetDiag\自检.bat" --no-pause
# 期望：PASS 5 / WARN 2（本机无 Npcap、未提权） / FAIL 0 → USABLE
# 有 --with-npcap 时 Npcap 那一条会提示包内安装器路径
```

清单抽查：

```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead("$PWD\logs\dist\NetDiag-0.2.0-lite.zip")
$zip.Entries | Where-Object { $_.FullName -match '^(\.git/|harness/|logs/.+|config/ai-config\.json$|reports/.+)$' } |
    Select-Object FullName
$zip.Entries | Where-Object { $_.FullName -match 'npcap|tools/' } | Select-Object FullName
$zip.Dispose()
# 期望：第一条只列出 reports/faults_demo.md 与 reports/faults_demo.json；
#       第二条为空（lite 里没有 npcap / tools）。
```

---

## 8. 发版（GitHub Release，只发 lite）

发布件先在**干净目录**生成、验证通过后再上传；**tag 指向 `main` HEAD**
（`v0.2.0` = `6015614`）：

```powershell
# 1) 生成公开 lite 包到独立目录（避免 SHA256SUMS 混入内部包）
python scripts\build_release.py --out logs\dist\release

# 2) 生成 release notes：CHANGELOG 的 v0.2.0 段 + 自行安装说明
#    （见 §8.1 的脚本）

# 3) 只上传 lite + SHA256SUMS
gh release create v0.2.0 `
  logs\dist\release\NetDiag-0.2.0-lite.zip `
  logs\dist\release\SHA256SUMS.txt `
  --target 601561426ffd8a4d569ec8b9e6242e1052df0ed5 `
  --title "NetDiag · 网络矩阵 v0.2.0（lite 源码包）" `
  --notes-file logs\dist\release\release-notes.md
```

> `--target` 必须用**完整 40 位 SHA**：实测短 SHA `6015614` 会被 GitHub 拒绝
> （`HTTP 422 Release.target_commitish is invalid`）。

```powershell
# 4) 核对：附件里绝不能出现 npcap / tools / Wireshark
gh release view v0.2.0
gh api repos/ftwvvt74r6-cloud/usb-net-diag/releases/tags/v0.2.0 --jq '.assets[].name'
```

### 8.1 release notes 生成（参考实现）

```powershell
$changelog = Get-Content CHANGELOG.md -Raw -Encoding UTF8
$start = $changelog.IndexOf("## v0.2.0")
$end = $changelog.IndexOf("## v0.1.0")
$section = $changelog.Substring($start, $end - $start).Trim()
@"
$section

---

## 安装前置（本包不含第三方二进制）

- 本 Release 只发 ``NetDiag-0.2.0-lite.zip``（源码 / 文档 / 测试），**不含** Python、Wireshark、Npcap。
- 运行需要 **Python 3.11+**：https://www.python.org/downloads/windows/
- 分析抓包文件需要 **tshark**：安装 Wireshark https://www.wireshark.org/download.html ，或设置 ``TSHARK_PATH``。
- 全网体检 / 单目标诊断 / 通信观察需要 **Npcap**：https://npcap.com/#download 和管理员权限。
- 解压后先双击 ``自检.bat``；lite 包用 ``python core\server.py`` 启动。
"@ | Set-Content logs\dist\release\release-notes.md -Encoding UTF8
```

**发版前必须确认**：`v0.2.0` 这个 tag 不存在（`git ls-remote --tags origin`）；
附件清单只有 lite + `SHA256SUMS.txt`；产物（zip / SHA256SUMS）**不入库**、不 `git add -f`。

> ⚠️ **不要**把 `--with-tools` / `--with-npcap` 的包上传到公开 Release。
> Npcap 免费版不允许对外再分发；Wireshark 是 GPL，公开再分发要承担源码提供义务。
> 见 [`licensing.md`](licensing.md) §2。

---

## 9. v0.2.0 实测记录（法务修正回合）

| 模式 | zip | zip 体积 | 条目数（文件） | Npcap 在包内 | 构建自检 |
|---|---|---|---|---|---|
| lite | `NetDiag-0.2.0-lite.zip` | 约 **0.7 MB** | 约 **142** | **否** | 系统 Python：235 tests `OK (skipped=19)` + 8 contract |
| `--with-tools` | `NetDiag-0.2.0-internal.zip` | 约 **147 MB** | 约 **2056** | **否** | 包内 Python：235 tests `OK (skipped=2)` + 8 contract |
| `--with-npcap` | `NetDiag-0.2.0-internal-npcap.zip` | 约 **149 MB** | 约 **2057** | **是**（仅内部） | 包内 Python：235 tests `OK (skipped=2)` + 8 contract |

> 详细证据（构建完整输出、空目录 `自检.bat`、Release 附件核对）见
> `review/chore-release-packaging-WRITER.md` 的「法务修正回合」一节。

---

## 10. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| `working tree has tracked changes` | 先提交；脚本只导出 HEAD，未提交改动不会进包 |
| lite 构建报 `缺少便携运行时目录` | 只有 `--with-tools` / `--with-npcap` 才需要 `tools\`；lite 不需要 |
| `tools/ 复制不完整` | 本机 `tools\` 缺失或被裁剪；按 §2 的标准构成补齐 |
| `git archive` 报 `not a git repository` | 在仓库根目录运行（脚本会自动定位，但仓库必须是 git 工作区） |
| zip 很大 / 构建慢 | 内部包正常：362 MB 运行时压缩到约 147–149 MB；杀软实时扫描会更慢 |
| 解压自检超时 | 把仓库加到杀软排除目录；或先用 `--skip-verify` 出包，再手工按 §7 验 |
| lite 包 `自检.bat` 报 tshark WARN | 正常：lite 不含 Wireshark，装 Wireshark 或设 `TSHARK_PATH` 后重跑 |
| lite 包双击 `start.bat` 报找不到 Python | 正常：`start.bat` 依赖 `tools\python`，lite 请用 `python core\server.py` |
| 包内测试 `skipped=2` 而不是 19 | 正常，见 §6：带 `tools/` 的包少跳过 17 项 |

---

## 11. 许可红线（读一遍再发版）

- 公开 Release：**只发 lite**（代码），不随附 Wireshark / Npcap / Python。
- 内部包：`--with-tools` 保留 Wireshark `COPYING.txt`；`--with-npcap` 只能内部同事之间用。
- **公开 repo 的 Release 永远不带 Npcap**；`gh release view` 里出现 `npcap` 就是发版事故。
- 把 `--with-npcap` 包发给同事 = 组织内部分发，是否合规由你们与 IT/法务确认。

完整说明见 [`licensing.md`](licensing.md)。
