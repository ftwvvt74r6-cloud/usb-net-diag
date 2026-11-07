# 构建与发布（便携包 v0.2.0 起）

> 面向维护者。目标：**一条命令**产出可对外分发的 `NetDiag-0.2.0-portable.zip`，
> 并且脚本自己先解压、用包内 Python 真跑一遍测试，通过才说 `BUILD OK`。
> 许可与再分发注意事项见 [`licensing.md`](licensing.md)。

---

## 1. 前置条件

| 项 | 要求 |
|---|---|
| 系统 | Windows 10/11（打包脚本本身只用标准库，但 `tools/` 是 Windows 运行时） |
| Git | 能在仓库根目录执行 `git archive`（脚本只导出 **HEAD 提交**里的受控文件） |
| Python | 系统 Python 3.9+ 即可跑脚本；也可以用仓库自带的 `tools\python\python.exe` |
| `tools\` | **本机必须已有**（约 362.5 MiB，被 `.gitignore` 排除，不在 git 里） |
| 磁盘 | ≥ 1.2 GB 空闲（暂存 + zip + 解压自检同时存在，脚本结束会清理） |
| 工作区 | 已跟踪文件必须干净；脚本默认拒绝脏工作区（`--allow-dirty` 只用于本地调试） |

`tools\` 的标准构成（不裁剪）：

```
tools\
├── python\                                   # 便携 Python 3.11.9（含 Scapy 2.8.0）
├── WiresharkPortable\App\Wireshark\          # Wireshark 4.7.4，含 tshark.exe / dumpcap.exe
└── npcap-1.79.exe                            # Npcap 离线安装包
```

---

## 2. 一条命令

在仓库根目录：

```bat
tools\python\python.exe scripts\build_release.py
```

（系统 Python 也行：`python scripts\build_release.py`。）

成功时最后一行是 **`BUILD OK`**，产物在：

```
logs\dist\NetDiag-0.2.0-portable.zip
logs\dist\SHA256SUMS.txt
```

> 为什么放 `logs\dist\`：`.gitignore` 里有 `/logs/*`，产物天然不入库；
> `dist\` 没有对应忽略规则，容易误提交。脚本默认值就是 `logs\dist\`。

常用参数：

| 参数 | 作用 |
|---|---|
| `--out DIR` | 换产物目录（默认 `logs\dist`） |
| `--skip-verify` | 只出包，跳过解压自检（**发布前不要用**） |
| `--allow-dirty` | 允许已跟踪文件有未提交改动（只用于本地试跑） |
| `--keep` | 保留解压后的自检目录，便于人工复核 |

---

## 3. 脚本做了什么（7 步）

1. `git archive HEAD` → 暂存目录 `NetDiag\`：只含 **141 个受控文件**（约 1.6 MB，以 `git ls-files` 为准）。
   `.git`、`harness/`、`logs/`、`config/ai-config.json`、`reports/` 里非示例文件
   天然不在里面（它们不在 git 里）。
2. **原样复制 `tools\`**（362.5 MiB / 1917 文件）；只跳过 `__pycache__` 和 `*.pyc`，
   **不裁剪 Wireshark**。
3. 生成包内 `README.txt`（到手即用的第一份说明）；`自检.bat` 来自 git（需已提交）。
4. 打 `NetDiag-<VERSION>-portable.zip`（`ZIP_DEFLATED`，level 6，含目录条目，
   空目录 `logs\` 也会保留）。
5. 写 `SHA256SUMS.txt`（`sha256sum` 兼容：`<hash>  <文件名>`，LF 换行）。
6. **解压到临时目录**（`logs\dist\_verify-*`），用**包内便携 Python**：
   - 全套 `unittest`（`235 tests`，见 §5 的 skipped 说明）；
   - 启动器契约（`test_launcher_contract.py`，8 tests）；
   - 清单断言：禁入项为零、`reports/` 只有两份示例、必要入口齐全、
     `自检.bat` 纯 ASCII + CRLF、`tools/` 文件数与体积达标。
7. 打印 zip 路径 / 大小 / SHA-256 / 测试行，最后输出 `BUILD OK`；任一步失败退出码非 0。

---

## 4. 包内结构（顶层是 `NetDiag\`）

```
NetDiag\
├── NetDiag.vbs / start.bat / 自检.bat / 导出诊断包.bat
├── README.txt                     # 构建时生成
├── VERSION / CHANGELOG.md / README.md / AGENTS.md
├── core\ ui\ mcp\ skills\ docs\ tests\
├── config\*.example.json         # 只有示例；ai-config.json 绝不入包
├── captures\faults_demo.pcap
├── reports\faults_demo.{md,json} # 只保留这两份示例
├── logs\                          # 空目录（首次运行写入）
└── tools\                         # 362.5 MiB，原样
```

**绝不入包**：`.git/`、`harness/`、`logs/` 里的文件、`config/ai-config.json`、
`reports/` 里除两份示例外的任何文件、`__pycache__/`。

---

## 5. 构建自检的通过标准

| 检查 | 通过标准 |
|---|---|
| 全套测试（包内 Python，有 `tools/`） | `Ran 235 tests ... OK (skipped=2)` |
| 干净 checkout（无 `tools/`，CI 环境） | `Ran 235 tests ... OK (skipped=19)` |
| 启动器契约 | `Ran 8 tests ... OK` |
| 包内清单 | 禁入项 0；`reports/` 只有 2 份；`tools/` ≥ 1900 文件 |
| 包内 `自检.bat` | 纯 ASCII（0 个 >0x7F 字节）+ CRLF |

> **skipped 为什么有两个数**：包里带 `tools/`（有 tshark + scapy），
> 跳过的只有「需要管理员 + Npcap 的真实抓包」和「需要本机 openssl 的 TLS 自检」= **2**；
> 干净 checkout 没有 tshark / scapy，会多跳过 17 项 = **19**。两者都是正常的，
> 不要为了凑 `skipped=19` 去删 `tools/`。

脚本只断言 `Ran N tests`（N ≥ 235）且结果为 `OK`，不把 skipped 数写死 ——
它随环境变化，写死会在 CI 或开发机上误报。

---

## 6. 人工验收（发布前 10 分钟）

```powershell
# 1) 解压到空目录
$dst = "$env:TEMP\netdiag-verify"
Remove-Item $dst -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive logs\dist\NetDiag-0.2.0-portable.zip -DestinationPath $dst

# 2) 自检（RESULT: USABLE 即通过；无管理员/Npcap 时是 WARN，不挡离线分析）
& "$dst\NetDiag\自检.bat" --no-pause
echo "exit=$LASTEXITCODE"

# 3) 包内 Python 跑全套测试
Push-Location "$dst\NetDiag"
$env:NETDIAG_LOG_DIR = "$env:TEMP\netdiag-selftest-logs"
.\tools\python\python.exe -m unittest discover -s tests
Pop-Location
# 期望：Ran 235 tests ... OK (skipped=2)

# 4) 校验和
Get-FileHash logs\dist\NetDiag-0.2.0-portable.zip -Algorithm SHA256
Get-Content logs\dist\SHA256SUMS.txt
```

清单抽查：

```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead("$PWD\logs\dist\NetDiag-0.2.0-portable.zip")
$zip.Entries | Where-Object { $_.FullName -match '^(\.git/|harness/|logs/.+|config/ai-config\.json$|reports/.+)$' } |
    Select-Object FullName
$zip.Dispose()
# 期望：只列出 reports/faults_demo.md 与 reports/faults_demo.json
```

---

## 7. 发版（GitHub Release）

发布件在本地生成、验证通过后上传；**tag 指向 `main` HEAD**：

```powershell
gh release create v0.2.0 `
  logs\dist\NetDiag-0.2.0-portable.zip `
  logs\dist\SHA256SUMS.txt `
  --target main `
  --title "NetDiag · 网络矩阵 v0.2.0（Windows 便携包）" `
  --notes-file logs\dist\release-notes.md

gh release view v0.2.0
```

`release-notes.md` 直接用 `CHANGELOG.md` 的 `## v0.2.0` 段（到 `## v0.1.0` 之前）。
上传 200 MB 级附件可能较慢，`gh` 偶发 TLS 失败时重试同一命令（附件已存在会报错，
用 `gh release upload v0.2.0 <file> --clobber` 补传）。

**发版前必须确认**：`v0.2.0` 这个 tag 不存在（`git ls-remote --tags origin`）；
同版本号不要重复发。产物（zip / SHA256SUMS）**不入库**、不 `git add -f`。

> ⚠️ 包里含 `tools\npcap-1.79.exe`。Npcap 免费版**不允许对外再分发**，
> 公开 Release 属于对外分发场景 —— 发之前先看 [`licensing.md`](licensing.md) §2，
> 由维护者决定「保留安装包 / 换 OEM 许可 / 让用户自行下载」。

---

## 8. v0.2.0 实测记录

| 项 | 值 |
|---|---|
| 构建命令 | `tools\python\python.exe scripts\build_release.py` |
| zip 大小 | 约 **142 MiB / 149 MB**（362.5 MiB 运行时压缩到约 39%） |
| SHA-256 | 每次构建都会变；**发布件以 GitHub Release 附件和同目录 `SHA256SUMS.txt` 为准** |
| 解压后大小 | 约 **364 MiB / 382 MB**，2057 个文件（其中 `tools/` 1915 个 / 362.5 MiB） |
| 包内测试 | `Ran 235 tests ... OK (skipped=2)` |
| 启动器契约 | `Ran 8 tests ... OK` |
| 构建耗时 | 约 85~100 秒（含复制 362 MB、压缩、解压、跑 235 条测试） |

> 发布件哈希与 GitHub Release 链接见仓库 `docs/release-v0.2.0.md`
> （该文件在构建完成后写，**不打进 zip**，避免“文档记录自己的哈希”这种自指）。

---

## 9. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| `working tree has tracked changes` | 先提交；脚本只导出 HEAD，未提交改动不会进包 |
| `tools/ 复制不完整` | 本机 `tools\` 缺失或被裁剪；按 §1 的标准构成补齐 |
| `git archive` 报 `not a git repository` | 在仓库根目录运行（脚本会自动定位，但仓库必须是 git 工作区） |
| zip 很大 / 构建慢 | 正常：362 MB 运行时压缩到约 200 MB，首次 2~5 分钟；杀软实时扫描会更慢 |
| 解压自检超时 | 把仓库加到杀软排除目录；或先用 `--skip-verify` 出包，再手工按 §6 验 |
| 路径太长 | 脚本的暂存/解压目录都在 `logs\dist\` 下（路径短）；不要手工解压到很深的目录 |
| 包内测试 `skipped=2` 而不是 19 | 正常，见 §5：包里带 `tools/` |
