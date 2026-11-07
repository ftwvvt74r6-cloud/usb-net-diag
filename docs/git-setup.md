# 公司电脑上的 Git 接管手册（给 AI 执行、给你确认）

> **这份文档的用法**：把它连同 `AGENTS.md` 一起交给那台电脑上的 AI，
> 让它按 §1 → §9 顺序执行。每一步都有「命令 → 期望输出 → 失败怎么办」，
> 你只需要在需要授权/输入的地方回答它。
>
> **前提**：那台电脑上还**没有配置过 git**。整个过程约 10~20 分钟，其中一半时间花在
> 「网络/代理」上——**这是最容易卡住的地方，所以我们把它放在第 4 步，而不是最后。**

---

## 0. 先明确三条纪律（AI 必须遵守）

1. **绝不 clone 到 U 盘**。仓库放本机（如 `D:\work\usb-net-diag`）；
   便携运行环境（`tools/`、`harness/`）仍留在 U 盘，两者互不干扰。
2. **绝不 `git add` 整个目录**。永远 `git add <明确路径>`，并在 `git status` 里逐条看过。
3. **绝不强推**（`git push -f`）。真需要时先问人。

理由（写给用户的）：U 盘是 exFAT，没有权限位、不支持符号链接/硬链接，
git 在上面既慢又容易出现「文件明明没改却显示已修改」；而且 U 盘会被拔。

---

## 1. 探测现状（先别装）

```powershell
git --version
```

| 输出 | 结论 | 下一步 |
|---|---|---|
| `git version 2.4x.x` | 已有 git | 跳到 §3 |
| `'git' 不是内部或外部命令` 或找不到 | 没装 | §2 |

顺便记录环境（后面排查用）：

```powershell
$PSVersionTable.PSVersion          # PowerShell 版本
[Environment]::OSVersion.Version   # Windows 版本
Test-Path "$env:ProgramFiles\Git"  # 是否装过但没进 PATH
```

---

## 2. 安装 Git（两种方式，优先 A）

### A. 官方安装包（推荐）

1. 打开 <https://git-scm.com/download/win>，下载 **64-bit Git for Windows Setup**。
2. 安装时**只改两个选项**，其余保持默认：
   - `Adjusting your PATH environment` → 选 **Git from the command line and also from 3rd-party software**
   - `Configuring the line ending conversions` → 选 **Checkout as-is, commit as-is**（仓库已有 `.gitattributes`，不要让它自动转换）
3. 装完**重开一个 PowerShell 窗口**（不改 PATH 的当前窗口读不到新命令），再验证：

```powershell
git --version
```

期望：`git version 2.4x.windows.1`

### B. 便携版（装不了安装包时，例如公司禁装软件）

1. 下载 `PortableGit-*-64-bit.7z.exe`（同一下载页最下方）。
2. 解压到 `D:\tools\PortableGit`（不要放 U 盘）。
3. **仅对当前窗口**生效：

```powershell
$env:Path = "D:\tools\PortableGit\cmd;" + $env:Path
git --version
```

> 这样每次新开窗口都要重设 PATH。要长期生效，就把它写进
> `[Environment]::SetEnvironmentVariable("Path", ...)`（需要用户权限，可能会被策略拦）。

---

## 3. 全局配置（一次配好，永久生效）

```powershell
git config --global user.name  "你的GitHub用户名"
git config --global user.email "你的GitHub隐私邮箱"
git config --global init.defaultBranch main
git config --global core.autocrlf false        # 换行交给 .gitattributes，别让它自动改
git config --global core.quotepath false        # 中文文件名不转义成 \344\275...
git config --global core.longpaths true         # 放行 Windows 260 字符路径限制
git config --global pull.rebase false
```

**隐私邮箱怎么找**：GitHub 网页 → 右上头像 → `Settings` → `Emails` →
勾选 *Keep my email addresses private* 后，页面上会显示
`12345678+用户名@users.noreply.github.com`。**用这个，不要用真实邮箱**（避免进提交历史）。

验证：

```powershell
git config --global --list
```

期望能看到 `user.name` / `user.email` / `core.autocrlf=false` 等行，**没有报错**。

> 如果 `user.email` 填错，后面提交记录改起来很麻烦（要 rebase）。
> 现在多看一眼，比之后返工便宜。

---

## 4. 网络与代理（最容易卡住的一步，务必单独验证）

### 4.1 先判断「直连能不能通」

```powershell
Test-NetConnection github.com -Port 443 |
  Select-Object ComputerName, RemotePort, TcpTestSucceeded
```

| `TcpTestSucceeded` | 含义 | 下一步 |
|---|---|---|
| `True` | TCP 能通 | 试 §4.2 的 `git ls-remote`，能过就跳到 §5 |
| `False` | 网络层就不通（DNS 污染 / 防火墙 / 必须走代理） | 走 §4.3 或 §4.4 |

### 4.2 用 git 自己验证（比 ping 准，因为它真的走 HTTPS）

```powershell
git ls-remote --heads https://github.com/ftwvvt74r6-cloud/usb-net-diag.git
```

| 输出 | 结论 |
|---|---|
| 一行 `0bd5dbf... refs/heads/main` | ✅ 通了，跳 §5 |
| `fatal: unable to access ... Could not resolve host` | DNS 问题 → §4.3 |
| `fatal: unable to access ... Failed to connect ... port 443` | 被拦/要走代理 → §4.3 |
| `SSL certificate problem` | 企业 TLS 拦截 → §4.5 |
| `Authentication failed` / 弹窗要账号 | 网络是通的，跳 §5 解决认证 |

### 4.3 配置 HTTP/HTTPS 代理

先查本机代理端口（两种常见来源）：

```powershell
# 1) Windows 系统代理
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" |
  Select-Object ProxyEnable, ProxyServer
# 2) WinHTTP 代理（某些公司环境只配这里）
netsh winhttp show proxy
```

假设查到 `127.0.0.1:7890`，则：

```powershell
git config --global http.proxy  http://127.0.0.1:7890
git config --global https.proxy http://127.0.0.1:7890
git ls-remote --heads https://github.com/ftwvvt74r6-cloud/usb-net-diag.git
```

不需要代理时记得**清掉**，否则换到能直连的网络会全部失败：

```powershell
git config --global --unset http.proxy
git config --global --unset https.proxy
```

> 只对单条命令用代理（不改全局）：
> `git -c http.proxy=http://127.0.0.1:7890 ls-remote ...`

### 4.4 代理不通 / 只允许 443 出口时：改走 SSH over 443

很多公司网只放行 443，而 SSH 默认 22 会被封。GitHub 官方支持 443 端口 SSH：

```powershell
# 1) 生成密钥（一路回车，用 ed25519 比 rsa 更短更快）
ssh-keygen -t ed25519 -C "work-pc-usbnetdiag"

# 2) 看公钥，整段复制（以 ssh-ed25519 开头）
Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub"

# 3) 浏览器打开 https://github.com/settings/keys → New SSH key → 粘贴 → Add

# 4) 让 github.com 的 SSH 走 443
@"
Host github.com
  HostName ssh.github.com
  Port 443
  User git
"@ | Out-File -Encoding ascii -Append "$env:USERPROFILE\.ssh\config"

# 5) 验证（第一次会问 yes/no，输 yes）
ssh -T -p 443 git@ssh.github.com
```

期望：`Hi <你的用户名>! You've successfully authenticated, but GitHub does not provide shell access.`
（看到这句话就是**成功**，不是错误。）

### 4.5 企业 TLS 拦截（`SSL certificate problem`）

优先做法：把公司的根证书路径告诉 git，而**不是关掉校验**。

```powershell
git config --global http.sslCAInfo "C:\path\to\corp-root-ca.crt"
```

应急（仅临时、且你清楚风险）：

```powershell
git -c http.sslVerify=false ls-remote ...
```

---

## 5. 认证：两条路，选一条

### 路线一：HTTPS + 个人访问令牌（PAT）—— 最省事

1. 浏览器：<https://github.com/settings/tokens> → `Generate new token (classic)`
   → 勾选 **`repo`** → 生成 → **立刻复制**（只显示一次）。
2. 首次 `git clone` / `push` 时弹窗：用户名填 GitHub 用户名，**密码位置粘 PAT**。
3. Windows 会把它存进「凭据管理器（Git Credential Manager）」，之后不再问。

验证是否存住：

```powershell
cmdkey /list | findstr /i github
```

### 路线二：SSH 密钥（§4.4 已做就选这条）

```powershell
git clone git@github.com:ftwvvt74r6-cloud/usb-net-diag.git D:\work\usb-net-diag
```

---

## 6. clone 到本机（不要 U 盘）

```powershell
New-Item -ItemType Directory -Force D:\work | Out-Null
git clone https://github.com/ftwvvt74r6-cloud/usb-net-diag.git D:\work\usb-net-diag
```

期望：`Receiving objects: 100% (27/27)`，随后 `done.`

验证仓库内容（应该 **27 个文件**、**没有** `tools/` 和 `harness/`）：

```powershell
cd D:\work\usb-net-diag
(git ls-files | Measure-Object).Count        # 期望 27
git log --oneline                            # 期望只有一行 0bd5dbf
Test-Path tools                               # 期望 False
Test-Path harness                             # 期望 False
```

---

## 7. 把 U 盘上已有的改动并进来（**这一步最容易出错，逐条对账**）

U 盘目录（`<你的工作目录>`）里除了源码，还有 `tools/`、`harness/`、`captures/`、
`logs/`、`reports/`、真实 `config/*.json`、以及我交付的 `docs/`、`scaffold/`、`dist/`。
**只把该进库的东西拷过去**：

| 从 U 盘拷 | 到仓库 | 说明 |
|---|---|---|
| `core\` `ui\` `mcp\` `skills\` `tests\` `config\*.example.json` | 同名位置 | 源码 |
| `README.md` `CHANGELOG.md` `VERSION` `start.bat` `doctor.bat` | 根目录 | 启动与说明 |
| `.gitignore` `.gitattributes` `.github\` | 同名位置 | **如果本地与仓库不同，先看清差异再覆盖** |
| `docs\` | `docs\` | 我的评审与索引 |
| `scaffold\` | `scaffold\` | 骨架（可选，但建议带上，41 个用例是活文档） |
| `scripts\` | `scripts\` | 接口文档生成器 |
| **`tools\` `harness\` `captures\*.pcap` `logs\` `reports\` `dist\` `config\ai-config.json`** | **不要拷** | 已被 `.gitignore` 排除，拷了也进不去，只会让 `git status` 变脏 |

拷完先对账，**不要急着 commit**：

```powershell
cd D:\work\usb-net-diag
git status --short
```

期望：只列出**你确实改过/新增的**文件。出现下面这些就说明拷错了，删掉：

```
?? tools/               ← 被 gitignore 的不会出现；出现了说明你 clone 错位置或改了 .gitignore
?? harness/
?? logs/
?? reports/
?? config/ai-config.json
```

> 如果 `git status` 里出现几百个文件，先 `git status --short | Measure-Object -Line` 看数量，
> 再判断是不是把 `tools/` 拷进去了。

---

## 8. 第一次提交与推送

```powershell
cd D:\work\usb-net-diag
git switch -c chore/import-usb-changes        # 不要在 main 上直接改
git add core ui mcp skills tests config/*.example.json *.md VERSION start.bat doctor.bat
git add docs scaffold scripts .github .gitignore .gitattributes
git status --short                             # 再确认一次
git commit -m "chore: 从 U 盘导入当前源码 + 评审文档与骨架"
git push -u origin chore/import-usb-changes
```

然后**在网页上开 PR → 等 CI 绿 → 合并**（这一步顺便把「不许直推 main」练一遍）。

合并后验证「本地与远端一致」：

```powershell
git switch main
git pull
git rev-parse HEAD
git rev-parse origin/main     # 两个 sha 必须相同
```

或直接交给我核对：把这句的输出发我，我 `git fetch` 后比对。

---

## 9. 打开分支保护（在网页上做，AI 改不了仓库设置）

`Settings` → `Branches` → `Add branch protection rule`：

- Branch name pattern：`main`
- ✅ Require a pull request before merging
- ✅ Require status checks to pass before merging → 选 `syntax-and-contract`
  （即 `.github/workflows/smoke.yml` 里那个 job）
- ✅ Require linear history
- ✅ Do not allow bypassing the above settings
- ❌ 不要勾 Allow force pushes

再把 `AGENTS.md` 提交到仓库根目录（内容已提供），
这样「不许 AI 直推 main / 不许改 rows 文案 / 不许引入依赖」才真正生效。

---

## 10. 日常循环（配好后每天就这几句）

```powershell
git switch -c feat/t05-rules-migration     # 1. 开分支（带任务号）
# ...改代码...
git status --short                          # 2. 看改了什么
git add core/rules core/analyzer.py         # 3. 精确 add
git commit -m "feat(rules): 把 build_findings 拆成独立 Rule"
git push -u origin HEAD                     # 4. 推分支
# 5. 网页开 PR → CI 绿 → 合并
git switch main && git pull                 # 6. 回到最新 main
```

---

## 11. 排错表

| 报错 | 原因 | 解决 |
|---|---|---|
| `Could not resolve host: github.com` | DNS 不通 | §4.3 配代理；或先把 DNS 改成 `223.5.5.5` 再试 |
| `Failed to connect ... port 443` | 出口被拦 | §4.3 代理 / §4.4 SSH over 443 |
| `SSL certificate problem: self signed certificate in certificate chain` | 企业拦截 TLS | §4.5 指定公司根证书 |
| `Permission denied (publickey)` | SSH 公钥没加 | §4.4 第 3 步重新添加，`ssh -T -p 443 git@ssh.github.com` 复验 |
| `Authentication failed for 'https://github.com/...'` | 用了账号密码而不是 PAT | §5 路线一，密码位置粘 PAT |
| `remote: Support for password authentication was removed` | GitHub 已禁用密码登录 | 同上 |
| `LF will be replaced by CRLF` | `core.autocrlf` 没关 | §3 设 `core.autocrlf false` |
| 中文文件名显示成 `\344\275\240` | `core.quotepath` 默认 true | §3 设 `false` |
| `filename too long` | Windows 260 字符限制 | §3 设 `core.longpaths true` |
| `non-fast-forward` / `rejected` | 远端有你本地没有的提交 | `git pull --rebase` 后再 push（**不要** `-f`） |
| `File ... is 512.00 MB; this exceeds GitHub's file size limit` | 误加了大文件 | `git rm --cached <file>`，确认 `.gitignore` 生效 |
| `git status` 显示一堆没改过的文件「已修改」 | 换行符被转换 | §3 设 `core.autocrlf false`，然后 `git checkout -- .` |
| 提交作者是别人 / 邮箱是真实邮箱 | `user.name/email` 没设或设错 | §3；已提交的错作者需 `git commit --amend --reset-author` |

---

## 12. 一页速查（可以直接整段复制给 AI 执行）

```powershell
# 0) 探测
git --version

# 1) 身份与习惯（把 <...> 换成实际值）
git config --global user.name  "<GitHub用户名>"
git config --global user.email "<隐私邮箱>"
git config --global init.defaultBranch main
git config --global core.autocrlf false
git config --global core.quotepath false
git config --global core.longpaths true

# 2) 网络验证（先不改任何配置）
Test-NetConnection github.com -Port 443 | Select-Object TcpTestSucceeded
git ls-remote --heads https://github.com/ftwvvt74r6-cloud/usb-net-diag.git

# 3) 若不通：代理
git config --global http.proxy  http://127.0.0.1:7890
git config --global https.proxy http://127.0.0.1:7890
git ls-remote --heads https://github.com/ftwvvt74r6-cloud/usb-net-diag.git

# 4) clone 到本机（不要 U 盘）
New-Item -ItemType Directory -Force D:\work | Out-Null
git clone https://github.com/ftwvvt74r6-cloud/usb-net-diag.git D:\work\usb-net-diag
cd D:\work\usb-net-diag
(git ls-files | Measure-Object).Count      # 期望 27

# 5) 并入 U 盘改动后对账 → 开分支 → 提交 → 推送 → 网页开 PR
git status --short
git switch -c chore/import-usb-changes
```

**给用户的一句话**：你只要在「弹窗要账号密码」时粘 PAT，
在「`ssh` 问 yes/no」时输 `yes`，其余命令让 AI 跑就行。
每一步如果没看到本文档写的「期望输出」，就停下来问，别硬往下走。
