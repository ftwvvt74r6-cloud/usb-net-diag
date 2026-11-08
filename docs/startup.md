# 启动与提权（NetDiag.exe / start.bat / NetDiag.vbs）

> 面向使用者与维护者。目标是把「拿到包 → 双击 → 能用」做成一条不折腾的路径：
> **启动不提权**，需要管理员的功能再按需请求。
>
> 本文的「启动器」部分（C1）已实现；「按需提权 UI 权限卡 / 首屏自检」属于 C2 增量，
> 文末列出待补内容，避免与现状混淆。

---

## 1. 三个入口，怎么选

| 入口 | 推荐度 | 适用场景 | 启动行为 |
|---|---|---|---|
| **`NetDiag.exe`** | ⭐ 推荐 | 日常双击、U 盘便携、右键「以管理员身份运行」 | 无控制台；定位 Python → 隐藏启动 `core\app.py` → 等 `/api/ping` 就绪 → 打开默认浏览器；**不请求提权** |
| `start.bat` | Python 回退 | 想看启动日志、`NetDiag.exe` 被安全软件拦下、手动排障 | 带控制台；默认以当前权限运行；`start.bat --admin` 才请求 UAC |
| `NetDiag.vbs` | 兼容 | 旧快捷方式、无 exe 的内部包 | 无控制台；优先包内 `tools\python\pythonw.exe`，回退系统 Python / `py -3`；**不再自动提权** |

`自检.bat` 仍然保留，用于逐项检查 Python / tshark / Npcap / 管理员权限；它不是启动入口。

> 为什么推荐 exe：`.vbs` 无法右键「以管理员身份运行 / 以其他用户运行」，也容易被
> 脚本宿主策略拦下；exe 是 Windows 原生入口，这两项是系统自带能力，不需要注册表。

---

## 2. 双击 `NetDiag.exe` 发生什么

1. 启动器以 **`asInvoker`** 运行（manifest 声明），**不弹 UAC**。
2. 先探测 `http://127.0.0.1:8787~8796/api/ping`：
   - 已有本程序实例在跑 → 直接打开浏览器，**不再启动第二个进程**；
   - 端口上回应的不是本程序（`app` 不含 `NetDiag`）→ 忽略，继续找。
3. 定位 Python（顺序见 §3）。
4. 以隐藏窗口启动：

   ```text
   <python> "<root>\core\app.py" --no-elevate
   ```

   工作目录 = `<root>`；不传 `--elevated`；`CreateNoWindow=true`、`UseShellExecute=false`。
5. 每 **200 ms** 轮询 `/api/ping`，总超时 **30 秒**；校验 `ok == true` 且 `app` 含 `NetDiag`。
6. 就绪后交给系统默认浏览器打开 `http://127.0.0.1:<port>/`。

失败时用系统 MessageBox 给出可操作提示（查看 `<root>\logs\app-*.log`、检查 Python/Npcap、
端口是否被占），退出码见 §3.3。启动器不检测、不请求管理员权限；用户自己右键
「以管理员身份运行」时它也不会二次提权。

---

## 3. 启动器细节

源码：`launcher/NetDiagLauncher.cs`；权限声明：`launcher/NetDiag.exe.manifest`（`asInvoker`）；
构建：`scripts/build_launcher.py`（系统自带 csc，无第三方依赖，产物不提交进 git）。

### 3.1 Python 定位顺序

1. `<root>\tools\python\pythonw.exe`（便携包自带，无控制台）；
2. `<root>\tools\python\python.exe`；
3. **系统 PATH 里的 `python.exe`**：启动器自己遍历 `PATH` 的每个目录找文件，
   不调用 `where python`、不解析任何本地化 CLI 文本；
4. `py.exe -3`（Python Launcher）：只有真正能跑且版本 **≥ 3.11** 才采用
   （只看退出码，不看输出文本）。

> 第 1/2 条是 lite 包以外的情况：公开 lite 包不带 `tools\`，需要系统 Python 3.11+。

### 3.2 `--dry-run`（排障 / 自动化）

`--dry-run` 只做「定位 Python」这一件事：不启动 app、不轮询、不开浏览器。

```bat
NetDiag.exe --dry-run --report "<临时目录>\launcher.json"
```

- 退出码：`0` = 找到 Python；`2` = 找不到 Python；
- `--report` 写 JSON（winexe 没有控制台，stdout 不可依赖，自动化请读文件）；
  关键键：`ok` / `dry_run` / `root` / `python` / `python_kind` / `app_script` /
  `app_script_exists` / `started`（恒 `false`）/ `browser_opened`（恒 `false`）/ `error`。
- 从命令行运行时，启动器会尝试挂到父控制台，方便直接看 Python 路径；没有控制台时
  只靠 `--report`。

### 3.3 退出码

| 退出码 | 含义 | 下一步 |
|---|---|---|
| `0` | 成功（服务就绪并已开浏览器；或已有实例直接开窗） | — |
| `2` | 找不到可用的 Python（需要 3.11+） | 安装 Python 并勾选 Add python.exe to PATH，或使用带 `tools\python` 的离线包 |
| `3` | 等待就绪超时（30 秒） | 看 `logs\app-*.log`；查端口 8787~8796 是否全被占、Npcap/安全软件是否拦截 |
| `4` | 启动失败（Python 进程提前退出 / `core\app.py` 缺失 / 浏览器打不开 / 报告写失败） | 看日志与提示中的具体路径 |

`--dry-run` 只会返回 `0` 或 `2`（`--report` 写失败时返回 `4`）。

### 3.4 安全边界

- manifest 固定 `asInvoker`，启动器**自身不提权**；
- 只访问 `127.0.0.1`（探测 `/api/ping`），不走系统代理、不联网；
- 不写注册表、不装服务、不开机自启、不做 UAC bypass；
- 不写真实路径/用户名进仓库；日志里的路径由运行环境决定。

---

## 4. 启动不提权，需要时再提权

### 4.1 已实现（C1）

- `core/app.py` 的 `main()` **删除**了启动时自动 `relaunch_as_admin()`；
  新增 `--no-elevate`（启动器传入，显式声明「本次不请求提权」，默认行为本来就相同）。
- 启动日志会写一行：`启动不提权；需要管理员的功能会在界面按需请求（admin=...）`。
- `--elevated` 仍保留：那是 `/api/elevate` 拉起的新进程，不是双击启动路径。
- `POST /api/elevate` 返回结构化 `{ok, restarted, error}`：
  - 已是管理员 → `{ok: true, restarted: false, already_admin: true}`，不重复弹 UAC；
  - 用户点「是」→ `{ok: true, restarted: true}`，旧服务安排退出，新进程等端口释放后监听；
  - 用户取消 / 被策略禁止 / 启动器异常 → `{ok: false, restarted: false, error: ...}`，
    **不抛异常、不杀当前进程**，离线分析、连通与速度测试继续可用。
- `start.bat` 默认不 RunAs；只有显式 `start.bat --admin` 才请求提权。

### 4.2 提权的现实边界

- 管理员账户 + 未被管控 → Windows UAC 确认框，点「是」生效；
- 标准用户 / 被管控 → Windows 自动弹**管理员凭据对话框**（输入有权限的账号）；
- 用户拒绝 / 公司组策略禁止请求提升 → 保持普通权限，功能降级；
- **做不到**「后台静默提权」：UAC 设计要求人工确认，绕过属于 UAC bypass（恶意行为），
  本项目不实现。

### 4.3 待补（C2 增量）

- 界面权限卡：非管理员点「实时抓包 / 通信观察」→「该功能需要管理员权限」+
  [以管理员身份重启] / [取消]，并提示离线功能仍可用；
- 提权前把表单（模式 / 目标 / 时长 / 网卡 / 文件）写入 `sessionStorage`，页面加载时恢复；
- 首屏「准备检查」五项（Python / tshark / Npcap / 端口 / 权限）与「重新检测」。

---

## 5. `start.bat`（Python 回退入口）

- 顶部会提示「推荐双击 `NetDiag.exe`；`start.bat` 为 Python 回退入口」；
- 默认以当前权限运行并提示「实时抓包 / 通信观察需要管理员时请在界面按需提权」；
- `start.bat --admin`：显式请求 UAC 后重启自身（仅这一条分支有 `-Verb RunAs`）；
- Npcap 未就绪时：**打开交互式安装向导**（`start /wait "" "<npcap 安装包>"`），
  提示「请在向导里完成安装」。免费版 Npcap 不支持 `/S` 静默安装（只有 OEM 版支持），
  所以不再尝试静默装；
- 没有内置 Npcap 安装包时打印官网链接，不联网下载；
- 保留三级 Python 回退与所有既有 `%ROOT%\...` 引用路径（`tests/test_launcher_contract.py` 守着）。

---

## 6. 常见启动问题

| 现象 | 可能原因 | 怎么查 / 怎么办 |
|---|---|---|
| 双击 `NetDiag.exe` 没反应 | 启动器被安全软件拦下 / 系统策略 | 改用 `start.bat` 看控制台报错；检查安全软件日志 |
| 弹「未找到可用的 Python 运行时」 | 没有 Python 3.11+，且包内无 `tools\python` | 安装 Python 3.11+ 并勾选 Add python.exe to PATH；或用内部离线包 |
| 弹「启动超时：30 秒内本地服务没有就绪」 | 端口全被占 / Python 导入失败 / Npcap 拦截 | 看 `logs\app-*.log`；关掉占用 8787~8796 的程序；重装/修复 Npcap |
| 弹「启动失败：Python 进程已退出」 | Python 版本过低、`core\` 文件不全 | 看日志里的 traceback；确认 exe 与 `core\` 在同一层 |
| 浏览器没打开但提示服务已就绪 | 默认浏览器关联异常 | 手动访问提示里的 `http://127.0.0.1:<port>/` |
| 右键「以管理员身份运行」后仍然没有权限 | 用户取消了 UAC，或被组策略禁止 | 用管理员账号；或让 IT 推送安装 Npcap/放行 |
| `start.bat` 双击闪退 | 控制台编码 / Python 路径问题 | 在 `cmd` 里运行 `start.bat` 看最后一行；确认 Python 3.11+ |

日志位置固定在 `<root>\logs\`：`app-*.log` 是启动/服务日志，`diag-*.log` 是诊断日志。

---

## 7. 维护者验证命令

```powershell
# 1) 源码/manifest 结构（ubuntu CI 也可跑，不需要 csc）
python scripts\build_launcher.py --check

# 2) 本机编译（默认输出到仓库根 NetDiag.exe；*.exe 不进 git）
python scripts\build_launcher.py

# 3) 只定位 Python，不启动服务/不开浏览器
.\NetDiag.exe --dry-run --report "$env:TEMP\netdiag-launcher.json"

# 4) 启动器/提权契约测试
python -m unittest discover -s tests -p "test_launcher_exe.py" -v
python -m unittest discover -s tests -p "test_elevate_api.py" -v
```

`--dry-run` 的验证**不启动可见浏览器、不弹 UAC**；需要 UI 行为验证时按 C2 的 headless 方案做。

---

## 8. C2 待补清单（下一个 writer）

- [ ] UI 权限卡接线（`POST /api/elevate` + 取消路径）；
- [ ] `sessionStorage['netdiag.form']` 表单保留 / 恢复；
- [ ] 首屏「准备检查」五项 + `GET /api/selfcheck`；
- [ ] 本文 §4.3 改为「已实现」，并补首屏自检的常见失败与修复。
