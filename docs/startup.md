# 启动与提权（NetDiag.exe / start.bat / NetDiag.vbs）

> 面向使用者与维护者。目标是把「拿到包 → 双击 → 能用」做成一条不折腾的路径：
> **启动不提权**，需要管理员的功能再按需请求；首次运行先做五项只读检查。
>
> C1（启动器 + 启动不提权）与 C2（按需提权 UI / 表单保留 / 首屏自检）均已实现，
> 本文描述的是当前行为。

---

## 1. 三个入口，怎么选

| 入口 | 推荐度 | 适用场景 | 启动行为 |
|---|---|---|---|
| **`NetDiag.exe`** | ⭐ 推荐 | 日常双击、U 盘便携、右键「以管理员身份运行」 | 无控制台；定位 Python → 隐藏启动 `core\app.py` → 等 `/api/ping` 就绪 → 打开默认浏览器；**不请求提权** |
| `start.bat` | Python 回退 | 想看启动日志、`NetDiag.exe` 被安全软件拦下、手动排障 | 带控制台；默认以当前权限运行；`start.bat --admin` 才请求 UAC |
| `NetDiag.vbs` | 兼容 | 旧快捷方式、无 exe 的内部包 | 无控制台；优先包内 `tools\python\pythonw.exe`，回退系统 Python / `py -3`；**不再自动提权** |

`自检.bat` 仍然保留，用于逐项检查 Python / tshark / Npcap / 管理员权限；
它现在是**备用入口**，日常不需要先跑它（首次启动时界面会做同样的检查）。

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

### 4.1 启动路径（C1，已实现）

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

### 4.2 按需提权 UI 权限卡（C2，已实现）

非管理员触发任何**需要管理员**的动作时，界面弹权限卡，而不是静默失败或直接跳错误：

| 触发点 | 行为 |
|---|---|
| 左侧「全网体检 / 单目标诊断 / 通信观察」导航点击 | 弹出权限卡，不切换模式 |
| 空状态快捷入口 / 「开始」按钮 / 目标框回车 | 先走 `checkAdmin()`，非管理员弹卡 |
| 失败卡片「重试」/「以管理员身份重启」/ 通信观察空结果「重试」 | 同样走权限卡 |

权限卡内容：

- 标题「该功能需要管理员权限」；说明为什么（打开 Npcap 驱动需要授权）；
- **[以管理员身份重启]** → `POST /api/elevate`；
- **[取消]** → 只关闭卡片，**不发任何请求**，保持非管理员、功能仍置灰；
- 明确提示「不重启也可用：分析抓包文件 / 连通与速度测试」。

点击「以管理员身份重启」后：

1. 先把表单写入 `sessionStorage['netdiag.form.v1']`（见 §4.3）；
2. 成功发起 UAC / 凭据框 → 卡片显示「已请求提权，请在弹出的系统窗口确认」；
3. 用户取消 / 组策略禁止 / 接口失败 → 卡片显示具体原因 + 离线功能仍可用，
   留在当前页、保持非管理员、不刷新、不静默；
4. 授权成功后旧服务退出、新进程监听同一端口；当前标签页会轮询到新 PID 并自动刷新，
   表单从 `sessionStorage` 恢复。

**已是管理员时不显示该卡片，也不请求提权**（`showPermModal()` 直接返回）。

### 4.3 提权后保留表单（C2，已实现）

- 统一 key：`sessionStorage['netdiag.form.v1']`（JSON），写入点：
  - 表单元素 `input` / `change`（目标、时长、网卡、引擎、pcap、探针目标/端口/次数/协议、
    两个复选框）；
  - 切换模式时；
  - 点击「以管理员身份重启」前（双保险）。
- 保存字段：`mode` / `target` / `duration` / `interface` / `pcap` / `shadow` /
  `probe{target,port,count,proto,path}` / `passive{duration,interface}`。
- 恢复点：页面加载 `boot()` 里，网卡下拉框填充完成后调用 `restoreForm()`；
  `pcap` 下拉是异步加载的，`loadCaptures()` 完成后再补齐选中项。
- 清空点：左侧「重置表单」与「连通与速度测试 → 重置表单」调用 `clearForm()`，
  同时 `sessionStorage.removeItem`；全部恢复默认值时写入逻辑也会主动清 key。
- 说明：`sessionStorage` 按标签页隔离。正常提权流程会在**原标签页**自动刷新，
  因此表单一定恢复；若浏览器另开新标签，以原标签页为准（新标签没有旧标签的
  `sessionStorage`）。这是浏览器的存储边界，不是应用丢表单。

### 4.4 提权的现实边界

- 管理员账户 + 未被管控 → Windows UAC 确认框，点「是」生效；
- 标准用户 / 被管控 → Windows 自动弹**管理员凭据对话框**（输入有权限的账号）；
- 用户拒绝 / 公司组策略禁止请求提升 → 保持普通权限，功能降级；
- **做不到**「后台静默提权」：UAC 设计要求人工确认，绕过属于 UAC bypass（恶意行为），
  本项目不实现。

---

## 5. 首屏「准备检查」（C2，已实现）

### 5.1 什么时候出现

首次运行（`config\ui-first-run.json` 不存在）且页面加载后 `GET /api/selfcheck`
返回 `first_run: true` 时显示。检查是**只读**的：不写文件、不请求提权、不启动抓包。

用户点「受限进入」或五项全过自动进入后，前端 `POST /api/selfcheck/ack` 写标记；
之后启动不再显示。标记写失败（U 盘只读 / 目录被锁）**不阻塞**：本次照常进入主界面，
只提示一句，下次启动会再检查一次。想再看一次面板，删除 `config\ui-first-run.json`
后刷新即可（人工验收步骤之一）。

### 5.2 五项检查

| key | 检查内容 | 通过条件 | 失败时的修复入口 |
|---|---|---|---|
| `python` | Python 版本 / 位数 / 便携或系统 | ≥ 3.11 | Python 官网下载页 |
| `tshark` | 是否找到、版本号 | 能找到 tshark | Wireshark 下载页 + `python core\diagnose.py --interfaces` |
| `npcap` | Npcap 驱动 | 已安装 | Npcap 官网下载页 |
| `port` | 8787~8796 有可用端口，或已有本程序实例 | 任一成立 | `netstat -ano \| findstr :8787` |
| `admin` | 当前是否管理员 | 是管理员 | 直接弹「以管理员身份重启」权限卡 |

每项都带 `key` / `name` / `ok` / `detail` / `fix_kind` / `fix_url` / `fix_command`；
失败项的 `detail` 是可执行的一句话（缺什么、为什么、下一步），不是干巴巴的 ❌。

### 5.3 面板行为

- ✅/❌ 五项 + 失败项修复链接/命令；
- **[重新检测]**：重新 `GET /api/selfcheck`，不刷新页面；
- **[受限进入]**：检查没全过也进主界面；离线分析、连通与速度测试不被锁死，
  抓包类仍按非管理员置灰；
- 五项全过：自动显示「正在进入主界面」并 ack，不需要用户多点一次；
- 非首次运行（标记存在）或后端没有 `first_run` 字段（旧载荷）：**不显示**面板。

### 5.4 `自检.bat` 的位置

`自检.bat` 继续保留，作为**备用/离线**检查脚本：界面起不来、或维护者想逐项看
Python / tshark / Npcap / 管理员权限时用它。它不再是唯一入口，也不代替首屏检查。

---

### 5.5 缺组件时的行为与修复（v0.3.2）

**缺组件不再阻塞启动。** 启动期只做两件「物理上无法继续」的例外：没有 Python
解释器（启动器层）和 8787~8796 全被占用（无法起本地服务）。除此之外，tshark /
Npcap / 端口 / 管理员权限的缺失都只降低能力：程序照常进入主界面，首屏自检如实显示
❌，主界面按能力置灰不可用模式并给出修复指引；补齐后点「重新检测」**不需要重启**。

`GET /api/selfcheck` 与 `GET /api/app` 都会下发 `capabilities`（后端唯一出处）：

| 能力 | 判定 | 缺了时 |
|---|---|---|
| `probe`（连通与速度测试） | 恒为 true | 永远可用，不依赖 tshark/Npcap |
| `offline`（分析抓包文件） | 找到 tshark | 置灰，原因 `tshark` |
| `live`（实时抓包） | tshark 且 Npcap | 置灰，原因 `tshark` / `npcap` / `tshark|npcap` |
| `passive`（通信观察） | tshark 或内置 scapy | 置灰，原因 `tshark|scapy` |
| `reports` / `settings` | 恒为 true | 永远可用 |

非管理员**不**是能力硬门槛：抓包类功能仍按 C2 的「按需提权」权限卡处理，不置灰封死。

#### tshark / Wireshark

- 推荐：安装 Wireshark（安装包自带 `tshark.exe`），装完点「重新检测」；
- 已有 tshark（便携版或自定义目录）时，设置环境变量 `TSHARK_PATH` 指向
  `tshark.exe` 的完整路径，重启程序后生效；
- lite 公开包**不含** Wireshark / tshark，也不会自动下载（合规策略不变）。

#### Npcap

- 实时抓包与通信观察需要 Npcap 抓包驱动；装 Wireshark 时勾选 Npcap 即可，
  也可单独安装 Npcap；
- 分析已有抓包文件**不需要** Npcap；
- 装完点「重新检测」，不需要重启。

#### Python（唯一无法进入界面的缺件）

lite 公开包不带 `tools\python`，需要系统 **Python 3.11+**（安装时勾选
`Add python.exe to PATH`）。没有可用 Python 时启动器会给出友好提示并退出（退出码 2）；
`--dry-run --report` 会写结构化 `ok:false` / `error`，不弹框。这是物理例外，不是本批
「缺可选组件」的阻塞。

#### 端口 8787~8796 全被占用（物理例外）

本地服务起不来，界面无法打开；弹窗会提示关掉占用端口的程序或重启电脑后重试。
此时不是缺 tshark，也不会误报。

---

## 6. `start.bat`（Python 回退入口）

- 顶部会提示「推荐双击 `NetDiag.exe`；`start.bat` 为 Python 回退入口」；
- 默认以当前权限运行并提示「实时抓包 / 通信观察需要管理员时请在界面按需提权」；
- `start.bat --admin`：显式请求 UAC 后重启自身（仅这一条分支有 `-Verb RunAs`）；
- Npcap 未就绪时：**打开交互式安装向导**（`start /wait "" "<npcap 安装包>"`），
  提示「请在向导里完成安装」。免费版 Npcap 不支持 `/S` 静默安装（只有 OEM 版支持），
  所以不再尝试静默装；
- 没有内置 Npcap 安装包时打印官网链接，不联网下载；
- 保留三级 Python 回退与所有既有 `%ROOT%\...` 引用路径（`tests/test_launcher_contract.py` 守着）。

---

## 7. 常见启动问题

| 现象 | 可能原因 | 怎么查 / 怎么办 |
|---|---|---|
| 双击 `NetDiag.exe` 没反应 | 启动器被安全软件拦下 / 系统策略 | 改用 `start.bat` 看控制台报错；检查安全软件日志 |
| 弹「未找到可用的 Python 运行时」 | 没有 Python 3.11+，且包内无 `tools\python` | 安装 Python 3.11+ 并勾选 Add python.exe to PATH；或用内部离线包 |
| 弹「启动超时：30 秒内本地服务没有就绪」 | 端口全被占 / Python 导入失败 / Npcap 拦截 | 看 `logs\app-*.log`；关掉占用 8787~8796 的程序；重装/修复 Npcap |
| 弹「启动失败：Python 进程已退出」 | Python 版本过低、`core\` 文件不全 | 看日志里的 traceback；确认 exe 与 `core\` 在同一层 |
| 浏览器没打开但提示服务已就绪 | 默认浏览器关联异常 | 手动访问提示里的 `http://127.0.0.1:<port>/` |
| 首屏 Python ❌ | 系统 Python < 3.11 / 包内 `tools\python` 缺失 | 点「打开下载页」装 3.11+；或换带 `tools\python` 的内部包后「重新检测」 |
| 首屏 tshark ❌ | 没装 Wireshark / `TSHARK_PATH` 不对 / 包不完整 | 点「打开下载页」；或重新解压便携包；用 `python core\diagnose.py --interfaces` 确认网卡 |
| 首屏 Npcap ❌ | 驱动未装 / 安装未完成 | 点「打开下载页」装 Npcap；装完「重新检测」。离线分析不受影响 |
| 首屏端口 ❌ | 8787~8796 被别的程序占用 | 按提示 `netstat -ano \| findstr :8787` 找 PID 并关掉；或重启电脑后重试 |
| 首屏管理员 ❌ | 当前不是管理员（正常现象） | 实时抓包需要时点「以管理员身份重启」；只做离线/体检可直接「受限进入」 |
| 首屏检查每次启动都有 | 标记写不进去（U 盘只读 / 目录被锁） | 本次仍可用；换可写目录或去掉写保护后，下次点「受限进入」即可记住 |
| 右键「以管理员身份运行」后仍然没有权限 | 用户取消了 UAC，或被组策略禁止 | 用管理员账号；或让 IT 推送安装 Npcap/放行 |
| `start.bat` 双击闪退 | 控制台编码 / Python 路径问题 | 在 `cmd` 里运行 `start.bat` 看最后一行；确认 Python 3.11+ |

日志位置固定在 `<root>\logs\`：`app-*.log` 是启动/服务日志，`diag-*.log` 是诊断日志。

---

## 8. 维护者验证命令

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

# 5) C2：首屏自检 / 表单保留 / 权限卡静态接线
python -m unittest discover -s tests -p "test_selfcheck.py" -v
python -m unittest discover -s tests -p "test_startup_ui.py" -v
```

本机 UI 验收**不启动可见浏览器**：用 headless Edge + 独立 `--user-data-dir`
（例如 `%TEMP%\c2-edge`，用完删除），或直接看 `/api/selfcheck` 的 JSON。
**自动化里绝不点击真实提权**（`/api/elevate` 必须 mock），真机 UAC 由用户按
PR 的「需人工验收项」操作。
