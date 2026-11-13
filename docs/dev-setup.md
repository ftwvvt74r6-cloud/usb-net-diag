# 开发环境准备（公司机 / 家里机）

> 本文件全部使用**相对路径**。无论仓库放在哪个盘、哪台机器，按"仓库根目录"理解即可。

## 0. 一句话

这个项目**不使用 venv、不安装任何 pip 依赖**（AGENTS.md 硬约束）。
运行与测试只需要 **Python 3.11+ 标准库**；抓包需要 tshark（包内自带）与 Npcap 驱动。

## 1. 两种环境

### A. 完整环境（推荐：公司机 / 需要真抓包）

仓库**不包含** `tools/`（约 360MB，`.gitignore` 排除）。因此：

1. 从公司机把整个工作目录压缩拷贝（U 盘/网盘）
2. 回家解压到任意位置，用 VSCode 打开该目录
3. 直接跑任务：`tools/python/python.exe -m unittest discover -s tests`

`tools/python` 自带 3.11.9 + scapy；`tools/WiresharkPortable` 自带 tshark 4.7；
Npcap 安装器在 `tools/npcap-1.79.exe`（每台机器装一次）。

### B. 仅 git 环境（轻量：只改代码/跑单测）

1. 安装 Python **3.11.x**（不要 3.12+：项目有 3.11 兼容红线，历史出过 f-string 语法事故）
2. `git clone <仓库>` 后，在 VSCode 里把默认解释器选成该 3.11
3. 跑全量测试；依赖 tshark/Npcap 的用例会自动 skip（这是设计好的）
4. 需要真抓包时再拷 `tools/` 或本机装 Wireshark+Npcap

可选：Node.js（用于 `node --check` 检查 `ui/v2/js/*.js` 语法）。

## 2. VSCode 配置

仓库自带 `.vscode/tasks.json`，`Ctrl+Shift+B` / 命令面板 `Tasks: Run Task` 可直接用：

| 任务 | 用途 |
|---|---|
| 跑全量测试 | `python -m unittest discover -s tests` |
| 3.11 语法检查 | `compileall -q core mcp tests`（提交前必跑） |
| 重生成接口文档并自检 | `scripts/gen_api_doc.py --check 0.95` |
| 构建自包含包 | `scripts/build_release.py --with-tools --with-npcap --skip-verify` |
| 跑单个测试文件 | 改 `-p` 后面的文件名 |

推荐插件：Python、GitLens（可选）。
不需要 C# 插件：启动器由 `scripts/build_launcher.py` 调 `csc` 编译。


### 2.1 本地创建 `.vscode/tasks.json`（个人配置，不入库）

`.vscode/` 在 `.gitignore` 里，所以任务配置**不进仓库**；在每台机器上把它粘到
仓库根目录的 `.vscode/tasks.json` 即可（两台机器各粘一次）：

```jsonc
{
  "version": "2.0.0",
  "tasks": [
    { "label": "跑全量测试", "type": "shell",
      "command": "${workspaceFolder}/tools/python/python.exe",
      "args": ["-m", "unittest", "discover", "-s", "tests"],
      "group": { "kind": "test", "isDefault": true } },
    { "label": "3.11 语法检查", "type": "shell",
      "command": "${workspaceFolder}/tools/python/python.exe",
      "args": ["-m", "compileall", "-q", "core", "mcp", "tests"] },
    { "label": "重生成接口文档并自检", "type": "shell",
      "command": "${workspaceFolder}/tools/python/python.exe",
      "args": ["scripts/gen_api_doc.py", "--check", "0.95"] },
    { "label": "构建自包含包", "type": "shell",
      "command": "${workspaceFolder}/tools/python/python.exe",
      "args": ["scripts/build_release.py", "--with-tools", "--with-npcap", "--skip-verify"] },
    { "label": "跑单个测试文件（改 -p）", "type": "shell",
      "command": "${workspaceFolder}/tools/python/python.exe",
      "args": ["-m", "unittest", "discover", "-s", "tests", "-p", "test_v2_backend.py"] }
  ]
}
```

家里若用系统 Python，把 `${workspaceFolder}/tools/python/python.exe` 换成 `python`。
## 3. 跨机器同步进度

同步的是 **git 仓库**，不是文件：

```bash
# 公司
git checkout -b feat/xxx && git push -u origin feat/xxx

# 家里
git fetch origin && git checkout feat/xxx && git pull

# 回家只想看最新主干
git checkout main && git pull --ff-only
```

不要用 OneDrive/网盘同步工作区（`.git` 会冲突）。
`logs/`、`reports/`、`captures/` 是运行产物，不入库。

## 4. 提交前自检（与 CI 一致）

```bash
<python> -m compileall -q core mcp tests          # 3.11 语法
<python> scripts/gen_api_doc.py --check 0.95      # 注释覆盖率
git status --short                                 # 确认没有 tools/ logs/ 等产物
```

## 5. 家里做真机测试的注意

- Npcap 每台机器只需装一次；安装时**不要**勾"仅管理员可访问"
- 无线相关字段（SSID/RSSI/协商速率）需要本机连 Wi-Fi 才有
- 公司内网环境与家用网络差异大：**不要预设网络结构**（代理/DNS/网关都可能不同），
  这正是"流程 C 陌生环境测试"要覆盖的

