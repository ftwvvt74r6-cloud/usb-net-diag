# 诊断包导出（给分发者 / 一线同事）

> 实现：`core/diagpack.py`（收集 + 脱敏 + 打包）、`core/sanitize.py`（脱敏规则）。
> 三个入口共用同一个 `build()`，产物完全一样：**默认脱敏、绝不联网、不自动上传**。

工具不联网上报。同事遇到问题时，让他**一键导出诊断包**，把 zip 原样发回来即可。
这个包足够回答「谁在什么环境跑了什么、哪一步失败、崩在哪」，但**不含**对方的
内网 IP / 域名 / 用户名 / MAC 原值。

---

## 一、让同事怎么导出（三个入口，任选其一）

### ① 界面按钮（最推荐）

1. 双击 `start.bat`（或 `NetDiag.vbs`）打开界面；
2. 点右上角 **「导出诊断包」**；
3. 弹窗会显示 zip 的**完整路径**、大小和文件数；
4. 点确定，然后去那个路径把 zip 发回来。

默认产物目录：`<工具目录>\logs\exports\`。

### ② 双击 `导出诊断包.bat`

在工具根目录双击 `导出诊断包.bat`。窗口里会打印 zip 的完整路径，按任意键关闭。
它优先用随身 Python（`tools\python\python.exe`），没有就回落到系统 `python`。

给同事的可复制话术：

> 双击工具目录里的「导出诊断包.bat」，看到 “诊断包已生成：……” 后，
> 把那个 .zip 文件直接发我，不用解压、不用改名。

### ③ 命令行（批量 / 脚本用）

```bat
tools\python\python.exe core\diagnose.py --export-diag
tools\python\python.exe core\diagnose.py --export-diag --include-reports
tools\python\python.exe core\diagnose.py --export-diag --out D:\tmp\diag
```

| 参数 | 作用 |
|---|---|
| `--export-diag` | 只导出诊断包后退出（不抓包、不分析） |
| `--include-reports` | 额外附最近 3 份报告（`.md` + `.json` 成对） |
| `--raw` | **不脱敏**（危险，见第四节） |
| `--out DIR` | 指定输出目录；省略 = `logs/exports/` |

文件名固定为：

```
NetDiag-diag-<机器名sha1前8位>-<YYYYmmdd-HHMM>.zip
例：NetDiag-diag-3f2a9c1d-20261107-2046.zip
```

* 机器名**不写进文件名**，只写哈希 —— 能区分「不同机器」，但反推不出机器名。
* 同一分钟导出第二个包时自动加 `-2` / `-3`，不会覆盖前一个。
* 输出目录不存在会自动创建（`mkdir(parents=True)`）。

---

## 二、包里有什么

| 条目 | 内容 | 数量 |
|---|---|---|
| `README.txt` | 包说明：是否脱敏、清单、被跳过的文件、怎么发回 | 1 |
| `env.json` | 环境快照：版本 / Windows 版本 / 管理员 / Npcap / tshark / Python / 配置指纹 | 1 |
| `logs/*.log` | 启动日志 `app-*.log`、诊断日志 `diag-*.log`（含 traceback） | 最近 30 天 |
| `runs/*.json` | 每次分析一条：模式 / 参数 / 耗时 / level / 错误码 / tshark 版本 | 最近 20 条 |
| `crashes/*.txt` | 未捕获异常快照（类型 / 消息 / traceback / 环境摘要） | 最近 10 份 |
| `reports/*.md|.json` | 完整诊断报告（仅 `--include-reports`） | 最近 3 份 |

包内路径一律用 `/`，文件名尽量 ASCII（Windows 下中文名可能乱码）。

---

## 三、脱敏规则（默认开启）

| 对象 | 原文示例 | 包内形态 | 说明 |
|---|---|---|---|
| 私有 IP | `192.168.1.100` | `192.168.1.***#25c9` | 保留网段（诊断需要知道是哪个网段），主机位打码 |
| 公网 IP | `8.8.8.8` | `8.8.***.***#53a6` | 保留前两段，后两段打码 |
| 域名 | `www.company.com` | `w**.c******.com#37f4` | 每段留首字符，顶级域保留 |
| 用户目录 | `C:\Users\alice\x.log` | `C:\Users\<user>\x.log` | 用户名换 `<user>`，文件名保留 |
| 用户目录变体 | `%USERPROFILE%\alice`、`C:\Users/alice/x.log`、`C:\Documents and Settings\alice` | `<home>\<user>`、`C:\Users/<user>/x.log`、`C:\Documents and Settings\<user>` | `%USERPROFILE%` / `%HOMEPATH%`、正反斜杠混用、含空格的用户目录都覆盖 |
| UNC 路径 | `\\fileserver\share\z` | `\\<host>\share\z` | 主机名段换 `<host>`，共享名保留（排障需要） |
| 前导零 IP | `192.168.001.100` | `192.168.1.***#25c9` | 先归一化再判断公私网，不因前导零跳过；与标准写法**同一伪名** |
| **文件名** | `192.168.1.100.pcap`、`www.company.com.pcap` | `192.168.1.***#25c9.pcap`、`w**.c******.com#37f4.pcap` | 扩展名保留，stem 里的 IP / 域名照常脱敏（用户名见下） |
| MAC | `aa:bb:cc:dd:ee:ff` | `aa:bb:cc:**:**:**#3170` | 前 3 字节（厂商）保留，尾 3 字节打码 |
| 其它绝对路径 | `D:\builds\agent-7\NetDiag\...\tshark.exe` | `<root>\Wireshark\tshark.exe` | 盘符与上层目录隐去，留最后两段 |
| IPv6 | `2001:db8::1` | `<ipv6>#1eec` | 整段隐去（前缀也可能定位到单位）；IPv4-mapped（`::ffff:192.168.1.100`）同样整段 `<ipv6>#8514` |

### 伪名后缀 `#xxxx`

`#` + `sha1(小写原文)` 的前 4 位十六进制。作用只有一个：**同一对端在包里出现多次时，
后缀相同**，维护者能看出「同一个 IP 出现了 37 次」，但**无法**从后缀反推原文。

### 保留不动的信息

* **端口**、协议、方向、错误码、版本号（排障必需，SPEC 明确不打码）；
* **普通**文件名（`faults_demo.json` / `app-20261107.log` 不会被当成域名误伤）；
  但 stem 里出现 **IP / 域名**时会脱敏，只保留扩展名；
* **裸用户名不会被脱敏**：只有出现在「路径 / 邮箱」上下文里（`C:\Users\alice\...`、`alice@corp.com`）
  才识别。像 `alice.pcap` 这种**纯名字当文件名**的，包内会保持原样 ——
  所以抓包文件名建议用日期/场景命名（`20261107-office.pcap`），不要把用户名写进文件名；
* 时间戳。

### 三条保证

1. **幂等**：已经脱敏过的文本再跑一遍不会二次打码（`***` / `#25c9` / `<user>` 不会被再次匹配）。
2. **脱敏失败就跳过**：某个文件读不了 / 处理异常时，该文件**不会进包**，只会在
   `README.txt` 的「没有收录 / 被跳过的文件」里留一行。**宁可少一个文件，也不导出原文。**
3. **写 zip 前做泄漏自检**：把脱敏过程中识别出的原值 token，对每个条目的**名字 + 内容**
   （以及 README）再扫一遍；任何 token 仍出现就**抛异常、不生成 zip**。错误信息只报
   命中类别（如「域名」），不打印原值。**宁可导出失败，不可泄露。**

> zip 条目名里的 `*` / `<` / `>` 会换成 `_`（Windows 解压不允许这些字符），例如
> `192.168.1.100.pcap` 在包内显示为 `192.168.1.___#25c9.pcap`；脱敏效果不变。

---

## 四、`--raw`：什么时候用、怎么防事故

`--raw` 关闭脱敏，保留原始 IP / 域名 / 用户名 / MAC。只在两种情况下用：

* 维护者明确要求原值（例如要复现某个内网路由问题）；
* 包已经通过内部可信渠道传递，且对方确认可以接收。

开启后会有**两道警告**：

1. 控制台打印 `[警告] --raw 已生效：本包未脱敏……`（stderr）；
2. 包内 `README.txt` 顶部写「⚠ 未脱敏（--raw）：已保留原值」。

> 不要把 `--raw` 的包贴到工单、论坛、聊天群或任何公开位置。

---

## 五、体积护栏

| 规则 | 阈值 | 超限行为 |
|---|---|---|
| 单文件 | 10 MB | 跳过该文件，写进 `README.txt` |
| 包内文件总量 | 100 MB | 按收集顺序（env → logs → runs → crashes → reports）跳过后面的文件，写进 README |

正常情况下 `logs/` 自己有更小的上限（单文件 5 MB、总量 100 MB，见 `docs/logging.md`），
所以诊断包一般只有几百 KB 到几 MB。

---

## 六、包里**没有**什么

* **不含 pcap / pcapng 抓包文件，也不含任何报文载荷** —— 体积大、可能带业务数据；
  需要抓包时让同事单独发 pcap（并说明用途）。
* 不含 `config/ai-config.json` 里的 AI Key，也不含 `config/app-config.json` 的任何值；
  `env.json` 只保留 `config_sha256` 指纹。诊断日志里若出现 AI 模型 / 地址，其中的
  域名与 IP 同样会脱敏。
* **工具不联网、不上传任何数据**：zip 只在本机生成，发不发、发给谁完全由使用者决定。

---

## 七、怎么汇总多个包（维护者视角）

1. **先看文件名**：`NetDiag-diag-<机器哈希>-<时间>.zip`。
   机器哈希相同 = 同一台机器；时间告诉你哪份更新。
2. **解压后先读 `README.txt`**：确认是否脱敏、哪些文件被跳过（跳过可能正是问题线索）。
3. **`env.json` 对账**：版本 / Windows / 管理员 / Npcap / tshark 版本。
   同一份抓包两次结论不同时，先比 `config_sha256` 与 tshark 版本。
4. **`runs/` 看时间线**：按文件名排序（`YYYYmmdd-HHMMSS`）即时间序，
   看 `ok` / `error_code` / `duration_ms` / `level` 定位「哪一步开始失败」。
5. **`crashes/` 看栈**：`文件:行` 是定位代码的最短路径；
   `fatal-*.log` **不在**诊断包里（只收 `*.txt`），需要进程级崩溃现场时让同事单独发。
6. **`logs/*.log` 看过程**：traceback、tshark 命令行、网卡选择、服务启动/退出。
7. 多个包对照时，用**伪名后缀**判断是不是同一个对端：不同机器上同一个公网 IP
   会得到同一个 `#xxxx`（因为哈希只看原文），可以直接横向比。

建议的归档命名：`<日期>_<同事/现场>_<机器哈希8位>.zip`，不要改包内文件名。

---

## 八、常见问题

| 现象 | 处理 |
|---|---|
| 双击 bat 窗口一闪而过 | 正常会有 `pause`；如果确实闪退，说明 bat 被改过或路径含特殊字符，改用界面按钮 |
| `[ERROR] 导出失败` / 返回码非 0 | 检查 `logs\` 是否可写、磁盘是否满；把窗口里的错误发回维护者 |
| 界面按钮提示「导出失败」 | 确认 `logs\` 可写；也可改用 bat 或命令行 |
| 包很小 / 只有 README | 看 README 的「没有收录 / 被跳过的文件」；常见原因：刚装好还没跑过诊断（无 runs）、日志超过 30 天 |
| 想确认脱敏是否生效 | 解压后搜索同事的 IP / 域名 / 用户名（**文件名也要搜**）：应搜不到；能搜到 `#xxxx` 伪名即正常。条目名里的 `*` 显示为 `_` 属正常 |
| 需要原始值 | 维护者明确要求时，用 `--export-diag --raw`，并走可信渠道 |
| zip 打不开 | 传输中断，重新导出 / 重新发送；不要用文本方式发 zip |

---

## 九、实现与测试索引

| 文件 | 作用 |
|---|---|
| `core/sanitize.py` | 纯函数：`mask_text` / `mask_obj` / `collect_tokens` / `pseudonym`（无 I/O、无网络 import） |
| `core/diagpack.py` | `build(out_dir=None, include_reports=False, raw=False) -> Path`；写 zip 前调 `_verify_no_leaks` 自检 |
| `core/diagnose.py` | CLI：`--export-diag` / `--include-reports` / `--raw` / `--out` |
| `core/server.py` | `POST /api/diagpack` → `{ok, path, size, entries}` |
| `ui/index.html` | 顶部按钮 `#diagpack`（「导出诊断包」） |
| `导出诊断包.bat` | 双击入口（优先 `tools\python\python.exe`，否则 `python`） |
| `tests/test_sanitize.py` | 脱敏规则 / 幂等 / 不联网 |
| `tests/test_diagpack.py` | 结构 / 数量上限 / 护栏 / 三个入口 / README |

包内 `README.txt` 是给**收到包的人**看的，`docs/log-collection.md`（本文件）是给
**分发者**看的；两者内容不一致时以代码为准。
