# 常驻采集 agent（`core/agent.py`）

把「网络现在怎么样」按时间轴连续记下来：每 N 秒采一次网关 / DNS / 监测目标 /
无线链路，写进 `logs/history/`，给历史接口（`/api/history`）和将来的 AP 热力图用。

**它只采样，不判定。** 阈值只用来决定「要不要落一条事件」；健康度结论仍然由
`analyzer` + `verdict` 给。两条线不能混，否则同一个数字会出现两种口径。

---

## 1. 权限：普通用户就够

| 能力 | 需要什么 | 说明 |
|---|---|---|
| 网关 / DNS / 目标采样（ICMP、TCP） | **普通权限** | `IcmpSendEcho` + `connect()`，不需要管理员、不需要 Npcap |
| 读 SSID / BSSID / 信号 | **普通权限** | `netsh wlan show interfaces`，普通用户可读 |
| 写 `logs/history/` | **普通权限** | 项目目录可写即可（U 盘写保护另说） |
| tshark 抓包 | **普通权限**，前提是装 Npcap 时**没有**勾「Restrict Npcap driver's access to Administrators only」 | 勾了就必须管理员。默认安装是不勾的 |
| MTR / 路径探测（scapy raw socket） | **管理员** | 所以路径探测是「界面上按需提权」，不是常驻 agent 的职责 |

结论：**agent 本身永远不需要提权**。安装脚本用 `/rl limited`，就是为了让这一点在
计划任务里也是硬约束 —— 一个后台常驻、每次开机都跑的东西，绝不该长期持有管理员权限。

注意 `/rl limited` 约束的是**任务跑起来之后**的权限。**创建**这个任务（`schtasks /create
/sc onlogon`）在多数 Windows 上仍需要管理员：脚本自己不弹 UAC，没权限就直接失败。
这两件事经常被混成一句「要不要管理员」，装不上时先按 §2.1 分清是哪一种。

---

## 2. 安装 / 卸载

```bat
install-agent.bat     :: 建计划任务（登录时触发，延迟 1 分钟，普通权限）
uninstall-agent.bat   :: 删计划任务
```

两条脚本**只用 `schtasks`**：不装 Windows 服务（`sc create` 需要管理员，且卸载
不干净会留尸），不弹 UAC。

实际执行的命令（与脚本一致）：

```bat
schtasks /create /tn "NetDiag Agent" /sc onlogon /delay 0001:00 /tr "\"%~dp0NetDiag-agent.exe\" --daemon" /rl limited /f
schtasks /delete /tn "NetDiag Agent" /f
```

* `NetDiag-agent.exe` 不存在时，脚本会自动回落到
  `tools\python\pythonw.exe core\agent.py --daemon` —— `pythonw` 无控制台窗口，
  效果等价。两条路径都不存在时脚本报错退出，不会建一个跑不起来的任务。
* `/delay 0001:00` 是登录后等 1 分钟：避开开机时磁盘/网络还在抢带宽的那一段，
  否则记录下来的头几条样本全是「开机很慢」的假故障。
* **装完立刻想试**：`schtasks /run /tn "NetDiag Agent"`，不用重启。
* **卸载后**：已经跑着的进程不会自己退出（它是常驻的），注销或重启即止；
  想马上停用 `taskkill /f /im NetDiag-agent.exe`。
* 卸载**不删** `logs\history\`：历史是证据，删数据得是显式动作。

### 2.1 装不上：`schtasks` 被安全策略拦住

先把两种「装不上」分开 —— 根因不同，处理方式完全相反：

| 看到的输出 | 根因 | 处理 |
|---|---|---|
| `错误: 拒绝访问。` / `Access is denied.`，但 `where schtasks` 找得到文件、`schtasks /query /?` 能正常打印帮助 | **权限不够**：创建 `onlogon` 任务通常要管理员 | 用管理员打开 cmd，再运行 `install-agent.bat`。任务本身仍是 `/rl limited`，装完不必一直提权 |
| `PermissionError: [WinError 5] 拒绝访问。`，连 `schtasks /query` 都失败（`where schtasks` 却有文件） | **程序被执行策略拦住**：AppLocker / WDAC / 组策略 / EDR 把 `schtasks.exe` 拉黑 | **加管理员也没用** —— 拦的是进程，不是权限。走下面四条替代 |

一秒区分：直接跑一次 `schtasks /query /tn "NetDiag Agent"`。

* 查询本身报「拒绝访问」→ 程序被拦（哪怕任务真的存在也查不出来）；
* 查询能给出「任务不存在」→ 只是权限不够，按第一行处理。

**提示语**（设置页和命令行都该这么说，不要只回一句 `[WinError 5]`）：

> 安装失败：系统策略禁止运行 schtasks.exe（常见于公司 EDR / AppLocker / 组策略）。
> 这不是权限问题，用管理员运行也解不开。
> 采集本身照常可用：可以手动启动，或者按下面任一方式让它开机自启。

三句话缺一不可：**不是你的权限不够** → **采集没坏** → **下一步在哪**。
只回「安装失败」，等于把人扔在死路上。

#### 替代 1：手动建任务（图形界面，不经过 `schtasks.exe`）

`Win+R` → `taskschd.msc` → 右栏「创建任务」，逐字段照填：

| 页签 | 字段 | 值 |
|---|---|---|
| 常规 | 名称 | `NetDiag Agent` —— **必须逐字一致**，状态接口按这个名字查 |
| 常规 | 描述 | `NetDiag 常驻采样` |
| 常规 | 安全选项 | 选「只在用户登录时运行」；**不要**勾「使用最高权限运行」（等价于 `/rl limited`） |
| 触发器 | 开始任务 | 「登录时」，具体用户选当前账户 |
| 触发器 | 延迟任务 | `1 分钟`（等价于 `/delay 0001:00`） |
| 操作 | 程序或脚本 | `<安装目录>\NetDiag-agent.exe`；没有这个 exe 就填 `<安装目录>\tools\python\pythonw.exe` |
| 操作 | 添加参数(可选) | 前者填 `--daemon`；后者填 `"<安装目录>\core\agent.py" --daemon` |
| 条件 | 电源 | 取消勾选「只有在计算机使用交流电源时才启动」，笔记本用电池时也要采 |

名称差一个字，`GET /api/agent/status` 的 `installed` 就永远是 `false` —— 界面上会
一直写「未安装计划任务」，而任务其实在跑。这是最常见的「手动装完没生效」。

#### 替代 2：启动文件夹（零权限，代价是丢掉「延迟 1 分钟」）

`Win+R` → `shell:startup` → 右键「新建快捷方式」→ 目标填：

```bat
"...\NetDiag-agent.exe" --daemon
:: 没有 exe 时
"...\tools\python\pythonw.exe" "...\core\agent.py" --daemon
```

* 好处：不调 `schtasks`、不需要任何额外权限，掉电重启照样起；
* 代价 1：**没有 1 分钟延迟**。开机那两分钟磁盘和网络都在抢带宽，记下来的头几条
  样本会是「开机很慢」的假故障，还可能按「连续 2 次超阈值」落成事件；
* 代价 2：设置页的 `installed` 仍然是 `false`、`running` 是 `true`。**这是如实显示**
  （确实没有计划任务），不是 bug —— 卡片上写的是「未安装计划任务 / 手动启动的」。

#### 替代 3：只在需要时手动起

```bat
python core\agent.py --daemon     :: 无控制台常驻；想停就 taskkill 或注销
python core\agent.py --once       :: 只采一轮，验证能不能采到
```

适合「复现一次抖动、采半小时就够」的场景。代价：**重新登录后不会自己回来**。

#### 替代 4：换一台策略允许的机器装一次

多机部署时最省事的对比手段：同一套安装包，在允许 `schtasks` 的机器上装一次，
就能证明「是这台机器的策略，不是安装包坏了」。

#### 策略允许的机器上，正常应该看到什么

| 时刻 | 期望 |
|---|---|
| 点「安装」立刻 | `GET /api/agent/status` → `installed=true`、`state="stopped"`（还没到触发点）、`last_error=""` |
| 任务计划程序里 | 任务名 `NetDiag Agent`；触发器「登录时」+ 延迟 `1 分钟`；「使用最高权限运行」未勾选；「上次运行结果」`0x0` |
| 登录后 1 分钟内 | `state="running"`；`logs/history/YYYY-MM-DD.jsonl` 出现当天第一条样本；设置页「最近一次采样」从「尚无采样记录」变成具体时间 |
| 卸载后 | `installed=false`、`state="stopped"`；**已在跑的进程不会自己退出**（注销或 `taskkill /f /im NetDiag-agent.exe`）；`logs/history/` 不删 |

#### 自检三条命令

```bat
where schtasks                                    :: 文件在不在（在 = 不是「命令找不到」）
schtasks /query /tn "NetDiag Agent" /fo LIST /v   :: 能不能查（查不了 = 进程被拦）
schtasks /run   /tn "NetDiag Agent"               :: 装好后立刻试一次，不用重新登录
```

接口失败时 `error` 字段是 `schtasks` 的**原始输出**（截断 400 字符），不吞不改写。
排障先看那行原文 —— 「拒绝访问」和「系统找不到指定的文件」是两个完全不同的问题。

---

## 3. 配置（`config/agent.json`）

不存在时用默认值，改任何一项都不必重启 agent —— 主循环每轮重读配置。

| 键 | 默认 | 说明 |
|---|---|---|
| `interval_s` | `10` | 采样间隔，**只能取 5 / 10 / 30 / 60**。非法值读的时候回落 10、写的时候报错 |
| `targets` | `[]` | 监测目标，**最多 3 个**。`{"key": "公司官网", "host": "example.com", "port": 443}`；省略 `port` = 走 ICMP |
| `thresholds.rtt_ms` | `120` | 时延阈值（毫秒） |
| `thresholds.jitter_ms` | `40` | 抖动阈值（毫秒） |
| `thresholds.loss_pct` | `2` | 丢包阈值（百分比） |
| `retain_days` | `7` | 样本保留天数 |
| `event_retain_days` | `30` | 事件保留天数 |
| `icmp_count` | `2` | 每轮每目标发几个包 |
| `icmp_timeout_ms` | `800` | 单包超时 |
| `tcp_timeout_s` | `1.5` | TCP 建连超时 |

改间隔的两种方式：

```bat
python core\agent.py --interval 30     :: 写配置，立即返回
```
或直接编辑 `config/agent.json`。**下一轮生效**：正在跑的那一轮不会被打断，
日志里会留一行 `采样间隔 10s → 30s，下一轮生效`。

> 只有四档是刻意的。1 秒会把本机 DNS / 网关打成压测；600 秒又让「连续 2 次超阈值」
> 变成「连续 20 分钟都坏才算」，事件形同虚设。

---

## 4. 数据格式

### 4.1 样本 `logs/history/YYYY-MM-DD.jsonl`

一行一条，UTF-8，无 BOM。字段**必须齐**（将来算热力图要按时间轴对齐）：

```json
{
  "t": "2026-11-11T16:57:48+08:00",
  "epoch": 1794387468.525,
  "interval_s": 10,
  "gateway": {"rtt_ms": 0.5, "loss_pct": 0.0, "jitter_ms": 0.5, "method": "icmp",
              "ip": "192.168.1.1", "ok": true},
  "dns":     {"rtt_ms": 0.5, "loss_pct": 0.0, "jitter_ms": 0.5, "method": "icmp",
              "ip": "172.17.34.3", "ok": true},
  "targets": [{"key": "公司官网", "rtt_ms": 23.1, "loss_pct": 0.0, "jitter_ms": 2.4,
               "method": "tcp", "port": 443, "ip": "203.0.113.9", "ok": true}],
  "wlan": {"ssid": "RR", "bssid": "50:4f:3b:e2:98:93", "rssi_dbm": -54,
           "rx_mbps": 433.3, "tx_mbps": 433.3, "band": "5 GHz", "channel": 153}
}
```

| 字段 | 说明 |
|---|---|
| `t` | 本地时间，**带时区偏移**。跨时区导出 CSV 时不会被误读成本地时间 |
| `epoch` | Unix 秒，聚合 / 查询用它排序，避免解析 ISO |
| `interval_s` | 本轮使用的采样间隔，灌进 `interval_s` 是为了让「覆盖率」算得出来 |
| `gateway` / `dns` | 测量块；**拿不到该角色时为 `null`**（没有默认路由 / 没配 DNS）。`null` = 没采样，不是 0 丢包 |
| `targets` | 每个配置目标一项，顺序与配置一致；`key` 用于事件归属 |
| `wlan` | 7 个字段**恒在**，取不到写 `null`。不删键，否则热力图没法对齐 |

测量块里 `method` 的三种取值：

* `icmp` —— 原生回显，RTT 是 ICMP 往返；
* `tcp` —— 建连耗时。**注意**：如果有 `degraded: true` + `method_note: "icmp_blocked"`，
  说明 ICMP 被中间设备丢了，这条 RTT 是 TCP 握手时间，和 ICMP 的数值不可直接比；
* `none` —— 目标为空，什么都没测。

`rtt_ms` / `jitter_ms` 在失败时为 `null`（不是 0）——0 会被下游当成「极快」。

### 4.2 事件 `logs/history/events.jsonl`

```json
{"t": "2026-11-11T17:02:08+08:00", "epoch": 1794387728.1, "target": "gateway",
 "type": "rtt", "value": 214.0, "threshold": 120.0, "duration_s": 10.0,
 "bssid": "50:4f:3b:e2:98:93", "rssi_dbm": -54}
```

* `target`：`gateway` / `dns` / 目标 `key`；
* `type`：`rtt` / `jitter` / `loss`；
* `duration_s`：从第一次越线到落事件之间经过的秒数（连续 2 次 = 一个间隔）；
* `bssid` / `rssi_dbm`：落事件那一刻的无线链路快照 —— 「这个时延是挂在哪个 AP 上发生的」
  是排障最关键的一格，事后再查是查不回来的。

**判定规则**：同一序列连续 **2 次**超阈值才落 1 条；条件持续不恢复**不会**重复报；
恢复后再次越线才算新事件。单次尖刺（路由器排队、无线重传）属于常态，一超就报会
让事件列表全是噪声。

### 4.3 人工标记 `logs/history/marks.jsonl`

`POST /api/history/mark` 写入，用于在时间轴上标注「这半小时是我在重启路由器」。
格式见 `docs/data-contract.md`。

### 4.4 怎么读这些数据

不用自己解析 JSONL —— 前台服务（`core/server.py`）已经开了五个只读接口：

| 想干什么 | 接口 |
|---|---|
| 画趋势（按 1m / 5m / 1h 分桶） | `GET /api/history?from=&to=&bucket=1m` |
| 看「什么时候抖过」 | `GET /api/history/events?from=&to=` |
| 打一个标记 / 看标记 | `POST /api/history/mark` / `GET /api/history/marks` |
| 拿去 Excel 或贴进周报 | `GET /api/history/export?format=csv|md&from=&to=` |

两点容易踩：

* 接口里的 `series[].t` 是 **epoch 秒**（前端画横轴用），不是 ISO 字符串；
* 事件类型在接口层叫 `latency` / `jitter` / `loss`，采集侧写的是 `rtt` ——
  同一个测量，两处叫法不同（`docs/data-contract.md` §7.4）。

样本**不落报告**：报告是「这一次诊断」的快照，历史是「这一周稳不稳」，
两者混在一份文件里会让报告的结论边界变糊。

---

## 5. 保留与滚动

| 对象 | 规则 |
|---|---|
| 样本分片 | 一天一个；单文件超 5 MB 滚动成 `YYYY-MM-DD.1.jsonl`、`.2`… |
| 样本保留 | 7 天，**启动时**清掉过期分片（含滚动出来的 `.N`） |
| 事件保留 | 30 天，启动时整文件重写剔除过期条目 |

启动清理只做一次，不在主循环里反复扫盘 —— 一个每 10 秒扫一遍目录的常驻进程
在 U 盘上会很显眼。

另外 `logstore.prune()` 对**整个 `logs/` 有 100 MB 总量预算**（按最旧优先删除，
跳过当天文件）。7 天样本按 400 B × 8640 条/天估算约 24 MB，离预算很远；
真到了预算上限，被删的也是最旧的分片 —— 和保留策略同向，不会误删当天数据。

样本**不进诊断包**：`core/diagpack.py` 只收 `logs/*.log`（顶层 `.log` 文件），
`history/` 是子目录，不会被卷进 zip。历史数据比日志大一个量级，混进去会让
「把日志带回来」这件事变得没人愿意做。

---

## 6. 排障

| 现象 | 看什么 |
|---|---|
| 点「安装」报「拒绝访问」/ `[WinError 5]` | 先分清是**权限不够**还是**`schtasks.exe` 被策略拦**：`schtasks /query /tn "NetDiag Agent"` 能不能跑。详见 §2.1 |
| 装完了设置页还写「未安装计划任务」 | 任务名不是逐字 `NetDiag Agent`，或装的是「启动文件夹快捷方式」（那本来就没有计划任务，见 §2.1 替代 2） |
| 历史是空的 | `python core\agent.py --status` 看 `history_dir` 与 `samples_total`；再 `--once` 看单轮能不能采到 |
| 网关一直是 `null` | 没有默认路由（只有直连网段 / 断网）。`gateway` 为 `null` 是正确结果，不是 bug |
| 目标 `method` 变成 `tcp` 且 `degraded` | ICMP 被中间设备丢了。这是设计行为，不是故障 |
| 事件一条都没有 | 阈值没超，或者只超了一次（需要连续 2 次）。先看 `--once` 的实际数值 |
| 日志里每分钟一条 WARN | 采样在持续失败（断网 / 拔盘）。同一条告警每分钟最多一行，被压掉的条数会在下一行里合并显示 |
| 起了两个 agent | 不会：`logs/agent.pid` 是单实例锁。上一轮崩溃留下的死 PID 会被自动覆盖 |

---

## 7. 相关文档

* `docs/data-contract.md` —— 历史接口的字段契约（`series` / `coverage.gaps` / CSV 列头）
* `docs/logging.md` —— `logs/` 目录的总体约定
* `docs/startup.md` —— 前台服务的启动链路（与 agent 是两条独立的进程）
