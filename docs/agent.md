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
