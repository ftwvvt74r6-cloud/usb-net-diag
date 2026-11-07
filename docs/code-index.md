# 代码定位索引（改哪里、哪一行）

> 目的：**省掉全仓扫描**。`core/` 约 4400 行，通读一遍大约 4 万 token；
> 这张表把 24 个既有问题 + **3 个由样本实跑新暴露的缺陷（#27~#29）** 定位到「文件:行」，
> 直接跳到那段看 30 行即可。
>
> 行号基于 `v0.1.0` 单一提交（`0bd5dbf`）。若已改动，用函数名搜索（表里都给了函数名）。

---

## 一、必改（会造成误判 / 泄露 / 无法维护）

| # | 问题 | 位置 | 现状 | 改法 | 任务 |
|---|---|---|---|---|---|
| 1 | 中文文案当接口值 | `core/analyzer.py` `_row()` ≈ L128；`core/verdict.py` `LAYER_RANK`/`CAT_RANK` ≈ L16-27 | `layer="L4 传输层"`、`severity="严重"` 被 UI/Markdown/AI/MCP 消费 | 新增机器码枚举 + 新字段，旧字段保留 | T01 T03 T05 |
| 2 | **TCP 指标无方向** | `core/analyzer.py` L280-308（`retrans` L286 / `dup_ack` L291 / `ooo` L294 / `zero_win` L297 / `win_full` L300） | 全部按流累加，分不清上行/下行，也分不清零窗口由谁通告 | `extract/aggregate.DirCounters` 按方向累计 → `TcpFeatures.dir_totals` | T04 |
| 3 | **AI 全量外发** | `core/ai.py` `build_messages()` L307-397（会话 L353、HTTP L366、DNS L373） | 私网 IP、公网 IP、DNS 服务器 IP、Host、URI、SNI、帧号全发云端 | `egress/sanitize` 在外发出口统一脱敏 | T08 |
| 4 | **URI 口令泄露** | `core/analyzer.py` L362-364 采集 → L766-770 拼进 `finding` | `?password=xxx` 前 50 字符进报告/AI/MCP | finding 只留 host + 参数名，值抹掉 | T09 |
| 5 | Basic 凭证进内存 | `core/analyzer.py` L359-361 | `http.authorization[:80]` 存进 `st["basic_auth"]` | 只记「存在 + 长度」，不存值 | T09 |
| 6 | **采集有效性只看空包** | `core/diagnose.py` L165-174；`core/verdict.py` `build()` L176-195 | 只有 `packets==0` 才提示；1 KB 抓包照报「各层正常」 | `Sufficiency` 闸门 + `VERDICT.INSUFFICIENT` | T06 |
| 7 | 单例任务槽 | `core/server.py` `JOB` L49-58、`start_job()` L104-121、`/api/status` L282-287 | 无 job_id、无取消、每次回传全量 result | `api/jobs.JobStore` | T11 |
| 8 | 无静态资源路由 | `core/server.py` `do_GET` L277-281 | 只回 `/` 与 `/index.html` → UI 只能单文件 | 加 `GET /static/*` | T12 |
| 9 | 上传无上限 | `core/server.py` `/api/upload` L370-388 | 按 `Content-Length` 直写，无上限/无校验 | 加 `max_upload_mb` + 分片 | T12 |
| 10 | 扁平 import + sys.path | `core/diagnose.py` L16-23、`core/server.py` L33-42、`core/analyzer.py` L22 | `from tshark import ...` 依赖 `sys.path.insert(0,'core')` | 改包结构 + 相对导入（分阶段） | T01 T02 |
| 11 | `conn_refused` 误判 | `core/analyzer.py` L504 | `sum(1 for x in streams if x["rst"])` → 正常关闭后的 RST 也算「端口没开」 | 只算「SYN 后 0~1 包内 RST」 | T07 |
| 12 | `dns_timeouts` 公式 | `core/analyzer.py` L516 | 查询数 − 响应数，重传查询/多响应会失真 | 按 (qname,txid) 配对 | T07 |

## 二、该清（低风险，顺手做）

| # | 问题 | 位置 | 改法 | 任务 |
|---|---|---|---|---|
| 13 | 死代码 `SEV_ORDER` | `core/analyzer.py` L85 | 删除 | T07 |
| 14 | 永不命中的过滤 | `core/verdict.py` `compute_layers()` L88 | `category != "安全观察"` 永远为真（安全项的 layer 是「安全观察」）；删掉并注释排除机制 | T07 |
| 15 | 报告覆盖写 | `core/report.py` `save()` L263-266 | `<stem>.md` 直接覆盖，无审计价值 | 带时间戳命名（`render/json_report.save`） | T05 T14 |
| 16 | `verdict.build()` 调两次 | `core/report.py` L274（`diagnose.py` L176 已算过一次） | 复用 `result["verdict"]`，别再算 | T05 |
| 17 | Npcap 靠文本判断 | `core/tshark.py` `npcap_installed()` L236-245 | 判断 `sc query` 输出里的 `RUNNING` 字样（本地化风险） | 查注册表/驱动目录（`platform/winapi`） | T02 |
| 18 | MCP 原文出口 | `mcp/wireshark-mcp/server.py` L168 | 完整 Markdown 直接交给 Agent | `_text()` 前脱敏 | T10 |
| 19 | CI 只编译不改行为 | `.github/workflows/smoke.yml` L28-32 | 只有 `compileall` + 启动器契约 | 加规则测试 job（ubuntu，喂 `features.json`） | T15 |
| 20 | pcap 被 gitignore | `.gitignore` L22-23（`*.pcap`）+ L28-30（`!captures/faults_demo.pcap`） | 新增 `tests/pcap_samples/*.pcap` 会被静默忽略 | 脚本生成样本，或显式加 `!` 例外 | T15 |

## 三、要保护（改了会出事故）

| # | 对象 | 位置 | 为什么不能动 |
|---|---|---|---|
| 21 | 零窗口文案（现有是**对的**） | `core/verdict.py` L143-145 | 「接收端处理不过来」方向正确。规划文档把它写成「服务端瓶颈」是**错的**，别照着改 |
| 22 | 启动器契约测试 | `tests/test_launcher_contract.py` | 守着 `start.bat` 的 `%ROOT%` 引用；改它等于放行破坏启动 |
| 23 | 协议自适应体检 | `core/probe.py`（946 行，`_identify()` ≈ L472） | 全项目最具差异化的部分，只搬不改 |
| 24 | 通信观察（被动监听） | `core/passive.py`（483 行） | scapy 2.8 的唯一使用者，只搬不改 |
| 25 | 盘符自适应 | `core/bootstrap.py` `gen_configs()` L29-58 | 每次启动重写 mcp/harness 配置，不要改成「只在缺失时写」 |
| 26 | 示例抓包 | `captures/faults_demo.pcap` | README 首跑引导 + CI 金标准（54 包 / 16s / 4 会话 / 重传 5.56%） |

---

## 四、样本实跑新暴露的三个缺陷（#27~#29）

这三个是**造完 8 个故障样本、拿真 tshark 跑现有代码**才发现的，规划文档里没有。
样本在 `scaffold/tests/fixtures/gen_pcap.py`，期望值在同目录 `expected.json`。

| # | 问题 | 位置 | 现状（有实跑证据） | 改法 | 任务 |
|---|---|---|---|---|---|
| 27 | **RTT 把「应用等待」算成网络时延** | `core/analyzer.py` L306-308（`tcp.analysis.ack_rtt` 直接当 RTT） | `ack_rtt` 测的是「数据包 → 它的 ACK」间隔，包含**延迟 ACK 策略与应用处理时间**。样本里若把响应晚 1.0s 才 ACK，L3 立刻报「RTT 平均 322ms、抖动 449ms」→ 误判成链路慢 | 只用 SYN/SYN-ACK 之间的时间是纯网络 RTT；数据包的 ack_rtt 单独记成「应用等待/ACK 延迟」，不进 L3 时延统计 | T04 T07 |
| 28 | **`_flag()` 不认多值 → dup-ACK 永远统计为 0** | `core/analyzer.py` L95-96（`_flag`）+ L280-305 调用点 | tshark 对 `tcp.analysis.duplicate_ack` 输出的是 `"1,1"`（该字段出现两次），而 `_flag()` 只认 `"1"/"true"/"yes"` → 恒 `False`。实测：`tcp_retransmission.pcap` 里 tshark 明确给出 2 个 dup-ACK，工具却报「重复 ACK 0.00%」 | `_flag` 先按 `,` 拆分再判断任一为真；或改用 `-E occurrence=f` 只取首个 | **T07（P0：方向推断全靠它）** |
| 29 | **「正常」行与「提示/警告」并存，自相矛盾** | `core/analyzer.py` L573-578、L683-686、L716-719（抑制条件只查 `严重/警告`） | `404_error.pcap` 同时输出「1 个请求返回 4xx（提示）」和「HTTP 响应正常（1 个请求，平均 2ms）」；`zero_window_client.pcap` 同时输出「传输质量正常（重传率 0%）」和「零窗口 5 次」 | 判「正常」行时把 `提示` 也算进抑制条件；同一类别只允许一条结论 | T05 T07 |

**为什么第 28 条是 P0**：评审修正后的「上行/下行丢包」规则靠 **dup-ACK 方向**判定，
而现状连 dup-ACK 数量都恒为 0 —— 也就是说，不修这条，`L4.RETRANS.HIGH` 永远只能给
「方向未知、低置信度」，规划第 5 步的核心价值根本落不了地。

**复现方式**（20 秒）：

```bat
cd scaffold
..\tools\python\python.exe tests\fixtures\gen_pcap.py --out %TEMP%\fx --only tcp_retransmission 404_error
cd ..
tools\python\python.exe -c "import sys;sys.path.insert(0,'core');import analyzer,glob,os;[print(os.path.basename(p),analyzer.analyze(p)['meta']['dup_ack'],[r['severity'] for r in analyzer.analyze(p)['rows']]) for p in glob.glob(os.path.expandvars(r'%TEMP%\fx\*.pcap'))]"
```

---

## 五、关键行为基线（改完必须保持不变）

来自 `reports/faults_demo.md`（当前提交的实跑结果），可直接当回归断言：

| 指标 | 基线值 | 断言位置 |
|---|---|---|
| 报文数 | 54 | `features.capture.packets` |
| 抓包时长 | 16.0 s | `features.capture.duration_s` |
| TCP 会话数 | 4 | `len(features.tcp.streams)` |
| 重传率 | 5.56%（2/36） | `features.tcp.retrans_rate` |
| RTT 均值 / 抖动 | 54 ms / 62 ms | `features.tcp.rtt` |
| DNS 均值 / 失败率 | 385 ms / 29% | `features.dns` |
| HTTP 均值 / P95 | 1210 ms / 2369 ms | `features.http` |
| 严重 / 警告数 | 3 / 5 | `summary.critical_count` / `warning_count` |
| 故障层 | L4 传输层 | `verdict.level` + 主 finding 的 `layer` |

> ⚠️ 但 `logs/diag_20261106.log` 里同一份 pcap 曾出现 2 → 0 → 0 的差异（T00）。
> **先把这个复现清楚**，再把这些数字写成 CI 断言。

---

## 六、怎么快速确认「我改的是这一行」

```bat
REM 看某个函数在哪
findstr /N /C:"def build_findings" core\analyzer.py
findstr /N /C:"def compute_layers" core\verdict.py

REM 看某行附近 20 行
more +495 core\analyzer.py       REM 只看前 20 行，然后按 Ctrl+C

REM 全仓找风险点
findstr /S /N /C:"192.168" /C:"password=" /C:"Authorization" core\*.py
```
