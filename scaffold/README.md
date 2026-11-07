# scaffold —— 目标架构骨架（不参与现有构建）

这里放的是 `docs/plan-review.md` 第 4 节目标架构的**可运行骨架**，用于：

1. 让你先看清「接口长什么样」，再决定怎么改；
2. 让 AI 后续改代码时有一个明确的契约边界，而不是自由发挥；
3. 证明「规则纯函数 + 特征可落盘 + 出口脱敏」这套设计真的跑得起来。

> **本目录不会影响现有程序**：没有模块 import 它，`start.bat` 不引用它，
> `.github/workflows/smoke.yml` 也不会编译它以外的路径。
> 你确认设计后，再按下面的迁移路径把文件搬进 `core/`。

---

## 一、文件清单

```
scaffold/
├── core/
│   ├── __init__.py
│   ├── contracts.py            ★ 全项目唯一数据契约（先看这个）
│   ├── errors.py               错误码 + 可展示异常
│   ├── config.py               统一配置 + config_sha256（用于可复现）
│   ├── copy/zh-CN.json         中文文案表（文案与逻辑分离）
│   ├── platform/
│   │   ├── paths.py            根目录探测（标记文件，不靠固定层级）
│   │   └── winapi.py           管理员 / Npcap / 网关 / DNS（ctypes，不解析本地化文本）
│   ├── capture/
│   │   ├── tshark.py           唯一 tshark 适配器
│   │   └── live.py             抓包编排 + 降级
│   ├── extract/
│   │   ├── fields.py           FIELDS 定义 + -T fields 解析
│   │   └── aggregate.py        流级聚合，**含 per-direction**
│   ├── rules/
│   │   ├── base.py             Rule 协议 + registry + requires
│   │   ├── thresholds.json     阈值外置
│   │   ├── l2.py l3.py l4.py l7.py security.py
│   │   └── legacy_map.py       ★ 旧 rows[] → Finding 迁移桥（T03 用，T05 后可删）
│   ├── verdict/verdict.py      findings → 主判定（纯函数）
│   ├── pathprobe.py            MTR + 影子探测（合并规划第 4、6 步）
│   ├── probe.py                协议自适应体检（迁移占位）
│   ├── passive.py              被动监听（迁移占位）
│   ├── egress/
│   │   ├── sanitize.py         ★ 出口脱敏（profile + 可逆伪名化 + 账本）
│   │   └── ai.py               模型调用（只接受已脱敏 payload）
│   ├── render/
│   │   ├── markdown.py
│   │   └── json_report.py
│   ├── api/
│   │   ├── app.py              路由 + 统一 envelope
│   │   └── jobs.py             JobStore（job_id / 取消 / 并发上限）
│   └── history.py              ★ 历史基线（sqlite3）
├── run_tests.py                自检入口（便携 Python 的 sys.path 补丁）
├── tools/gen_api_doc.py        接口文档生成器（搬进仓库时放 scripts/，**别放 tools/**）
└── tests/
    ├── __init__.py
    ├── test_skeleton.py        骨架自身 29 个用例
    ├── test_fixtures.py        样本生成器 + 迁移桥 12 个用例
    └── fixtures/
        ├── __init__.py
        └── gen_pcap.py         ★ 确定性 pcap 生成器（8 个故障样本，纯标准库）
```

★ = 优先落地：**契约**（contracts）、**出口脱敏**（egress/sanitize）、**历史基线**（history）、
**迁移桥**（rules/legacy_map）、**样本生成器**（tests/fixtures/gen_pcap）。

---

## 二、怎么跑这个骨架（已实测通过 54/54）

不需要 `tools/`、不需要 tshark、不需要联网，也**不写任何仓库文件**（临时目录用完即删）。

```powershell
cd <你的工作目录>\NetDiag\scaffold
..\tools\python\python.exe run_tests.py     # 项目便携 Python 3.11.9（实测 OK）
# 或
python run_tests.py                         # 系统 Python 3.11+（实测 OK）
```

实测输出：

```
Ran 54 tests in 4.72s
OK
用例 54 个｜失败 0｜错误 0｜跳过 0
```

> **不要用 `python -m unittest discover` 直接跑**：项目便携 Python 的
> `tools/python/python311._pth` 把 `sys.path` 固定成
> `python311.zip; .; Lib\site-packages`，**不含当前目录**（且忽略 `PYTHONPATH`），
> 会报 `No module named 'core'`。`run_tests.py` 就是为这个补的：
> `sys.path.insert(0, scaffold)` + `sys.dont_write_bytecode = True`。
> 同理，`tests/` 需要有 `__init__.py`，否则 discover 会报
> `Start directory is not importable`。

10 组用例覆盖：

| 组 | 验证了什么 |
|---|---|
| 契约 | `rule_id` 形态校验；推断类结论必须 `confidence < 1.0`；无样本不许冒充 0ms |
| L4 方向 | 客户端重传+服务端 dup-ACK → 上行；反向 → 下行；无 dup-ACK → 低置信度不下结论 |
| L4 零窗口 | 客户端通告 → 判**客户端**瓶颈（方向 S2C）；服务端通告 → 判服务端 |
| 充分性 | 3 秒短抓包 → `VERDICT.INSUFFICIENT`；空包 → `VERDICT.EMPTY`；健康 → `VERDICT.OK` |
| verdict | 同严重度时底层优先（L2 先于 L7）；高层更严重时以严重度为准；没样本的层是 NA 不是 OK |
| 脱敏 | 云档遮 IP/口令、**保留端口与域名后缀**、文件名不被当域名；本地档保留 IP 但口令仍抹 |
| 解析 | `-T fields` 行解析、方向判定、SYN 重发不计入重传率 |
| API/报告 | JobStore 状态机与协作式取消、并发上限、envelope 与 404/501、报告永不覆盖 |
| **样本生成** | 8 个 pcap 字节级确定性（两次生成 sha256 相同）、pcap 头合法、包数与 `expected.json` 一致、期望不自相矛盾 |
| **迁移桥** | 22 条真实 `row` 全部有归宿、正常行不产出 Finding、方向未知的规则降为「推断+低置信度」、漏项能被 `find_unmatched()` 抓到 |
| **接口文档** | 签名渲染（含 `*args`/仅关键字/默认值）、`self` 不算参数、私有符号不进文档、缺 Args/Returns 能被判出来、扫自己的 `core/` 无解析失败 |

---

## 三、故障样本生成器（8 个）

`.gitignore` 里的 `*.pcap` 会吞掉提交的样本（CI 里文件不存在、测试静默跳过），
所以样本一律**脚本生成**：

```powershell
cd <你的工作目录>\NetDiag\scaffold
..\tools\python\python.exe tests\fixtures\gen_pcap.py --list
..\tools\python\python.exe tests\fixtures\gen_pcap.py --out pcap_samples
REM 可选：用真 tshark 检查 tcp.analysis.* 这些派生字段是否真的出现
..\tools\python\python.exe tests\fixtures\gen_pcap.py --out pcap_samples --verify `
    --tshark ..\tools\WiresharkPortable\App\Wireshark\tshark.exe
```

| 样本 | 守的是什么 | 期望命中 |
|---|---|---|
| `arp_no_reply.pcap` | 只报真无应答的那个（邻居有应答作对照） | `L2.ARP.NO_REPLY` |
| `icmp_unreachable.pcap` | 「需要分片」→ 升级为严重 | `L3.ICMP.UNREACH` |
| `dns_timeout.pcap` | 3 次超时 + 1 次 NXDOMAIN（25%） | `L7.DNS.FAIL` `L7.DNS.SLOW` |
| `tcp_retransmission.pcap` | 客户端重传 + 服务端 dup-ACK → **上行**丢包 | `L4.RETRANS.HIGH`（direction=c2s） |
| `zero_window_client.pcap` | 客户端通告零窗口 → **客户端**瓶颈 | `L4.ZEROWIN.CLIENT` |
| `http_500.pcap` | 5xx 是服务端问题，不许甩锅链路 | `L7.HTTP.5XX` |
| `404_error.pcap` | 4xx 只给提示，不许升级 | `L7.HTTP.4XX` |
| `udp_no_response.pcap` | **负向对照**：UDP 序号缺 1 个也不许报丢包 | （无） |

`expected.json` 是契约：`rule_ids`（必须命中）、`must_not`（不许命中）、
`metrics`（关键数值）、`sha256`（防篡改）、`note`（这个样本守什么）。
CI 只读它，不 import 生成器。

> 生成器已在真实 **tshark 4.7.4** 上核对过派生字段
> （`tcp.analysis.retransmission=1`、`duplicate_ack=2`、`zero_window=5`、`dns.time`、`http.time`）。
> 这一步同时暴露了三个现存缺陷，见 `docs/code-index.md` 的 #27/#28/#29。

---

## 四、迁移路径（3 个 PR，每步都能回滚）

### PR 1：只加不改（不动任何现有文件）

| 动作 | 说明 |
|---|---|
| 复制 `core/contracts.py` → `core/contracts.py` | 新增文件，安全 |
| 复制 `core/errors.py`、`core/config.py`、`core/platform/` | 新增文件，安全 |
| 复制 `core/copy/zh-CN.json` | 新增文件，安全 |
| 改 `core/analyzer.py`：在 `analyze()` 返回前**额外**加一个 `findings_v2` 字段 | 不动 `rows`，UI 完全不受影响 |
| 改 `core/verdict.py`：加 `build_v2(findings) -> Verdict` | 旧 `build()` 保留 |

此时：UI/报告/AI/MCP 全部仍走旧路径，**零风险**。

### PR 2：切规则引擎

| 动作 | 说明 |
|---|---|
| 加 `core/extract/`，把 `collect()` 拆成「解析」+「聚合」，先只新增函数 | 旧 `collect()` 保留为薄壳，转调新函数 |
| 加 `core/rules/`，把 `build_findings()` 逐条搬成独立 Rule | 每搬一条，用 `tests/test_skeleton.py` 的写法加一个用例 |
| `build_findings()` 改成 `run_rules(...)` 的薄壳，输出仍转成旧的 `rows[]` | UI 仍不受影响 |
| 打开「证据充分性」闸门 | 旧路径下也生效（P0-4） |

此时：CRITICAL——`rows[]` 的**文本必须保持不变**，否则 UI 与报告会漂。
建议加一个「快照测试」：对 `captures/faults_demo.pcap` 的输出与迁移前逐字 diff。

### PR 3：切出口

| 动作 | 说明 |
|---|---|
| 加 `core/egress/sanitize.py`，先在 `core/ai.py` 的 `build_messages()` 前插一层 | 只影响 AI 出口 |
| 再扩到 `report.py`（导出时脱敏）与 MCP（`_text()` 前插一层） | 本地落盘的 `.md` 默认不脱敏（排障需要），导出时脱敏 |
| 加 `core/api/jobs.py`，`server.py` 内部先换成 JobStore，**HTTP 路由保持旧形态** | UI 不用改 |
| 最后再上 `/api/v1/*` + 静态资源路由 | 这一步才动 `ui/index.html` |

---

## 五、三条使用约定（给未来的 AI 协作者）

1. **只通过 `contracts.py` 交换数据**。任何模块都不许再自造 dict 结构。
2. **规则里不许出现中文字符串**（阈值可以进 `thresholds.json`，文案只能进 `copy/zh-CN.json`）。
   可以用一条很便宜的测试守住：`assert not re.search(r"[\u4e00-\u9fff]", inspect.getsource(rule_module))`。
3. **新规则必须同时给**：`rule_id`、`requires`、一个命中用例、一个不命中的反例。
   这条写进 `AGENTS.md`，CI 里能自动检查 `rule_id` 格式与唯一性。

---

## 六、已知的「故意留空」

骨架里这些地方是 `NotImplementedError`，属于**故意的**——它们要么依赖 tshark 会话，
要么需要你确认业务口径后再定：

| 位置 | 为什么留空 |
|---|---|
| `capture/tshark.py` `run()` / `iter_fields()` | 迁移期应直接转发现有 `core/tshark.py`，不重写 |
| `capture/live.py` | 同上（`core/diagnose.capture_live`） |
| `extract/aggregate.py` `build_features()` | 核心工作量在这里，需要先定 `Features` 的字段清单（已给出建议） |
| `platform/winapi.py` `adapters()` / `default_gateway()` / `dns_servers()` | ctypes 结构体比较长，且需要真机调试；先给签名 |
| `pathprobe.py` `run()` | 需要真机 + Npcap；先给账本与 BPF 排除逻辑（已实现） |
| `probe.py` / `passive.py` | 纯迁移占位，现有实现已经可用 |
| `render/markdown.py` 全量渲染 | 先给最小实现；完整渲染迁移 `core/report.py` |
| `api/app.py` 路由实现 | 先给路由表与 envelope，`Handler` 迁移现有 `core/server.py` |

`history.py` 与 `egress/sanitize.py` 是**完整实现**——它们不依赖 tshark，可以马上用。
