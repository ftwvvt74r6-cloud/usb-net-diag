# 接口参考（自动生成）

> 本文件由 `scripts/gen_api_doc.py` 从 AST 生成，**签名永远与代码一致**。
> 不要手改签名；要改内容就改源码里的 docstring，然后重跑：
>
> ```bat
> tools\python\python.exe scripts\gen_api_doc.py
> ```

- 扫描模块：**33** 个（有模块说明 33 个）
- 公开符号：**311** 个（有 docstring 311 个，合格 311 个）
- 合格率：**100.0%**（目标 ≥ 95%，见 `docs/api-style.md`）

阅读顺序建议：先看 `docs/overview.md`（一页看懂项目）→ 本文件的「按模块」→ 具体源码。

---

## `core/__init__.py`

**职责**：NetDiag（网络矩阵）核心包（目标架构骨架）。

_（无公开符号）_

## `core/ai.py`

**职责**：AI 模型服务：配置持久化 + OpenAI 兼容协议调用。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `AIError` | class | 88 | ✅ |
| `load_config` | function | 93 | ✅ |
| `save_config` | function | 160 | ✅ |
| `mask_key` | function | 178 | ✅ |
| `public_config` | function | 196 | ✅ |
| `chat` | function | 250 | ✅ |
| `test_connection` | function | 337 | ✅ |
| `build_messages` | function | 365 | ✅ |
| `analyze_result` | function | 490 | ✅ |

### `AIError`  (class)

```python
class AIError
```

```text
调用模型失败，message 可直接展示给用户。
```

### `load_config`

```python
def load_config() -> dict
```

```text
读取 AI 配置文件（``config/ai-config.json``）。

与 :func:`core.config.load_ai` 的区别：本模块**必须**能在只拷了 ``core/`` 的
极简环境里独立工作，所以自带默认值与容错，不依赖 ``core.config``。

Returns:
    dict: 键 ``provider`` / ``base_url`` / ``api_key`` / ``model`` / ``temperature`` /
        ``timeout`` / ``verify_ssl`` / ``updated_at``。
        文件缺失或损坏时返回全默认值（``api_key`` 为空 = 未配置）。
```

### `save_config`

```python
def save_config(patch: dict) -> dict
```

```text
把前端提交的改动合并进配置文件并原子落盘。

Args:
    patch: 只含需要改的键；会被 :func:`_clean` 过滤（非法字符、越界数值、
        缺字段的 base_url 都会被丢弃，避免写坏配置）。

Returns:
    dict: 写回后的完整配置（含新生成的 ``updated_at``）。
```

### `mask_key`

```python
def mask_key(key: str) -> str
```

```text
把 API Key 打码后回显给前端（配置页要显示「已填」，但不能显示原文）。

Args:
    key: 原始 Key。

Returns:
    str: 长度 ≤ 8 时整串星号；更长时保留前 4 后 4，中间 6 个星号。
        空串返回空串（前端据此显示「未配置」）。
```

### `public_config`

```python
def public_config(cfg: dict | None=None) -> dict
```

```text
给界面看的安全视图：**不含明文 Key**。

Args:
    cfg: 已加载的配置；省略时现场读盘。

Returns:
    dict: 除 ``api_key`` 外的全部字段，另加 ``has_key``（bool）与 ``key_hint``
        （打码后的样子）。这样前端既能显示「已配置」，又拿不到可用凭据。
```

### `chat`

```python
def chat(messages: list[dict], overrides: dict | None=None, timeout: int | None=None, max_tokens: int | None=None) -> str
```

```text
调用 OpenAI 兼容的 ``/chat/completions``，返回纯文本回复。

Args:
    messages: 标准对话数组，每项 ``{"role": "system"|"user"|"assistant", "content": str}``。
    overrides: 临时覆盖配置（如前端「测试连接」时用未保存的新地址），
        会过 :func:`_clean` 校验。
    timeout: 覆盖配置里的超时秒数。
    max_tokens: 覆盖最大输出长度；不传时用服务端默认。

Returns:
    str: 模型回复的正文（已去首尾空白）。

Raises:
    AIError: 未填 Key、地址非法、HTTP 非 2xx、返回体不是预期 JSON、
        或拿不到 ``choices[0].message.content``。消息内容可直接展示给用户。
```

### `test_connection`

```python
def test_connection(overrides: dict | None=None) -> dict
```

```text
最小代价验证配置是否可用（发一句短提示，看能否拿到回复）。

Args:
    overrides: 待验证的配置；省略时用磁盘上已保存的那份。

Returns:
    dict: 成功 ``{"ok": True, "model": str, "latency_ms": int, "reply": str}``；
        失败 ``{"ok": False, "error": str}``（``error`` 已含可操作提示）。
```

### `build_messages`

```python
def build_messages(result: dict, question: str='') -> list[dict]
```

```text
把诊断结果转成对话消息，**保留全部原始观测值**供模型引用。

Args:
    result: ``diagnose.run_scan()`` 的结果字典（含 ``meta`` / ``rows`` /
        ``metrics`` / ``verdict``）。
    question: 用户追加的追问；为空时用内置的「按四段结构分析」提示。

Returns:
    list[dict]: 两条消息 —— ``system``（角色约束：不许编造未观测到的事实）
        与 ``user``（拼好的诊断摘要 + 追问）。

Note:
    prompt 里的中文全部来自 ``core/copy/zh-CN.json`` 的 ``prompt`` section；
    本模块只负责拼装与取数。system 提示词同样来自文案表，改措辞不用改代码。
```

### `analyze_result`

```python
def analyze_result(result: dict, question: str='', overrides: dict | None=None) -> dict
```

```text
让模型解读一次诊断结果。

Args:
    result: 诊断结果字典。
    question: 用户追问，可空。
    overrides: 临时覆盖 AI 配置。

Returns:
    dict: ``{"ok": True, "analysis": str, "model": str, "latency_ms": int}``。

Raises:
    AIError: 上游调用失败（由调用方转成 HTTP 错误信封）。
```

## `core/analyzer.py`

**职责**：抓包分析引擎：网络故障分层定位（主）+ 安全隐患观察（次）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `collect` | function | 412 | ✅ |
| `build_findings` | function | 916 | ✅ |
| `analyze` | function | 1405 | ✅ |

### `collect`

```python
def collect(pcap: Path, log=None, display_filter: str | None=None) -> tuple[dict, str]
```

```text
流式解析 pcap，边读边聚合。

一次 tshark 调用取全所需字段，避免对同一文件扫多遍；输出按行消费，
几十万行的 pcap 也不会把内存吃满。

Args:
    pcap: 抓包文件路径。
    log: 可选日志回调 ``log(str)``，用于输出进度与 tshark 告警首行。
    display_filter: 可选的 tshark ``-Y`` 显示过滤表达式；``None``（默认）时
        不加任何过滤、行为与历史版本完全一致。影子探测用它做**第二道隔离**
        （抓包 BPF 之外的防御层）：探针的回复报文方向端口是反的，只靠 BPF
        可能漏进统计。

Returns:
    tuple[dict, str]: ``(stats, error)``。``stats`` 是全部计数器与时间戳的聚合字典；
        ``error`` 为空串表示成功。**非空时必须整体放弃结论** ——
        tshark 退出码非 0（典型：文件不完整 rc=14、被超时杀掉 rc<0）意味着
        只读到一部分报文，此时算出来的「严重 0 条」是假象（见 docs/t00-findings.md）。
```

### `build_findings`

```python
def build_findings(st: dict, m: dict, streams: list[dict]) -> list[dict]
```

```text
把统计聚合翻译成「按层归类的发现」，供 UI 与报告消费。

Args:
    st: :func:`collect` 的统计字典（各类计数器）。其中 ``st["dir"]`` 是分方向
        统计（``c2s`` / ``s2c`` 的数据重传、重复 ACK、帧数与方向未定的
        ``unknown`` 帧数）；缺失时（旧调用方的合成 st）退回通用重传行。
    m: :func:`_metrics` 算出的比率与时延指标（``retrans_rate`` / ``rtt_avg_ms`` 等）。
    streams: :func:`_stream_rows` 聚合出的会话列表。

Returns:
    list[dict]: 每项 ``{"layer", "category", "severity", "finding", "advice", "evidence"}``。
        ``finding`` / ``evidence`` / ``advice`` 的中文全部来自
        ``core/copy/zh-CN.json``（section：``finding`` / ``evidence`` / ``advice``），
        本模块只保留 key 与占位符实参。

Note:
    ``severity`` 有三种非故障取值：``"严重"/"警告"/"提示"`` 之外，
    ``"—"`` 表示「测了，正常」，``"na"`` 表示「没样本」（见 :data:`NEUTRAL_SEVERITY`
    与 :data:`NO_SAMPLE_SEVERITY`）。两者都不是问题，但只有前者能报绿色。

    中性行（``"—"``）的保留与否**不在产出的位置决定**，而是最后按 ``category``
    统一裁定：同类别只要出现过故障行，中性行一律丢弃。否则会出现
    「传输质量正常」与「出现 TCP 零窗口」并列这种自相矛盾的报告。

    ``layer`` / ``category`` / ``severity`` 三个字段是**结构化标识**（既被
    ``verdict`` / ``legacy_map`` 当键匹配，也直接进报告表格）：它们不是本轮
    可迁移的「文案」，改值会连带改变判定与映射，因此保留在代码里。

    方向判定（见 :func:`_retrans_direction`）只换重传行的**文案与建议**，
    不改严重度阈值，也不产生新行：没有重复 ACK 证据时仍是原来的通用行。
```

### `analyze`

```python
def analyze(pcap: Path | str, target: str='', ti_key: str='', log=None, display_filter: str | None=None) -> dict
```

```text
分析抓包文件（离线分析）：读取一个 pcap，产出完整结果字典。

Args:
    pcap: 抓包文件路径（``Path`` 或字符串）。
    target: 本次诊断目标的展示用名字（IP/域名），可空。
    ti_key: 威胁情报 API Key；为空则跳过可疑外联核对。
    log: 可选日志回调 ``log(str)``。
    display_filter: 可选的 tshark ``-Y`` 显示过滤表达式（影子探测隔离的
        防御层）；``None``（默认）时行为与输出完全不变 —— 离线分析的
        20 个产物逐字节红线靠这个默认值守住。

Returns:
    dict: 成功时 ``ok=True``，键含 ``meta``（采集与明细）、``metrics``（扁平指标）、
        ``rows``（中文发现列表）、``summary``（计数摘要），以及 T03 新增的
        ``findings_v2``（带机器码的结构化结论）与 ``provenance``（可复现信息）。
        文件不存在或解析失败时返回 ``{"ok": False, "error": "..."}``。
```

## `core/app.py`

**职责**：静默启动器：像应用一样双击即用，全程不弹控制台窗口。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `redirect_output` | function | 39 | ✅ |
| `msgbox` | function | 57 | ✅ |
| `is_admin` | function | 74 | ✅ |
| `relaunch_as_admin` | function | 86 | ✅ |
| `find_running` | function | 109 | ✅ |
| `first_free_port` | function | 135 | ✅ |
| `main` | function | 162 | ✅ |

### `redirect_output`

```python
def redirect_output() -> None
```

```text
pythonw 下 sys.stdout/stderr 是 None，任何 print 都会炸，先兜住。

实际落盘交给 :mod:`logstore`（写 ``logs/app-YYYYMMDD.log``）。日志句柄在
``logstore`` 里进程内复用，不会每来一次 ``print`` 就打开一个文件。

Returns:
    None: 目录不可写时静默降级（保持原来的 ``None`` 语义，不因日志失败而崩溃）。
```

### `msgbox`

```python
def msgbox(text: str, title: str='NetDiag · 网络矩阵', flags: int=MB_ICONINFO) -> None
```

```text
弹一个系统消息框 —— 静默启动（无控制台）时唯一的提示手段。

Args:
    text: 正文。
    title: 窗口标题。
    flags: ``MB_*`` 图标/按钮组合，默认信息图标 + 确定。

Returns:
    None: 弹窗失败（如非 Windows）静默忽略，绝不因此让启动流程崩掉。
```

### `is_admin`

```python
def is_admin() -> bool
```

```text
当前进程是否管理员（实时抓包的前提）。

Returns:
    bool: 查不到时返回 ``False``，让上层按「无提权」降级处理。
```

### `relaunch_as_admin`

```python
def relaunch_as_admin() -> bool
```

```text
用 UAC 提权重启自己。

Returns:
    bool: True 表示已成功拉起提权后的新进程（当前进程应立即退出，避免两个实例抢端口）；
        False 表示用户点了「否」或调用失败 —— 此时**不要**退出，
        以普通权限继续跑，实时抓包不可用但分析抓包文件照常。
```

### `find_running`

```python
def find_running() -> str
```

```text
探测本机是否已有实例在跑（单实例保护）。

逐个试 8787~8796 的 ``/api/ping``，并核对 ``app`` 字段是本程序，
避免把别的服务误认成自己。

Returns:
    str: 已运行实例的界面地址（如 ``http://127.0.0.1:8787/``）；没有则空串。
```

### `first_free_port`

```python
def first_free_port(base: int=8787, count: int=10) -> int | None
```

```text
在 ``127.0.0.1`` 上找一个当前能绑定的端口（只探测，不占用）。

与 :func:`find_running` 互补：先看有没有本程序实例，再看端口预算。实现只做
``bind`` / ``close``，不监听、不发包；端口被占或处于 ``TIME_WAIT`` 时继续试下一个。
首屏自检与 ``server.create_server`` 用同一段 8787~8796，所以这里默认也是 10 个。

Args:
    base: 起始端口，默认 8787。
    count: 顺延个数，默认 10（8787~8796）；非正数时返回 ``None``。

Returns:
    int | None: 第一个可绑定的端口号；全部被占用时 ``None``。
```

### `main`

```python
def main() -> int
```

```text
静默启动主流程。

顺序：日志基建 → 重定向输出 → 探测已有实例 → 建监听 → 开浏览器 → 阻塞。
启动路径**不请求提权**；`--elevated` 只用于 /api/elevate 拉起的新进程。

Returns:
    int: 进程退出码。0 = 正常（含「已有实例，直接把浏览器叫起来」、缺可选组件但
        服务已启动）；1 = 初始化失败 / 端口全被占用（物理上无法起本地服务）。
```

## `core/bootstrap.py`

**职责**：U 盘启动引导：按实际盘符生成配置 + 环境自检。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `write_json` | function | 24 | ✅ |
| `gen_configs` | function | 38 | ✅ |
| `check` | function | 87 | ✅ |
| `main` | function | 133 | ✅ |

### `write_json`

```python
def write_json(path: Path, data: dict) -> None
```

```text
写 JSON 文件（自动建父目录，统一缩进与不转义中文）。

Args:
    path: 目标文件。
    data: 待写入的对象。

Returns:
    None: 写失败会让异常抛出去 —— 配置文件写不出来是硬故障，应当尽早暴露。
```

### `gen_configs`

```python
def gen_configs() -> dict
```

```text
用当前盘符重写 MCP 与 Harness 配置。

U 盘盘符从 F: 变成 G: 后，MCP 客户端里写死的绝对路径全部失效；
每次启动重算一遍，是「插到任何机器都能用」的前提。

Returns:
    dict: 写出的文件路径，键 ``mcpServersFile`` / ``harnessFile`` 等，供日志展示。
```

### `check`

```python
def check(verbose: bool=True) -> dict
```

```text
环境自检：tshark、Npcap、管理员权限、网卡、Scapy 是否就绪。

Args:
    verbose: True 时向标准输出打印人类可读的检查过程。

Returns:
    dict: 键含 ``ok``（总体是否可用）、``root`` / ``python`` / ``python_exe`` /
        ``tshark`` / ``tshark_version`` / ``npcap`` / ``admin`` /
        ``interfaces``（网卡列表）/ ``scapy``。界面顶部的环境徽章就吃这份数据。
```

### `main`

```python
def main(argv=None) -> int
```

```text
``bootstrap.py`` 的命令行入口（供 ``doctor.bat`` 与自测调用）。

Args:
    argv: 参数列表；省略时取 ``sys.argv[1:]``。支持 ``--check``（只自检）、
        ``--npcap``（只查 Npcap，就绪返回 0）、``--quiet``（少打印）。

Returns:
    int: 0 正常；``--npcap`` 模式下 Npcap 未装返回 1。
```

## `core/conclusion.py`

**职责**：结论边界结构化渲染器：把一次诊断的「结论 + 依据 + 覆盖 / 未覆盖 + 置信」做成一份对象。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `derive_confidence` | function | 520 | ✅ |
| `build_conclusion` | function | 654 | ✅ |
| `render_conclusion_markdown` | function | 806 | ✅ |
| `render_conclusion_text` | function | 847 | ✅ |

### `derive_confidence`

```python
def derive_confidence(result: dict) -> float
```

```text
由证据形态自动推导结论级置信度（纯函数，不允许人工填写）。

三档映射（用户 2026-11-08 定稿）：

* :data:`CONFIDENCE_CONTRAST`（0.9，高）：有对照组（网关 vs 对端双侧探测）
  且两侧结论一致；
* :data:`CONFIDENCE_SINGLE_SIDE`（0.65，中）：仅单侧证据（只测目标 / 只有抓包
  无对照 / 只有一侧探针）；
* :data:`CONFIDENCE_INDIRECT`（0.3，低）：仅间接线索（无样本 / 证据不足 /
  ICMP 超时 / 采样异常）。

Args:
    result: 诊断结果字典（读 ``meta`` / ``rows`` / 可选 ``verdict``）。

Returns:
    float: 0.9 / 0.65 / 0.3 之一；``result`` 不是对象时按 0.3（证据不足）。
```

### `build_conclusion`

```python
def build_conclusion(result: dict, verdict: dict | None=None) -> dict
```

```text
构造结论边界对象（六出口的唯一出处）。

处理顺序：推导 ``confidence`` → 派生 ``confidence_level`` → 按等级取
``key_limit`` → 用 copy 模板填 ``basis`` / ``coverage`` / ``not_covered`` →
渲染 conclusion 句。**任何一项填充失败**都会把该项替换成「未知（原因：…）」，
并把最终 ``confidence`` 降为 :data:`CONFIDENCE_INDIRECT`（等级「低」）。

Args:
    result: 诊断结果字典（``meta`` / ``rows`` / ``summary`` / 可选 ``verdict``）。
    verdict: 已算好的判定字典；省略时读 ``result["verdict"]``。只读
        ``headline`` 与 ``probe_contrast``，不调用 ``verdict.build``。

Returns:
    dict: 键 ``conclusion``（str）/ ``basis`` / ``coverage`` /
        ``not_covered``（``list[str]``，保证非空、无空串）/
        ``confidence``（float）/ ``confidence_level``（高|中|低）/
        ``key_limit``（str）。**不含**任何缓存或本次结果以外的事实。
```

### `render_conclusion_markdown`

```python
def render_conclusion_markdown(block: dict, report_id: str | None=None) -> str
```

```text
把结论边界对象渲染成 Markdown 整块（报告 / 取证单 / 导出共用）。

输出固定包含：结论句、依据、本次覆盖、明确未覆盖、置信等级/关键边界。
任何字段缺失都会补「未知」；函数**永远不返回空串**。

Args:
    block: :func:`build_conclusion` 的返回值（或结构相同的对象）。
    report_id: 可选的报告标识（文件名 + 生成时间）。省略时不追加任何行 ——
        报告正文必须保持逐字节不变，只有复制/导出才带上标识。

Returns:
    str: 以 ``### 结论与边界`` 开头、以单个换行结尾的 Markdown 文本。
```

### `render_conclusion_text`

```python
def render_conclusion_text(block: dict, report_id: str | None=None) -> str
```

```text
把结论边界对象渲染成纯文本整块（复制给协作方 / 发微信 / 工单）。

与 :func:`render_conclusion_markdown` 同源，但不含 Markdown 符号
（无 ``#`` 标题、无 ``|`` 表格），并显式列出「结论 + 依据 + 本次覆盖 +
明确未覆盖 + 置信等级/关键边界」。传 ``report_id`` 时在末尾追加报告标识，
让协作方能手查到对应的 `.md` / `.json` 报告。

Args:
    block: :func:`build_conclusion` 的返回值（或结构相同的对象）。
    report_id: 可选的报告标识（文件名 + 生成时间）；省略时不追加。

Returns:
    str: 纯文本整块（以单个换行结尾，保证非空）。
```

## `core/config.py`

**职责**：统一配置加载。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `read_json` | function | 63 | ✅ |
| `load_app` | function | 87 | ✅ |
| `load_ai` | function | 115 | ✅ |
| `load_thresholds` | function | 126 | ✅ |
| `load_copy` | function | 136 | ✅ |
| `config_sha256` | function | 148 | ✅ |

### `read_json`

```python
def read_json(path: Path, default: Mapping[str, Any] | None=None) -> dict
```

```text
读 JSON 文件，缺失或损坏一律回退默认值。

U 盘场景里配置文件被拔盘截断、被杀软删都是常事，这里**绝不抛异常** ——
否则一个坏文件就能让整个工具起不来。

Args:
    path: 目标文件路径。
    default: 基础默认值；文件里存在的键会覆盖它（值为 ``None`` 的键跳过，避免把默认值抹掉）。

Returns:
    dict: 合并结果。文件不存在 / 不是合法 JSON / 顶层不是对象时，原样返回默认值副本。
```

### `load_app`

```python
def load_app() -> dict
```

```text
加载 ``config/app-config.json``（用户可改的那份）。

Returns:
    dict: 已做类型收敛的配置。键见 :data:`APP_DEFAULTS`
        （``server_port`` / ``default_duration`` / ``max_duration`` /
        ``threat_intel_key`` / ``auto_open_browser`` / ``idle_exit_min`` 等）。
        端口非法时回落 8787；``sufficiency`` 与默认值深合并。
```

### `load_ai`

```python
def load_ai() -> dict
```

```text
加载 ``config/ai-config.json``（AI 接口地址与 Key）。

Returns:
    dict: 键见 :data:`AI_DEFAULTS`（``provider`` / ``base_url`` / ``api_key`` /
        ``model`` / ``temperature`` / ``timeout`` / ``verify_ssl``）。
        文件缺失时返回默认值，``api_key`` 为空表示未配置。
```

### `load_thresholds`

```python
def load_thresholds() -> dict
```

```text
加载规则阈值 ``core/rules/thresholds.json``（随代码走，不属于用户配置）。

Returns:
    dict: 阈值表。缺失时返回空表 —— 规则会因 ``requires`` 未满足而跳过，
        而不是拿 0 当阈值瞎判。
```

### `load_copy`

```python
def load_copy(lang: str='zh-CN') -> dict
```

```text
加载文案表 ``core/copy/zh-CN.json``。

Args:
    lang: 语言代码，对应 ``core/copy/<lang>.json``。

Returns:
    dict: 文案 key → 文本。缺失时返回空表，渲染层回退成显示 ``rule_id`` 本身（不崩）。
```

### `config_sha256`

```python
def config_sha256() -> str
```

```text
把「影响结论的配置」一起哈希，写进 ``Provenance``。

只覆盖 app 配置与阈值，**不哈希 AI Key** —— 避免把密钥指纹写进报告，
也避免「换了 Key 就说结论不可复现」。

Returns:
    str: 16 位十六进制摘要。同一份配置恒等，改任意阈值即变。
```

## `core/contracts.py`

**职责**：全项目唯一数据契约。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `confidence_level_of` | function | 40 | ✅ |
| `Layer` | class | 73 | ✅ |
| `Layer.label_key` | method | 83 | ✅ |
| `Severity` | class | 96 | ✅ |
| `Direction` | class | 118 | ✅ |
| `EndpointKind` | class | 130 | ✅ |
| `EvidenceKind` | class | 140 | ✅ |
| `Category` | class | 147 | ✅ |
| `JobState` | class | 164 | ✅ |
| `to_jsonable` | function | 180 | ✅ |
| `Endpoint` | class | 209 | ✅ |
| `Endpoint.to_dict` | method | 229 | ✅ |
| `Stats` | class | 239 | ✅ |
| `Stats.from_values` | method | 249 | ✅ |
| `Stats.has_sample` | method | 272 | ✅ |
| `Stats.to_dict` | method | 280 | ✅ |
| `DirStat` | class | 290 | ✅ |
| `DirStat.to_dict` | method | 324 | ✅ |
| `CaptureMeta` | class | 339 | ✅ |
| `CaptureMeta.to_dict` | method | 360 | ✅ |
| `StreamStat` | class | 370 | ✅ |
| `StreamStat.dir_of` | method | 393 | ✅ |
| `StreamStat.to_dict` | method | 405 | ✅ |
| `TcpFeatures` | class | 415 | ✅ |
| `TcpFeatures.total` | method | 437 | ✅ |
| `TcpFeatures.has_streams` | method | 454 | ✅ |
| `TcpFeatures.to_dict` | method | 462 | ✅ |
| `Features` | class | 473 | ✅ |
| `Features.has` | method | 491 | ✅ |
| `Features.to_dict` | method | 502 | ✅ |
| `Finding` | class | 515 | ✅ |
| `Finding.validate` | method | 546 | ✅ |
| `Finding.rank` | method | 567 | ✅ |
| `Finding.to_dict` | method | 575 | ✅ |
| `Sufficiency` | class | 589 | ✅ |
| `Sufficiency.to_dict` | method | 598 | ✅ |
| `LayerStatus` | class | 609 | ✅ |
| `LayerStatus.to_dict` | method | 628 | ✅ |
| `Verdict` | class | 638 | ✅ |
| `Verdict.confidence_level` | method | 687 | ✅ |
| `Verdict.to_dict` | method | 696 | ✅ |
| `Provenance` | class | 710 | ✅ |
| `Provenance.to_dict` | method | 721 | ✅ |
| `AnalyzeResult` | class | 736 | ✅ |
| `AnalyzeResult.by_layer` | method | 755 | ✅ |
| `AnalyzeResult.worst` | method | 767 | ✅ |
| `AnalyzeResult.to_dict` | method | 777 | ✅ |
| `ProbeResult` | class | 787 | ✅ |
| `ProbeResult.to_dict` | method | 800 | ✅ |
| `PassiveResult` | class | 811 | ✅ |
| `PassiveResult.to_dict` | method | 821 | ✅ |
| `Job` | class | 834 | ✅ |
| `Job.running` | method | 862 | ✅ |
| `Job.public` | method | 870 | ✅ |
| `Job.to_dict` | method | 892 | ✅ |
| `envelope_ok` | function | 904 | ✅ |
| `envelope_err` | function | 918 | ✅ |

### `confidence_level_of`

```python
def confidence_level_of(confidence: float) -> str
```

```text
把结论级置信度映射成「高/中/低」（阈值唯一出处）。

等级不是可人工填写的字段，而是由 ``confidence`` 派生的展示态；
渲染层（:mod:`core.conclusion`）与 :class:`Verdict` 的属性都调用本函数，
避免两处阈值写不一致。

Args:
    confidence: 结论级置信度，必须落在 ``[0, 1]`` 区间内。

Returns:
    str: ``"高"``（≥ :data:`CONFIDENCE_HIGH_MIN`）、``"中"``
        （≥ :data:`CONFIDENCE_MEDIUM_MIN`）或 ``"低"``。

Raises:
    ValueError: 传入值不是数字、为 ``NaN`` 或超出 ``[0, 1]``。
```

### `Layer`  (class)

```python
class Layer
```

```text
OSI 分层。``SEC`` 是安全观察，不参与网络故障主判定。
```

### `Layer.label_key`  (method)

```python
@property
def label_key(self) -> str
```

```text
``layer.l4`` 形式的文案 key（去 ``copy/zh-CN.json`` 查）。

Returns:
    str: 小写前缀的 key，如 ``"layer.l4"``。

Note:
    不直接返回 ``"L4 传输层"`` 是为了让改文案不动逻辑，
    也让 CI 断言 ``layer`` 时不会因为改字而变红。
```

### `Severity`  (class)

```python
class Severity
```

```text
分级。用英文枚举而不是中文，是为了让 CI 断言不被文案改动影响。

``NA`` 与 ``OK`` 的区别很关键：``OK`` 是「测了，正常」，
``NA`` 是「没样本，测不了」—— 后者报成正常就是误报（评审 P0-4）。
```

### `Direction`  (class)

```python
class Direction
```

```text
数据流向（相对抓包点）。

注意语义：``C2S`` 指「客户端 → 服务端」的**数据**方向。
零窗口这类字段要记录**通告方**，见 ``Finding.metric["advertised_by"]``。
```

### `EndpointKind`  (class)

```python
class EndpointKind
```

```text
端点在会话里的角色。方向判定、零窗口归属、丢包归因都依赖它。
```

### `EvidenceKind`  (class)

```python
class EvidenceKind
```

```text
结论强度。``INFERRED`` 必须带 ``confidence < 1.0``。
```

### `Category`  (class)

```python
class Category
```

```text
故障类别英文码（原实现里是中文串）。
```

### `JobState`  (class)

```python
class JobState
```

```text
任务状态机：``QUEUED → RUNNING → (DONE | ERROR | CANCELLED)``。

``GET /api/v1/jobs/{id}`` 直接把 ``.value`` 下发给前端，
前端据此决定「继续轮询 / 停止 / 取结果」。
```

### `to_jsonable`

```python
def to_jsonable(value: Any) -> Any
```

```text
把契约对象递归转成可 JSON 序列化的结构。

统一处理 ``Enum`` / ``dataclass`` / ``Mapping`` / ``tuple`` / ``frozenset``，
避免每个类都手写一遍 ``to_dict``。

Args:
    value: 任意契约对象或普通容器。``Enum`` 取 ``.value``；dataclass 逐字段展开；
        ``Mapping`` 的键统一转 ``str``（JSON 只接受字符串键）。

Returns:
    Any: 只含 dict / list / str / int / float / bool / None 的结构；
        传入已是标量时原样返回。
```

### `Endpoint`  (class)

```python
@dataclass(frozen=True)
class Endpoint
```

```text
一个网络端点（IP + 可选端口 + 角色）。会话表、发现项、路径探测都用它说话。

字段：
    ip: IPv4/IPv6 字面量，**不带**方括号（拼 URL 时由渲染层加）。
    port: 传输层端口；``None`` 表示「不知道或不适用」，如 ICMP 只剩 IP。
    kind: 角色（客户端/服务端/网关/DNS/VDI/未知），由 SYN 方向推断，不靠端口大小猜。
    label: 给报告用的可读名字（域名、SNI、资产名），可为空。
```

### `Endpoint.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典，供 JSON 下发。

Returns:
    dict: 键 ``ip`` / ``port`` / ``kind`` / ``label``。
```

### `Stats`  (class)

```python
@dataclass(frozen=True)
class Stats
```

```text
毫秒级统计。没有样本时 ``n == 0``，**不要**用 0 冒充「很快」。
```

### `Stats.from_values`  (method)

```python
@classmethod
def from_values(cls, values: Iterable[float]) -> 'Stats'
```

```text
从一组毫秒值算出 n / avg / p95 / max / jitter。

``p95`` 用最近秩法（取下标 ``round(0.95*(n-1))``），不做插值 ——
样本少时插值会给出一个并不存在的值，运维按这个数去找包会找不到。

Args:
    values: 任意可迭代的毫秒值（int/float 均可，内部统一转 float）。

Returns:
    Stats: 空输入返回 ``n=0`` 的全零实例；调用方须先查 ``has_sample`` 再用。
```

### `Stats.has_sample`  (method)

```python
@property
def has_sample(self) -> bool
```

```text
是否有样本。

Returns:
    bool: ``n > 0``。为 False 时**不要**把 ``avg=0`` 当「很快」，应报「无样本」。
```

### `Stats.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: 键 ``n`` / ``avg`` / ``p95`` / ``max`` / ``jitter``，单位毫秒。
```

### `DirStat`  (class)

```python
@dataclass(frozen=True)
class DirStat
```

```text
**单个方向**的 TCP 统计 —— 评审 P0-2 的核心修复。

现有实现把 retrans / dup_ack / zero_win 全部按流累加，导致：
「客户端重传」既可能是上行丢包、也可能是下行 ACK 丢失，
而「零窗口」甚至可能来自客户端自己（VDI 场景常见）。

计数口径（三个字段容易混，必须分开记）：

* ``retrans`` —— **数据**重传次数，**不含 SYN**（与 ``analyzer`` 里
  ``st["retrans"]`` 的口径一致，否则重传率会与现有报告对不上）。
* ``syn`` —— 该方向 SYN 帧数（**含重传**）。
* ``syn_retrans`` —— SYN 重传次数。SYN 重传说明「握手包在路上丢了」，
  是上行连通性信号，与数据重传是两种故障，不能并进 ``retrans``。
```

### `DirStat.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: ``direction`` 是字符串；``rtt`` 是嵌套的 ``Stats.to_dict()``；
        其余是 12 个计数字段（packets/bytes/retrans/syn_retrans/dup_ack/
        ooo/zero_win/win_full/lost_seg/rst/syn/data_packets）。
```

### `CaptureMeta`  (class)

```python
@dataclass
class CaptureMeta
```

```text
采集元信息 —— 回答「这份结论是从哪份数据、用什么参数算出来的」。

字段：
    mode: ``live``（实时抓）或 ``offline``（分析抓包文件）。
    pcap_file / pcap_name: 绝对路径与文件名；报告命名用后者。
    packets / bytes / duration_s: 规模与时间跨度，判断证据是否充分的第一步。
    interface / bpf: 网卡与过滤器，复现同一份抓包时必需。
    first_ts / last_ts: 首末包的 epoch 秒，用于时间分桶与峰值窗标记。
```

### `CaptureMeta.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: 键同字段名，全部是标量（无嵌套、无 Enum）。
```

### `StreamStat`  (class)

```python
@dataclass
class StreamStat
```

```text
一条 TCP 会话（``tcp.stream``）的统计与端点角色。

字段：
    client / server: 谁是客户端由 SYN / SYN-ACK 方向推断，不靠端口大小猜。
    app_hint: 应用层线索（HTTP Host、TLS SNI、端口画像），用于「这条流是什么业务」。
    handshake_ms / think_ms: 握手耗时、服务端思考时间（收完请求到给出响应）。
    state: 结束方式（正常关闭 / RST / 无响应）。
    frames: 组成这条流的帧号，供报告跳转定位。
    dirs: 上下行各自的 ``DirStat``，键是 ``Direction``。
```

### `StreamStat.dir_of`  (method)

```python
def dir_of(self, direction: Direction) -> DirStat | None
```

```text
取某个方向的统计。

Args:
    direction: 想查的方向（``C2S`` / ``S2C``）；传字符串会被自动转成枚举。

Returns:
    DirStat | None: 该方向没有数据时返回 ``None``（**不是**全零对象）。
        调用方据此区分「这个方向没抓到包」和「这个方向捕到包但计数为 0」。
```

### `StreamStat.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: ``dirs`` 的键会转成 ``"c2s"`` / ``"s2c"`` 字符串，``frames`` 转列表。
```

### `TcpFeatures`  (class)

```python
@dataclass
class TcpFeatures
```

```text
TCP 层的全部特征（``extract`` 阶段的输出）。

字段：
    retrans_rate / dup_ack_rate / ooo_rate: 都是**百分比**（0~100），不是 0~1。
    rtt / handshake: ``Stats``，含 p95 与抖动。
    conn_fail / conn_refused: SYN 无应答 / 被对端 RST 的会话数。
    dir_totals: 按方向汇总的 ``DirStat``，键是 ``Direction.value``。
```

### `TcpFeatures.total`  (method)

```python
def total(self, direction: Direction) -> DirStat
```

```text
取某方向的汇总。

Args:
    direction: ``C2S`` / ``S2C`` / ``BIDIR``。

Returns:
    DirStat: 该方向的汇总；缺失时返回全零实例（**不会**返回 ``None``）。

Note:
    全零 ≠ 没样本。要判断有没有数据请先查 ``Features.missing``，
    否则会把「没抓到上行包」误报成「上行完全正常」。
```

### `TcpFeatures.has_streams`  (method)

```python
@property
def has_streams(self) -> bool
```

```text
是否聚合出了会话。

Returns:
    bool: 至少有一条 ``tcp.stream`` 才能做会话级判断（谁连谁、谁在重传）。
```

### `TcpFeatures.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: ``streams`` 是 ``StreamStat.to_dict()`` 的列表，
        ``dir_totals`` 是方向字符串到 ``DirStat.to_dict()`` 的映射。
```

### `Features`  (class)

```python
@dataclass
class Features
```

```text
``extract`` 层的唯一输出，可序列化为 ``features.json`` 供 CI 回放。

有了它，规则测试不再需要 tshark（评审第 2 步）。
```

### `Features.has`  (method)

```python
def has(self, key: str) -> bool
```

```text
某个特征是否算出来了。

Args:
    key: 特征键名，如 ``"tcp.rtt"`` / ``"dns.avg"``。

Returns:
    bool: True 表示可用。False 时规则应当**跳过**，而不是判「正常」。
```

### `Features.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典，可序列化为 ``features.json`` 供 CI 回放。

Returns:
    dict: 各特征块原样输出；``missing`` 转成排序后的列表，方便 diff。
```

### `Finding`  (class)

```python
@dataclass(frozen=True)
class Finding
```

```text
一条规则命中结果。**不含中文**，也不含建议文案。
```

### `Finding.validate`  (method)

```python
def validate(self) -> None
```

```text
校验字段自洽性；不合法直接抛 —— 宁可启动就炸，也不要产出坏结论。

Returns:
    None: 校验通过时无返回值。

Raises:
    ValueError: ``rule_id`` 形态不符 ``RULE_ID_RE``、``confidence`` 越界、
        推断类（``INFERRED``）却给了 1.0 置信度、或者判了严重却没有任何
        ``targets`` / ``metric`` 可用于定位。
```

### `Finding.rank`  (method)

```python
@property
def rank(self) -> int
```

```text
严重度排序权重（越小越严重）。

Returns:
    int: critical=0 / warning=1 / info=2 / ok=3 / na=4，用于 ``min()`` 找最坏项。
```

### `Finding.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: ``layer`` / ``severity`` / ``category`` / ``evidence_kind`` /
        ``direction`` 转成字符串，``targets`` / ``frames`` / ``streams`` 转列表。
```

### `Sufficiency`  (class)

```python
@dataclass(frozen=True)
class Sufficiency
```

```text
证据充分性。``ok=False`` 时结论必须降级为「无法判定」（评审 P0-4）。
```

### `Sufficiency.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: 键 ``ok`` / ``reasons`` / ``needed`` / ``reason_args``。
        前三者的内容是 copy 表的 key（不是成句中文），渲染层负责翻译。
```

### `LayerStatus`  (class)

```python
@dataclass(frozen=True)
class LayerStatus
```

```text
某一层的汇总状态（给 UI 的四层状态条用）。

字段：
    layer: 哪一层。
    severity: 该层最坏项的严重度。
    detail_key / detail_args: 「L4 有 2 条严重」这类描述的文案 key 与占位符实参。
    finding_ids: 归属这一层的 ``rule_id`` 列表。
```

### `LayerStatus.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: ``layer`` / ``severity`` 是字符串，``finding_ids`` 是列表。
```

### `Verdict`  (class)

```python
@dataclass(frozen=True)
class Verdict
```

```text
最终判定 —— 一句话结论 + 四层状态 + 本次结论的证据边界。

字段：
    level: 总体严重度。
    headline_key / headline_args: 结论文案的 key 与占位符实参（**不含中文**）。
    impact_key: 「对用户意味着什么」的文案 key。
    next_step_keys: 处置建议的 key 列表，按优先级排列。
    sufficiency: 证据是否够；``ok=False`` 时 ``level`` 必须是降级后的结论
        （见 ``VERDICT.INSUFFICIENT``），不能拿「没样本」当「正常」。
    confidence: 结论级置信度（**不是** ``Finding.confidence``），由证据推导，
        必须落在 ``[0,1]``；推断类结论不得为 1.0。
    basis / coverage / not_covered: 本次结论的依据 / 覆盖 / 明确未覆盖，
        已是可读句子的运行时事实（静态模板在 ``copy/zh-CN.json`` 的
        ``conclusion`` section）。三者都落库进报告 JSON 的 verdict 块。

注意：
    ``confidence_level`` 是派生 ``@property``，**不是** dataclass 字段，因此
    无法在构造器里人工填写、也无法赋值；``key_limit`` 只存在于渲染层，
    两者都**不落库**（见 E-IMPL-SPEC §1）。
```

### `Verdict.confidence_level`  (method)

```python
@property
def confidence_level(self) -> str
```

```text
派生置信等级（不是 dataclass 字段，无法人工填写）。

Returns:
    str: ``"高"`` / ``"中"`` / ``"低"``，阈值见
        :data:`CONFIDENCE_HIGH_MIN` 与 :data:`CONFIDENCE_MEDIUM_MIN`。
```

### `Verdict.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: ``layers`` 是 ``LayerStatus.to_dict()`` 的列表，
        ``sufficiency`` 是 ``Sufficiency.to_dict()``；
        ``confidence`` 为 float，``basis`` / ``coverage`` /
        ``not_covered`` 为字符串列表。**不含** ``confidence_level``
        与 ``key_limit``（二者是渲染期派生值，不落库）。
```

### `Provenance`  (class)

```python
@dataclass(frozen=True)
class Provenance
```

```text
让一份结论可复现（评审 4.1 第 5 条）。
```

### `Provenance.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: 键 ``app_version`` / ``schema_version`` / ``tshark_version`` /
        ``rules_version`` / ``config_sha256`` / ``prompt_version`` / ``generated_at``。
        任一来源取不到时该键是空串而非 ``None``，方便直接拼进报告表头。
```

### `AnalyzeResult`  (class)

```python
@dataclass
class AnalyzeResult
```

```text
一次离线/实时分析的完整结果（顶层对象）。

字段：
    capture: 采集元信息。
    features: 提取出的全部特征（``extract`` 的输出）。
    findings: 规则命中的结论，已按严重度排序。
    metrics: 给报告用的扁平指标表（含百分比、均值），保留旧字段名。
    verdict: 判定结果；``None`` 表示还没算。
    provenance: 可复现信息。
```

### `AnalyzeResult.by_layer`  (method)

```python
def by_layer(self, layer: Layer) -> tuple[Finding, ...]
```

```text
取某一层的全部发现。

Args:
    layer: 目标层（``Layer`` 枚举或其字符串值）。

Returns:
    tuple[Finding, ...]: 该层的发现，保持原有排序；无命中时是空元组而非 ``None``。
```

### `AnalyzeResult.worst`  (method)

```python
@property
def worst(self) -> Finding | None
```

```text
最严重的那一条发现。

Returns:
    Finding | None: 没有任何发现时返回 ``None``。
        注意 ``None`` 只表示「没命中规则」，**不代表**证据充分 ——
        那个要看 ``verdict.sufficiency.ok``。
```

### `AnalyzeResult.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典，作为 ``/api/v1/analyze`` 的响应体。

Returns:
    dict: 嵌套的 ``features`` / ``findings`` / ``verdict`` 已递归转成基本类型。
```

### `ProbeResult`  (class)

```python
@dataclass
class ProbeResult
```

```text
``probe``（协议自适应体检）的结果。字段含义沿用现有实现。
```

### `ProbeResult.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: ``segments`` 是分段计时列表，每段含 ``phase`` / ``ms`` / ``ok``；
        ``level`` 与 ``evidence_kind`` 转成字符串。
```

### `PassiveResult`  (class)

```python
@dataclass
class PassiveResult
```

```text
``passive``（通信观察 / 被动监听）的结果。
```

### `PassiveResult.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: ``flows`` 是会话列表；``summary`` 含计数、协议分布与扇出（fanout）提示。
```

### `Job`  (class)

```python
@dataclass
class Job
```

```text
一个后台任务。抓包、分析抓包文件、通信观察都走它。

字段：
    job_id: 短随机串，用作 API 路径参数。
    params: 启动参数原样保存，便于「按上次参数重跑」。
    progress: 0.0~1.0；无法估算进度时保持 0，前端显示为「进行中」而不是假的百分比。
    error: 失败时的 ``DiagError.to_dict()``。
    result_ref: 结果落盘路径；大结果不塞进内存，避免轮询把内存打满。
    trace_id: 关联日志，便于前端报错对上后端记录。
```

### `Job.running`  (method)

```python
@property
def running(self) -> bool
```

```text
是否还在执行。

Returns:
    bool: ``QUEUED`` 或 ``RUNNING`` 时为 True。
```

### `Job.public`  (method)

```python
def public(self) -> dict
```

```text
给 ``GET /api/v1/jobs/{id}`` 用的视图。

Returns:
    dict: 10 个字段（``job_id`` / ``kind`` / ``state`` / ``progress`` /
        ``created_at`` / ``started_at`` / ``finished_at`` / ``error`` /
        ``result_ref`` / ``trace_id``）。**不含**完整 ``result`` ——
        否则前端每次轮询都要拉几 MB 的结论。
```

### `Job.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典（含完整 ``result``，用于落盘存档）。

Returns:
    dict: 全部字段；``state`` 已转成字符串。
```

### `envelope_ok`

```python
def envelope_ok(data: Any, trace_id: str='') -> dict
```

```text
成功响应信封。所有 ``/api/v1/*`` 的成功返回都套这一层。

Args:
    data: 业务数据，任意契约对象（内部会 ``to_jsonable``）。
    trace_id: 请求追踪号，用于把前端报错对上后端日志。

Returns:
    dict: 键 ``schema_version`` / ``ok``(True) / ``data`` / ``error``(None) / ``trace_id``。
```

### `envelope_err`

```python
def envelope_err(code: str, message: str, hint: str='', trace_id: str='', **extra) -> dict
```

```text
失败响应信封。**所有**可预期失败都应走这里，不要混用纯文本 404。

Args:
    code: ``ErrorCode.value``，如 ``"E_NO_TSHARK"``。
    message: 面向用户的说明，一句话说清发生了什么。
    hint: 下一步怎么办；留空时由调用方从 ``errors.HINTS`` 取该 code 的默认提示。
    trace_id: 请求追踪号。
    **extra: 附加诊断信息，会被放进 ``error["detail"]``。

Returns:
    dict: 键 ``schema_version`` / ``ok``(False) / ``data``(None) / ``error`` / ``trace_id``；
        ``error`` 内含 ``code`` / ``message`` / ``hint``（有 extra 时加 ``detail``）。
```

## `core/copytext.py`

**职责**：文案表访问器：``core/copy/zh-CN.json`` 的唯一读取入口（带进程内缓存）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `reload` | function | 61 | ✅ |
| `load_table` | function | 72 | ✅ |
| `section` | function | 88 | ✅ |
| `get` | function | 106 | ✅ |
| `text` | function | 122 | ✅ |

### `reload`

```python
def reload() -> None
```

```text
清空文案表缓存。

正常运行时不需要调用（文件变化会按 mtime/size 自动失效）。
只有「测试 monkeypatch 了 ``core.config.load_copy``」这种**文件没变、来源变了**
的场景必须显式调用，否则会读到缓存里的真实表。
```

### `load_table`

```python
def load_table() -> dict
```

```text
读取文案表（按文件 mtime/size 缓存，重复调用 O(1)）。

Returns:
    dict: 解析后的 copy 表；文件缺失 / 损坏 / 顶层不是对象时返回空表。
        不抛异常 —— 调用方会回退成显示 key。
```

### `section`

```python
def section(table: dict, path: str) -> dict
```

```text
按点号路径取子表（如 ``verdict.titles``）。

Args:
    table: :func:`load_table` 返回的表。
    path: 点号分隔的 section 路径。

Returns:
    dict: 命中的子表；任一层缺失或不是对象时返回空表。
```

### `get`

```python
def get(table: dict, path: str, key: str, default=None)
```

```text
从给定表里取字符串文案（不格式化）。

Args:
    table: 文案表。
    path: section 点号路径。
    key: section 内的键（键本身可以带点，如 ``L4.RETRANS.ADVICE``）。
    default: 缺失或不是字符串时的返回值。

Returns:
    str | None: 命中返回字符串，否则返回 ``default``。
```

### `text`

```python
def text(path: str, key: str, default: str='', table: dict | None=None, **args) -> str
```

```text
取文案并按 ``str.format(**args)`` 填充占位符。

Args:
    path: section 点号路径（如 ``report`` / ``verdict.titles``）。
    key: section 内的键。
    default: 缺 key 时的回退值；为空时回退成 key 本身。
    table: 可选的已加载表。热循环（如 ``_stream_rows`` 的会话标记）传它可以把
        「读表」摊销到一次；不传时走 :func:`load_table`（有缓存，O(1)）。
    **args: 占位符实参。

Returns:
    str: 可直接展示的文案。缺 key / 缺实参都不抛异常。
```

## `core/diagnose.py`

**职责**：NetDiag（网络矩阵）采集与诊断主流程（CLI 入口）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `load_config` | function | 51 | ✅ |
| `log` | function | 114 | ✅ |
| `capture_filter_for` | function | 220 | ✅ |
| `bpf_for` | function | 306 | ✅ |
| `capture_live` | function | 604 | ✅ |
| `degraded_empty_capture_result` | function | 879 | ✅ |
| `run_scan` | function | 1056 | ✅ |
| `main` | function | 1381 | ✅ |

### `load_config`

```python
def load_config() -> dict
```

```text
读 ``config/app-config.json``（本模块自带的极简版本）。

Returns:
    dict: 默认值叠加文件内容。与 :func:`core.config.load_app` 的区别是不做类型收敛 ——
        这是历史入口，收敛逻辑在新模块里（两者结果在正常配置下一致）。
```

### `log`

```python
def log(msg: str) -> None
```

```text
默认日志回调：打印到控制台，同时追加到 ``logs/diag-YYYYMMDD.log``。

Args:
    msg: 日志正文。

Returns:
    None: 写盘失败只影响日志，不影响诊断。
```

### `capture_filter_for`

```python
def capture_filter_for(target: str, logger=None) -> dict
```

```text
决定「单目标诊断（定向抓包）」阶段到底用不用 BPF 过滤器。

路测根因：``-f "host baidu.com"`` 在 tshark 里会先把域名解析成 IP，而 mihomo
的 fake-ip（198.18.0.0/15）并不是真实业务地址，过滤后 0 包。因此只有**解析
结果全部是公网地址**时才用 ``host <ip>``；fake-ip / 私网 / 解析失败 / 无法
表达的目标一律不加抓包过滤器（抓全网），分析阶段仍按用户目标筛选。

Args:
    target: 用户输入的目标，如 ``192.168.1.10`` / ``192.168.1.0/24`` /
        ``baidu.com``；空串表示全网。
    logger: 日志回调；省略时不打印。

Returns:
    dict: 键 ``bpf``（最终过滤器，空串=无过滤）/ ``kind``（``none`` /
        ``ip`` / ``cidr`` / ``domain``）/ ``resolved``（域名解析出的 IP 列表）/
        ``reason``（决策原因）。只有**公网** IP、域名、CIDR 才会下过滤器；
        私网 / fake-ip / 回环等目标一律抓全网，分析阶段再按目标筛。
```

### `bpf_for`

```python
def bpf_for(target: str) -> str
```

```text
把目标转成实时抓包用的 BPF 过滤器（兼容旧调用方）。

只保留「能安全进 tshark 命令行」的写法，真正的取舍在
:func:`capture_filter_for`：域名解析到 fake-ip/私网/失败时返回空串（抓全网）。

Args:
    target: 用户输入的目标，如 ``192.168.1.10`` / ``10.0.0.0/24`` / ``example.com``。

Returns:
    str: BPF 串；空串表示抓全网（空目标、解析失败、fake-ip/私网域名、
        私网 IP / 私网 CIDR 等）。

Raises:
    ValueError: 目标含非法字符，或长度超过 200 个字符（由调用方转成可展示的错误）。
```

### `capture_live`

```python
def capture_live(target: str='', duration: int=30, interface: str | None=None, logger=log, shadow: bool=False) -> dict
```

```text
实时抓包并落盘到 ``captures/``。

Args:
    target: 抓包目标；空表示全网。实际过滤器由 :func:`capture_filter_for`
        决定：域名只有解析结果全是公网地址时才用 ``host <ip>``，fake-ip/
        私网/解析失败一律不加过滤器（分析阶段仍按目标筛选）。
    duration: 首块网卡的抓包秒数；换卡重试时每块缩短为 ``min(duration, 10)``。
    interface: 网卡序号或名称关键字；空则按 :func:`tshark.order_interfaces`
        的候选顺序逐块探测（每块 2 秒、最多 5 块），取第一块真有流量的；
        全都没流量再用 :func:`tshark.pick_interface` 兜底。显式指定时**只抓该网卡**：
        抓到 0 包/0 字节也不换卡（尊重用户选择，避免「指定 Meta 却静默换到 WLAN」
        给出错误结论），直接返回带候选网卡与自助命令的错误。
    logger: 日志回调。
    shadow: 是否在抓包同时启动影子探测与路径探测（MTR）。默认 ``False``；
        ``run_scan``/UI 传 ``True``。两类探针的抓包排除式都会**合并进 BPF**
        （第一道隔离），账本/路径结果随成功结果分别以 ``probe`` / ``path``
        键返回（``run_scan`` 据此注入基线/路径剖面）。**MTR 只在有目标时启动**：
        全网体检没有对端，逐跳没有意义。

Returns:
    dict: 成功 ``{"ok": True, "pcap": str, "interface": str, "interface_index": int,
        "bpf": str, "duration": int}``（``shadow=True`` 且确实发出探针时再加
        ``"probe"``：账本 + 聚合基线 + 三种过滤串；MTR 产出了逐跳数据时再加
        ``"path"``：路径剖面 + 两种过滤串）；失败 ``{"ok": False,
        "error": str, "degraded": bool, "empty": bool, "interface": str,
        "bpf": str}``。
        **所有**返回路径都带 ``interface`` / ``bpf``（没有可用值时为 ``""``），
        供降级卡与 ``degraded_*`` 报告写「最终网卡 / 实际过滤器」；``empty=True``
        表示抓包窗口内 0 包（可走 0 包降级），``degraded=True`` 表示
        「缺 tshark/Npcap/提权」这类环境问题，前端据此提示改用分析抓包文件。
        自动选择模式下抓满 0 包/0 字节时不直接失败，会按候选顺序自动换卡重试
        （最多 3 块）；全失败时 ``interface`` 是最后尝试的那块，错误里带
        ``--interfaces`` / ``--interface`` 指引与常见原因。显式指定模式 0 包时
        不换卡，错误里列出本次探测发现有流量的候选网卡和两条自助命令。

Note:
    返回前会等文件大小稳定（最多 3 秒）。tshark 进程退出 ≠ 数据已落盘，
    在写盘窗口期就开始分析会读到半份数据，进而产生幻影告警（T00）。
    0 包的空抓包文件会被删除（日志写一行「已删除空抓包」），避免在
    ``captures/`` 留下无法分析的垃圾。

    影子探测的线程收尾放在 ``finally``：抓包成功/失败/抛异常都会
    ``stop()`` + ``join(3)``；探针自身异常只写进账本 ``error``，不影响
    本函数返回值与主诊断退出码。路径探测同理：线程异常只写进 ``path.error``，
    时间预算（抓包时长 + 5s）用完就返回已完成的跳，绝不阻塞抓包。
```

### `degraded_empty_capture_result`

```python
def degraded_empty_capture_result(target: str='', duration: int=0, interface: str | None=None, capture_error: str='', bpf: str='', logger=log) -> dict | None
```

```text
0 包优雅降级：抓包窗口没有业务报文时，用链路可达性代替「红色失败」。

路测反馈：网卡选错、流量走 VPN/TUN、或目标本来就没流量时，三块网卡 0 包直接
判「诊断失败」会让人以为工具坏了。这里自动对「目标 → 默认网关」做一次 ICMP
体检，只要拿到时延/抖动/丢包就返回中性降级结论；只有连这组信息都拿不到
（如 Npcap 不可用、网卡打不开）时才让调用方报错。

Args:
    target: 用户填的目标；空表示全网体检（不设过滤，抓本机全部流量）。
    duration: 本次抓包时长（秒），写进结论。
    interface: 用户显式选择的网卡；空表示自动选择。
    capture_error: 抓包阶段的原始错误文案（放进「为什么」供排障）。
    bpf: 本次实际使用的 BPF 过滤器；空串表示全网。
    logger: 日志回调。

Returns:
    dict | None: 成功时 ``{"ok": True, "degraded": True, "headline",
        "plain", "link": {...}, "reasons": [...], "next_steps": [...],
        "capture": {...}}``；目标与默认网关都测不到时返回 ``None``
        （调用方应按真正的失败处理）。
```

### `run_scan`

```python
def run_scan(target: str='', duration: int=30, interface: str | None=None, pcap: str | None=None, logger=log, report_dir: str | Path | None=None, shadow: bool=False) -> dict
```

```text
完整诊断：抓包（或复用已有 pcap）→ 分析 → 落盘报告 → 记一条 run。

Args:
    target: 目标 IP/网段/域名；空表示全网。
    duration: 实时抓包秒数（仅无 ``pcap`` 时生效）。
    interface: 网卡序号或名称关键字。
    pcap: 分析抓包文件的路径。只给文件名时会到 ``captures/`` 下找
        （兼容 U 盘盘符变化）。
    logger: 日志回调。
    report_dir: 报告输出目录；``None``（默认）写 ``reports/``，与历史行为一致。
        给定时只写该目录（目录不存在会自动创建），文件名清洗仍由
        :func:`report.save` 负责。
    shadow: 实时抓包时是否同时做影子探测**与路径探测（MTR）**。**产品入口默认开**
        （CLI 不传 ``--no-shadow`` 即开、UI 默认勾选、``/api/scan`` 缺省
        ``true``）；本函数作为库入口默认 ``False``，保证旧调用方行为不变。
        **离线路径（``pcap`` 非空）恒不启动探针**——用户可能只是在分析别人
        给的抓包文件。MTR 只在有目标时启动（全网体检没有对端）。

Returns:
    dict: ``analyzer.analyze()`` 的结果，另加 ``report``（``.md``/``.json`` 落盘路径）
        与 ``capture``（本次采集参数）；有探针数据时 ``meta["probe_baseline"]``
        里带「探针基线」、有逐跳数据时 ``meta["path_profile"]`` 里带「路径剖面」
        （无数据时这两个键都不存在，输出与 main 逐字节一致）。
        失败时 ``{"ok": False, "error": "..."}``。

Note:
    无论成功、失败还是抛异常，都会调用一次 :func:`logstore.record_run`
    （``mode`` 为 ``offline`` / ``live``）。UI 的 ``/api/scan`` 也走本函数，
    所以两个入口共用同一个记录点，一次分析只有一条记录。

    影子探测的三层隔离都在本函数/``capture_live`` 内完成：抓包 BPF 合并、
    分析阶段 ``-Y`` 显示过滤、报告里写「已排除 N 个探针包」；任何一步失败
    都只降级为「探针不可用」，不改变主诊断结论与退出码。路径探测同理，并且
    多一条：ICMP type 11（TTL 超时）整类从**显示过滤**排除，排除数量写进报告。
```

### `main`

```python
def main(argv: list[str] | None=None) -> int
```

```text
``diagnose.py`` 的命令行入口（不开界面也能出报告）。

Args:
    argv: 参数列表；省略时取 ``sys.argv[1:]``。支持 ``--target`` / ``--duration`` /
        ``--interface`` / ``--pcap`` / ``--interfaces``（只列网卡）/ ``--json``
        （完整结论对象：``summary`` + ``conclusion`` 边界；旧版只打摘要）/
        ``--report-out``（把完整报告**只**写指定目录、**不再写** ``reports/``；
        省略时仍写 ``reports/``）/ ``--export-diag``（导出脱敏诊断包后退出，
        可配 ``--include-reports`` / ``--raw`` / ``--out``）/ ``--no-shadow``
        （实时抓包时关闭影子探测；默认开，离线分析恒不发探针）。

Returns:
    int: 0 成功；2 分析失败（如抓包文件不完整）；其它非 0 表示环境问题。

Note:
    入口第一件事是 :func:`_harden_console`：cp936 控制台下把编不出的 emoji
    转义成 ``\u274c``，避免「报告已落盘、打印时却 exit 1」。只影响控制台
    显示，``.md`` / ``.json`` 报告内容不变。
```

## `core/diagpack.py`

**职责**：诊断包导出：把 ``logs/`` 里能回答「出了什么问题」的现场打成一个**已脱敏**的 zip。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `build` | function | 69 | ✅ |

### `build`

```python
def build(out_dir=None, include_reports: bool=False, raw: bool=False) -> Path
```

```text
收集现场 → 脱敏 → 写 zip，返回诊断包路径（唯一公开入口，SPEC V1）。

Args:
    out_dir: 输出目录；``None`` 表示默认的 ``<日志根目录>/exports/``。
        相对路径按当前工作目录解析，不存在会自动创建。
    include_reports: 是否附上 ``reports/`` 里最近 3 份报告（``.md`` / ``.json``）。
    raw: ``True`` 表示**不脱敏**、保留原始 IP/域名/用户名/MAC；默认 ``False``。
        控制台警告由调用方（CLI / 服务端）打印，包内 README 也会写醒目警告。

Returns:
    Path: 新生成的 zip 的绝对路径。同名文件已存在时会顺延 ``-2`` / ``-3``，
        不会覆盖旧包。

Raises:
    OSError: 输出目录不可写、zip 写盘失败（半成品会被删除后重新抛出）。
        单个源文件读不到或脱敏失败不算错误，只会跳过并写进 README。
    RuntimeError: 泄漏自检发现仍有原值残留；此时**不会生成 zip**，错误信息只报
        token 类别、不含原值（默认拒绝：宁可导出失败，不可泄露）。

Note:
    自检只在默认（非 ``raw``）模式执行；``raw=True`` 按设计保留原值。
```

## `core/errors.py`

**职责**：错误码与可展示异常。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `ErrorCode` | class | 14 | ✅ |
| `DiagError` | class | 57 | ✅ |
| `DiagError.to_dict` | method | 69 | ✅ |

### `ErrorCode`  (class)

```python
class ErrorCode
```

```text
稳定错误码。前端按 ``code`` 分支处理，不靠匹配中文文案。

分四组：环境/依赖（``E_NO_*`` / ``E_NOT_WRITABLE``）、输入（``E_BAD_*`` /
``E_EMPTY_CAPTURE``）、任务（``E_JOB_*``）、AI 与外发（``E_AI_*``）。
```

### `DiagError`  (class)

```python
class DiagError
```

```text
可预期失败。``message`` 面向用户，``hint`` 面向「下一步怎么办」。
```

### `DiagError.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转成响应信封里的 ``error`` 对象。

Returns:
    dict: 键 ``code``（``ErrorCode.value``）/ ``message`` / ``hint``；
        构造时带了附加参数的话再加 ``detail``。
```

## `core/evidence.py`

**职责**：通用「取证请求单」：把本次诊断结论翻译成一张可直接转发的取证清单。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `validate_template` | function | 69 | ✅ |
| `load_template` | function | 122 | ✅ |
| `dimensions_for` | function | 282 | ✅ |
| `build_checklist` | function | 355 | ✅ |
| `render_checklist_markdown` | function | 438 | ✅ |
| `render_checklist_text` | function | 485 | ✅ |

### `validate_template`

```python
def validate_template(template: dict) -> list[str]
```

```text
校验清单模板结构，返回问题列表（空列表 = 合法）。

只校验**结构**，不校验措辞；厂商名由测试用 ``-F`` 扫描，避免把「一家厂商
改个名」这种文案变化误判成结构错误。

Args:
    template: 从 ``core/copy/evidence_checklist.json`` 读出的对象。

Returns:
    list[str]: 人类可读的问题列表；模板合法时为空列表。检查项：
        7 个维度键齐全且无多余键、每维 ``name``/``note`` 为非空字符串、
        ``items`` 为列表、每项恰好含 :data:`ITEM_FIELDS` 四键且值为非空字符串。
```

### `load_template`

```python
def load_template(path: Path | str | None=None) -> dict
```

```text
读取并校验清单模板（显式 loader，便于测试注入与变异）。

Args:
    path: 模板文件路径；省略时读仓库内的
        ``core/copy/evidence_checklist.json``。

Returns:
    dict: 已通过 :func:`validate_template` 的模板对象。

Raises:
    OSError: 文件不存在或不可读。
    json.JSONDecodeError: 文件不是合法 JSON。
    ValueError: JSON 合法但结构不符（缺维度、缺字段等），消息含前几条问题。
```

### `dimensions_for`

```python
def dimensions_for(result: dict, verdict: dict | None=None) -> list[str]
```

```text
把「本次结论」映射成相关维度集合（纯函数、可测试、可变异）。

规则（按顺序短路，命中即返回）：

1. 判定为「证据不足」或 ``verdict.sufficiency.ok is False`` 或存在
   ``category == "采集有效性"`` 的条目 → 返回**全部 7 维**（通用空白版）。
2. 判定为「正常」且没有任何 ``points`` → 返回空列表（报告不出现区块）。
3. 其余情况按问题条目逐条映射，并**始终包含** ``terminal``（工具自己已采，
   列出来是为了声明「这一侧不需要再要」）：

   - ``L2`` / ``本地可达性``（ARP、本地链路）→ ``wireless`` + ``wired``；
   - ``L3`` / ``网络可达性`` / ``网络时延``（含 ICMP 不可达）→ ``transport``；
   - ``L4`` / ``连接建立`` / ``传输质量``（重传、建连失败、零窗口）→ ``transport``；
   - ``L7`` / ``域名解析`` → ``naming``；``TLS 会话`` → ``crypto_proxy`` + ``service``；
     ``应用响应`` 或其它 L7 类别 → ``service``；
   - ``verdict.probe_contrast`` 指向对端（``TARGET_SIDE``）→ 追加 ``service``；
     指向本地（``LOCAL_SIDE``）→ 追加 ``wired``；
   - 安全观察行不参与映射；类别无法识别但有故障 → 兜底 ``transport``。

返回顺序固定为 :data:`DIMENSION_KEYS` 的顺序，便于逐字节断言。

Args:
    result: 诊断结果字典（读 ``verdict`` 与 ``rows``；缺 ``verdict`` 时现算）。
    verdict: 可选的已算好判定（报告渲染路径传入，避免重复计算）。

Returns:
    list[str]: 维度机器码列表；空列表表示本次不需要外部取证。
```

### `build_checklist`

```python
def build_checklist(result: dict, full: bool=False, verdict: dict | None=None, template: dict | None=None, conclusion: dict | None=None) -> dict
```

```text
按本次结论生成清单；``full=True`` 生成覆盖 7 维的通用空白版。

``full=True`` 时**不依赖 ``result`` 与结论**：``result={}`` 也能返回完整的
7 维（界面「复制通用空白版」在还没有诊断结果时也必须是可达的）。

Args:
    result: 诊断结果字典（``verdict`` / ``rows`` 决定相关维度）。
    full: 为 ``True`` 时忽略结论、输出全部 7 维（界面「复制通用空白版」用）。
    verdict: 可选的已算好判定；报告渲染/接口传入同一个判定，避免重复计算。
    template: 可选的模板对象（测试注入/变异用）；省略时用导入期加载的模板。
    conclusion: 可选的已算好结论边界对象（E1）。报告/接口可传入同一个
        :func:`core.conclusion.build_conclusion` 产物；省略且 ``full=False``
        时按本次 ``result`` + ``verdict`` 现算一次，保证取证单与报告同源。

Returns:
    dict: ``{"full": bool, "level": str, "layer": str, "dimensions": [...]}``；
        ``dimensions`` 每项 ``{"key", "name", "note", "items"}``，``items``
        每项恰好 ``field/why/where/criteria`` 四键。E1 起加法键
        ``conclusion``（结论边界对象，``full=True`` 时为通用空白版不加）；
        模板不可用时返回空 ``dimensions``（调用方据此不渲染区块）。
```

### `render_checklist_markdown`

```python
def render_checklist_markdown(checklist: dict, include_conclusion: bool=True) -> str
```

```text
把清单渲染成报告内 Markdown 区块（维度小标题 + 四列表格）。

维度与条目文字来自模板 JSON，标题/表头等标签来自 ``copy.evidence_checklist``；
没有维度时返回空串（调用方据此不追加区块）。E1 起若 ``checklist`` 带
``conclusion`` 边界对象，则在清单**之前**输出同一结论+边界块（与报告同源），
保证「任何只给结论不给边界的导出路径」不成立。

Args:
    checklist: :func:`build_checklist` 的返回值。
    include_conclusion: 是否在清单前输出结论边界块；报告正文第一节已经
        输出过同一块时也**保留**（报告末尾的取证单是「整块可转发」的副本，
        复制给协作方时结论和边界不会丢）。

Returns:
    str: 以 ``copy.evidence_checklist.section_title`` 开头、以换行结尾的 Markdown；
        无维度时返回 ``""``。
```

### `render_checklist_text`

```python
def render_checklist_text(checklist: dict, include_conclusion: bool=True) -> str
```

```text
把清单渲染成纯文本（方便直接发微信/工单，不含 Markdown 表格符号）。

E1 起若 ``checklist`` 带 ``conclusion`` 边界对象，则在清单前输出同一结论+
边界块的**纯文本版**（复制给协作方时结论与边界一起走）。

Args:
    checklist: :func:`build_checklist` 的返回值。
    include_conclusion: 是否在清单前输出结论边界块；默认输出。

Returns:
    str: 纯文本清单；无维度时返回 ``""``。正文不含 ``|`` 与 ``#`` 标题符号，
        每项四字段各占一行并缩进。
```

## `core/extract/__init__.py`

**职责**：extract 层：把 tshark 的原始输出变成可回放的 ``Features``。

_（无公开符号）_

## `core/extract/aggregate.py`

**职责**：把逐行报文聚合成 ``Features``（T04 的聚合层）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `_DirAcc.freeze` | method | 68 | ✅ |
| `build_features` | function | 251 | ✅ |

### `_DirAcc.freeze`  (method)

```python
def freeze(self, direction: Direction) -> DirStat
```

```text
冻结成不可变的 ``DirStat``。

Args:
    direction: 该累加器对应的方向。

Returns:
    DirStat: 计数字段逐一搬过去，``rtt`` 由 ``Stats.from_values`` 现算。
```

### `build_features`

```python
def build_features(rows: Sequence[Mapping[str, Any]], meta: Mapping[str, Any] | None=None, stats: Mapping[str, Any] | None=None) -> Features
```

```text
把逐行报文聚合成 ``Features``。

Args:
    rows: 每个报文一行，键是 tshark 字段名（``"tcp.stream"`` 等），
        值保留原始字符串。由 ``tshark -T fields`` 的输出来。
    meta: 采集元信息，可选键 ``pcap_file`` / ``pcap_name`` / ``mode`` /
        ``interface`` / ``bpf``。
    stats: 兼容 ``analyzer.collect()`` 的统计字典；仅在报文时间戳算不出
        时长时用它兜底填 ``capture.duration_s``。

Returns:
    Features: 含 TCP 全量特征与 ``missing`` 清单。
        ``missing`` 里登记的键表示「这份抓包里没有可算的样本」，
        规则层必须据此跳过判断，**不得**当成「一切正常」。
```

## `core/extract/fields.py`

**职责**：tshark 字段清单与「原始字符串 → Python 值」的解析函数。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `parse_flag` | function | 85 | ✅ |
| `parse_num` | function | 103 | ✅ |
| `parse_port` | function | 129 | ✅ |
| `parse_int` | function | 147 | ✅ |
| `parse_rows` | function | 173 | ✅ |

### `parse_flag`

```python
def parse_flag(v: Any) -> bool
```

```text
把 tshark 的布尔字段转成 ``bool``。

任一逗号分段命中 ``1`` / ``true`` / ``yes`` 即为真（大小写不敏感）。
这样 ``"True"``、``"1,1"``、``" 1 "`` 都能正确识别。

Args:
    v: tshark 原始值，可能是 ``"1"`` / ``"0"`` / ``"True"`` / ``"False"`` /
        ``"1,1"`` / ``None`` / 空串。

Returns:
    bool: 为真返回 True；空值、``"0"``、``"False"``、无法识别的串返回 False。
```

### `parse_num`

```python
def parse_num(v: Any) -> float | None
```

```text
把 tshark 的数值字段转成 ``float``；取不到就返回 ``None``。

取逗号聚合值的**第一段**（``"0.123,0.456"`` → ``0.123``）。

为什么返回 ``None`` 而不是 ``0.0``：``0`` 是一个合法测量值
（零延迟、零窗口），用它表示「没这个字段」会让上层无法区分
「测到 0」和「没测」，从而把「没样本」误判成「一切正常」。

Args:
    v: tshark 原始值。

Returns:
    float | None: 解析成功返回数值；空串 / ``None`` / 非数字返回 None。
```

### `parse_port`

```python
def parse_port(v: Any) -> int
```

```text
把 tshark 的端口字段转成 ``int``；失败返回 ``0``。

Args:
    v: tshark 原始值，可能是 ``"443"`` / ``"443,8080"`` / 空串。

Returns:
    int: 逗号取第一段；空串与非法值返回 0（端口 0 不是合法业务端口，
        上层可以据此判断「没有端口」）。
```

### `parse_int`

```python
def parse_int(v: Any) -> int
```

```text
把 tshark 的整数字段转成 ``int``；失败返回 ``0``。

与 :func:`parse_port` 的区别只在于语义：这里用于 frame.number / frame.len /
tcp.len 这类计数，``0`` 天然表示「没有」。

Args:
    v: tshark 原始值。

Returns:
    int: 解析成功返回整数（``"3.0"`` 这类也会转成 3）；失败返回 0。
```

### `parse_rows`

```python
def parse_rows(lines: Iterable[str]) -> list[dict[str, str]]
```

```text
把 ``tshark -T fields`` 的整段输出解析成行字典列表。

表头行（``-E header=y`` 产生的）会被识别并用作键名；没有表头时按
:data:`FIELDS` 的顺序对齐。列数不足时补空串 —— tshark 在字段全空的帧上
会少输出分隔符，直接 ``zip`` 会让后面的字段整体错位。

Args:
    lines: tshark 输出的行序列（已去掉行尾换行）。

Returns:
    list[dict[str, str]]: 每个报文一行，键是字段名，值是**原始字符串**
        （不做类型转换，交给 :func:`parse_flag` 等函数按需解析）。
```

## `core/logstore.py`

**职责**：唯一日志出口：目录、按日文件、裁剪、环境快照、分析记录、崩溃快照。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `log_root` | function | 69 | ✅ |
| `ensure_dirs` | function | 92 | ✅ |
| `_DailySink.close` | method | 189 | ✅ |
| `_DailySink.write` | method | 210 | ✅ |
| `_Stream.write` | method | 248 | ✅ |
| `_Stream.writelines` | method | 262 | ✅ |
| `_Stream.flush` | method | 274 | ✅ |
| `_Stream.isatty` | method | 278 | ✅ |
| `_Stream.writable` | method | 286 | ✅ |
| `_Stream.readable` | method | 294 | ✅ |
| `_Stream.fileno` | method | 302 | ✅ |
| `_Stream.closed` | method | 314 | ✅ |
| `_Stream.close` | method | 322 | ✅ |
| `app_log` | function | 351 | ✅ |
| `diag_log` | function | 363 | ✅ |
| `open_stream` | function | 375 | ✅ |
| `close_streams` | function | 385 | ✅ |
| `write_env_snapshot` | function | 456 | ✅ |
| `record_run` | function | 483 | ✅ |
| `record_crash` | function | 529 | ✅ |
| `install_excepthooks` | function | 612 | ✅ |
| `prune` | function | 711 | ✅ |

### `log_root`

```python
def log_root() -> Path
```

```text
返回日志根目录。

Returns:
    Path: 环境变量 ``NETDIAG_LOG_DIR`` 非空时用它，否则 ``<仓库>/logs``。
        每次调用都重新读环境变量，测试可以在同一进程里切换临时目录。
```

### `ensure_dirs`

```python
def ensure_dirs() -> Path
```

```text
创建日志目录树（``logs/``、``runs/``、``crashes/``）与当天的两个日文件。

当天的 ``app-YYYYMMDD.log`` / ``diag-YYYYMMDD.log`` 会以空文件形式先建出来，
这样「跑一次分析后的目录树」是稳定的，不依赖先打印了哪条日志。

Returns:
    Path: 日志根目录（创建失败也返回路径，真正写盘时再静默失败）。
```

### `_DailySink.close`  (method)

```python
def close(self) -> None
```

```text
关闭当前句柄；可重复调用。
```

### `_DailySink.write`  (method)

```python
def write(self, text: str) -> None
```

```text
追加一段文本；失败时静默丢弃（下一行会重试打开）。

Args:
    text: 要写入的文本；空串直接忽略。

Returns:
    None: 写盘失败只关闭句柄，不抛异常。
```

### `_Stream.write`  (method)

```python
def write(self, text) -> int
```

```text
写一段文本（兼容 ``print`` 的调用方式）。

Args:
    text: 字符串；非字符串按 0 长度处理。

Returns:
    int: 实际写入的字符数（``print`` 不看，但文件协议要求返回）。
```

### `_Stream.writelines`  (method)

```python
def writelines(self, lines) -> None
```

```text
逐行写入。

Args:
    lines: 字符串序列。

Returns:
    None: 空序列直接返回。
```

### `_Stream.flush`  (method)

```python
def flush(self) -> None
```

```text
空实现：底层每次写入已 flush，``print(..., flush=True)`` 不会报错。
```

### `_Stream.isatty`  (method)

```python
def isatty(self) -> bool
```

```text
永远不是终端（日志流不交互）。

Returns:
    bool: 恒为 ``False``。
```

### `_Stream.writable`  (method)

```python
def writable(self) -> bool
```

```text
可写：与真实 stdout 保持一致。

Returns:
    bool: 恒为 ``True``。
```

### `_Stream.readable`  (method)

```python
def readable(self) -> bool
```

```text
不可读：日志流只写。

Returns:
    bool: 恒为 ``False``。
```

### `_Stream.fileno`  (method)

```python
def fileno(self) -> int
```

```text
没有真实 fd；需要 fd 的库（如 faulthandler）必须用 ``logstore`` 的日文件。

Returns:
    int: 永不返回 —— 总是抛 ``OSError``，避免调用方拿到错误 fd。

Raises:
    OSError: 任何调用都会抛出（日志流不是真实文件）。
```

### `_Stream.closed`  (method)

```python
@property
def closed(self) -> bool
```

```text
永不关闭：句柄由 :func:`close_streams` 统一管理。

Returns:
    bool: 恒为 ``False``。
```

### `_Stream.close`  (method)

```python
def close(self) -> None
```

```text
空实现：防止 ``print`` 的消费方误关共享句柄。
```

### `app_log`

```python
def app_log(msg: str) -> None
```

```text
写一条启动器日志到 ``app-YYYYMMDD.log``，行格式 ``[HH:MM:SS] [INFO] msg``。

Args:
    msg: 日志正文；多行会逐行加前缀。

Returns:
    None: 写盘失败静默忽略。
```

### `diag_log`

```python
def diag_log(msg: str) -> None
```

```text
写一条诊断/服务日志到 ``diag-YYYYMMDD.log``，行格式同 :func:`app_log`。

Args:
    msg: 日志正文；多行（如 traceback）会逐行加前缀。

Returns:
    None: 写盘失败静默忽略。
```

### `open_stream`

```python
def open_stream() -> '_Stream'
```

```text
返回写往 ``app-YYYYMMDD.log`` 的文本流（供 ``app.redirect_output()`` 使用）。

Returns:
    _Stream: 具备 ``write`` / ``flush`` 的伪文件对象。底层句柄在进程内复用，
        不会每来一次 ``print`` 就打开一个文件。
```

### `close_streams`

```python
def close_streams() -> None
```

```text
关闭并清空进程内所有日志句柄（含 faulthandler 文件；测试与退出时用）。

Returns:
    None: 关闭失败静默忽略。
```

### `write_env_snapshot`

```python
def write_env_snapshot(extra: dict | None=None) -> dict
```

```text
写 ``logs/env.json``（覆盖写）并返回快照内容。

Args:
    extra: 追加/覆盖的字段（如入口名 ``{"entry": "app"}``）；``None`` 表示不加。

Returns:
    dict: 环境快照。文件写不进去也返回内容，只是没有落盘。
```

### `record_run`

```python
def record_run(record: dict) -> Path | None
```

```text
把一次分析写成 ``runs/<ts>-<8位随机>.json``。

字段约定见 ``docs/logging.md``：``mode`` / ``params`` / ``duration_ms`` /
``level`` / ``critical`` / ``warning`` / ``sufficiency_ok`` / ``error_code`` /
``tshark_version``。文件名带随机后缀，避免并发同秒撞名（Windows 文件名里
也不能出现 ``:``）。

Args:
    record: 记录内容（会被 JSON 序列化）。

Returns:
    Path | None: 写成功返回文件路径；目录不可写或内容不可序列化返回 ``None``
        （日志失败不影响分析本身）。
```

### `record_crash`

```python
def record_crash(exc_type, exc, tb) -> Path | None
```

```text
把一次未捕获异常写成 ``crashes/<ts>-<pid>-<tid>-<rand>.txt``（类型/消息/traceback/环境摘要）。

Args:
    exc_type: 异常类（``sys.excepthook`` 的第一个参数）。
    exc: 异常实例。
    tb: traceback 对象；为 ``None`` 时退化为「类型: 消息」。

Returns:
    Path | None: 写成功返回文件路径；写盘失败返回 ``None``。
```

### `install_excepthooks`

```python
def install_excepthooks() -> None
```

```text
启用崩溃兜底：``sys.excepthook`` + ``threading.excepthook`` + ``faulthandler``。

幂等：重复调用只补装缺失的部分。``faulthandler`` 的文件对象保存在模块级变量里，
否则它会被 GC 回收，进程真崩时什么也写不出来（见 SPEC 陷阱 3）。

Returns:
    None: 钩子/文件装不上时静默降级，不影响程序运行。
```

### `prune`

```python
def prune() -> dict
```

```text
执行保留策略（启动时调用一次，也可手动跑）。

顺序：单文件截尾 → ``runs/`` 数量 → ``crashes/`` 数量 → ``logs/`` 总量。
总量删除按「最旧优先」，并跳过 ``env.json`` / ``netdiag.pid`` / 当天的日志 ——
**绝不删除正在写的文件**（SPEC V2 / 陷阱 4）。

Returns:
    dict: ``{"truncated", "removed", "freed_bytes", "total_bytes"}`` 计数摘要。
        单个文件失败只跳过，不抛异常。
```

## `core/passive.py`

**职责**：被动流量监听：实时盯着网卡，把流量按会话聚合，用「端口 + 首包特征」识别协议。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `engine_status` | function | 62 | ✅ |
| `build_flows` | function | 472 | ✅ |
| `run` | function | 610 | ✅ |

### `engine_status`

```python
def engine_status() -> dict
```

```text
检测当前可用的采集引擎。

Returns:
    dict: 键 ``engine``（``scapy`` 或 ``tshark``）/ ``scapy``（bool）/
        ``scapy_version`` / ``pcap``（Scapy 是否绑定到 Npcap）/
        ``error``（Scapy 不可用的原因，便于界面直接展示）。
```

### `build_flows`

```python
def build_flows(recs: list[dict]) -> tuple[list[dict], dict]
```

```text
把逐包记录聚合成双向会话。

方向和客户端角色由 SYN 方向推断，不靠端口大小猜；同一对端口的双向流量
合并成一条会话，再分别统计上下行。

Args:
    recs: 逐包记录列表，每项至少含 ``src_ip`` / ``sport`` / ``dst_ip`` /
        ``dport`` / ``transport`` / ``size`` / ``ts``。

Returns:
    tuple[list[dict], dict]: ``(flows, summary)``。``flows`` 每项含五元组、
        包数/字节数、协议指纹、状态与应用线索；``summary`` 含会话总数、
        协议分布、扇出（同一本地端口连多个对端）提示等。
```

### `run`

```python
def run(interface: str | None=None, duration: int=20, target: str='', max_packets: int=20000, engine: str='auto', logger=None, should_stop=None) -> dict
```

```text
监听网卡若干秒，返回会话表与汇总。**只听不发**，不构造任何报文。

选卡规则与实时抓包一致：显式指定就只听那块；自动选择先按
:func:`tshark.order_interfaces` 排序并真实试抓 2 秒，取第一块有报文的网卡；
抓到 0 包时按候选顺序换下一块（最多 3 块），控制台逐块说明「第 N 块无流量」。

Args:
    interface: 网卡序号或名称关键字；空则自动挑选。
    duration: 监听秒数，夹在 3~300；换卡重试时每块缩短为 ``min(duration, 10)``。
    target: 只保留与该目标相关的会话（IP/CIDR/域名）；空表示全部流量。
    max_packets: 包数上限，夹在 200~200000，防止长时间监听把内存吃满。
    engine: ``auto`` / ``scapy`` / ``tshark``；``auto`` 优先 Scapy，不可用时回落 tshark。
    logger: 日志回调。
    should_stop: 可选无参回调，返回 True 时提前结束（界面「停止」按钮用）。

Returns:
    dict: 成功 ``{"ok": True, "interface", "interface_index", "device", "duration",
        "engine", "bpf", "flows": [...], "summary": {...}, "attempts", "tried",
        "auto"}``；0 会话时额外带 ``card="empty_sessions"`` / ``next_steps``，
        ``tried`` 记录每块候选网卡实际抓到多少报文。失败 ``{"ok": False, "error"}``
        （没有可用网卡、目标过滤器非法、两种引擎都打不开）。
```

## `core/pathprobe.py`

**职责**：影子探测（Shadow Probing）+ 路径探测（MTR）—— D 批次实现。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `scapy_available` | function | 158 | ✅ |
| `tracert_available` | function | 185 | ✅ |
| `ProbeKind` | class | 201 | ✅ |
| `HopStatus` | class | 209 | ✅ |
| `ProbeSpec` | class | 232 | ✅ |
| `ProbeSpec.to_dict` | method | 258 | ✅ |
| `ProbeRecord` | class | 283 | ✅ |
| `ProbeRecord.to_dict` | method | 307 | ✅ |
| `ProbeLedger` | class | 328 | ✅ |
| `ProbeLedger.ports` | method | 344 | ✅ |
| `ProbeLedger.targets` | method | 352 | ✅ |
| `ProbeLedger.kinds` | method | 360 | ✅ |
| `ProbeLedger.has_icmp` | method | 368 | ✅ |
| `ProbeLedger.exclusion_bpf` | method | 376 | ✅ |
| `ProbeLedger.exclusion_display_filter` | method | 395 | ✅ |
| `ProbeLedger.window` | method | 403 | ✅ |
| `ProbeLedger.baseline` | method | 411 | ✅ |
| `ProbeLedger.to_dict` | method | 439 | ✅ |
| `HopStat` | class | 462 | ✅ |
| `HopStat.loss_pct` | method | 482 | ✅ |
| `HopStat.to_dict` | method | 491 | ✅ |
| `PathProbeResult` | class | 516 | ✅ |
| `PathProbeResult.to_dict` | method | 552 | ✅ |
| `classify` | function | 592 | ✅ |
| `clamp_path_options` | function | 641 | ✅ |
| `build_hop_stats` | function | 772 | ✅ |
| `degraded_hops` | function | 850 | ✅ |
| `first_degraded_hop` | function | 869 | ✅ |
| `looks_like_tun` | function | 891 | ✅ |
| `summarize_path` | function | 938 | ✅ |
| `exclusion_bpf` | function | 1037 | ✅ |
| `exclusion_display_filter` | function | 1061 | ✅ |
| `probe_marker_display_filter` | function | 1082 | ✅ |
| `path_exclusion_display_filter` | function | 1113 | ✅ |
| `discover_targets` | function | 1192 | ✅ |
| `plan` | function | 1257 | ✅ |
| `shadow_specs` | function | 1283 | ✅ |
| `rounds_for` | function | 1304 | ✅ |
| `probe_len` | function | 1321 | ✅ |
| `probe_src_port` | function | 1333 | ✅ |
| `send_probe` | function | 1350 | ✅ |
| `ShadowProber` | class | 1427 | ✅ |
| `ShadowProber.start` | method | 1454 | ✅ |
| `ShadowProber.stop` | method | 1464 | ✅ |
| `ShadowProber.join` | method | 1468 | ✅ |
| `ShadowProber.run_round` | method | 1483 | ✅ |
| `ShadowProber.exclusion_bpf` | method | 1527 | ✅ |
| `ShadowProber.exclusion_display_filter` | method | 1536 | ✅ |
| `ShadowProber.marker_display_filter` | method | 1545 | ✅ |
| `ShadowProber.sent_count` | method | 1555 | ✅ |
| `ShadowProber.snapshot` | method | 1564 | ✅ |
| `aggregate_records` | function | 1585 | ✅ |
| `count_marked_packets` | function | 1655 | ✅ |
| `count_time_exceeded_packets` | function | 1690 | ✅ |
| `probe_tcp_reachable` | function | 1758 | ✅ |
| `check_target_port` | function | 1793 | ✅ |
| `path_engine_log_line` | function | 2219 | ✅ |
| `run` | function | 2249 | ✅ |
| `PathProfiler` | class | 2457 | ✅ |
| `PathProfiler.start` | method | 2494 | ✅ |
| `PathProfiler.stop` | method | 2505 | ✅ |
| `PathProfiler.join` | method | 2509 | ✅ |
| `PathProfiler.should_stop` | method | 2524 | ✅ |
| `PathProfiler.snapshot` | method | 2549 | ✅ |

### `scapy_available`

```python
def scapy_available() -> bool
```

```text
探测 scapy 是否真的可导入（不引入新依赖，不抛异常）。

先 ``importlib.util.find_spec`` 判模块是否存在，再真正 ``import scapy.all``：
只看 spec 不够 —— 模块目录可能在、但依赖的二进制/扩展加载失败（半残安装）。
这条探测只回答「能不能用」，不会替用户安装任何东西。

Returns:
    bool: scapy 可导入为 True；模块缺失、半残安装、探测异常一律 False。

Example:
    >>> isinstance(scapy_available(), bool)
    True
```

### `tracert_available`

```python
def tracert_available() -> bool
```

```text
系统是否自带 ``tracert``（Windows 命令，用 ``shutil.which`` 查，不解析文本）。

Returns:
    bool: PATH 上能找到 ``tracert`` 为 True；非 Windows / 被裁剪为 False。

Example:
    >>> isinstance(tracert_available(), bool)
    True
```

### `ProbeKind`  (class)

```python
class ProbeKind
```

```text
探针协议类型（同时是账本 / 统计里的机器码）。
```

### `HopStatus`  (class)

```python
class HopStatus
```

```text
路径探测（MTR）单跳的状态（机器码，中文文案在 copy 表）。

``OK`` 与 ``LOSS`` 保留既有语义（正常 / 全部超时）；``DEGRADED`` 表示
**劣化持续到目标或最后一个有响应的跳**（R5）：只在「从这一跳开始的丢包/RTT
异常一直延续到终点」时使用，不能再显示成「正常」，否则表格与「第几跳开始
劣化」的结论自相矛盾。``RATE_LIMITED`` 表示该跳自身有丢包/RTT 异常、但后面
的跳或目标已经恢复正常（企业网里常见于设备对 TTL 回复限速）—— 它不是承载网
故障证据，所以既不能显示成「劣化」，也不该粉饰成「正常」。
``FILTERED`` / ``UNREACHABLE`` / ``NO_TARGET`` 是保留机器码（当前由结论句 /
方法标注表达，未逐跳赋值）。
```

### `ProbeSpec`  (class)

```python
@dataclass(frozen=True)
class ProbeSpec
```

```text
一次探针的规格（发什么、发给谁、算哪个角色）。

Attributes:
    kind: 探针协议（ICMP / TCP SYN / UDP）。
    target: 目标 IPv4 字面量（域名在 :func:`discover_targets` 里已解析）。
    ttl: IP TTL，影子探测固定 64；路径探测（后续 PR）用递增 TTL。
    port: TCP / UDP 目的端口；ICMP 探针为 ``None``。
    samples: 计划采样数；影子探测固定 1（每轮每目标 1 包）。
    timeout_s: 单包等待上限（秒），上限 1s。
    interval_s: 轮询间隔（秒），影子探测固定 5s。
    role: 角色机器码：``gateway`` / ``dns`` / ``target``。
```

### `ProbeSpec.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
把规格转成可 JSON 序列化的字典（账本落进结果时用）。

Returns:
    dict: 键 ``kind``（机器码）/``target``/``ttl``/``port``/``samples``/
        ``timeout_s``/``interval_s``/``role``。
```

### `ProbeRecord`  (class)

```python
@dataclass(frozen=True)
class ProbeRecord
```

```text
一次探测的实际结果。**必须带时间戳**，否则无法与抓包对齐。

Attributes:
    spec: 本次探针规格。
    sent_monotonic: 发送时刻的 ``time.monotonic()``（算 RTT 用）。
    sent_epoch: 发送时刻的系统时钟（与 pcap 的 ``frame.time_epoch`` 同源，
        只做「区间归属」，不逐包对齐）。
    rtt_ms: 往返时延（毫秒）；没有响应时为 ``None``（**不许用 0.0 冒充**）。
    responded: 是否收到可判「通」的响应。
    responder: 响应方 IP；无响应时为空串。
    error: 失败原因（``timeout`` / ``scapy 不可用`` ……）；成功为空串。
    seq: 全局递增序号（ICMP seq / 源端口分配都从它派生）。
```

### `ProbeRecord.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
把一条记录转成可 JSON 序列化的字典。

Returns:
    dict: 键 ``spec``（:meth:`ProbeSpec.to_dict`）/``sent_monotonic``/
        ``sent_epoch``/``rtt_ms``/``responded``/``responder``/``error``/
        ``seq``；``rtt_ms`` 无样本时保持 ``None``。
```

### `ProbeLedger`  (class)

```python
@dataclass
class ProbeLedger
```

```text
探测账本：既用于**排除**探针流量，也用于报告复现。

Attributes:
    records: 逐条探测记录（按发送顺序）。
    started_epoch: 探针线程启动时刻（系统时钟）。
    finished_epoch: 探针线程收尾时刻（系统时钟）。
    clock_offset_ms: 预留的时钟偏移校准值；本批不做逐包对齐，固定 0。
```

### `ProbeLedger.ports`  (method)

```python
def ports(self) -> set[int]
```

```text
账本里出现过的探针目的端口集合。

Returns:
    set[int]: TCP/UDP 探针的目的端口；ICMP 记录不贡献端口。
```

### `ProbeLedger.targets`  (method)

```python
def targets(self) -> set[str]
```

```text
账本里出现过的探针目标地址集合。

Returns:
    set[str]: 去重后的目标 IP 字符串。
```

### `ProbeLedger.kinds`  (method)

```python
def kinds(self) -> set[ProbeKind]
```

```text
账本里实际出现过的探针协议集合。

Returns:
    set[ProbeKind]: 例如 ``{ProbeKind.ICMP, ProbeKind.TCP_SYN}``。
```

### `ProbeLedger.has_icmp`  (method)

```python
def has_icmp(self) -> bool
```

```text
账本里是否有 ICMP 探针（决定是否需要排除 echo 请求/回复）。

Returns:
    bool: 存在 ICMP 记录时为 True。
```

### `ProbeLedger.exclusion_bpf`  (method)

```python
def exclusion_bpf(self, ignore_icmp: bool=True) -> str
```

```text
把探针流量从**抓包**里排除掉的 BPF 表达式。

只排除「我们自己发的」那部分：ICMP echo 的固定 id、TCP/UDP 的固定源端口段，
并且端口段同时匹配源/目的 —— 探针的回复方向端口是反的，只排源端口会漏掉
SYN-ACK / RST / DNS 响应（这正是「只做 BPF 不够」的原因之一）。

Args:
    ignore_icmp: 是否把 ICMP echo 探针也排除；``False`` 时只给端口段条件
        （保留给「想单独看 ICMP」的调试场景）。

Returns:
    str: BPF 串；空账本返回空串（调用方据此判断「无需合并过滤」）。
```

### `ProbeLedger.exclusion_display_filter`  (method)

```python
def exclusion_display_filter(self) -> str
```

```text
把探针流量从**分析**里排除掉的 tshark ``-Y`` 表达式（防御层）。

Returns:
    str: 显示过滤串；空账本返回空串。
```

### `ProbeLedger.window`  (method)

```python
def window(self) -> tuple[float, float]
```

```text
探针线程的活动时间窗（系统时钟秒）。

Returns:
    tuple[float, float]: ``(started_epoch, finished_epoch)``；未启动时都是 0。
```

### `ProbeLedger.baseline`  (method)

```python
def baseline(self) -> dict
```

```text
按角色聚合出「探针基线」（报告 / 方向对照消费的数据）。

收发计数**由探针模块自己记**（:class:`ProbeRecord` 的 ``responded``），
不从抓包反推 —— 抓包过滤器本来就把探针排除了，反推永远是 0。超时 =
``sent - recv`` 是显式键，调用方不用自己推。

Returns:
    dict: 键 ``probe_count``（记录总数）/``sent``/``recv``/``timeout``
        （= sent - recv，含每角色三值见 ``roles``）/``window``/
        ``roles``（:func:`aggregate_records` 的结果）；``excluded_packets``
        固定 0，由调用方在分析前用 ``count_marked_packets`` 回填。
        没有 RTT 样本的角色 ``n=0`` 且 ``rtt_*`` 为 ``None`` —— 不是 0.0。
```

### `ProbeLedger.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
把账本转成可 JSON 序列化的字典（结果里 ``meta.probe_baseline`` 的底稿）。

Returns:
    dict: 键 ``started_epoch``/``finished_epoch``/``clock_offset_ms``/
        ``probe_count``/``targets``/``ports``/``kinds``/``exclusion_bpf``/
        ``exclusion_display_filter``/``records``（逐条记录）。
```

### `HopStat`  (class)

```python
@dataclass(frozen=True)
class HopStat
```

```text
路径探测（MTR）的单跳统计。

``sent`` / ``lost`` 表达「有没有样本」（``sent=0`` = 这一跳根本没探），
``rtt_n`` 表达「有没有 RTT 样本」（回了包但拿不到时间戳时为 0）；
RTT 三个值 + 抖动在 ``rtt_n=0`` 时是 ``None``，**不许用 0.0 冒充**。
```

### `HopStat.loss_pct`  (method)

```python
@property
def loss_pct(self) -> float
```

```text
单跳丢包率（百分比，1 位小数）。

Returns:
    float: ``lost / sent * 100``；``sent == 0``（无样本）时返回 0.0。
        「有没有样本」由 ``sent`` / ``rtt_n`` 表达，不要只看这个比例。
```

### `HopStat.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
把单跳统计转成可 JSON 序列化的字典（报告 / ``meta.path_profile`` 用）。

Returns:
    dict: 键 ``ttl``/``ip``/``sent``/``lost``/``loss_pct``/
        ``rtt_min_ms``/``rtt_avg_ms``/``rtt_max_ms``/``jitter_ms``/
        ``rtt_n``/``status``（机器码）；没有 RTT 样本时三个 RTT 与抖动
        都是 ``None``。
```

### `PathProbeResult`  (class)

```python
@dataclass(frozen=True)
class PathProbeResult
```

```text
路径探测（MTR）结果：逐跳数据 + 结论机器码 + 方法/降级标注。

``verdict_key`` 只用 :data:`PATH_OK` 等 6 个机器码；``unreachable`` 是附加
布尔（ICMP 与 TCP 都没响应时，渲染层据此写「目标不可达」而不是「正常」）。
``middle_loss_suspected`` / ``middle_loss_ttls`` 记录「中间跳有丢包/RTT 异常、
但劣化没有持续到目标或最后响应跳」的跳（R5）：这类跳不能算作劣化，只在报告里
提示可能是 ICMP 限速/策略过滤。

``method`` 取值：``icmp``（scapy ICMP 逐跳）/ ``tcp``（ICMP 被过滤后的 TCP SYN
重扫）/ ``tracert``（没有 scapy，系统 tracert 降级，固定每跳 3 次探测）。
``samples`` 因此可能是 3（tracert 固定）而不是调用方请求的样本数。
```

### `PathProbeResult.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
把路径探测结果转成可 JSON 序列化的字典（``meta.path_profile`` 的底稿）。

Returns:
    dict: 键 ``target``/``target_ip``/``verdict_key``/``degraded_ttl``/
        ``baseline_ms``/``icmp_filtered``/``target_port_reachable``/
        ``method``/``reached_target``/``completed``/``tun_suspected``/
        ``unreachable``/``middle_loss_suspected``/``middle_loss_ttls``/
        ``max_hops``/``samples``/``timeout_s``/``probes_sent``/``error``/
        ``hops``（逐跳）/``ledger``。``middle_loss_ttls`` 是「有丢包/RTT
        异常但未持续到目标或最后响应跳」的中间跳 TTL 列表（R5）。
```

### `classify`

```python
def classify(hops: Sequence[HopStat], target_port_reachable: bool | None=None) -> tuple[str, bool]
```

```text
把逐跳统计翻成「该找谁」（SPEC V7 要求保留的公开 API，主路径用 :func:`summarize_path`）。

四态的关键是**最后一种**：全部都丢但目标端口 TCP 可通 → 这不是故障，是
ICMP 被策略过滤（企业网常见），不能把「被过滤」误判成「链路故障」。

本函数只做「按最终响应者定界」的旧口径；它不计算 RTT 突增、不区分「探测未完成」，
**也不套用 R5 的持久性约束**（中间跳限速仍可能被它算成 losing）。实时路径 /
报告 / 服务端**主路径一律走 :func:`summarize_path`**，这里保留是为了兼容既有
调用方与 SPEC 的公开 API 形状。阈值复用模块常量，避免出现第二套魔数。

Args:
    hops: 逐跳统计（按 TTL 顺序）。
    target_port_reachable: 目标端口 TCP 是否可达；``None`` 表示没测。

Returns:
    tuple[str, bool]: ``(verdict_key, icmp_filtered)``。``verdict_key`` 是机器码
    （``PATH.OK`` / ``PATH.LOCAL_SIDE`` / ``PATH.SERVER_EDGE`` /
    ``PATH.TRANSPORT_NET`` / ``PATH.ICMP_FILTERED`` / ``PATH.NO_DATA``），
    由渲染层负责翻成中文。
```

### `clamp_path_options`

```python
def clamp_path_options(max_hops: int=PATH_DEFAULT_MAX_HOPS, samples: int=PATH_DEFAULT_SAMPLES, timeout_s: float=1.0) -> tuple[int, int, float]
```

```text
把路径探测的三个参数夹到安全范围（纯函数，调用方/测试共用）。

「MTR 长什么样」不设上限的话，一次 32 跳 × 10 样本 × 3 秒能把网卡打满，
也能把一次实时抓包拖到几分钟 —— 所以参数一律先夹取再使用。

Args:
    max_hops: 请求的最大跳数；夹到 :data:`PATH_MAX_HOPS_RANGE`。
    samples: 请求的每跳采样数；夹到 :data:`PATH_SAMPLES_RANGE`。
    timeout_s: 请求的单包等待上限（秒）；夹到 :data:`PATH_TIMEOUT_RANGE`。

Returns:
    tuple[int, int, float]: ``(max_hops, samples, timeout_s)``；脏值（``None`` /
        非数字）回落默认值而不是抛异常。

Example:
    >>> clamp_path_options(999, 0, 99)
    (32, 1, 3.0)
```

### `build_hop_stats`

```python
def build_hop_stats(rows: Iterable[Mapping], target_ip: str='') -> tuple[HopStat, ...]
```

```text
把原始采样记录聚合成逐跳统计（纯函数，MTR 与单测共用）。

每条原始记录键：``ttl``（整数）、``responded``（布尔）、``rtt_ms``
（浮点或 ``None``）、``responder``（响应方 IP，空串表示没响应）。

Args:
    rows: 原始采样记录（顺序无关，内部按 ``ttl`` 排序输出）。
    target_ip: 目标 IP 字面量；给了才知道哪一跳是目标跳，从而按 R5 的
        「劣化必须持续到目标/最后响应跳」赋值状态。省略时按最后一个有响应
        的跳作为终点（单跳 / 直调场景）。

Returns:
    tuple[HopStat, ...]: 按 TTL 升序的逐跳统计。``sent`` 是该 TTL 的采样数，
    ``lost`` 是没响应的采样数；``ip`` 取该跳出现过的非空响应方（取第一个），
    ``rtt_n`` 是真正拿到 RTT 的样本数，``rtt_min_ms``/``rtt_avg_ms``/
    ``rtt_max_ms``/``jitter_ms`` 在 ``rtt_n=0`` 时是 ``None``；
    ``jitter_ms`` 用总体标准差（与 :func:`aggregate_records` 口径一致）。
    ``status`` 与劣化判定同源：没有任何样本 → ``LOSS``；**异常持续到终点**
    → ``DEGRADED``（全丢仍保留 ``LOSS``）；异常被后续正常跳/目标打断
    → ``RATE_LIMITED``；其余 ``OK``。

Example:
    >>> [h.ttl for h in build_hop_stats([{"ttl": 2}, {"ttl": 1}])]
    [1, 2]
```

### `degraded_hops`

```python
def degraded_hops(hops: Sequence[HopStat]) -> tuple[int, ...]
```

```text
列出「已经劣化为承载网问题」的跳（纯函数，阈值全部来自模块常量）。

R5 的持久性约束在这里落地：单跳丢包/RTT 异常本身不够，必须**从这一跳开始
连续延续到目标或最后一个有响应的跳**才算劣化。中间跳不回 ICMP、但后续跳或
目标恢复正常的场景返回空元组（那是限速/策略过滤，不是承载网故障）。

Args:
    hops: 逐跳统计（顺序无关，内部按 ttl 排序）。没有目标 IP 时按「最后一个
        有响应的跳」作为终点（末尾 100% 不回包时按最后一个有采样的跳）；
        需要按目标跳判定时用 :func:`summarize_path`。

Returns:
    tuple[int, ...]: 持续劣化段的 TTL（升序）；没有持续劣化时是空元组。
        没有样本同样返回空元组 —— **空 ≠ 正常**，调用方需另判 ``PATH.NO_DATA``。
```

### `first_degraded_hop`

```python
def first_degraded_hop(hops: Sequence[HopStat]) -> int | None
```

```text
「第几跳开始劣化」——持续劣化段的第一跳 TTL。

只有从这一跳开始、异常一直延续到目标或最后响应跳，才会返回 TTL；中间跳
丢包但后续跳/目标恢复正常的场景返回 ``None``（R5，避免误判承载网）。

Args:
    hops: 逐跳统计。

Returns:
    int | None: 持续劣化段第一跳的 TTL；全部正常、只有中间跳异常、或没有任何
        样本时返回 ``None``。**没有样本 ≠ 正常**：调用方必须再看 ``sent`` /
        ``rtt_n`` 才能下结论（见 :func:`summarize_path` 的 ``PATH.NO_DATA``）。

Example:
    >>> first_degraded_hop(()) is None
    True
```

### `looks_like_tun`

```python
def looks_like_tun(hops: Sequence[HopStat], target_ip: str='') -> bool
```

```text
猜「本次逐跳走的是代理/TUN 的虚拟路径」。

**唯一可靠证据**是 ``198.18.0.0/15`` 出现在路径的关键位置。这段是 RFC 2544
的基准测试网段，mihomo / Clash 等 TUN 代理默认拿它做 fake-ip：

1. 目标解析到该网段（fake-ip 直接命中，逐跳探到的是代理的虚拟路径）；
2. 任一**有响应**的跳的 IP 落在该网段（TUN 虚拟网关在代为应答）。

**为什么不用跳数判断**：on-link 目标（同网段主机、本机物理网关）正常就只有
1 跳；ICMP 被过滤时也可能只看到 1~2 跳响应。把「有响应的最大 TTL ≤ 2」当成
代理证据，会把物理网关误报成 TUN（D+ 增量 2.5 的路测缺陷：对物理网关提示
「当前流量可能走代理」）。漏报只是少一句建议，误报会诱导用户去关代理，
所以**证据不足一律返回 False**（宁可不提示，不可误报）。

Args:
    hops: 逐跳统计。
    target_ip: 本次探测的目标 IP 字面量；空串表示不知道。

Returns:
    bool: 目标或任一有响应的跳落在 ``198.18.0.0/15`` 时为 True；其余情况
        （hop ip 为空 / 解析失败 / 全部丢包 / on-link LAN 目标 / 物理网关 /
        普通多跳公网）恒为 False。

Example:
    >>> looks_like_tun((), "198.18.0.2")
    True
```

### `summarize_path`

```python
def summarize_path(hops: Sequence[HopStat], target_port_reachable: bool | None=None, method: str='icmp', target_ip: str='') -> dict
```

```text
把逐跳统计翻成「第几跳开始劣化 + 该找谁」（纯函数，无中文长文案）。

与 :func:`classify` 的区别：这里同时看**丢包**与 **RTT 突增**，并且把
「没有样本」「ICMP 被过滤」「目标不可达」明确分开 —— 三者都不许落成「正常」。

「劣化」按 R5 的持久性口径：单跳异常必须**从该跳开始连续延续到目标或最后
一个有响应的跳**，才算 ``degraded_ttl``；中间跳异常但后续跳/目标恢复正常的，
只进 ``middle_loss_suspected`` / ``middle_loss_ttls``，结论仍是 ``PATH.OK``。

Args:
    hops: 逐跳统计。
    target_port_reachable: 目标端口 TCP 是否可达；``None`` 表示没测。
    method: ``"icmp"`` / ``"tcp"``；只有 ICMP 方法才可能判定「被过滤」。
    target_ip: 目标 IP 字面量，用于识别目标跳（判定终点）、「是否已探到目标」
        与 TUN 提示。

Returns:
    dict: 键 ``verdict_key``（:data:`PATH_OK` 等 6 个机器码）/
        ``degraded_ttl``（持续劣化段第一跳，无则 ``None``）/``baseline_ms``
        （基线平均 RTT，无样本 ``None``）/``icmp_filtered``/``unreachable``/
        ``reached_target``/``tun_suspected``/``middle_loss_suspected``（是否有
        「未持续到终点」的中间跳异常）/``middle_loss_ttls``（这些跳的 TTL 列表）。
        没有样本时恒为 ``PATH.NO_DATA``，绝不返回 ``PATH.OK``。

Example:
    >>> summarize_path(())["verdict_key"]
    'PATH.NO_DATA'
```

### `exclusion_bpf`

```python
def exclusion_bpf(kinds: Iterable[ProbeKind]) -> str
```

```text
按探针协议生成抓包排除表达式（纯函数，供账本与预规划共用）。

ICMP 用固定 id（请求 + 回复两种 type）；TCP/UDP 用固定源端口段并同时匹配
源/目的（回复方向端口是反的）。组合用 ``and``，空集合返回空串。

Args:
    kinds: 本次会发出的探针协议集合（``ProbeKind`` 或同值字符串）。

Returns:
    str: BPF 串；``kinds`` 为空时返回空串（= 不需要合并过滤）。
```

### `exclusion_display_filter`

```python
def exclusion_display_filter(kinds: Iterable[ProbeKind]) -> str
```

```text
按探针协议生成 tshark ``-Y`` 排除表达式（纯函数，分析阶段防御层）。

Args:
    kinds: 本次会发出的探针协议集合。

Returns:
    str: 显示过滤串；``kinds`` 为空时返回空串。
```

### `probe_marker_display_filter`

```python
def probe_marker_display_filter(kinds: Iterable[ProbeKind]) -> str
```

```text
生成「只匹配探针报文」的显示过滤（用于统计 pcap 里混进了多少探针包）。

ICMP 片段**显式排除 type 11**：Wireshark 的 ``icmp.ident`` 对 ICMP 错误报文会
命中内嵌的原始报文，不排除就会把我们自己的 time-exceeded 也算成「标记探针包」，
与 :func:`count_time_exceeded_packets` 的整类计数重复。两处口径因此互斥：
标记包 + type 11 包 = 本窗口被排除的互不重叠的包。

Args:
    kinds: 本次会发出的探针协议集合。

Returns:
    str: 显示过滤串；``kinds`` 为空时返回空串（调用方应跳过统计）。
```

### `path_exclusion_display_filter`

```python
def path_exclusion_display_filter(kinds: Iterable[ProbeKind]=(ProbeKind.ICMP, ProbeKind.TCP_SYN)) -> str
```

```text
MTR 期间的显示过滤：探针标记 + 排除 ICMP time-exceeded（type 11）。

为什么必须多排一条：路径上设备回的 ``ICMP type 11`` 外层 ident 不是
:data:`PROBE_ID`（我们的 id 埋在「原始 IP 头 + 8 字节」里），按 id/端口认不出来；
而分析层会把 type 11 计入 ``icmp_timeout``，不排就会凭空多出「TTL 耗尽」故障。

Args:
    kinds: MTR 可能发出的探针协议；默认 ICMP + TCP SYN（TCP 降级用）。

Returns:
    str: tshark ``-Y`` 串；``kinds`` 为空时也会返回 ``not (icmp.type == 11)``
        （只要 MTR 跑过，这一步就必须有）。

Example:
    >>> path_exclusion_display_filter([])
    'not (icmp.type == 11)'
```

### `discover_targets`

```python
def discover_targets(vdi_hint: str='', target: str='') -> dict[str, str]
```

```text
发现网关 / DNS / 业务目标（**绝不抛异常**，拿不到就不返回该键）。

平台能力复用 :mod:`core.platform.winapi`：``default_gateway()`` 走
``GetBestRoute``、``dns_servers()`` 读注册表（都不解析本地化 CLI 文本）。
业务目标来自抓包目标（IP / CIDR 取第一个主机 / 域名先解析）。

DNS 角色有一条「优雅跳过」规则：DNS 服务器是 ``127.0.0.0/8`` / ``::1`` 时
探针发出去只会打到自己（本地 stub 解析器），不产生任何有效对照，所以跳过并在
返回值里用 ``dns_skip`` 说明原因 —— 调用方据此在日志里交代一句，而不是发无效探针。

Args:
    vdi_hint: 调用方显式给的业务目标提示（优先于 ``target``）。
    target: 用户填写的诊断目标；空表示全网体检（没有业务目标角色）。

Returns:
    dict[str, str]: 可能含 ``gateway`` / ``dns`` / ``vdi`` / ``vdi_port``；
        出现但不可用时含 ``dns_skip``（``loopback`` / ``unusable``）。
        键缺失表示该角色这次不可用；不抛异常、不写文件。

Example:
    >>> discover_targets(target="192.0.2.10").get("vdi")
    '192.0.2.10'
```

### `plan`

```python
def plan(targets: Mapping[str, str], samples: int=5) -> tuple[ProbeSpec, ...]
```

```text
按角色生成探测计划：网关用 ICMP，DNS 用 UDP/53，业务目标用 TCP SYN。

Args:
    targets: :func:`discover_targets` 的结果；缺哪个角色就跳过哪个。
    samples: 每个目标的计划采样数（影子探测传 1）。

Returns:
    tuple[ProbeSpec, ...]: 探针规格；没有可用目标时是空元组。
```

### `shadow_specs`

```python
def shadow_specs(targets: Mapping[str, str], interval_s: float=PROBE_INTERVAL_S) -> tuple[ProbeSpec, ...]
```

```text
影子探测计划：每 ``interval_s`` 秒一轮，量很小（1 包/目标/轮）。

Args:
    targets: :func:`discover_targets` 的结果。
    interval_s: 轮询间隔（秒），默认 :data:`PROBE_INTERVAL_S`。

Returns:
    tuple[ProbeSpec, ...]: 每目标 1 个规格，``samples=1``、``timeout_s<=1``、
    ``interval_s`` 写成实际轮询间隔。
```

### `rounds_for`

```python
def rounds_for(duration: int | float, interval_s: float=PROBE_INTERVAL_S) -> int
```

```text
按抓包时长算探针最多跑几轮（首轮立即发，之后每 ``interval_s`` 一轮）。

Args:
    duration: 抓包时长（秒）。
    interval_s: 轮询间隔（秒）。

Returns:
    int: 轮数，至少 1；上限 :data:`PROBE_MAX_PACKETS_PER_TARGET`（单目标包数
    上限，180s → 37 轮）。
```

### `probe_len`

```python
def probe_len(specs: Iterable[ProbeSpec]) -> int
```

```text
预估探针报文数，用于给用户提示「本次会额外发多少包」。

Args:
    specs: 探针规格集合。

Returns:
    int: 每个规格至少 1 包的报文总数。
```

### `probe_src_port`

```python
def probe_src_port(seq: int) -> int
```

```text
按序号在固定端口段里分配源端口（纯函数，便于复现账本）。

Args:
    seq: 全局递增序号（从 1 开始）。

Returns:
    int: 落在 :data:`PROBE_SRC_PORT_RANGE` 内的源端口。
```

### `send_probe`

```python
def send_probe(spec: ProbeSpec, seq: int, timeout_s: float | None=None) -> tuple[bool, float | None, str, str]
```

```text
发出一个探针并判定「通 / 丢」（scapy 收发；依赖 Npcap，失败只降级）。

判定口径（SPEC V5）：ICMP 收到 echo-reply = 通、超时 = 丢；TCP 收到
SYN-ACK 或 RST = 通（网络可达）；UDP 收到任意响应、或 ICMP port-unreachable
= 通（主机可达，端口没开）；全部超时 = 丢。

Args:
    spec: 探针规格。
    seq: 全局序号（ICMP seq / 源端口都从它派生）。
    timeout_s: 覆盖规格里的等待上限；``None`` 时用 ``spec.timeout_s``。

Returns:
    tuple[bool, float | None, str, str]: ``(responded, rtt_ms, responder, error)``。
    失败时 ``rtt_ms`` 为 ``None``、``error`` 写原因（不含敏感信息）；本函数
    **不抛异常**（scapy 缺失 / 权限不足 / 网卡打不开都转成 error）。
```

### `ShadowProber`  (class)

```python
class ShadowProber
```

```text
后台影子探测线程：首轮立即发，之后每 ``interval_s`` 秒一轮，按轮数封顶。

生命周期（SPEC V3）：``start()`` 启动 daemon 线程并立刻发第一轮；``stop()``
置取消位，``join(timeout=3)`` 最多等 3 秒。探针异常在 :meth:`run_round`
内部吞掉并记进 ``error``，**绝不影响主诊断**。

Attributes:
    specs: 探针规格元组。
    ledger: :class:`ProbeLedger` 账本（线程安全地追加记录）。
```

### `ShadowProber.start`  (method)

```python
def start(self) -> None
```

```text
启动后台探针线程（幂等：已在跑时直接返回；不发任何包在调用线程里）。
```

### `ShadowProber.stop`  (method)

```python
def stop(self) -> None
```

```text
请求停止：置取消位，当前这一轮发完即收尾（不阻塞调用方）。
```

### `ShadowProber.join`  (method)

```python
def join(self, timeout: float=3.0) -> bool
```

```text
等探针线程退出（最多 ``timeout`` 秒）。

Args:
    timeout: 最长等待秒数，默认 3（SPEC V3 要求 3s 内退出）。

Returns:
    bool: 线程已退出返回 True；仍存活返回 False。
```

### `ShadowProber.run_round`  (method)

```python
def run_round(self) -> list[ProbeRecord]
```

```text
同步发一轮探针（每目标 1 包），返回本轮记录。

Returns:
    list[ProbeRecord]: 本轮产生的记录；发送器抛异常时也会记一条带
        ``error`` 的记录（保证「账本有痕迹」）。
```

### `ShadowProber.exclusion_bpf`  (method)

```python
def exclusion_bpf(self) -> str
```

```text
抓包排除表达式：已发记录优先，未发时按计划规格预生成（抓包前用）。

Returns:
    str: BPF 串；没有探针规格时返回空串。
```

### `ShadowProber.exclusion_display_filter`  (method)

```python
def exclusion_display_filter(self) -> str
```

```text
分析阶段排除表达式（已发记录优先，未发时按计划规格预生成）。

Returns:
    str: tshark ``-Y`` 串；没有探针规格时返回空串。
```

### `ShadowProber.marker_display_filter`  (method)

```python
def marker_display_filter(self) -> str
```

```text
只匹配探针报文的显示过滤（统计 pcap 里混入多少探针包）。

Returns:
    str: tshark ``-Y`` 串；没有探针规格时返回空串。
```

### `ShadowProber.sent_count`  (method)

```python
@property
def sent_count(self) -> int
```

```text
已写进账本的探针记录数（含发送失败的记录）。

Returns:
    int: 记录条数。
```

### `ShadowProber.snapshot`  (method)

```python
def snapshot(self) -> dict
```

```text
把「计划 + 账本 + 聚合基线 + 三种过滤串」打包成可 JSON 序列化的快照。

Returns:
    dict: 键 ``planned``（规格列表）/``ledger``（:meth:`ProbeLedger.to_dict`）/
        ``baseline``（:meth:`ProbeLedger.baseline`）/``exclusion_bpf``/
        ``exclusion_display_filter``/``marker_display_filter``。
```

### `aggregate_records`

```python
def aggregate_records(records: Iterable[ProbeRecord]) -> list[dict]
```

```text
按 ``(role, target, kind)`` 聚合探针记录（纯函数，报告与方向对照共用）。

Args:
    records: 逐条探针记录。

Returns:
    list[dict]: 每个角色/目标一组，键 ``role``/``kind``/``target``/``sent``/
        ``recv``/``timeout``/``loss_pct``/``n``/``rtt_min_ms``/``rtt_avg_ms``/
        ``rtt_max_ms``/``jitter_ms``/``errors``。``timeout = sent - recv`` 是
        **模块自记**的超时数（与 ``loss_pct`` 同源）。**没有 RTT 样本时**
        ``n=0`` 且 ``rtt_*`` 为 ``None``（不是 0.0）；``loss_pct`` 只在
        ``sent=0`` 时为 ``None``。分组按网关 → DNS → 业务目标排序。
```

### `count_marked_packets`

```python
def count_marked_packets(tshark_path, pcap, kinds: Iterable[ProbeKind]) -> int
```

```text
用 tshark 显示过滤统计 pcap 里混进了多少**标记探针报文**。

这是「已排除 N 个探针包」这句报告文案的取数口：抓包 BPF 生效时应为 0；
不为 0 说明 BPF 没盖住（例如抓的是 TUN 网卡），分析阶段的显示过滤会兜底。

口径与 :func:`count_time_exceeded_packets` **互斥**：ICMP 片段排除 type 11，
因此本函数不会把路径设备回的 time-exceeded（即使内嵌我们的 ``PROBE_ID``）
算进来；那些包由 ``path_profile.excluded_icmp`` 统一计数。

Args:
    tshark_path: tshark 可执行文件路径（``Path`` 或字符串）。
    pcap: 已抓好的抓包文件。
    kinds: 本次会发出的探针协议集合。

Returns:
    int: 命中的标记探针报文条数；表达式为空 / tshark 失败 / 文件读不了都返回 0
        （统计失败不改变诊断结论）。
```

### `count_time_exceeded_packets`

```python
def count_time_exceeded_packets(tshark_path, pcap) -> int
```

```text
统计 pcap 里的 ``ICMP type 11``（TTL 超时）报文数。

MTR 期间设备回的 time-exceeded 认不出探针 id，只能整类排除；这个数字就是
「本窗口内已从统计剔除的 ICMP 超时包数」的取数口。它**包含非探针流量**的
TTL 超时，所以报告里写明 N 是上限，不是「路径探测相关」的精确归因。
与 :func:`count_marked_packets` 互斥（后者显式排除 type 11），两数相加即
本窗口被两道显示过滤剔除的互不重叠报文数。

Args:
    tshark_path: tshark 可执行文件路径（``Path`` 或字符串）。
    pcap: 已抓好的抓包文件。

Returns:
    int: 命中的 type 11 报文数；tshark 失败 / 文件读不了返回 0
        （统计失败不改变诊断结论）。
```

### `probe_tcp_reachable`

```python
def probe_tcp_reachable(ip: str, port: int, timeout_s: float=PATH_TCP_CHECK_TIMEOUT_S) -> bool
```

```text
用一次普通 TCP 连接判断「目标端口是否可达」（不发送任何数据）。

判定口径与影子探针一致：**SYN-ACK（连上）或 RST（连接被拒）都算可达** ——
两种都证明「去目标的那条路是通的」，这正是区分「ICMP 被过滤」与「链路故障」
所需的证据；超时 / 网络不可达 / 参数非法都算不可达。

Args:
    ip: 目标 IPv4 字面量。
    port: 目标端口。
    timeout_s: 单次连接超时（秒）。

Returns:
    bool: 可达为 True；任何失败为 False（不抛异常）。
```

### `check_target_port`

```python
def check_target_port(ip: str, port: int | None=None, timeout_s: float=PATH_TCP_CHECK_TIMEOUT_S, checker: Callable[..., bool] | None=None) -> tuple[bool | None, int | None]
```

```text
判断目标端口可达性；未给端口时按 :data:`PATH_FALLBACK_PORTS` 依次尝试。

Args:
    ip: 目标 IPv4 字面量。
    port: 显式端口；``None`` 时尝试 443 → 80。
    timeout_s: 单次连接超时（秒）。
    checker: 可注入的单端口判定函数；省略时用 :func:`probe_tcp_reachable`
        （单测用，避免真连网）。

Returns:
    tuple[bool | None, int | None]: ``(reachable, port)``。``reachable`` 为
        ``None`` 表示根本没测（ip 为空）；``port`` 是实际测的那个端口
        （显式给的，或第一个可达的；都不可达时是第一个试的端口）。
```

### `path_engine_log_line`

```python
def path_engine_log_line(engine: str) -> str
```

```text
引擎日志文案（报告/日志共用，避免调用方各写一份中文）。

Args:
    engine: :data:`PATH_ENGINE_SCAPY` / :data:`PATH_ENGINE_TRACERT` 或任意串。

Returns:
    str: ``tracert`` 时是「scapy 不可用，使用系统 tracert 降级（每跳 3 次探测）」，
    其余一律按 scapy 写。**只用于日志**，不参与判定。

Example:
    >>> "tracert" in path_engine_log_line("tracert")
    True
```

### `run`

```python
def run(target: str, port: int | None=None, max_hops: int=PATH_DEFAULT_MAX_HOPS, samples: int=PATH_DEFAULT_SAMPLES, timeout_s: float=1.0, *, should_stop: Callable[[], bool] | None=None, sender: PathSender | None=None, tcp_checker: Callable[..., bool] | None=None, logger: Callable[[str], None] | None=None) -> PathProbeResult
```

```text
TTL 递增路径探测：逐跳 RTT/丢包/抖动 + 劣化判定 + 引擎降级。

流程（全部在 IPv4 上）：

1. 目标解析（域名先解析；IPv6 明确拒绝）；
2. 先测一次目标端口 TCP 可达性（``port`` 未给时试 443/80），留作「ICMP 被过滤」
   的判据；
3. **选引擎**：注入 ``sender``（单测）或 scapy 可导入 → 原有 MTR 批量
   ``sr()`` 实现；scapy 不可用 → 系统 ``tracert -d -h 16 -w <毫秒>`` 逐跳
   降级（每跳 3 次探测，``method="tracert"``）——「没有 scapy」不会变成
   路径探测不可用；
4. **ICMP 逐跳（scapy）**：TTL 1..max_hops 按 :data:`PATH_BATCH_HOPS` 分批，
   每批一次 ``sr()``；收到目标自己的回复即停；
5. 若 ICMP **一个响应都没有**而目标端口 TCP 可达 → 判定 ICMP 被策略过滤，
   改用 **TCP SYN 逐跳**重扫（样本减半；仅 scapy 引擎），结果带
   ``icmp_filtered=True`` / ``method="tcp"``，且 ``verdict_key`` 固定为
   ``PATH.ICMP_FILTERED``（TCP 有响应只证明端口可达，不能反推「ICMP 路径正常」）；
   TCP 也不可达 → ``PATH.NO_DATA`` + ``unreachable=True``；
6. :func:`summarize_path` 给出「第几跳开始劣化 + 该找谁」，TUN/代理再给提示。
   劣化按 R5 的持久性约束：单跳异常必须持续到目标或最后响应跳；中间跳限速
   只记进 ``middle_loss_suspected`` / ``middle_loss_ttls``，不判承载网。

Args:
    target: 目标 IP / 域名。
    port: 目标端口；``None`` 时用 443/80 做可达性判断，TCP 降级时也用它。
    max_hops: 最大跳数，夹到 :data:`PATH_MAX_HOPS_RANGE`；tracert 降级再夹到
        :data:`TRACERT_MAX_HOPS`（16）。
    samples: 每跳采样数，夹到 :data:`PATH_SAMPLES_RANGE`；tracert 降级固定 3。
    timeout_s: 单批等待上限（秒），夹到 :data:`PATH_TIMEOUT_RANGE`；tracert
        降级时换算成 ``-w`` 毫秒。
    should_stop: 可选的取消判定；每批发包前（tracert 为每 100ms）调用一次，
        返回 True 就收尾并把 ``completed`` 置 False（实时抓包取消/时间预算用）。
    sender: 可注入的批量发送器（单测用；省略时按 scapy 可用性选引擎）。
    tcp_checker: 可注入的可达性判定 ``(ip, port, timeout) -> bool``；省略时
        等价于 :func:`probe_tcp_reachable`（单测用，避免真连网）。
    logger: 可选日志回调；给出时写一行「使用哪个引擎」（scapy / tracert），
        不抛异常。单测 / 库调用可以不传。

Returns:
    :class:`PathProbeResult`: 逐跳统计 + ``verdict_key`` / ``degraded_ttl`` /
    ``method``（``icmp`` / ``tcp`` / ``tracert``）/ ``icmp_filtered`` /
    ``tun_suspected`` / ``middle_loss_suspected`` / ``middle_loss_ttls`` 等；
    参数非法 / 解析失败 / 两个引擎都不可用时也返回结果（``hops`` 为空、
    ``error`` 写明原因），**不抛异常** —— 调用方（实时抓包 / 体检）绝不允许
    被路径探测拖垮。

Note:
    本函数**不写文件、不读配置**；scapy 路径发出的每个包都带固定标记（ICMP id =
    :data:`PROBE_ID`、TCP 源端口 ∈ :data:`PROBE_SRC_PORT_RANGE`），抓包侧
    必须同时生效 :func:`exclusion_bpf` 与 :func:`path_exclusion_display_filter`。
    tracert 路径的探测包由系统命令发出，**不在**本模块的标记体系里；抓包时
    仍按 ICMP type 11 整类排除（见 ``docs/path-probe.md`` 的声明例外）。
    TCP 降级重扫失败时**保留** ICMP 的逐跳数据（「ICMP 全丢」本身已是结论），
    只把原因写进 ``error``，不会因此返回空路径。
```

### `PathProfiler`  (class)

```python
class PathProfiler
```

```text
后台路径探测线程：实时抓包同时跑 MTR，可取消、失败只降级。

生命周期与 :class:`ShadowProber` 一致（daemon 线程 + ``Event`` 取消 +
``join(timeout)``），额外带**时间预算**：到点后 :func:`run` 在下一批发包前
收尾并返回已完成的跳（``completed=False``），绝不把抓包主流程拖住。

Attributes:
    target: 目标 IP / 域名。
    port: 目标端口（``None`` 表示按 443/80 判断）。
    max_hops / samples / timeout_s: 已夹取的探测参数。
    budget_s: 时间预算（秒），由抓包时长 + 5 秒得出。
    result: :class:`PathProbeResult`；线程未跑完时为 ``None``。
    error: 线程内异常（探针不可用）的描述，成功为空串。
```

### `PathProfiler.start`  (method)

```python
def start(self) -> None
```

```text
启动后台线程（幂等：已在跑时直接返回）。
```

### `PathProfiler.stop`  (method)

```python
def stop(self) -> None
```

```text
请求停止：置取消位，当前这一批发完即收尾（不阻塞调用方）。
```

### `PathProfiler.join`  (method)

```python
def join(self, timeout: float=3.0) -> bool
```

```text
等线程退出（最多 ``timeout`` 秒）。

Args:
    timeout: 最长等待秒数。

Returns:
    bool: 已退出返回 True；仍存活返回 False。
```

### `PathProfiler.should_stop`  (method)

```python
def should_stop(self) -> bool
```

```text
取消判定：外部 ``stop()`` 或时间预算到点都算停。

Returns:
    bool: 该收尾时为 True。
```

### `PathProfiler.snapshot`  (method)

```python
def snapshot(self) -> dict
```

```text
把「参数 + 结果 + 过滤串」打包成可 JSON 序列化的快照。

Returns:
    dict: 键 ``profile``（:meth:`PathProbeResult.to_dict`；没有结果时
        ``None``）/``error``/``planned_kinds``/``started_epoch``/
        ``finished_epoch``/``budget_s``/``exclusion_bpf``/
        ``exclusion_display_filter``/``marker_display_filter``。
```

## `core/platform/__init__.py`

**职责**：平台适配层：只做「与操作系统打交道」的事，不含业务判断。

_（无公开符号）_

## `core/platform/paths.py`

**职责**：目录约定与根目录探测。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `find_root` | function | 32 | ✅ |
| `Paths` | class | 61 | ✅ |
| `Paths.core` | method | 67 | ✅ |
| `Paths.config` | method | 76 | ✅ |
| `Paths.captures` | method | 85 | ✅ |
| `Paths.reports` | method | 94 | ✅ |
| `Paths.logs` | method | 103 | ✅ |
| `Paths.data` | method | 112 | ✅ |
| `Paths.ui` | method | 121 | ✅ |
| `Paths.tools` | method | 130 | ✅ |
| `Paths.skills` | method | 139 | ✅ |
| `Paths.mcp` | method | 148 | ✅ |
| `Paths.tshark_exe` | method | 157 | ✅ |
| `Paths.python_exe` | method | 167 | ✅ |
| `Paths.ensure` | method | 175 | ✅ |
| `Paths.writable` | method | 192 | ✅ |

### `find_root`

```python
def find_root(start: Path | None=None) -> Path
```

```text
向上找到项目根目录（靠在标记文件，不靠固定的 ``parents[N]``）。

标记：同时存在 ``VERSION`` 与 ``start.bat``；或存在 ``config/`` + ``core/``。

Args:
    start: 从哪里开始找；省略时以本文件位置为起点。

Returns:
    Path: 解析后的绝对路径。优先级：环境变量 ``USB_NET_DIAG_ROOT`` >
        向上找标记 > 兜底「上两级父目录」（保证返回一个可用路径，不抛异常）。
```

### `Paths`  (class)

```python
@dataclass(frozen=True)
class Paths
```

```text
仓库内所有约定目录。任何模块都不许自己拼 ``Path(__file__).parent...``。
```

### `Paths.core`  (method)

```python
@property
def core(self) -> Path
```

```text
源代码目录。

Returns:
    Path: ``<root>/core``。
```

### `Paths.config`  (method)

```python
@property
def config(self) -> Path
```

```text
配置文件目录（``app-config.json`` / ``ai-config.json``）。

Returns:
    Path: ``<root>/config``。
```

### `Paths.captures`  (method)

```python
@property
def captures(self) -> Path
```

```text
抓包落盘目录，也是分析抓包文件唯一允许读取的位置。

Returns:
    Path: ``<root>/captures``。
```

### `Paths.reports`  (method)

```python
@property
def reports(self) -> Path
```

```text
报告输出目录（``.md`` / ``.json``）。

Returns:
    Path: ``<root>/reports``。
```

### `Paths.logs`  (method)

```python
@property
def logs(self) -> Path
```

```text
运行日志与 PID 文件目录。

Returns:
    Path: ``<root>/logs``。
```

### `Paths.data`  (method)

```python
@property
def data(self) -> Path
```

```text
持久化数据目录（历史基线 ``history.db`` 等）。

Returns:
    Path: ``<root>/data``。首次使用时才创建。
```

### `Paths.ui`  (method)

```python
@property
def ui(self) -> Path
```

```text
前端资源目录（单文件 ``index.html``）。

Returns:
    Path: ``<root>/ui``。
```

### `Paths.tools`  (method)

```python
@property
def tools(self) -> Path
```

```text
便携工具链目录（Python / Wireshark / Npcap 安装包）。

Returns:
    Path: ``<root>/tools``。
```

### `Paths.skills`  (method)

```python
@property
def skills(self) -> Path
```

```text
配套 Skill 文档目录。

Returns:
    Path: ``<root>/skills``。
```

### `Paths.mcp`  (method)

```python
@property
def mcp(self) -> Path
```

```text
MCP 服务端目录。

Returns:
    Path: ``<root>/mcp``。
```

### `Paths.tshark_exe`  (method)

```python
@property
def tshark_exe(self) -> Path
```

```text
便携版 tshark 的预期路径。

Returns:
    Path: ``<root>/tools/WiresharkPortable/App/Wireshark/tshark.exe``。
        **不保证存在** —— 需要实际可用时请用 ``tshark.find_tshark()``（它还会找系统安装）。
```

### `Paths.python_exe`  (method)

```python
@property
def python_exe(self) -> Path
```

```text
便携版解释器路径。

Returns:
    Path: ``<root>/tools/python/python.exe``。
```

### `Paths.ensure`  (method)

```python
def ensure(self, *which) -> tuple[Path, ...]
```

```text
按需创建目录（启动时调用，避免各模块自己 mkdir）。

Args:
    *which: 属性名列表，如 ``"captures"`` / ``"reports"`` / ``"logs"``。
        传不存在的属性名会抛 ``AttributeError``。

Returns:
    tuple[Path, ...]: 与入参一一对应的、已确保存在的目录路径。
```

### `Paths.writable`  (method)

```python
def writable(self, name: str='reports') -> bool
```

```text
探测某目录是否真的能写。

U 盘写保护、只读盘符、被安全软件锁定时，``mkdir`` 可能成功但写入失败 ——
所以这里真写一个探针文件再删掉。

Args:
    name: 属性名，默认 ``"reports"``。

Returns:
    bool: True 表示可写。失败时不抛异常，只返回 False，
        由调用方提示「请检查写保护开关」。
```

## `core/platform/winapi.py`

**职责**：Windows 平台能力：管理员、Npcap、网卡、网关、DNS。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `is_admin` | function | 79 | ✅ |
| `npcap_installed` | function | 94 | ✅ |
| `Adapter` | class | 130 | ✅ |
| `adapters` | function | 171 | ✅ |
| `default_gateway` | function | 213 | ✅ |
| `icmp_stats` | function | 242 | ✅ |
| `dns_servers` | function | 413 | ✅ |
| `interface_index_map` | function | 435 | ✅ |

### `is_admin`

```python
def is_admin() -> bool
```

```text
当前进程是否具备管理员权限（实时抓包的前提）。

Returns:
    bool: Windows 上问 ``IsUserAnAdmin()``；非 Windows 看 ``geteuid()==0``。
        调用失败返回 ``False``（保守：宁可提示可能抓不了包）。
```

### `npcap_installed`

```python
def npcap_installed() -> bool
```

```text
Npcap 是否就绪。

判定顺序（从便宜到贵）：驱动目录 → ``wpcap.dll`` → 服务注册表键。
**不判断服务状态文本** —— 服务名可能是 ``npcap`` 或 ``npf``，
``sc query`` 的输出还是本地化的，靠文本匹配会在中文/英文系统上表现不一致。

Returns:
    bool: 任一证据命中即 True；非 Windows 恒 True。
```

### `Adapter`  (class)

```python
@dataclass(frozen=True)
class Adapter
```

```text
一块网卡及其地址。

字段：
    name: 友好名（``以太网`` / ``WLAN``），给用户看。
    description: 原始设备串（``tshark -D`` 的整行），排障时用于确认是哪块卡。
    mac: MAC 地址；临时实现下为空。
    ipv4 / gateway / dns: 地址、网关、DNS 列表；临时实现下为空元组。
    is_up: 是否已连接。
```

### `adapters`

```python
def adapters() -> tuple[Adapter, ...]
```

```text
枚举网卡与地址（替代 ``ipconfig`` 文本解析）。

当前为**临时实现**：转发到 ``tshark -D``，只提供网卡序号与友好名，
``ipv4`` / ``gateway`` / ``dns`` / ``mac`` 均为空 —— 因为 ``-D`` 不带地址信息。
第 4 阶段（T13 路径探测）会换成 ``GetAdaptersAddresses`` 的 ctypes 实现，
届时这几个字段才有真实值。

实现要点（真机调试用）::

    GetAdaptersAddresses(
        Family=AF_UNSPEC,
        Flags=GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
        Reserved=None, SizePointer=byref(size), Addresses=buf)

先用 ``size=0`` 调一次拿 ``ERROR_BUFFER_OVERFLOW`` 的所需长度，
再分配缓冲区二次调用。字段：``FriendlyName`` / ``PhysicalAddress`` /
``FirstUnicastAddress`` / ``FirstGatewayAddress`` / ``FirstDnsServerAddress``。

Returns:
    按 ``tshark -D`` 顺序排列的 :class:`Adapter` 元组；找不到 tshark 时返回空元组
    （**不抛异常**，让上层用「无网卡」的正常分支处理）。
```

### `default_gateway`

```python
def default_gateway(dest: str='8.8.8.8') -> str
```

```text
默认网关地址（路径探测 / 0 包降级时判断「本地链路是否可达」）。

调 ``iphlpapi.GetBestRoute`` 查「去往 ``dest`` 的最优路由」的下一跳，**不解析
任何本地化命令行输出**。没有默认路由（如断网、只有直连网段）时返回空串。

Args:
    dest: 查询目的地址（IPv4 字面量），默认 ``8.8.8.8``，即走默认路由。

Returns:
    str: 网关 IPv4 地址；非 Windows、无默认路由或 API 调用失败时返回 ``""``。
```

### `icmp_stats`

```python
def icmp_stats(host: str, count: int=4, timeout_ms: int=800) -> dict
```

```text
用 Windows ``IcmpSendEcho`` 测一个地址的 RTT / 抖动 / 丢包（非管理员可用）。

0 包优雅降级需要一组「链路是否可达」的数字，但抓包可能根本看不到业务报文；
这里用系统 ICMP 回显做一次轻量探测。用 API 而不是解析 ``ping`` 文本：中文 /
英文系统的输出格式不同，做文本匹配会在别的机器上静默失效。

Args:
    host: IPv4 字面量（域名请先解析；本函数不联网查 DNS）。
    count: 探测次数，夹在 1~10；默认 4。
    timeout_ms: 单次等待毫秒数，夹在 100~5000；默认 800。

Returns:
    dict: 键 ``ok``（至少收到 1 个回复）/ ``host`` / ``sent`` / ``recv`` /
        ``loss_pct``（0~100，1 位小数）/ ``avg_ms`` / ``jitter_ms``（RTT 总体
        标准差，1 位小数）/ ``error``（失败原因，成功为空串）。非 Windows、
        非 IPv4、API 不可用时 ``ok=False`` 且 ``error`` 说明原因，不抛异常。
```

### `dns_servers`

```python
def dns_servers() -> tuple[str, ...]
```

```text
当前生效的 DNS 服务器列表（只读注册表，不解析本地化 CLI 文本）。

注意 DNS 可能来自 DHCP / 组策略 / 每网卡独立配置，开了 DoH（DNS over HTTPS）
之后注册表里的地址与真正发查询的地址还可能不一致 —— 报告里必须标注这一
不确定性：探 DNS 服务器只能证明「这台机器到该地址的 UDP/53 通不通」。

Returns:
    tuple[str, ...]: 去重后的 IPv4 地址（静态配置优先于 DHCP 下发，网卡顺序按
    注册表枚举顺序）；非 Windows、注册表不可读、没有任何有效地址时返回
    ``()`` —— **不抛异常**（探针拿不到 DNS 角色只会少一行，不该拖垮诊断）。

Example:
    >>> dns_servers()  # doctest: +SKIP
    ('192.0.2.53',)
```

### `interface_index_map`

```python
def interface_index_map() -> dict[str, int]
```

```text
网卡友好名 → tshark ``-i`` 序号。

现状靠正则从 ``tshark -D`` 的括号别名里抠（见 ``tshark.short_name``）；
更稳的做法是用 ``GetIfEntry2`` 的 ``InterfaceIndex`` 对齐。

Returns:
    dict[str, int]: 友好名到序号的映射。

Raises:
    NotImplementedError: 本阶段未实现。
```

## `core/probe.py`

**职责**：连通与速度测试（链路体检）：不抓包，直接分段测量一次真实访问，定位慢在哪一段。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `run` | function | 672 | ✅ |

### `run`

```python
def run(target: str, port: int | None=None, count: int=4, timeout: float=3.0, tls_override: bool | None=None, proto: str | None=None) -> dict
```

```text
执行一次分段体检，返回各段耗时、识别出的协议与结论。

先 ``MSG_PEEK`` 读首包判断对端是什么协议（TLS/HTTP/SMB/SSH/RDP/MySQL/不透明 TCP），
再按该协议分段计时 —— 因此端口不常见的服务也能给出有意义的耗时拆解。

Args:
    target: 目标，支持 ``host`` / ``host:port`` / ``http://host/path`` / ``[::1]:8080``。
    port: 显式端口；省略时从 target 或 scheme 推断（HTTPS→443，HTTP→80）。
    count: 探测次数（取中位数），影响 RTT 抖动估计。
    timeout: 单段超时秒数。
    tls_override: 强制走/不走 TLS；``None`` 表示按首包指纹自动判断。
    proto: 手动指定协议（``tls``/``http``/``smb``/``rdp``/``opaque``），
        用于端口不常见的场景；非法值忽略。

Returns:
    dict: 成功 ``{"ok": True, "target", "ip", "protocol", "segments": [...],
        "total_ms", "level", "headline", "advice"}``；
        失败 ``{"ok": False, "error": "..."}``（目标非法、DNS 失败、连接不通）。
```

## `core/report.py`

**职责**：报告渲染：分层故障定位（主）+ 完整技术明细（辅）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `render_markdown` | function | 374 | ✅ |
| `save` | function | 650 | ✅ |
| `render_degraded` | function | 754 | ✅ |
| `save_degraded` | function | 832 | ✅ |

### `render_markdown`

```python
def render_markdown(result: dict, vd: dict | None=None) -> str
```

```text
把一次诊断结果渲染成 Markdown 报告。

Args:
    result: ``analyze()``/``run_scan()`` 的结果字典。
    vd: 判定结果；省略时现场 ``verdict.build(result)`` 算一遍（避免调用方重复计算）。

Returns:
    str: 完整 Markdown 正文 —— 结论段、分层定位、问题清单（现象/处理/依据）、
        会话表与技术明细。
```

### `save`

```python
def save(result: dict, out_dir: Path) -> dict
```

```text
把报告写成 ``.md`` 与 ``.json`` 两份。

Args:
    result: 诊断结果字典。
    out_dir: 输出目录（通常是 ``reports/``）。

Returns:
    dict: 键 ``md`` / ``json``（绝对路径字符串）。

Note:
    JSON 侧**只挑** ``summary`` / ``meta`` / ``metrics`` / ``rows`` / ``verdict`` 五块写盘，
    因此新增的 ``findings_v2`` / ``provenance`` 不会改变已提交的报告快照。
    E1 起 ``verdict`` 块新增 ``confidence`` / ``basis`` / ``coverage`` /
    ``not_covered`` 四个键（声明例外）；``confidence_level`` / ``key_limit``
    只在渲染层出现，**不落库**。
    文件名取自抓包文件名，并过滤掉路径分隔符等危险字符。

    落盘前把 ``meta.tshark_path`` 替换成固定占位：绝对路径是机器相关键，
    换机器重跑会让 ``git diff reports/`` 一直脏（``analyze()`` 的原值不动，
    只在落盘时替换）。
```

### `render_degraded`

```python
def render_degraded(result: dict) -> str
```

```text
把 0 包降级结论渲染成 Markdown（结论 + 边界 + 事实 + 原因 + 建议）。

与正常诊断报告分开渲染：降级结果没有 ``rows`` / ``verdict``，强行套用
:func:`render_markdown` 会出现空章节，反而又变成「结果区没有内容」。

B1 起在同一节里输出统一的「结论与边界」整块（结论 / 依据 / 本次覆盖 /
明确未覆盖 / 置信等级+关键边界）：降级报告也是可下载、可归档的导出路径，
按 E-SPEC §1-四不能只给结论不给边界。原有一、二、三、四节的字段含义与
顺序不变，结论块是纯插入。

Args:
    result: :func:`diagnose.degraded_empty_capture_result` 的返回值，键含
        ``card_title`` / ``headline`` / ``plain`` / ``link`` / ``capture`` /
        ``reasons`` / ``next_steps`` / ``at``。

Returns:
    str: Markdown 正文（UTF-8 文本，LF 换行），含同一渲染器生成的
        「### 结论与边界」整块。
```

### `save_degraded`

```python
def save_degraded(result: dict, out_dir: Path) -> dict
```

```text
把 0 包降级结论落盘成 ``.md`` + ``.json``（复审遗留 #7）。

路测要求：降级卡不能只活在界面上，历史报告 / 导出诊断包里也要能查到这次
结论。文件名带时间戳，不覆盖任何既有报告。

B1 起 JSON 与 md 同步携带同一结论边界对象（``conclusion`` / ``basis`` /
``coverage`` / ``not_covered`` / ``confidence`` / ``confidence_level`` /
``key_limit``）。这是**独立导出**，允许出现渲染期派生字段；普通
:func:`save` 的五块报告 JSON 约定不变（仍不写 ``confidence_level`` /
``key_limit``）。

Args:
    result: :func:`diagnose.degraded_empty_capture_result` 的返回值。
    out_dir: 输出目录（通常是 ``reports/``）。

Returns:
    dict: 键 ``markdown`` / ``json``（绝对路径字符串）。
```

## `core/rules/__init__.py`

**职责**：规则包（渐进迁移中）。

_（无公开符号）_

## `core/rules/legacy_map.py`

**职责**：旧 ``rows[]`` → 新 ``Finding`` 的迁移桥（**临时件，T05 完成后可删**）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `LegacyPattern` | class | 60 | ✅ |
| `match` | function | 184 | ✅ |
| `is_normal` | function | 223 | ✅ |
| `to_finding` | function | 246 | ✅ |
| `map_rows` | function | 308 | ✅ |
| `find_unmatched` | function | 325 | ✅ |
| `coverage` | function | 345 | ✅ |
| `mapped_rule_ids` | function | 376 | ✅ |
| `missing_from_registry` | function | 388 | ✅ |

### `LegacyPattern`  (class)

```python
@dataclass(frozen=True)
class LegacyPattern
```

```text
一条映射规则。匹配条件 = 层 + 类别 + 关键词（空 = 该层该类别的异常行）。
```

### `match`

```python
def match(row: Mapping) -> LegacyPattern | None
```

```text
按「层 + 类别 + 关键词」找第一条匹配的映射规则。

Args:
    row: 旧结构的一行，需含 ``layer`` / ``category`` / ``finding``。

Returns:
    LegacyPattern | None: 命中的规则；返回 ``None`` 表示「新规则还没覆盖到」，
        调用方应把它记进未匹配清单（CI 里断言为空）。

Note:
    顺序敏感：``PATTERNS`` 里更具体的 ``keyword`` 必须排在前面，
    否则「连接建立」的三个模式会互相吃掉。
```

### `is_normal`

```python
def is_normal(row: Mapping) -> bool
```

```text
判断这一行是不是「测了、正常」的陈述（不该产出 Finding）。

Args:
    row: 旧结构的一行。

Returns:
    bool: 严重度映射为 :attr:`Severity.OK`（即 ``"—"``）时为 True。
        ``"na"``（没样本）返回 False —— 它是第三种状态，回答的是「没测到」
        而不是「没问题」。

Note:
    V4：判定改为**基于严重度**，不再靠 ``NORMAL_HINTS`` 对 finding 文本做
    关键词匹配。旧实现让 ``"na"`` 行靠「未检测到…」这类词兜住，是双向陷阱：
    改文案会静默改变迁移结果（漏项 / 多映射），而「没样本」也从来不是
    「正常」。现在文案怎么改都不影响判定。

    ``"na"`` 行虽然不算 normal，但同样不产出 Finding（没样本没有结论）：
    :func:`to_finding` 与 :func:`find_unmatched` 各自显式跳过它。
```

### `to_finding`

```python
def to_finding(row: Mapping, index: int=0) -> Finding | None
```

```text
把一行旧 ``row`` 转成结构化 ``Finding``。

Args:
    row: 旧结构的一行。
    index: 该行在原 ``rows[]`` 里的下标，写进 ``metric["legacy_index"]`` 便于回溯。

Returns:
    Finding | None: 正常行、或没有任何模式匹配时返回 ``None``。

Note:
    旧数据没有方向，所以 ``direction`` 一律为 ``None``；依赖方向才能定性的规则
    （重传、零窗口）会把置信度压到 0.6 并标成 ``INFERRED`` ——
    宁可写「疑似」，也不要给出确定结论。
```

### `map_rows`

```python
def map_rows(rows: Iterable[Mapping]) -> list[Finding]
```

```text
批量转换，保持原顺序。

Args:
    rows: 旧 ``rows[]`` 列表。

Returns:
    list[Finding]: 只含有结论的行；正常行与未匹配行被跳过。
```

### `find_unmatched`

```python
def find_unmatched(rows: Iterable[Mapping]) -> list[Mapping]
```

```text
找出「既不是正常行、也没有匹配到模式」的行。

Args:
    rows: 旧 ``rows[]`` 列表。

Returns:
    list[Mapping]: 漏映射的行。**CI 里应断言为空** ——
        非空意味着有人加了新规则却忘了补映射，迁移会静默漏项。
```

### `coverage`

```python
def coverage(rows: Sequence[Mapping]) -> dict
```

```text
迁移进度报告。

Args:
    rows: 旧 ``rows[]`` 列表。

Returns:
    dict: 键 ``total``（总行数）/ ``mapped``（已映射）/ ``normal``（测了正常）/
        ``no_sample``（没样本，``severity == "na"``）/ ``unmatched``（漏映射数）/
        ``unmatched_rows``（漏映射行的摘要，便于直接看）。

Note:
    ``na`` 行单独计数（V4 的 ``no_sample`` 桶）：它既不是 normal（没测过，
    不能报「正常」），也不该算「漏映射」（它本来就不该产出 Finding）。
```

### `mapped_rule_ids`

```python
def mapped_rule_ids() -> tuple[str, ...]
```

```text
本映射表能产出的全部 ``rule_id``。

Returns:
    tuple[str, ...]: 去重且保序的 ``rule_id`` 列表。
```

### `missing_from_registry`

```python
def missing_from_registry() -> tuple[str, ...]
```

```text
已能映射、但 ``core/rules/`` 还没实现的 ``rule_id`` —— 这就是 T05 的待办清单。

Returns:
    tuple[str, ...]: 尚未被新规则引擎接管的 ``rule_id``。
        返回空元组说明新引擎已吃下全部旧能力，本文件可以删了。
```

## `core/sanitize.py`

**职责**：诊断包脱敏：把日志里的 IP、域名、用户名、MAC 换成**不可还原**的伪名。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `pseudonym` | function | 159 | ✅ |
| `collect_tokens` | function | 174 | ✅ |
| `mask_text` | function | 226 | ✅ |
| `mask_obj` | function | 257 | ✅ |

### `pseudonym`

```python
def pseudonym(s: str) -> str
```

```text
返回稳定伪名：``sha1(小写原文)`` 的前 4 位十六进制。

Args:
    s: 原文（IP / 域名 / MAC）。空串返回空串。

Returns:
    str: 4 位小写十六进制。同一原文永远得到同一个值；不同原文可能碰撞，
        这里只用于「看得出是不是同一个对象」，不作为身份凭据。
```

### `collect_tokens`

```python
def collect_tokens(s: str) -> dict[str, str]
```

```text
扫描文本，返回 ``{原始敏感 token: 类别}``（供诊断包写 zip 前做泄漏自检）。

识别范围与 :func:`mask_text` 一致：IPv4 / IPv6 / 域名 / MAC / 用户名 / UNC 主机名。
只收集**确定会被替换**的 token（例如 ``999.999.999.999`` 这种非法 IP 不收集），
因此不会因为日志里出现版本号而误报。

Args:
    s: 待扫描文本（日志行、JSON 字段值、文件名都可以）。空串返回空字典。

Returns:
    dict[str, str]: token → 类别；类别取值 ``ipv4`` / ``ipv6`` / ``domain`` /
    ``mac`` / ``user`` / ``host``。
```

### `mask_text`

```python
def mask_text(s: str, tokens: dict[str, str] | None=None) -> str
```

```text
把一段文本里的 IP / 域名 / 用户名 / MAC 全部替换成脱敏形态。

Args:
    s: 待脱敏文本（日志行、JSON 字段值、报告正文、文件名都可以）。
    tokens: 可选收集器；传入 ``dict`` 时把识别到的原始敏感 token 写进去
        （供 ``core/diagpack.py`` 的泄漏自检使用），不传则不做收集。

Returns:
    str: 脱敏后的文本。空串原样返回；已经脱敏过的文本再跑一遍结果不变（幂等）。
        端口、版本号、普通文件名等诊断必需信息保持原样。
```

### `mask_obj`

```python
def mask_obj(o, tokens: dict[str, str] | None=None)
```

```text
递归脱敏 ``dict`` / ``list`` / ``tuple`` / ``str``，其它类型原样返回。

用于 ``env.json`` 与 ``runs/*.json``：先 ``json.loads`` 成对象，处理完再序列化。
**不修改入参**（返回新对象），这样调用方还能拿原始对象做别的判断。

Args:
    o: 任意 JSON 兼容对象。
    tokens: 可选收集器；递归传给 :func:`mask_text`。

Returns:
    object: 与入参同构的新对象；字符串值已按 :func:`mask_text` 脱敏。
```

## `core/selfcheck.py`

**职责**：首屏「准备检查」的六项只读环境检查 + 首次运行标记（C2 + G2）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `ui_copy` | function | 100 | ✅ |
| `marker_path` | function | 113 | ✅ |
| `is_first_run` | function | 126 | ✅ |
| `ack_first_run` | function | 141 | ✅ |
| `check_python` | function | 219 | ✅ |
| `check_tshark` | function | 238 | ✅ |
| `check_npcap` | function | 277 | ✅ |
| `check_port` | function | 290 | ✅ |
| `check_admin` | function | 318 | ✅ |
| `check_scapy` | function | 346 | ✅ |
| `capabilities` | function | 373 | ✅ |
| `collect` | function | 460 | ✅ |
| `invalidate_cache` | function | 504 | ✅ |
| `collect_cached` | function | 517 | ✅ |

### `ui_copy`

```python
def ui_copy() -> dict
```

```text
返回首屏自检 / 权限卡需要的 ``startup`` 文案表。

Returns:
    dict: ``core/copy/zh-CN.json`` 的 ``startup`` section；读取失败时 ``{}``。
        界面把它挂在 ``ui_copy.startup`` 上取用，不在 HTML 里再抄一份长文案。
```

### `marker_path`

```python
def marker_path(root: Path | None=None) -> Path
```

```text
首次运行标记文件的绝对路径。

Args:
    root: 仓库根目录；``None`` 表示本文件所在 ``core/`` 的上一级。测试传临时目录，
        避免写真实 ``config/``。

Returns:
    Path: ``<root>/config/ui-first-run.json``（文件可能还不存在）。
```

### `is_first_run`

```python
def is_first_run(root: Path | None=None) -> bool
```

```text
是否首次运行（标记文件不存在即首次）。

Args:
    root: 仓库根目录；``None`` 用运行时仓库根。

Returns:
    bool: 标记存在 → ``False``；不存在或读取失败 → ``True``（宁可直接显示检查）。
```

### `ack_first_run`

```python
def ack_first_run(root: Path | None=None) -> dict
```

```text
写入首次运行标记（用户看过首屏检查后调用）。

写入失败**不是错误**：U 盘可能只读、目录可能被安全软件锁定。此时返回
``{"ok": False, "writable": False}`` 但绝不抛异常，界面照常进入主界面，
只是下次启动会再显示一次检查。

Args:
    root: 仓库根目录；``None`` 用运行时仓库根。测试传临时目录。

Returns:
    dict: 成功 ``{"ok": True, "writable": True, "path": "config/ui-first-run.json"}``；
    失败 ``{"ok": False, "writable": False, "error": "...", "path": ...}``。
```

### `check_python`

```python
def check_python() -> dict
```

```text
检查 Python 版本是否 ≥ 3.11（实时抓包与离线分析都依赖它）。

Returns:
    dict: 通过时 ``detail`` 形如 ``Python 3.11.9（64 位，便携运行时）``；
        版本过低时 ``ok=False`` 并给出升级入口（Python 官网）。
```

### `check_tshark`

```python
def check_tshark() -> dict
```

```text
检查 tshark 是否存在，并读一次版本（失败时给 Wireshark 下载页与网卡命令）。

Returns:
    dict: 找到时 ``detail`` 含版本号（如 ``已找到 tshark 4.7.4``）；
        找不到时 ``ok=False``、``fix_url`` 指向 Wireshark 下载页、
        ``fix_command`` 是列出网卡的 ``--interfaces`` 命令。
```

### `check_npcap`

```python
def check_npcap() -> dict
```

```text
检查 Npcap 抓包驱动是否就绪（离线分析不需要它，但实时抓包与通信观察必须要）。

Returns:
    dict: 未安装时 ``ok=False``，``fix_url`` 指向 Npcap 官网下载页；
        已安装时 ``detail`` 说明驱动就绪。
```

### `check_port`

```python
def check_port() -> dict
```

```text
检查 8787~8796 是否有可用端口，或已有本程序实例在跑。

两件事都复用 :mod:`app` 的既有实现：:func:`app.find_running` 探测本程序
实例（读 ``/api/ping``），:func:`app.first_free_port` 只做 bind/close。
已有实例时不需要空闲端口 —— 启动器会直接打开那个地址。

Returns:
    dict: 已有实例 ``detail`` 带地址；有空闲端口 ``detail`` 带端口号；
        两者都没有 ``ok=False``，``fix_command`` 是查看端口占用的命令。
```

### `check_admin`

```python
def check_admin() -> dict
```

```text
检查当前进程是否管理员（实时抓包 / 通信观察的前提）。

Returns:
    dict: 是管理员时 ``detail`` 说明可直接抓包；不是管理员时 ``ok=False``、
        ``fix_kind="elevate"``（界面显示「以管理员身份重启」按钮），
        但离线分析与连通与速度测试不受影响。
```

### `check_scapy`

```python
def check_scapy() -> dict
```

```text
检查 scapy 是否可导入（缺了只降级，不是「不可用」）。

scapy 是可选加速引擎：它让逐跳样本更准（批量 ``sr()``、TCP 回退）。lite 包
**不内置 scapy**，所以这一项失败时不给下载链接、不引导安装，只说明「逐跳会
降级为系统 tracert（样本少、精度低）」。

Returns:
    dict: 可导入时 ``detail`` 说明逐跳使用 scapy；不可导入时 ``ok=False``、
        ``fix_kind="none"``，``impact`` 来自 copy 的 ``impact_scapy``。
```

### `capabilities`

```python
def capabilities(checks: list[dict] | None=None) -> dict
```

```text
把六项环境检查折算成「哪些功能现在可用」的能力矩阵（界面置灰的唯一依据）。

只读探测：不会写文件、不请求 UAC、不启动抓包子进程；但 ``checks`` 为空时会在
本机现场跑六项检查并探测 scapy/tracert 引擎，因此结果依赖本机环境，不是纯函数。
``admin`` 不是能力硬门槛 —— 非管理员仍可点「以管理员身份重启」按需提权，
不能置灰封死。

Args:
    checks: 可选，六项检查结果（结构同 :func:`collect` 的 ``checks``）。测试注入
        构造的 ✅/❌ 组合；``None`` 时跑真实的 :func:`check_python` 等六项。

Returns:
    dict: 键 ``probe`` / ``offline`` / ``live`` / ``passive`` / ``reports`` /
        ``settings``（bool）、``path_probe``（逐跳是否有引擎可用：scapy **或**
        系统 tracert）、``mtr_engine``（``scapy`` / ``tracert`` / ``None``）、
        ``missing``（不可用模式的机器码原因，键为模式名，值为 ``tshark`` /
        ``npcap`` / ``tshark|npcap`` / ``tshark|scapy`` /
        ``tshark|scapy|npcap``）、``scapy``（是否有 scapy 可用）。
        **缺 scapy 不会让 path_probe 变 False**：只要系统 tracert 在，逐跳
        就可用（降级）。

Example:
    >>> capabilities([{"key": "tshark", "ok": False},
    ...               {"key": "npcap", "ok": False}])["probe"]
    True
```

### `collect`

```python
def collect(root: Path | None=None) -> dict
```

```text
跑完六项检查并组装 ``GET /api/selfcheck`` 的响应。

纯读：不写标记文件、不请求 UAC、不启动抓包子进程。``first_run`` 只读
``<root>/config/ui-first-run.json`` 是否存在。单项检查抛异常时只把该项标成
``ok=False`` 并记录原因，绝不让整个接口 500。

Args:
    root: 仓库根目录（测试注入临时目录用）；``None`` 用运行时仓库根。

Returns:
    dict: 键 ``ok``（六项是否全过）/ ``version``（``VERSION`` 文件）/
        ``first_run``（标记不存在）/ ``checks``（固定 6 项，顺序为
        :data:`CHECK_KEYS`）/ ``capabilities``（能力矩阵）/
        ``ui_copy``（``{"startup": {...}}`` 文案）。
```

### `invalidate_cache`

```python
def invalidate_cache() -> None
```

```text
清空自检结果缓存（ack 写入首次运行标记后必须调用）。

ack 会改变 ``first_run``，缓存里还是旧值；不清掉的话 TTL 内下一次
``/api/selfcheck`` 会把「首次运行」又下发一遍。

Returns:
    None: 只清内存缓存，不写文件、不抛异常。
```

### `collect_cached`

```python
def collect_cached(root: Path | None=None, force: bool=False) -> dict
```

```text
带短 TTL 的自检结果，供 ``/api/app`` 与 ``/api/selfcheck`` 共用。

首屏会先取 ``/api/app``（应用信息 + 能力矩阵），再取 ``/api/selfcheck`` 画面板；
两次都跑全套检查会重复探测 tshark 版本 / 端口 / scapy（冷启动数百 ms）。这里
按 ``CACHE_TTL_SECONDS`` 缓存，TTL 内第二次调用直接返回上次结果；``force``
或 :func:`invalidate_cache` 可强制重新探测。

Args:
    root: 仓库根目录（测试注入临时目录用）；``None`` 用运行时仓库根。
    force: ``True`` 时跳过缓存重新跑六项检查（测试 / ack 后的强制刷新）。

Returns:
    dict: 与 :func:`collect` 相同结构。返回深拷贝，调用方改字段不会污染缓存。

Example:
    >>> first = collect_cached()          # 跑一次检查并缓存
    >>> second = collect_cached()         # TTL 内复用，不再探测本机
    >>> collect_cached(force=True)        # 强制重新检查
```

## `core/server.py`

**职责**：本地 Web UI + HTTP API（仅监听 127.0.0.1，不对外暴露）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `touch` | function | 144 | ✅ |
| `request_quit` | function | 149 | ✅ |
| `cleanup_pid` | function | 197 | ✅ |
| `BodyTooLarge` | class | 207 | ✅ |
| `doctor_cached` | function | 286 | ✅ |
| `log` | function | 382 | ✅ |
| `evidence_payload` | function | 478 | ✅ |
| `conclusion_report_id` | function | 602 | ✅ |
| `build_status_conclusion` | function | 633 | ✅ |
| `start_job` | function | 980 | ✅ |
| `report_index` | function | 1041 | ✅ |
| `request_elevation` | function | 1075 | ✅ |
| `engine_info` | function | 1114 | ✅ |
| `passive_start` | function | 1157 | ✅ |
| `passive_status` | function | 1192 | ✅ |
| `link_actions` | function | 1266 | ✅ |
| `Handler` | class | 1336 | ✅ |
| `Handler.handle_one_request` | method | 1362 | ✅ |
| `Handler.log_message` | method | 1398 | ✅ |
| `Handler.do_GET` | method | 1536 | ✅ |
| `Handler.do_POST` | method | 1553 | ✅ |
| `DiagServer` | class | 1852 | ✅ |
| `DiagServer.handle_error` | method | 1863 | ✅ |
| `create_server` | function | 1891 | ✅ |
| `main` | function | 1938 | ✅ |

### `touch`

```python
def touch() -> None
```

```text
记录一次界面访问，空闲计时据此重置。
```

### `request_quit`

```python
def request_quit(reason: str='') -> None
```

```text
请求服务退出：先让 HTTP 响应发出去，再关监听。

Args:
    reason: 退出原因，会写进运行日志（便于事后回答「它怎么就没了」）。
        留空表示人工触发。

Returns:
    None: 不阻塞调用方。真正关监听在后台线程里做，延迟 0.3 秒 ——
        否则 200 响应还没写回浏览器端口就被关掉，前端只会看到「连接被重置」。
```

### `cleanup_pid`

```python
def cleanup_pid() -> None
```

```text
只删自己的 PID 文件，避免误删新实例的。
```

### `BodyTooLarge`  (class)

```python
class BodyTooLarge
```

```text
请求体超过上限；携带 status 供路由层返回 413。
```

### `doctor_cached`

```python
def doctor_cached(ttl: int=60) -> dict
```

```text
环境自检（带缓存）。

自检要跑 ``tshark -v`` / ``tshark -D``，一次 1~2 秒；首屏每次刷新都跑会让界面明显卡顿，
所以缓存 :data:`ttl` 秒。用户装完 Npcap 想立刻看到变化时，刷一次缓存过期即可。

Args:
    ttl: 缓存有效期（秒）。传 0 表示强制重跑。

Returns:
    dict: ``bootstrap.check(verbose=False)`` 的结果，键含
        ``ok`` / ``tshark`` / ``npcap`` / ``admin`` / ``python`` / ``interfaces`` 等。
```

### `log`

```python
def log(msg: str) -> None
```

```text
写一条运行日志：同时进内存环形缓冲与磁盘日志。

Args:
    msg: 日志正文。不需要自己带时间戳，这里会补 ``HH:MM:SS``。

Returns:
    None: 内存里最多保留 400 条（超出丢最早的 100 条），界面靠轮询取增量；
        磁盘那份委托给 :func:`logstore.diag_log`（``logs/diag-YYYYMMDD.log``），
        供事后排障。
```

### `evidence_payload`

```python
def evidence_payload(result: dict | None, full: bool=False, fmt: str='md') -> dict
```

```text
生成 ``/api/evidence`` 的响应体（纯计算，不写文件、不联网）。

``full=True`` 是**通用空白版**：不依赖 ``JOB["result"]``，还没有诊断结果时
也返回全 7 维（``result=None`` 等价于空结果）。``full=False`` 才要求最近一次
诊断结果，并按结论挑相关维度。

为避免 ``dimensions_for`` 在缺 ``verdict`` 时回退去 ``verdict.build``（会读
copy 表），这里先把判定算好再显式传给 ``build_checklist``；已有
``result["verdict"]`` 时直接复用，不重复计算。

Args:
    result: 最近一次诊断结果（``JOB["result"]``）；``None`` 表示还没有结果。
    full: ``True`` 输出覆盖 7 维的通用空白版；``False`` 按本次结论取相关维度。
    fmt: ``"md"``（报告内区块同款 Markdown）或 ``"txt"``（纯文本，供复制）。
        其它值由路由层拒绝；这里按 ``md`` 兜底。

Returns:
    dict: 成功 ``{"ok": True, "fmt", "full", "dimensions": [维度机器码],
    "content": str}``；``full=False`` 且没有结果 / 本次不需要取证时
    ``{"ok": False, "error": "..."}``（错误可直接展示给用户）。
```

### `conclusion_report_id`

```python
def conclusion_report_id(result: dict) -> str
```

```text
生成给人看的「报告标识」（复制给协作方 / 导出时用于追溯）。

优先用真实落盘文件名（``.md`` / ``.json``），退化为抓包文件名 + 生成时间；
都没有时返回「本次诊断（未落盘报告）」。只在状态响应/导出里出现，不写进报告。

Args:
    result: 诊断结果字典（读 ``report`` / ``meta``）。

Returns:
    str: 非空标识，如 ``faults_demo.md / faults_demo.json · 2026-11-07 21:49:03``。
```

### `build_status_conclusion`

```python
def build_status_conclusion(result: dict) -> dict
```

```text
为 ``/api/status`` 构造结论边界对象（与 CLI/报告/MCP 同一 ``build_conclusion``）。

Args:
    result: ``JOB["result"]``（正常或 0 包降级结果）。

Returns:
    dict: :func:`core.conclusion.build_conclusion` 的 7 键对象；任何字段填充
        失败都由渲染器显式降级为「未知（原因：…）」+ 低置信，不返回空块。
```

### `start_job`

```python
def start_job(payload: dict) -> dict
```

```text
启动一次诊断任务（全网体检 / 单目标诊断 / 分析抓包文件）。

Args:
    payload: 前端提交的原始 JSON，键：
        ``mode``（``live`` / ``scan`` / ``offline``，非法值回落 ``live``）、
        ``target``（目标 IP/网段/域名，最多 300 字符）、
        ``duration``（秒，夹在 3 ~ ``max_duration`` 之间）、
        ``interface``（网卡序号，可空=自动挑）、
        ``pcap``（仅离线模式；**只接受 captures/ 下的文件名**，防任意文件读取）、
        ``shadow``（可选 bool，默认 ``True``：实时抓包同时做影子探测**与路径
        剖面（MTR）**；离线忽略；MTR 只在有目标时跑）。
        旧版前端不传 ``shadow`` 时按默认开处理，行为兼容。

Returns:
    dict: 成功 ``{"ok": True}``；已在跑或参数不合法时 ``{"ok": False, "error": "..."}``。
        任务本身在后台线程执行，进度请轮询 ``/api/status``。
```

### `report_index`

```python
def report_index(limit: int=50) -> list[dict]
```

```text
列出 ``reports/`` 下的历史报告（界面「报告与导出 → 历史报告」用）。

只读目录，不生成、不修改任何报告；按修改时间倒序，最多 ``limit`` 条。

Args:
    limit: 最多返回多少条（正数；调用方负责上限）。

Returns:
    list[dict]: 每项键 ``name``（.md 文件名）/ ``size``（字节）/
        ``mtime``（``YYYY-MM-DD HH:MM``）/ ``json``（同名 .json 存在时为文件名，
        否则空串）。目录不可读时返回空列表，不抛异常。
```

### `request_elevation`

```python
def request_elevation() -> dict
```

```text
UI「以管理员身份重启」：调用启动器已有的 UAC 提权路径。

提权本身是 Windows 的安全桌面确认，做不到静默；这里只负责发起请求：

* 已是管理员 → 直接返回 ``already_admin``，不重复弹 UAC；
* 用户点「是」→ 新进程以管理员权限启动（``core/app.py --elevated`` 会等旧实例
  释放端口后再监听，避免两个实例抢同一个端口），随后旧服务退出；
* 用户点「否」/ 被组策略禁止 → 返回 ``ok: False``，旧服务继续跑，
  分析抓包文件与连通与速度测试不受影响。

返回值是结构化契约（UI 只读这几个键，不要再让路由层猜）：

Returns:
    dict: 成功 ``{"ok": True, "restarted": True, "message": ...}``；
        本来就有权限 ``{"ok": True, "restarted": False, "already_admin": True,
        "message": ...}``；失败 ``{"ok": False, "restarted": False,
        "error": "..."}`` —— 失败**不抛异常、不杀当前进程**。
```

### `engine_info`

```python
def engine_info() -> dict
```

```text
当前可用的采集引擎（第一步就告诉用户「能不能用 Scapy」）。

导入 Scapy 约 2 秒，所以结果进程内缓存一次，不在每次探测时重来。

Returns:
    dict: 键 ``engine``（``scapy`` / ``tshark``）、``scapy``（bool）、
        可选 ``error``（Scapy 不可用时的原因，如 Npcap 缺失）。
```

### `passive_start`

```python
def passive_start(payload: dict) -> dict
```

```text
启动通信观察（被动监听，只听不发）。

Args:
    payload: 键 ``interface``（网卡序号，空=自动挑）、``duration``（秒，夹在 3~300）、
        ``target``（只保留与该目标相关的会话，空=全部流量）、
        ``engine``（``auto`` / ``scapy`` / ``tshark``，非法值回落 ``auto``）。

Returns:
    dict: 成功 ``{"ok": True, "engine": "<实际使用的引擎>"}``；
        已有监听在跑时 ``{"ok": False, "error": "..."}``。
```

### `passive_status`

```python
def passive_status() -> dict
```

```text
通信观察的当前状态与结果（界面每秒轮询它）。

Returns:
    dict: 键 ``ok`` / ``state``（``idle``/``running``/``done``/``error``）/
        ``result``（完成后是 ``passive.run()`` 的结果，运行中为 ``None``）/
        ``error`` / ``engine`` / ``engine_info`` / ``elapsed``（已运行秒数）。
```

### `link_actions`

```python
def link_actions(result: dict | None, gateway: str='') -> list[dict]
```

```text
生成结果页「接下来怎么做」里的一键复测按钮参数（只描述，不执行）。

这是**加法字段**：只进 ``/api/status`` 的响应，不写进报告 JSON / Markdown，
因此不会改变 ``reports/`` 快照。前端拿到后负责弹确认框、切模式、预填表单。

Args:
    result: ``JOB["result"]``（正常结果或 0 包降级结果）；空 / 非 dict 时返回 ``[]``。
    gateway: 默认网关（调用方查好传入，便于单测不碰系统 API）；空串时若降级
        结果里的 ``link.via == "gateway"`` 会用 ``link.host`` 兜底。

Returns:
    list[dict]: 每项键 ``kind``（``live`` / ``probe``）/ ``mode``（前端模式名）/
        ``label``（按钮文案）/ ``target`` / ``port``（live 为端口，probe 为 ``None``）/
        ``display``（确认框里的 ``IP:端口``）/ ``confirm``（确认文案）。
        ``live`` 只在结果里有合法 Stream 对端时出现，``probe`` 只在知道网关时出现；
        两者都没有时返回 ``[]``（结果页不显示空的按钮区）。
```

### `Handler`  (class)

```python
class Handler
```

```text
本地 Web UI 与 API 的请求处理器。

安全边界（都在这层落实，下游模块不需要重复做）：
    * **Host 校验**：只接受 ``127.0.0.1`` / ``localhost``，挡住 DNS 重绑定；
    * **Origin 校验**：写操作要求同源，挡住跨站请求伪造；
    * **统一响应头**：CSP / ``X-Frame-Options`` / ``nosniff`` 见 :data:`SECURITY_HEADERS`；
    * **异常兜底**：任何未捕获异常都转成 500 JSON，不把栈信息漏给浏览器。
```

### `Handler.handle_one_request`  (method)

```python
def handle_one_request(self) -> None
```

```text
包住基类：客户端提前断开只记一行 debug，绝不打印 traceback。

浏览器关标签页 / 取消请求时，服务端可能正在读请求行、读 body 或写响应，
对应 ``ConnectionResetError``（WinError 10054）/ ``ConnectionAbortedError`` /
``BrokenPipeError``。这些是正常的客户端行为，不是服务故障；不拦就会由
``socketserver`` 打印整段 traceback（G4 真机噪音）。
```

### `Handler.log_message`  (method)

```python
def log_message(self, fmt, *args)
```

```text
屏蔽默认访问日志（每个请求打一行会把控制台刷爆）。

Args:
    fmt: ``BaseHTTPRequestHandler`` 传来的格式化模板，这里不用。
    *args: 模板参数，同样不用。

Returns:
    None: 有意为空实现。需要看请求时请用 ``log()`` 写业务日志。
```

### `Handler.do_GET`  (method)

```python
def do_GET(self)
```

```text
处理 GET：静态页 + 只读 API。

Returns:
    None: 响应直接写入 socket。失败路径固定三种 ——
        403（来源不合法）、404（路径不存在）、500（内部错误，栈只进日志）。
```

### `Handler.do_POST`  (method)

```python
def do_POST(self)
```

```text
处理 POST：启动任务、上传、配置、退出等有副作用的操作。

Returns:
    None: 响应直接写入 socket。请求体超过 :data:`MAX_JSON_BODY` 时返回 413，
        并且会把剩余字节读完再关 —— 否则客户端只会看到「连接被重置」。
```

### `DiagServer`  (class)

```python
class DiagServer
```

```text
daemon_threads：关闭时不被长连接拖住。

allow_reuse_address 必须为 False：Windows 上 SO_REUSEADDR 语义与 Unix 不同，
置 True 会让两个进程同时绑上 8787，旧进程继续响应，改了代码却看不到效果。
端口被占时由 create_server() 顺延到下一个端口。
```

### `DiagServer.handle_error`  (method)

```python
def handle_error(self, request, client_address) -> None
```

```text
兜底：连接类异常只写一行 debug；其他异常保留「类型 + 原因」一行可诊断信息。

``Handler.handle_one_request`` 已经拦住绝大多数连接重置；这里覆盖
``socketserver`` 的默认实现，避免漏网的 ``BrokenPipeError`` 又打印整段
traceback。**不吞所有异常**：非连接异常仍写一行 error（类型 + 原因），
只是不再把栈直接刷到 stderr。

Args:
    request: 触发异常的套接字（``socketserver`` 传入，这里不使用）。
    client_address: 客户端地址（这里不使用；日志不含敏感信息）。

Returns:
    None: 只写日志，不向客户端发送任何内容（连接可能已断开）。
```

### `create_server`

```python
def create_server(port: int=8787, idle_exit_min: int=0, quiet: bool=False, register_pid: bool=True) -> tuple[DiagServer | None, str]
```

```text
建监听。端口被占用时顺延最多 10 个。

Args:
    port: 起始端口（默认 8787）。
    idle_exit_min: 无人访问多少分钟后自动退出；0 表示常驻不退出。
    quiet: True 时不打印启动横幅（静默启动用）。
    register_pid: 是否写 ``logs/netdiag.pid``。自测传 False，
        避免测试实例覆盖正在运行的应用的 PID 文件。

Returns:
    tuple[DiagServer | None, str]: ``(实例, 访问地址)``；10 个端口都被占用时返回 ``(None, "")``。

Note:
    ``allow_reuse_address`` 必须是 **False**。Windows 上它等价于 ``SO_REUSEADDR``，
    会让两个进程同时绑同一端口，旧进程继续响应新请求 —— 这正是曾经
    「改了代码却没生效」的根因。
```

### `main`

```python
def main() -> int
```

```text
命令行入口：读配置 → 建监听 → 开浏览器 → 阻塞服务。

Returns:
    int: 进程退出码。0 正常退出；1 端口全被占用。
```

## `core/tshark.py`

**职责**：tshark / dumpcap 定位与执行封装（纯标准库，适配便携 Python）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `short_name` | function | 44 | ✅ |
| `find_tshark` | function | 57 | ✅ |
| `find_dumpcap` | function | 67 | ✅ |
| `find_npcap_installer` | function | 76 | ✅ |
| `run` | function | 103 | ✅ |
| `iter_lines` | function | 135 | ✅ |
| `version` | function | 210 | ✅ |
| `list_interfaces` | function | 231 | ✅ |
| `order_interfaces` | function | 299 | ✅ |
| `pick_interface` | function | 318 | ✅ |
| `probe_interface` | function | 347 | ✅ |
| `is_admin` | function | 372 | ✅ |
| `npcap_installed` | function | 389 | ✅ |

### `short_name`

```python
def short_name(name: str) -> str
```

```text
把 ``tshark -D`` 的长设备名精简成括号里的网卡别名。

Args:
    name: 形如 ``1. \Device\NPF_{GUID} (以太网)`` 的原始串。

Returns:
    str: 括号内的可读名（``以太网``）；不含括号时原样返回。
```

### `find_tshark`

```python
def find_tshark() -> Path | None
```

```text
定位 ``tshark.exe``。

Returns:
    Path | None: 按「环境变量 ``TSHARK_PATH`` → 便携目录 → 系统安装目录 → PATH」
        的顺序找；都没找到返回 ``None``（调用方据此报 ``E_NO_TSHARK``）。
```

### `find_dumpcap`

```python
def find_dumpcap() -> Path | None
```

```text
定位 ``dumpcap.exe``（长时间抓包用它比 tshark 更省资源）。

Returns:
    Path | None: 找不到时返回 ``None``。
```

### `find_npcap_installer`

```python
def find_npcap_installer() -> Path | None
```

```text
在 ``tools/`` 下找 Npcap 离线安装包。

Returns:
    Path | None: 匹配 ``npcap-*.exe`` 的第一个；没有则 ``None``
        （此时前端提示用户自己去装）。
```

### `run`

```python
def run(args: list[str], timeout: int=180) -> tuple[int, str, str]
```

```text
跑一个子进程并收集输出。**不抛异常**，一切失败都折成返回码。

Args:
    args: 完整命令行（argv 列表，不经 shell，因此目标串里的特殊字符不会被解释）。
    timeout: 超时秒数，超时后子进程被杀。

Returns:
    tuple[int, str, str]: ``(returncode, stdout, stderr)``。约定返回码：
        正常为子进程自身退出码；``-9`` 超时；``-2`` 找不到可执行文件；``-3`` 其它 OS 错误。
        因此调用方判断失败**不要**只看 ``rc != 0``，要区分这几个负数。
```

### `iter_lines`

```python
def iter_lines(args: list[str], timeout: int=900, sink: dict | None=None)
```

```text
流式读取子进程 stdout，逐行 yield。

大 pcap 的 ``-T fields`` 输出可能有几十万行，整份读进内存会撑爆便携环境，
所以边读边吐。

Args:
    args: 完整命令行（argv 列表）。
    timeout: 超时秒数；到点直接 kill 子进程（其余行不再产出）。
    sink: 可选字典，函数结束前会写入 ``{"rc": 退出码, "stderr": 错误输出}``。
        调用方**必须**检查它 —— tshark 对不完整文件返回 14、
        被杀返回负数，只凭「有没有收到行」无法区分「读完了」和「读到一半」。

Yields:
    str: 一行输出（已去掉行尾换行符）。

Note:
    这是生成器：不把 ``sink`` 传进去就永远拿不到退出码，
    会把「解析中断」误当成「解析完成」（T00 的根因）。
```

### `version`

```python
def version(tshark: Path | None=None) -> str
```

```text
取 tshark 版本串。

Args:
    tshark: 可执行文件路径；省略时自动查找。

Returns:
    str: 版本首行，如 ``"TShark (Wireshark) 4.7.4 ..."``；
        找不到时返回 ``"未找到 tshark"``，取不到版本时返回 ``"tshark 版本未知 (rc=N)"``。
```

### `list_interfaces`

```python
def list_interfaces(tshark: Path | None=None) -> list[dict]
```

```text
列出可用于抓包的网卡（解析 ``tshark -D``）。

Args:
    tshark: 可执行文件路径；省略时自动查找。

Returns:
    list[dict]: 每项 ``{"index": int, "name": str, "raw": str}``。
        ``name`` 保留原串（含括号别名），展示前请过 ``short_name()``；
        找不到 tshark 或没有网卡时返回空列表。
```

### `order_interfaces`

```python
def order_interfaces(interfaces: list[dict]) -> list[dict]
```

```text
按候选优先级排序（物理优先、虚拟靠后），**不删除**任何网卡。

用户机器上常同时有 WLAN、断开的以太网、Clash/Meta TUN、VMware、蓝牙、
Wi-Fi Direct 等一堆网卡；名字看不出哪块通外网，但「物理网卡优先」能先把
最可能通外网的那块排前面，再交给 :func:`probe_interface` 用真实流量验证。

Args:
    interfaces: ``list_interfaces()`` 的返回值。

Returns:
    list[dict]: 新列表，顺序为「以太网/WLAN 等物理网卡 → 其它未命中
        :data:`SKIP_HINTS` 的网卡 → Meta/TUN 等 VPN 虚拟网卡 → VMware/蓝牙/
        回环/extcap 伪接口」。同类内按 :data:`PREFER_HINTS` 与 ``index``
        稳定排序；输入为空返回 ``[]``。
```

### `pick_interface`

```python
def pick_interface(interfaces: list[dict]) -> dict | None
```

```text
挑一块「像样」的默认网卡（按名字猜，不验证是否有流量）。

按业务优先级：先按 :data:`PREFER_HINTS` 找物理网卡（以太网/Wi-Fi），
再用 :data:`SKIP_HINTS` 把回环、蓝牙、虚拟网卡（VMware/Meta/Hyper-V 等）
降到后面。**只排序不删除**：虚拟网卡全被跳过时会退回完整列表，
避免「唯一可用的就是 VPN 网卡」时返回 ``None``。

注意：本函数只看名字，断开的以太网也会被选中；要真正选到有流量的网卡，
调用方应先用 :func:`probe_interface` 按 :func:`order_interfaces` 的顺序探测。

Args:
    interfaces: ``list_interfaces()`` 的返回值。

Returns:
    dict | None: 选中的那一项；输入为空时返回 ``None``。
```

### `probe_interface`

```python
def probe_interface(tshark_path: Path, candidates: list[dict], seconds: int=2) -> dict | None
```

```text
逐个网卡试抓几秒，返回第一个真有流量的。

用户机器上常有一堆虚拟网卡（VPN、Docker、VMware），名字看不出哪个通外网；
用「抓两秒看有没有包」比猜名字可靠。

Args:
    tshark_path: tshark 可执行文件路径。
    candidates: 候选网卡列表（最多试前 5 个，避免启动时等太久）。
    seconds: 每个网卡试抓的秒数。

Returns:
    dict | None: 第一个抓到包的网卡项；都没流量返回 ``None``。
```

### `is_admin`

```python
def is_admin() -> bool
```

```text
当前进程是否管理员。

Returns:
    bool: Windows 上问 ``IsUserAnAdmin()``；非 Windows 看 ``geteuid()==0``。
        查不到时返回 ``False``（保守：宁可提示「可能抓不了包」）。
```

### `npcap_installed`

```python
def npcap_installed() -> bool
```

```text
检测 Npcap 是否就绪（优先看文件，最后才问服务状态）。

只查文件系统是毫秒级；``sc query`` 在受限环境里可能卡住，因此放最后、
超时压到 5 秒，且不再把它的输出当唯一判据（服务名可能是 ``npcap`` 或 ``npf``，
输出还是本地化的）。

Returns:
    bool: 命中安装目录 / ``wpcap.dll`` / ``drivers/npcap.sys`` / ``Packet.dll``
        任一即 True；非 Windows 恒 True。
```

## `core/verdict.py`

**职责**：把结构化分析结果翻译成「故障定位结论」。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `compute_layers` | function | 198 | ✅ |
| `build` | function | 631 | ✅ |

### `compute_layers`

```python
def compute_layers(rows: list[dict], meta: dict, metrics: dict, sufficient: bool=True) -> list[dict]
```

```text
为每一层算一个状态块（UI 用横条展示「哪一层红了」）。

Args:
    rows: 旧 ``rows[]``；安全观察行**不参与**主判定。
    meta: 采集元信息；``L4`` 在没有 TCP 报文时标为 ``na``（没样本，别报正常）。
    metrics: 指标表，供状态块填明细。
    sufficient: 证据是否充分（即 ``verdict.sufficiency.ok``）。为 ``False`` 时，
        **没有真实样本行的层**一律置为 ``na``：否则会出现「结论是证据不足、
        分层表却显示 ✅ 正常」的自相矛盾。有样本行（含 ``"—"``=测了正常）的层
        仍按样本判定，保持 ``ok``。例外是 L3 的兜底中性行：它没有 ICMP/RTT
        样本时也会写「三层转发正常」，这种行不算样本。

Returns:
    list[dict]: 每项 ``{"id", "name", "protocol", "status"（ok/warn/bad/na）,
        "severity", "detail", "count"}``。
```

### `build`

```python
def build(result: dict) -> dict
```

```text
生成最终判定：一句话结论 + 分层状态 + 处置建议。

Args:
    result: 诊断结果字典（``meta`` / ``rows`` / ``metrics`` / ``summary``）。

Returns:
    dict: 键 ``level``（严重/警告/提示/正常/证据不足）/ ``headline``（一句话结论）/
        ``plain``（白话解释）/ ``impact``（对业务意味着什么）/ ``layer``（问题所在层）/
        ``layers``（四层状态）/ ``points``（问题明细）/
        ``next_steps``（按优先级排序的处置建议）/ ``metrics`` / ``flags`` /
        ``sufficiency``（:meth:`contracts.Sufficiency.to_dict` 的结果）。

Note:
    两道闸门拦「没抓到 = 没问题」：

    1. 抓空包（``packets == 0``）先返回「无法定位」而不是「各层正常」。
    2. 抓到了包但**没有任何可判定维度**时，``level`` 是「证据不足」而不是「正常」。
       见 :func:`_sufficiency`：判的是「每个维度有没有能支撑规则的样本」，
       不是全局的报文总数。

    本函数只做路由与拼装：用户可见文案全部来自 ``core/copy/zh-CN.json``，
    字典里的 ``level`` / ``layer`` / ``category`` 等是机器侧的结构化标识。
```

## `core/version.py`

**职责**：产品版本号的唯一读取点：仓库根 ``VERSION``（UTF-8，容忍 BOM 与首尾空白）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `read_version` | function | 16 | ✅ |

### `read_version`

```python
def read_version(root: Path | None=None) -> str
```

```text
读取 ``root/VERSION`` 里的产品版本号。

Args:
    root: 仓库根目录（``VERSION`` 所在目录）；``None`` 表示本文件所在
        ``core/`` 的上一级。测试可传临时目录。

Returns:
    str: 形如 ``0.2.0`` 的版本号。文件缺失或不可读（``OSError``）、
    内容为空或只有 UTF-8 BOM 时回退 ``0.0.0``；非 UTF-8 内容触发的
    ``UnicodeDecodeError`` 不在此兜底范围内，会照常抛出。
```

## `mcp/wireshark-mcp/server.py`

**职责**：wireshark-mcp：基于 tshark 的 MCP 服务器（stdio 传输，零第三方依赖）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `validate_payload` | function | 255 | ✅ |
| `build_diagnostic_payload` | function | 274 | ✅ |
| `call_tool` | function | 325 | ✅ |
| `handle` | function | 398 | ✅ |
| `main` | function | 439 | ✅ |

### `validate_payload`

```python
def validate_payload(payload, schema: dict=DIAG_OUTPUT_SCHEMA) -> list[str]
```

```text
用本地最小 JSON Schema 校验器校验输出（不引依赖、不抛异常）。

覆盖本文件实际用到的关键字：``type`` / ``required`` / ``properties`` /
``items`` / ``minItems`` / ``minLength`` / ``enum`` / ``minimum`` / ``maximum`` /
``additionalProperties`` / ``$ref`` / ``$defs``。**缺 required 字段一定会被报出来**。

Args:
    payload: 待校验的 Python 对象（通常是诊断返回的 dict）。
    schema: 根 Schema；默认 :data:`DIAG_OUTPUT_SCHEMA`。

Returns:
    list[str]: 错误列表；空列表表示通过。每条错误都是可操作的中文路径说明。
```

### `build_diagnostic_payload`

```python
def build_diagnostic_payload(result: dict) -> dict
```

```text
把一次诊断结果转成 MCP 结构化返回（结论对象与 CLI/报告/MCP 同源）。

Args:
    result: ``diagnose.run_scan`` 的成功结果（含 ``summary`` / ``meta`` /
        ``rows`` / 可选 ``verdict``）。

Returns:
    dict: 键 ``ok``（True）/ ``conclusion``（:func:`core.conclusion.build_conclusion`
    的 7 键对象，``basis`` / ``coverage`` / ``not_covered`` 必填）/ ``markdown``
    （同一报告的 Markdown 正文）/ ``summary``（摘要，便于 Agent 少读大段正文）。
    结论只在这里构造一次，三个诊断工具共用。
```

### `call_tool`

```python
def call_tool(name: str, args: dict) -> dict
```

```text
执行一个 MCP 工具调用。

Args:
    name: 工具名，见本文件 ``TOOLS`` 定义
        （``list_interfaces`` / ``doctor`` / ``capture_live_packets`` /
        ``analyze_pcap`` / ``probe_target`` / ``capture_passive`` 等）。
    args: 工具参数；数值类参数统一过 ``_num()`` 夹紧，
        防止模型给个 ``99999`` 把一次调用拖成几分钟。

Returns:
    dict: MCP 结果对象 ``{"content": [{"type": "text", "text": ...}], "isError": bool}``。
        未知工具或参数错误时返回 ``isError=True`` 的文本，不抛异常 ——
        抛异常会让整轮工具调用失败，模型拿不到任何可读信息。
```

### `handle`

```python
def handle(msg: dict) -> dict | None
```

```text
分发一条 JSON-RPC 消息。

Args:
    msg: 已解析的请求对象，需含 ``method``；``id`` 存在时表示要回包。

Returns:
    dict | None: 要回给客户端的 JSON-RPC 响应；
        对通知类消息（``notifications/initialized`` 等）返回 ``None``，表示不回包。
```

### `main`

```python
def main() -> int
```

```text
stdio 主循环：按行读 JSON-RPC → 分发 → 按行写回。

为什么是一行一条：MCP 的 stdio 传输用换行分隔消息，不能用「读满缓冲区」的方式。

Returns:
    int: 进程退出码。0 = stdin 关闭（客户端主动断开），属正常结束。
```

