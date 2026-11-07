# 接口参考（自动生成）

> 本文件由 `scripts/gen_api_doc.py` 从 AST 生成，**签名永远与代码一致**。
> 不要手改签名；要改内容就改源码里的 docstring，然后重跑：
>
> ```bat
> tools\python\python.exe scripts\gen_api_doc.py
> ```

- 扫描模块：**26** 个（有模块说明 26 个）
- 公开符号：**198** 个（有 docstring 198 个，合格 198 个）
- 合格率：**100.0%**（目标 ≥ 95%，见 `docs/api-style.md`）

阅读顺序建议：先看 `docs/overview.md`（一页看懂项目）→ 本文件的「按模块」→ 具体源码。

---

## `core/__init__.py`

**职责**：USB-Net-Diag 核心包（目标架构骨架）。

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
| `collect` | function | 407 | ✅ |
| `build_findings` | function | 902 | ✅ |
| `analyze` | function | 1394 | ✅ |

### `collect`

```python
def collect(pcap: Path, log=None) -> tuple[dict, str]
```

```text
流式解析 pcap，边读边聚合。

一次 tshark 调用取全所需字段，避免对同一文件扫多遍；输出按行消费，
几十万行的 pcap 也不会把内存吃满。

Args:
    pcap: 抓包文件路径。
    log: 可选日志回调 ``log(str)``，用于输出进度与 tshark 告警首行。

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
def analyze(pcap: Path | str, target: str='', ti_key: str='', log=None) -> dict
```

```text
离线分析一个 pcap，产出完整结果字典。

Args:
    pcap: 抓包文件路径（``Path`` 或字符串）。
    target: 本次诊断目标的展示用名字（IP/域名），可空。
    ti_key: 威胁情报 API Key；为空则跳过可疑外联核对。
    log: 可选日志回调 ``log(str)``。

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
| `redirect_output` | function | 35 | ✅ |
| `msgbox` | function | 53 | ✅ |
| `is_admin` | function | 70 | ✅ |
| `relaunch_as_admin` | function | 82 | ✅ |
| `find_running` | function | 100 | ✅ |
| `main` | function | 127 | ✅ |

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
def msgbox(text: str, title: str='网络诊断工具', flags: int=MB_ICONINFO) -> None
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
        以普通权限继续跑，实时抓包不可用但离线分析照常。
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

### `main`

```python
def main() -> int
```

```text
静默启动主流程。

顺序：日志基建 → 重定向输出 → 探测已有实例 → 需要时提权 → 建监听 → 开浏览器 → 阻塞。

Returns:
    int: 进程退出码。0 = 正常（含「已有实例，直接把浏览器叫起来」和
        「已拉起提权进程」两种提前返回）；1 = 端口全被占用。
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
| `Layer` | class | 38 | ✅ |
| `Layer.label_key` | method | 48 | ✅ |
| `Severity` | class | 61 | ✅ |
| `Direction` | class | 83 | ✅ |
| `EndpointKind` | class | 95 | ✅ |
| `EvidenceKind` | class | 105 | ✅ |
| `Category` | class | 112 | ✅ |
| `JobState` | class | 129 | ✅ |
| `to_jsonable` | function | 145 | ✅ |
| `Endpoint` | class | 174 | ✅ |
| `Endpoint.to_dict` | method | 194 | ✅ |
| `Stats` | class | 204 | ✅ |
| `Stats.from_values` | method | 214 | ✅ |
| `Stats.has_sample` | method | 237 | ✅ |
| `Stats.to_dict` | method | 245 | ✅ |
| `DirStat` | class | 255 | ✅ |
| `DirStat.to_dict` | method | 289 | ✅ |
| `CaptureMeta` | class | 304 | ✅ |
| `CaptureMeta.to_dict` | method | 325 | ✅ |
| `StreamStat` | class | 335 | ✅ |
| `StreamStat.dir_of` | method | 358 | ✅ |
| `StreamStat.to_dict` | method | 370 | ✅ |
| `TcpFeatures` | class | 380 | ✅ |
| `TcpFeatures.total` | method | 402 | ✅ |
| `TcpFeatures.has_streams` | method | 419 | ✅ |
| `TcpFeatures.to_dict` | method | 427 | ✅ |
| `Features` | class | 438 | ✅ |
| `Features.has` | method | 456 | ✅ |
| `Features.to_dict` | method | 467 | ✅ |
| `Finding` | class | 480 | ✅ |
| `Finding.validate` | method | 511 | ✅ |
| `Finding.rank` | method | 532 | ✅ |
| `Finding.to_dict` | method | 540 | ✅ |
| `Sufficiency` | class | 554 | ✅ |
| `Sufficiency.to_dict` | method | 563 | ✅ |
| `LayerStatus` | class | 574 | ✅ |
| `LayerStatus.to_dict` | method | 593 | ✅ |
| `Verdict` | class | 603 | ✅ |
| `Verdict.to_dict` | method | 627 | ✅ |
| `Provenance` | class | 638 | ✅ |
| `Provenance.to_dict` | method | 649 | ✅ |
| `AnalyzeResult` | class | 664 | ✅ |
| `AnalyzeResult.by_layer` | method | 683 | ✅ |
| `AnalyzeResult.worst` | method | 695 | ✅ |
| `AnalyzeResult.to_dict` | method | 705 | ✅ |
| `ProbeResult` | class | 715 | ✅ |
| `ProbeResult.to_dict` | method | 728 | ✅ |
| `PassiveResult` | class | 739 | ✅ |
| `PassiveResult.to_dict` | method | 749 | ✅ |
| `Job` | class | 762 | ✅ |
| `Job.running` | method | 790 | ✅ |
| `Job.public` | method | 798 | ✅ |
| `Job.to_dict` | method | 820 | ✅ |
| `envelope_ok` | function | 832 | ✅ |
| `envelope_err` | function | 846 | ✅ |

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
    mode: ``live``（实时抓）或 ``offline``（离线分析）。
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
最终判定 —— 一句话结论 + 四层状态 + 下一步做什么。

字段：
    level: 总体严重度。
    headline_key / headline_args: 结论文案的 key 与占位符实参（**不含中文**）。
    impact_key: 「对用户意味着什么」的文案 key。
    next_step_keys: 处置建议的 key 列表，按优先级排列。
    sufficiency: 证据是否够；``ok=False`` 时 ``level`` 必须是降级后的结论
        （见 ``VERDICT.INSUFFICIENT``），不能拿「没样本」当「正常」。
```

### `Verdict.to_dict`  (method)

```python
def to_dict(self) -> dict
```

```text
转字典。

Returns:
    dict: ``layers`` 是 ``LayerStatus.to_dict()`` 的列表，
        ``sufficiency`` 是 ``Sufficiency.to_dict()``。
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
``passive``（被动监听）的结果。
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
一个后台任务。抓包、离线分析、被动监听都走它。

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

**职责**：USB-Net-Diag 采集与诊断主流程（CLI 入口）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `load_config` | function | 43 | ✅ |
| `log` | function | 75 | ✅ |
| `bpf_for` | function | 88 | ✅ |
| `capture_live` | function | 116 | ✅ |
| `run_scan` | function | 234 | ✅ |
| `main` | function | 390 | ✅ |

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

### `bpf_for`

```python
def bpf_for(target: str) -> str
```

```text
把目标转成 BPF 过滤器表达式。

只接受 IP / CIDR / 域名，其它字符一律拒绝 —— 过滤器最终会进 tshark 命令行，
放任任意表达式等于把抓包器变成可编程工具。

Args:
    target: 用户输入的目标，如 ``192.168.1.10`` / ``10.0.0.0/24`` / ``example.com``。

Returns:
    str: 可用的 BPF 串；空目标返回空串（表示抓全网）。

Raises:
    ValueError: 目标含非法字符，或长度超过 200 个字符（由调用方转成可展示的错误）。
```

### `capture_live`

```python
def capture_live(target: str='', duration: int=30, interface: str | None=None, logger=log) -> dict
```

```text
实时抓包并落盘到 ``captures/``。

Args:
    target: 抓包目标（转成 BPF）；空表示全网。
    duration: 抓包秒数。
    interface: 网卡序号或名称关键字；空则自动挑选（见 ``tshark.pick_interface``）。
    logger: 日志回调。

Returns:
    dict: 成功 ``{"ok": True, "pcap": str, "interface": str, "interface_index": int,
        "bpf": str, "duration": int}``；失败 ``{"ok": False, "error": str,
        "degraded": bool}``，``degraded=True`` 表示「缺 tshark/Npcap/提权」这类
        环境问题，前端据此提示改用离线分析。

Note:
    返回前会等文件大小稳定（最多 3 秒）。tshark 进程退出 ≠ 数据已落盘，
    在写盘窗口期就开始分析会读到半份数据，进而产生幻影告警（T00）。
```

### `run_scan`

```python
def run_scan(target: str='', duration: int=30, interface: str | None=None, pcap: str | None=None, logger=log, report_dir: str | Path | None=None) -> dict
```

```text
完整诊断：抓包（或复用已有 pcap）→ 分析 → 落盘报告 → 记一条 run。

Args:
    target: 目标 IP/网段/域名；空表示全网。
    duration: 实时抓包秒数（仅无 ``pcap`` 时生效）。
    interface: 网卡序号或名称关键字。
    pcap: 离线分析的抓包路径。只给文件名时会到 ``captures/`` 下找
        （兼容 U 盘盘符变化）。
    logger: 日志回调。
    report_dir: 报告输出目录；``None``（默认）写 ``reports/``，与历史行为一致。
        给定时只写该目录（目录不存在会自动创建），文件名清洗仍由
        :func:`report.save` 负责。

Returns:
    dict: ``analyzer.analyze()`` 的结果，另加 ``report``（``.md``/``.json`` 落盘路径）
        与 ``capture``（本次采集参数）。失败时 ``{"ok": False, "error": "..."}``。

Note:
    无论成功、失败还是抛异常，都会调用一次 :func:`logstore.record_run`
    （``mode`` 为 ``offline`` / ``live``）。UI 的 ``/api/scan`` 也走本函数，
    所以两个入口共用同一个记录点，一次分析只有一条记录。
```

### `main`

```python
def main(argv: list[str] | None=None) -> int
```

```text
``diagnose.py`` 的命令行入口（不开界面也能出报告）。

Args:
    argv: 参数列表；省略时取 ``sys.argv[1:]``。支持 ``--target`` / ``--duration`` /
        ``--interface`` / ``--pcap`` / ``--interfaces``（只列网卡）/ ``--json``（只打摘要）/
        ``--report-out``（把完整报告**只**写指定目录、**不再写** ``reports/``；
        省略时仍写 ``reports/``）。

Returns:
    int: 0 成功；2 分析失败（如抓包文件不完整）；其它非 0 表示环境问题。
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
| `log_root` | function | 64 | ✅ |
| `ensure_dirs` | function | 87 | ✅ |
| `_DailySink.close` | method | 184 | ✅ |
| `_DailySink.write` | method | 205 | ✅ |
| `_Stream.write` | method | 243 | ✅ |
| `_Stream.writelines` | method | 257 | ✅ |
| `_Stream.flush` | method | 269 | ✅ |
| `_Stream.isatty` | method | 273 | ✅ |
| `_Stream.writable` | method | 281 | ✅ |
| `_Stream.readable` | method | 289 | ✅ |
| `_Stream.fileno` | method | 297 | ✅ |
| `_Stream.closed` | method | 309 | ✅ |
| `_Stream.close` | method | 317 | ✅ |
| `app_log` | function | 346 | ✅ |
| `diag_log` | function | 358 | ✅ |
| `open_stream` | function | 370 | ✅ |
| `close_streams` | function | 380 | ✅ |
| `write_env_snapshot` | function | 454 | ✅ |
| `record_run` | function | 481 | ✅ |
| `record_crash` | function | 527 | ✅ |
| `install_excepthooks` | function | 610 | ✅ |
| `prune` | function | 709 | ✅ |

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
| `build_flows` | function | 398 | ✅ |
| `run` | function | 528 | ✅ |

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

Args:
    interface: 网卡序号或名称关键字；空则自动挑选。
    duration: 监听秒数，夹在 3~300。
    target: 只保留与该目标相关的会话（IP/CIDR/域名）；空表示全部流量。
    max_packets: 包数上限，夹在 200~200000，防止长时间监听把内存吃满。
    engine: ``auto`` / ``scapy`` / ``tshark``；``auto`` 优先 Scapy，不可用时回落 tshark。
    logger: 日志回调。
    should_stop: 可选无参回调，返回 True 时提前结束（界面「停止」按钮用）。

Returns:
    dict: 成功 ``{"ok": True, "interface", "duration", "engine", "bpf",
        "flows": [...], "summary": {...}}``；失败 ``{"ok": False, "error": "..."}``
        （如没有可用网卡、目标过滤器非法）。
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
抓包落盘目录，也是离线分析唯一允许读取的位置。

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
| `is_admin` | function | 28 | ✅ |
| `npcap_installed` | function | 43 | ✅ |
| `Adapter` | class | 79 | ✅ |
| `adapters` | function | 120 | ✅ |
| `default_gateway` | function | 162 | ✅ |
| `dns_servers` | function | 175 | ✅ |
| `interface_index_map` | function | 190 | ✅ |

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
def default_gateway() -> str
```

```text
默认网关地址（路径探测的第 1 跳）。

Returns:
    str: 网关 IP。

Raises:
    NotImplementedError: 本阶段未实现。落地方案见 docstring 正文
        （``GetBestRoute2`` 或内置 Scapy 的 ``conf.route.default_gateway()``）。
```

### `dns_servers`

```python
def dns_servers() -> tuple[str, ...]
```

```text
当前生效的 DNS 服务器列表。

注意 DNS 可能来自 DHCP / 组策略 / 每网卡独立配置，开了 DoH 之后
注册表里的地址与真正发查询的地址还可能不一致 —— 报告里必须标注这一不确定性。

Returns:
    tuple[str, ...]: DNS 服务器地址。

Raises:
    NotImplementedError: 本阶段未实现（随 ``adapters()`` 一起落地）。
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

**职责**：链路体检：不抓包，直接分段测量一次真实访问，定位慢在哪一段。

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
| `render_markdown` | function | 71 | ✅ |
| `save` | function | 317 | ✅ |

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
    文件名取自抓包文件名，并过滤掉路径分隔符等危险字符。

    落盘前把 ``meta.tshark_path`` 替换成固定占位：绝对路径是机器相关键，
    换机器重跑会让 ``git diff reports/`` 一直脏（``analyze()`` 的原值不动，
    只在落盘时替换）。
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

## `core/server.py`

**职责**：本地 Web UI + HTTP API（仅监听 127.0.0.1，不对外暴露）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `touch` | function | 93 | ✅ |
| `request_quit` | function | 98 | ✅ |
| `cleanup_pid` | function | 146 | ✅ |
| `BodyTooLarge` | class | 156 | ✅ |
| `doctor_cached` | function | 183 | ✅ |
| `log` | function | 237 | ✅ |
| `start_job` | function | 311 | ✅ |
| `engine_info` | function | 358 | ✅ |
| `passive_start` | function | 401 | ✅ |
| `passive_status` | function | 435 | ✅ |
| `Handler` | class | 453 | ✅ |
| `Handler.log_message` | method | 499 | ✅ |
| `Handler.do_GET` | method | 637 | ✅ |
| `Handler.do_POST` | method | 654 | ✅ |
| `DiagServer` | class | 831 | ✅ |
| `create_server` | function | 843 | ✅ |
| `main` | function | 890 | ✅ |

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

### `start_job`

```python
def start_job(payload: dict) -> dict
```

```text
启动一次诊断任务（实时抓包 / 全网扫描 / 离线分析）。

Args:
    payload: 前端提交的原始 JSON，键：
        ``mode``（``live`` / ``scan`` / ``offline``，非法值回落 ``live``）、
        ``target``（目标 IP/网段/域名，最多 300 字符）、
        ``duration``（秒，夹在 3 ~ ``max_duration`` 之间）、
        ``interface``（网卡序号，可空=自动挑）、
        ``pcap``（仅离线模式；**只接受 captures/ 下的文件名**，防任意文件读取）。

Returns:
    dict: 成功 ``{"ok": True}``；已在跑或参数不合法时 ``{"ok": False, "error": "..."}``。
        任务本身在后台线程执行，进度请轮询 ``/api/status``。
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
启动被动监听（只听不发）。

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
被动监听的当前状态与结果（界面每秒轮询它）。

Returns:
    dict: 键 ``ok`` / ``state``（``idle``/``running``/``done``/``error``）/
        ``result``（完成后是 ``passive.run()`` 的结果，运行中为 ``None``）/
        ``error`` / ``engine`` / ``engine_info`` / ``elapsed``（已运行秒数）。
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
| `pick_interface` | function | 272 | ✅ |
| `probe_interface` | function | 295 | ✅ |
| `is_admin` | function | 320 | ✅ |
| `npcap_installed` | function | 337 | ✅ |

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

### `pick_interface`

```python
def pick_interface(interfaces: list[dict]) -> dict | None
```

```text
挑一块「像样」的默认网卡。

按业务优先级：先按 :data:`PREFER_HINTS` 找物理网卡（以太网/Wi-Fi），
再用 :data:`SKIP_HINTS` 排掉回环、蓝牙、虚拟网卡（VMware/Hyper-V 等）。

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
| `compute_layers` | function | 191 | ✅ |
| `build` | function | 522 | ✅ |

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

## `mcp/wireshark-mcp/server.py`

**职责**：wireshark-mcp：基于 tshark 的 MCP 服务器（stdio 传输，零第三方依赖）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `call_tool` | function | 161 | ✅ |
| `handle` | function | 234 | ✅ |
| `main` | function | 275 | ✅ |

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

