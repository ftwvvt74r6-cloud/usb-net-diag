# 接口参考（自动生成）

> 本文件由 `scripts/gen_api_doc.py` 从 AST 生成，**签名永远与代码一致**。
> 不要手改签名；要改内容就改源码里的 docstring，然后重跑：
>
> ```bat
> tools\python\python.exe scripts\gen_api_doc.py
> ```

- 扫描模块：**12** 个（有模块说明 12 个）
- 公开符号：**68** 个（有 docstring 35 个，合格 6 个）
- 合格率：**8.8%**（目标 ≥ 95%，见 `docs/api-style.md`）

阅读顺序建议：先看 `docs/overview.md`（一页看懂项目）→ 本文件的「按模块」→ 具体源码。

---

## `core/ai.py`

**职责**：AI 模型服务：配置持久化 + OpenAI 兼容协议调用。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `AIError` | class | 65 | ✅ |
| `load_config` | function | 70 | ⚠️ 无 docstring |
| `save_config` | function | 127 | ⚠️ 无 docstring |
| `mask_key` | function | 136 | ⚠️ 无 docstring |
| `public_config` | function | 145 | ⚠️ 无 docstring |
| `chat` | function | 190 | ⚠️ 缺参数说明、缺返回值说明 |
| `test_connection` | function | 262 | ⚠️ 缺参数说明、缺返回值说明 |
| `build_messages` | function | 318 | ⚠️ 缺参数说明、缺返回值说明 |
| `analyze_result` | function | 411 | ⚠️ 无 docstring |

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

> ⚠️ 缺少 docstring。

### `save_config`

```python
def save_config(patch: dict) -> dict
```

> ⚠️ 缺少 docstring。

### `mask_key`

```python
def mask_key(key: str) -> str
```

> ⚠️ 缺少 docstring。

### `public_config`

```python
def public_config(cfg: dict | None=None) -> dict
```

> ⚠️ 缺少 docstring。

### `chat`

```python
def chat(messages: list[dict], overrides: dict | None=None, timeout: int | None=None, max_tokens: int | None=None) -> str
```

```text
调用 /chat/completions，返回纯文本回复。失败抛 AIError。
```

### `test_connection`

```python
def test_connection(overrides: dict | None=None) -> dict
```

```text
最小代价验证：发一句短提示，看能否拿到回复。
```

### `build_messages`

```python
def build_messages(result: dict, question: str='') -> list[dict]
```

```text
把 diagnose 的结果转成对话消息，保留全部原始观测值供模型引用。
```

### `analyze_result`

```python
def analyze_result(result: dict, question: str='', overrides: dict | None=None) -> dict
```

> ⚠️ 缺少 docstring。

## `core/analyzer.py`

**职责**：抓包分析引擎：网络故障分层定位（主）+ 安全隐患观察（次）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `collect` | function | 170 | ⚠️ 缺参数说明、缺返回值说明 |
| `build_findings` | function | 573 | ⚠️ 无 docstring |
| `analyze` | function | 843 | ⚠️ 无 docstring |

### `collect`

```python
def collect(pcap: Path, log=None) -> tuple[dict, str]
```

```text
流式解析 pcap，返回 (stats, error)。
```

### `build_findings`

```python
def build_findings(st: dict, m: dict, streams: list[dict]) -> list[dict]
```

> ⚠️ 缺少 docstring。

### `analyze`

```python
def analyze(pcap: Path | str, target: str='', ti_key: str='', log=None) -> dict
```

> ⚠️ 缺少 docstring。

## `core/app.py`

**职责**：静默启动器：像应用一样双击即用，全程不弹控制台窗口。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `redirect_output` | function | 34 | ✅ |
| `msgbox` | function | 49 | ⚠️ 缺参数说明 |
| `is_admin` | function | 57 | ⚠️ 无 docstring |
| `relaunch_as_admin` | function | 64 | ⚠️ 缺返回值说明 |
| `find_running` | function | 76 | ⚠️ 缺返回值说明 |
| `main` | function | 96 | ⚠️ 无 docstring |

### `redirect_output`

```python
def redirect_output() -> None
```

```text
pythonw 下 sys.stdout/stderr 是 None，任何 print 都会炸，先兜住。
```

### `msgbox`

```python
def msgbox(text: str, title: str='网络诊断工具', flags: int=MB_ICONINFO) -> None
```

```text
没有控制台时唯一的提示手段。
```

### `is_admin`

```python
def is_admin() -> bool
```

> ⚠️ 缺少 docstring。

### `relaunch_as_admin`

```python
def relaunch_as_admin() -> bool
```

```text
UAC 提权重启自己；用户点「否」返回 False。
```

### `find_running`

```python
def find_running() -> str
```

```text
探测本机是否已有实例，返回它的界面地址；没有则空串。
```

### `main`

```python
def main() -> int
```

> ⚠️ 缺少 docstring。

## `core/bootstrap.py`

**职责**：U 盘启动引导：按实际盘符生成配置 + 环境自检。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `write_json` | function | 24 | ⚠️ 无 docstring |
| `gen_configs` | function | 29 | ⚠️ 缺返回值说明 |
| `check` | function | 71 | ⚠️ 无 docstring |
| `main` | function | 107 | ⚠️ 无 docstring |

### `write_json`

```python
def write_json(path: Path, data: dict) -> None
```

> ⚠️ 缺少 docstring。

### `gen_configs`

```python
def gen_configs() -> dict
```

```text
用当前盘符重写 MCP 与 Harness 配置（U 盘盘符变化后自动适配）。
```

### `check`

```python
def check(verbose: bool=True) -> dict
```

> ⚠️ 缺少 docstring。

### `main`

```python
def main(argv=None) -> int
```

> ⚠️ 缺少 docstring。

## `core/diagnose.py`

**职责**：USB-Net-Diag 采集与诊断主流程（CLI 入口）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `load_config` | function | 43 | ⚠️ 无 docstring |
| `log` | function | 66 | ⚠️ 无 docstring |
| `bpf_for` | function | 71 | ⚠️ 缺参数说明、缺返回值说明 |
| `capture_live` | function | 86 | ⚠️ 缺参数说明、缺返回值说明 |
| `run_scan` | function | 187 | ⚠️ 缺参数说明、缺返回值说明 |
| `main` | function | 236 | ⚠️ 无 docstring |

### `load_config`

```python
def load_config() -> dict
```

> ⚠️ 缺少 docstring。

### `log`

```python
def log(msg: str) -> None
```

> ⚠️ 缺少 docstring。

### `bpf_for`

```python
def bpf_for(target: str) -> str
```

```text
把目标转成 BPF 过滤器。只接受 IP / CIDR / 域名，避免把任意表达式喂给抓包器。
```

### `capture_live`

```python
def capture_live(target: str='', duration: int=30, interface: str | None=None, logger=log) -> dict
```

```text
实时抓包，返回 {ok, pcap, interface, bpf} 或 {ok:False, error, degraded}。
```

### `run_scan`

```python
def run_scan(target: str='', duration: int=30, interface: str | None=None, pcap: str | None=None, logger=log) -> dict
```

```text
完整诊断：抓包(或复用) → 分析 → 落盘报告。
```

### `main`

```python
def main(argv: list[str] | None=None) -> int
```

> ⚠️ 缺少 docstring。

## `core/passive.py`

**职责**：被动流量监听：实时盯着网卡，把流量按会话聚合，用「端口 + 首包特征」识别协议。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `engine_status` | function | 62 | ⚠️ 缺返回值说明 |
| `build_flows` | function | 392 | ⚠️ 缺参数说明、缺返回值说明 |
| `run` | function | 509 | ⚠️ 缺参数说明、缺返回值说明 |

### `engine_status`

```python
def engine_status() -> dict
```

```text
返回当前可用的采集引擎，供界面/自检显示。
```

### `build_flows`

```python
def build_flows(recs: list[dict]) -> tuple[list[dict], dict]
```

```text
把逐包记录聚合成双向会话，并给出协议、状态、包长等信息。
```

### `run`

```python
def run(interface: str | None=None, duration: int=20, target: str='', max_packets: int=20000, engine: str='auto', logger=None, should_stop=None) -> dict
```

```text
监听网卡 duration 秒，返回会话表 + 汇总。engine = auto|scapy|tshark。
```

## `core/probe.py`

**职责**：链路体检：不抓包，直接分段测量一次真实访问，定位慢在哪一段。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `run` | function | 672 | ⚠️ 缺参数说明、缺返回值说明 |

### `run`

```python
def run(target: str, port: int | None=None, count: int=4, timeout: float=3.0, tls_override: bool | None=None, proto: str | None=None) -> dict
```

```text
执行一次分段体检，返回各段耗时 + 协议 + 结论。

proto 可手动指定 tls/http/smb/rdp/opaque，用于端口不常见的场景。
```

## `core/report.py`

**职责**：报告渲染：分层故障定位（主）+ 完整技术明细（辅）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `render_markdown` | function | 46 | ⚠️ 无 docstring |
| `save` | function | 259 | ⚠️ 缺参数说明、缺返回值说明 |

### `render_markdown`

```python
def render_markdown(result: dict, vd: dict | None=None) -> str
```

> ⚠️ 缺少 docstring。

### `save`

```python
def save(result: dict, out_dir: Path) -> dict
```

```text
写出 .md 与 .json，返回路径。
```

## `core/server.py`

**职责**：本地 Web UI + HTTP API（仅监听 127.0.0.1，不对外暴露）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `touch` | function | 92 | ✅ |
| `request_quit` | function | 97 | ⚠️ 缺参数说明 |
| `cleanup_pid` | function | 136 | ✅ |
| `BodyTooLarge` | class | 146 | ✅ |
| `doctor_cached` | function | 173 | ⚠️ 缺参数说明、缺返回值说明 |
| `log` | function | 195 | ⚠️ 无 docstring |
| `start_job` | function | 226 | ⚠️ 无 docstring |
| `engine_info` | function | 259 | ⚠️ 缺返回值说明 |
| `passive_start` | function | 290 | ⚠️ 无 docstring |
| `passive_status` | function | 313 | ⚠️ 无 docstring |
| `Handler` | class | 324 | ⚠️ 无 docstring |
| `Handler.log_message` | method | 358 | ⚠️ 无 docstring |
| `Handler.do_GET` | method | 448 | ⚠️ 无 docstring |
| `Handler.do_POST` | method | 457 | ⚠️ 无 docstring |
| `DiagServer` | class | 614 | ✅ |
| `create_server` | function | 626 | ⚠️ 缺参数说明、缺返回值说明 |
| `main` | function | 660 | ⚠️ 无 docstring |

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
环境自检要跑 tshark -v / -D，较慢；缓存 60 秒，避免首屏卡顿。
```

### `log`

```python
def log(msg: str) -> None
```

> ⚠️ 缺少 docstring。

### `start_job`

```python
def start_job(payload: dict) -> dict
```

> ⚠️ 缺少 docstring。

### `engine_info`

```python
def engine_info() -> dict
```

```text
缓存采集引擎信息（scapy 导入要 2s，不必每次探测）。
```

### `passive_start`

```python
def passive_start(payload: dict) -> dict
```

> ⚠️ 缺少 docstring。

### `passive_status`

```python
def passive_status() -> dict
```

> ⚠️ 缺少 docstring。

### `Handler`  (class)

```python
class Handler
```

> ⚠️ 缺少 docstring。

### `Handler.log_message`  (method)

```python
def log_message(self, fmt, *args)
```

> ⚠️ 缺少 docstring。

### `Handler.do_GET`  (method)

```python
def do_GET(self)
```

> ⚠️ 缺少 docstring。

### `Handler.do_POST`  (method)

```python
def do_POST(self)
```

> ⚠️ 缺少 docstring。

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
建监听。端口被占用时顺延最多 10 个，返回 (实例, 访问地址)。

register_pid=False 供自测使用：避免测试实例覆盖正在运行的应用的 PID 文件。
```

### `main`

```python
def main() -> int
```

> ⚠️ 缺少 docstring。

## `core/tshark.py`

**职责**：tshark / dumpcap 定位与执行封装（纯标准库，适配便携 Python）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `short_name` | function | 44 | ⚠️ 缺参数说明、缺返回值说明 |
| `find_tshark` | function | 50 | ⚠️ 无 docstring |
| `find_dumpcap` | function | 54 | ⚠️ 无 docstring |
| `find_npcap_installer` | function | 58 | ⚠️ 无 docstring |
| `run` | function | 79 | ⚠️ 缺参数说明、缺返回值说明 |
| `iter_lines` | function | 101 | ⚠️ 缺参数说明 |
| `version` | function | 155 | ⚠️ 无 docstring |
| `list_interfaces` | function | 167 | ⚠️ 缺参数说明、缺返回值说明 |
| `pick_interface` | function | 199 | ⚠️ 缺参数说明、缺返回值说明 |
| `probe_interface` | function | 212 | ⚠️ 缺参数说明、缺返回值说明 |
| `is_admin` | function | 225 | ⚠️ 无 docstring |
| `npcap_installed` | function | 236 | ⚠️ 缺返回值说明 |

### `short_name`

```python
def short_name(name: str) -> str
```

```text
把 tshark -D 的长设备名精简为括号内的网卡别名。
```

### `find_tshark`

```python
def find_tshark() -> Path | None
```

> ⚠️ 缺少 docstring。

### `find_dumpcap`

```python
def find_dumpcap() -> Path | None
```

> ⚠️ 缺少 docstring。

### `find_npcap_installer`

```python
def find_npcap_installer() -> Path | None
```

> ⚠️ 缺少 docstring。

### `run`

```python
def run(args: list[str], timeout: int=180) -> tuple[int, str, str]
```

```text
执行子进程，返回 (returncode, stdout, stderr)。不抛异常。
```

### `iter_lines`

```python
def iter_lines(args: list[str], timeout: int=900, sink: dict | None=None)
```

```text
流式读取子进程 stdout，逐行 yield，避免大 pcap 的输出整份进内存。

结束时把 {"rc": 返回码, "stderr": 错误输出} 写回 sink。
```

### `version`

```python
def version(tshark: Path | None=None) -> str
```

> ⚠️ 缺少 docstring。

### `list_interfaces`

```python
def list_interfaces(tshark: Path | None=None) -> list[dict]
```

```text
解析 `tshark -D`，返回 [{'index':1,'name':'以太网','raw':'...'}]
```

### `pick_interface`

```python
def pick_interface(interfaces: list[dict]) -> dict | None
```

```text
挑选默认网卡：按业务优先级排序，跳过回环/虚拟/蓝牙适配器。
```

### `probe_interface`

```python
def probe_interface(tshark_path: Path, candidates: list[dict], seconds: int=2) -> dict | None
```

```text
逐个网卡试抓 2 秒，返回第一个有流量的网卡。
```

### `is_admin`

```python
def is_admin() -> bool
```

> ⚠️ 缺少 docstring。

### `npcap_installed`

```python
def npcap_installed() -> bool
```

```text
检测 Npcap 是否安装（看驱动文件优先，最后才问服务状态）。

只查文件系统是最快的（毫秒级）；`sc query` 在受限环境里可能卡住，
因此放最后并把超时压到 5 秒，且不再依赖它的输出做唯一判据。
```

## `core/verdict.py`

**职责**：把结构化分析结果翻译成「故障定位结论」。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `compute_layers` | function | 83 | ⚠️ 缺参数说明、缺返回值说明 |
| `build` | function | 168 | ⚠️ 缺参数说明、缺返回值说明 |

### `compute_layers`

```python
def compute_layers(rows: list[dict], meta: dict, metrics: dict) -> list[dict]
```

```text
每层一个状态块，UI 用横条展示「哪一层红了」。
```

### `build`

```python
def build(result: dict) -> dict
```

```text
返回 {level, headline, plain, layer, layers[], points[], next_steps[], metrics, flags}
```

## `mcp/wireshark-mcp/server.py`

**职责**：wireshark-mcp：基于 tshark 的 MCP 服务器（stdio 传输，零第三方依赖）。

| 符号 | 类型 | 行 | docstring |
|---|---|---|---|
| `call_tool` | function | 161 | ⚠️ 无 docstring |
| `handle` | function | 220 | ⚠️ 无 docstring |
| `main` | function | 252 | ⚠️ 无 docstring |

### `call_tool`

```python
def call_tool(name: str, args: dict) -> dict
```

> ⚠️ 缺少 docstring。

### `handle`

```python
def handle(msg: dict) -> dict | None
```

> ⚠️ 缺少 docstring。

### `main`

```python
def main() -> int
```

> ⚠️ 缺少 docstring。

