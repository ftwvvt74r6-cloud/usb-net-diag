# 注释与文档标准（写给「让完全不懂网络的人也能读懂」）

> 目标读者：会写一点代码、但不懂网络协议、也不懂这个项目历史的人。
> 验收方式：**可测量**，不靠感觉 —— `scripts/gen_api_doc.py --check 0.95`
> 通过即达标（报告见 `docs/docstring-gaps.md`）。

---

## 0. 现状基线（2026-11-06 实测）

| 指标 | 现状 | 目标 |
|---|---|---|
| 模块级说明 | **11/11**（每个文件开头都有） | 保持 |
| 公开符号数 | 55 | — |
| 有一句话 docstring | 23/55 | 100% |
| **写了参数/返回值含义** | **1/55（1.8%）** | **≥ 95%** |

也就是说：**这个项目不缺「这是一句话说明」，缺的是「这个参数是什么、返回值里有什么」**。
小白的第一个问题永远是「`collect(pcap, log=None)` 里的 `log` 传什么？返回的 dict 里有哪些键？」
—— 现在的代码回答不了这两个问题。

---

## 1. 三层注释，各司其职

### 第一层：模块头（必须有，2~6 行）

回答四个问题，缺一不可：

```python
"""抓包分析引擎：网络故障分层定位（主）+ 安全隐患观察（次）。

解决什么问题：把一份 pcap 变成「哪一层坏了、哪个协议、哪个对端」。
谁调用它：core/diagnose.py（CLI 与 HTTP 接口都走它）。
不做什么：不联网、不调用模型、不写文件（落盘在 report.py）。
输入输出：pcap 路径 → {"meta": {...}, "rows": [...], "metrics": {...}}。
"""
```

**为什么重要**：小白看目录名猜不出 `verdict.py` 和 `report.py` 的分界线，
而这条边界恰恰决定了「改需求时该改哪个文件」。

### 第二层：符号 docstring（必须有 Args / Returns / Raises）

```python
def collect(pcap: Path, log=None) -> tuple[dict, str]:
    """把 pcap 流式解析成统计字典。

    Args:
        pcap: 抓包文件路径，必须是 tshark 能读的 pcap/pcapng。
        log: 可调用对象，签名 ``log(str)``；用于把进度打到界面或控制台。
            传 ``None`` 表示静默（CI 里就这么用）。

    Returns:
        二元组 ``(stats, error)``：

        - ``stats``：聚合结果，键见 ``analyzer.build_findings`` 的入参；
          解析出 0 个报文时为 ``{}``。
        - ``error``：成功为空字符串；失败是可直接展示的中文原因。

    Raises:
        不抛异常。tshark 找不到、超时、权限不足都转成 ``error`` 返回
        —— 因为这是 U 盘工具，任何异常都不能让界面白屏。

    Example:
        >>> stats, err = collect(Path("captures/faults_demo.pcap"))
        >>> err
        ''
        >>> stats["packets"] > 0
        True
    """
```

**四条硬规则**（`gen_api_doc.py` 会检查）：

1. `Args:` 里**每个参数**都要出现，且写清「取值范围 / 传 None 会怎样」。
2. `Returns:` 里**结构化返回值要列键名**（dict/tuple 尤其），否则读者只能去翻实现。
3. `Raises:` 写「什么情况抛什么异常」；**不抛异常也要写一句「不抛异常」**，
   这是调用方最想知道的信息。
4. `Example:` 必须**可直接复制运行**（不要写 `...` 占位）。

### 第三层：行内注释（只在「为什么」处写）

```python
# 好：解释决策
# SYN 重发说明对端没回应，属于「建连问题」，不能算进链路重传率
if is_syn and retrans:
    syn_retrans += 1

# 坏：复述代码
retrans += 1          # 重传加一
i += 1                # i 加一
```

判据：**删掉这行注释，读者会不会误解代码的意图？** 不会 → 就别写。

---

## 2. 术语表（小白必读，改代码的人必须维护）

网络术语第一次出现时，就地给一句白话解释。统一写法：

| 术语 | 一句话解释（照抄即可） |
|---|---|
| TCP 三次握手 | 建立连接的三步确认，握手慢 = 双方来回一轮的延迟大 |
| 重传（retransmission） | 发出去的数据没收到确认，又发了一遍；重传率高就等于丢包 |
| dup-ACK（重复 ACK） | 接收方反复确认同一段，说明中间有一段没收到 |
| 零窗口（zero window） | 接收方缓冲区满了，通知发送方「先别发」；是**接收方**慢，不是网络慢 |
| RTT | 一次往返的时间；但 `ack_rtt` 含延迟 ACK 与处理时间，不等于网络时延 |
| NXDOMAIN | 域名不存在（DNS 明确的「查无此名」） |
| 分片 / MTU | 报文太大被拆开；「需要分片」提示通常意味着链路 MTU 配小了 |
| 上行 / 下行 | 客户端→服务端 / 服务端→客户端；**抓包点在本机，方向不能靠猜** |

写新模块时，凡是用到上表之外的术语，就在该模块 docstring 里补一行。

---

## 3. 三个必读文档（T16 的交付物）

| 文件 | 内容 | 谁维护 |
|---|---|---|
| `docs/overview.md` | **一页看懂**：这工具干什么、数据怎么流、5 个最重要的概念 | 人写，改架构时同步 |
| `docs/api-reference.md` | 所有公开接口的签名 + docstring | **自动生成**，禁止手改 |
| `docs/docstring-gaps.md` | 还差哪些注释 | **自动生成** |

生成/校验命令：

```bat
REM 生成文档 + 缺口清单
tools\python\python.exe scripts\gen_api_doc.py

REM CI 模式：合格率低于 95% 直接失败
tools\python\python.exe scripts\gen_api_doc.py --check 0.95
```

---

## 4. 提交前自检（贴在 PR 模板里）

- [ ] 新增/修改的公开函数都有 `Args:` / `Returns:` / `Raises:`
- [ ] 结构化返回值列出了键名
- [ ] `Example:` 能直接跑通
- [ ] 没写「复述代码」式注释
- [ ] 新术语在模块 docstring 里解释过一次
- [ ] `scripts/gen_api_doc.py --check 0.95` 通过

---

## 5. 一个反例（现有代码的真实情况）

`core/report.py` 的 `save()` 现在只有一句：

```python
def save(result: dict, out_dir: Path) -> dict:
    """写出 .md 与 .json，返回路径。"""
```

小白读到这里会问：`result` 里是什么？`out_dir` 不存在会怎样？返回的 dict 有哪些键？
文件名冲突时会不会覆盖？（**会覆盖**——而这正是评审 P1 提的问题，注释里一个字都没提。）

按本规范应该写成：

```python
def save(result: dict, out_dir: Path) -> dict:
    """把诊断结果落盘成 Markdown 报告与 JSON 快照。

    Args:
        result: ``analyzer.analyze()`` 的返回值，必须含 ``meta`` / ``rows`` /
            ``summary`` / ``verdict``；缺 ``meta`` 时文件名退化为 ``report``。
        out_dir: 输出目录；不存在会自动创建（含多级）。

    Returns:
        ``{"markdown": <绝对路径>, "json": <绝对路径>}``。

    Raises:
        不抛异常。写盘失败（U 盘只读、盘符消失）时静默跳过，报告只在内存里。

    Note:
        ⚠️ 已知缺陷：文件名只取 pcap 主名，**同一份 pcap 重复分析会覆盖上一份**
        （见 docs/code-index.md #15，计划由 render/json_report.py 的带时间戳命名替代）。

    Example:
        >>> save(result, Path("reports"))
        {'markdown': '...faults_demo.md', 'json': '...faults_demo.json'}
    """
```

差别不在字数，而在**回答了读者会问的三个问题**：入参能不能缺、返回什么、什么情况下会失败。
