# T00 结论：落地前提 + 「同一 pcap 结论不一致」根因

> 对应任务：`tasks/tasks.json` → `T00`（PR0）
> 结论：**算法本身是确定性的；不一致来自「分析了不完整的文件」，而工具把半份数据当成了完整结论。**
> 状态：根因已定位并修复（`core/analyzer.py` + `core/diagnose.py`），带 4 个回归用例。

---

## 1. 落地前提核查

| 项 | 结果 | 证据 |
|---|---|---|
| 便携 Python | ✅ 3.11.x，`tools\python\python.exe` 可执行 | `python -c "import sys;print(sys.version)"` |
| tshark | ✅ 4.7.4 可定位 | `/api/doctor`、`tests/selftest.py` |
| Npcap | ✅ 就绪（`wpcap.dll` + 服务） | `/api/interfaces` 返回 `npcap: true` |
| 管理员权限 | ✅ 已提权（`admin: true`） | `/api/app` |
| 实时抓包 | ✅ 能抓（selftest §3 抓包 6s 通过） | `tests/selftest.py` §3 |
| 离线分析 | ✅ 54 包 / 16s / 4 会话 / 重传 5.56% | `reports/faults_demo.md` |

结论：**prerequisites 全部满足，后续任务优先级不需要重排。**

---

## 2. 复现：同一输入三次结论是否一致

### 2.1 完整样本 `captures/faults_demo.pcap`

```
#1 ~ #3 摘要：严重 3 项，警告 5 项，重传率 5.56%，RTT 54.3ms，DNS 失败 28.6%，HTTP 1209.5ms
完整报告 JSON 归一化哈希：54dae19a6cf3e3b3 / 54dae19a6cf3e3b3 / 54dae19a6cf3e3b3
```

**三次完全一致**，且与 README 声明基线（严重 3 / 警告 5）吻合。
说明 `analyzer.build_findings` 没有隐藏的全局状态、也没有依赖文件系统时间。

### 2.2 但日志里的 2 → 0 → 0 确实存在

`logs/diag_20261106.log`：

```
[16:06:35] 抓包完成：diag_20261106_160617.pcapng（146 KB）
[16:06:36] 诊断完成：严重 0 项，警告 2 项     ← 第一次
[16:07:35] 诊断完成：严重 0 项，警告 0 项     ← 第二次
[16:07:45] 诊断完成：严重 0 项，警告 0 项     ← 第三次
```

原始 pcapng 已不在 `captures/`（迁移时只保留了 demo 样本），所以改用**受控实验**定位机制。

---

## 3. 受控实验：不完整的输入会怎样

### 3.1 按字节截断样本（模拟「抓包写到一半」「拷贝没拷全」）

| 输入 | 修复前 `ok` | 修复前 严重/警告 | 修复后 |
|---|---|---|---|
| 完整 100% | True | 3 / 5 | True（3 / 5，不变） |
| 截断 85% | **True** | **2** / 5 | False（明确报错） |
| 截断 60% | **True** | **2** / 4 | False |
| 截断 30% | **True** | **0** / 3 | False |

`tshark` 对这类文件的反应是**退出码 14 + stderr `appears to have been cut short`**：

```
logs/trunc_30.pcap   rc=14  行数=28  err='tshark: The file ... cut short in the middle of a packet.'
logs/trunc_85.pcap   rc=14  行数=48  err='...'
captures/faults_demo.pcap  rc=0  行数=54  err=''
```

### 3.2 模拟「解析到一半被超时杀掉」

只喂前 20 行、并让 `sink["rc"] = -9`：

```
ok      = True       ← 界面会把它当成正常结论
报文数  = 19（完整 54）
严重/警告 = 0 / 3    ← 完整应为 3 / 5
```

---

## 4. 根因

`core/analyzer.py collect()` 的收尾只判断一种失败：

```python
err = (sink.get("stderr") or "").strip()
if st["packets"] == 0:            # ← 只判断「一个包都没读到」
    return {}, f"解析失败..."
st["duration"] = ...
if err and log:
    log(f"[提示] tshark 有告警输出：...")   # ← 读到一部分时，告警只是一行提示
return st, ""                      # ← 于是一律「成功」
```

也就是说 **tshark 的退出码被完全忽略**。只要解析到 ≥1 个报文，无论文件是否完整、进程是否被 kill，都返回成功。

这与 AGENTS.md 硬约束 9「不许静默吞异常后返回『正常』」直接冲突，也是「同一文件两次结论不同」的真正来源：

- 第一次分析发生在抓包刚结束时，文件尾部还没落盘 → 读到不完整内容 → **幻影告警**（半截会话被判「建连无响应」）→ 警告 2；
- 稍后文件完整 → 警告 0。

---

## 5. 修复

### 5.1 `core/analyzer.py`：把「不完整」变成显式失败

```python
if rc not in (0, None):
    if rc == 14 or "cut short" in err.lower():
        hint = "抓包文件不完整（写盘中断，或抓包进程还没退出就开始分析）"
    elif rc < 0:
        hint = "解析进程被超时中断"
    else:
        hint = f"解析异常退出（rc={rc}）"
    return {}, (f"{hint}：只读到 {st['packets']} 个报文，结论不可信。...")
```

CLI 实测输出（退出码 2，不再打印「严重 0」）：

```
[错误] 抓包文件不完整（写盘中断，或抓包进程还没退出就开始分析）：只读到 28 个报文，
结论不可信。请等抓包完全结束/文件拷贝完成后再分析；反复出现可换更小的抓包文件。
```

### 5.2 `core/diagnose.py`：抓包结束后等落盘稳定再分析

新增 `_wait_file_stable(path, timeout=3.0)`：连续两次采样文件大小不变才认为写盘结束。
`capture_live()` 在返回前调用，最多等 3 秒（实测通常 0.15~0.3 秒）。

理由：`tshark` 进程退出 **不等于** 数据已全部落盘（杀软扫描、大文件缓存回写会滞后）。
之前正是这个窗口期被拿来分析，才读到 `rc=14` 的半份文件。

---

## 6. 回归测试

新增 `tests/test_incomplete_input.py`（4 例，无 tshark / 无样本时自动 skip，不污染 CI）：

| 用例 | 断言 |
|---|---|
| `test_complete_sample_matches_baseline` | 完整样本 → 严重 3 / 警告 5 |
| `test_truncated_file_fails_loudly` | 截断 30% → `ok is False` 且错误含「结论不可信」 |
| `test_truncated_tail_fails_loudly` | 截断 85%（最接近真实场景）→ `ok is False` |
| `test_same_input_gives_same_result` | 同一文件跑两次，归一化后逐字节一致 |

本地结果：

```
python -m unittest discover -s tests -v   → Ran 12 tests, OK（原 8 + 新 4）
tests/selftest.py --fast                  → 通过 62 · 失败 0
CLI 三次 faults_demo                      → 3/5 完全一致
```

---

## 7. 本次没解决、留给后续任务的（不要误以为已修）

| 问题 | 归属 | 现状 |
|---|---|---|
| 1 KB 空抓包仍会判「各层正常」（证据充分性闸门） | **T06** | 本次只保证「读不全就报错」；「读全了但样本太少」还没拦 |
| `dup-ACK` 恒为 0（`_flag()` 不认 `"1,1"` 多值） | **T07** | 未动，方向推断仍缺这一项特征 |
| 报告按 pcap 名覆盖写，无审计价值 | **T12/T14** | 未动 |
| `uri_secret` 把 URI 前 50 字符拼进 finding | **T09** | 未动（仍可能带出口令到报告/AI/MCP） |
| `conn_refused` 把正常关闭的 RST 算成「端口没开」 | **T07** | 未动 |

> 特别提醒：T06 的闸门要靠「特征缺失 ≠ 特征为零」，而当前 `collect()` 已经能把「读不全」区分出来了，
> 正好可以作为 `Sufficiency` 的输入之一（`partial` 直接判 `VERDICT.INSUFFICIENT`）。

---

## 8. 复现命令

```bat
REM 1) 完整样本是否稳定（应三次相同）
for %i in (1 2 3) do @tools\python\python.exe core\diagnose.py --pcap captures\faults_demo.pcap --json

REM 2) 截断样本是否报错（应 rc=2 且提示「结论不可信」）
tools\python\python.exe -c "import pathlib;d=pathlib.Path('captures/faults_demo.pcap').read_bytes();pathlib.Path('logs\t.pcap').write_bytes(d[:len(d)*3//10])"
tools\python\python.exe core\diagnose.py --pcap logs\t.pcap --json

REM 3) 回归用例
tools\python\python.exe -m unittest discover -s tests -v
```
