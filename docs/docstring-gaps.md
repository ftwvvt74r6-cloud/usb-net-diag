# 注释缺口清单（自动生成）

> 由 `scripts/gen_api_doc.py` 生成。**这张表就是「补注释」的待办**：
> 一行修完就少一行，`--check` 通过就说明达标了。

- 合格率：**99.4%**（315/317）
- 模块说明：34/34

## 按文件汇总

| 文件 | 公开符号 | 有 docstring | 合格 | 合格率 |
|---|---|---|---|---|
| `core/__init__.py` | 0 | 0 | 0 | 100% |
| `core/ai.py` | 9 | 9 | 9 | 100% |
| `core/analyzer.py` | 3 | 3 | 3 | 100% |
| `core/app.py` | 9 | 9 | 9 | 100% |
| `core/bootstrap.py` | 4 | 4 | 4 | 100% |
| `core/conclusion.py` | 4 | 4 | 4 | 100% |
| `core/config.py` | 6 | 6 | 6 | 100% |
| `core/contracts.py` | 57 | 57 | 57 | 100% |
| `core/copytext.py` | 5 | 5 | 5 | 100% |
| `core/diagnose.py` | 8 | 8 | 8 | 100% |
| `core/diagpack.py` | 1 | 1 | 1 | 100% |
| `core/errors.py` | 3 | 3 | 3 | 100% |
| `core/evidence.py` | 6 | 6 | 6 | 100% |
| `core/extract/__init__.py` | 0 | 0 | 0 | 100% |
| `core/extract/aggregate.py` | 2 | 2 | 2 | 100% |
| `core/extract/fields.py` | 5 | 5 | 5 | 100% |
| `core/logstore.py` | 22 | 22 | 22 | 100% |
| `core/passive.py` | 3 | 3 | 3 | 100% |
| `core/pathprobe.py` | 64 | 64 | 64 | 100% |
| `core/platform/__init__.py` | 0 | 0 | 0 | 100% |
| `core/platform/paths.py` | 16 | 16 | 16 | 100% |
| `core/platform/winapi.py` | 8 | 8 | 8 | 100% |
| `core/probe.py` | 1 | 1 | 1 | 100% |
| `core/report.py` | 4 | 4 | 4 | 100% |
| `core/rules/__init__.py` | 0 | 0 | 0 | 100% |
| `core/rules/legacy_map.py` | 9 | 9 | 9 | 100% |
| `core/sanitize.py` | 4 | 4 | 4 | 100% |
| `core/selfcheck.py` | 14 | 14 | 14 | 100% |
| `core/server.py` | 27 | 27 | 27 | 100% |
| `core/startmsg.py` | 2 | 2 | 0 | 0% |
| `core/tshark.py` | 13 | 13 | 13 | 100% |
| `core/verdict.py` | 2 | 2 | 2 | 100% |
| `core/version.py` | 1 | 1 | 1 | 100% |
| `mcp/wireshark-mcp/server.py` | 5 | 5 | 5 | 100% |

## 待补清单

| 文件:行 | 符号 | 缺什么 |
|---|---|---|
| `core/startmsg.py:68` | `render` | 缺参数说明、缺返回值说明 |
| `core/startmsg.py:74` | `main` | 缺参数说明、缺返回值说明 |

