# 注释缺口清单（自动生成）

> 由 `scripts/gen_api_doc.py` 生成。**这张表就是「补注释」的待办**：
> 一行修完就少一行，`--check` 通过就说明达标了。

- 合格率：**8.8%**（6/68）
- 模块说明：12/12

## 按文件汇总

| 文件 | 公开符号 | 有 docstring | 合格 | 合格率 |
|---|---|---|---|---|
| `core/ai.py` | 9 | 4 | 1 | 11% |
| `core/analyzer.py` | 3 | 1 | 0 | 0% |
| `core/app.py` | 6 | 4 | 1 | 17% |
| `core/bootstrap.py` | 4 | 1 | 0 | 0% |
| `core/diagnose.py` | 6 | 3 | 0 | 0% |
| `core/passive.py` | 3 | 3 | 0 | 0% |
| `core/probe.py` | 1 | 1 | 0 | 0% |
| `core/report.py` | 2 | 1 | 0 | 0% |
| `core/server.py` | 17 | 8 | 4 | 24% |
| `core/tshark.py` | 12 | 7 | 0 | 0% |
| `core/verdict.py` | 2 | 2 | 0 | 0% |
| `mcp/wireshark-mcp/server.py` | 3 | 0 | 0 | 0% |

## 待补清单

| 文件:行 | 符号 | 缺什么 |
|---|---|---|
| `core/ai.py:70` | `load_config` | 无 docstring |
| `core/ai.py:127` | `save_config` | 无 docstring |
| `core/ai.py:136` | `mask_key` | 无 docstring |
| `core/ai.py:145` | `public_config` | 无 docstring |
| `core/ai.py:190` | `chat` | 缺参数说明、缺返回值说明 |
| `core/ai.py:262` | `test_connection` | 缺参数说明、缺返回值说明 |
| `core/ai.py:318` | `build_messages` | 缺参数说明、缺返回值说明 |
| `core/ai.py:411` | `analyze_result` | 无 docstring |
| `core/analyzer.py:170` | `collect` | 缺参数说明、缺返回值说明 |
| `core/analyzer.py:556` | `build_findings` | 无 docstring |
| `core/analyzer.py:826` | `analyze` | 无 docstring |
| `core/app.py:49` | `msgbox` | 缺参数说明 |
| `core/app.py:57` | `is_admin` | 无 docstring |
| `core/app.py:64` | `relaunch_as_admin` | 缺返回值说明 |
| `core/app.py:76` | `find_running` | 缺返回值说明 |
| `core/app.py:96` | `main` | 无 docstring |
| `core/bootstrap.py:24` | `write_json` | 无 docstring |
| `core/bootstrap.py:29` | `gen_configs` | 缺返回值说明 |
| `core/bootstrap.py:71` | `check` | 无 docstring |
| `core/bootstrap.py:107` | `main` | 无 docstring |
| `core/diagnose.py:42` | `load_config` | 无 docstring |
| `core/diagnose.py:65` | `log` | 无 docstring |
| `core/diagnose.py:70` | `bpf_for` | 缺参数说明、缺返回值说明 |
| `core/diagnose.py:85` | `capture_live` | 缺参数说明、缺返回值说明 |
| `core/diagnose.py:149` | `run_scan` | 缺参数说明、缺返回值说明 |
| `core/diagnose.py:198` | `main` | 无 docstring |
| `core/passive.py:62` | `engine_status` | 缺返回值说明 |
| `core/passive.py:392` | `build_flows` | 缺参数说明、缺返回值说明 |
| `core/passive.py:509` | `run` | 缺参数说明、缺返回值说明 |
| `core/probe.py:672` | `run` | 缺参数说明、缺返回值说明 |
| `core/report.py:46` | `render_markdown` | 无 docstring |
| `core/report.py:259` | `save` | 缺参数说明、缺返回值说明 |
| `core/server.py:97` | `request_quit` | 缺参数说明 |
| `core/server.py:173` | `doctor_cached` | 缺参数说明、缺返回值说明 |
| `core/server.py:195` | `log` | 无 docstring |
| `core/server.py:226` | `start_job` | 无 docstring |
| `core/server.py:259` | `engine_info` | 缺返回值说明 |
| `core/server.py:290` | `passive_start` | 无 docstring |
| `core/server.py:313` | `passive_status` | 无 docstring |
| `core/server.py:324` | `Handler` | 无 docstring |
| `core/server.py:358` | `Handler.log_message` | 无 docstring |
| `core/server.py:448` | `Handler.do_GET` | 无 docstring |
| `core/server.py:457` | `Handler.do_POST` | 无 docstring |
| `core/server.py:626` | `create_server` | 缺参数说明、缺返回值说明 |
| `core/server.py:660` | `main` | 无 docstring |
| `core/tshark.py:44` | `short_name` | 缺参数说明、缺返回值说明 |
| `core/tshark.py:50` | `find_tshark` | 无 docstring |
| `core/tshark.py:54` | `find_dumpcap` | 无 docstring |
| `core/tshark.py:58` | `find_npcap_installer` | 无 docstring |
| `core/tshark.py:79` | `run` | 缺参数说明、缺返回值说明 |
| `core/tshark.py:101` | `iter_lines` | 缺参数说明 |
| `core/tshark.py:155` | `version` | 无 docstring |
| `core/tshark.py:167` | `list_interfaces` | 缺参数说明、缺返回值说明 |
| `core/tshark.py:199` | `pick_interface` | 缺参数说明、缺返回值说明 |
| `core/tshark.py:212` | `probe_interface` | 缺参数说明、缺返回值说明 |
| `core/tshark.py:225` | `is_admin` | 无 docstring |
| `core/tshark.py:236` | `npcap_installed` | 缺返回值说明 |
| `core/verdict.py:83` | `compute_layers` | 缺参数说明、缺返回值说明 |
| `core/verdict.py:168` | `build` | 缺参数说明、缺返回值说明 |
| `mcp/wireshark-mcp/server.py:161` | `call_tool` | 无 docstring |
| `mcp/wireshark-mcp/server.py:220` | `handle` | 无 docstring |
| `mcp/wireshark-mcp/server.py:252` | `main` | 无 docstring |

