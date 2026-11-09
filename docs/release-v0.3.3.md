# v0.3.3 发布记录（2026-11-09）

## 1. 发布资产

| 项 | 值 |
|---|---|
| Tag | `v0.3.3` |
| 资产 | `NetDiag-0.3.3-lite.zip`（1,264,353 B）+ `SHA256SUMS.txt` |
| sha256 | `71dd972f26dfa03e65ad04ad6296bd4600e8aea22cf86bf02ffa7f2e9a345822` |
| 包内文件 | 204 个，解压后 3,438,452 B |
| 启动器 | `NetDiag.exe` 70,144 B（构建时用系统 csc 编译） |
| 内容 | 源码 + NetDiag.exe + 文档；**不含** Wireshark / Npcap / 便携 Python（合规要求） |

## 2. 本版内容

**修复**（真机事故 `FileNotFoundError: 'F:\'`）

1. pcap 路径绝对化并持久化到 run 记录（不再只存文件名）
2. 分析失败错误卡补全：绝对路径 / 是否存在 / 大小 / 失败阶段 + 三条常见原因 + 重新抓包
3. 旧记录兼容：`record_schema` 版本识别 + 旧记录横幅 + 禁用含边界导出 + 不渲染四层「未知」卡
4. 本次失败时不混入上一轮结论

**新增（默认未启用）**

- `ui/v2/**` UI v2 骨架（苹果风 token / 9 枚内联 SVG 图标 / 8 个 JS 模块）。
  默认入口仍是 v1；`?ui=v2` 开关与 `/v2/**` 静态白名单将在后续版本接入。

## 3. 测试与红线

- 测试 1003 → **1020**（新增 `tests/test_analysis_path.py` 17 条）
- 红线：demo + 9 样本 `analyze()+verdict.build()+render_markdown()` 逐字节不变
- 干净 checkout 四项：compileall / unittest(1020 OK) / gen_api_doc --check / doc-sync 无 diff
- CI：语法检查 + 启动器契约、接口注释覆盖率 双绿

## 4. 升级说明

从 v0.3.2 升级：直接替换代码/启动器即可，`logs/runs/` 里的旧记录**不需要清**——
它们会被识别为旧格式并显示横幅，不再渲染「未知」结论卡。
