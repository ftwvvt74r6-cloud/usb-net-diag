"""NetDiag（网络矩阵）核心包（目标架构骨架）。

设计不变量（详见 docs/plan-review.md 第 4.1 节）：

1. 纯核心：``findings = rules(features)`` 不碰文件 / 网络 / 时钟。
2. 单一边界：只有 ``capture/`` 能调用 tshark / scapy；只有 ``egress/`` 能对外发送。
3. 契约先行：跨模块数据一律用 ``contracts``，并带 ``schema_version``。
4. 文案与逻辑分离：规则只产出 ``rule_id + 指标 + 证据``，中文查 ``copy/zh-CN.json``。
5. 可复现：任何结果都带 ``provenance``。
"""

__version__ = "0.3.1"
