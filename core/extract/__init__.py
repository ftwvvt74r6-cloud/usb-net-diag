"""extract 层：把 tshark 的原始输出变成可回放的 ``Features``。

这一层是「采集」与「判断」之间的分界线：

* :mod:`core.extract.fields` —— 字段清单 + 原始字符串解析（纯函数，不认识报文语义）
* :mod:`core.extract.aggregate` —— 逐帧聚合成 ``Features``（纯函数，不碰网络）

拆出来的目的只有一个：**规则引擎的单测不该需要 tshark**。
把一份 ``features.json`` 放进 ``tests/fixtures/``，CI 里就能完整回放整条判断链路。

依赖方向是单向的 ``analyzer → extract``。本包**不得** import ``core.analyzer``，
否则拆层白做。
"""

from __future__ import annotations

from .aggregate import STATE_CLOSED, STATE_NO_REPLY, STATE_RST, build_features
from .fields import FIELDS, parse_flag, parse_int, parse_num, parse_port, parse_rows

__all__ = [
    "FIELDS",
    "parse_flag",
    "parse_num",
    "parse_port",
    "parse_int",
    "parse_rows",
    "build_features",
    "STATE_CLOSED",
    "STATE_RST",
    "STATE_NO_REPLY",
]
