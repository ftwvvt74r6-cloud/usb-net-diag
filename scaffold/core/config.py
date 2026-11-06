"""统一配置加载。

三个目标：

1. **单一入口**：不再每个模块自己 ``json.loads(Path(...))``；
2. **schema 校验 + 默认值**：缺键不崩、类型不对降级；
3. **可复现**：``config_sha256()`` 进 ``Provenance``，能回答「同样的输入为什么结论不同」。

配置分两类（重要）：

* ``config/app-config.json``：**用户可改**，每台机器/每个客户不同；
* ``core/rules/thresholds.json``：**随代码走**，改了要升 ``rules_version``。
  把阈值塞进 app-config 会让「同一份报告不可复现」——因为你不知道当时的阈值是多少。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .platform import paths

APP_CONFIG = paths.PATHS.config / "app-config.json"
AI_CONFIG = paths.PATHS.config / "ai-config.json"
THRESHOLDS = paths.PATHS.core / "rules" / "thresholds.json"
COPY_DIR = paths.PATHS.core / "copy"

APP_DEFAULTS: dict[str, Any] = {
    "server_port": 8787,
    "server_host": "127.0.0.1",
    "auto_open_browser": True,
    "default_duration": 30,
    "max_duration": 180,
    "max_upload_mb": 512,
    "threat_intel_key": "",
    #: 本地日志/报告默认保留明文（排障需要）；导出/外发时才脱敏。
    "log_plaintext": True,
    #: 脱敏 profile：local | lan_mask | cloud_mask（见 egress/sanitize.py）
    "egress_profile": "cloud_mask",
    #: 证据充分性阈值（不够就判「无法判定」，见 contracts.Sufficiency）
    "sufficiency": {
        "min_duration_s": 10,
        "min_tcp_streams": 3,
        "min_rtt_samples": 5,
        "min_dns_samples": 0,
    },
}

AI_DEFAULTS: dict[str, Any] = {
    "provider": "deepseek",
    "base_url": "https://api.deepseek.com/v1",
    "api_key": "",
    "model": "deepseek-chat",
    "temperature": 0.2,
    "timeout": 90,
    "verify_ssl": True,
    "updated_at": "",
}


def read_json(path: Path, default: Mapping[str, Any] | None = None) -> dict:
    """读 JSON；文件缺失/损坏一律回退默认值，**绝不抛异常**（U 盘场景必需）。"""
    base = dict(default or {})
    try:
        if path.is_file():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                base.update({k: v for k, v in raw.items() if v is not None})
    except (OSError, ValueError):
        pass
    return base


def load_app() -> dict:
    cfg = read_json(APP_CONFIG, APP_DEFAULTS)
    # 类型收敛：配置文件是用户可改的，坏了不能让服务起不来
    for key, spec in (("server_port", int), ("default_duration", int),
                      ("max_duration", int), ("max_upload_mb", int)):
        try:
            cfg[key] = spec(cfg.get(key, APP_DEFAULTS[key]))
        except (TypeError, ValueError):
            cfg[key] = APP_DEFAULTS[key]
    if cfg["server_port"] not in range(1024, 65536):
        cfg["server_port"] = APP_DEFAULTS["server_port"]
    merged_suff = dict(APP_DEFAULTS["sufficiency"])
    if isinstance(cfg.get("sufficiency"), dict):
        merged_suff.update(cfg["sufficiency"])
    cfg["sufficiency"] = merged_suff
    if cfg.get("egress_profile") not in ("local", "lan_mask", "cloud_mask"):
        cfg["egress_profile"] = "cloud_mask"
    return cfg


def load_ai() -> dict:
    return read_json(AI_CONFIG, AI_DEFAULTS)


def load_thresholds() -> dict:
    """规则阈值。缺失时返回空表——规则会因 ``requires`` 未满足而跳过，而不是瞎判。"""
    return read_json(THRESHOLDS, {})


def load_copy(lang: str = "zh-CN") -> dict:
    """文案表。缺失时返回空表，渲染层回退到 ``rule_id`` 本身（不崩）。"""
    return read_json(COPY_DIR / f"{lang}.json", {})


def config_sha256() -> str:
    """把「影响结论的配置」一起哈希，写进 Provenance。

    只哈希 app 配置与阈值；**不哈希 AI Key**（避免把密钥指纹写进报告）。
    """
    payload = {"app": load_app(), "thresholds": load_thresholds()}
    payload["app"].pop("threat_intel_key", None)
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


__all__ = [
    "APP_CONFIG", "AI_CONFIG", "THRESHOLDS", "COPY_DIR",
    "APP_DEFAULTS", "AI_DEFAULTS", "read_json",
    "load_app", "load_ai", "load_thresholds", "load_copy", "config_sha256",
]
