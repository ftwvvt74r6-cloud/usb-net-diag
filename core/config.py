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
import os
from pathlib import Path
from typing import Any, Mapping

from .platform import paths

APP_CONFIG = paths.PATHS.config / "app-config.json"
AI_CONFIG = paths.PATHS.config / "ai-config.json"
#: 用户手填的组件路径（``POST /api/selfcheck/path`` 写入）：tshark / python 各一条。
#: 不写 .env、不把绝对路径提交进仓库 —— 这是 U 盘便携场景下「这台机器上的路径」，
#: 属于本地 config，与 ai-config 同一类。
PATHS_CONFIG = paths.PATHS.config / "paths.json"
#: 常驻采集 agent 的配置（采样间隔 / 监测目标 / 事件阈值）。
#: 与 app-config 分开的理由：agent 由**独立进程**（pythonw）读取，
#: 而 app-config 是界面进程的配置；两者改一个不该牵动另一个。
AGENT_CONFIG = paths.PATHS.config / "agent.json"
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

#: 手填路径的默认值：空串 = 未指定（走自动查找）。只有 ``tshark_path`` 与
#: ``python_path`` 两个键 —— scapy / npcap 不能靠路径指定（scapy 需 pip 安装、
#: npcap 需运行安装器），前端提交这两项会拿到 400 unsupported_key。
PATH_DEFAULTS: dict[str, Any] = {
    "tshark_path": "",
    "python_path": "",
}

#: 采样间隔的合法取值（秒）。不在这个集合里的值一律回落默认值 —— 间隔 1 秒会把
#: 本机 DNS / 网关打成压力测试，间隔 600 秒又让「事件」失去意义，所以只给四档。
AGENT_INTERVAL_CHOICES: tuple[int, ...] = (5, 10, 30, 60)

#: 监测目标上限。常驻 agent 每轮对所有目标各发一组探测包，目标越多越吵；
#: 3 个足够覆盖「网关 → 运营商 → 业务」三段。
AGENT_MAX_TARGETS = 3

AGENT_DEFAULTS: dict[str, Any] = {
    "interval_s": 10,
    #: [{"key": "公司官网", "host": "example.com", "port": 443}]；port 省略 = ICMP
    "targets": [],
    #: 事件阈值：连续 2 次超阈值才落一条事件（见 core/agent.py::EventTracker）
    "thresholds": {"rtt_ms": 120.0, "jitter_ms": 40.0, "loss_pct": 2.0},
    "retain_days": 7,
    "event_retain_days": 30,
    #: 单轮每目标发几个探测包（ICMP echo / TCP SYN 各算一个）
    "icmp_count": 2,
    "icmp_timeout_ms": 800,
    "tcp_timeout_s": 1.5,
}


def read_json(path: Path, default: Mapping[str, Any] | None = None) -> dict:
    """读 JSON 文件，缺失或损坏一律回退默认值。

    U 盘场景里配置文件被拔盘截断、被杀软删都是常事，这里**绝不抛异常** ——
    否则一个坏文件就能让整个工具起不来。

    Args:
        path: 目标文件路径。
        default: 基础默认值；文件里存在的键会覆盖它（值为 ``None`` 的键跳过，避免把默认值抹掉）。

    Returns:
        dict: 合并结果。文件不存在 / 不是合法 JSON / 顶层不是对象时，原样返回默认值副本。
    """
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
    """加载 ``config/app-config.json``（用户可改的那份）。

    Returns:
        dict: 已做类型收敛的配置。键见 :data:`APP_DEFAULTS`
            （``server_port`` / ``default_duration`` / ``max_duration`` /
            ``threat_intel_key`` / ``auto_open_browser`` / ``idle_exit_min`` 等）。
            端口非法时回落 8787；``sufficiency`` 与默认值深合并。
    """
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
    """加载 ``config/ai-config.json``（AI 接口地址与 Key）。

    Returns:
        dict: 键见 :data:`AI_DEFAULTS`（``provider`` / ``base_url`` / ``api_key`` /
            ``model`` / ``temperature`` / ``timeout`` / ``verify_ssl``）。
            文件缺失时返回默认值，``api_key`` 为空表示未配置。
    """
    return read_json(AI_CONFIG, AI_DEFAULTS)


def load_paths() -> dict:
    """加载用户手填的组件路径 ``config/paths.json``（``POST /api/selfcheck/path`` 写入）。

    与 :func:`load_ai` 同源：缺文件 / 损坏一律回退默认值（空串），绝不让自检
    因一个坏文件崩掉。空串表示「未手填」，自检回落到自动查找。

    Returns:
        dict: 键 ``tshark_path`` / ``python_path``，值为字符串（可能为空）。
    """
    return read_json(PATHS_CONFIG, PATH_DEFAULTS)


def save_paths(patch: dict) -> dict:
    """把用户手填的组件路径合并进 ``config/paths.json`` 并原子落盘。

    只接受白名单内的键（``tshark_path`` / ``python_path``），其余键丢弃 ——
    避免前端误传把配置写脏。``None`` 值跳过（同 :func:`read_json` 的口径）。

    Args:
        patch: 只含需要改的键（如 ``{"tshark_path": "C:\\\\...\\\\tshark.exe"}``）。

    Returns:
        dict: 写回后的完整路径配置。
    """
    cfg = load_paths()
    for key in PATH_DEFAULTS:
        value = patch.get(key)
        if value is not None:
            cfg[key] = str(value)
    PATHS_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    PATHS_CONFIG.write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return cfg


def agent_config_path() -> Path:
    """常驻 agent 配置文件的真实路径（允许测试重定向）。

    Returns:
        Path: 环境变量 ``NETDIAG_AGENT_CONFIG`` 非空时用它，否则 ``config/agent.json``。
            与 ``logstore.log_root()`` 认 ``NETDIAG_LOG_DIR`` 是同一套约定：
            测试注入临时文件，绝不写仓库 ``config/``。
    """
    raw = (os.environ.get("NETDIAG_AGENT_CONFIG") or "").strip()
    return Path(raw) if raw else AGENT_CONFIG


def _norm_interval(value: Any, *, strict: bool = False) -> int:
    """把采样间隔收敛到 :data:`AGENT_INTERVAL_CHOICES`。

    Args:
        value: 用户填的值（可能是字符串 ``"30"``、浮点 ``30.0`` 或非法值 ``7``）。
        strict: ``True`` 时非法值抛 ``ValueError``（写配置用：显式动作必须报错）；
            为 ``False`` 时回落默认值（读配置用：坏文件不该让 agent 起不来）。

    Returns:
        int: 合法间隔（5 / 10 / 30 / 60）。

    Raises:
        ValueError: ``strict=True`` 且值不在合法集合内。
    """
    try:
        got = int(float(value))
    except (TypeError, ValueError):
        got = None
    if got in AGENT_INTERVAL_CHOICES:
        return got
    if strict:
        raise ValueError(
            f"采样间隔必须是 {list(AGENT_INTERVAL_CHOICES)} 之一，收到 {value!r}")
    return int(AGENT_DEFAULTS["interval_s"])


def _norm_targets(raw: Any) -> list[dict]:
    """归一化监测目标列表：最多 :data:`AGENT_MAX_TARGETS` 个，只留 ``key``/``host``/``port``。

    接受两种写法：字符串（``"example.com"``）或对象
    （``{"key": "...", "host": "...", "port": 443}``）。没有 ``host`` 的条目丢弃，
    ``port`` 非法（非数字 / 越界 / 0）时按「无端口」处理 —— 也就是走 ICMP。

    Args:
        raw: 配置里的 ``targets`` 原值（任何类型都可能，坏数据不能崩）。

    Returns:
        list[dict]: 每项 ``{"key": str, "host": str, "port": int|None}``；
            没有 ``port`` 的条目**不带** ``port`` 键（避免下游把 ``None`` 当端口）。
    """
    out: list[dict] = []
    if not isinstance(raw, list):
        return out
    for i, item in enumerate(raw):
        if len(out) >= AGENT_MAX_TARGETS:
            break
        if isinstance(item, str):
            item = {"host": item}
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "").strip()
        if not host:
            continue
        entry: dict[str, Any] = {
            "key": str(item.get("key") or "").strip() or f"target-{i + 1}",
            "host": host,
        }
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            port = 0
        if 1 <= port <= 65535:
            entry["port"] = port
        out.append(entry)
    return out


def load_agent() -> dict:
    """加载 ``config/agent.json``（常驻采集 agent 的配置）。

    读路径**永不抛异常**：agent 是后台进程，一个坏配置不该让它起不来。
    非法间隔回落默认、目标超 3 个截断、阈值缺键用默认补齐。

    Returns:
        dict: 键见 :data:`AGENT_DEFAULTS`；``thresholds`` 已与默认值深合并，
            所以调用方可以只关心 ``cfg["thresholds"]["rtt_ms"]`` 一定存在。
    """
    cfg = read_json(agent_config_path(), AGENT_DEFAULTS)
    cfg["interval_s"] = _norm_interval(cfg.get("interval_s"))
    cfg["targets"] = _norm_targets(cfg.get("targets"))
    merged = dict(AGENT_DEFAULTS["thresholds"])
    if isinstance(cfg.get("thresholds"), dict):
        for key, value in cfg["thresholds"].items():
            if key not in merged:
                continue
            try:
                merged[key] = float(value)
            except (TypeError, ValueError):
                continue
    cfg["thresholds"] = merged
    for key in ("retain_days", "event_retain_days", "icmp_count"):
        try:
            cfg[key] = int(cfg.get(key, AGENT_DEFAULTS[key]))
        except (TypeError, ValueError):
            cfg[key] = AGENT_DEFAULTS[key]
    for key in ("icmp_timeout_ms", "tcp_timeout_s"):
        try:
            cfg[key] = float(cfg.get(key, AGENT_DEFAULTS[key]))
        except (TypeError, ValueError):
            cfg[key] = AGENT_DEFAULTS[key]
    cfg["retain_days"] = max(1, cfg["retain_days"])
    cfg["event_retain_days"] = max(1, cfg["event_retain_days"])
    cfg["icmp_count"] = max(1, min(10, cfg["icmp_count"]))
    return cfg


def save_agent(patch: dict) -> dict:
    """把 agent 配置合并进 ``config/agent.json`` 并原子落盘。

    只接受 :data:`AGENT_DEFAULTS` 里的键（其余丢弃，避免前端/脚本写脏配置）。
    ``targets`` 会被归一化（超 3 个截断），``interval_s`` 非法时**抛异常**而不是
    静默改成默认 —— 「我刚把间隔改成 7，它却还是 10」比报错更难查。

    Args:
        patch: 只含需要改的键，如 ``{"interval_s": 30}``。

    Returns:
        dict: 写回后的完整配置（与 :func:`load_agent` 同构）。

    Raises:
        ValueError: ``interval_s`` 不在 :data:`AGENT_INTERVAL_CHOICES` 内。
        OSError: 目标目录不可写。
    """
    cfg = load_agent()
    for key in AGENT_DEFAULTS:
        if key not in patch or patch[key] is None:
            continue
        if key == "interval_s":
            cfg["interval_s"] = _norm_interval(patch[key], strict=True)
        elif key == "targets":
            cfg["targets"] = _norm_targets(patch[key])
        elif key == "thresholds":
            merged = dict(cfg["thresholds"])
            if isinstance(patch[key], dict):
                for tkey, value in patch[key].items():
                    if tkey in merged:
                        try:
                            merged[tkey] = float(value)
                        except (TypeError, ValueError):
                            continue
            cfg["thresholds"] = merged
        else:
            cfg[key] = patch[key]
    path = agent_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return load_agent()


def load_thresholds() -> dict:
    """加载规则阈值 ``core/rules/thresholds.json``（随代码走，不属于用户配置）。

    Returns:
        dict: 阈值表。缺失时返回空表 —— 规则会因 ``requires`` 未满足而跳过，
            而不是拿 0 当阈值瞎判。
    """
    return read_json(THRESHOLDS, {})


def load_copy(lang: str = "zh-CN") -> dict:
    """加载文案表 ``core/copy/zh-CN.json``。

    Args:
        lang: 语言代码，对应 ``core/copy/<lang>.json``。

    Returns:
        dict: 文案 key → 文本。缺失时返回空表，渲染层回退成显示 ``rule_id`` 本身（不崩）。
    """
    return read_json(COPY_DIR / f"{lang}.json", {})


def config_sha256() -> str:
    """把「影响结论的配置」一起哈希，写进 ``Provenance``。

    只覆盖 app 配置与阈值，**不哈希 AI Key** —— 避免把密钥指纹写进报告，
    也避免「换了 Key 就说结论不可复现」。

    Returns:
        str: 16 位十六进制摘要。同一份配置恒等，改任意阈值即变。
    """
    payload = {"app": load_app(), "thresholds": load_thresholds()}
    payload["app"].pop("threat_intel_key", None)
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


__all__ = [
    "APP_CONFIG", "AI_CONFIG", "PATHS_CONFIG", "AGENT_CONFIG",
    "THRESHOLDS", "COPY_DIR",
    "APP_DEFAULTS", "AI_DEFAULTS", "PATH_DEFAULTS",
    "AGENT_DEFAULTS", "AGENT_INTERVAL_CHOICES", "AGENT_MAX_TARGETS",
    "read_json",
    "load_app", "load_ai", "load_paths", "save_paths",
    "agent_config_path", "load_agent", "save_agent",
    "load_thresholds", "load_copy", "config_sha256",
]
