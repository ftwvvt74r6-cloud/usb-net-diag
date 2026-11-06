"""出口脱敏。**唯一**允许构造「要发出去的数据」的地方。

对应评审第 3 步的结论：脱敏不是「送进 ai.py 之前」那一个点，而是**每个外发出口**：

    Verdict ─┬─► Markdown / JSON（本地，默认明文）
             ├─► AI 请求（云）      ← 本模块
             ├─► 日志 / 导出        ← 本模块
             └─► MCP 返回（Agent）  ← 本模块

三条设计原则（与规划原方案不同）：

1. **可逆伪名化 > 全掩码**。``192.168.1.100`` → ``<ip:lan-3>``，映射表只存本地。
   运维要能照着报告回查，全掩码等于把报告的可用性砍掉一半。
2. **保留结构特征**。端口、方向、帧序、协议、时序全部保留 —— 这些才是模型判断的依据。
   只替换「标识」，不替换「形态」。
3. **推断不越权**。域名保留末两级（``corp.example.com``）以便模型区分
   「同一站点」还是「到处都慢」，只把可识别的前缀换成短哈希。

用法::

    from core.egress.sanitize import Policy, Profile, sanitize, verify

    policy = Policy.preset(Profile.CLOUD_MASK)
    safe, ledger = sanitize(payload, policy)
    assert not verify(safe, ["192.168.1.100", "password"])
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

#: URL/查询串里出现的敏感键（命中即抹值，保留键名便于定位）。
SECRET_KEY_HINTS: tuple[str, ...] = (
    "password", "passwd", "pwd", "pass", "token", "secret", "api_key", "apikey",
    "api-key", "access_key", "session", "sessionid", "cookie", "authorization",
    "auth", "sig", "signature", "credential",
)

#: 请求/响应头里的敏感键。
SECRET_HEADERS: tuple[str, ...] = (
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "www-authenticate",
)

#: 这些「后缀」是文件名，不是域名——避免把 ``diag_x.pcapng`` 当成主机名抹掉。
FILE_SUFFIXES: frozenset[str] = frozenset({
    "pcap", "pcapng", "cap", "md", "json", "log", "txt", "csv", "html", "htm",
    "js", "css", "py", "exe", "dll", "pyd", "bat", "ps1", "tmp", "bak", "zip",
    "docx", "xlsx", "pptx", "pdf", "png", "jpg", "ico", "yaml", "yml", "ini",
})


class Profile(str, Enum):
    """脱敏档位。UI/配置里只暴露这三个字符串。"""

    LOCAL = "local"            # 不外发：本地报告、本地日志
    LAN_MASK = "lan_mask"      # 只遮私网 IP，保留域名/公网 IP
    CLOUD_MASK = "cloud_mask"  # 私网+公网 IP 都遮，域名前缀哈希（默认）


@dataclass(frozen=True)
class Policy:
    profile: Profile = Profile.CLOUD_MASK
    mask_private_ips: bool = True
    mask_public_ips: bool = True
    keep_ports: bool = True
    renumber_frames: bool = False      # True 时把帧号换成相对序号（需调用方给 total）
    hash_hosts: bool = True
    keep_host_suffix_labels: int = 2
    redact_secret_kv: bool = True
    redact_headers: bool = True
    max_string_len: int = 4000
    salt: str = "usb-net-diag"

    @classmethod
    def preset(cls, profile: Profile | str) -> "Policy":
        p = Profile(profile)
        if p is Profile.LOCAL:
            return cls(profile=p, mask_private_ips=False, mask_public_ips=False,
                       hash_hosts=False, redact_secret_kv=True, redact_headers=True)
        if p is Profile.LAN_MASK:
            return cls(profile=p, mask_private_ips=True, mask_public_ips=False,
                       hash_hosts=False, redact_secret_kv=True, redact_headers=True)
        return cls(profile=p, mask_private_ips=True, mask_public_ips=True,
                   hash_hosts=True, redact_secret_kv=True, redact_headers=True)


@dataclass
class Ledger:
    """伪名化账本。**只存本地**，用于还原与审计；默认不随报告外发。"""

    profile: str = ""
    ip: dict[str, str] = field(default_factory=dict)     # token -> 原值
    host: dict[str, str] = field(default_factory=dict)   # token -> 原值
    entries: list[dict] = field(default_factory=list)
    #: 每类 token 的递增序号，保证同一次外发里编号稳定
    seq: dict[str, int] = field(default_factory=dict)

    def next_index(self, bucket: str) -> int:
        self.seq[bucket] = self.seq.get(bucket, 0) + 1
        return self.seq[bucket]

    def note(self, kind: str, token: str, original: str) -> None:
        self.entries.append({"kind": kind, "token": token, "original": original})

    @property
    def count(self) -> int:
        return len(self.entries)

    def to_dict(self) -> dict:
        return {"profile": self.profile, "count": self.count,
                "ip": dict(self.ip), "host": dict(self.host)}

    def resolve(self, token: str) -> str | None:
        return self.ip.get(token) or self.host.get(token)


# ---------------------------------------------------------------- 正则

_IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?![\d.])")
#: 主机名/域名：至少两级，末级为 2~24 个字母；前后不能紧邻标识符字符。
_HOST_RE = re.compile(
    r"(?<![@\w.\-])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![-\w])",
    re.IGNORECASE,
)
#: 形如 ``password=xxx`` / ``"token": "xxx"`` 的键值对。
_KV_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(k) for k in SECRET_KEY_HINTS) + r")"
    r"(\s*[=:]\s*)(\"?)([^&\s\"',;}]+)(\3)"
)

REDACTED = "[REDACTED]"


# ---------------------------------------------------------------- 内部工具


def _short_hash(text: str, salt: str) -> str:
    return hashlib.sha1(f"{salt}:{text}".encode("utf-8")).hexdigest()[:4]


def _is_private(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return True


def _mask_ip(match: re.Match, policy: Policy, ledger: Ledger) -> str:
    ip, port = match.group(1), match.group(2)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return match.group(0)

    private = _is_private(ip)
    if private and not policy.mask_private_ips:
        return match.group(0)
    if not private and not policy.mask_public_ips:
        return match.group(0)

    bucket = "lan" if private else "pub"
    token = f"<ip:{bucket}-{ledger.next_index(bucket)}>"
    ledger.ip[token] = ip
    ledger.note("ip", token, ip)
    suffix = f":{port}" if (port and policy.keep_ports) else ""
    return token + suffix


def _mask_host(match: re.Match, policy: Policy, ledger: Ledger, env: str) -> str:
    host = match.group(1)
    labels = host.split(".")
    if labels[-1].lower() in FILE_SUFFIXES:      # 文件名，不是主机名
        return host
    if host.lower() in env.lower():              # 本机名，单独处理
        return host

    keep = max(0, int(policy.keep_host_suffix_labels))
    suffix = ".".join(labels[-keep:]) if keep else ""
    token = f"<host:{_short_hash(host, policy.salt)}>"
    ledger.host[token] = host
    ledger.note("host", token, host)
    return f"{token}.{suffix}" if suffix else token


def _redact_kv(text: str) -> str:
    return _KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED}{m.group(5)}", text)


def mask_text(text: str, policy: Policy, ledger: Ledger, env_host: str = "") -> str:
    """对一段自由文本做脱敏。这是所有出口的公共底座。"""
    if not isinstance(text, str) or not text:
        return text
    out = text
    if policy.redact_secret_kv:
        out = _redact_kv(out)
    if policy.mask_private_ips or policy.mask_public_ips:
        out = _IP_RE.sub(lambda m: _mask_ip(m, policy, ledger), out)
    if policy.hash_hosts:
        out = _HOST_RE.sub(lambda m: _mask_host(m, policy, ledger, env_host), out)
    if len(out) > policy.max_string_len:
        out = out[: policy.max_string_len] + "…[TRUNCATED]"
    return out


# ---------------------------------------------------------------- 主入口


def sanitize(obj: Any, policy: Policy | Profile | str | None = None,
             ledger: Ledger | None = None, env_host: str = "") -> tuple[Any, Ledger]:
    """递归脱敏任意 JSON-able 结构，返回 ``(safe_obj, ledger)``。

    * 不修改入参（深拷贝结果）；
    * ``dict`` 的**键名保留**（结构对模型有用），只处理值与敏感键；
    * 敏感键（``authorization`` / ``cookie`` / ``password`` 等）整值替换。
    """
    if not isinstance(policy, Policy):
        policy = Policy.preset(policy or Profile.CLOUD_MASK)
    ledger = ledger or Ledger(profile=policy.profile.value)

    def walk(node: Any, key_hint: str = "") -> Any:
        if isinstance(node, Mapping):
            out: dict[str, Any] = {}
            for key, value in node.items():
                name = str(key)
                lowered = name.lower()
                if (policy.redact_headers and lowered in SECRET_HEADERS) or (
                        policy.redact_secret_kv and lowered in SECRET_KEY_HINTS):
                    out[name] = REDACTED
                    ledger.note("field", name, "(redacted)")
                    continue
                out[name] = walk(value, lowered)
            return out
        if isinstance(node, (list, tuple)):
            return [walk(v, key_hint) for v in node]
        if isinstance(node, str):
            return mask_text(node, policy, ledger, env_host)
        return node

    return walk(obj), ledger


def sanitize_for_log(line: str, policy: Policy | Profile | str = Profile.LAN_MASK) -> str:
    """日志用：默认只遮私网 IP + 密钥串，保留域名（本地排障需要）。"""
    pol = policy if isinstance(policy, Policy) else Policy.preset(policy)
    safe, _ = sanitize(line, pol)
    return str(safe)


def verify(sanitized: Any, secrets: Sequence[str], *, text: bool = False) -> list[str]:
    """验收断言：返回**仍然出现**的敏感串（空列表 = 通过）。

    评审要求「双断言」中的正向这一半；反向（结论不变）由调用方对比 findings 完成。
    """
    blob = sanitized if isinstance(sanitized, str) else repr(sanitized)
    return [s for s in secrets if s and s in blob]


__all__ = [
    "Profile", "Policy", "Ledger", "REDACTED",
    "SECRET_KEY_HINTS", "SECRET_HEADERS", "FILE_SUFFIXES",
    "sanitize", "sanitize_for_log", "mask_text", "verify",
]
