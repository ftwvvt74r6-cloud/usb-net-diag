"""诊断包脱敏：把日志里的 IP、域名、用户名、MAC 换成**不可还原**的伪名。

为什么要有这一层（M2）：诊断包必须发回给维护者定位问题，但不能泄露对方的内网
拓扑、机器目录和账号。``core/diagpack.py`` 在写 zip **之前**调用这里的纯函数；本模块
不读文件、不开 socket、不发任何请求（SPEC V8：诊断包导出绝不联网）。

规则（``mask_text`` 一次处理完，顺序固定）::

    192.168.1.100          -> 192.168.1.***#a3f2        私有地址：尾段打码
    8.8.8.8                -> 8.8.***.***#b5c1          公网地址：后两段打码
    www.company.com        -> w**.c******.com#9d0e      域名：每段留首字符、顶级域保留
    C:\\Users\\alice\\x.log  -> C:\\Users\\<user>\\x.log   用户目录：用户名换 <user>
    aa:bb:cc:dd:ee:ff      -> aa:bb:cc:**:**:**#4e2a    MAC：尾 3 字节打码
    D:\\build\\NetDiag\\tshark.exe -> <root>\\NetDiag\\tshark.exe  其它绝对路径：盘符与上层目录隐去

伪名后缀是 ``#`` + ``sha1(小写原文)`` 的前 4 位十六进制。同一对象每次得到同一个后缀
（便于统计「同一对端出现 N 次」），但**不能**从后缀反推原文，也还原不了被打码的段。

两条硬约束：

1. **幂等**：对已脱敏文本再跑一遍不会二次打码（``***`` / ``#a3f2`` 不会被再次匹配）；
2. **保守匹配**：端口、版本号、文件名（``faults_demo.json``）保持原样，只动已知的
   个人信息形态。调用方 ``core/diagpack.py`` 一旦发现脱敏抛异常就**跳过该文件**，
   绝不静默导出原文（SPEC 红线 4）。
"""
from __future__ import annotations

import hashlib
import ipaddress
import re

__all__ = ["mask_text", "mask_obj", "pseudonym"]

#: 这些「顶级域」实际上是文件名扩展名。域名正则会在 ``faults_demo.json`` /
#: ``docs/api-reference.md`` 里误把后两段当域名，命中本集合就按文件名处理（SPEC 陷阱 4）。
_FILE_TLDS = frozenset({
    "json", "log", "md", "txt", "pcap", "pcapng", "cap", "exe", "dll", "sys",
    "py", "pyc", "pyo", "html", "htm", "css", "js", "mjs", "ts", "jsx", "tsx",
    "zip", "gz", "tgz", "tar", "rar", "7z", "ini", "cfg", "conf", "yaml", "yml",
    "xml", "csv", "tsv", "bat", "cmd", "vbs", "ps1", "sh", "ico", "png", "jpg",
    "jpeg", "gif", "bmp", "svg", "webp", "tmp", "bak", "db", "sqlite", "pem",
    "key", "crt", "cer", "dat", "bin", "msi", "jar", "whl", "egg", "lock",
    "toml", "map", "woff", "woff2", "ttf", "otf", "eot", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "mp4", "avi", "mkv", "mp3", "wav",
})

#: 点分四段 IP。前后都不许再跟数字/点，避免从 ``1.2.3.4.5`` 里截一段出来。
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

#: 6 组、每组 2 位十六进制、同一种分隔符（``:`` 或 ``-``）。前后不许再跟十六进制/分隔符。
_MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:-])"
    r"(?P<b0>[0-9A-Fa-f]{2})(?P<sep>[:-])"
    r"(?P<b1>[0-9A-Fa-f]{2})(?P=sep)"
    r"(?P<b2>[0-9A-Fa-f]{2})(?P=sep)"
    r"(?P<b3>[0-9A-Fa-f]{2})(?P=sep)"
    r"(?P<b4>[0-9A-Fa-f]{2})(?P=sep)"
    r"(?P<b5>[0-9A-Fa-f]{2})"
    r"(?![0-9A-Fa-f:-])"
)

#: IPv6 候选（先宽匹配，再用 ``ipaddress`` 校验；非法串原样返回）。
_IPV6_RE = re.compile(
    r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])"
)

#: 域名：至少两段，标签只含字母数字与连字符，TLD 至少 2 个字母。
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?P<tld>[A-Za-z]{2,24})"
    r"(?![A-Za-z0-9-])"
)

#: 单个路径组件：普通目录名，或**已脱敏的用户占位符** ``<user>``
#: （后者必须显式允许，否则 ``C:\Users\<user>`` 会被二次处理成 ``<root>\Users\<user>``，
#: 破坏「脱敏幂等」）。
_PATH_COMPONENT = r"(?:<user>|[^\\/\s:*?\"<>|,;\r\n，。；：、（）【】《》]+)"

#: Windows 绝对路径（``C:\...`` / ``C:/...``）。组件里不含空白与常见标点，
#: 保证「路径后面跟着一句中文」时不会把整句话吞掉。
_WIN_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?P<drive>[A-Za-z]):(?P<sep>[\\/]+)"
    r"(?P<body>" + _PATH_COMPONENT + r"(?:(?P=sep)" + _PATH_COMPONENT + r")*)"
)


# ---------------------------------------------------------------- 公共接口
def pseudonym(s: str) -> str:
    """返回稳定伪名：``sha1(小写原文)`` 的前 4 位十六进制。

    Args:
        s: 原文（IP / 域名 / MAC）。空串返回空串。

    Returns:
        str: 4 位小写十六进制。同一原文永远得到同一个值；不同原文可能碰撞，
            这里只用于「看得出是不是同一个对象」，不作为身份凭据。
    """
    if not s:
        return ""
    return hashlib.sha1(str(s).lower().encode("utf-8")).hexdigest()[:4]


def mask_text(s: str) -> str:
    """把一段文本里的 IP / 域名 / 用户名 / MAC 全部替换成脱敏形态。

    Args:
        s: 待脱敏文本（日志行、JSON 字段值、报告正文都可以）。

    Returns:
        str: 脱敏后的文本。空串原样返回；已经脱敏过的文本再跑一遍结果不变（幂等）。
            端口、版本号、文件名等诊断必需信息保持原样。
    """
    if not s:
        return s
    text = str(s)
    text = _WIN_PATH_RE.sub(_mask_path, text)
    text = _MAC_RE.sub(_mask_mac, text)
    text = _IPV4_RE.sub(_mask_ipv4, text)
    text = _IPV6_RE.sub(_mask_ipv6, text)
    text = _DOMAIN_RE.sub(_mask_domain, text)
    return text


def mask_obj(o):
    """递归脱敏 ``dict`` / ``list`` / ``tuple`` / ``str``，其它类型原样返回。

    用于 ``env.json`` 与 ``runs/*.json``：先 ``json.loads`` 成对象，处理完再序列化。
    **不修改入参**（返回新对象），这样调用方还能拿原始对象做别的判断。

    Args:
        o: 任意 JSON 兼容对象。

    Returns:
        object: 与入参同构的新对象；字符串值已按 :func:`mask_text` 脱敏。
    """
    if isinstance(o, str):
        return mask_text(o)
    if isinstance(o, dict):
        return {key: mask_obj(value) for key, value in o.items()}
    if isinstance(o, list):
        return [mask_obj(value) for value in o]
    if isinstance(o, tuple):
        return tuple(mask_obj(value) for value in o)
    return o


# ---------------------------------------------------------------- 各规则实现
def _mask_ipv4(match: re.Match) -> str:
    """IPv4 打码：私有地址尾段 ``***``；公网地址后两段 ``***``（都带稳定伪名）。"""
    text = match.group(0)
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        return text  # 999.999.999.999 这类「长得像但不是 IP」的串不动
    suffix = f"#{pseudonym(text)}"
    parts = text.split(".")
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.***{suffix}"
    return f"{parts[0]}.{parts[1]}.***.***{suffix}"


def _mask_mac(match: re.Match) -> str:
    """MAC 打码：保留前 3 字节（厂商标识），尾 3 字节换成 ``**`` 并带稳定伪名。"""
    text = match.group(0)
    sep = match.group("sep")
    head = sep.join((match.group("b0"), match.group("b1"), match.group("b2")))
    tail = sep.join(("**", "**", "**"))
    return f"{head}{sep}{tail}#{pseudonym(text)}"


def _mask_ipv6(match: re.Match) -> str:
    """IPv6 打码：整段换成 ``<ipv6>#伪名``（地址前缀也可能定位到单位，宁可全隐）。"""
    text = match.group(0)
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return text
    return f"<ipv6>#{pseudonym(text)}"


def _mask_domain(match: re.Match) -> str:
    """域名打码：每个标签留首字符、其余变 ``*``，顶级域保留，末尾加稳定伪名。"""
    text = match.group(0)
    labels = text.split(".")
    tld = labels[-1]
    if tld.lower() in _FILE_TLDS:
        return text  # 文件名不是域名
    masked = [label[:1] + "*" * (len(label) - 1) for label in labels[:-1]] + [tld]
    return ".".join(masked) + f"#{pseudonym(text)}"


def _mask_path(match: re.Match) -> str:
    """Windows 绝对路径：用户目录保留 ``C:\\Users\\<user>``，其余只留最后两段。

    ``env.json`` 的 ``tshark_path`` 是本机绝对路径，必须变成 ``<root>\\...`` 形式
    （SPEC 陷阱 3）：既说明「它在工具目录下」，又不暴露盘符和上层目录。
    """
    drive = match.group("drive")
    sep = match.group("sep")
    parts = [part for part in re.split(r"[\\/]+", match.group("body")) if part]
    lowered = [part.lower() for part in parts]
    for index, part in enumerate(lowered):
        if part in ("users", "documents and settings") and index + 1 < len(parts):
            kept = parts[:index + 1] + ["<user>"] + parts[index + 2:]
            return f"{drive}:{sep}" + sep.join(kept)
    if not parts:
        return "<root>"
    kept = parts[-2:]
    return "<root>" + sep + sep.join(kept)
