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

**文件名也走同一套规则**（审查阻塞 ①：同事常把抓包命名成目标 IP / 域名）。带扩展名的串
只把 stem 当文本脱敏、扩展名原样保留::

    192.168.1.100.pcap     -> 192.168.1.***#25c9.pcap
    www.company.com.pcap   -> w**.c******.com#37f4.pcap

路径变体（审查阻塞 ②）同样覆盖：``\\Users\\`` / ``/Users/``、``Documents and Settings``、
``%USERPROFILE%`` / ``%HOMEPATH%``、UNC ``\\\\host\\share``，以及前导零 IPv4
（``192.168.001.100`` 先归一化再判断）。用户名 / UNC 主机名分别变 ``<user>`` / ``<host>``，
不保留原文。

伪名后缀是 ``#`` + ``sha1(小写原文)`` 的前 4 位十六进制。同一对象每次得到同一个后缀
（便于统计「同一对端出现 N 次」），但**不能**从后缀反推原文，也还原不了被打码的段。

两条硬约束：

1. **幂等**：对已脱敏文本再跑一遍不会二次打码（``***`` / ``#a3f2`` / ``<user>`` 不会被再次匹配）；
2. **保守匹配**：端口、版本号、普通文件名（``faults_demo.json``）保持原样，只动已知的
   个人信息形态。``collect_tokens`` 收集被识别出的敏感原值，供 ``core/diagpack.py`` 在
   写 zip 前做「默认拒绝」的泄漏自检（SPEC 红线 4：宁可导出失败，不可泄露）。
"""
from __future__ import annotations

import hashlib
import ipaddress
import re

__all__ = ["collect_tokens", "mask_text", "mask_obj", "pseudonym"]

#: 这些「顶级域」实际上是文件名扩展名。域名正则会在 ``faults_demo.json`` /
#: ``docs/api-reference.md`` 里误把后两段当域名；命中本集合时只把扩展名之前的
#: **stem** 当域名/IP 处理，扩展名原样保留（审查阻塞 ①）。
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

#: 用户主目录下这些常见子目录**不是用户名**，``%USERPROFILE%\\AppData`` 不要误伤。
#: 其它未知子目录按「用户名段」处理（审查阻塞 ②：``%USERPROFILE%\\alice`` 必须消失）。
_PROFILE_KEEP = frozenset({
    "appdata", "desktop", "documents", "downloads", "pictures", "music",
    "videos", "onedrive", "favorites", "links", "contacts", "searches",
    "saved games", "3d objects", "source", "repos", "tmp", "temp",
    ".ssh", ".config", ".cache", ".vscode", ".git", ".gitconfig", ".npm",
})

#: 占位符本身就含这些词；收集 token 时跳过，避免自检把 ``<user>`` 当成泄漏。
_RESERVED_TOKENS = frozenset({"user", "host", "root", "home", "ipv6"})

#: 域名标签：字母数字开头结尾，中间允许连字符。
_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")

#: 点分四段 IP。前面不许再跟数字/点；后面允许句点或 ``.pcap`` 这类扩展名，
#: 但不许接 ``.5``（避免从 ``1.2.3.4.5`` 里截一段）。前导零由 ``_normalize_ipv4`` 归一化。
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")

#: IPv4-mapped IPv6（``::ffff:192.168.1.100``）。必须在 IPv4 规则前处理，
#: 否则会被 IPv4 先打码、再被 IPv6 截断成畸形串。
_IPV4_MAPPED_RE = re.compile(
    r"(?<![0-9A-Za-z:])::[Ff]{4}:(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

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

#: 邮箱：本地部分也属用户名（审查建议），域名部分复用域名规则。
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"(?P<local>[A-Za-z0-9._%+-]+)@"
    r"(?P<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})"
    r"(?![A-Za-z0-9-])"
)

#: 路径里允许出现的字符。``Documents and Settings`` 必须作为**一个**组件识别，
#: 否则含空格的用户目录分支永远不可达（审查阻塞 ②）。
_PATH_ATOM = (
    r"(?:<user>|<host>|(?i:Documents and Settings)"
    r"|[^\\/\s:*?\"<>|,;\r\n，。；：、（）【】《》]+)"
)

#: ``%USERPROFILE%`` / ``%HOMEPATH%``；可带一个后续组件（用于识别用户名段）。
_ENV_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?P<var>%(?:USERPROFILE|HOMEPATH)%)"
    r"(?:(?P<sep>[\\/]+)(?P<name>[^\\/\s:*?\"<>|,;\r\n，。；：、（）【】《》]+))?"
)

#: 任意位置的 ``\\Users\\alice`` / ``/Users/alice`` / ``\\Documents and Settings\\alice``。
_USER_DIR_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?P<pre>[\\/]+)"
    r"(?P<dir>(?i:Users|Documents\ and\ Settings))"
    r"(?P<sep>[\\/]+)"
    r"(?P<name>[^\\/\s:*?\"<>|,;\r\n，。；：、（）【】《》]+)"
)

#: UNC ``\\\\host\\share``：只抹主机名段（共享名不是账号信息，保留便于排障）。
#: 前面排除 ``:``，避免把 ``http://host`` 当成 UNC。
_UNC_RE = re.compile(
    r"(?<![A-Za-z0-9:\\/])"
    r"(?P<prefix>[\\/]{2})"
    r"(?P<host>[^\\/\s:*?\"<>|,;\r\n，。；：、（）【】《》]+)"
)

#: Windows 绝对路径（``C:\\...`` / ``C:/...``），允许正反斜杠混用。
_WIN_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?P<drive>[A-Za-z]):(?P<sep>[\\/]+)"
    r"(?P<body>" + _PATH_ATOM + r"(?:[\\/]+" + _PATH_ATOM + r")*)"
)

#: 占位符；自检扫描前先挖掉，避免 username 恰好叫 ``user`` 时把 ``<user>`` 当成泄漏。
_PLACEHOLDER_RE = re.compile(r"<(?:user|host|root|home|ipv6)>", re.IGNORECASE)


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


def collect_tokens(s: str) -> dict[str, str]:
    """扫描文本，返回 ``{原始敏感 token: 类别}``（供诊断包写 zip 前做泄漏自检）。

    识别范围与 :func:`mask_text` 一致：IPv4 / IPv6 / 域名 / MAC / 用户名 / UNC 主机名。
    只收集**确定会被替换**的 token（例如 ``999.999.999.999`` 这种非法 IP 不收集），
    因此不会因为日志里出现版本号而误报。

    Args:
        s: 待扫描文本（日志行、JSON 字段值、文件名都可以）。空串返回空字典。

    Returns:
        dict[str, str]: token → 类别；类别取值 ``ipv4`` / ``ipv6`` / ``domain`` /
        ``mac`` / ``user`` / ``host``。
    """
    tokens: dict[str, str] = {}
    if not s:
        return tokens
    text = str(s)

    for match in _ENV_PATH_RE.finditer(text):
        if _env_name_is_user(match):
            _remember(tokens, match.group("name"), "user")
    for match in _USER_DIR_RE.finditer(text):
        _remember(tokens, match.group("name"), "user")
    for match in _UNC_RE.finditer(text):
        _remember(tokens, match.group("host"), "host")
    for match in _EMAIL_RE.finditer(text):
        _remember(tokens, match.group("local"), "user")

    mapped_spans: list[tuple[int, int]] = []
    for match in _IPV4_MAPPED_RE.finditer(text):
        _remember(tokens, match.group(0), "ipv6")
        mapped_spans.append(match.span())

    for match in _MAC_RE.finditer(text):
        _remember(tokens, match.group(0), "mac")
    for match in _IPV6_RE.finditer(text):
        if any(start <= match.start() < end for start, end in mapped_spans):
            continue
        if _valid_ipv6(match.group(0)):
            _remember(tokens, match.group(0), "ipv6")
    for match in _IPV4_RE.finditer(text):
        if _normalize_ipv4(match.group(0)) is not None:
            _remember(tokens, match.group(0), "ipv4")

    for match in _DOMAIN_RE.finditer(text):
        parts = _domain_token_parts(match.group(0))
        if parts is not None:
            _remember(tokens, parts[0], "domain")
    return tokens


def mask_text(s: str, tokens: dict[str, str] | None = None) -> str:
    """把一段文本里的 IP / 域名 / 用户名 / MAC 全部替换成脱敏形态。

    Args:
        s: 待脱敏文本（日志行、JSON 字段值、报告正文、文件名都可以）。
        tokens: 可选收集器；传入 ``dict`` 时把识别到的原始敏感 token 写进去
            （供 ``core/diagpack.py`` 的泄漏自检使用），不传则不做收集。

    Returns:
        str: 脱敏后的文本。空串原样返回；已经脱敏过的文本再跑一遍结果不变（幂等）。
            端口、版本号、普通文件名等诊断必需信息保持原样。
    """
    if not s:
        return s
    raw = str(s)
    text = raw
    text = _ENV_PATH_RE.sub(_mask_env_path, text)
    text = _USER_DIR_RE.sub(_mask_user_dir, text)
    text = _UNC_RE.sub(_mask_unc, text)
    text = _WIN_PATH_RE.sub(_mask_path, text)
    text = _MAC_RE.sub(_mask_mac, text)
    text = _IPV4_MAPPED_RE.sub(_mask_ipv4_mapped, text)
    text = _IPV6_RE.sub(_mask_ipv6, text)
    text = _IPV4_RE.sub(_mask_ipv4, text)
    text = _EMAIL_RE.sub(_mask_email, text)
    text = _DOMAIN_RE.sub(_mask_domain, text)
    if tokens is not None:
        tokens.update(collect_tokens(raw))
    return text


def mask_obj(o, tokens: dict[str, str] | None = None):
    """递归脱敏 ``dict`` / ``list`` / ``tuple`` / ``str``，其它类型原样返回。

    用于 ``env.json`` 与 ``runs/*.json``：先 ``json.loads`` 成对象，处理完再序列化。
    **不修改入参**（返回新对象），这样调用方还能拿原始对象做别的判断。

    Args:
        o: 任意 JSON 兼容对象。
        tokens: 可选收集器；递归传给 :func:`mask_text`。

    Returns:
        object: 与入参同构的新对象；字符串值已按 :func:`mask_text` 脱敏。
    """
    if isinstance(o, str):
        return mask_text(o, tokens)
    if isinstance(o, dict):
        return {key: mask_obj(value, tokens) for key, value in o.items()}
    if isinstance(o, list):
        return [mask_obj(value, tokens) for value in o]
    if isinstance(o, tuple):
        return tuple(mask_obj(value, tokens) for value in o)
    return o


# ---------------------------------------------------------------- 内部工具
def _remember(tokens: dict[str, str], token: str, category: str) -> None:
    """把 token 记进收集器；占位符 / 过短用户名跳过（否则自检会自伤）。"""
    if not token:
        return
    low = token.lower()
    if "<" in token or ">" in token:
        return
    if category in ("user", "host"):
        if low in _RESERVED_TOKENS or len(token) < 2:
            return
    tokens.setdefault(token, category)


def _normalize_ipv4(text: str) -> str | None:
    """把 ``192.168.001.100`` 归一化成 ``192.168.1.100``；非法返回 ``None``。"""
    parts = text.split(".")
    if len(parts) != 4:
        return None
    try:
        numbers = [int(part) for part in parts]
    except ValueError:
        return None
    if any(number < 0 or number > 255 for number in numbers):
        return None
    return ".".join(str(number) for number in numbers)


def _valid_ipv6(text: str) -> bool:
    """``ipaddress`` 校验 IPv6；全是分隔符（如 ``::``）不算地址，避免误伤切片语法。"""
    if not re.search(r"[0-9A-Fa-f]", text):
        return False
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _is_domain_name(text: str) -> bool:
    """判断 ``text`` 是否是「至少两段、TLD 至少 2 个字母」的域名形态。"""
    labels = text.split(".")
    if len(labels) < 2:
        return False
    if not re.fullmatch(r"[A-Za-z]{2,24}", labels[-1]):
        return False
    if labels[-1].lower() in _FILE_TLDS:
        return False
    return all(_LABEL_RE.fullmatch(label) for label in labels)


def _domain_token_parts(text: str) -> tuple[str, str | None] | None:
    """返回 ``(需要脱敏的域名, 文件扩展名或 None)``；不是敏感对象返回 ``None``。

    带扩展名的串只把扩展名之前的 stem 当域名：``www.company.com.pcap`` →
    ``("www.company.com", "pcap")``；``faults_demo.json`` 的 stem 只有一段，返回 ``None``
    （普通文件名不误伤）。
    """
    labels = text.split(".")
    tld = labels[-1]
    if tld.lower() in _FILE_TLDS:
        stem = ".".join(labels[:-1])
        if len(labels) - 1 >= 2 and _is_domain_name(stem):
            return stem, tld
        return None
    if _is_domain_name(text):
        return text, None
    return None


def _mask_domain_text(text: str) -> str:
    """域名打码（含伪名），不带扩展名处理；调用方已确认它是域名。"""
    labels = text.split(".")
    masked = [label[:1] + "*" * (len(label) - 1) for label in labels[:-1]] + [labels[-1]]
    return ".".join(masked) + f"#{pseudonym(text)}"


def _is_filename_token(text: str) -> bool:
    """``x.log`` 这种有已知扩展名的串不是用户名（``%USERPROFILE%\\x.log`` 不误伤）。"""
    _, dot, suffix = text.rpartition(".")
    return bool(dot) and suffix.lower() in _FILE_TLDS


def _env_name_is_user(match: re.Match) -> bool:
    """``%USERPROFILE%\\alice`` 的 ``alice`` 是用户名；``%USERPROFILE%\\x.log`` 不是。"""
    name = match.group("name")
    if not name or name.lower() == "<user>":
        return False
    low = name.lower()
    return low not in _PROFILE_KEEP and not _is_filename_token(name)


# ---------------------------------------------------------------- 各规则实现
def _mask_ipv4(match: re.Match) -> str:
    """IPv4 打码：私有地址尾段 ``***``；公网地址后两段 ``***``（都带稳定伪名）。"""
    text = match.group(0)
    normalized = _normalize_ipv4(text)
    if normalized is None:
        return text  # 999.999.999.999 这类「长得像但不是 IP」的串不动
    addr = ipaddress.IPv4Address(normalized)
    suffix = f"#{pseudonym(normalized)}"
    parts = normalized.split(".")
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.***{suffix}"
    return f"{parts[0]}.{parts[1]}.***.***{suffix}"


def _mask_ipv4_mapped(match: re.Match) -> str:
    """IPv4-mapped IPv6 整段变 ``<ipv6>#伪名``（与 IPv6 规则一致，避免畸形串）。"""
    text = match.group(0)
    embedded = text.split(":")[-1]
    normalized = _normalize_ipv4(embedded)
    if normalized is None:
        return text
    return f"<ipv6>#{pseudonym('::ffff:' + normalized)}"


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
    if not _valid_ipv6(text):
        return text
    return f"<ipv6>#{pseudonym(text)}"


def _mask_domain(match: re.Match) -> str:
    """域名打码：每个标签留首字符、其余变 ``*``，顶级域保留，末尾加稳定伪名。

    带扩展名时只脱敏 stem、扩展名原样拼回（``www.company.com.pcap`` 不再整串放过）。
    """
    parts = _domain_token_parts(match.group(0))
    if parts is None:
        return match.group(0)  # 普通文件名不是域名
    domain, extension = parts
    masked = _mask_domain_text(domain)
    return f"{masked}.{extension}" if extension else masked


def _mask_email(match: re.Match) -> str:
    """邮箱：本地部分换 ``<user>``，域名部分按域名规则脱敏。"""
    domain = match.group("domain")
    return f"<user>@{_mask_domain_text(domain)}"


def _mask_env_path(match: re.Match) -> str:
    """``%USERPROFILE%`` / ``%HOMEPATH%`` → ``<home>``；紧跟的用户名段 → ``<user>``。"""
    sep = match.group("sep")
    name = match.group("name")
    if not sep or not name:
        return "<home>"
    if _env_name_is_user(match):
        return f"<home>{sep}<user>"
    return f"<home>{sep}{name}"


def _mask_user_dir(match: re.Match) -> str:
    """``\\Users\\alice`` / ``\\Documents and Settings\\alice`` 的用户名段 → ``<user>``。"""
    return f"{match.group('pre')}{match.group('dir')}{match.group('sep')}<user>"


def _mask_unc(match: re.Match) -> str:
    """UNC 主机名段 → ``<host>``（``\\\\fileserver\\share\\z`` → ``\\\\<host>\\share\\z``）。"""
    return f"{match.group('prefix')}<host>"


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
            if parts[index + 1].lower() == "<user>":
                return f"{drive}:{sep}" + sep.join(parts)
            kept = parts[:index + 1] + ["<user>"] + parts[index + 2:]
            return f"{drive}:{sep}" + sep.join(kept)
    if not parts:
        return "<root>"
    kept = parts[-2:]
    return "<root>" + sep + sep.join(kept)
