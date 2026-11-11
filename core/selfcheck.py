"""首屏「准备检查」的六项只读环境检查 + 首次运行标记（C2 + G2）。

这个模块只回答一个问题：**这台机器现在能不能直接用**。它被三块代码调用：

* ``GET /api/selfcheck``（界面首屏 / 「重新检测」按钮）—— 返回六项检查结果；
* ``GET /api/app``（首屏先拿应用信息）—— 复用同一份检查结果里的能力矩阵；
* ``POST /api/selfcheck/ack``（用户看过面板后）—— 写 ``config/ui-first-run.json``。

六项按固定顺序：Python / tshark / Npcap / **scapy** / 端口 / 管理员权限。scapy
这一项不是「必须装」：缺它时逐跳会自动降级为系统 tracert（样本少、精度低），
所以文案只解释影响，不给安装链接（lite 包合规不带 scapy）。

两个 GET 走 :func:`collect_cached` 的短 TTL 缓存，避免首屏背靠背跑两遍全套检查；
ack 改写了 ``first_run`` 后会清缓存。

设计边界（为什么单独成模块而不是塞进 ``server.py``）：

1. **纯读**：检查过程不写任何文件、不请求 UAC、不启动抓包子进程；唯一会起进程的
   是 ``tshark -v``（读版本），那正是「tshark 是否可用」本身。
2. **复用既有探测**：管理员 / Npcap 走 :mod:`core.platform.winapi`；tshark 走
   :mod:`tshark`；已有实例 / 可用端口走 :mod:`app`，不在这里重复实现一套。
3. **失败不抛**：U 盘可能只读、驱动可能被卸载、端口可能被占 —— 所有失败都变成
   一项 ``ok: false`` + 可执行 ``detail`` + 修复信息，界面据此显示 ❌ 与修复入口。
4. **文案在 copy 表**：名称 / 说明 / 修复动作都取 ``core/copy/zh-CN.json`` 的
   ``startup`` section；本文件只留 key 与探测逻辑。
"""
from __future__ import annotations

import copy
import json
import re
import sys
import threading
import time
from pathlib import Path

CORE = Path(__file__).resolve().parent
ROOT = CORE.parent
sys.path.insert(0, str(CORE))
# ``core.platform`` 是包内模块，需要仓库根在 sys.path 上（与 diagnose.py 同口径）。
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402
import copytext  # noqa: E402
import pathprobe  # noqa: E402
import tshark  # noqa: E402
import version  # noqa: E402

try:  # 被动监听引擎只在探测 scapy 时用；导入失败按「没有 scapy」降级
    import passive  # noqa: E402
except Exception:  # noqa: BLE001  裁剪发行包可能没有 passive.py
    passive = None  # type: ignore[assignment]

try:  # 平台能力缺失（如被裁剪的发行包）时退回 tshark 的兼容实现
    from core.platform import winapi  # noqa: E402
except Exception:  # noqa: BLE001  导入失败只让 npcap/管理员检查降级，不拖垮模块
    winapi = None  # type: ignore[assignment]

#: 六项检查的固定顺序与固定 key（UI/测试都按这个清单断言，不许增删改名）。
CHECK_KEYS = ("python", "tshark", "npcap", "scapy", "port", "admin")

#: 首次运行标记：放在 ``config/`` 下（U 盘便携、可写；写不进去下次再显示）。
MARKER_REL = Path("config") / "ui-first-run.json"

PYTHON_DOWNLOAD_URL = "https://www.python.org/downloads/windows/"
WIRESHARK_DOWNLOAD_URL = "https://www.wireshark.org/download.html"
NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"
SCAPY_DOWNLOAD_URL = "https://scapy.net"
INTERFACES_COMMAND = "python core\\diagnose.py --interfaces"
#: 缺组件时的修复命令（fix_command 字段，前端「复制命令」按钮直接取用）。
#: tshark 走便携版放置说明（不是命令）：把 WiresharkPortable 放到 tools/ 下即可被
#: find_tshark 的便携目录扫描命中，无需改环境变量、无需重启。
TSHARK_FIX_COMMAND = "将便携版 Wireshark 解压到 tools\\WiresharkPortable\\，使其包含 App\\Wireshark\\tshark.exe"
SCAPY_FIX_COMMAND = "python -m pip install scapy"
#: Npcap 只能用安装器装（驱动级，不可能靠手填路径）；fix_command 是导入/安装引导，
#: 绝不静默执行安装 —— 前端只是「复制命令」，真正装不装由用户自己决定。
NPCAP_FIX_COMMAND = "运行 tools\\_internal\\npcap-*.exe（或从 https://npcap.com 下载安装器）"

#: 缺组件修复说明的文档位置（相对仓库根；界面可复制/展示，不写死本机盘符）。
DOCS_STARTUP = "docs/startup.md"

#: ``/api/app`` 与 ``/api/selfcheck`` 复用自检结果的短 TTL（秒）。
#: 首屏这两个接口背靠背请求；没有缓存时 tshark 版本 / 端口探测 / scapy 导入会各跑两遍
#: （冷启动数百 ms、端口全占的沙箱里可到 5.8 s），而两次结果在首屏尺度上等价。
CACHE_TTL_SECONDS = 1.5

_CACHE_LOCK = threading.Lock()
#: 缓存键是仓库根（测试用临时 root），值是 ``(monotonic 时间, collect 结果)``。
_CACHE: dict[str, tuple[float, dict]] = {}


def _t(key: str, **args) -> str:
    """取 ``startup`` section 的文案并填充占位符（缺失时回退成 key）。

    Args:
        key: ``core/copy/zh-CN.json`` → ``startup`` 下的键名。
        **args: ``str.format`` 占位符实参。

    Returns:
        str: 可直接展示的文案；copy 表损坏时返回 key 本身（不抛异常）。
    """
    try:
        return copytext.text("startup", key, default=key, **args)
    except Exception:  # noqa: BLE001  文案表损坏也不该让首屏检查崩掉
        return key


def ui_copy() -> dict:
    """返回首屏自检 / 权限卡需要的 ``startup`` 文案表。

    Returns:
        dict: ``core/copy/zh-CN.json`` 的 ``startup`` section；读取失败时 ``{}``。
            界面把它挂在 ``ui_copy.startup`` 上取用，不在 HTML 里再抄一份长文案。
    """
    try:
        return copytext.section(copytext.load_table(), "startup")
    except Exception:  # noqa: BLE001  文案缺失不拖垮状态接口
        return {}


def marker_path(root: Path | None = None) -> Path:
    """首次运行标记文件的绝对路径。

    Args:
        root: 仓库根目录；``None`` 表示本文件所在 ``core/`` 的上一级。测试传临时目录，
            避免写真实 ``config/``。

    Returns:
        Path: ``<root>/config/ui-first-run.json``（文件可能还不存在）。
    """
    return Path(root) / MARKER_REL if root is not None else ROOT / MARKER_REL


def is_first_run(root: Path | None = None) -> bool:
    """是否首次运行（标记文件不存在即首次）。

    Args:
        root: 仓库根目录；``None`` 用运行时仓库根。

    Returns:
        bool: 标记存在 → ``False``；不存在或读取失败 → ``True``（宁可直接显示检查）。
    """
    try:
        return not marker_path(root).is_file()
    except OSError:
        return True


def ack_first_run(root: Path | None = None) -> dict:
    """写入首次运行标记（用户看过首屏检查后调用）。

    写入失败**不是错误**：U 盘可能只读、目录可能被安全软件锁定。此时返回
    ``{"ok": False, "writable": False}`` 但绝不抛异常，界面照常进入主界面，
    只是下次启动会再显示一次检查。

    Args:
        root: 仓库根目录；``None`` 用运行时仓库根。测试传临时目录。

    Returns:
        dict: 成功 ``{"ok": True, "writable": True, "path": "config/ui-first-run.json"}``；
        失败 ``{"ok": False, "writable": False, "error": "...", "path": ...}``。
    """
    path = marker_path(root)
    payload = {
        "app": "NetDiag",
        "acked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version": version.read_version(Path(root) if root is not None else ROOT),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                        encoding="utf-8")
        return {"ok": True, "writable": True, "path": MARKER_REL.as_posix()}
    except Exception as exc:  # noqa: BLE001  写保护/策略拒绝都只降级，不阻塞界面
        return {"ok": False, "writable": False,
                "path": MARKER_REL.as_posix(),
                "error": f"{type(exc).__name__}: {exc}"}


def _check(key: str, ok: bool, detail: str, fix_kind: str = "none",
           fix_url: str = "", fix_command: str = "") -> dict:
    """组装一项检查的固定结构（六项都返回同样的键，UI 不用猜缺哪个）。

    Args:
        key: 固定机器码（见 :data:`CHECK_KEYS`）。
        ok: 该项是否通过。
        detail: 给人看的一句话说明（失败时必须可执行）。
        fix_kind: ``url`` / ``command`` / ``elevate`` / ``none``。
        fix_url: 修复链接（``fix_kind == "url"`` 时用）。
        fix_command: 修复命令（``fix_kind == "command"`` 时用）。

    Returns:
        dict: 键 ``key`` / ``name`` / ``ok`` / ``detail`` / ``fix_kind`` /
            ``fix_url`` / ``fix_command`` / ``impact`` / ``doc_url``
            （后五个失败时才有意义）。
    """
    return {
        "key": key,
        "name": _t(f"check_{key}"),
        "ok": bool(ok),
        "detail": str(detail or ""),
        "fix_kind": fix_kind,
        "fix_url": fix_url,
        "fix_command": fix_command,
        # impact 是「缺了会怎样」的一句话，放在 copy 表里，界面不用自己编文案。
        "impact": _t(f"impact_{key}"),
        "doc_url": DOCS_STARTUP,
    }


def _python_runtime() -> str:
    """当前 Python 是包内便携运行时还是系统 Python（只用于说明文字）。

    Returns:
        str: ``startup.runtime_portable`` 或 ``startup.runtime_system`` 的文案。
    """
    try:
        exe = Path(sys.executable).resolve()
        portable = (ROOT / "tools" / "python").resolve()
        if exe == portable or portable in exe.parents:
            return _t("runtime_portable")
    except Exception:  # noqa: BLE001  路径解析失败只影响一句说明
        pass
    return _t("runtime_system")


def check_python(override: Path | None = None) -> dict:
    """检查 Python 版本是否 ≥ 3.11（实时抓包与离线分析都依赖它）。

    手填路径（``POST /api/selfcheck/path``）时，用指定解释器跑 ``-V`` 读版本；
    否则用当前解释器（``sys.version_info``）。手填路径失效（不存在/不可执行/
    读不到版本）时不抛异常，回落到当前解释器并照常报告。

    Args:
        override: 用户手填的 python 可执行文件路径；``None`` 用当前解释器。

    Returns:
        dict: 通过时 ``detail`` 形如 ``Python 3.11.9（64 位，便携运行时）``；
            版本过低时 ``ok=False`` 并给出升级入口（Python 官网）。
    """
    info: tuple[int, int, int] | None = None
    text = ""
    bits = 64 if sys.maxsize > 2 ** 32 else 32
    runtime = _python_runtime()
    if override is not None:
        text, info = _probe_python(override)
        if info is not None:
            # 手填的是另一个解释器：说明文字标「手填路径」，不再套用当前运行时文案。
            runtime = _t("runtime_manual")
    if info is None:
        info = tuple(sys.version_info[:3])
        text = ".".join(str(part) for part in info)
    ok = info >= (3, 11)
    detail = _t("python_ok" if ok else "python_low",
                version=text, bits=bits, runtime=runtime)
    return _check("python", ok, detail,
                  fix_kind="none" if ok else "url",
                  fix_url="" if ok else PYTHON_DOWNLOAD_URL)


def _probe_python(exe: Path) -> tuple[str, tuple[int, int, int] | None]:
    """跑 ``<exe> -V`` 读版本串与 ``(major, minor, micro)``。

    任何失败（不存在/不可执行/读不到版本）都返回 ``(说明串, None)``，调用方
    据此回落。绝不抛异常 —— 手填路径失效不该拖垮整个自检。

    Args:
        exe: 用户手填的 python 可执行文件路径。

    Returns:
        tuple[str, tuple | None]: ``(版本文本, 版本三元组或 None)``。
    """
    try:
        rc, out, err = tshark.run([str(exe), "-V"], timeout=15)
    except Exception:  # noqa: BLE001
        return "", None
    raw = (out or err or "").strip()
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", raw)
    if rc != 0 or not m:
        return raw or f"无法读取版本 (rc={rc})", None
    parts = [int(m.group(i)) for i in (1, 2)]
    parts.append(int(m.group(3) or 0))
    return raw, tuple(parts)  # type: ignore[return-value]


def check_tshark(override: Path | None = None) -> dict:
    """检查 tshark 是否存在，并读一次版本（失败时给 Wireshark 下载页与便携版说明）。

    手填路径（``POST /api/selfcheck/path``）时优先用指定路径；否则走
    :func:`tshark.find_tshark` 的自动查找。手填路径失效时回落到自动查找。

    Args:
        override: 用户手填的 tshark 可执行文件路径；``None`` 走自动查找。

    Returns:
        dict: 找到时 ``detail`` 含版本号（如 ``已找到 tshark 4.7.4``）；
            找不到时 ``ok=False``、``fix_url`` 指向 Wireshark 下载页、
            ``fix_command`` 是便携版放置路径说明。
    """
    path = override if override is not None and override.is_file() else tshark.find_tshark()
    if not path:
        return _check("tshark", False, _t("tshark_missing"),
                      fix_kind="url", fix_url=WIRESHARK_DOWNLOAD_URL,
                      fix_command=TSHARK_FIX_COMMAND)
    raw = tshark.version(path)
    match = re.search(r"\d+\.\d+\.\d+", str(raw or ""))
    text = match.group(0) if match else str(raw or "").strip()
    return _check("tshark", True, _t("tshark_ok", version=text or "-"))


def _npcap_installed() -> bool:
    """Npcap 是否安装（优先走 ``winapi``，不可用时退回 ``tshark`` 的兼容实现）。"""
    try:
        if winapi is not None:
            return bool(winapi.npcap_installed())
        return bool(tshark.npcap_installed())
    except Exception:  # noqa: BLE001  驱动查询失败按「没装」处理，让用户看到修复入口
        return False


def _is_admin() -> bool:
    """当前是否管理员（优先走 ``winapi``，不可用时退回 ``tshark``）。"""
    try:
        if winapi is not None:
            return bool(winapi.is_admin())
        return bool(tshark.is_admin())
    except Exception:  # noqa: BLE001  权限查询失败按「不是管理员」处理
        return False


def check_npcap() -> dict:
    """检查 Npcap 抓包驱动是否就绪（离线分析不需要它，但实时抓包与通信观察必须要）。

    Returns:
        dict: 未安装时 ``ok=False``，``fix_url`` 指向 Npcap 官网下载页；
            已安装时 ``detail`` 说明驱动就绪。
    """
    ok = _npcap_installed()
    return _check("npcap", ok, _t("npcap_ok" if ok else "npcap_missing"),
                  fix_kind="none" if ok else "url",
                  fix_url="" if ok else NPCAP_DOWNLOAD_URL,
                  fix_command="" if ok else NPCAP_FIX_COMMAND)


def check_port() -> dict:
    """检查能否起本地服务：已有实例 → 区间有空端口 → 端口 0（系统分配）。

    三件事都复用 :mod:`app` 的既有实现：:func:`app.find_running` 探测本程序
    实例（读 ``/api/ping``），:func:`app.port_plan` 给「这次要监听哪个端口」
    （区间内第一个空闲；都被占则 ``0``，交给系统分配）。已有实例时不需要空闲
    端口 —— 启动器会直接打开那个地址。

    Returns:
        dict: 已有实例 ``detail`` 带地址；区间有空端口带端口号；只能由系统分配时
            也算 ``ok=True``（服务照样起得来，只是地址每次不同）；
            连端口 0 都绑不上才 ``ok=False``，``fix_command`` 是查看端口占用的命令。
    """
    try:
        url = app.find_running()
    except Exception:  # noqa: BLE001  探测失败按「没有实例」继续找空闲端口
        url = ""
    if url:
        return _check("port", True, _t("port_running", url=url))
    try:
        plan = app.port_plan()
    except Exception:  # noqa: BLE001  端口探测失败按「一个都绑不上」处理
        plan = None
    if plan is None:
        return _check("port", False, _t("port_busy"),
                      fix_kind="command",
                      fix_command="netstat -ano | findstr :8787")
    if plan == 0:
        # 0 是「系统分配」的标记，不是端口号，所以不能拿它去填 {port}。
        return _check("port", True, _t("port_ephemeral"))
    return _check("port", True, _t("port_free", port=plan))


def check_admin() -> dict:
    """检查当前进程是否管理员（实时抓包 / 通信观察的前提）。

    Returns:
        dict: 是管理员时 ``detail`` 说明可直接抓包；不是管理员时 ``ok=False``、
            ``fix_kind="elevate"``（界面显示「以管理员身份重启」按钮），
            但离线分析与连通与速度测试不受影响。
    """
    ok = _is_admin()
    return _check("admin", ok, _t("admin_ok" if ok else "admin_no"),
                  fix_kind="none" if ok else "elevate")


def _scapy_available() -> bool:
    """本机是否能导入 scapy（被动监听/逐跳的加速引擎，不是必需组件）。

    Returns:
        bool: ``True`` 表示 scapy 可导入；模块缺失 / 导入失败 / 探测异常都返回 ``False``
            （lite 包没有 scapy 时：被动监听只能依赖 tshark，逐跳降级系统 tracert）。
    """
    try:
        if passive is None:
            return False
        return bool(passive.engine_status().get("scapy"))
    except Exception:  # noqa: BLE001  scapy 探测失败只让 passive 降级，不拖垮自检
        return False


def check_scapy() -> dict:
    """检查 scapy 是否可导入（缺了只降级，不是「不可用」，但给可选安装入口）。

    scapy 是可选加速引擎：它让逐跳样本更准（批量 ``sr()``、TCP 回退）。lite 包
    **不内置 scapy**。这一项失败时给 ``fix_url``（scapy.net 官网）与
    ``fix_command``（``pip install scapy``）作为**可选**加速手段，但 ``impact``
    仍说明「逐跳会降级为系统 tracert」—— 不装也能用，不是必须项。

    Returns:
        dict: 可导入时 ``detail`` 说明逐跳使用 scapy；不可导入时 ``ok=False``、
            ``fix_kind="url"``，给官网链接 + pip 安装命令。
    """
    ok = _scapy_available()
    return _check("scapy", ok, _t("scapy_ok" if ok else "scapy_missing"),
                  fix_kind="none" if ok else "url",
                  fix_url="" if ok else SCAPY_DOWNLOAD_URL,
                  fix_command="" if ok else SCAPY_FIX_COMMAND)


def _tracert_available() -> bool:
    """系统是否有 ``tracert``（逐跳降级引擎，复用 :func:`pathprobe.tracert_available`）。

    Returns:
        bool: PATH 上能找到 tracert 为 True；探测异常一律 False。
    """
    try:
        return bool(pathprobe.tracert_available())
    except Exception:  # noqa: BLE001  探测失败按「没有 tracert」处理，UI 只置灰逐跳
        return False


def capabilities(checks: list[dict] | None = None) -> dict:
    """把六项环境检查折算成「哪些功能现在可用」的能力矩阵（界面置灰的唯一依据）。

    只读探测：不会写文件、不请求 UAC、不启动抓包子进程；但 ``checks`` 为空时会在
    本机现场跑六项检查并探测 scapy/tracert 引擎，因此结果依赖本机环境，不是纯函数。
    ``admin`` 不是能力硬门槛 —— 非管理员仍可点「以管理员身份重启」按需提权，
    不能置灰封死。

    Args:
        checks: 可选，六项检查结果（结构同 :func:`collect` 的 ``checks``）。测试注入
            构造的 ✅/❌ 组合；``None`` 时跑真实的 :func:`check_python` 等六项。

    Returns:
        dict: 键 ``probe`` / ``offline`` / ``live`` / ``passive`` / ``reports`` /
            ``settings``（bool）、``path_probe``（逐跳是否有引擎可用：scapy **或**
            系统 tracert）、``mtr_engine``（``scapy`` / ``tracert`` / ``None``）、
            ``missing``（不可用模式的机器码原因，键为模式名，值为 ``tshark`` /
            ``npcap`` / ``tshark|npcap`` / ``tshark|scapy`` /
            ``tshark|scapy|npcap``）、``scapy``（是否有 scapy 可用）。
            **缺 scapy 不会让 path_probe 变 False**：只要系统 tracert 在，逐跳
            就可用（降级）。

    Example:
        >>> capabilities([{"key": "tshark", "ok": False},
        ...               {"key": "npcap", "ok": False}])["probe"]
        True
    """
    if checks is None:
        checks = [check_python(), check_tshark(), check_npcap(), check_scapy(),
                  check_port(), check_admin()]
    by_key: dict[str, bool] = {}
    for item in checks:
        if isinstance(item, dict) and item.get("key"):
            by_key[str(item["key"])] = bool(item.get("ok"))

    tshark_ok = by_key.get("tshark", False)
    npcap_ok = by_key.get("npcap", False)
    scapy_ok = _scapy_available()
    tracert_ok = _tracert_available()
    live_ok = tshark_ok and npcap_ok
    # 通信观察要真正打开网卡收包：两种引擎都必须落在 Npcap 驱动上。
    # 缺驱动时 tshark / scapy 再能导入也抓不到包（运行期见 passive.py 的
    # 「没有可用网卡：请安装 Npcap」），所以 Npcap 是 passive 的前置条件。
    passive_ok = npcap_ok and (tshark_ok or scapy_ok)
    # 逐跳只需要「能发出 TTL 探测」：scapy 更准，系统 tracert 也能给逐跳表格。
    # 两个都没有才置灰（UI 只在 path_probe === false 时禁用「逐跳路径」开关）。
    if scapy_ok:
        mtr_engine: str | None = "scapy"
    elif tracert_ok:
        mtr_engine = "tracert"
    else:
        mtr_engine = None
    path_probe_ok = mtr_engine is not None

    missing: dict[str, str] = {}
    if not tshark_ok:
        # 离线分析只需要 tshark；实时抓包还额外要 Npcap，所以原因分开写。
        missing["offline"] = "tshark"
    if not live_ok:
        if not tshark_ok and not npcap_ok:
            missing["live"] = "tshark|npcap"
        else:
            missing["live"] = "tshark" if not tshark_ok else "npcap"
    if not passive_ok:
        # 原因按「引擎在前、驱动在后」聚合，UI 的 capTag 按 | 分段识别。
        reasons: list[str] = []
        if not (tshark_ok or scapy_ok):
            reasons.append("tshark|scapy")
        if not npcap_ok:
            reasons.append("npcap")
        missing["passive"] = "|".join(reasons)

    return {
        "probe": True,          # 连通与速度测试只用标准库 socket，永远可用
        "offline": tshark_ok,   # 分析抓包文件：只要 tshark，不需要 Npcap
        "live": live_ok,        # 实时抓包：tshark + Npcap
        "passive": passive_ok,  # 通信观察：Npcap 驱动 + (tshark 或内置 scapy)
        "reports": True,
        "settings": True,
        # 逐跳：scapy 或系统 tracert 任一可用即可（缺 scapy 只降级，不置灰）。
        "path_probe": path_probe_ok,
        "mtr_engine": mtr_engine,
        "missing": missing,
        "scapy": scapy_ok,
    }


def collect(root: Path | None = None) -> dict:
    """跑完六项检查并组装 ``GET /api/selfcheck`` 的响应。

    纯读：不写标记文件、不请求 UAC、不启动抓包子进程。``first_run`` 只读
    ``<root>/config/ui-first-run.json`` 是否存在。单项检查抛异常时只把该项标成
    ``ok=False`` 并记录原因，绝不让整个接口 500。

    Args:
        root: 仓库根目录（测试注入临时目录用）；``None`` 用运行时仓库根。

    Returns:
        dict: 键 ``ok``（六项是否全过）/ ``version``（``VERSION`` 文件）/
            ``first_run``（标记不存在）/ ``checks``（固定 6 项，顺序为
            :data:`CHECK_KEYS`）/ ``capabilities``（能力矩阵）/
            ``ui_copy``（``{"startup": {...}}`` 文案）。
    """
    funcs = (
        ("python", check_python),
        ("tshark", check_tshark),
        ("npcap", check_npcap),
        ("scapy", check_scapy),
        ("port", check_port),
        ("admin", check_admin),
    )
    # 手填路径（config/paths.json，POST /api/selfcheck/path 写入）：python / tshark
    # 两项优先用用户指定的可执行文件探测；其它项不受影响。路径失效（文件被删 /
    # 不可执行）时 check_* 内部会回落到自动查找，不会因一个旧路径把该项判成失败。
    overrides: dict[str, Path] = {}
    try:
        from core.config import load_paths  # 延迟导入：config 走 core 包相对导入
        paths = load_paths()
    except Exception:  # noqa: BLE001  paths.json 损坏/导入失败也不该拖垮自检
        paths = {}
    for key, field in (("tshark", "tshark_path"), ("python", "python_path")):
        raw = str((paths or {}).get(field) or "").strip()
        if raw:
            overrides[key] = Path(raw)
    checks: list[dict] = []
    for key, func in funcs:
        try:
            # 只有 python / tshark 支持手填路径覆盖；其余 check 函数无参调用。
            item = func(overrides[key]) if key in overrides else func()
            if not isinstance(item, dict):
                raise TypeError(f"检查项 {key} 没有返回 dict")
        except Exception as exc:  # noqa: BLE001  单项失败只降级该项，整体响应照常返回
            item = _check(key, False,
                          _t("check_error", reason=f"{type(exc).__name__}: {exc}"))
        checks.append(item)
    return {
        "ok": all(item.get("ok") for item in checks),
        "version": version.read_version(Path(root) if root is not None else ROOT),
        "first_run": is_first_run(root),
        "checks": checks,
        "capabilities": capabilities(checks),
        "ui_copy": {"startup": ui_copy()},
    }


def invalidate_cache() -> None:
    """清空自检结果缓存（ack 写入首次运行标记后必须调用）。

    ack 会改变 ``first_run``，缓存里还是旧值；不清掉的话 TTL 内下一次
    ``/api/selfcheck`` 会把「首次运行」又下发一遍。

    Returns:
        None: 只清内存缓存，不写文件、不抛异常。
    """
    with _CACHE_LOCK:
        _CACHE.clear()


def collect_cached(root: Path | None = None, force: bool = False) -> dict:
    """带短 TTL 的自检结果，供 ``/api/app`` 与 ``/api/selfcheck`` 共用。

    首屏会先取 ``/api/app``（应用信息 + 能力矩阵），再取 ``/api/selfcheck`` 画面板；
    两次都跑全套检查会重复探测 tshark 版本 / 端口 / scapy（冷启动数百 ms）。这里
    按 ``CACHE_TTL_SECONDS`` 缓存，TTL 内第二次调用直接返回上次结果；``force``
    或 :func:`invalidate_cache` 可强制重新探测。

    Args:
        root: 仓库根目录（测试注入临时目录用）；``None`` 用运行时仓库根。
        force: ``True`` 时跳过缓存重新跑六项检查（测试 / ack 后的强制刷新）。

    Returns:
        dict: 与 :func:`collect` 相同结构。返回深拷贝，调用方改字段不会污染缓存。

    Example:
        >>> first = collect_cached()          # 跑一次检查并缓存
        >>> second = collect_cached()         # TTL 内复用，不再探测本机
        >>> collect_cached(force=True)        # 强制重新检查
    """
    key = str(Path(root).resolve()) if root is not None else ""
    if not force:
        with _CACHE_LOCK:
            hit = _CACHE.get(key)
        if hit is not None and (time.monotonic() - hit[0]) < CACHE_TTL_SECONDS:
            return copy.deepcopy(hit[1])
    # 单飞：拿到锁后再次确认，避免两个并发首屏请求同时跑全套检查。
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if not force and hit is not None and (time.monotonic() - hit[0]) < CACHE_TTL_SECONDS:
            return copy.deepcopy(hit[1])
        data = collect(root)
        _CACHE[key] = (time.monotonic(), data)
        return copy.deepcopy(data)


__all__ = [
    "CHECK_KEYS", "MARKER_REL", "CACHE_TTL_SECONDS", "collect", "collect_cached",
    "invalidate_cache", "capabilities", "marker_path",
    "is_first_run", "ack_first_run", "ui_copy", "check_python", "check_tshark",
    "check_npcap", "check_scapy", "check_port", "check_admin",
]
