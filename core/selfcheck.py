"""首屏「准备检查」的五项只读环境检查 + 首次运行标记（C2）。

这个模块只回答一个问题：**这台机器现在能不能直接用**。它被两块代码调用：

* ``GET /api/selfcheck``（界面首屏 / 「重新检测」按钮）—— 返回五项检查结果；
* ``POST /api/selfcheck/ack``（用户看过面板后）—— 写 ``config/ui-first-run.json``。

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

import json
import re
import sys
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
import tshark  # noqa: E402
import version  # noqa: E402

try:  # 平台能力缺失（如被裁剪的发行包）时退回 tshark 的兼容实现
    from core.platform import winapi  # noqa: E402
except Exception:  # noqa: BLE001  导入失败只让 npcap/管理员检查降级，不拖垮模块
    winapi = None  # type: ignore[assignment]

#: 五项检查的固定顺序与固定 key（UI/测试都按这个清单断言，不许增删改名）。
CHECK_KEYS = ("python", "tshark", "npcap", "port", "admin")

#: 首次运行标记：放在 ``config/`` 下（U 盘便携、可写；写不进去下次再显示）。
MARKER_REL = Path("config") / "ui-first-run.json"

PYTHON_DOWNLOAD_URL = "https://www.python.org/downloads/windows/"
WIRESHARK_DOWNLOAD_URL = "https://www.wireshark.org/download.html"
NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"
INTERFACES_COMMAND = "python core\\diagnose.py --interfaces"


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
    """组装一项检查的固定结构（五项都返回同样的键，UI 不用猜缺哪个）。

    Args:
        key: 固定机器码（见 :data:`CHECK_KEYS`）。
        ok: 该项是否通过。
        detail: 给人看的一句话说明（失败时必须可执行）。
        fix_kind: ``url`` / ``command`` / ``elevate`` / ``none``。
        fix_url: 修复链接（``fix_kind == "url"`` 时用）。
        fix_command: 修复命令（``fix_kind == "command"`` 时用）。

    Returns:
        dict: 键 ``key`` / ``name`` / ``ok`` / ``detail`` / ``fix_kind`` /
            ``fix_url`` / ``fix_command``（后四个失败时才有意义）。
    """
    return {
        "key": key,
        "name": _t(f"check_{key}"),
        "ok": bool(ok),
        "detail": str(detail or ""),
        "fix_kind": fix_kind,
        "fix_url": fix_url,
        "fix_command": fix_command,
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


def check_python() -> dict:
    """检查 Python 版本是否 ≥ 3.11（实时抓包与离线分析都依赖它）。

    Returns:
        dict: 通过时 ``detail`` 形如 ``Python 3.11.9（64 位，便携运行时）``；
            版本过低时 ``ok=False`` 并给出升级入口（Python 官网）。
    """
    info = tuple(sys.version_info[:3])
    text = ".".join(str(part) for part in info)
    bits = 64 if sys.maxsize > 2 ** 32 else 32
    runtime = _python_runtime()
    ok = info >= (3, 11)
    detail = _t("python_ok" if ok else "python_low",
                version=text, bits=bits, runtime=runtime)
    return _check("python", ok, detail,
                  fix_kind="none" if ok else "url",
                  fix_url="" if ok else PYTHON_DOWNLOAD_URL)


def check_tshark() -> dict:
    """检查 tshark 是否存在，并读一次版本（失败时给 Wireshark 下载页与网卡命令）。

    Returns:
        dict: 找到时 ``detail`` 含版本号（如 ``已找到 tshark 4.7.4``）；
            找不到时 ``ok=False``、``fix_url`` 指向 Wireshark 下载页、
            ``fix_command`` 是列出网卡的 ``--interfaces`` 命令。
    """
    path = tshark.find_tshark()
    if not path:
        return _check("tshark", False, _t("tshark_missing"),
                      fix_kind="url", fix_url=WIRESHARK_DOWNLOAD_URL,
                      fix_command=INTERFACES_COMMAND)
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
    """检查 Npcap 抓包驱动是否就绪（离线分析不需要它，但实时抓包必须要）。

    Returns:
        dict: 未安装时 ``ok=False``，``fix_url`` 指向 Npcap 官网下载页；
            已安装时 ``detail`` 说明驱动就绪。
    """
    ok = _npcap_installed()
    return _check("npcap", ok, _t("npcap_ok" if ok else "npcap_missing"),
                  fix_kind="none" if ok else "url",
                  fix_url="" if ok else NPCAP_DOWNLOAD_URL)


def check_port() -> dict:
    """检查 8787~8796 是否有可用端口，或已有本程序实例在跑。

    两件事都复用 :mod:`app` 的既有实现：:func:`app.find_running` 探测本程序
    实例（读 ``/api/ping``），:func:`app.first_free_port` 只做 bind/close。
    已有实例时不需要空闲端口 —— 启动器会直接打开那个地址。

    Returns:
        dict: 已有实例 ``detail`` 带地址；有空闲端口 ``detail`` 带端口号；
            两者都没有 ``ok=False``，``fix_command`` 是查看端口占用的命令。
    """
    try:
        url = app.find_running()
    except Exception:  # noqa: BLE001  探测失败按「没有实例」继续找空闲端口
        url = ""
    if url:
        return _check("port", True, _t("port_running", url=url))
    try:
        port = app.first_free_port()
    except Exception:  # noqa: BLE001  端口探测失败按「全被占用」处理
        port = None
    if port:
        return _check("port", True, _t("port_free", port=port))
    return _check("port", False, _t("port_busy"),
                  fix_kind="command",
                  fix_command="netstat -ano | findstr :8787")


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


def collect(root: Path | None = None) -> dict:
    """跑完五项检查并组装 ``GET /api/selfcheck`` 的响应。

    纯读：不写标记文件、不请求 UAC、不启动抓包子进程。``first_run`` 只读
    ``<root>/config/ui-first-run.json`` 是否存在。

    Args:
        root: 仓库根目录（测试注入临时目录用）；``None`` 用运行时仓库根。

    Returns:
        dict: 键 ``ok``（五项是否全过）/ ``version``（``VERSION`` 文件）/
            ``first_run``（标记不存在）/ ``checks``（固定 5 项，顺序为
            :data:`CHECK_KEYS`）/ ``ui_copy``（``{"startup": {...}}`` 文案）。
    """
    checks = [check_python(), check_tshark(), check_npcap(),
              check_port(), check_admin()]
    return {
        "ok": all(item.get("ok") for item in checks),
        "version": version.read_version(Path(root) if root is not None else ROOT),
        "first_run": is_first_run(root),
        "checks": checks,
        "ui_copy": {"startup": ui_copy()},
    }


__all__ = [
    "CHECK_KEYS", "MARKER_REL", "collect", "marker_path", "is_first_run",
    "ack_first_run", "ui_copy", "check_python", "check_tshark", "check_npcap",
    "check_port", "check_admin",
]
