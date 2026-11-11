"""静默启动器：像应用一样双击即用，全程不弹控制台窗口。

由 NetDiag.exe / NetDiag.vbs 用 pythonw.exe 拉起（pythonw 无控制台），流程：
  1. 已有实例在跑 → 直接把浏览器指过去，退出（避免开第二份
  2. **启动不提权**：需要管理员的功能（实时抓包 / 通信观察）由界面按需请求，
     用户点「否」就保持普通权限，分析抓包文件 / 连通与速度测试仍可用
  3. 生成配置 → 起本地服务（后台线程）→ 打开浏览器
  4. 界面点「退出」或长时间无人访问 → 自动收尾，不留后台进程

手工调试可以 `python core/app.py --console` 前台跑，看得到日志。
"""
from __future__ import annotations

import ctypes
import json
import os
import socket
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

CORE = Path(__file__).resolve().parent
ROOT = CORE.parent
sys.path.insert(0, str(CORE))

import logstore  # noqa: E402

MB_ICONERROR = 0x10
MB_ICONINFO = 0x40

#: 缺组件/启动失败时的排查文档（相对仓库根；日志里给出可复制路径，不写死盘符）。
DOCS_STARTUP = "docs/startup.md"

#: 浏览器打开权归属的环境变量（H1）。
#:
#: 双击 ``NetDiag.exe`` 时，启动器是**唯一**打开浏览器的地方：它给本进程设
#: ``NETDIAG_NO_BROWSER=1``，本文件与 :mod:`core.server` 的所有 ``webbrowser.open``
#: 都必须让路，否则用户会看到两个标签页（launcher 开一个 + app/server 各开一个）。
#: 直接 ``python core\\app.py`` 不设这个变量，保持「自己开浏览器」的兼容行为。
NO_BROWSER_ENV = "NETDIAG_NO_BROWSER"

#: 视为「已接管」的取值（大小写不敏感）。只认显式真值，拼错/空值不改变默认行为。
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


# ----------------------------------------------------------------- 基础工具
def browser_disabled() -> bool:
    """本进程是否已被启动器接管浏览器打开（H1 单次打开的开关）。

    Returns:
        bool: 环境变量 :data:`NO_BROWSER_ENV` 为 ``1/true/yes/on`` 时 True。
            读不到环境变量（极简运行环境）时按 False 处理，保持兼容。

    Example:
        >>> os.environ["NETDIAG_NO_BROWSER"] = "1"
        >>> browser_disabled()
        True
    """
    try:
        return (os.environ.get(NO_BROWSER_ENV) or "").strip().lower() in _TRUE_VALUES
    except Exception:  # noqa: BLE001  环境变量读取失败按「未接管」处理
        return False


def open_browser(url: str) -> bool:
    """打开默认浏览器（受 :func:`browser_disabled` 控制的唯一入口）。

    所有打开点都走这里，而不是直接调 ``webbrowser.open``：这样「谁启动、谁决定
    是否开浏览器」只有一处判断，测试也只需要 mock 一个函数。

    Args:
        url: 要打开的本地界面地址；空串直接忽略。

    Returns:
        bool: True 表示已调用系统浏览器；被环境变量接管、URL 为空或调用失败时 False。

    Example:
        >>> os.environ["NETDIAG_NO_BROWSER"] = "1"
        >>> open_browser("http://127.0.0.1:8787/")
        False
    """
    if not url or browser_disabled():
        return False
    try:
        return bool(webbrowser.open(url))
    except Exception:  # noqa: BLE001  打不开浏览器只降级，不阻塞服务
        return False


def redirect_output() -> None:
    """pythonw 下 sys.stdout/stderr 是 None，任何 print 都会炸，先兜住。

    实际落盘交给 :mod:`logstore`（写 ``logs/app-YYYYMMDD.log``）。日志句柄在
    ``logstore`` 里进程内复用，不会每来一次 ``print`` 就打开一个文件。

    Returns:
        None: 目录不可写时静默降级（保持原来的 ``None`` 语义，不因日志失败而崩溃）。
    """
    if sys.stdout is not None and sys.stderr is not None:
        return
    stream = logstore.open_stream()
    if sys.stdout is None:
        sys.stdout = stream
    if sys.stderr is None:
        sys.stderr = stream


def msgbox(text: str, title: str = "NetDiag · 网络矩阵", flags: int = MB_ICONINFO) -> None:
    """弹一个系统消息框 —— 静默启动（无控制台）时唯一的提示手段。

    Args:
        text: 正文。
        title: 窗口标题。
        flags: ``MB_*`` 图标/按钮组合，默认信息图标 + 确定。

    Returns:
        None: 弹窗失败（如非 Windows）静默忽略，绝不因此让启动流程崩掉。
    """
    try:
        ctypes.windll.user32.MessageBoxW(None, text, title, flags)
    except Exception:  # noqa: BLE001
        pass


def is_admin() -> bool:
    """当前进程是否管理员（实时抓包的前提）。

    Returns:
        bool: 查不到时返回 ``False``，让上层按「无提权」降级处理。
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def relaunch_as_admin(port: int | None = None) -> bool:
    """用 UAC 提权重启自己。

    提权只重启**服务进程**，界面标签页已经开着；所以提权后的新进程必须继承
    ``NETDIAG_NO_BROWSER=1``（H1：否则用户会在提权后再被弹出第二个标签页）。
    ``ShellExecuteW`` 创建的子进程继承当前进程环境，这里在调用前显式置位，
    也覆盖「直接从命令行启动、没经过 launcher」的情况。

    Args:
        port: 当前实例监听的端口；给了就通过 ``--port`` 传给新进程，让它优先绑回
            同一个端口。**端口 0（系统分配）时必须传**，否则新进程会拿到另一个随机
            端口，已经开着的标签页就指向了一个不存在的地址。

    Returns:
        bool: True 表示已成功拉起提权后的新进程（当前进程应立即退出，避免两个实例抢端口）；
            False 表示用户点了「否」或调用失败 —— 此时**不要**退出，
            以普通权限继续跑，实时抓包不可用但分析抓包文件照常。
    """
    try:
        exe = sys.executable
        # UAC 拉起的新进程不能再弹控制台：优先换成同目录的 pythonw.exe。
        # 若当前就是 pythonw，Path(...).with_name("pythonw.exe") 还是它自己。
        pythonw = Path(exe).with_name("pythonw.exe")
        if pythonw.is_file():
            exe = str(pythonw)
        # 提权后不自动开浏览器（同源：H1 统一打开点）。子进程继承本进程环境。
        os.environ[NO_BROWSER_ENV] = "1"
        # pythonw 提权后仍无控制台；__file__ 用绝对路径，工作目录设为 ROOT
        params = f'"{Path(__file__).resolve()}" --elevated'
        try:
            wanted = int(port) if port else 0
        except (TypeError, ValueError):
            wanted = 0
        if 0 < wanted < 65536:
            params += f" --port {wanted}"
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, str(ROOT), 1)
        return int(rc) > 32
    except Exception:  # noqa: BLE001
        return False


def preferred_port(argv: list[str] | None = None) -> int | None:
    """从命令行取 ``--port N``（提权重启用来「绑回同一个端口」）。

    Args:
        argv: 参数列表；省略时用 ``sys.argv``。

    Returns:
        int | None: 合法端口（1~65535）；没传或值非法时 ``None``（回落配置端口）。

    Note:
        非法值**不报错**：这条参数只在提权链路自动追加，用户不会手敲；
        真写坏了也只该退回默认端口，不该让服务起不来。
    """
    args = list(sys.argv if argv is None else argv)
    for index, item in enumerate(args):
        value = ""
        if item == "--port" and index + 1 < len(args):
            value = args[index + 1]
        elif item.startswith("--port="):
            value = item.split("=", 1)[1]
        if not value:
            continue
        try:
            port = int(str(value).strip())
        except (TypeError, ValueError):
            return None
        return port if 0 < port < 65536 else None
    return None


def _port_open(port: int, timeout: float = 0.15) -> bool:
    """``127.0.0.1:<port>`` 上有没有进程在监听（只做 TCP 连接，不发 HTTP）。

    为什么需要它（H2 实测）：``urllib`` 打到一个**没人监听**的端口会等满
    ``timeout`` 才失败；10 个端口 = 7 秒，占冷启动的一半以上。先做一次
    TCP 连接探测（关闭端口本机立即拒绝，约 1ms），只对真正在监听的端口发
    ``/api/ping``，把「找自己」从 7 秒降到几十毫秒。

    Args:
        port: 要探测的本地端口。
        timeout: 连接超时（秒）；本机回环通常毫秒级返回。

    Returns:
        bool: 有进程在监听返回 True；拒绝/超时/异常都返回 False（不抛）。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(max(0.01, float(timeout)))
        return sock.connect_ex(("127.0.0.1", int(port))) == 0
    except OSError:
        return False
    finally:
        sock.close()


def find_running() -> str:
    """探测本机是否已有实例在跑（单实例保护）。

    先读 ``logs/netdiag.port``（服务自己写的真实端口）—— 8787~8796 全被占时服务会
    绑端口 0，那种实例按固定区间永远扫不到；文件里的端口敲不通（进程已死留下的陈旧
    文件）再退回按区间扫。扫的时候逐个试 8787~8796 的 ``/api/ping``，并核对 ``app``
    字段是本程序，避免把别的服务误认成自己。先用 :func:`_port_open` 过滤没人监听的
    端口，不对关闭端口发 HTTP（H2：否则 10 个端口会白等 7 秒）。

    Returns:
        str: 已运行实例的界面地址（如 ``http://127.0.0.1:8787/``）；没有则空串。
    """
    try:
        import server  # noqa: PLC0415
    except Exception:  # noqa: BLE001  导入失败（打包缺文件）不影响退回按区间扫
        server = None
    if server is not None:
        hint = server.read_port_file() or {}
        port = hint.get("port")
        if port and _port_open(int(port)):
            url = _probe_ping(int(port))
            if url:
                return url
    try:
        base = int(server.diagnose.load_config().get("server_port", 8787))
    except Exception:  # noqa: BLE001
        base = 8787
    for port in range(base, base + 10):
        if not _port_open(port):
            continue
        url = _probe_ping(port)
        if url:
            return url
    return ""


def _probe_ping(port: int) -> str:
    """对单个端口敲一次 ``/api/ping``；确认是本程序才返回界面地址。

    Args:
        port: 待探测的本机端口。

    Returns:
        str: 本程序返回的界面地址；端口没人应答 / 不是本程序时是空串。
    """
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ping", timeout=0.7) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        if data.get("app") == "USBNetDiag" and data.get("ok"):
            return data.get("url") or f"http://127.0.0.1:{port}/"
    except Exception:  # noqa: BLE001
        return ""
    return ""


def first_free_port(base: int = 8787, count: int = 10) -> int | None:
    """在 ``127.0.0.1`` 上找一个当前能绑定的端口（只探测，不占用）。

    与 :func:`find_running` 互补：先看有没有本程序实例，再看端口预算。实现只做
    ``bind`` / ``close``，不监听、不发包；端口被占或处于 ``TIME_WAIT`` 时继续试下一个。
    首屏自检与 ``server.create_server`` 用同一段 8787~8796，所以这里默认也是 10 个。

    Args:
        base: 起始端口，默认 8787。
        count: 顺延个数，默认 10（8787~8796）；非正数时返回 ``None``。

    Returns:
        int | None: 第一个可绑定的端口号；全部被占用时 ``None``。传 ``base=0`` 时
            返回的是系统当场分配的那个端口（用于判断「端口 0 能不能绑」）。
    """
    for port in range(int(base), int(base) + max(0, int(count))):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
            return int(sock.getsockname()[1])
        except OSError:
            continue
        finally:
            sock.close()
    return None


def port_plan(base: int = 8787, count: int = 10) -> int | None:
    """决定**本次要监听哪个端口**：区间内第一个空闲 → 0（系统分配）→ 真没有。

    Args:
        base: 起始端口，默认 8787。
        count: 顺延个数，默认 10（8787~8796）。

    Returns:
        int | None: 可用的端口号；``0`` 表示「区间都被占用，交给系统分配」；
            ``None`` 表示连端口 0 都绑不上（本机回环栈不可用，界面确实起不来）。

    Note:
        0 是一个**合法返回值**而不是「假值」：调用方必须按 ``is None`` 判断，
        写成 ``if port:`` 会把「交给系统分配」误当成「没端口可用」。
        这与 ``server.create_server`` 的顺延策略一一对应。
    """
    port = first_free_port(base, count)
    if port:
        return port
    return 0 if first_free_port(0, 1) is not None else None


# --------------------------------------------------------------------- 主流程
def main() -> int:
    """静默启动主流程。

    顺序：日志基建 → 重定向输出 → 探测已有实例 → 建监听 → 开浏览器 → 阻塞。
    启动路径**不请求提权**；`--elevated` 只用于 /api/elevate 拉起的新进程。

    Returns:
        int: 进程退出码。0 = 正常（含「已有实例，直接把浏览器叫起来」、缺可选组件但
            服务已启动）；1 = 初始化失败 / 端口全被占用（物理上无法起本地服务）。
    """
    # 日志基建（每次启动一次）：目录 → 裁剪 → 环境快照 → 崩溃钩子。
    # 必须在 redirect_output 之前裁剪：此时当天的 app 日志还没被本进程打开。
    logstore.ensure_dirs()
    logstore.prune()
    logstore.write_env_snapshot({"entry": "app"})
    logstore.install_excepthooks()
    redirect_output()
    elevated = "--elevated" in sys.argv
    no_elevate = "--no-elevate" in sys.argv
    # H1：浏览器打开权的唯一判定。launcher 会设 NETDIAG_NO_BROWSER=1 并由它开；
    # --elevated 是「界面已开着」的提权重启，再开一个标签页只会让用户困惑。
    auto_open = not browser_disabled() and not elevated

    # 1. 已有一个实例在跑：直接开浏览器，不重复起服务。
    #    例外：本次是「界面点提权重启」拉起的 --elevated 新进程，旧实例会主动退出，
    #    这里要等它释放端口，否则新进程会误以为已有实例、把浏览器指回旧的普通权限服务。
    url = find_running()
    if url and elevated:
        for _ in range(40):  # 最多等 10 秒
            time.sleep(0.25)
            url = find_running()
            if not url:
                break
    if url:
        if auto_open:
            open_browser(url)
        else:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 已有实例但浏览器由启动器/提权流程接管，"
                  f"本次不自动打开：{url}")
        return 0

    # 2. 启动不提权：需要管理员的功能（实时抓包 / 通信观察）由界面按需请求
    #    （POST /api/elevate）。这里不再自动 relaunch_as_admin —— 双击启动不该
    #    先弹 UAC，也不该因为用户点了「否」就弹一个吓人的失败提示。
    #    --no-elevate 是启动器传入的显式声明；默认行为本来就相同，属于双保险。
    #    --elevated 仍保留：那是 /api/elevate 拉起的新进程，不是启动路径。
    if elevated and no_elevate:
        print("[提示] 同时收到 --elevated 与 --no-elevate，按不提权处理")
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 启动不提权；"
          f"需要管理员的功能会在界面按需请求（admin={is_admin()}）")

    import bootstrap  # noqa: PLC0415
    import diagnose  # noqa: PLC0415
    import server  # noqa: PLC0415
    import tshark  # noqa: PLC0415

    try:
        bootstrap.gen_configs()
        cfg = diagnose.load_config()
    except Exception as exc:  # noqa: BLE001
        msgbox(f"初始化失败：{type(exc).__name__}: {exc}\n\n"
               f"请确认项目目录完整：\n{ROOT}", flags=MB_ICONERROR)
        return 1

    # 3. 缺抓包引擎只降级，不阻塞启动：连通与速度测试、报告与设置仍可用，
    #    UI 读 /api/selfcheck 的 capabilities 置灰不可用模式并给修复指引。
    #    这是 F1 的核心行为：绝不因为可选组件缺失弹原生错误框退出。
    if not tshark.find_tshark():
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [警告] 未找到 tshark："
              f"实时抓包/通信观察/分析抓包文件不可用；其余功能继续"
              f"（安装 Wireshark（含 tshark）或设置环境变量 TSHARK_PATH 后重启；"
              f"详见 {DOCS_STARTUP}）")

    # 4. 起服务。idle_exit_min：浏览器关了没人访问就自动退出，
    #    避免「窗口看不见、进程还在」的僵尸状态
    idle_min = int(cfg.get("idle_exit_min", 30) or 0)
    # 提权重启会带 --port <当前端口>：优先绑回同一个，已开着的标签页才不会指向空地址。
    # 常规启动没有这个参数，仍按配置端口 → 顺延 → 端口 0 走。
    wanted = preferred_port() or int(cfg.get("server_port", 8787))
    httpd, url = server.create_server(wanted, idle_exit_min=idle_min, quiet=True)
    if httpd is None:
        # 到这一步说明连「端口 0（系统分配）」都绑不上 —— 本机回环栈不可用，
        # 属于 SPEC 声明的物理例外（8787~8796 全被占**不再是**例外，那时会自动
        # 落到端口 0）。提示面向普通使用者、可操作，不出现本机绝对路径。
        msgbox("本地服务端口绑不上，界面暂时打不开。\n\n"
               "请重启电脑后再试；仍不行请把 logs 目录下的日志发给技术支持。",
               flags=MB_ICONERROR)
        return 1

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 启动 {url} pid={os.getpid()} "
          f"admin={is_admin()} idle_exit={idle_min}min")
    if server.SERVER.get("ephemeral"):
        # 端口 0：地址每次启动都不同，日志里写清「为什么不是 8787」比排查时再猜便宜。
        base_port = int(cfg.get("server_port", 8787))
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [提示] 配置端口 "
              f"{base_port}~{base_port + 9} 都被占用，本次由系统分配端口 "
              f"{server.SERVER.get('port')}（已写 logs/netdiag.port 供启动器读取）")

    def _open() -> None:
        time.sleep(0.4)  # 等 serve_forever 起来，避免瞬间 502
        open_browser(url)   # 内层再判一次 env：线程启动后环境被改也不会误开

    if auto_open:
        threading.Thread(target=_open, daemon=True).start()
    else:
        # env=1（launcher 唯一打开点）或 --elevated：**连线程都不启动**，
        # 避免测量/测试里出现迟到的浏览器窗口。
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 浏览器打开由启动器接管，"
              f"本次不自动打开（{NO_BROWSER_ENV}={os.environ.get(NO_BROWSER_ENV, '') or '0'}）")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        server.cleanup_pid()
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 服务已退出")
    return 0


if __name__ == "__main__":
    sys.exit(main())
