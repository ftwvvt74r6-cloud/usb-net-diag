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


# ----------------------------------------------------------------- 基础工具
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


def relaunch_as_admin() -> bool:
    """用 UAC 提权重启自己。

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
        # pythonw 提权后仍无控制台；__file__ 用绝对路径，工作目录设为 ROOT
        params = f'"{Path(__file__).resolve()}" --elevated'
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, str(ROOT), 1)
        return int(rc) > 32
    except Exception:  # noqa: BLE001
        return False


def find_running() -> str:
    """探测本机是否已有实例在跑（单实例保护）。

    逐个试 8787~8796 的 ``/api/ping``，并核对 ``app`` 字段是本程序，
    避免把别的服务误认成自己。

    Returns:
        str: 已运行实例的界面地址（如 ``http://127.0.0.1:8787/``）；没有则空串。
    """
    try:
        import server  # noqa: PLC0415

        base = int(server.diagnose.load_config().get("server_port", 8787))
    except Exception:  # noqa: BLE001
        base = 8787
    for port in range(base, base + 10):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ping", timeout=0.7) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            if data.get("app") == "USBNetDiag" and data.get("ok"):
                return data.get("url") or f"http://127.0.0.1:{port}/"
        except Exception:  # noqa: BLE001
            continue
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
        int | None: 第一个可绑定的端口号；全部被占用时 ``None``。
    """
    for port in range(int(base), int(base) + max(0, int(count))):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            sock.close()
    return None


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
        webbrowser.open(url)
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
    httpd, url = server.create_server(int(cfg.get("server_port", 8787)),
                                      idle_exit_min=idle_min, quiet=True)
    if httpd is None:
        # 8787~8796 全被占 = 物理上无法起本地服务，属于 SPEC 声明的例外；
        # 提示面向一线、可操作，不出现本机绝对路径/开发者口吻。
        msgbox("本地服务端口 8787~8796 都被占用了，界面暂时打不开。\n\n"
               "请关掉占用这些端口的程序（可能是另一个 NetDiag 窗口或调试工具），"
               "或重启电脑后再试。", flags=MB_ICONERROR)
        return 1

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 启动 {url} pid={os.getpid()} "
          f"admin={is_admin()} idle_exit={idle_min}min")

    def _open() -> None:
        time.sleep(0.4)  # 等 serve_forever 起来，避免瞬间 502
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=_open, daemon=True).start()

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
