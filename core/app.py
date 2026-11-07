"""静默启动器：像应用一样双击即用，全程不弹控制台窗口。

由 NetDiag.vbs 用 pythonw.exe 拉起（pythonw 无控制台），流程：
  1. 已有实例在跑 → 直接把浏览器指过去，退出（避免开第二份
  2. 非管理员 → 用 UAC 提权重启自己（抓包需要 Npcap 的驱动权限）；
     用户点「否」就降级为普通权限继续跑，分析抓包文件 / 连通与速度测试仍可用
  3. 生成配置 → 起本地服务（后台线程）→ 打开浏览器
  4. 界面点「退出」或长时间无人访问 → 自动收尾，不留后台进程

手工调试可以 `python core/app.py --console` 前台跑，看得到日志。
"""
from __future__ import annotations

import ctypes
import json
import os
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


# --------------------------------------------------------------------- 主流程
def main() -> int:
    """静默启动主流程。

    顺序：日志基建 → 重定向输出 → 探测已有实例 → 需要时提权 → 建监听 → 开浏览器 → 阻塞。

    Returns:
        int: 进程退出码。0 = 正常（含「已有实例，直接把浏览器叫起来」和
            「已拉起提权进程」两种提前返回）；1 = 端口全被占用。
    """
    # 日志基建（每次启动一次）：目录 → 裁剪 → 环境快照 → 崩溃钩子。
    # 必须在 redirect_output 之前裁剪：此时当天的 app 日志还没被本进程打开。
    logstore.ensure_dirs()
    logstore.prune()
    logstore.write_env_snapshot({"entry": "app"})
    logstore.install_excepthooks()
    redirect_output()
    as_console = "--console" in sys.argv
    elevated = "--elevated" in sys.argv

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

    # 2. 提权（只做一次）。UAC 被拒就以普通权限继续，功能降级但不崩
    if not is_admin():
        if not elevated and relaunch_as_admin():
            return 0
        if not as_console:
            msgbox("未获得管理员权限：全网体检 / 单目标诊断 / 通信观察将不可用"
                   "（分析抓包文件、连通与速度测试仍可用）。\n\n"
                   "如需完整功能，请关闭后右键 NetDiag.vbs 选择"
                   "「以管理员身份运行」，或用 start.bat 启动。")

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

    if not tshark.find_tshark():
        msgbox("没找到 tshark，抓包与分析抓包文件都不可用。\n\n"
               "请把 Wireshark 便携版解压到：\n"
               f"{ROOT}\\tools\\WiresharkPortable\\App\\Wireshark\\",
               flags=MB_ICONERROR)
        return 1

    # 3. 起服务。idle_exit_min：浏览器关了没人访问就自动退出，
    #    避免「窗口看不见、进程还在」的僵尸状态
    idle_min = int(cfg.get("idle_exit_min", 30) or 0)
    httpd, url = server.create_server(int(cfg.get("server_port", 8787)),
                                      idle_exit_min=idle_min, quiet=True)
    if httpd is None:
        msgbox("端口 8787-8796 都被占用了，无法启动本地服务。\n"
               "请关掉占用端口的程序后重试。", flags=MB_ICONERROR)
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
