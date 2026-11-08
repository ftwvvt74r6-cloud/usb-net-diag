"""启动脚本的中文提示（``start.bat`` 必须保持纯 ASCII，中文只能从 Python 侧输出）。

为什么要有这个文件
------------------
``start.bat`` 在中文 Windows 下会踩一个 cmd 的经典坑：``chcp 65001`` 之后，cmd 仍按
**字节偏移**继续读批处理文件，遇到多字节字符的边界就会把一个汉字劈成两半，后半截被
当成一条命令 —— 现场表现是 ``'鍏朵綑鍔熻兘...' 不是内部或外部命令``，用户看到一串
乱码加报错。实测结论：只要文件里还有非 ASCII 字节，就无法稳定避免断行
（改注释、换全角标点、加 BOM + 空首行都试过，断行数分别是 5 / 2 / 5）。

所以分工改成：``start.bat`` 只做探测与调用（全 ASCII），所有面向用户的中文提示都由
本模块输出。模块用 UTF-8 字节直接写 stdout，不再经过 locale 编码，避免在 cp936 环境
下二次转码。

用法::

    python core/startmsg.py <key> [参数...]

退出码：0 正常输出；2 未知 key（此时**不输出任何内容**，调用方自己决定兜底）。
"""
from __future__ import annotations

import sys

#: key -> 消息模板。``{0}`` 之类的位置参数由命令行追加参数填充。
MESSAGES: dict[str, str] = {
    "banner": (
        "============================================================\n"
        "  NetDiag · 网络矩阵   便携网络诊断工具\n"
        "  运行目录: {0}\n"
        "============================================================"
    ),
    "admin_elevating": ' [*] 正在请求管理员权限（UAC 请点"是"）...',
    "admin_cancelled": " [!] 提权被取消，以普通权限继续：实时抓包/通信观察可能不可用。",
    "no_admin": (
        " [i] 当前以普通权限运行（启动不请求管理员权限）。\n"
        "     分析抓包文件、连通与速度测试不受影响；\n"
        "     实时抓包 / 通信观察需要管理员权限时，请在界面里按需提权，\n"
        "     或关闭本窗口后运行: start.bat --admin"
    ),
    "portable_fallback": " [i] 未找到包内 Portable Python，回退到系统运行时：{0}",
    "no_tshark": (
        " [警告] 未找到 tshark：实时抓包 / 通信观察 / 分析抓包文件不可用；"
        "其余功能照常，界面会提示怎么修复。"
    ),
    "npcap_missing": " [*] Npcap 驱动未就绪，启动交互式安装向导（需 UAC 授权）...",
    "npcap_file": "     正在启动安装向导: {0}",
    "npcap_hint": "     请在向导里完成安装（免费版不支持 /S 静默安装）。",
    "npcap_installed": " [OK] Npcap 安装完成。",
    "npcap_failed": (
        " [!] Npcap 仍未就绪，实时抓包不可用；"
        "「分析抓包文件」（离线分析，上传 pcap）不受影响。\n"
        "     可手动安装：https://npcap.com/#download"
    ),
    "npcap_ready": " [OK] Npcap 驱动就绪。",
    "harness_hint": " [i] 检测到 DeepSeek Harness（Agent 底座）。如需同时启动请运行: start.bat ai",
    "harness_start": " [*] 启动 Agent 底座: {0}",
    "start_ui": (
        " [*] 启动本地诊断服务，浏览器将自动打开...\n"
        "     （关闭本窗口即停止服务；界面右上角「退出」也可以）\n"
        " [i] 日常使用建议双击 NetDiag.exe：无控制台窗口、启动不提权\n"
        "     本文件（start.bat）是 Python 回退入口，需要管理员时用 start.bat --admin"
    ),
    "bye": "  服务已退出。",
}


def render(key: str, args: list[str] | None = None) -> str:
    """按 key 生成消息文本；未知 key 抛 ``KeyError``（调用方据此回退出码 2）。"""
    template = MESSAGES[key]
    return template.format(*(args or []))


def main(argv: list[str] | None = None) -> int:
    """把消息以 UTF-8 字节写进 stdout（不经 locale 转码）。"""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return 2
    try:
        text = render(argv[0], argv[1:])
    except (KeyError, IndexError):
        return 2
    out = getattr(sys.stdout, "buffer", None)
    payload = (text + "\r\n").encode("utf-8")
    if out is None:  # 测试里被 StringIO 替换时退化成文本写
        sys.stdout.write(text + "\n")
    else:
        out.write(payload)
        out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
