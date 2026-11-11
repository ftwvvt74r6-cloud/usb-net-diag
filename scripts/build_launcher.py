"""编译 NetDiag.exe 启动器（Windows 系统自带 csc，零第三方依赖）。

这个脚本解决什么问题：
    ``launcher/NetDiagLauncher.cs`` 是要提交的**源码**，但用户拿到 lite 包时应该
    看到双击就能用的 ``NetDiag.exe``。仓库约定不提交二进制（``*.exe`` 不入库），
    所以构建/发版时用本脚本现场编译。

谁调用它：
    * 维护者本地：``python scripts/build_launcher.py`` → 仓库根 ``NetDiag.exe``；
    * ``scripts/build_release.py``：构建 lite 包时编译到临时目录再塞进 zip；
    * ``tests/test_launcher_exe.py``：``--check`` 在 ubuntu CI 可跑，编译用例在
      有 csc 的 Windows 上跑。

不做什么：
    * 不下载/安装 .NET、不联网、不签名、不写注册表；
    * 不修改系统 Python、不启动服务、不请求管理员权限。

输入输出：
    输入：``launcher/NetDiagLauncher.cs`` + ``launcher/SplashForm.cs``
    + ``launcher/NetDiag.exe.manifest`` + ``NetDiag.ico``。
    输出：目标目录下的 ``NetDiag.exe``（默认仓库根；``--out DIR`` 可改）。

用法::

    python scripts/build_launcher.py                 # 编译到仓库根
    python scripts/build_launcher.py --out D:\\tmp    # 编译到指定目录
    python scripts/build_launcher.py --check         # 只校验源码/manifest，不编译（CI 可跑）
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "launcher" / "NetDiagLauncher.cs"
SPLASH_SOURCE = ROOT / "launcher" / "SplashForm.cs"
MANIFEST = ROOT / "launcher" / "NetDiag.exe.manifest"
ICON = ROOT / "NetDiag.ico"
EXE_NAME = "NetDiag.exe"
#: 一个 /target:winexe 的托管启动器正常约 30~90 KB；小于 8 KB 说明编出来的
#: 不是完整 PE（或只是空壳），发出去双击必然失败，所以在这里就拦住。
MIN_EXE_BYTES = 8 * 1024
COMPILE_TIMEOUT_S = 300
#: splash 用到的系统程序集（.NET Framework 自带，发布包不许带第三方 DLL）。
SYSTEM_ASSEMBLIES = ("System.Windows.Forms.dll", "System.Drawing.dll")

#: --check 的源码契约：任何一条缺失都说明启动器行为被删（例如 --dry-run 没了）。
#: H1/H2/H3/H6 的契约标记也在内 —— 它们对应「单次打开浏览器 / 计时 / splash /
#: 统一 preflight」四件容易在后续重构里被悄悄删掉的事。
REQUIRED_SOURCE_MARKERS = (
    "--dry-run",
    "--report",
    "--measure",
    "--no-splash",
    "--no-browser",
    "--splash-test",
    "--no-elevate",
    "CreateNoWindow = true",
    "UseShellExecute = false",
    "127.0.0.1",
    "PortMin = 8787",
    "PortMax = 8796",
    "PollIntervalMs = 200",
    "ReadyTimeoutMs = 30000",
    '"tools", "python"',
    '"pythonw.exe"',
    '"python.exe"',
    "py.exe",
    "ExitNoPython = 2",
    "ExitWaitTimeout = 3",
    "ExitLaunchFailed = 4",
    "NETDIAG_NO_BROWSER",
    "EnvironmentVariables",
    # S1：并发双击只放行一个启动编排（命名互斥锁 + 异常退出兜底）。
    "Mutex",
    "Global\\NetDiagLauncher",
    "AbandonedMutexException",
    "startup.log",
    "launcher-cache.json",
    "/api/preflight",
    # 端口文件：8787~8796 全被占时服务绑端口 0，启动器只能靠这个文件找到真实端口。
    # 删掉它 = 「端口区间被占满 → 界面打不开」，所以列进契约。
    "netdiag.port",
    "SplashForm",
)


def find_csc() -> Path | None:
    """按「64 位 Framework → 32 位 Framework → PATH」找 csc.exe。

    Returns:
        Path | None: 找到的 csc 绝对路径；都没有时返回 ``None``（由调用方给可操作错误）。
    """
    windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
    candidates = [
        windir / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe",
        windir / "Microsoft.NET" / "Framework" / "v4.0.30319" / "csc.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    found = shutil.which("csc")
    if found:
        return Path(found)
    # 少数环境把 csc 放在 Roslyn 目录，但不在 PATH；不去猜，保持可解释。
    return None


def check_structure() -> list[str]:
    """只读校验源码 / manifest / 图标结构，不依赖 Windows 或 csc。

    Returns:
        list[str]: 问题清单；空列表表示通过。调用方负责打印与退出码。
    """
    problems: list[str] = []
    if not SOURCE.is_file():
        problems.append(f"缺少启动器源码：{SOURCE}")
    elif SOURCE.stat().st_size < 1024:
        problems.append(f"启动器源码异常小（{SOURCE.stat().st_size} 字节）：{SOURCE}")
    if not SPLASH_SOURCE.is_file():
        problems.append(f"缺少 splash 源码：{SPLASH_SOURCE}")
    elif SPLASH_SOURCE.stat().st_size < 1024:
        problems.append(f"splash 源码异常小（{SPLASH_SOURCE.stat().st_size} 字节）：{SPLASH_SOURCE}")
    if not MANIFEST.is_file():
        problems.append(f"缺少 manifest：{MANIFEST}")
    if not ICON.is_file():
        problems.append(f"缺少图标：{ICON}")

    if MANIFEST.is_file():
        text = MANIFEST.read_text(encoding="utf-8")
        if 'level="asInvoker"' not in text:
            problems.append("manifest 缺少 requestedExecutionLevel level=\"asInvoker\"")
        if 'level="requireAdministrator"' in text:
            problems.append("manifest 出现 requireAdministrator：启动器会变成启动即提权")
        # H3 / V13：高 DPI 下 splash 居中不错位必须有 DPI 声明。
        if "dpiAware" not in text:
            problems.append("manifest 缺少 dpiAware（splash 在高 DPI 下会错位）")
        try:
            ET.parse(MANIFEST)
        except ET.ParseError as exc:
            problems.append(f"manifest 不是合法 XML：{exc}")

    combined = ""
    for path in (SOURCE, SPLASH_SOURCE):
        if path.is_file():
            combined += path.read_text(encoding="utf-8") + "\n"
    if combined:
        for marker in REQUIRED_SOURCE_MARKERS:
            if marker not in combined:
                problems.append(f"启动器源码缺少契约标记：{marker}")
        if "requireAdministrator" in combined:
            problems.append("启动器源码出现 requireAdministrator（启动器自身不许提权）")
    return problems


def compile_launcher(csc: Path, out_dir: Path) -> Path:
    """用系统 csc 编译启动器到 ``out_dir/NetDiag.exe``。

    Args:
        csc: csc.exe 路径。
        out_dir: 输出目录（不存在会创建）。

    Returns:
        Path: 编译出的 exe 路径。

    Raises:
        RuntimeError: csc 返回非 0、或产物缺失/小于 :data:`MIN_EXE_BYTES`。
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / EXE_NAME
    cmd = [
        str(csc),
        "/nologo",
        "/target:winexe",
        "/optimize+",
        # 源码是 UTF-8（含中文注释/文案）；中文系统 csc 默认按 ACP936 读会乱码。
        "/codepage:65001",
        "/utf8output",
        f"/win32icon:{ICON}",
        f"/win32manifest:{MANIFEST}",
        f"/out:{out}",
    ]
    # WinForms splash（H3）只用系统 .NET Framework 程序集，发布包不带第三方 DLL。
    for assembly in SYSTEM_ASSEMBLIES:
        cmd.append(f"/r:{assembly}")
    cmd.extend((str(SOURCE), str(SPLASH_SOURCE)))
    proc = subprocess.run(
        cmd, cwd=str(ROOT), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=COMPILE_TIMEOUT_S,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"csc 编译失败（rc={proc.returncode}）\n"
            f"命令：{' '.join(cmd)}\n"
            f"--- stdout ---\n{proc.stdout[-4000:]}\n"
            f"--- stderr ---\n{proc.stderr[-4000:]}"
        )
    if not out.is_file():
        raise RuntimeError(f"csc 返回成功但没有产物：{out}")
    size = out.stat().st_size
    if size < MIN_EXE_BYTES:
        raise RuntimeError(
            f"启动器产物只有 {size} 字节（< {MIN_EXE_BYTES}），不像是完整 exe：{out}"
        )
    return out


def main(argv: list[str] | None = None) -> int:
    """命令行入口：``--check`` 只校验；否则找 csc 并编译。

    Returns:
        int: 0 成功；1 结构/编译失败；2 找不到 csc。
    """
    parser = argparse.ArgumentParser(description="Build the NetDiag.exe launcher with system csc")
    parser.add_argument("--check", action="store_true",
                        help="只校验源码/manifest 结构，不编译（ubuntu CI 可跑）")
    parser.add_argument("--out", default=str(ROOT),
                        help="输出目录（默认仓库根；build_release 用临时目录）")
    parser.add_argument("--quiet", action="store_true", help="只输出最终结果行")
    args = parser.parse_args(argv)

    problems = check_structure()
    if problems:
        print("LAUNCHER CHECK FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    if args.check:
        print(f"LAUNCHER CHECK OK: {SOURCE.relative_to(ROOT)} + "
              f"{SPLASH_SOURCE.relative_to(ROOT)} + "
              f"{MANIFEST.relative_to(ROOT)} (asInvoker, no csc needed)")
        return 0

    csc = find_csc()
    if csc is None:
        print(
            "找不到 csc.exe（.NET Framework 4.x 编译器）。\n"
            "可操作的处理：\n"
            "  1) 确认本机是 Windows 且已安装 .NET Framework 4.x（Windows 10/11 自带）；\n"
            "  2) 检查 %WINDIR%\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe 是否存在；\n"
            "  3) 只验证源码结构可运行：python scripts/build_launcher.py --check。",
            file=sys.stderr,
        )
        return 2

    if not args.quiet:
        print(f"[launcher] csc : {csc}", flush=True)
        print(f"[launcher] src : {SOURCE}", flush=True)
    out = compile_launcher(csc, Path(args.out).resolve())
    print(f"LAUNCHER OK: {out} ({out.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
