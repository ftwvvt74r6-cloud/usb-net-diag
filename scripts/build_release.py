"""一键生成 NetDiag 发布包，并在真解压环境里做构建自检。

法务边界（2026-11 修正）决定这个脚本有**三种包装模式**：

===============  ==========================  ==========  =========================
模式             产物                         含 ``tools/``  用途
===============  ==========================  ==========  =========================
默认（lite）     ``NetDiag-<V>-lite.zip``     否          公开 Release：只发代码，
                                                            Wireshark / Npcap 由用户自装
``--with-tools`` ``NetDiag-<V>-internal.zip`` 是（无 Npcap）内部离线包：Wireshark 随包，
                                                            Npcap 由用户自装
``--with-npcap`` ``NetDiag-<V>-internal-npcap.zip`` 是（含 Npcap）**仅限组织内部**
                                                            同事之间分发，禁止上传公开仓库
===============  ==========================  ==========  =========================

脚本本身只做发布工程，不参与产品运行：

1. ``git archive`` 导出**受控文件**（只含已提交内容，天然排除 ``.git`` /
   ``harness/`` / ``logs/`` / ``config/ai-config.json``）；
2. 按模式决定是否复制本机 ``tools/`` 便携运行时：``--with-tools`` 排除
   ``npcap-*.exe``，``--with-npcap`` 才带上安装包（该模式会打印醒目警告）；
3. 补上包内 ``README.txt``（构建时按模式生成）；``自检.bat`` 随 git 导出；
4. 打成对应模式的 zip（顶层目录 ``NetDiag/``，``ZIP_DEFLATED``），并写
   ``SHA256SUMS.txt``；
5. **自动解压到临时目录**：lite 包用**系统 Python**、带 ``tools/`` 的包用
   **包内便携 Python** 跑全套测试 + 启动器契约，并核对包内清单
   （禁入项 / reports 只留 demo 两份 / 模式对应的 tools 与 Npcap 断言）；
6. 全部通过才输出 ``BUILD OK``；任一步失败退出码非 0。

用法（仓库根目录或任意目录均可）::

    python scripts/build_release.py                       # 公开 lite 包
    python scripts/build_release.py --with-tools          # 内部离线包（无 Npcap）
    python scripts/build_release.py --with-npcap          # 内部离线包（带 Npcap，禁止公开）
    python scripts/build_release.py --out D:\\tmp\\rel
    python scripts/build_release.py --skip-verify         # 仅本地迭代，发布前不要用

注意：``git archive`` 只导出 **HEAD 提交**里的文件。改了代码要先提交，
否则打出来的包是旧内容；工作区有未提交的**已跟踪**改动时脚本默认拒绝构建
（``--allow-dirty`` 可跳过，仅用于本地调试）。
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
PKG_NAME = "NetDiag"
ZIP_COMPRESS_LEVEL = 6
#: 发布包内允许出现的 reports/ 文件（示例报告，其余一律不打包）。
REPORT_ALLOWLIST = ("faults_demo.md", "faults_demo.json")
#: tools/ 里不打包的目录 / 后缀（运行时缓存，不是运行时本身）。
TOOLS_IGNORE_DIRS = {"__pycache__"}
TOOLS_IGNORE_SUFFIXES = {".pyc", ".pyo"}
#: Npcap 安装包文件名模式：``--with-tools`` 必须排除，``--with-npcap`` 才允许。
NPCAP_PATTERN = "npcap-*.exe"
#: 包内禁止出现的路径（红线：密钥、私有运行环境、历史日志）。
FORBIDDEN_PREFIXES = (".git/", "harness/")
FORBIDDEN_EXACT = ("config/ai-config.json",)
#: 维护者发布记录：记录的是「这个 zip 自己的哈希」，放进包里会造成自指，
#: 因此所有模式都排除（它仍在 git 里，随仓库源码走）。
PACKAGE_EXCLUDE = ("docs/release-v0.2.0.md",)
#: 所有模式都必须存在的入口 / 文档 / 示例。
REQUIRED_COMMON = (
    "VERSION",
    "start.bat",
    "NetDiag.vbs",
    "自检.bat",
    "README.txt",
    "core/diagnose.py",
    "core/bootstrap.py",
    "ui/index.html",
    "captures/faults_demo.pcap",
    "reports/faults_demo.md",
    "reports/faults_demo.json",
    "tests/test_launcher_contract.py",
)
#: 只有带 ``tools/`` 的包才要求存在的便携运行时。
REQUIRED_TOOLS = (
    "tools/python/python.exe",
    "tools/WiresharkPortable/App/Wireshark/tshark.exe",
)
MIN_TOOLS_FILES = 1900
MIN_TOOLS_BYTES = 350 * 1024 * 1024
MIN_TEST_COUNT = 235

MODE_LITE = "lite"
MODE_INTERNAL = "internal"
MODE_INTERNAL_NPCAP = "internal-npcap"
#: 每种模式的产物名后缀、是否带 tools、是否带 Npcap 安装包。
MODE_SPECS: dict[str, dict] = {
    MODE_LITE: {"suffix": "lite", "with_tools": False, "with_npcap": False},
    MODE_INTERNAL: {"suffix": "internal", "with_tools": True, "with_npcap": False},
    MODE_INTERNAL_NPCAP: {"suffix": "internal-npcap", "with_tools": True, "with_npcap": True},
}
NPCAP_WARNING = (
    "!!!!  WARNING: this package contains tools/npcap-*.exe  !!!!\n"
    "!!!!  Npcap free edition may NOT be externally redistributed.  !!!!\n"
    "!!!!  Use it ONLY for internal/offline distribution to colleagues.  !!!!\n"
    "!!!!  NEVER upload it to a public GitHub repo, Release or cloud drive.  !!!!"
)


def read_version(root: Path = ROOT) -> str:
    """读根目录 ``VERSION``（去 BOM / 空白；非法时抛 ``ValueError``）。"""
    raw = (root / "VERSION").read_text(encoding="utf-8-sig")
    version = raw.strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError(f"VERSION 格式不对：{version!r}")
    return version


def zip_name(version: str, mode: str) -> str:
    """返回该模式的 zip 文件名（公开包叫 lite，内部包带 ``internal`` 前缀）。"""
    return f"{PKG_NAME}-{version}-{MODE_SPECS[mode]['suffix']}.zip"


def sha256_file(path: Path) -> str:
    """流式计算文件 SHA-256（几百 MB 的 zip 也不吃内存）。"""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def human_bytes(size: int) -> str:
    """把字节数转成便于写进文档的十进制 / 二进制双单位。"""
    return f"{size:,} B ({size / 1024 / 1024:.1f} MiB / {size / 1_000_000:.1f} MB)"


def _run(cmd: list[str], cwd: Path, timeout: int, check: bool = True) -> subprocess.CompletedProcess:
    """跑子进程并解码输出（UTF-8 + 替换非法字节，避免控制台编码炸掉构建）。"""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    proc = subprocess.run(
        cmd, cwd=str(cwd), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout, env=env,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed (rc={proc.returncode}): {' '.join(cmd)}\n"
            f"--- stdout ---\n{proc.stdout[-4000:]}\n"
            f"--- stderr ---\n{proc.stderr[-4000:]}"
        )
    return proc


def check_git_state(root: Path, allow_dirty: bool) -> str:
    """确认仓库干净并返回 HEAD 短 sha；脏工作区按开关决定是否放行。"""
    head = _run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"], root, 30).stdout.strip()
    dirty = _run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
        root, 30,
    ).stdout.strip()
    if dirty and not allow_dirty:
        raise RuntimeError(
            "working tree has tracked changes; commit them first "
            "(or pass --allow-dirty for a throwaway local build):\n" + dirty
        )
    return head


def export_controlled(root: Path, dest_zip: Path) -> None:
    """用 ``git archive`` 导出 HEAD 里所有受控文件（顶层前缀 ``NetDiag/``）。"""
    _run(
        ["git", "-C", str(root), "archive", "--format=zip",
         f"--prefix={PKG_NAME}/", "-o", str(dest_zip), "HEAD"],
        root, 300,
    )


def copy_tools(root: Path, staging: Path, with_npcap: bool) -> tuple[int, int, int]:
    """复制 ``tools/``：只跳过缓存；``with_npcap=False`` 时排除 ``npcap-*.exe``。

    Returns:
        tuple[int, int, int]: ``(文件数, 总字节, 被排除的 Npcap 文件数)``。
    """
    src = root / "tools"
    dst = staging / PKG_NAME / "tools"
    if not src.is_dir():
        raise RuntimeError(f"缺少便携运行时目录：{src}")
    excluded_npcap = 0

    def _ignore(directory: str, names: list[str]) -> set[str]:
        """copytree 的 ignore 回调：滤掉字节码缓存；不带 Npcap 时再滤掉安装包。"""
        nonlocal excluded_npcap
        ignored = {n for n in names if n.lower() in TOOLS_IGNORE_DIRS}
        ignored |= {n for n in names if Path(n).suffix.lower() in TOOLS_IGNORE_SUFFIXES}
        if not with_npcap:
            npcap = {n for n in names if fnmatch.fnmatch(n.lower(), NPCAP_PATTERN)}
            excluded_npcap += len(npcap)
            ignored |= npcap
        return ignored

    shutil.copytree(src, dst, ignore=_ignore, copy_function=shutil.copy2)
    files = [p for p in dst.rglob("*") if p.is_file()]
    count = len(files)
    size = sum(p.stat().st_size for p in files)
    if count < MIN_TOOLS_FILES or size < MIN_TOOLS_BYTES:
        raise RuntimeError(
            f"tools/ 复制不完整：{count} files / {size} bytes "
            f"(expected >= {MIN_TOOLS_FILES} files / {MIN_TOOLS_BYTES} bytes)"
        )
    return count, size, excluded_npcap


def package_readme(version: str, mode: str) -> str:
    """按模式生成包内 ``README.txt``（给拿到 zip 的人看的第一份说明）。"""
    spec = MODE_SPECS[mode]
    if mode == MODE_LITE:
        kind_line = (
            "这个包是公开 lite 包：只含 NetDiag 源码 / 文档 / 测试，"
            "不含 Python、Wireshark、Npcap 等第三方二进制。\n"
            "运行前请按下面第二节自行准备环境（Python 必装）。"
        )
        first_step = "双击 `自检.bat`（或在包根目录的命令行里运行 `自检.bat`；**不要**用 `python 自检.bat`）。"
        launch = (
            "启动控制台：在包根目录运行 `python core\\server.py`（浏览器自动打开\n"
            "http://127.0.0.1:8787/ ，Ctrl+C 停止）。\n"
            "注意：`start.bat` / `NetDiag.vbs` 依赖 `tools\\python`，只有内部离线包才带；\n"
            "lite 包请用上面的 python 命令启动（前提是系统 Python 在 PATH 里）。"
        )
        py_tree = "  python 命令      系统 Python 3.11+（不在包内）"
    elif mode == MODE_INTERNAL:
        kind_line = (
            "这个包是内部离线包：含便携 Python 3.11.9 与 Wireshark 4.7.4（tshark），"
            "但**不含 Npcap 安装包**。请勿把它当作公开 Release 资产上传。"
        )
        first_step = "双击 `自检.bat`：逐项检查 Python / tshark / Npcap / 管理员权限，并用示例抓包跑一次「分析抓包文件」（离线分析）。"
        launch = "双击 `NetDiag.vbs`（推荐，无黑窗、自动提权）或 `start.bat`（带窗口，便于看日志）；浏览器自动打开 http://127.0.0.1:8787/ 。"
        py_tree = "  tools\\python\\      便携 Python 3.11.9（包内自带）"
    else:
        kind_line = (
            "这个包是**内部离线包（含 Npcap 安装器）**：含便携 Python 3.11.9、"
            "Wireshark 4.7.4（tshark）与 npcap-1.79.exe。\n"
            "***** 只能用于组织内部 / 离线机器 **，禁止上传到公开仓库、公开 Release、网盘或外网。 *****"
        )
        first_step = "双击 `自检.bat`：逐项检查 Python / tshark / Npcap / 管理员权限，并用示例抓包跑一次「分析抓包文件」（离线分析）。"
        launch = "双击 `NetDiag.vbs`（推荐，无黑窗、自动提权）或 `start.bat`（带窗口，便于看日志）；浏览器自动打开 http://127.0.0.1:8787/ 。"
        py_tree = "  tools\\python\\      便携 Python 3.11.9（包内自带）"

    if mode == MODE_LITE:
        py_hint = (
            "1) Python 3.11+：本包不含运行时。安装 https://www.python.org/downloads/windows/\n"
            "   安装时勾选 Add python.exe to PATH，然后在包根目录用 python 命令。\n"
        )
        tshark_hint = (
            "2) 分析抓包文件（离线分析）：需要 tshark。安装 Wireshark https://www.wireshark.org/download.html\n"
            "   （安装时勾选 TShark），或把环境变量 TSHARK_PATH 指向 tshark.exe。\n"
        )
        npcap_hint = (
            "3) 全网体检（全网扫描）/ 单目标诊断（定向抓包）/ 通信观察（被动监听）：需要 Npcap 驱动，从 https://npcap.com/#download 下载安装；\n"
            "   并需要管理员权限。分析抓包文件（离线分析）不需要 Npcap。\n"
        )
    elif mode == MODE_INTERNAL:
        py_hint = "1) Python 3.11+：包内已带 tools\\python，无需另装。\n"
        tshark_hint = "2) 分析抓包文件（离线分析）：包内已带 tools\\WiresharkPortable\\...\\tshark.exe，无需另装。\n"
        npcap_hint = (
            "3) 全网体检（全网扫描）/ 单目标诊断（定向抓包）/ 通信观察（被动监听）：需要 Npcap 驱动。本包不含安装器，\n"
            "   请从 https://npcap.com/#download 下载安装；并需要管理员权限。\n"
            "   分析抓包文件（离线分析）不需要 Npcap。\n"
        )
    else:
        py_hint = "1) Python 3.11+：包内已带 tools\\python，无需另装。\n"
        tshark_hint = "2) 分析抓包文件（离线分析）：包内已带 tools\\WiresharkPortable\\...\\tshark.exe，无需另装。\n"
        npcap_hint = (
            "3) 全网体检（全网扫描）/ 单目标诊断（定向抓包）/ 通信观察（被动监听）：包内带 tools\\npcap-1.79.exe，双击安装即可；\n"
            "   并需要管理员权限。分析抓包文件（离线分析）不需要 Npcap。\n"
            "   Npcap 免费版不允许对外再分发：这个安装器只能随本包在组织内部使用。\n"
        )

    tools_tree = (
        "  tools\\           便携 Python + Wireshark(tshark)" +
        (" + Npcap 安装包" if spec["with_npcap"] else "") + "\n"
        if spec["with_tools"] else "  （本包不含 tools\\ 目录）\n"
    )
    return f"""NetDiag（网络矩阵）v{version} 包说明
================================================

{kind_line}

第一次使用
------------------------------------------------
{first_step}
看到 `RESULT: USABLE` 表示**核心功能可用**；若 `tshark` / `Npcap` / 管理员 显示 WARN，
则对应能力暂不可用（分析抓包文件、全网体检、单目标诊断、通信观察），按 WARN 提示补齐后重跑即可。
{launch}

运行前提
------------------------------------------------
{py_hint}{tshark_hint}{npcap_hint}

不会联网、不会上传
------------------------------------------------
工具只监听 127.0.0.1，不向任何服务器发数据；只有你主动点「AI 解读」并配置了
模型接口时才会访问你填的地址。抓包文件、报告、日志都只写在本目录下。

导出诊断包（反馈问题时用）
------------------------------------------------
- 界面右上角「导出诊断包」；或双击 `导出诊断包.bat`；
- 默认已脱敏（IP / 域名 / 用户名 / MAC 替换为伪名），不含 pcap；
  只有加 `--raw` 才会保留原始值，**不要**把 --raw 的包发给不可信的人。

反馈问题
------------------------------------------------
请附上：① 复现步骤与现象；② 「导出诊断包」生成的 zip；③ 如果是判定问题，
附示例 pcap（先确认里面没有敏感流量）。不要直接贴 API Key。

目录说明
------------------------------------------------
  core\\        诊断引擎与本地服务
  ui\\          单文件控制台
  captures\\    抓包落盘（含 faults_demo.pcap 示例）
  reports\\     报告落盘（含 faults_demo 示例报告）
  logs\\        运行日志（首次运行自动生成）
  config\\      配置（ai-config.json / app-config.json 首次运行按示例生成）
{py_tree}
{tools_tree}  docs\\        使用与开发文档（含 build.md / licensing.md）

本包不包含可选的 `harness/`（DeepSeek Harness Agent 底座）；需要 Agent 能力时
请单独准备。版本与更新记录见 `CHANGELOG.md`。
"""


def build_zip(staging: Path, zip_path: Path) -> int:
    """把暂存目录打成 zip（目录条目 + 文件条目；路径统一用 ``/``）。"""
    files = 0
    started = time.monotonic()
    with zipfile.ZipFile(
        zip_path, "w", compression=zipfile.ZIP_DEFLATED,
        compresslevel=ZIP_COMPRESS_LEVEL, allowZip64=True,
    ) as zf:
        for dirpath, dirnames, filenames in os.walk(staging):
            dirnames.sort()
            filenames.sort()
            current = Path(dirpath)
            rel = current.relative_to(staging)
            arc_dir = PurePosixPath(*rel.parts) if rel.parts else PurePosixPath()
            if rel.parts:
                zf.write(current, str(arc_dir))
            for name in filenames:
                zf.write(current / name, str(arc_dir / name))
                files += 1
                if files % 500 == 0:
                    elapsed = time.monotonic() - started
                    print(f"  zipped {files:>5} files ... {elapsed:5.1f}s", flush=True)
    return files


def _zip_names(zip_path: Path) -> list[str]:
    """列出 zip 条目名（``/`` 分隔）。"""
    with zipfile.ZipFile(zip_path) as zf:
        return zf.namelist()


def assert_manifest(pkg_root: Path, mode: str) -> dict:
    """核对解压后的包内清单：模式对应的 tools/Npcap、禁入项、reports 白名单等。"""
    spec = MODE_SPECS[mode]
    pkg = pkg_root / PKG_NAME
    if not pkg.is_dir():
        raise RuntimeError(f"包内顶层目录不是 {PKG_NAME}/：{pkg}")

    all_files = sorted(p.relative_to(pkg).as_posix() for p in pkg.rglob("*") if p.is_file())
    forbidden = [
        rel for rel in all_files
        if rel.startswith(FORBIDDEN_PREFIXES) or rel in FORBIDDEN_EXACT
        or rel.startswith("logs/")
    ]
    if forbidden:
        raise RuntimeError(f"包内出现禁止项：{forbidden[:10]}")
    leaked = [rel for rel in all_files if rel in PACKAGE_EXCLUDE]
    if leaked:
        raise RuntimeError(f"发布记录不该进包（会自指）：{leaked}")

    reports = sorted(p.name for p in (pkg / "reports").iterdir() if p.is_file())
    if reports != sorted(REPORT_ALLOWLIST):
        raise RuntimeError(f"reports/ 只应保留 {REPORT_ALLOWLIST}，实际：{reports}")

    missing = [rel for rel in REQUIRED_COMMON if not (pkg / rel).exists()]
    if missing:
        raise RuntimeError(f"包内缺少必要文件：{missing}")

    bat = (pkg / "自检.bat").read_bytes()
    if any(byte > 0x7F for byte in bat):
        raise RuntimeError("自检.bat 必须是纯 ASCII（避免 cp1252/cp936 乱码）")
    if b"\r\n" not in bat:
        raise RuntimeError("自检.bat 必须是 CRLF 换行（cmd.exe 兼容）")

    if spec["with_tools"]:
        missing = [rel for rel in REQUIRED_TOOLS if not (pkg / rel).exists()]
        if missing:
            raise RuntimeError(f"包内缺少便携运行时：{missing}")
        pycache = [rel for rel in all_files if "__pycache__" in rel or rel.endswith(".pyc")]
        if pycache:
            raise RuntimeError(f"包内仍有 Python 缓存：{pycache[:5]}")
        tools_files = [rel for rel in all_files if rel.startswith("tools/")]
        tools_bytes = sum((pkg / rel).stat().st_size for rel in tools_files)
        if len(tools_files) < MIN_TOOLS_FILES or tools_bytes < MIN_TOOLS_BYTES:
            raise RuntimeError(
                f"tools/ 不完整：{len(tools_files)} files / {tools_bytes} bytes"
            )
        npcap = sorted(p.name for p in (pkg / "tools").glob(NPCAP_PATTERN))
        if not spec["with_npcap"] and npcap:
            raise RuntimeError(f"--with-tools 包里不允许出现 Npcap 安装包：{npcap}")
        if spec["with_npcap"] and not npcap:
            raise RuntimeError("--with-npcap 包里缺少 Npcap 安装包")
        npcap_label = npcap[0] if npcap else "absent"
    else:
        if (pkg / "tools").exists():
            raise RuntimeError("lite 包里不允许出现 tools/ 目录")
        npcap = [rel for rel in all_files if fnmatch.fnmatch(Path(rel).name.lower(), NPCAP_PATTERN)]
        if npcap:
            raise RuntimeError(f"lite 包里不允许出现 Npcap 安装包：{npcap}")
        tools_files = []
        tools_bytes = 0
        npcap_label = "absent"

    return {
        "files": len(all_files),
        "tools_files": len(tools_files),
        "tools_bytes": tools_bytes,
        "reports": reports,
        "npcap": npcap_label,
        "mode": mode,
    }


def _parse_ran(output: str) -> tuple[int, str]:
    """从 unittest 输出里取 ``Ran N tests`` 与 ``OK...`` 那一行。"""
    ran = re.search(r"^Ran (\d+) tests? in [\d.]+s", output, re.MULTILINE)
    ok = re.search(r"^(OK(?: \(skipped=\d+\))?)$", output, re.MULTILINE)
    if not ran or not ok:
        raise RuntimeError(f"unittest 输出里找不到 Ran/OK：\n{output[-3000:]}")
    return int(ran.group(1)), ok.group(1)


def verify_package(pkg_root: Path, work_dir: Path, mode: str) -> dict:
    """真跑全套测试 + 启动器契约：lite 用系统 Python，带 tools 的包用包内 Python。"""
    pkg = pkg_root / PKG_NAME
    if MODE_SPECS[mode]["with_tools"]:
        python = pkg / "tools" / "python" / "python.exe"
        python_label = "packaged python"
    else:
        python = Path(sys.executable)
        python_label = "system python"
    if not python.is_file():
        raise RuntimeError(f"自检 Python 缺失：{python}")
    log_dir = work_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["NETDIAG_LOG_DIR"] = str(log_dir)
    env["PYTHONIOENCODING"] = "utf-8"
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    print(f"  [verify] using {python_label}: {python}", flush=True)

    def _unittest(args: list[str], timeout: int) -> subprocess.CompletedProcess:
        """在包根目录跑 unittest，返回原始输出（stdout+stderr 合并）。"""
        proc = subprocess.run(
            [str(python), "-m", "unittest", *args], cwd=str(pkg),
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=env,
        )
        proc.stdout = (proc.stdout or "") + (proc.stderr or "")
        return proc

    print("  [verify] full unittest suite ...", flush=True)
    proc = _unittest(["discover", "-s", "tests"], timeout=1800)
    count, ok_line = _parse_ran(proc.stdout)
    if proc.returncode != 0 or count < MIN_TEST_COUNT:
        raise RuntimeError(f"包内测试失败（rc={proc.returncode}）：\n{proc.stdout[-5000:]}")
    print(f"  [verify] {count} tests OK ({ok_line})", flush=True)

    print("  [verify] launcher contract ...", flush=True)
    proc = _unittest(["discover", "-s", "tests", "-p", "test_launcher_contract.py"], timeout=300)
    contract_count, contract_line = _parse_ran(proc.stdout)
    if proc.returncode != 0:
        raise RuntimeError(f"启动器契约失败（rc={proc.returncode}）：\n{proc.stdout[-5000:]}")
    print(f"  [verify] {contract_count} launcher-contract tests OK ({contract_line})", flush=True)

    return {"tests": count, "ok": ok_line, "contract": contract_count,
            "verify_python": str(python)}


def write_sha256sums(out_dir: Path, zip_path: Path) -> Path:
    """写 ``SHA256SUMS.txt``（sha256sum 兼容的“哈希 + 两空格 + 文件名”）。"""
    digest = sha256_file(zip_path)
    sums = out_dir / "SHA256SUMS.txt"
    sums.write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8", newline="\n")
    return sums


def _mode_from_args(args: argparse.Namespace) -> str:
    """把命令行开关折成三种模式之一（``--with-npcap`` 隐含 ``--with-tools``）。"""
    if args.with_npcap:
        return MODE_INTERNAL_NPCAP
    if args.with_tools:
        return MODE_INTERNAL
    return MODE_LITE


def main(argv: list[str] | None = None) -> int:
    """命令行入口：导出 → （可选）复制 tools → 打包 → 写校验 → 解压自检 → ``BUILD OK``。"""
    parser = argparse.ArgumentParser(description="Build a NetDiag release zip (lite / internal)")
    parser.add_argument("--out", default=str(ROOT / "logs" / "dist"),
                        help="产物目录（默认 logs/dist；该目录被 /logs/* 忽略，不会入库）")
    parser.add_argument("--with-tools", action="store_true",
                        help="内部离线包：带 tools/（便携 Python + Wireshark），但排除 npcap-*.exe")
    parser.add_argument("--with-npcap", action="store_true",
                        help="内部离线包：带 tools/ 且带 npcap-*.exe（仅限组织内部分发，禁止公开）")
    parser.add_argument("--skip-verify", action="store_true",
                        help="跳过解压真跑自检（仅本地迭代；发布前不要用）")
    parser.add_argument("--allow-dirty", action="store_true",
                        help="允许已跟踪文件有未提交改动（仅本地调试）")
    parser.add_argument("--keep", action="store_true",
                        help="保留解压后的自检目录，便于人工复核")
    args = parser.parse_args(argv)

    started = time.monotonic()
    version = read_version()
    mode = _mode_from_args(args)
    spec = MODE_SPECS[mode]
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / zip_name(version, mode)
    for stale in (zip_path, out_dir / "SHA256SUMS.txt"):
        if stale.exists():
            stale.unlink()

    print("=" * 74)
    print(f"NetDiag release build  version={version}  mode={mode}")
    print(f"repo   : {ROOT}")
    print(f"output : {out_dir}")
    print("=" * 74)
    if spec["with_npcap"]:
        print(NPCAP_WARNING, flush=True)
    print(flush=True)

    head = check_git_state(ROOT, args.allow_dirty)
    print(f"[1/7] git archive HEAD ({head}) -> controlled files only", flush=True)
    staging = Path(tempfile.mkdtemp(prefix="_stage-", dir=str(out_dir)))
    src_zip = staging / "_src.zip"
    try:
        export_controlled(ROOT, src_zip)
        with zipfile.ZipFile(src_zip) as zf:
            zf.extractall(staging)
            controlled = len([n for n in zf.namelist() if not n.endswith("/")])
        src_zip.unlink()
        for rel in PACKAGE_EXCLUDE:
            excluded_doc = staging / PKG_NAME / rel
            if excluded_doc.is_file():
                excluded_doc.unlink()
        print(f"      {controlled} controlled files "
              f"({len(PACKAGE_EXCLUDE)} release-record doc excluded)", flush=True)

        if spec["with_tools"]:
            print("[2/7] copy tools/ ...", flush=True)
            tools_count, tools_bytes, excluded = copy_tools(ROOT, staging, spec["with_npcap"])
            npcap_note = "INCLUDED (internal only)" if spec["with_npcap"] else "excluded"
            print(f"      tools/: {tools_count} files, {human_bytes(tools_bytes)}", flush=True)
            print(f"      npcap-*.exe: {npcap_note}"
                  f"{f' ({excluded} file skipped)' if excluded else ''}", flush=True)
        else:
            print("[2/7] lite package: skip tools/ (source-only, no third-party binaries)", flush=True)
            tools_count = 0

        print("[3/7] add package README.txt + verify launcher files ...", flush=True)
        readme = staging / PKG_NAME / "README.txt"
        readme.write_text(package_readme(version, mode), encoding="utf-8", newline="\r\n")
        for required in ("自检.bat", "start.bat", "NetDiag.vbs"):
            if not (staging / PKG_NAME / required).is_file():
                raise RuntimeError(f"git archive 里缺少 {required}（是否忘了提交？）")
        (staging / PKG_NAME / "logs").mkdir(exist_ok=True)

        print("[4/7] build zip ...", flush=True)
        files = build_zip(staging, zip_path)
        zip_size = zip_path.stat().st_size
        print(f"      {files} files -> {zip_path.name} ({human_bytes(zip_size)})", flush=True)

        print("[5/7] write SHA256SUMS.txt ...", flush=True)
        sums = write_sha256sums(out_dir, zip_path)
        print(f"      {sums.read_text(encoding='utf-8').strip()}", flush=True)

        result = {"files": files, "zip_bytes": zip_size, "sha256": sha256_file(zip_path)}
        if not args.skip_verify:
            print("[6/7] extract to a temp dir and run the self-check ...", flush=True)
            verify_dir = Path(tempfile.mkdtemp(prefix="_verify-", dir=str(out_dir)))
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    zf.extractall(verify_dir)
                manifest = assert_manifest(verify_dir, mode)
                print(f"      package files={manifest['files']} "
                      f"tools={manifest['tools_files']} "
                      f"reports={manifest['reports']} npcap={manifest['npcap']}", flush=True)
                checks = verify_package(verify_dir, verify_dir, mode)
                result.update(checks)
            finally:
                if args.keep:
                    print(f"      kept verify dir: {verify_dir}", flush=True)
                else:
                    shutil.rmtree(verify_dir, ignore_errors=True)
        else:
            print("[6/7] SKIP verify (--skip-verify)", flush=True)
            result.update({"tests": 0, "ok": "SKIPPED", "contract": 0})

        print("[7/7] summary", flush=True)
        print(f"      mode   : {mode}")
        print(f"      zip    : {zip_path}")
        print(f"      size   : {human_bytes(zip_size)}")
        print(f"      sha256 : {result['sha256']}")
        print(f"      elapsed: {time.monotonic() - started:.1f}s", flush=True)
        if not args.skip_verify:
            print(f"      tests  : Ran {result['tests']} tests ... {result['ok']}")
            print(f"      launch : {result['contract']} tests ... OK")
        if spec["with_npcap"]:
            print()
            print(NPCAP_WARNING)
        print()
        print("BUILD OK")
        return 0
    except Exception as exc:  # noqa: BLE001  发布脚本：给出可读失败原因 + 非 0 退出
        print(f"\nBUILD FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
