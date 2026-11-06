"""U 盘启动引导：按实际盘符生成配置 + 环境自检。

由 start.bat 调用；也可手动运行 `python core\\bootstrap.py --check`。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parent
ROOT = CORE.parent
sys.path.insert(0, str(CORE))

import tshark  # noqa: E402

PYTHON_EXE = ROOT / "tools" / "python" / "python.exe"
TSHARK_EXE = ROOT / "tools" / "WiresharkPortable" / "App" / "Wireshark" / "tshark.exe"
MCP_DIR = ROOT / "mcp" / "wireshark-mcp"
CONFIG_DIR = ROOT / "config"


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def gen_configs() -> dict:
    """用当前盘符重写 MCP 与 Harness 配置（U 盘盘符变化后自动适配）。"""
    python = PYTHON_EXE if PYTHON_EXE.is_file() else Path(sys.executable)
    tshark_path = tshark.find_tshark() or TSHARK_EXE

    mcp_cfg = {
        "mcpServers": {
            "wireshark-mcp": {
                "command": str(python),
                "args": [str(MCP_DIR / "server.py")],
                "env": {
                    "TSHARK_PATH": str(tshark_path),
                    "USB_NET_DIAG_ROOT": str(ROOT),
                },
            }
        }
    }
    write_json(CONFIG_DIR / "mcp-wireshark.json", mcp_cfg)

    harness_cfg = {
        "workspace": str(ROOT),
        "customSkillDirs": [{"path": str(ROOT / "skills"), "rank": 300}],
        "mcpServersFile": str(CONFIG_DIR / "mcp-wireshark.json"),
        "defaultSkill": "network-diagnose",
        "capturesDir": str(ROOT / "captures"),
        "reportsDir": str(ROOT / "reports"),
    }
    write_json(CONFIG_DIR / "harness-config.json", harness_cfg)
    return {"mcpServersFile": str(CONFIG_DIR / "mcp-wireshark.json"),
            "harnessConfig": str(CONFIG_DIR / "harness-config.json")}


def _scapy_version() -> str:
    """不 import scapy（要 2s），直接读 dist-info，够判断能不能用。"""
    import re
    base = ROOT / "tools" / "python" / "Lib" / "site-packages"
    for d in base.glob("scapy-*.dist-info"):
        m = re.search(r"scapy-([0-9][^-]*)\.dist-info", d.name)
        return m.group(1) if m else "已内置"
    return ""


def check(verbose: bool = True) -> dict:
    ts = tshark.find_tshark()
    npcap = tshark.npcap_installed()
    admin = tshark.is_admin()
    ifaces = tshark.list_interfaces(ts) if ts else []
    status = {
        "root": str(ROOT),
        "python": sys.version.split()[0],
        "python_exe": sys.executable,
        "tshark": str(ts) if ts else "",
        "tshark_version": tshark.version(ts) if ts else "",
        "npcap": npcap,
        "admin": admin,
        "interfaces": [i["name"] for i in ifaces],
        "npcap_installer": str(tshark.find_npcap_installer() or ""),
        "scapy": _scapy_version(),
    }
    if verbose:
        print("=" * 62)
        print(" USB-Net-Diag 环境自检")
        print("=" * 62)
        print(f" 运行目录  : {status['root']}")
        print(f" Python    : {status['python']}  ({status['python_exe']})")
        print(f" tshark    : {status['tshark'] or '未找到 (!)'}")
        if status["tshark_version"]:
            print(f" 版本      : {status['tshark_version']}")
        print(f" Npcap     : {'已就绪' if npcap else '未安装 (!)'}")
        print(f" 管理员    : {'是' if admin else '否（实时抓包可能失败）'}")
        print(f" Scapy     : {status['scapy'] or '未内置（被动监听将用 tshark 兜底）'}")
        print(f" 网卡      : {len(ifaces)} 个")
        for i in ifaces[:8]:
            print(f"            [{i['index']}] {i['name']}")
        print("=" * 62)
    return status


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="仅自检")
    ap.add_argument("--npcap", action="store_true", help="仅检查 Npcap：就绪返回 0，否则返回 1")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if args.npcap:
        return 0 if tshark.npcap_installed() else 1

    if not args.check:
        paths = gen_configs()
        if not args.quiet:
            print(f"[配置] 已按当前盘符生成：{paths['mcpServersFile']}")
            print(f"[配置] {paths['harnessConfig']}")
    st = check(verbose=not args.quiet)
    return 0 if st["tshark"] else 3


if __name__ == "__main__":
    sys.exit(main())
