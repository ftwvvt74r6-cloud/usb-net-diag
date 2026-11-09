"""一键切换 UI 入口版本（写 ``config/ui-version.json``，无需重启服务）。

``server.ui_entry`` 读的是同一份 ``config/ui-version.json``，所以脚本写完后，
下一个无 ``?ui=``、无 ``nd_ui`` Cookie 的请求立刻按新版本走；已经带 Cookie 的
浏览器仍按 Cookie（优先级高于 config），要生效请清 Cookie 或改用 ``?ui=``。

用法（在仓库根目录）::

    python scripts/ui_switch.py v1     # 回 v1（默认）
    python scripts/ui_switch.py v2     # 切到 v2

只接受 ``v1`` / ``v2``，其它值退出码 2；写文件失败（目录不存在/不可写）退出码 1。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "ui-version.json"


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in ("v1", "v2"):
        print("用法：python scripts/ui_switch.py v1|v2", file=sys.stderr)
        return 2
    version = argv[0]
    try:
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.write_text(
            json.dumps({"default": version}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"写 {CONFIG} 失败：{exc}", file=sys.stderr)
        return 1
    print(f"已切换 UI 入口到 {version}（写入 {CONFIG}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
