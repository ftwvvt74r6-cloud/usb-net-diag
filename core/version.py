"""产品版本号的唯一读取点：仓库根 ``VERSION``（UTF-8，容忍 BOM 与首尾空白）。

为什么要有这一层（L 轮补丁）：版本号会出现在启动横幅、``/api/ping`` / ``/api/app``、
报告 ``provenance``、环境快照与诊断包 ``README.txt``。过去 ``server`` / ``analyzer`` /
``logstore`` / ``diagpack`` 四处各写一遍 ``read_text(...).strip()``；``strip()`` 只去
空白、不去 UTF-8 BOM（U+FEFF，Windows 记事本保存时默认写入），同一份带 BOM 的
``VERSION`` 会被读成「不可见字符 + 0.2.0」。读取口径收敛到这里后，BOM 处理只有一份实现。
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_version(root: Path | None = None) -> str:
    """读取 ``root/VERSION`` 里的产品版本号。

    Args:
        root: 仓库根目录（``VERSION`` 所在目录）；``None`` 表示本文件所在
            ``core/`` 的上一级。测试可传临时目录。

    Returns:
        str: 形如 ``0.2.0`` 的版本号。文件缺失、读失败、内容为空或只有
        UTF-8 BOM 时回退 ``0.0.0``，任何情况都不抛异常。
    """
    base = Path(root) if root is not None else ROOT
    try:
        version = (base / "VERSION").read_text(encoding="utf-8")
    except OSError:
        return "0.0.0"
    return version.lstrip("\ufeff").strip() or "0.0.0"
