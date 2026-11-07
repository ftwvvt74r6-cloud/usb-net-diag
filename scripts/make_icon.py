"""生成 NetDiag 品牌图标（纯标准库：手写 PNG + ICO 容器）。

品牌语义：深蓝圆角方底 + 四个网络层节点（L2/L3/L4/L7）连成矩阵 + 一个高亮节点，
对应「网络矩阵 · 四层定位」。所有图形用归一化坐标定义，再按目标尺寸做解析式
抗锯齿渲染，因此 16px 下依然是四个实心圆点 + 至少 2px 的实线，不会糊成一团。

产物：
  * ``NetDiag.ico``                 7 个尺寸：16 / 24 / 32 / 48 / 64 / 128 / 256
  * ``docs/assets/logo-256.png``    256px 品牌图（README / PR 预览用）

``docs/assets/logo.svg`` 是同一套几何的矢量源，手工维护（不依赖字体）。
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: ICO 内按从大到小排列会被 Windows 按需挑选，这里升序打包、目录项数 = 7。
SIZES = (16, 24, 32, 48, 64, 128, 256)

# ---- 设计常量（归一化到 0..1 画布）-------------------------------------------
CORNER_INSET = 0.02          # 圆角方底离画布边距
CORNER_RADIUS = 0.20         # 圆角半径
NODE_RADIUS = 0.085          # 节点半径；16px 下再抬到最小 1.45px
NODE_RADIUS_MIN = 1.7        # 16px 下节点直径约 3.4px，仍能和 2px 连线分开
HIGHLIGHT_SCALE = 1.18       # 高亮节点略大，16px 下也能一眼看出来
LINE_HALF = 0.017            # 连线半宽；16px 下抬到最小 1px（线宽 >= 2px）
LINE_HALF_MIN = 1.0
NODE_CENTERS = (             # 2×2 矩阵四角：L2 / L3 / L7 / L4（顺时针）
    (0.285, 0.285),
    (0.715, 0.285),
    (0.715, 0.715),
    (0.285, 0.715),
)
HIGHLIGHT_INDEX = 1          # 右上角节点 = 高亮
EDGES = ((0, 1), (1, 2), (2, 3), (3, 0))

BG_TOP = (12, 27, 51)        # #0C1B33 深海军蓝
BG_BOTTOM = (30, 58, 138)    # #1E3A8A 品牌蓝
LINE_COLOR = (196, 214, 240)  # #C4D6F0 冷白
NODE_COLOR = (234, 242, 255)  # #EAF2FF 近白
GLOW_COLOR = (56, 189, 248)   # #38BDF8 品牌青（高亮节点）


def _clamp01(v: float) -> float:
    """把浮点覆盖度夹到 0..1。"""
    return 0.0 if v < 0.0 else 1.0 if v > 1.0 else v


def _mix(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    """线性混色：``t=0`` 取 a，``t=1`` 取 b。"""
    return (
        int(a[0] + (b[0] - a[0]) * t + 0.5),
        int(a[1] + (b[1] - a[1]) * t + 0.5),
        int(a[2] + (b[2] - a[2]) * t + 0.5),
    )


def _rounded_rect_alpha(x: float, y: float, n: float) -> float:
    """圆角方形底的解析覆盖度（0..1），自带 1px 级抗锯齿。"""
    half = n / 2 - CORNER_INSET * n
    radius = CORNER_RADIUS * n
    qx = abs(x - n / 2) - (half - radius)
    qy = abs(y - n / 2) - (half - radius)
    dx, dy = max(qx, 0.0), max(qy, 0.0)
    dist = (dx * dx + dy * dy) ** 0.5 + min(max(qx, qy), 0.0) - radius
    return _clamp01(0.5 - dist)


def _segment_alpha(x: float, y: float, x1: float, y1: float,
                   x2: float, y2: float, half: float) -> float:
    """点到线段距离 → 胶囊形覆盖度；``half`` 是线宽的一半（像素）。"""
    dx, dy = x2 - x1, y2 - y1
    length2 = dx * dx + dy * dy
    if length2 <= 0:
        t = 0.0
    else:
        t = _clamp01(((x - x1) * dx + (y - y1) * dy) / length2)
    px, py = x1 + t * dx, y1 + t * dy
    dist = ((x - px) ** 2 + (y - py) ** 2) ** 0.5
    return _clamp01(half + 0.5 - dist)


def paint(n: int) -> bytearray:
    """按 ``n×n`` 画一张 RGBA 图（直接目标分辨率 + 解析式抗锯齿）。"""
    px = bytearray()
    node_r = max(NODE_RADIUS * n, NODE_RADIUS_MIN)
    line_half = max(LINE_HALF * n, LINE_HALF_MIN)
    centers = [(cx * n, cy * n) for cx, cy in NODE_CENTERS]
    for j in range(n):
        y = j + 0.5
        for i in range(n):
            x = i + 0.5
            alpha = _rounded_rect_alpha(x, y, n)
            if alpha <= 0.002:
                px += b"\x00\x00\x00\x00"
                continue
            color = _mix(BG_TOP, BG_BOTTOM, _clamp01((x + y) / (2 * n)))

            for a, b in EDGES:
                cov = _segment_alpha(x, y, *centers[a], *centers[b], line_half)
                if cov > 0.0:
                    color = _mix(color, LINE_COLOR, cov)

            for idx, (cx, cy) in enumerate(centers):
                radius = node_r * (HIGHLIGHT_SCALE if idx == HIGHLIGHT_INDEX else 1.0)
                dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
                cov = _clamp01(radius + 0.5 - dist)
                if cov > 0.0:
                    shade = GLOW_COLOR if idx == HIGHLIGHT_INDEX else NODE_COLOR
                    color = _mix(color, shade, cov)

            px += bytes((color[0], color[1], color[2], int(alpha * 255 + 0.5)))
    return px


def png(n: int) -> bytes:
    """把 ``paint(n)`` 的像素数据封成 PNG（8bit RGBA，无第三方库）。"""
    raw = paint(n)
    rows = b"".join(
        b"\x00" + bytes(raw[j * n * 4:(j + 1) * n * 4]) for j in range(n)
    )

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0)  # 8bit RGBA
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def build_ico(sizes: tuple[int, ...] = SIZES) -> bytes:
    """把每个尺寸的 PNG 打包成 ICO（每项 1 个 PNG，32bit RGBA）。"""
    blobs = [(n, png(n)) for n in sizes]
    head = struct.pack("<HHH", 0, 1, len(blobs))
    offset = 6 + 16 * len(blobs)
    entries, data = b"", b""
    for n, blob in blobs:
        # ICO 里 256 的宽高字节写 0（规范约定），其余写实际像素
        dim = 0 if n >= 256 else n
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
        data += blob
    return head + entries + data


def main() -> int:
    """生成 ``NetDiag.ico`` 与 ``docs/assets/logo-256.png``，并打印尺寸清单。"""
    ico_bytes = build_ico()
    ico_path = ROOT / "NetDiag.ico"
    ico_path.write_bytes(ico_bytes)

    assets = ROOT / "docs" / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    logo_path = assets / "logo-256.png"
    logo_path.write_bytes(png(256))

    print(f"已生成 {ico_path}（{ico_path.stat().st_size / 1024:.1f} KB，"
          f"{len(SIZES)} 个尺寸：{'/'.join(str(n) for n in SIZES)}）")
    print(f"已生成 {logo_path}（{logo_path.stat().st_size / 1024:.1f} KB，256×256）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
