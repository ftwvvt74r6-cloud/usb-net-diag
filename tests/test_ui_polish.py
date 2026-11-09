"""公共修复（refactor/ui-polish）的静态契约：字阶 / 间距 / 对比度 / 阅读宽度 / 焦点。

这些不是「审美偏好」，每一条都对应一个可复现的缺陷，所以要用测试钉住，
否则下一次改样式又会冒出 10.5px、13px、18px 这类值：

* 字阶：21 种字号里有 9 个半像素值，行高基线永远差 0.5px，页面对不齐；
* 间距：22 种内距值，卡片内对齐线差 1~2px；
* 对比度：``--muted`` 在白底 4.36:1、导航副标题 2.56:1，12px 下不达 WCAG AA；
* 阅读宽度：主区原来铺满 1164px（80~90 汉字/行）；
* 焦点：按钮/导航/折叠头没有焦点样式，Tab 一圈不知道焦点在哪。
"""
from __future__ import annotations

import re
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import _uisrc  # noqa: E402
CSS = _uisrc.css()
HTML = _uisrc.html()

ALLOWED_FS = {"--fs-xs": 12, "--fs-sm": 13, "--fs-base": 14, "--fs-md": 16, "--fs-lg": 20, "--fs-xl": 24}
ALLOWED_SP = {"--sp-1": 4, "--sp-2": 8, "--sp-3": 12, "--sp-4": 16, "--sp-5": 24}


def _lum(hex_color: str) -> float:
    hex_color = hex_color.lstrip("#")
    channels = [int(hex_color[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(fg: str, bg: str) -> float:
    """WCAG 相对对比度（1~21）。"""
    a, b = sorted((_lum(fg), _lum(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


def _token(name: str) -> str:
    m = re.search(rf"{re.escape(name)}\s*:\s*([^;]+);", CSS)
    if not m:
        raise AssertionError(f"app.css 缺少 token：{name}")
    return m.group(1).strip()


class TypeScaleTest(unittest.TestCase):
    """字号只有 6 级，且所有 font-size 都引用 token。"""

    def test_only_six_tokens_defined(self):
        for name, px in ALLOWED_FS.items():
            with self.subTest(token=name):
                self.assertEqual(_token(name), f"{px}px")

    def test_no_literal_px_font_size_left(self):
        literals = re.findall(r"font-size:\s*([0-9.]+)px", CSS)
        self.assertEqual(literals, [], f"仍有字面量字号：{sorted(set(literals))}")

    def test_no_half_pixel_font_size_anywhere(self):
        stripped = re.sub(r"/\*.*?\*/", "", CSS, flags=re.S)
        half = re.findall(r"font-size:[^;}\n]*\.\d+px", stripped)
        self.assertEqual(half, [], f"出现半像素字号：{half[:3]}")

    def test_no_px_inside_font_shorthand(self):
        """``font:13.5px/1.6 …`` 这类简写也藏字号，必须一并收进 token。"""
        bad = re.findall(r"font://s*[0-9.]+px", re.sub(r"/\*.*?\*/", "", CSS, flags=re.S))
        self.assertEqual(bad, [], f"font 简写里仍有字面量字号：{bad[:3]}")

    def test_every_font_size_uses_a_token(self):
        values = re.findall(r"font-size:\s*([^;}]+)", CSS)
        bad = [v for v in values if not v.strip().startswith("var(--fs-")]
        self.assertEqual(bad, [], f"这些 font-size 没走 token：{bad[:5]}")


class SpacingScaleTest(unittest.TestCase):
    """内距只有 5 档（4/8/12/16/24），不再有 7/9/11/13/18px 这类零散值。"""

    def test_five_tokens_defined(self):
        for name, px in ALLOWED_SP.items():
            with self.subTest(token=name):
                self.assertEqual(_token(name), f"{px}px")

    def test_no_stray_padding_or_margin_px(self):
        stray = []
        for m in re.finditer(r"(?:padding|margin|gap)(?:-[a-z]+)?\s*:\s*([^;}]+)", CSS):
            for num in re.findall(r"(?<![\w-])([0-9]+)px", m.group(1)):
                value = int(num)
                # 1~3px 是芯片内视觉微调，>=29px 是版式级留白，都不进节奏
                if 5 <= value <= 28:
                    stray.append(f"{m.group(0)[:40]} -> {value}px")
        self.assertEqual(stray, [], f"仍有零散内距：{stray[:5]}")


class ContrastTest(unittest.TestCase):
    """辅助文字在 12px 下必须达到 WCAG AA（4.5:1）。"""

    def _muted(self) -> str:
        return _token("--muted")

    def test_muted_on_white(self):
        self.assertGreaterEqual(contrast(self._muted(), "#ffffff"), 4.5)

    def test_muted_on_page_background(self):
        self.assertGreaterEqual(contrast(self._muted(), _token("--bg")), 4.5)

    def test_no_legacy_low_contrast_grey(self):
        """旧灰值不许再出现在**声明**里（注释里留对比度说明是可以的）。"""
        stripped = re.sub(r"/\*.*?\*/", "", CSS, flags=re.S)
        for legacy in ("#94a3b8", "#6b7a90"):
            with self.subTest(colour=legacy):
                self.assertNotIn(legacy, stripped,
                                 "这个灰在白底 <4.5:1，已被 --muted 取代")

    def test_semantic_colours_unchanged(self):
        """颜色语义不改：info 灰白 / success 青绿 / warn 琥珀 / 仅真错误红。"""
        self.assertEqual(_token("--ok").lower(), "#059669")
        self.assertEqual(_token("--warn").lower(), "#b45309")
        self.assertEqual(_token("--crit").lower(), "#b91c1c")


class ReadingWidthTest(unittest.TestCase):
    def test_read_token_is_960(self):
        self.assertEqual(_token("--read"), "960px")

    def test_main_children_are_capped_and_centred(self):
        self.assertRegex(
            CSS, r"\.main-scroll > \*\{[^}]*max-width:var\(--read\)[^}]*margin-left:auto")


class FocusAndModalTest(unittest.TestCase):
    def test_focus_visible_rule_exists(self):
        self.assertIn(":focus-visible", CSS)
        self.assertIn("--focus", CSS)

    def test_no_outline_none_without_replacement(self):
        # 允许关 outline 的地方必须同时给 box-shadow 兜底（.btn/.topbtn 那两条）
        stripped = re.sub(r"/\*.*?\*/", "", CSS, flags=re.S)
        for m in re.finditer(r"([^{}]+)\{([^}]*outline:none[^}]*)\}", stripped):
            with self.subTest(selector=m.group(1).strip()[:40]):
                self.assertIn("box-shadow", m.group(2),
                              f"{m.group(1).strip()} 关了 outline 却没给替代焦点样式")

    def test_all_five_masks_wired(self):
        for mask in ("startup-mask", "perm-mask", "cap-mask", "link-mask", "ai-mask"):
            with self.subTest(mask=mask):
                self.assertIn(f'"{mask}"', HTML)
        self.assertIn("function wireModalA11y", HTML)
        self.assertIn("wireModalA11y();", HTML, "只在定义没调用，等于没接")
        self.assertIn('attributeFilter: ["class"]', HTML)

    def test_escape_maps_to_each_modal_own_button(self):
        self.assertIn('"startup-mask": "#startup-limited"', HTML)
        self.assertIn('"perm-mask": "#perm-cancel"', HTML)
        self.assertIn('"cap-mask": "#cap-close"', HTML)
        self.assertIn('"link-mask": "#link-cancel"', HTML)

    def test_focus_trap_wraps_tab(self):
        self.assertIn("e.shiftKey && document.activeElement === first", HTML)
        self.assertIn("!e.shiftKey && document.activeElement === last", HTML)

    def test_focus_return_has_fallback_target(self):
        """启动检测是自动弹的，没有触发控件；不能把焦点丢回 body。"""
        self.assertIn("back !== document.body", HTML)
        self.assertIn('($("#run") || document.querySelector("[data-mode]"))', HTML)


class AppBarStabilityTest(unittest.TestCase):
    """顶栏不许因为「徽章多了一个」而重排。

    原缺陷：``.appright`` 与 ``#badges`` 都是 ``flex-wrap:wrap``。多出一个
    临时徽章（探测中 / 分析中）时，徽章换到第二行被 56px 的顶栏裁掉一半，
    同时把按钮组挤动 1~3px。屏幕上读起来就是顶栏在「抖」。
    断言取**层叠之后**的值，所以基准规则里写着 wrap 也不算过——
    只要后面有一条更晚的 nowrap 把它盖掉即可（这正是本次修法）。
    """

    @staticmethod
    def _last_decl(selector: str, prop: str) -> str | None:
        """按出现顺序取某个选择器最后一条声明的 prop 值（够用的层叠模拟）。"""
        stripped = re.sub(r"/\*.*?\*/", "", CSS, flags=re.S)
        value = None
        for m in re.finditer(r"([^{}]+)\{([^}]*)\}", stripped):
            if selector not in [s.strip() for s in m.group(1).split(",")]:
                continue
            hit = re.search(rf"(?:^|;)\s*{prop}\s*:\s*([^;]+)", m.group(2))
            if hit:
                value = hit.group(1).strip()
        return value

    def test_badges_never_wrap(self):
        self.assertEqual(self._last_decl("#badges", "flex-wrap"), "nowrap",
                         "徽章换行 = 第二行被顶栏裁掉 + 按钮位移，必须 nowrap")

    def test_badge_container_absorbs_width_not_buttons(self):
        self.assertEqual(self._last_decl(".appright", "flex-wrap"), "nowrap")
        self.assertEqual(self._last_decl(".appbar .brand", "flex"), "0 0 auto",
                         "品牌区一旦参与收缩，徽章变多时 logo 文案会被压出省略号")

    def test_buttons_keep_intrinsic_width(self):
        self.assertRegex(CSS, r"\.appright>button\{[^}]*flex:none")


if __name__ == "__main__":
    unittest.main(verbosity=2)
