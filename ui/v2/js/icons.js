/* ============================================================================
   icons.js · 手写线条图标（无图标库、无字体图标、无外链）
   ----------------------------------------------------------------------------
   统一规格：viewBox 0 0 24 24、stroke-width 1.8、currentColor、圆头圆角、
   fill:none（个别实心点单独标 fill）。装饰性一律 aria-hidden，
   名字由相邻文字或 title/aria-label 承担。
   ========================================================================== */
(function (ND) {
  "use strict";

  var PATHS = {
    /* 总览：仪表盘 —— 半圆弧 + 指针 + 圆心 */
    overview:
      '<path d="M3.4 16.2a8.6 8.6 0 0 1 17.2 0"/>' +
      '<path d="M12 16.2 15.9 10.9"/>' +
      '<circle cx="12" cy="16.2" r="1.15"/>',

    /* 全网体检：雷达扫描弧 —— 三段同心弧 + 一条扫描线 */
    scan:
      '<path d="M9 20a5 5 0 0 0-5-5"/>' +
      '<path d="M14 20A10 10 0 0 0 4 10"/>' +
      '<path d="M19 20A15 15 0 0 0 4 5"/>' +
      '<path d="M4 20 14.6 9.4"/>' +
      '<circle cx="4" cy="20" r="1.15"/>',

    /* 单目标诊断：靶心 */
    target:
      '<circle cx="12" cy="12" r="7.4"/>' +
      '<circle cx="12" cy="12" r="2.9"/>' +
      '<path d="M12 2.2v2.6M12 19.2v2.6M2.2 12h2.6M19.2 12h2.6"/>',

    /* 通信观察：眼睛 */
    observe:
      '<path d="M2.6 12S6.1 6.6 12 6.6 21.4 12 21.4 12 17.9 17.4 12 17.4 2.6 12 2.6 12z"/>' +
      '<circle cx="12" cy="12" r="2.5"/>',

    /* 连通与速度测试：闪电 */
    speed:
      '<path d="M13.2 2.8 5.6 13.4h5.2l-1 7.8 7.6-10.7h-5.2z"/>',

    /* 分析抓包文件：文档 + 放大镜 */
    file:
      '<path d="M13.4 3H7.2A1.7 1.7 0 0 0 5.5 4.7v14.6A1.7 1.7 0 0 0 7.2 21h4.4"/>' +
      '<path d="M13.4 3l4.6 4.6v3.1"/>' +
      '<path d="M13.4 3v4.6h4.6"/>' +
      '<circle cx="16.4" cy="16.4" r="3.2"/>' +
      '<path d="M18.7 18.7 21 21"/>',

    /* 报告与导出：柱状图 */
    report:
      '<path d="M4 20h16"/>' +
      '<path d="M7.4 20v-8.6M12 20V4.8M16.6 20v-6"/>',

    /* 日志中心：列表 */
    logs:
      '<path d="M6.2 4h11.6A1.7 1.7 0 0 1 19.5 5.7v12.6A1.7 1.7 0 0 1 17.8 20H6.2' +
      'A1.7 1.7 0 0 1 4.5 18.3V5.7A1.7 1.7 0 0 1 6.2 4z"/>' +
      '<path d="M8 9h8M8 12.4h8M8 15.8h5"/>',

    /* 设置：齿轮（8 齿多边形 + 中心圆） */
    gear:
      '<path d="M18.4 9.4 21.2 10.3 21.2 13.7 18.4 14.6 18.3 14.7 19.7 17.3 17.3 19.7' +
      ' 14.7 18.3 14.6 18.4 13.7 21.2 10.3 21.2 9.4 18.4 9.3 18.3 6.7 19.7 4.3 17.3' +
      ' 5.7 14.7 5.6 14.6 2.8 13.7 2.8 10.3 5.6 9.4 5.7 9.3 4.3 6.7 6.7 4.3 9.3 5.7' +
      ' 9.4 5.6 10.3 2.8 13.7 2.8 14.6 5.6 14.7 5.7 17.3 4.3 19.7 6.7 18.3 9.3Z"/>' +
      '<circle cx="12" cy="12" r="3.1"/>'
  };

  var SVG_OPEN =
    '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" ' +
    'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" ' +
    'aria-hidden="true" focusable="false">';

  function markup(name) {
    if (!Object.prototype.hasOwnProperty.call(PATHS, name)) return "";
    return SVG_OPEN + PATHS[name] + "</svg>";
  }

  function el(name) {
    var span = document.createElement("span");
    span.className = "ic";
    span.innerHTML = markup(name);
    return span;
  }

  /* 把 <span class="ic" data-icon="scan"> 就地填成图标；名字不存在就留空，不抛错 */
  function mount(root) {
    var nodes = (root || document).querySelectorAll("[data-icon]");
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      if (n.firstElementChild) continue;
      n.innerHTML = markup(n.getAttribute("data-icon"));
    }
  }

  ND.icons = { has: function (n) { return !!PATHS[n]; }, markup: markup, el: el, mount: mount };
})(window.ND = window.ND || {});
