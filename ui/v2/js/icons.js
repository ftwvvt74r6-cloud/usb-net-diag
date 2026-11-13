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
      '<circle cx="12" cy="12" r="3.1"/>',

    /* ---- 状态与动作（S2 起用；同一套 1.8 描边，不引入第二个图标体系） ---- */

    /* 就绪 */
    check: '<path d="M4.8 12.6 9.6 17.4 19.2 6.6"/>',

    /* 开始 / 播放（等边三角形，描边不填充，和其余图标同一套笔画） */
    play: '<path d="M7.6 4.9 19 12 7.6 19.1z"/>',

    /* 受限 / 注意 */
    alert:
      '<path d="M12 3.8 21.2 19.6H2.8z"/>' +
      '<path d="M12 9.6v4.3"/>' +
      '<path d="M12 16.9v.4"/>',

    /* 缺失 / 失败 */
    cross: '<path d="M6.2 6.2 17.8 17.8M17.8 6.2 6.2 17.8"/>',

    /* 复制 */
    copy:
      '<rect x="9" y="9" width="11" height="11" rx="2.2"/>' +
      '<path d="M15 5.7A1.7 1.7 0 0 0 13.3 4H5.7A1.7 1.7 0 0 0 4 5.7v7.6' +
      'A1.7 1.7 0 0 0 5.7 15"/>',

    /* 外链 */
    external:
      '<path d="M14.2 4H20v5.8"/>' +
      '<path d="M20 4 11.4 12.6"/>' +
      '<path d="M18 13.4v5.1A1.5 1.5 0 0 1 16.5 20h-11A1.5 1.5 0 0 1 4 18.5v-11' +
      'A1.5 1.5 0 0 1 5.5 6h5.1"/>',

    /* 重新检测 */
    refresh:
      '<path d="M20 12a8 8 0 1 1-2.5-5.8"/>' +
      '<path d="M20.2 3.9v4.6h-4.6"/>',

    /* 指定路径 */
    folder:
      '<path d="M3.6 7.6A1.6 1.6 0 0 1 5.2 6h3.6l2.1 2.6h7.9A1.6 1.6 0 0 1 20.4 10.2' +
      'v7.2A1.6 1.6 0 0 1 18.8 19H5.2a1.6 1.6 0 0 1-1.6-1.6z"/>',

    /* 下载 / 导出 */
    download:
      '<path d="M12 4.2v10.2"/>' +
      '<path d="M7.6 10.6 12 15l4.4-4.4"/>' +
      '<path d="M4.6 19.4h14.8"/>',

    /* 时间 */
    clock:
      '<circle cx="12" cy="12" r="8.2"/>' +
      '<path d="M12 7.6V12l3 1.8"/>',

    /* 关闭 */
    close: '<path d="M6.2 6.2 17.8 17.8M17.8 6.2 6.2 17.8"/>',
    /* 顶栏「退出后台」专用：电源符号，别和 X（关闭弹层）混用 */
    power: '<path d="M12 3.4v8.2"/><path d="M7.3 6.4a7.2 7.2 0 1 0 9.4 0"/>'
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
