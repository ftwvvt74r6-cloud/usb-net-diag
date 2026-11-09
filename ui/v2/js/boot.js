/* ============================================================================
   boot.js · S1 只做骨架：图标挂载、导航渲染、hash 路由、当前页高亮
   ----------------------------------------------------------------------------
   数据一律留到 S2/S3 接 /api/*；本文件不写任何中文（全部来自 copy.js 与
   #ui-config），也不碰 v1 的任何函数。
   ========================================================================== */
(function (ND) {
  "use strict";

  var cfgEl = document.getElementById("ui-config");
  var UI = {};
  try {
    UI = JSON.parse(cfgEl && cfgEl.textContent ? cfgEl.textContent : "{}");
  } catch (e) {
    UI = {};
  }

  var C = ND.copy || {};

  /* 轨道条目：五个模式取 #ui-config 的 label，其余取 copy.nav */
  var NAV = [
    { id: "home", icon: "overview", href: "#/home", text: (C.nav || {}).home },
    { id: "scan", icon: "scan", href: "#/scan", mode: "scan" },
    { id: "live", icon: "target", href: "#/live", mode: "live" },
    { id: "passive", icon: "observe", href: "#/passive", mode: "passive" },
    { id: "probe", icon: "speed", href: "#/probe", mode: "probe" },
    { id: "offline", icon: "file", href: "#/offline", mode: "offline" }
  ];

  var FOOT = [
    { id: "reports", icon: "report", href: "#/reports", text: (C.nav || {}).reports },
    { id: "logs", icon: "logs", href: "#/logs", text: (C.nav || {}).logs },
    { id: "settings", icon: "gear", href: "#/settings", text: (C.nav || {}).settings }
  ];

  function labelOf(item) {
    if (item.text) return item.text;
    var m = UI.modes && UI.modes[item.mode];
    return (m && m.label) || item.id;
  }

  /* ---------------------------------------------------------------- 文案 */
  /* HTML 里只留 data-copy="kpi.health" 这样的路径，真实文字全部来自 copy.js，
     保证「同一句话只有一个来源」。缺 key 就留空，不显示 undefined。 */
  function resolve(path) {
    var cur = C;
    var parts = String(path).split(".");
    for (var i = 0; i < parts.length; i++) {
      if (cur == null) return "";
      cur = cur[parts[i]];
    }
    return typeof cur === "string" ? cur : "";
  }

  function applyCopy(root) {
    var nodes = (root || document).querySelectorAll("[data-copy]");
    for (var i = 0; i < nodes.length; i++) {
      var txt = resolve(nodes[i].getAttribute("data-copy"));
      if (txt) nodes[i].textContent = txt;
    }
  }

  function itemEl(item) {
    var a = document.createElement("a");
    a.className = "rail-item";
    a.href = item.href;
    a.dataset.id = item.id;
    var label = labelOf(item);
    /* title 始终给：1024 收成纯图标时，气泡与读屏都靠它 */
    a.title = label;
    a.setAttribute("aria-label", label);

    var ic = document.createElement("span");
    ic.className = "ic";
    ic.innerHTML = (ND.icons && ND.icons.markup(item.icon)) || "";
    a.appendChild(ic);

    var lb = document.createElement("span");
    lb.className = "lbl";
    lb.textContent = label;
    a.appendChild(lb);
    return a;
  }

  function renderRails() {
    var nav = document.getElementById("railnav");
    var foot = document.getElementById("railfoot");
    if (!nav || !foot) return;
    NAV.forEach(function (it) { nav.appendChild(itemEl(it)); });
    FOOT.forEach(function (it) { foot.appendChild(itemEl(it)); });
  }

  function currentId() {
    var h = (location.hash || "").replace(/^#\/?/, "");
    var all = NAV.concat(FOOT);
    for (var i = 0; i < all.length; i++) if (all[i].id === h) return h;
    return "home";
  }

  function setActive(id) {
    var items = document.querySelectorAll(".rail-item");
    for (var i = 0; i < items.length; i++) {
      var on = items[i].dataset.id === id;
      if (on) items[i].setAttribute("aria-current", "page");
      else items[i].removeAttribute("aria-current");
    }
    var title = document.getElementById("page-title");
    if (title) {
      var all = NAV.concat(FOOT);
      for (var j = 0; j < all.length; j++) {
        if (all[j].id === id) {
          title.textContent = labelOf(all[j]);
          break;
        }
      }
    }
  }

  /* 环境徽章在顶栏（D2 的信息架构）；S2 接 /api/selfcheck 后填真值，
     现在先给三枚占位，保证顶栏左右配重不塌 */
  function renderEnvPlaceholder() {
    var box = document.getElementById("env-chips");
    if (!box || box.children.length) return;
    for (var i = 0; i < 3; i++) {
      var s = document.createElement("span");
      s.className = "chip na";
      s.textContent = (C.na || "");
      box.appendChild(s);
    }
  }

  function boot() {
    applyCopy();
    renderRails();
    renderEnvPlaceholder();
    setActive(currentId());
    if (ND.icons) ND.icons.mount(document);
    window.addEventListener("hashchange", function () {
      setActive(currentId());
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})(window.ND = window.ND || {});
