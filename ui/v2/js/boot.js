/* ============================================================================
   boot.js · 启动装配：解析 #ui-config、画左轨道、hash 路由、顶栏环境徽章
   ----------------------------------------------------------------------------
   S2 起本文件不再画页面内容，只负责「进哪个页面、高亮哪一项、哪些入口置灰」。
   页面渲染在 home/settings/logs 三个模块里，各自只认接口返回的数据。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};

  var cfgEl = document.getElementById("ui-config");
  var cfg = {};
  try {
    cfg = JSON.parse(cfgEl && cfgEl.textContent ? cfgEl.textContent : "{}");
  } catch (e) {
    cfg = {};
  }
  ND.cfg = cfg;

  /* 轨道条目：五个模式取 #ui-config 的 label，其余取 copy.nav */
  var NAV = [
    { id: "home", icon: "overview", href: "#/home", text: C.nav.home },
    { id: "scan", icon: "scan", href: "#/scan", mode: "scan" },
    { id: "live", icon: "target", href: "#/live", mode: "live" },
    { id: "passive", icon: "observe", href: "#/passive", mode: "passive" },
    { id: "probe", icon: "speed", href: "#/probe", mode: "probe" },
    { id: "offline", icon: "file", href: "#/offline", mode: "offline" }
  ];

  var FOOT = [
    { id: "reports", icon: "report", href: "#/reports", text: C.nav.reports },
    { id: "logs", icon: "logs", href: "#/logs", text: C.nav.logs },
    { id: "settings", icon: "gear", href: "#/settings", text: C.nav.settings }
  ];

  var PAGES = {
    home: function () { return ND.home; },
    logs: function () { return ND.logs; },
    settings: function () { return ND.settings; }
  };

  function labelOf(item) {
    if (item.text) return item.text;
    var m = cfg.modes && cfg.modes[item.mode];
    return (m && m.label) || item.id;
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

    /* 缺依赖时入口仍留在原位（用户要看得见功能存在），但点进去只解释原因 */
    a.addEventListener("click", function (e) {
      if (a.getAttribute("aria-disabled") !== "true") return;
      e.preventDefault();
      U.toast((C.env || {}).locked, "warn");
      if (currentId() !== "home") location.hash = "#/home";
    });
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
    var h = (location.hash || "").replace(/^#\/?/, "").split("?")[0];
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

  /* ------------------------------------------------------------ 顶栏徽章 */
  function paintChips(checks) {
    var box = document.getElementById("env-chips");
    if (!box) return;
    U.clear(box);
    if (!checks || !checks.length) {
      for (var i = 0; i < 3; i++) box.appendChild(U.chip("na", C.common.na));
      return;
    }
    box.appendChild(ND.env.chips(checks));
  }

  /* ------------------------------------------------------------ 能力置灰 */
  function applyCapabilities(caps) {
    if (!caps) return;
    var items = document.querySelectorAll(".rail-item");
    for (var i = 0; i < items.length; i++) {
      var id = items[i].dataset.id;
      if (!Object.prototype.hasOwnProperty.call(caps, id)) continue;
      var ok = !!caps[id];
      var label = labelOf({ id: id, mode: id, text: (C.nav || {})[id] });
      if (ok) {
        items[i].removeAttribute("aria-disabled");
        items[i].classList.remove("locked");
        items[i].title = label;
      } else {
        items[i].setAttribute("aria-disabled", "true");
        items[i].classList.add("locked");
        items[i].title = label + " · " + ((C.env || {}).locked || "");
      }
    }
  }

  /* ------------------------------------------------------------ 未接数据的页面 */
  function renderStub(view, id) {
    U.clear(view);
    var m = (cfg.modes || {})[id];
    var name = labelOf(m ? { id: id, mode: id } : { id: id, text: (C.nav || {})[id] });

    var head = U.el("div", "pagehead");
    head.appendChild(U.el("h2", "", (m && m.title) || name));
    if (m && m.sub) head.appendChild(U.el("p", "", m.sub));
    view.appendChild(head);

    if (m) {
      var card = U.el("section", "card");
      var bd = U.el("div", "card-bd");
      if (m.guide) bd.appendChild(U.el("p", "lead", m.guide));
      if (m.points && m.points.length) {
        var ul = U.el("ul", "points");
        m.points.forEach(function (p) { ul.appendChild(U.el("li", "", p)); });
        bd.appendChild(ul);
      }
      if (m.term) bd.appendChild(U.el("p", "muted", m.term));
      card.appendChild(bd);
      view.appendChild(card);
    }

    var note = U.el("section", "card");
    var nb = U.el("div", "card-bd");
    nb.appendChild(U.el("p", "result-head", C.stub.title));
    nb.appendChild(U.el("p", "muted", U.tpl(C.stub.body, { name: name })));
    note.appendChild(nb);
    view.appendChild(note);
  }

  /* ------------------------------------------------------------ 路由 */
  function route(first) {
    var id = currentId();
    setActive(id);
    var view = document.getElementById("view");
    if (!view) return;

    var page = PAGES[id] ? PAGES[id]() : null;
    if (page && page.render) page.render(view);
    else renderStub(view, id);

    if (!first) {
      window.scrollTo(0, 0);
      /* 键盘用户换页后焦点落到新内容上，但不要画焦点环 */
      try { view.focus({ preventScroll: true }); } catch (e) { view.focus(); }
    }
  }

  function boot() {
    var rail = document.querySelector(".rail");
    if (rail) rail.setAttribute("aria-label", C.app.railLabel || "");
    var brand = document.querySelector(".brand");
    if (brand) {
      brand.setAttribute("aria-label", C.app.name || "");
      brand.title = C.app.name || "";
    }
    var img = brand && brand.querySelector("img");
    if (img) img.alt = C.app.name || "";

    renderRails();
    paintChips(null);
    if (ND.icons) ND.icons.mount(document);
    route(true);
    window.addEventListener("hashchange", function () { route(false); });

    /* 环境状态全站共用一次请求：顶栏徽章 + 入口置灰 + 首页依赖卡的兜底数据。
       页面自己的「重新检测」走 /api/selfcheck，回来后覆盖同一份缓存。 */
    ND.api.app().then(function (res) {
      if (!res.ok) return;
      ND.appCache = res.data || {};
      var checks = ND.appCache.checks || [];
      if (checks.length) paintChips(checks);
      applyCapabilities(ND.appCache.capabilities || null);
    });
  }

  ND.boot = {
    paintChips: paintChips,
    applyCapabilities: applyCapabilities,
    route: route
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})(window.ND = window.ND || {});
