/* ============================================================================
   ui.js · DOM 小工具 / 格式化 / 提示条 / 弹层
   ----------------------------------------------------------------------------
   只做「怎么显示」，不做「显示什么」：所有中文都从 copy.js 取。
   弹层自带焦点陷阱、Esc 关闭、关闭后焦点归位（与 v1 公共修复同一套行为）。
   ========================================================================== */
(function (ND) {
  "use strict";

  var C = ND.copy || {};

  /* ------------------------------------------------------------ 文案模板 */
  function tpl(str, vars) {
    if (!str) return "";
    return String(str).replace(/\{(\w+)\}/g, function (m, key) {
      var v = vars ? vars[key] : undefined;
      return v === undefined || v === null ? "" : String(v);
    });
  }

  function txt(path, fallback) {
    var cur = C;
    var parts = String(path).split(".");
    for (var i = 0; i < parts.length; i++) {
      if (cur == null) return fallback || "";
      cur = cur[parts[i]];
    }
    return typeof cur === "string" ? cur : (fallback || "");
  }

  /* ------------------------------------------------------------ 元素 */
  function el(tag, cls, content) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (content !== undefined && content !== null) {
      if (content instanceof Node) n.appendChild(content);
      else n.textContent = String(content);
    }
    return n;
  }

  function clear(node) {
    if (!node) return node;
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  function icon(name, cls) {
    var s = el("span", "ic" + (cls ? " " + cls : ""));
    s.innerHTML = (ND.icons && ND.icons.markup(name)) || "";
    return s;
  }

  function chip(kind, label) {
    var c = el("span", "chip" + (kind ? " " + kind : ""), label);
    return c;
  }

  /* opts: { kind: "primary"|"ghost", size: "sm", icon: "refresh", onClick, title, disabled } */
  function btn(label, opts) {
    opts = opts || {};
    var b = el("button", "btn");
    b.type = "button";
    if (opts.kind === "ghost") b.classList.add("ghost");
    if (opts.size === "sm") b.classList.add("sm");
    if (opts.disabled) b.disabled = true;
    if (opts.title) b.title = opts.title;
    if (opts.icon) b.appendChild(icon(opts.icon));
    b.appendChild(el("span", "btn-t", label));
    if (opts.onClick) b.addEventListener("click", opts.onClick);
    return b;
  }

  /* ------------------------------------------------------------ 格式化 */
  function num(v, digits) {
    if (v === null || v === undefined || v === "" || !isFinite(Number(v))) return null;
    var n = Number(v);
    var d = digits === undefined ? 0 : digits;
    return n.toFixed(d);
  }

  function dur(ms) {
    var v = Number(ms);
    if (!isFinite(v) || v < 0) return null;
    if (v < 1000) return Math.round(v) + txt("unit.ms");
    if (v < 60000) return (v / 1000).toFixed(1) + txt("unit.sec");
    var m = Math.floor(v / 60000);
    var s = Math.round((v % 60000) / 1000);
    return m + txt("unit.min") + " " + s + txt("unit.sec");
  }

  function pad2(n) { return n < 10 ? "0" + n : String(n); }

  /* 时间一律按本机时区渲染：今天 / 昨天 / 月-日 时:分。
     epoch 优先（后端给的 ISO 也带时区，但秒级 epoch 更不容易被时区规则坑到）。 */
  function when(epoch, iso) {
    var d = null;
    if (epoch) d = new Date(Number(epoch) * 1000);
    else if (iso) d = new Date(iso);
    if (!d || isNaN(d.getTime())) return txt("time.unknown");

    var now = new Date();
    var startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    var t = d.getTime();
    var hm = pad2(d.getHours()) + ":" + pad2(d.getMinutes());
    if (t >= startOfToday) return txt("time.today") + " " + hm;
    if (t >= startOfToday - 86400000) return txt("time.yesterday") + " " + hm;
    return pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()) + " " + hm;
  }

  function size(bytes) {
    var b = Number(bytes);
    if (!isFinite(b) || b < 0) return "";
    if (b < 1024) return b + " B";
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
    return (b / 1024 / 1024).toFixed(1) + " MB";
  }

  /* ------------------------------------------------------------ 模式 */
  /* 五个模式的名称与说明只有 #ui-config 一份来源，这里只做查表 */
  function mode(id) {
    var modes = (ND.cfg && ND.cfg.modes) || {};
    return modes[id] || null;
  }

  function modeLabel(id) {
    var m = mode(id);
    return (m && m.label) || "";
  }

  /* ------------------------------------------------------------ 剪贴板 */
  function copyText(str) {
    var text = String(str == null ? "" : str);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () {
        return true;
      }, function () {
        return legacyCopy(text);
      });
    }
    return Promise.resolve(legacyCopy(text));
  }

  function legacyCopy(text) {
    var ta = el("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "readonly");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }

  /* ------------------------------------------------------------ 提示条 */
  function toast(message, kind) {
    var host = document.getElementById("toasts");
    if (!host || !message) return;
    var t = el("div", "toast" + (kind ? " " + kind : ""), message);
    host.appendChild(t);
    requestAnimationFrame(function () { t.classList.add("in"); });
    setTimeout(function () {
      t.classList.remove("in");
      setTimeout(function () {
        if (t.parentNode) t.parentNode.removeChild(t);
      }, 200);
    }, 2600);
  }

  /* 把接口失败翻译成一句人话（不把英文异常直接甩给用户） */
  function why(res) {
    if (!res) return txt("toast.network");
    if (res.status === 0) {
      return res.error === "timeout" ? txt("toast.timeout") : txt("toast.network");
    }
    return res.error || tpl(txt("toast.http"), { status: res.status });
  }

  /* ------------------------------------------------------------ 弹层 */
  var openModals = [];

  function modal(opts) {
    opts = opts || {};
    var last = document.activeElement;

    var mask = el("div", "modal-mask");
    var panel = el("div", "modal");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "true");

    var titleId = "modal-t-" + (openModals.length + 1) + "-" + Date.now();
    var hd = el("div", "modal-hd");
    var h = el("h2", "", opts.title || "");
    h.id = titleId;
    panel.setAttribute("aria-labelledby", titleId);
    hd.appendChild(h);

    var closeBtn = el("button", "modal-x");
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", txt("modal.close"));
    closeBtn.title = txt("modal.close");
    closeBtn.appendChild(icon("close"));
    closeBtn.addEventListener("click", function () { close(); });
    hd.appendChild(closeBtn);
    panel.appendChild(hd);

    var bd = el("div", "modal-bd");
    if (opts.body) bd.appendChild(opts.body instanceof Node ? opts.body : el("p", "", opts.body));
    panel.appendChild(bd);

    var acts = [];
    if (opts.actions && opts.actions.length) {
      var ft = el("div", "modal-ft");
      opts.actions.forEach(function (a) {
        if (a) { acts.push(a); ft.appendChild(a); }
      });
      panel.appendChild(ft);
    }

    mask.appendChild(panel);
    document.getElementById("modal-root").appendChild(mask);
    openModals.push(mask);

    /* 打开动画：只碰 opacity / transform */
    requestAnimationFrame(function () { mask.classList.add("in"); });

    function focusables() {
      return panel.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]),' +
        ' textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
    }

    function onKey(e) {
      if (e.key === "Escape") {
        e.preventDefault();
        close();
        return;
      }
      if (e.key !== "Tab") return;
      var list = focusables();
      if (!list.length) return;
      var first = list[0];
      var lastEl = list[list.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        lastEl.focus();
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault();
        first.focus();
      }
    }

    function close() {
      document.removeEventListener("keydown", onKey, true);
      mask.classList.remove("in");
      var idx = openModals.indexOf(mask);
      if (idx >= 0) openModals.splice(idx, 1);
      setTimeout(function () {
        if (mask.parentNode) mask.parentNode.removeChild(mask);
        if (last && last.focus && document.contains(last)) last.focus();
        else if (document.body) document.body.focus();
        if (opts.onClose) opts.onClose();
      }, 160);
    }

    document.addEventListener("keydown", onKey, true);
    var firstFocus = panel.querySelector("input, textarea, button:not(.modal-x)") || closeBtn;
    setTimeout(function () { if (firstFocus && firstFocus.focus) firstFocus.focus(); }, 30);

    return { close: close, panel: panel, body: bd };
  }

  ND.ui = {
    tpl: tpl,
    txt: txt,
    el: el,
    clear: clear,
    icon: icon,
    chip: chip,
    btn: btn,
    num: num,
    dur: dur,
    when: when,
    size: size,
    mode: mode,
    modeLabel: modeLabel,
    copyText: copyText,
    toast: toast,
    why: why,
    modal: modal
  };
})(window.ND = window.ND || {});
