/* ============================================================================
   logs.js · 日志中心：列出 logs 下的 app / diag / startup，支持过滤 / 查看 /
   复制 / 下载，并给「导出诊断包（脱敏）」的入口
   ----------------------------------------------------------------------------
   日志接口（R5）还没进 core：读不到列表时不说「加载失败」，直接说清楚现在
   读不到，并保留仍然可用的「导出诊断包」——那条路走的是已有的 /api/diagpack。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};

  var files = [];
  var query = "";
  var filterEl = null;

  function render(view) {
    U.clear(view);
    files = [];
    query = "";

    var L = C.logs || {};

    /* ---- 顶部：说明 + 导出诊断包 ---- */
    var head = U.el("section", "card");
    var hd = U.el("div", "card-hd");
    hd.appendChild(U.el("h2", "", L.title));
    head.appendChild(hd);
    var hb = U.el("div", "card-bd");
    hb.appendChild(U.el("p", "muted", L.hint));
    var acts = U.el("div", "setting-acts");
    var pack = U.btn(L.pack, { kind: "ghost", size: "sm", icon: "download" });
    pack.addEventListener("click", function () { exportPack(pack); });
    acts.appendChild(pack);
    hb.appendChild(acts);
    head.appendChild(hb);
    view.appendChild(head);

    /* ---- 列表（标题与上面那张卡不能重名，否则像同一块内容渲染了两遍） ---- */
    var listCard = U.el("section", "card");
    var lh = U.el("div", "card-hd");
    lh.appendChild(U.el("h2", "", L.listTitle));
    var count = U.el("span", "card-sub");
    lh.appendChild(count);
    var filter = U.el("input", "input filter");
    filter.type = "search";
    filter.placeholder = L.filterPh || "";
    filter.setAttribute("aria-label", L.filter);
    filter.addEventListener("input", function () {
      query = (filter.value || "").trim().toLowerCase();
      paintList(listCard.body, L);
    });
    filter.classList.add("hd-act");
    lh.appendChild(filter);
    filterEl = filter;
    listCard.appendChild(lh);
    var lb = U.el("div", "card-bd");
    listCard.appendChild(lb);
    view.appendChild(listCard);

    lb.appendChild(skeleton(4));

    ND.api.logs().then(function (res) {
      U.clear(lb);
      if (ND.api.absent(res)) {
        var box = U.el("div", "empty");
        box.appendChild(U.icon("logs"));
        box.appendChild(U.el("b", "", L.unsupported));
        lb.appendChild(box);
        setFilterVisible(false);
        return;
      }
      if (!res.ok) {
        lb.appendChild(U.el("p", "muted", U.tpl(L.loadFail, { reason: U.why(res) })));
        setFilterVisible(false);
        return;
      }
      files = normalize(res.data);
      paintList(lb, L);
    });
  }

  /* 没有文件可过滤时，把过滤框一起收起来：留着只能输入，不会有任何结果 */
  function setFilterVisible(visible) {
    if (!filterEl) return;
    filterEl.hidden = !visible;
    if (!visible) filterEl.value = "";
  }

  /* 列表占位：读取期间先用灰块撑住高度，避免整页跳一下 */
  function skeleton(n) {
    var box = U.el("div", "stack");
    for (var i = 0; i < n; i++) {
      var s = U.el("div", "sk");
      s.style.setProperty("--w", (58 + i * 8) + "%");
      box.appendChild(s);
    }
    return box;
  }

  function normalize(data) {
    var raw = (data && (data.files || data.items)) || [];
    var out = [];
    raw.forEach(function (f) {
      if (!f) return;
      var name = String(f.name || f.path || "");
      if (!name) return;
      out.push({
        name: name,
        kind: String(f.kind || guessKind(name)),
        size: Number(f.size || 0),
        mtime: String(f.mtime || ""),
        epoch: Number(f.epoch || 0)
      });
    });
    out.sort(function (a, b) {
      if (a.epoch && b.epoch) return b.epoch - a.epoch;
      return a.name < b.name ? 1 : -1;
    });
    return out;
  }

  function guessKind(name) {
    var n = name.toLowerCase();
    if (n.indexOf("diag") === 0) return "diag";
    if (n.indexOf("startup") === 0) return "startup";
    if (n.indexOf("app") === 0) return "app";
    return "other";
  }

  function kindLabel(kind) {
    var L = C.logs || {};
    if (kind === "diag") return L.kindDiag;
    if (kind === "startup") return L.kindStartup;
    if (kind === "app") return L.kindApp;
    return L.kindOther;
  }

  function paintList(host, L) {
    U.clear(host);
    var shown = files.filter(function (f) {
      return !query || f.name.toLowerCase().indexOf(query) >= 0;
    });

    var sub = host.parentNode && host.parentNode.querySelector(".card-hd .card-sub");
    if (sub) sub.textContent = files.length ? U.tpl(L.count, { count: files.length }) : "";

    setFilterVisible(files.length > 1);

    if (!files.length) {
      host.appendChild(U.el("p", "muted", L.empty));
      return;
    }
    if (!shown.length) {
      host.appendChild(U.el("p", "muted", U.tpl(L.noMatch, { q: query })));
      return;
    }

    var ul = U.el("ul", "loglist");
    shown.forEach(function (f) {
      var li = U.el("li", "logrow");

      li.appendChild(U.el("span", "tag " + (f.kind === "diag" ? "info" : "na"),
        kindLabel(f.kind)));

      var main = U.el("div", "logmain");
      main.appendChild(U.el("span", "logname mono", f.name));
      var sub = [];
      if (f.size) sub.push(U.size(f.size));
      if (f.mtime) sub.push(f.mtime);
      if (sub.length) main.appendChild(U.el("span", "logsub muted", sub.join(" · ")));
      li.appendChild(main);

      var acts = U.el("div", "logacts");
      acts.appendChild(U.btn(C.act.view, {
        kind: "ghost", size: "sm",
        onClick: function () { openLog(f); }
      }));
      acts.appendChild(U.btn(C.act.copy, {
        kind: "ghost", size: "sm", icon: "copy",
        onClick: function () { copyLog(f); }
      }));
      acts.appendChild(U.btn(C.act.download, {
        kind: "ghost", size: "sm", icon: "download",
        onClick: function () { downloadLog(f); }
      }));
      li.appendChild(acts);

      ul.appendChild(li);
    });
    host.appendChild(ul);
  }

  /* ------------------------------------------------------------ 单个日志 */
  function fetchLog(f) {
    return ND.api.logFile(f.name).then(function (res) {
      if (ND.api.absent(res)) return { ok: false, unsupported: true };
      if (!res.ok) return { ok: false, error: U.why(res) };
      var d = res.data || {};
      return { ok: true, text: String(d.text || d.content || ""), truncated: !!d.truncated };
    });
  }

  function openLog(f) {
    var L = C.logs || {};
    var body = U.el("div", "logview");
    var pre = U.el("pre", "mono");
    pre.textContent = C.common.loading;
    body.appendChild(pre);

    var copyBtn = U.btn(C.act.copy, { kind: "ghost", size: "sm", icon: "copy" });
    var dlBtn = U.btn(C.act.download, { kind: "ghost", size: "sm", icon: "download" });
    var close = U.btn(C.act.close, { kind: "ghost" });
    copyBtn.disabled = true;
    dlBtn.disabled = true;

    var box = U.modal({
      title: U.tpl(L.viewerTitle, { name: f.name }),
      body: body,
      actions: [copyBtn, dlBtn, close]
    });
    close.addEventListener("click", function () { box.close(); });

    fetchLog(f).then(function (r) {
      if (!r.ok) {
        pre.textContent = r.unsupported ? L.unsupported : r.error;
        return;
      }
      pre.textContent = r.text;
      copyBtn.disabled = false;
      dlBtn.disabled = false;
      if (r.truncated) {
        body.insertBefore(U.el("p", "muted", U.tpl(L.tooBig, { size: U.size(f.size) })), pre);
      }
      copyBtn.addEventListener("click", function () {
        U.copyText(r.text).then(function (ok) {
          U.toast(ok ? C.act.copied : C.act.copyFail, ok ? "ok" : "crit");
        });
      });
      dlBtn.addEventListener("click", function () { saveText(f.name, r.text); });
    });
  }

  function copyLog(f) {
    fetchLog(f).then(function (r) {
      if (!r.ok) {
        U.toast(r.unsupported ? (C.logs || {}).unsupported : r.error, "crit");
        return;
      }
      U.copyText(r.text).then(function (ok) {
        U.toast(ok ? C.act.copied : C.act.copyFail, ok ? "ok" : "crit");
      });
    });
  }

  function downloadLog(f) {
    fetchLog(f).then(function (r) {
      if (!r.ok) {
        U.toast(r.unsupported ? (C.logs || {}).unsupported : r.error, "crit");
        return;
      }
      saveText(f.name, r.text);
    });
  }

  /* 日志接口只回 JSON，就把正文在本地拼成 Blob 下载：
     不额外要求后端提供 text/plain 分支，接口面越小越好。 */
  function saveText(name, text) {
    var blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  /* ------------------------------------------------------------ 诊断包 */
  function exportPack(button) {
    var L = C.logs || {};
    if (button.disabled) return;
    var label = button.querySelector(".btn-t");
    var old = label.textContent;
    button.disabled = true;
    label.textContent = L.packing;
    ND.api.diagpack({ include_reports: false, raw: false }).then(function (res) {
      button.disabled = false;
      label.textContent = old;
      if (!res.ok) {
        U.toast(U.tpl(L.packFail, { reason: U.why(res) }), "crit");
        return;
      }
      var d = res.data || {};
      U.toast(U.tpl(L.packDone, { path: d.path || "", size: U.size(d.size) }), "ok");
    });
  }

  ND.logs = { render: render };
})(window.ND = window.ND || {});
