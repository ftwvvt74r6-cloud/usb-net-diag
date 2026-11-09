/* ============================================================================
   settings.js · 设置页：后台服务 / 网卡与运行信息 / AI 分析
   ----------------------------------------------------------------------------
   只读展示 + 两个真实动作：立即退出后台（POST /api/quit）、重新读取 AI 配置。
   「AI 配置」本身在 config/ai-config.json 里改（这是本机工具，不做在线表单）。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var R = ND.render;

  /* AI 配置是本地 JSON（core/ai.py 的 AI_CONFIG），配置入口就是「告诉你它在哪」 */
  var AI_CONFIG_REL = "config/ai-config.json";

  function render(view) {
    U.clear(view);
    var S = C.settings || {};

    var service = card(S.service);
    var runtime = card(S.runtime);
    var ai = card(S.ai);

    view.appendChild(service.section);
    view.appendChild(runtime.section);
    view.appendChild(ai.section);

    service.body.appendChild(skeleton(2));
    runtime.body.appendChild(skeleton(3));
    ai.body.appendChild(skeleton(2));

    ND.api.app().then(function (res) {
      var app = res.ok ? (res.data || {}) : {};
      paintService(service, app);
      paintRuntime(runtime, app);
      return ND.api.interfaces();
    }).then(function (res) {
      if (res && res.ok) paintInterfaces(runtime, res.data || {});
    });

    ND.api.ai().then(function (res) {
      paintAi(ai, res);
    });
  }

  /* 卡片与骨架块统一用 render.js 那一套：设置页不该有第二份卡片实现 */
  function card(title) {
    return R.card(title);
  }

  function skeleton(n) {
    return R.skeleton(n, 62);
  }

  /* ------------------------------------------------------------ 后台服务 */
  function paintService(target, app) {
    var S = C.settings || {};
    U.clear(target.body);

    var idle = Number(app.idle_exit_min || 0);
    var line = U.el("p", "setting-line");
    line.appendChild(U.el("b", "", (S.idleLabel || "") + "："));
    line.appendChild(document.createTextNode(
      idle > 0 ? U.tpl(S.idleOn, { minutes: idle }) : S.idleOff
    ));
    target.body.appendChild(line);
    target.body.appendChild(U.el("p", "muted", S.serviceHint));

    var quit = U.btn(S.quit, { kind: "ghost", size: "sm" });
    quit.addEventListener("click", function () { confirmQuit(quit); });
    var row = U.el("div", "setting-acts");
    row.appendChild(quit);
    target.body.appendChild(row);
  }

  function confirmQuit(trigger) {
    var S = C.settings || {};
    var body = document.createDocumentFragment();
    body.appendChild(U.el("p", "", S.quitConfirmBody));

    var cancel = U.btn(C.act.cancel, { kind: "ghost" });
    var ok = U.btn(S.quit, {});
    var box = U.modal({ title: S.quitConfirmTitle, body: body, actions: [cancel, ok] });
    cancel.addEventListener("click", function () { box.close(); });
    ok.addEventListener("click", function () {
      ok.disabled = true;
      cancel.disabled = true;
      ok.querySelector(".btn-t").textContent = S.quitting;
      ND.api.quit().then(function (res) {
        box.close();
        if (res.ok) {
          /* 服务已经停了，页面留着也没用：换成一张「可以关了」的静态说明 */
          var view = document.getElementById("view");
          if (view) {
            U.clear(view);
            var c = card(S.service);
            c.body.appendChild(U.el("p", "result-head ok", S.quitDone));
            view.appendChild(c.section);
          }
          return;
        }
        U.toast(U.tpl(S.quitFail, { reason: U.why(res) }), "crit");
        if (trigger) trigger.disabled = false;
      });
    });
  }

  /* ------------------------------------------------------------ 运行信息 */
  function paintRuntime(target, app) {
    var S = C.settings || {};
    U.clear(target.body);

    var dl = U.el("dl", "kv kv-2");
    add(dl, S.version, app.version || "—");
    add(dl, S.pid, app.pid ? String(app.pid) : "—");
    add(dl, S.port, app.port ? String(app.port) : "—");
    add(dl, S.admin, app.admin ? S.adminYes : S.adminNo);
    if (app.url) {
      var row = U.el("div", "kv-row");
      row.appendChild(U.el("dt", "", S.url));
      var dd = U.el("dd", "");
      var a = U.el("a", "link", app.url);
      a.href = app.url;
      dd.appendChild(a);
      row.appendChild(dd);
      dl.appendChild(row);
    }
    target.body.appendChild(dl);

    var ifaceBox = U.el("div", "ifaces");
    ifaceBox.id = "iface-box";
    target.body.appendChild(ifaceBox);
  }

  function add(dl, k, v) {
    var row = U.el("div", "kv-row");
    row.appendChild(U.el("dt", "", k));
    row.appendChild(U.el("dd", "", v));
    dl.appendChild(row);
  }

  function paintInterfaces(target, data) {
    var S = C.settings || {};
    var box = document.getElementById("iface-box");
    if (!box || box.parentNode !== target.body) return;
    U.clear(box);

    var list = (data.interfaces || []).slice(0, 6);
    var head = U.el("p", "setting-line");
    head.appendChild(U.el("b", "", S.iface + "："));
    head.appendChild(document.createTextNode(
      list.length ? U.tpl(S.ifaceCount, { count: (data.interfaces || []).length }) : S.ifaceEmpty
    ));
    box.appendChild(head);

    if (!list.length) return;
    var ul = U.el("ul", "ifacelist");
    list.forEach(function (it) {
      var li = U.el("li", "");
      var short = String(it.short || it.name || "");
      li.appendChild(U.el("span", "mono", short));
      /* name 通常就是「短名 + 括号里的型号」，只把括号那半截当补充信息 */
      var rest = String(it.name || "");
      if (short && rest.indexOf(short) === 0) rest = rest.slice(short.length).trim();
      if (rest && rest !== short) li.appendChild(U.el("span", "muted", rest));
      ul.appendChild(li);
    });
    box.appendChild(ul);
  }

  /* ------------------------------------------------------------ AI 分析 */
  function paintAi(target, res) {
    var S = C.settings || {};
    U.clear(target.body);

    if (!res.ok) {
      target.body.appendChild(U.el("p", "muted", U.why(res)));
      return;
    }
    var cfg = res.data || {};
    var ready = !!cfg.ready;

    var head = U.el("div", "setting-line");
    head.appendChild(U.chip(ready ? "ok" : "na", ready ? S.aiOn : S.aiOff));
    head.appendChild(document.createTextNode(" " + (S.aiModel || "") + "：" + (cfg.model || "—")));
    target.body.appendChild(head);

    var dl = U.el("dl", "kv kv-2");
    add(dl, S.aiProvider, cfg.provider || "—");
    add(dl, S.aiBase, cfg.base_url || "—");
    add(dl, S.aiKey, cfg.has_key ? (cfg.key_masked || "—") : "—");
    target.body.appendChild(dl);

    target.body.appendChild(U.el("p", "muted", S.aiConfigHint));

    var acts = U.el("div", "setting-acts");
    acts.appendChild(U.btn(S.aiCopyPath, {
      kind: "ghost", size: "sm", icon: "copy",
      onClick: function () {
        U.copyText(AI_CONFIG_REL).then(function (ok) {
          U.toast(ok ? C.act.copied : C.act.copyFail, ok ? "ok" : "crit");
        });
      }
    }));
    acts.appendChild(U.btn(S.aiReload, {
      kind: "ghost", size: "sm", icon: "refresh",
      onClick: function () {
        ND.api.ai().then(function (r) { paintAi(target, r); });
      }
    }));
    target.body.appendChild(acts);
  }

  ND.settings = { render: render };
})(window.ND = window.ND || {});
