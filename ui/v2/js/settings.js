/* ============================================================================
   settings.js · 设置页：常驻采集 / 监测目标 / 告警阈值 / 后台服务 / 运行信息 / AI
   ----------------------------------------------------------------------------
   三块新增的（S6）都在讲同一件事：**让这台机器持续留痕**。
   · 常驻采集：状态 + 采样间隔 + 安装/卸载 + 最近一次采样时间；
   · 监测目标：最多 3 条 地址[:端口]，留空只测网关与 DNS；
   · 告警阈值：时延 / 抖动 / 丢包，改完立刻下发，不必重启。

   接口未就绪（404/405）时不许装：该块直接写「采集未开启」并说明原因，
   不显示 0、不显示「正常」。阈值与目标可以编辑，但会明确标注「暂存本机」——
   配置是本机的，数据是采集来的，两者不能混着假装。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var R = ND.render;

  /* AI 配置是本地 JSON（core/ai.py 的 AI_CONFIG），配置入口就是「告诉你它在哪」 */
  var AI_CONFIG_REL = "config/ai-config.json";

  /* 接口没就绪时，配置落在本机，别让用户白填 */
  var LS_KEY = "nd_monitor";
  var DEFAULTS = { rtt_ms: 120, jitter_ms: 40, loss_pct: 2 };

  var state = {
    agent: null,          /* /api/agent/status 的 data */
    agentAbsent: false,   /* 接口不存在（404/405） */
    targets: [],
    thresholds: { rtt_ms: DEFAULTS.rtt_ms, jitter_ms: DEFAULTS.jitter_ms, loss_pct: DEFAULTS.loss_pct },
    monitorAbsent: false
  };

  function clone(o) {
    var out = {};
    Object.keys(o || {}).forEach(function (k) { out[k] = o[k]; });
    return out;
  }

  /* ------------------------------------------------------------ 本机暂存 */
  function loadLocal() {
    try {
      var raw = localStorage.getItem(LS_KEY);
      if (!raw) return;
      var o = JSON.parse(raw);
      if (o && Array.isArray(o.targets)) state.targets = o.targets.slice(0, 3);
      if (o && o.thresholds) state.thresholds = merge(DEFAULTS, o.thresholds);
    } catch (e) { /* 坏数据就当没有 */ }
  }

  function saveLocal() {
    try {
      localStorage.setItem(LS_KEY, JSON.stringify({ targets: state.targets, thresholds: state.thresholds }));
    } catch (e) { /* 隐私模式下写不进去，不影响页面 */ }
  }

  function merge(a, b) {
    var out = {};
    Object.keys(a).forEach(function (k) { out[k] = a[k]; });
    Object.keys(b || {}).forEach(function (k) { if (isFinite(Number(b[k]))) out[k] = Number(b[k]); });
    return out;
  }

  /* ------------------------------------------------------------ 入口 */
  function render(view) {
    U.clear(view);
    var S = C.settings || {};

    var agent = R.card(S.agentTitle, { sub: S.agentSub, cls: "set-agent" });
    var targets = card(S.targetsTitle, S.targetsSub);
    var thr = card(S.thrTitle, S.thrSub);
    var service = card(S.service);
    var runtime = card(S.runtime);
    var ai = card(S.ai);

    view.appendChild(agent.section);
    view.appendChild(targets.section);
    view.appendChild(thr.section);
    view.appendChild(service.section);
    view.appendChild(runtime.section);
    view.appendChild(ai.section);

    agent.body.appendChild(skeleton(2));
    targets.body.appendChild(skeleton(2));
    thr.body.appendChild(skeleton(1));
    service.body.appendChild(skeleton(2));
    runtime.body.appendChild(skeleton(3));
    ai.body.appendChild(skeleton(2));

    loadLocal();
    paintTargets(targets);
    paintThresholds(thr);

    ND.api.monitor().then(function (res) {
      if (res && res.ok && res.data) {
        var d = res.data;
        if (Array.isArray(d.targets)) state.targets = d.targets.slice(0, 3);
        if (d.thresholds) state.thresholds = merge(DEFAULTS, d.thresholds);
        state.monitorAbsent = false;
      } else {
        /* 没这个接口：保留本机暂存值，界面上明确写「暂存本机」 */
        state.monitorAbsent = ND.api.absent(res);
      }
      paintTargets(targets);
      paintThresholds(thr);
    });

    ND.api.agent().then(function (res) {
      if (res && res.ok && res.data) {
        state.agent = res.data;
        state.agentAbsent = false;
      } else {
        state.agent = null;
        state.agentAbsent = true;
      }
      paintAgent(agent);
    });

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
  function card(title, sub) {
    return R.card(title, { sub: sub });
  }

  function skeleton(n) {
    return R.skeleton(n, 62);
  }

  /* ------------------------------------------------------------ 常驻采集 */
  function paintAgent(target) {
    var S = C.settings || {};
    U.clear(target.body);

    var a = state.agent || {};
    var running = !!a.running;
    var installed = !!a.installed;
    var bad = String(a.state || "") === "error";

    var head = U.el("div", "setting-line");
    /* 接口都不在时不能写「未安装」——那是猜的；只写「未开启」 */
    var kind = state.agentAbsent ? "na" : (running ? "ok" : (bad ? "crit" : "na"));
    var label = state.agentAbsent ? (S.agentStateUnknown || "")
      : (running ? S.agentStateOn : (bad ? S.agentStateErr : S.agentStateOff));
    head.appendChild(U.chip(kind, label));
    if (installed && a.interval_s) {
      head.appendChild(document.createTextNode("　" + (S.agentInterval || "") + "：" +
        U.tpl(S.agentIntervalVal || "{n}", { n: a.interval_s })));
    }
    target.body.appendChild(head);

    if (state.agentAbsent || !installed) {
      var off = U.el("div", "set-off");
      off.appendChild(U.el("b", "", S.agentOffTitle || ""));
      off.appendChild(U.el("p", "", state.agentAbsent ? (S.agentOffBody || "") : (S.agentInstallHint || "")));
      if (state.agentAbsent) off.appendChild(U.el("p", "set-why", S.agentOffWhy || ""));
      target.body.appendChild(off);
    }

    if (bad && a.last_error) {
      target.body.appendChild(U.el("p", "set-why", U.tpl(S.agentErr || "{reason}", { reason: a.last_error })));
    }

    /* 采样间隔：装了才有意义 */
    if (installed && !state.agentAbsent) {
      var row = U.el("div", "set-row");
      var f = U.el("div", "field");
      f.appendChild(U.el("label", "", S.agentInterval || ""));
      var sel = document.createElement("select");
      sel.className = "input set-sel";
      sel.setAttribute("aria-label", S.agentInterval || "");
      [5, 10, 30, 60].forEach(function (sec) {
        var o = document.createElement("option");
        o.value = String(sec);
        o.textContent = U.tpl(S.agentIntervalVal || "{n}", { n: sec });
        if (Number(a.interval_s) === sec) o.selected = true;
        sel.appendChild(o);
      });
      sel.addEventListener("change", function () {
        var v = Number(sel.value);
        ND.api.agentConfig({ interval_s: v }).then(function (res) {
          if (res && res.ok) {
            state.agent = clone(a);
            state.agent.interval_s = v;
            U.toast(S.targetsSaved || "", "ok");
          } else {
            U.toast(U.tpl(S.agentIntervalFail || "{reason}", { reason: U.why(res) }), "crit");
          }
        });
      });
      f.appendChild(sel);
      row.appendChild(f);
      target.body.appendChild(row);
    }

    /* 最近一次采样 */
    var last = U.el("p", "set-last");
    last.appendChild(U.el("b", "", (S.agentLast || "") + "："));
    last.appendChild(document.createTextNode(a.last_sample_at || S.agentLastNone || ""));
    target.body.appendChild(last);

    /* 装了就给「卸载」，没装才给「安装」：两个按钮同时挂着，用户不知道该按哪个 */
    if (!state.agentAbsent) {
      var acts = U.el("div", "setting-acts");
      if (!installed) {
        var inst = U.btn(S.agentInstall || "", { kind: "ghost", size: "sm", icon: "download" });
        inst.addEventListener("click", function () { install(inst); });
        acts.appendChild(inst);
      } else {
        var un = U.btn(S.agentUninstall || "", { kind: "ghost", size: "sm" });
        un.addEventListener("click", function () { confirmUninstall(un); });
        acts.appendChild(un);
      }
      target.body.appendChild(acts);
    }
  }

  function install(btn) {
    var S = C.settings || {};
    btn.disabled = true;
    var label = btn.querySelector(".btn-t");
    var old = label ? label.textContent : "";
    if (label) label.textContent = S.agentInstalling || old;
    ND.api.agentInstall().then(function (res) {
      if (res && res.ok) {
        U.toast(S.agentInstallHint || "", "ok");
        return ND.api.agent().then(function (r) {
          if (r && r.ok && r.data) state.agent = r.data;
          state.agentAbsent = false;
        });
      }
      U.toast(U.why(res), "crit");
      if (label) label.textContent = old;
      btn.disabled = false;
    });
  }

  function confirmUninstall(trigger) {
    var S = C.settings || {};
    var body = document.createDocumentFragment();
    body.appendChild(U.el("p", "", S.agentUninstallBody || ""));
    var cancel = U.btn(C.act.cancel, { kind: "ghost" });
    var ok = U.btn(S.agentUninstall || "", {});
    var box = U.modal({ title: S.agentUninstallTitle || "", body: body, actions: [cancel, ok] });
    cancel.addEventListener("click", function () { box.close(); });
    ok.addEventListener("click", function () {
      ok.disabled = true;
      cancel.disabled = true;
      ND.api.agentUninstall().then(function (res) {
        box.close();
        if (res && res.ok) {
          state.agent = { installed: false, running: false, state: "stopped" };
          var bg = currentAgentCard();
          if (bg) paintAgent(bg);
          return;
        }
        U.toast(U.why(res), "crit");
      });
    });
  }

  /* 卸载成功后重画整张卡：卡片节点没存引用，按类名找回来 */
  function currentAgentCard() {
    var sec = document.querySelector(".card.set-agent");
    if (!sec) return null;
    var body = sec.querySelector(".card-bd");
    return body ? { body: body } : null;
  }

  /* ------------------------------------------------------------ 监测目标 */
  function hostOk(s) {
    var t = String(s || "").trim();
    if (!t) return true;
    if (t.length > 255) return false;
    if (/[\s/\\]/.test(t)) return false;
    if (t.indexOf("://") >= 0) return false;
    return /^[A-Za-z0-9._:\-\[\]]+$/.test(t);
  }

  function paintTargets(target) {
    var S = C.settings || {};
    U.clear(target.body);
    target.body.appendChild(U.el("p", "muted", S.targetsHint || ""));

    var list = U.el("ul", "set-list");
    if (!state.targets.length) {
      list.appendChild(U.el("li", "set-empty", S.targetsEmpty || ""));
    }
    state.targets.forEach(function (t, i) {
      var li = U.el("li", "set-item");

      var host = document.createElement("input");
      host.className = "input";
      host.type = "text";
      host.value = t.host || "";
      host.placeholder = S.targetsHostPh || "";
      host.setAttribute("aria-label", S.targetsHost || "");
      host.addEventListener("change", function () {
        if (!hostOk(host.value)) {
          host.classList.add("is-bad");
          U.toast(S.targetsInvalid || "", "warn");
          host.value = t.host || "";
          return;
        }
        host.classList.remove("is-bad");
        t.host = host.value.trim();
        persistTargets();
      });

      var port = document.createElement("input");
      port.className = "input set-port";
      port.type = "text";
      port.inputMode = "numeric";
      port.value = t.port ? String(t.port) : "";
      port.placeholder = S.targetsPortPh || "";
      port.setAttribute("aria-label", S.targetsPort || "");
      port.addEventListener("change", function () {
        var v = port.value.trim();
        if (v && (!/^\d+$/.test(v) || Number(v) < 1 || Number(v) > 65535)) {
          port.classList.add("is-bad");
          port.value = t.port ? String(t.port) : "";
          return;
        }
        port.classList.remove("is-bad");
        t.port = v ? Number(v) : null;
        persistTargets();
      });

      var del = U.btn(S.targetsRemove || "", { kind: "ghost", size: "sm" });
      del.addEventListener("click", function () {
        state.targets.splice(i, 1);
        persistTargets();
        paintTargets(target);
      });

      li.appendChild(host);
      li.appendChild(port);
      li.appendChild(del);
      list.appendChild(li);
    });
    target.body.appendChild(list);

    var acts = U.el("div", "setting-acts");
    var add = U.btn(state.targets.length >= 3 ? (S.targetsFull || "") : (S.targetsAdd || ""), {
      kind: "ghost", size: "sm"
    });
    add.disabled = state.targets.length >= 3;
    add.addEventListener("click", function () {
      if (state.targets.length >= 3) return;
      state.targets.push({ host: "", port: null });
      paintTargets(target);
      var first = target.body.querySelector(".set-item:last-child input");
      if (first) first.focus();
    });
    acts.appendChild(add);
    target.body.appendChild(acts);

    if (state.monitorAbsent) {
      target.body.appendChild(U.el("p", "set-why", S.thrLocalOnly || ""));
    }
  }

  function persistTargets() {
    saveLocal();
    var body = { targets: state.targets.filter(function (t) { return String(t.host || "").trim(); }) };
    ND.api.saveMonitor(body).then(function (res) {
      if (res && res.ok) {
        state.monitorAbsent = false;
        U.toast((C.settings || {}).targetsSaved || "", "ok");
        return;
      }
      state.monitorAbsent = ND.api.absent(res);
      U.toast(state.monitorAbsent
        ? ((C.settings || {}).thrLocalOnly || "")
        : U.tpl((C.settings || {}).targetsSaveFail || "{reason}", { reason: U.why(res) }),
        state.monitorAbsent ? "warn" : "crit");
    });
  }

  /* ------------------------------------------------------------ 告警阈值 */
  function paintThresholds(target) {
    var S = C.settings || {};
    U.clear(target.body);

    var grid = U.el("div", "set-thr");
    [["rtt_ms", S.thrRtt, "ms", 10], ["jitter_ms", S.thrJitter, "ms", 5], ["loss_pct", S.thrLoss, "%", 1]]
      .forEach(function (spec) {
        var key = spec[0];
        var f = U.el("div", "field");
        f.appendChild(U.el("label", "", spec[1] || ""));
        var wrap = U.el("div", "set-num");
        var input = document.createElement("input");
        input.className = "input";
        input.type = "number";
        input.min = "0";
        input.step = String(spec[3]);
        input.value = String(state.thresholds[key]);
        input.setAttribute("aria-label", spec[1] || "");
        input.addEventListener("change", function () {
          var v = Number(input.value);
          if (!isFinite(v) || v < 0) { input.value = String(state.thresholds[key]); return; }
          state.thresholds[key] = v;
          persistThresholds();
        });
        wrap.appendChild(input);
        wrap.appendChild(U.el("span", "set-unit", spec[2] || ""));
        f.appendChild(wrap);
        grid.appendChild(f);
      });
    target.body.appendChild(grid);

    target.body.appendChild(U.el("p", "muted", S.thrHint || ""));
    if (state.monitorAbsent) target.body.appendChild(U.el("p", "set-why", S.thrLocalOnly || ""));
  }

  function persistThresholds() {
    saveLocal();
    ND.api.saveMonitor({ thresholds: state.thresholds }).then(function (res) {
      if (res && res.ok) {
        state.monitorAbsent = false;
        U.toast((C.settings || {}).thrSaved || "", "ok");
        return;
      }
      state.monitorAbsent = ND.api.absent(res);
      U.toast(state.monitorAbsent
        ? ((C.settings || {}).thrLocalOnly || "")
        : U.tpl((C.settings || {}).targetsSaveFail || "{reason}", { reason: U.why(res) }),
        state.monitorAbsent ? "warn" : "crit");
    });
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
