/* ============================================================================
   modes.js · 五个模式页（全网体检 / 单目标诊断 / 通信观察 / 连通与速度测试 /
   分析抓包文件）
   ----------------------------------------------------------------------------
   一个模式页只有三段，按状态出现：
     参数卡（填好 → 点开始） → 运行卡（进度 + 控制台 + 技术详情） → 结果卡

   取数全部走 ND.state；本文件不直接 fetch。轮询也由 state 管：
   进页面 acquire("modes")，任务结束立刻 release —— 不让后台服务因为一个空转的
   页面永不空闲退出。连通与速度测试是同步接口（/api/probe），不走任务态。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var R = ND.render;

  var page = null;        /* 当前页面的活动上下文，切页时 cleanup 掉 */

  function cleanup() {
    if (!page) return;
    if (page.unsub) page.unsub();
    ND.state.release("modes");
    page = null;
  }

  /* ------------------------------------------------------------ 入口 */
  function render(view, id) {
    cleanup();
    U.clear(view);
    if (id === "probe") return renderProbe(view, id);

    var mode = U.mode(id) || {};
    var ctx = {
      id: id, mode: mode, view: view,
      jobKey: "",          /* 上一次渲染时的状态签名，避免无变化重建 */
      stream: null,
      progressHost: null,
      techHost: null,
      form: null,
      runCard: null,
      resultHost: null,
      error: ""
    };
    page = ctx;

    view.appendChild(pageHead(mode));

    ctx.form = buildForm(id, mode, ctx);
    view.appendChild(ctx.form.section);

    ctx.runCard = R.card(C.run.cardTitle, { cls: "runcard" });
    ctx.runCard.section.hidden = true;
    ctx.progressHost = U.el("div", "run-progress");
    ctx.runCard.body.appendChild(ctx.progressHost);
    ctx.techHost = U.el("div", "run-tech");
    view.appendChild(ctx.runCard.section);

    ctx.resultHost = U.el("div", "result-zone");
    view.appendChild(ctx.resultHost);

    ctx.unsub = ND.state.subscribe(function (S, evt) {
      if (evt === "job" || evt === "init") apply(S);
    });

    /* 进来先看一次：可能是刚跑完的任务，也可能正跑到一半 */
    ND.state.refreshStatus();
    apply(ND.state.get());
  }

  function pageHead(mode) {
    var head = U.el("div", "pagehead");
    head.appendChild(U.el("h2", "", mode.title || mode.label || ""));
    if (mode.sub) head.appendChild(U.el("p", "", mode.sub));
    if (mode.guide) head.appendChild(U.el("p", "muted", mode.guide));
    return head;
  }

  /* ------------------------------------------------------------ 参数卡 */
  function buildForm(id, mode, ctx) {
    var F = C.form || {};
    var c = R.card(mode.label || "", { sub: mode.tech || "" });
    var wrap = U.el("div", "form-grid");
    var fields = mode.fields || [];
    var inputs = {};

    if (fields.indexOf("target") >= 0) {
      var tf = field(F.target, F.targetHint);
      var ti = U.el("input", "input");
      ti.type = "text";
      ti.placeholder = F.targetPh || "";
      ti.spellcheck = false;
      ti.value = ctx.targetValue || "";
      tf.box.appendChild(ti);
      inputs.target = ti;
      wrap.appendChild(tf.box);
    }

    if (fields.indexOf("duration") >= 0) {
      var df = field(F.duration, F.durationHint);
      var di = U.el("input", "input input-num");
      di.type = "number";
      di.min = "3";
      di.max = "180";
      di.step = "5";
      di.value = "30";
      df.box.appendChild(di);
      inputs.duration = di;
      wrap.appendChild(df.box);
    }

    if (fields.indexOf("iface") >= 0) {
      var iff = field(F.iface, F.ifaceHint);
      var si = U.el("select", "input");
      si.appendChild(option("", F.ifaceAuto));
      iff.box.appendChild(si);
      inputs.iface = si;
      wrap.appendChild(iff.box);
      ND.api.interfaces().then(function (res) {
        if (!res.ok) return;
        var list = (res.data || {}).interfaces || [];
        U.clear(si);
        si.appendChild(option("", F.ifaceAuto));
        list.forEach(function (it) {
          si.appendChild(option(String(it.index || ""), it.name || it.short || ""));
        });
      });
    }

    if (fields.indexOf("engine") >= 0) {
      var ef = field(F.engine, F.engineHint);
      var ei = U.el("select", "input");
      ei.appendChild(option("auto", F.engineAuto));
      ei.appendChild(option("scapy", F.engineScapy));
      ei.appendChild(option("tshark", F.engineTshark));
      ef.box.appendChild(ei);
      inputs.engine = ei;
      wrap.appendChild(ef.box);
    }

    if (fields.indexOf("offline") >= 0) {
      var pf = field(F.pcap, "");
      var pi = U.el("select", "input");
      pi.appendChild(option("", F.pcapPh));
      pf.box.appendChild(pi);
      inputs.pcap = pi;
      wrap.appendChild(pf.box);
      ctx.pcapHint = U.el("p", "muted", "");
      pf.box.appendChild(ctx.pcapHint);
      ND.api.captures().then(function (res) {
        var files = res.ok ? ((res.data || {}).files || []) : [];
        U.clear(pi);
        pi.appendChild(option("", files.length ? F.pcapPh : F.pcapEmpty));
        files.forEach(function (f) {
          pi.appendChild(option(f.name, f.name + " · " + U.size(f.size)));
        });
      });
    }

    c.body.appendChild(wrap);

    /* 探针与逐跳：只有实时抓包类模式才有 */
    if (mode.shadow) {
      var line = U.el("label", "checkline");
      var cb = U.el("input");
      cb.type = "checkbox";
      cb.checked = true;
      line.appendChild(cb);
      line.appendChild(U.el("span", "", F.shadow || ""));
      c.body.appendChild(line);
      c.body.appendChild(U.el("p", "muted", F.shadowHint || ""));
      inputs.shadow = cb;
    }

    var err = U.el("p", "formerr");
    var acts = U.el("div", "form-acts");
    var go = U.btn(mode.btn || "", { icon: "play" });
    acts.appendChild(go);
    c.body.appendChild(acts);
    c.body.appendChild(err);

    ctx.inputs = inputs;
    ctx.goBtn = go;
    ctx.errEl = err;

    go.addEventListener("click", function () {
      var payload = collect(id, inputs);
      var bad = validate(id, payload);
      err.textContent = bad || "";
      if (bad) return;
      if (go.disabled) return;
      go.disabled = true;
      var label = go.querySelector(".btn-t");
      var old = label.textContent;
      label.textContent = F.starting || "";
      ND.state.startJob(payload).then(function (res) {
        go.disabled = false;
        label.textContent = old;
        if (res && res.ok) {
          ND.state.acquire("modes", 900);
          return;
        }
        var why = (res && res.data && (res.data.error || res.data.reason)) || U.why(res);
        err.textContent = U.tpl(F.startFail, { reason: why });
        U.toast(U.tpl(F.startFail, { reason: why }), "crit");
      });
    });

    return c;
  }

  function field(label, hint) {
    var box = U.el("div", "field");
    if (label) box.appendChild(U.el("label", "", label));
    if (hint) box.appendChild(U.el("p", "field-hint", hint));
    return { box: box };
  }

  function option(value, text) {
    var o = document.createElement("option");
    o.value = value;
    o.textContent = text || "";
    return o;
  }

  function collect(id, inputs) {
    var payload = { mode: id === "offline" ? "offline" : id };
    if (inputs.target) payload.target = (inputs.target.value || "").trim();
    if (inputs.duration) payload.duration = Number(inputs.duration.value) || 30;
    if (inputs.iface) payload.interface = inputs.iface.value || null;
    if (inputs.engine) payload.engine = inputs.engine.value || "auto";
    if (inputs.pcap) payload.pcap = inputs.pcap.value || "";
    if (inputs.shadow) payload.shadow = !!inputs.shadow.checked;
    return payload;
  }

  function validate(id, payload) {
    var F = C.form || {};
    if (id === "live" && !payload.target) return F.needTarget || "";
    if (id === "offline" && !payload.pcap) return F.needPcap || "";
    return "";
  }

  /* ------------------------------------------------------------ 状态刷新 */
  function apply(S) {
    if (!page) return;
    var job = S.job;
    var state = (job && job.state) || "idle";
    var running = state === "running" || state === "starting";
    var done = state === "done" || state === "error";

    /* 运行中把参数卡锁住：避免用户以为改了参数会影响这一次 */
    setFormLocked(page, running);

    /* 运行卡：运行中给进度 + 控制台 + 技术详情（技术详情此时只有一句说明）；
       结束后收起进度、控制台折叠成一行，技术详情才有真数据。
       旧版本记录不是本次运行出来的，连运行卡一起收掉，只留横幅 + 重新诊断。 */
    var legacyRec = !running && done && job && job.result && job.result.legacy === true;
    if ((running || done) && !legacyRec) {
      page.runCard.section.hidden = false;
      U.clear(page.progressHost);
      if (running) page.progressHost.appendChild(ND.console.progress(job));
      if (!page.stream) {
        page.stream = ND.console.stream(job);
        page.runCard.body.appendChild(page.stream.el);
        page.runCard.body.appendChild(page.techHost);
      } else {
        page.stream.update(job);
      }
      if (page.techKey !== state) {
        page.techKey = state;
        U.clear(page.techHost);
        page.techHost.appendChild(R.techDetails(job));
      }
    } else {
      page.runCard.section.hidden = true;
    }

    /* 结果区只在「状态 / 结果身份」变化时重建，别每次轮询都掀桌子 */
    var res = job && job.result;
    var key = [state, ymdhms(job && job.started_at), job && job.error,
               res ? ((res.meta || {}).generated_at || "1") : "0",
               res ? (res.rows || []).length : 0].join("|");
    if (key === page.jobKey) return;
    page.jobKey = key;

    if (running) {
      ND.state.acquire("modes", 900);
      U.clear(page.resultHost);
      return;
    }

    ND.state.release("modes");
    U.clear(page.resultHost);
    if (job && job.state === "done") page.resultHost.appendChild(renderDone(job));
    else if (job && job.state === "error") page.resultHost.appendChild(renderFail(job));
  }

  function ymdhms(v) {
    return v === null || v === undefined ? "" : String(v).slice(0, 19);
  }

  function setFormLocked(ctx, locked) {
    if (!ctx.form) return;
    var inputs = ctx.form.section.querySelectorAll("input, select");
    for (var i = 0; i < inputs.length; i++) inputs[i].disabled = locked;
    if (ctx.goBtn) {
      ctx.goBtn.disabled = locked;
      var t = ctx.goBtn.querySelector(".btn-t");
      if (t) {
        t.textContent = locked
          ? ((C.run || {}).runningLabel || "")
          : (ctx.mode.btn || "");
      }
    }
  }

  /* ------------------------------------------------------------ 结果 */
  function renderDone(job) {
    var box = U.el("div", "stack-lg");
    var res = job.result || null;

    if (!res) {
      box.appendChild(R.banner("warn", C.result.title, C.lastRun.summaryOnly));
      box.appendChild(actionsRow(job, false));
      return box;
    }

    /* 旧版本记录：只给横幅 + 重新诊断，不渲染结论、不给含边界导出 */
    if (res.legacy === true) {
      box.appendChild(R.banner("warn", C.lastRun.legacyTitle, C.lastRun.legacyBody));
      box.appendChild(actionsRow(job, false));
      return box;
    }

    /* 降级：0 包或证据不足 —— 结论照给（低置信），但先把原因说在前面 */
    var degrade = degradeInfo(job);
    if (degrade) {
      box.appendChild(R.banner("warn",
        degrade.zero ? C.degrade.zeroTitle : C.degrade.title,
        degrade.zero ? C.degrade.zeroBody : U.tpl(C.degrade.thinBody, { packets: degrade.packets })));
    }

    var concl = R.conclusion(job, {
      evidence: R.evidence(job),
      advice: R.advice(job)
    });
    if (concl) box.appendChild(concl);
    else box.appendChild(R.banner("warn", C.result.title, C.tech.empty));

    /* 技术详情只挂在「运行」卡里（运行中/结束都同一位置），结果区不再复制一份 */
    box.appendChild(actionsRow(job, true));
    return box;
  }

  function actionsRow(job, withExport) {
    var row = U.el("div", "result-acts");
    var modeId = (job && job.mode) || page.id;
    row.appendChild(U.btn(C.act.rerun, {
      kind: "ghost", size: "sm", icon: "refresh",
      onClick: function () { restart(modeId); }
    }));
    if (withExport && job && job.result && (job.result.report_path || job.result.report_id)) {
      row.appendChild(U.btn(C.act.view, {
        kind: "ghost", size: "sm", icon: "report",
        onClick: function () { showReport(job); }
      }));
    }
    return row;
  }

  /* 重新诊断：把上次的参数填回表单，用户确认后再点开始 */
  function restart(modeId) {
    if (modeId !== page.id) {
      location.hash = "#/" + modeId;
      return;
    }
    var inputs = page.inputs || {};
    if (inputs.target) inputs.target.focus();
    if (inputs.target) inputs.target.select();
    U.toast(C.act.rerun, "");
  }

  function showReport(job) {
    var res = (job && job.result) || {};
    var md = res.report_markdown || res.report_path || "";
    var body = document.createDocumentFragment();
    if (res.report_path) body.appendChild(R.kv([[C.result.reportPath, res.report_path]], { cols: 1 }));
    if (md) {
      var pre = U.el("pre", "mono logview-pre", String(md).slice(0, 20000));
      body.appendChild(pre);
    } else {
      body.appendChild(U.el("p", "muted", C.result.exportNone));
    }
    var close = U.btn(C.act.close, { kind: "ghost" });
    var box = U.modal({ title: C.act.view, body: body, actions: [close] });
    close.addEventListener("click", function () { box.close(); });
  }

  function degradeInfo(job) {
    var res = (job && job.result) || {};
    var meta = res.meta || {};
    var v = res.verdict || {};
    var pk = Number(meta.packets);
    if (isFinite(pk) && pk === 0) return { zero: true, packets: 0 };
    if (v.sufficiency && v.sufficiency.ok === false) return { zero: false, packets: isFinite(pk) ? pk : 0 };
    return null;
  }

  /* ------------------------------------------------------------ 失败 */
  function renderFail(job) {
    var box = U.el("div", "stack-lg");
    var F = C.fail || {};
    var c = R.card(C.result.title, { tag: { kind: "crit", text: C.lastRun.failTag } });
    c.body.appendChild(U.el("p", "result-head crit", F.title));

    var reason = (job && job.error) || "";
    if (reason) c.body.appendChild(labeled(F.reasonLabel, reason));
    else c.body.appendChild(labeled(F.reasonLabel, F.reasonGeneric));
    c.body.appendChild(labeled(F.adviceLabel, F.advice));

    var acts = U.el("div", "result-acts");
    acts.appendChild(U.btn(C.act.retry, { size: "sm", icon: "refresh",
      onClick: function () { restart(page.id); } }));
    acts.appendChild(U.btn(C.act.logs, { kind: "ghost", size: "sm", onClick: function () {
      location.hash = "#/logs";
    } }));
    c.body.appendChild(acts);

    box.appendChild(c.section);
    return box;
  }

  function labeled(label, text) {
    var p = U.el("p", "result-label");
    p.appendChild(U.el("b", "", (label || "") + "："));
    p.appendChild(document.createTextNode(text || ""));
    return p;
  }

  /* ------------------------------------------------------------ 连通与速度测试 */
  /* 同步接口：点了就等（最多 10 来秒），没有进度条，但一样给结论/证据/技术详情 */
  function renderProbe(view, id) {
    var mode = U.mode(id) || {};
    var F = C.form || {};
    var ctx = { id: id, busy: false };
    page = ctx;

    view.appendChild(pageHead(mode));

    var c = R.card(mode.label || "", { sub: mode.tech || "" });
    var wrap = U.el("div", "form-grid");

    var tf = field(F.target, F.targetHint);
    var ti = U.el("input", "input");
    ti.type = "text";
    ti.placeholder = F.targetPh || "";
    ti.spellcheck = false;
    tf.box.appendChild(ti);
    wrap.appendChild(tf.box);

    var pf = field(F.port || "端口", F.portHint || "");
    var pi = U.el("input", "input input-num");
    pi.type = "number";
    pi.min = "1";
    pi.max = "65535";
    pi.placeholder = "443";
    pf.box.appendChild(pi);
    wrap.appendChild(pf.box);

    c.body.appendChild(wrap);

    var line = U.el("label", "checkline");
    var cb = U.el("input");
    cb.type = "checkbox";
    cb.checked = true;
    line.appendChild(cb);
    line.appendChild(U.el("span", "", F.path || ""));
    c.body.appendChild(line);

    var err = U.el("p", "formerr");
    var acts = U.el("div", "form-acts");
    var go = U.btn(mode.btn || "", { icon: "play" });
    acts.appendChild(go);
    c.body.appendChild(acts);
    c.body.appendChild(err);
    view.appendChild(c.section);

    var out = U.el("div", "result-zone");
    view.appendChild(out);

    go.addEventListener("click", function () {
      var target = (ti.value || "").trim();
      if (!target) { err.textContent = F.needTarget || ""; ti.focus(); return; }
      if (ctx.busy) return;
      ctx.busy = true;
      go.disabled = true;
      var label = go.querySelector(".btn-t");
      var old = label.textContent;
      label.textContent = F.starting || "";
      U.clear(out);
      out.appendChild(cardWith(R.skeleton(3)));
      ND.api.post("/api/probe", {
        target: target,
        port: pi.value ? Number(pi.value) : null,
        path: !!cb.checked
      }).then(function (res) {
        ctx.busy = false;
        go.disabled = false;
        label.textContent = old;
        U.clear(out);
        if (!res.ok) {
          err.textContent = U.tpl(F.startFail, { reason: U.why(res) });
          return;
        }
        out.appendChild(renderProbeResult(res.data || {}));
      });
    });
  }

  function cardWith(content) {
    var c = R.card(C.result.title);
    c.body.appendChild(content);
    return c.section;
  }

  function renderProbeResult(d) {
    var box = U.el("div", "stack-lg");
    var c = R.card(C.result.title, {
      tag: d.ok ? { kind: "ok", text: C.lastRun.okTag } : { kind: "crit", text: C.lastRun.failTag }
    });

    c.body.appendChild(U.el("p", "result-head", d.headline || ""));
    if (d.advice) c.body.appendChild(labeled(C.fail.adviceLabel, d.advice));

    var segs = d.segments || [];
    if (segs.length) {
      var tbl = U.el("ul", "seglist");
      segs.forEach(function (s) {
        var li = U.el("li", "segrow " + (s.status || ""));
        li.appendChild(U.el("span", "seg-name", s.name || ""));
        li.appendChild(U.el("span", "seg-ms mono",
          s.ms === null || s.ms === undefined ? "—" : Number(s.ms).toFixed(1) + " ms"));
        if (s.note) li.appendChild(U.el("span", "seg-note", s.note));
        tbl.appendChild(li);
      });
      c.body.appendChild(tbl);
    }
    box.appendChild(c.section);

    /* 逐跳（体检带 path 时后端才给） */
    var pp = d.path_profile;
    if (pp && pp.hops && pp.hops.length) {
      var pc = R.card(C.tech.path);
      pc.body.appendChild(hopTable(pp));
      box.appendChild(pc.section);
    }
    return box;
  }

  function hopTable(pp) {
    var tbl = U.el("div", "hop-table");
    var head = U.el("div", "hop-row hop-head");
    ((C.tech || {}).hopCols || []).forEach(function (t) { head.appendChild(U.el("span", "", t)); });
    tbl.appendChild(head);
    (pp.hops || []).forEach(function (h) {
      var row = U.el("div", "hop-row");
      row.appendChild(U.el("span", "mono", String(h.ttl || "")));
      row.appendChild(U.el("span", "mono", h.ip || "*"));
      row.appendChild(U.el("span", "mono", (h.sent || 0) + "/" + (h.lost || 0)));
      row.appendChild(U.el("span", "mono",
        (h.loss_pct === null || h.loss_pct === undefined) ? "—" : h.loss_pct + "%"));
      row.appendChild(U.el("span", "mono",
        isFinite(Number(h.rtt_avg_ms)) ? Number(h.rtt_avg_ms).toFixed(1) + " ms" : "—"));
      tbl.appendChild(row);
    });
    return tbl;
  }

  ND.modes = { render: render, cleanup: cleanup };
})(window.ND = window.ND || {});
