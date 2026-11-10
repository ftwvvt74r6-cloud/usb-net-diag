/* ============================================================================
   home.js · 总览页：指标卡 + 实时与专业数据（左三层结论 / 右专业面板）+ 环境
   ----------------------------------------------------------------------------
   这一页只做两件事：
   1) 把「现在到底能不能上网、卡在哪」用三层结构说清楚（ND.verdict）
   2) 把同一份结果的原始数字摊开（ND.panel），每行都能复制 Wireshark 过滤器

   有任务在跑时：KPI 显示「诊断中…」，左边不摆结论（还没算出来，摆就是编），
   右边给出进度摘要。轮询只在有任务时开，任务结束立刻释放。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var R = ND.render;
  var P = C.panel || {};

  var page = null;

  function cleanup() {
    if (!page) return;
    if (page.unsub) page.unsub();
    ND.state.release("home");
    page = null;
  }

  function render(view) {
    cleanup();
    U.clear(view);

    var kpis = U.el("dl", "kpis");
    var src = U.el("p", "kpi-src");
    view.appendChild(kpis);
    view.appendChild(src);

    /* ---- 实时与专业数据：一张卡，左说人话右给数据 ---- */
    var card = U.el("section", "card livecard");
    var hd = U.el("div", "card-hd");
    hd.appendChild(U.el("h2", "", P.title || ""));
    hd.appendChild(U.el("span", "card-sub", P.sub || ""));

    var sw = U.el("label", "pro-sw");
    var cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = ND.state.isPro();
    cb.setAttribute("aria-label", P.pro || "");
    cb.addEventListener("change", function () {
      ND.state.setPro(cb.checked);
      U.toast(cb.checked ? (C.pro || {}).on : (C.pro || {}).off, "");
    });
    sw.appendChild(cb);
    sw.appendChild(U.el("span", "pro-sw-t", P.pro || ""));
    sw.title = P.proHint || "";
    hd.appendChild(sw);

    var fold = U.btn(P.fold || "", { kind: "ghost", size: "sm", onClick: function () { togglePanel(fold); } });
    hd.appendChild(fold);
    card.appendChild(hd);

    var prow = U.el("div", "prow");
    var left = U.el("div", "p-left");
    var right = U.el("div", "p-right");
    prow.appendChild(left);
    prow.appendChild(right);
    card.appendChild(prow);
    view.appendChild(card);

    var envHost = U.el("div", "home-env");
    view.appendChild(envHost);

    page = { kpis: kpis, src: src, left: left, right: right, prow: prow,
             envHost: envHost, foldBtn: fold, envDrawn: false, sig: "" };

    paint(true);
    left.appendChild(skeletonBlock());
    right.appendChild(skeletonBlock());

    page.unsub = ND.state.subscribe(function (S, evt) {
      if (evt === "job" || evt === "last" || evt === "init" || evt === "pro") apply();
    });

    if (!(ND.state.get().checks || []).length) ND.state.loadChecks();

    ND.state.refreshLastRun().then(function () { ND.state.refreshStatus(); });
  }

  function togglePanel(btn) {
    if (!page) return;
    var show = page.right.hidden;
    page.right.hidden = !show;
    page.right.classList.toggle("is-hidden", !show);
    page.prow.classList.toggle("is-full", !show);
    var t = btn.querySelector(".btn-t");
    if (t) t.textContent = show ? (P.fold || "") : (P.unfold || "");
  }

  function apply() {
    if (!page) return;
    var S = ND.state.get();
    var running = ND.state.isRunning();
    paint(false, running);

    if (running) ND.state.acquire("home", 1200);
    else ND.state.release("home");

    var sig = [
      S.last ? (S.last.epoch || S.last.time || "1") : "0",
      S.last && S.last.full_result ? 1 : 0,
      S.last && S.last.legacy ? 1 : 0,
      S.result ? 1 : 0,
      running ? 1 : 0,
      ND.state.isPro() ? 1 : 0,
      /* 专业模式的控制台尾巴跟着日志走：日志变了就得重画，否则永远停在打开那一刻 */
      ND.state.isPro() ? (((S.job || {}).logs || []).length) : 0
    ].join("|");
    if (page.sig === sig) return;
    page.sig = sig;

    U.clear(page.left);
    leftPane(running);

    /* 专业面板：运行中给进度摘要，结束后给真实统计。
       旧记录 / 上次失败没有本次数据，不拿别的记录往上凑。 */
    var last = S.last;
    var stale = !!(last && (last.legacy || !last.ok));
    ND.panel.render(page.right, stale ? null : resultOf(S, running), {
      bare: true, pro: ND.state.isPro(), job: S.job
    });

    if (!page.envDrawn && (S.checks || []).length) {
      page.envDrawn = true;
      U.clear(page.envHost).appendChild(ND.env.card(S.checks, {
        onRecheck: function (list) {
          if (ND.boot && ND.boot.paintChips) ND.boot.paintChips(list);
          ND.state.applyJob(ND.state.get().job);
        }
      }));
    }
  }

  /* 本次结果优先：status 里刚跑完的那份比 last-run 更新 */
  function resultOf(S, running) {
    if (running) return null;
    var job = S.job || {};
    if (job.state === "done" && job.result) return job.result;
    return S.result || (job.state === "done" ? job.result : null);
  }

  /* ------------------------------------------------------------ 左栏 */
  function leftPane(running) {
    var S = ND.state.get();
    var last = S.last;
    var host = page.left;

    if (running) {
      var jb = S.job || {};
      host.appendChild(R.empty("speed", P.running || "",
        U.tpl(P.runningBody || "", {
          phase: jb.phase || "", elapsed: U.num(jb.elapsed, 0) || "0",
          lines: (jb.logs || []).length
        }),
        [U.btn(C.act.view, {
          kind: "ghost", size: "sm",
          onClick: function () { location.hash = "#/" + (jb.mode || "scan"); }
        })]));
      return;
    }

    if (!last) {
      host.appendChild(R.empty("report", C.lastRun.emptyTitle, C.lastRun.emptyBody, [startBtn()]));
      return;
    }

    /* 旧记录：没有边界也就没有专业数据，只留横幅 + 重新诊断 */
    if (last.legacy) {
      host.appendChild(R.banner("warn", C.lastRun.legacyTitle, C.lastRun.legacyBody));
      host.appendChild(actionsRow(last, false));
      return;
    }

    if (!last.ok) {
      host.appendChild(failBlock(last));
      return;
    }

    var job = { result: resultOf(S, false), mode: last.mode };
    if (!job.result) {
      host.appendChild(R.banner("warn", C.lastRun.summaryOnly));
      host.appendChild(actionsRow(last, false));
      return;
    }
    job.conclusion = job.result.conclusion || null;
    job.report_id = job.result.report_id;
    job.link_actions = (S.job || {}).link_actions || [];   /* 复测用后端给的地址，不自己猜 */
    job.mode = (S.job && S.job.mode) || last.mode;

    var card = ND.verdict.card(job, { bare: true });
    if (card) {
      host.appendChild(card);
      host.appendChild(actionsRow(last, false));
    } else {
      host.appendChild(R.banner("warn", C.result.title, C.tech.empty));
    }
  }

  function startBtn() {
    var m = U.mode("scan");
    var go = U.btn((m && m.btn) || C.act.rerun, { size: "sm" });
    go.addEventListener("click", function () { location.hash = "#/scan"; });
    return go;
  }

  function actionsRow(last, withExport) {
    var row = U.el("div", "result-acts");
    row.appendChild(U.btn(C.act.view, {
      kind: "ghost", size: "sm", icon: "report",
      onClick: function () { summaryModal(last); }
    }));
    row.appendChild(U.btn(C.act.rerun, {
      kind: "ghost", size: "sm", icon: "refresh",
      onClick: function () { location.hash = "#/" + ((last && last.mode) || "scan"); }
    }));
    return row;
  }

  function failBlock(last) {
    var box = U.el("div", "left-fail");
    var F = C.fail || {};
    box.appendChild(U.el("p", "result-head crit", F.title));
    box.appendChild(labeled(F.reasonLabel, F.reasonGeneric));
    box.appendChild(labeled(F.adviceLabel, F.advice));
    var acts = U.el("div", "result-acts");
    acts.appendChild(U.btn(C.act.retry, { kind: "ghost", size: "sm", onClick: function () { location.hash = "#/" + ((last && last.mode) || "scan"); } }));
    acts.appendChild(U.btn(C.act.logs, { kind: "ghost", size: "sm", onClick: function () { location.hash = "#/logs"; } }));
    box.appendChild(acts);
    return box;
  }

  function labeled(label, text) {
    var p = U.el("p", "result-label");
    p.appendChild(U.el("b", "", (label || "") + "："));
    p.appendChild(document.createTextNode(text || ""));
    return p;
  }

  function skeletonBlock() {
    var c = U.el("div", "left-sk");
    c.appendChild(R.skeleton(4, 62));
    return c;
  }

  /* ------------------------------------------------------------ 指标卡 */
  function paint(loading, running) {
    var host = page.kpis;
    U.clear(host);
    var S = ND.state.get();
    var last = S.last;
    var res = resultOf(S, running);
    var meta = (res && res.meta) || {};
    var metrics = (res && res.metrics) || {};
    var verdict = (res && res.verdict) || {};
    var K = C.kpi || {};

    if (running) {
      var job = S.job || {};
      host.appendChild(R.kpi(K.health, "", K.runningSub, "", { running: true }));
      host.appendChild(R.kpi(K.latency, "", "", "", { running: true }));
      host.appendChild(R.kpi(K.loss, "", "", "", { running: true }));
      host.appendChild(R.kpi(K.session, "", "", "", { running: true }));
      U.clear(page.src);
      page.src.appendChild(U.el("b", "", (C.source.label || "") + "："));
      page.src.appendChild(document.createTextNode(U.tpl(C.source.running || "", {
        mode: U.modeLabel(job.mode), phase: job.phase || ""
      })));
      return;
    }

    var level = String((verdict && verdict.level) || (last && last.level) || "");
    var legacy = !!(last && last.legacy);
    var failed = !!(last && !last.ok && !legacy);

    /* 0 包 / 样本不足时 RTT 与重传率都是 0，那是「没样本」而不是「很好」 */
    var zeroPkt = isFinite(Number(meta.packets)) && Number(meta.packets) === 0;
    var sufficiency = verdict && verdict.sufficiency;
    var thin = zeroPkt || level === (C.sev || {}).na ||
               !!(sufficiency && sufficiency.ok === false);

    var rtt = thin ? null : pick(metrics.rtt_avg_ms, meta.rtt_avg_ms, res && res.summary && res.summary.rtt_avg_ms);
    var loss = thin ? null : pick(meta.retrans_rate, res && res.summary && res.summary.retrans_rate);
    var streams = thin ? null : (meta.streams_total === undefined ? null : meta.streams_total);

    var why = !last ? K.noData
      : failed ? K.failed
      : thin ? K.thin
      : K.summaryOnly;

    host.appendChild(R.kpi(K.health, level,
      level ? (legacy ? K.healthSubLegacy : K.healthSub) : why, kindOfLevel(level), { loading: loading }));
    host.appendChild(R.kpi(K.latency, rtt === null ? "" : U.num(rtt, 1) + " ms",
      rtt === null ? why : K.latencySub, "", { loading: loading }));
    host.appendChild(R.kpi(K.loss, loss === null ? "" : U.num(loss, 2) + "%",
      loss === null ? why : K.lossSub, "", { loading: loading }));
    host.appendChild(R.kpi(K.session, streams === null ? "" : U.num(streams, 0),
      streams === null ? why : K.sessionSub, "", { loading: loading }));

    U.clear(page.src);
    if (loading) { page.src.textContent = C.common.loading; return; }
    if (!last) { page.src.textContent = C.source.none; return; }
    page.src.appendChild(U.el("b", "", (C.source.label || "") + "："));
    var tail = last.target ? (" · " + last.target) : "";
    var packets = meta.packets;
    page.src.appendChild(document.createTextNode(
      packets === undefined || packets === null
        ? U.tpl(C.source.summary, { when: U.when(last.epoch, last.time), mode: U.modeLabel(last.mode), target: tail })
        : U.tpl(C.source.line, {
            when: U.when(last.epoch, last.time), mode: U.modeLabel(last.mode), target: tail,
            packets: U.num(packets, 0)
          })
    ));
  }

  function pick() {
    for (var i = 0; i < arguments.length; i++) {
      var v = arguments[i];
      if (v !== null && v !== undefined && v !== "" && isFinite(Number(v))) return Number(v);
    }
    return null;
  }

  function kindOfLevel(level) {
    var s = C.sev || {};
    if (!level) return "na";
    if (level === s.critical) return "crit";
    if (level === s.warning) return "warn";
    if (level === s.info) return "warn";
    if (level === s.ok) return "ok";
    return "";
  }

  /* ------------------------------------------------------------ 摘要弹窗 */
  function summaryModal(last) {
    var body = document.createDocumentFragment();
    body.appendChild(R.kv([
      [C.lastRun.rowWhen, U.when(last.epoch, last.time)],
      [C.lastRun.rowMode, U.modeLabel(last.mode)],
      [C.lastRun.rowTarget, last.target || "—"],
      [C.lastRun.rowLevel, String(last.level || C.common.na)],
      [C.lastRun.rowCritical, String(last.critical || 0)],
      [C.lastRun.rowWarning, String(last.warning || 0)],
      [C.lastRun.rowDuration, U.dur(last.duration_ms) || "—"]
    ], { cols: 1 }));
    body.appendChild(U.el("p", "muted",
      last.full_result ? C.lastRun.summaryKept : C.lastRun.summaryGone));

    var close = U.btn(C.act.close, { kind: "ghost" });
    var box = U.modal({ title: C.lastRun.summaryTitle, body: body, actions: [close] });
    close.addEventListener("click", function () { box.close(); });
  }

  ND.home = { render: render, cleanup: cleanup };
})(window.ND = window.ND || {});
