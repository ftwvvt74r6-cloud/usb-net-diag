/* ============================================================================
   home.js · 总览页：四张指标卡 + 最近一次结果 + 环境与依赖
   ----------------------------------------------------------------------------
   数据只有一个来源：ND.state（背后是 /api/last-run + /api/last-run/result）。
   有任务在跑时，KPI 显示「诊断中…」+ 小 spinner，而不是「暂无数据」——
   否则用户切回首页会以为任务没在跑，回去再点一次。
   轮询只在有任务时开（state.acquire("home")），任务结束立刻释放，
   不让一个空转的首页把后台服务的空闲退出拖住。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var R = ND.render;

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
    var cols = U.el("div", "cols");
    var left = U.el("div", "col-main");
    var right = U.el("div", "col-side");

    view.appendChild(kpis);
    view.appendChild(src);
    cols.appendChild(left);
    cols.appendChild(right);
    view.appendChild(cols);

    page = { view: view, kpis: kpis, src: src, left: left, right: right, envDrawn: false, resultSig: "" };

    paint(true);

    left.appendChild(skeletonCard(C.card.lastRun));
    right.appendChild(skeletonCard(C.card.env));

    page.unsub = ND.state.subscribe(function (S, evt) {
      if (evt === "last" || evt === "job" || evt === "init") apply();
    });

    /* 环境检查与顶栏徽章共用 state 里那一份，不重复请求 */
    if (!(ND.state.get().checks || []).length) ND.state.loadChecks();

    ND.state.refreshLastRun().then(function () {
      ND.state.refreshStatus();
    });
  }

  function apply() {
    if (!page) return;
    var S = ND.state.get();
    var running = ND.state.isRunning();

    paint(false, running);

    if (running) ND.state.acquire("home", 1500);
    else ND.state.release("home");

    /* 结果卡：数据变了才重建 */
    var sig = [
      S.last ? (S.last.epoch || S.last.time || "1") : "0",
      S.last ? (S.last.full_result ? 1 : 0) : 0,
      S.last && S.last.legacy ? 1 : 0,
      S.result ? 1 : 0,
      running ? 1 : 0
    ].join("|");
    if (page.resultSig !== sig) {
      page.resultSig = sig;
      U.clear(page.left).appendChild(lastRunCard(running));
    }

    /* 环境卡：检查结果到位后画一次，之后由「重新检测」自己更新 */
    if (!page.envDrawn && (S.checks || []).length) {
      page.envDrawn = true;
      U.clear(page.right).appendChild(ND.env.card(S.checks, {
        onRecheck: function (list) {
          if (ND.boot && ND.boot.paintChips) ND.boot.paintChips(list);
          ND.state.applyJob(ND.state.get().job);
        }
      }));
    }
  }

  /* ------------------------------------------------------------ 指标卡 */
  function paint(loading, running) {
    var host = page.kpis;
    U.clear(host);
    var S = ND.state.get();
    var last = S.last;
    var res = S.result;
    var meta = (res && res.meta) || {};
    var metrics = (res && res.metrics) || {};
    var verdict = (res && res.verdict) || {};
    var K = C.kpi || {};

    if (running) {
      /* 运行中：四个数值位置统一换成 spinner，避免旧值被当成本次结果 */
      var job = S.job || {};
      host.appendChild(R.kpi(K.health, "", K.runningSub, "", { running: true }));
      host.appendChild(R.kpi(K.latency, "", "", "", { running: true }));
      host.appendChild(R.kpi(K.loss, "", "", "", { running: true }));
      host.appendChild(R.kpi(K.session, "", "", "", { running: true }));
      U.clear(page.src);
      page.src.appendChild(U.el("b", "", (C.source.label || "") + "："));
      page.src.appendChild(document.createTextNode(
        U.tpl(C.source.running || "", {
          mode: U.modeLabel(job.mode),
          phase: job.phase || ""
        })
      ));
      return;
    }

    var level = String((verdict && verdict.level) || (last && last.level) || "");
    var legacy = !!(last && last.legacy);
    var failed = !!(last && !last.ok && !legacy);

    /* 0 包 / 样本不足时 RTT 与重传率都是 0，那是「没样本」而不是「很好」：
       一律退回「暂无数据」，避免把 0.00% 读成完美链路。 */
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

    /* 数据来源行：必须让用户知道这不是实时值 */
    U.clear(page.src);
    if (loading) {
      page.src.textContent = C.common.loading;
      return;
    }
    if (!last) {
      page.src.textContent = C.source.none;
      return;
    }
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

  function skeletonCard(title) {
    var c = R.card(title);
    c.body.appendChild(R.skeleton(3, 78));
    return c.section;
  }

  /* ------------------------------------------------------------ 最近一次结果 */
  function lastRunCard(running) {
    var S = ND.state.get();
    var last = S.last;
    var sec = R.card(C.card.lastRun);

    if (!last) {
      if (running) {
        sec.body.appendChild(R.empty("speed", C.kpi.running, C.kpi.runningSub, [
          U.btn(C.act.view, { kind: "ghost", size: "sm", onClick: function () {
            location.hash = "#/" + ((S.job && S.job.mode) || "scan");
          } })
        ]));
        return sec.section;
      }
      sec.body.appendChild(R.empty("report", C.lastRun.emptyTitle, C.lastRun.emptyBody, [startBtn()]));
      return sec.section;
    }

    sec.hd.appendChild(R.tag(
      last.legacy ? "warn" : (last.ok ? "ok" : "crit"),
      last.legacy ? C.lastRun.legacyTag : (last.ok ? C.lastRun.okTag : C.lastRun.failTag)
    ));

    if (last.legacy) {
      sec.body.appendChild(R.banner("warn", C.lastRun.legacyTitle, C.lastRun.legacyBody));
      sec.body.appendChild(legacyBody(last));
      return sec.section;
    }
    if (!last.ok) {
      sec.body.appendChild(failBody(last));
      return sec.section;
    }
    var bad = degradeInfo(S.result);
    sec.body.appendChild(bad ? degradeBody(last, bad) : okBody(last));
    return sec.section;
  }

  function startBtn() {
    var m = U.mode("scan");
    var go = U.btn((m && m.btn) || C.act.rerun, { size: "sm" });
    go.addEventListener("click", function () { location.hash = "#/scan"; });
    return go;
  }

  function whenLine(last) {
    var p = U.el("p", "result-when");
    p.appendChild(U.icon("clock", "mini"));
    p.appendChild(document.createTextNode(
      U.tpl(C.lastRun.when, {
        when: U.when(last.epoch, last.time),
        mode: U.modeLabel(last.mode),
        target: last.target ? (" · " + last.target) : ""
      })
    ));
    return p;
  }

  function counters(last) {
    return U.el("p", "result-counts", U.tpl(C.lastRun.counters, {
      critical: last.critical || 0,
      warning: last.warning || 0,
      duration: U.dur(last.duration_ms) || "—"
    }));
  }

  function okBody(last) {
    var wrap = U.el("div", "result");
    wrap.appendChild(whenLine(last));
    var main = U.el("div", "result-main");
    var v = (ND.state.get().result || {}).verdict || {};
    if (v.headline) main.appendChild(U.el("p", "result-head", v.headline));
    main.appendChild(counters(last));
    var strip = R.layerStrip(v);
    if (strip) main.appendChild(strip);
    if (!last.full_result) main.appendChild(U.el("p", "result-note", C.lastRun.summaryOnly));

    var acts = U.el("div", "result-acts");
    acts.appendChild(U.btn(C.act.view, { kind: "ghost", size: "sm", onClick: function () { summaryModal(last); } }));
    acts.appendChild(U.btn(C.act.rerun, { size: "sm", onClick: function () { goRun(last); } }));
    main.appendChild(acts);
    wrap.appendChild(main);
    return wrap;
  }

  function failBody(last) {
    var wrap = U.el("div", "result");
    wrap.appendChild(whenLine(last));
    var main = U.el("div", "result-main");
    var F = C.fail || {};
    main.appendChild(U.el("p", "result-head crit", F.title));
    main.appendChild(labeled(F.reasonLabel, F.reasonGeneric));
    main.appendChild(labeled(F.adviceLabel, F.advice));
    var acts = U.el("div", "result-acts");
    acts.appendChild(U.btn(C.act.retry, { kind: "ghost", size: "sm", onClick: function () { goRun(last); } }));
    acts.appendChild(U.btn(C.act.logs, { kind: "ghost", size: "sm", onClick: function () { location.hash = "#/logs"; } }));
    main.appendChild(acts);
    wrap.appendChild(main);
    return wrap;
  }

  function degradeBody(last, bad) {
    var wrap = U.el("div", "result");
    wrap.appendChild(whenLine(last));
    var main = U.el("div", "result-main");
    var g = C.degrade || {};
    main.appendChild(U.el("p", "result-head warn", bad.zero ? g.zeroTitle : g.title));
    main.appendChild(U.el("p", "result-counts", bad.zero
      ? g.zeroBody
      : U.tpl(g.thinBody, { packets: bad.packets })));
    main.appendChild(labeled(C.fail.adviceLabel, g.advice));
    var acts = U.el("div", "result-acts");
    acts.appendChild(U.btn(g.again, { kind: "ghost", size: "sm", onClick: function () { goRun(last); } }));
    main.appendChild(acts);
    wrap.appendChild(main);
    return wrap;
  }

  function legacyBody(last) {
    var wrap = U.el("div", "result");
    wrap.appendChild(whenLine(last));
    var main = U.el("div", "result-main");
    /* 旧记录：只有横幅 + 重新诊断；不渲染四层「未知」卡，也不给含边界导出 */
    main.appendChild(counters(last));
    var acts = U.el("div", "result-acts");
    acts.appendChild(U.btn(C.act.rerun, { size: "sm", onClick: function () { goRun(last); } }));
    main.appendChild(acts);
    wrap.appendChild(main);
    return wrap;
  }

  function labeled(label, text) {
    var p = U.el("p", "result-label");
    p.appendChild(U.el("b", "", (label || "") + "："));
    p.appendChild(document.createTextNode(text || ""));
    return p;
  }

  function goRun(last) {
    location.hash = "#/" + ((last && last.mode) || "scan");
  }

  /* 0 包 / 证据不足：有完整结果才能判定 */
  function degradeInfo(res) {
    if (!res) return null;
    var meta = res.meta || {};
    var v = res.verdict || {};
    var pk = Number(meta.packets);
    if (isFinite(pk) && pk === 0) return { zero: true, packets: 0 };
    if (v.sufficiency && v.sufficiency.ok === false) return { zero: false, packets: isFinite(pk) ? pk : 0 };
    return null;
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
