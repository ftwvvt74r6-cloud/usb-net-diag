/* ============================================================================
   home.js · 总览页：指标卡 + 三段报告（结论 / 证据 / 数据）+ 环境
   ----------------------------------------------------------------------------
   三段报告由 report.js 统一渲染，首页与五个模式页**同一套**：
   这里只负责「什么时候有报告可画」，不参与报告长什么样。

   有任务在跑时：KPI 显示「诊断中…」，报告位先摆三段骨架 —— 结构先立住，
   数字等采集结束再填（不许拿半截数据编结论）。轮询只在有任务时开。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var R = ND.render;
  var RP = C.report || {};

  var page = null;

  function cleanup() {
    if (!page) return;
    if (page.unsub) page.unsub();
    if (ND.history && ND.history.unmount) ND.history.unmount();
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

    /* 三段报告（结论 / 证据 / 数据）—— 首页与模式页同一组件 */
    var reportHost = U.el("div", "home-report");
    view.appendChild(reportHost);

    var envHost = U.el("div", "home-env");
    view.appendChild(envHost);

    /* 历史趋势：常驻采集积累的时延 / 丢包曲线（自己取数、自己重画，
       不跟着报告的刷新节奏走，否则每 1.2 秒重画一次 288 个点） */
    var histHost = U.el("div", "home-hist");
    view.appendChild(histHost);

    /* 没有诊断结果时，网络参数仍是可单独使用的表，所以给它一个独立卡片位 */
    var wifiHost = U.el("div", "home-wifi");
    view.appendChild(wifiHost);

    page = { kpis: kpis, src: src, reportHost: reportHost, histHost: histHost,
             envHost: envHost, wifiHost: wifiHost, envDrawn: false, sig: "" };

    paint(true);
    U.clear(reportHost);
    var sk = R.card(RP.title || "", { sub: RP.sub || "" });
    sk.body.appendChild(R.skeleton(4, 52));
    reportHost.appendChild(sk.section);

    if (ND.history && ND.history.mount) ND.history.mount(histHost);

    page.unsub = ND.state.subscribe(function (S, evt) {
      if (evt === "job" || evt === "last" || evt === "init" || evt === "pro") apply();
    });

    if (!(ND.state.get().checks || []).length) ND.state.loadChecks();

    ND.state.refreshLastRun().then(function () { ND.state.refreshStatus(); });
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
      /* 专业模式的控制台尾巴跟着日志走：日志变了就得重画 */
      ND.state.isPro() ? (((S.job || {}).logs || []).length) : 0
    ].join("|");
    if (page.sig === sig) return;
    page.sig = sig;

    drawReport(S, running);

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

  /* ------------------------------------------------------------ 报告位 */
  function drawReport(S, running) {
    var host = page.reportHost;
    /* 专业模式是本机偏好（state.pro），但面板只认 opts.pro：
       不显式传下去，开关就只切了状态，数据段永远按非专业渲染。 */
    var opts = {
      pro: ND.state.isPro(),
      onPro: function () { /* state 已 emit("pro")，这里不用再画 */ }
    };
    U.clear(host);
    page.wifiHost.hidden = true;

    if (running) {
      ND.report.placeholder(host, S.job, opts);
      return;
    }

    var last = S.last;
    if (!last) {
      host.appendChild(R.empty("report", C.lastRun.emptyTitle, C.lastRun.emptyBody, [startBtn()]));
      mountWifi();
      return;
    }

    /* 旧记录：没有边界也就没有证据与数据，只留横幅 + 重新诊断 */
    if (last.legacy) {
      host.appendChild(R.banner("warn", C.lastRun.legacyTitle, C.lastRun.legacyBody));
      host.appendChild(actionsRow(last));
      mountWifi();
      return;
    }

    if (!last.ok) {
      host.appendChild(failBlock(last));
      mountWifi();
      return;
    }

    var job = { result: resultOf(S, false), mode: last.mode };
    if (!job.result) {
      host.appendChild(R.banner("warn", C.lastRun.summaryOnly));
      host.appendChild(actionsRow(last));
      mountWifi();
      return;
    }
    job.conclusion = job.result.conclusion || null;
    job.report_id = job.result.report_id;
    job.link_actions = (S.job || {}).link_actions || [];   /* 复测用后端给的地址，不自己猜 */
    job.mode = (S.job && S.job.mode) || last.mode;
    /* 控制台尾巴要看采集日志：日志没带进来，专业模式开了也是空的 */
    job.logs = (S.job || {}).logs || [];

    if (!ND.report.render(host, job, opts)) {
      host.appendChild(R.banner("warn", C.result.title, C.tech.empty));
      mountWifi();
    }
  }

  /* 只有「没有报告可看」时才把网络参数单独摆出来；有报告时它在第三段里 */
  function mountWifi() {
    if (page.wifiHost.hidden) {
      page.wifiHost.hidden = false;
      if (ND.wifi && ND.wifi.mount) ND.wifi.mount(page.wifiHost);
    }
  }

  function startBtn() {
    var m = U.mode("scan");
    var go = U.btn((m && m.btn) || C.act.rerun, { size: "sm" });
    go.addEventListener("click", function () { location.hash = "#/scan"; });
    return go;
  }

  function actionsRow(last) {
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
