/* ============================================================================
   home.js · 总览页：四张指标卡 + 最近一次结果 + 环境与依赖
   ----------------------------------------------------------------------------
   数据来源只有三个接口：/api/app（应用信息 + checks）、/api/selfcheck（同一份
   检查，用于「重新检测」）、/api/last-run（上次结果摘要）。摘要里带
   full_result=true 时才去取 /api/last-run/result 补明细指标。
   任何数字缺失一律显示「暂无数据」并说明原因，绝不画一根进度条假装实时。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};

  var state = {
    app: null,
    checks: [],
    last: null,
    result: null,
    caps: null
  };

  /* ------------------------------------------------------------ 进入 */
  function render(view) {
    U.clear(view);
    state.app = null;
    state.checks = [];
    state.last = null;
    state.result = null;

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

    paintKpis(kpis, src, true);
    left.appendChild(skeletonCard(C.card.lastRun));
    right.appendChild(skeletonCard(C.card.env));

    Promise.all([ND.api.selfcheck(), ND.api.lastRun()]).then(function (r) {
      var check = r[0], last = r[1];

      /* 两份检查同源（后端同一短 TTL 缓存）：优先 selfcheck（「重新检测」也走这条），
         失败才退回启动时 /api/app 带下来的 checks —— 首页不必再单独请求一次 */
      var appChecks = (ND.appCache && ND.appCache.checks) || [];
      state.checks = (check.ok && (check.data.checks || []).length)
        ? check.data.checks
        : appChecks;

      if (last.ok) state.last = last.data ? last.data.last : null;
      if (ND.boot && ND.boot.paintChips && state.checks.length) ND.boot.paintChips(state.checks);

      if (state.last && state.last.full_result) {
        return ND.api.lastRunResult().then(function (res) {
          if (res.ok) state.result = res.data.result || null;
        });
      }
      return null;
    }).then(function () {
      paintKpis(kpis, src, false);
      U.clear(left).appendChild(lastRunCard());
      U.clear(right).appendChild(ND.env.card(state.checks, {
        onRecheck: function (list) {
          state.checks = list;
          if (ND.boot && ND.boot.paintChips) ND.boot.paintChips(list);
        }
      }));
    });
  }

  function skeletonCard(title) {
    var sec = U.el("section", "card");
    var hd = U.el("div", "card-hd");
    hd.appendChild(U.el("h2", "", title));
    sec.appendChild(hd);
    var bd = U.el("div", "card-bd");
    var box = U.el("div", "stack");
    [78, 56, 64].forEach(function (w) {
      var s = U.el("div", "sk");
      s.style.setProperty("--w", w + "%");
      box.appendChild(s);
    });
    bd.appendChild(box);
    sec.appendChild(bd);
    return sec;
  }

  /* ------------------------------------------------------------ 指标卡 */
  function paintKpis(host, srcHost, loading) {
    U.clear(host);
    var last = state.last;
    var res = state.result;
    var meta = (res && res.meta) || {};
    var metrics = (res && res.metrics) || {};
    var verdict = (res && res.verdict) || {};
    var K = C.kpi || {};

    var level = String((verdict && verdict.level) || (last && last.level) || "");
    var legacy = !!(last && last.legacy);
    var failed = !!(last && !last.ok && !legacy);

    /* 0 包 / 样本不足时 RTT 与重传率都是 0，那是「没样本」而不是「很好」：
       一律退回「暂无数据」，避免把 0.00% 读成完美链路。
       判定看三处：报文数为 0、四层结论的 sufficiency、等级是否为「无样本」。 */
    var zeroPkt = isFinite(Number(meta.packets)) && Number(meta.packets) === 0;
    var sufficiency = verdict && verdict.sufficiency;
    var thin = zeroPkt || level === (C.sev || {}).na ||
               !!(sufficiency && sufficiency.ok === false);

    var rtt = thin ? null : pick(metrics.rtt_avg_ms, meta.rtt_avg_ms, res && res.summary && res.summary.rtt_avg_ms);
    var loss = thin ? null : pick(meta.retrans_rate, res && res.summary && res.summary.retrans_rate);
    var streams = thin ? null : (meta.streams_total === undefined ? null : meta.streams_total);

    /* 每个「暂无数据」都要能自解释，四种原因不能共用一句话 */
    var why = !last ? K.noData
      : failed ? K.failed
      : thin ? K.thin
      : K.summaryOnly;

    host.appendChild(kpi(K.health, level,
      level ? (legacy ? K.healthSubLegacy : K.healthSub) : why, kindOfLevel(level), loading));
    host.appendChild(kpi(K.latency, rtt === null ? "" : U.num(rtt, 1) + " ms",
      rtt === null ? why : K.latencySub, "", loading));
    host.appendChild(kpi(K.loss, loss === null ? "" : U.num(loss, 2) + "%",
      loss === null ? why : K.lossSub, "", loading));
    host.appendChild(kpi(K.session, streams === null ? "" : U.num(streams, 0),
      streams === null ? why : K.sessionSub, "", loading));

    /* 数据来源行：必须让用户知道这不是实时值 */
    U.clear(srcHost);
    if (loading) {
      srcHost.textContent = C.common.loading;
      return;
    }
    if (!last) {
      srcHost.textContent = C.source.none;
      return;
    }
    srcHost.appendChild(U.el("b", "", C.source.label + "："));
    var tail = last.target ? (" · " + last.target) : "";
    var packets = meta.packets;
    srcHost.appendChild(document.createTextNode(
      packets === undefined || packets === null
        ? U.tpl(C.source.summary, { when: U.when(last.epoch, last.time), mode: U.modeLabel(last.mode), target: tail })
        : U.tpl(C.source.line, {
            when: U.when(last.epoch, last.time), mode: U.modeLabel(last.mode), target: tail,
            packets: U.num(packets, 0)
          })
    ));
  }

  function naText() { return C.common.na; }

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

  function kpi(label, value, sub, kind, loading) {
    var wrap = U.el("div", "kpi");
    wrap.appendChild(U.el("dt", "", label));
    var v = U.el("dd", "kpi-v" + (kind ? " " + kind : "") + (value ? "" : " na"));
    v.textContent = value || (loading ? "" : naText());
    wrap.appendChild(v);
    wrap.appendChild(U.el("dd", "kpi-sub", loading ? "" : (sub || "")));
    return wrap;
  }

  /* ------------------------------------------------------------ 最近一次结果 */
  function lastRunCard() {
    var last = state.last;
    var sec = U.el("section", "card lastcard");
    var hd = U.el("div", "card-hd");
    hd.appendChild(U.el("h2", "", C.card.lastRun));

    if (!last) {
      sec.appendChild(hd);
      sec.appendChild(U.el("div", "card-bd")).appendChild(emptyState());
      return sec;
    }

    var tag = U.el("span", "tag " + (last.legacy ? "warn" : (last.ok ? "ok" : "crit")),
      last.legacy ? C.lastRun.legacyTag : (last.ok ? C.lastRun.okTag : C.lastRun.failTag));
    hd.appendChild(tag);
    sec.appendChild(hd);

    var bd = U.el("div", "card-bd");
    sec.appendChild(bd);

    if (last.legacy) {
      bd.appendChild(legacyBanner());
      bd.appendChild(bodyOf(last, "legacy"));
      return sec;
    }
    if (!last.ok) {
      bd.appendChild(bodyOf(last, "fail"));
      return sec;
    }
    var bad = degradeInfo();
    if (bad) {
      bd.appendChild(bodyOf(last, "degrade", bad));
      return sec;
    }
    bd.appendChild(bodyOf(last, "ok"));
    return sec;
  }

  function emptyState() {
    var box = U.el("div", "empty");
    box.appendChild(U.icon("report"));
    box.appendChild(U.el("b", "", C.lastRun.emptyTitle));
    box.appendChild(U.el("p", "", C.lastRun.emptyBody));
    var m = U.mode("scan");
    if (m) {
      var go = U.btn(m.btn || C.act.rerun, { size: "sm" });
      go.addEventListener("click", function () { location.hash = "#/scan"; });
      box.appendChild(go);
    }
    return box;
  }

  function legacyBanner() {
    var b = U.el("div", "banner warn");
    b.appendChild(U.icon("alert", "banner-ic"));
    var main = U.el("div", "banner-main");
    main.appendChild(U.el("b", "", C.lastRun.legacyTitle));
    main.appendChild(U.el("p", "", C.lastRun.legacyBody));
    b.appendChild(main);
    return b;
  }

  /* 四种结果态的正文：摘要头部共用，右侧动作按状态给 */
  function bodyOf(last, kind, extra) {
    var wrap = U.el("div", "result");

    var head = U.el("div", "result-hd");
    var when = U.el("p", "result-when");
    when.appendChild(U.icon("clock", "mini"));
    when.appendChild(document.createTextNode(
      U.tpl(C.lastRun.when, {
        when: U.when(last.epoch, last.time),
        mode: U.modeLabel(last.mode),
        target: last.target ? (" · " + last.target) : ""
      })
    ));
    head.appendChild(when);
    wrap.appendChild(head);

    var main = U.el("div", "result-main");
    var acts = U.el("div", "result-acts");

    if (kind === "ok") {
      var v = (state.result && state.result.verdict) || {};
      if (v.headline) main.appendChild(U.el("p", "result-head", v.headline));
      var counts = U.el("p", "result-counts", U.tpl(C.lastRun.counters, {
        critical: last.critical || 0,
        warning: last.warning || 0,
        duration: U.dur(last.duration_ms) || "—"
      }));
      main.appendChild(counts);
      var strip = layerStrip(v);
      if (strip) main.appendChild(strip);
      if (!last.full_result) main.appendChild(U.el("p", "result-note", C.lastRun.summaryOnly));

      acts.appendChild(U.btn(C.act.view, { kind: "ghost", size: "sm", onClick: function () { summaryModal(last); } }));
      acts.appendChild(rerunBtn(last));
    } else if (kind === "fail") {
      var f = C.fail || {};
      var r = state.result || {};
      main.appendChild(U.el("p", "result-head crit", f.title));
      var reason = r.error || f.reasonGeneric;
      main.appendChild(labeled(f.reasonLabel, reason));
      main.appendChild(labeled(f.adviceLabel, f.advice));
      acts.appendChild(U.btn(C.act.retry, { kind: "ghost", size: "sm", onClick: function () { goRun(last); } }));
      acts.appendChild(U.btn(C.act.logs, { kind: "ghost", size: "sm", onClick: function () { location.hash = "#/logs"; } }));
    } else if (kind === "degrade") {
      var g = C.degrade || {};
      main.appendChild(U.el("p", "result-head warn", extra.zero ? g.zeroTitle : g.title));
      main.appendChild(U.el("p", "result-counts", extra.zero
        ? g.zeroBody
        : U.tpl(g.thinBody, { packets: extra.packets })));
      main.appendChild(labeled(C.fail.adviceLabel, g.advice));
      acts.appendChild(U.btn(g.again, { kind: "ghost", size: "sm", onClick: function () { goRun(last); } }));
    } else {
      /* legacy：只有横幅 + 重新诊断，不渲染四层「未知」卡，也不给含边界的导出 */
      main.appendChild(U.el("p", "result-counts", U.tpl(C.lastRun.counters, {
        critical: last.critical || 0,
        warning: last.warning || 0,
        duration: U.dur(last.duration_ms) || "—"
      })));
      acts.appendChild(rerunBtn(last));
    }

    if (acts.childNodes.length) main.appendChild(acts);
    wrap.appendChild(main);
    return wrap;
  }

  /* 四层状态条：只是「哪一层有话说」的索引，完整结论与边界在结果页。
     status: ok / warn / bad（core/analyzer.py 的 layers[*].status） */
  function layerStrip(v) {
    if (!v || !v.layers || !v.layers.length) return null;
    var box = U.el("div", "layers");
    v.layers.forEach(function (l) {
      var kind = l.status === "ok" ? "ok" : (l.status === "warn" ? "warn" : "crit");
      var c = U.chip(kind, String(l.id || "") + (l.name ? " " + l.name : ""));
      var tip = [l.protocol, l.severity, l.detail].filter(Boolean).join(" · ");
      if (tip) c.title = tip;
      box.appendChild(c);
    });
    return box;
  }

  function labeled(label, text) {
    var p = U.el("p", "result-label");
    p.appendChild(U.el("b", "", label + "："));
    p.appendChild(document.createTextNode(text));
    return p;
  }

  function rerunBtn(last) {
    return U.btn(C.act.rerun, { size: "sm", onClick: function () { goRun(last); } });
  }

  function goRun(last) {
    var id = (last && last.mode) || "scan";
    location.hash = "#/" + id;
  }

  /* 0 包 / 证据不足：有完整结果才能判定，只有摘要时按正常摘要展示 */
  function degradeInfo() {
    var r = state.result;
    if (!r) return null;
    var meta = r.meta || {};
    var v = r.verdict || {};
    var pk = Number(meta.packets);
    if (packetsZero(pk)) return { zero: true, packets: 0 };
    var suf = v.sufficiency;
    if (v.level === (C.sev || {}).na) return { zero: pk === 0, packets: pk };
    if (suf && suf.ok === false) return { zero: false, packets: pk };
    return null;
  }

  function packetsZero(pk) { return isFinite(pk) && pk === 0; }

  /* ------------------------------------------------------------ 摘要弹窗 */
  function summaryModal(last) {
    var body = document.createDocumentFragment();
    var rows = [
      [C.lastRun.rowWhen, U.when(last.epoch, last.time)],
      [C.lastRun.rowMode, U.modeLabel(last.mode)],
      [C.lastRun.rowTarget, last.target || "—"],
      [C.lastRun.rowLevel, String(last.level || naText())],
      [C.lastRun.rowCritical, String(last.critical || 0)],
      [C.lastRun.rowWarning, String(last.warning || 0)],
      [C.lastRun.rowDuration, U.dur(last.duration_ms) || "—"]
    ];

    var dl = U.el("dl", "kv");
    rows.forEach(function (r) {
      var row = U.el("div", "kv-row");
      row.appendChild(U.el("dt", "", r[0]));
      row.appendChild(U.el("dd", "", r[1]));
      dl.appendChild(row);
    });
    body.appendChild(dl);
    body.appendChild(U.el("p", "muted",
      last.full_result ? C.lastRun.summaryKept : C.lastRun.summaryGone));

    var close = U.btn(C.act.close, { kind: "ghost" });
    var box = U.modal({ title: C.lastRun.summaryTitle, body: body, actions: [close] });
    close.addEventListener("click", function () { box.close(); });
  }

  ND.home = { render: render };
})(window.ND = window.ND || {});
