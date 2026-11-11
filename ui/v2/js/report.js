/* ============================================================================
   report.js · 结果区的固定三段：① 定性结论 ② 证据 ③ 数据
   ----------------------------------------------------------------------------
   首页与五个模式页**共用这一个组件**（不再各画一套）。三段都默认展开：

     ① 定性结论  横幅（结论 + 影响范围）+ 一行边界 + 处置步骤 + 责任归属
     ② 证据      3~6 条证据（层级/现象/关键数值/判定）+ 关键指标表（带阈值色）
     ③ 数据      专业统计（传输质量 / Top 会话 / 应用层分布 / DNS）+ 网络参数表

   只有「更深一层」的东西才折进「展开明细」：探针基线、路径剖面、抓包命令与 BPF、
   统计口径、后端结论原文。关键指标表与网络参数表**不进折叠**——它们属于正文。

   阈值色：正常青绿 / 关注琥珀 / 异常红，全表最多 3 处「关注/异常」标记
   （专业面板十几个数字，全染色等于没染色）。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var RP = C.report || {};
  var V = C.verdict || {};
  var SEV = C.sev || {};

  var MAX_EV = 6;

  function n(v) {
    if (v === null || v === undefined || v === "") return null;
    var x = Number(v);
    return isFinite(x) ? x : null;
  }

  function num(v, d) {
    var x = n(v);
    return x === null ? null : x.toFixed(d === undefined ? 0 : d);
  }

  /* ------------------------------------------------------------ 入口 */
  /* host 是容器；job 形如 {result, conclusion, report_id, link_actions, mode, logs, state}
     opts: { pro, onPro } —— onPro 给了才画「专业模式」开关 */
  function render(host, job, opts) {
    opts = opts || {};
    U.clear(host);
    var res = (job && job.result) || null;
    if (!res) return null;

    var model = ND.verdict.build(job);
    if (!model) return null;

    var root = shell(opts);
    model.el = root;
    root.appendChild(secConcl(job, model, opts));
    root.appendChild(secEvidence(job, model, res, opts));
    root.appendChild(secData(job, model, res, opts));
    root.appendChild(foldDetail(job, model));
    host.appendChild(root);
    return root;
  }

  /* 运行中：三段先摆出来，让用户知道「等的是这三块」 */
  function placeholder(host, job, opts) {
    opts = opts || {};
    U.clear(host);
    var root = shell(opts);
    [RP.sec1, RP.sec2, RP.sec3].forEach(function (name, i) {
      var s = section(i + 1, name, [RP.sec1sub, RP.sec2sub, RP.sec3sub][i], U.el("div", "rpt-ph"));
      s.appendChild(U.el("p", "rpt-ph-t", RP.running || ""));
      s.appendChild(ND.render.skeleton(3, 46));
      root.appendChild(s);
    });
    if (RP.runningBody) {
      var meta = U.el("p", "rpt-note");
      meta.textContent = U.tpl(RP.runningBody, {
        phase: (job && job.phase) || "", elapsed: num(job && job.elapsed, 0) || "0",
        lines: ((job && job.logs) || []).length
      });
      root.appendChild(meta);
    }
    host.appendChild(root);
    return root;
  }

  function shell(opts) {
    var root = U.el("section", "card rpt");
    var hd = U.el("div", "card-hd");
    hd.appendChild(U.el("h2", "", RP.title || ""));
    hd.appendChild(U.el("span", "card-sub", RP.sub || ""));

    var sw = U.el("label", "pro-sw");
    var cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = !!(ND.state && ND.state.isPro && ND.state.isPro());
    cb.setAttribute("aria-label", RP.pro || "");
    cb.addEventListener("change", function () {
      if (ND.state && ND.state.setPro) ND.state.setPro(cb.checked);
      if (opts.onPro) opts.onPro(cb.checked);
    });
    sw.appendChild(cb);
    sw.appendChild(U.el("span", "pro-sw-t", RP.pro || ""));
    sw.title = RP.proHint || "";
    hd.appendChild(sw);

    root.appendChild(hd);
    root.appendChild(U.el("div", "rpt-bd"));
    return root;
  }

  function section(no, name, sub, body) {
    var sec = U.el("section", "rpt-sec");
    var hd = U.el("div", "rpt-h");
    hd.appendChild(U.el("span", "rpt-no", String(no)));
    hd.appendChild(U.el("h3", "", name || ""));
    if (sub) hd.appendChild(U.el("span", "rpt-sub", sub));
    sec.appendChild(hd);
    var bd = U.el("div", "rpt-body");
    if (body) bd.appendChild(body);
    sec.appendChild(bd);
    return sec;
  }

  /* ------------------------------------------------------------ ① 定性结论 */
  function secConcl(job, model, opts) {
    var box = U.el("div", "rpt-c1");
    box.appendChild(ND.verdict.head(job, model));
    var st = ND.verdict.steps(job, model);
    if (st) box.appendChild(st);
    box.appendChild(ND.verdict.owner(job, model));
    box.appendChild(ND.verdict.footer(job, model));
    return section(1, RP.sec1, RP.sec1sub, box);
  }

  /* ------------------------------------------------------------ ② 证据 */
  function secEvidence(job, model, res, opts) { /* jshint ignore:line */
    var box = U.el("div", "rpt-c2");

    /* 证据条目：层级 / 现象 / 关键数值 / 判定 */
    var items = evItems(res);
    var h1 = U.el("div", "rpt-h4");
    h1.appendChild(U.el("h4", "", RP.evTitle || ""));
    /* 0 条时不写「0 条」——那读起来像「没证据」，其实是「没有越线的条目」 */
    if (items.length) h1.appendChild(U.el("span", "rpt-dim", U.tpl(RP.evCount || "", { n: items.length })));
    box.appendChild(h1);

    if (!items.length) {
      box.appendChild(U.el("p", "muted", RP.evEmpty || ""));
    } else {
      box.appendChild(evTable(items));
    }

    /* 关键指标表：与导出文件同一份取数（metricstable.js），不在这里再写一遍 */
    var h2 = U.el("div", "rpt-h4");
    h2.appendChild(U.el("h4", "", RP.metricsTitle || ""));
    h2.appendChild(U.el("span", "rpt-dim", RP.metricsSub || ""));
    box.appendChild(h2);
    box.appendChild(ND.metrics.table(res));
    box.appendChild(U.el("p", "rpt-note", RP.metricsNote || ""));
    return section(2, RP.sec2, RP.sec2sub, box);
  }

  /* rows 优先（finding/evidence），没有就退到 verdict.points（title/proof） */
  function evItems(res) {
    var rows = (res.rows || []).filter(function (x) { return x && (x.finding || x.title); });
    var list = rows.length ? rows
      : ((res.verdict || {}).points || []).filter(function (x) { return x && (x.title || x.finding); });
    var out = list.map(function (x) {
      var layer = [x.layer, x.protocol].filter(function (s) {
        return s && String(s).trim() && String(s).trim() !== "—";
      }).join(" · ");
      return {
        layer: layer,
        what: x.finding || x.title || "",
        num: x.evidence || x.proof || "",
        sev: x.severity || ""
      };
    });
    /* 严重的排前面：第二段第一眼该看到的是「最要紧的那几条」 */
    var rank = function (s) { return s === SEV.critical ? 0 : (s === SEV.warning ? 1 : 2); };
    out.sort(function (a, b) { return rank(a.sev) - rank(b.sev); });
    return out.slice(0, MAX_EV);
  }

  function evTable(items) {
    var tbl = U.el("table", "evi-table");
    var thead = document.createElement("thead");
    var hr = document.createElement("tr");
    [RP.evLayer, RP.evWhat, RP.evNum, RP.evJudge].forEach(function (t) {
      hr.appendChild(U.el("th", "", t || ""));
    });
    thead.appendChild(hr);
    tbl.appendChild(thead);

    var tb = document.createElement("tbody");
    items.forEach(function (it) {
      var tr = document.createElement("tr");
      tr.appendChild(U.el("td", "evi-lv", it.layer || "—"));
      tr.appendChild(U.el("td", "evi-what", it.what));
      tr.appendChild(U.el("td", "evi-num mono", it.num || "—"));
      var td = U.el("td", "evi-judge");
      if (it.sev && it.sev !== "—") td.appendChild(U.chip(ND.render.sevKind(it.sev), it.sev));
      else td.textContent = "—";
      tr.appendChild(td);
      tb.appendChild(tr);
    });
    tbl.appendChild(tb);
    return tbl;
  }

  /* ------------------------------------------------------------ ③ 数据 */
  function secData(job, model, res, opts) {
    var box = U.el("div", "rpt-c3");
    var pro = !!(opts && opts.pro);
    var b = ND.panel.blocks(res, { pro: pro, job: job });
    var m = b.model;

    /* 网络参数：无线链路 + 主机网关（与诊断结果无关，任何时候都在）。
       它属于数据段的一栏，不是独立卡片 —— 首页卡片数不因此增加。 */
    var net = U.el("div", "dp-col dp-net");
    var nh = U.el("div", "rpt-h4");
    nh.appendChild(U.el("h4", "", RP.netTitle || ""));
    nh.appendChild(U.el("span", "rpt-dim", RP.netSub || ""));
    net.appendChild(nh);
    net.appendChild(U.el("div", "np-embed"));

    if (!b.has) {
      box.appendChild(U.el("p", "muted", (C.panel || {}).empty || ""));
      box.appendChild(net);
    } else {
      /* 概览一行：给下面所有数字一个上下文（多少报文、多长时间） */
      var metaRow = U.el("p", "dp-meta");
      metaRow.textContent = [
        (C.panel || {}).ovPackets + " " + num(m.packets, 0),
        (C.panel || {}).ovStreams + " " + num(m.streams, 0),
        (C.panel || {}).ovDuration + " " + (num(m.duration, 0) || "—") + ((C.unit || {}).sec || "")
      ].join("　·　");
      box.appendChild(metaRow);

      /* 数据段主体左右两栏：左栏专业面板，右栏网络参数 */
      var grid = U.el("div", "dp-grid");

      var left = U.el("div", "dp-col");
      if (b.quality) left.appendChild(b.quality);
      if (b.dns) left.appendChild(b.dns);
      if (b.l7) left.appendChild(b.l7);
      if (left.firstChild) grid.appendChild(left);
      grid.appendChild(net);
      box.appendChild(grid);

      /* 通栏块：会话明细最宽，留到最后仍然通栏 */
      if (b.sessions) box.appendChild(b.sessions);
      if (b.extra) box.appendChild(b.extra);
      if (b.logs) box.appendChild(b.logs);
    }

    if (ND.wifi && ND.wifi.embed) ND.wifi.embed(net.querySelector(".np-embed"));

    return section(3, RP.sec3, RP.sec3sub, box);
  }

  /* ------------------------------------------------------------ 明细（折叠） */
  function foldDetail(job, model) {
    var det = document.createElement("details");
    det.className = "rpt-detail";
    var sum = document.createElement("summary");
    sum.appendChild(U.el("span", "rd-t", RP.detail || ""));
    sum.appendChild(U.el("span", "rd-s", RP.detailSub || ""));
    det.appendChild(sum);
    det.appendChild(ND.render.detail(job, model));
    return det;
  }

  /* ------------------------------------------------------------ 连通与速度测试 */
  /* 它不是抓包诊断，没有 rows/verdict/meta，但结果区必须与其余模式同一套三段：
     ① 结论（可达性判定 + 建议）② 证据（分阶段耗时）③ 数据（逐跳路径）。 */
  function renderProbe(host, d) {
    d = d || {};
    U.clear(host);
    var root = U.el("section", "card rpt");
    var hd = U.el("div", "card-hd");
    hd.appendChild(U.el("h2", "", RP.title || ""));
    hd.appendChild(U.el("span", "card-sub", RP.sub || ""));
    root.appendChild(hd);

    /* ① 结论 */
    var c1 = U.el("div", "rpt-c1");
    var ban = U.el("div", "v-banner " + (d.ok ? "ok" : "crit"));
    var top = U.el("div", "v-b-top");
    top.appendChild(U.el("span", "v-kicker", RP.sec1 || ""));
    ban.appendChild(top);
    ban.appendChild(U.el("h2", "v-title", d.headline || ""));
    if (d.advice) {
      var p = U.el("p", "v-problem");
      p.textContent = String(d.advice);
      ban.appendChild(p);
    }
    c1.appendChild(ban);
    root.appendChild(section(1, RP.sec1, RP.sec1sub, c1));

    /* ② 证据：分阶段耗时 */
    var c2 = U.el("div", "rpt-c2");
    var segs = d.segments || [];
    if (segs.length) {
      var tbl = U.el("table", "evi-table");
      var thead = document.createElement("thead");
      var hr = document.createElement("tr");
      ["阶段", RP.evNum, RP.evJudge].forEach(function (t) { hr.appendChild(U.el("th", "", t)); });
      thead.appendChild(hr);
      tbl.appendChild(thead);
      var tb = document.createElement("tbody");
      segs.forEach(function (sg) {
        var tr = document.createElement("tr");
        tr.appendChild(U.el("td", "evi-lv", sg.name || ""));
        tr.appendChild(U.el("td", "evi-num mono",
          sg.ms === null || sg.ms === undefined ? "—" : Number(sg.ms).toFixed(1) + " ms"));
        var td = U.el("td", "evi-judge");
        td.appendChild(U.el("i", "mt-dot " + (sg.status === "ok" ? "ok" : (sg.status === "warn" ? "warn" : "crit"))));
        td.appendChild(U.el("span", "", sg.status === "ok" ? (RP.stOk || "") : (sg.status === "warn" ? (RP.stWarn || "") : (RP.stCrit || ""))));
        tr.appendChild(td);
        if (sg.note) tr.title = sg.note;
        tb.appendChild(tr);
      });
      tbl.appendChild(tb);
      c2.appendChild(tbl);
    } else {
      c2.appendChild(U.el("p", "muted", RP.evEmpty || ""));
    }
    root.appendChild(section(2, RP.sec2, RP.sec2sub, c2));

    /* ③ 数据：逐跳路径 + 网络参数表（与抓包类模式一致，模式页也带这块） */
    var c3 = U.el("div", "rpt-c3");
    var pp = d.path_profile;
    if (pp && (pp.hops || []).length) {
      var h = U.el("div", "rpt-h4");
      h.appendChild(U.el("h4", "", RP.dataPath || RP.dataPanels || ""));
      c3.appendChild(h);
      c3.appendChild(ND.render.hopTable(pp));
    } else {
      c3.appendChild(U.el("p", "muted", (C.panel || {}).noData || "—"));
    }

    var nh = U.el("div", "rpt-h4");
    nh.appendChild(U.el("h4", "", RP.netTitle || ""));
    nh.appendChild(U.el("span", "rpt-dim", RP.netSub || ""));
    c3.appendChild(nh);
    var npHost = U.el("div", "np-embed");
    c3.appendChild(npHost);
    if (ND.wifi && ND.wifi.embed) ND.wifi.embed(npHost);

    root.appendChild(section(3, RP.sec3, RP.sec3sub, c3));

    host.appendChild(root);
    return root;
  }

  ND.report = { render: render, placeholder: placeholder, renderProbe: renderProbe };
})(window.ND = window.ND || {});
