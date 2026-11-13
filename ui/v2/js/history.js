/* ============================================================================
   history.js · 首页「历史趋势」卡
   ----------------------------------------------------------------------------
   回答一个问题：**这段时间网络稳不稳**。不回答「现在为什么慢」——那是报告的事。

   图表三件事，不多不少：
     · 折线  RTT（本机到监测目标的往返时延）
     · 虚线  阈值（/api/monitor 的 rtt_ms，没读到就用 120 ms）
     · 色块  丢包（贴底一条带，高度按该点丢包率，没有丢包的时段是空的）

   事件用竖线标在时间轴上，点一下在图下列出这条事件的细节（目标 / 实测 / 阈值 /
   持续多久 / 当时的 AP 与 RSSI）—— 相关性靠这三个字段才连得起来。

   接口没就绪（404）或没有采样点时，一律显示「采集未开启」引导，**不画一条
   贴底的 0 线**：那是「测了但很好」，和「没测」是两件事。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var H = C.history || {};

  var NS = "http://www.w3.org/2000/svg";

  var RANGES = [
    { id: "1h", sec: 3600, bucket: "1m" },
    { id: "24h", sec: 86400, bucket: "5m" },
    { id: "7d", sec: 604800, bucket: "1h" }
  ];

  var DEFAULT_THR = 120;

  var state = {
    host: null,
    el: null,
    range: "24h",
    series: [],
    marks: [],
    events: [],
    coverage: null,
    thr: DEFAULT_THR,
    absent: false,
    loading: false,
    seq: 0,
    sel: null
  };

  /* ------------------------------------------------------------ 小工具 */
  function n(v) {
    if (v === null || v === undefined || v === "") return null;
    var x = Number(v);
    return isFinite(x) ? x : null;
  }

  function rangeOf(id) {
    for (var i = 0; i < RANGES.length; i++) if (RANGES[i].id === id) return RANGES[i];
    return RANGES[1];
  }

  function pad2(x) { return x < 10 ? "0" + x : String(x); }

  function hhmm(t) {
    var d = new Date(t * 1000);
    return pad2(d.getHours()) + ":" + pad2(d.getMinutes());
  }

  function mmdd(t) {
    var d = new Date(t * 1000);
    return pad2(d.getMonth() + 1) + "-" + pad2(d.getDate());
  }

  function stamp(t) {
    return mmdd(t) + " " + hhmm(t);
  }

  function durSec(s) {
    var v = n(s);
    if (v === null || v <= 0) return "—";
    if (v < 60) return Math.round(v) + ((C.unit || {}).sec || " 秒");
    if (v < 3600) return Math.round(v / 60) + ((C.unit || {}).min || " 分钟");
    var h = v / 3600;
    return (h % 1 === 0 ? String(h) : h.toFixed(1)) + ((C.unit || {}).hour || " 小时");
  }

  function svg(tag, cls, attrs) {
    var e = document.createElementNS(NS, tag);
    if (cls) e.setAttribute("class", cls);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    return e;
  }

  /* 纵轴取整到 1/2/5 × 10^n，标签才不会是 137.4 这种 */
  function niceMax(v) {
    if (!(v > 0)) return 10;
    var exp = Math.pow(10, Math.floor(Math.log(v) / Math.LN10));
    var base = v / exp;
    var step = base <= 1 ? 1 : base <= 2 ? 2 : base <= 5 ? 5 : 10;
    return step * exp;
  }

  /* ------------------------------------------------------------ 挂载 */
  function mount(host) {
    if (!host) return;
    state.host = host;
    U.clear(host);

    var card = U.el("section", "card hist");
    var hd = U.el("div", "card-hd");
    hd.appendChild(U.el("h2", "", H.title || ""));
    hd.appendChild(U.el("span", "card-sub", H.sub || ""));

    var ctrl = U.el("div", "hist-ctrl");
    var seg = U.el("div", "seg hist-seg");
    seg.setAttribute("role", "group");
    seg.setAttribute("aria-label", H.title || "");
    RANGES.forEach(function (r) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "seg-b";
      b.setAttribute("data-range", r.id);
      b.textContent = H["r" + r.id] || r.id;
      b.addEventListener("click", function () {
        if (state.range === r.id) return;
        state.range = r.id;
        state.sel = null;
        paintSeg();
        load();
      });
      seg.appendChild(b);
    });
    ctrl.appendChild(seg);

    var btnMark = U.btn(H.mark || "", { kind: "ghost", size: "sm", onClick: markNow });
    var btnCsv = U.btn(H.exportCsv || "", {
      kind: "ghost", size: "sm", icon: "download",
      onClick: function () { exportFile("csv"); }
    });
    var btnMd = U.btn(H.exportMd || "", {
      kind: "ghost", size: "sm", icon: "download",
      onClick: function () { exportFile("md"); }
    });
    ctrl.appendChild(btnMark);
    ctrl.appendChild(btnCsv);
    ctrl.appendChild(btnMd);
    hd.appendChild(ctrl);
    card.appendChild(hd);

    var bd = U.el("div", "card-bd");
    var chart = U.el("div", "hist-chart");
    var detail = U.el("div", "hist-detail");
    var events = U.el("div", "hist-events");
    bd.appendChild(chart);
    bd.appendChild(detail);
    bd.appendChild(events);
    bd.appendChild(U.el("p", "hist-note", H.note || ""));
    card.appendChild(bd);

    host.appendChild(card);
    state.el = { card: card, chart: chart, detail: detail, events: events,
                 btns: [btnMark, btnCsv, btnMd] };

    paintSeg();
    load();

    /* 宽度变化重画（A5）：容器自己变宽/变窄时 window.resize 不一定触发
       （断点切换、CDP 改视口、侧栏折叠都只改容器宽度），用 ResizeObserver 盯 chart。
       lastChartW 只记上一次实际画过的宽度，避免首屏与抖动重复重画；
       drawChart 里的 U.clear(box) 会清掉旧 SVG，旧尺寸不会残留。 */
    lastChartW = 0;
    if (window.ResizeObserver && chart) {
      chartRO = new ResizeObserver(function (entries) {
        var w = Math.floor((entries[0] && entries[0].contentRect.width) || 0);
        if (!w || !state.el || !state.series.length) return;
        if (w === lastChartW) return;
        lastChartW = w;
        drawChart();
      });
      chartRO.observe(chart);
    } else {
      window.addEventListener("resize", onResize);
    }
  }

  function unmount() {
    if (chartRO) { chartRO.disconnect(); chartRO = null; }
    lastChartW = 0;              /* 清旧尺寸：下次挂载必须按新容器重算 */
    if (rt) { clearTimeout(rt); rt = 0; }
    window.removeEventListener("resize", onResize);
    state.host = null;
    state.el = null;
    state.seq++;
  }

  var chartRO = null;
  var lastChartW = 0;
  var rt = 0;
  function onResize() {
    if (rt) clearTimeout(rt);
    rt = setTimeout(function () {
      rt = 0;
      if (state.el && state.series.length) drawChart();
    }, 150);
  }

  function paintSeg() {
    if (!state.el) return;
    var list = state.el.card.querySelectorAll(".hist-seg .seg-b");
    for (var i = 0; i < list.length; i++) {
      var on = list[i].getAttribute("data-range") === state.range;
      list[i].classList.toggle("on", on);
      list[i].setAttribute("aria-pressed", on ? "true" : "false");
    }
  }

  /* ------------------------------------------------------------ 取数 */
  function windowOf() {
    var r = rangeOf(state.range);
    /* 取上取整，不用 floor：标记/事件的 epoch 带毫秒，刚打完标记立刻重查时
       floor 会把 to 截到「这一秒的 0.000」，比标记还早 —— 后端按 [from,to]
       闭区间过滤，刚建的那条就被当成「超出区间」丢掉，界面上什么也不会变。
       上取整让当前这一秒算在窗口内，最多多查 1 秒（这一秒本来就没数据）。 */
    var to = Math.ceil(Date.now() / 1000);
    return { r: r, to: to, from: to - r.sec, q: "from=" + (to - r.sec) + "&to=" + to + "&bucket=" + r.bucket };
  }

  function load() {
    var w = windowOf();
    var seq = ++state.seq;
    state.loading = true;
    state.absent = false;
    if (!state.series.length) paintBusy();

    /* 阈值只用来画那条虚线：读不到就用默认值，不因此判定「无数据」 */
    var thrP = ND.api.monitor().then(function (res) {
      var t = res && res.ok && res.data && res.data.thresholds ? n(res.data.thresholds.rtt_ms) : null;
      return t === null ? localThr() : t;
    }).catch(function () { return localThr(); });

    Promise.all([ND.api.history(w.q), ND.api.historyEvents("from=" + w.from + "&to=" + w.to), thrP])
      .then(function (all) {
        if (seq !== state.seq) return;          /* 切了范围，这批结果作废 */
        var hist = all[0] || {};
        var ev = all[1] || {};
        state.thr = all[2] || DEFAULT_THR;
        state.loading = false;

        if (!hist.ok) {
          state.absent = ND.api.absent(hist);
          state.series = [];
          state.events = [];
          state.marks = [];
          paint();
          return;
        }
        var d = hist.data || {};
        state.absent = false;
        state.series = (d.series || []).filter(function (s) { return s && n(s.t) !== null; })
          .sort(function (a, b) { return a.t - b.t; });
        state.marks = d.marks || [];
        state.coverage = d.coverage || null;
        state.events = (ev && ev.ok && (ev.data || {}).events) ? ev.data.events : [];
        paint();
      });
  }

  function localThr() {
    try {
      var o = JSON.parse(localStorage.getItem("nd_monitor") || "{}");
      var v = o && o.thresholds ? n(o.thresholds.rtt_ms) : null;
      return v === null ? DEFAULT_THR : v;
    } catch (e) { return DEFAULT_THR; }
  }

  /* ------------------------------------------------------------ 绘制 */
  function paintBusy() {
    if (!state.el) return;
    U.clear(state.el.chart).appendChild(U.el("p", "muted hist-loading", H.loading || ""));
    U.clear(state.el.events);
    U.clear(state.el.detail);
  }

  function paint() {
    if (!state.el) return;
    U.clear(state.el.detail);
    state.sel = null;
    /* 采集都没开，标记与导出点了只会弹错误：直接禁用，别让人白点 */
    (state.el.btns || []).forEach(function (b) { b.disabled = state.absent; });

    if (state.absent) return paintOff();
    if (!state.series.length) return paintEmpty();

    drawChart();
    drawEvents();
  }

  /* 「采集未开启」：说明 + 一个去设置的入口。不画空图，也不写 0 */
  function paintOff() {
    U.clear(state.el.chart);
    U.clear(state.el.events);
    var box = U.el("div", "hist-off");
    box.appendChild(U.el("b", "", H.offTitle || ""));
    box.appendChild(U.el("p", "", H.offBody || ""));
    box.appendChild(U.btn(H.offGo || "", {
      kind: "ghost", size: "sm",
      onClick: function () { location.hash = "#/settings"; }
    }));
    state.el.chart.appendChild(box);
  }

  function paintEmpty() {
    U.clear(state.el.chart);
    U.clear(state.el.events);
    var box = U.el("div", "hist-off");
    box.appendChild(U.el("b", "", H.emptyTitle || ""));
    box.appendChild(U.el("p", "", H.emptyBody || ""));
    state.el.chart.appendChild(box);
  }

  function drawChart() {
    var box = state.el.chart;
    U.clear(box);

    var W = Math.max(320, Math.floor(box.clientWidth || (box.parentNode && box.parentNode.clientWidth) || 640));
    var PH = 150, L = 46, R = 16, T = 14, B = 22;
    var HH = T + PH + B;
    var series = state.series;

    var t0 = series[0].t;
    var t1 = series[series.length - 1].t;
    /* 横轴不能只取数据首尾：桶的 t 是**桶起点**，所以「此刻」打的标记与刚触发
       的事件（时刻 >= 当前桶起点）永远落在 t1 右边，被当成超出范围丢掉 ——
       越是刚发生的越看不见。把标记/事件也算进定义域。 */
    (state.marks || []).forEach(function (m) {
      var t = n(m && m.t);
      if (t === null) return;
      if (t < t0) t0 = t;
      if (t > t1) t1 = t;
    });
    (state.events || []).forEach(function (ev) {
      var t = n(ev && ev.t);
      if (t === null) return;
      if (t < t0) t0 = t;
      if (t > t1) t1 = t;
    });
    if (t1 <= t0) t1 = t0 + 60;

    var maxRtt = state.thr * 1.25;
    series.forEach(function (s) { maxRtt = Math.max(maxRtt, n(s.rtt_ms) || 0); });
    var ymax = niceMax(maxRtt);

    var maxLoss = 0;
    series.forEach(function (s) { maxLoss = Math.max(maxLoss, n(s.loss_pct) || 0); });

    function x(t) { return L + (t - t0) / (t1 - t0) * (W - L - R); }
    function y(v) { return T + PH - Math.min(v, ymax) / ymax * PH; }

    var svgRoot = svg("svg", "hp-svg", {
      viewBox: "0 0 " + W + " " + HH,
      width: "100%",
      height: String(HH),
      role: "img",
      "aria-label": (H.title || "") + " " + (H["r" + state.range] || "")
    });
    svgRoot.setAttribute("preserveAspectRatio", "none");

    /* 横向网格 + 纵轴刻度：只画 0 / 中 / 顶三条，多了就是噪点 */
    [0, 0.5, 1].forEach(function (f) {
      var vy = y(ymax * f);
      svgRoot.appendChild(svg("line", "hp-grid", { x1: L, y1: vy, x2: W - R, y2: vy }));
      var label = svg("text", "hp-ytick", { x: L - 8, y: vy + 4, "text-anchor": "end" });
      label.textContent = String(Math.round(ymax * f));
      svgRoot.appendChild(label);
    });

    /* 事件热区先垫在下面（见下），所以要先算出「哪一刻有事件」。
       同一时刻常常有好几条（时延与丢包是一起报的），按横坐标并成一组：
       一组一条热区，点开列出这一时刻的全部事件 —— 叠着画两张热区，
       只有最上面那张点得到，下面那条等于没画。 */
    var groups = {};
    var order = [];
    (state.events || []).forEach(function (ev) {
      var t = n(ev && ev.t);
      if (t === null || t < t0 || t > t1) return;
      var k = String(Math.round(x(t)));
      if (!groups[k]) { groups[k] = { x: x(t), t: t, list: [] }; order.push(k); }
      groups[k].list.push(ev);
    });
    order.forEach(function (k) {
      var g = groups[k];
      var hit = svg("rect", "hp-hit", {
        x: g.x - 5, y: T, width: 10, height: PH, tabindex: "0", role: "button"
      });
      var said = stamp(g.t) + " " + g.list.map(function (ev) {
        return typeText(ev.type) + " " + fmtNum(ev.value);
      }).join(" / ");
      hit.setAttribute("aria-label", said);
      /* 橙虚线的含义不写在图里，鼠标停到热区上给一句，别让人猜颜色 */
      var tip = svg("title", "", {});
      tip.textContent = said;
      hit.appendChild(tip);
      hit.addEventListener("click", function () { showEvents(g.list); });
      hit.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); showEvents(g.list); }
      });
      svgRoot.appendChild(hit);
    });

    /* 丢包色块：贴底一条带，高度按该点丢包率 */
    var bw = Math.max(2, (W - L - R) / Math.max(series.length, 1));
    var bandH = 16;
    series.forEach(function (s) {
      var l = n(s.loss_pct) || 0;
      if (l <= 0) return;
      var hgt = Math.max(2, Math.min(l / Math.max(maxLoss, 1), 1) * bandH);
      svgRoot.appendChild(svg("rect", "hp-loss" + (l >= 2 ? " hi" : ""), {
        x: x(s.t) - bw / 2, y: T + PH - hgt, width: Math.max(1.5, bw - 0.5), height: hgt
      }));
    });

    /* RTT 折线：中间缺点就断开，别用直线连过去假装有数据 */
    var segs = [];
    var cur = [];
    series.forEach(function (s) {
      var v = n(s.rtt_ms);
      if (v === null) { if (cur.length) { segs.push(cur); cur = []; } return; }
      cur.push(x(s.t).toFixed(1) + "," + y(v).toFixed(1));
    });
    if (cur.length) segs.push(cur);
    segs.forEach(function (pts) {
      svgRoot.appendChild(svg("polyline", "hp-line", { points: pts.join(" ") }));
    });

    /* 阈值虚线。文字留到最后再画：它压在右边，而事件竖线（橙虚线）常在「此刻」
       正好也靠在右边 —— 先画字就会被线划过去，读不出是多少。 */
    var ty = y(state.thr);
    svgRoot.appendChild(svg("line", "hp-thr", { x1: L, y1: ty, x2: W - R, y2: ty }));
    var tl = svg("text", "hp-thr-t", { x: W - R, y: ty - 5, "text-anchor": "end" });
    tl.textContent = (H.chartThr || "") + " " + state.thr + " ms";

    /* 标记（用户手动打的点） */
    (state.marks || []).forEach(function (m) {
      var t = n(m && m.t);
      if (t === null || t < t0 || t > t1) return;
      svgRoot.appendChild(svg("line", "hp-mark", { x1: x(t), y1: T, x2: x(t), y2: T + PH }));
      var f = svg("path", "hp-mark-f", { d: "M" + (x(t) - 4) + " " + T + " l8 0 l-4 7 z" });
      var ttl = svg("title", "", {});
      ttl.textContent = m.note || (H.markFlag || "");
      f.appendChild(ttl);
      svgRoot.appendChild(f);
    });

    /* 事件竖线：橙色虚线，压在折线与色块之上（热区在下面，见上） */
    (state.events || []).forEach(function (ev) {
      var t = n(ev && ev.t);
      if (t === null || t < t0 || t > t1) return;
      svgRoot.appendChild(svg("line", "hp-ev", { x1: x(t), y1: T, x2: x(t), y2: T + PH }));
    });

    /* 横轴刻度：按可用宽度决定刻数，窄屏少刻、宽屏多刻，
       避免 1024 紧凑栏与 2560 超宽栏共用 4 个固定标签时相邻文字叠在一起。
       text-anchor 首尾贴边、中间居中；7d 带日期，每个标签要留更宽的位置。 */
    var labelWide = state.range === "7d";
    var slots = (W - L - R) / (labelWide ? 86 : 52);
    var count = Math.max(2, Math.min(labelWide ? 4 : 6, Math.floor(slots)));
    var fracs = [];
    for (var q = 0; q < count; q++) fracs.push(q / (count - 1));
    fracs.forEach(function (f, i) {
      var t = t0 + (t1 - t0) * f;
      var tx = svg("text", "hp-xtick", {
        x: Math.min(W - R, Math.max(L, x(t))),
        y: T + PH + 15,
        "text-anchor": i === 0 ? "start" : (i === count - 1 ? "end" : "middle")
      });
      tx.textContent = labelWide ? (mmdd(t) + " " + hhmm(t)) : hhmm(t);
      svgRoot.appendChild(tx);
    });

    /* 单位：纵轴是 ms，只标一次，不每格都写 */
    var unit = svg("text", "hp-unit", { x: L, y: T - 2 });
    unit.textContent = "ms";
    svgRoot.appendChild(unit);

    /* 阈值文字最后画（见上）：白描边托底，压在折线/竖线上也读得清 */
    svgRoot.appendChild(tl);

    box.appendChild(svgRoot);
  }

  function typeText(t) {
    var k = String(t || "");
    if (k === "loss") return H.typeLoss || "";
    if (k === "jitter") return H.typeJitter || "";
    return H.typeRtt || "";
  }

  /* 点事件竖线：在图下方给一条细节，而不是弹窗 —— 图表还要继续看 */
  function showEvents(list) {
    if (!state.el || !list || !list.length) return;
    var box = state.el.detail;
    U.clear(box);
    state.sel = list[0];

    var wrap = U.el("div", "hist-ev");
    var head = U.el("div", "hist-ev-h");
    head.appendChild(U.el("b", "", H.evDetail || ""));
    head.appendChild(U.el("span", "hist-ev-t", stamp(n(list[0].t) || 0)));
    if (list.length > 1) head.appendChild(U.el("span", "hist-ev-n", String(list.length)));
    var close = U.btn(C.act.close, { kind: "ghost", size: "sm" });
    close.addEventListener("click", function () { U.clear(box); state.sel = null; });
    head.appendChild(close);
    wrap.appendChild(head);

    list.forEach(function (ev) {
      var unit = ev.type === "loss" ? (H.unitPct || "") : (H.unitMs || "");
      var dl = U.el("dl", "kv kv-2 hist-ev-row");
      addKv(dl, H.evType, typeText(ev.type));
      addKv(dl, H.evTarget, ev.target || "—");
      addKv(dl, H.evValue, fmtNum(ev.value) + " " + unit);
      addKv(dl, H.evThr, fmtNum(ev.threshold) + " " + unit);
      addKv(dl, H.evDur, durSec(ev.duration_s));
      addKv(dl, H.evAp, [ev.bssid, ev.rssi_dbm === null || ev.rssi_dbm === undefined ? "" : ev.rssi_dbm + " dBm"]
        .filter(Boolean).join(" · ") || "—");
      wrap.appendChild(dl);
    });

    box.appendChild(wrap);
  }

  function addKv(dl, k, v) {
    var row = U.el("div", "kv-row");
    row.appendChild(U.el("dt", "", k || ""));
    row.appendChild(U.el("dd", "", v === "" || v === null || v === undefined ? "—" : String(v)));
    dl.appendChild(row);
  }

  function fmtNum(v) {
    var x = n(v);
    if (x === null) return "—";
    return x % 1 === 0 ? String(x) : x.toFixed(1);
  }

  /* ------------------------------------------------------------ 事件表 */
  function drawEvents() {
    var host = state.el.events;
    U.clear(host);
    var list = (state.events || []).slice().sort(function (a, b) { return (b.t || 0) - (a.t || 0); });

    var hd = U.el("div", "rpt-h4");
    hd.appendChild(U.el("h4", "", H.evTitle || ""));
    hd.appendChild(U.el("span", "rpt-dim", H["r" + state.range] || ""));
    if (state.coverage && n(state.coverage.samples) !== null) {
      hd.appendChild(U.el("span", "hist-cov", U.tpl(H.covSamples || "", {
        n: state.coverage.samples, g: state.coverage.gaps === undefined ? 0 : state.coverage.gaps
      })));
    }
    host.appendChild(hd);

    if (!list.length) {
      host.appendChild(U.el("p", "muted", H.evEmpty || ""));
      return;
    }

    var tbl = U.el("table", "evi-table hist-table");
    var thead = document.createElement("thead");
    var hr = document.createElement("tr");
    [H.evTime, H.evTarget, H.evType, H.evValue, H.evThr, H.evDur, H.evAp].forEach(function (t) {
      hr.appendChild(U.el("th", "", t || ""));
    });
    thead.appendChild(hr);
    tbl.appendChild(thead);

    var tb = document.createElement("tbody");
    list.forEach(function (ev) {
      var tr = document.createElement("tr");
      var unit = ev.type === "loss" ? (H.unitPct || "") : (H.unitMs || "");
      tr.appendChild(U.el("td", "mono", stamp(n(ev.t) || 0)));
      tr.appendChild(U.el("td", "", ev.target || "—"));
      var td = U.el("td", "");
      td.appendChild(U.chip(ev.type === "loss" ? "crit" : "warn", typeText(ev.type)));
      tr.appendChild(td);
      tr.appendChild(U.el("td", "mono", fmtNum(ev.value) + " " + unit));
      tr.appendChild(U.el("td", "mono", fmtNum(ev.threshold) + " " + unit));
      tr.appendChild(U.el("td", "mono", durSec(ev.duration_s)));
      tr.appendChild(U.el("td", "mono",
        [ev.bssid || "—", ev.rssi_dbm === null || ev.rssi_dbm === undefined ? "" : ev.rssi_dbm + " dBm"]
          .filter(Boolean).join(" · ")));
      tr.addEventListener("click", function () { showEvents([ev]); });
      tb.appendChild(tr);
    });
    tbl.appendChild(tb);
    host.appendChild(tbl);
  }

  /* ------------------------------------------------------------ 动作 */
  function markNow() {
    var body = document.createDocumentFragment();
    body.appendChild(U.el("p", "", H.markBody || ""));
    var input = document.createElement("input");
    input.className = "input";
    input.type = "text";
    input.placeholder = H.markPh || "";
    input.setAttribute("aria-label", H.markTitle || "");
    body.appendChild(input);

    var cancel = U.btn(C.act.cancel, { kind: "ghost" });
    var ok = U.btn(C.act.confirm || C.act.save || "", {});
    var box = U.modal({ title: H.markTitle || "", body: body, actions: [cancel, ok] });
    cancel.addEventListener("click", function () { box.close(); });
    ok.addEventListener("click", function () {
      ok.disabled = true;
      ND.api.historyMark(input.value.trim() || (H.markDefault || "")).then(function (res) {
        box.close();
        if (res && res.ok) {
          U.toast(H.markDone || "", "ok");
          load();
          return;
        }
        U.toast(U.tpl(H.markFail || "{reason}", { reason: U.why(res) }), "crit");
      });
    });
    setTimeout(function () { input.focus(); }, 30);
  }

  function exportFile(fmt) {
    var w = windowOf();
    var q = "from=" + w.from + "&to=" + w.to;
    ND.api.historyExport(fmt, q).then(function (res) {
      if (!res || !res.ok || !res.text) {
        U.toast(U.tpl(H.exportFail || "{reason}", { reason: (res && res.error) || "" }), "crit");
        return;
      }
      /* 优先用后端给的文件名（带它自己的时间戳），拿不到才本地拼一个 */
      var ext = fmt === "md" ? "md" : "csv";
      var fallback = "netdiag-history-" + state.range + "-" + w.to + "." + ext;
      ND.render.saveText(res.name || fallback, res.text);
    });
  }

  ND.history = { mount: mount, unmount: unmount };
})(window.ND = window.ND || {});
