/* ============================================================================
   panel.js · 首页「实时与专业数据」右侧的专业面板（业务渲染层）
   ----------------------------------------------------------------------------
   左边的三层结论给人看，这里给数字看。每一行都能点：复制对应的 Wireshark
   过滤器，用户接着就能在自己的 Wireshark 里复现。

   数据全部来自本次结果（result.meta / result.metrics），没有就不显示 ——
   宁可留白也不给估算值。唯一的例外是「应用层分布」：后端没有按应用层协议的
   报文占比（需求单 R8-1），这里按**会话数**统计，并在标题上写明口径。

   颜色只用来标「超阈值」，且同屏最多 3 个（超出降为中性）：
   专业面板一屏十几个数字，全染色等于没染色。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var P = C.panel || {};

  var MAX_MARKS = 3;

  function n(v) {
    if (v === null || v === undefined || v === "") return null;
    var x = Number(v);
    return isFinite(x) ? x : null;
  }

  function f(v, d) {
    var x = n(v);
    return x === null ? (P.noData || "—") : x.toFixed(d === undefined ? 0 : d);
  }

  /* ------------------------------------------------------------ 阈值 */
  function grade(v, warn, crit) {
    var x = n(v);
    if (x === null) return "";
    if (x >= crit) return "crit";
    if (x >= warn) return "warn";
    return "";
  }

  function rank(level) { return level === "crit" ? 2 : level === "warn" ? 1 : 0; }

  /* ------------------------------------------------------------ 模型 */
  function quality(meta, metrics) {
    var rate = n(meta.retrans_rate);
    var rows = [
      {
        key: "retrans", label: P.qRetrans,
        count: n(meta.retrans), rate: rate,
        level: grade(rate, 1, 3),
        filter: retransFilter(meta)
      },
      {
        key: "ooo", label: P.qOoo,
        count: n(meta.ooo), rate: n(metrics.ooo_rate),
        level: grade(n(metrics.ooo_rate) === null ? n(meta.ooo) : n(metrics.ooo_rate), 0.5, 2),
        filter: "tcp.analysis.out_of_order"
      },
      {
        key: "rst", label: P.qRst,
        count: n(meta.rst), rate: null,
        level: grade(n(meta.rst), 1, 5),
        filter: "tcp.flags.reset == 1"
      },
      {
        key: "zero", label: P.qZeroWin,
        count: n(meta.zero_win), rate: null,
        level: grade(n(meta.zero_win), 1, 3),
        filter: "tcp.analysis.zero_window"
      },
      {
        key: "dup", label: P.qDupAck,
        count: n(meta.dup_ack), rate: n(metrics.dup_ack_rate),
        level: grade(n(meta.dup_ack), 3, 10),
        filter: "tcp.analysis.duplicate_ack"
      }
    ];
    /* 只给最严重的 3 个染色，其余中性 —— 这是「同屏最多 3 个重点标记」 */
    var order = rows.slice().sort(function (a, b) { return rank(b.level) - rank(a.level); });
    var budget = 0;
    order.forEach(function (r) {
      if (!r.level) return;
      if (budget < MAX_MARKS) budget++;
      else r.level = "";
    });
    return rows;
  }

  function retransFilter(meta) {
    var worst = null;
    ((meta.streams_top || []) || []).forEach(function (s) {
      if (!s) return;
      var r = n(s.retrans) || 0;
      if (r > 0 && (!worst || r > (n(worst.retrans) || 0))) worst = s;
    });
    /* 有明确的「重传大户」就把 ip.addr 带上，用户打开 Wireshark 直接落到那台对端 */
    if (worst && worst.server) return "tcp.analysis.retransmission && ip.addr==" + worst.server;
    return "tcp.analysis.retransmission";
  }

  function sessions(meta, all) {
    var list = (meta.streams_top || []).slice();
    if (!all) list = list.slice(0, 5);
    return list.map(function (s) {
      /* 源端口对「这是谁跟谁」没用，省下来给目标端口，表格就不会一列全是省略号 */
      var src = String(s.client || "");
      var dst = String(s.server || "") + (s.dport ? ":" + s.dport : "");
      return {
        stream: s.stream,
        flow: src + " → " + dst,
        pkts: s.packets,
        bytes: s.bytes,
        rtt: s.rtt_avg,
        retrans: s.retrans,
        app: s.app || "",
        filter: s.stream !== undefined && s.stream !== null ? "tcp.stream eq " + s.stream : ""
      };
    });
  }

  /* 应用层分布：只在 streams_top 覆盖了全部会话时才是精确值 */
  function l7(meta) {
    var total = n(meta.streams_total);
    var top = meta.streams_top || [];
    if (!total || !top.length) return null;
    var counts = { TLS: 0, HTTP: 0, other: 0 };
    top.forEach(function (s) {
      var a = String((s && s.app) || "").toUpperCase();
      if (a === "TLS") counts.TLS++;
      else if (a === "HTTP") counts.HTTP++;
      else counts.other++;
    });
    var sum = counts.TLS + counts.HTTP + counts.other;
    if (!sum) return null;
    var buckets = [
      { key: "tls", label: P.l7Tls, n: counts.TLS, pct: counts.TLS * 100 / sum, filter: "tls.handshake.type == 1" },
      { key: "http", label: P.l7Http, n: counts.HTTP, pct: counts.HTTP * 100 / sum, filter: "http.request" },
      { key: "other", label: P.l7Other, n: counts.other, pct: counts.other * 100 / sum, filter: "" }
    ];
    return { buckets: buckets, complete: top.length >= total, sampled: top.length, total: total };
  }

  function build(res, opts) {
    opts = opts || {};
    var meta = (res && res.meta) || {};
    var metrics = (res && res.metrics) || {};
    var duration = n(meta.duration);
    if (duration === null) duration = n(meta.capture_duration);
    return {
      has: !!(res && (n(meta.packets) !== null || n(meta.streams_total) !== null)),
      packets: n(meta.packets),
      streams: n(meta.streams_total),
      duration: duration,
      samples: {
        rtt: n(metrics.rtt_samples), hs: n(metrics.hs_samples),
        dns: n(metrics.dns_samples), http: n(metrics.http_samples)
      },
      quality: quality(meta, metrics),
      sessions: sessions(meta, !!opts.pro),
      sessionTotal: (meta.streams_top || []).length,
      l7: l7(meta),
      dns: {
        q: n(meta.dns_total), r: n(meta.dns_resp),
        avg: n(meta.dns_avg_ms), fail: n(meta.dns_fail_rate)
      },
      extra: {
        rttP95: n(metrics.rtt_p95_ms), jitter: n(metrics.rtt_jitter_ms),
        hs: n(metrics.hs_avg_ms), http: n(metrics.http_avg_ms),
        tp: n(meta.throughput_mbps), probe: meta.probe_baseline || null
      },
      /* 专业模式下把采集层原样输出也放出来：专家要看的往往是最后几行 */
      logs: (opts.pro && opts.job && opts.job.logs) ? opts.job.logs : []
    };
  }

  /* ------------------------------------------------------------ 渲染 */
  /* host 是一个容器；清空后重画。opts: { job, pro, onPro, bare } */
  function render(host, res, opts) {
    opts = opts || {};
    U.clear(host);
    var wrap = U.el("div", "pro" + (opts.bare ? " bare" : ""));
    host.appendChild(wrap);

    /* 头部只有「独立成卡」时才画；嵌在首页那张大卡里由页面统一给标题和开关 */
    if (!opts.bare) {
      var hd = U.el("div", "pro-hd");
      var tt = U.el("div", "pro-t");
      tt.appendChild(U.el("h3", "", P.title || ""));
      tt.appendChild(U.el("span", "pro-sub", P.sub || ""));
      hd.appendChild(tt);

      var sw = U.el("label", "pro-sw");
      var cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = !!opts.pro;
      cb.addEventListener("change", function () {
        if (opts.onPro) opts.onPro(cb.checked);
      });
      sw.appendChild(cb);
      sw.appendChild(U.el("span", "pro-sw-t", P.pro || ""));
      sw.title = P.proHint || "";
      hd.appendChild(sw);
      wrap.appendChild(hd);
    }

    var running = !!(opts.job && (opts.job.state === "running" || opts.job.state === "starting"));
    if (running) {
      wrap.appendChild(runningBlock(opts.job));
      return wrap;
    }
    if (!res) {
      wrap.appendChild(U.el("p", "pro-empty", P.empty || ""));
      return wrap;
    }

    var m = build(res, opts);
    if (!m.has) {
      wrap.appendChild(U.el("p", "pro-empty", P.empty || ""));
      return wrap;
    }

    var bd = U.el("div", "pro-bd");
    bd.appendChild(overview(m));
    bd.appendChild(qualitySec(m));
    bd.appendChild(sessionsSec(m, opts));
    bd.appendChild(l7Sec(m));
    bd.appendChild(dnsSec(m));
    if (opts.pro) bd.appendChild(extraSec(m));
    wrap.appendChild(bd);
    return wrap;
  }

  function runningBlock(job) {
    var box = U.el("div", "pro-run");

    /* 头部一行：转圈 + 一句「在干嘛」。不再重复左边那句话的完整版，
       左边负责「正在采集」，右边负责「这些位置在等着填数」。 */
    var hd = U.el("div", "pro-run-hd");
    var sp = U.el("span", "spinner");
    sp.setAttribute("aria-hidden", "true");
    hd.appendChild(sp);
    hd.appendChild(U.el("span", "pro-run-t", P.runningFill || P.running || ""));
    hd.appendChild(U.el("span", "pro-run-b", U.tpl(P.runningBody || "", {
      phase: job.phase || "", elapsed: f(job.elapsed, 0),
      lines: (job.logs || []).length
    })));
    box.appendChild(hd);

    /* 骨架：把「结束后会出现哪几块」先摆出来，用户知道自己在等什么 */
    var sk = U.el("div", "pro-skel");
    [P.secOverview, P.secQuality, P.secStreams, P.secL7, P.secDns].forEach(function (name) {
      var row = U.el("div", "sk-row");
      row.appendChild(U.el("span", "sk-k", name || ""));
      var bars = U.el("span", "sk-bars");
      bars.appendChild(U.el("i", "sk-line"));
      bars.appendChild(U.el("i", "sk-line sk-short"));
      row.appendChild(bars);
      sk.appendChild(row);
    });
    box.appendChild(sk);
    return box;
  }

  function overview(m) {
    var sec = U.el("section", "pro-sec");
    sec.appendChild(U.el("h4", "pro-h", P.secOverview || ""));
    var grid = U.el("div", "pro-ov");
    grid.appendChild(ovCell(P.ovPackets, m.packets === null ? null : f(m.packets, 0)));
    grid.appendChild(ovCell(P.ovStreams, m.streams === null ? null : f(m.streams, 0)));
    grid.appendChild(ovCell(P.ovDuration, m.duration === null ? null : f(m.duration, 0) + (C.unit || {}).sec));
    var sm = m.samples;
    grid.appendChild(ovCell(P.ovSamples, [sm.rtt, sm.hs, sm.dns, sm.http].every(function (x) { return x === null; })
      ? null
      : f(sm.rtt, 0) + " / " + f(sm.hs, 0) + " / " + f(sm.dns, 0) + " / " + f(sm.http, 0)));
    sec.appendChild(grid);
    return sec;
  }

  function ovCell(label, value) {
    var c = U.el("div", "ov");
    c.appendChild(U.el("span", "ov-k", label || ""));
    c.appendChild(U.el("b", "ov-v" + (value === null ? " na" : ""), value === null ? (P.noData || "—") : value));
    return c;
  }

  function qualitySec(m) {
    var sec = U.el("section", "pro-sec");
    sec.appendChild(U.el("h4", "pro-h", P.secQuality || ""));
    var list = U.el("ul", "q-list");
    m.quality.forEach(function (r) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "q-row" + (r.level ? " " + r.level : "");
      b.appendChild(U.el("span", "q-k", r.label || ""));
      var val = U.el("b", "q-v", r.count === null ? (P.noData || "—") : f(r.count, 0));
      b.appendChild(val);
      if (r.rate !== null) b.appendChild(U.el("span", "q-r", f(r.rate, 2) + "%"));
      else b.appendChild(U.el("span", "q-r", ""));
      if (r.filter) {
        b.appendChild(U.el("span", "q-copy", P.copyFilter || ""));
        b.setAttribute("aria-label", (r.label || "") + " " + f(r.count, 0) + " · " + (P.copyFilter || "") + "：" + r.filter);
        b.addEventListener("click", function () { copyFilter(r.filter); });
      } else {
        b.disabled = true;
      }
      list.appendChild(b);
    });
    sec.appendChild(list);
    sec.appendChild(U.el("p", "pro-hint", P.streamsHint || ""));
    return sec;
  }

  function sessionsSec(m, opts) {
    var sec = U.el("section", "pro-sec");
    var hd = U.el("h4", "pro-h");
    hd.appendChild(document.createTextNode(P.secStreams || ""));
    if (m.sessionTotal) hd.appendChild(U.el("span", "pro-dim", " · " + m.sessionTotal));
    sec.appendChild(hd);

    if (!m.sessions.length) {
      sec.appendChild(U.el("p", "pro-empty", P.empty || ""));
      return sec;
    }

    var tbl = U.el("div", "st-table");
    var head = U.el("div", "st-row st-head");
    [P.colFlow, P.colPkts, P.colBytes, P.colRtt, P.colRetrans].forEach(function (t) {
      head.appendChild(U.el("span", "", t || ""));
    });
    tbl.appendChild(head);

    m.sessions.forEach(function (s) {
      var row = document.createElement("button");
      row.type = "button";
      row.className = "st-row";
      if (s.retrans && n(s.retrans) > 0) row.classList.add("warn");
      var flow = U.el("span", "st-flow mono", s.flow);
      flow.title = s.flow;
      row.appendChild(flow);
      row.appendChild(U.el("span", "st-n mono", f(s.pkts, 0)));
      row.appendChild(U.el("span", "st-n mono", bytes(s.bytes)));
      row.appendChild(U.el("span", "st-n mono", s.rtt === null || s.rtt === undefined || Number(s.rtt) === 0
        ? "—" : f(s.rtt, 1) + " ms"));
      row.appendChild(U.el("span", "st-n mono", f(s.retrans, 0)));
      if (s.filter) {
        row.title = (P.copyFilter || "") + "：" + s.filter;
        row.setAttribute("aria-label", s.flow + " · " + (P.copyFilter || "") + "：" + s.filter);
        row.addEventListener("click", function () { copyFilter(s.filter); });
      }
      tbl.appendChild(row);
    });
    sec.appendChild(tbl);
    sec.appendChild(U.el("p", "pro-hint", P.streamsHint || ""));
    return sec;
  }

  function l7Sec(m) {
    var sec = U.el("section", "pro-sec");
    var hd = U.el("h4", "pro-h");
    hd.appendChild(document.createTextNode(P.secL7 || ""));
    if (m.l7 && !m.l7.complete) {
      hd.appendChild(U.el("span", "pro-dim", " · " + U.tpl(P.l7Sample, { n: m.l7.sampled, total: m.l7.total })));
    }
    sec.appendChild(hd);

    if (!m.l7) {
      sec.appendChild(U.el("p", "pro-empty", P.l7Empty || ""));
      return sec;
    }

    var bar = U.el("div", "l7-bar");
    m.l7.buckets.forEach(function (b) {
      if (!b.n) return;
      var seg = U.el("span", "l7-seg l7-" + b.key);
      seg.style.flexGrow = String(Math.max(b.pct, 2));
      seg.title = (b.label || "") + " " + b.n + " · " + b.pct.toFixed(0) + "%";
      bar.appendChild(seg);
    });
    sec.appendChild(bar);

    var legend = U.el("ul", "l7-legend");
    m.l7.buckets.forEach(function (b) {
      if (!b.n) return;                       /* 0% 的类别不占位，别让图例看起来像缺数据 */
      var li = document.createElement(b.filter ? "button" : "span");
      if (b.filter) {
        li.type = "button";
        li.addEventListener("click", function () { copyFilter(b.filter); });
        li.title = (P.copyFilter || "") + "：" + b.filter;
      }
      li.className = "l7-leg l7-" + b.key;
      li.appendChild(U.el("i", "l7-dot"));
      li.appendChild(U.el("span", "", (b.label || "") + " " + b.n + " · " + b.pct.toFixed(0) + "%"));
      legend.appendChild(li);
    });
    sec.appendChild(legend);
    sec.appendChild(U.el("p", "pro-hint", P.l7Note || ""));
    return sec;
  }

  function dnsSec(m) {
    var sec = U.el("section", "pro-sec");
    sec.appendChild(U.el("h4", "pro-h", P.secDns || ""));
    var d = m.dns;
    if (d.q === null && d.r === null) {
      sec.appendChild(U.el("p", "pro-empty", P.noData || "—"));
      return sec;
    }
    var row = U.el("div", "dns-row");
    row.appendChild(dnsCell(P.dnsQueries, f(d.q, 0)));
    row.appendChild(dnsCell(P.dnsResp, f(d.r, 0)));
    row.appendChild(dnsCell(P.dnsAvg, d.avg === null ? (P.noData || "—") : f(d.avg, 0) + " ms"));
    if (d.fail !== null) row.appendChild(dnsCell(P.dnsFail, f(d.fail, 1) + "%", d.fail >= 20 ? "warn" : ""));
    sec.appendChild(row);
    return sec;
  }

  function dnsCell(label, value, level) {
    var c = U.el("div", "dns-cell");
    c.appendChild(U.el("span", "dns-k", label || ""));
    c.appendChild(U.el("b", "dns-v" + (level ? " " + level : ""), value));
    return c;
  }

  /* 专业模式才展开的字段：小白看不懂，专家恰恰要这些 */
  function extraSec(m) {
    var sec = U.el("section", "pro-sec");
    sec.appendChild(U.el("h4", "pro-h", P.secExtra || ""));
    var box = U.el("div", "pro-extra");
    box.appendChild(kvLine(P.exRttP95, m.extra.rttP95 === null ? "—" : f(m.extra.rttP95, 1) + " ms"));
    box.appendChild(kvLine(P.exJitter, m.extra.jitter === null ? "—" : f(m.extra.jitter, 1) + " ms"));
    box.appendChild(kvLine(P.exHs, m.extra.hs === null ? "—" : f(m.extra.hs, 1) + " ms"));
    box.appendChild(kvLine(P.exHttpAvg, m.extra.http === null ? "—" : f(m.extra.http, 0) + " ms"));
    box.appendChild(kvLine(P.exThroughput, m.extra.tp === null ? "—" : f(m.extra.tp, 2) + " Mbps"));
    sec.appendChild(box);

    var pb = m.extra.probe;
    if (pb) {
      var T = C.tech || {};
      sec.appendChild(U.el("p", "pro-hint", (P.exProbe || "") + "：" + U.tpl(T.statsProbe, {
        sent: f(pb.sent, 0), recv: f(pb.recv, 0),
        timeout: f(pb.timeout, 0), excluded: f(pb.excluded_packets, 0)
      })));
    } else {
      sec.appendChild(U.el("p", "pro-hint", (P.exProbe || "") + "：" + (P.exProbeNone || "")));
    }

    /* 「专业模式 = 控制台默认展开」在首页的落地：不留一整块控制台，只给最后几行 */
    if (m.logs && m.logs.length) {
      var tail = m.logs.slice(-8).map(function (row) { return String((row && row.m) || ""); })
        .filter(function (s) { return s !== ""; });
      if (tail.length) {
        var lh = U.el("h4", "pro-h pro-h-sub");
        lh.appendChild(document.createTextNode(U.tpl(P.secLogs || "", { n: tail.length })));
        sec.appendChild(lh);
        var pre = U.el("pre", "pro-logs mono");
        tail.forEach(function (line) { pre.appendChild(U.el("div", "pl-line", "› " + line)); });
        sec.appendChild(pre);
      }
    }
    return sec;
  }

  function kvLine(k, v) {
    var d = U.el("div", "pe-line");
    d.appendChild(U.el("span", "pe-k", k || ""));
    d.appendChild(U.el("b", "pe-v mono", v));
    return d;
  }

  function bytes(v) {
    var x = n(v);
    if (x === null) return "—";
    if (x < 1024) return x + " B";
    if (x < 1024 * 1024) return (x / 1024).toFixed(1) + " KB";
    return (x / 1024 / 1024).toFixed(1) + " MB";
  }

  function copyFilter(filter) {
    if (!filter) return;
    U.copyText(filter).then(function (ok) {
      U.toast(ok ? U.tpl(P.filterCopied, { f: filter }) : U.tpl(P.filterFail, { f: filter }),
        ok ? "ok" : "crit");
    });
  }

  ND.panel = { render: render, build: build, copyFilter: copyFilter };
})(window.ND = window.ND || {});
