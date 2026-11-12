/* ============================================================================
   render.js · 块级渲染件（卡片 / 指标 / 横幅 / 键值 / 证据 / 技术详情）
   ----------------------------------------------------------------------------
   这一层只做「一块内容长什么样」，不知道任何接口字段之外的东西：
   进来的都是已经取好的数据，出去的都是 DOM 节点。
   页面（home / modes / settings / logs）负责取数与装配顺序。

   S4 起「结论区」不在这里：它要判断「哪层坏了 / 该找谁」，属于业务，
   搬到了 verdict.js。本文件只剩证据、建议、技术详情这些纯块级件。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};

  /* ------------------------------------------------------------ 容器 */
  /* opts: { sub, tag, actions[] } */
  function card(title, opts) {
    opts = opts || {};
    var section = U.el("section", "card" + (opts.cls ? " " + opts.cls : ""));
    var hd = U.el("div", "card-hd");
    hd.appendChild(U.el("h2", "", title || ""));
    if (opts.sub) hd.appendChild(U.el("span", "card-sub", opts.sub));
    if (opts.tag) hd.appendChild(tag(opts.tag.kind, opts.tag.text));
    (opts.actions || []).forEach(function (a) {
      if (!a) return;
      a.classList.add("hd-act");
      hd.appendChild(a);
    });
    section.appendChild(hd);
    var body = U.el("div", "card-bd");
    section.appendChild(body);
    return { section: section, hd: hd, body: body };
  }

  function tag(kind, text) {
    return U.el("span", "tag" + (kind ? " " + kind : ""), text);
  }

  /* rows: [[label, value], ...]；opts: { cols: 1|2, mono: bool } */
  function kv(rows, opts) {
    opts = opts || {};
    var dl = U.el("dl", "kv" + (opts.cols === 2 ? " kv-2" : ""));
    (rows || []).forEach(function (r) {
      if (!r || !r[0]) return;
      var row = U.el("div", "kv-row");
      row.appendChild(U.el("dt", "", r[0]));
      var dd = U.el("dd", r[1] instanceof Node ? "" : (r[2] ? "mono" : ""));
      if (r[1] instanceof Node) dd.appendChild(r[1]);
      else dd.textContent = r[1] === undefined || r[1] === null || r[1] === "" ? "—" : String(r[1]);
      row.appendChild(dd);
      dl.appendChild(row);
    });
    return dl;
  }

  /* kind: warn / crit / ok */
  function banner(kind, title, body) {
    var b = U.el("div", "banner " + (kind || "warn"));
    b.appendChild(U.icon(kind === "crit" ? "alert" : "alert", "banner-ic"));
    var main = U.el("div", "banner-main");
    main.appendChild(U.el("b", "", title || ""));
    if (body) main.appendChild(U.el("p", "", body));
    b.appendChild(main);
    return b;
  }

  function empty(iconName, title, body, actions) {
    var box = U.el("div", "empty");
    box.appendChild(U.icon(iconName || "report"));
    if (title) box.appendChild(U.el("b", "", title));
    if (body) box.appendChild(U.el("p", "", body));
    (actions || []).forEach(function (a) { if (a) box.appendChild(a); });
    return box;
  }

  function skeleton(n, startPct) {
    var box = U.el("div", "stack");
    var base = startPct || 58;
    for (var i = 0; i < n; i++) {
      var s = U.el("div", "sk");
      s.style.setProperty("--w", (base + i * 8) + "%");
      box.appendChild(s);
    }
    return box;
  }

  function list(items, cls) {
    var ul = U.el("ul", cls || "points");
    (items || []).forEach(function (t) { if (t) ul.appendChild(U.el("li", "", t)); });
    return ul;
  }

  /* ------------------------------------------------------------ 指标 */
  function kpi(label, value, sub, kind, opts) {
    opts = opts || {};
    var wrap = U.el("div", "kpi" + (opts.running ? " is-running" : ""));
    wrap.appendChild(U.el("dt", "", label));
    var v = U.el("dd", "kpi-v" + (kind ? " " + kind : "") + (value ? "" : " na"));
    if (opts.running) {
      var sp = U.el("span", "spinner");
      sp.setAttribute("aria-hidden", "true");
      v.appendChild(sp);
      v.appendChild(U.el("span", "", value || (C.kpi || {}).running || ""));
    } else {
      v.textContent = value || (opts.loading ? "" : ((C.common || {}).na || ""));
    }
    wrap.appendChild(v);
    wrap.appendChild(U.el("dd", "kpi-sub", opts.loading ? "" : (sub || "")));
    return wrap;
  }

  /* 四层状态条：只是「哪一层有话说」的索引 */
  function layerStrip(verdict) {
    if (!verdict || !verdict.layers || !verdict.layers.length) return null;
    var box = U.el("div", "layers");
    verdict.layers.forEach(function (l) {
      var kind = l.status === "ok" ? "ok" : (l.status === "warn" ? "warn" : "crit");
      var c = U.chip(kind, String(l.id || "") + (l.name ? " " + l.name : ""));
      var tip = [l.protocol, l.severity, l.detail].filter(Boolean).join(" · ");
      if (tip) c.title = tip;
      box.appendChild(c);
    });
    return box;
  }

  /* ------------------------------------------------------------ 结论卡 */
  /* S4：结论区的「一眼三层」搬到 verdict.js（那里才做判断）。
     本文件只留它用到的证据 / 建议 / 技术详情这些块级件。 */

  /* 导出的正文统一由 reporter.js 生成（结论 · 指标 · 证据 · 数据 · 上下文），
     本文件只保留「文件名 / 落盘 / 复制」这些壳；后端的 conclusion_markdown
     只在 reporter 不可用时兜底。 */
  function textOf(job, kind) {
    var r = (job && job.result) || {};
    if (ND.reporter) {
      if (kind === "json") return ND.reporter.json(job);
      var m = ND.reporter.build(job);
      if (m) return ND.reporter.md(m);
      return "";
    }
    if (kind === "md") return r.conclusion_markdown || job.conclusion_markdown || "";
    var exp = r.conclusion_export || job.conclusion_export;
    if (exp) return JSON.stringify(exp, null, 2);
    return r.conclusion_markdown ? "" : JSON.stringify((job && job.conclusion) || {}, null, 2);
  }

  function copyConclusion(job) {
    if (ND.reporter) { ND.reporter.copy(job); return; }
    var R = C.result || {};
    var ui = (job && job.ui_copy && job.ui_copy.conclusion) || {};
    var text = (job && job.result && job.result.conclusion_text) || job.conclusion_text || "";
    if (!text) {
      U.toast(R.copyFail, "crit");
      return;
    }
    U.copyText(text).then(function (ok) {
      U.toast(ok ? (ui.copy_ok || R.copyOk) : (ui.copy_fail || R.copyFail), ok ? "ok" : "crit");
    });
  }

  function reportName(job, ext) {
    var r = (job && job.result) || {};
    var id = r.report_id || (job && job.report_id) || "";
    /* 没有报告号时按时间起名（netdiag-20261111-2149），
       不要再叫 conclusion-<毫秒>：文件名是给人看的 */
    if (!id) {
      var d = new Date();
      function p(x) { return x < 10 ? "0" + x : String(x); }
      id = "netdiag-" + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) +
        "-" + p(d.getHours()) + p(d.getMinutes());
    }
    return String(id).replace(/[\\/:*?"<>|]/g, "_") + "." + ext;
  }

  function saveText(name, text) {
    var R = C.result || {};
    if (!text) {
      U.toast(R.exportNone || (C.tech || {}).valueEmpty || "", "warn");
      return;
    }
    var blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  /* ------------------------------------------------------------ 证据 */
  /* 优先用 rows（finding/evidence/advice），没有就用 verdict.points（title/proof/action） */
  function evidence(job) {
    var r = (job && job.result) || {};
    var rows = (r.rows || []).filter(function (x) { return x && (x.finding || x.title); });
    var points = ((r.verdict || {}).points || []).filter(function (x) { return x && (x.title || x.finding); });
    var list_ = rows.length ? rows : points;
    var R = C.result || {};

    var box = U.el("div", "concl-sec");
    var head = U.el("h3", "concl-h");
    head.appendChild(document.createTextNode(R.evidenceHeading || ""));
    if (list_.length) head.appendChild(U.el("span", "concl-count", U.tpl(R.evidenceCount, { count: list_.length })));
    box.appendChild(head);

    if (!list_.length) {
      box.appendChild(U.el("p", "muted", R.evidenceEmpty || ""));
      return box;
    }

    var ul = U.el("ul", "evidence");
    list_.forEach(function (x) {
      var li = U.el("li", "ev-item");
      var top = U.el("div", "ev-top");
      /* 后端用 "—" 表示「不适用 / 无此维度」（例如安全观察这一行没有严重度），
         这不是内容，直接渲染会把占位符当证据给用户看 */
      if (!blank(x.severity)) top.appendChild(U.chip(sevKind(x.severity), String(x.severity)));
      if (!blank(x.layer)) top.appendChild(U.el("span", "ev-layer", String(x.layer)));
      if (!blank(x.protocol)) top.appendChild(U.el("span", "ev-proto mono", String(x.protocol)));
      if (top.childNodes.length) li.appendChild(top);
      li.appendChild(U.el("p", "ev-title", x.finding || x.title || ""));
      var proof = blank(x.evidence) ? (blank(x.proof) ? "" : x.proof) : x.evidence;
      if (!blank(proof)) li.appendChild(U.el("p", "ev-proof mono", String(proof)));
      ul.appendChild(li);
    });
    box.appendChild(ul);
    return box;
  }

  function sevKind(sev) {
    var s = C.sev || {};
    if (sev === s.critical) return "crit";
    if (sev === s.warning) return "warn";
    if (sev === s.info) return "info";
    if (sev === s.ok) return "ok";
    return "na";
  }

  /* 后端把「没有这个维度」写成 —、–、- 或空串；这类值不能当内容渲染 */
  function blank(v) {
    if (v === null || v === undefined) return true;
    var s = String(v).trim();
    return !s || s === "—" || s === "–" || s === "-" || s === "－";
  }

  /* ------------------------------------------------------------ 建议 */
  function advice(job) {
    var r = (job && job.result) || {};
    var v = r.verdict || {};
    var out = [];
    var seen = {};
    function push(t) {
      if (!t) return;
      var key = String(t).slice(0, 40);
      if (seen[key]) return;
      seen[key] = 1;
      out.push(String(t));
    }
    (v.next_steps || []).forEach(push);
    if (!out.length) {
      (r.rows || []).forEach(function (x) { if (x) push(x.advice); });
      (v.points || []).forEach(function (x) { if (x) push(x.action); });
    }
    var R = C.result || {};
    var box = U.el("div", "concl-sec");
    box.appendChild(U.el("h3", "concl-h", R.adviceHeading || ""));
    if (!out.length) box.appendChild(U.el("p", "muted", R.adviceEmpty || ""));
    else {
      var ol = U.el("ol", "advice");
      out.forEach(function (t) { ol.appendChild(U.el("li", "", t)); });
      box.appendChild(ol);
    }
    return box;
  }

  /* ------------------------------------------------------------ 技术详情 */
  /* details 包一层：默认收起，展开后才是原始参数；运行中也给（有多少显示多少） */
  function techDetails(job) {
    var T = C.tech || {};
    var res = (job && job.result) || null;
    var meta = (res && res.meta) || {};
    var metrics = (res && res.metrics) || {};

    var det = document.createElement("details");
    det.className = "tech";
    var sum = document.createElement("summary");
    sum.textContent = T.title || "";
    det.appendChild(sum);

    var bd = U.el("div", "tech-bd");
    det.appendChild(bd);
    bd.appendChild(U.el("p", "muted", T.hint));

    if (!res) {
      bd.appendChild(U.el("p", "muted", T.runningNote));
      return det;
    }

    /* 抓包命令：按参数推算，明确标注来源，不假装是实际命令行。
       后端在离线分析时会把 interface 写成 "-"、把模式文案塞进 bpf（真实数据），
       这种输入拼出来的命令是假的，宁可只给一句说明。 */
    var cmd = captureCommand(meta);
    var cb = U.el("div", "tech-blk");
    cb.appendChild(U.el("h4", "", T.command));
    if (cmd) {
      cb.appendChild(U.el("pre", "mono tech-pre", cmd));
      cb.appendChild(U.el("p", "tech-note", T.commandNote));
    } else {
      cb.appendChild(U.el("p", "tech-todo", T.commandTodo));
    }
    bd.appendChild(cb);

    /* 采集参数 */
    bd.appendChild(U.el("h4", "", T.params));
    bd.appendChild(kv([
      [T.iface, shown(meta.interface)],
      [T.bpf, shown(asciiText(meta.bpf))],
      [T.window, meta.capture_duration ? meta.capture_duration + (C.unit || {}).sec : shown("")],
      [T.tshark, shown(meta.tshark_path)],
      [T.pcap, shown(meta.pcap_file)]
    ], { cols: 2 }));

    /* 统计口径：样本数决定「这个结论有多少底气」 */
    var samples = [
      "RTT " + num(metrics.rtt_samples),
      "握手 " + num(metrics.hs_samples),
      "DNS " + num(metrics.dns_samples),
      "HTTP " + num(metrics.http_samples)
    ].join(" · ");
    var rows2 = [];
    rows2.push([T.statsPackets, num(meta.packets) + " / " + num(meta.streams_total)]);
    rows2.push([T.statsSamples, samples]);
    var pb = meta.probe_baseline;
    rows2.push([T.statsProbe.split("：")[0], probeLine(pb)]);
    bd.appendChild(U.el("h4", "", T.stats));
    bd.appendChild(kv(rows2, { cols: 1 }));

    /* 每块网卡探测结果：后端还没下发（R6-2），如实说明而不是留空 */
    var ifb = U.el("div", "tech-blk");
    ifb.appendChild(U.el("h4", "", T.ifaces));
    var probes = (job && job.interfaces_probe) || meta.interfaces_probe;
    if (probes && probes.length) {
      ifb.appendChild(list(probes.map(function (p, i) {
        return U.tpl(T.ifaceRow, { n: p.index || (i + 1), name: p.name || p.iface || "" });
      }), "tech-list"));
    } else {
      ifb.appendChild(U.el("p", "tech-todo", T.ifacesTodo));
    }
    bd.appendChild(ifb);

    /* 探针明细与逐跳路径已移到「展开证据」里（结论卡的证据折叠区），
       这里只留采集侧参数，避免同一个表在页面上出现两次 */

    /* 阶段耗时分解：后端还没下发（R6-3） */
    var tb = U.el("div", "tech-blk");
    tb.appendChild(U.el("h4", "", T.timing));
    tb.appendChild(U.el("p", "tech-todo", T.timingTodo));
    bd.appendChild(tb);

    return det;
  }

  /* ------------------------------------------------------------ 证据细节件 */
  /* 探针基线：发出 / 收到 / 超时 / 每类探针的丢包。结论卡与证据区共用 */
  function probeBaseline(pb) {
    var T = C.tech || {};
    if (!pb) return U.el("p", "muted", (C.panel || {}).exProbeNone || "");
    var box = U.el("div", "tech-blk");
    box.appendChild(U.el("p", "tech-dim", U.tpl(T.statsProbe, {
      sent: num(pb.sent), recv: num(pb.recv),
      timeout: num(pb.timeout), excluded: num(pb.excluded_packets)
    })));
    var roles = pb.roles || [];
    if (roles.length) {
      var ul = U.el("ul", "tech-list");
      roles.forEach(function (r) {
        var li = U.el("li", "");
        li.appendChild(U.el("b", "", U.tpl(T.probeRole, {
          role: r.role || "", kind: String(r.kind || "").toUpperCase(), target: r.target || ""
        })));
        li.appendChild(U.el("span", "tech-dim", U.tpl(T.probeRoleDetail, {
          sent: num(r.sent), recv: num(r.recv), loss: num(r.loss_pct, 0)
        })));
        /* 丢包 100% 但 TCP 可达：必须就地标注，否则这一行会被读成「链路全丢」 */
        var reason = String(r.reason || "");
        if (reason === "icmp_filtered" || reason === "refused") {
          li.appendChild(U.el("span", "tech-dim", U.tpl(T.probeRoleFiltered, {
            reason: reason === "refused" ? (T.reasonRefused || "") : (T.reasonIcmpFiltered || "")
          })));
        }
        if (r.errors && r.errors.length) {
          li.appendChild(U.el("span", "tech-err", U.tpl(T.probeError, { reason: r.errors.join("；") })));
        }
        ul.appendChild(li);
      });
      box.appendChild(ul);
    }
    return box;
  }

  /* 逐跳表：结论卡的路径剖面与探针页共用一份实现 */
  function hopTable(pp) {
    var T = C.tech || {};
    var tbl = U.el("div", "hop-table");
    var head = U.el("div", "hop-row hop-head");
    (T.hopCols || []).forEach(function (t) { head.appendChild(U.el("span", "", t)); });
    tbl.appendChild(head);
    (pp && pp.hops || []).forEach(function (h) {
      var row = U.el("div", "hop-row");
      row.appendChild(U.el("span", "mono", String(h.ttl || "")));
      row.appendChild(U.el("span", "mono", h.ip || "*"));
      row.appendChild(U.el("span", "mono", (h.sent || 0) + "/" + (h.lost || 0)));
      row.appendChild(U.el("span", "mono",
        (h.loss_pct === null || h.loss_pct === undefined) ? "—"
          : ((h.reason === "icmp_filtered" || h.status === "filtered")
              ? (T.hopFiltered || "—")
              : h.loss_pct + "%")));
      row.appendChild(U.el("span", "mono",
        isFinite(Number(h.rtt_avg_ms)) ? Number(h.rtt_avg_ms).toFixed(1) + " ms" : "—"));
      tbl.appendChild(row);
    });
    return tbl;
  }

  /* ------------------------------------------------------------ 明细（折叠） */
  /* 只有「更深一层」的东西才进来：探针基线、路径剖面、抓包命令与 BPF、统计口径。
     关键指标表与网络参数表不在这里 —— 它们属于第二/第三段，默认就该看得见。 */
  function detail(job, model) {
    var T = C.tech || {};
    var V = C.verdict || {};
    var R = C.result || {};
    var res = (job && job.result) || {};
    var meta = res.meta || {};
    var metrics = res.metrics || {};
    var block = (model && model.block) || {};

    var bd = U.el("div", "ev-bd");

    /* 依据 / 覆盖 / 未覆盖：口径的来源，不进正文。
       结论块（后端 /api/status 的 conclusion）没有就退回 verdict 自带的三份清单 —— 真报告
       的 coverage / not_covered 一直在 verdict 里，写在结论块是后来才加的。 */
    var vd = res.verdict || {};
    var grid = U.el("div", "ev-grid");
    grid.appendChild(evBlock(V.evBasis || R.basis, block.basis || vd.basis));
    grid.appendChild(evBlock(V.evCoverage || R.coverage, block.coverage || vd.coverage));
    grid.appendChild(evBlock(V.evNot || R.notCovered, block.not_covered || vd.not_covered));
    bd.appendChild(grid);

    var conf = U.el("p", "ev-conf");
    conf.appendChild(U.el("b", "", (V.evConf || R.confidence || "") + "："));
    conf.appendChild(document.createTextNode(model ? model.confidence : ""));
    if (block.key_limit) {
      conf.appendChild(document.createTextNode("　·　"));
      conf.appendChild(U.el("b", "", (V.boundaryFull || "") + "："));
      conf.appendChild(document.createTextNode(String(block.key_limit)));
    }
    bd.appendChild(conf);

    /* 后端原文：① 用的是规范表述，这里保留原句以便追溯 */
    if (res.verdict && res.verdict.plain) {
      var op = U.el("div", "dt-blk");
      op.appendChild(U.el("h4", "ev-h", (C.report || {}).originTitle || ""));
      op.appendChild(U.el("p", "dt-quote", String(res.verdict.plain)));
      bd.appendChild(op);
    }

    /* 探针基线 */
    var pb = meta.probe_baseline;
    var pbBox = U.el("div", "ev-sec");
    pbBox.appendChild(U.el("h4", "ev-h", V.evProbe || ""));
    pbBox.appendChild(pb ? probeBaseline(pb) : U.el("p", "muted", (C.panel || {}).exProbeNone || ""));
    bd.appendChild(pbBox);

    /* 路径剖面 */
    var pp = meta.path_profile;
    var ppBox = U.el("div", "ev-sec");
    ppBox.appendChild(U.el("h4", "ev-h", V.evPath || ""));
    ppBox.appendChild(pp && (pp.hops || []).length
      ? hopTable(pp)
      : U.el("p", "muted", (C.panel || {}).noData || "—"));
    bd.appendChild(ppBox);

    /* 抓包命令与 BPF */
    var cmd = captureCommand(meta);
    var cb = U.el("div", "dt-blk");
    cb.appendChild(U.el("h4", "ev-h", (C.report || {}).captureTitle || T.command || ""));
    if (cmd) {
      cb.appendChild(U.el("pre", "mono tech-pre", cmd));
      cb.appendChild(U.el("p", "tech-note", T.commandNote));
    } else {
      cb.appendChild(U.el("p", "muted", T.commandTodo));
    }
    cb.appendChild(kv([
      [T.iface, shown(meta.interface)],
      [T.bpf, shown(asciiText(meta.bpf))],
      [T.window, meta.capture_duration ? meta.capture_duration + (C.unit || {}).sec : shown("")],
      [T.pcap, shown(meta.pcap_file)]
    ], { cols: 2 }));
    bd.appendChild(cb);

    /* 统计口径 */
    var samples = [
      "RTT " + num(metrics.rtt_samples),
      "握手 " + num(metrics.hs_samples),
      "DNS " + num(metrics.dns_samples),
      "HTTP " + num(metrics.http_samples)
    ].join(" · ");
    var sc = U.el("div", "dt-blk");
    sc.appendChild(U.el("h4", "ev-h", (C.report || {}).scaleTitle || T.stats || ""));
    sc.appendChild(kv([
      [T.statsPackets, num(meta.packets) + " / " + num(meta.streams_total)],
      [T.statsSamples, samples],
      [T.statsProbe.split("：")[0], probeLine(pb)]
    ], { cols: 1 }));
    bd.appendChild(sc);

    /* 每网卡探测与阶段耗时：后端还没下发，如实写待补 */
    var ifb = U.el("div", "dt-blk");
    ifb.appendChild(U.el("h4", "ev-h", T.ifaces || ""));
    var probes = (job && job.interfaces_probe) || meta.interfaces_probe;
    if (probes && probes.length) {
      ifb.appendChild(list(probes.map(function (p, i) {
        return U.tpl(T.ifaceRow, { n: p.index || (i + 1), name: p.name || p.iface || "" });
      }), "tech-list"));
    } else {
      ifb.appendChild(U.el("p", "tech-todo", T.ifacesTodo));
    }
    bd.appendChild(ifb);

    var tb = U.el("div", "dt-blk");
    tb.appendChild(U.el("h4", "ev-h", T.timing || ""));
    tb.appendChild(U.el("p", "tech-todo", T.timingTodo));
    bd.appendChild(tb);

    return bd;
  }

  function evBlock(heading, items) {
    var box = U.el("div", "ev-blk");
    box.appendChild(U.el("h4", "ev-h", heading || ""));
    if (items && items.length) box.appendChild(list(items, "ev-list"));
    else box.appendChild(U.el("p", "muted", (C.tech || {}).valueEmpty || "—"));
    return box;
  }

  function num(v, digits) {
    var n = U.num(v, digits === undefined ? 0 : digits);
    return n === null ? "—" : n;
  }

  function probeLine(pb) {
    var T = C.tech || {};
    if (!pb) return T.statsProbeNone;
    /* statsProbe 自带「探针：」前缀，用作 kv 的 value 时要去掉，否则出现「探针 探针：…」 */
    return U.tpl(T.statsProbe, {
      sent: num(pb.sent), recv: num(pb.recv),
      timeout: num(pb.timeout), excluded: num(pb.excluded_packets)
    }).replace(/^[^：]*：/, "");
  }

  function captureCommand(meta) {
    if (!meta || !meta.tshark_path) return "";
    /* 网卡必须是真实设备名；BPF 必须是 ASCII 表达式。后端离线分析会给
       interface="-"、bpf="分析抓包文件"（模式文案），拼出来是假命令 */
    var iface = blank(meta.interface) ? "" : String(meta.interface).trim();
    var bpf = blank(meta.bpf) ? "" : String(meta.bpf).trim();
    if (!iface) return "";
    if (bpf && /[^\x00-\x7F]/.test(bpf)) return "";
    var parts = [];
    parts.push('"' + meta.tshark_path + '"');
    parts.push("-i " + iface);
    if (bpf) parts.push("-f \"" + bpf + "\"");
    if (meta.capture_duration) parts.push("-a duration:" + meta.capture_duration);
    parts.push("-w " + (meta.pcap_name || "capture.pcapng"));
    return parts.join(" ");
  }

  /* 后端把「没有这个维度」写成 -、—、空串；这类值直接显示成「未记录」 */
  function shown(v) {
    return blank(v) ? ((C.tech || {}).valueMissing || "") : String(v).trim();
  }

  /* BPF 只能由 ASCII 构成；出现中文说明后端把模式文案写进了这个字段（真实数据），
     当过滤器展示会误导用户 */
  function asciiText(v) {
    return (blank(v) || /[^\x00-\x7F]/.test(String(v))) ? "" : String(v);
  }

  ND.render = {
    card: card,
    tag: tag,
    kv: kv,
    banner: banner,
    empty: empty,
    skeleton: skeleton,
    list: list,
    kpi: kpi,
    layerStrip: layerStrip,
    evidence: evidence,
    advice: advice,
    techDetails: techDetails,
    detail: detail,
    probeBaseline: probeBaseline,
    hopTable: hopTable,
    saveText: saveText,
    textOf: textOf,
    reportName: reportName,
    copyConclusion: copyConclusion,
    captureCommand: captureCommand,
    sevKind: sevKind
  };
})(window.ND = window.ND || {});
