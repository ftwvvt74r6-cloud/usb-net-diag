/* ============================================================================
   reporter.js · 可分析报告的**唯一**构建器（md / 复制文本 / json 同源）
   ----------------------------------------------------------------------------
   以前的「复制给协作方 / 导出报告」只有结论与边界两段，工程师拿到文件没法复核：
   「说丢包 5%，哪来的 5%？重传几次？DNS 多少毫秒？」——这一层把同一份模型同时
   序列化成 markdown、纯文本、json，三份内容不可能不一致。

   固定七段（顺序不许动，前端页面与导出文件对齐）：
     1 标题 + 时间 + 采样上下文（报文数 / 会话数 / 时长 / 网卡 / 模式 / 目标）
     2 结论（一句话定性 + 影响范围）
     3 关键指标表（**必须数值**，取数与页面同一份 ND.metrics.rows）
     4 证据明细（层级 / 现象 / 关键数值 / 判定 / 证据帧）
     5 数据表（Top 会话 + 网络参数）
     6 技术上下文（抓包命令与完整 BPF / 探针 / 样本数 / 采样窗口）
     7 边界与置信度（只留两行，不占主体）

   「依据 / 本次覆盖 / 明确未覆盖」不再进正文 —— 它们是页面上的复核辅助，
   导出文件里只保留最要紧的两行（适用范围 + 置信度）。

   JSON 保留全部原始字段（metrics / rows / verdict / meta / l7_packets / wlan），
   不做裁剪：下游要复算，就得拿到原料。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var E = C.exporter || {};
  var RP = C.report || {};

  function n(v) {
    if (v === null || v === undefined || v === "") return null;
    var x = Number(v);
    return isFinite(x) ? x : null;
  }

  function num(v, d) {
    var x = n(v);
    return x === null ? null : x.toFixed(d === undefined ? 0 : d);
  }

  /* copy.unit.* 里带前导空格（给 dur() 直接拼），这里要自己控制分隔 */
  function secUnit() {
    return String(((C.unit || {}).sec) || "秒").trim();
  }

  function txt(v, fallback) {
    if (v === null || v === undefined || v === "") return fallback === undefined ? (E.noData || "—") : fallback;
    return String(v);
  }

  function pick() {
    for (var i = 0; i < arguments.length; i++) {
      var v = arguments[i];
      if (v !== null && v !== undefined && v !== "" && isFinite(Number(v))) return Number(v);
    }
    return null;
  }

  /* 时间戳一律写成绝对值：导出文件会被转发到别人的机器上，「今天 14:03」没意义 */
  function stamp(job, res) {
    var meta = (res && res.meta) || {};
    var raw = meta.generated_at;
    if (raw && /^\d{4}-\d{2}-\d{2}/.test(String(raw))) return String(raw);
    var epoch = n(job && job.epoch) || n(res && res.epoch) || n(meta.epoch);
    var d = epoch ? new Date(epoch * 1000) : new Date();
    if (isNaN(d.getTime())) d = new Date();
    function p(x) { return x < 10 ? "0" + x : String(x); }
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " +
      p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }

  /* 证据帧：行里的 evidence 形如「10.0.0.5:8080（SYN 3 包）｜帧 #35,#36,#53」 */
  function framesOf(x) {
    var out = [];
    if (x && x.frames && x.frames.length) out = x.frames.map(String);
    if (!out.length) {
      var m = String((x && x.evidence) || "").match(/帧\s*#?\s*([0-9][0-9\s,#]*)/);
      if (m) out = (m[1].match(/\d+/g) || []);
    }
    out = out.filter(function (s) { return s; });
    return out.slice(0, 8);
  }

  function framesText(list) {
    if (!list || !list.length) return "";
    return list.map(function (f) { return "#" + f; }).join(", ");
  }

  /* ------------------------------------------------------------ 段 4：证据 */
  function framesByStream(meta, text) {
    var m = String(text || "").match(/Stream\s+(\d+)/i);
    if (!m) return [];
    var hit = null;
    (meta.streams_top || []).forEach(function (s) {
      if (String(s && s.stream) === m[1]) hit = s;
    });
    return hit && hit.frames ? hit.frames.map(String).slice(0, 8) : [];
  }

  function evidenceOf(res) {
    var rows = (res && res.rows) || [];
    var list = rows.filter(function (x) { return x && (x.finding || x.title); });
    if (!list.length) {
      var v = (res && res.verdict) || {};
      list = (v.points || []).filter(function (x) { return x && (x.title || x.finding); });
    }
    var sev = C.sev || {};
    var rank = function (s) {
      return s === sev.critical ? 0 : (s === sev.warning ? 1 : 2);
    };
    var meta = (res && res.meta) || {};
    var out = list.map(function (x) {
      var layer = [x.layer, x.protocol].filter(function (s) {
        return s && String(s).trim() && String(s).trim() !== "—";
      }).join(" · ");
      var num = x.evidence || x.proof || "";
      var frames = framesOf(x);
      if (!frames.length) frames = framesByStream(meta, num);
      return {
        layer: layer || "",
        what: x.finding || x.title || "",
        num: num,
        judge: x.severity || "",
        frames: frames
      };
    });
    out.sort(function (a, b) { return rank(a.judge) - rank(b.judge); });
    return out;
  }

  /* ------------------------------------------------------------ 段 5：数据 */
  function sessionsOf(meta, limit) {
    var top = (meta.streams_top || []).slice();
    var out = top.slice(0, limit).map(function (s) {
      var src = String(s.client || "");
      var dst = String(s.server || "") + (s.dport ? ":" + s.dport : "");
      return {
        flow: src + " → " + dst,
        pkts: s.packets,
        bytes: s.bytes,
        rtt: n(s.rtt_avg),
        retrans: s.retrans
      };
    });
    return { rows: out, more: Math.max(0, top.length - out.length), total: top.length };
  }

  /* 网络参数：本机可采集字段（SSID / AP MAC / 频段 / 信道 / 协议 / RSSI /
     协商速率 / 网关 RTT / 抖动 / 丢包）。拿不到的写「—」，不编。 */
  function netOf(snap) {
    if (!snap) return null;
    var w = snap.wlan || {};
    var h = snap.host || {};
    var pr = snap.probe || {};
    var L = E;
    var rows = [];
    function add(k, v, unit) {
      rows.push({ k: k, v: v === null || v === undefined || v === "" ? (E.noData || "—") : (String(v) + (unit || "")) });
    }
    add(L.netSsid, w.ssid);
    add(L.netBssid, w.bssid);
    add(L.netBand, w.band);
    add(L.netChannel, w.channel);
    add(L.netRadio, w.radio);
    add(L.netRssi, n(w.rssi_dbm), " dBm");
    add(L.netRate, (w.rx_mbps === null || w.rx_mbps === undefined) && (w.tx_mbps === null || w.tx_mbps === undefined)
      ? null
      : txt(w.rx_mbps, "—") + " / " + txt(w.tx_mbps, "—"), " Mbps");
    add(L.netLocal, h.local_ip);
    add(L.netGateway, h.gateway);
    add(L.netGwRtt, n(pr.rtt_ms), " ms");
    add(L.netGwJitter, n(pr.jitter_ms), " ms");
    add(L.netGwLoss, n(pr.loss_pct), " %");
    return rows;
  }

  /* ------------------------------------------------------------ 段 6：技术上下文 */
  function techOf(job, res) {
    var meta = (res && res.meta) || {};
    var metrics = (res && res.metrics) || {};
    var out = [];
    var cmd = ND.render && ND.render.captureCommand ? ND.render.captureCommand(meta) : "";
    out.push([E.techCommand, cmd || (E.techCommandNone || "")]);
    var bpf = String(meta.bpf || "").trim();
    var bpfOk = bpf && !/[^\x00-\x7F]/.test(bpf);      /* BPF 只能是 ASCII，中文是后端塞的模式文案 */
    out.push([E.techBpf, bpfOk ? bpf : (C.tech || {}).valueMissing || ""]);

    var pb = meta.probe_baseline;
    out.push([E.techProbe, pb
      ? U.tpl(E.probeVal || "", {
          sent: txt(num(pb.sent, 0)), recv: txt(num(pb.recv, 0)), timeout: txt(num(pb.timeout, 0))
        })
      : (E.probeNone || "")]);

    out.push([E.techSamples, U.tpl(E.techSamplesVal || "", {
      rtt: txt(num(metrics.rtt_samples, 0)), hs: txt(num(metrics.hs_samples, 0)),
      dns: txt(num(metrics.dns_samples, 0)), http: txt(num(metrics.http_samples, 0))
    })]);

    var win = num(pick(meta.duration, meta.capture_duration), 0);
    var set = n(meta.capture_duration);
    out.push([E.techWindow, set > 0
      ? U.tpl(E.techWindowVal || "", { dur: txt(win), set: txt(num(set, 0)) })
      : (txt(win) + " " + secUnit())]);
    return out;
  }

  /* ------------------------------------------------------------ 模型 */
  function build(job) {
    var res = (job && job.result) || null;
    if (!res) return null;
    var meta = res.meta || {};
    var vm = (ND.verdict && ND.verdict.build) ? ND.verdict.build(job) : null;
    if (!vm) return null;

    var summary = res.summary || {};
    var mode = job.mode || (job && job.ui_mode) || "";
    var target = summary.target || meta.target || "";
    if (!target && meta.pcap_name) target = meta.pcap_name;

    var head = [
      [E.generatedAt, stamp(job, res)],
      [E.reportId, txt(res.report_id || job.report_id, "")]
    ];
    var ctx = [
      [E.ctxPackets, txt(num(meta.packets, 0))],
      [E.ctxStreams, txt(num(meta.streams_total, 0))],
      [E.ctxDuration, txt(num(pick(meta.duration, meta.capture_duration), 0)) + " " + secUnit()],
      [E.ctxIface, txt(meta.interface, (E.noData || "—"))],
      [E.ctxMode, U.modeLabel(mode) || (E.noData || "—")],
      [E.ctxTarget, txt(target)]
    ];

    var own = vm.owner && vm.owner.key ? vm.owner : null;
    var cell = null;
    if (own) {
      own.cells.forEach(function (c) { if (c.on) cell = c; });
    }

    var metrics = (ND.metrics && ND.metrics.rows) ? ND.metrics.rows(res, { budget: false }) : [];
    var l7o = (ND.metrics && ND.metrics.l7) ? ND.metrics.l7(res) : null;

    return {
      head: head,
      context: ctx,
      title: vm.title,
      problem: vm.problem,
      scope: vm.scopeLabel,
      boundary: vm.boundary,
      confidence: vm.confidence,
      steps: (vm.steps || []).map(function (s) { return s.text; }),
      owner: cell ? { label: cell.label, basis: cell.basis, ask: cell.partner } : null,
      metrics: metrics.map(function (r) {
        /* L7 这一格在导出文件里带上样本数（HTTP 38 包 / 70%），
           表格里那种「HTTP 70%」看不出统计基数 */
        var l7row = (r.key === "mL7" && l7o);
        var val = l7row ? ND.metrics.l7TextFull(l7o) : r.value;
        /* 导出不写「（按报文数）」这种括号补丁，直接用一句话说明口径 */
        if (l7row) val += " · " + (l7o.basis === "packets" ? (RP.mL7PacketsNote || "") : (RP.mL7SessionsNote || ""));
        return {
          k: r.label,
          v: val,
          u: r.unit,
          state: r.state,
          judge: r.state ? ND.metrics.stateText(r.state) : "",
          flag: l7row ? "" : r.flag
        };
      }),
      l7: l7o,
      evidence: evidenceOf(res),
      sessions: sessionsOf(meta, 10),
      net: netOf(ND.wifi && ND.wifi.snapshot ? ND.wifi.snapshot() : null),
      tech: techOf(job, res),
      tail: [
        [E.boundary, vm.boundary || ""],
        [E.confidence, vm.confidence || ""]
      ],
      reportId: res.report_id || job.report_id || ""
    };
  }

  /* ------------------------------------------------------------ 序列化：markdown */
  function cellText(s) {
    return String(s === null || s === undefined ? "" : s).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
  }

  function mdTable(headers, rows) {
    var out = [];
    out.push("| " + headers.map(cellText).join(" | ") + " |");
    out.push("| " + headers.map(function () { return "---"; }).join(" | ") + " |");
    rows.forEach(function (r) {
      out.push("| " + r.map(cellText).join(" | ") + " |");
    });
    return out.join("\n");
  }

  function md(model) {
    var L = [];
    var E2 = E;

    /* 1 标题 + 时间 + 采样上下文 */
    L.push("# " + (E2.title || "") + " · " + model.title);
    L.push("");
    model.head.forEach(function (kv) {
      if (!kv[1]) return;
      L.push("- " + kv[0] + "：" + kv[1]);
    });
    L.push("- " + (E2.context || "") + "：" + model.context.map(function (kv) {
      return kv[0] + " " + kv[1];
    }).join(" · "));
    L.push("");

    /* 2 结论 */
    L.push("## 1 " + (E2.sec1 || ""));
    L.push("");
    L.push("**" + model.problem + "**");
    L.push("");
    L.push("- " + (E2.scope || "") + "：" + (model.scope || "—"));
    if (model.steps.length) {
      L.push("");
      L.push((E2.steps || "") + "：");
      L.push("");
      model.steps.forEach(function (s, i) { L.push((i + 1) + ". " + s); });
    }
    if (model.owner) {
      L.push("");
      L.push((E2.owner || "") + "：**" + model.owner.label + "**");
      if (model.owner.basis) L.push("- " + (E2.basis || "") + "：" + model.owner.basis);
      if (model.owner.ask) L.push("- " + (E2.ask || "") + "：" + model.owner.ask);
    }
    L.push("");

    /* 3 关键指标 */
    L.push("## 2 " + (E2.sec2 || "") );
    L.push("");
    L.push(mdTable(
      [E2.colItem || "", E2.colValue || "", E2.colJudge || ""],
      model.metrics.map(function (r) {
        var v = String(r.v) + (r.u || "") + (r.flag ? "（" + r.flag + "）" : "");
        return [r.k, v, r.judge || "—"];
      })
    ));
    L.push("");

    /* 4 证据明细 */
    L.push("## 3 " + (E2.sec3 || ""));
    L.push("");
    if (!model.evidence.length) {
      L.push((C.report || {}).evEmpty || "");
    } else {
      L.push(mdTable(
        [E2.colLayer || "", E2.colWhat || "", E2.colNum || "", E2.colJudge || "", E2.colFrame || ""],
        model.evidence.map(function (e) {
          return [e.layer || "—", e.what, e.num || "—", e.judge || "—", framesText(e.frames) || "—"];
        })
      ));
    }
    L.push("");

    /* 5 数据表 */
    L.push("## 4 " + (E2.sec4 || ""));
    L.push("");
    L.push("### 4.1 " + (E2.sessions || ""));
    L.push("");
    if (!model.sessions.rows.length) {
      L.push((C.panel || {}).empty || "");
    } else {
      L.push(mdTable(
        [E2.colFlow || "", E2.colPkts || "", E2.colBytes || "", E2.colRtt || "", E2.colRetrans || ""],
        model.sessions.rows.map(function (s) {
          return [
            s.flow,
            txt(num(s.pkts, 0)),
            U.size(s.bytes) || "—",
            s.rtt === null ? "—" : s.rtt.toFixed(1) + " ms",
            txt(num(s.retrans, 0))
          ];
        })
      ));
      if (model.sessions.more) {
        L.push("");
        L.push(U.tpl(E2.sessionsMore || "", { n: model.sessions.total, k: model.sessions.rows.length }));
      }
    }
    L.push("");
    L.push("### 4.2 " + (E2.netTitle || ""));
    L.push("");
    if (!model.net) {
      L.push(E2.netEmpty || "");
    } else {
      L.push(mdTable([E2.colItem || "", E2.colValue || ""], model.net.map(function (r) { return [r.k, r.v]; })));
    }
    L.push("");

    /* 6 技术上下文 */
    L.push("## 5 " + (E2.sec5 || ""));
    L.push("");
    model.tech.forEach(function (kv) {
      L.push("- " + kv[0] + "：" + (kv[1] || "—"));
    });
    L.push("");

    /* 7 边界与置信度：只留两行 */
    L.push("## 6 " + (E2.sec6 || ""));
    L.push("");
    model.tail.forEach(function (kv) {
      if (!kv[1]) return;
      L.push("- " + kv[0] + "：" + kv[1]);
    });
    L.push("");
    return L.join("\n");
  }

  /* ------------------------------------------------------------ 序列化：纯文本 */
  /* 给聊天窗口用：不用管道表格（微信/企微里会散架），一行一项 */
  function text(model) {
    var L = [];
    L.push((E.title || "") + " · " + model.title);
    model.head.forEach(function (kv) { if (kv[1]) L.push(kv[0] + "：" + kv[1]); });
    L.push((E.context || "") + "：" + model.context.map(function (kv) { return kv[0] + " " + kv[1]; }).join(" · "));
    L.push("");

    L.push("一、" + (E.sec1 || ""));
    L.push(model.problem);
    L.push((E.scope || "") + "：" + (model.scope || "—"));
    if (model.steps.length) {
      L.push((E.steps || "") + "：");
      model.steps.forEach(function (s, i) { L.push("  " + (i + 1) + ". " + s); });
    }
    if (model.owner) {
      L.push((E.owner || "") + "：" + model.owner.label);
      if (model.owner.basis) L.push("  " + (E.basis || "") + "：" + model.owner.basis);
      if (model.owner.ask) L.push("  " + (E.ask || "") + "：" + model.owner.ask);
    }
    L.push("");

    L.push("二、" + (E.sec2 || ""));
    model.metrics.forEach(function (r) {
      L.push("  " + r.k + "：" + r.v + (r.u || "") + (r.flag ? "（" + r.flag + "）" : "") + (r.judge ? "　" + r.judge : ""));
    });
    L.push("");

    L.push("三、" + (E.sec3 || ""));
    if (!model.evidence.length) L.push("  " + ((C.report || {}).evEmpty || ""));
    model.evidence.forEach(function (e, i) {
      L.push("  " + (i + 1) + ". [" + (e.layer || "—") + "] " + e.what);
      L.push("     " + (e.num || "—") + "　" + (e.judge || "—") + (e.frames.length ? "　" + framesText(e.frames) : ""));
    });
    L.push("");

    L.push("四、" + (E.sec4 || ""));
    if (model.sessions.rows.length) {
      model.sessions.rows.forEach(function (s) {
        L.push("  " + s.flow + "　包 " + txt(num(s.pkts, 0)) + "　" + (U.size(s.bytes) || "—") +
          "　RTT " + (s.rtt === null ? "—" : s.rtt.toFixed(1) + " ms") + "　重传 " + txt(num(s.retrans, 0)));
      });
      if (model.sessions.more) {
        L.push("  " + U.tpl(E.sessionsMore || "", { n: model.sessions.total, k: model.sessions.rows.length }));
      }
    }
    if (model.net) {
      L.push("  " + (E.netTitle || "") + "：");
      model.net.forEach(function (r) { L.push("    " + r.k + "：" + r.v); });
    } else {
      L.push("  " + (E.netEmpty || ""));
    }
    L.push("");

    L.push("五、" + (E.sec5 || ""));
    model.tech.forEach(function (kv) { L.push("  " + kv[0] + "：" + (kv[1] || "—")); });
    L.push("");

    L.push("六、" + (E.sec6 || ""));
    model.tail.forEach(function (kv) { if (kv[1]) L.push("  " + kv[0] + "：" + kv[1]); });
    return L.join("\n");
  }

  /* ------------------------------------------------------------ 序列化：json */
  /* 全量保留：一份原始结果 + 页面算出来的口径说明。下游要复算就得拿到原料。 */
  function json(job) {
    var res = (job && job.result) || {};
    var model = build(job);
    var out = {
      schema: "nd-report/1",
      generated_at: stamp(job, res),
      report_id: res.report_id || (job && job.report_id) || "",
      mode: (job && job.mode) || "",
      mode_label: U.modeLabel(job && job.mode),
      /* 名字不叫 conclusion：原始 result 可能自带后端给的 conclusion 块，
         那个字段要原样保留（下面 Object.keys 会把它带进来） */
      ui_conclusion: model ? {
        headline: model.title,
        problem: model.problem,
        scope: model.scope,
        boundary: model.boundary,
        confidence: model.confidence,
        steps: model.steps,
        owner: model.owner
      } : null
    };
    /* 原始字段原样带上（不裁剪），新增字段只加不改 */
    var raw = res || {};
    Object.keys(raw).forEach(function (k) {
      if (out[k] === undefined) out[k] = raw[k];
    });
    out.metrics_rows = model ? model.metrics : [];
    out.l7_packets = res.l7_packets || null;
    out.l7_basis = model && model.l7 ? model.l7.basis : "";
    out.wlan = (ND.wifi && ND.wifi.snapshot ? ND.wifi.snapshot() : null) || null;
    out.probe_baseline = (res.meta || {}).probe_baseline || null;
    try {
      return JSON.stringify(out, null, 2);
    } catch (e) {
      /* 理论上不会发生；真遇到循环引用就退成「只带结论」的版本，不给空文件 */
      return JSON.stringify({ schema: "nd-report/1", generated_at: out.generated_at, error: "serialize" }, null, 2);
    }
  }

  /* ------------------------------------------------------------ 导出 */
  /* 网络参数是异步来的：点导出时如果还没读到，先补一次再落盘，
     免得导出的文件里「网络参数」整段是空的。 */
  function ensureWifi() {
    if (!ND.wifi) return Promise.resolve();
    if (ND.wifi.snapshot && ND.wifi.snapshot()) return Promise.resolve();
    if (!ND.wifi.load) return Promise.resolve();
    return Promise.resolve(ND.wifi.load(false)).catch(function () { /* 读不到就按空处理 */ });
  }

  function download(job, kind) {
    var model = build(job);
    if (!model) {
      U.toast(E.exportNone || "", "warn");
      return Promise.resolve(false);
    }
    return ensureWifi().then(function () {
      model = build(job) || model;
      var body = kind === "json" ? json(job) : md(model);
      ND.render.saveText(ND.render.reportName(job, kind === "json" ? "json" : "md"), body);
      return true;
    });
  }

  /* 复制给协作方：纯文本版，内容和 md 逐段对齐 */
  function copy(job) {
    var model = build(job);
    if (!model) {
      U.toast(E.exportNone || "", "warn");
      return Promise.resolve(false);
    }
    return ensureWifi().then(function () {
      model = build(job) || model;
      return U.copyText(text(model)).then(function (ok) {
        U.toast(ok ? (E.copyOk || "") : (E.copyFail || ""), ok ? "ok" : "crit");
        return ok;
      });
    });
  }

  ND.reporter = {
    build: build,
    md: md,
    text: text,
    json: json,
    download: download,
    copy: copy
  };
})(window.ND = window.ND || {});
