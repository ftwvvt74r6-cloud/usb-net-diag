/* ============================================================================
   metricstable.js · 「关键指标」的唯一来源
   ----------------------------------------------------------------------------
   为什么单独一层：同一张表有三个消费者 —— 三段报告的 ② 证据段、导出构建器
   （md / 复制 / json）、专业数据面板。三处各写一遍取数逻辑，迟早出现
   「页面 5.56%、导出文件 5.6%」这种对不上的事故。

   规矩：
   · rows(res) 只出**数值**，不出「表现是：很卡」这类定性话术 —— 工程师要能复核；
   · 阈值色只标「超阈值」，同屏最多 3 处（超出按严重度竞争，落选的降为中性）；
     十几个数字全染色等于没染色；
   · 缺值写 null，由渲染层统一显示「—」；不许拿 0 冒充「没测到」；
   · 丢包率只认探针基线（1 - 收到/发出）。没发探针就写「未启用探针」，
     不拿重传率冒充丢包率 —— 两者口径不同，混用会让结论失真；
   · 同一个数字在不同原因下含义不同：目标不回 ICMP（后端 roles[].reason 已判）
     时，探针的 100% 只说明「目标不理 ICMP」，那行不许染色，也不许写「异常」，
     否则与结论卡自相矛盾。改口径不改数字 —— 工程师复核时看到的必须还是原值。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var RP = C.report || {};
  var P = C.panel || {};

  var MAX_MARKS = 3;

  function n(v) {
    if (v === null || v === undefined || v === "") return null;
    var x = Number(v);
    return isFinite(x) ? x : null;
  }

  function num(v, d) {
    var x = n(v);
    return x === null ? null : x.toFixed(d === undefined ? 0 : d);
  }

  function pick() {
    for (var i = 0; i < arguments.length; i++) {
      var v = arguments[i];
      if (v !== null && v !== undefined && v !== "" && isFinite(Number(v))) return Number(v);
    }
    return null;
  }

  /* 阈值：等于或超过 crit 判异常，等于或超过 warn 判关注 */
  function grade(v, warn, crit) {
    var x = n(v);
    if (x === null) return "";
    if (x >= crit) return "crit";
    if (x >= warn) return "warn";
    return "ok";
  }

  function stateText(s) {
    return s === "crit" ? (RP.stCrit || "") : (s === "warn" ? (RP.stWarn || "") : (s === "ok" ? (RP.stOk || "") : ""));
  }

  /* ------------------------------------------------------------ L7 分布 */
  /* 口径优先级：报文数（result.l7_packets，basis=packets）> 会话数（streams_top 的 app 计数）。
     报文数是后端新口径；老结果没有这个字段时回退会话数，并在表内注明，
     不把两种口径混成同一个百分比。 */
  function bucketNum(x) {
    if (typeof x === "number") return isFinite(x) ? x : null;
    if (x && typeof x === "object") {
      return pick(x.packets, x.n, x.count, x.value, x.total);
    }
    return null;
  }

  function l7Buckets(src) {
    var out = [];
    [["tls", P.l7Tls || "TLS"], ["http", P.l7Http || "HTTP"], ["other", P.l7Other || "其他"]].forEach(function (pair) {
      var raw = src[pair[0]];
      var cnt = bucketNum(raw);
      if (cnt === null) return;
      var pct = raw && typeof raw === "object" ? n(raw.pct) : null;
      out.push({ key: pair[0], label: pair[1], n: cnt, pct: pct });
    });
    if (!out.length) return null;
    var sum = 0;
    out.forEach(function (b) { sum += b.n; });
    if (sum <= 0) return null;
    out.forEach(function (b) {
      if (b.pct === null) b.pct = b.n * 100 / sum;
    });
    return out;
  }

  /* res.l7_packets 允许两种写法：
       { basis: "packets", tls: 1234, http: 234, other: 45 }
       { basis: "packets", tls: { packets: 1234, pct: 78 }, ... } */
  function l7(res) {
    var meta = (res && res.meta) || {};
    var lp = res && res.l7_packets;
    if (lp && typeof lp === "object") {
      var byPkt = l7Buckets(lp);
      if (byPkt) {
        return {
          basis: "packets",
          buckets: byPkt,
          total: lp.total !== undefined ? n(lp.total) : null,
          note: RP.mL7ByPackets || "",
          caption: RP.mL7ByPackets || ""
        };
      }
    }
    var top = meta.streams_top || [];
    if (!top.length) return null;
    var cnt = { tls: 0, http: 0, other: 0 };
    top.forEach(function (s) {
      var a = String((s && s.app) || "").toUpperCase();
      if (a === "TLS") cnt.tls++;
      else if (a === "HTTP") cnt.http++;
      else cnt.other++;
    });
    var bySes = l7Buckets(cnt);
    if (!bySes) return null;
    var total = n(meta.streams_total);
    return {
      basis: "sessions",
      buckets: bySes,
      total: total,
      sampled: top.length,
      note: RP.mL7BySessions || "",
      caption: top.length < (total || 0)
        ? (RP.mL7Sample || "") : (RP.mL7BySessions || "")
    };
  }

  /* 表格里那一格：紧凑写法（TLS 78% · HTTP 12%） */
  function l7Text(l7obj) {
    if (!l7obj) return (C.panel || {}).noData || "—";
    var on = l7obj.buckets.filter(function (b) { return b.n > 0; });
    return (on.length ? on : l7obj.buckets).map(function (b) {
      return (b.label || "") + " " + Math.round(b.pct) + "%";
    }).join(" · ");
  }

  /* 导出文件里那一行：带样本数（TLS 1,234 包 / 78%） */
  function l7TextFull(l7obj) {
    if (!l7obj) return "—";
    var unit = l7obj.basis === "packets" ? (RP.unitPkt || "") : (RP.unitSes || "");
    var on = l7obj.buckets.filter(function (b) { return b.n > 0; });
    return (on.length ? on : l7obj.buckets).map(function (b) {
      return (b.label || "") + " " + fmtInt(b.n) + unit + "（" + Math.round(b.pct) + "%）";
    }).join(" · ");
  }

  function fmtInt(v) {
    var x = n(v);
    if (x === null) return "—";
    return String(Math.round(x)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  /* ------------------------------------------------------------ 丢包率的口径 */
  /* 数字与判定要分开：8 发 0 收确实是 100%，但「100%」在不同原因下含义相反 ——
     链路真丢了，还是目标不理 ICMP（服务器侧策略）？后者在结论卡里已经写明
     「目标不回 ICMP」，指标表却把同一件事标成红色「异常」，同屏自相矛盾；
     导出文件里更只剩一个 100%，被转发出去就是「你这网丢了 100% 的包」。

     只认后端给的两条证据：分角色探针的 reason == "icmp_filtered"，或路径剖面
     的 target_icmp_filtered。本轮不导出 / 不复用结论卡那层判定（下一轮的事）；
     这里只负责把「这个数该怎么解释」落到 rows() 的 mLoss 行上 —— rows() 是
     页面、导出 md、导出 json 的唯一来源，改一处三处一致。 */
  function lossFiltered(meta) {
    var m = meta || {};
    var roles = (m.probe_baseline || {}).roles || [];
    for (var i = 0; i < roles.length; i++) {
      if (String((roles[i] || {}).reason || "") === "icmp_filtered") return true;
    }
    return !!(m.path_profile || {}).target_icmp_filtered;
  }

  /* ------------------------------------------------------------ 行模型 */
  /* judge 是「判定列写什么」的覆盖值：多数行由 stateText(state) 推出来，
     但「DNS 9/0 无响应」这类事实不能写成通用的「异常」——页面、导出 md、
     导出 json 都读同一个字段，才不会页面写「无响应」、导出写「异常」。 */
  function row(key, value, unit, state, flag, judge) {
    return {
      key: key,
      label: RP[key] || "",
      value: value === null || value === undefined ? "—" : value,
      unit: value === null || value === undefined ? "" : (unit || ""),
      state: state || "",
      flag: flag || "",
      judge: judge || ""
    };
  }

  /* 12 项：RTT 均值 / P95 / 抖动、丢包率、重传率、重复 ACK、RST、零窗口、
     DNS 查询/响应、DNS 耗时、DNS 失败率、L7 分布。全部给数值。 */
  function rows(res, opts) {
    var meta = (res && res.meta) || {};
    var metrics = (res && res.metrics) || {};
    var out = [];

    var rtt = pick(metrics.rtt_avg_ms, meta.rtt_avg_ms);
    out.push(row("mRtt", num(rtt, 1), " ms", grade(rtt, 100, 200)));

    var p95 = pick(metrics.rtt_p95_ms, meta.rtt_p95_ms);
    out.push(row("mRttP95", num(p95, 1), " ms", grade(p95, 200, 400)));

    var jit = pick(metrics.rtt_jitter_ms, meta.rtt_jitter_ms);
    out.push(row("mJitter", num(jit, 1), " ms", grade(jit, 30, 80)));

    var pb = meta.probe_baseline;
    var loss = null;
    if (pb && n(pb.sent) > 0) loss = Math.max(0, (1 - (n(pb.recv) || 0) / n(pb.sent)) * 100);
    if (loss === null) {
      out.push({
        key: "mLoss", label: RP.mLoss || "",
        value: RP.mLossNone || "—", unit: "", state: "", flag: ""
      });
    } else if (lossFiltered(meta)) {
      /* 数值照实给（不改数字），但不给 state：不标红/琥珀，判定列也不写「异常」——
         同一屏上「结论：目标不回 ICMP」与「丢包率 100% 异常」是两句互相打脸的话。
         为什么会有这么个数，由 flag 说清楚（页面、导出 md、导出 json 同一份）。 */
      out.push(row("mLoss", loss.toFixed(1), " %", "", RP.mLossIcmp || ""));
    } else {
      out.push(row("mLoss", loss.toFixed(1), " %", grade(loss, 1, 3), RP.mLossProbe || ""));
    }

    var rt = pick(meta.retrans_rate, metrics.retrans_rate);
    out.push(row("mRetrans", num(rt, 2), " %", grade(rt, 1, 3)));

    /* 重复 ACK：次数是主值，占比是补充（后端两种都给，别只显示一半） */
    var dupRate = n(metrics.dup_ack_rate);
    out.push({
      key: "mDupAck", label: RP.mDupAck || "",
      value: num(meta.dup_ack, 0) === null ? "0" : num(meta.dup_ack, 0),
      unit: dupRate === null ? "" : " · " + dupRate.toFixed(2) + " %",
      state: grade(n(meta.dup_ack), 3, 10), flag: ""
    });

    /* RST：≥10 次异常、2~9 关注、<2 中性。原来的 1/5 会把「2 次」直接染红 */
    out.push(row("mRst", num(meta.rst, 0) === null ? "0" : num(meta.rst, 0), " 次", grade(n(meta.rst), 2, 10)));
    out.push(row("mZeroWin", num(meta.zero_win, 0) === null ? "0" : num(meta.zero_win, 0), " 次", grade(n(meta.zero_win), 1, 3)));

    /* DNS 无响应是一条独立事实：9 发 0 收时「耗时 0 ms」「失败率 0 %」都是
       **没测到**，不是「测到很快」。同屏出现「DNS 9 / 0」+ 绿点「正常 · 0 ms」
       会直接误导。证据优先级：后端显式 dns_noresp → fail_rate>=100 →
       这两个字段缺失时按 dns_resp==0 兜底（B 后续会补前两个字段）。 */
    var dnsTotal = n(meta.dns_total);
    var dnsResp = n(meta.dns_resp);
    var dnsFailVal = pick(meta.dns_fail_rate, metrics.dns_fail_rate);
    var dnsNoResp = false;
    if (dnsTotal !== null && dnsTotal > 0) {
      if (meta.dns_noresp === true) dnsNoResp = true;
      else if (meta.dns_noresp === false) dnsNoResp = false;
      else if (dnsFailVal !== null && dnsFailVal >= 100) dnsNoResp = true;
      else dnsNoResp = (dnsResp === 0);
    }
    out.push({
      key: "mDns", label: RP.mDns || "",
      value: (dnsTotal === null ? "0" : String(Math.round(dnsTotal))) + " / " +
             (dnsResp === null ? "0" : String(Math.round(dnsResp))),
      unit: "", state: dnsNoResp ? "crit" : "", flag: "",
      judge: dnsNoResp ? (RP.mDnsNoResp || "") : ""
    });

    var dnsMs = pick(meta.dns_avg_ms, metrics.dns_avg_ms);
    if (dnsNoResp) {
      /* 无响应时这两格没有实测值：写「—」且中性，不写 0 ms / 0 % / 正常 / 绿点 */
      out.push(row("mDnsMs", "—", "", "", ""));
      out.push(row("mDnsFail", "—", "", "", ""));
    } else {
      out.push(row("mDnsMs", num(dnsMs, 0), " ms", grade(dnsMs, 100, 300)));
      out.push(row("mDnsFail", num(dnsFailVal, 1), " %", grade(dnsFailVal, 20, 50)));
    }

    var L = l7(res);
    out.push({
      key: "mL7", label: RP.mL7 || "",
      value: L ? l7Text(L) : ((C.panel || {}).noData || "—"),
      unit: "", state: "", flag: L ? L.caption : ""
    });

    /* 页面用预算（同屏最多 3 处颜色）；导出文件 budget:false ——
       报告是给人复核的，超阈值的每一项都必须标出来 */
    if (opts && opts.budget === false) {
      out.forEach(function (r) { r.mark = r.state === "warn" || r.state === "crit" || r.state === "ok"; });
      return out;
    }
    return budget(out);
  }

  /* 颜色预算严格 ≤3：参与竞争的**只有** warn / crit（「关注」就是 warn），
     ok 既不占预算也不给颜色 —— 以前 r.mark = r.state === "ok" 会让满屏小绿点，
     十几个「正常」比真正超阈值的三项还扎眼，等于把预算架空。
     按严重度取前 3（crit 优先），其余一律 dim；判定文字照写，只收颜色。 */
  function budget(list) {
    var cand = list.filter(function (r) { return r.state === "warn" || r.state === "crit"; });
    var ranked = cand.slice().sort(function (a, b) {
      var ra = a.state === "crit" ? 2 : 1;
      var rb = b.state === "crit" ? 2 : 1;
      return rb - ra;
    });
    var keep = {};
    ranked.slice(0, MAX_MARKS).forEach(function (r) { keep[r.key] = 1; });
    list.forEach(function (r) {
      r.mark = (r.state === "warn" || r.state === "crit") && !!keep[r.key];
    });
    return list;
  }

  /* ------------------------------------------------------------ 渲染 */
  /* 标记：CSS 类 mt-table / mt-k / mt-v / mt-u / mt-flag / mt-s / mt-dot */
  function table(res) {
    var list = rows(res);
    var tbl = U.el("table", "mt-table");
    var thead = document.createElement("thead");
    var hr = document.createElement("tr");
    [RP.colItem, RP.colValue, RP.colState].forEach(function (t) {
      hr.appendChild(U.el("th", "", t || ""));
    });
    thead.appendChild(hr);
    tbl.appendChild(thead);

    var tb = document.createElement("tbody");
    list.forEach(function (r) {
      var tr = document.createElement("tr");
      if (r.mark && (r.state === "warn" || r.state === "crit")) tr.className = "is-" + r.state;
      tr.appendChild(U.el("td", "mt-k", r.label));

      var vd = U.el("td", "mt-v");
      vd.appendChild(U.el("b", "mono", r.value));
      if (r.unit) vd.appendChild(U.el("span", "mt-u", r.unit));
      if (r.flag) vd.appendChild(U.el("span", "mt-flag", r.flag));
      tr.appendChild(vd);

      var sd = U.el("td", "mt-s" + (r.mark ? "" : " dim"));
      if (r.state) {
        /* 超过 3 处预算的行只去掉颜色，判定文字照写 */
        if (r.mark) sd.appendChild(U.el("i", "mt-dot " + r.state));
        sd.appendChild(U.el("span", "", r.judge || stateText(r.state)));
      } else {
        sd.textContent = "—";
      }
      tr.appendChild(sd);
      tb.appendChild(tr);
    });
    tbl.appendChild(tb);
    return tbl;
  }

  ND.metrics = {
    rows: rows,
    table: table,
    l7: l7,
    l7Text: l7Text,
    l7TextFull: l7TextFull,
    stateText: stateText,
    grade: grade,
    fmtInt: fmtInt,
    MAX_MARKS: MAX_MARKS
  };
})(window.ND = window.ND || {});
