/* ============================================================================
   verdict.js · 结论区「一眼三层」（业务渲染层）
   ----------------------------------------------------------------------------
   为什么单独一层：render.js 只该知道「一块内容长什么样」，而这一块要**判断**
   —— 哪一层坏了、影响多大、先做哪三步、该找谁。判断逻辑集中在这里，
   render.js 保持无业务、modes/home 只负责把它挂上去。

   三层的硬规矩（改文案前先看这里）：
   · 第一层横幅：标题 ≤14 字、问题句 ≤40 字；标题说「哪一层」，问题句说「影响」
   · 第二层动作：最多 3 条、动词开头、≤30 字；每条右边是一个**真按钮**
   · 第三层归属：四格固定顺序（本机 / 本地网络 / 运营商 / 对端），只高亮一格
   · 边界：横幅下方紧贴一行，永远与结论同卡；完整证据折进「展开证据」

   同屏重点标记（红/黄）上限 3：本卡里只有横幅 + 高亮那一格算标记，正好 2 个；
   证据里的严重度色块默认折着，展开是用户自己要看，不算同屏。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var V = C.verdict || {};

  /* ------------------------------------------------------------ 小工具 */
  function n(v) {
    if (v === null || v === undefined || v === "") return null;
    var x = Number(v);
    return isFinite(x) ? x : null;
  }

  /* 文案预算兜底：超长就断在最近的标点，不硬切半个词 */
  function clip(s, max) {
    var str = String(s == null ? "" : s).trim();
    if (str.length <= max) return str;
    var head = str.slice(0, max);
    var cut = Math.max(
      head.lastIndexOf("，"), head.lastIndexOf("、"), head.lastIndexOf("；"),
      head.lastIndexOf("："), head.lastIndexOf(" ")
    );
    if (cut >= max * 0.5) head = head.slice(0, cut);
    return head.replace(/[，、；：,;:\s]+$/, "") + "…";
  }

  /* 数字加粗：一句里所有数字各自包 <b>，单位保持常规字重。
     用 textContent 拼节点，不拼 HTML 字符串。 */
  function rich(text) {
    var frag = document.createDocumentFragment();
    var str = String(text == null ? "" : text);
    var re = /\d+(?:[.,]\d+)?/g;
    var last = 0, m;
    while ((m = re.exec(str)) !== null) {
      if (m.index > last) frag.appendChild(document.createTextNode(str.slice(last, m.index)));
      frag.appendChild(U.el("b", "vn", m[0]));
      last = m.index + m[0].length;
    }
    if (last < str.length) frag.appendChild(document.createTextNode(str.slice(last)));
    return frag;
  }

  function tpl(str, vars) { return U.tpl(str || "", vars || {}); }

  /* ------------------------------------------------------------ 取数 */
  function worstLayer(v) {
    var layers = (v && v.layers) || [];
    var bad = null, warn = null;
    for (var i = 0; i < layers.length; i++) {
      var l = layers[i];
      if (!l) continue;
      /* 按 L2 → L7 顺序取「最靠底层的那个坏层」：底层坏了上层必然跟着坏，
         报 L4 比报 L7 更接近根因 */
      if (!bad && l.status === "bad") bad = l;
      if (!warn && l.status === "warn") warn = l;
    }
    return bad || warn || null;
  }

  function badPeers(meta) {
    var out = [], seen = {};
    ((meta && meta.streams_top) || []).forEach(function (s) {
      if (!s || !(s.flags || []).length) return;
      var key = String(s.server || "") + ":" + String(s.dport || "");
      if (seen[key]) return;
      seen[key] = 1;
      out.push(key);
    });
    return out;
  }

  function peerLabel(meta) {
    var peers = badPeers(meta);
    if (peers.length === 1) return peers[0];
    var top = ((meta && meta.streams_top) || [])[0];
    if (top && top.server) return String(top.server) + (top.dport ? ":" + top.dport : "");
    return "";
  }

  function privateV4(ip) {
    return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(String(ip || ""));
  }

  function firstLoss(hops) {
    for (var i = 0; i < (hops || []).length; i++) {
      var h = hops[i];
      if (!h) continue;
      var loss = n(h.loss_pct);
      if (loss !== null && loss >= 5) return { ttl: n(h.ttl) || (i + 1), loss: loss };
    }
    return null;
  }

  /* ------------------------------------------------------------ 影响范围 */
  /* 只回答一件事：这次是「这一个对端」的事，还是「整机上网」的事 */
  function scopeOf(meta, lay, kind) {
    if (kind === "ok") return "none";
    if (kind === "unknown") return "unknown";
    var id = lay && lay.id;
    var connFail = n(meta.conn_fail) || 0;
    var peers = badPeers(meta);

    if (id === "L2") return "all";
    if (id === "L3") {
      /* ICMP 不可达/超时 = 报文在中途被拒，坏的往往是一组目标（网段/主机），
         不是「整机都不能上网」 —— 措辞要跟后端的 impact（部分业务不通）对齐 */
      var icmp = (n(meta.icmp_unreach) || 0) + (n(meta.icmp_timeout) || 0);
      if (icmp > 0 && (n(meta.retrans_rate) || 0) < 1) return "some";
      return "all";
    }
    if (id === "L4") {
      if (connFail > 0 && peers.length === 1) return "peer";
      if ((n(meta.conn_refused) || 0) > 0 && peers.length <= 1) return "peer";
      return "all";
    }
    if (id === "L7") {
      if ((n(meta.http_err5) || 0) > 0) return "peer";
      if ((n(meta.dns_fail_rate) || 0) >= 20) return "all";
      return "all";
    }
    /* 没有坏层（正常/无样本）：按计数器粗略判断 */
    if (connFail > 0 && peers.length === 1) return "peer";
    return "all";
  }

  /* ------------------------------------------------------------ 责任归属 */
  /* 返回 {key, why:{kind,...}}；key ∈ host|lan|carrier|peer */
  function blame(meta, lay, scopeKey) {
    var id = lay && lay.id;

    /* L2 坏 = 本地链路（ARP / 网线 / 交换机口）。别用 arp_no_reply 单独判：
       它常常只是伴随项，真正坏的那层才该决定找谁 */
    if (id === "L2") return { key: "lan", why: { kind: "arp" } };
    /* 端口明确被拒：对方在，但不给连 */
    if ((n(meta.conn_refused) || 0) > 0) return { key: "peer", why: { kind: "refused" } };
    /* 单个对端连不上：对端服务或对方防火墙 */
    if ((n(meta.conn_fail) || 0) > 0 && scopeKey === "peer") {
      return { key: "peer", why: { kind: "single", target: peerLabel(meta) } };
    }
    /* 5xx 是服务端自己的问题，网络不背锅 */
    if ((n(meta.http_err5) || 0) > 0 && id === "L7") {
      return { key: "peer", why: { kind: "5xx", n: n(meta.http_err5) } };
    }
    /* DNS 失败：看 DNS 服务器在内网还是公网，决定找网管还是找运营商 */
    if ((n(meta.dns_fail_rate) || 0) >= 20 && id === "L7") {
      var srv = ((meta.dns_servers || [])[0] || [])[0];
      return { key: privateV4(srv) ? "lan" : "carrier",
               why: { kind: "dns", srv: srv, rate: n(meta.dns_fail_rate) } };
    }
    /* 有逐跳数据就按「第几跳开始丢」判，这是最硬的依据 */
    var hop = firstLoss((meta.path_profile || {}).hops);
    if (hop) {
      if (hop.ttl <= 1) return { key: "lan", why: { kind: "hop", hop: 1 } };
      return { key: "carrier", why: { kind: "hop", hop: hop.ttl, loss: hop.loss } };
    }
    /* 逐跳数据缺席时的 L3：ICMP 不可达比「重传率」更能说明被谁拦了 */
    var icmpN = (n(meta.icmp_unreach) || 0) + (n(meta.icmp_timeout) || 0);
    if (id === "L3" && icmpN > 0) {
      return { key: "carrier", why: { kind: "icmp", n: icmpN } };
    }
    /* 接收窗口塞满而重传不高：本机应用读得慢 */
    if ((n(meta.zero_win) || 0) > 0 && (n(meta.retrans_rate) || 0) < 1) {
      return { key: "host", why: { kind: "win", n: n(meta.zero_win) } };
    }
    /* 大面积丢包：链路（运营商/承载网） */
    if ((n(meta.retrans_rate) || 0) >= 1) {
      return { key: "carrier", why: { kind: "both", loss: n(meta.retrans_rate) } };
    }
    /* L3 有话说（RTT/ICMP）→ 链路侧 */
    if (id === "L3") return { key: "carrier", why: { kind: "both", loss: n(meta.retrans_rate) } };
    return { key: "host", why: { kind: "ok" } };
  }

  function ownerCells(meta, lay, scopeKey, highlight) {
    var CL = V.clear || {}, OW = V.owners || {};
    var b = blame(meta, lay, scopeKey);
    var basisOf = basisText(b.why);
    var order = ["host", "lan", "carrier", "peer"];
    var cells = [];
    order.forEach(function (key) {
      var on = highlight && key === b.key;
      var ow = OW[key] || {};
      /* 同一个人，不同故障能做的事不一样：ICMP 拦截要查路由，不是查丢包。
         没被指到的三格只报状态、不给建议 —— 本机明明没事还劝人「降低并发占用」
         就是自相矛盾（用户会照着做，然后白折腾）。 */
      var partner = on ? ((ow.byKind && ow.byKind[b.why.kind]) || ow.partner || "") : "";
      cells.push({
        key: key,
        label: ow.label || key,
        partner: partner,
        basis: on ? basisOf : (CL[key] || ""),
        on: on
      });
    });
    return { key: highlight ? b.key : "", why: b.why, cells: cells };
  }

  function basisText(why) {
    var B = V.basis || {};
    switch (why.kind) {
      case "arp": return B.lanArp;
      case "hop": return why.hop <= 1 ? tpl(B.lanHop, { hop: 1 }) : tpl(B.carrierHop, { hop: why.hop, loss: numTxt(why.loss, 1) });
      case "single": return tpl(B.peerSingle, { target: why.target || "" });
      case "5xx": return tpl(B.peer5xx, { n: numTxt(why.n, 0) });
      case "refused": return B.peerRefused;
      case "win": return tpl(B.hostWin, { n: numTxt(why.n, 0) });
      case "dns": return tpl(B.dnsFail, { rate: numTxt(why.rate, 0), srv: why.srv || "—" });
      case "both": return tpl(B.carrierBoth, { loss: numTxt(why.loss, 1) });
      case "icmp": return tpl(B.carrierIcmp, { n: numTxt(why.n, 0) });
      default: return B.hostOk;
    }
  }

  function numTxt(v, d) {
    var x = n(v);
    return x === null ? "—" : x.toFixed(d);
  }

  /* ------------------------------------------------------------ 三步动作 */
  /* 先取与「最坏那层」最贴合的一组，三条一组写死，保证可执行；
     规则组不够时不再拼凑 —— 少一条也比给一条假动作强。 */
  function stepsOf(meta, lay, kind) {
    var S = V.steps || {};
    var id = lay && lay.id;
    var groups = [];
    if (kind === "ok") groups = [S.ok];
    else if (kind === "zero") groups = [S.zero];
    else if (kind === "thin") groups = [S.thin];
    else {
      if ((n(meta.conn_fail) || 0) > 0 || (n(meta.conn_refused) || 0) > 0) groups.push(S.connFail);
      if ((n(meta.dns_fail_rate) || 0) >= 20 && id === "L7") groups.push(S.dns);
      if ((n(meta.http_err5) || 0) > 0 && id === "L7") groups.push(S.http);
      if ((n(meta.retrans_rate) || 0) >= 1) groups.push(S.retrans);
      if ((n(meta.arp_no_reply) || 0) > 0) groups.push(S.arp);
      /* ICMP 不可达但几乎不丢包：报文是被拒的，不是被磨的 */
      if (id === "L3" &&
          ((n(meta.icmp_unreach) || 0) + (n(meta.icmp_timeout) || 0)) > 0 &&
          (n(meta.retrans_rate) || 0) < 1) {
        groups.unshift(S.icmp);
      }
      if (!groups.length) groups.push(S.retrans);
    }
    var out = [];
    groups.forEach(function (g) {
      (g || []).forEach(function (s) {
        if (s && out.length < 3) out.push(s);
      });
    });
    return out.slice(0, 3);
  }

  function actBtn(act, job, model) {
    var A = V.act || {};
    var label = A[act] || "";
    var b;
    if (act === "retest") {
      b = U.btn(label, { kind: "sm", icon: "play", onClick: function () { retest(job); } });
    } else if (act === "hops") {
      b = U.btn(label, { kind: "ghost", size: "sm", onClick: function () { retest(job, { focus: "path" }); } });
    } else if (act === "copy") {
      b = U.btn(label, { kind: "ghost", size: "sm", icon: "copy", onClick: function () { copySummary(model); } });
    } else if (act === "logs") {
      b = U.btn(label, { kind: "ghost", size: "sm", onClick: function () { location.hash = "#/logs"; } });
    } else if (act === "rerun") {
      b = U.btn(label, { kind: "ghost", size: "sm", onClick: function () { rerun(job); } });
    } else if (act === "fold") {
      b = U.btn(label, { kind: "ghost", size: "sm", onClick: function () { openFold(model.el); } });
    } else {
      b = U.btn(label, { kind: "ghost", size: "sm" });
    }
    return b;
  }

  function openFold(root) {
    if (!root) return;
    var d = root.querySelector("details.evfold");
    if (!d) return;
    d.open = true;
    try { d.scrollIntoView({ block: "start", behavior: "smooth" }); } catch (e) { d.scrollIntoView(); }
    var s = d.querySelector("summary");
    if (s) s.focus();
  }

  /* 复测：交给 modes 决定用哪个模式、填什么参数。
     后端 /api/status 已经下发 link_actions（对端 + 网关），那是权威值；
     这里不自己从 summary.target 猜 —— 「全网」不是能探测的目标。 */
  function retest(job, opts) {
    if (!ND.modes || !ND.modes.retest) return;
    ND.modes.retest(job, { focus: (opts || {}).focus || "" });
  }

  /* 重新采集：回到本次用的那个模式页，参数还在表单里，改完再点开始 */
  function rerun(job) {
    var id = (job && job.mode) || "scan";
    location.hash = "#/" + id;
  }

  /* ------------------------------------------------------------ 摘要文本 */
  /* 「复制给协作方」= 完整报告（结论 · 指标 · 证据 · 数据 · 上下文），
     不是结论摘要：只给结论的版本没法复核。模型里带着 job，这里直接交给构建器。 */
  function copySummary(model) {
    if (ND.reporter && model && model.job) {
      ND.reporter.copy(model.job);
      return;
    }
    /* 构建器缺失（理论上不会）：至少把结论与边界复制出去，不给空剪贴板 */
    var text = [model.title + "：" + model.problem, V.summaryScope + (model.boundary || "")].join("\n");
    U.copyText(text).then(function (ok) {
      U.toast(ok ? (V.copySummaryOk || "") : (V.copySummaryFail || ""), ok ? "ok" : "crit");
    });
  }

  /* ------------------------------------------------------------ 模型 */
  function build(job) {
    var res = (job && job.result) || null;
    if (!res) return null;
    var meta = res.meta || {};
    var v = res.verdict || {};
    var block = (job && job.conclusion) || res.conclusion || null;
    var sev = C.sev || {};

    var pk = n(meta.packets);
    var zero = pk !== null && pk === 0;
    var suff = v.sufficiency || null;
    var thin = !zero && suff && suff.ok === false;
    var level = String(v.level || "");

    var kind = zero ? "zero" : thin ? "thin"
      : level === sev.critical ? "crit"
      : level === sev.warning ? "warn"
      : level === sev.ok ? "ok" : (v.flags && v.flags.network_ok === false ? "warn" : "ok");

    var lay = worstLayer(v);
    /* 0 包 / 样本不足时范围就是「无法判断」，归属也不该硬指一格 */
    var scopeKey = (kind === "zero" || kind === "thin") ? "unknown" : scopeOf(meta, lay, kind);

    var title = kind === "ok" ? V.titleOk
      : kind === "zero" ? V.titleZero
      : kind === "thin" ? V.titleThin
      : lay ? (String(lay.id || "") + " " + String(lay.name || "") + (V.titleSuffix || "异常"))
      : V.titleOk;

    var highlight = kind === "crit" || kind === "warn";
    var owner = ownerCells(meta, lay, scopeKey, highlight);
    /* 一句话定性按「到底是谁的问题」选词（blame 的 kind），比复述后端 plain 更稳：
       plain 是面向排障者的长文，且属于后端文案（core/copy），前端不做二次改写 */
    var problem = problemOf(v, kind, owner && owner.why ? owner.why.kind : "");

    /* 置信度：结论块（后端给 level+value）优先，其次用 verdict 自己的单值 */
    var confBlock = block && isFinite(Number(block.confidence)) ? Number(block.confidence) : null;
    var confValue = confBlock !== null ? confBlock
      : (isFinite(Number(v.confidence)) ? Number(v.confidence) : null);
    var confLevel = (block && block.confidence_level) || "";
    var conf = confValue !== null
      ? (confLevel ? tpl(V.confidence, { level: confLevel, value: confValue.toFixed(2) })
        : confValue.toFixed(2))
      : (V.confidenceNone || "");

    return {
      kind: kind,
      tone: kind === "crit" ? "crit" : (kind === "ok" ? "ok" : "warn"),
      title: clip(title, 14),
      problem: clip(problem, 40),
      scopeKey: scopeKey,
      scopeLabel: (V.scope || {})[scopeKey] || "",
      lay: lay,
      meta: meta,
      block: block,
      confidence: conf,
      boundary: boundaryOf(block, kind, v),
      steps: stepsOf(meta, lay, kind),
      owner: owner,
      reportId: res.report_id || (job && job.report_id) || "",
      /* 导出/复制要整份 job（result + mode + epoch + link_actions），
         模型里留个引用，按钮就不必再回传参数 */
      job: job,
      summary: ""
    };
  }

  function problemOf(v, kind, whyKind) {
    var V2 = V;
    if (kind === "ok") return V2.okProblem || "";
    if (kind === "zero") return V2.zeroProblem || "";
    if (kind === "thin") return V2.thinProblem || "";
    var byKind = (V2.problemByKind || {})[whyKind];
    if (byKind) return byKind;
    /* 没有对应的规范表述时才退回后端原句（例如未知故障族） */
    var plain = String(v.plain || "").replace(/^\s*表现是[：:]\s*/, "");
    if (plain) {
      var first = plain.split(/[。；]/)[0];
      if (first) return first;
    }
    if (v.headline) return String(v.headline);
    var pts = v.points || [];
    for (var i = 0; i < pts.length; i++) {
      if (pts[i] && (pts[i].title || pts[i].finding)) return String(pts[i].title || pts[i].finding);
    }
    return "";
  }

  /* 一行边界：优先用后端给的 key_limit（它说的就是「这套结论能用到哪」），
     其次退到覆盖/未覆盖的条数（结论块没有就读 verdict 自己的），最后给一句固定口径。
     这一行必须永远有话说 —— 它紧跟在结论横幅下面，空着等于结论没有适用范围。 */
  function boundaryOf(block, kind, v) {
    var key = block && block.key_limit ? String(block.key_limit) : "";
    if (key) return key;
    var cov = (block && block.coverage) || (v && v.coverage) || [];
    var not = (block && block.not_covered) || (v && v.not_covered) || [];
    if (cov.length || not.length) return tpl(V.boundaryCount, { a: cov.length, b: not.length });
    return V.boundaryFallback || "";
  }

  /* ------------------------------------------------------------ ① 定性结论 */
  /* 卡片不再是「一个函数画完」：三段报告（report.js）要按 ①/②/③ 拼接，
     所以这里只导出三块零件 —— head（横幅 + 边界）、steps（处置步骤）、owner（责任）。
     边界必须紧跟横幅、不进任何折叠：结论和「这套结论能用到哪」是不可拆的。 */
  function head(job, model) {
    var box = document.createDocumentFragment();
    var uid = "v-" + Math.random().toString(36).slice(2, 7);

    var ban = U.el("div", "v-banner " + model.tone);
    ban.setAttribute("aria-labelledby", uid + "-t");
    var top = U.el("div", "v-b-top");
    top.appendChild(U.el("span", "v-kicker", V.kicker || ""));
    if (model.scopeLabel) {
      var sc = U.el("span", "v-scope");
      sc.appendChild(U.el("span", "v-scope-k", V.scopeLabel || ""));
      sc.appendChild(U.el("b", "", model.scopeLabel));
      top.appendChild(sc);
    }
    ban.appendChild(top);

    var h = U.el("h2", "v-title", model.title);
    h.id = uid + "-t";
    ban.appendChild(h);
    var p = U.el("p", "v-problem");
    p.appendChild(rich(model.problem));
    ban.appendChild(p);
    box.appendChild(ban);

    if (model.boundary) {
      var R = C.result || {};
      var bd = U.el("p", "v-boundary");
      bd.appendChild(U.el("b", "", (V.boundaryLead || "") + "："));
      bd.appendChild(U.el("span", "v-boundary-t", model.boundary));
      bd.appendChild(U.el("span", "v-conf", (R.confidence || "") + " " + model.confidence));
      bd.title = (V.boundaryLead || "") + "：" + model.boundary;
      box.appendChild(bd);
    }
    return box;
  }

  /* 处置步骤：最多 3 条，每条一个真按钮 */
  function steps(job, model) {
    if (!model.steps.length) return null;
    var sec = U.el("div", "v-steps");
    sec.appendChild(U.el("h3", "v-h", V.stepsHeading || ""));
    var ol = U.el("ol", "v-step-list");
    model.steps.forEach(function (s, i) {
      var li = U.el("li", "v-step");
      li.appendChild(U.el("span", "v-step-no", String(i + 1)));
      var body = U.el("p", "v-step-t");
      body.appendChild(rich(s.text));
      li.appendChild(body);
      li.appendChild(actBtn(s.act, job, model));
      ol.appendChild(li);
    });
    sec.appendChild(ol);
    return sec;
  }

  /* 责任归属：四格只亮一格 */
  function owner(job, model) {
    var sec = U.el("div", "v-owner");
    sec.appendChild(U.el("h3", "v-h", V.ownerHeading || ""));
    var grid = U.el("div", "v-grid");
    model.owner.cells.forEach(function (c) {
      var cell = U.el("div", "v-cell" + (c.on ? " on" : ""));
      cell.appendChild(U.el("div", "v-cell-t", c.label));
      var b1 = U.el("p", "v-cell-b");
      b1.appendChild(rich(c.basis || ""));
      cell.appendChild(b1);
      if (c.partner) cell.appendChild(U.el("p", "v-cell-p", c.partner));
      grid.appendChild(cell);
    });
    sec.appendChild(grid);

    var foot = U.el("div", "v-copy");
    foot.appendChild(U.el("p", "v-copy-t", model.owner.key ? (V.copyFooter || "") : (V.ownerNone || "")));
    if (model.owner.key) {
      foot.appendChild(U.btn(V.copySummary || "", {
        kind: "ghost", size: "sm", icon: "copy",
        onClick: function () { copySummary(model); }
      }));
    }
    sec.appendChild(foot);
    return sec;
  }

  /* 页脚：复制 / 导出（始终可见，不进折叠）。
     正文由 reporter.js 统一生成 —— 结论、指标、证据、数据、上下文一份文件全带，
     只给「结论与边界」两段的版本不再产出。 */
  function footer(job, model) {
    var R = C.result || {};
    var ft = U.el("div", "v-ft");
    var ui = (job && job.ui_copy && job.ui_copy.conclusion) || {};
    ft.appendChild(U.btn(ui.btn_copy || R.copy || "", {
      kind: "ghost", size: "sm", icon: "copy",
      onClick: function () { copySummary(model); }
    }));
    ft.appendChild(U.btn(ui.btn_export_md || R.exportMd || "", {
      kind: "ghost", size: "sm", icon: "download",
      onClick: function () {
        if (ND.reporter) ND.reporter.download(job, "md");
        else ND.render.saveText(ND.render.reportName(job, "md"), ND.render.textOf(job, "md"));
      }
    }));
    ft.appendChild(U.btn(ui.btn_export_json || R.exportJson || "", {
      kind: "ghost", size: "sm", icon: "download",
      onClick: function () {
        if (ND.reporter) ND.reporter.download(job, "json");
        else ND.render.saveText(ND.render.reportName(job, "json"), ND.render.textOf(job, "json"));
      }
    }));
    if (model.reportId) ft.appendChild(U.el("span", "v-id mono", tpl(R.reportId, { id: model.reportId })));
    return ft;
  }

  function openFold(root) {
    if (!root) return;
    var d = root.querySelector("details.rpt-detail");
    if (!d) return;
    d.open = true;
    try { d.scrollIntoView({ block: "center", behavior: "smooth" }); } catch (e) { d.scrollIntoView(); }
  }

  ND.verdict = {
    build: build,
    head: head,
    steps: steps,
    owner: owner,
    footer: footer,
    copySummary: copySummary
  };
})(window.ND = window.ND || {});
