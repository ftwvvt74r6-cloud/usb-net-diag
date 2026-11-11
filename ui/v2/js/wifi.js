/**
 * 「网络参数」—— 把本机可采集的无线/主机/链路参数放成一张表。
 *
 * 设计要点
 * --------
 * * 数据全部来自后端 `/api/wifi`（本机 netsh + ping + 本地地址），不联网、不调厂商 AC；
 * * 本机拿不到的字段（空口时延 / AP 名称 / 漫游轨迹 / 信道利用率）不编造，
 *   缺就显示「—」，不写猜测值；
 * * 估计信噪比标注「估算」，避免被当成设备侧实测值；
 * * 两种挂法共用同一份缓存：
 *     - mount(el)  —— 独立成卡（首页无结果时的空态）；
 *     - embed(el)  —— 只出表，供三段报告「③ 数据」复用。
 */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};
  var RP = C.report || {};

  var T = {
    title: RP.netTitle || "网络参数",
    sub: RP.netSub || "",
    refresh: RP.netRefresh || "刷新参数",
    empty: RP.netEmpty || "",
    fail: RP.netFail || "",
    groupWireless: RP.netGroupWireless || "",
    groupHost: RP.netGroupHost || "",
    labels: {
      state: "连接状态", ssid: "SSID", bssid: "AP MAC", band: "频段", channel: "信道",
      radio: "无线协议", auth: "加密方式", signal: "信号强度", rssi: "RSSI",
      snr: "估计信噪比", rate: "协商速率", local: "本机 IP", gateway: "默认网关",
      gwRtt: "网关 RTT", gwJitter: "网关抖动", gwLoss: "网关丢包"
    }
  };

  var host = null;      /* 独立卡片宿主 */
  var embeds = [];      /* 嵌在三段报告里的宿主 */
  var data = null;
  var loading = false;
  var inflight = null;

  function row(table, label, value, cls) {
    var tr = document.createElement("tr");
    var th = document.createElement("th");
    th.textContent = label;
    var td = document.createElement("td");
    td.textContent = value == null || value === "" ? "—" : String(value);
    if (cls) td.className = cls;
    tr.appendChild(th);
    tr.appendChild(td);
    table.appendChild(tr);
    return tr;
  }

  function groupRow(table, text) {
    var tr = document.createElement("tr");
    tr.className = "np-group";
    var td = document.createElement("td");
    td.colSpan = 2;
    td.textContent = text;
    tr.appendChild(td);
    table.appendChild(tr);
  }

  function fmtRate(w) {
    if (!w) return null;
    if (w.rx_mbps == null && w.tx_mbps == null) return null;
    return (w.rx_mbps == null ? "—" : w.rx_mbps) + " / " + (w.tx_mbps == null ? "—" : w.tx_mbps) + " Mbps（收/发）";
  }

  function table() {
    var tbl = U.el("table", "np-table");
    var w = data.wlan || {};
    var h = data.host || {};
    var pr = data.probe || {};

    groupRow(tbl, T.groupWireless);
    row(tbl, T.labels.state, w.state === "connected" ? "已连接" : (w.state || "—"));
    row(tbl, T.labels.ssid, w.ssid);
    row(tbl, T.labels.bssid, w.bssid);
    row(tbl, T.labels.band, w.band);
    row(tbl, T.labels.channel, w.channel);
    row(tbl, T.labels.radio, w.radio);
    row(tbl, T.labels.signal, w.signal_pct == null ? null : w.signal_pct + " %");
    row(tbl, T.labels.rssi, w.rssi_dbm == null ? null : w.rssi_dbm + " dBm");
    row(tbl, T.labels.snr, w.snr_est_db == null ? null : "≈ " + w.snr_est_db + " dB（估算）");
    row(tbl, T.labels.rate, fmtRate(w));
    row(tbl, T.labels.auth, [w.auth, w.cipher].filter(Boolean).join(" / ") || null);

    groupRow(tbl, T.groupHost);
    var tun = h.local_ip && String(h.local_ip).indexOf("198.18.") === 0;
    row(tbl, T.labels.local, h.local_ip ? h.local_ip + (tun ? "（代理 TUN，非物理网卡）" : "") : null);
    row(tbl, T.labels.gateway, h.gateway);
    row(tbl, T.labels.gwRtt, pr.rtt_ms == null ? null : pr.rtt_ms + " ms");
    row(tbl, T.labels.gwJitter, pr.jitter_ms == null ? null : pr.jitter_ms + " ms");
    row(tbl, T.labels.gwLoss, pr.loss_pct == null ? null : pr.loss_pct + " %");
    return tbl;
  }

  /* 只画一个嵌入宿主。报告段是「先建节点、后挂根节点」，
     embed() 被调用时宿主可能还没连到文档上 —— 这里不做 isConnected 判断，
     传进来就照画，避免首帧空白。 */
  function paintOne(el) {
    U.clear(el);
    if (loading && !data) { el.appendChild(U.el("p", "muted", "正在读取…")); return; }
    if (!data || !data.ok) { el.appendChild(U.el("p", "muted", T.fail)); return; }
    if (!data.available) { el.appendChild(U.el("p", "muted", T.empty)); return; }
    var bar = U.el("div", "np-bar");
    bar.appendChild(U.btn(T.refresh, { kind: "ghost", size: "sm", onClick: function () { load(true); } }));
    el.appendChild(bar);
    el.appendChild(table());
  }

  /* 三处可能同时存在：卡片 / 数据段 / 另一份数据段（模式页切页重建）。
     统一从这里重画，避免「刷新只刷新了看得见的那一个」。
     注意：这里**不做 isConnected 过滤** —— 报告是「先建节点、后挂根节点」，
     embed() 被调用时宿主还没连到文档上，过滤会把刚交给我们的宿主丢掉。 */
  function paint() {
    if (host) {
      U.clear(host);
      var card = U.el("section", "card np-card");
      var hd = U.el("div", "card-hd");
      hd.appendChild(U.el("h2", "", T.title));
      if (T.sub) hd.appendChild(U.el("span", "card-sub", T.sub));
      hd.appendChild(U.btn(T.refresh, { kind: "ghost", size: "sm", onClick: function () { load(true); } }));
      card.appendChild(hd);

      if (loading) card.appendChild(U.el("p", "np-note", "正在读取…"));
      else if (!data || !data.ok) card.appendChild(U.el("p", "np-note", T.fail + (data && data.error ? "：" + data.error : "")));
      else if (!data.available) card.appendChild(U.el("p", "np-note", T.empty));
      else card.appendChild(table());
      host.appendChild(card);
    }

    embeds.forEach(paintOne);
  }

  /* 切页/重画后旧报告的宿主会被丢掉，攒着没用；等一帧再清，此时该连的已经连上。 */
  function prune() {
    embeds = embeds.filter(function (el) { return el.isConnected; });
  }

  /* 报告是一次性同步建树：宿主在 embed() 返回后才连到文档。
     下一帧再清一遍，顺带补一次绘制。 */
  var raf = 0;
  function schedule() {
    if (raf || typeof requestAnimationFrame !== "function") return;
    raf = requestAnimationFrame(function () { raf = 0; prune(); paint(); });
  }

  function load(force) {
    if (inflight && !force) return inflight;
    loading = true;
    paint();
    /* ND.api.get 统一 resolve 成 {ok,status,data,error} 信封，这里取 data 本体。 */
    inflight = ND.api.get("/api/wifi" + (force ? "?force=1" : ""))
      .then(function (res) {
        if (res && res.ok && res.data) data = res.data;
        else data = { ok: false, error: (res && res.error) || "" };
      })
      .catch(function () { data = { ok: false }; })
      .then(function () { loading = false; inflight = null; paint(); schedule(); });
    return inflight;
  }

  ND.wifi = {
    mount: function (el) {
      host = el;
      if (data) paint(); else load(false);
    },
    /* 只出表：三段报告的「③ 数据」用它，卡片头由报告给 */
    embed: function (el) {
      if (!el) return el;
      if (embeds.indexOf(el) < 0) embeds.push(el);
      if (data) { paintOne(el); schedule(); }
      else load(false);          /* load 内部会 paint 到所有宿主 */
      return el;
    },
    unmount: function () { host = null; }
  };
})(window.ND = window.ND || {});
