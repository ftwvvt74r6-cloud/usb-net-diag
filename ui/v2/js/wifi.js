/**
 * 「网络参数」卡 —— 把本机可采集的无线/主机/链路参数放成一张表。
 *
 * 设计要点
 * --------
 * * 数据全部来自后端 `/api/wifi`（本机 netsh + ping + 本地地址），不联网、不调厂商 AC；
 * * 本机拿不到的字段（空口时延 / AP 名称 / 漫游轨迹 / 信道利用率）不编造，
 *   统一显示「需网络后台」并在卡片底部说明去向；
 * * 估计信噪比标注「估算」，避免被当成设备侧实测值。
 */
(function (ND) {
  "use strict";

  var U = ND.ui;

  var C = {
    title: "网络参数",
    sub: "本机可采集的关键链路参数（对标无线控制器后台字段）",
    refresh: "刷新参数",
    estTip: "估计信噪比 = RSSI − 噪声底(-95 dBm)，仅作参考，不是设备实测值。",
    empty: "当前没有可用的无线连接信息（可能是有线连接，或无线接口未连接）。",
    fail: "读取网络参数失败",
    groupWireless: "无线链路",
    groupHost: "主机与网关",
    labels: {
      state: "连接状态", ssid: "SSID", bssid: "AP MAC", band: "频段", channel: "信道",
      radio: "无线协议", auth: "加密方式", signal: "信号强度", rssi: "RSSI",
      snr: "估计信噪比", rate: "协商速率", local: "本机 IP", gateway: "默认网关",
      gwRtt: "网关 RTT", gwJitter: "网关抖动", gwLoss: "网关丢包"
    }
  };

  var host = null;
  var data = null;
  var loading = false;

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

  function draw() {
    if (!host) return;
    U.clear(host);
    var card = U.el("section", "card np-card");
    var hd = U.el("div", "card-hd");
    hd.appendChild(U.el("h2", "", C.title));
    hd.appendChild(U.el("span", "card-sub", C.sub));
    var btn = U.btn(C.refresh, { kind: "ghost", size: "sm", onClick: function () { load(true); } });
    hd.appendChild(btn);
    card.appendChild(hd);

    if (loading) {
      card.appendChild(U.el("p", "np-note", "正在读取…"));
      host.appendChild(card);
      return;
    }
    if (!data || !data.ok) {
      card.appendChild(U.el("p", "np-note", C.fail + (data && data.error ? "：" + data.error : "")));
      host.appendChild(card);
      return;
    }
    if (!data.available) {
      card.appendChild(U.el("p", "np-note", C.empty));
      host.appendChild(card);
      return;
    }

    var table = U.el("table", "np-table");
    var w = data.wlan || {};
    var h = data.host || {};
    var pr = data.probe || {};

    groupRow(table, C.groupWireless);
    row(table, C.labels.state, w.state === "connected" ? "已连接" : (w.state || "—"));
    row(table, C.labels.ssid, w.ssid);
    row(table, C.labels.bssid, w.bssid);
    row(table, C.labels.band, w.band);
    row(table, C.labels.channel, w.channel);
    row(table, C.labels.radio, w.radio);
    row(table, C.labels.signal, w.signal_pct == null ? null : w.signal_pct + " %");
    row(table, C.labels.rssi, w.rssi_dbm == null ? null : w.rssi_dbm + " dBm");
    row(table, C.labels.snr, w.snr_est_db == null ? null : "≈ " + w.snr_est_db + " dB（估算）");
    row(table, C.labels.rate, fmtRate(w));
    row(table, C.labels.auth, [w.auth, w.cipher].filter(Boolean).join(" / ") || null);

    groupRow(table, C.groupHost);
    var tun = h.local_ip && String(h.local_ip).indexOf("198.18.") === 0;
    row(table, C.labels.local, h.local_ip ? h.local_ip + (tun ? "（代理 TUN，非物理网卡）" : "") : null);
    row(table, C.labels.gateway, h.gateway);
    row(table, C.labels.gwRtt, pr.rtt_ms == null ? null : pr.rtt_ms + " ms");
    row(table, C.labels.gwJitter, pr.jitter_ms == null ? null : pr.jitter_ms + " ms");
    row(table, C.labels.gwLoss, pr.loss_pct == null ? null : pr.loss_pct + " %");

    card.appendChild(table);
    host.appendChild(card);
  }

  function load(force) {
    loading = true;
    draw();
    // ND.api.get 统一 resolve 成 {ok,status,data,error} 信封，这里取 data 本体。
    ND.api.get("/api/wifi" + (force ? "?force=1" : ""))
      .then(function (res) {
        if (res && res.ok && res.data) data = res.data;
        else data = { ok: false, error: (res && res.error) || "" };
      })
      .catch(function () { data = { ok: false }; })
      .then(function () { loading = false; draw(); });
  }

  ND.wifi = {
    mount: function (el) {
      host = el;
      if (data) draw(); else load(false);
    },
    unmount: function () { host = null; }
  };
})(window.ND = window.ND || {});
