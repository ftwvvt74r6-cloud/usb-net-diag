/* ============================================================================
   api.js · 与本地服务对话的唯一出口
   ----------------------------------------------------------------------------
   约定：
   · 所有请求都带 no-store：这是本机进程的内存状态，缓存没有意义还会让人看到旧值。
   · 永不 reject —— 统一 resolve 成 { ok, status, data, error }。
     页面据此走「有数据 / 没数据 / 接口还没开放」三条分支，不用写 try/catch。
   · 不在这里写中文：错误只回状态码与后端原文，给人看的话在 copy.js。
   ========================================================================== */
(function (ND) {
  "use strict";

  var TIMEOUT = 12000;

  function request(path, opt) {
    opt = opt || {};
    var init = {
      method: opt.method || "GET",
      cache: "no-store",
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    };
    if (opt.body !== undefined) {
      init.headers["Content-Type"] = "application/json; charset=utf-8";
      init.body = JSON.stringify(opt.body || {});
    }

    var controller = null;
    var timer = 0;
    if (typeof AbortController === "function") {
      controller = new AbortController();
      init.signal = controller.signal;
      timer = setTimeout(function () { controller.abort(); }, opt.timeout || TIMEOUT);
    }

    return fetch(path, init).then(function (resp) {
      if (timer) clearTimeout(timer);
      return resp.text().then(function (raw) {
        var data = null;
        if (raw) {
          try { data = JSON.parse(raw); } catch (e) { data = null; }
        }
        if (!resp.ok) {
          var said = data && (data.error || data.reason || data.message);
          return {
            ok: false,
            status: resp.status,
            data: data,
            error: typeof said === "string" && said ? said : ""
          };
        }
        return { ok: true, status: resp.status, data: data || {}, error: "" };
      });
    }).catch(function (err) {
      if (timer) clearTimeout(timer);
      var aborted = err && err.name === "AbortError";
      return {
        ok: false,
        status: 0,
        data: null,
        error: aborted ? "timeout" : ((err && err.message) || "network")
      };
    });
  }

  /* 接口还没实现（路由缺失）与「真的没数据」要分开：前者给解释，后者给空态。
     core 现在的 404 是纯文本，R1/R5 之后仍是 404 —— 两种都按「没有这个接口」处理。 */
  function absent(res) {
    return !res || (!res.ok && (res.status === 404 || res.status === 405 || res.status === 501));
  }

  /* 导出类接口回的是 csv/md 正文，不是 JSON：单独走一次纯文本请求，
     仍然由本文件负责「只在这里发请求」的约定。 */
  function text(path) {
    return fetch(path, { cache: "no-store", credentials: "same-origin" })
      .then(function (resp) {
        return resp.text().then(function (body) {
          return { ok: resp.ok, status: resp.status, text: body, error: resp.ok ? "" : ("http " + resp.status) };
        });
      })
      .catch(function (err) {
        return { ok: false, status: 0, text: "", error: (err && err.message) || "network" };
      });
  }

  ND.api = {
    get: function (path, opt) { return request(path, opt); },
    post: function (path, body, opt) {
      var merged = opt || {};
      merged.method = "POST";
      merged.body = body === undefined ? {} : body;
      return request(path, merged);
    },
    absent: absent,

    /* ---- 语义化封装：路径只写一次，页面里不出现字符串常量 ---- */
    app: function () { return request("/api/app"); },
    selfcheck: function () { return request("/api/selfcheck"); },
    status: function () { return request("/api/status"); },
    lastRun: function () { return request("/api/last-run"); },
    lastRunResult: function () { return request("/api/last-run/result"); },
    interfaces: function () { return request("/api/interfaces"); },
    captures: function () { return request("/api/captures"); },
    ai: function () { return request("/api/ai"); },

    /* 走 POST 的写操作 */
    scan: function (payload) {
      return request("/api/scan", { method: "POST", body: payload || {} });
    },
    quit: function () { return request("/api/quit", { method: "POST", body: {} }); },
    elevate: function () { return request("/api/elevate", { method: "POST", body: {} }); },
    diagpack: function (body) { return request("/api/diagpack", { method: "POST", body: body || {} }); },
    /* R4（待后端实现）：保存手填路径 → 立刻重检 */
    savePath: function (key, path) {
      return request("/api/selfcheck/path", { method: "POST", body: { key: key, path: path } });
    },
    /* R4（待后端实现）：弹系统的选文件/选目录对话框，回绝对路径 */
    pickPath: function (kind) {
      return request("/api/pick-path", { method: "POST", body: { kind: kind || "file" } });
    },
    /* S6（待后端实现）：常驻采集状态与监测目标 */
    agent: function () { return request("/api/agent/status"); },
    agentInstall: function () { return request("/api/agent/install", { method: "POST", body: {} }); },
    agentUninstall: function () { return request("/api/agent/uninstall", { method: "POST", body: {} }); },
    agentConfig: function (body) { return request("/api/agent/config", { method: "POST", body: body || {} }); },
    monitor: function () { return request("/api/monitor"); },
    saveMonitor: function (body) { return request("/api/monitor", { method: "POST", body: body || {} }); },

    /* S6（待后端实现）：历史趋势 */
    history: function (q) { return request("/api/history?" + q); },
    historyEvents: function (q) { return request("/api/history/events?" + q); },
    historyMark: function (note) { return request("/api/history/mark", { method: "POST", body: { note: note || "" } }); },
    historyExport: function (fmt, q) { return text("/api/history/export?format=" + fmt + "&" + q); },

    /* R5（待后端实现）：日志列表与单个日志正文 */
    logs: function () { return request("/api/logs"); },
    logFile: function (name) {
      return request("/api/log?name=" + encodeURIComponent(name));
    }
  };
})(window.ND = window.ND || {});
