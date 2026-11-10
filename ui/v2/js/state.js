/* ============================================================================
   state.js · 全局状态与轮询调度（数据只在 api.js 拿，页面只订阅这里）
   ----------------------------------------------------------------------------
   为什么要一个 store：
   总览页要知道「现在有没有任务在跑」，模式页要知道「跑到哪个阶段」，
   两边是同一个 /api/status。让每个页面各自轮询，既会有两份不一致的快照，
   也会把后台的空闲退出拖住（空闲退出是按「有没有请求」算的）。

   所以这里只有一个轮询器，按**引用计数**开关：
   · modes.acquire("job", 900)  → 运行中每 0.9 秒一次
   · home.acquire("home", 1500) → 只在有任务时按 1.5 秒跟，任务结束立刻释放
   · 设置 / 日志页不 acquire → 一个请求都不发，空闲退出照常生效
   ========================================================================== */
(function (ND) {
  "use strict";

  var S = {
    app: null,          /* /api/app 原始响应 */
    checks: [],         /* 环境检查（selfcheck 与 app 同源） */
    caps: null,         /* capabilities */
    job: null,          /* /api/status 最近一次快照 */
    jobAt: 0,           /* 快照时间（本机毫秒） */
    last: null,         /* /api/last-run 的 last */
    result: null,       /* /api/last-run/result 的 result（内存里有才取） */
    pollError: "",      /* 轮询失败的原因，页面据此提示「连不上本地服务」 */
    pro: false          /* 专业模式：控制台默认展开、面板显示全字段 */
  };

  /* 专业模式是本机偏好，不是运行状态：放 localStorage，刷新后保持 */
  var PRO_KEY = "nd_pro";
  try { S.pro = window.localStorage.getItem(PRO_KEY) === "1"; } catch (e) { S.pro = false; }

  function isPro() { return !!S.pro; }

  function setPro(on) {
    S.pro = !!on;
    try { window.localStorage.setItem(PRO_KEY, S.pro ? "1" : "0"); } catch (e) { /* 隐私模式写不进去也不影响本次 */ }
    emit("pro");
  }

  var subs = [];
  var watchers = {};
  var timerId = 0;
  var polling = false;

  function get() { return S; }

  function subscribe(fn) {
    subs.push(fn);
    return function () {
      var i = subs.indexOf(fn);
      if (i >= 0) subs.splice(i, 1);
    };
  }

  function emit(evt) {
    for (var i = subs.length - 1; i >= 0; i--) {
      try { subs[i](S, evt); } catch (e) { /* 单个订阅者出错不拖垮其余 */ }
    }
  }

  /* ------------------------------------------------------------ 状态快照 */
  function isRunning() {
    return !!(S.job && (S.job.state === "running" || S.job.state === "starting"));
  }

  function hasJob() {
    return !!(S.job && S.job.state && S.job.state !== "idle");
  }

  function applyJob(data) {
    var prev = S.job ? String(S.job.state || "") : "";
    S.job = data || null;
    S.jobAt = Date.now();
    S.pollError = "";
    var now = S.job ? String(S.job.state || "") : "";
    emit("job");
    /* 任务刚结束：把「最近一次结果」一起刷新，总览不用等下一次进页面 */
    if (prev === "running" && now && now !== "running") refreshLastRun();
  }

  function refreshStatus() {
    return ND.api.status().then(function (res) {
      if (!res.ok) {
        S.pollError = ND.ui.why(res);
        emit("job");
        return res;
      }
      applyJob(res.data || {});
      return res;
    });
  }

  function refreshLastRun() {
    return ND.api.lastRun().then(function (res) {
      if (res.ok) S.last = res.data ? (res.data.last || null) : null;
      var full = S.last && S.last.full_result;
      if (!full) {
        S.result = null;
        emit("last");
        return null;
      }
      return ND.api.lastRunResult().then(function (r) {
        S.result = r.ok ? ((r.data || {}).result || null) : null;
        emit("last");
      });
    });
  }

  function loadApp() {
    return ND.api.app().then(function (res) {
      if (!res.ok) return res;
      S.app = res.data || {};
      S.caps = S.app.capabilities || null;
      if ((S.app.checks || []).length) S.checks = S.app.checks;
      emit("app");
      return res;
    });
  }

  function loadChecks() {
    return ND.api.selfcheck().then(function (res) {
      var list = res.ok ? ((res.data || {}).checks || []) : [];
      if (list.length) {
        S.checks = list;
        S.caps = (res.data || {}).capabilities || S.caps;
        emit("checks");
      }
      return res;
    });
  }

  /* ------------------------------------------------------------ 轮询调度 */
  function desiredMs() {
    var ms = 0;
    for (var k in watchers) {
      if (!Object.prototype.hasOwnProperty.call(watchers, k)) continue;
      if (!ms || watchers[k] < ms) ms = watchers[k];
    }
    return ms;
  }

  function loop() {
    timerId = 0;
    var ms = desiredMs();
    if (!ms) return;
    refreshStatus().then(function () {
      var next = desiredMs();
      if (!next) return;
      timerId = setTimeout(loop, next);
    });
  }

  /* 页面挂载时领一份轮询，卸载时还回去；同一 key 重复领只生效一次 */
  function acquire(key, ms) {
    watchers[key] = Math.max(300, Number(ms) || 1000);
    if (!timerId && !polling) {
      polling = true;
      Promise.resolve().then(function () {
        polling = false;
        if (!timerId) loop();
      });
    }
  }

  function release(key) {
    delete watchers[key];
    if (!desiredMs() && timerId) {
      clearTimeout(timerId);
      timerId = 0;
    }
  }

  function releaseAll() {
    watchers = {};
    if (timerId) {
      clearTimeout(timerId);
      timerId = 0;
    }
  }

  /* ------------------------------------------------------------ 启动任务 */
  function startJob(payload) {
    return ND.api.scan(payload).then(function (res) {
      if (!res.ok) return res;
      /* 先把状态拉一次，再开轮询：按钮点下去到第一帧进度之间不留空白 */
      return refreshStatus().then(function () {
        acquire("run", 900);
        return res;
      });
    });
  }

  ND.state = {
    get: get,
    subscribe: subscribe,
    isRunning: isRunning,
    hasJob: hasJob,
    isPro: isPro,
    setPro: setPro,
    applyJob: applyJob,
    refreshStatus: refreshStatus,
    refreshLastRun: refreshLastRun,
    loadApp: loadApp,
    loadChecks: loadChecks,
    startJob: startJob,
    acquire: acquire,
    release: release,
    releaseAll: releaseAll
  };
})(window.ND = window.ND || {});
