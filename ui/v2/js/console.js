/* ============================================================================
   console.js · 运行态的两个部件：进度条 + 采集控制台流
   ----------------------------------------------------------------------------
   进度条只读 /api/status 的四个字段：phase / elapsed / duration / attempt(s)。
   没有「假装平滑」的本地插值：数字来源于系统真实进度，宁可跳一下也不编动画。

   控制台流是采集层的原样输出（logs[{t,m}]）。三条规矩：
   · 只有用户本来就在底部时才自动滚到底（往上翻看历史时不许把他拽下来）；
   · 运行中实时追加；结束后自动折叠成一行，点一下能再展开；
   · 用 role="log" + aria-live="polite"，读屏不会抢焦点。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};

  function clip(n, min, max) {
    return Math.max(min, Math.min(max, n));
  }

  /* ------------------------------------------------------------ 进度条 */
  /* 用 CSS 变量 --p 驱动宽度，避免每帧写 style.width 触发回流判断 */
  function progress(job) {
    var R = C.run || {};
    var box = U.el("div", "runbar");

    var top = U.el("div", "runbar-top");
    var phase = U.el("p", "run-phase");
    phase.appendChild(U.el("span", "run-phase-k", R.phase || ""));
    phase.appendChild(U.el("b", "", (job && job.phase) || ""));
    top.appendChild(phase);

    var time = U.el("p", "run-time");
    var total = Number(job && job.duration) || 0;
    var elapsed = Number(job && job.elapsed) || 0;
    if (total > 0) {
      var remain = clip(Math.round(total - elapsed), 0, total);
      time.textContent = U.tpl(R.remain, { remain: remain, total: Math.round(total) });
    } else {
      time.textContent = U.tpl(R.openEnded, { elapsed: Math.round(elapsed) });
    }
    top.appendChild(time);
    box.appendChild(top);

    var track = U.el("div", "run-track");
    track.setAttribute("role", "progressbar");
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", total ? String(Math.round(total)) : "100");
    track.setAttribute("aria-valuenow", String(Math.round(elapsed)));
    var now = Number(job && job.elapsed) || 0;
    var pct = total > 0 ? clip((now / total) * 100, 0, 100) : (job && job.state === "running" ? 12 : 0);
    track.style.setProperty("--s", (pct / 100).toFixed(4));
    var fill = U.el("span", "run-fill");
    track.appendChild(fill);
    box.appendChild(track);

    var foot = U.el("div", "runbar-foot");
    if (total > 0) foot.appendChild(U.el("span", "run-pct", U.tpl(R.percent, { percent: Math.round(pct) })));
    if (job && job.attempts && job.attempts > 1) {
      foot.appendChild(U.el("span", "run-attempt",
        U.tpl(R.attempt, { n: job.attempt || 0, m: job.attempts })));
    }
    box.appendChild(foot);

    return box;
  }

  /* ------------------------------------------------------------ 控制台流 */
  /* returns { el, update(job), destroy() } —— 由页面持有时更新，避免整块重建 */
  function stream(job, opts) {
    opts = opts || {};
    var R = C.run || {};

    var box = U.el("div", "console");
    var hd = U.el("div", "console-hd");
    hd.appendChild(U.el("h3", "", R.consoleTitle || ""));
    var tools = U.el("div", "console-tools");
    hd.appendChild(tools);
    box.appendChild(hd);

    var scroller = U.el("div", "console-bd");
    scroller.setAttribute("role", "log");
    scroller.setAttribute("aria-live", "polite");
    scroller.setAttribute("aria-relevant", "additions");
    scroller.tabIndex = 0;
    box.appendChild(scroller);

    var pre = U.el("pre", "console-pre mono");
    scroller.appendChild(pre);

    var foot = U.el("div", "console-ft");
    box.appendChild(foot);

    var running0 = !!(job && (job.state === "running" || job.state === "starting"));
    /* 专业模式：结束后控制台保持展开，省掉每次点「展开输出」 */
    var expanded = running0 || (ND.state && ND.state.isPro && ND.state.isPro());
    var lastCount = -1;
    var collapsed = false;

    function lines(j) {
      /* 「›」是采集行的行首标记：让裸文本看起来像流，而不是一段被截断的说明 */
      return ((j && j.logs) || []).map(function (row) {
        var m = String((row && row.m) || "");
        return m === "" ? "" : "› " + m;
      }).filter(function (s) { return s !== ""; });
    }

    function nearBottom() {
      return scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 28;
    }

    function paint(j) {
      var arr = lines(j);
      var running = !!(j && (j.state === "running" || j.state === "starting"));

      /* 运行结束且用户没主动展开 → 折叠成一行 */
      collapsed = !running && !expanded;

      U.clear(tools);
      U.clear(foot);

      if (collapsed) {
        pre.hidden = true;
        var oldSum = box.querySelector(".console-collapsed");
        if (oldSum && oldSum.parentNode) oldSum.parentNode.removeChild(oldSum);
        var summary = U.el("button", "console-collapsed");
        summary.type = "button";
        summary.appendChild(U.icon("download", "mini"));
        summary.appendChild(U.el("span", "", U.tpl(R.consoleDone, { count: arr.length })));
        summary.appendChild(U.el("span", "console-more", R.consoleExpand || ""));
        summary.addEventListener("click", function () {
          expanded = true;
          paint(j);
        });
        scroller.hidden = true;
        box.classList.add("is-collapsed");
        foot.hidden = true;
        /* 把摘要放在 hd 下面（scroller 之前） */
        box.insertBefore(summary, scroller);
        return;
      }

      box.classList.remove("is-collapsed");
      var old = box.querySelector(".console-collapsed");
      if (old && old.parentNode) old.parentNode.removeChild(old);
      scroller.hidden = false;
      pre.hidden = false;
      /* 脚注写的是「采集结束 · N 行输出」，运行中显示它等于自己打自己 */
      foot.hidden = !!running;

      if (running) {
        var live = U.el("span", "console-live");
        live.setAttribute("aria-label", R.live || "");
        live.title = R.live || "";
        live.appendChild(U.el("span", "dot"));
        live.appendChild(U.el("span", "", R.live || ""));
        tools.appendChild(live);
      } else if (j && j.state && j.state !== "running") {
        var btn = U.btn(R.consoleCollapse || "", {
          kind: "ghost", size: "sm",
          onClick: function () { expanded = false; paint(j); }
        });
        tools.appendChild(btn);
      }

      if (!arr.length) {
        pre.textContent = R.consoleEmpty || "";
        return;
      }

      var stick = lastCount === -1 || nearBottom();
      pre.textContent = arr.join("\n");
      lastCount = arr.length;
      if (stick) scroller.scrollTop = scroller.scrollHeight;

      if (!running) foot.textContent = U.tpl(R.consoleDone, { count: arr.length });
    }

    paint(job);

    return {
      el: box,
      update: function (j) { paint(j); }
    };
  }

  ND.console = { progress: progress, stream: stream };
})(window.ND = window.ND || {});
