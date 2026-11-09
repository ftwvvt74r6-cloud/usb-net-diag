/* ============================================================================
   env.js · 「环境与依赖」卡（首页右侧 / 也是能力置灰的唯一依据）
   ----------------------------------------------------------------------------
   后端 /api/selfcheck 与 /api/app 的 checks 是同一份（同一短 TTL 缓存），
   每项形状固定：{key,name,ok,detail,fix_kind,fix_url,fix_command,impact,doc_url}。
   这里只做三件事：排序、把 ok/受限/缺失翻译成图标与一句话、按 fix_* 给修复动作。
   ========================================================================== */
(function (ND) {
  "use strict";

  var U = ND.ui;
  var C = ND.copy || {};

  /* 四项主检查的顺序由产品定：驱动 → 权限 → 引擎 → 逐跳引擎。
     python / port 收在「其他检查」里，它们不在主链路上。 */
  var MAIN = ["npcap", "admin", "tshark", "scapy"];
  var OTHER = ["python", "port"];

  function index(checks) {
    var map = {};
    (checks || []).forEach(function (c) {
      if (c && c.key) map[c.key] = c;
    });
    return map;
  }

  /* ok → 绿勾；能降级使用的（权限不足 / 没有 scapy）→ 黄叹号；其余 → 红叉 */
  function severity(check) {
    if (!check) return "na";
    if (check.ok) return "ok";
    if (check.fix_kind === "elevate" || check.key === "scapy") return "warn";
    return "bad";
  }

  function glyph(sev) {
    if (sev === "ok") return "check";
    if (sev === "warn") return "alert";
    if (sev === "bad") return "cross";
    return "alert";
  }

  function stateLabel(sev) {
    var e = C.env || {};
    if (sev === "ok") return e.stOk || "";
    if (sev === "warn") return e.stLimited || "";
    return e.stMissing || "";
  }

  function missingCount(checks) {
    var n = 0;
    (checks || []).forEach(function (c) { if (c && !c.ok) n++; });
    return n;
  }

  /* 顶栏三枚徽章：只放主链路上的三项，多了会把标题挤掉 */
  function chips(checks) {
    var map = index(checks);
    var box = document.createDocumentFragment();
    ["tshark", "npcap", "admin"].forEach(function (key) {
      var c = map[key];
      if (!c) return;
      var sev = severity(c);
      var kind = sev === "ok" ? "ok" : (sev === "warn" ? "warn" : "crit");
      var label = shortName(c);
      var ch = U.chip(kind, label);
      if (c.detail) ch.title = c.detail;
      box.appendChild(ch);
    });
    return box;
  }

  function shortName(check) {
    var name = String(check.name || check.key || "");
    /* 后端名字带后缀（「Npcap 抓包驱动」），顶栏只留前半截 */
    return name.split(" ")[0] || name;
  }

  /* ------------------------------------------------------------ 卡片 */
  /* opts: { onRecheck: function(checks) } */
  function card(checks, opts) {
    opts = opts || {};
    var E = C.env || {};
    var map = index(checks);

    var sec = U.el("section", "card");
    var hd = U.el("div", "card-hd");
    hd.appendChild(U.el("h2", "", C.card.env));
    var sub = U.el("span", "card-sub", C.card.envSub);
    hd.appendChild(sub);

    var recheck = U.btn(C.act.recheck, {
      kind: "ghost",
      size: "sm",
      icon: "refresh",
      onClick: function () { recheckAll(body, opts, recheck); }
    });
    recheck.classList.add("hd-act");
    hd.appendChild(recheck);
    sec.appendChild(hd);

    var bd = U.el("div", "card-bd");
    var body = U.el("div", "envbody");
    bd.appendChild(body);
    sec.appendChild(bd);

    paint(body, checks, opts);

    /* 重新检测：POST 没有，GET /api/selfcheck 是新一次探测（缓存 TTL 只有 1.5s） */
    function recheckAll(host, options, button) {
      if (button.disabled) return;
      var label = button.querySelector(".btn-t");
      var old = label.textContent;
      button.disabled = true;
      label.textContent = C.act.rechecking;
      ND.api.selfcheck().then(function (res) {
        button.disabled = false;
        label.textContent = old;
        if (!res.ok) {
          U.toast(U.tpl(E.recheckFail, { reason: U.why(res) }), "crit");
          return;
        }
        var list = (res.data && res.data.checks) || [];
        paint(host, list, options);
        /* 依赖补齐后入口要能立刻解锁，不用刷新页面 */
        if (res.data && res.data.capabilities && ND.boot && ND.boot.applyCapabilities) {
          ND.boot.applyCapabilities(res.data.capabilities);
        }
        if (options.onRecheck) options.onRecheck(list);
        var left = missingCount(list);
        U.toast(left ? U.tpl(E.recheckDone, { count: left }) : E.recheckAllOk,
                left ? "warn" : "ok");
      });
    }

    return sec;
  }

  function paint(host, checks, opts) {
    U.clear(host);
    var map = index(checks);
    var E = C.env || {};
    var left = missingCount(checks);

    if (!checks || !checks.length) {
      host.appendChild(U.el("p", "muted", E.none));
      return;
    }

    var lead = U.el("p", "envlead" + (left ? " warn" : ""));
    lead.textContent = left
      ? U.tpl(E.missingLead, { count: left })
      : E.allOk;
    host.appendChild(lead);

    var list = U.el("ul", "envlist");
    MAIN.forEach(function (key) {
      if (map[key]) list.appendChild(row(map[key]));
    });
    host.appendChild(list);

    var other = OTHER.filter(function (k) { return map[k]; });
    if (other.length) {
      var det = document.createElement("details");
      det.className = "envother";
      var sum = document.createElement("summary");
      sum.textContent = E.groupOther + "（" + other.length + "）";
      det.appendChild(sum);
      var ul = U.el("ul", "envlist");
      other.forEach(function (k) { ul.appendChild(row(map[k])); });
      det.appendChild(ul);
      host.appendChild(det);
    }

    host.appendChild(U.el("p", "envfoot", E.fixHint));
  }

  function row(check) {
    var E = C.env || {};
    var sev = severity(check);
    var li = U.el("li", "envrow " + sev);

    li.appendChild(U.icon(glyph(sev), "envic"));

    var main = U.el("div", "envmain");
    var top = U.el("div", "envtop");
    top.appendChild(U.el("span", "envname", check.name || check.key));
    top.appendChild(U.el("span", "envst " + sev, stateLabel(sev)));
    main.appendChild(top);

    if (check.detail) main.appendChild(U.el("p", "envdetail", check.detail));
    if (sev !== "ok" && check.impact) {
      main.appendChild(U.el("p", "envimpact", E.impactLabel + "：" + check.impact));
    }
    li.appendChild(main);

    var acts = actions(check);
    if (acts) li.appendChild(acts);
    return li;
  }

  /* 按钮由后端给的修复手段决定：fix_kind=url → 官网；有 fix_command → 复制命令；
     fix_kind=elevate → 直接发起 UAC 提权；每项都可以「我有路径」。
     后端没给手段的（例如 scapy）就不硬塞按钮 —— 一个点了没反应的按钮
     比没有按钮更糟。重新检测是全局动作，放在卡片标题栏，不在每行重复。 */
  function actions(check) {
    var E = C.env || {};
    if (check.ok) return null;
    var box = U.el("div", "envacts");

    if (check.fix_kind === "elevate") {
      box.appendChild(U.btn(E.elevate, {
        kind: "ghost", size: "sm", icon: "refresh",
        onClick: function (e) { askElevate(e.currentTarget); }
      }));
    } else if (check.fix_url) {
      var a = U.btn(C.act.openSite, { kind: "ghost", size: "sm", icon: "external" });
      a.addEventListener("click", function () {
        window.open(check.fix_url, "_blank", "noopener");
      });
      box.appendChild(a);
    }

    if (check.fix_command) {
      box.appendChild(U.btn(C.act.copyCmd, {
        kind: "ghost", size: "sm", icon: "copy",
        onClick: function () {
          U.copyText(check.fix_command).then(function (ok) {
            U.toast(ok ? C.act.copied : C.act.copyFail, ok ? "ok" : "crit");
          });
        }
      }));
    }

    box.appendChild(U.btn(C.act.havePath, {
      kind: "ghost", size: "sm", icon: "folder",
      onClick: function () { openPath(check); }
    }));
    return box;
  }

  /* 提权：走启动器已有的 UAC 路径，成功后旧服务会退出，页面需要重连 */
  function askElevate(button) {
    var E = C.env || {};
    if (button) button.disabled = true;
    ND.api.elevate().then(function (res) {
      if (button) button.disabled = false;
      if (res.ok) {
        U.toast((res.data && res.data.message) || E.elevateAsk, "ok");
        return;
      }
      U.toast(U.tpl(E.elevateFail, { reason: U.why(res) }) + " " + E.elevateManual, "crit");
    });
  }

  /* ------------------------------------------------------------ 我有路径 */
  function openPath(check) {
    var E = C.env || {};
    var body = document.createDocumentFragment();

    body.appendChild(U.el("p", "muted", U.tpl(E.pathBody, { name: check.name || check.key })));

    var field = U.el("div", "field");
    var label = U.el("label", "", E.pathLabel);
    var input = U.el("input", "input");
    input.type = "text";
    input.placeholder = E.pathPh || "";
    input.spellcheck = false;
    var inputId = "path-" + String(check.key || "x");
    input.id = inputId;
    label.setAttribute("for", inputId);
    field.appendChild(label);

    var line = U.el("div", "field-row");
    line.appendChild(input);
    field.appendChild(line);
    body.appendChild(field);

    var err = U.el("p", "formerr");
    body.appendChild(err);

    var cancel = U.btn(C.act.cancel, { kind: "ghost" });
    var save = U.btn(C.act.save, {});
    var browser = U.btn(E.pathBrowse, {
      kind: "ghost", size: "sm", icon: "folder",
      onClick: function () {
        ND.api.pickPath("file").then(function (res) {
          if (res.ok && res.data && res.data.path) {
            input.value = res.data.path;
            err.textContent = "";
            return;
          }
          /* 浏览器读不到绝对路径时，别假装成功，直接把话说清楚 */
          err.textContent = E.pathBrowseFail;
        });
      }
    });
    line.appendChild(browser);

    var box = U.modal({
      title: E.pathTitle,
      body: body,
      actions: [cancel, save]
    });

    cancel.addEventListener("click", function () { box.close(); });
    save.addEventListener("click", function () {
      var val = (input.value || "").trim();
      if (!val) {
        err.textContent = E.pathEmpty;
        input.focus();
        return;
      }
      save.disabled = true;
      save.querySelector(".btn-t").textContent = C.act.saving;
      ND.api.savePath(check.key, val).then(function (res) {
        save.disabled = false;
        save.querySelector(".btn-t").textContent = C.act.save;
        if (res.ok) {
          box.close();
          U.toast(E.pathSaved, "ok");
          return;
        }
        if (ND.api.absent(res)) {
          /* R4 还没实现：不报错，给出可执行的手工办法 */
          err.textContent = U.tpl(E.pathSaveUnsupported, { name: check.name || check.key });
          return;
        }
        err.textContent = U.tpl(E.pathSaveFail, { reason: U.why(res) });
      });
    });
  }

  ND.env = {
    MAIN: MAIN,
    OTHER: OTHER,
    index: index,
    severity: severity,
    missingCount: missingCount,
    chips: chips,
    card: card
  };
})(window.ND = window.ND || {});
