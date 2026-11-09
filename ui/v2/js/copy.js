/* ============================================================================
   copy.js · v2 的全部用户可见中文
   ----------------------------------------------------------------------------
   规则：除本文件与 #ui-config（v1 既有文案块）之外，js/html 里不许出现中文。
   五个模式的名称不在这里重复 —— 一律取 #ui-config 的 modes[*].label，
   避免同一句话有两个来源。

   关于占位符：字符串里的 {name} 由 ND.ui.tpl() 替换；缺值时整段留空而不是
   显示 {name}，避免把模板语法漏到界面上。
   ========================================================================== */
(function (ND) {
  "use strict";

  ND.copy = {
    /* 品牌与读屏标签 */
    app: {
      name: "NetDiag 网络矩阵",
      railLabel: "主导航"
    },

    /* 五个模式之外的入口 */
    nav: {
      home: "总览",
      reports: "报告与导出",
      logs: "日志中心",
      settings: "设置"
    },

    /* 通用 */
    common: {
      loading: "正在读取…",
      na: "暂无数据"
    },

    /* 后端 severity 词表（core/analyzer.py 的 SEV_ORDER）——
       前端只做查表比较，不在代码里硬写中文 */
    sev: {
      critical: "严重",
      warning: "警告",
      info: "提示",
      ok: "正常",
      na: "无样本"
    },

    /* 通用动词 */
    act: {
      retry: "重试",
      recheck: "重新检测",
      rechecking: "正在检测…",
      copy: "复制",
      copied: "已复制",
      copyFail: "复制失败，请手动选中后复制",
      openSite: "打开官网",
      copyCmd: "复制安装命令",
      havePath: "我有路径",
      close: "关闭",
      cancel: "取消",
      save: "保存",
      saving: "正在保存…",
      refresh: "刷新",
      download: "下载",
      view: "查看",
      rerun: "重新诊断",
      logs: "查看日志",
      confirm: "确定"
    },

    /* 指标卡 */
    kpi: {
      health: "健康度",
      latency: "平均延迟",
      loss: "丢包",
      session: "会话数",
      healthSub: "来自四层结论",
      healthSubLegacy: "旧记录只有等级，没有四层结论",
      latencySub: "TCP 往返均值",
      lossSub: "按 TCP 重传率估算",
      sessionSub: "本次抓到的会话数",
      noSample: "本次没有样本",
      thin: "样本不足，不给数值",
      failed: "上次任务失败，没有指标",
      noData: "还没有诊断数据",
      summaryOnly: "只剩摘要",
      running: "诊断中…",
      runningSub: "任务正在运行，完成后这里会更新"
    },

    /* 数据来源（必须让用户知道不是实时值） */
    source: {
      label: "数据来源",
      line: "{when} · {mode}{target} · {packets} 个报文，不是实时值",
      summary: "{when} · {mode}{target} · 只有摘要，没有明细指标",
      none: "还没有可用的诊断数据；完成一次诊断后这里才会出现数字。",
      running: "本次任务正在运行（{mode} · {phase}），结束后这里会更新为这次的结果。"
    },

    /* 卡片标题 */
    card: {
      lastRun: "最近一次结果",
      env: "环境与依赖",
      envSub: "四项各自影响哪些功能"
    },

    /* 环境与依赖 */
    env: {
      stOk: "已就绪",
      stMissing: "缺失",
      stLimited: "受限",
      impactLabel: "缺了会怎样",
      detailLabel: "当前",
      noCommand: "这一项没有可一键复制的命令，请用官网安装包",
      pathTitle: "手动指定程序路径",
      pathBody: "把 {name} 的安装目录或可执行文件路径填进来，保存后会立刻重新检测。",
      pathLabel: "程序路径",
      pathPh: "例如 D:\\Tools\\Wireshark\\tshark.exe",
      pathEmpty: "请先填入路径",
      pathBrowse: "浏览…",
      pathBrowseFail: "浏览器读不到完整路径：请手动粘贴，或用系统的文件管理器复制路径",
      pathSaveUnsupported: "当前版本还不能自动保存路径。请把 {name} 加到系统的 PATH（或装到默认目录），然后点「重新检测」。",
      pathSaved: "已保存，正在重新检测…",
      pathSaveFail: "保存失败：{reason}",
      elevate: "以管理员身份重启",
      elevateAsk: "已请求管理员权限，请在系统弹窗里点「是」",
      elevateFail: "提权请求失败：{reason}",
      elevateManual: "请关掉这个页面，右键启动器选「以管理员身份运行」。",
      recheckDone: "重新检测完成：{count} 项没有通过。",
      recheckAllOk: "重新检测完成：全部通过。",
      recheckFail: "重新检测失败：{reason}",
      groupOther: "其他检查",
      otherHint: "这两项只在特定场景才影响结果，不影响上面的四项。",
      none: "没有读到环境检查结果，点右上角「重新检测」再试。",
      fixHint: "补齐后点「重新检测」，不需要重启程序。",
      allOk: "四项都已就绪，抓包、抓文件分析、逐跳路径都可用。",
      locked: "暂不可用：环境里缺依赖，到「总览 → 环境与依赖」补齐后点「重新检测」",
      missingLead: "{count} 项没通过，相关入口已置灰；连通与速度测试、报告与导出仍然可用。"
    },

    /* 最近一次结果 */
    lastRun: {
      emptyTitle: "还没有诊断结果",
      emptyBody: "从左侧任一入口开始一次诊断，结果会留在这里。",
      when: "{when} · {mode}{target}",
      counters: "严重 {critical} · 警告 {warning} · 用时 {duration}",
      summaryOnly: "完整结果已不在内存（服务重启过，或超出保留上限），只能看摘要；重新诊断一次就能看到完整结论。",
      summaryTitle: "上次结果摘要",
      summaryKept: "完整结果还在内存里，可以重新打开结果页查看四层结论。",
      summaryGone: "完整结果已不在内存，只有这份摘要。",
      legacyTitle: "这是旧版本的诊断结果，缺少结论边界信息",
      legacyBody: "旧记录没有结论适用范围与边界，不能给出可复核的结论；本页只保留「重新诊断」，不提供含边界的导出。",
      legacyTag: "旧版本",
      okTag: "已完成",
      failTag: "未成功",
      /* 摘要弹窗的行标签 */
      rowWhen: "时间",
      rowMode: "模式",
      rowTarget: "目标",
      rowLevel: "健康度",
      rowCritical: "严重项",
      rowWarning: "警告项",
      rowDuration: "用时"
    },

    /* 失败卡 */
    fail: {
      title: "这次诊断没有完成",
      reasonLabel: "原因",
      adviceLabel: "建议",
      reasonGeneric: "没有拿到结论。具体原因记录在日志里，最后一条错误通常是根因。",
      advice: "先看日志里最后一条错误，按提示补齐环境（驱动 / 权限 / 网卡）后再重试一次。",
      legacy: "上一次任务没有成功，所以没有可展示的结论。"
    },

    /* 降级卡 */
    degrade: {
      title: "证据不足，给不出结论",
      zeroTitle: "这次一个报文都没抓到",
      zeroBody: "0 个报文说明流量根本没进到网卡：多半是网卡选错、过滤条件把流量挡掉了，或者目标没有在通信。",
      thinBody: "本次只抓到 {packets} 个报文，样本太少，任何一层都给不出可信结论。",
      advice: "把时长调到 30–60 秒；全网体检先确认网卡选对；单目标诊断换一个确定可达的目标再试一次。",
      again: "再测一次"
    },

    /* 设置页 */
    settings: {
      service: "后台服务",
      idleLabel: "空闲退出",
      serviceHint: "没有页面访问时，后台服务会在空闲时间到达后自动退出并释放端口；有任务在跑时不会退出。",
      idleOn: "{minutes} 分钟无访问后自动退出",
      idleOff: "已关闭自动退出（配置项 idle_exit_min = 0）",
      quit: "立即退出后台",
      quitConfirmTitle: "立即停止本机后台服务？",
      quitConfirmBody: "正在运行的任务会被中断，本页面随后会失去连接。下次使用请重新双击工具目录里的启动器。",
      quitting: "正在停止…",
      quitDone: "本地服务已停止，可以直接关闭这个页面。",
      quitFail: "停止失败：{reason}",
      runtime: "网卡与运行信息",
      version: "版本",
      pid: "进程号",
      port: "本地端口",
      url: "打开地址",
      admin: "权限",
      adminYes: "管理员",
      adminNo: "普通用户",
      iface: "网卡",
      ifaceCount: "{count} 个",
      ifaceEmpty: "没有读到网卡",
      ai: "AI 分析",
      aiOn: "已配置",
      aiOff: "未配置",
      aiProvider: "服务商",
      aiModel: "模型",
      aiBase: "接口地址",
      aiKey: "密钥",
      aiConfigHint: "配置文件：config/ai-config.json（相对工具目录），改完点下面的按钮重新读取。",
      aiCopyPath: "复制配置路径",
      aiManage: "打开配置说明",
      aiReload: "重新读取"
    },

    /* 日志中心 */
    logs: {
      title: "日志文件",
      listTitle: "全部日志",
      count: "{count} 个文件",
      hint: "日志都在工具目录的 logs 下：app 是服务日志，diag 是诊断日志，startup 是启动日志。",
      filter: "过滤文件名",
      filterPh: "过滤文件名，例如 diag-2026",
      empty: "logs 目录里还没有日志文件。",
      noMatch: "没有匹配「{q}」的日志。",
      unsupported: "本地服务还没有开放日志接口，暂时读不到 logs 目录。可以先用「导出诊断包」把日志一起打包带走。",
      loadFail: "读取日志列表失败：{reason}",
      openFail: "读取这个日志失败：{reason}",
      tooBig: "文件较大（{size}），只显示最后 200 行。",
      pack: "导出诊断包（脱敏）",
      packing: "正在打包…",
      packDone: "诊断包已生成：{path}（{size}）",
      packFail: "导出失败：{reason}",
      kindApp: "服务",
      kindDiag: "诊断",
      kindStartup: "启动",
      kindOther: "其他",
      viewerTitle: "{name}"
    },

    /* ---------------------------------------------------------- 模式页表单 */
    form: {
      target: "诊断目标",
      targetPh: "域名、IP 或网段，例如 oa.example.com",
      targetHint: "只抓和这个目标相关的流量；留空等于不过滤，等于看全部流量。",
      duration: "抓包时长（秒）",
      durationHint: "窗口越短越容易只看到零星流量；排查建议 30~60 秒。",
      iface: "网卡",
      ifaceAuto: "自动选择（推荐）",
      ifaceHint: "自动选择会先探测哪块网卡真有流量，再开始抓包。",
      ifaceEmpty: "没有读到网卡列表，先到「总览 → 环境与依赖」看一眼 Npcap。",
      engine: "采集引擎",
      engineAuto: "自动（优先 Scapy，失败回落 tshark）",
      engineScapy: "Scapy（Python 逐包解析）",
      engineTshark: "tshark（Wireshark 自带）",
      engineHint: "通信观察只读不发包；会话表按「端口 + 首包特征」识别协议。",
      pcap: "已有抓包文件",
      pcapPh: "— 选择 captures 目录中的文件 —",
      pcapEmpty: "captures 目录里还没有 pcap 文件：先用实时模式抓一次再来。",
      port: "端口",
      portHint: "留空按协议画像自动选（HTTPS 443 / HTTP 80）。",
      path: "同时做逐跳路径（MTR / tracert）",
      shadow: "抓包同时做路径剖面与探针基线（每 5 秒，少量探测包）",
      shadowHint: "探针只发少量 ICMP / TCP SYN / DNS 查询，并做一次 TTL 递增的逐跳探测；都已从业务统计里排除。",
      needTarget: "请先填写要诊断的域名或 IP",
      needPcap: "请先选择一个 pcap 文件",
      startFail: "启动失败：{reason}",
      starting: "正在启动…",
      noAdmin: "当前不是管理员：抓包类模式需要关掉页面，右键启动器选「以管理员身份运行」后再试。",
      locked: "这个模式现在不可用：环境里缺依赖，到「总览 → 环境与依赖」补齐。"
    },

    /* ---------------------------------------------------------- 运行态 */
    run: {
      phase: "当前阶段",
      remain: "剩余 {remain} 秒 / 共 {total} 秒",
      elapsed: "已用 {elapsed} 秒 / 共 {total} 秒",
      openEnded: "已用 {elapsed} 秒",
      attempt: "第 {n}/{m} 块网卡",
      percent: "{percent}%",
      consoleTitle: "采集控制台",
      consoleHint: "采集层的原样输出，等宽字体；结束时自动折叠成一行。",
      consoleEmpty: "还没有输出…",
      consoleDone: "采集结束 · {count} 行输出",
      consoleExpand: "展开输出",
      consoleCollapse: "收起输出",
      consoleFollow: "自动滚到底",
      live: "实时追加",
      noJob: "还没有开始。填好参数后点下面的按钮。",
      starting: "正在启动…",
      runningLabel: "运行中…",
      cardTitle: "运行"
    },

    /* ---------------------------------------------------------- 技术详情 */
    tech: {
      title: "技术详情",
      hint: "原始参数与中间结果，报问题时连同截图一起给对方最快。",
      command: "抓包命令",
      commandNote: "按本次下发参数推算；实际命令行由采集层拼装（需求单 R6-1 会直接下发）。",
      runningNote: "任务还在运行，这些数据结束后才会出现。",
      bpf: "BPF 过滤器",
      iface: "网卡",
      window: "抓包窗口",
      tshark: "tshark",
      pcap: "原始 pcap",
      openWireshark: "在 Wireshark 打开",
      openWiresharkTodo: "需要后端提供「用 Wireshark 打开」接口（需求单 R6-4）",
      stats: "统计口径",
      statsWindow: "采样窗口",
      statsSamples: "样本数",
      statsPackets: "报文数 / TCP 会话",
      statsProbe: "探针：发出 {sent} · 收到 {recv} · 超时 {timeout} · 已排除 {excluded}",
      statsProbeNone: "本次没有发探针",
      ifaces: "每块网卡探测结果",
      ifacesTodo: "后端还没有按网卡下发探测结果（需求单 R6-2）",
      ifaceRow: "第 {n} 块 · {name}",
      ifaceRowDetail: "{seconds} 秒 · {packets} 个报文",
      probe: "探针明细",
      probeRole: "{role}（{kind} → {target}）",
      probeRoleDetail: "发出 {sent} · 收到 {recv} · 丢包 {loss}%",
      probeError: "错误：{reason}",
      path: "逐跳路径",
      hopCols: ["TTL", "地址", "发/丢", "丢包", "RTT"],
      pathRow: "第 {hop} 跳 · {addr}",
      pathRowDetail: "{rtt} · 丢包 {loss}%",
      pathEngine: "引擎：{engine}",
      timing: "阶段耗时",
      timingTodo: "后端还没有下发阶段耗时分解（需求单 R6-3）",
      timingRow: "{phase} · {seconds} 秒",
      params: "采集参数",
      commandTodo: "这次没有下发网卡和过滤条件（离线分析 / 旧记录），给不出可复制命令。",
      valueMissing: "未记录",
      empty: "本次没有这项数据。",
      valueEmpty: "—"
    },

    /* ---------------------------------------------------------- 结果态 */
    result: {
      title: "诊断结果",
      kicker: "四层结论",
      layersHeading: "四层",
      evidenceHeading: "证据",
      adviceHeading: "建议",
      evidenceEmpty: "本次没有可列出的证据条目。",
      adviceEmpty: "本次没有给出建议条目。",
      evidenceCount: "{count} 条",
      exportMd: "导出报告（.md）",
      exportJson: "导出结果（.json）",
      exportFail: "导出失败：{reason}",
      exportNone: "这次结果没有可导出的正文。",
      rerun: "再测一次",
      boundary: "适用范围与边界",
      confidence: "置信度",
      basis: "依据",
      coverage: "本次覆盖",
      notCovered: "明确未覆盖",
      conclusion: "结论",
      reportId: "报告标识：{id}",
      copyOk: "已复制 ✓",
      copyFail: "复制失败，请手动选择文本",
      copy: "复制给协作方",
      reportPath: "报告文件",
      legacyNoExport: "旧记录没有边界信息，不提供含边界的导出。"
    },

    /* 还没接数据的页面（S3 起逐页替换） */
    stub: {
      title: "这个入口的运行视图在下一阶段接入",
      body: "本阶段的交付范围是总览、日志中心和设置三页；{name} 的运行与结果视图会在下一步接入，现在可以从总览页查看已有结果。"
    },

    /* 弹层与提示 */
    modal: {
      close: "关闭"
    },
    toast: {
      network: "连不上本地服务，请确认工具还在运行",
      http: "本地服务返回 {status}",
      timeout: "本地服务响应超时"
    },

    /* 单位与时间前缀：格式化一律走 ND.ui，不在这里拼句子 */
    unit: {
      sec: " 秒",
      ms: " 毫秒",
      min: " 分钟",
      packet: " 个"
    },
    time: {
      today: "今天",
      yesterday: "昨天",
      unknown: "时间未知"
    }
  };
})(window.ND = window.ND || {});
