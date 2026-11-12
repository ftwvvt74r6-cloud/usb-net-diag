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
      latencySub: "TCP 往返时延均值",
      lossSub: "TCP 重传率估算值",
      sessionSub: "本次捕获会话数",
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
      pathBrowseFail: "无法读取完整路径：请手动粘贴，或从系统文件管理器复制路径",
      pathSaveUnsupported: "当前版本还不能自动保存路径。请把 {name} 加到系统的 PATH（或装到默认目录），然后点「重新检测」。",
      pathSaved: "已保存，正在重新检测…",
      pathSaveFail: "保存失败：{reason}",
      elevate: "以管理员身份重启",
      elevateAsk: "已请求管理员权限，请在系统弹窗里点「是」",
      elevateFail: "提权请求失败：{reason}",
      elevateManual: "请关闭本页面，右键启动器并选择「以管理员身份运行」。",
      recheckDone: "重新检测完成：{count} 项没有通过。",
      recheckAllOk: "重新检测完成：全部通过。",
      recheckFail: "重新检测失败：{reason}",
      groupOther: "其他检查",
      otherHint: "这两项只在特定场景才影响结果，不影响上面的四项。",
      none: "未读取到环境检查结果，请点击右上角「重新检测」。",
      fixHint: "补齐后点「重新检测」，不需要重启程序。",
      allOk: "四项均已就绪：抓包、离线分析、逐跳路径可用。",
      locked: "暂不可用：环境里缺依赖，到「总览 → 环境与依赖」补齐后点「重新检测」",
      missingLead: "{count} 项没通过，相关入口已置灰；连通与速度测试、报告与导出仍然可用。"
    },

    /* 最近一次结果 */
    lastRun: {
      emptyTitle: "还没有诊断结果",
      emptyBody: "从左侧任一入口发起诊断，结果将保留在此处。",
      when: "{when} · {mode}{target}",
      counters: "严重 {critical} · 警告 {warning} · 用时 {duration}",
      summaryOnly: "完整结果已不在内存（服务重启过，或超出保留上限），只能看摘要；重新诊断一次就能看到完整结论。",
      summaryTitle: "上次结果摘要",
      summaryKept: "完整结果仍在内存中，可重新打开结果页查看四层结论。",
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
      reasonGeneric: "未取得结论；具体原因见日志，末条错误通常为根因。",
      advice: "查看日志末条错误，补齐环境（驱动 / 权限 / 网卡）后重试。",
      legacy: "上一次任务没有成功，所以没有可展示的结论。"
    },

    /* 设置页 */
    settings: {
      /* ---- 常驻采集 ---- */
      agentTitle: "常驻采集",
      agentSub: "后台按间隔采样，积累时延与丢包趋势",
      agentStateOn: "运行中",
      agentStateOff: "未安装",
      agentStateErr: "异常",
      agentStateUnknown: "未开启",
      agentInterval: "采样间隔",
      agentIntervalVal: "{n} 秒",
      agentLast: "最近一次采样",
      agentLastNone: "尚无采样记录",
      agentInstall: "安装常驻采集",
      agentInstalling: "正在安装…",
      agentUninstall: "卸载",
      agentUninstalling: "正在卸载…",
      agentInstallHint: "安装包在工具目录内：双击 install-agent.bat 完成安装（需要管理员权限）。",
      agentUninstallTitle: "卸载常驻采集？",
      agentUninstallBody: "卸载后不再后台采样，历史趋势会停止增长；已经记录的数据保留在 reports/history 下。",
      agentOffTitle: "采集未开启",
      agentOffBody: "本地服务还没有提供常驻采集接口，趋势与历史事件暂时没有数据。开启后会按间隔自动记录本机到监测目标的时延。",
      agentOffWhy: "当前版本未提供该接口：升级到带常驻采集的版本后再试。",
      agentManualTitle: "未安装计划任务",
      agentManualBody: "采集进程当前是手动启动的，重新登录后不会自动开始；点下面的按钮安装成计划任务。",
      agentErr: "最近一次错误：{reason}",
      agentIntervalFail: "采样间隔未能下发：{reason}",
      agentIntervalSaved: "采样间隔已改，下一轮按新间隔采样",

      /* ---- 监测目标 ---- */
      targetsTitle: "监测目标",
      targetsSub: "最多 3 条",
      targetsHint: "填入业务服务器地址后，会持续测量本机到该服务器的时延 / 抖动 / 丢包；留空只测网关与 DNS。",
      targetsHost: "地址",
      targetsHostPh: "10.0.0.5 或 oa.company.com",
      targetsPort: "端口（选填）",
      targetsPortPh: "443",
      targetsAdd: "添加目标",
      targetsFull: "已满 3 条",
      targetsRemove: "移除",
      targetsEmpty: "尚未添加目标：当前只测网关与 DNS。",
      targetsInvalid: "地址格式不对：填 IP 或域名，不要带协议头与路径。",
      targetsSaved: "监测目标已保存，立即生效",
      targetsSaveFail: "保存失败：{reason}",

      /* ---- 阈值 ---- */
      thrTitle: "告警阈值",
      thrSub: "超出即记为事件",
      thrRtt: "时延",
      thrJitter: "抖动",
      thrLoss: "丢包",
      thrHint: "历史事件按这三条阈值判定；改完立即生效，不需要重启。",
      thrSaved: "阈值已更新，立即生效",
      thrLocalOnly: "采集未开启：阈值已保存在本机，常驻采集就绪后自动下发。",

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
      targetHint: "仅采集与该目标相关的流量；留空表示不过滤，采集全部流量。",
      duration: "抓包时长（秒）",
      durationHint: "采集窗口过短会遗漏流量；排查建议 30–60 秒。",
      iface: "网卡",
      ifaceAuto: "自动选择（推荐）",
      ifaceHint: "自动选择会先探测有流量的网卡，再开始采集。",
      ifaceEmpty: "没有读到网卡列表，先到「总览 → 环境与依赖」看一眼 Npcap。",
      engine: "采集引擎",
      engineAuto: "自动（优先 Scapy，失败回落 tshark）",
      engineScapy: "Scapy（Python 逐包解析）",
      engineTshark: "tshark（Wireshark 自带）",
      engineHint: "通信观察只读不发包；会话表按「端口 + 首包特征」识别协议。",
      pcap: "已有抓包文件",
      pcapPh: "— 选择 captures 目录中的文件 —",
      pcapEmpty: "captures 目录中没有 pcap 文件：请先完成一次实时采集。",
      port: "端口",
      portHint: "留空按协议画像自动选（HTTPS 443 / HTTP 80）。",
      path: "同时做逐跳路径（MTR / tracert）",
      shadow: "抓包同时做路径剖面与探针基线（每 5 秒，少量探测包）",
      shadowHint: "探针仅发送少量 ICMP / TCP SYN / DNS 查询，并执行一次 TTL 递增的逐跳探测；均已从业务统计中排除。",
      needTarget: "请先填写要诊断的域名或 IP",
      needPcap: "请先选择一个 pcap 文件",
      startFail: "启动失败：{reason}",
      starting: "正在启动…",
      noAdmin: "当前未以管理员身份运行：抓包类模式需关闭本页面，右键启动器选择「以管理员身份运行」后重试。",
      locked: "该模式当前不可用：环境缺少依赖，请到「总览 → 环境与依赖」补齐。"
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
      consoleEmpty: "暂无输出…",
      consoleDone: "采集结束 · {count} 行输出",
      consoleExpand: "展开输出",
      consoleCollapse: "收起输出",
      consoleFollow: "自动滚到底",
      live: "实时追加",
      noJob: "尚未开始采集：填写参数后点击下方按钮启动。",
      starting: "正在启动…",
      runningLabel: "运行中…",
      cardTitle: "运行"
    },

    /* ---------------------------------------------------------- 技术详情 */
    tech: {
      title: "技术详情",
      hint: "原始参数与中间结果；提交问题时随截图一并提供。",
      command: "抓包命令",
      commandNote: "依据本次下发参数推算；实际命令行由采集层生成（需求单 R6-1 待后端下发）。",
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
      probeRoleFiltered: "（{reason}：目标不回 ICMP，不是链路丢包）",
      reasonIcmpFiltered: "ICMP 被过滤",
      reasonRefused: "目标拒绝（RST）",
      reasonTimeout: "无响应",
      hopFiltered: "被过滤",
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
      evidenceEmpty: "未发现达到判定阈值的异常条目。",
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

    /* ---------------------------------------------------------- 一眼三层（结论区） */
    /* 硬要求：横幅标题 ≤14 字、问题句 ≤40 字、每条动作 ≤30 字且动词开头。
       这里所有句子都按这个预算写，UI 侧另有一道 clip 兜底。 */
    verdict: {
      kicker: "定性结论",
      scopeLabel: "影响范围",
      scope: {
        peer: "仅影响该对端",
        some: "影响部分目标",
        all: "影响整机出网",
        none: "全部正常",
        unknown: "无法判断"
      },
      titleSuffix: "异常",
      titleOk: "四层指标未见异常",
      titleZero: "未采集到任何报文",
      titleThin: "证据不足，暂不下结论",
      okProblem: "四层指标均未见异常",
      zeroProblem: "采集网卡或过滤条件导致零报文",
      thinProblem: "样本量不足，四层判定均不可信",
      /* ① 的一句话定性：按故障类型给规范表述，不复述后端口语原文。
         后端的 verdict.plain 原文仍保留在「明细 → 后端结论原文」里可追溯。 */
      problemByKind: {
        single: "连接建立失败或超时：目标端口未响应或连接被拒绝",
        refused: "连接被对端主动拒绝：目标端口无监听，或访问控制未放行",
        retrans: "应用响应延迟升高：页面加载停滞、远程桌面帧率下降、批量传输吞吐降低",
        both: "应用响应延迟升高：页面加载停滞、远程桌面帧率下降、批量传输吞吐降低",
        icmp: "网络层不可达：目标网段或主机路由被阻断，连接无法建立",
        dns: "域名解析失败率升高：部分域名无法解析，应用表现为连接超时",
        "5xx": "服务端返回 5xx：请求被服务端拒绝，与链路质量无关",
        arp: "本地链路不可达：网关地址解析无响应，出网流量无法转发",
        win: "本机接收窗口耗尽：应用侧读取缓慢，链路被动丢包",
        hop: "链路中途劣化：逐跳路径上出现丢包，应用响应随之抖动",
        icmpFiltered: "目标不响应 ICMP（常见于服务器侧策略），本次以 TCP 指标为准"
      },
      stepsHeading: "处置步骤",
      stepNo: "第 {n} 步",
      ownerHeading: "责任归属",
      ownerBasis: "判定依据",
      ownerPartner: "协作建议",
      ownerNone: "四层无异常项，本次无需跨方协作。",
      copyFooter: "跨方协作材料：结论 · 依据 · 请求事项",
      copySummary: "复制摘要",
      copySummaryOk: "摘要已复制",
      copySummaryFail: "复制失败，请手动选择文本",
      prefillLive: "已将 {target} 填入单目标诊断，确认参数后开始采集",
      noTarget: "本次结果中没有可复测的地址，请手动填写目标",
      evFold: "展开明细",
      evBasis: "依据",
      evCoverage: "本次覆盖",
      evNot: "明确未覆盖",
      evConf: "置信度",
      evItems: "证据",
      evAdvice: "完整处置建议",
      evProbe: "探针基线",
      evPath: "路径剖面（MTR / Traceroute）",
      evEmpty: "未发现达到判定阈值的异常条目；阈值内指标见下方关键指标表。",
      boundaryLead: "适用范围",
      boundaryFull: "完整边界",
      boundaryNone: "旧记录缺少边界信息",
      /* 后端没给 key_limit / 覆盖清单时的兜底：一行也要说清「这套结论用到哪」 */
      boundaryFallback: "仅覆盖本次抓包窗口内经本机网卡的 TCP/IPv4 流量",
      confidence: "{level}（{value}）",
      confidenceNone: "未给出",
      /* 动作按钮：只允许这几个真实动作，宁可少一个也不放不能点的文字 */
      act: {
        retest: "立即复测",
        hops: "逐跳定位",
        copy: "复制摘要",
        logs: "查看日志",
        rerun: "调整参数复测",
        fold: "展开明细"
      },
      /* 责任归属四格：一格给「是谁」，一格给「建议怎么协作」 */
      owners: {
        host: { label: "本机", partner: "建议本机侧操作：降低并发占用（关闭大流量下载/上传）" },
        lan: { label: "本地网络", partner: "建议网络管理员核查交换机与链路" },
        carrier: {
          label: "运营商·承载网",
          partner: "建议提交运营商核查承载网",
          byKind: { icmp: "建议提交运营商核查路由与拦截策略" }
        },
        peer: {
          label: "对端服务",
          partner: "建议对端服务方核查服务与防火墙",
          byKind: { icmpFiltered: "对端策略屏蔽了 ICMP：请对端放通或直接忽略该项" }
        }
      },
      /* 判断依据的模板（数字会被加粗） */
      basis: {
        hostWin: "本机接收窗口耗尽 {n} 次",
        hostOk: "本机网卡与协议栈未见异常",
        lanArp: "网关 ARP 无响应",
        lanHop: "第 {hop} 跳（网关）出现丢包",
        carrierHop: "第 {hop} 跳起出现丢包，累计 {loss}%",
        carrierBoth: "双向均存在丢包，网关侧 {loss}%",
        peerSingle: "仅 {target} 不可达，其余对端正常",
        peer5xx: "对端返回 {n} 次 5xx",
        peerRefused: "对端主动拒绝连接",
        dnsFail: "DNS 解析失败率 {rate}%（服务器 {srv}）",
        carrierIcmp: "收到 {n} 条 ICMP 不可达，链路中途阻断",
        icmpFiltered: "ICMP 全丢但 TCP 可达：目标不响应 ICMP，不是链路丢包"
      },
      boundaryCount: "{a} 条覆盖 · {b} 项未覆盖",
      /* 没被高亮的三格也要各给一句，否则只剩标签像半成品 */
      clear: {
        host: "本机侧指标未见异常",
        lan: "网关与本地链路未见异常",
        carrier: "链路侧未见丢包",
        peer: "对端响应未见异常"
      },
      /* 三步动作（动词开头、≤30 字）。按故障类型取，最多 3 条 */
      steps: {
        connFail: [
          { text: "复测确认目标端口可达性", act: "retest" },
          { text: "逐跳定位，确认阻断起始跳", act: "hops" },
          { text: "将对端连通性证据提交服务方", act: "copy" }
        ],
        retrans: [
          { text: "复测确认丢包持续性", act: "retest" },
          { text: "逐跳定位（Traceroute/MTR），确认劣化起始跳", act: "hops" },
          { text: "将逐跳与丢包证据提交运营商核查承载网", act: "copy" }
        ],
        /* ICMP 不可达 / 超时：报文被中途拒掉，「变慢」那套动作会误导用户 */
        icmp: [
          { text: "确认受影响目标范围", act: "retest" },
          { text: "逐跳定位 ICMP 不可达来源", act: "hops" },
          { text: "将 ICMP 记录提交运营商核查", act: "copy" }
        ],
        /* 目标不回 ICMP（TCP 正常）：不要劝人「查丢包」，那条路上没证据 */
        icmpFiltered: [
          { text: "按 TCP 口径复测时延与重传", act: "retest" },
          { text: "查看逐跳，跳过不回 ICMP 的跳", act: "hops" },
          { text: "把「目标不回 ICMP」写进交付说明", act: "copy" }
        ],
        dns: [
          { text: "切换公共 DNS 服务器复测", act: "retest" },
          { text: "核查本机 DNS 配置", act: "logs" },
          { text: "将 DNS 解析结果提交网络管理员", act: "copy" }
        ],
        http: [
          { text: "核查服务端日志确认 5xx", act: "logs" },
          { text: "复测确认问题可复现性", act: "retest" },
          { text: "将 HTTP 状态码提交服务方", act: "copy" }
        ],
        arp: [
          { text: "检查网线与交换机端口连接", act: "retest" },
          { text: "核对默认网关地址配置", act: "logs" },
          { text: "提交网络管理员核查交换机", act: "copy" }
        ],
        ok: [
          { text: "归档本次报告", act: "copy" },
          { text: "间隔 10 分钟后复测", act: "retest" },
          { text: "查看明细核对统计口径", act: "fold" }
        ],
        /* 0 包 / 样本不足：不指着「找谁」发力，先让用户把采集搞对 */
        zero: [
          { text: "更换采集网卡后重新采集", act: "rerun" },
          { text: "查看采集日志定位原因", act: "logs" }
        ],
        thin: [
          { text: "将采集时长调整为 30–60 秒", act: "rerun" },
          { text: "更换可达目标后复测", act: "rerun" }
        ]
      },
      /* 复制给协作方的摘要骨架 */
      summaryTitle: "【结论】",
      summaryBasis: "【依据】",
      summaryAsk: "【请对方做的事】",
      summaryOwner: "【责任归属】",
      summaryScope: "【适用范围】",
      summaryReport: "【报告】"
    },

    /* ---------------------------------------------------------- 三段报告骨架 */
    report: {
      title: "诊断报告",
      sub: "结论 · 证据 · 数据",
      sec1: "定性结论",
      sec2: "证据",
      sec3: "数据",
      sec1sub: "一句话定性 · 影响范围 · 处置路径",
      sec2sub: "证据条目与关键指标",
      sec3sub: "专业统计与网络参数",
      /** 第二段：证据条目四列 */
      evTitle: "证据条目",
      evCount: "{n} 条",
      evLayer: "层级",
      evWhat: "现象",
      evNum: "关键数值",
      evJudge: "判定",
      evEmpty: "未发现达到判定阈值的异常条目；阈值内指标见下方关键指标表。",
      /** 第二段：关键指标表 */
      metricsTitle: "关键指标",
      metricsSub: "阈值色标识：正常 / 关注 / 异常",
      colItem: "指标",
      colValue: "数值",
      colState: "判定",
      mRtt: "RTT 均值",
      mRttP95: "RTT P95",
      mJitter: "RTT 抖动",
      mLoss: "丢包率",
      mRetrans: "重传率",
      mDupAck: "重复 ACK",
      mRst: "RST",
      mZeroWin: "零窗口",
      mDns: "DNS 查询 / 响应",
      mDnsMs: "DNS 平均耗时",
      mDnsFail: "DNS 失败率",
      mL7: "L7 协议分布",
      mL7Note: "按 TCP 会话数",
      mL7ByPackets: "按报文数",
      mL7BySessions: "按会话数",
      mL7PacketsNote: "按报文数统计",
      mL7SessionsNote: "按会话数统计",
      mL7Sample: "样本 {n}/{total} 会话",
      unitPkt: " 包",
      unitSes: " 会话",
      evFrames: "证据帧",
      mLossProbe: "探针",
      mLossNone: "未启用探针",
      metricsNote: "丢包率取自探针基线；未启用探针时以重传率作为链路劣化指标。目标不响应 ICMP 时（探测侧已用 TCP 证明可达），丢包率只说明「目标不理 ICMP」，以 TCP 的 RTT 与重传为准。",
      stOk: "正常",
      stWarn: "关注",
      stCrit: "异常",
      /** 第三段：数据 */
      dataPanels: "专业统计",
      /* 连通与速度测试没有抓包统计，第三段的正文是逐跳路径，标题不能叫「专业统计」 */
      dataPath: "逐跳路径（Traceroute）",
      netTitle: "网络参数",
      netSub: "无线链路与主机网关（本机可采集字段）",
      netRefresh: "刷新参数",
      netEmpty: "当前无可用无线连接信息（可能为有线连接，或无线接口未连接）。",
      netFail: "读取网络参数失败",
      netGroupWireless: "无线链路",
      netGroupHost: "主机与网关",
      /** 明细折叠 */
      detail: "展开明细",
      detailSub: "探针基线 / 路径剖面 / 抓包命令与 BPF / 统计口径",
      originTitle: "后端结论原文",
      originSub: "core/copy/zh-CN.json 的原始表述，保留可追溯",
      captureTitle: "抓包命令与 BPF",
      scaleTitle: "统计口径",
      /** 运行中占位 */
      running: "采集中，三段内容在采集结束后生成",
      runningBody: "{phase} · 已用 {elapsed} 秒 · 控制台 {lines} 行",
      pro: "专业模式",
      proHint: "开启后数据段显示全部字段，采集控制台默认展开"
    },

    /* ---------------------------------------------------------- 导出构建器 */
    /* 导出文件会被转发到别人的机器上：这里的词要能脱离界面独立成立，
       不许出现「上面那张表」「如图所示」这类指着页面说话的表述。 */
    exporter: {
      title: "网络诊断报告",
      generatedAt: "生成时间",
      reportId: "报告编号",
      context: "采样上下文",
      ctxPackets: "报文",
      ctxStreams: "会话",
      ctxDuration: "时长",
      ctxIface: "网卡",
      ctxMode: "模式",
      ctxTarget: "目标",
      sec1: "结论",
      sec2: "关键指标",
      sec3: "证据明细",
      sec4: "数据表",
      sec5: "技术上下文",
      sec6: "边界与置信度",
      headline: "定性结论",
      scope: "影响范围",
      boundary: "适用范围",
      confidence: "置信度",
      steps: "处置建议",
      owner: "责任归属",
      basis: "依据",
      ask: "请求事项",
      sessions: "Top 会话",
      sessionsMore: "（共 {n} 条会话，此处列出前 {k} 条；完整明细见 JSON 导出）",
      netTitle: "网络参数",
      netEmpty: "未读取到网络参数（无线接口未连接，或无权限读取）",
      techCommand: "抓包命令",
      techCommandNone: "—（本次未下发网卡与过滤条件：离线分析或旧记录）",
      techBpf: "BPF 过滤器",
      techProbe: "探针基线",
      techSamples: "样本数",
      techWindow: "采样窗口",
      techSamplesVal: "RTT {rtt} · 握手 {hs} · DNS {dns} · HTTP {http}",
      techWindowVal: "{dur} 秒（抓包设定 {set} 秒）",
      probeVal: "发出 {sent} · 收到 {recv} · 超时 {timeout}",
      probeNone: "未启用探针",
      colLayer: "层级",
      colWhat: "现象",
      colNum: "关键数值",
      colJudge: "判定",
      colFrame: "证据帧",
      colFlow: "源 → 目标:端口",
      colPkts: "包",
      colBytes: "字节",
      colRtt: "RTT",
      colRetrans: "重传",
      colItem: "项目",
      colValue: "数值",
      netSsid: "SSID",
      netBssid: "AP MAC",
      netBand: "频段",
      netChannel: "信道",
      netRadio: "无线协议",
      netRssi: "RSSI",
      netRate: "协商速率（收 / 发）",
      netLocal: "本机 IP",
      netGateway: "默认网关",
      netGwRtt: "网关 RTT",
      netGwJitter: "网关抖动",
      netGwLoss: "网关丢包",
      noData: "—",
      copyOk: "已复制完整报告（结论 · 指标 · 证据 · 数据），可直接转发",
      copyFail: "复制失败，请改用「导出报告」下载文件",
      exportNone: "本次没有可导出的报告"
    },

    /* ---------------------------------------------------------- 历史趋势 */
    /* 这张卡只讲「这段时间怎么样」，不讲「现在为什么」。结论在报告里。 */
    history: {
      title: "历史趋势",
      sub: "本机常驻采样 · 时延与丢包",
      r1h: "近 1 小时",
      r24h: "近 24 小时",
      r7d: "近 7 天",
      mark: "标记此刻",
      exportCsv: "导出 CSV",
      exportMd: "导出摘要 md",
      markTitle: "标记此刻",
      markBody: "给这个时间点加一句备注，回看趋势时能对上是哪次变更。",
      markPh: "例：换到 5G 信道 149",
      markDefault: "手动标记",
      markDone: "已标记",
      markFail: "标记失败：{reason}",
      exportFail: "导出失败：{reason}",
      offTitle: "采集未开启",
      offBody: "常驻采集还没有运行，这里不会有趋势与事件。到「设置 → 常驻采集」开启后，会按间隔自动记录本机到监测目标的时延与丢包。",
      offGo: "去设置",
      emptyTitle: "暂无采样数据",
      emptyBody: "采集已开启，但这个时间范围内没有采样点；换一个时间范围试试。",
      note: "本机测「网络段 RTT」，不含服务端处理时延；与后台看趋势相关性，不比绝对值。",
      evTitle: "事件",
      evTime: "时间",
      evTarget: "目标",
      evType: "类型",
      evValue: "实测值",
      evThr: "阈值",
      evDur: "持续时长",
      evAp: "当时 AP / RSSI",
      evEmpty: "这段时间没有触发阈值的事件。",
      evDetail: "事件详情",
      typeRtt: "时延",
      typeLoss: "丢包",
      typeJitter: "抖动",
      covSamples: "采样 {n} 点 · 缺口 {g}",
      chartRtt: "RTT",
      chartLoss: "丢包",
      chartThr: "阈值",
      loading: "正在读取…",
      retry: "重试",
      unitMs: "ms",
      unitPct: "%",
      markFlag: "标记"
    },

    /* ---------------------------------------------------------- 专业数据面板 */
    panel: {
      title: "专业数据",
      sub: "原始抓包统计",
      pro: "专业模式",
      proOn: "专业模式已开启",
      proOff: "专业模式已关闭",
      proHint: "开启后采集控制台默认展开、面板显示全部字段",
      fold: "收起面板",
      unfold: "展开面板",
      secOverview: "概览",
      secQuality: "传输质量",
      secStreams: "Top 会话",
      secL7: "应用层分布",
      secDns: "DNS",
      ovPackets: "报文总数",
      ovStreams: "TCP 会话",
      ovDuration: "抓包时长",
      ovSamples: "采样样本数",
      qRetrans: "重传",
      qOoo: "乱序",
      qRst: "RST",
      qZeroWin: "零窗口",
      qDupAck: "重复 ACK",
      times: "{n} 次",
      ofRate: "{n} 次 · {rate}%",
      streamsHint: "选择任一记录可复制对应 Wireshark 过滤器",
      colFlow: "源 → 目标",
      colPkts: "包",
      colBytes: "字节",
      colRtt: "RTT",
      colRetrans: "重传",
      copyFilter: "复制过滤器",
      filterCopied: "过滤器已复制：{f}",
      filterFail: "复制失败，请手动复制：{f}",
      more: "显示全部 {n} 条会话",
      l7Note: "按 TCP 会话数统计；DNS 为 UDP，单独统计",
      l7CapPackets: "按报文数统计",
      l7CapSessions: "按会话数统计",
      l7UnitPkt: " 包",
      l7NotePackets: "按应用层报文数统计；DNS 为 UDP，单独统计",
      l7NoteSessions: "本次结果未下发报文数口径，按会话数统计；DNS 为 UDP，单独统计",
      l7Sample: "样本 {n}/{total} 个会话",
      l7Missing: "后端未下发应用层报文占比（需求单 R8-1），这里按会话类型统计",
      l7Empty: "本次没有可归类的会话",
      l7Http: "HTTP",
      l7Tls: "TLS",
      l7Other: "其他",
      dnsQueries: "查询",
      dnsResp: "响应",
      dnsAvg: "平均耗时",
      dnsFail: "失败率",
      empty: "完成一次诊断后展示本次专业统计",
      running: "采集中，结束后生成统计",
      runningFill: "采集中，各指标在采集结束后依次生成",
      runningBody: "{phase} · 已用 {elapsed} 秒 · 控制台 {lines} 行",
      noData: "—",
      secExtra: "更多字段",
      exRttP95: "RTT P95",
      exJitter: "抖动",
      exHs: "握手均值",
      exHttpAvg: "HTTP 均值",
      exThroughput: "吞吐",
      exProbe: "探针基线",
      exProbeNone: "本次没有发探针",
      secLogs: "控制台（最近 {n} 行）",
      secLogsNone: "本次没有控制台输出"
    },

    /* 零散的开关提示 */
    pro: {
      on: "专业模式已开启：控制台默认展开，面板显示全部字段",
      off: "专业模式已关闭：只显示摘要"
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
      network: "无法连接本地服务，请确认工具进程仍在运行",
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
