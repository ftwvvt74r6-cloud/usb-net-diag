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

    /* ---------------------------------------------------------- 一眼三层（结论区） */
    /* 硬要求：横幅标题 ≤14 字、问题句 ≤40 字、每条动作 ≤30 字且动词开头。
       这里所有句子都按这个预算写，UI 侧另有一道 clip 兜底。 */
    verdict: {
      kicker: "本次结论",
      scopeLabel: "影响范围",
      scope: {
        peer: "只影响这个对端",
        some: "影响部分目标",
        all: "影响整机上网",
        none: "全部正常",
        unknown: "无法判断"
      },
      titleSuffix: "异常",
      titleOk: "四层全部正常",
      titleZero: "一个报文都没抓到",
      titleThin: "证据不足，先别下结论",
      okProblem: "没有发现影响上网的问题",
      zeroProblem: "网卡选错，或过滤把流量挡住了",
      thinProblem: "样本太少，任何一层都判不准",
      stepsHeading: "现在怎么做",
      stepNo: "第 {n} 步",
      ownerHeading: "找谁解决",
      ownerBasis: "判断依据",
      ownerPartner: "需要谁配合",
      ownerNone: "四层没有异常项，本次不需要找人协作。",
      copyFooter: "需要协作时发给对方的内容：结论 + 依据 + 请对方做的事",
      copySummary: "复制摘要",
      copySummaryOk: "摘要已复制",
      copySummaryFail: "复制失败，请手动选择文本",
      prefillLive: "已把 {target} 填进单目标诊断，确认参数后点开始",
      noTarget: "这次结果里没有可复测的地址，请手动填写目标",
      evFold: "展开证据",
      evBasis: "依据",
      evCoverage: "本次覆盖",
      evNot: "明确未覆盖",
      evConf: "置信度",
      evItems: "证据",
      evAdvice: "完整排查思路",
      evProbe: "探针基线",
      evPath: "路径剖面",
      evEmpty: "本次没有可列出的证据条目。",
      boundaryLead: "适用范围",
      boundaryFull: "完整边界",
      boundaryNone: "旧记录没有边界信息",
      confidence: "{level}（{value}）",
      confidenceNone: "未给出",
      /* 动作按钮：只允许这几个真实动作，宁可少一个也不放不能点的文字 */
      act: {
        retest: "立即复测",
        hops: "查看逐跳",
        copy: "复制摘要",
        logs: "查看日志",
        rerun: "改参数再测",
        fold: "展开证据"
      },
      /* 责任归属四格 */
      /* 每格一句「需要谁配合」，控制在 12 字内：四格在总览左栏只有 100 多像素宽 */
      owners: {
        host: { label: "本机", partner: "需要你：关掉占带宽的程序" },
        lan: { label: "本地网络", partner: "需要网管：查交换机与网线" },
        carrier: {
          label: "运营商·承载网",
          partner: "需要运营商：查线路丢包",
          byKind: { icmp: "需要运营商：查路由与拦截策略" }
        },
        peer: { label: "对端服务", partner: "需要对方：查服务与防火墙" }
      },
      /* 判断依据的模板（数字会被加粗） */
      basis: {
        hostWin: "本机接收窗口被塞满 {n} 次",
        hostOk: "本机网卡与协议栈没有异常",
        lanArp: "网关 ARP 无应答",
        lanHop: "第 {hop} 跳（网关）开始丢包",
        carrierHop: "第 {hop} 跳之后开始丢包，共 {loss}%",
        carrierBoth: "两侧都在丢包，网关侧也丢 {loss}%",
        peerSingle: "只有 {target} 连不上，其他对端正常",
        peer5xx: "对端返回 {n} 次 5xx",
        peerRefused: "对端明确拒绝连接",
        dnsFail: "DNS 解析失败率 {rate}%（服务器 {srv}）",
        carrierIcmp: "收到 {n} 条 ICMP 不可达，链路中途被拦"
      },
      boundaryCount: "{a} 条覆盖 · {b} 项未覆盖",
      /* 没被高亮的三格也要各给一句，否则只剩标签像半成品 */
      clear: {
        host: "本机能看到的项目都正常",
        lan: "网关与本地链路正常",
        carrier: "链路侧没有丢包",
        peer: "对端响应正常"
      },
      /* 三步动作（动词开头、≤30 字）。按故障类型取，最多 3 条 */
      steps: {
        connFail: [
          { text: "复测确认端口是否可达", act: "retest" },
          { text: "看第几跳开始不通", act: "hops" },
          { text: "把报告发给对端服务方", act: "copy" }
        ],
        retrans: [
          { text: "复测确认丢包是否持续", act: "retest" },
          { text: "看第几跳开始变慢", act: "hops" },
          { text: "把丢包数据发给运营商", act: "copy" }
        ],
        /* ICMP 不可达 / 超时：报文被中途拒掉，「变慢」那套动作会误导用户 */
        icmp: [
          { text: "确认哪些地址连不上", act: "retest" },
          { text: "看第几跳回 ICMP 不可达", act: "hops" },
          { text: "把 ICMP 记录发给运营商", act: "copy" }
        ],
        dns: [
          { text: "换一个公共 DNS 再测", act: "retest" },
          { text: "查本机 DNS 设置是否正确", act: "logs" },
          { text: "把 DNS 结果发给网管", act: "copy" }
        ],
        http: [
          { text: "查服务端日志确认 5xx", act: "logs" },
          { text: "复测确认是否稳定复现", act: "retest" },
          { text: "把状态码发给服务方", act: "copy" }
        ],
        arp: [
          { text: "插回网线或换个端口", act: "retest" },
          { text: "确认网关地址是否正确", act: "logs" },
          { text: "找网管查交换机", act: "copy" }
        ],
        ok: [
          { text: "保存本次报告留档", act: "copy" },
          { text: "过 10 分钟再测一次", act: "retest" },
          { text: "展开证据看统计口径", act: "fold" }
        ],
        /* 0 包 / 样本不足：不指着「找谁」发力，先让用户把采集搞对 */
        zero: [
          { text: "换一块网卡再测一次", act: "rerun" },
          { text: "看采集日志找原因", act: "logs" }
        ],
        thin: [
          { text: "把时长调到 30-60 秒再测", act: "rerun" },
          { text: "换一个确定可达的目标", act: "rerun" }
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

    /* ---------------------------------------------------------- 专业数据面板 */
    panel: {
      title: "实时与专业数据",
      sub: "左边说人话，右边给原始数据",
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
      streamsHint: "点任意一行复制对应的 Wireshark 过滤器",
      colFlow: "源 → 目标",
      colPkts: "包",
      colBytes: "字节",
      colRtt: "RTT",
      colRetrans: "重传",
      copyFilter: "复制过滤器",
      filterCopied: "过滤器已复制：{f}",
      filterFail: "复制失败，请手动复制：{f}",
      more: "显示全部 {n} 条会话",
      l7Note: "按 TCP 会话数统计；DNS 走 UDP，见下一行",
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
      empty: "完成一次诊断后，这里会出现本次的专业数据",
      running: "正在采集，结束后这里出统计",
      runningFill: "采集中，下面这些位置结束后依次填数",
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
