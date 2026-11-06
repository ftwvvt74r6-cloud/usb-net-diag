"""AI 模型服务：配置持久化 + OpenAI 兼容协议调用。

设计要点：
  - 配置存 U 盘内 config/ai-config.json，改完即时生效（每次读盘，不缓存）。
  - 只用标准库 urllib，便携 Python 无需 pip。
  - 任何 OpenAI 兼容端点（DeepSeek / 通义 / Kimi / 智谱 / OpenAI / 本地 vLLM、Ollama）都能用，
    预置只是把 Base URL 与模型名填好，用户可随时手改。

对外接口：
  load_config()            读取合并后的配置
  save_config(patch)       局部更新并落盘，返回新配置
  public_config(cfg)       脱敏后的配置（可安全返回给前端）
  chat(messages, ...)      调用模型
  test_connection(...)     连通性测试
  build_messages(result)   把诊断结果转成对话消息
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
AI_CONFIG = CONFIG_DIR / "ai-config.json"

# 预置服务商：只用于前端一键填充，不限制用户填任意 OpenAI 兼容地址
PRESETS: list[dict] = [
    {"id": "deepseek", "name": "DeepSeek 官方",
     "base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat",
     "key_url": "https://platform.deepseek.com/api_keys"},
    {"id": "qwen", "name": "阿里云百炼（通义千问）",
     "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "model": "qwen-plus",
     "key_url": "https://bailian.console.aliyun.com/?apiKey=1"},
    {"id": "kimi", "name": "月之暗面 Kimi",
     "base_url": "https://api.moonshot.cn/v1", "model": "moonshot-v1-8k",
     "key_url": "https://platform.moonshot.cn/console/api-keys"},
    {"id": "zhipu", "name": "智谱 GLM",
     "base_url": "https://open.bigmodel.cn/api/paas/v4", "model": "glm-4-flash",
     "key_url": "https://bigmodel.cn/usercenter/apikeys"},
    {"id": "openai", "name": "OpenAI",
     "base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini",
     "key_url": "https://platform.openai.com/api-keys"},
    {"id": "custom", "name": "自定义 / 本地模型（OpenAI 兼容）",
     "base_url": "http://127.0.0.1:11434/v1", "model": "qwen2.5:7b",
     "key_url": ""},
]

DEFAULTS: dict = {
    "provider": "deepseek",
    "base_url": "https://api.deepseek.com/v1",
    "api_key": "",
    "model": "deepseek-chat",
    "temperature": 0.2,
    "timeout": 90,
    "verify_ssl": True,
    "updated_at": "",
}


class AIError(RuntimeError):
    """调用模型失败，message 可直接展示给用户。"""


# ---------------------------------------------------------------- 配置读写
def load_config() -> dict:
    """读取 AI 配置文件（``config/ai-config.json``）。

    与 :func:`core.config.load_ai` 的区别：本模块**必须**能在只拷了 ``core/`` 的
    极简环境里独立工作，所以自带默认值与容错，不依赖 ``core.config``。

    Returns:
        dict: 键 ``provider`` / ``base_url`` / ``api_key`` / ``model`` / ``temperature`` /
            ``timeout`` / ``verify_ssl`` / ``updated_at``。
            文件缺失或损坏时返回全默认值（``api_key`` 为空 = 未配置）。
    """
    cfg = dict(DEFAULTS)
    if AI_CONFIG.is_file():
        try:
            raw = json.loads(AI_CONFIG.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                cfg.update({k: v for k, v in raw.items() if v is not None})
        except (ValueError, OSError):
            pass
    return cfg


def _clean(patch: dict) -> dict:
    """校验并归一化用户输入。"""
    out: dict = {}
    if "provider" in patch:
        out["provider"] = str(patch.get("provider") or "custom").strip()[:40]
    if "base_url" in patch:
        url = str(patch.get("base_url") or "").strip().rstrip("/")
        if not url:
            raise ValueError("接口地址不能为空")
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError("接口地址必须以 http:// 或 https:// 开头")
        if any(c in url for c in " \t\r\n\"'<>"):
            raise ValueError("接口地址含有非法字符（空格或引号）")
        parsed = urllib.parse.urlsplit(url)
        if not parsed.hostname:
            raise ValueError("接口地址缺少主机名，例如 https://api.deepseek.com/v1")
        out["base_url"] = url
    if "api_key" in patch:
        # 只保留可见 ASCII，避免把换行/控制字符塞进 HTTP 头造成头部注入
        key = "".join(c for c in str(patch.get("api_key") or "") if 32 <= ord(c) < 127)
        out["api_key"] = key.strip()
    if "model" in patch:
        model = str(patch.get("model") or "").strip()
        if not model:
            raise ValueError("模型名称不能为空")
        out["model"] = model[:100]
    if "temperature" in patch:
        try:
            t = float(patch.get("temperature"))
        except (TypeError, ValueError):
            t = 0.2
        out["temperature"] = round(min(2.0, max(0.0, t)), 2)
    if "timeout" in patch:
        try:
            out["timeout"] = int(min(600, max(10, int(patch.get("timeout")))))
        except (TypeError, ValueError):
            out["timeout"] = DEFAULTS["timeout"]
    if "verify_ssl" in patch:
        v = patch.get("verify_ssl")
        # 前端可能传字符串 "false" / "0"，bool("false") 会是 True，这里显式判一次
        out["verify_ssl"] = (str(v).strip().lower() in ("1", "true", "yes", "on")
                             if isinstance(v, str) else bool(v))
    return out


def save_config(patch: dict) -> dict:
    """把前端提交的改动合并进配置文件并原子落盘。

    Args:
        patch: 只含需要改的键；会被 :func:`_clean` 过滤（非法字符、越界数值、
            缺字段的 base_url 都会被丢弃，避免写坏配置）。

    Returns:
        dict: 写回后的完整配置（含新生成的 ``updated_at``）。
    """
    cfg = load_config()
    cfg.update(_clean(patch or {}))
    cfg["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    AI_CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return cfg


def mask_key(key: str) -> str:
    """把 API Key 打码后回显给前端（配置页要显示「已填」，但不能显示原文）。

    Args:
        key: 原始 Key。

    Returns:
        str: 长度 ≤ 8 时整串星号；更长时保留前 4 后 4，中间 6 个星号。
            空串返回空串（前端据此显示「未配置」）。
    """
    key = key or ""
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}{'*' * 6}{key[-4:]}"


def public_config(cfg: dict | None = None) -> dict:
    """给界面看的安全视图：**不含明文 Key**。

    Args:
        cfg: 已加载的配置；省略时现场读盘。

    Returns:
        dict: 除 ``api_key`` 外的全部字段，另加 ``has_key``（bool）与 ``key_hint``
            （打码后的样子）。这样前端既能显示「已配置」，又拿不到可用凭据。
    """
    cfg = dict(cfg or load_config())
    key = cfg.get("api_key") or ""
    return {
        "provider": cfg.get("provider", "custom"),
        "base_url": cfg.get("base_url", ""),
        "model": cfg.get("model", ""),
        "temperature": cfg.get("temperature", 0.2),
        "timeout": cfg.get("timeout", 90),
        "verify_ssl": bool(cfg.get("verify_ssl", True)),
        "updated_at": cfg.get("updated_at", ""),
        "has_key": bool(key),
        "key_masked": mask_key(key),
        "ready": bool(key and cfg.get("base_url") and cfg.get("model")),
        "presets": PRESETS,
    }


# ---------------------------------------------------------------- 调用
def _endpoint(base_url: str) -> str:
    b = (base_url or "").strip().rstrip("/")
    if b.endswith("/chat/completions"):
        return b
    return b + "/chat/completions"


def _error_from_body(body: bytes, code: int) -> str:
    text = body.decode("utf-8", "replace").strip()
    try:
        data = json.loads(text)
        err = data.get("error")
        if isinstance(err, dict):
            msg = err.get("message") or err.get("msg") or err.get("code")
            if msg:
                return f"HTTP {code}：{msg}"
        if isinstance(err, str) and err:
            return f"HTTP {code}：{err}"
        msg = data.get("message") or data.get("msg")
        if msg:
            return f"HTTP {code}：{msg}"
    except ValueError:
        pass
    return f"HTTP {code}：{text[:300] or '服务端返回空响应'}"


def chat(messages: list[dict], overrides: dict | None = None,
         timeout: int | None = None, max_tokens: int | None = None) -> str:
    """调用 OpenAI 兼容的 ``/chat/completions``，返回纯文本回复。

    Args:
        messages: 标准对话数组，每项 ``{"role": "system"|"user"|"assistant", "content": str}``。
        overrides: 临时覆盖配置（如前端「测试连接」时用未保存的新地址），
            会过 :func:`_clean` 校验。
        timeout: 覆盖配置里的超时秒数。
        max_tokens: 覆盖最大输出长度；不传时用服务端默认。

    Returns:
        str: 模型回复的正文（已去首尾空白）。

    Raises:
        AIError: 未填 Key、地址非法、HTTP 非 2xx、返回体不是预期 JSON、
            或拿不到 ``choices[0].message.content``。消息内容可直接展示给用户。
    """
    cfg = load_config()
    if overrides:
        cfg.update(_clean(overrides))

    key = (cfg.get("api_key") or "").strip()
    if not key:
        raise AIError("尚未填写 API Key，请点右上角「AI 设置」填写并保存")
    base = cfg.get("base_url") or ""
    if not base:
        raise AIError("尚未填写接口地址 Base URL")

    payload = {
        "model": cfg.get("model"),
        "messages": messages,
        "temperature": float(cfg.get("temperature") or 0.2),
        "stream": False,
    }
    if max_tokens:
        payload["max_tokens"] = int(max_tokens)

    req = urllib.request.Request(
        _endpoint(base),
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {key}",
            "User-Agent": "USB-Net-Diag/1.0",
        },
    )
    ctx = None
    if not cfg.get("verify_ssl", True):
        ctx = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout or int(cfg.get("timeout") or 90), context=ctx) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raise AIError(_error_from_body(exc.read(), exc.code)) from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise AIError(f"无法连接 {base}（{reason}）；请检查网络、代理或 Base URL 是否正确") from exc
    except TimeoutError as exc:
        raise AIError("请求超时，可在设置里调大「超时秒数」，或换用响应更快的模型") from exc
    except ssl.SSLError as exc:
        raise AIError(f"TLS 握手失败（{exc}）；内网自签证书可在设置里关闭「校验 SSL 证书」") from exc

    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError as exc:
        raise AIError(f"返回内容不是 JSON：{raw[:200]!r}") from exc

    choices = data.get("choices") or []
    if not choices:
        err = data.get("error")
        raise AIError(f"返回中没有 choices：{err or data}")
    first = choices[0] or {}
    content = (first.get("message") or {}).get("content")
    if content is None:
        content = first.get("text") or ""
    if isinstance(content, list):  # 部分服务把 content 拆成块
        content = "".join(c.get("text", "") for c in content if isinstance(c, dict))
    text = str(content or "").strip()
    if not text:
        raise AIError("模型返回了空内容，可能触发了内容过滤或参数不兼容")
    return text


def test_connection(overrides: dict | None = None) -> dict:
    """最小代价验证配置是否可用（发一句短提示，看能否拿到回复）。

    Args:
        overrides: 待验证的配置；省略时用磁盘上已保存的那份。

    Returns:
        dict: 成功 ``{"ok": True, "model": str, "latency_ms": int, "reply": str}``；
            失败 ``{"ok": False, "error": str}``（``error`` 已含可操作提示）。
    """
    started = time.time()
    try:
        reply = chat([{"role": "user", "content": "只回复两个字：可用"}],
                     overrides=overrides, timeout=30, max_tokens=16)
        cfg = load_config()
        return {
            "ok": True,
            "model": (overrides or {}).get("model") or cfg.get("model"),
            "latency_ms": int((time.time() - started) * 1000),
            "reply": reply[:80],
        }
    except AIError as exc:
        return {"ok": False, "error": str(exc), "latency_ms": int((time.time() - started) * 1000)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------- 诊断解读
SYSTEM_PROMPT = (
    "你是资深网络排障工程师，读者是**一线桌面运维**：懂电脑、会看日志，但不熟网络协议。"
    "你的唯一目标：让他读完就知道「哪一层坏了、哪个协议、哪个对端、下一步做什么」。"
    "网络安全只是附带观察，不是重点。\n"
    "\n"
    "输出四段，缺一不可：\n"
    "\n"
    "### 一句话结论（60 字以内）\n"
    "句式：`【层】+【协议】+【现象】+【要不要立刻处理】`。"
    "例：「L4 传输层 TCP：到 10.0.0.5:8080 的连接完全无响应，业务不可用，需要立刻处理。」\n"
    "\n"
    "### 故障定位\n"
    "用小表格：层次 | 协议 | 对端/目标 | 关键数值 | 判断依据。"
    "只列有问题的层；没问题的层一行带过。\n"
    "\n"
    "### 现象解释（说人话，2～4 句）\n"
    "解释这一层坏了，用户实际会看到什么（打不开、转圈、卡顿、报 500……），"
    "以及为什么这一层会导致这个现象。不要堆术语，出现了就顺手解释。\n"
    "\n"
    "### 处置步骤（编号，按执行顺序）\n"
    "每条都是可直接落地的动作：具体命令、看哪个指标、改哪个配置、找谁。"
    "第 1 条必须是最先做、且做完能验证有没有效果的。"
    "排查顺序永远自下而上：先确认通不通，再看丢不丢包，最后看应用。\n"
    "\n"
    "硬性要求：\n"
    "1. 只能引用给定数据里的 IP、端口、域名、数值、帧号、Stream 编号，禁止编造。\n"
    "2. 关键数字必须原样保留：重传率、RTT、握手时间、DNS/HTTP 耗时、5xx 数量。\n"
    "3. 必须区分「网络慢」和「服务端慢」：RTT/握手小但首字节或服务端等待大 = 服务端问题；"
    "两者都大 = 链路问题；有建连失败 = 网络或防火墙问题。\n"
    "4. 只给 1～3 个最可能的成因，按可能性排序，不要罗列所有可能。\n"
    "5. 证据不足时写「需补充证据」，并说明下一步抓什么、加什么过滤条件。\n"
    "6. 安全观察只在没有网络故障时用一句话带过，不要展开。\n"
    "7. 总长 700 字以内，简体中文，不要免责声明。"
)


def build_messages(result: dict, question: str = "") -> list[dict]:
    """把诊断结果转成对话消息，**保留全部原始观测值**供模型引用。

    Args:
        result: ``diagnose.run_scan()`` 的结果字典（含 ``meta`` / ``rows`` /
            ``metrics`` / ``verdict``）。
        question: 用户追加的追问；为空时用内置的「按四段结构分析」提示。

    Returns:
        list[dict]: 两条消息 —— ``system``（角色约束：不许编造未观测到的事实）
            与 ``user``（拼好的诊断摘要 + 追问）。
    """
    result = result or {}
    meta = result.get("meta") or {}
    rows = result.get("rows") or []
    m = result.get("metrics") or {}
    vd = result.get("verdict") or {}

    lines = [
        "以下是本次抓包诊断结果，请按四段结构分析。",
        "",
        "【采集概况】",
        f"抓包文件：{meta.get('pcap_name', '-')}｜网卡：{meta.get('interface', '-')}"
        f"｜过滤器：{meta.get('bpf', '-')}",
        f"报文 {meta.get('packets', '-')} 个（TCP {meta.get('tcp_packets', '-')}，会话 "
        f"{meta.get('streams_total', '-')} 个）｜时长 {meta.get('duration', '-')} 秒"
        f"｜吞吐 {m.get('throughput_mbps', 0)} Mbps",
        "",
        "【分层指标】",
        f"- L2 本地链路：ARP 无应答 {m.get('arp_no_reply', 0)} 个地址",
        f"- L3 网络层：RTT 均值 {m.get('rtt_avg_ms', 0)}ms / P95 {m.get('rtt_p95_ms', 0)}ms"
        f" / 最大 {m.get('rtt_max_ms', 0)}ms / 抖动 {m.get('rtt_jitter_ms', 0)}ms"
        f"（{m.get('rtt_samples', 0)} 个采样）；ICMP 不可达 {m.get('icmp_unreach', 0)} 条，"
        f"超时 {m.get('icmp_timeout', 0)} 条",
        f"- L4 传输层：重传率 {m.get('retrans_rate', 0)}%；乱序 {m.get('ooo_rate', 0)}%；"
        f"重复 ACK {m.get('dup_ack_rate', 0)}%；建连失败 {m.get('conn_fail', 0)} 个；"
        f"被 RST {m.get('conn_refused', 0)} 个；握手均值 {m.get('hs_avg_ms', 0)}ms"
        f"（{m.get('hs_samples', 0)} 个样本）",
        f"- L7 应用层：DNS 均值 {m.get('dns_avg_ms', 0)}ms / P95 {m.get('dns_p95_ms', 0)}ms"
        f" / 失败率 {m.get('dns_fail_rate', 0)}% / 超时 {m.get('dns_timeouts', 0)} 次；"
        f"HTTP 均值 {m.get('http_avg_ms', 0)}ms / P95 {m.get('http_p95_ms', 0)}ms"
        f" / 5xx {m.get('http_err5', 0)} 个 / 4xx {m.get('http_err4', 0)} 个",
        "",
        "【分层状态】（规则引擎判定）",
    ]
    for x in vd.get("layers") or []:
        lines.append(f"- {x.get('id')} {x.get('name')}：{x.get('status')}（{x.get('detail')}）")

    lines += ["", "【问题清单】（层次｜协议｜类别｜严重程度｜发现｜证据｜建议）"]
    for r in rows:
        lines.append(
            f"- {r.get('layer', '')}｜{r.get('protocol', '')}｜{r.get('category', '')}"
            f"｜{r.get('severity', '')}｜{r.get('finding', '')}"
            f"｜{r.get('evidence', '')}｜{r.get('advice', '')}"
        )

    streams = meta.get("streams_top") or []
    if streams:
        lines += ["", "【会话明细】（Stream｜客户端→服务端｜协议｜包/字节｜握手｜RTT｜重传｜"
                      "服务端等待｜标记）"]
        for s in streams:
            lines.append(
                f"- #{s.get('stream')}｜{s.get('client')}:{s.get('sport')}→"
                f"{s.get('server')}:{s.get('dport')}｜{s.get('app')}｜{s.get('packets')} 包/"
                f"{s.get('bytes')} 字节｜握手 {s.get('handshake_ms')}ms｜RTT {s.get('rtt_avg')}ms"
                f"｜重传 {s.get('retrans')}｜服务端等待 {s.get('think_ms')}ms"
                f"｜{'、'.join(s.get('flags') or []) or '正常'}"
            )

    slow = meta.get("http_slow") or []
    if slow:
        lines += ["", "【HTTP 请求（按耗时降序）】"]
        for h in slow[:6]:
            lines.append(f"- {h.get('method')} {h.get('host')}{h.get('uri')} → {h.get('code')}"
                         f"，耗时 {h.get('ms')}ms，帧 #{h.get('frame')}")

    dns_detail = meta.get("dns_detail") or []
    if dns_detail:
        lines += ["", "【DNS 解析（按耗时降序）】"]
        for d in dns_detail[:8]:
            lines.append(f"- {d.get('name')} → {d.get('ms')}ms，rcode {d.get('rcode')}，"
                         f"服务器 {d.get('server')}，帧 #{d.get('frame')}")

    if meta.get("icmp_detail"):
        lines += ["", "【ICMP 异常】"]
        for i in meta["icmp_detail"][:6]:
            lines.append(f"- {i.get('src')}→{i.get('dst')} {i.get('desc')}，帧 #{i.get('frame')}")

    sec = [r for r in rows if r.get("layer") == "安全观察" and r.get("severity") != "—"]
    if sec:
        lines += ["", "【安全观察（附带项，非主线）】"]
        for r in sec[:4]:
            lines.append(f"- {r.get('category')}：{r.get('finding')}（{r.get('severity')}）")

    if question.strip():
        lines += ["", "另外请重点回答这个问题：" + question.strip()]

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "\n".join(lines)},
    ]


def analyze_result(result: dict, question: str = "", overrides: dict | None = None) -> dict:
    """让模型解读一次诊断结果。

    Args:
        result: 诊断结果字典。
        question: 用户追问，可空。
        overrides: 临时覆盖 AI 配置。

    Returns:
        dict: ``{"ok": True, "analysis": str, "model": str, "latency_ms": int}``。

    Raises:
        AIError: 上游调用失败（由调用方转成 HTTP 错误信封）。
    """
    started = time.time()
    text = chat(build_messages(result, question), overrides=overrides)
    cfg = load_config()
    return {
        "ok": True,
        "analysis": text,
        "model": (overrides or {}).get("model") or cfg.get("model"),
        "latency_ms": int((time.time() - started) * 1000),
    }
