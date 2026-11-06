"""路由 + 统一 envelope。

现状问题（评审 4.5）：错误格式有三种（``{"ok": false}`` / 纯文本 404 / 500），
且没有 job_id，前端只能靠「轮询全量 status」猜状态。

这里给出的是**纯路由层**：``dispatch()`` 不启动 socket、不碰 tshark，
所有能力通过 ``handlers`` 注入 —— 于是它可以被单测直接调用。

迁移做法（PR 3）：

1. 先把 ``core/server.py`` 里 ``do_GET`` / ``do_POST`` 的分支改成调 ``dispatch()``，
   路由路径保持旧形态 → UI 一行都不用改；
2. 再加 ``/api/v1/*``；
3. 旧路由挂 ``deprecated`` 标记，一个版本后删除。
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..contracts import SCHEMA_VERSION, envelope_err, envelope_ok
from ..errors import DiagError, ErrorCode
from .jobs import JobStore

#: ``(method, path)`` → handler 名
ROUTES: dict[tuple[str, str], str] = {
    ("GET", "/health"): "health",
    ("GET", "/api/doctor"): "doctor",
    ("GET", "/api/interfaces"): "interfaces",
    ("GET", "/api/v1/jobs"): "list_jobs",
    ("POST", "/api/v1/jobs"): "create_job",
    ("GET", "/api/v1/jobs/{id}"): "get_job",
    ("GET", "/api/v1/jobs/{id}/result"): "job_result",
    ("POST", "/api/v1/jobs/{id}/cancel"): "cancel_job",
    ("GET", "/api/v1/captures"): "captures",
    ("POST", "/api/v1/ai/analyze"): "ai_analyze",
}

Handler = Callable[..., Any]


@dataclass
class ApiApp:
    store: JobStore = field(default_factory=JobStore)
    handlers: Mapping[str, Handler] = field(default_factory=dict)

    # ---------------------------------------------------------------- 路由匹配

    def _match(self, method: str, path: str) -> tuple[Handler | None, dict]:
        path = path.rstrip("/") or "/"
        for (m, pattern), name in ROUTES.items():
            if m != method:
                continue
            if "{" not in pattern:
                if pattern.rstrip("/") == path:
                    return self.handlers.get(name), {}
                continue
            got = self._match_template(pattern, path)
            if got is not None:
                handler = self.handlers.get(name)
                return handler, got
        return None, {}

    @staticmethod
    def _match_template(pattern: str, path: str) -> dict | None:
        p_parts = pattern.strip("/").split("/")
        r_parts = path.strip("/").split("/")
        if len(p_parts) != len(r_parts):
            return None
        params: dict[str, str] = {}
        for want, got in zip(p_parts, r_parts):
            if want.startswith("{") and want.endswith("}"):
                params[want[1:-1]] = got
            elif want != got:
                return None
        return params

    # ---------------------------------------------------------------- 分发

    def dispatch(self, method: str, path: str, payload: Mapping | None = None,
                 query: Mapping | None = None, trace_id: str = "") -> tuple[int, dict]:
        """返回 ``(http_status, envelope)``。**任何异常都转成 envelope**。"""
        handler, params = self._match(method.upper(), path)
        if handler is None:
            return 404, envelope_err(ErrorCode.BAD_PARAM.value, f"未知路由：{method} {path}",
                                     trace_id=trace_id)
        try:
            data = handler(payload=dict(payload or {}), query=dict(query or {}),
                           params=params, app=self, trace_id=trace_id)
            status = 200
            if isinstance(data, tuple) and len(data) == 2:
                status, data = data
            return int(status), envelope_ok(data, trace_id=trace_id)
        except DiagError as exc:
            return exc.http_status, envelope_err(exc.code.value, exc.message, exc.hint,
                                                 trace_id=trace_id, **exc.detail)
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            return 500, envelope_err(ErrorCode.INTERNAL.value,
                                     f"{type(exc).__name__}: {exc}", trace_id=trace_id)


# ---------------------------------------------------------------- 默认 handler


def build_default_handlers() -> dict[str, Handler]:
    """把现有能力接进来。

    TODO(迁移)：逐个替换下面的 ``NotImplementedError``。对应关系::

        health      → {"ok": True, "schema_version": SCHEMA_VERSION}
        doctor      → bootstrap.check(verbose=False)
        interfaces  → tshark.list_interfaces()
        create_job  → app.store.submit(kind, fn, params)    # 返回 202 + job_id
        get_job     → app.store.snapshot(job_id, since)
        job_result  → render.to_document(result)
        cancel_job  → app.store.cancel(job_id)
        captures    → 列出 captures/*.pcap*
        ai_analyze  → egress.ai.analyze(result, question)
    """

    def health(**_kw: Any) -> dict:
        return {"ok": True, "schema_version": SCHEMA_VERSION}

    def not_ready(name: str) -> Handler:
        def _handler(**_kw: Any) -> Any:
            raise DiagError(ErrorCode.NOT_IMPLEMENTED, f"{name} 尚未接入（见 build_default_handlers）",
                            hint="按 docstring 的对应关系把现有实现搬进来", http_status=501)

        return _handler

    out: dict[str, Handler] = {"health": health}
    for key in set(ROUTES.values()) - {"health"}:
        out.setdefault(key, not_ready(key))
    return out


def create_app() -> ApiApp:
    return ApiApp(handlers=build_default_handlers())


__all__ = ["ROUTES", "ApiApp", "build_default_handlers", "create_app"]
