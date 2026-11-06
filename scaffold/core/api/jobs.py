"""任务注册表：job_id / 取消 / 并发上限 / 日志环形缓冲。

修的是现有 ``core/server.py`` 的单例槽问题（评审 P1）：

* 全局只有一个 ``JOB``，第二次点击直接报「已有任务在执行」，且无法追溯；
* 没有 job_id，报告与日志无法对应；
* 只有被动监听能取消，诊断不能；
* ``/api/status`` 每次回传全量 result，1.2 s 一轮，大 pcap 时 UI 会卡。

本模块只用标准库，线程安全。设计要点：``Job`` 是**契约对象**（可直接进 JSON），
日志与线程句柄放在旁路字典里，不污染 API 视图。
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..contracts import Job, JobState, to_jsonable
from ..errors import DiagError, ErrorCode

#: 任务函数：``(should_stop, log) -> result``
JobFn = Callable[[Callable[[], bool], Callable[[str], None]], Any]


@dataclass
class _Slot:
    job: Job
    stop: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    logs: deque = field(default_factory=lambda: deque(maxlen=400))


class JobStore:
    """线程安全的任务表。

    ``submit()`` 立即返回 ``Job``（``state=queued``），实际执行在后台线程；
    调用方（HTTP 层）返回 202 + ``job_id``，前端轮询 ``get()``。
    """

    def __init__(self, max_concurrent: int = 1, max_logs: int = 400) -> None:
        self.max_concurrent = max(1, int(max_concurrent))
        self.max_logs = max(50, int(max_logs))
        self._lock = threading.Lock()
        self._slots: dict[str, _Slot] = {}
        self._order: list[str] = []

    # ---------------------------------------------------------------- 查询

    def _slot(self, job_id: str) -> _Slot:
        slot = self._slots.get(job_id)
        if slot is None:
            raise DiagError(ErrorCode.JOB_NOT_FOUND, f"没有这个任务：{job_id}",
                            http_status=404)
        return slot

    def get(self, job_id: str) -> Job:
        with self._lock:
            return self._slot(job_id).job

    def logs(self, job_id: str, limit: int = 100) -> list[dict]:
        with self._lock:
            slot = self._slot(job_id)
            items = list(slot.logs)[-max(1, int(limit)):]
        return items

    def list(self, limit: int = 20) -> list[dict]:
        with self._lock:
            ids = list(reversed(self._order))[: max(1, int(limit))]
            return [self._slots[i].job.public() for i in ids if i in self._slots]

    @property
    def running_count(self) -> int:
        with self._lock:
            return sum(1 for s in self._slots.values() if s.job.running)

    def result(self, job_id: str) -> Any:
        job = self.get(job_id)
        if job.state is not JobState.DONE:
            raise DiagError(ErrorCode.JOB_NOT_FOUND,
                            f"任务 {job_id} 尚未完成（{job.state.value}）", http_status=409)
        return job.result

    # ---------------------------------------------------------------- 提交 / 取消

    def submit(self, kind: str, fn: JobFn, params: Mapping | None = None,
               trace_id: str = "") -> Job:
        if self.running_count >= self.max_concurrent:
            raise DiagError(ErrorCode.JOB_BUSY,
                            f"已有 {self.running_count} 个任务在执行，请等待完成或取消",
                            hint="GET /api/v1/jobs 可查看当前任务", http_status=429)

        job = Job(job_id=uuid.uuid4().hex[:12], kind=str(kind),
                  state=JobState.QUEUED, params=dict(params or {}),
                  created_at=time.time(), trace_id=trace_id)
        slot = _Slot(job=job)
        with self._lock:
            self._slots[job.job_id] = slot
            self._order.append(job.job_id)

        thread = threading.Thread(target=self._run, args=(slot, fn),
                                  name=f"job-{job.job_id}", daemon=True)
        slot.thread = thread
        thread.start()
        return job

    def cancel(self, job_id: str) -> bool:
        """置停止位。**合作式取消**：任务函数必须自己检查 ``should_stop()``。"""
        with self._lock:
            slot = self._slot(job_id)
            if not slot.job.running:
                return False
            slot.stop.set()
            slot.logs.append({"t": round(time.time(), 3), "m": "收到取消请求，正在收尾…"})
            return True

    def wait(self, job_id: str, timeout: float = 10.0) -> Job:
        slot = self._slot(job_id)
        if slot.thread is not None:
            slot.thread.join(timeout=timeout)
        return slot.job

    # ---------------------------------------------------------------- 执行

    def _run(self, slot: _Slot, fn: JobFn) -> None:
        job = slot.job
        with self._lock:
            job.state = JobState.RUNNING
            job.started_at = time.time()

        def log(msg: str) -> None:
            with self._lock:
                if len(slot.logs) >= self.max_logs:
                    slot.logs.popleft()
                slot.logs.append({"t": round(time.time(), 3), "m": str(msg)[:800]})

        def should_stop() -> bool:
            return slot.stop.is_set()

        try:
            result = fn(should_stop, log)
            with self._lock:
                if slot.stop.is_set():
                    job.state = JobState.CANCELLED
                else:
                    job.state = JobState.DONE
                    job.result = result
                    job.progress = 1.0
        except Exception as exc:  # noqa: BLE001  任务异常不能打死进程
            with self._lock:
                job.state = JobState.CANCELLED if slot.stop.is_set() else JobState.ERROR
                job.error = (
                    exc.to_dict() if isinstance(exc, DiagError)
                    else {"code": ErrorCode.INTERNAL.value,
                          "message": f"{type(exc).__name__}: {exc}", "hint": ""}
                )
        finally:
            with self._lock:
                job.finished_at = time.time()
                slot.stop.set()

    def prune(self, keep: int = 50) -> int:
        """清理已结束的旧任务（长跑场景防止内存增长）。返回清理条数。"""
        removed = 0
        with self._lock:
            finished = [i for i in self._order
                        if i in self._slots and not self._slots[i].job.running]
            for job_id in finished[: max(0, len(finished) - keep)]:
                self._slots.pop(job_id, None)
                self._order.remove(job_id)
                removed += 1
        return removed

    def snapshot(self, job_id: str, since: int = 0) -> dict:
        """``GET /api/v1/jobs/{id}`` 的 payload：状态 + 增量日志，**不含完整 result**。"""
        job = self.get(job_id)
        logs = self.logs(job_id, limit=200)
        return {
            "job": job.public(),
            "logs": logs[max(0, int(since)):],
            "log_cursor": len(logs),
            "has_result": job.state is JobState.DONE,
            "result_ref": job.result_ref,
            "error": to_jsonable(job.error),
        }


__all__ = ["JobStore", "JobFn"]
