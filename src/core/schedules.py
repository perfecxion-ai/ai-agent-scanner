"""One-slot read-only scheduling preflight, finalized by the owning dispatcher."""

from concurrent.futures import ThreadPoolExecutor
from time import monotonic

from src.core.scope import ScopeValidationError, bounded_integer
from src.core.templates import template_revision


def schedule_definition(data):
    fields = {"template_id", "template_revision", "interval_seconds", "total_runs"}
    if not isinstance(data, dict) or set(data) != fields:
        raise ScopeValidationError("Schedule requires template_id, template_revision, interval_seconds, and total_runs")
    identifier = data["template_id"]
    if not isinstance(identifier, str) or not identifier or len(identifier) > 64:
        raise ScopeValidationError("Invalid template_id")
    return {"template_id": identifier, "template_revision": template_revision(data["template_revision"]),
            "interval_seconds": bounded_integer(data["interval_seconds"], "interval_seconds", 2592000, 60),
            "total_runs": bounded_integer(data["total_runs"], "total_runs", 100)}


class ScheduleService:
    """Only preflight runs off-thread. It receives no admission or mutation callback."""

    def __init__(self, candidate, preflight, admit, recover, *, clock=monotonic, preflight_seconds=60):
        self.candidate, self.preflight, self.admit, self.recover = candidate, preflight, admit, recover
        self.executor = None
        self.future = None
        self.pending = None
        self.generation = 0
        self.stopped = True
        self.healthy = True
        self.retry_after = 0.0
        self.clock, self.preflight_seconds = clock, preflight_seconds
        self.started_at = None
        self.timed_out = False
        self.timeout_recorded = False

    def start(self):
        self.recover()
        self.generation += 1
        self.stopped = False
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="schedule-preflight")

    def stop(self):
        self.stopped = True
        self.generation += 1
        if self.future:
            self.future.cancel()
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)

    def tick(self, stop):
        if self.stopped or stop.is_set():
            return
        if self.clock() < self.retry_after:
            return
        try:
            self._tick(stop)
            self.healthy = not (self.future is not None and self.timed_out)
        except Exception:
            self.healthy = False
            self.retry_after = self.clock() + 1.0
            raise

    def _tick(self, stop):
        if self.future is not None:
            generation, candidate = self.pending
            if self.clock() - self.started_at >= self.preflight_seconds:
                self.timed_out = True
            if self.timed_out and not self.timeout_recorded:
                if not self.stopped and not stop.is_set() and generation == self.generation:
                    self.admit(candidate, {"error": "preflight_timeout"}, stop)
                self.timeout_recorded = True
            if not self.future.done():
                return
            future, pending = self.future, self.pending
            self.future, self.pending = None, None
            if self.timed_out:
                return
            try:
                result = future.result()
            except Exception:
                result = {"error": "preflight_failed"}
            generation, candidate = pending
            if not self.stopped and not stop.is_set() and generation == self.generation:
                self.admit(candidate, result, stop)
            return
        candidate = self.candidate()
        if candidate is not None and not self.stopped and not stop.is_set():
            self.pending = (self.generation, candidate)
            self.started_at = self.clock()
            self.timed_out = self.timeout_recorded = False
            self.future = self.executor.submit(self.preflight, candidate)
