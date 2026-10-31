"""Read-only scheduling preflight cannot delay cancellation or enqueue after stop."""

import threading
from unittest.mock import Mock

import pytest

from src.core.jobs import JobDispatcher
from src.core.schedules import ScheduleService
from tests.test_api_auth import api as api
from tests.test_jobs import store as store, enqueue, complete, until, state


def test_service_bounds_preflight_and_discards_late_result():
    release, started, stopped = threading.Event(), threading.Event(), threading.Event()
    candidate, admitted = Mock(return_value={"id": "fixture"}), Mock()

    def preflight(row):
        started.set()
        assert release.wait(3)
        return {"definition": "fixture"}

    service = ScheduleService(candidate, preflight, admitted, Mock())
    service.start()
    try:
        service.tick(stopped)
        assert started.wait(3)
        for _ in range(20):
            service.tick(stopped)
        assert candidate.call_count == 1
        service.stop()
        release.set()
        service.future.result(timeout=3)
        service.tick(stopped)
        admitted.assert_not_called()
    finally:
        release.set()
        service.stop()


def test_blocked_preflight_preserves_cancellation_and_no_old_enqueue_after_restart(store):
    release, started, worker_started = threading.Event(), threading.Event(), threading.Event()
    admitted = Mock()

    def preflight(row):
        started.set()
        assert release.wait(5)
        return {"definition": "fixture"}

    def worker(scan_id, cancelled):
        worker_started.set()
        assert cancelled.wait(5)
        complete(store, scan_id)

    service = ScheduleService(lambda: {"id": "fixture"}, preflight, admitted, lambda: None)
    enqueue(store, "active")
    dispatcher = JobDispatcher(store, worker, poll_seconds=0.01, service=service)
    second = None
    dispatcher.start()
    try:
        assert started.wait(3) and worker_started.wait(3)
        assert store.cancel("active") == "cancel_requested"
        until(lambda: state(store, "active") == "cancelled")
        assert dispatcher.stop(timeout=0.1) is False
        second = JobDispatcher(store, lambda scan_id, cancelled: None, poll_seconds=0.01)
        with pytest.raises(RuntimeError, match='Another dispatcher owns this database'):
            second.start()
        release.set()
        service.future.result(timeout=3)
        assert dispatcher.stop(timeout=1) is True
        second.start()
        service.tick(threading.Event())
        admitted.assert_not_called()
        assert second.ready
    finally:
        release.set()
        dispatcher.stop()
        if second:
            second.stop()


def test_auxiliary_persistence_errors_make_dispatcher_unready(store):
    failing = threading.Event()
    failing.set()

    def candidate():
        if failing.is_set():
            raise RuntimeError("synthetic persistence failure")
        return None

    dispatcher = JobDispatcher(store, lambda scan_id, cancelled: None, poll_seconds=0.01,
        service=ScheduleService(candidate, Mock(), Mock(), Mock()))
    dispatcher.start()
    try:
        until(lambda: not dispatcher._healthy)
        assert not dispatcher.ready
        failing.clear()
        until(lambda: dispatcher.ready)
    finally:
        dispatcher.stop()


@pytest.mark.parametrize("operation", ["candidate", "admit"])
def test_persistence_retry_is_rate_limited_and_unready_during_backoff(operation):
    clock = [0.0]
    candidate = Mock(return_value={"id": "fixture"})
    admitted = Mock()
    service = ScheduleService(candidate, lambda row: {"definition": "fixture"}, admitted, Mock(),
                              clock=lambda: clock[0])
    stop = threading.Event()
    service.start()
    try:
        if operation == "candidate":
            candidate.side_effect = RuntimeError("fixture persistence failure")
            callback = candidate
        else:
            service.tick(stop)
            service.future.result(timeout=3)
            admitted.side_effect = RuntimeError("fixture persistence failure")
            callback = admitted
        with pytest.raises(RuntimeError, match="fixture persistence"):
            service.tick(stop)
        attempts = callback.call_count
        assert not service.healthy
        for value in (0.25, 0.5, 0.99):
            clock[0] = value
            service.tick(stop)
        assert callback.call_count == attempts and not service.healthy
        clock[0] = 1.01
        if operation == "candidate":
            candidate.side_effect = None
            candidate.return_value = None
        else:
            admitted.side_effect = None
        service.tick(stop)
        assert service.healthy
    finally:
        service.stop()


def test_soft_deadline_pauses_once_retains_busy_slot_and_discards_late_result():
    release, started = threading.Event(), threading.Event()
    clock = [0.0]
    candidate, admitted = Mock(return_value={"id": "fixture"}), Mock()

    def preflight(row):
        started.set()
        assert release.wait(3)
        return {"definition": "late fixture"}

    service = ScheduleService(candidate, preflight, admitted, Mock(), clock=lambda: clock[0])
    stop = threading.Event()
    service.start()
    try:
        service.tick(stop)
        assert started.wait(3)
        original = service.future
        clock[0] = 59.9
        service.tick(stop)
        admitted.assert_not_called()
        assert service.healthy
        clock[0] = 60.0
        service.tick(stop)
        admitted.assert_called_once_with({"id": "fixture"}, {"error": "preflight_timeout"}, stop)
        assert not service.healthy and service.future is original
        for _ in range(20):
            service.tick(stop)
        assert candidate.call_count == admitted.call_count == 1
        release.set()
        original.result(timeout=3)
        service.tick(stop)
        assert service.healthy and service.future is None
        assert admitted.call_count == 1
    finally:
        release.set()
        service.stop()


def test_timed_out_preflight_does_not_block_job_cancellation_or_readiness_recovery(store):
    release, started, worker_started = threading.Event(), threading.Event(), threading.Event()
    clock = [0.0]

    def preflight(row):
        started.set()
        assert release.wait(5)
        return {"definition": "fixture"}

    def worker(scan_id, cancelled):
        worker_started.set()
        assert cancelled.wait(5)
        complete(store, scan_id)

    service = ScheduleService(lambda: {"id": "fixture"}, preflight, Mock(), Mock(), clock=lambda: clock[0])
    enqueue(store, "active")
    dispatcher = JobDispatcher(store, worker, poll_seconds=0.01, service=service)
    dispatcher.start()
    try:
        assert started.wait(3) and worker_started.wait(3)
        clock[0] = 60.0
        until(lambda: not dispatcher.ready)
        assert store.cancel("active") == "cancel_requested"
        until(lambda: state(store, "active") == "cancelled")
        release.set()
        until(lambda: dispatcher.ready)
    finally:
        release.set()
        dispatcher.stop()
