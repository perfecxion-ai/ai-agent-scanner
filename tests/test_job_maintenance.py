"""Derived inventory maintenance keeps dispatcher ownership and queue priority."""

import threading
from unittest.mock import Mock

import pytest

from src.core.jobs import JobDispatcher
from tests.test_api_auth import api as api
from tests.test_jobs import store as store, enqueue, complete, state, until


def test_idle_maintenance_owns_dispatcher_lock_and_observes_stop(store):
    entered, stopped = threading.Event(), threading.Event()

    def maintenance(stop):
        entered.set()
        assert stop.wait(3)
        stopped.set()

    first = JobDispatcher(store, Mock(), poll_seconds=0.01, maintenance=maintenance)
    second = JobDispatcher(store, Mock(), poll_seconds=0.01)
    try:
        first.start()
        assert entered.wait(3)
        assert first.ready
        with pytest.raises(RuntimeError, match='Another dispatcher'):
            second.start()
    finally:
        first.stop()
    assert stopped.is_set()
    second.start()
    second.stop()


def test_queued_work_runs_before_maintenance_and_active_worker_suppresses_it(store):
    enqueue(store, 'priority')
    entered, release, maintained = threading.Event(), threading.Event(), threading.Event()

    def run(scan_id, cancelled):
        entered.set()
        assert release.wait(3)
        complete(store, scan_id)

    def maintenance(stop):
        assert state(store, 'priority') == 'completed'
        maintained.set()

    dispatcher = JobDispatcher(store, run, workers=1, poll_seconds=0.01, maintenance=maintenance)
    try:
        dispatcher.start()
        assert entered.wait(3)
        assert state(store, 'priority') == 'running'
        assert not maintained.is_set()
        release.set()
        assert maintained.wait(3)
        assert dispatcher.ready
    finally:
        release.set()
        dispatcher.stop()


def test_failed_projection_does_not_disable_scan_queue_or_schedule_ticks(store, caplog):
    attempted = threading.Event()
    service = Mock()
    service.healthy = True
    service.future = None

    def maintenance(stop):
        attempted.set()
        raise RuntimeError('synthetic-private-projection-error')

    dispatcher = JobDispatcher(store, lambda scan_id, cancelled: complete(store, scan_id),
                               poll_seconds=0.01, service=service, maintenance=maintenance)
    try:
        dispatcher.start()
        assert attempted.wait(3)
        enqueue(store, 'after-projection-error')
        dispatcher.wake()
        until(lambda: state(store, 'after-projection-error') == 'completed')
        assert dispatcher.ready
        assert service.tick.call_count > 0
        assert 'Background inventory maintenance failed' in caplog.text
        assert 'synthetic-private-projection-error' not in caplog.text
    finally:
        assert dispatcher.stop() is True


def test_uncooperative_maintenance_cannot_release_live_dispatcher_ownership(store):
    entered, release = threading.Event(), threading.Event()

    def maintenance(stop):
        entered.set()
        assert release.wait(3)

    first = JobDispatcher(store, Mock(), poll_seconds=0.01, maintenance=maintenance)
    second = JobDispatcher(store, Mock(), poll_seconds=0.01)
    try:
        first.start()
        assert entered.wait(3)
        first.stop(timeout=0.01)
        with pytest.raises(RuntimeError, match='Another dispatcher'):
            second.start()
        release.set()
        first.stop()
        second.start()
    finally:
        release.set()
        first.stop()
        second.stop()
