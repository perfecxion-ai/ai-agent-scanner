"""Persistent queue tests use real SQLite transactions and synthetic workers."""

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy import MetaData, create_engine, insert, select, update, event

from src.core.jobs import DispatcherLock, JobDispatcher, JobStore
from src.core.scope import ScopeValidationError
from tests.test_api_auth import api as api, headers


@pytest.fixture
def store(api, tmp_path):
    module, _ = api
    metadata = MetaData()
    scans = module.ScanSession.__table__.to_metadata(metadata)
    jobs = module.ScanJob.__table__.to_metadata(metadata)
    results = module.ScanResult.__table__.to_metadata(metadata)
    engine = create_engine(f"sqlite:///{tmp_path / 'jobs.db'}")
    metadata.create_all(engine)
    yield JobStore(engine, jobs, scans, results)
    engine.dispose()


def enqueue(store, scan_id, status="queued", with_job=True):
    with store.engine.begin() as connection:
        connection.execute(insert(store.scans).values(
            id=scan_id, organization_id="tenant-a", scan_name=scan_id,
            scan_type="discovery_only", status="queued" if status == "queued" else "running",
            target_scope={"network_ranges": ["192.0.2.1/32"]}, scan_config={},
        ))
        if with_job:
            connection.execute(insert(store.jobs).values(scan_id=scan_id, status=status))


def state(store, scan_id):
    with store.engine.connect() as connection:
        return connection.scalar(select(store.jobs.c.status).where(store.jobs.c.scan_id == scan_id))


def result(store, scan_id):
    with store.engine.connect() as connection:
        return connection.scalar(select(store.results.c.result).where(store.results.c.scan_id == scan_id))


def complete(store, scan_id):
    with store.engine.begin() as connection:
        connection.execute(update(store.scans).where(store.scans.c.id == scan_id).values(status="completed"))


def until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    assert predicate(), "Timed out waiting for synthetic worker"


def test_competing_sqlite_claims_are_unique(store):
    for number in range(20):
        enqueue(store, str(number))
    barrier = threading.Barrier(4)

    def claim_all(owner):
        claimed = []
        barrier.wait(timeout=3)
        for _ in range(100):
            scan_id = store.claim(owner)
            if scan_id is not None:
                claimed.append(scan_id)
            elif not store.queued_count():
                break
        return claimed

    with ThreadPoolExecutor(max_workers=4) as executor:
        claimed = [scan_id for claims in executor.map(claim_all, ["a", "b", "c", "d"]) for scan_id in claims]
    assert len(claimed) == len(set(claimed)) == 20
    assert store.queued_count() == 0


def test_restart_preserves_queue_and_interrupts_active_jobs(store):
    enqueue(store, "pending")
    enqueue(store, "active", "running")
    enqueue(store, "cancel", "cancel_requested")
    enqueue(store, "legacy", "running", with_job=False)
    restarted = JobStore(store.engine, store.jobs, store.scans, store.results)
    assert restarted.recover() == 3
    assert state(store, "pending") == "queued"
    assert state(store, "active") == result(store, "active")["status"] == "interrupted"
    assert state(store, "cancel") == result(store, "cancel")["status"] == "cancelled"
    assert result(store, "legacy")["status"] == "interrupted"
    assert restarted.claim("new-process") == "pending"
    assert restarted.claim("new-process") is None


def test_queued_cancellation_never_executes(store):
    enqueue(store, "queued")
    assert store.cancel("queued") == "cancelled"
    assert store.claim("worker") is None
    assert result(store, "queued")["status"] == "cancelled"
    assert store.cancel("queued") is None


def test_finish_serializes_with_accepted_cancel(store):
    enqueue(store, "race", "running")
    complete(store, "race")
    observed = threading.Event()

    def before(connection, cursor, statement, parameters, context, many):
        if threading.current_thread().name == "finish-race" and statement.startswith("UPDATE"):
            observed.set()

    def after(connection, cursor, statement, parameters, context, many):
        # A read-first implementation would observe stale state before cancellation commits.
        if threading.current_thread().name == "finish-race" and statement.startswith("SELECT"):
            observed.set()

    event.listen(store.engine, "before_cursor_execute", before)
    event.listen(store.engine, "after_cursor_execute", after)
    try:
        with store.engine.begin() as connection:
            connection.execute(update(store.jobs).where(store.jobs.c.scan_id == "race").values(status="cancel_requested"))
            thread = threading.Thread(target=lambda: store.finish("race"), name="finish-race")
            thread.start()
            assert observed.wait(3)
    finally:
        event.remove(store.engine, "before_cursor_execute", before)
        event.remove(store.engine, "after_cursor_execute", after)
    thread.join(3)
    assert not thread.is_alive()
    assert state(store, "race") == result(store, "race")["status"] == "cancelled"


def test_second_dispatcher_cannot_recover_live_work(store):
    enqueue(store, "active")
    started = threading.Event()

    def run(scan_id, cancelled):
        started.set()
        assert cancelled.wait(3)
        complete(store, scan_id)

    first = JobDispatcher(store, run, workers=1, poll_seconds=0.01)
    second = JobDispatcher(store, Mock(), workers=1, poll_seconds=0.01)
    try:
        first.start()
        assert started.wait(3)
        with pytest.raises(RuntimeError, match="Another dispatcher"):
            second.start()
        assert state(store, "active") == "running"
        assert result(store, "active") is None
    finally:
        first.stop()
    second.start()
    second.stop()


def test_dispatcher_rejects_nonpersistent_sqlite():
    engine = create_engine("sqlite:///:memory:")
    try:
        with pytest.raises(RuntimeError, match="file-backed"):
            DispatcherLock(engine).acquire()
    finally:
        engine.dispose()


def test_lock_stays_held_until_uncooperative_worker_returns(store):
    enqueue(store, "active")
    started, release = threading.Event(), threading.Event()

    def run(scan_id, cancelled):
        started.set()
        assert release.wait(3)
        complete(store, scan_id)

    first = JobDispatcher(store, run, workers=1, poll_seconds=0.01)
    second = JobDispatcher(store, Mock(), workers=1, poll_seconds=0.01)
    try:
        first.start()
        assert started.wait(3)
        first.stop(timeout=0.01)
        with pytest.raises(RuntimeError, match="Another dispatcher"):
            second.start()
        release.set()
        until(lambda: state(store, "active") == "completed")
    finally:
        release.set()
        first.stop()
    second.start()
    second.stop()


def test_dispatcher_retries_failed_result_finalization(store, monkeypatch):
    enqueue(store, "retry")
    original = store.finish
    calls = []

    def finish(scan_id, error=None):
        calls.append(scan_id)
        if len(calls) == 1:
            raise RuntimeError("temporary database failure")
        original(scan_id, error)

    monkeypatch.setattr(store, "finish", finish)
    dispatcher = JobDispatcher(store, lambda scan_id, cancelled: complete(store, scan_id),
                               workers=1, poll_seconds=0.01)
    try:
        dispatcher.start()
        until(lambda: state(store, "retry") == "completed")
        assert calls == ["retry", "retry"]
        assert result(store, "retry")["status"] == "completed"
    finally:
        dispatcher.stop()


def test_dispatcher_resumes_queue_and_limits_workers(store):
    for number in range(5):
        enqueue(store, str(number))
    release = threading.Event()
    lock = threading.Lock()
    active = peak = 0

    def run(scan_id, cancelled):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        assert release.wait(3)
        complete(store, scan_id)
        with lock:
            active -= 1

    dispatcher = JobDispatcher(store, run, workers=2, poll_seconds=0.01)
    try:
        dispatcher.start()
        until(lambda: active == 2)
        assert dispatcher.ready
        assert store.queued_count() == 3
        release.set()
        until(lambda: all(state(store, str(number)) == "completed" for number in range(5)))
        assert peak == 2
    finally:
        release.set()
        dispatcher.stop()
    assert not dispatcher.ready


def test_running_cancel_is_cooperative_and_persisted(store):
    enqueue(store, "active")
    started = threading.Event()

    def run(scan_id, cancelled):
        started.set()
        assert cancelled.wait(3)

    dispatcher = JobDispatcher(store, run, workers=1, poll_seconds=0.01)
    try:
        dispatcher.start()
        assert started.wait(3)
        assert store.cancel("active") == "cancel_requested"
        dispatcher.wake()
        until(lambda: state(store, "active") == "cancelled")
        assert result(store, "active")["status"] == "cancelled"
    finally:
        dispatcher.stop()


def test_worker_exception_is_terminal_and_does_not_disclose_details(store):
    enqueue(store, "failed")

    def fail(scan_id, cancelled):
        raise RuntimeError("private credential must not enter report")

    dispatcher = JobDispatcher(store, fail, workers=1, poll_seconds=0.01)
    try:
        dispatcher.start()
        until(lambda: state(store, "failed") == "failed")
        assert result(store, "failed")["error"] == "Scan worker failed"
    finally:
        dispatcher.stop()


def test_shutdown_cancels_active_work_without_claiming_remaining_queue(store):
    enqueue(store, "a")
    enqueue(store, "b")
    started = threading.Event()

    def run(scan_id, cancelled):
        started.set()
        assert cancelled.wait(3)
        with store.engine.begin() as connection:
            connection.execute(update(store.scans).where(store.scans.c.id == scan_id).values(status="interrupted"))

    dispatcher = JobDispatcher(store, run, workers=1, poll_seconds=0.01)
    dispatcher.start()
    assert started.wait(3)
    dispatcher.stop()
    assert state(store, "a") == "interrupted"
    assert state(store, "b") == "queued"


def test_api_enqueues_atomically_and_cancel_is_tenant_scoped(api):
    module, client = api
    response = client.post("/api/scans", headers=headers(module), json={
        "scan_type": "discovery_only", "target_scope": {"network_ranges": ["192.0.2.1/32"]}})
    assert response.status_code == 202
    scan_id = response.json["scan_id"]
    assert module.db.session.get(module.ScanSession, scan_id).status == "queued"
    assert module.db.session.get(module.ScanJob, scan_id).status == "queued"
    for forbidden in (scan_id, "missing"):
        assert client.post(f"/api/scans/{forbidden}/cancel", headers=headers(module, "tenant-b")).status_code == 404
    response = client.post(f"/api/scans/{scan_id}/cancel", headers=headers(module))
    assert response.status_code == 202
    assert response.json["status"] == "cancelled"
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanResult, scan_id).result["status"] == "cancelled"
    assert client.post(f"/api/scans/{scan_id}/cancel", headers=headers(module)).status_code == 409


def test_failed_admission_transaction_leaves_no_orphan(api, monkeypatch):
    module, client = api
    monkeypatch.setattr(module.db.session, "commit", Mock(side_effect=RuntimeError("fixture")))
    response = client.post("/api/scans", headers=headers(module), json={
        "scan_type": "discovery_only", "target_scope": {"network_ranges": ["192.0.2.1/32"]}})
    assert response.status_code == 500
    assert module.ScanSession.query.count() == module.ScanJob.query.count() == 0


def test_queued_job_revalidates_current_allowlist(api, monkeypatch):
    module, client = api
    response = client.post("/api/scans", headers=headers(module), json={
        "scan_type": "discovery_only", "target_scope": {"network_ranges": ["192.0.2.1/32"]}})
    monkeypatch.setitem(module.app.config, "SCAN_ALLOWED_NETWORKS", ("198.51.100.0/24",))
    runner = Mock()
    monkeypatch.setattr(module, "_run_scan_in_thread", runner)
    with pytest.raises(ScopeValidationError, match="allowlist"):
        module._execute_job(response.json["scan_id"], threading.Event())
    runner.assert_not_called()


def test_async_cancel_persists_matching_scan_and_report(api, monkeypatch):
    module, _ = api
    module.db.session.add(module.ScanSession(id="cancel", organization_id="tenant-a", scan_name="cancel",
                          scan_type="discovery_only", status="running", target_scope={}, scan_config={}))
    module.db.session.add(module.ScanJob(scan_id="cancel", status="cancel_requested"))
    module.db.session.commit()
    cancelled = threading.Event()

    async def running(*args):
        cancelled.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(module, "_execute_scan", running)
    module._run_scan_in_thread("cancel", "discovery_only", {}, {}, cancelled)
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, "cancel").status == "cancelled"
    assert module.db.session.get(module.ScanResult, "cancel").result["status"] == "cancelled"


def test_cancelled_job_never_starts_pipeline(api, monkeypatch):
    module, _ = api
    cancelled = threading.Event()
    cancelled.set()
    pipeline = AsyncMock()
    monkeypatch.setattr(module, "_execute_scan", pipeline)
    module._run_scan_in_thread("absent", "discovery_only", {}, {}, cancelled)
    pipeline.assert_not_called()


def test_readiness_requires_database_and_dispatcher(api, monkeypatch):
    module, client = api
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 503
    monkeypatch.setattr(module, "_job_dispatcher", Mock(ready=True))
    assert client.get("/health/ready").status_code == 200
    monkeypatch.setattr(module.db.session, "execute", Mock(side_effect=RuntimeError("database unavailable")))
    assert client.get("/health/ready").status_code == 503
