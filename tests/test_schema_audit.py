"""Real SQLite upgrade, transaction and tenant history acceptance tests."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from sqlalchemy import MetaData, create_engine, event, inspect, insert, select, text, CheckConstraint

from src.core.jobs import JobDispatcher
from src.core.schema import BASE_TABLES, LEGACY_LAYOUTS, SchemaError, initialize_schema
from tests.test_api_auth import api as api, headers
from tests.test_jobs import store as store, enqueue, state, result


@pytest.fixture
def database(api, tmp_path):
    module, _ = api
    engine = create_engine(f"sqlite:///{tmp_path / 'upgrade.db'}")
    yield module, engine
    engine.dispose()


def version(engine, module):
    with engine.connect() as connection:
        return connection.execute(select(module.SchemaVersion.__table__)).all()


def history(store):
    with store.engine.connect() as connection:
        return connection.execute(select(store.audit).order_by(store.audit.c.id)).mappings().all()


def test_fresh_schema_and_restart_are_idempotent(database):
    module, engine = database
    initialize_schema(engine, module.db.metadata)
    assert set(inspect(engine).get_table_names()) == set(module.db.metadata.tables)
    initialize_schema(engine, module.db.metadata)
    assert version(engine, module) == [(1, 1)]


@pytest.mark.parametrize("layout", LEGACY_LAYOUTS)
def test_recognized_legacy_upgrade_preserves_rows_and_creates_no_fake_history(database, layout):
    module, engine = database
    metadata = MetaData()
    for name in layout:
        module.db.metadata.tables[name].to_metadata(metadata)
    metadata.create_all(engine)
    scans = metadata.tables["scan_session"]
    with engine.begin() as connection:
        connection.execute(insert(scans).values(id="old", organization_id="tenant-a", scan_name="legacy",
                           scan_type="discovery_only", status="completed", target_scope={}, scan_config={}))
        if "scan_result" in layout:
            connection.execute(insert(metadata.tables["scan_result"]).values(
                scan_id="old", result={"status": "completed", "retained": "finding"}))
        if "scan_job" in layout:
            connection.execute(insert(metadata.tables["scan_job"]).values(scan_id="old", status="completed"))
    initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.scalar(select(scans.c.scan_name)) == "legacy"
        assert connection.execute(select(module.AuditEvent.__table__)).all() == []
        if "scan_result" in layout:
            assert connection.scalar(select(module.ScanResult.result))["retained"] == "finding"
        if "scan_job" in layout:
            assert connection.scalar(select(module.ScanJob.status)) == "completed"
    assert version(engine, module) == [(1, 1)]


@pytest.mark.parametrize("mutation", ["unknown_table", "extra_column", "missing_column", "future_version",
                                      "partial_versioned", "unversioned_audit", "unknown_trigger",
                                      "unknown_view", "unknown_constraint"])
def test_unknown_schemas_fail_without_changing_database(database, mutation):
    module, engine = database
    if mutation in {"future_version", "partial_versioned"}:
        initialize_schema(engine, module.db.metadata)
    else:
        metadata = MetaData()
        for name in BASE_TABLES:
            module.db.metadata.tables[name].to_metadata(metadata)
        if mutation == "unknown_constraint":
            metadata.tables["scan_session"].append_constraint(CheckConstraint("status = 'completed'"))
        metadata.create_all(engine)
    with engine.begin() as connection:
        if mutation == "unknown_table":
            connection.execute(text("CREATE TABLE operator_data (id INTEGER)"))
        elif mutation == "extra_column":
            connection.execute(text("ALTER TABLE scan_session ADD COLUMN unknown TEXT"))
        elif mutation == "missing_column":
            connection.execute(text("ALTER TABLE scan_session DROP COLUMN user_ip"))
        elif mutation == "future_version":
            connection.execute(text("UPDATE schema_version SET version = 9"))
        elif mutation == "partial_versioned":
            connection.execute(text("DROP TABLE scan_result"))
        elif mutation == "unversioned_audit":
            module.AuditEvent.__table__.create(connection)
        elif mutation == "unknown_trigger":
            connection.execute(text("CREATE TRIGGER mutate_scan AFTER INSERT ON scan_session "
                                    "BEGIN UPDATE scan_session SET scan_name = 'changed' WHERE id = NEW.id; END"))
        elif mutation == "unknown_view":
            connection.execute(text("CREATE VIEW custom_scan_view AS SELECT id FROM scan_session"))
        before = connection.execute(text("SELECT name, sql FROM sqlite_master ORDER BY name")).all()
    with pytest.raises(SchemaError):
        initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT name, sql FROM sqlite_master ORDER BY name")).all() == before


def test_schema_ddl_and_version_stamp_roll_back_together(database):
    module, engine = database

    def fail_stamp(connection, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO schema_version"):
            raise RuntimeError("injected upgrade failure")

    event.listen(engine, "before_cursor_execute", fail_stamp)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, "before_cursor_execute", fail_stamp)
    assert inspect(engine).get_table_names() == []
    initialize_schema(engine, module.db.metadata)
    assert version(engine, module) == [(1, 1)]


def test_benign_extra_index_is_preserved_during_acceptance(database):
    module, engine = database
    initialize_schema(engine, module.db.metadata)
    with engine.begin() as connection:
        connection.execute(text("CREATE INDEX operator_scan_tenant ON scan_session (organization_id)"))
    initialize_schema(engine, module.db.metadata)
    assert any(index["name"] == "operator_scan_tenant"
               for index in inspect(engine).get_indexes("scan_session"))


def test_live_dispatcher_blocks_upgrade_callback_before_database_changes(store):
    first = JobDispatcher(store, Mock(), workers=1)
    initializer = Mock()
    second = JobDispatcher(store, Mock(), workers=1, initialize=initializer)
    try:
        first.start()
        with pytest.raises(RuntimeError, match="Another dispatcher"):
            second.start()
        initializer.assert_not_called()
    finally:
        first.stop()


def test_tenant_history_contains_only_fixed_transition_fields(api):
    module, client = api
    response = client.post("/api/scans", headers=headers(module), json={
        "scan_name": "credential-secret-prompt", "scan_type": "discovery_only",
        "target_scope": {"network_ranges": ["192.0.2.1/32"]}})
    scan_id = response.json["scan_id"]
    for forbidden in (scan_id, "missing"):
        denied = client.get(f"/api/scans/{forbidden}/audit", headers=headers(module, "tenant-b"))
        assert denied.status_code == 404
    assert client.post(f"/api/scans/{scan_id}/cancel", headers=headers(module)).status_code == 202
    response = client.get(f"/api/scans/{scan_id}/audit", headers=headers(module))
    assert [row["event"] for row in response.json["events"]] == ["admitted", "terminal"]
    assert "credential-secret-prompt" not in json.dumps(response.json)
    assert all(set(row) == {"id", "event", "previous_status", "status", "created_at"}
               for row in response.json["events"])
    page = client.get(f"/api/scans/{scan_id}/audit?limit=1", headers=headers(module)).json
    assert len(page["events"]) == 1
    after = page["next_after"]
    assert client.get(f"/api/scans/{scan_id}/audit?after={after}", headers=headers(module)).json["events"][0]["event"] == "terminal"
    assert client.get(f"/api/scans/{scan_id}/audit?after=bad", headers=headers(module)).status_code == 400
    for pagination in ("after=-1", f"after={2**63}", "after=" + "9" * 4096,
                       "limit=0", "limit=201", "limit=-1"):
        assert client.get(f"/api/scans/{scan_id}/audit?{pagination}", headers=headers(module)).status_code == 400


def test_transition_retries_do_not_duplicate_audit_events(store):
    enqueue(store, "cancel")
    assert store.claim("worker") == "cancel"
    assert store.cancel("cancel") == store.cancel("cancel") == "cancel_requested"
    store.finish("cancel")
    store.finish("cancel")
    assert [row["event"] for row in history(store)] == ["claimed", "cancel_requested", "terminal"]
    assert all(row["organization_id"] == "tenant-a" for row in history(store))
    assert state(store, "cancel") == result(store, "cancel")["status"] == "cancelled"


def test_audit_failure_rolls_back_claim_and_terminal_state(store, monkeypatch):
    enqueue(store, "rollback")
    original = store._event
    monkeypatch.setattr(store, "_event", Mock(side_effect=RuntimeError("audit write failed")))
    with pytest.raises(RuntimeError):
        store.claim("worker")
    assert state(store, "rollback") == "queued"
    with pytest.raises(RuntimeError):
        store.cancel("rollback")
    assert state(store, "rollback") == "queued"
    assert result(store, "rollback") is None
    monkeypatch.setattr(store, "_event", original)
    assert store.cancel("rollback") == "cancelled"
    assert len(history(store)) == 1


def test_result_snapshots_and_summary_roll_back_with_failed_terminal_event(store, api, monkeypatch):
    module, _ = api
    snapshots = module.DiscoveredAgentModel.__table__
    snapshots.create(store.engine)
    enqueue(store, "result")
    assert store.claim("worker") == "result"
    output = {"status": "completed", "agents": [{"id": "finding"}], "summary": {
        "agents_discovered": 1, "vulnerabilities_found": 1,
        "critical_risks": 1, "overall_risk_score": 70.0}}
    records = [{"id": "snapshot", "scan_id": "result", "agent_name": "agent",
                "agent_type": "test", "discovery_method": "fixture"}]
    original = store._event
    monkeypatch.setattr(store, "_event", Mock(side_effect=RuntimeError("terminal event write failed")))
    with pytest.raises(RuntimeError):
        store.save_result("result", output, snapshots, records)
    with store.engine.connect() as connection:
        assert connection.execute(select(snapshots)).all() == []
        assert connection.scalar(select(store.scans.c.agents_discovered)) == 0
    assert state(store, "result") == "running"
    assert result(store, "result") is None
    monkeypatch.setattr(store, "_event", original)
    assert store.cancel("result") == "cancel_requested"
    store.save_result("result", output, snapshots, records)
    with store.engine.connect() as connection:
        assert connection.scalar(select(snapshots.c.id)) == "snapshot"
        assert connection.scalar(select(store.scans.c.agents_discovered)) == 1
    assert result(store, "result")["agents"] == [{"id": "finding"}]
    assert state(store, "result") == result(store, "result")["status"] == "cancelled"


def test_concurrent_result_and_cancellation_have_one_consistent_terminal_event(store):
    # Actual write contention exercises both allowed outcomes, depending on which wins.
    for number in range(16):
        scan_id = f"race-{number}"
        enqueue(store, scan_id)
        assert store.claim("worker") == scan_id
        barrier = threading.Barrier(2)
        output = {"status": "completed", "agents": [], "summary": {
            "agents_discovered": 0, "vulnerabilities_found": 0,
            "critical_risks": 0, "overall_risk_score": None}}

        def save():
            barrier.wait(3)
            store.save_result(scan_id, output, None, [])

        def cancel():
            barrier.wait(3)
            return store.cancel(scan_id)

        with ThreadPoolExecutor(max_workers=2) as executor:
            saved, cancelled = executor.submit(save), executor.submit(cancel)
            saved.result(3)
            accepted = cancelled.result(3)
        terminal = state(store, scan_id)
        assert terminal == result(store, scan_id)["status"]
        assert terminal == ("cancelled" if accepted else "completed")
        with store.engine.connect() as connection:
            assert connection.scalar(select(store.scans.c.status).where(store.scans.c.id == scan_id)) == terminal
        events = [row for row in history(store) if row["scan_id"] == scan_id]
        assert sum(row["event"] == "terminal" for row in events) == 1
        assert sum(row["event"] == "cancel_requested" for row in events) == bool(accepted)


def test_recovery_history_is_idempotent_and_persists_across_restart(store):
    enqueue(store, "interrupted", "running")
    assert store.recover() == 1
    assert store.recover() == 0
    assert [(row["event"], row["status"]) for row in history(store)] == [("terminal", "interrupted")]


def test_worker_error_overrides_implicit_completed_scan_but_preserves_explicit_interrupt(store):
    enqueue(store, "failed", "running")
    with store.engine.begin() as connection:
        connection.execute(text("UPDATE scan_session SET status = 'completed' WHERE id = 'failed'"))
    store.finish("failed", "Scan worker failed")
    assert state(store, "failed") == result(store, "failed")["status"] == "failed"
    enqueue(store, "interrupted", "running")
    store.finish("interrupted", "Server stopped during scan", status="interrupted")
    assert state(store, "interrupted") == result(store, "interrupted")["status"] == "interrupted"
