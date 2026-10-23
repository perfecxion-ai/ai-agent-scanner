"""Real SQLite upgrade, transaction and tenant history acceptance tests."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, event, inspect, insert, select, text, CheckConstraint, DefaultClause
from sqlalchemy.exc import IntegrityError

from src.core.jobs import JobDispatcher
from src.core.schema import BASE_TABLES, LEGACY_LAYOUTS, SCHEMA_VERSION, VERSION_ONE_TABLES, SchemaError, initialize_schema
from tests.test_api_auth import api as api, headers
from tests.test_jobs import store as store, enqueue, state, result
from tests.historical_schema import historical_metadata


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
    assert version(engine, module) == [(1, SCHEMA_VERSION)]


@pytest.mark.parametrize('old_version', [1, 2, 3])
def test_historical_fixtures_keep_not_null_scores_and_python_zero_defaults(database, old_version):
    _, engine = database
    metadata = historical_metadata(version=old_version)
    metadata.create_all(engine)
    scans, assets = metadata.tables['scan_session'], metadata.tables['discovered_agent']
    for table, name in ((scans, 'overall_risk_score'), (assets, 'risk_score')):
        assert table.c[name].nullable is False
        assert table.c[name].default.arg == 0.0
        assert table.c[name].server_default is None
        stored = next(column for column in inspect(engine).get_columns(table.name) if column['name'] == name)
        assert stored['nullable'] is False and stored['default'] is None
    with engine.begin() as connection:
        connection.execute(insert(scans).values(id='default-zero', organization_id='tenant-a',
                           scan_name='Frozen old fixture', scan_type='discovery_only',
                           target_scope={}, scan_config={}))
        connection.execute(insert(assets).values(id='default-zero', scan_id='default-zero',
                           agent_name='Frozen old fixture', agent_type='assistant', discovery_method='fixture'))
    with engine.connect() as connection:
        assert connection.scalar(select(scans.c.overall_risk_score)) == 0.0
        assert connection.scalar(select(assets.c.risk_score)) == 0.0
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(scans.update().values(overall_risk_score=None))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(assets.update().values(risk_score=None))


@pytest.mark.parametrize("layout", LEGACY_LAYOUTS)
def test_recognized_legacy_upgrade_preserves_rows_and_creates_no_fake_history(database, layout):
    module, engine = database
    metadata = historical_metadata(layout)
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
    assert version(engine, module) == [(1, SCHEMA_VERSION)]


@pytest.mark.parametrize("mutation", ["unknown_table", "extra_column", "missing_column", "future_version",
                                      "partial_versioned", "unversioned_audit", "unknown_trigger",
                                      "unknown_view", "unknown_constraint", "unknown_unique_index",
                                      "unknown_default"])
def test_unknown_schemas_fail_without_changing_database(database, mutation):
    module, engine = database
    if mutation in {"future_version", "partial_versioned"}:
        initialize_schema(engine, module.db.metadata)
    else:
        metadata = historical_metadata(BASE_TABLES)
        if mutation == "unknown_constraint":
            metadata.tables["scan_session"].append_constraint(CheckConstraint("status = 'completed'"))
        if mutation == "unknown_default":
            metadata.tables["scan_session"].c.status.server_default = DefaultClause("queued")
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
        elif mutation == "unknown_unique_index":
            connection.execute(text("CREATE UNIQUE INDEX custom_scan_name ON scan_session (scan_name)"))
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
    assert version(engine, module) == [(1, SCHEMA_VERSION)]


def version_one_database(module, engine):
    metadata = historical_metadata(version=1)
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(metadata.tables["schema_version"]).values(id=1, version=1))
        connection.execute(insert(metadata.tables["scan_session"]).values(
            id="existing", organization_id="tenant-a", scan_name="retained", scan_type="discovery_only",
            status="completed", target_scope={}, scan_config={}))
        connection.execute(insert(metadata.tables["scan_result"]).values(
            scan_id="existing", result={"status": "completed", "retained": "finding"}))
    return metadata


def test_version_one_upgrade_preserves_existing_rows(database):
    module, engine = database
    version_one_database(module, engine)
    initialize_schema(engine, module.db.metadata)
    initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.scalar(select(module.ScanSession.scan_name)) == "retained"
        assert connection.scalar(select(module.ScanResult.result))["retained"] == "finding"
        assert connection.execute(select(module.ScanTemplate.__table__)).all() == []
    assert version(engine, module) == [(1, SCHEMA_VERSION)]


def test_version_one_upgrade_failure_rolls_back_table_and_stamp(database):
    module, engine = database
    version_one_database(module, engine)

    def fail_stamp(connection, cursor, statement, parameters, context, many):
        if statement.startswith("UPDATE schema_version"):
            raise RuntimeError("injected upgrade failure")

    event.listen(engine, "before_cursor_execute", fail_stamp)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            initialize_schema(engine, module.db.metadata)
    finally:
        event.remove(engine, "before_cursor_execute", fail_stamp)
    assert set(inspect(engine).get_table_names()) == VERSION_ONE_TABLES
    assert version(engine, module) == [(1, 1)]
    initialize_schema(engine, module.db.metadata)
    assert version(engine, module) == [(1, SCHEMA_VERSION)]


@pytest.mark.parametrize("mutation", ["unstamped_template", "missing_base", "future", "duplicate_stamp",
                                      "wrong_stamp_id", "changed_column", "extra_default"])
def test_version_one_unknown_layout_rejected_without_writes(database, mutation):
    module, engine = database
    version_one_database(module, engine)
    with engine.begin() as connection:
        if mutation == "unstamped_template":
            module.ScanTemplate.__table__.create(connection)
        elif mutation == "missing_base":
            connection.exec_driver_sql("DROP TABLE scan_result")
        elif mutation == "future":
            connection.exec_driver_sql(f"UPDATE schema_version SET version = {SCHEMA_VERSION + 1}")
        elif mutation == "duplicate_stamp":
            connection.exec_driver_sql("INSERT INTO schema_version VALUES (2, 1)")
        elif mutation == "wrong_stamp_id":
            connection.exec_driver_sql("UPDATE schema_version SET id = 2")
        elif mutation == "changed_column":
            connection.exec_driver_sql("ALTER TABLE scan_session ADD COLUMN unknown TEXT")
        else:
            connection.exec_driver_sql("ALTER TABLE audit_event ADD COLUMN unknown TEXT DEFAULT 'x'")
        before = connection.exec_driver_sql("SELECT name, sql FROM sqlite_master ORDER BY name").all()
        before_stamp = connection.exec_driver_sql("SELECT * FROM schema_version ORDER BY id").all()
    with pytest.raises(SchemaError):
        initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT name, sql FROM sqlite_master ORDER BY name").all() == before
        assert connection.exec_driver_sql("SELECT * FROM schema_version ORDER BY id").all() == before_stamp


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
        store.save_result("result", output, snapshots, records, owner='worker')
    with store.engine.connect() as connection:
        assert connection.execute(select(snapshots)).all() == []
        assert connection.scalar(select(store.scans.c.agents_discovered)) == 0
    assert state(store, "result") == "running"
    assert result(store, "result") is None
    monkeypatch.setattr(store, "_event", original)
    assert store.cancel("result") == "cancel_requested"
    store.save_result("result", output, snapshots, records, owner='worker')
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
            store.save_result(scan_id, output, None, [], owner='worker')

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


def test_jobless_legacy_terminal_retry_does_not_duplicate_history(store):
    enqueue(store, "legacy", "running", with_job=False)
    store.finish("legacy", "Scan worker failed")
    store.finish("legacy", "Scan worker failed")
    assert result(store, "legacy")["status"] == "failed"
    assert [(row["event"], row["status"]) for row in history(store)] == [("terminal", "failed")]


def test_completed_legacy_scan_does_not_get_fabricated_result_or_event(store):
    enqueue(store, "legacy", "running", with_job=False)
    with store.engine.begin() as connection:
        connection.execute(text("UPDATE scan_session SET status = 'completed' WHERE id = 'legacy'"))
    store.finish("legacy", "Scan worker failed")
    store.save_result("legacy", {"status": "completed"}, None, [])
    assert result(store, "legacy") is None
    assert history(store) == []
