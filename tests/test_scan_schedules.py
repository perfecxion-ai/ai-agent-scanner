"""Finite scheduling uses synthetic time, local policy, and real SQLite transactions."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest
from sqlalchemy import MetaData, create_engine, event, inspect, insert, select

from src.core.jobs import TERMINAL_STATES
from src.core.schedules import schedule_definition
from src.core.schema import SCHEMA_VERSION, VERSION_TWO_TABLES, SchemaError, initialize_schema
from src.core.scope import ScopeValidationError
from tests.test_api_auth import api as api, headers
from tests.test_scan_templates import file_api as file_api, save, definition, source_fixture, security_definition


NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)


def create(module, client, template=None, **changes):
    template = template or save(module, client)
    data = {"template_id": template["id"], "template_revision": template["revision"],
            "interval_seconds": 60, "total_runs": 2, **changes}
    response = client.post("/api/schedules", headers=headers(module), json=data)
    assert response.status_code == 201, response.json
    return response.json["schedule"]


def fetch(module, client, row):
    return client.get(f"/api/schedules/{row['id']}", headers=headers(module)).json["schedule"]


def action(module, client, row, name):
    return client.post(f"/api/schedules/{row['id']}/{name}", headers=headers(module),
                       json={"revision": row["revision"]})


def due(module, identifier):
    row = module.db.session.get(module.ScanSchedule, identifier)
    row.next_due_at = NOW - timedelta(days=10)
    module.db.session.commit()


def admit(module):
    candidate = module._schedule_candidate()
    assert candidate is not None
    result = module._schedule_preflight(candidate)
    module._schedule_admit(candidate, result, threading.Event())
    return candidate, result


def counts(module):
    return tuple(model.query.count() for model in (
        module.ScanSession, module.ScanJob, module.AuditEvent, module.ScanOccurrence))


def test_creation_is_disabled_and_has_no_scan_or_wake(api, monkeypatch):
    module, client = api
    dispatcher = Mock()
    monkeypatch.setattr(module, "_job_dispatcher", dispatcher)
    row = create(module, client)
    assert row["state"] == "disabled" and row["next_due_at"] is None
    assert row["admitted_runs"] == 0 and row["revision"] == 1
    assert counts(module) == (0, 0, 0, 0)
    assert module._schedule_candidate() is None
    dispatcher.wake.assert_not_called()
    assert fetch(module, client, row) == row
    page = client.get("/api/schedules?limit=1", headers=headers(module)).json
    assert page["total"] == 1 and page["schedules"] == [row]


@pytest.mark.parametrize("method,suffix", [("get", ""), ("delete", ""), ("post", "/enable"),
                                        ("post", "/pause"), ("get", "/occurrences")])
def test_tenant_isolation_and_auth(api, method, suffix):
    module, client = api
    row = create(module, client)
    path = f"/api/schedules/{row['id']}{suffix}"
    assert getattr(client, method)(path, json={}).status_code == 401
    foreign = getattr(client, method)(path, headers=headers(module, "tenant-b"), json={})
    missing = getattr(client, method)(f"/api/schedules/missing{suffix}",
                                      headers=headers(module, "tenant-b"), json={})
    assert foreign.status_code == missing.status_code == 404 and foreign.json == missing.json
    assert client.get("/api/schedules", headers=headers(module, "tenant-b")).json["schedules"] == []


@pytest.mark.parametrize("method", ["get", "post"])
def test_collection_requires_auth(api, method):
    _, client = api
    assert getattr(client, method)("/api/schedules", json={}).status_code == 401


@pytest.mark.parametrize("changes", [{"interval_seconds": 59}, {"interval_seconds": 2592001},
    {"interval_seconds": True}, {"interval_seconds": "60"}, {"total_runs": 0}, {"total_runs": 101},
    {"total_runs": False}, {"template_revision": 0}, {"template_revision": 2**31},
    {"template_id": ""}, {"template_id": []}, {"template_id": "x" * 65},
    {"enabled": True}, {"organization_id": "other"}, {"api_key": "synthetic-secret"}])
def test_invalid_contract_never_persists_or_echoes(api, changes):
    module, client = api
    template = save(module, client)
    response = client.post("/api/schedules", headers=headers(module), json={
        "template_id": template["id"], "template_revision": 1, "interval_seconds": 60, "total_runs": 1,
        **changes})
    assert response.status_code == 400
    assert "synthetic-secret" not in response.get_data(as_text=True)
    assert module.ScanSchedule.query.count() == 0 and counts(module) == (0, 0, 0, 0)


@pytest.mark.parametrize("data", [None, [], "value", {}, {"template_id": "fixture"}])
def test_incomplete_contract_is_invalid(data):
    with pytest.raises(ScopeValidationError):
        schedule_definition(data)


@pytest.mark.parametrize("setting", ["SCAN_MAX_SCHEDULES", "SCAN_MAX_SCHEDULES_GLOBAL"])
def test_quota_is_bounded(api, monkeypatch, setting):
    module, client = api
    monkeypatch.setitem(module.app.config, setting, 1)
    template = save(module, client)
    create(module, client, template)
    response = client.post("/api/schedules", headers=headers(module), json={
        "template_id": template["id"], "template_revision": 1, "interval_seconds": 60, "total_runs": 1})
    assert response.status_code == 429 and module.ScanSchedule.query.count() == 1


@pytest.mark.parametrize("path", ["/api/schedules", "/api/schedules/ID/occurrences"])
@pytest.mark.parametrize("query", ["limit=0", "limit=101", "offset=-1", "offset=100001", "limit=bad"])
def test_list_bounds(api, path, query):
    module, client = api
    row = create(module, client)
    response = client.get(f"{path.replace('ID', row['id'])}?{query}", headers=headers(module))
    assert response.status_code == 400


def test_enable_pause_cas_and_first_run_is_not_immediate(api, monkeypatch):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    row = create(module, client)
    enabled = action(module, client, row, "enable")
    assert enabled.status_code == 200
    enabled = enabled.json["schedule"]
    assert enabled["state"] == "enabled" and enabled["revision"] == 2
    assert enabled["next_due_at"] == (NOW + timedelta(seconds=60)).isoformat()
    assert module._schedule_candidate() is None and counts(module) == (0, 0, 0, 0)
    assert action(module, client, row, "pause").status_code == 409
    paused = action(module, client, enabled, "pause")
    assert paused.status_code == 200 and paused.json["schedule"]["pause_reason"] == "operator_paused"
    assert paused.json["schedule"]["next_due_at"] is None


@pytest.mark.parametrize("body", [{}, [], None, {"revision": True}, {"revision": 0},
                                 {"revision": 1, "enabled": True}])
def test_action_body_is_strict(api, body):
    module, client = api
    row = create(module, client)
    response = client.post(f"/api/schedules/{row['id']}/enable", headers=headers(module), json=body)
    assert response.status_code == 400 and fetch(module, client, row)["state"] == "disabled"


@pytest.mark.parametrize("terminal", sorted(TERMINAL_STATES))
def test_finite_runs_consume_all_terminal_outcomes_and_never_catch_up(api, monkeypatch, terminal):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    row = create(module, client)
    assert action(module, client, row, "enable").status_code == 200
    due(module, row["id"])
    admit(module)
    current = fetch(module, client, row)
    assert current["admitted_runs"] == 1 and current["outstanding_scan_id"]
    assert current["next_due_at"] is None and counts(module) == (1, 1, 1, 1)
    assert module._schedule_candidate() is None
    module._get_job_store().finish(current["outstanding_scan_id"], status=terminal)
    assert module._schedule_candidate() is None
    current = fetch(module, client, row)
    assert current["state"] == "enabled" and current["outstanding_scan_id"] is None
    assert current["next_due_at"] == (NOW + timedelta(seconds=60)).isoformat()
    assert module._schedule_candidate() is None
    due(module, row["id"])
    admit(module)
    current = fetch(module, client, row)
    module._get_job_store().finish(current["outstanding_scan_id"], status=terminal)
    assert module._schedule_candidate() is None
    current = fetch(module, client, row)
    assert current["state"] == "completed" and current["admitted_runs"] == 2
    assert current["next_due_at"] is None and current["outstanding_scan_id"] is None
    occurrences = client.get(f"/api/schedules/{row['id']}/occurrences", headers=headers(module)).json
    assert occurrences["total"] == 2 and [item["ordinal"] for item in occurrences["occurrences"]] == [1, 2]
    assert counts(module) == (2, 2, 4, 2)
    assert action(module, client, current, "enable").status_code == 409


def test_queue_full_defers_without_consuming_occurrence(api, monkeypatch):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    monkeypatch.setitem(module.app.config, "SCAN_MAX_QUEUED", 1)
    row = create(module, client)
    action(module, client, row, "enable")
    due(module, row["id"])
    assert client.post("/api/scans", headers=headers(module), json=definition()).status_code == 202
    admit(module)
    current = fetch(module, client, row)
    assert current["admitted_runs"] == 0 and current["state"] == "enabled"
    assert current["next_due_at"] == (NOW + timedelta(seconds=60)).isoformat()
    assert counts(module) == (1, 1, 1, 0)


def test_competing_final_admissions_create_one_occurrence(file_api, monkeypatch):
    module, client = file_api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    row = create(module, client)
    action(module, client, row, "enable")
    due(module, row["id"])
    candidate = module._schedule_candidate()
    result = module._schedule_preflight(candidate)
    barrier = threading.Barrier(2)

    def submit():
        barrier.wait(3)
        module._schedule_admit(candidate, result, threading.Event())

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(lambda number: submit(), range(2)))
    module.db.session.expire_all()
    assert counts(module) == (1, 1, 1, 1)
    assert fetch(module, client, row)["admitted_runs"] == 1


def test_competing_schedule_actions_use_revision_cas(file_api):
    module, client = file_api
    row = create(module, client)
    barrier = threading.Barrier(2)

    def submit(name):
        with module.app.test_client() as concurrent:
            barrier.wait(3)
            return action(module, concurrent, row, name).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, ["enable", "pause"]))
    assert sorted(results) == [200, 409]
    assert fetch(module, client, row)["revision"] == 2


@pytest.mark.parametrize("phase", ["create", "enable", "preflight"])
@pytest.mark.parametrize("mutation", ["policy", "source"])
def test_changes_during_validation_require_review(api, monkeypatch, phase, mutation):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    source_fixture(module)
    template = save(module, client, security_definition())
    row = None
    if phase != "create":
        row = create(module, client, template)
    if phase == "preflight":
        action(module, client, row, "enable")
        due(module, row["id"])
    original = module._prepare_template

    def change(data, tenant, **kwargs):
        result = original(data, tenant, **kwargs)
        if mutation == "policy":
            monkeypatch.setitem(module.app.config, "SCAN_MAX_REQUESTS", 1)
        else:
            source = module.db.session.get(module.ScanResult, "source")
            source.result = {"agents": [{"id": "changed", "endpoint": "https://192.0.2.1/other"}]}
            module.db.session.commit()
        return result

    monkeypatch.setattr(module, "_prepare_template", change)
    if phase == "create":
        response = client.post("/api/schedules", headers=headers(module), json={
            "template_id": template["id"], "template_revision": 1, "interval_seconds": 60, "total_runs": 1})
        assert response.status_code == 409 and module.ScanSchedule.query.count() == 0
    elif phase == "enable":
        assert action(module, client, row, "enable").status_code == 409
        assert fetch(module, client, row)["state"] == "disabled"
    else:
        candidate = module._schedule_candidate()
        result = module._schedule_preflight(candidate)
        assert result == {"error": "policy_review"}
        module._schedule_admit(candidate, result, threading.Event())
        assert fetch(module, client, row)["pause_reason"] == "policy_review"
    assert module.ScanJob.query.count() == 0


def test_foreign_template_and_stale_template_revision_are_rejected(api):
    module, client = api
    template = save(module, client)
    data = {"template_id": template["id"], "template_revision": 1, "interval_seconds": 60, "total_runs": 1}
    foreign = client.post("/api/schedules", headers=headers(module, "tenant-b"), json=data)
    assert foreign.status_code == 404
    stale = client.post("/api/schedules", headers=headers(module), json={**data, "template_revision": 2})
    assert stale.status_code == 409 and module.ScanSchedule.query.count() == 0


def test_preflight_source_removal_has_accurate_fixed_review_reason(api, monkeypatch):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    source_fixture(module)
    template = save(module, client, security_definition())
    row = create(module, client, template)
    action(module, client, row, "enable")
    due(module, row["id"])
    module.db.session.delete(module.db.session.get(module.ScanSession, "source"))
    module.db.session.commit()
    _, result = admit(module)
    assert result == {"error": "policy_review"}
    assert fetch(module, client, row)["pause_reason"] == "policy_review"


def test_symlink_change_during_schedule_lifetime_is_revalidated(api, monkeypatch, tmp_path):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    allowed = tmp_path / "allowed"
    denied = tmp_path / "denied"
    allowed.mkdir()
    denied.mkdir()
    (allowed / "fixture.txt").write_text("local fixture", encoding="utf-8")
    declaration = tmp_path / "declaration"
    declaration.symlink_to(allowed, target_is_directory=True)
    monkeypatch.setitem(module.app.config, "SCAN_ALLOWED_PATH_ROOTS", (str(allowed),))
    template = save(module, client, definition(target_scope={"repositories": [str(declaration)]}))
    row = create(module, client, template)
    action(module, client, row, "enable")
    due(module, row["id"])
    declaration.unlink()
    declaration.symlink_to(denied, target_is_directory=True)
    _, result = admit(module)
    assert result == {"error": "policy_review"} and module.ScanJob.query.count() == 0


def test_scheduled_job_worker_revalidates_after_admission(api, monkeypatch):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    row = create(module, client)
    action(module, client, row, "enable")
    due(module, row["id"])
    admit(module)
    current = fetch(module, client, row)
    monkeypatch.setitem(module.app.config, "SCAN_ALLOWED_NETWORKS", ())
    with patch.object(module, "_run_scan_in_thread") as run:
        with pytest.raises(ScopeValidationError):
            module._execute_job(current["outstanding_scan_id"], threading.Event())
    run.assert_not_called()


def test_scheduler_json_is_operational_only(api):
    module, client = api
    row = create(module, client)
    assert not set(row) & {"target_scope", "scan_config", "organization_id", "created_by", "definition", "token"}


def test_revision_ceiling_cannot_wrap_or_admit(api, monkeypatch):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    row = create(module, client)
    action(module, client, row, "enable")
    due(module, row["id"])
    current = module.db.session.get(module.ScanSchedule, row["id"])
    current.revision = 2**31 - 1
    module.db.session.commit()
    admit(module)
    current = fetch(module, client, row)
    assert current["revision"] == 2**31 - 1 and current["pause_reason"] == "revision_limit"
    assert module.ScanJob.query.count() == 0


@pytest.mark.parametrize("mutation", ["update", "delete"])
def test_template_mutation_pauses_atomically_and_does_not_cancel_snapshot(api, monkeypatch, mutation):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    template = save(module, client)
    row = create(module, client, template)
    action(module, client, row, "enable")
    due(module, row["id"])
    admit(module)
    scan_id = fetch(module, client, row)["outstanding_scan_id"]
    if mutation == "update":
        response = client.put(f"/api/templates/{template['id']}", headers=headers(module),
                              json={**definition(scan_name="Changed"), "revision": 1})
    else:
        response = client.delete(f"/api/templates/{template['id']}", headers=headers(module))
    assert response.status_code == 200
    current = fetch(module, client, row)
    assert current["state"] == "paused" and current["pause_reason"] == f"template_{'changed' if mutation == 'update' else 'deleted'}"
    scan = module.db.session.get(module.ScanSession, scan_id)
    assert scan.status == "queued" and scan.scan_name == "Fixture inventory"
    assert action(module, client, current, "enable").status_code == (409 if mutation == "update" else 404)


@pytest.mark.parametrize("mutation", ["pause", "template", "policy", "source", "stop"])
def test_late_preflight_cannot_admit_stale_intent(api, monkeypatch, mutation):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    if mutation == "source":
        source_fixture(module)
        template = save(module, client, security_definition())
    else:
        template = save(module, client)
    row = create(module, client, template)
    action(module, client, row, "enable")
    due(module, row["id"])
    candidate = module._schedule_candidate()
    result = module._schedule_preflight(candidate)
    stop = threading.Event()
    if mutation == "pause":
        action(module, client, fetch(module, client, row), "pause")
    elif mutation == "template":
        client.put(f"/api/templates/{template['id']}", headers=headers(module),
                   json={**definition(), "revision": 1})
    elif mutation == "policy":
        monkeypatch.setitem(module.app.config, "SCAN_ALLOWED_NETWORKS", ())
    elif mutation == "source":
        module.db.session.get(module.ScanSession, "source").status = "failed"
        module.db.session.commit()
    else:
        stop.set()
    before = counts(module)
    module._schedule_admit(candidate, result, stop)
    assert counts(module) == before
    if mutation in {"policy", "source"}:
        assert fetch(module, client, row)["pause_reason"] == "policy_review"


def test_preflight_revalidates_changed_dns_and_never_echoes_failure(api, monkeypatch):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    monkeypatch.setattr("src.core.scope.resolve_domain", lambda host: ["192.0.2.1"])
    template = save(module, client, definition(target_scope={"domains": ["fixture.test"]}))
    row = create(module, client, template)
    action(module, client, row, "enable")
    due(module, row["id"])
    monkeypatch.setattr("src.core.scope.resolve_domain", lambda host: ["169.254.169.254"])
    _, result = admit(module)
    assert result == {"error": "policy_review"}
    assert fetch(module, client, row)["pause_reason"] == "policy_review"
    assert counts(module) == (0, 0, 0, 0)


def test_atomic_occurrence_admission_rolls_back_all_records(file_api, monkeypatch):
    module, client = file_api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    row = create(module, client)
    action(module, client, row, "enable")
    due(module, row["id"])

    def fail(connection, cursor, statement, parameters, context, many):
        if statement.startswith("INSERT INTO scan_occurrence"):
            raise RuntimeError("injected commit failure")

    event.listen(module.db.engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            admit(module)
    finally:
        event.remove(module.db.engine, "before_cursor_execute", fail)
    assert counts(module) == (0, 0, 0, 0)
    current = fetch(module, client, row)
    assert current["admitted_runs"] == 0 and current["outstanding_scan_id"] is None


def test_restart_pauses_enabled_and_preserves_disabled_and_admitted_jobs(api, monkeypatch):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    active, disabled = create(module, client), create(module, client)
    action(module, client, active, "enable")
    due(module, active["id"])
    admit(module)
    scan_id = fetch(module, client, active)["outstanding_scan_id"]
    module._schedule_recover()
    current = fetch(module, client, active)
    assert current["state"] == "paused" and current["pause_reason"] == "restart_review"
    assert current["outstanding_scan_id"] == scan_id and module.db.session.get(module.ScanJob, scan_id).status == "queued"
    assert fetch(module, client, disabled)["state"] == "disabled"
    assert module._schedule_candidate() is None


def test_delete_requires_inactive_finished_pointer_and_preserves_scan(api, monkeypatch):
    module, client = api
    monkeypatch.setattr(module, "_utcnow", lambda: NOW)
    row = create(module, client, total_runs=1)
    action(module, client, row, "enable")
    assert client.delete(f"/api/schedules/{row['id']}", headers=headers(module)).status_code == 409
    due(module, row["id"])
    admit(module)
    current = fetch(module, client, row)
    scan_id = current["outstanding_scan_id"]
    assert action(module, client, current, "pause").status_code == 200
    assert client.delete(f"/api/schedules/{row['id']}", headers=headers(module)).status_code == 409
    module._get_job_store().cancel(scan_id)
    module._schedule_candidate()
    assert client.delete(f"/api/schedules/{row['id']}", headers=headers(module)).status_code == 200
    assert module.ScanOccurrence.query.count() == 0 and module.ScanSchedule.query.count() == 0
    assert module.db.session.get(module.ScanSession, scan_id).status == "cancelled"




@pytest.mark.parametrize("fail", [False, True])
def test_exact_version_two_upgrade_is_atomic_and_preserves_template(api, tmp_path, fail):
    module, _ = api
    engine = create_engine(f"sqlite:///{tmp_path / 'schedule-upgrade.db'}")
    metadata = MetaData()
    for name in VERSION_TWO_TABLES:
        module.db.metadata.tables[name].to_metadata(metadata)
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(metadata.tables["schema_version"]).values(id=1, version=2))
        connection.execute(insert(metadata.tables["scan_template"]).values(
            id="retained", organization_id="tenant-a", **definition()))

    def fail_stamp(connection, cursor, statement, parameters, context, many):
        if statement.startswith("UPDATE schema_version"):
            raise RuntimeError("injected stamp failure")

    if fail:
        event.listen(engine, "before_cursor_execute", fail_stamp)
        try:
            with pytest.raises(RuntimeError, match="injected"):
                initialize_schema(engine, module.db.metadata)
        finally:
            event.remove(engine, "before_cursor_execute", fail_stamp)
        assert set(inspect(engine).get_table_names()) == VERSION_TWO_TABLES
        with engine.connect() as connection:
            assert connection.scalar(select(metadata.tables["schema_version"].c.version)) == 2
    initialize_schema(engine, module.db.metadata)
    initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.scalar(select(module.SchemaVersion.version)) == SCHEMA_VERSION
        assert connection.scalar(select(module.ScanTemplate.scan_name)) == "Fixture inventory"
        assert connection.execute(select(module.ScanSchedule)).all() == []
        assert connection.execute(select(module.ScanOccurrence)).all() == []
    engine.dispose()


@pytest.mark.parametrize("mutation", ["unstamped_schedule", "unstamped_occurrence", "missing_template", "extra_column"])
def test_unknown_version_two_layout_is_rejected_without_changes(api, tmp_path, mutation):
    module, _ = api
    engine = create_engine(f"sqlite:///{tmp_path / 'invalid-schedule.db'}")
    metadata = MetaData()
    for name in VERSION_TWO_TABLES:
        module.db.metadata.tables[name].to_metadata(metadata)
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(metadata.tables["schema_version"]).values(id=1, version=2))
        if mutation == "unstamped_schedule":
            module.ScanSchedule.__table__.create(connection)
        elif mutation == "unstamped_occurrence":
            module.ScanOccurrence.__table__.create(connection)
        elif mutation == "missing_template":
            connection.exec_driver_sql("DROP TABLE scan_template")
        else:
            connection.exec_driver_sql("ALTER TABLE scan_template ADD COLUMN custom TEXT")
        before = connection.exec_driver_sql("SELECT name, sql FROM sqlite_master ORDER BY name").all()
    with pytest.raises(SchemaError):
        initialize_schema(engine, module.db.metadata)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT name, sql FROM sqlite_master ORDER BY name").all() == before
        assert connection.scalar(select(module.SchemaVersion.version)) == 2
    engine.dispose()
