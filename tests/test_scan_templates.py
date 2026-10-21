"""Saved recipe boundaries use local policy fixtures and real SQLite admission."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine

from src.core.scope import ScopeValidationError
from src.core.templates import MAX_TEMPLATE_BYTES, project_template
from tests.test_api_auth import api as api, headers


def definition(**updates):
    return {"scan_name": "Fixture inventory", "scan_type": "discovery_only",
            "target_scope": {"network_ranges": ["192.0.2.1/32"]}, "scan_config": {}, **updates}


def save(module, client, body=None, tenant="tenant-a"):
    response = client.post("/api/templates", headers=headers(module, tenant), json=body or definition())
    assert response.status_code == 201, response.json
    return response.json["template"]


def counts(module):
    return tuple(model.query.count() for model in (module.ScanSession, module.ScanJob, module.AuditEvent))


def source_fixture(module, *, tenant="tenant-a", status="completed", has_result=True, has_assets=True,
                   redacted=False):
    module.db.session.add(module.ScanSession(id="source", organization_id=tenant, scan_name="source",
                          scan_type="discovery_only", status=status, target_scope={}, scan_config={}))
    if has_result:
        module.db.session.add(module.ScanResult(scan_id="source", result={"agents": [{
            "id": "asset", "name": "Fixture model", "endpoint": "https://192.0.2.1/v1/chat",
            "endpoint_redacted": redacted}]}))
    if has_assets:
        module.db.session.add(module.DiscoveredAgentModel(id="snapshot", scan_id="source", agent_name="Fixture",
                              agent_type="llm", discovery_method="network",
                              endpoint_url="https://192.0.2.1/v1/chat", metadata_json={"asset_id": "asset"}))
    module.db.session.commit()


def security_definition(**options):
    return definition(scan_type="security_only", target_scope={},
                      scan_config={"source_scan_id": "source", "model_overrides": {"asset": "chosen-model"}, **options})


@pytest.fixture
def file_api(api, tmp_path):
    module, client = api
    module.db.session.remove()
    original = module.db.engines[None]
    engine = create_engine(f"sqlite:///{tmp_path / 'templates.db'}")
    module.db.engines[None] = engine
    module.initialize_schema(engine, module.db.metadata)
    try:
        yield module, client
    finally:
        module.db.session.remove()
        module.db.engines[None] = original
        engine.dispose()


def test_round_trip_crud_pagination_and_no_execution(api, monkeypatch):
    module, client = api
    dispatcher = Mock()
    monkeypatch.setattr(module, "_job_dispatcher", dispatcher)
    row = save(module, client)
    assert row["revision"] == 1
    assert counts(module) == (0, 0, 0)
    dispatcher.wake.assert_not_called()
    fetched = client.get(f"/api/templates/{row['id']}", headers=headers(module)).json["template"]
    assert fetched == row
    page = client.get("/api/templates?limit=1&offset=0", headers=headers(module)).json
    assert page["total"] == 1 and len(page["templates"]) == 1
    assert "target_scope" not in page["templates"][0]
    updated = client.put(f"/api/templates/{row['id']}", headers=headers(module), json={
        **definition(scan_name="Changed"), "revision": 1})
    assert updated.status_code == 200 and updated.json["template"]["revision"] == 2
    assert counts(module) == (0, 0, 0)
    assert client.delete(f"/api/templates/{row['id']}", headers=headers(module)).status_code == 200
    assert client.get(f"/api/templates/{row['id']}", headers=headers(module)).status_code == 404


@pytest.mark.parametrize("method,path", [("get", "/api/templates"), ("post", "/api/templates"),
                                        ("get", "/api/templates/missing"), ("put", "/api/templates/missing"),
                                        ("delete", "/api/templates/missing"), ("post", "/api/templates/missing/run")])
def test_all_template_routes_require_auth(api, method, path):
    _, client = api
    assert getattr(client, method)(path, json={}).status_code == 401


@pytest.mark.parametrize("method,suffix", [("get", ""), ("put", ""), ("delete", ""), ("post", "/run")])
def test_foreign_templates_are_indistinguishable_from_missing(api, method, suffix):
    module, client = api
    row = save(module, client)
    foreign = getattr(client, method)(f"/api/templates/{row['id']}{suffix}",
                                      headers=headers(module, "tenant-b"), json={})
    missing = getattr(client, method)(f"/api/templates/missing{suffix}",
                                      headers=headers(module, "tenant-b"), json={})
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json == missing.json
    assert client.get("/api/templates", headers=headers(module, "tenant-b")).json["templates"] == []
    assert counts(module) == (0, 0, 0)


@pytest.mark.parametrize("body", [None, [], "value", {"organization_id": "tenant-b"},
    definition(api_key="fixture-secret"), definition(scan_config={"headers": {"Authorization": "fixture-secret"}}),
    definition(target_scope={"endpoints": ["https://192.0.2.1"]}),
    definition(target_scope={"include_cloud": True}), definition(scan_config={"timeout_seconds": True}),
    definition(scan_name="line\nname"), definition(scan_name="https://user:fixture-secret@host.test/path"),
    definition(scan_name="https://host.test/path?key=fixture-secret"),
    definition(target_scope={"network_ranges": ["192.0.2.1"] * 33}),
    definition(scan_config={"timeout_seconds": 301}), definition(scan_name="x" * 256),
    definition(scan_config={"canary": "fixture-secret"}), definition(scan_config={"api_key_env": "CREDENTIAL"}),
    definition(target_scope={"include_network": "true"})])
def test_invalid_recipe_is_not_persisted_or_echoed(api, body):
    module, client = api
    response = client.post("/api/templates", headers=headers(module), json=body)
    assert response.status_code == 400
    assert "fixture-secret" not in json.dumps(response.json)
    assert module.ScanTemplate.query.count() == 0 and counts(module) == (0, 0, 0)


@pytest.mark.parametrize("value", [float("inf"), float("nan"), float("-inf")])
def test_nonfinite_template_json_rejected(value):
    with pytest.raises(ScopeValidationError):
        project_template(definition(scan_config={"timeout_seconds": value}))


def test_template_bytes_are_bounded(api):
    module, client = api
    body = definition(target_scope={"repositories": ["/" + "x" * 4095] * 5})
    assert len(json.dumps(body).encode()) > MAX_TEMPLATE_BYTES
    assert client.post("/api/templates", headers=headers(module), json=body).status_code == 400
    assert module.ScanTemplate.query.count() == 0


def test_applied_defaults_also_count_toward_limit(api, monkeypatch):
    module, client = api
    oversized = definition(target_scope={"repositories": ["/" + "x" * 4095] * 5})
    monkeypatch.setattr(module, "_prepare_scan", Mock(return_value=oversized))
    assert client.post("/api/templates", headers=headers(module), json=definition()).status_code == 400
    assert module.ScanTemplate.query.count() == 0


def test_projection_exact_byte_limit_and_invalid_json_strings():
    base = len(json.dumps({"scan_name": ""}, ensure_ascii=False).encode("utf-8"))
    assert project_template({"scan_name": "x" * (MAX_TEMPLATE_BYTES - base)})
    with pytest.raises(ScopeValidationError, match="16 KiB"):
        project_template({"scan_name": "x" * (MAX_TEMPLATE_BYTES - base + 1)})
    for value in ("\ud800", "http://[invalid", object()):
        with pytest.raises(ScopeValidationError):
            project_template({"scan_name": value})


def test_template_quota_is_tenant_owned_and_delete_releases_capacity(api, monkeypatch):
    module, client = api
    monkeypatch.setitem(module.app.config, "SCAN_MAX_TEMPLATES", 1)
    first = save(module, client)
    assert client.post("/api/templates", headers=headers(module), json=definition()).status_code == 429
    other = save(module, client, tenant="tenant-b")
    assert first["id"] != other["id"]
    assert client.delete(f"/api/templates/{first['id']}", headers=headers(module)).status_code == 200
    save(module, client)
    assert module.ScanTemplate.query.count() == 2


@pytest.mark.parametrize("pagination", ["limit=0", "limit=101", "limit=bad", "offset=-1", "offset=100001", "offset=bad"])
def test_template_pagination_bounded(api, pagination):
    module, client = api
    assert client.get(f"/api/templates?{pagination}", headers=headers(module)).status_code == 400


@pytest.mark.parametrize("revision", [None, True, 0, -1, "1", 2**31])
def test_update_requires_valid_revision(api, revision):
    module, client = api
    row = save(module, client)
    response = client.put(f"/api/templates/{row['id']}", headers=headers(module),
                          json={**definition(), "revision": revision})
    assert response.status_code == 400
    assert module.db.session.get(module.ScanTemplate, row["id"]).revision == 1


def test_stale_revision_and_overrides_never_admit(api):
    module, client = api
    row = save(module, client)
    path = f"/api/templates/{row['id']}"
    assert client.put(path, headers=headers(module), json={**definition(), "revision": 1}).status_code == 200
    assert client.put(path, headers=headers(module), json={**definition(), "revision": 1}).status_code == 409
    assert client.post(path + "/run", headers=headers(module), json={"revision": 1}).status_code == 409
    assert client.post(path + "/run", headers=headers(module), json={"scan_config": {}}).status_code == 400
    assert client.post(path + "/run", headers=headers(module)).status_code == 400
    assert counts(module) == (0, 0, 0)


def test_run_shares_admission_audit_queue_cap_and_snapshot(api, monkeypatch):
    module, client = api
    row = save(module, client)
    dispatcher = Mock()
    monkeypatch.setattr(module, "_job_dispatcher", dispatcher)
    response = client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={"revision": 1})
    assert response.status_code == 202 and counts(module) == (1, 1, 1)
    dispatcher.wake.assert_called_once()
    scan_id = response.json["scan_id"]
    job = module.db.session.get(module.ScanSession, scan_id)
    assert job.organization_id == "tenant-a" and job.scan_name == row["scan_name"]
    assert module.AuditEvent.query.one().event == "admitted"
    monkeypatch.setitem(module.app.config, "SCAN_MAX_QUEUED", 1)
    assert client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={}).status_code == 429
    assert client.post("/api/scans", headers=headers(module), json=definition()).status_code == 429
    assert counts(module) == (1, 1, 1)
    assert client.put(f"/api/templates/{row['id']}", headers=headers(module),
                      json={**definition(scan_name="New recipe"), "revision": 1}).status_code == 200
    assert client.delete(f"/api/templates/{row['id']}", headers=headers(module)).status_code == 200
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, scan_id).scan_name == "Fixture inventory"


@pytest.mark.parametrize("use_template", [False, True])
def test_declared_domain_survives_admission_and_worker_rechecks(api, monkeypatch, use_template):
    module, client = api
    resolver = Mock(return_value=["192.0.2.1"])
    monkeypatch.setattr("src.core.scope.resolve_domain", resolver)
    body = definition(target_scope={"domains": ["lab.example.test"]})
    if use_template:
        row = save(module, client, body)
        assert row["target_scope"]["domains"] == ["lab.example.test"]
        response = client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={})
    else:
        response = client.post("/api/scans", headers=headers(module), json=body)
    assert response.status_code == 202
    job = module.db.session.get(module.ScanSession, response.json["scan_id"])
    assert job.target_scope["domains"] == ["lab.example.test"] and job.target_scope["network_ranges"] == []
    resolver.return_value = ["198.51.100.1"]
    runner = Mock()
    monkeypatch.setattr(module, "_run_scan_in_thread", runner)
    with pytest.raises(ScopeValidationError):
        module._execute_job(job.id, threading.Event())
    runner.assert_not_called()


def test_changed_domain_and_current_limits_reject_run(api, monkeypatch):
    module, client = api
    resolver = Mock(return_value=["192.0.2.1"])
    monkeypatch.setattr("src.core.scope.resolve_domain", resolver)
    row = save(module, client, definition(target_scope={"domains": ["lab.example.test"]}))
    resolver.return_value = ["169.254.169.254"]
    assert client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={}).status_code == 400
    resolver.return_value = ["192.0.2.1"]
    monkeypatch.setitem(module.app.config, "SCAN_TIMEOUT_SECONDS", 10)
    assert client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={}).status_code == 400
    assert counts(module) == (0, 0, 0)


@pytest.mark.parametrize("mutation,status", [("missing", 404), ("foreign", 404), ("pending", 400),
                                             ("result", 400), ("assets", 400), ("redacted", 400), ("model", 400)])
def test_security_recipe_requires_owned_replayable_source(api, mutation, status):
    module, client = api
    if mutation != "missing":
        source_fixture(module, tenant="tenant-b" if mutation == "foreign" else "tenant-a",
                       status="queued" if mutation == "pending" else "completed",
                       has_result=mutation != "result", has_assets=mutation != "assets",
                       redacted=mutation == "redacted")
    body = security_definition()
    if mutation == "model":
        body["scan_config"]["model_overrides"] = {"unknown": "chosen-model"}
    response = client.post("/api/templates", headers=headers(module), json=body)
    assert response.status_code == status
    assert module.ScanTemplate.query.count() == 0 and module.ScanJob.query.count() == 0


def test_security_recipe_rechecks_source_and_current_policy_at_run_and_worker(api, monkeypatch):
    module, client = api
    source_fixture(module)
    row = save(module, client, security_definition())
    response = client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={})
    assert response.status_code == 202
    scan_id = response.json["scan_id"]
    runner = Mock()
    monkeypatch.setattr(module, "_run_scan_in_thread", runner)
    module._execute_job(scan_id, threading.Event())
    assert runner.call_args.args[1:4] == ("security_only", {}, {
        "source_scan_id": "source", "model_overrides": {"asset": "chosen-model"}, "timeout_seconds": 300})
    assert "model" not in module.db.session.get(module.ScanResult, "source").result["agents"][0]
    monkeypatch.setitem(module.app.config, "SCAN_ALLOWED_NETWORKS", ("198.51.100.0/24",))
    assert client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={}).status_code == 400
    with pytest.raises(ScopeValidationError):
        module._execute_job(scan_id, threading.Event())
    monkeypatch.setitem(module.app.config, "SCAN_ALLOWED_NETWORKS", ("192.0.2.0/24",))
    source = module.db.session.get(module.ScanSession, "source")
    source.organization_id = "tenant-b"
    module.db.session.commit()
    assert client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={}).status_code == 404
    assert client.put(f"/api/templates/{row['id']}", headers=headers(module),
                      json={**security_definition(), "revision": 1}).status_code == 404


def test_relative_template_paths_remain_unsupported(api, tmp_path):
    module, client = api
    response = client.post("/api/templates", headers=headers(module), json=definition(
        target_scope={"repositories": ["relative/input.py"]}))
    assert response.status_code == 400 and "absolute" in response.json["error"]
    assert module.ScanTemplate.query.count() == 0


def test_declared_path_is_rechecked_after_symlink_change(api, monkeypatch, tmp_path):
    module, client = api
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    inside = allowed / "input.py"
    inside.write_text("fixture")
    outside = tmp_path / "outside.py"
    outside.write_text("outside")
    link = allowed / "declared.py"
    link.symlink_to(inside)
    monkeypatch.setitem(module.app.config, "SCAN_ALLOWED_PATH_ROOTS", (str(allowed),))
    row = save(module, client, definition(target_scope={"repositories": [str(link)]}))
    assert row["target_scope"]["repositories"] == [str(link)]
    response = client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={})
    assert response.status_code == 202
    link.unlink()
    link.symlink_to(outside)
    with pytest.raises(ScopeValidationError, match="outside"):
        module._execute_job(response.json["scan_id"], threading.Event())
    assert client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={}).status_code == 400


def test_preflight_does_not_hold_admission_lock(api, monkeypatch):
    module, client = api

    def resolve(_):
        acquired = module._admission_lock.acquire(blocking=False)
        assert acquired
        module._admission_lock.release()
        return ["192.0.2.1"]

    monkeypatch.setattr("src.core.scope.resolve_domain", resolve)
    body = definition(target_scope={"domains": ["lab.example.test"]})
    row = save(module, client, body)
    assert client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={}).status_code == 202
    assert client.post("/api/scans", headers=headers(module), json=body).status_code == 202


@pytest.mark.parametrize("operation", ["create", "update", "run", "delete"])
def test_failed_template_transactions_roll_back(api, monkeypatch, operation):
    module, client = api
    row = save(module, client) if operation != "create" else None
    monkeypatch.setattr(module.db.session, "commit", Mock(side_effect=RuntimeError("fixture-secret")))
    if operation == "create":
        response = client.post("/api/templates", headers=headers(module), json=definition())
    elif operation == "update":
        response = client.put(f"/api/templates/{row['id']}", headers=headers(module),
                              json={**definition(scan_name="Changed"), "revision": 1})
    elif operation == "delete":
        response = client.delete(f"/api/templates/{row['id']}", headers=headers(module))
    else:
        response = client.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={})
    assert response.status_code == 500 and "fixture-secret" not in json.dumps(response.json)
    assert counts(module) == (0, 0, 0)
    assert module.ScanTemplate.query.count() == (0 if operation == "create" else 1)
    if row:
        assert module.ScanTemplate.query.one().revision == 1
        assert module.ScanTemplate.query.one().scan_name == "Fixture inventory"


def test_concurrent_creation_cannot_exceed_quota(file_api, monkeypatch):
    module, _ = file_api
    monkeypatch.setitem(module.app.config, "SCAN_MAX_TEMPLATES", 1)
    original = module._prepare_template
    barrier = threading.Barrier(2)

    def prepare(*args, **kwargs):
        result = original(*args, **kwargs)
        barrier.wait(timeout=3)
        return result

    monkeypatch.setattr(module, "_prepare_template", prepare)

    def create(_):
        with module.app.test_client() as client:
            return client.post("/api/templates", headers=headers(module), json=definition()).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(create, range(2))) == [201, 429]
    assert module.ScanTemplate.query.count() == 1


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_recipe_change_during_run_preflight_cannot_admit(file_api, monkeypatch, operation):
    module, client = file_api
    row = save(module, client)
    entered, released = threading.Event(), threading.Event()
    original = module._prepare_template

    def prepare(*args, **kwargs):
        result = original(*args, **kwargs)
        if threading.current_thread().name == "template-run":
            entered.set()
            assert released.wait(3)
        return result

    monkeypatch.setattr(module, "_prepare_template", prepare)
    result = []

    def run():
        with module.app.test_client() as local:
            result.append(local.post(f"/api/templates/{row['id']}/run", headers=headers(module), json={}).status_code)

    thread = threading.Thread(target=run, name="template-run")
    thread.start()
    try:
        assert entered.wait(3)
        if operation == "update":
            assert client.put(f"/api/templates/{row['id']}", headers=headers(module),
                              json={**definition(), "revision": 1}).status_code == 200
        else:
            assert client.delete(f"/api/templates/{row['id']}", headers=headers(module)).status_code == 200
    finally:
        released.set()
        thread.join(3)
    assert not thread.is_alive()
    assert result == [409 if operation == "update" else 404]
    assert counts(module) == (0, 0, 0)
