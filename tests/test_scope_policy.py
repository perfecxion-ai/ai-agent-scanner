"""Synthetic request, filesystem, and network boundary regression cases."""

import asyncio
import threading
from unittest.mock import Mock, patch

import pytest

from src.core.scope import ScopePolicy, ScopeValidationError, validate_agent_endpoints, validate_request
from tests.test_api_auth import api as api, headers


def config(**updates):
    return {"SCAN_ALLOWED_NETWORKS": ("192.0.2.0/24", "2001:db8::/32"),
            "SCAN_ALLOWED_PATH_ROOTS": (), **updates}


def request_body(**scope):
    return {"scan_type": "discovery_only", "target_scope": scope}


@pytest.mark.parametrize("value", [None, [], "text", 42])
def test_body_requires_object(value):
    with pytest.raises(ScopeValidationError, match="JSON object"):
        validate_request(value, config())


@pytest.mark.parametrize("value", ["192.0.2.1/32", {}, [42], [None], [""], ["x"] * 33])
def test_network_target_requires_bounded_string_list(value):
    with pytest.raises(ScopeValidationError):
        validate_request(request_body(network_ranges=value), config())


@pytest.mark.parametrize("value", ["169.254.169.254/32", "fe80::1/128", "224.0.0.1/32",
                                  "0.0.0.0/32", "::ffff:127.0.0.1/128", "fd00:ec2::254/128",
                                  "100.100.100.200/32", "168.63.129.16/32"])
def test_metadata_and_special_ranges_always_denied(value):
    policy = ScopePolicy.from_config(config(SCAN_ALLOWED_NETWORKS=("0.0.0.0/0", "::/0")))
    with pytest.raises(ScopeValidationError, match="Forbidden"):
        policy.network(value)


def test_network_allowlist_defaults_closed_and_loopback_needs_opt_in():
    with pytest.raises(ScopeValidationError, match="allowlist"):
        ScopePolicy.from_config({}).network("192.0.2.1")
    loopback = config(SCAN_ALLOWED_NETWORKS=("127.0.0.1/32",))
    with pytest.raises(ScopeValidationError, match="Forbidden"):
        ScopePolicy.from_config(loopback).network("127.0.0.1")
    loopback["SCAN_ALLOW_LOOPBACK"] = True
    assert str(ScopePolicy.from_config(loopback).network("127.0.0.1")) == "127.0.0.1/32"


def test_aggregate_budget_counts_multiple_ranges():
    with pytest.raises(ScopeValidationError, match="aggregate"):
        validate_request(request_body(network_ranges=["192.0.2.0/25", "192.0.2.128/25"]),
                         config(SCAN_MAX_HOSTS=200))


def test_domains_resolve_once_to_allowed_literal_targets():
    resolver = Mock(return_value=["192.0.2.1", "2001:db8::1"])
    _, _, scope, _ = validate_request(request_body(domains=["fixture.example"]), config(), resolver)
    assert scope["network_ranges"] == ["192.0.2.1/32", "2001:db8::1/128"]
    assert scope["domains"] == []
    resolver.assert_called_once_with("fixture.example")


def test_one_disallowed_dns_answer_rejects_entire_domain():
    with pytest.raises(ScopeValidationError, match="Forbidden"):
        validate_request(request_body(domains=["fixture.example"]), config(),
                         lambda _: ["192.0.2.1", "169.254.169.254"])


@pytest.mark.parametrize("scope", [{"cloud_accounts": {"aws": {}}}, {"include_cloud": True},
                                  {"repositories": "file"}, {"include_network": "true"},
                                  {"network_ranges": ["192.0.2.1"], "include_network": False}])
def test_unsupported_or_mistyped_scope_rejected(scope):
    with pytest.raises(ScopeValidationError):
        validate_request(request_body(**scope), config())


def test_paths_require_allowlisted_roots_and_no_nested_symlinks(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("secret")
    policy = ScopePolicy.from_config(config(SCAN_ALLOWED_PATH_ROOTS=(str(allowed),)))
    with pytest.raises(ScopeValidationError, match="outside"):
        policy.validate_files([str(outside)])
    (allowed / "escape").symlink_to(outside)
    with pytest.raises(ScopeValidationError, match="Symlinks"):
        policy.validate_files([str(allowed)])


def test_file_budget_and_special_files(tmp_path):
    (tmp_path / "one.py").write_text("import openai")
    (tmp_path / "two.py").write_text("import openai")
    policy = ScopePolicy.from_config(config(SCAN_ALLOWED_PATH_ROOTS=(str(tmp_path),), SCAN_MAX_FILES=2))
    with pytest.raises(ScopeValidationError, match="budget"):
        policy.validate_files([str(tmp_path)])


def test_file_scans_normalize_flags_and_paths(tmp_path):
    fixture = tmp_path / "agent.py"
    fixture.write_text("import openai")
    _, _, scope, _ = validate_request(request_body(repositories=[str(tmp_path)]),
                                      config(SCAN_ALLOWED_PATH_ROOTS=(str(tmp_path),)))
    assert scope["repositories"] == [str(tmp_path)]
    assert scope["include_repositories"] and not scope["include_network"]


@pytest.mark.parametrize("endpoint", ["file:///etc/passwd", "http://user:pass@192.0.2.1/",
                                     "http://169.254.169.254/", "http://192.0.2.1:0/",
                                     "http://192.0.2.1/#fragment"])
def test_agent_endpoints_checked_before_probing(endpoint):
    with pytest.raises(ScopeValidationError):
        validate_agent_endpoints([{"endpoint": endpoint}], config())


def test_endpoint_validation_preserves_https_hostname():
    agents = [{"endpoint": "https://fixture.example/v1/chat"}]
    assert validate_agent_endpoints(agents, config(), lambda _: ["192.0.2.1"]) == agents


@pytest.mark.parametrize("body", [{"scan_type": "unsupported"},
                                  {"scan_type": "security_only"},
                                  {"scan_type": "discovery_only", "scan_config": {"timeout_seconds": True}},
                                  {"scan_type": "discovery_only", "scan_config": {"timeout_seconds": 301}}])
def test_modes_and_timeouts_validated(body):
    with pytest.raises(ScopeValidationError):
        validate_request(body, config())


@pytest.mark.parametrize("body", [[], None, "text", {"target_scope": {"domains": "example.com"}}])
def test_api_rejects_bad_request_without_worker(api, body):
    module, client = api
    with patch.object(module.threading, "Thread") as thread:
        response = client.post("/api/scans", headers=headers(module), json=body)
    assert response.status_code == 400
    thread.assert_not_called()


def test_api_payload_limit_is_413(api):
    module, client = api
    response = client.post("/api/scans", headers=headers(module), json={"padding": "x" * 65536})
    assert response.status_code == 413


def test_concurrency_limit_and_startup_failure_release_slot(api, monkeypatch):
    module, client = api
    monkeypatch.setattr(module, "_scan_slots", threading.BoundedSemaphore(1))
    body = request_body(network_ranges=["192.0.2.1/32"])
    with patch.object(module.threading, "Thread") as thread:
        thread.return_value.start.side_effect = RuntimeError("fixture")
        assert client.post("/api/scans", headers=headers(module), json=body).status_code == 500
    with patch.object(module.threading, "Thread"):
        assert client.post("/api/scans", headers=headers(module), json=body).status_code == 200
        assert client.post("/api/scans", headers=headers(module), json=body).status_code == 429
    assert module.ScanSession.query.filter_by(status="failed").count() == 1


def test_security_source_is_tenant_scoped(api):
    module, client = api
    module.db.session.add(module.ScanSession(id="other", organization_id="tenant-b", scan_name="x",
                          scan_type="discovery_only", status="completed", target_scope={}, scan_config={}))
    module.db.session.commit()
    for source in ("other", "missing"):
        response = client.post("/api/scans", headers=headers(module), json={
            "scan_type": "security_only", "scan_config": {"source_scan_id": source}})
        assert response.status_code == 404
        assert response.json["error"] == "Source scan not found"


def test_deadline_marks_failed_and_worker_releases_capacity(api, monkeypatch):
    module, _ = api
    module.db.session.add(module.ScanSession(id="deadline", organization_id="tenant-a", scan_name="x",
                          scan_type="discovery_only", target_scope={}, scan_config={}))
    module.db.session.commit()

    async def forever(*args):
        await asyncio.Event().wait()

    monkeypatch.setattr(module, "_execute_scan", forever)
    monkeypatch.setattr(module, "_scan_slots", threading.BoundedSemaphore(1))
    assert module._scan_slots.acquire(blocking=False)
    module._run_admitted_scan("deadline", "discovery_only", {}, {"timeout_seconds": 0.01})
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, "deadline").status == "failed"
    assert module._scan_slots.acquire(blocking=False)
