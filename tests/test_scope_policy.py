"""Synthetic request, filesystem, and network boundary regression cases."""

import asyncio
from unittest.mock import Mock, mock_open, patch

import pytest

from src.core.scope import (ScopePolicy, ScopeResolutionError, ScopeValidationError,
                            local_host_addresses, resolve_domain, validate_agent_endpoints, validate_request)
from src.core.transport import current_budget
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


def test_hosts_file_aliases_use_bounded_local_lookup_without_dns():
    hosts = b'192.0.2.5 primary fixture.example # fixture\n2001:db8::1 fixture.example\n'
    with patch('pathlib.Path.open', mock_open(read_data=hosts)), patch('dns.resolver.resolve') as dns:
        assert resolve_domain('fixture.example') == ['192.0.2.5', '2001:db8::1']
        dns.assert_not_called()


def test_hosts_file_complete_set_still_rejects_metadata():
    hosts = b'192.0.2.5 fixture.example\n169.254.169.254 fixture.example\n'
    with patch('pathlib.Path.open', mock_open(read_data=hosts)):
        with pytest.raises(ScopeValidationError, match='Forbidden'):
            ScopePolicy.from_config(config()).addresses('fixture.example')


@pytest.mark.parametrize('data', [b'x' * 65537,
                                b''.join(f'192.0.2.{index} fixture.example\n'.encode() for index in range(1, 34))])
def test_hosts_file_bounds_reject_incomplete_answer_sets(data):
    with patch('pathlib.Path.open', mock_open(read_data=data)):
        with pytest.raises(ScopeResolutionError):
            local_host_addresses('fixture.example')


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


def test_security_only_accepts_bounded_model_overrides():
    _, _, _, options = validate_request({"scan_type": "security_only", "scan_config": {
        "source_scan_id": "source", "model_overrides": {"asset": "fixture-model"},
    }}, config())
    assert options["model_overrides"] == {"asset": "fixture-model"}


@pytest.mark.parametrize("overrides", [[], {"asset": ""}, {"asset": {"endpoint": "https://other.example"}}])
def test_invalid_model_overrides_rejected(overrides):
    with pytest.raises(ScopeValidationError):
        validate_request({"scan_type": "security_only", "scan_config": {
            "source_scan_id": "source", "model_overrides": overrides,
        }}, config())


@pytest.mark.parametrize("scan_type", ["full", "discovery_only"])
def test_model_overrides_only_apply_to_saved_sources(scan_type):
    with pytest.raises(ScopeValidationError, match="only valid for security_only"):
        validate_request({"scan_type": scan_type, "scan_config": {"model_overrides": {}},
                          "target_scope": {"network_ranges": ["192.0.2.1/32"]}}, config())


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


def test_queue_limit_does_not_create_extra_scan(api, monkeypatch):
    module, client = api
    monkeypatch.setitem(module.app.config, "SCAN_MAX_QUEUED", 1)
    body = request_body(network_ranges=["192.0.2.1/32"])
    with patch.object(module.threading, "Thread") as thread:
        assert client.post("/api/scans", headers=headers(module), json=body).status_code == 202
        assert client.post("/api/scans", headers=headers(module), json=body).status_code == 429
        thread.assert_not_called()
    assert module.ScanSession.query.count() == module.ScanJob.query.count() == 1


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


def test_deadline_marks_failed_with_consistent_report(api, monkeypatch):
    module, _ = api
    module.db.session.add(module.ScanSession(id="deadline", organization_id="tenant-a", scan_name="x",
                          scan_type="discovery_only", target_scope={}, scan_config={}))
    module.db.session.commit()

    async def forever(*args):
        await asyncio.Event().wait()

    monkeypatch.setattr(module, "_execute_scan", forever)
    module._run_scan_in_thread("deadline", "discovery_only", {}, {"timeout_seconds": 0.01})
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, "deadline").status == "failed"
    assert module.db.session.get(module.ScanResult, "deadline").result["status"] == "failed"


@pytest.mark.parametrize("counter", ["failures", "rejections"])
def test_transport_failures_cannot_produce_clean_scan(api, monkeypatch, counter):
    module, _ = api
    module.db.session.add(module.ScanSession(id="transport", organization_id="tenant-a", scan_name="x",
                          scan_type="discovery_only", target_scope={}, scan_config={}))
    module.db.session.add(module.ScanJob(scan_id="transport", status="running"))
    module.db.session.commit()

    async def blocked(*args):
        budget = current_budget()
        assert budget.allowed_networks == ("192.0.2.0/24",)
        assert budget.allow_loopback is False
        setattr(budget, counter, 1)
        with module.app.app_context():
            scan = module.db.session.get(module.ScanSession, "transport")
            scan.status = "completed"
            module.db.session.commit()

    monkeypatch.setattr(module, "_execute_scan", blocked)
    module._run_scan_in_thread("transport", "discovery_only", {}, {})
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, "transport").status == "failed"


def test_loopback_opt_in_reaches_worker_transport(api, monkeypatch):
    module, _ = api
    monkeypatch.setitem(module.app.config, "SCAN_ALLOWED_NETWORKS", ("127.0.0.1/32",))
    monkeypatch.setitem(module.app.config, "SCAN_ALLOW_LOOPBACK", True)
    seen = []

    async def local_fixture(*args):
        budget = current_budget()
        budget.check_address("127.0.0.1")
        seen.append(budget.allow_loopback)

    monkeypatch.setattr(module, "_execute_scan", local_fixture)
    module._run_scan_in_thread("local", "discovery_only", {}, {})
    assert seen == [True]
