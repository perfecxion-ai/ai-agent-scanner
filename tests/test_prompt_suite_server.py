"""Opt-in prompt suites stay pinned, private, and isolated across server jobs."""

from tests.claimed_execution import execute_scan, execute_job

import asyncio
from copy import deepcopy
import json
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.core.evidence_profiles import EvidenceProfiles, PIN_FIELD as PROFILE_PIN
from src.core.scope import ScopeValidationError, validate_request
from src.core.transport import ScanBudget, scan_transport
from src.security.prompt_suites import (
    PIN_FIELD, PROTECTED_DISCLOSURE_SUITE, candidate_payloads, prompt_suite_pin,
)
from tests.test_api_auth import api as api, headers
from tests.test_evidence_profiles import CANARY, ENV, document, registry
from tests.test_pipeline import add_scan, asset


SOURCE = "suite-source"


def body():
    return {"scan_type": "security_only", "scan_config": {
        "source_scan_id": SOURCE, "model_overrides": {"stable-asset": "fixture-model"},
        "evidence_profiles": {"stable-asset": "fixture-v1"},
        "prompt_suite": PROTECTED_DISCLOSURE_SUITE}}


async def source(module, monkeypatch, extra=None):
    agents = [{**asset(), "provider": "openai-compatible", "model": None}]
    if extra:
        agents.append(extra)
    monkeypatch.setattr(module, "discovery_engine", SimpleNamespace(
        discover_agents=AsyncMock(return_value=agents)))
    add_scan(module, SOURCE, mode="discovery_only")
    with scan_transport(ScanBudget()):
        await execute_scan(module, SOURCE, "discovery_only", {}, {})
    module.db.session.expire_all()
    monkeypatch.setattr(module, "_evidence_profiles", registry(monkeypatch))
    return deepcopy(module.db.session.get(module.ScanResult, SOURCE).result)


@pytest.mark.parametrize("value", [None, True, 1, [], {}, "", "default", "baseline", CANARY,
                                   "PROTECTED-DISCLOSURE-V1"])
def test_invalid_suite_is_static_before_source_or_profile_lookup(api, monkeypatch, value):
    module, client = api
    protected = Mock()
    monkeypatch.setattr(module, "_evidence_profiles", protected)
    definition = body()
    definition["scan_config"]["prompt_suite"] = value
    response = client.post("/api/scans", headers=headers(module), json=definition)
    assert response.status_code == 400
    assert CANARY not in response.get_data(as_text=True) and ENV not in response.get_data(as_text=True)
    assert module.ScanJob.query.filter(module.ScanJob.scan_id != SOURCE).count() == module.ScanSession.query.count() == 0
    assert protected.mock_calls == []


@pytest.mark.parametrize("mutation", ["top_suite", "top_pin", "nested_pin", "full", "discovery", "no_refs", "empty_refs"])
def test_rejected_selection_never_resolves_targets(api, monkeypatch, mutation):
    module, client = api
    definition = body()
    if mutation == "top_suite":
        definition["prompt_suite"] = definition["scan_config"].pop("prompt_suite")
    elif mutation == "top_pin":
        definition[PIN_FIELD] = CANARY
    elif mutation == "nested_pin":
        definition["scan_config"][PIN_FIELD] = CANARY
    elif mutation in ("full", "discovery"):
        definition["scan_type"] = "full" if mutation == "full" else "discovery_only"
        definition["target_scope"] = {"domains": ["never-resolve.invalid"]}
    elif mutation == "no_refs":
        del definition["scan_config"]["evidence_profiles"]
    else:
        definition["scan_config"]["evidence_profiles"] = {}
    forbidden = Mock(side_effect=AssertionError("DNS must not run"))
    monkeypatch.setattr("src.core.scope.ScopePolicy.addresses", forbidden)
    response = client.post("/api/scans", headers=headers(module), json=definition)
    assert response.status_code == 400 and module.ScanJob.query.filter(module.ScanJob.scan_id != SOURCE).count() == 0
    forbidden.assert_not_called()
    assert CANARY not in response.get_data(as_text=True)


def test_omission_preserves_legacy_options():
    definition = {"scan_type": "security_only", "scan_config": {"source_scan_id": SOURCE}}
    _, _, _, options = validate_request(definition, {"SCAN_TIMEOUT_SECONDS": 300})
    assert options == {"source_scan_id": SOURCE, "timeout_seconds": 300}


@pytest.mark.asyncio
async def test_supported_admission_canonicalizes_pins_without_persisting_markers(api, monkeypatch):
    module, client = api
    original = await source(module, monkeypatch)
    selected = body()
    snapshot = module.DiscoveredAgentModel.query.one()
    selected["scan_config"]["model_overrides"] = {snapshot.id: "fixture-model"}
    selected["scan_config"]["evidence_profiles"] = {snapshot.id: "fixture-v1"}
    response = client.post("/api/scans", headers=headers(module), json=selected)
    assert response.status_code == 202, response.json
    queued = module.db.session.get(module.ScanSession, response.json["scan_id"])
    assert queued.scan_config[PIN_FIELD] == prompt_suite_pin()
    assert queued.scan_config[PROFILE_PIN]
    assert queued.scan_config["evidence_profiles"] == {"stable-asset": "fixture-v1"}
    assert module.db.session.get(module.ScanResult, SOURCE).result == original
    stored = json.dumps(queued.scan_config)
    assert CANARY not in stored and ENV not in stored and "system_prompt_canary" not in stored


@pytest.mark.asyncio
async def test_catalog_change_between_validation_and_queue_cannot_admit(api, monkeypatch):
    module, client = api
    await source(module, monkeypatch)
    prepare = module._prepare_scan

    def drift(*args, **kwargs):
        definition = prepare(*args, **kwargs)
        monkeypatch.setattr(module, "prompt_suite_pin", lambda: "0" * 64)
        return definition

    monkeypatch.setattr(module, "_prepare_scan", drift)
    response = client.post("/api/scans", headers=headers(module), json=body())
    assert response.status_code == 400 and module.ScanJob.query.filter(module.ScanJob.scan_id != SOURCE).count() == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("testable", [False, True])
async def test_every_effective_testable_asset_needs_selected_evidence(api, monkeypatch, testable):
    module, client = api
    extra = {**asset(asset_id="other"), "provider": "openai-compatible",
             "model": "other-model" if testable else None}
    await source(module, monkeypatch, extra)
    response = client.post("/api/scans", headers=headers(module), json=body())
    assert response.status_code == (400 if testable else 202), response.json
    assert module.ScanJob.query.filter(module.ScanJob.scan_id != SOURCE).count() == (0 if testable else 1)


@pytest.mark.asyncio
async def test_historical_source_canary_cannot_replace_an_explicit_profile(api, monkeypatch):
    module, client = api
    extra = {**asset(asset_id="other"), "provider": "openai-compatible", "model": "other-model"}
    await source(module, monkeypatch, extra)
    previous = module.db.session.get(module.ScanResult, SOURCE)
    historical = deepcopy(previous.result)
    historical["agents"][1].update(system_prompt_canary="synthetic-unconfigured-canary-f290d7",
                                    evidence_context_id="unconfigured-context-v1")
    previous.result = historical
    module.db.session.commit()
    response = client.post("/api/scans", headers=headers(module), json=body())
    assert response.status_code == 400 and module.ScanJob.query.filter(module.ScanJob.scan_id != SOURCE).count() == 0
    assert module.db.session.get(module.ScanResult, SOURCE).result == historical


@pytest.mark.asyncio
@pytest.mark.parametrize("worker", [False, True])
async def test_historical_skipped_marker_keeps_redaction_provenance_by_refusal(api, monkeypatch, caplog, worker):
    module, client = api
    extra = {**asset(asset_id="skipped"), "provider": "unsupported-fixture", "model": "other-model"}
    await source(module, monkeypatch, extra)
    queued = None
    if worker:
        response = client.post("/api/scans", headers=headers(module), json=body())
        assert response.status_code == 202, response.json
        queued = module.db.session.get(module.ScanSession, response.json["scan_id"])
    previous = module.db.session.get(module.ScanResult, SOURCE)
    historical = deepcopy(previous.result)
    marker = "synthetic-skipped-private-canary-91bc86"
    historical["agents"][1].update(name=marker, system_prompt_canary=marker,
                                    evidence_context_id="historical-public-context-v1")
    previous.result = historical
    module.db.session.commit()
    pipeline = AsyncMock(side_effect=AssertionError("No candidate request may start"))
    monkeypatch.setattr(module, "run_pipeline", pipeline)
    if worker:
        await execute_scan(module, queued.id, queued.scan_type, {}, queued.scan_config)
        module.db.session.expire_all()
        assert module.db.session.get(module.ScanSession, queued.id).status == "failed"
        failed = module.db.session.get(module.ScanResult, queued.id).result
        assert not failed.get("agents") and marker not in json.dumps(failed)
    else:
        response = client.post("/api/scans", headers=headers(module), json=body())
        assert response.status_code == 400 and module.ScanJob.query.filter(module.ScanJob.scan_id != SOURCE).count() == 0
        assert marker not in response.get_data(as_text=True)
    pipeline.assert_not_called()
    assert marker not in caplog.text
    assert module.db.session.get(module.ScanResult, SOURCE).result == historical


@pytest.mark.asyncio
@pytest.mark.parametrize("marker", [PROTECTED_DISCLOSURE_SUITE, prompt_suite_pin()[:16], "_prompt_suite_pin"])
async def test_public_suite_identity_collisions_never_persist(api, monkeypatch, marker):
    module, client = api
    await source(module, monkeypatch)
    monkeypatch.setenv(ENV, marker)
    monkeypatch.setattr(module, "_evidence_profiles", EvidenceProfiles.from_document(document()))
    response = client.post("/api/scans", headers=headers(module), json=body())
    assert response.status_code == 400 and module.ScanJob.query.filter(module.ScanJob.scan_id != SOURCE).count() == 0
    assert marker not in response.json["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["pin_missing", "pin_changed", "suite_removed", "catalog_changed", "profile_removed", "marker_removed"])
async def test_queued_jobs_fail_closed_before_execution(api, monkeypatch, mutation):
    module, client = api
    await source(module, monkeypatch)
    response = client.post("/api/scans", headers=headers(module), json=body())
    queued = module.db.session.get(module.ScanSession, response.json["scan_id"])
    options = deepcopy(queued.scan_config)
    if mutation == "pin_missing":
        del options[PIN_FIELD]
    elif mutation == "pin_changed":
        options[PIN_FIELD] = "0" * 64
    elif mutation == "suite_removed":
        del options["prompt_suite"]
    elif mutation == "catalog_changed":
        monkeypatch.setattr(module, "prompt_suite_pin", lambda: "0" * 64)
    elif mutation == "profile_removed":
        monkeypatch.setattr(module, "_evidence_profiles", EvidenceProfiles())
    else:
        monkeypatch.delenv(ENV)
    queued.scan_config = options
    module.db.session.commit()
    execute = Mock()
    monkeypatch.setattr(module, "_run_scan_in_thread", execute)
    with pytest.raises(ScopeValidationError):
        execute_job(module, queued.id, None)
    execute.assert_not_called()


@pytest.mark.asyncio
async def test_template_updates_keep_hidden_pin_and_reject_drift(api, monkeypatch):
    module, client = api
    await source(module, monkeypatch)
    response = client.post("/api/templates", headers=headers(module), json=body())
    assert response.status_code == 201, response.json
    template = response.json["template"]
    assert PIN_FIELD not in template["scan_config"]
    assert PROFILE_PIN not in template["scan_config"]
    row = module.db.session.get(module.ScanTemplate, template["id"])
    pin = row.scan_config[PIN_FIELD]
    update = {key: template[key] for key in ("scan_name", "scan_type", "target_scope", "scan_config", "revision")}
    update["scan_name"] = "Edited display name"
    changed = client.put(f"/api/templates/{row.id}", headers=headers(module), json=update)
    assert changed.status_code == 200, changed.json
    module.db.session.expire_all()
    row = module.db.session.get(module.ScanTemplate, row.id)
    assert row.scan_config[PIN_FIELD] == pin
    monkeypatch.setattr(module, "prompt_suite_pin", lambda: "0" * 64)
    update["revision"] = row.revision
    assert client.put(f"/api/templates/{row.id}", headers=headers(module), json=update).status_code == 400
    assert client.post(f"/api/templates/{row.id}/run", headers=headers(module), json={}).status_code == 400
    assert module.ScanJob.query.filter(module.ScanJob.scan_id != SOURCE).count() == 0


@pytest.mark.asyncio
async def test_template_update_cannot_submit_hidden_pin(api, monkeypatch):
    module, client = api
    await source(module, monkeypatch)
    template = client.post("/api/templates", headers=headers(module), json=body()).json["template"]
    update = {key: template[key] for key in ("scan_name", "scan_type", "target_scope", "scan_config", "revision")}
    update["scan_config"][PIN_FIELD] = CANARY
    response = client.put(f"/api/templates/{template['id']}", headers=headers(module), json=update)
    assert response.status_code == 400 and CANARY not in response.json["error"]
    assert module.db.session.get(module.ScanTemplate, template["id"]).revision == template["revision"]


@pytest.mark.asyncio
async def test_schedule_catalog_race_pauses_without_admitting(api, monkeypatch):
    module, client = api
    await source(module, monkeypatch)
    created = client.post("/api/templates", headers=headers(module), json=body()).json["template"]
    response = client.post("/api/schedules", headers=headers(module), json={
        "template_id": created["id"], "template_revision": created["revision"],
        "interval_seconds": 60, "total_runs": 1})
    assert response.status_code == 201, response.json
    schedule = response.json["schedule"]
    assert client.post(f"/api/schedules/{schedule['id']}/enable", headers=headers(module),
                       json={"revision": schedule["revision"]}).status_code == 200
    from tests.test_scan_schedules import due
    due(module, schedule["id"])
    candidate = module._schedule_candidate()
    validated = module._schedule_preflight(candidate)
    assert "error" not in validated
    monkeypatch.setattr(module, "prompt_suite_pin", lambda: "0" * 64)
    assert module._schedule_preflight(candidate) == {"error": "policy_review"}
    module._schedule_admit(candidate, validated, threading.Event())
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSchedule, schedule["id"]).state == "paused"
    assert module.ScanJob.query.filter(module.ScanJob.scan_id != SOURCE).count() == 0


@pytest.mark.asyncio
async def test_concurrent_candidate_and_baseline_keep_global_engine_unchanged(api, monkeypatch):
    module, client = api
    original = await source(module, monkeypatch)
    baseline_engine = module.security_engine
    baseline_catalog = deepcopy(baseline_engine.prompt_tester.injection_payloads)
    candidate_response = client.post("/api/scans", headers=headers(module), json=body())
    baseline = body()
    del baseline["scan_config"]["prompt_suite"]
    baseline_response = client.post("/api/scans", headers=headers(module), json=baseline)
    assert candidate_response.status_code == baseline_response.status_code == 202
    seen, barrier = [], asyncio.Event()

    async def pipeline(discovery, security, risk, scope, scan_type, **kwargs):
        seen.append(security)
        if len(seen) == 2:
            barrier.set()
        await asyncio.wait_for(barrier.wait(), timeout=2)
        return deepcopy(original)

    monkeypatch.setattr(module, "run_pipeline", pipeline)
    jobs = [module.db.session.get(module.ScanSession, response.json["scan_id"])
            for response in (candidate_response, baseline_response)]
    await asyncio.gather(*(execute_scan(module, job.id, job.scan_type, {}, job.scan_config) for job in jobs))
    assert len(seen) == 2 and seen[0] is not baseline_engine and seen[1] is baseline_engine
    assert seen[0].prompt_tester.injection_payloads == candidate_payloads()
    assert module.security_engine is baseline_engine
    assert baseline_engine.prompt_tester.injection_payloads == baseline_catalog
    assert module.db.session.get(module.ScanResult, SOURCE).result == original
