"""Execution and persistence regressions without network access."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.core.pipeline import run_pipeline, to_sarif
from tests.test_api_auth import api as api_fixture, headers


@pytest.fixture
def api(monkeypatch):
    yield from api_fixture.__wrapped__(monkeypatch)


def asset(endpoint="https://example.test", asset_id="stable-asset"):
    return {"id": asset_id, "name": "fixture", "type": "assistant", "provider": "test",
            "endpoint": endpoint, "discovery_method": "fixture", "metadata": {}}


def engines(agents, status="completed"):
    finding = {"vulnerability_type": "fixture", "severity": "critical", "description": "Fixture evidence"}
    discovery = SimpleNamespace(discover_agents=AsyncMock(return_value=agents))
    security = SimpleNamespace(test_agents=AsyncMock(return_value=[{
        "agent_id": "stable-asset", "agent_name": "fixture", "status": status,
        "vulnerabilities": [finding] if status == "completed" else [],
    }]))
    risk = SimpleNamespace(assess_risks=AsyncMock(return_value=[{
        "agent_id": "stable-asset", "overall_risk_score": 90, "risk_level": "critical",
    }]))
    return discovery, security, risk


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,status,tested", [
    ("full", "completed", 1), ("full", "failed", 0), ("discovery_only", "not_tested", 0),
])
async def test_pipeline_preserves_test_state(mode, status, tested):
    discovery, security, risk = engines([asset()], status)
    result = await run_pipeline(discovery, security, risk, None, mode)
    assert result["agents"][0]["security_status"] == status
    assert result["summary"]["agents_tested"] == tested
    assert result["summary"]["overall_risk_score"] == (90 if tested else None)
    assert to_sarif(result)["runs"][0]["invocations"][0]["executionSuccessful"] == bool(tested)


@pytest.mark.asyncio
async def test_missing_endpoint_is_skipped():
    discovery, security, risk = engines([asset(None)])
    result = await run_pipeline(discovery, security, risk, None)
    security.test_agents.assert_not_called()
    risk.assess_risks.assert_not_called()
    assert result["summary"]["agents_skipped"] == 1
    assert result["agents"][0]["risk_level"] == "unknown"


@pytest.mark.asyncio
async def test_empty_and_failed_execution():
    discovery, security, risk = engines([])
    result = await run_pipeline(discovery, security, risk, None)
    assert result["agents"] == []
    assert result["summary"]["overall_risk_score"] is None
    discovery.discover_agents.return_value = [asset()]
    security.test_agents.side_effect = RuntimeError("secret upstream URL")
    result = await run_pipeline(discovery, security, risk, None)
    assert result["status"] == "partial"
    assert "secret" not in str(result)


@pytest.mark.asyncio
async def test_risk_failure_retains_findings():
    discovery, security, risk = engines([asset()])
    risk.assess_risks.side_effect = RuntimeError("assessment failed")
    result = await run_pipeline(discovery, security, risk, None)
    assert result["status"] == "partial"
    assert result["risk_assessment_status"] == "failed"
    assert result["summary"]["vulnerabilities_found"] == 1
    assert result["agents"][0]["risk_score"] is None


@pytest.mark.asyncio
async def test_partial_findings_and_secret_redaction():
    agent = asset()
    agent['system_prompt_canary'] = 'private-canary-value'
    agent['metadata'] = {'api_key': 'private-key-value', 'internet_facing': True}
    discovery, security, risk = engines([agent])
    security.test_agents.return_value[0]['status'] = 'partial'
    security.test_agents.return_value[0]['vulnerabilities'][0]['description'] = 'private-canary-value'
    result = await run_pipeline(discovery, security, risk, None)
    assert result['summary']['vulnerabilities_found'] == 1
    assert result['summary']['agents_partial'] == 1
    assert result['status'] == 'partial'
    assert 'private-canary-value' not in str(result)
    assert 'private-key-value' not in str(result)
    assert result['agents'][0]['metadata'] == {'internet_facing': True}
    assert not to_sarif(result)['runs'][0]['invocations'][0]['executionSuccessful']


def add_scan(module, scan_id, organization="tenant-a", mode="full"):
    module.db.session.add(module.ScanSession(id=scan_id, organization_id=organization,
                          scan_name=scan_id, scan_type=mode, target_scope={}, scan_config={}))
    module.db.session.commit()


@pytest.mark.asyncio
async def test_repeated_scan_persistence_and_report_authorization(api, monkeypatch):
    module, client = api
    discovery, security, risk = engines([asset()])
    monkeypatch.setattr(module, "discovery_engine", discovery)
    monkeypatch.setattr(module, "security_engine", security)
    monkeypatch.setattr(module, "risk_assessor", risk)
    for scan_id in ("first", "second"):
        add_scan(module, scan_id)
        await module._execute_scan(scan_id, "full", {}, {})
        module.db.session.expire_all()
        scan = module.db.session.get(module.ScanSession, scan_id)
        assert scan.status == "completed"
        assert scan.vulnerabilities_found == scan.critical_risks == 1
        assert scan.overall_risk_score == 90
    rows = module.DiscoveredAgentModel.query.all()
    assert len({row.id for row in rows}) == 2
    assert {row.metadata_json["asset_id"] for row in rows} == {"stable-asset"}
    response = client.get("/api/scans/first/report?format=sarif", headers=headers(module))
    assert response.status_code == 200
    assert len(response.json["runs"][0]["results"]) == 1
    assert client.get("/api/scans/first/report", headers=headers(module, "tenant-b")).status_code == 404


@pytest.mark.asyncio
async def test_security_only_reuses_owned_source(api, monkeypatch):
    module, _ = api
    discovery, security, risk = engines([asset()])
    monkeypatch.setattr(module, "discovery_engine", discovery)
    monkeypatch.setattr(module, "security_engine", security)
    monkeypatch.setattr(module, "risk_assessor", risk)
    add_scan(module, "source")
    await module._execute_scan("source", "discovery_only", {}, {})
    discovery.discover_agents.reset_mock()
    for scan_id, tenant in (("owned", "tenant-a"), ("foreign", "tenant-b")):
        add_scan(module, scan_id, tenant, "security_only")
        await module._execute_scan(scan_id, "security_only", {}, {"source_scan_id": "source"})
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, "owned").status == "completed"
    assert module.db.session.get(module.ScanSession, "foreign").status == "failed"
    discovery.discover_agents.assert_not_called()
