"""Orderly CLI interruption exports genuine tenant evidence from an unfinished check."""

import asyncio
import json

import click
import pytest

import scanner_cli
from src.core.risk_projection import project_report_risk
from tests.tenant_progress_fixture import (
    privacy_values, tenant_progress_target, unfinished_tenant_engine,
)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,ordinal,calls', [('subject', 2, 4), ('attack', 4, 5)])
@pytest.mark.parametrize('fmt', ['json', 'sarif'])
@pytest.mark.parametrize('interruption', ['deadline', 'cancel'])
async def test_cli_exports_acknowledged_tenant_receipt_before_check_return(
        tmp_path, monkeypatch, caplog, mode, ordinal, calls, fmt, interruption):
    output = tmp_path / ('tenant-progress.' + fmt)
    engine = unfinished_tenant_engine()
    monkeypatch.setattr(scanner_cli, 'SecurityTestEngine', lambda **kwargs: engine)
    with tenant_progress_target(mode) as (agent, state):
        task = asyncio.create_task(scanner_cli._execute(
            None, [agent], str(output), fmt, 'security_only', False,
            max_requests=8, max_response_bytes=16384,
            timeout_seconds=3 if interruption == 'deadline' else 15,
            request_timeout_seconds=10, allow_loopback=True))
        try:
            assert await asyncio.to_thread(state.stall.wait, 5), 'Tenant check did not reach its later request'
            if interruption == 'cancel':
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                with pytest.raises(click.ClickException, match='deadline exhausted'):
                    await task
            assert len(state.calls) == calls
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        encoded = output.read_text()
        assert all(value.casefold() not in (encoded + caplog.text).casefold() for value in privacy_values(state))
    assert output.stat().st_mode & 0o777 == 0o600
    document = json.loads(encoded)
    if fmt == 'json':
        assert document['status'] == ('failed' if interruption == 'deadline' else 'cancelled')
        assert document['checkpoint']['version'] == '3.0'
        assert document['check_evidence_schema_version'] == '2.0'
        assert document['summary']['checks_unfinished'] == 1
        assert document['summary']['checks_completed'] == 0
        asset = document['agents'][0]
        assert asset['security_status'] == asset['risk_coverage_status'] == 'partial'
        assert asset['risk_score'] == document['summary']['overall_risk_score'] == 90
        assert asset['risk_level'] == 'critical'
        assert len(asset['vulnerabilities']) == len(asset['check_evidence']) == 1
        receipt = asset['check_evidence'][0]
        assert receipt['finding_id'] == asset['vulnerabilities'][0]['id']
        assert not any(check['rule_id'] == receipt['rule_id'] for check in asset['checks'])
        summary, assets = project_report_risk(document)
        assert summary['overall_risk_score'] == assets[asset['id']]['risk_score'] == 90
        assert document['producer_identity']['component'] == 'cli'
    else:
        run = document['runs'][0]
        assert not run['invocations'][0]['executionSuccessful']
        assert run['properties']['checkpoint']['version'] == '3.0'
        assert run['properties']['check_evidence_schema_version'] == '2.0'
        assert run['properties']['summary']['overall_risk_score'] == 90
        assert run['properties']['summary']['checks_unfinished'] == 1
        assert run['properties']['summary']['checks_completed'] == 0
        assert len(run['results']) == len(run['properties']['check_evidence']) == 1
        ledger = run['properties']['check_evidence'][0]
        assert len(ledger['check_evidence']) == 1
        receipt = ledger['check_evidence'][0]
        assert receipt['finding_id'] == run['results'][0]['properties']['vulnerability_id']
        assert ledger['agent_id'] == run['results'][0]['properties']['agent_id']
        assert not any(check['rule_id'] == receipt['rule_id'] for check in run['properties']['checks'])
        assert run['properties']['producer_identity']['component'] == 'cli'
    assert receipt['source'] == 'controlled_tenant_response'
    assert receipt['request_ordinal'] == ordinal
    assert receipt['requests_attempted'] == receipt['responses_evaluated'] == (3 if mode == 'subject' else 4)
    assert receipt['control_proof'] == {'request_ordinals': [1, 2, 3], 'status_codes': [200, 200, 403]}
