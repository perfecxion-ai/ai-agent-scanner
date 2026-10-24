"""Real prompt disclosure survives orderly CLI interruption before category return."""

import asyncio
import json

import click
import pytest

import scanner_cli
from src.core.risk_projection import project_report_risk
from src.security.prompt_suites import PROTECTED_DISCLOSURE_SUITE
from tests.prompt_progress_fixture import CANARY, disclosure_target, unfinished_prompt_engine


@pytest.mark.asyncio
@pytest.mark.parametrize('fmt', ['json', 'sarif'])
@pytest.mark.parametrize('suite', [None, PROTECTED_DISCLOSURE_SUITE])
@pytest.mark.parametrize('interruption', ['deadline', 'cancel'])
async def test_cli_retains_actual_disclosure_inside_unfinished_category(
        tmp_path, monkeypatch, fmt, suite, interruption, caplog):
    ready = asyncio.Event()
    security = unfinished_prompt_engine(ready.set, prompt_suite=suite)
    monkeypatch.setattr(scanner_cli, 'SecurityTestEngine', lambda **kwargs: security)
    output = tmp_path / ('unfinished.' + fmt)
    with disclosure_target() as (agent, calls):
        task = asyncio.create_task(scanner_cli._execute(
            None, [agent], str(output), fmt, 'security_only', False,
            max_requests=5, timeout_seconds=1 if interruption == 'deadline' else 10,
            allow_loopback=True, prompt_suite=suite))
        try:
            if interruption == 'cancel':
                await asyncio.wait_for(ready.wait(), timeout=5)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                with pytest.raises(click.ClickException, match='deadline exhausted'):
                    await task
            assert len(calls) == 1
            assert CANARY not in json.dumps(calls)
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    encoded = output.read_text()
    assert CANARY not in encoded + caplog.text
    assert output.stat().st_mode & 0o777 == 0o600
    document = json.loads(encoded)
    if fmt == 'json':
        assert document['status'] == ('failed' if interruption == 'deadline' else 'cancelled')
        assert document['summary']['overall_risk_score'] == 70
        assert document['summary']['checks_unfinished'] == 1
        assert document['summary']['checks_completed'] == 0
        asset = document['agents'][0]
        assert asset['security_status'] == 'partial'
        assert asset['risk_coverage_status'] == 'partial'
        assert len(asset['vulnerabilities']) == len(asset['check_evidence']) == 1
        receipt = asset['check_evidence'][0]
        assert receipt['finding_id'] == asset['vulnerabilities'][0]['id']
        assert receipt['requests_attempted'] == receipt['responses_evaluated'] == 1
        assert not any(check['rule_id'] == receipt['rule_id'] for check in asset['checks'])
        summary, assets = project_report_risk(document)
        assert summary['overall_risk_score'] == assets[asset['id']]['risk_score'] == 70
    else:
        run = document['runs'][0]
        assert not run['invocations'][0]['executionSuccessful']
        assert len(run['results']) == 1
        assert run['properties']['summary']['overall_risk_score'] == 70
        assert run['properties']['summary']['checks_unfinished'] == 1
        assert run['properties']['check_evidence_schema_version'] == '2.0'
        assert len(run['properties']['check_evidence']) == 1
        ledger = run['properties']['check_evidence'][0]
        assert len(ledger['check_evidence']) == 1
        receipt = ledger['check_evidence'][0]
        assert receipt['finding_id'] == run['results'][0]['properties']['vulnerability_id']
        assert ledger['agent_id'] == run['results'][0]['properties']['agent_id']
        assert receipt['requests_attempted'] == receipt['responses_evaluated'] == 1
        assert not any(check['rule_id'] == receipt['rule_id'] for check in run['properties']['checks'])
