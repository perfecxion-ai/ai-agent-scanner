"""Actual verified HTTPS access observations survive real CLI interruptions."""

import asyncio
from copy import deepcopy
import json

import click
import pytest

import scanner_cli
from src.core.build_identity import saved_identity
from src.core.contracts import validate_checkpoint_report
from src.core.risk_projection import project_report_risk
from tests.access_progress_independent_fixture import (
    ISSUED, METHODS, access_progress_target, privacy_values, selected_access_engine,
)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('mode', ['protected', 'complete', 'later_503', 'deadline', 'cancel'])
@pytest.mark.parametrize('fmt', ['json', 'sarif'])
async def test_real_https_cli_access_progress_before_later_interruption(
        tmp_path, monkeypatch, capsys, caplog, rule, mode, fmt):
    engine = selected_access_engine(rule)
    monkeypatch.setattr(scanner_cli, 'SecurityTestEngine', lambda: engine)
    checkpoints, final_reports = [], []
    original = scanner_cli.run_pipeline

    async def tracked_pipeline(*args, **kwargs):
        actual = kwargs['checkpoint_callback']
        async def retain(report):
            validate_checkpoint_report(report)
            checkpoints.append(deepcopy(report))
            await actual(report)
        kwargs['checkpoint_callback'] = retain
        report = await original(*args, **kwargs)
        final_reports.append(deepcopy(report))
        return report

    monkeypatch.setattr(scanner_cli, 'run_pipeline', tracked_pipeline)
    output = tmp_path / ('access-progress.' + fmt)
    with access_progress_target(rule, mode) as (agent, state):
        task = asyncio.create_task(scanner_cli._execute(
            None, [agent], str(output), fmt, 'security_only', False,
            max_requests=80, max_response_bytes=16384, timeout_seconds=1 if mode == 'deadline' else 10,
            request_timeout_seconds=5, allow_loopback=True))
        try:
            if mode in {'cancel', 'deadline'}:
                assert await asyncio.to_thread(state.blocked.wait, 5)
                acknowledged = [report for report in checkpoints if report['agents'][0].get('check_evidence')]
                assert acknowledged, 'No receipt was published before the next request began'
                assert not any(check['rule_id'] == rule for check in acknowledged[-1]['agents'][0]['checks'])
                assert acknowledged[-1]['summary']['checks_unfinished'] == 1
                if mode == 'cancel':
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                else:
                    with pytest.raises(click.ClickException, match='deadline exhausted') as failure:
                        await task
                    assert failure.value.exit_code == 1
            elif mode == 'later_503':
                with pytest.raises(click.ClickException, match='No security checks completed') as failure:
                    await task
                assert failure.value.exit_code == 1
            else:
                assert await task is None
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        assert not state.errors
        assert all(call['tls'] in {'TLSv1.2', 'TLSv1.3'} for call in state.calls)
        assert state.calls[0]['credential'] == ISSUED
        assert state.calls[1]['credential'].startswith('scanner-invalid-')
        assert state.directory.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in state.directory.iterdir())
        private = privacy_values(state)

    document = json.loads(output.read_text())
    assert output.stat().st_mode & 0o777 == 0o600
    score = 0 if mode == 'protected' else 90 if rule == 'weak_credentials' else 70
    partial = mode in {'later_503', 'deadline', 'cancel'}
    expected_status = {'deadline': 'failed', 'cancel': 'cancelled', 'later_503': 'partial'}.get(mode, 'completed')
    if fmt == 'json':
        report = document
    elif final_reports:
        report = final_reports[0]
    else:
        report = deepcopy(checkpoints[-1])
        report['status'] = expected_status
    assert report['status'] == expected_status
    assert report['check_evidence_schema_version'] == '3.0' and report['checkpoint']['version'] == '4.0'
    asset = report['agents'][0]
    assert report['summary']['overall_risk_score'] == asset['risk_score'] == score
    assert type(asset['risk_score']) in (int, float)
    assert asset['risk_level'] == ('minimal' if not score else 'critical' if score == 90 else 'high')
    assert asset['risk_coverage_status'] == ('partial' if partial else 'sampled')
    assert project_report_risk(report)[0]['overall_risk_score'] == score
    identity = report['producer_identity']
    assert saved_identity(identity) == identity and identity['component'] == 'cli'
    assert all(item['producer_identity'] == identity for item in checkpoints)
    receipts, findings = asset['check_evidence'], asset['vulnerabilities']
    assert len(receipts) == len(findings) == (0 if mode == 'protected' else 1)
    if receipts:
        receipt, finding = receipts[0], findings[0]
        assert receipt['source'] == 'controlled_access_response' and receipt['source_version'] == '1.0'
        assert receipt['request_ordinal'] == receipt['requests_attempted'] == receipt['responses_evaluated'] == 3
        assert receipt['sequence'] == 1 and receipt['run_id'] == asset['check_evidence_run_id']
        assert receipt['finding_id'] == finding['id'] and receipt['id'] == finding['check_evidence_id']
        assert receipt['agent_id'] == asset['id'] and receipt['rule_id'] == finding['rule_id'] == rule
        assert receipt['control_proof'] == {'request_ordinals': [1, 2], 'status_codes': [200, 403]}
        target = receipt['access_target']
        assert target['endpoint'] == agent['endpoint']
        assert target['provider'] == agent['provider'] and target['model'] == agent['model']
        assert target['evidence_context_id'] == agent['evidence_context_id']
        assert finding['protected_control_version'] == 3
        if rule == 'authorization_bypass':
            assert receipt['protected_path_index'] == 0
        else:
            assert receipt['sample_index'] == 0
            if rule == 'weak_api_key':
                assert receipt['header_index'] == 0
    if mode in {'deadline', 'cancel'}:
        assert not any(check['rule_id'] == rule for check in asset['checks'])
        assert report['summary']['checks_unfinished'] == 1
    else:
        current = next(check for check in asset['checks'] if check['rule_id'] == rule)
        assert current['outcome'] == ('passed' if mode == 'protected' else 'confirmed')
        assert current['status'] == ('failed' if mode == 'later_503' else 'completed')
    if fmt == 'sarif':
        run = document['runs'][0]
        assert run['properties']['summary']['overall_risk_score'] == score
        assert run['properties']['producer_identity'] == identity
        assert run['invocations'][0]['executionSuccessful'] is (not partial)
        assert run['properties']['check_evidence_schema_version'] == '3.0'
        assert run['properties']['check_evidence'][0]['check_evidence'] == receipts
        assert {item['properties']['vulnerability_id'] for item in run['results']} == {
            finding['id'] for finding in findings}
    captured = capsys.readouterr()
    public = output.read_text() + json.dumps(checkpoints) + captured.out + captured.err + caplog.text
    assert all(value not in public for value in private)
