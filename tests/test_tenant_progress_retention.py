"""Actual HTTPS tenant findings survive unfinished checks and later failures."""

import asyncio
from contextlib import suppress
from copy import deepcopy
import json

import pytest

from src.core.contracts import confirmed_findings, validate_checkpoint_report
from src.core.pipeline import run_pipeline, to_sarif
from src.core.risk_projection import project_report_risk
from src.core.transport import ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from tests.tenant_progress_fixture import privacy_values, tenant_progress_target, unfinished_tenant_engine


async def run(agent, engine, saved, budget):
    async def checkpoint(report):
        validate_checkpoint_report(report)
        saved.append(deepcopy(report))
    with scan_transport(budget):
        return await run_pipeline(None, engine, RiskAssessment(), None, 'security_only',
                                  agents=[agent], checkpoint_callback=checkpoint)


async def stalled(state, task):
    async def wait():
        while not state.stall.is_set():
            if task.done():
                await task
                raise AssertionError('Owned HTTPS target did not reach its expected stall')
            await asyncio.sleep(0.005)
    await asyncio.wait_for(wait(), 4)


def assert_prefix(saved, final=None):
    values = saved + ([final] if final is not None else [])
    for report in values:
        assert report['checkpoint']['version'] == '4.0'
        assert report['check_evidence_schema_version'] == '3.0'
        assert report['agents'][0]['check_evidence_schema_version'] == '3.0'
        assert report['producer_identity'] == values[0]['producer_identity']
    observed = [report for report in values if report['agents'][0]['check_evidence']]
    assert observed
    original = observed[0]['agents'][0]
    receipts = deepcopy(original['check_evidence'])
    findings = deepcopy(original['vulnerabilities'])
    assert len(receipts) == len(findings) == 1
    for report in observed:
        item = report['agents'][0]
        assert item['check_evidence'][:len(receipts)] == receipts
        assert [finding for finding in item['vulnerabilities'] if finding['id'] == findings[0]['id']] == findings
        assert report['security_results'][0]['check_evidence'] == item['check_evidence']
        assert report['producer_identity'] == observed[0]['producer_identity']
    return receipts, findings


def assert_partial_risk(report, state):
    item = report['agents'][0]
    assert report['status'] == 'partial'
    assert report['summary']['overall_risk_score'] == item['risk_score'] == 90
    assert item['risk_level'] == 'critical' and item['risk_coverage_status'] == 'partial'
    summary, projected = project_report_risk(report)
    assert summary['overall_risk_score'] == projected[item['id']]['risk_score'] == 90
    assert projected[item['id']]['risk_level'] == 'critical'
    assert json.loads(json.dumps(report, allow_nan=False)) == report
    sarif = to_sarif(report)['runs'][0]
    assert sarif['invocations'][0]['executionSuccessful'] is False
    assert sarif['properties']['summary']['overall_risk_score'] == 90
    assert sarif['properties']['check_evidence_schema_version'] == '3.0'
    assert sarif['properties']['check_evidence'][0]['check_evidence'] == item['check_evidence']
    assert len(sarif['results']) == len(item['vulnerabilities']) == 1
    assert sarif['results'][0]['level'] == 'error'
    rendered = json.dumps([report, sarif], ensure_ascii=False).casefold()
    assert all(value.casefold() not in rendered for value in privacy_values(state))


def budget():
    return ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True,
                      max_requests=8, max_response_bytes=65536, request_timeout_seconds=2)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,expected_requests,ordinal', [('subject', 4, 2), ('attack', 5, 4)])
@pytest.mark.parametrize('interruption', ['timeout', 'cancel'])
async def test_https_tenant_observation_survives_later_stall(mode, expected_requests, ordinal, interruption, caplog):
    with tenant_progress_target(mode) as (agent, state):
        saved, limits = [], budget()
        task = asyncio.create_task(run(agent, unfinished_tenant_engine(), saved, limits))
        try:
            await stalled(state, task)
            assert len(state.calls) == limits.requests == expected_requests
            receipts, findings = assert_prefix(saved)
            assert receipts[0]['request_ordinal'] == ordinal
            assert receipts[0]['control_proof'] == {'request_ordinals': [1, 2, 3], 'status_codes': [200, 200, 403]}
            assert findings[0]['check_evidence_id'] == receipts[0]['id']
            if interruption == 'timeout':
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(task, 0.03)
            else:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        report = saved[-1]
        assert report['summary']['checks_unfinished'] == 1
        assert not any(check['rule_id'] == 'tenant_isolation_violation' for check in report['agents'][0]['checks'])
        assert len(confirmed_findings({**report['agents'][0], 'status': 'partial', 'check_schema_version': '1.0'})) == 1
        assert_partial_risk(report, state)
        assert all(value.casefold() not in caplog.text.casefold() for value in privacy_values(state))


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,requests', [('subject_cleanup', 3), ('attack_cleanup', 8)])
async def test_https_acknowledged_receipt_survives_actual_cleanup_failure(mode, requests, caplog):
    with tenant_progress_target(mode) as (agent, state):
        saved, limits = [], budget()
        report = await run(agent, unfinished_tenant_engine(), saved, limits)
        receipts, _ = assert_prefix(saved, report)
        assert state.cleanup_failures == 1
        assert len(state.calls) == limits.requests == requests
        tenant = next(check for check in report['agents'][0]['checks'] if check['rule_id'] == 'tenant_isolation_violation')
        assert tenant['status'] == 'failed' and tenant['outcome'] == 'confirmed'
        assert report['summary']['checks_unfinished'] == 0
        assert report['agents'][0]['check_evidence'] == receipts
        assert_partial_risk(report, state)
        assert all(value.casefold() not in caplog.text.casefold() for value in privacy_values(state))


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,requests', [('later_failure', 8), ('later_taint', 5)])
async def test_https_later_failed_or_tainted_request_keeps_original_evidence(mode, requests, caplog):
    with tenant_progress_target(mode) as (agent, state):
        saved, limits = [], budget()
        report = await run(agent, unfinished_tenant_engine(), saved, limits)
        receipts, findings = assert_prefix(saved, report)
        assert receipts[0]['request_ordinal'] == 4
        assert report['agents'][0]['check_evidence'] == receipts
        assert report['agents'][0]['vulnerabilities'] == findings
        assert len(state.calls) == limits.requests == requests
        tenant = next(check for check in report['agents'][0]['checks'] if check['rule_id'] == 'tenant_isolation_violation')
        assert tenant['status'] == 'failed' and tenant['outcome'] == 'confirmed'
        assert tenant['requests_attempted'] == requests and tenant['responses_evaluated'] == 4
        if mode == 'later_taint':
            assert state.calls[-1]['reflection']
        assert_partial_risk(report, state)
        assert all(value.casefold() not in caplog.text.casefold() for value in privacy_values(state))
