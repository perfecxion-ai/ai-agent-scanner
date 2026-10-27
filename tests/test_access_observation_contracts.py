"""Actual GET receipts, frozen compatibility and bounded public evidence rules."""

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import asyncio

from aiohttp import web
import pytest

from src.core.access_evidence import access_evidence_context
from src.core.access_observation_policy import ACCESS_CAPS
from src.core.access_probe_policy import PROTECTED_ACCESS_PATHS, protected_access_probe
from src.core.contracts import (
    AccessObservation, CheckpointError, collect_checks, collect_evidence, confirmed_findings,
    observe_access_response, preserves_observation_eligibility, risk_assessment_eligible,
    validate_check_evidence, validate_checkpoint_report,
)
from src.core.transport import ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security import access_control_tests as producer
from src.security.access_control_tests import AccessControlTester


MARKER = 'core-access-observation-record-482917'
ISSUED = 'core-access-observation-issued-key-623941'
REFERENCE = 'ACCESS_OBSERVATION_CORE_FIXTURE_KEY'
METHODS = {'authentication_bypass': '_test_authentication_bypass', 'weak_credentials': '_test_weak_credentials',
           'weak_api_key': '_test_api_key_security', 'authorization_bypass': '_test_authorization_bypass'}


@pytest.fixture
async def resource(monkeypatch):
    monkeypatch.setenv('SCAN_EVIDENCE_PROFILES_FILE', '/tmp/aiscan-operator-registry-must-not-exist.json')
    monkeypatch.setenv(REFERENCE, ISSUED)
    monkeypatch.setattr(producer, 'asyncio', SimpleNamespace(sleep=AsyncMock(), CancelledError=asyncio.CancelledError))
    state = SimpleNamespace(mode='vulnerable', calls=[])

    async def handler(request):
        state.calls.append(request.path)
        credential = next((value for key, value in request.headers.items() if key.casefold() in {
            'authorization', 'x-api-key', 'x-goog-api-key', 'api-key', 'apikey'}), '')
        if credential == 'Bearer ' + ISSUED:
            return web.Response(text=MARKER)
        if 'scanner-invalid-' in credential:
            return web.Response(status=403, text='Denied')
        return web.Response(text=MARKER) if state.mode == 'vulnerable' else web.Response(status=403, text='Denied')

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    agent = dict(id='access-core', name='Core access fixture', provider='openai-compatible', model='fixture',
                 endpoint=f'http://127.0.0.1:{port}/resource', authentication_required=True,
                 api_key_env=REFERENCE, protected_response_marker=MARKER,
                 protected_path_markers={path: MARKER for path in PROTECTED_ACCESS_PATHS},
                 evidence_context_id='access-core-v1', metadata={})
    try:
        yield agent, state
    finally:
        await runner.cleanup()


async def execute(agent, rule='authentication_bypass', *, schema='3.0', observer=None):
    tester, findings = AccessControlTester(), []
    with scan_transport(ScanBudget(allow_loopback=True, allowed_networks=('127.0.0.1/32',), max_requests=126)), \
            access_evidence_context([agent]), collect_evidence(agent, observer, schema_version=schema) as evidence, \
            collect_checks() as checks:
        for selected in METHODS if rule == 'all' else [rule]:
            findings.extend(await getattr(tester, METHODS[selected])(agent))
    return dict(agent, agent_id=agent['id'], status='partial' if any(item['status'] == 'failed' for item in checks) else 'completed',
                check_schema_version='1.0', check_evidence_schema_version=schema, check_evidence_run_id=evidence.run_id,
                check_evidence=deepcopy(evidence.receipts), vulnerabilities=findings, checks=checks)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
async def test_actual_receipts_and_full_sample_counts(resource, rule):
    agent, state = resource
    result = await execute(agent, rule)
    receipts = result['check_evidence']
    assert len(receipts) == ACCESS_CAPS[rule]
    assert result['checks'][0]['requests_attempted'] == len(state.calls)
    assert result['checks'][0]['responses_evaluated'] == len(state.calls)
    assert [item['sequence'] for item in receipts] == list(range(1, len(receipts) + 1))
    assert receipts[0]['request_ordinal'] == receipts[0]['responses_evaluated'] == 3
    assert receipts[0]['control_proof'] == {'request_ordinals': [1, 2], 'status_codes': [200, 403]}
    assert all(item['access_target']['endpoint'] == agent['endpoint'] for item in receipts)
    assert risk_assessment_eligible(result)
    assert len(confirmed_findings(result)) == len(receipts)
    assert (await RiskAssessment()._assess_agent_risk(result))['overall_risk_score'] == (90 if rule == 'weak_credentials' else 70)
    assert all(value not in json.dumps(receipts) for value in (MARKER, ISSUED, REFERENCE))


@pytest.mark.asyncio
async def test_all_four_groups_have_thirty_six_receipts_from_fifty_eight_requests(resource):
    agent, state = resource
    result = await execute(agent, 'all')
    assert len(result['check_evidence']) == len(result['vulnerabilities']) == 36
    assert len(state.calls) == 58 and risk_assessment_eligible(result)
    assert {rule: sum(item['rule_id'] == rule for item in result['check_evidence']) for rule in METHODS} == ACCESS_CAPS


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('mode', ['protected', 'vulnerable'])
async def test_supported_native_none_context_and_genuine_zero(resource, rule, mode):
    agent, state = resource
    agent['model'] = agent['evidence_context_id'] = None
    state.mode = mode
    result = await execute(agent, rule)
    assert risk_assessment_eligible(result)
    expected = 0 if mode == 'protected' else 90 if rule == 'weak_credentials' else 70
    assert (await RiskAssessment()._assess_agent_risk(result))['overall_risk_score'] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize('schema', ['1.0', '2.0'])
async def test_explicit_frozen_collector_keeps_finalized_v3_semantics(resource, schema):
    agent, _ = resource
    result = await execute(agent, schema=schema)
    original = json.dumps(result, sort_keys=True)
    assert result['check_evidence'] == [] and len(result['vulnerabilities']) == 18
    assert not protected_access_probe(result['checks'][0], provider=agent['provider'], model=agent['model']).requires_receipt
    assert risk_assessment_eligible(result)
    assert (await RiskAssessment()._assess_agent_risk(result))['overall_risk_score'] == 70
    assert json.dumps(result, sort_keys=True) == original


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['protected', 'vulnerable'])
@pytest.mark.parametrize('envelope', ['missing', 'legacy1', 'legacy2'])
async def test_modern_hash_cannot_gain_finalized_fallback_after_envelope_removal(resource, mode, envelope):
    agent, state = resource
    state.mode = mode
    result = await execute(agent)
    assert protected_access_probe(result['checks'][0], provider=agent['provider'], model=agent['model']).requires_receipt
    for field in ('check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence'):
        result.pop(field)
    for finding in result['vulnerabilities']:
        finding.pop('check_evidence_id')
    if envelope != 'missing':
        result.update(check_evidence_schema_version='1.0' if envelope == 'legacy1' else '2.0', check_evidence=[])
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['bool-counter', 'float-counter', 'duplicate-id', 'duplicate-finding', 'wrong-run',
                                     'wrong-agent', 'wrong-source', 'wrong-version', 'extra-field', 'wrong-target',
                                     'bad-proof-order', 'bool-status', 'wrong-sample', 'missing-link', 'missing-receipt'])
async def test_complete_ledger_rejects_mutated_receipt_links_and_proofs(resource, mutation):
    agent, _ = resource
    result = await execute(agent)
    receipt, finding = result['check_evidence'][0], result['vulnerabilities'][0]
    if mutation == 'bool-counter':
        receipt['request_ordinal'] = True
    elif mutation == 'float-counter':
        receipt['responses_evaluated'] = 3.0
    elif mutation == 'duplicate-id':
        result['check_evidence'].append(deepcopy(receipt))
    elif mutation == 'duplicate-finding':
        result['vulnerabilities'].append(deepcopy(finding))
    elif mutation == 'wrong-run':
        receipt['run_id'] = 'different-run'
    elif mutation == 'wrong-agent':
        receipt['agent_id'] = 'different-agent'
    elif mutation == 'wrong-source':
        receipt['source'] = 'unknown-source'
    elif mutation == 'wrong-version':
        receipt['source_version'] = '2.0'
    elif mutation == 'extra-field':
        receipt['private'] = 'Synthetic private material'
    elif mutation == 'wrong-target':
        receipt['access_target']['endpoint'] += '/wrong'
        finding['access_target'] = deepcopy(receipt['access_target'])
    elif mutation == 'bad-proof-order':
        receipt['control_proof']['request_ordinals'] = [2, 1]
    elif mutation == 'bool-status':
        receipt['control_proof']['status_codes'][0] = True
    elif mutation == 'wrong-sample':
        receipt['sample_index'] = finding['sample_index'] = True
    elif mutation == 'missing-link':
        finding.pop('check_evidence_id')
    else:
        result['check_evidence'].pop(0)
    for strict in (True, False):
        with pytest.raises(ValueError):
            validate_check_evidence(result, strict=strict)
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_authz_numeric_path_survives_private_admin_redaction_without_target_changes(resource):
    from src.core.redaction import redact_secrets
    agent, _ = resource
    result = await execute(agent, 'authorization_bypass')
    public = redact_secrets(result, {'admin'})
    assert public['vulnerabilities'][0]['path'] == '/[redacted]'
    assert public['check_evidence'][0]['access_target']['endpoint'] == agent['endpoint']
    assert risk_assessment_eligible(public)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['task', 'agent', 'phase', 'sample', 'reuse'])
async def test_active_wrong_context_never_mints_from_the_invalid_call(resource, monkeypatch, kind):
    agent, _ = resource
    actual = observe_access_response
    challenged = False

    async def changed(response, **kwargs):
        nonlocal challenged
        if kwargs['phase'] != 'probe' or challenged:
            return await actual(response, **kwargs)
        challenged = True
        if kind == 'reuse':
            first = await actual(response, **kwargs)
            assert isinstance(first, AccessObservation) and len(first.findings) == 1
            second = await actual(response, **kwargs)
            assert second == AccessObservation(False, ())
            return first
        invalid = deepcopy(kwargs)
        if kind == 'agent':
            invalid['agent']['model'] = 'different'
        elif kind == 'phase':
            invalid['phase'] = 'denied_control'
        elif kind == 'sample':
            invalid['sample_index'] = True
        bad = await asyncio.create_task(actual(response, **invalid)) if kind == 'task' else await actual(response, **invalid)
        assert bad == AccessObservation(False, ())
        return await actual(response, **kwargs)

    monkeypatch.setattr(producer, 'observe_access_response', changed)
    result = await execute(agent)
    assert challenged and result['checks'][0]['status'] == 'failed'
    assert all(isinstance(item['request_ordinal'], int) for item in result['check_evidence'])
    assert len({item['id'] for item in result['check_evidence']}) == len(result['check_evidence'])
    assert risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['sink', 'cancel'])
async def test_sink_failure_escapes_before_another_request(resource, failure):
    agent, state = resource
    saved = []
    async def sink(receipt, finding):
        saved.append((deepcopy(receipt), deepcopy(finding)))
        if failure == 'cancel':
            raise asyncio.CancelledError()
        raise OSError('Synthetic private sink message')
    with pytest.raises(asyncio.CancelledError if failure == 'cancel' else CheckpointError):
        await execute(agent, observer=sink)
    assert len(state.calls) == 3 and len(saved) == 1
    assert saved[0][0]['finding_id'] == saved[0][1]['id']


def checkpoint(result):
    fields = ('provider', 'model', 'endpoint', 'evidence_context_id', 'checks', 'vulnerabilities',
              'check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence')
    source = {key: deepcopy(result[key]) for key in fields}
    source.update(agent_id=result['agent_id'], status=result['status'])
    asset = {key: deepcopy(result[key]) for key in fields}
    asset.update(id=result['agent_id'], name='Fixture', security_status=result['status'])
    return dict(schema_version='1.0', check_schema_version='1.0', check_evidence_schema_version='3.0',
                status='partial', agents=[asset], security_results=[source], risk_assessments=[], summary={},
                checkpoint={'version': '4.0', 'sequence': 1, 'coverage': 'confirmed_observations_and_finalized_checks'})


@pytest.mark.asyncio
async def test_self_consistent_wrong_target_is_refused_by_checkpoint_writer(resource):
    agent, _ = resource
    result = await execute(agent)
    report = checkpoint(result)
    validate_checkpoint_report(report)
    for value in [report['agents'][0], report['security_results'][0]]:
        value['check_evidence'][0]['access_target']['endpoint'] += '/wrong'
        value['vulnerabilities'][0]['access_target'] = deepcopy(value['check_evidence'][0]['access_target'])
    with pytest.raises(CheckpointError):
        validate_checkpoint_report(report)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', ['authentication_bypass', 'authorization_bypass'])
async def test_initial_public_unknown_remains_readable_but_cannot_erase_acknowledged_eligibility(resource, rule):
    agent, _ = resource
    if rule == 'authorization_bypass':
        agent['protected_path_markers'] = {'/admin': MARKER}
    result = await execute(agent, rule)
    unknown = deepcopy(result)
    unknown['model'] = '[redacted]'
    for value in unknown['check_evidence'] + unknown['vulnerabilities']:
        value['access_target']['model'] = '[redacted]'
    validate_check_evidence(unknown, strict=False)
    validate_checkpoint_report(checkpoint(unknown))
    assert not risk_assessment_eligible(unknown)
    assert not preserves_observation_eligibility(result, unknown)
    assert preserves_observation_eligibility(unknown, deepcopy(unknown))
    wrong = deepcopy(unknown)
    wrong['check_evidence'][0]['access_target']['endpoint'] += '/wrong'
    wrong['vulnerabilities'][0]['access_target'] = deepcopy(wrong['check_evidence'][0]['access_target'])
    with pytest.raises(ValueError):
        validate_check_evidence(wrong, strict=False)


@pytest.mark.asyncio
async def test_modern_partial_receipts_need_no_invented_terminal_check(resource):
    agent, _ = resource
    result = await execute(agent)
    result.update(status='partial', checks=[])
    assert risk_assessment_eligible(result)
    report = checkpoint(result)
    validate_checkpoint_report(report)
    assert report['checkpoint']['version'] == '4.0'
    assert report['agents'][0]['checks'] == []


@pytest.mark.asyncio
@pytest.mark.parametrize('rule,field', [('authentication_bypass', 'sample_index'),
                                      ('weak_api_key', 'header_index'), ('authorization_bypass', 'protected_path_index')])
@pytest.mark.parametrize('value', [False, 0.0])
async def test_finding_index_types_cannot_alias_the_receipt_integer(resource, rule, field, value):
    agent, _ = resource
    result = await execute(agent, rule)
    assert result['vulnerabilities'][0][field] == 0
    result['vulnerabilities'][0][field] = value
    for strict in (True, False):
        with pytest.raises(ValueError):
            validate_check_evidence(result, strict=strict)
    assert not risk_assessment_eligible(result)
