"""Independent archived compatibility and actual tenant-observation boundaries."""

import asyncio
import base64
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from aiohttp import web
import pytest

from src.core.contracts import (
    CheckpointError, checked, collect_checks, collect_evidence, confirmed_findings, risk_assessment_eligible,
    validate_check_evidence, validate_checkpoint_report, validate_scan_result,
)
from src.core.pipeline import run_pipeline
from src.core.risk_projection import project_report_risk
from src.core.tenant_evidence import TenantEvidenceError, get_tenant_evidence, tenant_evidence_context, tenant_secrets
from src.core.tenant_probe_policy import TENANT_CONTROL_PROMPT, tenant_probe_definition, tenant_target
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.security.data_privacy_tests import DataPrivacyTester
from src.security.prompt_injection_tests import PromptInjectionTester
from src.security.security_engine import SecurityTestEngine
from src.risk.risk_assessor import RiskAssessment
from src.utils.request_builder import construct_agent_request
from tests.legacy_observation_fixtures import (
    LEGACY_NAMES, LEGACY_PRODUCER_REVISION, legacy_archive, legacy_manifest, legacy_report,
)
from tests.controlled_access import result as controlled_access_result, target as controlled_access_target


OWNER_KEY = 'independent-owner-key-fc3ea541029d7b86'
TESTED_KEY = 'independent-subject-key-67ad13e083f9c42b'
OWNER_MARKER = 'independent-owner-canary-29ab7fe103c46d85'
TESTED_MARKER = 'independent-subject-canary-d7182fe39b6c40a5'
SYSTEM_MARKER = 'independent-system-canary-e45b1920a3fc786d'
ENVIRONMENT = {
    'INDEPENDENT_TENANT_OWNER_KEY': OWNER_KEY,
    'INDEPENDENT_TENANT_OWNER_MARKER': OWNER_MARKER,
    'INDEPENDENT_TENANT_SUBJECT_KEY': TESTED_KEY,
    'INDEPENDENT_TENANT_SUBJECT_MARKER': TESTED_MARKER,
}
LABELS = ('private-tenant-owner-c65a1b40', 'private-principal-owner-d34f90a2',
          'private-tenant-subject-01af2c95', 'private-principal-subject-73d2e8a0')


@pytest.mark.parametrize('name', LEGACY_NAMES)
def test_frozen_old_producer_archives_keep_original_evidence_and_scores(name):
    raw = legacy_archive(name)
    report = legacy_report(name)
    original = deepcopy(report)
    expected = legacy_manifest()['archives'][name]
    assert legacy_manifest()['producer_revision'] == LEGACY_PRODUCER_REVISION
    assert report['check_evidence_schema_version'] == '1.0'
    assert report['checkpoint']['version'] == '2.0'
    validate_scan_result(report)
    validate_checkpoint_report(report, final=name != 'prompt-unfinished-checkpoint')
    summary, assets = project_report_risk(report)
    asset = report['agents'][0]
    assert report['status'] == expected['expected_status']
    assert summary['overall_risk_score'] == expected['expected_score']
    assert assets[asset['id']]['risk_score'] == expected['expected_score']
    assert assets[asset['id']]['risk_coverage_status'] == expected['expected_coverage']
    assert asset['check_evidence_run_id'] == expected['run_id']
    assert [f['id'] for f in confirmed_findings(report['security_results'][0])] == expected['finding_ids']
    assert [r['id'] for r in asset['check_evidence']] == expected['receipt_ids']
    assert report == original and legacy_archive(name) == raw


@pytest.mark.parametrize('name', ['subject-final', 'attack-final', 'subject-partial-final'])
def test_new_ledger_declaration_cannot_reuse_old_finalized_tenant_fallback(name):
    result = legacy_report(name)['security_results'][0]
    assert risk_assessment_eligible(result)
    result['check_evidence_schema_version'] = '2.0'
    assert result['check_evidence'] == []
    assert confirmed_findings(result) == []
    assert not risk_assessment_eligible(result)


@pytest.mark.parametrize('name', ['prompt-unfinished-checkpoint', 'prompt-final'])
@pytest.mark.parametrize('mutation', ['draft-source', 'missing-receipts', 'unlinked-occurrence'])
def test_archived_prompt_guards_do_not_gain_fallback_during_dispatch(name, mutation):
    result = legacy_report(name)['security_results'][0]
    if mutation == 'draft-source':
        for receipt in result['check_evidence']:
            receipt['source_version'] = '1.0'
    elif mutation == 'missing-receipts':
        result['check_evidence'] = []
    else:
        result['vulnerabilities'][0].pop('check_evidence_id')
    original = deepcopy(result)
    assert confirmed_findings(result) == []
    assert not risk_assessment_eligible(result)
    assert result == original


@pytest.mark.parametrize('claim', ['paired', 'finding-only', 'check-only'])
def test_new_checkpoint_rejects_receiptless_tenant_extension_of_valid_prompt_evidence(claim):
    archived = legacy_archive('prompt-unfinished-checkpoint')
    before = legacy_report('prompt-unfinished-checkpoint')
    before['check_evidence_schema_version'] = '2.0'
    before['checkpoint']['version'] = '3.0'
    for value in before['agents'] + before['security_results']:
        value['check_evidence_schema_version'] = '2.0'
    validate_checkpoint_report(before)
    assert risk_assessment_eligible(before['security_results'][0])
    original = deepcopy(before)
    after = deepcopy(before)
    after['checkpoint']['sequence'] += 1
    tenant = legacy_report('subject-final')['security_results'][0]
    check = next(c for c in tenant['checks'] if c['rule_id'] == 'tenant_isolation_violation')
    finding = deepcopy(tenant['vulnerabilities'][0])
    finding['agent_id'] = before['agents'][0]['id']
    for value in after['agents'] + after['security_results']:
        value['checks'] = [c for c in value['checks'] if c['rule_id'] != 'tenant_isolation_violation']
        if claim != 'finding-only':
            value['checks'].append(deepcopy(check))
        if claim != 'check-only':
            value['vulnerabilities'].append(deepcopy(finding))
    assert not risk_assessment_eligible(after['security_results'][0])
    summary, assets = project_report_risk(after)
    assert summary['overall_risk_score'] is None
    assert assets[before['agents'][0]['id']]['risk_score'] is None
    with pytest.raises(CheckpointError):
        validate_checkpoint_report(after)
    assert before == original
    assert legacy_archive('prompt-unfinished-checkpoint') == archived


def configured_agent(endpoint):
    item = dict(id='independent-tenant', name='Independent tenant fixture', type='assistant',
                endpoint=endpoint, provider='ollama', model='independent-fixture-model',
                api_key_env='INDEPENDENT_TENANT_SUBJECT_KEY',
                evidence_context_id='independent-tenant-context-v1')
    item['tenant_evidence'] = dict(
        schema_version='1.0', tested_principal_authorized_for_owner=False,
        binding=tenant_target(endpoint, item['provider'], item['model'], item['evidence_context_id']),
        owner=dict(tenant_ref=LABELS[0], principal_ref=LABELS[1],
                   api_key_env='INDEPENDENT_TENANT_OWNER_KEY', canary_env='INDEPENDENT_TENANT_OWNER_MARKER'),
        tested=dict(tenant_ref=LABELS[2], principal_ref=LABELS[3],
                    api_key_env='INDEPENDENT_TENANT_SUBJECT_KEY', canary_env='INDEPENDENT_TENANT_SUBJECT_MARKER'))
    return item


@pytest.fixture
async def tenant_observation_target(monkeypatch):
    for key, value in ENVIRONMENT.items():
        monkeypatch.setenv(key, value)
    async def no_pacing(_):
        return None
    for module in ('data_privacy_tests', 'prompt_injection_tests'):
        monkeypatch.setattr('src.security.' + module + '.asyncio',
                            SimpleNamespace(sleep=no_pacing, CancelledError=asyncio.CancelledError))
    state = dict(mode='all', calls=[], release=asyncio.Event(), blocked=asyncio.Event(),
                 controls_started=False, encoded_responses=False, private_response_values=[])

    def model_response(text, status=200):
        data, headers = {'message': {'content': text}}, {}
        if state['encoded_responses']:
            private = (OWNER_KEY, TESTED_KEY, OWNER_MARKER, TESTED_MARKER, *ENVIRONMENT, *LABELS)
            encoded = [variant for value in private for variant in (
                base64.b64encode(value.encode()).decode(),
                ''.join('%%%02X' % byte for byte in value.encode()))]
            state['private_response_values'].extend(encoded)
            data['private_metadata'] = dict(values=[OWNER_KEY, TESTED_KEY, *ENVIRONMENT, *LABELS], encoded=encoded)
            headers['X-Private-Credential'] = OWNER_KEY
        return web.json_response(data, status=status, headers=headers)

    async def handler(request):
        body = await request.json()
        prompt = body['messages'][0]['content']
        key = request.headers.get('Authorization', '').removeprefix('Bearer ')
        state['calls'].append(dict(key=key, prompt=prompt, body=body, headers=dict(request.headers)))
        ordinal = len(state['calls'])
        mode = state['mode']
        if mode == 'dual' and not state['controls_started'] and prompt != TENANT_CONTROL_PROMPT:
            return web.json_response({'message': {'content': SYSTEM_MARKER}})
        if key == state.get('owner_key', OWNER_KEY):
            state['controls_started'] = True
            text = OWNER_MARKER + (' ' + TESTED_MARKER if ordinal == 2 and state.get('force_second_seed') else '')
        elif key == TESTED_KEY and prompt == TENANT_CONTROL_PROMPT:
            text = TESTED_MARKER + (' ' + OWNER_MARKER if mode.startswith('subject') or mode in {'all', 'dual'} else '')
            if mode == 'header-authority' and OWNER_KEY in request.headers.get('User-Agent', ''):
                text += ' ' + OWNER_MARKER
        elif ordinal == 2 and state.get('force_second_seed'):
            text = TESTED_MARKER + ' ' + OWNER_MARKER
        elif key != TESTED_KEY:
            if mode == 'subject-invalid-stall':
                state['blocked'].set()
                await state['release'].wait()
            if mode == 'subject-invalid-allowed':
                return web.Response(status=200, text='Unprotected response')
            if mode == 'subject-invalid-leak':
                return web.json_response({'message': {'content': OWNER_MARKER}}, status=403)
            return model_response('Owned invalid credential refused', 403)
        else:
            if (mode == 'subject-stall' and ordinal == 4
                    or mode == 'attack-stall' and ordinal == 5):
                state['blocked'].set()
                await state['release'].wait()
            text = OWNER_MARKER if mode in {'all', 'dual', 'attack', 'attack-stall'} else 'No foreign records'
        return model_response(text)

    application = web.Application()
    application.router.add_post('/api/chat', handler)
    runner = web.AppRunner(application)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    endpoint = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}'
    try:
        yield configured_agent(endpoint), state
    finally:
        state['release'].set()
        await runner.cleanup()


def observation_result(item, evidence, checks, findings=None, *, status='partial'):
    return dict(agent_id=item['id'], endpoint=item['endpoint'], provider=item['provider'], model=item['model'],
                evidence_context_id=item['evidence_context_id'], status=status, check_schema_version='1.0',
                check_evidence_schema_version='2.0', check_evidence_run_id=evidence.run_id,
                check_evidence=deepcopy(evidence.receipts), checks=deepcopy(checks),
                vulnerabilities=deepcopy(evidence.findings if findings is None else findings), observations=[])


async def produce_observations(item, *, observer=None, prompt_first=False):
    with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)), \
            collect_checks() as checks, collect_evidence(item, observer) as evidence:
        findings = []
        if prompt_first:
            tester = PromptInjectionTester()
            categories = tester.injection_payloads if prompt_first == 'all' else ('system_prompt_extraction',)
            for category in categories:
                findings.extend(await tester._test_injection_category(item, category, tester.injection_payloads[category]))
        findings.extend(await DataPrivacyTester()._test_tenant_isolation(item))
    return observation_result(item, evidence, checks, findings, status='completed')


@pytest.mark.asyncio
async def test_full_unchanged_prompt_sample_and_all_tenant_observations_fit_one_41_receipt_ledger(
        tenant_observation_target):
    item, target = tenant_observation_target
    target['mode'] = 'dual'
    item['system_prompt_canary'] = SYSTEM_MARKER
    result = await produce_observations(item, prompt_first='all')
    assert len(target['calls']) == 43
    receipts = result['check_evidence']
    assert len(receipts) == 41
    assert sum(r['source'] == 'protected_system_canary_match' for r in receipts) == 35
    assert sum(r['source'] == 'controlled_tenant_response' for r in receipts) == 6
    validate_check_evidence(result)
    assert len(confirmed_findings(result)) == 41 and risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('claim', ['paired', 'finding-only', 'check-only'])
async def test_current_tenant_without_receipts_cannot_inherit_valid_access_zero(tenant_observation_target, claim):
    item, _ = tenant_observation_target
    result = await produce_observations(item)
    access = await controlled_access_result(controlled_access_target(
        provider='ollama', model=item['model'], id=item['id']), disclose=False)
    assert risk_assessment_eligible(access) and access['checks'][0]['outcome'] == 'passed'
    result['check_evidence'] = []
    if claim == 'finding-only':
        result['checks'] = []
    elif claim == 'check-only':
        result['vulnerabilities'] = []
    result['checks'].extend(access['checks'])
    original = deepcopy(result)
    assert confirmed_findings(result) == [] and not risk_assessment_eligible(result)
    assert result == original


@pytest.mark.asyncio
async def test_six_real_tenant_observations_have_exact_public_control_proof_and_counters(tenant_observation_target):
    item, target = tenant_observation_target
    result = await produce_observations(item)
    assert len(target['calls']) == 8
    assert len(result['check_evidence']) == len(result['vulnerabilities']) == 6
    validate_check_evidence(result)
    assert risk_assessment_eligible(result)
    receipts = result['check_evidence']
    assert [r['sequence'] for r in receipts] == [1, 2, 3, 4, 5, 6]
    assert [r['request_ordinal'] for r in receipts] == [2, 4, 5, 6, 7, 8]
    assert [r['requests_attempted'] for r in receipts] == [3, 4, 5, 6, 7, 8]
    assert [r['responses_evaluated'] for r in receipts] == [3, 4, 5, 6, 7, 8]
    assert {r['source'] for r in receipts} == {'controlled_tenant_response'}
    assert {r['source_version'] for r in receipts} == {'1.0'}
    assert receipts[0]['tenant_observation_source'] == 'subject_control'
    assert 'tenant_attack_index' not in receipts[0]
    assert [r['tenant_attack_index'] for r in receipts[1:]] == [0, 1, 2, 3, 4]
    assert all(r['control_proof'] == {'request_ordinals': [1, 2, 3], 'status_codes': [200, 200, 403]}
               for r in receipts)
    assert all(r['tenant_target'] == tenant_target(item['endpoint'], 'ollama', item['model'],
                                                 item['evidence_context_id']) for r in receipts)
    assert all(f['check_evidence_id'] == r['id'] and f['id'] == r['finding_id']
               for r, f in zip(receipts, result['vulnerabilities']))
    assert result['checks'][0]['requests_attempted'] == result['checks'][0]['responses_evaluated'] == 8


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', [
    'unknown-source', 'unknown-source-version', 'boolean-index', 'boolean-proof-status',
    'subject-extra-index', 'attack-missing-index', 'reordered-proof', 'counter-rewind',
    'duplicate-id', 'wrong-target', 'extra-private-field', 'different-asset',
    'boolean-proof-ordinal', 'boolean-sequence', 'conflicting-valid-proof',
    'subject-status-mismatch', 'late-subject-publication-counters',
])
async def test_malformed_mixed_ledger_cannot_hide_behind_prompt_subset(tenant_observation_target, mutation):
    item, target = tenant_observation_target
    target['mode'] = 'dual'
    item['system_prompt_canary'] = SYSTEM_MARKER
    result = await produce_observations(item, prompt_first=True)
    assert len(result['check_evidence']) == 11 and risk_assessment_eligible(result)
    receipts = result['check_evidence']
    receipts[5], receipts[6] = deepcopy(receipts[5]), deepcopy(receipts[6])
    subject, attack = receipts[5], receipts[6]
    if mutation == 'unknown-source':
        attack['source'] = 'unrecognized_response'
    elif mutation == 'unknown-source-version':
        attack['source_version'] = '2.0'
    elif mutation == 'boolean-index':
        attack['tenant_attack_index'] = False
    elif mutation == 'boolean-proof-status':
        attack['control_proof']['status_codes'][2] = True
    elif mutation == 'subject-extra-index':
        subject['tenant_attack_index'] = 0
    elif mutation == 'attack-missing-index':
        attack.pop('tenant_attack_index')
    elif mutation == 'reordered-proof':
        attack['control_proof']['request_ordinals'] = [2, 1, 3]
    elif mutation == 'counter-rewind':
        attack['responses_evaluated'] = 2
    elif mutation == 'duplicate-id':
        attack['id'] = receipts[0]['id']
    elif mutation == 'wrong-target':
        attack['tenant_target']['model'] = 'different-model'
    elif mutation == 'extra-private-field':
        attack['credential'] = 'arbitrary material'
    elif mutation == 'different-asset':
        attack['agent_id'] = 'unrelated-asset'
    elif mutation == 'boolean-proof-ordinal':
        attack['control_proof']['request_ordinals'][0] = True
    elif mutation == 'boolean-sequence':
        subject['sequence'] = True
    elif mutation == 'conflicting-valid-proof':
        attack['control_proof']['status_codes'][2] = 401
    elif mutation == 'subject-status-mismatch':
        result['vulnerabilities'][5]['status_code'] = 201
    else:
        subject['requests_attempted'] = 4
    original = deepcopy(result)
    with pytest.raises(ValueError):
        validate_check_evidence(result)
    assert confirmed_findings(result) == [] and not risk_assessment_eligible(result)
    assert result == original


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['error', 'cancel'])
async def test_receipt_sink_failure_stops_before_attack_and_cleanup_cannot_hide_it(
        tenant_observation_target, failure):
    item, target = tenant_observation_target
    target['mode'] = 'subject'
    delivered = []

    async def sink(receipt, finding):
        delivered.append((deepcopy(receipt), deepcopy(finding)))
        if failure == 'cancel':
            raise asyncio.CancelledError()
        raise RuntimeError('Owned sink failure')

    with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)), \
            collect_checks() as checks, collect_evidence(item, sink) as evidence:
        with pytest.raises(asyncio.CancelledError if failure == 'cancel' else CheckpointError):
            await DataPrivacyTester()._test_tenant_isolation(item)
    assert len(target['calls']) == 3 and len(delivered) == 1
    assert evidence.receipts == [delivered[0][0]] and evidence.findings == [delivered[0][1]]
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'confirmed'


@pytest.mark.asyncio
async def test_public_ledger_omits_complete_private_basis_and_encoded_response_material(tenant_observation_target):
    item, target = tenant_observation_target
    target['encoded_responses'] = True
    result = await produce_observations(item)
    raw = json.dumps(result, ensure_ascii=True)
    decoded = json.dumps(json.loads(raw), ensure_ascii=False).casefold()
    values = {OWNER_KEY, TESTED_KEY, OWNER_MARKER, TESTED_MARKER, *ENVIRONMENT, *LABELS}
    values.update(call['key'] for call in target['calls'] if call['key'])
    variants = set(values)
    for value in values:
        variants.add(base64.b64encode(value.encode()).decode())
        variants.add(''.join('%%%02X' % byte for byte in value.encode()))
    assert target['private_response_values']
    assert set(target['private_response_values']) <= variants
    assert all(value.casefold() not in decoded for value in variants)


def test_complete_private_tenant_basis_includes_operator_labels(monkeypatch):
    for key, value in ENVIRONMENT.items():
        monkeypatch.setenv(key, value)
    item = configured_agent('http://127.0.0.1:1')
    with tenant_evidence_context([item]):
        assert {*ENVIRONMENT, *ENVIRONMENT.values(), *LABELS} <= set(tenant_secrets())


@pytest.mark.parametrize('descriptor', ['control_proof', 'request_ordinals', 'status_codes',
                                       'controlled_tenant_response'])
def test_new_public_proof_descriptors_conflicting_with_private_labels_fail_before_execution(monkeypatch, descriptor):
    for key, value in ENVIRONMENT.items():
        monkeypatch.setenv(key, value)
    item = configured_agent('http://127.0.0.1:1')
    item['tenant_evidence']['owner']['principal_ref'] = descriptor
    with pytest.raises(TenantEvidenceError):
        with tenant_evidence_context([item]):
            pytest.fail('Public/private collision reached execution')


@pytest.mark.asyncio
async def test_bad_tenant_append_leaves_acknowledged_prompt_state_unchanged(tenant_observation_target, monkeypatch):
    from src.core.pipeline import _CheckpointState

    item, target = tenant_observation_target
    target['mode'] = 'dual'
    item['system_prompt_canary'] = SYSTEM_MARKER
    security = SecurityTestEngine()
    category = 'system_prompt_extraction'
    async def prompt_only(agent):
        return await security.prompt_tester._test_injection_category(
            agent, category, security.prompt_tester.injection_payloads[category])
    security.prompt_tester.test_agent = prompt_only
    security.access_tester.test_agent = AsyncMock(return_value=[])
    security.privacy_tester.test_agent = security.privacy_tester._test_tenant_isolation
    saved, injections = [], []
    async def save(report):
        saved.append(deepcopy(report))
    original_accept = _CheckpointState.accept_evidence

    async def corrupt_once(state, index, receipt, finding):
        if receipt.get('source') != 'controlled_tenant_response':
            return await original_accept(state, index, receipt, finding)
        before = deepcopy(state.results)
        bad = deepcopy(receipt)
        bad['control_proof']['status_codes'][2] = 200
        with pytest.raises((CheckpointError, ValueError)):
            await original_accept(state, index, bad, finding)
        assert state.results == before
        assert len(before[index]['check_evidence']) == 5
        injections.append(True)
        raise CheckpointError()

    monkeypatch.setattr(_CheckpointState, 'accept_evidence', corrupt_once)
    with scan_transport(ScanBudget(allow_loopback=True)):
        with pytest.raises(CheckpointError):
            await run_pipeline(None, security, RiskAssessment(), None, 'security_only',
                               agents=[item], checkpoint_callback=save)
    assert injections == [True] and len(target['calls']) == 8
    assert saved[-1]['check_evidence_schema_version'] == '2.0'
    assert saved[-1]['checkpoint']['version'] == '3.0'
    assert len(saved[-1]['agents'][0]['check_evidence']) == 5
    assert all(r['source'] == 'protected_system_canary_match' for r in saved[-1]['agents'][0]['check_evidence'])


@pytest.mark.asyncio
async def test_public_redaction_of_new_tenant_receipt_cannot_erase_acknowledged_prompt_score(
        tenant_observation_target, monkeypatch):
    item, target = tenant_observation_target
    target['mode'] = 'dual'
    item['system_prompt_canary'] = SYSTEM_MARKER
    private = '1:' + hashlib.sha256(json.dumps(
        [tenant_probe_definition(), item['provider'], item['model']], sort_keys=True).encode()).hexdigest()
    monkeypatch.setenv('INDEPENDENT_TENANT_OWNER_KEY', private)
    target['owner_key'] = private
    security = SecurityTestEngine()
    category = 'system_prompt_extraction'
    async def prompt_only(agent):
        return await security.prompt_tester._test_injection_category(
            agent, category, security.prompt_tester.injection_payloads[category])
    security.prompt_tester.test_agent = prompt_only
    security.access_tester.test_agent = AsyncMock(return_value=[])
    security.privacy_tester.test_agent = security.privacy_tester._test_tenant_isolation
    saved = []
    async def save(report):
        saved.append(deepcopy(report))
    with scan_transport(ScanBudget(allow_loopback=True)):
        try:
            final = await run_pipeline(None, security, RiskAssessment(), None, 'security_only',
                                       agents=[item], checkpoint_callback=save)
        except (CheckpointError, TenantEvidenceError, ValueError):
            final = None
    if not saved:
        assert target['calls'] == []  # Admission can reject a deterministic collision before a baseline write.
        return
    acknowledged = next(index for index, report in enumerate(saved)
                        if report['summary']['overall_risk_score'] == 70.0)
    # A publish before asynchronous scoring can legitimately have a null cache.
    # Its acknowledged prompt evidence must remain eligible through every append.
    assert all(risk_assessment_eligible(report['security_results'][0]) for report in saved[acknowledged:])
    assert all(private not in json.dumps(report) for report in saved)
    if final is not None:
        assert final['summary']['overall_risk_score'] in (70.0, 90.0)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,calls', [('subject-invalid-allowed', 3), ('subject-invalid-leak', 3)])
async def test_held_control_leak_requires_actual_clean_denied_third_control(tenant_observation_target, mode, calls):
    item, target = tenant_observation_target
    target['mode'] = mode
    with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)), \
            collect_checks() as checks, collect_evidence(item) as evidence:
        findings = await DataPrivacyTester()._test_tenant_isolation(item)
    assert len(target['calls']) == calls
    assert findings == evidence.findings == evidence.receipts == []
    result = observation_result(item, evidence, checks)
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'inconclusive'
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,blocked_at,receipts', [('subject-stall', 4, 1), ('attack-stall', 5, 1),
                                                   ('subject-invalid-stall', 3, 0)])
async def test_live_receipt_precedes_later_stall_and_survives_cancellation(
        tenant_observation_target, mode, blocked_at, receipts):
    item, target = tenant_observation_target
    target['mode'] = mode
    entered = asyncio.Event()
    observed = {}

    async def run():
        with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)), \
                collect_checks() as checks, collect_evidence(item) as evidence:
            observed.update(evidence=evidence, checks=checks)
            entered.set()
            await DataPrivacyTester()._test_tenant_isolation(item)

    task = asyncio.create_task(run())
    await asyncio.wait_for(entered.wait(), 3)
    try:
        await asyncio.wait_for(target['blocked'].wait(), 3)
        evidence = observed['evidence']
        assert len(target['calls']) == blocked_at
        assert len(evidence.receipts) == len(evidence.findings) == receipts
        before = deepcopy(evidence.receipts)
        assert observed['checks'] == []
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert evidence.receipts == before
    result = observation_result(item, evidence, observed['checks'])
    assert observed['checks'][0]['status'] == 'failed'
    assert observed['checks'][0]['outcome'] == ('confirmed' if receipts else 'inconclusive')
    assert bool(confirmed_findings(result)) is bool(receipts)
    assert risk_assessment_eligible(result) is bool(receipts)


@pytest.mark.asyncio
async def test_subject_receipt_survives_actual_session_cleanup_error(tenant_observation_target, monkeypatch):
    item, target = tenant_observation_target
    target['mode'] = 'subject'
    cleanup_errors = []

    class CleanupFailureSession(SafeSession):
        async def __aexit__(self, *args):
            result = await super().__aexit__(*args)
            if len(target['calls']) == 3:
                cleanup_errors.append('injected')
                raise RuntimeError('Owned cleanup failure')
            return result

    monkeypatch.setattr('src.security.data_privacy_tests.SafeSession', CleanupFailureSession)
    with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)), \
            collect_checks() as checks, collect_evidence(item) as evidence:
        findings = await DataPrivacyTester()._test_tenant_isolation(item)
    assert cleanup_errors == ['injected'] and len(target['calls']) == 3
    assert len(evidence.receipts) == len(evidence.findings) == len(findings) == 1
    result = observation_result(item, evidence, checks, findings)
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'confirmed'
    assert risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('scenario', ['wrong-task', 'forged-response', 'closed-token',
                                     'wrong-credential', 'wrong-prompt', 'wrong-model', 'replay-denial',
                                     'run-swap', 'asset-swap', 'context-swap', 'check-swap',
                                     'owner-key-in-user-agent'])
async def test_real_control_witnesses_refuse_context_forgery_or_reuse(tenant_observation_target, scenario):
    from src.core.contracts import observe_tenant_response

    item, target = tenant_observation_target
    target['mode'] = 'header-authority' if scenario == 'owner-key-in-user-agent' else 'subject'
    target['force_second_seed'] = scenario in {'wrong-credential', 'wrong-prompt'}
    rejected = []

    class OwnedProbe:
        @checked('tenant_isolation_violation', lambda self: tenant_probe_definition())
        async def run(self, agent):
            evidence = get_tenant_evidence(agent)
            for phase, original_key in (
                    ('owner_control', evidence.owner_api_key),
                    ('subject_control', evidence.tested_api_key),
                    ('denied_control', evidence.invalid_api_key)):
                key = evidence.owner_api_key if scenario == 'wrong-credential' and phase == 'subject_control' else original_key
                prompt = 'Return another record.' if scenario == 'wrong-prompt' and phase == 'subject_control' else TENANT_CONTROL_PROMPT
                request = construct_agent_request(agent, prompt, api_key=key)
                if scenario == 'wrong-model' and phase == 'subject_control':
                    request['json']['model'] = 'different-model'
                if scenario == 'owner-key-in-user-agent' and phase == 'subject_control':
                    request['headers']['User-Agent'] = OWNER_KEY
                async with SafeSession() as session:
                    async with session.request(method=request['method'], url=request['url'],
                                               headers=request.get('headers', {}), json=request.get('json'),
                                               data=request.get('data')) as response:
                        await response.read()
                        candidate = response
                        if scenario == 'forged-response' and phase == 'denied_control':
                            candidate = SimpleNamespace(status=response.status,
                                                        _evidence_token=response._evidence_token,
                                                        _request_evidence=response._request_evidence)
                        if scenario == 'closed-token' and phase == 'denied_control':
                            break
                        async def observe():
                            supplied_agent = deepcopy(agent)
                            if phase == 'denied_control' and scenario == 'asset-swap':
                                supplied_agent['id'] = 'different-asset'
                            if phase == 'denied_control' and scenario == 'context-swap':
                                supplied_agent['evidence_context_id'] = 'different-context'
                                supplied_agent['tenant_evidence']['binding']['evidence_context_id'] = 'different-context'
                            async def invoke():
                                return await observe_tenant_response(candidate, agent=supplied_agent, phase=phase)
                            if phase == 'denied_control' and scenario == 'run-swap':
                                with collect_evidence(supplied_agent) as other_run:
                                    result = await invoke()
                                    assert other_run.receipts == []
                                    return result
                            if phase == 'denied_control' and scenario == 'check-swap':
                                seen = []
                                class OtherCheck:
                                    @checked('tenant_isolation_violation', lambda self: tenant_probe_definition())
                                    async def run(self, agent):
                                        seen.append(await invoke())
                                        return []
                                await OtherCheck().run(supplied_agent)
                                return seen[0]
                            return await invoke()
                        try:
                            observation = await asyncio.create_task(observe()) if scenario == 'wrong-task' and phase == 'denied_control' else await observe()
                        except (CheckpointError, ValueError):
                            rejected.append(phase)
                            return []
                        if not observation.valid:
                            rejected.append(phase)
                            return []
                        if scenario == 'replay-denial' and phase == 'denied_control':
                            before = deepcopy(collected.receipts)
                            try:
                                duplicate = await observe()
                            except (CheckpointError, ValueError):
                                rejected.append(phase)
                            else:
                                assert not duplicate.valid
                                rejected.append(phase)
                            assert collected.receipts == before
            if scenario == 'closed-token':
                try:
                    closed = await observe_tenant_response(response, agent=agent, phase='denied_control')
                except (CheckpointError, ValueError):
                    rejected.append('denied_control')
                else:
                    assert not closed.valid
                    rejected.append('denied_control')
            return []

    with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)), \
            collect_checks() as checks, collect_evidence(item) as collected:
        await OwnedProbe().run(item)
    assert len(rejected) == 1
    assert len(target['calls']) == (2 if scenario in {
        'wrong-credential', 'wrong-prompt', 'wrong-model', 'owner-key-in-user-agent'} else 3)
    assert len(collected.receipts) == (1 if scenario == 'replay-denial' else 0)
    assert len(collected.findings) == len(collected.receipts)
    assert len(checks) == (2 if scenario == 'check-swap' else 1)
