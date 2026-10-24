"""Tenant receipts require real ordered controls and immutable mixed-ledger links."""

import asyncio
from copy import deepcopy
import json
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

from aiohttp import web
import pytest

from src.core.contracts import (
    CheckpointError, TenantObservation, checked, collect_checks, collect_evidence, confirmed_findings,
    ensure_evidence_active, observe_tenant_response, risk_assessment_eligible, validate_check_evidence,
    preserves_observation_eligibility, validate_checkpoint_report, validate_scan_result,
    tenant_evidence_views_match,
)
from src.core.tenant_evidence import get_tenant_evidence, tenant_evidence_context
from src.core.tenant_probe_policy import TENANT_ATTACK_PROMPTS, TENANT_CONTROL_PROMPT, TENANT_RULE, tenant_probe_definition
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.core.prompt_catalog import baseline_payloads
from src.core.request_evidence import current_trace
from src.utils.request_builder import construct_agent_request
from tests.legacy_observation_fixtures import LEGACY_NAMES, legacy_archive, legacy_report
from tests.test_tenant_controls import (
    OWNER_KEY, OWNER_MARKER, TESTED_KEY, TESTED_MARKER, configured_agent,
    prepared_environment as prepared_environment,
)


@pytest.fixture
async def controlled_server():
    state = {'mode': 'six', 'calls': []}
    async def respond(request):
        body = await request.json()
        key = request.headers.get('Authorization', '').removeprefix('Bearer ')
        prompt = body['messages'][0]['content']
        state['calls'].append((key, prompt))
        mode = state['mode']
        if mode == 'denied':
            return web.Response(status=403, text='Denied')
        if key == state.get('owner_key', OWNER_KEY):
            generated = 'No seeded owner record' if mode == 'unseeded' else OWNER_MARKER
        elif key == TESTED_KEY and prompt == TENANT_CONTROL_PROMPT:
            generated = TESTED_MARKER + (' ' + OWNER_MARKER if mode in {'six', 'subject', 'bad-denial'} else '')
        elif key != TESTED_KEY:
            return web.Response(status=403, text=OWNER_MARKER if mode == 'bad-denial' else 'Denied')
        else:
            generated = (state['prompt_canary'] if state.get('prompt_canary') and prompt not in TENANT_ATTACK_PROMPTS
                         else OWNER_MARKER if mode in {'six', 'attack'} else 'No foreign record disclosed')
        return web.json_response({'message': {'content': generated}})
    application = web.Application()
    application.router.add_post('/api/chat', respond)
    runner = web.AppRunner(application)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}', state
    finally:
        await runner.cleanup()


class ObservedCheck:
    def __init__(self, *, stop=False, request_mutation=None, response_mutation=None):
        self.stop, self.request_mutation, self.response_mutation = stop, request_mutation, response_mutation

    @checked(TENANT_RULE, lambda self: tenant_probe_definition())
    async def run(self, agent):
        context, findings = get_tenant_evidence(agent), []
        phases = [('owner_control', None, TENANT_CONTROL_PROMPT, context.owner_api_key),
                  ('subject_control', None, TENANT_CONTROL_PROMPT, context.tested_api_key),
                  ('denied_control', None, TENANT_CONTROL_PROMPT, context.invalid_api_key)]
        phases += [('attack', index, prompt, context.tested_api_key) for index, prompt in enumerate(TENANT_ATTACK_PROMPTS)]
        for phase, index, prompt, key in phases:
            request = construct_agent_request(agent, prompt, api_key=key)
            if self.request_mutation:
                self.request_mutation(request, phase)
            async with SafeSession() as session:
                async with session.request(request['method'], request['url'], headers=request['headers'], json=request['json']) as response:
                    await response.text()
                    if self.response_mutation:
                        self.response_mutation(response, phase)
                    observed = await observe_tenant_response(response, agent=agent, phase=phase, attack_index=index)
                    assert isinstance(observed, TenantObservation)
                    findings.extend(observed.findings)
                    if self.stop and observed.findings:
                        raise RuntimeError('Synthetic interruption after observed evidence')
                    if not observed.valid:
                        return findings
        return findings


async def execute(item, *, check=None, sink=None):
    with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)), \
            collect_evidence(item, sink, schema_version='2.0') as state, collect_checks() as checks:
        try:
            await (check or ObservedCheck()).run(item)
        except (RuntimeError, asyncio.CancelledError):
            pass
    result = {key: item[key] for key in ('id', 'endpoint', 'provider', 'model', 'evidence_context_id')}
    result.update(status='partial' if checks and checks[0]['status'] == 'failed' else 'completed',
                  check_schema_version='1.0', check_evidence_schema_version='2.0',
                  check_evidence_run_id=state.run_id, check_evidence=deepcopy(state.receipts),
                  vulnerabilities=deepcopy(state.findings), checks=deepcopy(checks))
    return result


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,count', [('six', 6), ('subject', 1), ('attack', 5), ('secure', 0)])
async def test_genuine_controls_mint_only_observed_foreign_generated_text(controlled_server, mode, count):
    endpoint, state = controlled_server
    state['mode'] = mode
    result = await execute(configured_agent(endpoint))
    validate_check_evidence(result)
    assert len(result['check_evidence']) == count
    assert len(confirmed_findings(result)) == count
    assert risk_assessment_eligible(result) == bool(count)
    assert result['checks'][0]['requests_attempted'] == result['checks'][0]['responses_evaluated'] == 8
    assert result['checks'][0]['outcome'] == ('confirmed' if count else 'inconclusive')
    if mode in {'six', 'subject'}:
        receipt = result['check_evidence'][0]
        assert (receipt['request_ordinal'], receipt['requests_attempted'], receipt['responses_evaluated']) == (2, 3, 3)
        assert receipt['control_proof'] == {'request_ordinals': [1, 2, 3], 'status_codes': [200, 200, 403]}
        assert 'tenant_attack_index' not in receipt
    serialized = json.dumps(result)
    assert all(secret not in serialized for secret in (OWNER_KEY, OWNER_MARKER, TESTED_KEY, TESTED_MARKER))


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,requests', [('denied', 1), ('unseeded', 1), ('bad-denial', 3)])
async def test_missing_controls_never_publish_a_held_subject_observation(controlled_server, mode, requests):
    endpoint, state = controlled_server
    state['mode'] = mode
    result = await execute(configured_agent(endpoint))
    assert len(state['calls']) == requests
    assert result['check_evidence'] == [] and result['vulnerabilities'] == []
    assert result['checks'][0]['outcome'] != 'passed'
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_absent_collector_is_the_only_legacy_none_result():
    assert await observe_tenant_response(object(), agent={}, phase='owner_control') is None
    with collect_evidence({}):
        invalid = await observe_tenant_response(object(), agent={}, phase='owner_control')
        assert isinstance(invalid, TenantObservation) and invalid.valid is False and invalid.findings == ()


@pytest.mark.asyncio
@pytest.mark.parametrize('location', ['credential', 'user-agent', 'selected-user-agent', 'model', 'prompt', 'host'])
async def test_actual_request_role_and_phase_binding_cannot_be_forged(controlled_server, location):
    endpoint, state = controlled_server
    def mutate(request, phase):
        if phase != 'subject_control':
            return
        if location == 'credential':
            request['headers']['Authorization'] = 'Bearer ' + OWNER_KEY
        elif location == 'user-agent':
            request['headers']['User-Agent'] = OWNER_KEY
        elif location == 'selected-user-agent':
            request['headers']['User-Agent'] = TESTED_KEY
        elif location == 'model':
            request['json']['model'] = 'different-model'
        elif location == 'prompt':
            request['json']['messages'][0]['content'] = TENANT_ATTACK_PROMPTS[0]
        else:
            request['headers']['Host'] = 'different-fixture.example'
    result = await execute(configured_agent(endpoint), check=ObservedCheck(request_mutation=mutate))
    assert len(state['calls']) == 2
    assert result['check_evidence'] == [] and not risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_another_role_key_inside_the_selected_credential_cannot_be_hidden(controlled_server, monkeypatch):
    endpoint, state = controlled_server
    key_prefix = TESTED_KEY.rsplit('-', 1)[0]
    monkeypatch.setenv('TENANT_FIXTURE_OWNER_KEY', key_prefix)
    state['owner_key'] = key_prefix
    result = await execute(configured_agent(endpoint))
    assert len(state['calls']) == 2
    assert result['check_evidence'] == [] and not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('counter', ['requests', 'evaluated', 'ordinal'])
async def test_boolean_live_transport_counters_stop_before_a_second_control(controlled_server, counter):
    endpoint, state = controlled_server
    def mutate(response, phase):
        if phase == 'owner_control':
            if counter == 'ordinal':
                response._evidence_token.ordinal = True
            else:
                setattr(current_trace(), counter, True)
    try:
        result = await execute(configured_agent(endpoint), check=ObservedCheck(response_mutation=mutate))
    except ValueError:
        result = None  # The finalized CheckRecord also rejects forged Boolean counters.
    assert len(state['calls']) == 1
    assert result is None or result['check_evidence'] == []


@pytest.mark.asyncio
async def test_complete_genuine_prompt_and_tenant_ledgers_share_the_41_receipt_cap(controlled_server, monkeypatch):
    from src.security.prompt_injection_tests import PromptInjectionTester
    endpoint, server = controlled_server
    canary = 'system-canary-tenant-retention-f9e6a318'
    server['prompt_canary'] = canary
    item = {**configured_agent(endpoint), 'system_prompt_canary': canary}
    monkeypatch.setattr('src.security.prompt_injection_tests.asyncio', SimpleNamespace(
        sleep=AsyncMock(), CancelledError=asyncio.CancelledError))
    with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)), \
            collect_evidence(item) as state, collect_checks() as checks:
        await PromptInjectionTester().test_agent(item)
        await ObservedCheck().run(item)
    result = {key: item[key] for key in ('id', 'endpoint', 'provider', 'model', 'evidence_context_id')}
    result.update(status='completed', check_schema_version='1.0', check_evidence_schema_version='2.0',
                  check_evidence_run_id=state.run_id, check_evidence=deepcopy(state.receipts),
                  vulnerabilities=deepcopy(state.findings), checks=checks)
    validate_check_evidence(result)
    assert len(result['check_evidence']) == len(confirmed_findings(result)) == 41
    assert sum(receipt['source'] == 'controlled_tenant_response' for receipt in state.receipts) == 6
    assert canary not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,ordinal', [('subject', 2), ('attack', 4)])
async def test_observed_confirmation_survives_later_check_interruption(controlled_server, mode, ordinal):
    endpoint, state = controlled_server
    state['mode'] = mode
    acknowledged = []
    async def save(receipt, finding):
        acknowledged.append((deepcopy(receipt), deepcopy(finding)))
    result = await execute(configured_agent(endpoint), check=ObservedCheck(stop=True), sink=save)
    assert len(acknowledged) == len(result['check_evidence']) == 1
    assert result['check_evidence'][0]['request_ordinal'] == ordinal
    assert result['check_evidence'][0] == acknowledged[0][0]
    assert result['status'] == 'partial' and result['checks'][0]['status'] == 'failed'
    assert risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_sink_failure_and_cancellation_remain_fatal(controlled_server):
    endpoint, state = controlled_server
    state['mode'] = 'subject'
    item = configured_agent(endpoint)
    async def failed(receipt, finding):
        raise OSError('Synthetic persistence failure')
    with tenant_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)), collect_evidence(item, failed):
        with pytest.raises(CheckpointError):
            await ObservedCheck().run(item)
        with pytest.raises(CheckpointError):
            ensure_evidence_active()
    assert len(state['calls']) == 3


@pytest.mark.parametrize('name', LEGACY_NAMES)
def test_original_prompt_and_controlled_tenant_archives_retain_supported_semantics(name):
    before = legacy_archive(name)
    value = legacy_report(name)
    validate_scan_result(value)
    assert all(risk_assessment_eligible(result) for result in value['security_results'])
    assert legacy_archive(name) == before


@pytest.mark.parametrize('addition', ['finding', 'check', 'both'])
def test_new_checkpoint_cannot_append_receiptless_tenant_claims_to_valid_prompt_evidence(addition):
    report = legacy_report('prompt-unfinished-checkpoint')
    report['check_evidence_schema_version'] = '2.0'
    report['checkpoint']['version'] = '3.0'
    for value in [*report['agents'], *report['security_results']]:
        value['check_evidence_schema_version'] = '2.0'
    validate_checkpoint_report(report)
    old = legacy_report('subject-final')['security_results'][0]
    for value in [*report['agents'], *report['security_results']]:
        if addition in {'finding', 'both'}:
            value['vulnerabilities'].append(deepcopy(old['vulnerabilities'][0]))
        if addition in {'check', 'both'}:
            value['checks'].append(deepcopy(next(check for check in old['checks'] if check['rule_id'] == TENANT_RULE)))
    with pytest.raises(CheckpointError):
        validate_checkpoint_report(report)


def test_new_checkpoint_rejects_a_draft_prompt_receipt_extension_without_changing_legacy_reader():
    report = legacy_report('prompt-unfinished-checkpoint')
    report['check_evidence_schema_version'] = '2.0'
    report['checkpoint']['version'] = '3.0'
    receipt_id, finding_id = str(uuid.uuid4()), str(uuid.uuid4())
    for value in [*report['agents'], *report['security_results']]:
        value['check_evidence_schema_version'] = '2.0'
        receipt, finding = deepcopy(value['check_evidence'][0]), deepcopy(value['vulnerabilities'][0])
        receipt.update(id=receipt_id, finding_id=finding_id, source_version='1.0',
                       sample_index=1, sequence=2, request_ordinal=2, requests_attempted=2, responses_evaluated=2)
        finding.update(id=receipt['finding_id'], check_evidence_id=receipt['id'],
                       payload=baseline_payloads()[finding['category']][1])
        value['check_evidence'].append(receipt)
        value['vulnerabilities'].append(finding)
    with pytest.raises(CheckpointError):
        validate_checkpoint_report(report)
    old = legacy_report('prompt-unfinished-checkpoint')['security_results'][0]
    old['check_evidence'][0]['source_version'] = '1.0'
    validate_check_evidence(old, strict=False)
    assert not risk_assessment_eligible(old)


def unknown_probe_extension():
    report = legacy_report('prompt-unfinished-checkpoint')
    report['check_evidence_schema_version'] = '2.0'
    report['checkpoint']['version'] = '3.0'
    receipt_id, finding_id = str(uuid.uuid4()), str(uuid.uuid4())
    rule = 'prompt_injection.role_manipulation'
    for value in [*report['agents'], *report['security_results']]:
        value['check_evidence_schema_version'] = '2.0'
        receipt, finding = deepcopy(value['check_evidence'][0]), deepcopy(value['vulnerabilities'][0])
        receipt.update(id=receipt_id, finding_id=finding_id, rule_id=rule, probe_id=rule + '.sample',
                       probe_version='1:' + 'a' * 64, sample_index=0, sequence=1,
                       request_ordinal=1, requests_attempted=1, responses_evaluated=1)
        finding.update(id=finding_id, check_evidence_id=receipt_id, rule_id=rule, probe_id=rule + '.sample',
                       probe_version=receipt['probe_version'], category='role_manipulation',
                       payload=baseline_payloads()['role_manipulation'][0])
        value['checks'] = [check for check in value['checks'] if check['rule_id'] != rule]
        value['check_evidence'].append(receipt)
        value['vulnerabilities'].append(finding)
    return report


@pytest.mark.parametrize('view', ['agents', 'security_results'])
def test_acknowledged_mixed_eligibility_survives_unknown_probe_group_extensions(view):
    previous = legacy_report('prompt-unfinished-checkpoint')[view][0]
    previous['check_evidence_schema_version'] = '2.0'
    current = unknown_probe_extension()[view][0]
    assert not preserves_observation_eligibility(previous, current)
    unchanged = deepcopy(previous)
    unchanged.pop('risk_score', None)
    unchanged.pop('risk_level', None)
    assert preserves_observation_eligibility(previous, unchanged)


def test_initial_redaction_unknown_and_old_ledger_shapes_keep_existing_semantics():
    previous = legacy_report('prompt-unfinished-checkpoint')['agents'][0]
    current = deepcopy(previous)
    current['model'] = '[REDACTED]'
    assert preserves_observation_eligibility(previous, current)  # Legacy policy is unchanged.
    previous['check_evidence_schema_version'] = current['check_evidence_schema_version'] = '2.0'
    assert not preserves_observation_eligibility(previous, current)
    assert preserves_observation_eligibility(current, deepcopy(current))  # Never established current eligibility.


@pytest.mark.parametrize('field,value', [('endpoint', 'https://different-fixture.example:443/api/chat'),
                                       ('evidence_context_id', 'different-fixture-context')])
def test_positive_tenant_views_cannot_disagree_on_endpoint_or_context(field, value):
    report = legacy_report('subject-final')
    report['security_results'][0][field] = value
    with pytest.raises(ValueError, match='tenant target bindings disagree'):
        validate_scan_result(report)


def test_tenant_view_binding_allows_canonical_url_spellings_and_prompt_views_without_target():
    item = {'endpoint': 'https://fixture.example/api/chat', 'provider': 'ollama', 'model': 'fixture-model',
            'evidence_context_id': 'fixture-v1', 'vulnerabilities': [
                {'vulnerability_type': TENANT_RULE, 'evidence_status': 'confirmed'}]}
    source = deepcopy(item)
    source['endpoint'] = 'https://FIXTURE.EXAMPLE:443/api/chat'
    assert tenant_evidence_views_match(item, source)
    prompt = legacy_report('prompt-final')
    assert tenant_evidence_views_match(prompt['agents'][0], prompt['security_results'][0])


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['unknown-source', 'extra-field', 'duplicate-receipt', 'duplicate-finding',
                                     'bad-link', 'bool-status', 'bool-counter', 'bad-target', 'missing-receipts',
                                     'wrong-version', 'bad-ordinal'])
async def test_complete_mixed_ledger_rejects_corruption_before_kind_filtering(controlled_server, mutation):
    endpoint, _ = controlled_server
    value = await execute(configured_agent(endpoint))
    if mutation == 'unknown-source':
        value['check_evidence'][0]['source'] = 'unsupported'
    elif mutation == 'extra-field':
        value['check_evidence'][0]['private'] = 'Synthetic private input'
    elif mutation == 'duplicate-receipt':
        value['check_evidence'].append(deepcopy(value['check_evidence'][0]))
    elif mutation == 'duplicate-finding':
        value['vulnerabilities'].append(deepcopy(value['vulnerabilities'][0]))
    elif mutation == 'bad-link':
        value['vulnerabilities'][0]['check_evidence_id'] = value['check_evidence'][1]['id']
    elif mutation == 'bool-status':
        value['check_evidence'][0]['control_proof']['status_codes'][0] = True
    elif mutation == 'bool-counter':
        value['check_evidence'][0]['responses_evaluated'] = True
    elif mutation == 'bad-target':
        value['check_evidence'][0]['tenant_target']['model'] = 'different-model'
    elif mutation == 'missing-receipts':
        value['check_evidence'] = []
    elif mutation == 'wrong-version':
        value['check_evidence'][0]['source_version'] = '999'
    else:
        value['check_evidence'][0]['request_ordinal'] = 3
    with pytest.raises(ValueError):
        validate_check_evidence(value)
    assert not risk_assessment_eligible(value) and confirmed_findings(value) == []
