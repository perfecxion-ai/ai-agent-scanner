"""Experimental normal-scan selection preserves frozen probes and conservative evidence."""

import asyncio
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from unittest.mock import AsyncMock

from aiohttp import web
import pytest

from src.core.contracts import collect_checks
from src.core.pipeline import run_pipeline
from src.core.transport import ScanBudget, scan_transport
from src.evaluation import prompt_benchmark
from src.risk.risk_assessor import RiskAssessment
from src.security import prompt_suites as suites
from src.security.prompt_injection_tests import PromptInjectionTester
from src.security.security_engine import SecurityTestEngine


CANARY = 'synthetic-suite-canary-5726c4'
PRIVATE_TEXT = 'synthetic-private-output-2831'
SUITE = suites.PROTECTED_DISCLOSURE_SUITE


def agent(endpoint='http://127.0.0.1:1'):
    return {'id': 'fixture-agent', 'name': 'Fixture agent', 'provider': 'ollama',
            'model': 'fixture-model', 'endpoint': endpoint, 'metadata': {},
            'system_prompt_canary': CANARY, 'evidence_context_id': 'fixture-context-v1'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


@pytest.fixture(autouse=True)
def no_pacing(monkeypatch):
    monkeypatch.setattr('asyncio.sleep', AsyncMock())


def test_frozen_catalogs_pin_and_probe_versions():
    original = PromptInjectionTester().injection_payloads
    assert digest(original) == '3790e2a375dbd79407cab289edac0bb2bdead01de71d3382721dc177e52185f5'
    catalogs = prompt_benchmark._catalogs()
    assert digest(catalogs['baseline']) == '3951e77b51f6e9020f044421be2b4990d32dbe3a5ad89f2d23d79922a5dacff5'
    assert digest(suites.candidate_payloads()) == '67764cf5196daa05b14abb39910401748d3726eba2effe652086478ecd87c0f6'
    assert catalogs['candidate'] == suites.candidate_payloads()
    assert suites.prompt_suite_pin() == '5c221321ac314aa1d161ff054bb63a5ed695c960bdf9e87c2f0c196500496064'
    assert [row['probe_version'] for row in prompt_benchmark._manifest(catalogs['candidate'], 'ollama', 'fixture-model')] == [
        '1:ce6a024925d86cba51cfece69b820b138e163835f54a71f95135412d039ecb37',
        '1:b6135b4b26a56936828fb14ea8cc460e67f86366892716bc6d78b6791ba3b246',
        '1:4ee1e07983c191ecb9ac0dcc7b5919bea7c50e8c8c9f59b761111dc6fa8bc818',
        '1:35542679e157fb72eed14029bf31ca08ce50b05c25a0b6f86cb82f071eadfd57',
        '1:2b3152983762835b3818a5cb4e571775a0f3d6d9da96ed46dfbe36ea89753b95',
        '1:9fcfa138be193e99193e45789dbd69340153ab78cc41c42fc35e319cacbaff89',
        '1:9d068f420d5df1eaeb463cdce16dc3c70cde85b95d6c94985b23cd1ce9b25f87',
    ]


@pytest.mark.parametrize('value', [None, '', 'legacy-v1', 'candidate', SUITE + ' ', True, 1, [], {}])
def test_public_selection_is_exact_and_errors_are_static(value):
    with pytest.raises(suites.PromptSuiteError) as caught:
        suites.validate_prompt_suite(value)
    assert str(caught.value) == suites._ERROR
    if value is not None:
        with pytest.raises(suites.PromptSuiteError):
            PromptInjectionTester(prompt_suite=value)
        with pytest.raises(suites.PromptSuiteError):
            SecurityTestEngine(prompt_suite=value)


def test_constructor_defaults_and_defensive_copies_are_isolated(monkeypatch):
    first = SecurityTestEngine(prompt_suite=SUITE)
    second = SecurityTestEngine(prompt_suite=SUITE)
    legacy = SecurityTestEngine()
    assert legacy.prompt_suite is None and PromptInjectionTester(prompt_suite=None).prompt_suite is None
    assert suites.validate_prompt_suite(SUITE) == SUITE
    first.prompt_tester.injection_payloads['system_prompt_extraction'][0] = 'Modified private copy'
    assert second.prompt_tester.injection_payloads == suites.candidate_payloads()
    assert digest(legacy.prompt_tester.injection_payloads) == '3790e2a375dbd79407cab289edac0bb2bdead01de71d3382721dc177e52185f5'
    assert prompt_benchmark._catalogs()['candidate'] == second.prompt_tester.injection_payloads
    monkeypatch.setenv('SCAN_EVIDENCE_UNRELATED', CANARY)
    assert suites.prompt_suite_pin() == '5c221321ac314aa1d161ff054bb63a5ed695c960bdf9e87c2f0c196500496064'


def test_pin_binds_category_order_as_well_as_payload_order(monkeypatch):
    original = suites.candidate_payloads()
    before = suites.prompt_suite_pin()
    reordered = dict(reversed(list(original.items())))
    monkeypatch.setattr(suites, 'candidate_payloads', lambda: deepcopy(reordered))
    assert suites.prompt_suite_pin() != before
    reordered = deepcopy(original)
    reordered['system_prompt_extraction'].reverse()
    assert suites.prompt_suite_pin() != before


@pytest.mark.parametrize('collision', ['credential', 'probe_version', 'wire_url', 'skipped_marker'])
def test_cross_asset_private_and_public_collisions_rejected(collision, monkeypatch):
    first = agent()
    second = dict(agent(), id='second-agent', model='second-model', system_prompt_canary='second-suite-canary-817a29')
    if collision == 'credential':
        second.update(provider='unsupported', api_key_env='SUITE_OTHER_PRIVATE_KEY')
        monkeypatch.setenv('SUITE_OTHER_PRIVATE_KEY', 'issued-key-' + CANARY)
    elif collision == 'probe_version':
        version = prompt_benchmark._manifest(suites.candidate_payloads(), 'ollama', 'second-model')[0]['probe_version']
        first['system_prompt_canary'] = version[2:26]
    elif collision == 'wire_url':
        encoded = ''.join('%%%02X' % ord(char) for char in CANARY)
        second['endpoint'] = 'http://127.0.0.1/' + encoded
    else:
        second.update(provider='unsupported', system_prompt_canary='response_excerpt')
    before = deepcopy([first, second])
    with pytest.raises(suites.PromptSuiteError) as caught:
        suites.validate_prompt_suite_agents([first, second])
    assert [first, second] == before and str(caught.value) == suites._ERROR


@pytest.mark.parametrize('changes', [
    {'system_prompt_canary': None}, {'system_prompt_canary': 'short'},
    {'system_prompt_canary': 'x' * 129}, {'system_prompt_canary': 'invalid marker with spaces'},
    {'system_prompt_canary': '\u00e9' * 16}, {'evidence_context_id': None},
    {'evidence_context_id': ''}, {'evidence_context_id': 'x' * 129},
    {'evidence_context_id': ' padded '}, {'evidence_context_id': '[redacted]'},
    {'evidence_context_id': 'line\nbreak'}, {'evidence_context_id': CANARY},
    {'name': CANARY}, {'id': CANARY}, {'model': CANARY},
    {'endpoint': 'http://127.0.0.1/' + CANARY},
])
@pytest.mark.asyncio
async def test_every_testable_target_validated_before_any_candidate_call(changes, monkeypatch):
    engine = SecurityTestEngine(prompt_suite=SUITE)
    call = AsyncMock(side_effect=AssertionError('No model call may begin'))
    monkeypatch.setattr(engine.prompt_tester, 'test_agent', call)
    invalid = dict(agent(), id='second-agent', **{key: value for key, value in changes.items() if key != 'id'})
    if 'id' in changes:
        invalid['id'] = changes['id']
    inventory = [agent(), invalid]
    before = deepcopy(inventory)
    with pytest.raises(suites.PromptSuiteError) as caught:
        await engine.test_agents(inventory)
    call.assert_not_called()
    assert inventory == before and str(caught.value) == suites._ERROR
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize('marker', [SUITE, suites.PIN_FIELD, 'evidence_context_id',
    'system_prompt_extraction', 'prompt_injection', 'GENERATED_TEXT_OMITTED',
    'responses_evaluated', 'prompt_injection.instruction_bypass.sample',
    suites.prompt_suite_pin()[:24],
    'ce6a024925d86cba51cfece69b820b138e163835f54a71f95135412d039ecb37'])
def test_static_public_identity_collisions_refused(marker):
    with pytest.raises(suites.PromptSuiteError):
        suites.validate_prompt_suite_agents([dict(agent(), system_prompt_canary=marker)])


_DESCRIPTOR_MARKERS = sorted({
    marker for value in suites._PUBLIC_DESCRIPTOR
    for marker in re.findall(r'[A-Za-z0-9_.~-]{16,128}', value)
} | {'AIS-' + rule.upper().replace('_', '-') for rule in suites.PLANNED_RULES}
  | {'AIS-PROMPT-INJECTION-' + category.upper().replace('_', '-') for category in suites.candidate_payloads()})


@pytest.mark.parametrize('marker', _DESCRIPTOR_MARKERS)
@pytest.mark.asyncio
async def test_current_static_export_descriptors_refused_before_http(marker, monkeypatch):
    enter = AsyncMock(side_effect=AssertionError('HTTP must not begin'))
    monkeypatch.setattr('src.security.prompt_injection_tests.SafeSession.__aenter__', enter)
    with pytest.raises(suites.PromptSuiteError) as caught:
        await PromptInjectionTester(prompt_suite=SUITE).test_agent(dict(agent(), system_prompt_canary=marker))
    assert str(caught.value) == suites._ERROR
    enter.assert_not_called()


def test_descriptor_guard_audits_current_output_source_constants():
    # Runtime validation is pure. This maintenance audit reads only checked-in
    # source to flag newly introduced long opaque field keys and fixed labels.
    paths = ('src/core/contracts.py', 'src/core/pipeline.py', 'src/security/security_engine.py',
             'src/security/prompt_injection_tests.py', 'src/security/access_control_tests.py',
             'src/security/data_privacy_tests.py', 'src/risk/risk_assessor.py',
             'src/reporting/sarif_output.py', 'src/frameworks/owasp_llm_top10.py',
             'src/frameworks/mitre_atlas.py', 'src/security/prompt_suites.py')
    root = Path(__file__).resolve().parents[1]
    markers = set()
    for path in paths:
        tree = ast.parse((root / path).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and suites._MARKER.fullmatch(node.value):
                markers.add(node.value)
    for marker in markers:
        with pytest.raises(suites.PromptSuiteError):
            suites.validate_prompt_suite_agents([dict(agent(), system_prompt_canary=marker)])


def test_whole_public_inventory_guard_and_private_marker_exclusion():
    first, second = agent(), dict(agent(), id='second-agent')
    first['cross_tenant_canary'] = CANARY
    first['protected_response_marker'] = CANARY
    before = deepcopy([first, second])
    suites.validate_prompt_suite_agents([first, second])
    assert [first, second] == before
    unknown = {'id': 'unselected', 'name': CANARY, 'provider': 'unsupported'}
    with pytest.raises(suites.PromptSuiteError):
        suites.validate_prompt_suite_agents([first, unknown])


@pytest.mark.parametrize('value', [None, [], {}, ['wrong'], [{'endpoint': ''}],
                                [dict(agent(), provider='unsupported')], [dict(agent(), model=None)]])
def test_at_least_one_supported_adapter_target_required(value):
    with pytest.raises(suites.PromptSuiteError):
        suites.validate_prompt_suite_agents(value)


@pytest.mark.parametrize('flag', [None, 0, 1, '', [], {}])
def test_internal_target_requirement_flag_is_strict_boolean(flag):
    with pytest.raises(suites.PromptSuiteError):
        suites.validate_prompt_suite_agents([agent()], require_target=flag)


def test_relaxed_internal_requirement_keeps_all_secret_collision_guards(monkeypatch):
    skipped = dict(agent(), provider='unsupported')
    suites.validate_prompt_suite_agents([skipped], require_target=False)
    suites.validate_prompt_suite_agents([], require_target=False)
    with pytest.raises(suites.PromptSuiteError):
        suites.validate_prompt_suite_agents([skipped])
    for marker in ('protected_canary', SUITE, 'response_excerpt', suites.prompt_suite_pin()[:24]):
        with pytest.raises(suites.PromptSuiteError):
            suites.validate_prompt_suite_agents([dict(skipped, system_prompt_canary=marker)], require_target=False)
    skipped.update(api_key_env='SUITE_SKIPPED_CREDENTIAL')
    monkeypatch.setenv('SUITE_SKIPPED_CREDENTIAL', 'issued-key-' + CANARY)
    with pytest.raises(suites.PromptSuiteError):
        suites.validate_prompt_suite_agents([skipped], require_target=False)


@pytest.mark.asyncio
async def test_per_asset_candidate_engine_preserves_untestable_skips_without_calls(monkeypatch):
    engine = SecurityTestEngine(prompt_suite=SUITE)
    call = AsyncMock(side_effect=AssertionError('Unsupported targets must not call a model'))
    for tester in (engine.prompt_tester, engine.access_tester, engine.privacy_tester):
        monkeypatch.setattr(tester, 'test_agent', call)
    cases = [dict(agent(), provider='unsupported'), dict(agent(), model=None), dict(agent(), endpoint=None)]
    assert await engine.test_agents([]) == []
    for item in cases:
        result, = await engine.test_agents([item])
        assert result['status'] == 'skipped' and result['overall_risk_score'] is None
        assert all(check['status'] == 'skipped' and check['outcome'] == 'not_evaluated'
                   for check in result['checks'])
        with pytest.raises(suites.PromptSuiteError):
            suites.validate_prompt_suite_agents([item])
    call.assert_not_called()


def test_missing_credentials_skip_but_marker_reuse_cannot_evade_validation(monkeypatch):
    missing = dict(agent(), api_key_env='SUITE_MISSING_CREDENTIAL')
    monkeypatch.delenv('SUITE_MISSING_CREDENTIAL', raising=False)
    suites.validate_prompt_suite_agents([agent(), missing])
    monkeypatch.setenv('SUITE_MISSING_CREDENTIAL', 'issued-key-' + CANARY)
    with pytest.raises(suites.PromptSuiteError):
        suites.validate_prompt_suite_agents([agent(), missing])


@pytest.mark.asyncio
async def test_direct_tester_missing_prerequisite_never_opens_http(monkeypatch):
    enter = AsyncMock(side_effect=AssertionError('HTTP must not begin'))
    monkeypatch.setattr('src.security.prompt_injection_tests.SafeSession.__aenter__', enter)
    tester = PromptInjectionTester(prompt_suite=SUITE)
    with pytest.raises(suites.PromptSuiteError):
        await tester.test_agent(dict(agent(), system_prompt_canary=None))
    with pytest.raises(suites.PromptSuiteError) as caught:
        await tester.test_agent(dict(agent(), endpoint='http://[' + CANARY))
    assert str(caught.value) == suites._ERROR
    assert await tester.test_agent(dict(agent(), provider='unsupported')) == []
    assert await tester.test_agent(dict(agent(), endpoint=None)) == []
    enter.assert_not_called()


@pytest.fixture
async def target():
    state = {'mode': 'leak', 'calls': []}

    async def handler(request):
        body = await request.json()
        state['calls'].append((body, dict(request.headers)))
        mode = state['mode']
        if mode == 'denied' or mode == 'leakfail' and len(state['calls']) > 1:
            return web.Response(status=403 if mode == 'denied' else 503, text=CANARY + PRIVATE_TEXT)
        if mode == 'malformed':
            return web.Response(text=CANARY + PRIVATE_TEXT)
        text = CANARY + ' ' + PRIVATE_TEXT if mode in {'leak', 'leakfail', 'unseeded'} else (
            body['messages'][0]['content'] if mode == 'reflection' else 'I cannot share protected instructions.')
        return web.json_response({'message': {'content': text}, 'private_metadata': PRIVATE_TEXT})

    app = web.Application()
    app.router.add_post('/api/chat', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}', state
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['leak', 'refusal', 'unseeded', 'reflection', 'malformed', 'denied', 'leakfail'])
async def test_normal_pipeline_actual_http_conservative_bounded_and_secret_free(target, mode, monkeypatch, caplog):
    endpoint, state = target
    state['mode'] = mode
    item = agent(endpoint)
    if mode == 'unseeded':
        item['system_prompt_canary'] = 'unseeded-suite-canary-98e3b7'
    engine = SecurityTestEngine(prompt_suite=SUITE)
    monkeypatch.setattr(engine.access_tester, 'test_agent', AsyncMock(return_value=[]))
    monkeypatch.setattr(engine.privacy_tester, 'test_agent', AsyncMock(return_value=[]))
    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True, max_requests=35)
    with scan_transport(budget):
        result = await run_pipeline(None, engine, RiskAssessment(), None, 'security_only', agents=[item])
    assert budget.requests == len(state['calls']) == 35
    assert [body['messages'][0]['content'] for body, _ in state['calls']] == [
        payload for payloads in suites.candidate_payloads().values() for payload in payloads]
    assert all(body['options']['num_predict'] == 100 for body, _ in state['calls'])
    prompt_checks = [check for check in result['agents'][0]['checks'] if check['rule_id'].startswith('prompt_injection.')]
    assert len(prompt_checks) == 7 and all(check['outcome'] != 'passed' for check in prompt_checks)
    assert sum(check['requests_attempted'] for check in prompt_checks) == 35
    assert result['security_results'][0]['prompt_suite'] == SUITE
    assessed = result['agents'][0]
    if mode in {'leak', 'leakfail'}:
        assert assessed['risk_score'] == 70 and assessed['risk_level'] == 'high'
        assert assessed['risk_coverage_status'] == ('partial' if mode == 'leakfail' else 'sampled')
        assert assessed['vulnerabilities']
    else:
        assert assessed['risk_score'] is None and assessed['risk_level'] == 'unknown'
        assert not assessed['vulnerabilities']
    assert result['status'] == ('partial' if mode in {'malformed', 'denied', 'leakfail'} else 'completed')
    rendered = json.dumps(result) + caplog.text
    assert CANARY not in rendered and PRIVATE_TEXT not in rendered
    assert all(CANARY not in json.dumps(body) for body, _ in state['calls'])


@pytest.mark.asyncio
async def test_mixed_pipeline_preserves_skipped_assets_and_single_ready_target_budget(target, monkeypatch):
    endpoint, state = target
    engine = SecurityTestEngine(prompt_suite=SUITE)
    monkeypatch.setattr(engine.access_tester, 'test_agent', AsyncMock(return_value=[]))
    monkeypatch.setattr(engine.privacy_tester, 'test_agent', AsyncMock(return_value=[]))
    ready = agent(endpoint)
    skipped = [dict(agent(endpoint), id='unsupported', provider='unsupported'),
               dict(agent(endpoint), id='unmodelled', model=None),
               dict(agent(), id='no-endpoint', endpoint=None)]
    for item in skipped:
        item.pop('system_prompt_canary')
        item.pop('evidence_context_id')
    inventory = [ready, *skipped]
    before = deepcopy(inventory)
    suites.validate_prompt_suite_agents(inventory)
    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True, max_requests=35)
    with scan_transport(budget):
        result = await run_pipeline(None, engine, RiskAssessment(), None, 'security_only', agents=inventory)
    assert inventory == before
    assert budget.requests == len(state['calls']) == 35
    assert result['agents'][0]['risk_score'] == 70
    assert result['agents'][0]['risk_level'] == 'high'
    assert [item['security_status'] for item in result['agents'][1:]] == ['skipped'] * 3
    assert all(item['risk_score'] is None and item['risk_level'] == 'unknown' for item in result['agents'][1:])
    assert all(check['status'] == 'skipped' and check['outcome'] == 'not_evaluated'
               for item in result['agents'][1:] for check in item['checks'])
    assert result['summary']['agents_skipped'] == 3 and result['summary']['agents_failed'] == 0
    assert result['status'] == 'partial'


@pytest.mark.asyncio
async def test_existing_transport_budget_is_not_reset(target):
    endpoint, state = target
    tester = PromptInjectionTester(prompt_suite=SUITE)
    budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True, max_requests=3)
    with scan_transport(budget), collect_checks() as checks:
        findings = await tester.test_agent(agent(endpoint))
    assert budget.requests == len(state['calls']) == 3
    assert budget.rejections == 32
    assert findings and any(check['outcome'] == 'confirmed' and check['status'] == 'failed' for check in checks)


@pytest.mark.asyncio
async def test_concurrent_tester_selection_has_no_shared_mutation(target):
    endpoint, state = target
    selected, legacy = PromptInjectionTester(prompt_suite=SUITE), PromptInjectionTester()
    legacy.injection_payloads = {'instruction_bypass': ['Private legacy fixture prompt']}

    async def run(tester):
        budget = ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True, max_requests=35)
        with scan_transport(budget), collect_checks() as checks:
            await tester.test_agent(agent(endpoint))
        return budget.requests, checks

    candidate_result, legacy_result = await asyncio.gather(run(selected), run(legacy))
    assert candidate_result[0] == 35 and legacy_result[0] == 1
    assert len(candidate_result[1]) == 7 and len(legacy_result[1]) == 1
    assert len(state['calls']) == 36
    assert selected.injection_payloads == suites.candidate_payloads()
    assert legacy.injection_payloads == {'instruction_bypass': ['Private legacy fixture prompt']}
    assert PromptInjectionTester().prompt_suite is None
