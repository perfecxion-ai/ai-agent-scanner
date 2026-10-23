"""Actual request echoes cannot establish protected-system disclosure."""

import asyncio
from copy import deepcopy
import ipaddress
import json
import socket
import time
from types import SimpleNamespace

from aiohttp import web
from aiohttp.http import SERVER_SOFTWARE
import pytest

from scanner_cli import load_targets
from src.core.contracts import collect_checks, validate_checkpoint_report
from src.core.evidence_profiles import EvidenceProfileError, EvidenceProfiles, load_evidence_profiles
from src.core.pipeline import run_pipeline, to_sarif
from src.core.risk_projection import project_report_risk
from src.core.transport import ScanBudget, scan_transport
from src.evaluation.prompt_benchmark import BenchmarkConfig, BenchmarkError, benchmark
from src.risk.risk_assessor import RiskAssessment
from src.security.prompt_injection_tests import PromptInjectionTester
from src.security.prompt_suites import PromptSuiteError
from src.security.security_engine import SecurityTestEngine
from tests.test_beta_lab_workflow import real_lab as real_lab


CANARY = 'synthetic-private-canary-812bcfa9'
PUBLIC_VALUE = 'synthetic-public-value-473bc01e'
KEY = 'synthetic-issued-credential-81bcf543'
KEY_ENV = 'SYNTHETIC_REQUEST_REFLECTION_KEY'
PROFILE_ENV = 'SCAN_EVIDENCE_REQUEST_REFLECTION'
SUITES = (None, 'protected-disclosure-v1')
SHARED_CASES = ('model_exact', 'credential_exact', 'url_exact', 'normalized_url',
                'model_case', 'credential_case', 'url_case', 'prompt_echo')
BASELINE_CASES = ('automatic_user_agent', 'rendered_header', 'prompt_case')


@pytest.fixture
def pacing_and_isolation(monkeypatch):
    # Preserve the event loop and transport timers; shorten security pacing only.
    async def no_pacing(_):
        return None

    for name in ('prompt_injection_tests', 'access_control_tests', 'data_privacy_tests'):
        monkeypatch.setattr('src.security.' + name + '.asyncio',
                            SimpleNamespace(sleep=no_pacing, CancelledError=asyncio.CancelledError))
    monkeypatch.delenv('SCAN_EVIDENCE_PROFILES_FILE', raising=False)
    original = socket.socket

    class LoopbackSocket(original):
        def connect(self, address):
            if self.family in (socket.AF_INET, socket.AF_INET6):
                assert ipaddress.ip_address(address[0]).is_loopback
            return super().connect(address)

        def connect_ex(self, address):
            if self.family in (socket.AF_INET, socket.AF_INET6):
                assert ipaddress.ip_address(address[0]).is_loopback
            return super().connect_ex(address)

    monkeypatch.setattr(socket, 'socket', LoopbackSocket)


@pytest.fixture
async def echo_target(pacing_and_isolation):
    state = {'mode': 'leak', 'calls': [], 'headers': [], 'paths': []}

    async def handler(request):
        if request.method != 'POST':
            return web.Response(status=401, text='Denied fixture GET')
        body = await request.json()
        state['calls'].append(body)
        state['headers'].append(dict(request.headers))
        state['paths'].append(request.raw_path)
        payload = body['messages'][0]['content']
        mode = state['mode']
        if mode.startswith('model'):
            content = body['model']
        elif mode.startswith('credential'):
            content = request.headers.get('Authorization', '')
        elif mode.startswith('url') or mode == 'normalized_url':
            content = request.path
        elif mode == 'automatic_user_agent':
            content = request.headers.get('User-Agent', '')
        elif mode == 'rendered_header':
            content = 'Content-Type: ' + request.headers.get('Content-Type', '')
        elif mode in {'prompt_echo', 'prompt_case'}:
            content = payload
        else:
            content = CANARY.lower() if mode == 'response_case' else CANARY
        if mode.endswith('_case') and mode != 'response_case':
            content = content.upper()
        return web.json_response({'message': {'content': content}})

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}', state
    finally:
        await runner.cleanup()


def fixture_agent(endpoint, case, monkeypatch):
    agent = {'id': 'request-reflection-fixture', 'name': 'Request reflection fixture',
             'type': 'assistant', 'provider': 'ollama', 'model': 'fixture-model',
             'endpoint': endpoint, 'discovery_method': 'fixture', 'metadata': {},
             'system_prompt_canary': CANARY, 'evidence_context_id': 'request-reflection-v1'}
    if case.startswith('model'):
        agent['model'] = PUBLIC_VALUE
        agent['system_prompt_canary'] = PUBLIC_VALUE
    elif case.startswith('credential'):
        monkeypatch.setenv(KEY_ENV, KEY)
        agent.update(api_key_env=KEY_ENV, system_prompt_canary=KEY)
    elif case.startswith('url') or case == 'normalized_url':
        agent['endpoint'] += '/' + ('%73' + PUBLIC_VALUE[1:] if case == 'normalized_url' else PUBLIC_VALUE)
        agent['system_prompt_canary'] = PUBLIC_VALUE
    elif case == 'automatic_user_agent':
        agent['system_prompt_canary'] = SERVER_SOFTWARE
    elif case == 'rendered_header':
        agent['system_prompt_canary'] = 'Content-Type: application/json'
    elif case == 'prompt_case':
        agent['system_prompt_canary'] = PromptInjectionTester().injection_payloads['system_prompt_extraction'][0]
    if case.endswith('_case'):
        agent['system_prompt_canary'] = agent['system_prompt_canary'].upper()
    return agent


def budget():
    return ScanBudget(allowed_networks=('127.0.0.1/32',), allow_loopback=True,
                      max_requests=100, max_response_bytes=65536, request_timeout_seconds=2)


async def pipeline(agent, suite, checkpoints=None):
    async def save(report):
        validate_checkpoint_report(report)
        checkpoints.append(deepcopy(report))

    with scan_transport(budget()):
        return await asyncio.wait_for(run_pipeline(
            None, SecurityTestEngine(prompt_suite=suite), RiskAssessment(), None,
            'security_only', agents=[agent], checkpoint_callback=save if checkpoints is not None else None), 45)


def assert_no_disclosure(report):
    if 'checkpoint' in report:
        validate_checkpoint_report(report, final=True)
    summary, projections = project_report_risk(report)
    assert summary['overall_risk_score'] is None
    assert report['summary']['overall_risk_score'] is None
    for agent in report['agents']:
        assert agent['risk_score'] is None
        assert projections[agent['id']]['risk_score'] is None
        assert not agent['check_evidence']
        assert not any(finding.get('evidence_status') == 'confirmed' for finding in agent['vulnerabilities'])
        assert not any(check['outcome'] in {'confirmed', 'passed'}
                       for check in agent['checks'] if check['rule_id'].startswith('prompt_injection.'))


@pytest.mark.asyncio
@pytest.mark.parametrize('suite', SUITES)
@pytest.mark.parametrize('checkpointed', [False, True])
@pytest.mark.parametrize('case', SHARED_CASES)
async def test_normal_pipeline_reflected_request_material_is_not_disclosure(
        echo_target, monkeypatch, suite, checkpointed, case):
    endpoint, state = echo_target
    state['mode'] = case
    agent = fixture_agent(endpoint, case, monkeypatch)
    checkpoints = [] if checkpointed else None
    try:
        report = await pipeline(agent, suite, checkpoints)
    except PromptSuiteError:
        # The opt-in suite may refuse unsafe explicit configuration before I/O.
        assert suite is not None and not state['calls']
        return
    assert_no_disclosure(report)
    if case in SHARED_CASES and case != 'prompt_echo':
        assert not state['calls']
    for checkpoint in checkpoints or []:
        assert_no_disclosure(checkpoint)


@pytest.mark.asyncio
@pytest.mark.parametrize('checkpointed', [False, True])
@pytest.mark.parametrize('case', BASELINE_CASES)
async def test_baseline_implicit_or_rendered_request_echo_is_unassessed(
        echo_target, monkeypatch, checkpointed, case):
    endpoint, state = echo_target
    state['mode'] = case
    checkpoints = [] if checkpointed else None
    report = await pipeline(fixture_agent(endpoint, case, monkeypatch), None, checkpoints)
    assert_no_disclosure(report)
    for checkpoint in checkpoints or []:
        assert_no_disclosure(checkpoint)


@pytest.mark.asyncio
@pytest.mark.parametrize('case', SHARED_CASES + BASELINE_CASES)
async def test_standalone_real_producer_does_not_confirm_reflection(echo_target, monkeypatch, case):
    endpoint, state = echo_target
    state['mode'] = case
    with scan_transport(budget()), collect_checks() as checks:
        findings = await asyncio.wait_for(
            PromptInjectionTester().test_agent(fixture_agent(endpoint, case, monkeypatch)), 10)
    assert not any(finding.get('evidence_status') == 'confirmed' for finding in findings)
    assert not any(check['outcome'] in {'confirmed', 'passed'} for check in checks)
    assert all('check_evidence_id' not in finding for finding in findings)


@pytest.mark.asyncio
@pytest.mark.parametrize('suite', SUITES)
async def test_standalone_genuine_target_only_marker_keeps_full_sample(echo_target, monkeypatch, suite):
    endpoint, state = echo_target
    agent = fixture_agent(endpoint, 'leak', monkeypatch)
    with scan_transport(budget()), collect_checks() as checks:
        findings = await asyncio.wait_for(PromptInjectionTester(prompt_suite=suite).test_agent(agent), 10)
    assert len(state['calls']) == len(findings) == 35
    assert len(checks) == 7
    assert all(check['outcome'] == 'confirmed' and check['status'] == 'completed'
               and check['requests_attempted'] == check['responses_evaluated'] == 5 for check in checks)
    assert all('check_evidence_id' not in finding for finding in findings)
    assert CANARY not in json.dumps([findings, checks, state['calls'], state['headers'], state['paths']])


@pytest.mark.asyncio
@pytest.mark.parametrize('case', ['model_case', 'credential_case', 'leak'])
async def test_paired_benchmark_uses_same_request_provenance_boundary(echo_target, monkeypatch, case):
    endpoint, state = echo_target
    state['mode'] = case
    agent = fixture_agent(endpoint, case, monkeypatch)
    monkeypatch.setenv(PROFILE_ENV, agent['system_prompt_canary'])
    reference = 'SCAN_BENCHMARK_KEY_REFLECTION_FIXTURE'
    monkeypatch.setenv(reference, KEY)
    config = BenchmarkConfig(
        endpoint=agent['endpoint'], provider=agent['provider'], model=agent['model'],
        evidence_context_id=agent['evidence_context_id'], canary_env=PROFILE_ENV,
        revision='a' * 40, allowed_networks=('127.0.0.1/32',), allow_loopback=True,
        api_key_env=reference if case == 'credential_case' else None, pairs=1,
    )
    try:
        result = await asyncio.wait_for(benchmark(config), 10)
    except BenchmarkError:
        assert case != 'leak' and not state['calls']
        return
    assert result['status'] == 'completed'
    assert len(result['runs']) == 2 and len(state['calls']) == 70
    assert all(run['detected'] is (case == 'leak') for run in result['runs'])
    assert all(run['requests_attempted'] == run['responses_evaluated'] == 35 for run in result['runs'])
    assert agent['system_prompt_canary'] not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('suite', SUITES)
@pytest.mark.parametrize('checkpointed', [False, True])
async def test_genuine_target_only_marker_retains_exact_full_sample_and_private_score(
        echo_target, monkeypatch, suite, checkpointed, caplog):
    endpoint, state = echo_target
    agent = fixture_agent(endpoint, 'leak', monkeypatch)
    checkpoints = [] if checkpointed else None
    report = await pipeline(agent, suite, checkpoints)
    result = report['agents'][0]
    assert len(result['vulnerabilities']) == len(result['check_evidence']) == 35
    checks = [check for check in result['checks'] if check['rule_id'].startswith('prompt_injection.')]
    assert len(checks) == 7
    assert all(check['status'] == 'completed' and check['outcome'] == 'confirmed'
               and check['requests_attempted'] == check['responses_evaluated'] == 5 for check in checks)
    assert result['risk_score'] == project_report_risk(report)[1][result['id']]['risk_score'] == 70
    assert report['summary']['overall_risk_score'] == 70
    expected = PromptInjectionTester(prompt_suite=suite).injection_payloads
    assert [body['messages'][0]['content'] for body in state['calls'][:35]] == [
        payload for values in expected.values() for payload in values[:5]]
    assert CANARY not in json.dumps([state['calls'], state['headers'], state['paths']])
    assert CANARY not in json.dumps([report, checkpoints, to_sarif(report)]) + caplog.text
    if checkpoints:
        assert any(value['agents'][0]['check_evidence'] for value in checkpoints)
        assert any(value['summary']['overall_risk_score'] == 70 for value in checkpoints)


@pytest.mark.asyncio
@pytest.mark.parametrize('suite', SUITES)
async def test_response_marker_matching_remains_case_sensitive(echo_target, monkeypatch, suite):
    endpoint, state = echo_target
    state['mode'] = 'response_case'
    report = await pipeline(fixture_agent(endpoint, 'response_case', monkeypatch), suite)
    assert len(state['calls']) >= 35
    assert_no_disclosure(report)


@pytest.mark.asyncio
@pytest.mark.parametrize('suite', SUITES)
@pytest.mark.parametrize('mode', ['pipeline', 'standalone'])
@pytest.mark.parametrize('fault', ['missing', 'body_limit'])
async def test_actual_http_without_complete_request_provenance_cannot_confirm(
        echo_target, monkeypatch, suite, mode, fault):
    from src.core import request_provenance

    endpoint, state = echo_target
    agent = fixture_agent(endpoint, 'leak', monkeypatch)
    if fault == 'missing':
        monkeypatch.setattr(request_provenance.RequestCapture, 'seal', lambda self, response: None)
    else:
        capture = request_provenance.RequestCapture.sent_chunk

        def limited_capture(self, method, url, chunk):
            # Reduce only private capture capacity, after adapter preflight. The
            # actual request and target response still complete unchanged.
            with monkeypatch.context() as bounds:
                bounds.setattr(request_provenance, 'MAX_REQUEST_BODY', 1)
                capture(self, method, url, chunk)

        monkeypatch.setattr(request_provenance.RequestCapture, 'sent_chunk', limited_capture)
    if mode == 'pipeline':
        checkpoints = []
        report = await pipeline(agent, suite, checkpoints)
        assert_no_disclosure(report)
        for checkpoint in checkpoints:
            assert_no_disclosure(checkpoint)
    else:
        with scan_transport(budget()), collect_checks() as checks:
            findings = await asyncio.wait_for(PromptInjectionTester(prompt_suite=suite).test_agent(agent), 10)
        assert not any(finding.get('evidence_status') == 'confirmed' for finding in findings)
        assert not any(check['outcome'] in {'passed', 'confirmed'} for check in checks)
    assert len(state['calls']) >= 35


def profile_document(agent):
    return {'schema_version': '1.0', 'profiles': {'reflection-fixture': {
        'organization_id': 'local-beta-operator', 'endpoint': agent['endpoint'],
        'provider': agent['provider'], 'model': agent['model'],
        'evidence_context_id': 'request-reflection-v1', 'system_prompt_canary_env': PROFILE_ENV,
    }}}


@pytest.mark.parametrize('marker', [SERVER_SOFTWARE, 'Content-Type: application/json'])
def test_cli_marker_admission_is_distinct_from_server_profile_grammar(tmp_path, monkeypatch, marker):
    agent = fixture_agent('http://127.0.0.1:12345', 'leak', monkeypatch)
    agent['system_prompt_canary'] = marker
    path = tmp_path / 'synthetic-targets.json'
    path.write_text(json.dumps({'agents': [agent]}))
    _, loaded = load_targets((), (), config=str(path), allow_loopback=True)
    assert loaded[0]['system_prompt_canary'] == marker
    monkeypatch.setenv(PROFILE_ENV, marker)
    with pytest.raises(EvidenceProfileError):
        EvidenceProfiles.from_document(profile_document(agent))


@pytest.mark.parametrize('suite', SUITES)
def test_real_profile_api_model_echo_cannot_become_confirmed_risk(real_lab, monkeypatch, tmp_path, suite):
    module, client, operator_key, calls, _, _ = real_lab
    import tests.test_beta_lab_workflow as lab

    monkeypatch.setattr(lab, 'PRIVATE_OUTPUT', lambda body, headers: body['model'].upper())
    monkeypatch.setattr(module.security_engine, 'prompt_tester', PromptInjectionTester())
    fixture_timeout = 45
    monkeypatch.setitem(module.app.config, 'SCAN_TIMEOUT_SECONDS', fixture_timeout)
    login = client.post('/api/auth/token', json={'api_key': operator_key})
    assert login.status_code == 200
    headers = {'Authorization': 'Bearer ' + login.json['token']}

    def request(method, path, definition=None):
        module.db.session.remove()
        return client.open(path, method=method, headers=headers, json=definition)

    def finish(identifier):
        deadline = time.monotonic() + fixture_timeout + 5
        while time.monotonic() < deadline:
            state = request('GET', f'/api/scans/{identifier}/status')
            assert state.status_code == 200
            if state.json['status'] in module.TERMINAL_STATES:
                assert state.json['status'] in {'completed', 'partial'}
                response = request('GET', f'/api/scans/{identifier}/report?format=json')
                assert response.status_code == 200
                return response.json
            time.sleep(0.02)
        pytest.fail('Owned reflection workflow exceeded its test deadline')

    created = request('POST', '/api/scans', {'scan_type': 'discovery_only', 'target_scope': {
        'network_ranges': ['127.0.0.1/32']}})
    assert created.status_code == 202
    source_id = created.json['scan_id']
    source = finish(source_id)
    assert len(source['agents']) == 1
    agent = {**source['agents'][0], 'model': lab.MODEL}
    monkeypatch.setenv(PROFILE_ENV, lab.MODEL.upper())
    private = tmp_path / 'private-reflection-profiles.json'
    private.write_text(json.dumps(profile_document(agent)))
    private.chmod(0o600)
    registry = load_evidence_profiles(str(private))
    monkeypatch.setattr(module, '_evidence_profiles', registry)
    definition = {'scan_type': 'security_only', 'scan_config': {
        'source_scan_id': source_id, 'model_overrides': {agent['id']: lab.MODEL},
        'evidence_profiles': {agent['id']: 'reflection-fixture'},
    }}
    if suite is not None:
        definition['scan_config']['prompt_suite'] = suite
    admitted = request('POST', '/api/scans', definition)
    if suite is not None:
        assert admitted.status_code == 400
        assert admitted.json == {'success': False, 'error': str(PromptSuiteError())}
        assert not any(method == 'POST' for method, _, _ in calls)
        assert request('GET', f'/api/scans/{source_id}/report?format=json').json == source
        return
    assert admitted.status_code == 202
    assessed_id = admitted.json['scan_id']
    assessed = finish(assessed_id)
    assert_no_disclosure(assessed)
    projected = request('GET', f'/api/scans/{assessed_id}/results')
    assert projected.status_code == 200
    assert projected.json['results']['summary']['overall_risk_score'] is None
    assert all(item['risk_score'] is None for item in projected.json['results']['agents'])
    assert request('GET', f'/api/scans/{source_id}/report?format=json').json == source
    assert lab.MODEL.upper() not in json.dumps([assessed, projected.json])
