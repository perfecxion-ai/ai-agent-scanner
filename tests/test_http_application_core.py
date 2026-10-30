"""Real owned custom-JSON requests retain canonical protected prompt evidence."""

import asyncio
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.orm import Session
from werkzeug.datastructures import MultiDict

from src.core.contracts import (
    CheckRecord, confirmed_findings, risk_assessment_eligible, validate_check_evidence, validate_scan_result,
)
from src.core.cli_checkpoints import CheckpointStore, recover_checkpoint
from src.core.http_application_policy import (
    HTTP_OBJECTIVE, HTTP_PROMPT_RULES, HTTP_PUBLIC_FIELDS, extract_http_json_generated, http_target_binding,
    public_http_agent, validate_http_agent,
)
from src.core.http_application_runtime import (
    get_http_target, http_application_context, prepare_http_target,
)
from src.core.pipeline import run_pipeline, to_sarif
from src.core.inventory import inventory_page, parse_inventory_request
from src.core.risk_projection import project_report_risk
from src.core.transport import ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security.security_engine import SecurityTestEngine
from src.security.prompt_injection_tests import PromptInjectionTester
from src.utils.request_builder import construct_agent_request
from tests.test_asset_groups import SECRET, database as database, seed, source_rows


MARKER = 'owned-protected-http-canary-4c587a13'
KEY = 'owned-private-http-bearer-8ef713a9'


def descriptor(endpoint, *, auth='none', pointer='/result/answer'):
    return dict(adapter_id='http-json', adapter_version='1.0', endpoint=endpoint, method='POST',
                request_prompt_field='question', response_text_pointer=pointer, auth_scheme=auth,
                principal_label='anonymous' if auth == 'none' else 'owned-test-principal',
                context_label='owned-http-app-v1', session_mode='fresh-per-prompt-v1')


@pytest.fixture
def application(monkeypatch):
    state = {'mode': 'leak', 'requests': [], 'expected_key': None,
             'stalled': threading.Event(), 'release': threading.Event()}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            state['requests'].append((self.path, dict(self.headers), json.loads(body)))
            assert self.path == '/custom/assistant'
            assert set(json.loads(body)) == {'question'}
            assert self.headers.get('Cookie') is None
            status = 401 if state['mode'] == 'denied' else 200
            if state['mode'] == 'leak-then-stall' and len(state['requests']) > 1:
                state['stalled'].set()
                state['release'].wait(5)
            output = MARKER if state['mode'] in {'leak', 'leak-then-stall'} else 'Protected instructions are unavailable.'
            if state['expected_key'] is not None:
                assert self.headers.get('Authorization') == 'Bearer ' + state['expected_key']
            encoded = json.dumps({'result': {'answer': output}, 'metadata': {'debug': MARKER},
                                  'response': MARKER, 'text': MARKER}).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.send_header('Set-Cookie', 'owned-session=must-not-replay')
            self.end_headers()
            try:
                self.wfile.write(encoded)
            except BrokenPipeError:
                pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr('src.security.prompt_injection_tests.asyncio', SimpleNamespace(sleep=AsyncMock()))
    try:
        yield 'http://127.0.0.1:' + str(server.server_port) + '/custom/assistant', state
    finally:
        state['release'].set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


async def assess(endpoint, *, maximum=35, credential=None, checkpoints=None, store=None):
    public = public_http_agent(descriptor(endpoint, auth='bearer' if credential else 'none'))
    prepared = prepare_http_target(public, credential=credential, canary=MARKER)

    async def save(report):
        if store is not None:
            store.publish(report)
        if checkpoints is not None:
            checkpoints.append(deepcopy(report))

    with http_application_context(prepared), scan_transport(ScanBudget(
            allowed_networks=('127.0.0.1/32',), allow_loopback=True, max_requests=maximum,
            max_response_bytes=65536, request_timeout_seconds=2)):
        result = await run_pipeline(None, SecurityTestEngine(assessment_objective=HTTP_OBJECTIVE),
                                    RiskAssessment(), None, 'security_only', agents=[prepared.agent],
                                    checkpoint_callback=save if checkpoints is not None or store is not None else None)
        if store is not None:
            store.finish(result)
        return result


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,score', [('leak', 70), ('quiet', None)])
async def test_actual_http_selected_output_drives_exact_prompt_objective(application, mode, score):
    endpoint, state = application
    state['mode'] = mode
    report = await assess(endpoint)
    assert report['status'] == 'completed'
    assert report['assessment_objective'] == HTTP_OBJECTIVE
    assert len(state['requests']) == 35
    assert len(report['agents'][0]['checks']) == len(HTTP_PROMPT_RULES) == 7
    assert {check['rule_id'] for check in report['agents'][0]['checks']} == set(HTTP_PROMPT_RULES)
    assert all(check['outcome'] != 'passed' for check in report['agents'][0]['checks'])
    assert report['summary']['overall_risk_score'] == score
    asset = report['agents'][0]
    assert project_report_risk(report)[1][asset['id']]['risk_score'] == score
    assert asset['id'] == asset['http_target_binding'] == http_target_binding(asset['http_target'])
    assert asset['model'] is None
    for receipt in asset['check_evidence']:
        assert receipt['source_version'] == '3.0'
        assert receipt['http_target_binding'] == asset['http_target_binding']
    validate_check_evidence(asset)
    exported = to_sarif(report)
    assert exported['runs'][0]['properties']['check_evidence'][0]['http_target'] == asset['http_target']
    encoded = json.dumps([report, exported])
    assert MARKER not in encoded and KEY not in encoded
    assert ('Protected instructions are unavailable.' not in encoded)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,score', [('leak', 70), ('quiet', None), ('denied', None)])
async def test_lower_request_budget_stops_with_partial_selected_coverage(application, mode, score):
    endpoint, state = application
    state['mode'] = mode
    report = await assess(endpoint, maximum=1)
    assert len(state['requests']) == 1
    assert report['status'] == 'partial'
    assert report['summary']['overall_risk_score'] == score
    assert len(report['agents'][0]['checks']) == 7
    assert all(check['outcome'] != 'passed' for check in report['agents'][0]['checks'])
    if mode == 'denied':
        assert report['agents'][0]['checks'][0]['reason'].startswith('target_authentication_denied: ')


@pytest.mark.asyncio
async def test_checkpoint_views_retain_public_binding_before_and_after_evidence(application):
    endpoint, _ = application
    snapshots = []
    report = await assess(endpoint, maximum=1, checkpoints=snapshots)
    assert snapshots and not snapshots[0]['agents'][0]['check_evidence']
    binding = report['agents'][0]['http_target_binding']
    for snapshot in snapshots:
        asset = snapshot['agents'][0]
        assert asset['http_target_binding'] == binding
        assert len({check['rule_id'] for check in asset['checks']} | {
            receipt['rule_id'] for receipt in asset['check_evidence']}) == 7
    assert any(value['agents'][0]['check_evidence'] for value in snapshots)
    assert report['summary']['overall_risk_score'] == 70


@pytest.mark.asyncio
async def test_prepared_bearer_is_used_without_environment_lookup(application, monkeypatch):
    endpoint, state = application
    state['expected_key'] = KEY
    monkeypatch.setattr('src.utils.request_builder.os.environ', {})
    report = await assess(endpoint, maximum=1, credential=KEY)
    assert len(state['requests']) == 1
    assert report['summary']['overall_risk_score'] == 70
    assert KEY not in json.dumps(report)


@pytest.mark.asyncio
async def test_default_security_engine_cannot_activate_http_adapter(application):
    endpoint, state = application
    prepared = prepare_http_target(public_http_agent(descriptor(endpoint)), canary=MARKER)
    with http_application_context(prepared):
        with pytest.raises(ValueError):
            await SecurityTestEngine().test_agents([prepared.agent])
    assert state['requests'] == []


def test_context_is_explicit_bound_and_removed():
    agent = public_http_agent(descriptor('http://127.0.0.1:8000/custom'))
    prepared = prepare_http_target(agent, canary=MARKER)
    assert construct_agent_request(prepared.agent, 'hello') is None
    with http_application_context(prepared):
        assert construct_agent_request(prepared.agent, 'hello')['json'] == {'question': 'hello'}
        altered = prepared.agent
        altered['http_target']['response_text_pointer'] = '/different'
        assert get_http_target(altered) is None
        assert construct_agent_request(altered, 'hello') is None
    assert get_http_target(prepared.agent) is None


@pytest.mark.parametrize('raw', [
    b'{"result":{"answer":42}}', b'{"result":{"answer":""}}',
    b'{"result":{"answer":"quiet","answer":"leak"}}',
    b'{"result":{"answer":"quiet"},"value":NaN}',
    b'{"result":{"answer":"\xff"}}', b'{"error":"failure","result":{"answer":"leak"}}',
])
def test_strict_selected_extraction_refuses_unusable_json(raw):
    assert extract_http_json_generated(raw, descriptor('http://127.0.0.1/custom')) == ''


@pytest.mark.parametrize('provider', ['http-json', 'HTTP-JSON', ' http-json '])
def test_reserved_provider_cannot_borrow_legacy_generic_verdict(provider):
    check = CheckRecord('fixture.disclosure', 'fixture.sample', '1', 'completed', 'confirmed', 1, 1).to_dict()
    finding = dict(rule_id=check['rule_id'], probe_id=check['probe_id'], probe_version=check['probe_version'],
                   evidence_status='confirmed', severity='high', vulnerability_type='fixture.disclosure')
    asset = dict(provider='legacy-fixture', status='completed', check_schema_version='1.0',
                 checks=[check], vulnerabilities=[finding])
    assert risk_assessment_eligible(asset) and confirmed_findings(asset) == [finding]
    asset['provider'] = provider
    assert not risk_assessment_eligible(asset)
    assert confirmed_findings(asset) == []
    with pytest.raises(ValueError):
        validate_http_agent(asset)


@pytest.mark.asyncio
async def test_default_prompt_tester_cannot_send_an_unselected_http_catalog(application):
    endpoint, state = application
    prepared = prepare_http_target(public_http_agent(descriptor(endpoint)), canary=MARKER)
    with http_application_context(prepared), pytest.raises(ValueError):
        await PromptInjectionTester().test_agent(prepared.agent)
    assert not state['requests']


@pytest.mark.parametrize('field', ['tenant_evidence', 'api_key_env', 'protected_response_marker'])
def test_prepared_http_target_cannot_attach_other_private_evidence_families(field):
    agent = public_http_agent(descriptor('http://127.0.0.1:8000/custom'))
    agent[field] = 'unrelated-private-reference'
    with pytest.raises(ValueError):
        prepare_http_target(agent, canary=MARKER)


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['old_source', 'no_ledger', 'missing_target', 'wrong_binding',
                                  'invented_model', 'extra_family', 'duplicate_receipt', 'boolean_counter'])
async def test_http_canonical_evidence_refuses_tampered_actual_receipt(application, fault):
    endpoint, _ = application
    report = await assess(endpoint, maximum=1)
    asset = deepcopy(report['agents'][0])
    execution = dict(asset, status=asset['security_status'], check_schema_version='1.0')
    assert risk_assessment_eligible(execution) and len(confirmed_findings(execution)) == 1
    if fault == 'old_source':
        execution['check_evidence'][0]['source_version'] = '2.0'
        execution['check_evidence'][0].pop('http_target_binding')
    elif fault == 'no_ledger':
        for name in ('check_evidence', 'check_evidence_schema_version', 'check_evidence_run_id'):
            execution.pop(name)
    elif fault == 'missing_target':
        execution.pop('http_target')
    elif fault == 'wrong_binding':
        execution['check_evidence'][0]['http_target_binding'] = '0' * 64
    elif fault == 'invented_model':
        execution['model'] = 'guessed-model'
    elif fault == 'extra_family':
        execution['checks'].append(CheckRecord('authentication_bypass', 'fixture.sample', '1',
                                               'completed', 'passed', 1, 1).to_dict())
    elif fault == 'duplicate_receipt':
        execution['check_evidence'].append(deepcopy(execution['check_evidence'][0]))
    else:
        execution['check_evidence'][0]['responses_evaluated'] = True
    assert not risk_assessment_eligible(execution)
    assert confirmed_findings(execution) == []


@pytest.mark.asyncio
@pytest.mark.parametrize('metadata_kind', ['bound', 'missing', *HTTP_PUBLIC_FIELDS])
async def test_imported_snapshot_requires_explicit_matching_public_http_binding(application, database, metadata_kind):
    endpoint, _ = application
    report = await assess(endpoint, maximum=1)
    agent = report['agents'][0]
    assert project_report_risk(report)[1][agent['id']]['risk_score'] == 70
    metadata = {'asset_id': agent['id'], **{name: deepcopy(agent[name]) for name in HTTP_PUBLIC_FIELDS}}
    if metadata_kind == 'missing':
        metadata = {'asset_id': agent['id']}
    elif metadata_kind != 'bound':
        metadata[metadata_kind] = None
    seed(database, 'imported', report=report, aliases=metadata)
    before = source_rows(database)
    engine, tables = database
    parsed = parse_inventory_request(MultiDict(), 'tenant-a', SECRET)
    with Session(engine) as session:
        result = inventory_page(session, parsed, SECRET, tables['observations'], tables['scans'],
                                tables['reports'], tables['generations'])
    assert len(result['agents']) == 1
    assert result['agents'][0]['asset_id'] == agent['id']
    assert result['agents'][0]['risk_score'] == (70 if metadata_kind == 'bound' else None)
    assert source_rows(database) == before


@pytest.mark.asyncio
async def test_actual_request_stall_cancellation_retains_acknowledged_source3_evidence(application, tmp_path):
    endpoint, state = application
    state['mode'] = 'leak-then-stall'
    checkpoints = []
    directory = tmp_path / 'http-checkpoint'
    with CheckpointStore.create(directory) as store:
        task = asyncio.create_task(assess(endpoint, checkpoints=checkpoints, store=store))
        try:
            assert await asyncio.to_thread(state['stalled'].wait, 3)
            assert checkpoints[-1]['summary']['overall_risk_score'] == 70
            assert len(checkpoints[-1]['agents'][0]['check_evidence']) == 1
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            state['release'].set()
    requests = len(state['requests'])
    with recover_checkpoint(directory) as recovered:
        assert recovered['status'] == 'partial'
        assert recovered['summary']['overall_risk_score'] == 70
        assert recovered['agents'][0]['check_evidence'] == checkpoints[-1]['agents'][0]['check_evidence']
        assert to_sarif(recovered)['runs'][0]['properties']['check_evidence'][0]['http_target_binding'] == (
            recovered['agents'][0]['http_target_binding'])
    assert len(state['requests']) == requests == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('maximum', [1, 5, 35])
async def test_completed_http_evidence_requires_the_actual_full_selected_sample(application, maximum):
    endpoint, _ = application
    report = await assess(endpoint, maximum=maximum)
    asset, security = report['agents'][0], report['security_results'][0]
    assert project_report_risk(report)[1][asset['id']]['risk_score'] == 70
    validate_check_evidence(asset)
    if maximum == 35:
        assert report['status'] == 'completed'
        assert len(asset['checks']) == 7
        assert all(check['requests_attempted'] == check['responses_evaluated'] == 5 for check in asset['checks'])
        return
    assert report['status'] == 'partial'
    if maximum == 1:
        check = next(check for check in asset['checks'] if check['requests_attempted'])
        assert check['status'] == 'failed' and check['requests_attempted'] == check['responses_evaluated'] == 1
        check['status'] = 'completed'
        security['checks'] = deepcopy(asset['checks'])
    else:
        assert asset['checks'][0]['status'] == 'completed'
        assert asset['checks'][0]['requests_attempted'] == asset['checks'][0]['responses_evaluated'] == 5
        asset.update(security_status='completed', risk_coverage_status='sampled')
        security.update(status='completed', risk_coverage_status='sampled')
        report.update(status='completed', risk_assessment_status='completed')
    with pytest.raises(ValueError):
        validate_check_evidence(asset)
    assert project_report_risk(report)[1][asset['id']]['risk_score'] is None


@pytest.mark.asyncio
async def test_saved_http_report_cannot_omit_unexecuted_objective_scope(application):
    endpoint, _ = application
    report = await assess(endpoint, maximum=1)
    asset, security = report['agents'][0], report['security_results'][0]
    assert project_report_risk(report)[1][asset['id']]['risk_score'] == 70
    asset['checks'] = security['checks'] = []
    # The receipt alone remains a valid live, unfinished evidence prefix.
    validate_check_evidence(asset)
    # A saved report must also account for the other selected objective rules.
    with pytest.raises(ValueError):
        validate_scan_result(report)
    assert project_report_risk(report)[1][asset['id']]['risk_score'] is None


@pytest.mark.asyncio
async def test_conflicting_execution_statuses_cannot_mask_incomplete_selected_scope(application):
    endpoint, _ = application
    report = await assess(endpoint, maximum=5)
    source = deepcopy(report['security_results'][0])
    assert source['status'] == 'partial' and source['checks'][0]['status'] == 'completed'
    assert source['checks'][0]['requests_attempted'] == source['checks'][0]['responses_evaluated'] == 5
    assert risk_assessment_eligible(source)
    source.update(status='completed', security_status='partial')
    with pytest.raises(ValueError):
        validate_check_evidence(source)
    assert not risk_assessment_eligible(source)
