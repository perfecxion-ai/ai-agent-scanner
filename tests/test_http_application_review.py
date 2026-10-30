"""Independent strict-output, provenance and compatibility controls for HTTP apps."""

import asyncio
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from yarl import URL

from src.core.contracts import risk_assessment_eligible, validate_check_evidence
from src.core.http_application_policy import (
    extract_http_json_generated, http_json_request_matches_capture, http_target_binding,
    public_http_agent, validate_http_public_privacy,
)
from src.core.http_application_runtime import (
    get_http_target, http_application_context, prepare_http_target,
)
from src.core.pipeline import run_pipeline
from src.core.request_provenance import RequestEvidence, request_excludes_canary
from src.core.risk_projection import project_report_risk
from src.core.transport import ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security.security_engine import SecurityTestEngine
from tests.legacy_observation_fixtures import legacy_archive, legacy_report
from tests.test_api_risk_projection import report as synthetic_legacy_policy_claim


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/acceptance-http-assessment.py'
SPEC = importlib.util.spec_from_file_location('independent_http_acceptance', SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
MARKER = 'owned-independent-http-canary-b13df98476'
KEY = 'owned-independent-http-key-c94a57183e'


def descriptor(**changes):
    value = gate.descriptor('https://app.example.test/custom/infer')
    value.update(changes)
    return value


@pytest.mark.parametrize('pointer,body,expected', [
    ('/answer/text', {'answer': {'text': MARKER}, 'metadata': 'quiet'}, MARKER),
    ('/answer/text', {'answer': {'text': 'quiet'}, 'response': MARKER, 'metadata': MARKER}, 'quiet'),
    ('/answer/text', {'choices': [{'message': {'content': MARKER}}]}, ''),
    ('/answer/text', {'answer': {'text': MARKER}, 'error': None}, MARKER),
    ('/answer/text', {'answer': {'text': MARKER}, 'error': 'unavailable'}, ''),
    ('/answer/text', {'answer': {'text': MARKER}, 'error': False}, ''),
    ('/answer/text', {'answer': {'text': MARKER}, 'error': 0}, ''),
    ('/0/answer', [{'answer': MARKER}], MARKER),
    ('/a~1b/~0/0', {'a/b': {'~': [MARKER]}}, MARKER),
    ('/', {'': MARKER}, MARKER),
    ('/items/01', {'items': [MARKER]}, ''),
    ('/items/-', {'items': [MARKER]}, ''),
    ('/items/1', {'items': [MARKER]}, ''),
    ('/items/01', {'items': {'01': MARKER}}, MARKER),
    ('/answer/text', {'answer': {'text': None}}, ''),
    ('/answer/text', {'answer': {'text': 70}}, ''),
    ('/answer/text', {'answer': {'text': ['text', MARKER]}}, ''),
    ('/answer/text', {'answer': {'text': ' \n\t'}}, ''),
])
def test_selected_generated_output_is_the_only_response_oracle(pointer, body, expected):
    raw = json.dumps(body).encode()
    assert extract_http_json_generated(raw, descriptor(response_text_pointer=pointer)) == expected


@pytest.mark.parametrize('raw', [
    b'{"answer":{"text":"quiet","text":"leak"}}',
    b'{"answer":{"text":"quiet"},"answer":{"text":"leak"}}',
    b'{"answer":{"text":"leak"},"metadata":{"unused":1,"unused":2}}',
    b'{"answer":{"text":"leak"},"metadata":NaN}',
    b'{"answer":{"text":"leak"},"metadata":Infinity}',
    b'{"answer":{"text":"leak"},"metadata":1e10000}',
    b'{"answer":{"text":"leak"},"metadata":-1e10000}',
    b'{"answer":{"text":"leak"},"metadata":"\xff"}',
    b'{"answer":{"text":"leak"}} trailing',
    b'leak',
])
def test_invalid_json_cannot_confirm_even_when_the_selected_string_looks_valid(raw):
    assert extract_http_json_generated(raw, descriptor()) == ''


@pytest.mark.parametrize('pointer', ['', '#/answer', '/a~2b', '/a~', '/a/' * 9, '/' + 'x' * 256])
def test_response_pointer_has_no_implicit_fallback_or_expression_semantics(pointer):
    assert extract_http_json_generated(json.dumps({'answer': MARKER}).encode(),
                                       descriptor(response_text_pointer=pointer)) == ''


@pytest.mark.parametrize('kind', ['depth', 'nodes', 'bytes'])
def test_generated_output_parsing_respects_finite_work_limits(monkeypatch, kind):
    from src.core import http_application_policy as policy
    body = {'answer': {'text': MARKER}}
    if kind == 'depth':
        nested = None
        for _ in range(20):
            nested = [nested]
        body['metadata'] = nested
    elif kind == 'nodes':
        body['metadata'] = [0] * 9000
    else:
        monkeypatch.setattr(policy, 'MAX_RESPONSE_BYTES', 128)
        body['metadata'] = 'x' * 256
    assert extract_http_json_generated(json.dumps(body).encode(), descriptor()) == ''


@pytest.mark.parametrize('field,replacement', [
    ('endpoint', 'https://app.example.test/different'), ('request_prompt_field', 'message'),
    ('response_text_pointer', '/different'), ('principal_label', 'another-operator'),
    ('context_label', 'another-fixture'),
])
def test_public_binding_changes_with_application_semantics_without_secret_input(field, replacement):
    original = descriptor(auth_scheme='bearer', principal_label='owned-principal')
    altered = dict(original, **{field: replacement})
    assert http_target_binding(original) != http_target_binding(altered)
    agent = public_http_agent(original)
    prepared = prepare_http_target(agent, credential=KEY, canary=MARKER)
    other = prepare_http_target(agent, credential=KEY + '-rotated', canary=MARKER + '-rotated')
    assert prepared.agent['id'] == other.agent['id'] == agent['http_target_binding']
    assert MARKER not in repr(prepared) and KEY not in repr(prepared)


@pytest.mark.parametrize('public', [
    {'request_prompt_field': MARKER}, {MARKER: 'ordinary-value'},
    {'nested': ({MARKER.upper(): 'ordinary'},)},
])
def test_public_key_and_nested_descriptor_collisions_are_rejected_before_redaction(public):
    with pytest.raises(ValueError):
        validate_http_public_privacy(public, [MARKER])


def request_evidence(agent, *, credential=None, payload='owned probe'):
    raw = json.dumps({'question': payload}).encode()
    url = str(URL(agent['endpoint']))
    headers = [('Host', URL(url).raw_authority), ('Content-Type', 'application/json'),
               ('Content-Length', str(len(raw)))]
    if credential:
        headers.append(('Authorization', 'Bearer ' + credential))
    return RequestEvidence('POST', url, tuple(headers), raw)


@pytest.mark.parametrize('fault', [
    'method', 'path', 'payload', 'extra-body', 'duplicate-body', 'credential',
    'cookie', 'extra-header', 'duplicate-header', 'host',
])
def test_actual_outbound_capture_must_match_the_prepared_adapter(fault):
    agent = public_http_agent(descriptor(auth_scheme='bearer', principal_label='owned-principal'))
    original = request_evidence(agent, credential=KEY)
    assert http_json_request_matches_capture(original, agent, 'owned probe', KEY)
    fields = {name: getattr(original, name) for name in ('method', 'url', 'headers', 'body')}
    if fault == 'method':
        fields['method'] = 'GET'
    elif fault == 'path':
        fields['url'] += '/different'
    elif fault == 'payload':
        fields['body'] = b'{"question":"different probe"}'
    elif fault == 'extra-body':
        fields['body'] = b'{"question":"owned probe","system":"extra"}'
    elif fault == 'duplicate-body':
        fields['body'] = b'{"question":"wrong","question":"owned probe"}'
    elif fault == 'credential':
        fields['headers'] = tuple((name, value + '-different' if name == 'Authorization' else value)
                                  for name, value in original.headers)
    elif fault == 'host':
        fields['headers'] = tuple((name, 'different.example.test' if name == 'Host' else value)
                                  for name, value in original.headers)
    else:
        fields['headers'] += {'cookie': (('Cookie', 'session=unrecognized'),),
                              'extra-header': (('X-Unknown-Credential', KEY),),
                              'duplicate-header': (('authorization', 'Bearer ' + KEY),)}[fault]
    assert not http_json_request_matches_capture(RequestEvidence(**fields), agent, 'owned probe', KEY)


def test_complete_automatic_header_reflection_fails_canary_provenance():
    agent = public_http_agent(descriptor())
    evidence = request_evidence(agent)
    assert http_json_request_matches_capture(evidence, agent, 'owned probe', None)
    assert request_excludes_canary(evidence, MARKER)
    reflected = RequestEvidence(evidence.method, evidence.url,
                                evidence.headers + (('User-Agent', MARKER.swapcase()),), evidence.body)
    assert http_json_request_matches_capture(reflected, agent, 'owned probe', None)
    assert not request_excludes_canary(reflected, MARKER)


@pytest.mark.parametrize('header', ['User-Agent', 'Accept'])
def test_actual_transport_added_canary_header_cannot_confirm(tmp_path, header):
    import aiohttp
    tmp_path.chmod(0o700)
    original = aiohttp.ClientSession
    def session(*args, **kwargs):
        kwargs['headers'] = {header: MARKER.swapcase(), **kwargs.get('headers', {})}
        return original(*args, **kwargs)
    with gate.targets(tmp_path, MARKER, 'owned-cookie-never-returned') as fixture, patch(
            'src.security.prompt_injection_tests.asyncio', SimpleNamespace(sleep=AsyncMock())):
        endpoint = fixture['http'] + '/custom/leak/infer'
        positive = asyncio.run(actual_assessment(endpoint))
        assert positive['summary']['overall_risk_score'] == 70
        with patch('src.core.transport.aiohttp.ClientSession', session):
            reflected = asyncio.run(actual_assessment(endpoint))
        assert len(fixture['calls']['leak']) == 2
        assert fixture['calls']['leak'][-1]['user_agent' if header == 'User-Agent' else 'accept'] == MARKER.swapcase()
        assert reflected['summary']['overall_risk_score'] is None
        assert not reflected['agents'][0]['check_evidence']
        assert not reflected['agents'][0]['vulnerabilities']


async def actual_assessment(endpoint, *, maximum=1, checkpoints=None):
    agent = public_http_agent(gate.descriptor(endpoint))
    prepared = prepare_http_target(agent, canary=MARKER)
    with http_application_context(prepared), scan_transport(ScanBudget(
            allowed_networks=('127.0.0.1/32',), allow_loopback=True, max_requests=maximum,
            request_timeout_seconds=2, max_response_bytes=65536)):
        async def save(document):
            if checkpoints is not None:
                checkpoints.append(deepcopy(document))
        return await run_pipeline(None, SecurityTestEngine(assessment_objective=gate.OBJECTIVE),
                                  RiskAssessment(), None, 'security_only', agents=[prepared.agent],
                                  checkpoint_callback=save if checkpoints is not None else None)


@pytest.fixture(scope='module')
def genuine_http_run(tmp_path_factory):
    directory = tmp_path_factory.mktemp('independent-http-source').resolve()
    directory.chmod(0o700)
    with gate.targets(directory, MARKER, 'owned-cookie-never-returned') as fixture, patch(
            'src.security.prompt_injection_tests.asyncio', SimpleNamespace(sleep=AsyncMock())):
        checkpoints = []
        report = asyncio.run(actual_assessment(fixture['http'] + '/custom/leak/infer', checkpoints=checkpoints))
        assert report['summary']['overall_risk_score'] == 70
        assert len(fixture['calls']['leak']) == 1
        assert len(report['agents'][0]['check_evidence']) == 1
        validate_check_evidence(report['agents'][0])
        assert any(value['agents'][0]['check_evidence'] for value in checkpoints)
        complete = asyncio.run(actual_assessment(fixture['http'] + '/custom/leak/infer', maximum=35))
        assert len(fixture['calls']['leak']) == 36
        assert complete['status'] == 'completed' and complete['summary']['overall_risk_score'] == 70
        assert len(complete['agents'][0]['check_evidence']) == 35
        assert len(complete['agents'][0]['checks']) == 7
        assert all(value['status'] == 'completed' and value['requests_attempted'] == value['responses_evaluated'] == 5
                   for value in complete['agents'][0]['checks'])
        validate_check_evidence(complete['agents'][0])
        category = asyncio.run(actual_assessment(fixture['http'] + '/custom/leak/infer', maximum=5))
        assert len(fixture['calls']['leak']) == 41
        assert category['status'] == 'partial' and category['summary']['overall_risk_score'] == 70
        assert sum(value['status'] == 'completed' for value in category['agents'][0]['checks']) == 1
        validate_check_evidence(category['agents'][0])
        return report, checkpoints, complete, category


@pytest.fixture(scope='module')
def genuine_http_report(genuine_http_run):
    return genuine_http_run[0]


@pytest.mark.parametrize('field,value', [
    ('id', []), ('finding_id', []), ('source_version', '2.0'), ('source_version', 'future'),
    ('http_target_binding', '0' * 64), ('sample_index', True), ('sequence', True),
    ('request_ordinal', True), ('requests_attempted', 6), ('responses_evaluated', 0),
    ('evidence_context_id', 'different-context'), ('rule_id', 'authentication_bypass'),
])
def test_changed_receipt_cannot_borrow_a_genuine_prior_confirmation(genuine_http_report, field, value):
    document = deepcopy(genuine_http_report)
    asset = document['agents'][0]
    asset['check_evidence'][0][field] = value
    document['security_results'][0]['check_evidence'] = deepcopy(asset['check_evidence'])
    with pytest.raises(ValueError):
        validate_check_evidence(asset)
    assert project_report_risk(document)[1][asset['id']]['risk_score'] is None


@pytest.mark.parametrize('fault', ['duplicate-receipt', 'duplicate-finding', 'extra-family', 'unknown-field',
                                 'missing-ledger', 'old-ledger'])
def test_complete_http_ledger_rejects_malformed_extensions_before_selecting_findings(genuine_http_report, fault):
    document = deepcopy(genuine_http_report)
    asset = document['agents'][0]
    if fault == 'duplicate-receipt':
        asset['check_evidence'].append(deepcopy(asset['check_evidence'][0]))
    elif fault == 'duplicate-finding':
        asset['vulnerabilities'].append(deepcopy(asset['vulnerabilities'][0]))
    elif fault == 'extra-family':
        asset['checks'].append(dict(asset['checks'][-1], rule_id='authentication_bypass'))
    elif fault == 'unknown-field':
        asset['check_evidence'][0]['unknown_source_field'] = 'cannot silently partition away'
    elif fault == 'missing-ledger':
        asset.pop('check_evidence_schema_version')
        asset.pop('check_evidence')
    else:
        asset['check_evidence_schema_version'] = '2.0'
    document['security_results'][0].update({key: deepcopy(asset[key]) for key in (
        'checks', 'vulnerabilities', 'check_evidence', 'check_evidence_schema_version') if key in asset})
    assert project_report_risk(document)[1][asset['id']]['risk_score'] is None


@pytest.mark.parametrize('view', ['agent', 'security'])
@pytest.mark.parametrize('field', ['http_target', 'http_target_binding', 'assessment_objective',
                                 'assessment_contract_version', 'evidence_context_id'])
def test_public_view_binding_changes_withhold_current_risk(genuine_http_report, view, field):
    document = deepcopy(genuine_http_report)
    selected = document['agents'][0] if view == 'agent' else document['security_results'][0]
    if field == 'http_target':
        selected[field]['response_text_pointer'] = '/different'
    else:
        selected[field] = 'different'
    assert project_report_risk(document)[1][document['agents'][0]['id']]['risk_score'] is None


@pytest.mark.parametrize('field', ['http_target', 'http_target_binding', 'assessment_objective',
                                 'assessment_contract_version', 'evidence_context_id', 'provider', 'model'])
def test_acknowledged_checkpoint_adapter_context_cannot_change(genuine_http_run, field):
    from src.core.cli_checkpoints import _extends
    previous = next(value for value in genuine_http_run[1] if value['agents'][0]['check_evidence'])
    assert _extends(previous, deepcopy(previous))
    altered = deepcopy(previous)
    for view in (altered['agents'][0], altered['security_results'][0]):
        if field == 'http_target':
            view[field]['response_text_pointer'] = '/different'
        else:
            view[field] = 'different'
    assert not _extends(previous, altered)


@pytest.mark.parametrize('whole_execution', [False, True], ids=['category', 'execution'])
def test_genuine_partial_prefix_cannot_be_relabelled_as_complete(genuine_http_run, whole_execution):
    document = deepcopy(genuine_http_run[3] if whole_execution else genuine_http_run[0])
    asset, security = document['agents'][0], document['security_results'][0]
    receipt = asset['check_evidence'][0]
    check = next(value for value in asset['checks'] if value['rule_id'] == receipt['rule_id'])
    if whole_execution:
        assert check['status'] == 'completed' and check['requests_attempted'] == check['responses_evaluated'] == 5
    else:
        assert check['status'] == 'failed' and check['requests_attempted'] == check['responses_evaluated'] == 1
        check['status'] = 'completed'
    security['checks'] = deepcopy(asset['checks'])
    if whole_execution:
        validate_check_evidence(asset)
        asset.update(security_status='completed', risk_coverage_status='sampled')
        security.update(status='completed', risk_coverage_status='sampled')
        document.update(status='completed', risk_assessment_status='completed')
    assert project_report_risk(document)[1][asset['id']]['risk_score'] is None
    with pytest.raises(ValueError):
        validate_check_evidence(asset)


def test_conflicting_status_alias_cannot_hide_an_incomplete_http_execution(genuine_http_run):
    source = deepcopy(genuine_http_run[3]['security_results'][0])
    assert source['status'] == 'partial'
    validate_check_evidence(source)
    assert risk_assessment_eligible(source)
    source.update(status='completed', security_status='partial')
    with pytest.raises(ValueError):
        validate_check_evidence(source)
    assert not risk_assessment_eligible(source)


@pytest.mark.parametrize('provider', ['http-json', 'HTTP-JSON', ' Http-Json '])
def test_reserved_http_provider_cannot_borrow_an_otherwise_eligible_legacy_claim(provider):
    # This synthetic descriptor is only a policy control, not an executed model attack.
    document = synthetic_legacy_policy_claim(70, partial=True)
    assert project_report_risk(document)[1]['stable-asset']['risk_score'] == 70
    document['agents'][0].update(provider=provider, model=None)
    assert project_report_risk(document)[1]['stable-asset']['risk_score'] is None


def test_legacy_prompt_source_two_remains_supported_without_rewriting_archives():
    raw = legacy_archive('prompt-final')
    before = hashlib.sha256(raw).hexdigest()
    document = legacy_report('prompt-final')
    asset = document['agents'][0]
    assert {receipt['source_version'] for receipt in asset['check_evidence']} == {'2.0'}
    assert project_report_risk(document)[1][asset['id']]['risk_score'] == 70
    assert hashlib.sha256(legacy_archive('prompt-final')).hexdigest() == before


def test_prepared_context_rejects_changed_target_and_does_not_resolve_ambient_keys(monkeypatch):
    from src.utils.request_builder import construct_agent_request
    agent = public_http_agent(descriptor(auth_scheme='bearer', principal_label='owned-principal'))
    prepared = prepare_http_target(agent, credential=KEY, canary=MARKER)
    monkeypatch.setattr('src.utils.request_builder.os.environ', {})
    assert get_http_target(prepared.agent) is None
    with http_application_context(prepared):
        request = construct_agent_request(prepared.agent, 'owned probe')
        assert request['headers']['Authorization'] == 'Bearer ' + KEY
        assert request['json'] == {'question': 'owned probe'}
        altered = prepared.agent
        altered['http_target']['response_text_pointer'] = '/different'
        assert get_http_target(altered) is None
        assert construct_agent_request(altered, 'owned probe') is None
    assert get_http_target(prepared.agent) is None
