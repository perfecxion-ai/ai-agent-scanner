"""Protected disclosures exclude bounded actual outbound request material."""

import asyncio
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from aiohttp import web
from multidict import CIMultiDict
import pytest

from src.core.contracts import collect_checks, collect_evidence, risk_assessment_eligible, validate_check_evidence
from src.core.request_provenance import (
    MAX_HEADER_COUNT, MAX_REQUEST_BODY, MAX_REQUEST_HEADERS, MAX_REQUEST_URL,
    RequestCapture, RequestEvidence, known_request_excludes_canary, request_excludes_canary,
)
from src.core.transport import BoundedResponse, SafeSession, ScanBudget, scan_transport
from src.security.prompt_injection_tests import PromptInjectionTester
from src.utils.request_builder import construct_agent_request


CANARY = 'TARGET_ONLY_PROTECTED_CANARY_82397'
URL = 'http://127.0.0.1:9999/api/chat'
CATEGORY = 'system_prompt_extraction'


def capture_for(body=b'{"model":"fixture","messages":[]}', *, url=URL, extra_headers=()):
    headers = CIMultiDict([('Host', '127.0.0.1:9999'), ('Content-Type', 'application/json'),
                          ('Content-Length', str(len(body))), *extra_headers])
    capture = RequestCapture()
    capture.sent_headers('POST', url, headers)
    capture.sent_chunk('POST', url, body)
    info = SimpleNamespace(method='POST', url=url, real_url=url, headers=headers)
    return capture, SimpleNamespace(request_info=info), headers


def complete_evidence(**kwargs):
    capture, response, _ = capture_for(**kwargs)
    evidence = capture.seal(response)
    assert evidence is not None
    return evidence


def test_snapshot_is_complete_immutable_once_and_does_not_render_secrets():
    capture, response, headers = capture_for(extra_headers=(('Authorization', 'Bearer private-key'),))
    evidence = capture.seal(response)
    assert isinstance(evidence, RequestEvidence)
    assert request_excludes_canary(evidence, CANARY)
    headers['Authorization'] = 'changed'
    response.request_info.method = 'DELETE'
    capture.sent_chunk('POST', URL, b'changed')
    assert evidence.headers[-1] == ('Authorization', 'Bearer private-key')
    assert evidence.method == 'POST' and capture.body == bytearray()
    assert capture.seal(response) is None
    assert 'private-key' not in repr(evidence)
    with pytest.raises(FrozenInstanceError):
        evidence.body = b'changed'
    bounded = BoundedResponse(SimpleNamespace(status=200), ScanBudget(), request_evidence=evidence)
    with pytest.raises(AttributeError):
        bounded._request_evidence = None


@pytest.mark.parametrize('fault', [
    'absent_info', 'absent_headers', 'method', 'url', 'real_url', 'headers', 'duplicate_headers',
    'missing_body', 'truncated_body', 'long_body', 'wrong_body_url', 'wrong_body_method', 'body_type',
    'duplicate_length', 'bad_length', 'negative_length', 'length_limit', 'missing_length',
    'chunked', 'compression', 'header_count', 'header_bytes', 'header_type', 'url_limit',
])
def test_missing_incomplete_unsupported_or_oversized_capture_is_not_safe(fault):
    capture, response, headers = capture_for()
    if fault == 'absent_info':
        del response.request_info
    elif fault == 'absent_headers':
        capture = RequestCapture()
    elif fault in {'method', 'url', 'real_url'}:
        setattr(response.request_info, fault, 'mismatch')
    elif fault == 'headers':
        headers['Authorization'] = 'unobserved-value'
    elif fault == 'duplicate_headers':
        capture.sent_headers('POST', URL, headers)
    elif fault == 'missing_body':
        capture.body.clear()
    elif fault == 'truncated_body':
        capture.body.pop()
    elif fault == 'long_body':
        capture.sent_chunk('POST', URL, b'x' * (MAX_REQUEST_BODY + 1))
    elif fault in {'wrong_body_url', 'wrong_body_method', 'body_type'}:
        capture.sent_chunk('GET' if fault == 'wrong_body_method' else 'POST',
                           URL + '/other' if fault == 'wrong_body_url' else URL,
                           'not-bytes' if fault == 'body_type' else b'x')
    else:
        if fault == 'duplicate_length':
            headers.add('Content-Length', headers['Content-Length'])
        elif fault == 'bad_length':
            headers['Content-Length'] = 'abc'
        elif fault == 'negative_length':
            headers['Content-Length'] = '-1'
        elif fault == 'length_limit':
            headers['Content-Length'] = '1' * 11
        elif fault == 'missing_length':
            del headers['Content-Length']
        elif fault == 'chunked':
            headers['Transfer-Encoding'] = 'chunked'
        elif fault == 'compression':
            headers['Content-Encoding'] = 'gzip'
        elif fault == 'header_count':
            headers.extend((f'Extra-{index}', 'x') for index in range(MAX_HEADER_COUNT))
        elif fault == 'header_bytes':
            headers['Extra'] = '\u00e9' * (MAX_REQUEST_HEADERS // 2)
        elif fault == 'header_type':
            headers = {'Host': 123}
        capture = RequestCapture()
        url = 'x' * (MAX_REQUEST_URL + 1) if fault == 'url_limit' else URL
        capture.sent_headers('POST', url, headers)
        capture.sent_chunk('POST', url, b'{"model":"fixture","messages":[]}')
        response.request_info.headers = headers
    evidence = capture.seal(response)
    assert evidence is None
    assert not request_excludes_canary(evidence, CANARY)


@pytest.mark.parametrize('marker,body,url,headers', [
    ('CASE_VARIANT_MODEL_IDENTIFIER', b'{"model":"case_variant_model_identifier"}', URL, ()),
    ('CASE_VARIANT_API_CREDENTIAL', b'{}', URL, (('Authorization', 'Bearer case_variant_api_credential'),)),
    ('CASE_VARIANT_URL_IDENTIFIER', b'{}', URL + '?q=case_variant_url_identifier', ()),
    ('DECODED PATH IDENTIFIER', b'{}', URL + '/decoded%2520path%2520identifier', ()),
    ('CONTENT-TYPE: APPLICATION/JSON', b'{}', URL, ()),
    ('CONTENT-TYPE:APPLICATION/JSON', b'{}', URL, ()),
    ('USER-AGENT: SYNTHETIC CLIENT', b'{}', URL, (('User-Agent', 'Synthetic Client'),)),
    ('JSON_KEY_CANARY_VALUE', b'{"json_key_canary_value":"ordinary"}', URL, ()),
    ('UNICODE_STRA\u00dfE_IDENTIFIER', b'{"value":"unicode_strasse_identifier"}', URL, ()),
    ('JSON_UNESCAPED_\u00e9_IDENTIFIER', b'{"value":"json_unescaped_\\u00e9_identifier"}', URL, ()),
    ('POST /API/CHAT HTTP/1.1', b'{}', URL, ()),
])
def test_actual_outbound_keys_values_and_renderings_are_casefold_excluded(marker, body, url, headers):
    evidence = complete_evidence(body=body, url=url, extra_headers=headers)
    assert not request_excludes_canary(evidence, marker)
    assert request_excludes_canary(evidence, CANARY)


@pytest.mark.parametrize('mutation', [
    {'body': b'not JSON'}, {'body': b'\xff'}, {'body': 'wrong-type'},
    {'headers': ()}, {'headers': (('Content-Length', '999'),)},
    {'headers': (('Content-Length', '34'), ('Transfer-Encoding', 'chunked'))},
    {'url': ''}, {'method': None},
])
def test_direct_incomplete_snapshot_never_establishes_exclusion(mutation):
    assert not request_excludes_canary(replace(complete_evidence(), **mutation), CANARY)


def test_deep_or_excessive_request_material_fails_closed():
    nested = 'ordinary'
    for _ in range(20):
        nested = [nested]
    for body in (nested, [0] * 8193):
        request = {'method': 'POST', 'url': URL, 'headers': {}, 'json': body}
        assert not known_request_excludes_canary(request, CANARY)
    assert not known_request_excludes_canary({}, CANARY)
    assert not known_request_excludes_canary({'url': URL, 'json': 'x' * (MAX_REQUEST_BODY + 1)}, CANARY)


@pytest.mark.parametrize('field', ['model', 'payload', 'url', 'api_key', 'rendered_header'])
def test_known_case_related_collisions_are_refused_before_transport(field, monkeypatch):
    value = 'OUTBOUND_MARKER_IDENTIFIER'
    item = {'id': 'fixture', 'provider': 'ollama', 'model': 'fixture', 'endpoint': URL,
            'system_prompt_canary': value}
    payload = 'Ordinary harmless prompt'
    if field == 'model':
        item['model'] = value.lower()
    elif field == 'payload':
        payload = value.lower()
    elif field == 'url':
        item['endpoint'] += '?value=' + value.lower()
    elif field == 'api_key':
        monkeypatch.setenv('SYNTHETIC_REQUEST_TEST_KEY', value.lower())
        item['api_key_env'] = 'SYNTHETIC_REQUEST_TEST_KEY'
    else:
        item['system_prompt_canary'] = 'CONTENT-TYPE: APPLICATION/JSON'
    assert construct_agent_request(item, payload) is None


@pytest.fixture
async def target():
    state = {'requests': []}

    async def handler(request):
        state['requests'].append((request.method, str(request.rel_url), tuple(request.headers.items()),
                                  await request.read()))
        return web.json_response({'message': {'content': CANARY}})

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
async def test_actual_wire_capture_matches_received_headers_and_exact_serialized_body(target):
    endpoint, state = target
    sent_body = {'message': 'ordinary', 'number': 7}
    with scan_transport(ScanBudget(allow_loopback=True)):
        async with SafeSession(json_serialize=lambda value: json.dumps(value, indent=2)) as session:
            async with session.request('POST', endpoint + '/api/chat', json=sent_body) as response:
                evidence = response._request_evidence
                assert request_excludes_canary(evidence, CANARY)
                assert await response.json() == {'message': {'content': CANARY}}
    received = state['requests'][0]
    assert evidence.method == received[0]
    assert evidence.headers == received[2]
    assert evidence.body == received[3] == json.dumps(sent_body, indent=2).encode()
    assert any(key == 'User-Agent' for key, _ in evidence.headers)
    assert not request_excludes_canary(evidence, 'Content-Type: application/json')
    sent_body['message'] = CANARY
    assert request_excludes_canary(evidence, CANARY)


@pytest.mark.asyncio
@pytest.mark.parametrize('option', ['chunked', 'compress'])
async def test_actual_unsupported_body_encoding_never_gets_safe_snapshot(target, option):
    endpoint, state = target
    with scan_transport(ScanBudget(allow_loopback=True)):
        async with SafeSession() as session:
            async with session.request('POST', endpoint + '/api/chat', json={'value': 'ordinary'},
                                       **{option: True}) as response:
                assert response._request_evidence is None
                assert not request_excludes_canary(response._request_evidence, CANARY)
                assert await response.json() == {'message': {'content': CANARY}}
    assert len(state['requests']) == 1


@pytest.mark.asyncio
async def test_current_receipts_require_new_exclusion_source_version_but_legacy_stays_legacy(target, monkeypatch):
    endpoint, _ = target
    monkeypatch.setattr(asyncio, 'sleep', AsyncMock())
    item = {'id': 'fixture', 'provider': 'ollama', 'model': 'fixture', 'endpoint': endpoint,
            'system_prompt_canary': CANARY, 'evidence_context_id': 'fixture-v1'}
    tester = PromptInjectionTester()
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as ledger:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    asset = dict(item, status='completed', check_schema_version='1.0', check_evidence_schema_version='1.0',
                 check_evidence_run_id=ledger.run_id, check_evidence=ledger.receipts,
                 checks=checks, vulnerabilities=findings)
    assert len(ledger.receipts) == 5
    assert {receipt['source_version'] for receipt in ledger.receipts} == {'2.0'}
    assert validate_check_evidence(asset) is asset and risk_assessment_eligible(asset)
    draft = deepcopy(asset)
    for receipt in draft['check_evidence']:
        receipt['source_version'] = '1.0'
    assert validate_check_evidence(draft, strict=False) is draft
    with pytest.raises(ValueError):
        validate_check_evidence(draft)
    assert not risk_assessment_eligible(draft)
    legacy = deepcopy(asset)
    for field in ('check_evidence_schema_version', 'check_evidence_run_id', 'check_evidence'):
        legacy.pop(field)
    for finding in legacy['vulnerabilities']:
        finding.pop('check_evidence_id')
    # Archived finalized semantics are not retroactive proof of request exclusion.
    assert risk_assessment_eligible(legacy)


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['missing', 'oversized', 'colliding'])
async def test_overridden_analyzer_cannot_mint_without_actual_request_exclusion(target, monkeypatch, fault):
    endpoint, state = target
    monkeypatch.setattr(asyncio, 'sleep', AsyncMock())
    item = {'id': 'fixture', 'provider': 'ollama', 'model': 'fixture', 'endpoint': endpoint,
            'system_prompt_canary': CANARY, 'evidence_context_id': 'fixture-v1'}
    safe_evidence = complete_evidence(body=b'{}')
    if fault == 'missing':
        monkeypatch.setattr(RequestCapture, 'seal', lambda self, response: None)
    elif fault == 'oversized':
        original_chunk = RequestCapture.sent_chunk

        def overflow(self, method, url, chunk):
            original_chunk(self, method, url, b'x' * (MAX_REQUEST_BODY + 1))

        monkeypatch.setattr(RequestCapture, 'sent_chunk', overflow)
    else:
        original_enter = SafeSession.__aenter__

        async def with_collision(self):
            self.kwargs['headers'] = {'X-Synthetic': CANARY.lower()}
            return await original_enter(self)

        monkeypatch.setattr(SafeSession, '__aenter__', with_collision)
    tester = PromptInjectionTester()
    analyze = tester._analyze_response

    def forced_analysis(agent, category, payload, text, status, **kwargs):
        return analyze(agent, category, payload, text, status, request_evidence=safe_evidence)

    monkeypatch.setattr(tester, '_analyze_response', forced_analysis)
    with scan_transport(ScanBudget(allow_loopback=True)), collect_checks() as checks, collect_evidence(item) as ledger:
        findings = await tester._test_injection_category(item, CATEGORY, tester.injection_payloads[CATEGORY])
    # A caller-overridden analyzer is not trusted by the actual-response receipt boundary.
    assert ledger.receipts == [] and ledger.findings == []
    assert all('check_evidence_id' not in finding for finding in findings)
    asset = dict(item, status='completed', check_schema_version='1.0', check_evidence_schema_version='1.0',
                 check_evidence_run_id=ledger.run_id, check_evidence=[], checks=checks, vulnerabilities=findings)
    assert not risk_assessment_eligible(asset)
    assert len(findings) == len(state['requests']) == 5


@pytest.mark.parametrize('metadata', [None, {}, SimpleNamespace(body=b'{}')])
def test_standalone_analyzer_without_complete_provenance_cannot_confirm(metadata):
    tester = PromptInjectionTester()
    item = {'system_prompt_canary': CANARY}
    result = tester._analyze_response(item, CATEGORY, 'ordinary', CANARY, 200,
                                      request_evidence=metadata)
    assert result is None or result['evidence_status'] != 'confirmed'


def test_response_match_stays_exact_while_outbound_exclusion_is_casefolded():
    tester = PromptInjectionTester()
    item = {'system_prompt_canary': CANARY}
    evidence = complete_evidence()
    assert tester._analyze_response(item, CATEGORY, 'ordinary', CANARY, 200,
                                   request_evidence=evidence)['evidence_status'] == 'confirmed'
    assert tester._analyze_response(item, CATEGORY, 'ordinary', CANARY.lower(), 200,
                                   request_evidence=evidence) is None
