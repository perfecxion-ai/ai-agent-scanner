"""Real protected-resource GETs require exact private outbound provenance."""

import asyncio
import base64
from copy import deepcopy
from dataclasses import replace
import json
from aiohttp.client_reqrep import ClientRequest
import pytest

from src.core.access_evidence import (
    AccessEvidenceError, access_evidence_context, access_evidence_usable, access_secrets,
    get_access_evidence, guard_access_request, observe_access_request, verify_access_response,
)
from src.core.access_probe_policy import PROTECTED_CONTROL_VERSION
from src.core.contracts import collect_checks, risk_assessment_eligible
from src.core.redaction import collect_secrets, redact_secrets
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.risk.risk_assessor import RiskAssessment
from src.security import access_control_tests as producer
from src.security.access_control_tests import AccessControlTester, _protected_headers
from tests.access_provenance_fixture import ISSUED, MARKER, REFERENCE, access_target, current_access_report


METHODS = ('_test_authentication_bypass', '_test_weak_credentials',
           '_test_api_key_security', '_test_authorization_bypass')


@pytest.fixture
async def resource(monkeypatch):
    monkeypatch.delenv('SCAN_EVIDENCE_PROFILES_FILE', raising=False)
    async with access_target() as target:
        yield target


async def execute(agent, method, *, maximum=100):
    budget = ScanBudget(allow_loopback=True, allowed_networks=('127.0.0.1/32',), max_requests=maximum)
    with scan_transport(budget), access_evidence_context([agent]), collect_checks() as checks:
        findings = await getattr(AccessControlTester(), method)(agent)
        secrets = set(access_secrets()) | collect_secrets(findings)
    assert len(checks) == 1
    result = dict(agent_id=agent['id'], provider=agent['provider'], model=agent['model'],
                  status='completed' if checks[0]['status'] == 'completed' else 'partial',
                  check_schema_version='1.0', checks=checks, vulnerabilities=findings)
    return result, budget, redact_secrets(result, secrets)


@pytest.mark.asyncio
@pytest.mark.parametrize('method,total', list(zip(METHODS, (20, 7, 32, 3))))
@pytest.mark.parametrize('mode', ['protected', 'vulnerable', 'partial'])
async def test_real_capture_keeps_genuine_zero_confirmation_and_partial(resource, method, total, mode):
    agent, state = resource
    state.mode = mode
    if mode == 'partial' and method == METHODS[3]:
        agent['protected_path_markers']['/admin/'] = MARKER
        total *= 2
    result, budget, public = await execute(agent, method)
    check = result['checks'][0]
    assert len(state.calls) == budget.requests <= total
    assert check['requests_attempted'] == len(state.calls)
    assert risk_assessment_eligible(result)
    expected = 0 if mode == 'protected' else 90 if method == METHODS[1] else 70
    assert (await RiskAssessment()._assess_agent_risk(result))['overall_risk_score'] == expected
    assert check['outcome'] == ('passed' if mode == 'protected' else 'confirmed')
    if mode == 'protected':
        assert len(state.calls) == check['responses_evaluated'] == total
    if mode != 'protected':
        assert all(finding['protected_control_version'] == PROTECTED_CONTROL_VERSION == 3
                   for finding in result['vulnerabilities'])
    assert all(value not in json.dumps(public) for value in (MARKER, ISSUED, REFERENCE))


@pytest.mark.asyncio
@pytest.mark.parametrize('method,issued', [(METHODS[1], 'admin:admin'), (METHODS[2], 'test-key')])
async def test_intentional_weak_candidate_can_equal_the_issued_credential(resource, monkeypatch, method, issued):
    agent, state = resource
    state.issued = issued
    monkeypatch.setenv(REFERENCE, issued)
    result, _, public = await execute(agent, method)
    assert result['checks'][0]['outcome'] == 'confirmed'
    assert len(result['vulnerabilities']) == 1 and risk_assessment_eligible(result)
    assert issued not in json.dumps(public)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('mode', ['unseeded', 'denial-leak', 'denial-header-leak', 'denial-upper-leak',
                                 'denial-json-leak', 'denial-json-malformed', 'denial-json-deep',
                                 'denial-json-wide', 'denial-json-duplicate', 'denial-json-nonfinite',
                                 'denial-json-bom-leak', 'denial-json-inner-bom', 'denial-json-nul',
                                 'denial-utf16', 'denial-utf32', 'denial-invalid-utf8', 'denial-nul-body'])
async def test_failed_controls_never_become_passes_or_confirmations(resource, method, mode):
    agent, state = resource
    state.mode = mode
    result, _, _ = await execute(agent, method)
    assert result['checks'][0]['status'] == 'failed'
    assert result['checks'][0]['outcome'] == 'inconclusive'
    assert result['vulnerabilities'] == [] and not risk_assessment_eligible(result)
    assert len(state.calls) == (1 if mode == 'unseeded' else 2)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('mode', ['probe-header-leak', 'probe-upper-leak', 'probe-json-leak', 'probe-json-malformed',
                                 'probe-json-bom-leak', 'probe-utf16', 'probe-invalid-utf8', 'probe-nul-body'])
async def test_denied_probe_disclosure_never_establishes_a_sampled_pass(resource, method, mode):
    agent, state = resource
    state.mode = mode
    result, _, _ = await execute(agent, method)
    assert result['vulnerabilities'] == []
    assert result['checks'][0]['outcome'] == 'inconclusive'
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['denial-json-boundary-depth', 'denial-json-boundary-nodes', 'denial-json-bom-valid'])
async def test_valid_denial_json_at_the_supported_bounds_still_passes(resource, mode):
    agent, state = resource
    state.mode = mode
    result, _, _ = await execute(agent, METHODS[0])
    assert result['checks'][0]['outcome'] == 'passed'
    assert risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('rule', ['authentication_bypass', 'weak_credentials', 'weak_api_key', 'authorization_bypass'])
@pytest.mark.parametrize('mode', ['protected', 'vulnerable', 'partial'])
async def test_live_report_factory_keeps_current_pipeline_risk(rule, mode):
    result = await current_access_report(rule=rule, mode=mode)
    expected = 0 if mode == 'protected' else 90 if rule == 'weak_credentials' else 70
    assert result['summary']['overall_risk_score'] == expected
    assert result['agents'][0]['risk_coverage_status'] == ('partial' if mode == 'partial' else 'sampled')
    assert all(value not in json.dumps(result) for value in (MARKER, ISSUED, REFERENCE))


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('version', [None, 2, True, 3.0])
async def test_current_confirmation_requires_exact_numeric_v3_tag(resource, method, version):
    agent, state = resource
    state.mode = 'vulnerable'
    result, _, _ = await execute(agent, method)
    assert risk_assessment_eligible(result)
    for finding in result['vulnerabilities']:
        if version is None:
            finding.pop('protected_control_version')
        else:
            finding['protected_control_version'] = version
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('kind', ['reflection', 'credential', 'encoded-marker', 'encoded-key'])
async def test_transport_added_private_material_cannot_confirm(resource, monkeypatch, method, kind):
    agent, state = resource
    state.mode = 'reflection' if kind in {'reflection', 'encoded-marker'} else 'credential'
    original = ClientRequest.update_auto_headers

    def inject(request, skip):
        original(request, skip)
        if kind == 'reflection':
            request.headers['X-Reflected-Marker'] = MARKER
        elif kind == 'credential':
            request.headers['X-Extra-Issued-Key'] = ISSUED
        else:
            value = MARKER if kind == 'encoded-marker' else ISSUED
            request.headers['Connection'] = base64.b64encode(value.encode()).decode()

    monkeypatch.setattr(ClientRequest, 'update_auto_headers', inject)
    result, _, public = await execute(agent, method)
    assert result['vulnerabilities'] == [] and not risk_assessment_eligible(result)
    assert result['checks'][0]['status'] == 'failed'
    assert len(state.calls) == 1
    assert all(value not in json.dumps(public) for value in (MARKER, ISSUED, REFERENCE))


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('mutation', ['missing', 'wrong-url', 'body', 'bool-active', 'closed',
                                     'duplicate-auth', 'cookie', 'wrong-host', 'oversize-headers'])
async def test_corrupted_actual_capture_fails_closed(resource, monkeypatch, method, mutation):
    agent, state = resource
    state.mode = 'vulnerable'
    original = producer.verify_access_response

    def changed(response, **kwargs):
        actual = response._request_evidence
        if mutation == 'missing':
            actual = None
        elif mutation == 'wrong-url':
            actual = replace(actual, url=actual.url + '/different')
        elif mutation == 'body':
            actual = replace(actual, body=b'Unexpected')
        elif mutation == 'duplicate-auth':
            actual = replace(actual, headers=(*actual.headers, ('Authorization', 'Bearer ' + ISSUED)))
        elif mutation == 'cookie':
            actual = replace(actual, headers=(*actual.headers, ('Cookie', 'issued=' + ISSUED)))
        elif mutation == 'wrong-host':
            actual = replace(actual, headers=tuple((key, 'other.example' if key.casefold() == 'host' else value)
                                                   for key, value in actual.headers))
        elif mutation == 'oversize-headers':
            actual = replace(actual, headers=(*actual.headers, ('X-Large', 'a' * 65537)))
        if mutation in {'bool-active', 'closed'}:
            response._request_active = 1 if mutation == 'bool-active' else False
        response._BoundedResponse__request_evidence = actual
        return original(response, **kwargs)

    monkeypatch.setattr(producer, 'verify_access_response', changed)
    result, _, _ = await execute(agent, method)
    assert result['vulnerabilities'] == [] and not risk_assessment_eligible(result)
    assert result['checks'][0]['status'] == 'failed' and len(state.calls) == 1


@pytest.mark.asyncio
async def test_environment_rotation_cannot_rebind_a_prepared_check(resource, monkeypatch):
    agent, state = resource
    with access_evidence_context([agent]):
        context = get_access_evidence(agent)
        monkeypatch.setenv(REFERENCE, 'rotated-private-key-647829')
        result, _, _ = await execute(agent, METHODS[0])
        assert get_access_evidence(agent) is context
        assert context.issued_key == ISSUED
    assert result['checks'][0]['outcome'] == 'passed'
    assert state.calls[0][1]['Authorization'] == 'Bearer ' + ISSUED


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['id', 'endpoint', 'model', 'api_key_env', 'protected_response_marker', 'evidence_context_id'])
async def test_nested_context_refuses_public_or_private_rebinding(resource, field):
    agent, state = resource
    changed = deepcopy(agent)
    changed[field] = 'changed-private-input-478291'
    with access_evidence_context([agent]):
        with pytest.raises(AccessEvidenceError, match='^Protected access evidence is unavailable') as error:
            with access_evidence_context([changed]):
                pass
        assert changed[field] not in str(error.value)
    assert state.calls == []


@pytest.mark.asyncio
async def test_known_and_prior_transmitted_markers_taint_the_private_context(resource):
    agent, state = resource
    with access_evidence_context([agent]):
        assert access_evidence_usable(agent)
        with pytest.raises(AccessEvidenceError):
            guard_access_request('GET', agent['endpoint'], {'headers': {'X-Record': MARKER}}, {})
        observe_access_request(None)
        assert not access_evidence_usable(agent)
        result, _, _ = await execute(agent, METHODS[0])
    assert result['vulnerabilities'] == [] and result['checks'][0]['status'] == 'failed'
    assert state.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
async def test_request_cap_includes_controls_and_no_unobserved_pass(resource, method):
    agent, state = resource
    result, budget, _ = await execute(agent, method, maximum=1)
    assert len(state.calls) == budget.requests == 1
    assert result['checks'][0]['status'] == 'failed'
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
async def test_cancellation_escapes_secondary_session_cleanup_error(resource, monkeypatch, method):
    agent, state = resource
    state.mode = 'stall'
    original = SafeSession.__aexit__

    async def cleanup(session, *args):
        await original(session, *args)
        if len(state.calls) >= 3:
            raise OSError('Synthetic private cleanup detail')

    monkeypatch.setattr(SafeSession, '__aexit__', cleanup)
    task = asyncio.create_task(execute(agent, method))
    try:
        await asyncio.wait_for(state.entered.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(state.calls) == 3
    finally:
        state.release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_returned_response_cannot_establish_later_provenance(resource):
    agent, _ = resource
    headers = _protected_headers({'Authorization': 'Bearer ' + ISSUED})
    with access_evidence_context([agent]), scan_transport(ScanBudget(allow_loopback=True)):
        async with SafeSession() as session:
            async with session.get(agent['endpoint'], headers=headers) as response:
                await response.text()
                assert verify_access_response(response, agent=agent, endpoint=agent['endpoint'], headers=headers)
            assert not verify_access_response(response, agent=agent, endpoint=agent['endpoint'], headers=headers)
