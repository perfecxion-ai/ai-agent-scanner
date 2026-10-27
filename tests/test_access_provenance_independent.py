"""Independent actual-wire controls and immutable access-v2 compatibility."""

import asyncio
import base64
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import unquote

import aiohttp
from aiohttp import web
import pytest
from sqlalchemy import create_engine, event, insert, select

from src.core.contracts import (
    collect_checks, risk_assessment_eligible, validate_scan_result,
)
from src.core.pipeline import run_pipeline
from src.core.risk_projection import project_report_risk
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.reporting.workflows import compare_reports
from src.risk.risk_assessor import RiskAssessment
from src.security.access_control_tests import AccessControlTester
from src.security.security_engine import SecurityTestEngine
from tests.legacy_access_fixtures import (
    LEGACY_ACCESS_NAMES, LEGACY_ACCESS_REVISION, legacy_access_archive,
    legacy_access_manifest, legacy_access_report,
)
from tests.test_api_auth import api as api


MARKER = 'independent-access-record-83b1f4e679c20a5d'
ISSUED = 'independent-access-issued-key-7c341b296fa0e85d'
REFERENCE = 'INDEPENDENT_ACCESS_ISSUED_KEY'
METHODS = ('_test_authentication_bypass', '_test_weak_credentials',
           '_test_api_key_security', '_test_authorization_bypass')


@pytest.mark.parametrize('name', LEGACY_ACCESS_NAMES)
def test_original_access_v2_archive_bytes_ids_and_versions_are_frozen(name):
    raw = legacy_access_archive(name)
    report = legacy_access_report(name)
    manifest = legacy_access_manifest()
    expected = manifest['archives'][name]
    assert manifest['producer_revision'] == LEGACY_ACCESS_REVISION
    original = deepcopy(report)
    validate_scan_result(report)
    asset = report['agents'][0]
    assert asset['risk_score'] == expected['original_score']
    assert asset['risk_level'] == expected['original_level']
    assert asset['risk_coverage_status'] == expected['original_coverage']
    assert [item['id'] for item in asset['vulnerabilities']] == expected['finding_ids']
    assert [item['id'] for item in asset['check_evidence']] == expected['receipt_ids']
    assert asset['check_evidence_run_id'] == expected['run_id']
    assert [{key: check.get(key) for key in ('rule_id', 'probe_id', 'probe_version', 'status', 'outcome',
                                          'requests_attempted', 'responses_evaluated')}
            for check in asset['checks'] if check['probe_version'] != '1:unexecuted'] == expected['checks']
    access = [check for check in expected['checks'] if not check['rule_id'].startswith('prompt_injection.')
              and check['rule_id'] != 'tenant_isolation_violation']
    assert len(access) == (4 if name in {'zero', 'mixed'} else 1)
    assert report == original and legacy_access_archive(name) == raw


@pytest.mark.parametrize('name', ['zero', 'high', 'partial'])
def test_original_v2_access_cache_claims_are_unknown_under_current_wire_semantics(name):
    report = legacy_access_report(name)
    raw = legacy_access_archive(name)
    original = deepcopy(report)
    summary, assets = project_report_risk(report)
    assert summary['overall_risk_score'] is None
    assert assets[report['agents'][0]['id']]['risk_score'] is None
    assert not risk_assessment_eligible(report['security_results'][0])
    assert report == original and legacy_access_archive(name) == raw


def test_old_access_passes_do_not_erase_independent_prompt_and_tenant_evidence():
    report = legacy_access_report('mixed')
    raw = legacy_access_archive('mixed')
    assert len(report['agents'][0]['check_evidence']) == 6
    assert {receipt['source'] for receipt in report['agents'][0]['check_evidence']} == {
        'protected_system_canary_match', 'controlled_tenant_response'}
    summary, assets = project_report_risk(report)
    assert summary['overall_risk_score'] == assets[report['agents'][0]['id']]['risk_score'] == 90
    assert assets[report['agents'][0]['id']]['risk_level'] == 'critical'
    assert legacy_access_archive('mixed') == raw


def test_old_v2_confirmation_is_not_resolved_by_an_old_v2_quiet_sample():
    before, after = legacy_access_report('high'), legacy_access_report('zero')
    original_before, original_after = deepcopy(before), deepcopy(after)
    diff = compare_reports(before, after)
    assert diff['resolved'] == [] and len(diff['resolution_unverified']) == 1
    assert before == original_before and after == original_after


@pytest.fixture
async def access_target(monkeypatch):
    monkeypatch.setenv(REFERENCE, ISSUED)
    async def no_pacing(_):
        return None
    monkeypatch.setattr('src.security.access_control_tests.asyncio',
                        SimpleNamespace(sleep=no_pacing, CancelledError=asyncio.CancelledError))
    state = dict(mode='protected', calls=[])

    async def handle(request):
        headers = dict(request.headers)
        state['calls'].append(dict(method=request.method, path=request.path, headers=headers))
        credential = next((value for name, value in headers.items()
                           if name.lower() in {'authorization', 'x-api-key', 'x-goog-api-key'}), '')
        if state['mode'] == 'reflect':
            if 'scanner-invalid-' in credential:
                return web.Response(status=403, text='Denied')
            decoded = unquote(json.dumps(headers))
            for value in headers.values():
                try:
                    decoded += base64.b64decode(value + '=' * (-len(value) % 4)).decode()
                except (ValueError, UnicodeError):
                    pass
            return web.Response(text=decoded)
        if credential in {ISSUED, 'Bearer ' + ISSUED}:
            return web.Response(text=MARKER)
        if 'scanner-invalid-' in credential:
            if state['mode'] == 'denied-control-header':
                return web.Response(status=403, text='Denied', headers={'X-Protected-Record': MARKER})
            if state['mode'] == 'denied-control-case':
                return web.Response(status=403, text=MARKER.upper())
            if state['mode'] == 'denied-control-json':
                escaped = ''.join('\\u%04x' % ord(char) for char in MARKER)
                return web.Response(status=403, text='{"error":"' + escaped + '"}', content_type='application/json')
            if state['mode'] == 'denied-control-bom':
                escaped = ''.join('\\u%04x' % ord(char) for char in MARKER)
                return web.Response(status=403, text='\ufeff{"error":"' + escaped + '"}', content_type='application/json')
            return web.Response(status=403, text='Denied')
        if state['mode'] == 'denied-probe-header':
            return web.Response(status=403, text='Denied', headers={'X-Protected-Record': MARKER})
        if state['mode'] == 'wire-authorized' and ISSUED in unquote(json.dumps(headers)):
            return web.Response(text=MARKER)
        if state['mode'] in {'high', 'partial'} and len(state['calls']) == 3:
            return web.Response(text=MARKER)
        if state['mode'] == 'partial' and len(state['calls']) > 3:
            return web.Response(status=503, text='Unavailable')
        return web.Response(status=403, text='Denied')

    application = web.Application()
    application.router.add_route('*', '/{path:.*}', handle)
    runner = web.AppRunner(application)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    endpoint = 'http://127.0.0.1:' + str(site._server.sockets[0].getsockname()[1])
    item = dict(id='independent-access', name='Independent access fixture', provider='ollama',
                model='independent-access-model', endpoint=endpoint, type='assistant', metadata={},
                discovery_method='owned-fixture', authentication_required=True,
                protected_response_marker=MARKER, protected_path_markers={'/admin': MARKER},
                api_key_env=REFERENCE, evidence_context_id='independent-access-context-v1')
    try:
        yield item, state
    finally:
        await runner.cleanup()


async def execute(item, method):
    budget = ScanBudget(allow_loopback=True, allowed_networks=('127.0.0.1/32',), max_requests=100)
    with scan_transport(budget), collect_checks() as checks:
        findings = await getattr(AccessControlTester(), method)(item)
    result = dict(agent_id=item['id'], provider=item['provider'], model=item['model'],
                  endpoint=item['endpoint'], evidence_context_id=item['evidence_context_id'],
                  status='completed' if checks[0]['status'] == 'completed' else 'partial',
                  check_schema_version='1.0', checks=checks, vulnerabilities=findings)
    return result, budget


@pytest.mark.asyncio
@pytest.mark.parametrize('method,count', list(zip(METHODS, (20, 7, 32, 3))))
async def test_genuine_v3_controlled_zero_keeps_each_original_get_sample(access_target, method, count):
    item, state = access_target
    result, budget = await execute(item, method)
    assert len(state['calls']) == budget.requests == count
    assert result['checks'][0]['outcome'] == 'passed'
    assert result['checks'][0]['requests_attempted'] == result['checks'][0]['responses_evaluated'] == count
    assert result['vulnerabilities'] == [] and risk_assessment_eligible(result)
    assert (await RiskAssessment()._assess_agent_risk(result))['overall_risk_score'] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('location,encoded', [('added-header', False), ('selected-user-agent', False),
                                            ('connection-percent', True), ('connection-base64', True)])
async def test_lower_client_reflection_cannot_confirm_or_pass(access_target, monkeypatch, method, location, encoded):
    item, state = access_target
    state['mode'] = 'reflect'
    original = aiohttp.ClientRequest.update_auto_headers
    def mutate(request, skip):
        original(request, skip)
        name = {'added-header': 'X-Reflected-Input', 'selected-user-agent': 'User-Agent',
                'connection-percent': 'Connection', 'connection-base64': 'Connection'}[location]
        value = MARKER
        if encoded:
            value = (''.join('%%%02X' % byte for byte in MARKER.encode()) if location.endswith('percent')
                     else base64.b64encode(MARKER.encode()).decode())
        request.headers[name] = value
    monkeypatch.setattr(aiohttp.ClientRequest, 'update_auto_headers', mutate)
    result, _ = await execute(item, method)
    assert state['calls'] and result['vulnerabilities'] == []
    assert result['checks'][0]['outcome'] == 'inconclusive'
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('location', ['added-header', 'connection-percent'])
async def test_actual_extra_issued_credential_cannot_be_a_bypass(access_target, monkeypatch, method, location):
    item, state = access_target
    state['mode'] = 'wire-authorized'
    original = aiohttp.ClientRequest.update_auto_headers
    def mutate(request, skip):
        original(request, skip)
        name = 'X-Additional-Credential' if location == 'added-header' else 'Connection'
        request.headers[name] = (ISSUED if location == 'added-header'
                                 else ''.join('%%%02X' % byte for byte in ISSUED.encode()))
    monkeypatch.setattr(aiohttp.ClientRequest, 'update_auto_headers', mutate)
    result, _ = await execute(item, method)
    assert state['calls'] and result['vulnerabilities'] == []
    assert result['checks'][0]['outcome'] == 'inconclusive'
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
async def test_missing_real_capture_never_creates_a_pass(access_target, monkeypatch, method):
    from src.core.request_provenance import RequestCapture
    item, state = access_target
    monkeypatch.setattr(RequestCapture, 'seal', lambda self, response: None)
    result, _ = await execute(item, method)
    assert state['calls'] and result['vulnerabilities'] == []
    assert result['checks'][0]['outcome'] == 'inconclusive'
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('mode', ['denied-control-header', 'denied-probe-header',
                                'denied-control-case', 'denied-control-json'])
async def test_denied_response_disclosure_cannot_establish_sampled_absence(access_target, method, mode):
    item, state = access_target
    state['mode'] = mode
    result, _ = await execute(item, method)
    assert state['calls'] and result['vulnerabilities'] == []
    assert result['checks'][0]['outcome'] == 'inconclusive'
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
async def test_json_bom_cannot_hide_a_disclosed_record_in_a_denied_control(access_target):
    item, state = access_target
    state['mode'] = 'denied-control-bom'
    result, _ = await execute(item, METHODS[0])
    assert result['checks'][0]['outcome'] == 'inconclusive'
    assert not risk_assessment_eligible(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,coverage', [('high', 'sampled'), ('partial', 'partial')])
async def test_genuine_v3_disclosure_survives_completed_or_failed_later_requests(access_target, mode, coverage):
    item, state = access_target
    state['mode'] = mode
    result, _ = await execute(item, METHODS[0])
    assert len(result['vulnerabilities']) == 1 and risk_assessment_eligible(result)
    assert result['vulnerabilities'][0]['protected_control_version'] == 3
    assessed = await RiskAssessment()._assess_agent_risk(result)
    assert assessed['overall_risk_score'] == 70 and assessed['coverage_status'] == coverage


@pytest.mark.asyncio
@pytest.mark.parametrize('control_version', [None, 2, True, 3.0])
async def test_current_positive_cannot_reuse_a_missing_old_or_aliased_control_tag(access_target, control_version):
    item, state = access_target
    state['mode'] = 'high'
    result, _ = await execute(item, METHODS[0])
    assert risk_assessment_eligible(result)
    if control_version is None:
        result['vulnerabilities'][0].pop('protected_control_version')
    else:
        result['vulnerabilities'][0]['protected_control_version'] = control_version
    original = deepcopy(result)
    assert not risk_assessment_eligible(result)
    assert result == original


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['closed-response', 'forged-wrapper', 'different-agent', 'wrong-resource', 'get-body'])
async def test_access_verifier_requires_the_actual_live_bound_resource(access_target, monkeypatch, mutation):
    from src.core.access_evidence import access_evidence_context, verify_access_response
    from src.security.access_control_tests import _protected_headers
    item, state = access_target
    endpoint = item['endpoint'] + ('/unrelated' if mutation == 'wrong-resource' else '')
    headers = _protected_headers({'Authorization': 'Bearer ' + ISSUED})
    if mutation == 'get-body':
        original = aiohttp.ClientRequest.update_body_from_data
        def replace_body(request, body, *args, **kwargs):
            return original(request, b'{}', *args, **kwargs)
        monkeypatch.setattr(aiohttp.ClientRequest, 'update_body_from_data', replace_body)
    with access_evidence_context([item]), scan_transport(ScanBudget(allow_loopback=True)):
        async with SafeSession() as session:
            async with session.get(endpoint, headers=headers) as response:
                await response.read()
                if mutation == 'closed-response':
                    pass
                else:
                    supplied = response
                    changed = deepcopy(item)
                    if mutation == 'forged-wrapper':
                        supplied = SimpleNamespace(body=response.body, _request_active=True,
                                                   _request_evidence=response._request_evidence)
                    elif mutation == 'different-agent':
                        changed['model'] = 'different-model'
                    assert not verify_access_response(supplied, agent=changed, endpoint=endpoint, headers=headers)
        if mutation == 'closed-response':
            assert not verify_access_response(response, agent=item, endpoint=endpoint, headers=headers)
    assert len(state['calls']) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('rotation', ['replace', 'unset'])
async def test_pipeline_pins_issued_control_before_its_first_checkpoint(access_target, monkeypatch, rotation):
    item, state = access_target
    engine = SecurityTestEngine()
    engine.prompt_tester.test_agent = AsyncMock(return_value=[])
    engine.privacy_tester.test_agent = AsyncMock(return_value=[])
    engine.access_tester.test_agent = engine.access_tester._test_authentication_bypass
    saved = []
    async def checkpoint(report):
        saved.append(deepcopy(report))
        if len(saved) == 1:
            if rotation == 'replace':
                monkeypatch.setenv(REFERENCE, 'rotated-independent-key-f0a953d2')
            else:
                monkeypatch.delenv(REFERENCE)
    with scan_transport(ScanBudget(allow_loopback=True, max_requests=100)):
        report = await run_pipeline(None, engine, RiskAssessment(), None, 'security_only',
                                    agents=[item], checkpoint_callback=checkpoint)
    assert len(state['calls']) == 20
    assert report['summary']['overall_risk_score'] == 0
    assert report['agents'][0]['risk_coverage_status'] == 'sampled'


@pytest.mark.parametrize('fail_at', [None, 'snapshot-update', 'version-update'])
def test_policy_and_group_schema_upgrade_preserves_archive_bytes_and_untouched_owner_tokens(api, tmp_path, fail_at):
    from src.core.schema import initialize_schema
    from tests.historical_schema import historical_metadata

    module, _ = api
    historical = historical_metadata(version=5)
    engine = create_engine('sqlite:///' + str(tmp_path / 'owned-access-policy.db'))
    historical.create_all(engine)
    archived = {'changed': legacy_access_archive('high'), 'retained': legacy_access_archive('mixed')}
    reports = {key: json.loads(raw) for key, raw in archived.items()}
    try:
        with engine.begin() as connection:
            connection.execute(insert(historical.tables['schema_version']).values(id=1, version=5))
            for key, report in reports.items():
                asset = report['agents'][0]
                connection.execute(insert(historical.tables['scan_session']).values(
                    id=key, organization_id=key, scan_name=key, scan_type='security_only', status=report['status'],
                    target_scope={}, scan_config={}, overall_risk_score=asset['risk_score']))
                connection.exec_driver_sql('INSERT INTO scan_result (scan_id,result) VALUES (?,?)',
                                           (key, archived[key].decode()))
                connection.execute(insert(historical.tables['discovered_agent']).values(
                    id='row-' + key, scan_id=key, agent_name=asset['name'], agent_type=asset['type'],
                    provider=asset['provider'], model_name=asset['model'], endpoint_url=asset['endpoint'],
                    discovery_method=asset['discovery_method'], risk_score=asset['risk_score'],
                    risk_level=asset['risk_level'], vulnerabilities=asset['vulnerabilities'],
                    metadata={'asset_id': asset['id']}))
        def snapshot():
            with engine.connect() as connection:
                return dict(
                    scans=connection.exec_driver_sql('SELECT * FROM scan_session ORDER BY id').fetchall(),
                    agents=connection.exec_driver_sql('SELECT * FROM discovered_agent ORDER BY id').fetchall(),
                    reports=connection.exec_driver_sql('SELECT scan_id,result FROM scan_result ORDER BY scan_id').fetchall(),
                    generations=dict(connection.exec_driver_sql('SELECT organization_id,generation FROM inventory_generation').all()),
                    ddl=connection.exec_driver_sql("SELECT type,name,sql FROM sqlite_master WHERE type IN ('table','index','trigger') ORDER BY type,name").fetchall(),
                    version=connection.scalar(select(historical.tables['schema_version'].c.version)))
        before = snapshot()
        injected = []
        def interrupt(connection, cursor, statement, parameters, context, many):
            normalized = statement.lstrip().upper()
            expected = 'UPDATE DISCOVERED_AGENT' if fail_at == 'snapshot-update' else 'UPDATE SCHEMA_VERSION'
            if fail_at and normalized.startswith(expected):
                injected.append(True)
                raise RuntimeError('Owned migration interruption')
        event.listen(engine, 'before_cursor_execute', interrupt)
        try:
            if fail_at:
                with pytest.raises(RuntimeError, match='Owned migration interruption'):
                    initialize_schema(engine, module.db.metadata)
            else:
                initialize_schema(engine, module.db.metadata)
        finally:
            event.remove(engine, 'before_cursor_execute', interrupt)
        after = snapshot()
        if fail_at:
            assert injected == [True] and after == before
            return
        from tests.asset_group_schema_assertions import assert_group_extension
        assert after['version'] == 7
        assert_group_extension(before['ddl'], after['ddl'])
        assert dict(after['reports']) == {key: raw.decode() for key, raw in archived.items()}
        for table, caches in [('scans', {'overall_risk_score'}), ('agents', {'risk_score', 'risk_level'})]:
            assert [{key: value for key, value in row._mapping.items() if key not in caches}
                    for row in after[table]] == [
                        {key: value for key, value in row._mapping.items() if key not in caches}
                        for row in before[table]]
        assert after['generations']['changed'] != before['generations']['changed']
        assert after['generations']['retained'] == before['generations']['retained']
        with engine.connect() as connection:
            assert connection.exec_driver_sql('SELECT overall_risk_score FROM scan_session WHERE id=?', ('changed',)).scalar_one() is None
            assert connection.exec_driver_sql('SELECT risk_score,risk_level FROM discovered_agent WHERE id=?', ('row-changed',)).one() == (None, 'unknown')
            assert connection.exec_driver_sql('SELECT risk_score,risk_level FROM discovered_agent WHERE id=?', ('row-retained',)).one() == (90, 'critical')
        writes = []
        def record_writes(connection, cursor, statement, parameters, context, many):
            if statement.lstrip().split(None, 1)[0].upper() in {'CREATE', 'DROP', 'ALTER', 'INSERT', 'UPDATE', 'DELETE', 'REPLACE'}:
                writes.append(statement)
        event.listen(engine, 'before_cursor_execute', record_writes)
        try:
            initialize_schema(engine, module.db.metadata)
        finally:
            event.remove(engine, 'before_cursor_execute', record_writes)
        assert writes == [] and snapshot() == after
    finally:
        engine.dispose()
