"""Server HTTP references are immutable, bounded and separate from private values."""

from copy import deepcopy
import json
import math
import threading
from unittest.mock import AsyncMock, Mock

import pytest

from src.core.evidence_profiles import EvidenceProfileError, EvidenceProfiles, load_evidence_profiles
from src.core.http_application_runtime import http_application_context
from src.core.scope import ScopeValidationError, validate_request
from src.core.server_http_profiles import ServerHTTPProfileError
from src.utils.request_builder import construct_agent_request
from tests.claimed_execution import execute_job
from tests.test_api_auth import api as api, headers
from tests.test_evidence_profiles import CANARY as PROVIDER_CANARY, ENV as PROVIDER_ENV, make_source
from tests.test_http_application_core import descriptor


CANARY = 'owned-server-canary-48f620a19'
CREDENTIAL = 'owned-server-credential-92a10ec8'
CANARY_ENV = 'SCAN_EVIDENCE_HTTP_FIXTURE_CANARY'
CREDENTIAL_ENV = 'SCAN_EVIDENCE_HTTP_FIXTURE_BEARER'
IDENTIFIER = 'owned-http-v1'


def document(endpoint='http://127.0.0.1:19237/custom/assistant', *, tenant='tenant-a', bearer=False):
    return {'schema_version': '2.0', 'profiles': {}, 'http_targets': {IDENTIFIER: {
        'organization_id': tenant, 'schema_version': '1.0', 'name': 'Owned HTTP application',
        'http_target': descriptor(endpoint, auth='bearer' if bearer else 'none'),
        'allowed_networks': ['127.0.0.1/32'], 'credential_env': CREDENTIAL_ENV if bearer else None,
        'canary_env': CANARY_ENV, 'canary_seeded': True}}}


def registry(monkeypatch, **kwargs):
    monkeypatch.setenv(CANARY_ENV, CANARY)
    monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL)
    return EvidenceProfiles.from_document(document(**kwargs))


def body(loaded, *, tenant='tenant-a', **options):
    revision = loaded.http_targets._revision(IDENTIFIER, loaded.http_targets._entries[IDENTIFIER])
    return {'scan_type': 'security_only', 'target_scope': {}, 'scan_config': {
        'http_target_profile': IDENTIFIER, 'http_target_revision': revision, **options}}


def configure(api, monkeypatch):
    module, client = api
    loaded = registry(monkeypatch)
    monkeypatch.setattr(module, '_evidence_profiles', loaded)
    monkeypatch.setitem(module.app.config, 'SCAN_ALLOWED_NETWORKS', ('127.0.0.1/32',))
    monkeypatch.setitem(module.app.config, 'SCAN_ALLOW_LOOPBACK', True)
    return module, client, loaded


def test_private_registry_load_is_immutable_and_worker_values_are_pinned(monkeypatch, tmp_path):
    monkeypatch.setenv(CANARY_ENV, CANARY)
    monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL)
    path = tmp_path / 'owned-registry.json'
    path.write_text(json.dumps(document(bearer=True)))
    path.chmod(0o600)
    loaded = load_evidence_profiles(str(path))
    path.unlink()
    revision = body(loaded)['scan_config']['http_target_revision']
    prepared = loaded.http_targets.prepare(IDENTIFIER, 'tenant-a', revision, {})
    monkeypatch.setenv(CANARY_ENV, CANARY + '-rotated')
    monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL + '-rotated')
    with http_application_context(prepared):
        request = construct_agent_request(prepared.agent, 'owned test prompt')
        assert request['headers']['Authorization'] == 'Bearer ' + CREDENTIAL
        assert prepared.agent['system_prompt_canary'] == CANARY
    assert CANARY not in repr(loaded.http_targets._entries)
    assert CREDENTIAL not in repr(prepared)


@pytest.mark.parametrize('change', ['endpoint', 'request_prompt_field', 'response_text_pointer',
    'principal_label', 'context_label', 'name', 'organization_id', 'allowed_networks',
    'canary_env', 'credential_env', 'catalog'])
def test_revision_covers_definition_scope_references_and_catalog(monkeypatch, change):
    original = registry(monkeypatch, bearer=True)
    before = body(original)['scan_config']['http_target_revision']
    data = document(bearer=True)
    entry = data['http_targets'][IDENTIFIER]
    if change in entry['http_target']:
        entry['http_target'][change] = ('http://127.0.0.1:19238/other' if change == 'endpoint'
            else '/other' if change == 'response_text_pointer' else 'other')
    elif change in ('credential_env', 'canary_env'):
        entry[change] += '_OTHER'
        monkeypatch.setenv(entry[change], CREDENTIAL if change == 'credential_env' else CANARY)
    elif change == 'allowed_networks':
        entry[change] = ['127.0.0.0/24']
    elif change == 'catalog':
        monkeypatch.setattr('src.core.server_http_profiles.prompt_suite_pin', lambda: '0' * 64)
    else:
        entry[change] = 'other'
    changed = EvidenceProfiles.from_document(data)
    assert body(changed)['scan_config']['http_target_revision'] != before
    with pytest.raises(ServerHTTPProfileError):
        changed.http_targets.token(IDENTIFIER, entry['organization_id'], before)


@pytest.mark.parametrize('field,value', [
    ('credential_env', 'OPERATOR_API_KEY'), ('canary_env', 'SECRET_KEY'),
    ('canary_seeded', False), ('system_prompt_canary', CANARY), ('api_key', CREDENTIAL),
    ('profile_path', '/private/unread-profile'), ('allowed_networks', []),
    ('organization_id', ''), ('unknown', 'value'),
])
def test_registry_rejects_private_or_unsupported_input_with_static_error(monkeypatch, field, value):
    registry(monkeypatch)
    data = document()
    data['http_targets'][IDENTIFIER][field] = value
    with pytest.raises(EvidenceProfileError) as caught:
        EvidenceProfiles.from_document(data)
    assert CANARY not in str(caught.value) and CREDENTIAL not in str(caught.value)
    assert '/private/' not in str(caught.value)


def test_startup_and_live_list_guard_cross_target_and_provider_collisions(monkeypatch):
    loaded = registry(monkeypatch)
    data = document()
    other = deepcopy(data['http_targets'][IDENTIFIER])
    other['canary_env'] += '_OTHER'
    monkeypatch.setenv(other['canary_env'], 'owned-other-canary-03c6bd17')
    data['http_targets']['other'] = other
    loaded = EvidenceProfiles.from_document(data)
    monkeypatch.setenv(other['canary_env'], 'Owned HTTP application')
    with pytest.raises(ServerHTTPProfileError):
        loaded.http_targets.plans('tenant-a', {'SCAN_ALLOWED_NETWORKS': ['127.0.0.1/32']})
    data['http_targets'][IDENTIFIER]['name'] = 'contains-' + CANARY
    with pytest.raises(EvidenceProfileError):
        EvidenceProfiles.from_document(data)


@pytest.mark.parametrize('option,value', [('max_requests', True), ('max_requests', 36),
    ('max_requests', 0), ('max_response_bytes', 65537), ('timeout_seconds', 181),
    ('timeout_seconds', 0), ('request_timeout_seconds', True),
    ('request_timeout_seconds', math.nan), ('request_timeout_seconds', math.inf),
    ('request_timeout_seconds', 11), ('max_response_bytes', '1024')])
def test_http_only_budgets_reject_invalid_types_and_bounds(monkeypatch, option, value):
    definition = body(registry(monkeypatch), **{option: value})
    with pytest.raises(ScopeValidationError):
        validate_request(definition, {})


def test_only_http_branch_accepts_budget_options(monkeypatch):
    request = body(registry(monkeypatch), timeout_seconds=2, max_requests=1,
                   max_response_bytes=128, request_timeout_seconds=1)
    _, mode, scope, options = validate_request(request, {})
    assert mode == 'security_only' and scope == {}
    assert options['timeout_seconds'] == 2 and options['max_requests'] == 1
    for key in ('max_requests', 'max_response_bytes', 'request_timeout_seconds'):
        with pytest.raises(ScopeValidationError):
            validate_request({'scan_type': 'security_only', 'scan_config': {'source_scan_id': 'old', key: 1}}, {})


def test_list_and_plan_are_authenticated_tenant_scoped_and_offline(api, monkeypatch):
    module, client, loaded = configure(api, monkeypatch)
    forbidden = Mock(side_effect=AssertionError('Offline target previews must not resolve or connect'))
    monkeypatch.setattr('src.core.scope.resolve_domain', forbidden)
    monkeypatch.setattr('src.core.transport.aiohttp.ClientSession', forbidden)
    before = module.ScanSession.query.count()
    assert client.get('/api/http-targets').status_code == 401
    plan = client.get('/api/http-targets/' + IDENTIFIER + '/plan', headers=headers(module))
    assert plan.status_code == 200
    value = plan.json['target']
    assert value['revision'] == body(loaded)['scan_config']['http_target_revision']
    assert value['configuration_status'] == 'ready' and value['network_readiness_status'] == 'not_checked'
    assert value['selected_rule_count'] == 7 and value['shared_attempt_budget'] == 35
    listing = client.get('/api/http-targets', headers=headers(module)).json
    assert listing == {'success': True, 'targets': [value]}
    assert client.get('/api/http-targets', headers=headers(module, 'other')).json['targets'] == []
    missing = client.get('/api/http-targets/missing/plan', headers=headers(module))
    foreign = client.get('/api/http-targets/' + IDENTIFIER + '/plan', headers=headers(module, 'other'))
    assert missing.status_code == foreign.status_code == 404 and missing.json == foreign.json
    assert module.ScanSession.query.count() == before
    forbidden.assert_not_called()
    assert all(private not in json.dumps(listing) for private in (CANARY, CREDENTIAL, CANARY_ENV, CREDENTIAL_ENV))


@pytest.mark.parametrize('field', ['source_scan_id', 'model_overrides', 'evidence_profiles', 'prompt_suite',
    'http_target', 'credential_env', 'canary_env', 'system_prompt_canary', 'api_key', 'profile_path'])
def test_http_admission_rejects_mixed_or_private_inputs_without_rows(api, monkeypatch, field):
    module, client, loaded = configure(api, monkeypatch)
    request = body(loaded)
    request['scan_config'][field] = CANARY
    response = client.post('/api/scans', headers=headers(module), json=request)
    assert response.status_code == 400
    assert CANARY not in response.get_data(as_text=True)
    assert module.ScanSession.query.count() == module.ScanJob.query.count() == module.AuditEvent.query.count() == 0


def test_commit_rechecks_rotation_before_any_admission_rows(api, monkeypatch):
    module, client, loaded = configure(api, monkeypatch)
    prepare = module._prepare_scan
    name = 'owned-public-job-name-72e4ab8c'
    def rotated(*args, **kwargs):
        result = prepare(*args, **kwargs)
        monkeypatch.setenv(CANARY_ENV, name)
        return result
    monkeypatch.setattr(module, '_prepare_scan', rotated)
    request = {**body(loaded), 'scan_name': name}
    response = client.post('/api/scans', headers=headers(module), json=request)
    assert response.status_code == 400 and name not in response.get_data(as_text=True)
    assert module.ScanSession.query.count() == module.ScanJob.query.count() == module.AuditEvent.query.count() == 0


def test_http_templates_are_explicitly_refused_and_valid_admission_stores_only_public_refs(api, monkeypatch):
    module, client, loaded = configure(api, monkeypatch)
    request = body(loaded, timeout_seconds=2, max_requests=1)
    assert client.post('/api/templates', headers=headers(module), json=request).status_code == 400
    response = client.post('/api/scans', headers=headers(module), json=request)
    assert response.status_code == 202, response.json
    stored = module.db.session.get(module.ScanSession, response.json['scan_id'])
    assert set(stored.scan_config) == {'http_target_profile', 'http_target_revision', 'timeout_seconds',
                                     'max_requests', 'max_response_bytes', 'request_timeout_seconds'}
    encoded = json.dumps(stored.scan_config)
    assert all(private not in encoded for private in (CANARY, CREDENTIAL, CANARY_ENV, CREDENTIAL_ENV))


@pytest.mark.asyncio
@pytest.mark.parametrize('collision', ['provider-id', 'provider-pin', 'scan-name', 'rotated-id', 'rotated-pin'])
async def test_http_private_values_cannot_enter_legacy_provider_admission(api, monkeypatch, collision):
    module, client, _ = configure(api, monkeypatch)
    monkeypatch.setitem(module.app.config, 'SCAN_ALLOWED_NETWORKS', ('127.0.0.1/32', '192.0.2.0/24'))
    monkeypatch.setenv(PROVIDER_ENV, PROVIDER_CANARY)
    identifier = CANARY if collision == 'provider-id' else 'owned-legacy-provider'
    data = document()
    data['profiles'] = {identifier: {'organization_id': 'tenant-a', 'endpoint': 'https://192.0.2.1',
        'provider': 'openai-compatible', 'model': 'fixture-model',
        'evidence_context_id': 'owned-provider-context-v1', 'system_prompt_canary_env': PROVIDER_ENV}}
    private = CANARY
    if collision in ('provider-pin', 'rotated-pin'):
        prior = EvidenceProfiles.from_document({'schema_version': '1.0', 'profiles': data['profiles']})
        private = prior._profiles[identifier].revision
        if collision == 'provider-pin':
            monkeypatch.setenv(CANARY_ENV, private)
    elif collision == 'rotated-id':
        private = identifier
    if collision in ('provider-id', 'provider-pin'):
        with pytest.raises(EvidenceProfileError):
            EvidenceProfiles.from_document(data)
        return
    loaded = EvidenceProfiles.from_document(data)
    monkeypatch.setattr(module, '_evidence_profiles', loaded)
    if collision.startswith('rotated-'):
        monkeypatch.setenv(CANARY_ENV, private)
    await make_source(module, monkeypatch)
    response = client.post('/api/scans', headers=headers(module), json={
        'scan_type': 'security_only', 'scan_name': private if collision == 'scan-name' else 'Owned provider scan',
        'scan_config': {'source_scan_id': 'profile-source',
            'model_overrides': {'stable-asset': 'fixture-model'}, 'evidence_profiles': {'stable-asset': identifier}}})
    assert response.status_code == 400
    assert private not in response.get_data(as_text=True)
    assert module.ScanSession.query.filter(module.ScanSession.id != 'profile-source').count() == 0


@pytest.mark.parametrize('private', [CANARY, CANARY_ENV, CREDENTIAL_ENV])
def test_legacy_input_errors_and_commits_never_reflect_http_private_fields(api, monkeypatch, private):
    module, client, _ = configure(api, monkeypatch)
    if private == CREDENTIAL_ENV:
        monkeypatch.setattr(module, '_evidence_profiles', registry(monkeypatch, bearer=True))
    response = client.post('/api/scans', headers=headers(module), json={
        'scan_type': 'discovery_only', 'target_scope': {'network_ranges': [private]}})
    assert response.status_code == 400 and private not in response.get_data(as_text=True)
    assert module.ScanSession.query.count() == 0


def test_missing_unrelated_http_reference_does_not_block_legacy_admission(api, monkeypatch):
    module, client, _ = configure(api, monkeypatch)
    monkeypatch.delenv(CANARY_ENV)
    response = client.post('/api/scans', headers=headers(module), json={
        'scan_type': 'discovery_only', 'target_scope': {'network_ranges': ['127.0.0.1/32']}})
    assert response.status_code == 202


def test_reference_rotation_in_before_commit_hook_rolls_back_all_admission_rows(api, monkeypatch):
    module, _, loaded = configure(api, monkeypatch)
    name = 'owned-hook-rotation-public-name'
    definition = module._prepare_scan({**body(loaded), 'scan_name': name}, 'tenant-a', allow_http_targets=True)
    def rotate(scan_id):
        monkeypatch.setenv(CANARY_ENV, name)
    with module._admission_lock, pytest.raises(ServerHTTPProfileError):
        module._queue_scan(definition, 'tenant-a', 'operator', None, before_commit=rotate)
    module.db.session.rollback()
    assert module.ScanSession.query.count() == module.ScanJob.query.count() == module.AuditEvent.query.count() == 0


def test_encoded_protected_values_are_rejected_before_persisting_a_public_label(api, monkeypatch):
    module, client, loaded = configure(api, monkeypatch)
    request = {**body(loaded), 'scan_name': CANARY.encode().hex()}
    response = client.post('/api/scans', headers=headers(module), json=request)
    assert response.status_code == 400
    assert module.ScanSession.query.count() == 0


def queued_named_target(api, monkeypatch):
    module, client, _ = configure(api, monkeypatch)
    monkeypatch.setitem(module.app.config, 'SCAN_ALLOWED_NETWORKS', ('192.0.2.0/24',))
    monkeypatch.setattr('src.core.scope.resolve_domain', lambda host: ['192.0.2.7'])
    data = document('https://bounded.example.test/custom/assistant')
    data['http_targets'][IDENTIFIER]['allowed_networks'] = ['192.0.2.0/24']
    loaded = EvidenceProfiles.from_document(data)
    monkeypatch.setattr(module, '_evidence_profiles', loaded)
    response = client.post('/api/scans', headers=headers(module),
                           json=body(loaded, timeout_seconds=1, max_requests=1))
    assert response.status_code == 202
    return module, response.json['scan_id']


def test_queued_http_preflight_does_not_resolve_before_the_worker_deadline(api, monkeypatch):
    module, scan_id = queued_named_target(api, monkeypatch)
    resolver = Mock(side_effect=AssertionError('Queued preflight must not resolve outside its work deadline'))
    worker = Mock()
    monkeypatch.setattr('src.core.scope.resolve_domain', resolver)
    monkeypatch.setattr(module, '_run_scan_in_thread', worker)
    execute_job(module, scan_id, threading.Event())
    resolver.assert_not_called()
    worker.assert_called_once()
    assert worker.call_args.args[3]['timeout_seconds'] == 1


def test_prepared_http_pipeline_avoids_blocking_endpoint_dns_on_its_event_loop(api, monkeypatch):
    module, scan_id = queued_named_target(api, monkeypatch)
    resolver = Mock(side_effect=AssertionError('Prepared HTTP work must enforce DNS in its async transport'))
    tester = AsyncMock(return_value=[])
    monkeypatch.setattr('src.core.scope.resolve_domain', resolver)
    monkeypatch.setattr(module.SecurityTestEngine, 'test_agents', tester)
    execute_job(module, scan_id, threading.Event())
    resolver.assert_not_called()
    tester.assert_awaited_once()
    module.db.session.expire_all()
    assert module.db.session.get(module.ScanSession, scan_id).status == 'partial'
