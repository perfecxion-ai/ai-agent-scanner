"""Current controlled-access identity is bounded and independent of executors."""

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import AsyncMock, Mock

import pytest

from src.core import access_probe_policy as policy
from src.core.contracts import collect_checks
from src.core.pipeline import run_pipeline
from src.core.transport import ScanBudget, scan_transport
from src.security.access_control_tests import AccessControlTester


PROVIDER = 'openai-compatible'
MODEL = 'fixture-model'
CONTEXT = 'protected-access-fixture-v1'
METHODS = {
    'authentication_bypass': '_test_authentication_bypass',
    'weak_credentials': '_test_weak_credentials',
    'weak_api_key': '_test_api_key_security',
    'authorization_bypass': '_test_authorization_bypass',
}
FROZEN_VERSIONS = {
    'authentication_bypass': '1:3f0447b8efe8505911d5cae3c705432cb5073f9bb5d2ccf8ad69d78e6c94994b',
    'weak_credentials': '1:2949e75b8ac1689d274abe960c5ea0a6dbea3a319844a617f5675218412a8a3e',
    'weak_api_key': '1:1d40302a992dec4913f0b3a178ea7fa439dc2acc700bebbebf374fdd2a00ded3',
    'authorization_bypass': '1:4aaad5bc54ac79328891d87fa42c28b1468005c52f72afe0e42cfa2b5dac8cfc',
}
FROZEN_PATHS = ('/admin', '/admin/', '/administrator', '/api/admin', '/api/v1/admin',
                '/admin/users', '/admin/config', '/system')
FROZEN_DEFINITIONS = {
    'authentication_bypass': ['18-header-variations', 'authorized-and-denied-resource-controls-v2'],
    'weak_credentials': [[('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
                          ('admin', ''), ('test', 'test')], 'authorized-and-denied-resource-controls-v2'],
    'weak_api_key': [['test-key', 'demo-key', 'dev-key', 'api-key', '123456789'],
                     'six-header-variations-v1', 'authorized-and-denied-resource-controls-v2'],
    'authorization_bypass': ['admin-path-sample-v1', list(FROZEN_PATHS),
                             'authorized-and-denied-resource-controls-v2'],
}


def frozen_version(rule, *, provider=PROVIDER, model=MODEL, paths=('/admin',), definition=None):
    identity = [FROZEN_DEFINITIONS[rule] if definition is None else definition, provider, model]
    if rule == 'authorization_bypass':
        identity.append(list(paths))
    return '1:' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def records(rule, *, provider=PROVIDER, model=MODEL, paths=('/admin',), outcome='confirmed'):
    count = {'authentication_bypass': 20, 'weak_credentials': 7,
             'weak_api_key': 32, 'authorization_bypass': 3 * len(paths)}[rule]
    check = {'rule_id': rule, 'probe_id': rule + '.sample',
             'probe_version': frozen_version(rule, provider=provider, model=model, paths=paths),
             'status': 'completed', 'outcome': outcome,
             'requests_attempted': count, 'responses_evaluated': count,
             'reason': None, 'evidence_context_id': CONTEXT}
    finding = {key: check[key] for key in ('rule_id', 'probe_id', 'probe_version', 'evidence_context_id')}
    finding.update(vulnerability_type=rule, evidence_status='confirmed', status_code=200,
                   control_status=policy.ACCESS_CONTROL_STATUS)
    if rule == 'authorization_bypass':
        finding['path'] = paths[0]
    return check, finding


@pytest.mark.parametrize('rule', METHODS)
def test_frozen_current_hashes_and_counts(rule):
    check, finding = records(rule)
    assert check['probe_version'] == FROZEN_VERSIONS[rule]
    probe = policy.protected_access_probe(check, provider=PROVIDER, model=MODEL)
    assert probe.expected_pass_responses == check['responses_evaluated']
    assert policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    assert policy.protected_access_pass(dict(check, outcome='passed'), provider=PROVIDER, model=MODEL)
    with pytest.raises(FrozenInstanceError):
        probe.max_requests = 100


@pytest.mark.parametrize('mask', range(1, 256))
def test_every_ordered_admin_subset_has_exact_identity_and_pass_count(mask):
    paths = tuple(path for index, path in enumerate(FROZEN_PATHS) if mask & (1 << index))
    check, finding = records('authorization_bypass', paths=paths)
    probe = policy.protected_access_probe(check, provider=PROVIDER, model=MODEL)
    assert probe.protected_paths == paths
    assert probe.expected_pass_responses == 3 * len(paths)
    assert policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    assert policy.protected_access_pass(dict(check, outcome='passed'), provider=PROVIDER, model=MODEL)
    assert not policy.protected_access_confirmation(
        check, dict(finding, path='/not-covered'), provider=PROVIDER, model=MODEL)


@pytest.mark.asyncio
async def test_real_decorators_preserve_all_current_hashes_without_requests(monkeypatch):
    monkeypatch.delenv('ACCESS_POLICY_UNSET_KEY', raising=False)
    tester = AccessControlTester()
    agent = {'provider': PROVIDER, 'model': MODEL, 'authentication_required': True,
             'protected_response_marker': 'opaque-fixture-protected-value',
             'api_key_env': 'ACCESS_POLICY_UNSET_KEY'}
    cases = [(rule, ('/admin',)) for rule in METHODS if rule != 'authorization_bypass']
    cases.extend(('authorization_bypass', tuple(path for index, path in enumerate(FROZEN_PATHS)
                                               if mask & (1 << index))) for mask in range(1, 256))
    for rule, paths in cases:
        agent['protected_path_markers'] = {path: 'opaque-fixture-protected-value' for path in paths}
        with collect_checks() as checks:
            assert await getattr(tester, METHODS[rule])(agent) == []
        assert checks[0]['requests_attempted'] == 0
        assert checks[0]['probe_version'] == frozen_version(rule, paths=paths)
        assert policy.protected_access_probe(checks[0], provider=PROVIDER, model=MODEL) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['_test_authentication_bypass', '_test_authorization_bypass'])
@pytest.mark.parametrize('marker', [
    'protected_control_version', 'PROTECTED_CONTROL_VERSION', 'protected_control',
    'PROTECTED_CONTROL', 'd_control_version', 'protected_path_index',
    'PROTECTED_PATH_INDEX', 'protected_path_i', 'PROTECTED_PATH_I', 'ected_path_index',
])
async def test_default_access_checks_reject_public_descriptor_markers_without_io(monkeypatch, method, marker):
    assert 16 <= len(marker) <= 128
    monkeypatch.setenv('ACCESS_POLICY_ISSUED_KEY', 'issued-fixture-key-3d8e49af')
    session = Mock(side_effect=AssertionError('Descriptor collision must not perform I/O'))
    monkeypatch.setattr('src.security.access_control_tests.SafeSession', session)
    agent = {'id': 'fixture', 'name': 'Fixture', 'provider': PROVIDER, 'model': MODEL,
             'endpoint': 'http://192.0.2.1/resource', 'authentication_required': True,
             'protected_response_marker': marker, 'protected_path_markers': {'/admin': marker},
             'api_key_env': 'ACCESS_POLICY_ISSUED_KEY', 'evidence_context_id': CONTEXT}
    with collect_checks() as checks:
        findings = await getattr(AccessControlTester(), method)(agent)
    assert findings == []
    assert checks[0]['status'] == 'skipped' and checks[0]['outcome'] == 'not_evaluated'
    assert checks[0]['requests_attempted'] == checks[0]['responses_evaluated'] == 0
    assert marker.casefold() not in json.dumps([checks, findings]).casefold()

    class AccessOnly:
        prompt_suite = None
        test_agents = AsyncMock(side_effect=AssertionError('Privacy preflight must precede security testing'))

    security = AccessOnly()
    checkpoint = AsyncMock()
    with pytest.raises(ValueError, match='^Protected evidence conflicts with public access fields$') as error:
        await run_pipeline(None, security, None, None, 'security_only', agents=[agent],
                           checkpoint_callback=checkpoint)
    assert marker.casefold() not in str(error.value).casefold()
    security.test_agents.assert_not_awaited()
    checkpoint.assert_not_awaited()
    session.assert_not_called()


@pytest.mark.parametrize('rule', METHODS)
def test_explicit_null_model_is_distinct_from_other_models(rule):
    check, finding = records(rule, provider='gemini', model=None)
    assert policy.protected_access_confirmation(check, finding, provider='gemini', model=None)
    assert policy.protected_access_pass(dict(check, outcome='passed'), provider='gemini', model=None)
    assert policy.protected_access_probe(check, provider='gemini', model='fixture-model') is None
    with pytest.raises(TypeError):
        policy.protected_access_probe(check, provider='gemini')


@pytest.mark.parametrize('value', ['', ' padded', 'padded ', '\n', 'x\x7f', '[redacted]',
                                  'prefix[redacted]suffix', 4, [], {}, True])
@pytest.mark.parametrize('field', ['provider', 'model'])
def test_invalid_public_context_is_not_cached(field, value):
    check, _ = records('authentication_bypass')
    context = {'provider': PROVIDER, 'model': MODEL, field: value}
    before = policy._authorization_probes.cache_info()
    assert policy.protected_access_probe(check, **context) is None
    assert policy._authorization_probes.cache_info() == before


@pytest.mark.parametrize(('provider', 'model'), [('x' * 65, MODEL), (PROVIDER, 'x' * 257)])
def test_oversized_context_fails_before_cache(provider, model):
    check, _ = records('authentication_bypass')
    before = policy._authorization_probes.cache_info()
    assert policy.protected_access_probe(check, provider=provider, model=model) is None
    assert policy._authorization_probes.cache_info() == before


def test_hash_context_preserves_case_and_internal_model_spaces():
    check, _ = records('authentication_bypass', provider='Ollama', model='local [label] model')
    assert policy.protected_access_probe(check, provider='Ollama', model='local [label] model') is not None
    assert policy.protected_access_probe(check, provider='ollama', model='local [label] model') is None


@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('delta', [-1, 1])
def test_pass_requires_exact_actual_counts(rule, delta):
    check, _ = records(rule, outcome='passed')
    check['requests_attempted'] += delta
    check['responses_evaluated'] += delta
    assert not policy.protected_access_pass(check, provider=PROVIDER, model=MODEL)


@pytest.mark.parametrize('rule', METHODS)
def test_confirmed_partial_check_requires_at_least_two_controls_and_probe(rule):
    check, finding = records(rule)
    check.update(status='failed', reason='Some interactions failed', requests_attempted=3, responses_evaluated=3)
    assert policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    for attempted, evaluated in ((2, 2), (3, 2), (2, 3), (True, 1), (3, True), (-1, 0)):
        mutated = dict(check, requests_attempted=attempted, responses_evaluated=evaluated)
        assert not policy.protected_access_confirmation(mutated, finding, provider=PROVIDER, model=MODEL)


@pytest.mark.parametrize(('rule', 'maximum'), [
    ('authentication_bypass', 56), ('weak_credentials', 12),
    ('weak_api_key', 37), ('authorization_bypass', 4),
])
def test_failed_confirmations_obey_recorded_accounting_and_evaluation_bounds(rule, maximum):
    check, finding = records(rule)
    evaluated = check['responses_evaluated']
    check.update(status='failed', reason='Some required interactions failed', requests_attempted=maximum)
    assert policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    assert not policy.protected_access_confirmation(
        dict(check, requests_attempted=maximum + 1), finding, provider=PROVIDER, model=MODEL)
    assert not policy.protected_access_confirmation(
        dict(check, requests_attempted=maximum + 1, responses_evaluated=evaluated + 1),
        finding, provider=PROVIDER, model=MODEL)
    assert not policy.protected_access_confirmation(
        dict(check, reason={}), finding, provider=PROVIDER, model=MODEL)


@pytest.mark.asyncio
@pytest.mark.parametrize(('rule', 'wire_requests', 'recorded_attempts', 'findings_count'), [
    ('authentication_bypass', 20, 54, 1), ('weak_credentials', 7, 12, 5),
    ('weak_api_key', 32, 37, 5), ('authorization_bypass', 9, 12, 3),
])
async def test_actual_cleanup_failures_preserve_confirmations_with_bounded_accounting(
        monkeypatch, rule, wire_requests, recorded_attempts, findings_count):
    marker = 'opaque-resource-proof-8a917c21'
    issued = 'issued-fixture-credential-4f780d92'
    monkeypatch.setenv('ACCESS_POLICY_ISSUED_KEY', issued)
    monkeypatch.setattr('src.security.access_control_tests.asyncio.sleep', AsyncMock())
    budget = ScanBudget(allowed_networks=('192.0.2.0/24',))
    state = {'probes': 0}

    class Response:
        def __init__(self, status, body):
            self.status, self.body = status, body

        async def text(self):
            return self.body

    class Request:
        def __init__(self, session, url, headers):
            self.session, self.url, self.headers = session, url, headers

        async def __aenter__(self):
            budget.reserve(self.url)
            credential = self.headers.get('Authorization', '')
            if credential == 'Bearer ' + issued:
                return Response(200, marker)
            if credential.startswith('Bearer scanner-invalid-'):
                return Response(403, 'Denied')
            state['probes'] += 1
            index = state['probes']
            self.session.cleanup_error = (index > 1 if rule == 'authentication_bypass' else
                                          index % 6 == 0 if rule == 'weak_api_key' else True)
            return Response(200, 'Public resource' if rule == 'weak_api_key' and index % 6 else marker)

        async def __aexit__(self, *args):
            if self.session.cleanup_error:
                raise OSError('Synthetic response cleanup failure')

    class Session:
        def __init__(self, **kwargs):
            self.cleanup_error = False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            if self.cleanup_error and rule == 'authentication_bypass':
                raise OSError('Synthetic session cleanup failure')

        def get(self, url, *, headers, allow_redirects):
            assert allow_redirects is False
            return Request(self, url, headers)

    monkeypatch.setattr('src.security.access_control_tests.SafeSession', Session)
    agent = {'id': 'fixture', 'provider': PROVIDER, 'model': MODEL,
             'endpoint': 'http://192.0.2.1/resource', 'authentication_required': True,
             'protected_response_marker': marker, 'api_key_env': 'ACCESS_POLICY_ISSUED_KEY',
             'protected_path_markers': {path: marker for path in FROZEN_PATHS[:3]},
             'evidence_context_id': CONTEXT}
    with scan_transport(budget), collect_checks() as checks:
        findings = await getattr(AccessControlTester(), METHODS[rule])(agent)
    assert budget.requests == wire_requests
    assert checks[0]['requests_attempted'] == recorded_attempts
    assert checks[0]['responses_evaluated'] == wire_requests
    assert checks[0]['status'] == 'failed' and checks[0]['outcome'] == 'confirmed'
    assert len(findings) == findings_count
    assert all(finding['protected_control_version'] == 2 for finding in findings)
    assert all(policy.protected_access_confirmation(checks[0], finding, provider=PROVIDER, model=MODEL)
               for finding in findings)
    assert not policy.protected_access_pass(checks[0], provider=PROVIDER, model=MODEL)


@pytest.mark.parametrize('count', range(7, 33))
def test_completed_key_confirmation_allows_existing_early_breaks(count):
    check, finding = records('weak_api_key')
    check.update(requests_attempted=count, responses_evaluated=count)
    assert policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    assert policy.protected_access_pass(dict(check, outcome='passed'), provider=PROVIDER, model=MODEL) == (count == 32)


@pytest.mark.parametrize(('field', 'value'), [
    ('rule_id', 'weak_credentials'), ('probe_id', 'arbitrary'), ('probe_version', '1:unexecuted'),
    ('evidence_context_id', 'different'), ('evidence_context_id', '[redacted]'),
    ('control_status', 'denied_control_only'), ('status_code', 403), ('status_code', True),
    ('evidence_status', 'heuristic'), ('vulnerability_type', 'prompt_injection'),
])
def test_confirmation_rejects_mutated_finding_provenance(field, value):
    check, finding = records('authentication_bypass')
    finding[field] = value
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)


def test_null_evidence_context_must_match_and_be_present():
    check, finding = records('authentication_bypass')
    check['evidence_context_id'] = finding['evidence_context_id'] = None
    assert policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    del finding['evidence_context_id']
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)


@pytest.mark.parametrize('context', [
    '[CANARY_REDACTED]', '[GENERATED_TEXT_OMITTED]', '[RESPONSE_TEXT_OMITTED]',
    '[redacted]', 'prefix[CANARY_REDACTED]suffix', 'context[', 'context]',
])
@pytest.mark.parametrize('binding', ['both', 'check', 'finding'])
def test_bracketed_evidence_context_cannot_establish_confirmation_or_pass(context, binding):
    check, finding = records('authentication_bypass')
    if binding in ('both', 'check'):
        check['evidence_context_id'] = context
    if binding in ('both', 'finding'):
        finding['evidence_context_id'] = context
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    if binding in ('both', 'check'):
        assert not policy.protected_access_pass(dict(check, outcome='passed'), provider=PROVIDER, model=MODEL)


def test_bracketed_model_with_original_public_context_remains_eligible():
    model = 'local [label] model'
    check, finding = records('authentication_bypass', model=model)
    assert policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=model)
    assert policy.protected_access_pass(dict(check, outcome='passed'), provider=PROVIDER, model=model)


@pytest.mark.parametrize('rule', METHODS)
@pytest.mark.parametrize('status', [
    policy.ACCESS_CONTROL_STATUS,
    'authorized_marker_verified_and_[redacted]_credential_denied',
    '[redacted]_marker_verified_and_invalid_credential_[redacted]',
    '[redacted]',
])
def test_numeric_control_provenance_supports_bounded_literal_redaction(rule, status):
    check, finding = records(rule)
    finding.update(control_status=status, protected_control_version=2)
    assert policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    del finding['protected_control_version']
    assert policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL) == (
        status == policy.ACCESS_CONTROL_STATUS)


@pytest.mark.parametrize('version', [True, False, None, 0, 1, 3, '2', 2.0, [], {}])
def test_present_control_version_must_be_exact_supported_integer(version):
    check, finding = records('authentication_bypass')
    finding['protected_control_version'] = version
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)


@pytest.mark.parametrize('status', [
    None, [], '', 'denied_control_only', 'unrelated_[redacted]_credential_denied',
    '[other]', '[REDACTED]', '[redacted]' * 9, '[redacted]' + 'a' * 128,
    policy.ACCESS_CONTROL_STATUS + '[redacted]', '[redacted]' + policy.ACCESS_CONTROL_STATUS,
])
def test_numeric_control_version_cannot_repair_conflicting_or_missing_text(status):
    check, finding = records('authentication_bypass')
    finding.update(protected_control_version=2, control_status=status)
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    del finding['control_status']
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)


@pytest.mark.parametrize(('index', 'path'), [
    (0, '/admin'), (0, '/[redacted]'), (0, '[redacted]'), (0, '/[redacted]d[redacted]'),
    (2, '/[redacted]istrator'), (3, '/api/[redacted]'), (5, '/[redacted]/users'),
])
def test_indexed_path_retains_exact_or_compatible_redacted_public_reference(index, path):
    check, finding = records('authorization_bypass', paths=FROZEN_PATHS)
    finding.update(path=path, protected_path_index=index)
    assert policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)


@pytest.mark.parametrize(('index', 'path'), [
    (True, '/admin'), (None, '/admin'), (-1, '/admin'), (8, '/admin'), ('0', '/admin'),
    (0, '/api/admin'), (0, '/not-covered/[redacted]'), (0, '[other]'), (0, '/[REDACTED]'),
    (0, None), (0, []), (0, ''), (0, '/admin[redacted]'), (0, '[redacted]/admin'),
    (0, '[redacted]' * 9), (0, '[redacted]' + 'a' * 128), (0, '/[redacted]x'),
])
def test_indexed_path_rejects_invalid_missing_or_conflicting_references(index, path):
    check, finding = records('authorization_bypass', paths=FROZEN_PATHS)
    finding.update(path=path, protected_path_index=index)
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)


def test_index_does_not_expand_selected_path_coverage_or_replace_missing_path():
    check, finding = records('authorization_bypass', paths=('/admin',))
    finding.update(path='/api/[redacted]', protected_path_index=3)
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    finding['protected_path_index'] = 0
    del finding['path']
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    finding.update(path='/[redacted]')
    del finding['protected_path_index']
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)


@pytest.mark.parametrize('rule', METHODS)
def test_old_definition_and_custom_sample_are_not_current(rule):
    check, finding = records(rule)
    old = {'authentication_bypass': '18-header-variations-denied-control-v1',
           'weak_credentials': FROZEN_DEFINITIONS['weak_credentials'][0],
           'weak_api_key': FROZEN_DEFINITIONS['weak_api_key'][:2],
           'authorization_bypass': FROZEN_DEFINITIONS['authorization_bypass'][:2]}[rule]
    check['probe_version'] = finding['probe_version'] = frozen_version(rule, definition=old)
    assert not policy.protected_access_confirmation(check, finding, provider=PROVIDER, model=MODEL)
    assert not policy.protected_access_pass(dict(check, outcome='passed'), provider=PROVIDER, model=MODEL)
    check['probe_version'] = frozen_version(rule, definition=['custom-sample', policy.ACCESS_CONTROL_VERSION])
    assert policy.protected_access_probe(check, provider=PROVIDER, model=MODEL) is None


def test_empty_reordered_or_unknown_admin_subsets_are_not_current():
    for paths in ((), ('/admin/', '/admin'), ('/not-covered',), ('/admin', '/admin')):
        check = {'rule_id': 'authorization_bypass', 'probe_id': 'authorization_bypass.sample',
                 'probe_version': frozen_version('authorization_bypass', paths=paths)}
        assert policy.protected_access_probe(check, provider=PROVIDER, model=MODEL) is None


def test_public_cache_is_bounded_and_immutable():
    policy._authorization_probes.cache_clear()
    for index in range(130):
        check, _ = records('authorization_bypass', model='fixture-' + str(index))
        assert policy.protected_access_probe(check, provider=PROVIDER, model='fixture-' + str(index)) is not None
    info = policy._authorization_probes.cache_info()
    assert info.currsize == info.maxsize == 128
    versions = policy._authorization_probes(PROVIDER, MODEL)
    assert len(versions) == 255
    with pytest.raises(TypeError):
        versions['new'] = None
    policy._authorization_probes.cache_clear()


def test_fixed_probes_do_not_enumerate_admin_subsets():
    policy._authorization_probes.cache_clear()
    for rule in METHODS:
        if rule != 'authorization_bypass':
            check, _ = records(rule)
            assert policy.protected_access_probe(check, provider=PROVIDER, model=MODEL) is not None
    assert policy._authorization_probes.cache_info().misses == 0


def test_projection_helper_imports_no_engine_or_contracts():
    code = ('import sys; import src.core.access_probe_policy; '
            'assert "src.core.contracts" not in sys.modules; '
            'assert not any(name.startswith("src.security") for name in sys.modules)')
    result = subprocess.run([sys.executable, '-c', code], cwd=Path(__file__).parents[1],
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
