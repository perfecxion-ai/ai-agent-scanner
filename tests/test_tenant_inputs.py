"""Private local tenant declarations, pinned values, and server rejection."""

import asyncio
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from click.testing import CliRunner
import pytest

import scanner_cli
from src.core import tenant_evidence as private
from src.core.pipeline import run_pipeline, to_sarif
from src.core.redaction import collect_secrets, redact_secrets
from src.core.request_provenance import RequestEvidence
from src.core.scope import ScopeValidationError, validate_request
from src.core.tenant_probe_policy import tenant_target
from src.utils.request_builder import construct_agent_request, resolve_api_key
from tests.test_api_auth import api as api, headers
from tests.test_scan_templates import definition, source_fixture, security_definition
from tests.claimed_execution import execute_scan


OWNER_KEY = 'synthetic-owner-key-238b379f'
TESTED_KEY = 'synthetic-tested-key-61ca992a'
OWNER_MARKER = 'synthetic-owner-marker-8a5b3348'
TESTED_MARKER = 'synthetic-tested-marker-32e34698'
VALUES = dict(TENANT_FIXTURE_OWNER_KEY=OWNER_KEY, TENANT_FIXTURE_TESTED_KEY=TESTED_KEY,
              TENANT_FIXTURE_OWNER_MARKER=OWNER_MARKER, TENANT_FIXTURE_TESTED_MARKER=TESTED_MARKER)


def tenant_agent(endpoint='https://192.0.2.1/v1/chat'):
    agent = dict(id='asset', name='Tenant fixture', endpoint=endpoint, provider='openai-compatible',
                 model='fixture-model', evidence_context_id='tenant-fixture-v1',
                 api_key_env='TENANT_FIXTURE_TESTED_KEY')
    agent['tenant_evidence'] = dict(
        schema_version='1.0',
        binding=tenant_target(endpoint, agent['provider'], agent['model'], agent['evidence_context_id']),
        tested_principal_authorized_for_owner=False,
        owner=dict(tenant_ref='owner-tenant', principal_ref='owner-principal',
                   api_key_env='TENANT_FIXTURE_OWNER_KEY', canary_env='TENANT_FIXTURE_OWNER_MARKER'),
        tested=dict(tenant_ref='tested-tenant', principal_ref='tested-principal',
                    api_key_env='TENANT_FIXTURE_TESTED_KEY', canary_env='TENANT_FIXTURE_TESTED_MARKER'))
    return agent


class Environment(dict):
    def __init__(self, values=VALUES):
        super().__init__(values)
        self.reads = []

    def get(self, key, default=None):
        self.reads.append(key)
        return super().get(key, default)


@pytest.fixture
def controlled_env(monkeypatch):
    environment = Environment()
    monkeypatch.setattr(private, 'os', SimpleNamespace(environ=environment))
    return environment


@pytest.mark.parametrize('mutation', [
    'missing_attestation', 'true_attestation', 'numeric_attestation', 'unknown_field', 'unknown_actor',
    'wrong_schema', 'raw_canary', 'same_tenant', 'same_principal', 'same_reference', 'wrong_outer_key',
    'wrong_endpoint', 'wrong_provider', 'wrong_model', 'wrong_context', 'invalid_environment',
    'private_registry', 'extra_binding', 'no_model', 'no_context', 'bad_envelope', 'bad_actor',
])
def test_invalid_declarations_fail_before_environment_lookup(controlled_env, mutation):
    agent = tenant_agent()
    value = agent['tenant_evidence']
    if mutation == 'missing_attestation':
        del value['tested_principal_authorized_for_owner']
    elif mutation in {'true_attestation', 'numeric_attestation'}:
        value['tested_principal_authorized_for_owner'] = True if mutation == 'true_attestation' else 0
    elif mutation == 'unknown_field':
        value['private_extra'] = OWNER_MARKER
    elif mutation == 'unknown_actor':
        value['owner']['private_extra'] = OWNER_MARKER
    elif mutation == 'wrong_schema':
        value['schema_version'] = '2.0'
    elif mutation == 'raw_canary':
        agent['cross_tenant_canary'] = OWNER_MARKER
    elif mutation in {'same_tenant', 'same_principal', 'same_reference'}:
        field = {'same_tenant': 'tenant_ref', 'same_principal': 'principal_ref',
                 'same_reference': 'canary_env'}[mutation]
        value['tested'][field] = value['owner'][field]
    elif mutation == 'wrong_outer_key':
        agent['api_key_env'] = value['owner']['api_key_env']
    elif mutation.startswith('wrong_'):
        value['binding'][{'wrong_context': 'evidence_context_id'}.get(mutation, mutation[6:])] = 'other'
    elif mutation in {'invalid_environment', 'private_registry'}:
        value['owner']['api_key_env'] = 'private-ref=' if mutation == 'invalid_environment' else 'SCAN_EVIDENCE_PROFILES_FILE'
    elif mutation == 'extra_binding':
        value['binding']['private_extra'] = OWNER_MARKER
    elif mutation == 'no_model':
        del agent['model']
    elif mutation == 'no_context':
        del agent['evidence_context_id']
    elif mutation == 'bad_envelope':
        agent['tenant_evidence'] = None
    else:
        value['owner'] = []
    with pytest.raises(private.TenantEvidenceError) as caught, private.tenant_evidence_context([agent]):
        pytest.fail('Invalid declaration was prepared')
    assert controlled_env.reads == []
    assert all(secret not in str(caught.value) for secret in (*VALUES, *VALUES.values()))


@pytest.mark.parametrize('endpoint', [
    'http://192.0.2.1', 'http://localhost', 'http://loopback.test', 'https://user:pass@192.0.2.1',
    'https://192.0.2.1?', 'https://192.0.2.1/#', 'https://192.0.2.1/%2e',
    'https://192.0.2.1/a/../b', 'https://192.0.2.1\\private', 'https://192.0.2.1:0',
])
def test_unsafe_transport_or_ambiguous_endpoint_never_resolves(controlled_env, endpoint):
    agent = tenant_agent()
    agent['endpoint'] = agent['tenant_evidence']['binding']['endpoint'] = endpoint
    with pytest.raises(private.TenantEvidenceError), private.tenant_evidence_context([agent]):
        pytest.fail('Unsafe transport accepted')
    assert controlled_env.reads == []


@pytest.mark.parametrize('endpoint', ['http://127.0.0.1:12345', 'http://[::1]:12345', 'https://192.0.2.1'])
def test_local_or_tls_target_prepares_immutable_controls(controlled_env, endpoint):
    agent = tenant_agent(endpoint)
    with private.tenant_evidence_context([agent]) as secrets:
        context = private.get_tenant_evidence(agent)
        assert context.target == agent['tenant_evidence']['binding']
        assert set(VALUES.values()) <= set(secrets) and set(VALUES) <= set(secrets)
        assert context.invalid_api_key in secrets
        assert all(value not in repr(context) for value in VALUES.values())
        with pytest.raises(FrozenInstanceError):
            context.owner_api_key = TESTED_KEY
        with pytest.raises(TypeError):
            context.target['model'] = 'other'
    assert private.tenant_secrets() == () and private.tenant_context(agent) is None


@pytest.mark.parametrize('reference,value', [
    ('TENANT_FIXTURE_OWNER_KEY', None), ('TENANT_FIXTURE_TESTED_KEY', ''),
    ('TENANT_FIXTURE_OWNER_MARKER', 'short'), ('TENANT_FIXTURE_TESTED_MARKER', 'contains spaces in marker'),
    ('TENANT_FIXTURE_OWNER_MARKER', 'x' * 129), ('TENANT_FIXTURE_OWNER_KEY', TESTED_KEY),
    ('TENANT_FIXTURE_TESTED_MARKER', OWNER_MARKER.upper()),
    ('TENANT_FIXTURE_TESTED_MARKER', OWNER_MARKER + 'suffix'),
    ('TENANT_FIXTURE_OWNER_KEY', OWNER_MARKER.upper()),
    ('TENANT_FIXTURE_TESTED_KEY', TESTED_MARKER + 'prefix'),
    ('TENANT_FIXTURE_OWNER_KEY', 'tenant_control_version'),
])
def test_unavailable_overlapping_or_structural_secrets_fail(controlled_env, reference, value):
    controlled_env[reference] = value
    with pytest.raises(private.TenantEvidenceError), private.tenant_evidence_context([tenant_agent()]):
        pytest.fail('Invalid secrets accepted')
    assert private.tenant_secrets() == ()


@pytest.mark.parametrize('field', ['id', 'name', 'model', 'evidence_context_id', 'metadata'])
@pytest.mark.parametrize('secret', [OWNER_MARKER, TESTED_MARKER, OWNER_KEY, TESTED_KEY])
def test_public_input_collisions_fail_before_testers(controlled_env, field, secret):
    agent = tenant_agent()
    agent[field] = {'note': secret.upper()} if field == 'metadata' else secret.upper()
    if field in agent['tenant_evidence']['binding']:
        agent['tenant_evidence']['binding'][field] = agent[field]
    with pytest.raises(private.TenantEvidenceError), private.tenant_evidence_context([agent]):
        pytest.fail('Private material in public input accepted')


def test_values_pin_once_and_copied_or_nested_agents_do_not_reread(controlled_env):
    agent = tenant_agent()
    with private.tenant_evidence_context([agent]):
        context = private.get_tenant_evidence(agent)
        assert len(controlled_env.reads) == 4
        controlled_env.clear()
        with private.tenant_evidence_context([deepcopy(agent)]):
            assert private.tenant_context(deepcopy(agent)) is context
            assert resolve_api_key(agent) == TESTED_KEY
            assert construct_agent_request(agent, 'ordinary request')['headers']['Authorization'] == 'Bearer ' + TESTED_KEY
            assert construct_agent_request(agent, 'owner request', api_key=context.owner_api_key)['headers']['Authorization'] == 'Bearer ' + OWNER_KEY
            assert len(controlled_env.reads) == 4
    assert private.tenant_secrets() == ()


@pytest.mark.parametrize('mutation', ['model', 'endpoint', 'context', 'ref', 'remove', 'new_asset'])
def test_nested_mutation_cannot_rebind_or_reresolve(controlled_env, mutation):
    original = tenant_agent()
    with private.tenant_evidence_context([original]):
        changed = deepcopy(original)
        if mutation in {'model', 'endpoint', 'context'}:
            field = 'evidence_context_id' if mutation == 'context' else mutation
            changed[field] = 'other' if field != 'endpoint' else 'https://192.0.2.2/'
            changed['tenant_evidence']['binding'][field] = changed[field]
        elif mutation == 'ref':
            changed['tenant_evidence']['owner']['api_key_env'] = 'OTHER_OWNER_KEY'
        elif mutation == 'remove':
            del changed['tenant_evidence']
        else:
            changed['id'] = 'other-asset'
        with pytest.raises(private.TenantEvidenceError), private.tenant_evidence_context([changed]):
            pytest.fail('Nested context changed identity')
        assert len(controlled_env.reads) == 4


@pytest.mark.parametrize('marker', [OWNER_MARKER, TESTED_MARKER])
@pytest.mark.parametrize('location', ['payload', 'credential'])
def test_every_adapter_request_excludes_both_pinned_markers(controlled_env, marker, location):
    agent = tenant_agent()
    with private.tenant_evidence_context([agent]):
        if location == 'payload':
            request = construct_agent_request(agent, 'echo ' + marker.upper())
        else:
            request = construct_agent_request(agent, 'ordinary request', api_key=marker.upper())
        assert request is None


def test_unprepared_declaration_never_reads_credentials_or_issues_request(controlled_env):
    agent = tenant_agent()
    assert resolve_api_key(agent) is None
    assert construct_agent_request(agent, 'ordinary request') is None
    assert construct_agent_request(agent, 'ordinary request', api_key=TESTED_KEY) is None
    assert controlled_env.reads == []


@pytest.mark.asyncio
async def test_parallel_scan_contexts_are_isolated_and_cleanup_after_failure(controlled_env):
    ready = asyncio.Event()
    contexts = []
    async def run(identifier):
        agent = {**tenant_agent(), 'id': identifier}
        with private.tenant_evidence_context([agent]):
            contexts.append(private.tenant_context(agent))
            if len(contexts) == 2:
                ready.set()
            await ready.wait()
            assert private.tenant_context(agent) in contexts
            other = {**agent, 'id': 'second' if identifier == 'first' else 'first'}
            assert private.tenant_context(other) is None
    await asyncio.gather(run('first'), run('second'))
    assert contexts[0].invalid_api_key != contexts[1].invalid_api_key
    assert private.tenant_secrets() == ()
    with pytest.raises(RuntimeError), private.tenant_evidence_context([tenant_agent()]):
        raise RuntimeError('fixture interruption')
    assert private.tenant_secrets() == ()


def test_whole_private_envelope_omitted_without_redacting_schema_version(controlled_env):
    agent = tenant_agent()
    with private.tenant_evidence_context([agent]):
        secrets = collect_secrets(agent) | set(private.tenant_secrets())
        clean = redact_secrets(dict(schema_version='1.0', agent=agent, secret_echo=OWNER_MARKER), secrets)
        assert clean['schema_version'] == '1.0'
        assert clean['agent']['tenant_evidence'] == '[redacted]'
        serialized = json.dumps(clean)
        assert all(value not in serialized for value in (*VALUES, *VALUES.values(), 'owner-principal', 'owner-tenant'))


def test_cli_accepts_strict_private_envelope_without_resolving(tmp_path, controlled_env):
    config = tmp_path / 'input.json'
    config.write_text(json.dumps({'agents': [tenant_agent()]}))
    _, agents = scanner_cli.load_targets((), (), config=str(config))
    assert agents[0]['tenant_evidence'] == tenant_agent()['tenant_evidence']
    assert controlled_env.reads == []


def test_cli_invalid_attestation_is_static_and_precedes_execution(tmp_path, controlled_env, monkeypatch):
    agent = tenant_agent()
    del agent['tenant_evidence']['tested_principal_authorized_for_owner']
    config = tmp_path / 'input.json'
    config.write_text(json.dumps({'agents': [agent]}))
    execution = AsyncMock()
    monkeypatch.setattr(scanner_cli, 'run_pipeline', execution)
    result = CliRunner().invoke(scanner_cli.cli, ['scan', '--config', str(config)])
    assert result.exit_code != 0 and 'Tenant evidence is invalid' in result.output
    execution.assert_not_called()
    assert controlled_env.reads == []
    assert all(value not in result.output for value in (*VALUES, *VALUES.values()))


@pytest.mark.parametrize('placement', ['root', 'options', 'scope', 'metadata'])
@pytest.mark.parametrize('field', ['tenant_evidence', 'cross_tenant_canary'])
def test_server_admission_rejects_private_inputs_before_resolution(api, controlled_env, placement, field):
    module, client = api
    data = definition()
    target = data if placement == 'root' else data.setdefault(
        {'options': 'scan_config', 'scope': 'target_scope', 'metadata': 'metadata'}[placement], {})
    target[field] = tenant_agent()['tenant_evidence'] if field == 'tenant_evidence' else OWNER_MARKER
    with pytest.raises(ScopeValidationError, match='only in local'):
        validate_request(data, module.app.config)
    for endpoint in ('/api/scans', '/api/templates'):
        response = client.post(endpoint, headers=headers(module), json=data)
        assert response.status_code == 400
        assert all(value not in response.get_data(as_text=True) for value in (*VALUES, *VALUES.values()))
    assert controlled_env.reads == []
    assert module.ScanJob.query.count() == 0


@pytest.mark.parametrize('placement', ['agent', 'metadata'])
def test_saved_source_private_envelope_rejected_without_mutation(api, controlled_env, placement):
    module, client = api
    source_fixture(module)
    stored = module.db.session.get(module.ScanResult, 'source')
    report = deepcopy(stored.result)
    target = report['agents'][0] if placement == 'agent' else report['agents'][0].setdefault('metadata', {})
    target['tenant_evidence'] = tenant_agent()['tenant_evidence']
    stored.result = deepcopy(report)
    module.db.session.commit()
    for endpoint in ('/api/scans', '/api/templates'):
        response = client.post(endpoint, headers=headers(module), json=security_definition())
        assert response.status_code == 400
    assert module.db.session.get(module.ScanResult, 'source').result == report
    assert controlled_env.reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['full', 'discovery_only'])
async def test_fresh_server_discovery_rejects_before_env_testers_or_checkpoint(api, controlled_env, monkeypatch, mode):
    module, _ = api
    agent = tenant_agent()
    monkeypatch.setattr(module, 'discovery_engine', SimpleNamespace(discover_agents=AsyncMock(return_value=[agent])))
    tester = AsyncMock()
    monkeypatch.setattr(module.security_engine, 'test_agents', tester)
    module.db.session.add(module.ScanSession(id='tenant-fixture', organization_id='tenant-a',
                          scan_name='fixture', scan_type=mode, target_scope={}, scan_config={}, status='queued'))
    module.db.session.commit()
    await execute_scan(module, 'tenant-fixture', mode, {}, {})
    assert module.db.session.get(module.ScanSession, 'tenant-fixture').status == 'failed'
    report = module.db.session.get(module.ScanResult, 'tenant-fixture').result
    assert report['status'] == 'failed' and report['agents'] == []
    assert 'checkpoint' not in report
    assert all(value not in json.dumps(report) for value in (*VALUES, *VALUES.values()))
    assert controlled_env.reads == []
    tester.assert_not_called()


@pytest.mark.asyncio
async def test_pipeline_checkpoint_pins_values_and_omits_private_envelope(controlled_env):
    from src.risk.risk_assessor import RiskAssessment
    agent = tenant_agent()
    contexts, snapshots = [], []
    async def checkpoint(report):
        snapshots.append(deepcopy(report))
        controlled_env.clear()
    async def assess(values):
        contexts.append(private.tenant_context(values[0]))
        assert resolve_api_key(values[0]) == TESTED_KEY
        return [dict(agent_id='asset', status='skipped', vulnerabilities=[], reason='Fixture skip')]
    security = SimpleNamespace(test_agents=assess)
    output = await run_pipeline(Mock(), security, RiskAssessment(), None, 'security_only',
                                agents=[agent], checkpoint_callback=checkpoint)
    assert len(contexts) == 1 and contexts[0].owner_api_key == OWNER_KEY
    assert snapshots and len(controlled_env.reads) == 4
    for report in [output, *snapshots]:
        serialized = json.dumps([report, to_sarif(report)])
        assert report['schema_version'] == '1.0'
        assert all(value not in serialized for value in (*VALUES, *VALUES.values(), 'owner-principal', 'owner-tenant'))
    assert private.tenant_secrets() == ()


@pytest.mark.asyncio
@pytest.mark.parametrize('placement', ['options', 'scope'])
async def test_queued_definition_rejects_private_inputs_before_discovery(api, controlled_env, monkeypatch, placement):
    module, _ = api
    discovery = AsyncMock()
    monkeypatch.setattr(module, 'discovery_engine', SimpleNamespace(discover_agents=discovery))
    scope, options = {}, {}
    target = scope if placement == 'scope' else options
    target['tenant_evidence'] = tenant_agent()['tenant_evidence']
    module.db.session.add(module.ScanSession(id='queued-tenant', organization_id='tenant-a',
                          scan_name='fixture', scan_type='full', target_scope={}, scan_config={}, status='queued'))
    module.db.session.commit()
    await execute_scan(module, 'queued-tenant', 'full', scope, options)
    discovery.assert_not_called()
    assert controlled_env.reads == []
    assert module.db.session.get(module.ScanSession, 'queued-tenant').status == 'failed'


@pytest.mark.asyncio
async def test_queued_source_changed_after_admission_is_rejected(api, controlled_env, monkeypatch):
    module, client = api
    source_fixture(module)
    admitted = client.post('/api/scans', headers=headers(module), json=security_definition())
    assert admitted.status_code == 202
    scan_id = admitted.json['scan_id']
    stored = module.db.session.get(module.ScanResult, 'source')
    changed = deepcopy(stored.result)
    changed['agents'][0]['tenant_evidence'] = tenant_agent()['tenant_evidence']
    stored.result = changed
    module.db.session.commit()
    tester = AsyncMock()
    monkeypatch.setattr(module.security_engine, 'test_agents', tester)
    await execute_scan(module, scan_id, 'security_only', {}, security_definition()['scan_config'])
    tester.assert_not_called()
    assert controlled_env.reads == []
    assert module.db.session.get(module.ScanSession, scan_id).status == 'failed'
    assert module.db.session.get(module.ScanResult, 'source').result == changed


def test_default_port_binding_and_existing_opaque_marker_grammar(controlled_env):
    agent = tenant_agent()
    agent['tenant_evidence']['binding']['endpoint'] = agent['endpoint']
    controlled_env['TENANT_FIXTURE_OWNER_MARKER'] = 'fixture.owner~marker.8a5b3348'
    with private.tenant_evidence_context([agent]):
        context = private.tenant_context(agent)
        assert context.target['endpoint'] == 'https://192.0.2.1:443/v1/chat'
        assert context.owner_canary == 'fixture.owner~marker.8a5b3348'


@pytest.mark.parametrize('location', ['url', 'header_name', 'header_value', 'session_header', 'json', 'data', 'params'])
@pytest.mark.parametrize('marker', [OWNER_MARKER, TESTED_MARKER])
def test_transport_preflight_covers_all_known_request_material(controlled_env, location, marker):
    agent = tenant_agent()
    method, url, kwargs, headers = 'POST', agent['endpoint'], {}, {}
    marker = marker.upper()
    if location == 'url':
        url += '/' + marker
    elif location == 'header_name':
        kwargs['headers'] = {marker: 'fixture'}
    elif location == 'header_value':
        kwargs['headers'] = {'Fixture': marker}
    elif location == 'session_header':
        headers['Fixture'] = marker
    else:
        kwargs[location] = {'private': marker}
    with private.tenant_evidence_context([agent]):
        with pytest.raises(private.TenantEvidenceError):
            private.guard_tenant_request(method, url, kwargs, headers)
        # Rejection precedes I/O, so it does not invent transmitted contamination.
        assert private.tenant_evidence_usable(agent)


@pytest.mark.parametrize('evidence', [None, RequestEvidence('POST', 'https://192.0.2.1/', (), b'')])
def test_missing_or_incomplete_transmitted_provenance_taints_control_set(controlled_env, evidence):
    agent = tenant_agent()
    with private.tenant_evidence_context([agent]):
        context = private.tenant_context(agent)
        private.observe_tenant_request(evidence)
        assert private.tenant_context(agent) is context
        assert private.tenant_evidence_tainted(agent)
        assert not private.tenant_evidence_usable(agent)
        with private.tenant_evidence_context([deepcopy(agent)]):
            assert not private.tenant_evidence_usable(agent)
        assert len(controlled_env.reads) == 4


@pytest.mark.parametrize('marker', [OWNER_MARKER, TESTED_MARKER])
def test_transport_added_headers_taint_without_discarding_pinned_credentials(controlled_env, marker):
    agent = tenant_agent()
    # Pure request-audit contract fixture. Real transport acceptance is separate.
    snapshot = RequestEvidence('GET', agent['endpoint'], (('User-Agent', marker.upper()),), b'')
    with private.tenant_evidence_context([agent]):
        private.observe_tenant_request(snapshot)
        assert not private.tenant_evidence_usable(agent)
        assert resolve_api_key(agent) == TESTED_KEY


def test_unrelated_request_does_not_taint_and_audit_does_not_escape_scan(controlled_env):
    agent = tenant_agent()
    snapshot = RequestEvidence('GET', agent['endpoint'], (('User-Agent', 'fixture-client'),), b'')
    with private.tenant_evidence_context([agent]):
        private.guard_tenant_request('GET', agent['endpoint'], {'timeout': object()}, {'Accept': 'application/json'})
        private.observe_tenant_request(snapshot)
        assert private.tenant_evidence_usable(agent)
        private.observe_tenant_request(None)
        assert private.tenant_evidence_tainted(agent)
    with private.tenant_evidence_context([agent]):
        assert private.tenant_evidence_usable(agent)
    private.guard_tenant_request('POST', 'unavailable', {'data': object()}, {})
    private.observe_tenant_request(None)
    assert not private.tenant_evidence_tainted(agent)


def test_audit_bounds_taint_to_matching_prepared_assets(controlled_env):
    first = tenant_agent()
    second = deepcopy(first)
    second['id'] = 'second-asset'
    for actor in ('owner', 'tested'):
        for key in ('api_key_env', 'canary_env'):
            previous = second['tenant_evidence'][actor][key]
            replacement = previous + '_SECOND'
            second['tenant_evidence'][actor][key] = replacement
            controlled_env[replacement] = controlled_env[previous] + '-second'
    second['api_key_env'] = second['tenant_evidence']['tested']['api_key_env']
    with private.tenant_evidence_context([first, second]):
        snapshot = RequestEvidence('GET', first['endpoint'], (('Fixture', OWNER_MARKER),), b'')
        private.observe_tenant_request(snapshot)
        assert private.tenant_evidence_tainted(first)
        assert private.tenant_evidence_usable(second)
        private.observe_tenant_request(None)
        assert private.tenant_evidence_tainted(second)
