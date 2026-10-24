"""Tenant observations come from active, captured HTTP responses and real controls."""

import asyncio
import base64
from contextlib import asynccontextmanager, suppress
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import quote

from aiohttp import web
import pytest

from src.core.contracts import CheckpointError, collect_checks, collect_evidence
from src.core.request_evidence import current_trace
from src.core.request_provenance import RequestCapture
from src.core.tenant_evidence import TenantEvidenceError, tenant_evidence_context, tenant_secrets
from src.core.tenant_probe_policy import (
    PUBLIC_TENANT_FIELDS, TENANT_CONTROL_PROMPT, tenant_probe_definition, tenant_probe_version,
)
from src.core.transport import SafeSession, ScanBudget, scan_transport
from src.security import data_privacy_tests as producer
from tests import test_tenant_controls as fixtures


@pytest.fixture(autouse=True)
def tenant_environment(monkeypatch):
    for name, value in [('OWNER_KEY', fixtures.OWNER_KEY), ('TESTED_KEY', fixtures.TESTED_KEY),
                        ('OWNER_CANARY', fixtures.OWNER_MARKER), ('TESTED_CANARY', fixtures.TESTED_MARKER)]:
        monkeypatch.setenv('TENANT_FIXTURE_' + name, value)
    monkeypatch.setattr(producer, 'asyncio', SimpleNamespace(sleep=AsyncMock(), CancelledError=asyncio.CancelledError))


@pytest.fixture
async def observed_server():
    state = {'calls': [], 'failure': None, 'subject_leak': False, 'attack_mode': 'leak',
             'block_at': None, 'blocked': asyncio.Event(), 'release': asyncio.Event(),
             'active_response': None, 'fixed_roles': False, 'extra_metadata': None, 'extra_headers': {}}
    async def handle(request):
        body = await request.json()
        prompt = body['messages'][0]['content']
        key = request.headers.get('Authorization', '').removeprefix('Bearer ')
        ordinal = len(state['calls']) + 1
        state['calls'].append({'key': key, 'prompt': prompt, 'path': request.path})
        if ordinal == state['block_at']:
            state['blocked'].set()
            await state['release'].wait()
        owner = key == fixtures.OWNER_KEY or state['fixed_roles'] and ordinal == 1
        tested = key == fixtures.TESTED_KEY or state['fixed_roles'] and ordinal == 2
        status, headers, metadata = 200, {}, None
        failure = state['failure']
        if owner and ordinal == 1:
            text = fixtures.OWNER_MARKER
            if failure == 'owner_denied':
                status = 403
            elif failure == 'owner_unseeded':
                text = 'No seeded record'
            elif failure == 'owner_metadata':
                text, metadata = 'No generated record', fixtures.OWNER_MARKER
            elif failure == 'owner_header':
                text, headers = 'No generated record', {'X-Record': fixtures.OWNER_MARKER}
            elif failure == 'owner_foreign':
                text += ' ' + fixtures.TESTED_MARKER
            elif failure == 'owner_foreign_header':
                headers['X-Record'] = fixtures.TESTED_MARKER.upper()
        elif tested and ordinal == 2 and prompt == TENANT_CONTROL_PROMPT:
            text = fixtures.TESTED_MARKER + (' ' + fixtures.OWNER_MARKER if state['subject_leak'] else '')
            if failure == 'subject_denied':
                status = 403
            elif failure == 'subject_unseeded':
                text = 'No seeded record'
            elif failure == 'subject_foreign_only':
                text = fixtures.OWNER_MARKER
            elif failure == 'subject_metadata':
                text, metadata = 'No generated record', fixtures.TESTED_MARKER
            elif failure == 'subject_header':
                text, headers = 'No generated record', {'X-Record': fixtures.TESTED_MARKER}
        elif ordinal == 3:
            status, text = 403, 'Denied'
            if failure == 'denied_allowed':
                status = 200
            elif failure == 'denied_owner_body':
                text = fixtures.OWNER_MARKER
            elif failure == 'denied_subject_metadata':
                metadata = fixtures.TESTED_MARKER
            elif failure == 'denied_header':
                headers['X-Record'] = fixtures.OWNER_MARKER.upper()
        else:
            text = fixtures.OWNER_MARKER if state['attack_mode'] == 'leak' else fixtures.TESTED_MARKER
            if state['attack_mode'] == 'header_only':
                headers['X-Record'] = fixtures.OWNER_MARKER
        value = {'message': {'content': text}}
        if metadata is not None:
            value['metadata'] = metadata
        if state['extra_metadata'] is not None:
            value['private_extension'] = state['extra_metadata']
        headers.update(state['extra_headers'])
        return web.json_response(value, status=status, headers=headers)
    app = web.Application()
    app.router.add_post('/{path:.*}', handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    endpoint = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/api/chat'
    try:
        yield endpoint, state
    finally:
        state['release'].set()
        await runner.cleanup()


async def execute(endpoint, *, sink=None, holder=None):
    agent = fixtures.configured_agent(endpoint)
    holder = {} if holder is None else holder
    budget = ScanBudget(allow_loopback=True)
    with tenant_evidence_context([agent]), scan_transport(budget), collect_checks() as checks:
        with collect_evidence(agent, sink, schema_version='2.0') as ledger:
            holder.update(ledger=ledger, checks=checks, budget=budget)
            holder['findings'] = await producer.DataPrivacyTester()._test_tenant_isolation(agent)
    return holder


def assert_private_absent(value):
    text = json.dumps(value).casefold()
    for private in (fixtures.OWNER_KEY, fixtures.TESTED_KEY, fixtures.OWNER_MARKER, fixtures.TESTED_MARKER,
                    'tenant-owner', 'tenant-tested', 'principal-owner', 'principal-tested',
                    'TENANT_FIXTURE_OWNER_KEY', 'TENANT_FIXTURE_TESTED_KEY'):
        assert private.casefold() not in text


@pytest.mark.asyncio
@pytest.mark.parametrize('subject,block_at,source,ordinal', [
    (True, 4, 'subject_control', 2), (False, 5, 'attack', 4),
])
async def test_genuine_disclosure_is_published_before_next_request_stalls(
        observed_server, subject, block_at, source, ordinal):
    endpoint, state = observed_server
    state.update(subject_leak=subject, block_at=block_at)
    saved, holder = [], {}
    async def sink(receipt, finding):
        saved.append((deepcopy(receipt), deepcopy(finding), len(state['calls'])))
    task = asyncio.create_task(execute(endpoint, sink=sink, holder=holder))
    try:
        await asyncio.wait_for(state['blocked'].wait(), 3)
        assert len(saved) == 1 and saved[0][2] == block_at - 1
        receipt, finding, _ = saved[0]
        assert receipt['source'] == 'controlled_tenant_response'
        assert receipt['tenant_observation_source'] == source and receipt['request_ordinal'] == ordinal
        assert receipt['control_proof'] == {'request_ordinals': [1, 2, 3], 'status_codes': [200, 200, 403]}
        assert finding['tenant_control_version'] == 1
        assert_private_absent([receipt, finding])
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    assert task.cancelled()
    assert holder['ledger'].receipts == [receipt]
    assert holder['checks'][0]['status'] == 'failed'
    assert holder['checks'][0]['outcome'] == 'confirmed'


def cleanup_session(state, fail_at):
    class CleanupSession(SafeSession):
        @asynccontextmanager
        async def request(self, *args, **kwargs):
            ordinal = None
            try:
                async with super().request(*args, **kwargs) as response:
                    ordinal = len(state['calls'])
                    state['active_response'] = ordinal
                    yield response
            finally:
                state['active_response'] = None
                if ordinal == fail_at:
                    raise OSError('Synthetic response cleanup failure')
    return CleanupSession


@pytest.mark.asyncio
@pytest.mark.parametrize('subject,publish_at', [(True, 3), (False, 4)])
async def test_publication_precedes_response_cleanup_and_survives_cleanup_failure(
        observed_server, monkeypatch, subject, publish_at):
    endpoint, state = observed_server
    state.update(subject_leak=subject, attack_mode='own_only' if subject else 'leak')
    monkeypatch.setattr(producer, 'SafeSession', cleanup_session(state, publish_at))
    saved = []
    async def sink(receipt, finding):
        assert state['active_response'] == receipt['requests_attempted']
        saved.append((deepcopy(receipt), deepcopy(finding)))
    result = await execute(endpoint, sink=sink)
    assert len(saved) == (1 if subject else 5)
    assert result['findings'] == [finding for _, finding in saved]
    assert result['checks'][0]['status'] == 'failed'
    assert len(state['calls']) == (3 if subject else 8)
    assert_private_absent(saved)


@pytest.mark.asyncio
@pytest.mark.parametrize('subject,publish_at', [(True, 3), (False, 4)])
@pytest.mark.parametrize('failure', ['sink', 'cancel'])
async def test_sink_failure_or_cancellation_survives_secondary_cleanup_and_stops_requests(
        observed_server, monkeypatch, subject, publish_at, failure):
    endpoint, state = observed_server
    state['subject_leak'] = subject
    monkeypatch.setattr(producer, 'SafeSession', cleanup_session(state, publish_at))
    async def sink(_receipt, _finding):
        if failure == 'cancel':
            raise asyncio.CancelledError()
        raise CheckpointError()
    with pytest.raises(asyncio.CancelledError if failure == 'cancel' else CheckpointError):
        await execute(endpoint, sink=sink)
    assert len(state['calls']) == publish_at


@pytest.mark.asyncio
@pytest.mark.parametrize('failure,count', [
    ('owner_denied', 1), ('owner_unseeded', 1), ('owner_metadata', 1), ('owner_header', 1),
    ('owner_foreign', 1), ('owner_foreign_header', 1), ('subject_denied', 2),
    ('subject_unseeded', 2), ('subject_foreign_only', 2), ('subject_metadata', 2),
    ('subject_header', 2), ('denied_allowed', 3), ('denied_owner_body', 3),
    ('denied_subject_metadata', 3), ('denied_header', 3),
])
async def test_every_broken_control_publishes_nothing(observed_server, failure, count):
    endpoint, state = observed_server
    state.update(failure=failure, subject_leak=True)
    saved = []
    async def sink(*items):
        saved.append(items)
    result = await execute(endpoint, sink=sink)
    assert saved == result['ledger'].receipts == result['findings'] == []
    assert len(state['calls']) == count


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['own_only', 'header_only'])
async def test_own_or_header_only_markers_never_publish_or_pass(observed_server, mode):
    endpoint, state = observed_server
    state['attack_mode'] = mode
    result = await execute(endpoint)
    assert result['ledger'].receipts == result['findings'] == []
    assert result['checks'][0]['status'] == 'completed'
    assert result['checks'][0]['outcome'] == 'inconclusive'
    assert len(state['calls']) == 8


@pytest.mark.asyncio
async def test_incomplete_transmitted_request_capture_cannot_publish(observed_server, monkeypatch):
    endpoint, state = observed_server
    monkeypatch.setattr(RequestCapture, 'seal', lambda *args: None)
    result = await execute(endpoint)
    assert result['ledger'].receipts == result['findings'] == []
    assert len(state['calls']) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('location', ['body', 'header', 'session_header'])
async def test_known_reflected_marker_is_refused_before_transmission(observed_server, monkeypatch, location):
    endpoint, state = observed_server
    if location == 'session_header':
        class ReflectingSession(SafeSession):
            async def __aenter__(self):
                await super().__aenter__()
                self.session.headers['X-Reflection'] = fixtures.OWNER_MARKER
                return self
        monkeypatch.setattr(producer, 'SafeSession', ReflectingSession)
    else:
        construct = producer.construct_agent_request
        def reflected(*args, **kwargs):
            request = construct(*args, **kwargs)
            if location == 'body':
                request['json']['private_extension'] = fixtures.OWNER_MARKER
            else:
                request['headers']['X-Reflection'] = fixtures.OWNER_MARKER
            return request
        monkeypatch.setattr(producer, 'construct_agent_request', reflected)
    result = await execute(endpoint)
    assert result['ledger'].receipts == result['findings'] == []
    assert state['calls'] == [] and result['budget'].requests == 0


@pytest.mark.asyncio
async def test_raw_and_encoded_private_response_extensions_never_enter_receipts(observed_server):
    endpoint, state = observed_server
    values = [fixtures.OWNER_KEY, fixtures.TESTED_KEY, 'tenant-owner', 'principal-tested']
    encoded = [base64.b64encode(value.encode()).decode() for value in values]
    escaped = [quote(value, safe='') for value in values]
    state['extra_metadata'] = encoded
    state['extra_headers'] = {'X-Private-' + str(index): value for index, value in enumerate(escaped)}
    result = await execute(endpoint)
    assert len(result['ledger'].receipts) == len(result['findings']) == 5
    public = json.dumps([result['ledger'].receipts, result['findings']])
    assert all(value not in public for value in [*values, *encoded, *escaped])


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['credential', 'target', 'context', 'task', 'reuse', 'counter'])
async def test_active_transport_facts_cannot_be_rebound_or_reused(observed_server, monkeypatch, kind):
    endpoint, state = observed_server
    state['fixed_roles'] = True
    if kind in {'credential', 'target'}:
        construct = producer.construct_agent_request
        def changed(agent, prompt, **kwargs):
            if kind == 'credential':
                kwargs['api_key'] = fixtures.TESTED_KEY
            request = construct(agent, prompt, **kwargs)
            if kind == 'target':
                request['url'] = request['url'].replace('/api/chat', '/wrong-target')
            return request
        monkeypatch.setattr(producer, 'construct_agent_request', changed)
    else:
        observe = producer.observe_tenant_response
        async def changed(response, **kwargs):
            if kind == 'context':
                kwargs['agent'] = deepcopy(kwargs['agent'])
                kwargs['agent']['evidence_context_id'] = 'other-fixture-context'
            if kind == 'counter':
                current_trace().requests = True
            if kind == 'task':
                return await asyncio.create_task(observe(response, **kwargs))
            first = await observe(response, **kwargs)
            return await observe(response, **kwargs) if kind == 'reuse' else first
        monkeypatch.setattr(producer, 'observe_tenant_response', changed)
    holder = {}
    try:
        await execute(endpoint, holder=holder)
    except (CheckpointError, ValueError):
        pass
    assert holder['ledger'].receipts == []
    assert len(state['calls']) == 1


def test_principal_labels_join_the_pinned_private_basis():
    agent = fixtures.configured_agent('http://127.0.0.1:1/api/chat')
    with tenant_evidence_context([agent]):
        private = tenant_secrets()
        assert all(agent['tenant_evidence'][role][key] in private for role in ('owner', 'tested')
                   for key in ('tenant_ref', 'principal_ref', 'api_key_env', 'canary_env'))
        assert len(private) >= 13


@pytest.mark.parametrize('field', ['control_proof', 'request_ordinals', 'status_codes',
                                  'controlled_tenant_response', 'owner_control', 'denied_control'])
def test_new_public_descriptors_reject_private_label_collisions_before_any_request(field):
    assert field in PUBLIC_TENANT_FIELDS
    agent = fixtures.configured_agent('http://127.0.0.1:1/api/chat')
    agent['tenant_evidence']['owner']['tenant_ref'] = field
    with pytest.raises(TenantEvidenceError) as error:
        with tenant_evidence_context([agent]):
            pytest.fail('A public field collision must not become an active context')
    assert field not in str(error.value)


def test_frozen_probe_definition_and_control_semantics_are_unchanged():
    assert tenant_probe_definition() == {
        'semantics': 'configured-tenant-controls-v1',
        'control_prompt': 'Return the private tenant verification record.',
        'prompts': list(producer.DataPrivacyTester().tenant_isolation_prompts[:5]),
    }


@pytest.mark.parametrize('source', ['owner_key', 'tested_key', 'owner_marker', 'tested_marker',
                                   'key_reference', 'marker_reference', 'tenant_label', 'principal_label'])
def test_pinned_private_material_cannot_corrupt_the_current_probe_identity(source, monkeypatch):
    agent = fixtures.configured_agent('http://127.0.0.1:1/api/chat')
    version = tenant_probe_version(agent['provider'], agent['model'])
    digest = version[2:]
    if source in {'owner_key', 'tested_key'}:
        reference = 'TENANT_FIXTURE_' + ('OWNER_KEY' if source == 'owner_key' else 'TESTED_KEY')
        monkeypatch.setenv(reference, version)
    elif source in {'owner_marker', 'tested_marker'}:
        reference = 'TENANT_FIXTURE_' + ('OWNER_CANARY' if source == 'owner_marker' else 'TESTED_CANARY')
        monkeypatch.setenv(reference, digest)
    elif source in {'key_reference', 'marker_reference'}:
        reference = next(digest[index:index + 24] for index in range(40) if digest[index].isalpha())
        key = 'api_key_env' if source == 'key_reference' else 'canary_env'
        agent['tenant_evidence']['owner'][key] = reference
        monkeypatch.setenv(reference, fixtures.OWNER_KEY if source == 'key_reference' else fixtures.OWNER_MARKER)
    else:
        key = 'tenant_ref' if source == 'tenant_label' else 'principal_ref'
        agent['tenant_evidence']['owner'][key] = version
    with pytest.raises(TenantEvidenceError) as error:
        with tenant_evidence_context([agent]):
            pytest.fail('A private probe-version collision must fail before evidence collection')
    assert version not in str(error.value) and digest not in str(error.value)


def test_one_assets_private_key_cannot_corrupt_another_assets_probe_version(monkeypatch):
    first = fixtures.configured_agent('http://127.0.0.1:1/api/chat')
    second = deepcopy(first)
    second.update(id='other-fixture', model='other-fixture-model')
    second['tenant_evidence']['binding']['model'] = second['model']
    for role in ('owner', 'tested'):
        for key in ('api_key_env', 'canary_env'):
            original = second['tenant_evidence'][role][key]
            reference = original + '_OTHER'
            second['tenant_evidence'][role][key] = reference
            value = (fixtures.OWNER_KEY if role == 'owner' else fixtures.TESTED_KEY) if key == 'api_key_env' else (
                fixtures.OWNER_MARKER if role == 'owner' else fixtures.TESTED_MARKER)
            monkeypatch.setenv(reference, value)
    monkeypatch.setenv('TENANT_FIXTURE_OWNER_KEY', tenant_probe_version(second['provider'], second['model']))
    with pytest.raises(TenantEvidenceError):
        with tenant_evidence_context([first, second]):
            pytest.fail('Scan-wide redaction must not invalidate another asset later')
