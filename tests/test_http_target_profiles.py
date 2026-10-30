"""Private profile boundaries and offline readiness for explicit HTTP targets."""

from copy import deepcopy
import json
import os
import socket
import stat
import sys
from unittest.mock import Mock

import pytest

from src.core.http_target_profiles import (
    TargetProfileError, create_http_target_profile, load_http_target_profile,
    plan_http_profile, prepare_http_profile, validate_http_target_profile,
)
import src.core.http_target_profiles as profiles


CANARY = 'synthetic-http-canary-4d035719'
CREDENTIAL = 'synthetic-http-bearer-5392c610'
CANARY_ENV = 'AIS_FIXTURE_HTTP_CANARY'
CREDENTIAL_ENV = 'AIS_FIXTURE_HTTP_CREDENTIAL'


def document(*, bearer=False, endpoint='http://127.0.0.1:19876/chat'):
    return {'schema_version': '1.0', 'name': 'Support application',
            'http_target': {'adapter_id': 'http-json', 'adapter_version': '1.0', 'endpoint': endpoint,
                            'method': 'POST', 'request_prompt_field': 'question',
                            'response_text_pointer': '/answer/text',
                            'auth_scheme': 'bearer' if bearer else 'none',
                            'principal_label': 'authorized-test-v1' if bearer else 'anonymous',
                            'context_label': 'support-protected-fixture-v1', 'session_mode': 'fresh-per-prompt-v1'},
            'allowed_networks': ['127.0.0.1/32'], 'credential_env': CREDENTIAL_ENV if bearer else None,
            'canary_env': CANARY_ENV, 'canary_seeded': True}


@pytest.fixture
def references(monkeypatch):
    monkeypatch.setenv(CANARY_ENV, CANARY)
    monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL)


def profile_file(tmp_path, value=None):
    target = tmp_path / 'private-profiles' / 'target.json'
    create_http_target_profile(target, document() if value is None else value)
    return target


def test_owned_profile_roundtrip_and_generated_public_identity(tmp_path, references):
    path = profile_file(tmp_path)
    profile = load_http_target_profile(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert profile.descriptor['endpoint'] == 'http://127.0.0.1:19876/chat'
    profile.descriptor['request_prompt_field'] = 'Changed copy'
    assert load_http_target_profile(path).descriptor['request_prompt_field'] == 'question'
    prepared = prepare_http_profile(profile, path, allow_loopback=True)
    assert prepared.agent['provider'] == 'http-json' and prepared.agent['model'] is None
    assert len(prepared.agent['id']) == 64 and prepared.agent['id'] == prepared.agent['http_target_binding']
    assert prepared.agent['system_prompt_canary'] == CANARY
    assert CANARY not in path.read_text() and CREDENTIAL not in path.read_text()
    assert all(value not in repr(prepared) + repr(profile) for value in (CANARY, CREDENTIAL, CANARY_ENV, str(path)))


@pytest.mark.parametrize('kind', ['file', 'symlink', 'hardlink', 'directory'])
def test_creation_never_clobbers_an_existing_destination(tmp_path, references, kind):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    other = tmp_path / 'original'
    other.write_bytes(b'Unrelated original bytes')
    path = directory / 'target.json'
    if kind == 'file':
        path.write_bytes(b'Existing profile bytes')
    elif kind == 'symlink':
        path.symlink_to(other)
    elif kind == 'hardlink':
        os.link(other, path)
    else:
        path.mkdir()
    before = path.read_bytes() if kind != 'directory' else None
    with pytest.raises(TargetProfileError, match='destination already exists'):
        create_http_target_profile(path, document())
    assert other.read_bytes() == b'Unrelated original bytes'
    if before is not None:
        assert path.read_bytes() == before


@pytest.mark.parametrize('fault', ['public-file', 'public-directory', 'symlink', 'hardlink', 'fifo', 'owner'])
def test_unsafe_profiles_are_refused_before_read(tmp_path, references, monkeypatch, fault):
    path = profile_file(tmp_path)
    if fault == 'public-file':
        path.chmod(0o644)
    elif fault == 'public-directory':
        path.parent.chmod(0o755)
    elif fault == 'owner':
        actual = os.getuid()
        monkeypatch.setattr(profiles.os, 'getuid', lambda: actual + 1)
    else:
        original = path.with_name('original.json')
        path.rename(original)
        if fault == 'symlink':
            path.symlink_to(original)
        elif fault == 'hardlink':
            os.link(original, path)
        else:
            os.mkfifo(path, mode=0o600)
    read = Mock(side_effect=AssertionError('Unsafe file must not be read'))
    monkeypatch.setattr(profiles.os, 'read', read)
    with pytest.raises(TargetProfileError):
        load_http_target_profile(path)
    read.assert_not_called()


@pytest.mark.parametrize('raw', [b'{', b'null', b'[]', b'\xff', b' ' * 32769,
                               b'[' * 30 + b'0' + b']' * 30,
                               b'{"padding":NaN}', b'{"padding":1e10000}',
                               b'{"schema_version":"1.0","schema_version":"1.0"}',
                               json.dumps({'padding': list(range(600))}).encode()],
                         ids=['malformed', 'null', 'array', 'utf8', 'oversized', 'deep', 'nan', 'overflow', 'duplicate', 'nodes'])
def test_uninterpretable_profile_has_a_static_error_and_no_rewrite(tmp_path, references, raw):
    path = profile_file(tmp_path)
    path.write_bytes(raw)
    with pytest.raises(TargetProfileError) as error:
        load_http_target_profile(path)
    assert str(path) not in str(error.value)
    assert path.read_bytes() == raw


def test_profile_node_budget_rejects_before_json_object_allocation(monkeypatch):
    raw = json.dumps({'padding': list(range(600))}).encode()
    decode = Mock(side_effect=AssertionError('Oversized structure must be refused before JSON decoding'))
    monkeypatch.setattr(profiles.json, 'loads', decode)
    with pytest.raises(TargetProfileError):
        profiles._decode(raw)
    decode.assert_not_called()


def test_selected_directory_symlink_refused_but_canonical_ancestor_alias_supported(tmp_path, references):
    real = tmp_path / 'real'
    real.mkdir(mode=0o700)
    alias = tmp_path / 'alias'
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(TargetProfileError):
        create_http_target_profile(alias / 'target.json', document())
    target = alias / 'selected-private-directory' / 'target.json'
    create_http_target_profile(target, document())
    assert load_http_target_profile(target).descriptor['request_prompt_field'] == 'question'
    assert alias.is_symlink()


def test_write_failure_removes_only_the_owned_partial_file_and_new_directory(tmp_path, references, monkeypatch):
    path = tmp_path / 'private' / 'target.json'
    original_write = os.write
    calls = 0
    def write(fd, content):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(fd, content[:7])
        raise OSError('Synthetic write failure')
    monkeypatch.setattr(profiles.os, 'write', write)
    with pytest.raises(TargetProfileError):
        create_http_target_profile(path, document())
    assert not path.exists() and not path.parent.exists()


@pytest.mark.parametrize('existing_parent', [False, True])
def test_final_parent_check_failure_removes_only_the_new_owned_profile(tmp_path, references, monkeypatch,
                                                                     existing_parent):
    path = tmp_path / 'private' / 'target.json'
    original = tmp_path / 'unrelated.txt'
    original.write_bytes(b'Unrelated original bytes')
    if existing_parent:
        path.parent.mkdir(mode=0o700)
        retained = path.parent / 'keep.txt'
        retained.write_bytes(b'Existing private directory contents')
    actual = profiles._check_parent
    calls = 0
    def final_failure(parent, descriptor):
        nonlocal calls
        calls += 1
        actual(parent, descriptor)
        if calls == 3:
            raise TargetProfileError('target_profile_unavailable')
    monkeypatch.setattr(profiles, '_check_parent', final_failure)
    with pytest.raises(TargetProfileError):
        create_http_target_profile(path, document())
    assert calls == 3 and not path.exists()
    assert original.read_bytes() == b'Unrelated original bytes'
    if existing_parent:
        assert path.parent.is_dir() and retained.read_bytes() == b'Existing private directory contents'
    else:
        assert not path.parent.exists()


def test_final_parent_failure_never_removes_a_replacement_inode(tmp_path, references, monkeypatch):
    path = tmp_path / 'private' / 'target.json'
    actual = profiles._check_parent
    calls = 0
    def replaced(parent, descriptor):
        nonlocal calls
        calls += 1
        actual(parent, descriptor)
        if calls == 3:
            path.rename(path.with_name('moved-owned-profile.json'))
            path.write_bytes(b'Replacement must remain untouched')
            path.chmod(0o600)
            raise TargetProfileError('target_profile_unavailable')
    monkeypatch.setattr(profiles, '_check_parent', replaced)
    with pytest.raises(TargetProfileError):
        create_http_target_profile(path, document())
    assert path.read_bytes() == b'Replacement must remain untouched'
    assert path.with_name('moved-owned-profile.json').exists()


def test_leaf_replacement_during_read_is_refused_and_replacement_kept(tmp_path, references, monkeypatch):
    path = profile_file(tmp_path)
    original_read = os.read
    replaced = False
    def read(fd, maximum):
        nonlocal replaced
        data = original_read(fd, maximum)
        if not replaced:
            replaced = True
            path.rename(path.with_name('original.json'))
            path.write_text('Replacement must remain')
            path.chmod(0o600)
        return data
    monkeypatch.setattr(profiles.os, 'read', read)
    with pytest.raises(TargetProfileError):
        load_http_target_profile(path)
    assert path.read_text() == 'Replacement must remain'


def test_plan_has_no_network_default_credential_or_server_access(tmp_path, references, monkeypatch):
    value = document(endpoint='https://app.example.test/chat')
    value['allowed_networks'] = ['192.0.2.7/24']
    path = profile_file(tmp_path, value)
    selected = load_http_target_profile(path)
    def forbidden(*args, **kwargs):
        raise AssertionError('Plan must stay local')
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setitem(sys.modules, 'app', None)
    reads = []
    original_get = profiles.os.environ.get
    def get(key, default=None):
        reads.append(key)
        assert key == CANARY_ENV
        return original_get(key, default)
    monkeypatch.setattr(profiles.os.environ, 'get', get)
    plan = plan_http_profile(selected, path)
    assert plan['configuration_status'] == 'ready'
    assert plan['selected_rule_count'] == 7 and plan['maximum_prompt_http_attempts'] == 35
    assert plan['network_readiness_status'] == 'not_checked'
    assert plan['target'] == {'name': 'Support application', 'http_target': selected.descriptor,
                              'allowed_networks': ['192.0.2.0/24']}
    assert plan['target']['http_target']['endpoint'] == 'https://app.example.test:443/chat'
    assert selected.allowed_networks == ('192.0.2.0/24',)
    assert reads == [CANARY_ENV]
    assert all(value not in json.dumps(plan) for value in (CANARY, CREDENTIAL, CANARY_ENV, str(path)))


def test_scope_preview_checks_protected_collisions_before_binding(tmp_path, references, monkeypatch):
    network = '2001:db8:aaaa:bbbb::/64'
    value = document(bearer=True)
    value['allowed_networks'].append(network)
    selected = validate_http_target_profile(value)
    monkeypatch.setenv(CREDENTIAL_ENV, network)
    import src.core.http_application_policy as policy
    binding = Mock(side_effect=AssertionError('A private scope collision must be caught before hashing'))
    monkeypatch.setattr(policy, 'http_target_binding', binding)
    with pytest.raises(TargetProfileError, match='Protected values conflict'):
        plan_http_profile(selected, tmp_path / 'profile.json', allow_loopback=True)
    binding.assert_not_called()


@pytest.mark.parametrize('where', ['name', 'request-field', 'pointer', 'public-key', 'plan-key', 'context'])
def test_protected_value_collisions_refused_before_binding_or_output(tmp_path, references, monkeypatch, where):
    value = document()
    marker = CANARY
    if where == 'name':
        value['name'] = CANARY
    elif where == 'request-field':
        value['http_target']['request_prompt_field'] = CANARY
    elif where == 'pointer':
        value['http_target']['response_text_pointer'] = '/' + CANARY
    elif where == 'context':
        value['http_target']['context_label'] = CANARY
    elif where == 'public-key':
        marker = 'request_prompt_field'
    else:
        marker = 'network_readiness_status'
    monkeypatch.setenv(CANARY_ENV, marker)
    import src.core.http_application_policy as policy
    binding = Mock(side_effect=AssertionError('Collision must be caught before hashing'))
    monkeypatch.setattr(policy, 'http_target_binding', binding)
    selected = validate_http_target_profile(value)
    with pytest.raises(TargetProfileError, match='Protected values conflict'):
        plan_http_profile(selected, tmp_path / 'profile.json', allow_loopback=True)
    binding.assert_not_called()


@pytest.mark.parametrize('missing', ['canary', 'credential'])
def test_missing_reference_blocks_plan_and_execution_without_exposing_names(tmp_path, references, monkeypatch, missing):
    path = profile_file(tmp_path, document(bearer=True))
    selected = load_http_target_profile(path)
    monkeypatch.delenv(CANARY_ENV if missing == 'canary' else CREDENTIAL_ENV)
    plan = plan_http_profile(selected, path, allow_loopback=True)
    assert plan['configuration_status'] == 'blocked'
    code = 'protected_canary_reference_unavailable' if missing == 'canary' else 'credential_reference_unavailable'
    assert plan['reason_codes'] == [code]
    with pytest.raises(TargetProfileError) as error:
        prepare_http_profile(selected, path, allow_loopback=True)
    assert error.value.code == code
    assert CANARY_ENV not in str(error.value) and CREDENTIAL_ENV not in str(error.value)


def test_references_are_resolved_once_and_execution_keeps_the_original_values(tmp_path, references, monkeypatch):
    path = profile_file(tmp_path, document(bearer=True))
    selected = load_http_target_profile(path)
    reads = []
    original_get = profiles.os.environ.get
    def get(key, default=None):
        reads.append(key)
        return original_get(key, default)
    monkeypatch.setattr(profiles.os.environ, 'get', get)
    prepared = prepare_http_profile(selected, path, allow_loopback=True)
    assert reads == [CANARY_ENV, CREDENTIAL_ENV]
    monkeypatch.setenv(CANARY_ENV, 'different-canary-value-72046')
    monkeypatch.setenv(CREDENTIAL_ENV, 'different-bearer-value-02468')
    assert prepared.canary == CANARY and prepared.credential == CREDENTIAL


@pytest.mark.parametrize('endpoint,networks,allow_loopback,code', [
    ('http://127.0.0.1/chat', ['127.0.0.1/32'], False, 'plaintext_credential_refused'),
    ('https://127.0.0.1/chat', ['192.0.2.0/24'], True, 'target_scope_refused'),
    ('https://169.254.169.254/chat', ['169.254.0.0/16'], False, 'target_scope_refused'),
])
def test_local_scope_checks_refuse_without_dns(endpoint, networks, allow_loopback, code, tmp_path, references):
    value = document(bearer=True, endpoint=endpoint)
    value['allowed_networks'] = networks
    selected = validate_http_target_profile(value)
    assert plan_http_profile(selected, tmp_path / 'selected.json', allow_loopback=allow_loopback)['reason_codes'] == [code]


@pytest.mark.parametrize('mutation', ['extra', 'unseeded', 'same-ref', 'registry-ref', 'wrong-auth', 'duplicate-network'])
def test_profile_validation_rejects_unsupported_or_ambiguous_setup(mutation):
    value = deepcopy(document(bearer=True))
    if mutation == 'extra':
        value['literal_key'] = CREDENTIAL
    elif mutation == 'unseeded':
        value['canary_seeded'] = False
    elif mutation == 'same-ref':
        value['credential_env'] = CANARY_ENV
    elif mutation == 'registry-ref':
        value['canary_env'] = 'SCAN_EVIDENCE_PROFILES_FILE'
    elif mutation == 'wrong-auth':
        value['credential_env'] = None
    else:
        value['allowed_networks'] *= 2
    with pytest.raises(TargetProfileError):
        validate_http_target_profile(value)
