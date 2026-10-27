"""Stable grouping uses public target selectors, never credential equivalence."""

from copy import deepcopy
import json
import os
import re
import socket

import pytest

from src.core.asset_identity import GroupIdentity, target_group_identity


def agent(**changes):
    return {'id': 'scan-local-alias', 'name': 'Target', 'type': 'assistant', 'provider': 'ollama',
            'model': 'fixture-model', 'evidence_context_id': 'fixture-context',
            'endpoint': 'http://example.test:80/resource', 'metadata': {}, **changes}


def identity(value=None, *, organization='tenant-a', observation='observation-a'):
    return target_group_identity(agent() if value is None else value,
                                 organization_id=organization, observation_id=observation)


def test_public_target_identity_is_stable_and_does_not_mutate_inputs(monkeypatch):
    original = agent()
    untouched = deepcopy(original)
    first = identity(original)
    monkeypatch.setenv('SECRET_KEY', 'different-synthetic-signing-secret')
    original.update(id='other-alias', name='Renamed', type='service', discovery_method='another-source')
    original['metadata'] = {'confidence': 0.2, 'api_key': 'never-hash-this-credential'}
    second = identity(original, observation='different-observation')
    assert first == second and isinstance(first, GroupIdentity)
    assert first.status == 'grouped' and first.reason is None
    assert re.fullmatch('[0-9a-f]{64}', first.group_id)
    assert first.target == {'kind': 'http_target', 'endpoint': 'http://example.test/resource',
                            'provider': 'ollama', 'model': 'fixture-model',
                            'evidence_context_id': 'fixture-context'}
    assert untouched == agent()
    assert 'never-hash-this-credential' not in json.dumps(first.target)


@pytest.mark.parametrize('url', ['http://example.test/resource', 'HTTP://EXAMPLE.TEST:80/resource'])
def test_only_safe_endpoint_authority_normalization_coalesces(url):
    assert identity(agent(endpoint=url)).group_id == identity().group_id


@pytest.mark.parametrize('before,after', [
    ('https://example.test', 'https://EXAMPLE.TEST:443/'),
    ('http://[2001:db8::1]:80/', 'http://[2001:0db8:0:0:0:0:0:1]/'),
])
def test_default_ports_empty_path_and_numeric_ipv6_are_canonical(before, after):
    assert identity(agent(endpoint=before)).group_id == identity(agent(endpoint=after)).group_id


@pytest.mark.parametrize('changes', [
    {'endpoint': 'https://example.test/resource'}, {'endpoint': 'http://example.test:8080/resource'},
    {'endpoint': 'http://example.test/resource/'}, {'endpoint': 'http://example.test/Resource'},
    {'endpoint': 'http://example.test/%72esource'}, {'provider': 'openai-compatible'},
    {'model': 'other-model'}, {'evidence_context_id': 'other-context'},
    {'model': None}, {'evidence_context_id': None},
])
def test_other_public_selectors_remain_distinct(changes):
    assert identity(agent(**changes)).group_id != identity().group_id


def test_null_selectors_are_explicit_and_tenant_namespace_is_part_of_id():
    value = agent(model=None, evidence_context_id=None)
    assert identity(value).status == 'grouped'
    assert identity(value).group_id == identity(value, observation='another-observation').group_id
    assert identity(value).group_id != identity(value, organization='tenant-b').group_id


@pytest.mark.parametrize('url', [
    'http://user:password@example.test/', 'http://user@example.test/',
    'http://example.test/?key=private-key', 'http://example.test/?',
    'http://example.test/#private-key', 'http://example.test/#',
    'http://example.test\\@other.test/', 'http://example.test/with space',
    'http://example.test/\n', 'http://example.test:0/', 'http://example.test:65536/',
    'http://[fe80::1%25en0]/', 'http://example.test./', 'ftp://example.test/resource',
    'http://', '//example.test/resource', 'http://example.test/[redacted]',
])
def test_unsafe_or_unusable_endpoint_is_separate_without_private_material(url):
    result = identity(agent(endpoint=url))
    assert result.status == 'unmerged' and result.reason == 'invalid_endpoint'
    assert result.target is None
    assert result.group_id != identity(agent(endpoint=url), observation='other-observation').group_id
    assert result.group_id == identity(agent(endpoint='ftp://other.test/')).group_id


@pytest.mark.parametrize('changes,reason', [
    ({'endpoint': None}, 'missing_endpoint'), ({'provider': None}, 'unknown_provider'),
    ({'provider': 'unknown'}, 'unknown_provider'), ({'provider': True}, 'unknown_provider'),
    ({'provider': ' ollama'}, 'unknown_provider'), ({'model': False}, 'invalid_model'),
    ({'model': '[redacted]'}, 'invalid_model'), ({'evidence_context_id': ''}, 'invalid_context'),
    ({'evidence_context_id': {'private': 'context'}}, 'invalid_context'),
    ({'endpoint_redacted': True}, 'redacted_target'),
    ({'metadata': {'endpoint_redacted': True}}, 'redacted_target'),
    ({'metadata': []}, 'invalid_target'),
])
def test_incomplete_or_redacted_identity_is_an_explicit_singleton(changes, reason):
    value = identity(agent(**changes))
    assert (value.status, value.reason, value.target) == ('unmerged', reason, None)


@pytest.mark.parametrize('cloud,resource', [
    ('aws', 'arn:aws:sagemaker:us-east-1:123456789012:endpoint/fixture'),
    ('aws', 'arn:aws-us-gov:lambda:us-gov-west-1:123456789012:function:fixture'),
    ('azure', '/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/fixture/providers/Microsoft.CognitiveServices/accounts/fixture/deployments/model'),
    ('gcp', 'projects/fixture-project/locations/us-central1/endpoints/12345'),
])
def test_complete_public_cloud_resource_is_namespaced_and_endpoint_independent(cloud, resource):
    value = agent(endpoint=None, metadata={'cloud': cloud, 'resource_id': resource})
    first = identity(value)
    assert first.status == 'grouped'
    assert first.target == {'kind': 'cloud_resource', 'cloud': cloud, 'resource_id': resource,
                             'provider': 'ollama', 'model': 'fixture-model',
                             'evidence_context_id': 'fixture-context'}
    value['endpoint'] = 'https://new-endpoint.example.test/resource'
    assert identity(value).group_id == first.group_id
    value['metadata']['resource_id'] += '-different'
    assert identity(value).group_id != first.group_id


@pytest.mark.parametrize('metadata', [
    {'cloud': 'aws', 'resource_id': 'endpoint/fixture'},
    {'cloud': 'aws', 'resource_id': 'arn:aws:sagemaker:us-east-1::endpoint/fixture'},
    {'cloud': 'aws', 'resource_id': 'arn:aws:sagemaker:us-east-1:123456789012:endpoint/[redacted]'},
    {'cloud': 'gcp', 'resource_id': 'locations/us-central1/endpoints/12345'},
    {'cloud': 'azure', 'resource_id': '/resourceGroups/fixture/providers/Microsoft.Test/accounts/fixture'},
    {'cloud': 'azure', 'resource_id': '/subscriptions/not-a-subscription/resourceGroups/fixture/providers/Microsoft.Test/accounts/fixture'},
    {'cloud': 'private-cloud', 'resource_id': 'resource'}, {'cloud': 'aws'}, {'resource_id': 'resource'},
])
def test_partial_cloud_locators_do_not_fall_back_to_endpoint_coalescing(metadata):
    assert identity(agent(metadata=metadata)).reason == 'cloud_identity_incomplete'


@pytest.mark.parametrize('organization,observation', [('', 'o'), ('o', ''), (None, 'o'),
                                                     ('o', None), ('x' * 65, 'o'), ('o', 'x' * 65)])
def test_invalid_ownership_is_rejected_without_echo(organization, observation):
    with pytest.raises(ValueError, match='^Invalid asset-group ownership or observation identity$'):
        identity(organization=organization, observation=observation)


def test_identity_never_resolves_dns_environment_or_private_files(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Identity must not resolve external or private context')

    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(os, 'getenv', forbidden)
    monkeypatch.setattr('builtins.open', forbidden)
    assert identity().status == 'grouped'


@pytest.mark.parametrize('field', ['provider', 'model', 'evidence_context_id'])
@pytest.mark.parametrize('private', ['https://user:private-key@example.test/model',
                                     'https://example.test/model?api_key=private-key'])
def test_credential_bearing_selector_is_never_copied_or_hashed(field, private):
    value = identity(agent(**{field: private}))
    assert (value.status, value.reason, value.target) == ('unmerged', 'private_target', None)
    assert value.group_id == identity(agent(endpoint=None)).group_id


def test_bounded_target_encoding_handles_large_unicode_without_public_copy():
    value = identity(agent(endpoint='https://example.test/' + '\U0001f600' * 3000))
    assert value.status == 'unmerged' and value.reason == 'target_too_large'
    assert value.target is None


@pytest.mark.parametrize('label', ['organization', 'observation'])
def test_credential_bearing_ownership_identifier_is_not_hashed(label):
    arguments = {label: 'https://user:password@example.test/'}
    with pytest.raises(ValueError, match='^Invalid asset-group ownership or observation identity$'):
        identity(**arguments)
