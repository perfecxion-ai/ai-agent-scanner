"""Stable public-target groups, without credential or principal equivalence."""

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit

from src.core.redaction import collect_secrets, redact_secrets


IDENTITY_VERSION = 'public-target-group-v1'
MAX_TARGET_BYTES = 8192
_UNSAFE = re.compile(r'[\x00-\x20\x7f\\]')
_REDACTED = re.compile(r'\[redacted(?:[^\]]*)\]', re.IGNORECASE)
_AWS = re.compile(r'arn:aws(?:-[a-z0-9-]+)?:[a-z0-9-]+:[a-z0-9-]+:[0-9]{12}:[^\s?#]+\Z')
_SUBSCRIPTION = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z')
_GCP = re.compile(r'projects/[A-Za-z0-9:_-]+/locations/[a-z0-9-]+/(?:endpoints|models)/[A-Za-z0-9._:-]+\Z')


@dataclass(frozen=True)
class GroupIdentity:
    group_id: str
    status: str
    reason: str | None
    target: dict | None


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(',', ':'), allow_nan=False).encode('ascii')).hexdigest()


def _label(value, maximum, *, nullable=False):
    return ((value is None and nullable) or (type(value) is str and 0 < len(value) <= maximum
            and not any(ord(character) < 32 or ord(character) == 127 for character in value)
            and value == value.strip() and not _REDACTED.search(value)))


def _endpoint(value):
    if not isinstance(value, str) or not value or len(value) > 4096 or _UNSAFE.search(value):
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {'http', 'https'} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or '?' in value or '#' in value):
            return None
        host, port = parsed.hostname.lower(), parsed.port
        if port == 0:
            return None
        if '%' in host or host.endswith('.'):
            return None
        try:
            host = ipaddress.ip_address(host).compressed
        except ValueError:
            # Preserve Unicode/punycode and DNS aliases separately; never resolve.
            if not all(character.isalnum() or character in '.-' for character in host):
                return None
        if ':' in host:
            host = '[' + host + ']'
        if port is not None and port not in {80 if parsed.scheme == 'http' else 443}:
            host += ':' + str(port)
        return urlunsplit((parsed.scheme, host, parsed.path or '/', '', ''))
    except (ValueError, UnicodeError):
        return None


def _cloud_resource(cloud, resource):
    if not _label(resource, 2048) or _UNSAFE.search(resource) or any(mark in resource for mark in '?#@'):
        return False
    if cloud == 'aws':
        return bool(_AWS.fullmatch(resource))
    if cloud == 'gcp':
        return bool(_GCP.fullmatch(resource))
    if cloud == 'azure':
        pieces = resource.split('/')
        return (len(pieces) >= 9 and len(pieces) % 2 == 1 and pieces[0] == ''
                and pieces[1].casefold() == 'subscriptions' and bool(_SUBSCRIPTION.fullmatch(pieces[2]))
                and pieces[3].casefold() == 'resourcegroups' and pieces[5].casefold() == 'providers'
                and pieces[6].casefold().startswith('microsoft.') and all(pieces[1:]))
    return False


def target_group_identity(agent, *, organization_id, observation_id):
    """Hash only a complete public target, otherwise retain one separate row."""
    if (not _label(organization_id, 64) or not _label(observation_id, 64)
            or redact_secrets(organization_id, collect_secrets(organization_id)) != organization_id
            or redact_secrets(observation_id, collect_secrets(observation_id)) != observation_id):
        raise ValueError('Invalid asset-group ownership or observation identity')

    def unmerged(reason):
        return GroupIdentity(_hash([IDENTITY_VERSION, organization_id, 'observation', observation_id]),
                             'unmerged', reason, None)

    if not isinstance(agent, dict):
        return unmerged('invalid_target')
    metadata = agent.get('metadata', {})
    if not isinstance(metadata, dict):
        return unmerged('invalid_target')
    if agent.get('endpoint_redacted') or metadata.get('endpoint_redacted'):
        return unmerged('redacted_target')
    provider, model, context = agent.get('provider'), agent.get('model'), agent.get('evidence_context_id')
    if not _label(provider, 100) or provider.casefold() in {'unknown', 'unidentified'}:
        return unmerged('unknown_provider')
    if not _label(model, 255, nullable=True):
        return unmerged('invalid_model')
    if not _label(context, 256, nullable=True):
        return unmerged('invalid_context')
    target = {'provider': provider, 'model': model, 'evidence_context_id': context}
    cloud, resource = metadata.get('cloud'), metadata.get('resource_id')
    if cloud is not None or resource is not None:
        if not _cloud_resource(cloud, resource):
            return unmerged('cloud_identity_incomplete')
        target.update(kind='cloud_resource', cloud=cloud, resource_id=resource)
        if agent.get('endpoint') is not None:
            endpoint = _endpoint(agent['endpoint'])
            if endpoint is None or _REDACTED.search(endpoint):
                return unmerged('invalid_endpoint')
    else:
        if agent.get('endpoint') is None:
            return unmerged('missing_endpoint')
        endpoint = _endpoint(agent['endpoint'])
        if endpoint is None or _REDACTED.search(endpoint):
            return unmerged('invalid_endpoint')
        target.update(kind='http_target', endpoint=endpoint)
    raw = json.dumps(target, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    if len(raw) > MAX_TARGET_BYTES:
        return unmerged('target_too_large')
    if redact_secrets(target, collect_secrets(target)) != target:
        return unmerged('private_target')
    return GroupIdentity(_hash([IDENTITY_VERSION, organization_id, target]), 'grouped', None, target)
