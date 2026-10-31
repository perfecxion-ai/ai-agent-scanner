"""Immutable server-owned HTTP targets with public revisions and private preparation."""

import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
import os
import re
from types import MappingProxyType
from urllib.parse import quote, urlsplit

from src.core.http_application_policy import (
    HTTP_OBJECTIVE, public_http_agent, validate_http_public_privacy,
)
from src.core.http_application_runtime import prepare_http_target
from src.core.http_target_profiles import validate_http_target_profile
from src.core.scope import ScopeValidationError, bounded_integer, validate_agent_endpoints
from src.core.transport import ScanBudget
from src.security.prompt_suites import _PUBLIC_DESCRIPTOR, prompt_suite_pin


HTTP_OPTIONS = frozenset({'http_target_profile', 'http_target_revision', 'timeout_seconds',
                          'max_requests', 'request_timeout_seconds', 'max_response_bytes'})
HTTP_SELECTION = frozenset({'http_target_profile', 'http_target_revision'})
MAX_HTTP_TARGETS = 100
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
_ENV = re.compile(r'SCAN_EVIDENCE_[A-Z][A-Z0-9_]{0,111}\Z')
_MARKER = re.compile(r'[A-Za-z0-9_.~-]{16,128}\Z')
_REVISION = re.compile(r'[0-9a-f]{64}\Z')
_ERROR = 'HTTP target is unavailable or changed; review server configuration'
_PUBLIC = (
    _ERROR, 'HTTP target assessments are supported only by one-shot scan admission',
    *HTTP_OPTIONS, 'http_targets', 'targets', 'target', 'success', 'revision', 'name',
    'organization_id', 'scan_name', 'scan_id', 'scan_type', 'scan_config', 'target_scope',
    'configuration_status', 'reason_codes', 'assessment_objective', 'http_target_binding',
    'allowed_networks', 'selected_rule_count', 'maximum_prompt_http_attempts',
    'shared_attempt_budget', 'overall_timeout_seconds', 'session_mode',
    'canary_seeding_status', 'network_readiness_status', 'limitations', 'operator_attested',
    'not_checked', 'ready', 'blocked', 'credential_reference_unavailable',
    'protected_canary_reference_unavailable', 'target_scope_refused',
    'Scan execution failed', 'Scan worker failed', 'Scan deadline exceeded',
    'admitted', 'claimed', 'terminal', 'queued', 'running', 'completed', 'partial',
    'failed', 'cancelled', 'interrupted', 'created_by', 'user_ip',
)


class ServerHTTPProfileError(ScopeValidationError):
    def __init__(self):
        super().__init__(_ERROR)


class ServerHTTPProfileNotFound(ServerHTTPProfileError):
    pass


def _privacy(public, protected):
    forms = set()
    for value in protected:
        if type(value) is str and value:
            raw = value.encode('utf-8')
            forms.update((value, quote(value, safe=''), json.dumps(value)[1:-1], raw.hex(),
                          base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
                          base64.urlsafe_b64encode(raw).decode().rstrip('=')))
    # Keep setup readiness consistent with the existing suite's fixed report,
    # check and SARIF privacy prerequisites before any durable output exists.
    validate_http_public_privacy([public, _PUBLIC_DESCRIPTOR], forms)


@dataclass(frozen=True, repr=False)
class _Entry:
    organization_id: str
    profile: object


def http_scan_options(data, config):
    """The new branch accepts public references and budgets, never target inputs."""
    try:
        options = data['scan_config']
        if (set(data) - {'scan_name', 'scan_type', 'target_scope', 'scan_config'}
                or data.get('scan_type') != 'security_only' or data.get('target_scope', {}) != {}
                or set(options) - HTTP_OPTIONS or not HTTP_SELECTION <= set(options)
                or type(options['http_target_profile']) is not str
                or not _ID.fullmatch(options['http_target_profile'])
                or type(options['http_target_revision']) is not str
                or not _REVISION.fullmatch(options['http_target_revision'])):
            raise ServerHTTPProfileError()
        return {**options, **http_limits(config, options)}
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ServerHTTPProfileError() from None


def http_limits(config, options=None):
    options = options or {}
    result = {}
    for key, setting, default in (
        ('timeout_seconds', 'SCAN_TIMEOUT_SECONDS', 180),
        ('max_requests', 'SCAN_MAX_REQUESTS', 35),
        ('max_response_bytes', 'SCAN_MAX_RESPONSE_BYTES', 65536),
    ):
        maximum = min(default, config.get(setting, default))
        result[key] = bounded_integer(options.get(key, maximum), key, maximum)
    maximum = min(10, config.get('SCAN_REQUEST_TIMEOUT_SECONDS', 10))
    value = options.get('request_timeout_seconds', maximum)
    if type(value) not in (int, float) or not math.isfinite(value) or not 1 <= value <= maximum:
        raise ServerHTTPProfileError()
    result['request_timeout_seconds'] = value
    return result


class ServerHTTPProfiles:
    def __init__(self, entries=None, *, private_path=None):
        self._entries = MappingProxyType(dict(entries or {}))
        self._private_path = private_path

    @property
    def enabled(self):
        return bool(self._entries)

    @classmethod
    def from_document(cls, document, *, private_path=None):
        try:
            if type(document) is not dict or len(document) > MAX_HTTP_TARGETS:
                raise ServerHTTPProfileError()
            entries = {}
            for identifier, value in document.items():
                if (type(identifier) is not str or not _ID.fullmatch(identifier)
                        or type(value) is not dict or type(value.get('organization_id')) is not str
                        or not 1 <= len(value['organization_id']) <= 64
                        or value['organization_id'] != value['organization_id'].strip()
                        or any(ord(char) < 32 or ord(char) == 127 for char in value['organization_id'])):
                    raise ServerHTTPProfileError()
                profile = validate_http_target_profile({key: item for key, item in value.items()
                                                        if key != 'organization_id'})
                if any(reference is not None and not _ENV.fullmatch(reference)
                       for reference in (profile.canary_env, profile.credential_env)):
                    raise ServerHTTPProfileError()
                entries[identifier] = _Entry(value['organization_id'], profile)
            registry = cls(entries, private_path=private_path)
            registry.validate_startup()
            return registry
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise ServerHTTPProfileError() from None

    def _entry(self, identifier, tenant):
        entry = self._entries.get(identifier)
        if entry is None or entry.organization_id != tenant:
            raise ServerHTTPProfileNotFound()
        return entry

    def _revision(self, identifier, entry):
        public = ['server-http-target-v1', identifier, entry.organization_id,
                  entry.profile.document(), prompt_suite_pin()]
        return hashlib.sha256(json.dumps(public, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def token(self, identifier, tenant, revision):
        entry = self._entry(identifier, tenant)
        if revision != self._revision(identifier, entry):
            raise ServerHTTPProfileError()
        return entry

    @staticmethod
    def _resolve(entry):
        profile = entry.profile
        canary = os.environ.get(profile.canary_env)
        credential = os.environ.get(profile.credential_env) if profile.credential_env else None
        problems = []
        if type(canary) is not str or not _MARKER.fullmatch(canary):
            problems.append('protected_canary_reference_unavailable')
        if profile.credential_env is not None and (type(credential) is not str
                or not 16 <= len(credential) <= 4096
                or any(not 33 <= ord(char) <= 126 for char in credential)):
            problems.append('credential_reference_unavailable')
        return canary, credential, problems

    def _private(self, entry, canary, credential):
        return tuple(value for value in (canary, credential, entry.profile.canary_env,
            entry.profile.credential_env, self._private_path) if type(value) is str and value)

    def _public(self, identifier, entry):
        return {'id': identifier, 'revision': self._revision(identifier, entry),
                'name': entry.profile.name, 'http_target': entry.profile.descriptor,
                'allowed_networks': list(entry.profile.allowed_networks)}

    def _snapshots(self, extra_private=()):
        snapshots = {key: self._resolve(entry) for key, entry in self._entries.items()}
        protected = list(extra_private)
        for key, entry in self._entries.items():
            canary, credential, _ = snapshots[key]
            protected.extend(self._private(entry, canary, credential))
        return snapshots, protected

    def validate_global_public(self, public, *, extra_private=()):
        """Opted-in HTTP secrets cannot enter another scan's public definition.

        Missing unrelated references do not require readiness. Existing v1-only
        registries retain their previous admission behavior.
        """
        if not self._entries:
            return
        _, protected = self._snapshots(extra_private)
        try:
            _privacy([public, _PUBLIC], protected)
        except ValueError:
            raise ServerHTTPProfileError() from None

    def validate_startup(self, *, extra_public=(), extra_protected=()):
        public = [self._public(identifier, entry) for identifier, entry in self._entries.items()]
        protected = list(extra_protected)
        for entry in self._entries.values():
            canary, credential, problems = self._resolve(entry)
            if problems:
                raise ServerHTTPProfileError()
            protected.extend(self._private(entry, canary, credential))
            # This also rejects a canary carried in the credential itself.
            prepare_http_target(public_http_agent(entry.profile.descriptor, entry.profile.name),
                                credential=credential, canary=canary)
        try:
            _privacy([public, extra_public, _PUBLIC], protected)
        except ValueError:
            raise ServerHTTPProfileError() from None

    def networks(self, identifier, tenant, config, revision):
        entry = self.token(identifier, tenant, revision)
        try:
            server = [ipaddress.ip_network(value, strict=False)
                      for value in config.get('SCAN_ALLOWED_NETWORKS', ())]
            selected = [ipaddress.ip_network(value) for value in entry.profile.allowed_networks]
            intersection = set()
            for left in selected:
                for right in server:
                    if left.version == right.version and left.overlaps(right):
                        intersection.add(str(left if left.subnet_of(right) else right))
            if not intersection:
                raise ServerHTTPProfileError()
            return tuple(sorted(intersection))
        except (ValueError, TypeError):
            raise ServerHTTPProfileError() from None

    def scope(self, identifier, tenant, revision, config, *, resolve):
        entry = self.token(identifier, tenant, revision)
        networks = self.networks(identifier, tenant, config, revision)
        agent = public_http_agent(entry.profile.descriptor, entry.profile.name)
        if resolve:
            validate_agent_endpoints([agent], {**config, 'SCAN_ALLOWED_NETWORKS': networks})
        else:
            host = urlsplit(agent['endpoint']).hostname
            try:
                literal = ipaddress.ip_address(host)
            except ValueError:
                literal = None
            if literal is not None:
                ScanBudget(allowed_networks=networks,
                           allow_loopback=config.get('SCAN_ALLOW_LOOPBACK', False)).check_address(literal)
        return networks

    def validate_public(self, identifier, tenant, revision, public, *, extra_private=()):
        entry = self.token(identifier, tenant, revision)
        snapshots, protected = self._snapshots(extra_private)
        canary, credential, problems = snapshots[identifier]
        if problems:
            raise ServerHTTPProfileError()
        try:
            private = self._private(entry, canary, credential)
            _privacy([public, self._public(identifier, entry), _PUBLIC], protected)
            prepare_http_target(public_http_agent(entry.profile.descriptor, entry.profile.name),
                                credential=credential, canary=canary, private_values=private)
        except ValueError:
            raise ServerHTTPProfileError() from None

    def prepare(self, identifier, tenant, revision, public, *, extra_private=()):
        entry = self.token(identifier, tenant, revision)
        snapshots, protected = self._snapshots(extra_private)
        canary, credential, problems = snapshots[identifier]
        if problems:
            raise ServerHTTPProfileError()
        try:
            _privacy([public, self._public(identifier, entry), _PUBLIC], protected)
            return prepare_http_target(public_http_agent(entry.profile.descriptor, entry.profile.name),
                                       credential=credential, canary=canary, private_values=protected)
        except ValueError:
            raise ServerHTTPProfileError() from None

    def plans(self, tenant, config, identifier=None, *, extra_private=()):
        if identifier is not None:
            self._entry(identifier, tenant)
        selected = [(key, entry) for key, entry in self._entries.items()
                    if entry.organization_id == tenant and (identifier is None or identifier == key)]
        snapshots, protected = self._snapshots(extra_private)
        plans = []
        for key, entry in selected:
            canary, credential, problems = snapshots[key]
            if not problems:
                try:
                    prepare_http_target(public_http_agent(entry.profile.descriptor, entry.profile.name),
                                        credential=credential, canary=canary)
                except ValueError:
                    raise ServerHTTPProfileError() from None
            public = self._public(key, entry)
            try:
                self.scope(key, tenant, public['revision'], config, resolve=False)
            except ValueError:
                problems.append('target_scope_refused')
            limits = http_limits(config)
            plans.append({**public, 'configuration_status': 'blocked' if problems else 'ready',
                'reason_codes': problems, 'assessment_objective': HTTP_OBJECTIVE,
                'selected_rule_count': 7, 'maximum_prompt_http_attempts': 35,
                'shared_attempt_budget': limits['max_requests'],
                'max_response_bytes': limits['max_response_bytes'],
                'overall_timeout_seconds': limits['timeout_seconds'],
                'request_timeout_seconds': limits['request_timeout_seconds'],
                'session_mode': 'fresh-per-prompt-v1', 'canary_seeding_status': 'operator_attested',
                'network_readiness_status': 'not_checked',
                'limitations': ['Reachability, DNS, TLS, response mapping and seeding are not independently verified.',
                    'Fresh client sessions do not reset server state; quiet responses remain inconclusive.']})
        try:
            _privacy([plans, _PUBLIC, {'success': True, 'targets': plans}], protected)
        except ValueError:
            raise ServerHTTPProfileError() from None
        return plans
