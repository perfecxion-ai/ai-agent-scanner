"""Explicit private profiles for one bounded HTTP application assessment."""

from contextlib import contextmanager
from dataclasses import dataclass
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit


MAX_PROFILE_BYTES = 32768
MAX_PROFILE_DEPTH = 16
MAX_PROFILE_NODES = 512
_ENV = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z')
_MARKER = re.compile(r'[A-Za-z0-9_.~-]{16,128}\Z')
_FIELDS = frozenset({'schema_version', 'name', 'http_target', 'allowed_networks',
                     'credential_env', 'canary_env', 'canary_seeded'})
_ERRORS = {
    'target_profile_invalid': 'Target profile is invalid or unsupported',
    'target_profile_unavailable': 'Target profile is unavailable or unsafe',
    'target_profile_destination_exists': 'Target profile destination already exists',
    'target_profile_permissions_invalid': 'Use an owned private profile directory and file',
    'invalid_target_scope': 'Configure explicit allowed network CIDRs for the target',
    'credential_reference_unavailable': 'The declared credential reference is unavailable',
    'protected_canary_reference_unavailable': 'The declared protected canary reference is unavailable',
    'protected_value_conflicts_public_definition': 'Protected values conflict with the public target definition',
    'target_scope_refused': 'The target is outside the permitted scope',
    'plaintext_credential_refused': 'Bearer authentication requires HTTPS or explicitly permitted literal loopback',
}
_PLAN_FIELDS = ('configuration_status', 'reason_codes', 'assessment_objective', 'http_target_binding',
                'target', 'name', 'http_target', 'allowed_networks',
                'selected_rule_count', 'maximum_prompt_http_attempts', 'shared_attempt_budget',
                'max_response_bytes', 'overall_timeout_seconds', 'request_timeout_seconds',
                'session_mode', 'canary_seeding_status', 'network_readiness_status', 'limitations',
                'operator_attested', 'not_checked', 'ready', 'blocked')


class TargetProfileError(ValueError):
    def __init__(self, code='target_profile_invalid'):
        self.code = code if code in _ERRORS else 'target_profile_invalid'
        super().__init__(_ERRORS[self.code])


@dataclass(frozen=True, repr=False)
class TargetProfile:
    name: str
    descriptor_json: str
    allowed_networks: tuple
    credential_env: str | None
    canary_env: str

    @property
    def descriptor(self):
        return json.loads(self.descriptor_json)

    def document(self):
        return {'schema_version': '1.0', 'name': self.name, 'http_target': self.descriptor,
                'allowed_networks': list(self.allowed_networks), 'credential_env': self.credential_env,
                'canary_env': self.canary_env, 'canary_seeded': True}


def _text(value, maximum):
    return (type(value) is str and 0 < len(value) <= maximum and value == value.strip()
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def validate_http_target_profile(document):
    from src.core.http_application_policy import validate_http_target
    try:
        if (type(document) is not dict or set(document) != _FIELDS
                or document['schema_version'] != '1.0' or document['canary_seeded'] is not True
                or not _text(document['name'], 128)):
            raise TargetProfileError()
        descriptor = validate_http_target(document['http_target'])
        networks = document['allowed_networks']
        if (type(networks) is not list or not 1 <= len(networks) <= 32
                or any(not _text(value, 64) for value in networks)):
            raise TargetProfileError('invalid_target_scope')
        try:
            networks = [str(ipaddress.ip_network(value, strict=False)) for value in networks]
        except ValueError:
            raise TargetProfileError('invalid_target_scope') from None
        if len(set(networks)) != len(networks):
            raise TargetProfileError('invalid_target_scope')
        credential, canary = document['credential_env'], document['canary_env']
        if (type(canary) is not str or not _ENV.fullmatch(canary)
                or canary == 'SCAN_EVIDENCE_PROFILES_FILE'
                or credential is not None and (type(credential) is not str or not _ENV.fullmatch(credential)
                    or credential == 'SCAN_EVIDENCE_PROFILES_FILE' or credential == canary)
                or (descriptor['auth_scheme'] == 'bearer') != (credential is not None)):
            raise TargetProfileError()
        return TargetProfile(document['name'], json.dumps(descriptor, sort_keys=True, separators=(',', ':')),
                             tuple(networks), credential, canary)
    except TargetProfileError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        raise TargetProfileError() from None


def _identity(info):
    return info.st_dev, info.st_ino


def _safe_directory(info):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise TargetProfileError('target_profile_permissions_invalid')


def _safe_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}):
        raise TargetProfileError('target_profile_permissions_invalid')


def _check_parent(parent, descriptor):
    current = os.stat(parent, follow_symlinks=False)
    opened = os.fstat(descriptor)
    _safe_directory(current)
    _safe_directory(opened)
    if _identity(current) != _identity(opened):
        raise TargetProfileError('target_profile_unavailable')


@contextmanager
def _parent(path, *, create=False, on_failure=None):
    descriptor = ancestor = None
    created = False
    parent_identity = None
    try:
        raw = os.fspath(path)
        if (not isinstance(raw, str) or not raw or len(os.fsencode(raw)) > 4096
                or '\0' in raw or os.path.basename(raw) in {'', '.', '..'}):
            raise TargetProfileError()
        requested = Path(raw).absolute()
        parent = requested.parent
        if create:
            base = parent.parent.resolve(strict=True)
            ancestor = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.mkdir(parent.name, 0o700, dir_fd=ancestor)
                created = True
                parent_identity = _identity(os.stat(parent.name, dir_fd=ancestor, follow_symlinks=False))
            except FileExistsError:
                pass
        # The selected directory itself cannot be an alias. Earlier canonical
        # ancestors may be legitimate platform aliases such as macOS /var.
        named = parent.lstat()
        _safe_directory(named)
        parent = parent.resolve(strict=True)
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        _check_parent(parent, descriptor)
        if _identity(named) != _identity(os.fstat(descriptor)):
            raise TargetProfileError('target_profile_unavailable')
        parent_identity = _identity(os.fstat(descriptor))
        yield parent, descriptor, requested.name
        _check_parent(parent, descriptor)
    except TargetProfileError:
        if on_failure is not None and descriptor is not None:
            on_failure(descriptor, requested.name)
        raise
    except (OSError, ValueError, TypeError, OverflowError):
        if on_failure is not None and descriptor is not None:
            on_failure(descriptor, requested.name)
        raise TargetProfileError('target_profile_unavailable') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if created and ancestor is not None:
            try:
                named = os.stat(requested.parent.name, dir_fd=ancestor, follow_symlinks=False)
                if parent_identity is not None and _identity(named) == parent_identity:
                    os.rmdir(requested.parent.name, dir_fd=ancestor)
            except OSError:
                pass
        if ancestor is not None:
            os.close(ancestor)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TargetProfileError()
        result[key] = value
    return result


def _constant(value):
    raise TargetProfileError()


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise TargetProfileError()
    return number


def _decode(raw):
    # Bound structure before the JSON decoder allocates its object tree.
    text = raw.decode('utf-8')
    depth, nodes, quoted, escaped, primitive = 0, 0, False, False, False
    for mark in text:
        if quoted:
            if escaped:
                escaped = False
            elif mark == '\\':
                escaped = True
            elif mark == '"':
                quoted = False
        elif mark == '"':
            quoted = True
            primitive = False
            nodes += 1
        elif mark in '[{':
            depth += 1
            nodes += 1
            primitive = False
            if depth > MAX_PROFILE_DEPTH:
                raise TargetProfileError()
        elif mark in ']}':
            depth -= 1
            primitive = False
        elif mark in ',:' or mark.isspace():
            primitive = False
        elif not primitive:
            primitive = True
            nodes += 1
        if depth < 0 or nodes > MAX_PROFILE_NODES:
            raise TargetProfileError()
    if quoted or depth:
        raise TargetProfileError()
    document = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_finite_float)
    pending, count = [document], 0
    while pending:
        value = pending.pop()
        count += 1
        if count > MAX_PROFILE_NODES:
            raise TargetProfileError()
        if type(value) is dict:
            if count + len(pending) + 2 * len(value) > MAX_PROFILE_NODES:
                raise TargetProfileError()
            pending.extend(value.keys())
            pending.extend(value.values())
        elif type(value) is list:
            if count + len(pending) + len(value) > MAX_PROFILE_NODES:
                raise TargetProfileError()
            pending.extend(value)
    return document


def load_http_target_profile(path):
    descriptor = None
    try:
        with _parent(path) as (parent, directory, name):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directory)
            before = os.fstat(descriptor)
            _safe_file(before)
            if before.st_size > MAX_PROFILE_BYTES:
                raise TargetProfileError()
            content = bytearray()
            while len(content) <= MAX_PROFILE_BYTES:
                part = os.read(descriptor, min(8192, MAX_PROFILE_BYTES + 1 - len(content)))
                if not part:
                    break
                content.extend(part)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            _safe_file(after)
            _safe_file(named)
            if (len(content) > MAX_PROFILE_BYTES or _identity(named) != _identity(before)
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise TargetProfileError('target_profile_unavailable')
            _check_parent(parent, directory)
            document = _decode(bytes(content))
        return validate_http_target_profile(document)
    except TargetProfileError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise TargetProfileError('target_profile_unavailable') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def create_http_target_profile(path, document):
    profile = validate_http_target_profile(document)
    canary, credential, _ = _references(profile)
    _public(profile, path, canary, credential)
    content = (json.dumps(profile.document(), indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode()
    if len(content) > MAX_PROFILE_BYTES:
        raise TargetProfileError()
    descriptor = None
    owned = None

    def remove_owned(directory, name):
        if owned is not None:
            try:
                named = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if _identity(named) == owned:
                    os.unlink(name, dir_fd=directory)
            except OSError:
                pass

    with _parent(path, create=True, on_failure=remove_owned) as (parent, directory, name):
        try:
            try:
                descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=directory)
            except FileExistsError:
                raise TargetProfileError('target_profile_destination_exists') from None
            owned = _identity(os.fstat(descriptor))
            os.fchmod(descriptor, 0o600)
            _safe_file(os.fstat(descriptor))
            pending = memoryview(content)
            while pending:
                written = os.write(descriptor, pending)
                if written < 1:
                    raise TargetProfileError('target_profile_unavailable')
                pending = pending[written:]
            os.fsync(descriptor)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            _safe_file(named)
            if _identity(named) != owned:
                raise TargetProfileError('target_profile_unavailable')
            _check_parent(parent, directory)
        except BaseException:
            remove_owned(directory, name)
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
    return profile


def _references(profile):
    canary = os.environ.get(profile.canary_env)
    credential = os.environ.get(profile.credential_env) if profile.credential_env is not None else None
    problems = []
    if type(canary) is not str or not _MARKER.fullmatch(canary):
        problems.append('protected_canary_reference_unavailable')
    if profile.credential_env is not None and (type(credential) is not str or not 16 <= len(credential) <= 4096
            or any(not 33 <= ord(char) <= 126 for char in credential)):
        problems.append('credential_reference_unavailable')
    return canary, credential, problems


def _scope(profile, *, allow_loopback):
    from src.core.transport import ScanBudget, TransportPolicyError
    parts = urlsplit(profile.descriptor['endpoint'])
    try:
        literal = ipaddress.ip_address(parts.hostname)
    except ValueError:
        literal = None
    if profile.descriptor['auth_scheme'] == 'bearer' and parts.scheme != 'https':
        if literal is None or not literal.is_loopback or not allow_loopback:
            raise TargetProfileError('plaintext_credential_refused')
    if literal is not None:
        try:
            ScanBudget(allowed_networks=profile.allowed_networks, allow_loopback=allow_loopback).check_address(literal)
        except TransportPolicyError:
            raise TargetProfileError('target_scope_refused') from None


def _public(profile, profile_path, canary, credential):
    from src.core.http_application_policy import public_http_agent, validate_http_public_privacy
    private = tuple(value for value in (canary, credential, profile.credential_env, profile.canary_env,
                                        os.fspath(profile_path)) if isinstance(value, str) and value)
    try:
        validate_http_public_privacy({'target': {'http_target': profile.descriptor, 'name': profile.name,
                                               'allowed_networks': list(profile.allowed_networks)},
                                     'public_fields': [*_FIELDS, *_PLAN_FIELDS, *_ERRORS, *_ERRORS.values()]}, private)
        agent = public_http_agent(profile.descriptor, name=profile.name)
        validate_http_public_privacy(agent, private)
        return agent, private
    except (ValueError, TypeError):
        raise TargetProfileError('protected_value_conflicts_public_definition') from None


def prepare_http_profile(profile, profile_path, *, allow_loopback=False):
    from src.core.http_application_runtime import prepare_http_target
    canary, credential, problems = _references(profile)
    agent, private = _public(profile, profile_path, canary, credential)
    if problems:
        raise TargetProfileError(problems[0])
    _scope(profile, allow_loopback=allow_loopback)
    try:
        return prepare_http_target(agent, credential=credential, canary=canary, private_values=private)
    except (ValueError, TypeError):
        raise TargetProfileError('protected_value_conflicts_public_definition') from None


def plan_http_profile(profile, profile_path, *, allow_loopback=False, max_requests=35,
                      max_response_bytes=65536, timeout_seconds=180, request_timeout_seconds=10):
    from src.core.http_application_policy import HTTP_OBJECTIVE
    canary, credential, problems = _references(profile)
    agent, _ = _public(profile, profile_path, canary, credential)
    try:
        _scope(profile, allow_loopback=allow_loopback)
    except TargetProfileError as error:
        problems.append(error.code)
    plan = {'configuration_status': 'blocked' if problems else 'ready', 'reason_codes': problems,
            'assessment_objective': HTTP_OBJECTIVE, 'http_target_binding': agent['http_target_binding'],
            'target': {'name': profile.name, 'http_target': profile.descriptor,
                       'allowed_networks': list(profile.allowed_networks)},
            'selected_rule_count': 7, 'maximum_prompt_http_attempts': 35,
            'shared_attempt_budget': max_requests, 'max_response_bytes': max_response_bytes,
            'overall_timeout_seconds': timeout_seconds, 'request_timeout_seconds': request_timeout_seconds,
            'session_mode': 'fresh-per-prompt-v1', 'canary_seeding_status': 'operator_attested',
            'network_readiness_status': 'not_checked',
            'limitations': ['Target reachability, response mapping and canary seeding are not independently verified.',
                            'Fresh client sessions do not reset application state; server-side resets are operator-attested.',
                            'Quiet responses cannot establish a passed prompt check.']}
    from src.core.http_application_policy import validate_http_public_privacy
    try:
        validate_http_public_privacy(plan, [value for value in (canary, credential, profile.credential_env,
                                    profile.canary_env, os.fspath(profile_path)) if isinstance(value, str) and value])
    except (ValueError, TypeError):
        raise TargetProfileError('protected_value_conflicts_public_definition') from None
    return plan
