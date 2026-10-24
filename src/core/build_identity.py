"""Public content identity for an immutable scanner installation.

Fingerprints describe process-lifetime source snapshots, not Git revisions,
dependency attestations, executed coverage, or cryptographic report authenticity.
No operator configuration or caller-selected file path is consulted.
"""

import ast
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from src._version import __version__
from src.core.prompt_catalog import baseline_payloads, candidate_payloads
from src.core.redaction import contains_literal


IDENTITY_SCHEMA_VERSION = '1.0'
SOURCE_SCOPE = 'scanner-python-v1'
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_FILES = 2048
MAX_SOURCE_ENTRIES = 8192
MAX_SOURCE_DEPTH = 16
MAX_CATALOG_BYTES = 4 * 1024 * 1024
_ROOT = Path(__file__).resolve().parents[2]
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_IDENTIFIER = re.compile(r'[a-z][a-z0-9_.-]{0,127}\Z')
_VERSION = re.compile(r'v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*'
                      r'(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?'
                      r'(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?'
                      r'(?:[-_.]?dev[-_.]?[0-9]*)?'
                      r'(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\Z', re.IGNORECASE)
_FAILURES = (OSError, ValueError, TypeError, KeyError, AttributeError, SyntaxError, UnicodeError,
             OverflowError, RecursionError)


def _flags(*, directory=False):
    # Refuse unsupported no-follow operation rather than weaken path confinement.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    return flags | os.O_DIRECTORY if directory else flags


def _read_file(parent, name, *, allowance=MAX_SOURCE_FILE_BYTES):
    descriptor = os.open(name, _flags(), dir_fd=parent)
    try:
        metadata = os.fstat(descriptor)
        maximum = min(MAX_SOURCE_FILE_BYTES, allowance)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError('Unavailable source file')
        chunks, total = [], 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError('Unavailable source size')
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        os.close(descriptor)


def _digest(records, namespace):
    digest = hashlib.sha256(namespace.encode('ascii') + b'\0')
    for name, value in sorted(records):
        encoded = name.encode('utf-8')
        digest.update(len(encoded).to_bytes(8, 'big'))
        digest.update(encoded)
        digest.update(len(value).to_bytes(8, 'big'))
        digest.update(value)
    return digest.hexdigest()


def _source_records():
    """Walk directory descriptors without following source symlinks."""
    if not _ROOT.is_absolute() or _ROOT.resolve() != _ROOT:
        raise ValueError('Unavailable scanner root')
    records, total, entries = [], 0, 0
    if MAX_SOURCE_FILES < 1:
        raise ValueError('Unavailable source budget')
    root = os.open(_ROOT, _flags(directory=True))
    try:
        cli = _read_file(root, 'scanner_cli.py', allowance=MAX_SOURCE_BYTES)
        records.append(('scanner_cli.py', cli))
        total += len(cli)
        def walk(parent, prefix, depth):
            nonlocal total, entries
            if depth > MAX_SOURCE_DEPTH:
                raise ValueError('Unavailable source depth')
            with os.scandir(parent) as children:
                for child in children:
                    entries += 1
                    if entries > MAX_SOURCE_ENTRIES:
                        raise ValueError('Unavailable source entries')
                    if child.name in {'__pycache__', '.git'}:
                        continue
                    if child.is_symlink():
                        raise ValueError('Unavailable source link')
                    relative = prefix + '/' + child.name
                    if child.is_dir(follow_symlinks=False):
                        nested = os.open(child.name, _flags(directory=True), dir_fd=parent)
                        try:
                            walk(nested, relative, depth + 1)
                        finally:
                            os.close(nested)
                    elif child.name.endswith('.py'):
                        if len(records) >= MAX_SOURCE_FILES:
                            raise ValueError('Unavailable source budget')
                        value = _read_file(parent, child.name, allowance=MAX_SOURCE_BYTES - total)
                        total += len(value)
                        records.append((relative, value))
        source = os.open('src', _flags(directory=True), dir_fd=root)
        try:
            walk(source, 'src', 0)
        finally:
            os.close(source)
    finally:
        os.close(root)
    if not {'src/_version.py', 'src/core/build_identity.py'} <= {name for name, _ in records}:
        raise ValueError('Unavailable scanner source')
    return records


def _catalog(values, identifier):
    if type(values) is not dict or not 1 <= len(values) <= 128:
        raise ValueError('Unavailable bundled catalog')
    count = 0
    for category, payloads in values.items():
        if (not isinstance(category, str) or not _IDENTIFIER.fullmatch(category)
                or type(payloads) is not list or not payloads
                or any(not isinstance(value, str) or not value for value in payloads)):
            raise ValueError('Unavailable bundled definitions')
        count += len(payloads)
        if count > 16384:
            raise ValueError('Unavailable catalog count')
    encoded = json.dumps(list(values.items()), ensure_ascii=True, sort_keys=True,
                         separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(encoded) > MAX_CATALOG_BYTES:
        raise ValueError('Unavailable catalog size')
    return {'id': identifier, 'sha256': hashlib.sha256(encoded).hexdigest(),
            'categories': len(values), 'payloads': count}


def _catalogs(records):
    """Read only literal public semantics, without importing security engines."""
    source = dict(records)['src/security/prompt_suites.py']
    literals = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {'PROTECTED_DISCLOSURE_SUITE', '_SEMANTICS'}:
                    literals[target.id] = ast.literal_eval(node.value)
    suite, semantics = literals['PROTECTED_DISCLOSURE_SUITE'], literals['_SEMANTICS']
    if not _identifier(suite) or not _identifier(semantics):
        raise ValueError('Unavailable catalog semantics')
    baseline, candidate = baseline_payloads(), candidate_payloads()
    protected = _catalog(candidate, suite)
    # Match the existing public suite pin exactly; payload bytes and sampling stay unchanged.
    public = {'suite': suite, 'semantics': semantics, 'payloads': list(candidate.items())}
    protected.update(semantics=semantics, pin=hashlib.sha256(json.dumps(
        public, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
    return {'scope': 'bundled_definitions', 'status': 'available',
            'baseline': _catalog(baseline, 'baseline-prompt-v1'), 'protected_disclosure': protected}


@lru_cache(maxsize=1)
def _snapshot():
    source = {'scope': SOURCE_SCOPE, 'status': 'unavailable', 'sha256': None}
    catalogs = {'scope': 'bundled_definitions', 'status': 'unavailable',
                'baseline': None, 'protected_disclosure': None}
    try:
        records = _source_records()
        source.update(status='available', sha256=_digest(records, SOURCE_SCOPE))
    except _FAILURES:
        return source, catalogs
    try:
        catalogs = _catalogs(records)
    except _FAILURES:
        pass
    return source, catalogs


@lru_cache(maxsize=1)
def _server_snapshot():
    try:
        if not _ROOT.is_absolute() or _ROOT.resolve() != _ROOT:
            raise ValueError('Unavailable scanner root')
        parent = os.open(_ROOT, _flags(directory=True))
        try:
            data = _read_file(parent, 'app.py')
        finally:
            os.close(parent)
        return {'status': 'available', 'sha256': _digest([('app.py', data)], 'server-app-python-v1')}
    except _FAILURES:
        return {'status': 'unavailable', 'sha256': None}


def _server_component():
    # Do not inspect a library host's unrelated app.py. Docker's separately
    # copied server entrypoint is explicitly outside this checkout-only scope.
    module = sys.modules.get('app')
    filename = getattr(module, '__file__', None)
    if type(filename) is not str or filename != str(_ROOT / 'app.py'):
        return {'status': 'unavailable', 'sha256': None}
    # Absence above is deliberately not cached: an early library diagnostic
    # must not prevent a later legitimate scanner server from being identified.
    return _server_snapshot()


def current_identity(component='library'):
    """Return an independent public identity for this immutable process snapshot."""
    if type(component) is not str or component not in {'library', 'cli', 'server'}:
        raise ValueError('Unsupported scanner identity component')
    source, catalogs = _snapshot()
    server = _server_component() if component == 'server' else {'status': 'not_applicable', 'sha256': None}
    return deepcopy({'identity_schema_version': IDENTITY_SCHEMA_VERSION, 'package_version': __version__,
                     'component': component, 'source': source, 'server_app': server, 'catalogs': catalogs})


def _identifier(value):
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _hash_status(value, statuses):
    return (type(value) is dict and set(value) == {'status', 'sha256'} and value['status'] in statuses
            and (type(value['sha256']) is str and _HEX.fullmatch(value['sha256']) is not None
                 if value['status'] == 'available' else value['sha256'] is None))


def _catalog_valid(value, *, protected=False):
    fields = {'id', 'sha256', 'categories', 'payloads'} | ({'semantics', 'pin'} if protected else set())
    return (type(value) is dict and set(value) == fields and _identifier(value['id'])
            and type(value['sha256']) is str and _HEX.fullmatch(value['sha256']) is not None
            and type(value['categories']) is int and 0 <= value['categories'] <= 128
            and type(value['payloads']) is int and value['categories'] <= value['payloads'] <= 16384
            and (not protected or _identifier(value['semantics']) and type(value['pin']) is str
                 and _HEX.fullmatch(value['pin']) is not None))


def saved_identity(value):
    """Validate declared historical provenance, never authenticate or replace it."""
    try:
        if (type(value) is not dict or set(value) != {
                'identity_schema_version', 'package_version', 'component', 'source', 'server_app', 'catalogs'}
                or value['identity_schema_version'] != IDENTITY_SCHEMA_VERSION
                or type(value['package_version']) is not str or len(value['package_version']) > 64
                or not _VERSION.fullmatch(value['package_version'])
                or value['component'] not in {'library', 'cli', 'server'}):
            return None
        source, server, catalogs = value['source'], value['server_app'], value['catalogs']
        if (type(source) is not dict or set(source) != {'scope', 'status', 'sha256'}
                or source['scope'] != SOURCE_SCOPE
                or not _hash_status({key: source[key] for key in ('status', 'sha256')}, {'available', 'unavailable'})
                or not _hash_status(server, {'available', 'unavailable'} if value['component'] == 'server'
                                    else {'not_applicable'})
                or type(catalogs) is not dict or set(catalogs) != {'scope', 'status', 'baseline', 'protected_disclosure'}
                or catalogs['scope'] != 'bundled_definitions'):
            return None
        if catalogs['status'] == 'available':
            if not _catalog_valid(catalogs['baseline']) or not _catalog_valid(catalogs['protected_disclosure'], protected=True):
                return None
        elif catalogs['status'] != 'unavailable' or catalogs['baseline'] is not None or catalogs['protected_disclosure'] is not None:
            return None
        return deepcopy(value)
    except _FAILURES:
        return None


def public_identity(value, secrets=()):
    """A private collision makes the claimed producer explicitly unknown."""
    result = saved_identity(value)
    if result is None or isinstance(secrets, (str, bytes)):
        return None
    def folded_strings(value):
        if isinstance(value, str):
            return value.casefold()
        if isinstance(value, dict):
            return {key.casefold(): folded_strings(item) for key, item in value.items()}
        if isinstance(value, list):
            return [folded_strings(item) for item in value]
        return value
    material = folded_strings(result)
    try:
        for index, secret in enumerate(secrets):
            if index >= 4096 or type(secret) is not str:
                return None
            if secret and contains_literal(material, secret.casefold()):
                return None
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        return None
    return result


def validate_identity_fields(secrets):
    """Public report keys cannot themselves disclose a protected value."""
    message = 'Protected data conflicts with scanner identity fields'
    if isinstance(secrets, (str, bytes)):
        raise ValueError(message)
    try:
        for index, secret in enumerate(secrets):
            if index >= 4096 or type(secret) is not str:
                raise ValueError(message)
            if secret and contains_literal(['producer_identity', 'exporter_identity'], secret.casefold()):
                raise ValueError(message)
    except (TypeError, UnicodeError, OverflowError, RecursionError):
        raise ValueError(message) from None
