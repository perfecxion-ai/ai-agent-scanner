"""Content identity is bounded, public, reproducible and independent of operator state."""

import ast
from copy import deepcopy
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from src._version import __version__
from src.core import build_identity as identity
from src.security.prompt_suites import prompt_suite_pin


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated_snapshots():
    identity._snapshot.cache_clear()
    identity._server_snapshot.cache_clear()
    yield
    identity._snapshot.cache_clear()
    identity._server_snapshot.cache_clear()


@pytest.fixture
def source_tree(tmp_path, monkeypatch):
    root = tmp_path / 'scanner'
    shutil.copytree(ROOT / 'src', root / 'src', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copyfile(ROOT / 'scanner_cli.py', root / 'scanner_cli.py')
    shutil.copyfile(ROOT / 'app.py', root / 'app.py')
    monkeypatch.setattr(identity, '_ROOT', root)
    return root


def test_current_public_identity_and_exact_existing_bundled_suite_pin():
    value = identity.current_identity()
    assert value['identity_schema_version'] == '1.0'
    assert value['package_version'] == __version__ == '1.2.0.dev0'
    assert value['source']['status'] == 'available'
    assert value['source']['scope'] == 'scanner-python-v1'
    assert value['server_app'] == {'status': 'not_applicable', 'sha256': None}
    catalogs = value['catalogs']
    assert catalogs['scope'] == 'bundled_definitions' and catalogs['status'] == 'available'
    assert (catalogs['baseline']['categories'], catalogs['baseline']['payloads']) == (7, 70)
    assert (catalogs['protected_disclosure']['categories'], catalogs['protected_disclosure']['payloads']) == (7, 35)
    assert catalogs['protected_disclosure']['pin'] == prompt_suite_pin()
    assert identity.saved_identity(value) == value
    assert identity.public_identity(value) == value


def test_canonical_version_is_dependency_free_and_build_metadata_uses_it():
    source = ast.parse((ROOT / 'src' / '_version.py').read_text())
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(source))
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib
    configuration = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    assert 'version' not in configuration['project']
    assert configuration['project']['dynamic'] == ['version']
    assert configuration['tool']['setuptools']['dynamic']['version']['attr'] == 'src._version.__version__'


def test_source_digest_matches_copies_and_ignores_locations_mtime_and_generated_files(source_tree, monkeypatch, tmp_path):
    first = identity.current_identity('library')
    second_root = tmp_path / 'installed-copy'
    shutil.copytree(source_tree, second_root)
    (second_root / 'src' / '__pycache__').mkdir()
    (second_root / 'src' / '__pycache__' / 'unrelated.pyc').write_bytes(b'Ignored generated cache')
    (second_root / '.private-operator-config').write_text('Ignored synthetic private value')
    for path in second_root.rglob('*.py'):
        os.utime(path, (1, 1))
    monkeypatch.setattr(identity, '_ROOT', second_root)
    identity._snapshot.cache_clear()
    second = identity.current_identity('cli')
    assert first['source'] == second['source']
    assert first['catalogs'] == second['catalogs']
    assert str(source_tree) not in json.dumps(first)
    assert str(second_root) not in json.dumps(second)


@pytest.mark.parametrize('relative', ['scanner_cli.py', 'src/core/contracts.py', 'src/core/prompt_catalog.py'])
def test_public_source_changes_alter_the_scanner_fingerprint(source_tree, relative):
    first = identity.current_identity()['source']['sha256']
    path = source_tree / relative
    path.write_bytes(path.read_bytes() + b'\n# Synthetic source change\n')
    identity._snapshot.cache_clear()
    assert identity.current_identity()['source']['sha256'] != first


def test_cached_snapshot_and_returned_copy_are_independent(source_tree):
    original = identity.current_identity()
    changed = deepcopy(original)
    changed['source']['sha256'] = 'a' * 64
    original['source']['sha256'] = 'b' * 64
    original['catalogs']['baseline']['payloads'] = 999
    (source_tree / 'scanner_cli.py').write_bytes(b'Changed after process snapshot')
    again = identity.current_identity()
    assert again['source']['sha256'] not in {'a' * 64, 'b' * 64}
    assert again['catalogs']['baseline']['payloads'] == 70


def test_catalog_change_alters_only_the_relevant_public_definition_hash_and_pin(source_tree, monkeypatch):
    first = identity.current_identity()
    definitions = identity.candidate_payloads()
    definitions[next(iter(definitions))].append('Synthetic extra bundled definition')
    monkeypatch.setattr(identity, 'candidate_payloads', lambda: deepcopy(definitions))
    identity._snapshot.cache_clear()
    second = identity.current_identity()
    assert second['source'] == first['source']
    assert second['catalogs']['baseline'] == first['catalogs']['baseline']
    assert second['catalogs']['protected_disclosure']['sha256'] != first['catalogs']['protected_disclosure']['sha256']
    assert second['catalogs']['protected_disclosure']['pin'] != first['catalogs']['protected_disclosure']['pin']
    assert second['catalogs']['protected_disclosure']['payloads'] == 36


def test_public_suite_semantics_are_read_without_loading_operator_configuration(source_tree, monkeypatch):
    monkeypatch.setenv('SCAN_EVIDENCE_PROFILES_FILE', '/private/never-open-profile.json')
    monkeypatch.setenv('DATABASE_URL', 'invalid inherited operator setting')
    monkeypatch.setattr(importlib.metadata, 'version', lambda *args: pytest.fail('Stale installed metadata was consulted'))
    first = identity.current_identity()
    suites = source_tree / 'src' / 'security' / 'prompt_suites.py'
    suites.write_text(suites.read_text().replace('nondisclosure-inconclusive-v2', 'nondisclosure-inconclusive-v3'))
    identity._snapshot.cache_clear()
    second = identity.current_identity()
    assert first['catalogs']['protected_disclosure']['semantics'] == 'nondisclosure-inconclusive-v2'
    assert second['catalogs']['protected_disclosure']['semantics'] == 'nondisclosure-inconclusive-v3'
    assert first['catalogs']['protected_disclosure']['pin'] != second['catalogs']['protected_disclosure']['pin']
    assert '/private/' not in json.dumps(second)


@pytest.mark.parametrize('kind', ['missing-cli', 'file-link', 'directory-link', 'root-link', 'oversized'])
def test_unavailable_source_does_not_follow_symlinks_or_publish_private_paths(source_tree, monkeypatch, tmp_path, kind):
    private = tmp_path / 'outside'
    private.mkdir()
    (private / 'operator.py').write_text('Synthetic private text never read')
    if kind == 'missing-cli':
        (source_tree / 'scanner_cli.py').unlink()
    elif kind == 'file-link':
        (source_tree / 'src' / 'outside.py').symlink_to(private / 'operator.py')
    elif kind == 'directory-link':
        (source_tree / 'src' / 'outside').symlink_to(private, target_is_directory=True)
    elif kind == 'root-link':
        link = tmp_path / 'root-alias'
        link.symlink_to(source_tree, target_is_directory=True)
        monkeypatch.setattr(identity, '_ROOT', link)
    else:
        (source_tree / 'src' / 'oversized.py').write_bytes(b'x' * (identity.MAX_SOURCE_FILE_BYTES + 1))
    value = identity.current_identity()
    assert value['package_version'] == __version__
    assert value['source'] == {'scope': 'scanner-python-v1', 'status': 'unavailable', 'sha256': None}
    assert str(private) not in json.dumps(value) and 'Synthetic private text' not in json.dumps(value)
    assert identity.saved_identity(value) == value


def test_read_failure_is_static_and_a_large_source_is_rejected_before_reading(source_tree, monkeypatch):
    path = source_tree / 'large.py'
    path.write_bytes(b'x' * (identity.MAX_SOURCE_FILE_BYTES + 1))
    parent = os.open(source_tree, identity._flags(directory=True))
    try:
        monkeypatch.setattr(identity.os, 'read', lambda *args: pytest.fail('Oversized source bytes were fetched'))
        with pytest.raises(ValueError, match='Unavailable source file'):
            identity._read_file(parent, 'large.py')
    finally:
        os.close(parent)


@pytest.mark.parametrize('limit', ['MAX_SOURCE_BYTES', 'MAX_SOURCE_FILES', 'MAX_SOURCE_ENTRIES', 'MAX_SOURCE_DEPTH'])
def test_source_traversal_has_finite_aggregate_limits(source_tree, monkeypatch, limit):
    monkeypatch.setattr(identity, limit, 0)
    assert identity.current_identity()['source']['status'] == 'unavailable'


def test_server_component_is_checkout_only_and_absence_is_not_cached(source_tree, monkeypatch, tmp_path):
    monkeypatch.delitem(identity.sys.modules, 'app', raising=False)
    first = identity.current_identity('server')
    assert first['server_app'] == {'status': 'unavailable', 'sha256': None}
    monkeypatch.setitem(identity.sys.modules, 'app', SimpleNamespace(__file__=str(source_tree / 'app.py')))
    second = identity.current_identity('server')
    assert second['server_app']['status'] == 'available'
    assert second['source'] == first['source']
    outside = tmp_path / 'outside-app'
    outside.mkdir()
    (outside / 'app.py').write_text('Synthetic private embedding source')
    monkeypatch.setitem(identity.sys.modules, 'app', SimpleNamespace(__file__=str(outside / 'app.py')))
    assert identity.current_identity('server')['server_app'] == {'status': 'unavailable', 'sha256': None}


def test_server_file_symlink_is_unavailable_and_never_reads_its_target(source_tree, monkeypatch, tmp_path):
    outside = tmp_path / 'outside-app.py'
    outside.write_text('Synthetic private source')
    (source_tree / 'app.py').unlink()
    (source_tree / 'app.py').symlink_to(outside)
    monkeypatch.setitem(identity.sys.modules, 'app', SimpleNamespace(__file__=str(source_tree / 'app.py')))
    value = identity.current_identity('server')
    assert value['server_app'] == {'status': 'unavailable', 'sha256': None}
    assert 'Synthetic private' not in json.dumps(value)


def test_historical_identity_preserves_different_legitimate_version_catalog_and_digest():
    old = identity.current_identity()
    old.update(package_version='1.1.0')
    old['source']['sha256'] = '1' * 64
    old['catalogs']['baseline'].update(id='baseline-prompt-v0', sha256='2' * 64, categories=2, payloads=4)
    old['catalogs']['protected_disclosure'].update(id='protected-disclosure-v0', semantics='earlier-semantics-v1',
                                                 sha256='3' * 64, pin='4' * 64, categories=1, payloads=1)
    saved = identity.saved_identity(old)
    assert saved == old and saved is not old
    saved['source']['sha256'] = '5' * 64
    assert old['source']['sha256'] == '1' * 64


@pytest.mark.parametrize('version', ['1', '1.0rc1.dev2', '1!2.0.post1.dev3+older.build', '1.0RC1', 'v1.0'])
def test_saved_identity_accepts_legitimate_older_version_forms(version):
    value = identity.current_identity()
    value['package_version'] = version
    assert identity.saved_identity(value) == value


@pytest.mark.parametrize('mutation', ['schema', 'version', 'private-field', 'hash', 'redacted', 'status',
                                     'boolean-count', 'oversized-count', 'catalog-status', 'component'])
def test_malformed_or_redacted_claimed_provenance_becomes_unknown(mutation):
    value = identity.current_identity()
    if mutation == 'schema':
        value['identity_schema_version'] = '999'
    elif mutation == 'version':
        value['package_version'] = 'private/operator/path'
    elif mutation == 'private-field':
        value['extra'] = 'Synthetic secret'
    elif mutation in {'hash', 'redacted'}:
        value['source']['sha256'] = 'not-a-hash' if mutation == 'hash' else '[REDACTED]'
    elif mutation == 'status':
        value['source']['status'] = ['available']
    elif mutation == 'boolean-count':
        value['catalogs']['baseline']['payloads'] = True
    elif mutation == 'oversized-count':
        value['catalogs']['baseline']['payloads'] = 100000
    elif mutation == 'catalog-status':
        value['catalogs']['status'] = 'unavailable'
    else:
        value['component'] = 'server'
    assert identity.saved_identity(value) is None
    assert identity.public_identity(value) is None


def test_historical_missing_and_private_collisions_never_substitute_current(monkeypatch):
    value = identity.current_identity()
    protected = value['source']['sha256']
    monkeypatch.setattr(identity, 'current_identity', lambda *args: pytest.fail('Historical producer was replaced'))
    assert identity.saved_identity(None) is None
    assert identity.saved_identity({}) is None
    assert identity.public_identity(value, secrets=[protected.upper()]) is None
    assert identity.public_identity(value, secrets=['Synthetic unrelated private value']) == value
    assert identity.public_identity(value, secrets=[object()]) is None


@pytest.mark.parametrize('protected', ['null', 'true', 'false', '35', '70', ':', '{'])
def test_json_syntax_and_numeric_values_are_not_literal_identity_collisions(protected):
    value = identity.current_identity()
    # Keep numeric counts in the identity while excluding accidental digit
    # sequences in independently generated source/catalog fingerprints.
    value['source']['sha256'] = 'a' * 64
    value['catalogs']['baseline']['sha256'] = 'b' * 64
    value['catalogs']['protected_disclosure'].update(sha256='c' * 64, pin='d' * 64)
    assert identity.public_identity(value, secrets=[protected]) == value


@pytest.mark.parametrize('location', ['source', 'catalog', 'version', 'key'])
def test_real_string_identity_collisions_still_become_unknown(location):
    value = identity.current_identity()
    if location == 'source':
        protected = value['source']['sha256']
    elif location == 'catalog':
        protected = value['catalogs']['protected_disclosure']['pin']
    elif location == 'version':
        protected = value['package_version']
    else:
        protected = 'identity_schema_version'
    assert identity.public_identity(value, secrets=[protected.upper()]) is None


def test_invalid_component_is_rejected_before_any_source_read(monkeypatch):
    monkeypatch.setattr(identity, '_snapshot', lambda: pytest.fail('Invalid component reached source files'))
    with pytest.raises(ValueError, match='Unsupported scanner identity component') as caught:
        identity.current_identity('/private/operator-profile.json')
    assert '/private/' not in str(caught.value)


@pytest.mark.parametrize('protected', ['producer_identity', 'exporter_identity', 'PRODUCER_IDENTITY', 'EXPORTER_IDENTITY'])
def test_outer_public_identity_field_collisions_fail_static_privacy_preflight(protected):
    with pytest.raises(ValueError, match='Protected data conflicts with scanner identity fields') as caught:
        identity.validate_identity_fields({protected})
    assert protected not in str(caught.value)


@pytest.mark.parametrize('values', [None, 'private-literal-value', [object()], ['unrelated-secret'] * 4097])
def test_invalid_identity_field_privacy_context_fails_without_echo(values):
    with pytest.raises(ValueError, match='Protected data conflicts with scanner identity fields'):
        identity.validate_identity_fields(values)


def test_identity_field_privacy_preflight_is_pure_and_allows_unrelated_protected_values(monkeypatch):
    monkeypatch.setattr(identity, 'current_identity', lambda *args: pytest.fail('Privacy preflight read current identity'))
    monkeypatch.setattr(identity, '_snapshot', lambda: pytest.fail('Privacy preflight read source files'))
    assert identity.validate_identity_fields({'unrelated-synthetic-protected-value', ''}) is None
