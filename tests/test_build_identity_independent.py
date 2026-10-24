"""Independent provenance boundaries, historical views, and producer retention."""

from copy import deepcopy
import importlib.metadata
import json
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest
from sqlalchemy import event

from src.core import build_identity
from src.core import pipeline
from src.reporting.report_generator import ReportGenerator
from tests.test_api_auth import api as api, headers
from tests.test_job_checkpoints import (
    checkpoint_store as checkpoint_store, report as checkpoint_report, save as save_checkpoint,
    store as store,
)
from tests.test_jobs import result as stored_result
from tests.test_pipeline import asset, engines


@pytest.fixture
def identity(monkeypatch):
    build_identity._snapshot.cache_clear()
    build_identity._server_snapshot.cache_clear()
    yield build_identity
    build_identity._snapshot.cache_clear()
    build_identity._server_snapshot.cache_clear()


@pytest.fixture
def owned_source(identity, monkeypatch, tmp_path):
    root = tmp_path.resolve() / 'owned-source'
    files = {
        'scanner_cli.py': '# Owned CLI source\n',
        'src/_version.py': "__version__ = '1.2.0.dev0'\n",
        'src/core/build_identity.py': '# Owned scanner source\n',
        'src/security/prompt_suites.py': (
            "PROTECTED_DISCLOSURE_SUITE = 'protected-disclosure-v1'\n"
            "_SEMANTICS = 'nondisclosure-inconclusive-v2'\n"),
    }
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    monkeypatch.setattr(identity, '_ROOT', root)
    return root


def renewed(identity, component='library'):
    identity._snapshot.cache_clear()
    identity._server_snapshot.cache_clear()
    return identity.current_identity(component)


def test_identity_ignores_installed_metadata_git_environment_and_network(identity, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Identity must not consult external context')
    monkeypatch.setattr(importlib.metadata, 'version', forbidden)
    monkeypatch.setattr(importlib.metadata, 'distribution', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setenv('DATABASE_URL', 'sqlite:////private/never-open.sqlite')
    monkeypatch.setenv('SCAN_EVIDENCE_PROFILES_FILE', '/private/never-open.json')
    monkeypatch.setenv('GIT_COMMIT', 'untrusted-commit-from-environment')
    value = identity.current_identity()
    assert value['package_version'] == '1.2.0.dev0'
    assert value['source']['status'] == 'available'
    assert value['catalogs']['scope'] == 'bundled_definitions'
    assert value['server_app'] == {'status': 'not_applicable', 'sha256': None}
    assert '/private/' not in json.dumps(value) and 'untrusted-commit' not in json.dumps(value)


def test_public_snapshot_is_independent_and_bundled_catalogs_are_not_execution(identity):
    first = identity.current_identity('cli')
    original = deepcopy(first)
    first['source']['sha256'] = 'f' * 64
    first['catalogs']['baseline']['payloads'] = 0
    second = identity.current_identity('cli')
    assert second == original
    assert second['catalogs']['baseline']['categories'] == 7
    assert second['catalogs']['baseline']['payloads'] == 70
    assert second['catalogs']['protected_disclosure']['categories'] == 7
    assert second['catalogs']['protected_disclosure']['payloads'] == 35
    from src.security.prompt_suites import prompt_suite_pin
    assert second['catalogs']['protected_disclosure']['pin'] == prompt_suite_pin()
    assert 'executed' not in json.dumps(second) and 'coverage' not in second


def test_source_scope_includes_cli_and_python_but_excludes_server_and_context(identity, owned_source):
    original = renewed(identity)
    assert original['source']['status'] == 'available'
    for relative in ['app.py', 'README.md', 'operator-config.json', 'src/notes.txt']:
        (owned_source / relative).write_text('Context is outside the Python fingerprint\n')
    assert renewed(identity) == original
    (owned_source / 'scanner_cli.py').write_text('# Different CLI bytes\n')
    changed = renewed(identity)
    assert changed['source']['sha256'] != original['source']['sha256']
    (owned_source / 'src/added.py').write_text('VALUE = 1\n')
    assert renewed(identity)['source']['sha256'] != changed['source']['sha256']
    assert renewed(identity)['catalogs'] == original['catalogs']


@pytest.mark.parametrize('kind', ['cli-link', 'python-link', 'directory-link', 'root-link'])
def test_source_symlinks_make_provenance_unavailable(identity, owned_source, monkeypatch, tmp_path, kind):
    outside = tmp_path / 'outside'
    outside.mkdir()
    secret = outside / 'private.py'
    secret.write_text('PRIVATE_SENTINEL = 1\n')
    if kind == 'cli-link':
        path = owned_source / 'scanner_cli.py'
        path.unlink()
        path.symlink_to(secret)
    elif kind == 'python-link':
        (owned_source / 'src/linked.py').symlink_to(secret)
    elif kind == 'directory-link':
        (owned_source / 'src/linked').symlink_to(outside, target_is_directory=True)
    else:
        alias = tmp_path / 'source-alias'
        alias.symlink_to(owned_source, target_is_directory=True)
        monkeypatch.setattr(identity, '_ROOT', alias)
    value = renewed(identity)
    assert value['source'] == {'scope': 'scanner-python-v1', 'status': 'unavailable', 'sha256': None}
    assert value['catalogs']['status'] == 'unavailable'
    assert str(outside) not in json.dumps(value) and 'PRIVATE_SENTINEL' not in json.dumps(value)


def test_source_read_error_has_no_partial_hash_or_exception_context(identity, owned_source, monkeypatch):
    original = identity.os.open
    def denied(path, *args, **kwargs):
        if path == 'scanner_cli.py':
            raise PermissionError('private-file-content-must-not-escape')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(identity.os, 'open', denied)
    value = renewed(identity)
    assert value['source']['status'] == 'unavailable' and value['source']['sha256'] is None
    assert value['catalogs']['baseline'] is None and value['catalogs']['protected_disclosure'] is None
    assert 'private-file-content' not in json.dumps(value)


@pytest.mark.parametrize('budget,value', [
    ('MAX_SOURCE_BYTES', 1), ('MAX_SOURCE_FILES', 1), ('MAX_SOURCE_ENTRIES', 1),
    ('MAX_SOURCE_FILE_BYTES', 1), ('MAX_SOURCE_DEPTH', 0),
])
def test_source_limits_fail_closed_without_a_partial_fingerprint(identity, owned_source, monkeypatch, budget, value):
    monkeypatch.setattr(identity, budget, value)
    result = renewed(identity)
    assert result['source']['status'] == 'unavailable'
    assert result['source']['sha256'] is None


def test_unrelated_loaded_app_is_never_read_as_scanner_server(identity, owned_source, monkeypatch, tmp_path):
    other = tmp_path / 'unrelated-app'
    other.mkdir()
    path = other / 'app.py'
    path.write_text('PRIVATE_OTHER_APP = True\n')
    opened = []
    original_open = identity.os.open
    def observed_open(filename, *args, **kwargs):
        opened.append(filename)
        return original_open(filename, *args, **kwargs)
    monkeypatch.setattr(identity.os, 'open', observed_open)
    monkeypatch.setitem(sys.modules, 'app', SimpleNamespace(__file__=str(path)))
    result = identity.current_identity('server')
    assert result['server_app'] == {'status': 'unavailable', 'sha256': None}
    assert other not in opened and str(other) not in opened
    assert str(path) not in json.dumps(result)


def test_source_server_identity_is_separate_and_late_loading_is_supported(identity, owned_source, monkeypatch):
    monkeypatch.delitem(sys.modules, 'app', raising=False)
    assert identity.current_identity('server')['server_app']['status'] == 'unavailable'
    path = owned_source / 'app.py'
    path.write_text('SERVER_SOURCE = 1\n')
    monkeypatch.setitem(sys.modules, 'app', SimpleNamespace(__file__=str(path)))
    server = identity.current_identity('server')
    assert server['server_app']['status'] == 'available'
    assert server['source'] == identity.current_identity('cli')['source']
    assert server['server_app']['sha256'] != server['source']['sha256']
    assert identity.current_identity()['server_app']['status'] == 'not_applicable'


@pytest.mark.parametrize('field', ['source', 'catalog', 'version'])
def test_public_identity_collision_withholds_without_mutating_cached_snapshot(identity, field):
    stamp = identity.current_identity()
    marker = {'source': stamp['source']['sha256'], 'catalog': stamp['catalogs']['baseline']['sha256'],
              'version': stamp['package_version']}[field]
    before = deepcopy(stamp)
    assert identity.public_identity(stamp, [marker.upper()]) is None
    assert stamp == before and identity.current_identity() == before


@pytest.mark.parametrize('mutation', [
    'extra-path', 'source-redacted', 'catalog-bool', 'source-status-list', 'component-list',
    'version-path', 'server-on-library', 'uppercase-hash', 'catalog-missing',
])
def test_invalid_producer_claims_never_become_current(identity, mutation):
    value = identity.current_identity()
    if mutation == 'extra-path':
        value['source']['path'] = '/private/never-publish.py'
    elif mutation == 'source-redacted':
        value['source']['sha256'] = '[redacted]'
    elif mutation == 'catalog-bool':
        value['catalogs']['baseline']['categories'] = True
    elif mutation == 'source-status-list':
        value['source']['status'] = ['available']
    elif mutation == 'component-list':
        value['component'] = ['library']
    elif mutation == 'version-path':
        value['package_version'] = '/private/operator-version'
    elif mutation == 'server-on-library':
        value['server_app'] = {'status': 'available', 'sha256': 'a' * 64}
    elif mutation == 'uppercase-hash':
        value['source']['sha256'] = 'A' * 64
    else:
        value['catalogs']['baseline'] = None
    assert identity.saved_identity(value) is None
    assert identity.public_identity(value) is None
    report = {'agents': [], 'status': 'completed', 'summary': {}, 'producer_identity': value}
    before = deepcopy(report)
    sarif = pipeline.to_sarif(report)
    assert sarif['runs'][0]['properties']['producer_identity'] is None
    assert sarif['runs'][0]['properties']['exporter_identity'] is None
    assert 'version' not in sarif['runs'][0]['tool']['driver']
    assert report == before


@pytest.mark.parametrize('kind', ['absent', 'explicit-null', 'valid-old'])
def test_historical_producer_and_current_exporter_are_distinct_without_rewriting(identity, kind):
    historical = {'agents': [], 'status': 'completed', 'summary': {}}
    if kind == 'explicit-null':
        historical['producer_identity'] = None
    elif kind == 'valid-old':
        stamp = identity.current_identity('cli')
        stamp['package_version'] = '0.7.2'
        stamp['source']['sha256'] = 'a' * 64
        historical['producer_identity'] = stamp
    before = deepcopy(historical)
    run = pipeline.to_sarif(historical)['runs'][0]
    expected = historical.get('producer_identity')
    assert run['properties']['producer_identity'] == expected
    assert run['properties']['exporter_identity'] == (None if kind == 'explicit-null' else identity.current_identity())
    if kind == 'valid-old':
        assert run['tool']['driver']['version'] == '0.7.2'
    else:
        assert 'version' not in run['tool']['driver']
    assert historical == before


@pytest.mark.asyncio
async def test_run_retains_the_pre_discovery_producer_across_later_identity_changes(identity, monkeypatch):
    first = identity.current_identity('cli')
    later = deepcopy(first)
    later['source']['sha256'] = 'b' * 64
    calls, checkpoints = [], []
    def capture(component):
        calls.append(component)
        return deepcopy(first)
    async def discover(scope):
        monkeypatch.setattr(pipeline, 'current_identity', lambda component: deepcopy(later))
        return [asset()]
    async def checkpoint(value):
        checkpoints.append(deepcopy(value))
    _, security, risk = engines([asset()])
    monkeypatch.setattr(pipeline, 'current_identity', capture)
    report = await pipeline.run_pipeline(SimpleNamespace(discover_agents=discover), security, risk, None,
                                         checkpoint_callback=checkpoint, producer_component='cli')
    assert calls == ['cli'] and len(checkpoints) >= 2
    assert all(value['producer_identity'] == first for value in checkpoints + [report])
    assert report['summary']['overall_risk_score'] == 90
    assert all('exporter_identity' not in value for value in checkpoints + [report])


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['source', 'catalog', 'version'])
async def test_redacted_producer_cannot_reappear_in_derived_formatters(identity, field):
    stamp = identity.current_identity()
    marker = {'source': stamp['source']['sha256'], 'catalog': stamp['catalogs']['baseline']['sha256'],
              'version': stamp['package_version']}[field]
    target = {**asset(), 'system_prompt_canary': marker}
    discovery, security, risk = engines([target])
    result = await pipeline.run_pipeline(discovery, security, risk, None)
    assert result['producer_identity'] is None
    sarif = pipeline.to_sarif(result)
    comprehensive = ReportGenerator().generate_comprehensive_report(scan_metadata=result)
    assert sarif['runs'][0]['properties']['exporter_identity'] is None
    assert comprehensive['exporter_identity'] is None
    assert marker.casefold() not in json.dumps([result, sarif, comprehensive]).casefold()


def test_authenticated_build_route_uses_no_database_queries(api, identity):
    module, client = api
    queries = []
    def observed(connection, cursor, statement, parameters, context, executemany):
        queries.append(statement)
    event.listen(module.db.engine, 'before_cursor_execute', observed)
    try:
        assert client.get('/api/build').status_code == 401
        response = client.get('/api/build', headers=headers(module))
    finally:
        event.remove(module.db.engine, 'before_cursor_execute', observed)
    assert response.status_code == 200 and response.json['success'] is True
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.json['build']['package_version'] == '1.2.0.dev0'
    assert queries == []


@pytest.mark.parametrize('producer', ['absent', None])
def test_raw_historical_json_download_preserves_original_stamp_presence(api, producer):
    module, client = api
    original = {'schema_version': '1.0', 'agents': [], 'summary': {}, 'status': 'completed'}
    if producer != 'absent':
        original['producer_identity'] = producer
    module.db.session.add(module.ScanSession(
        id='old-archive', organization_id='tenant-a', scan_name='Historical fixture',
        scan_type='discovery_only', status='completed', target_scope={}, scan_config={}))
    module.db.session.add(module.ScanResult(scan_id='old-archive', result=deepcopy(original)))
    module.db.session.commit()
    response = client.get('/api/scans/old-archive/report?format=json', headers=headers(module))
    assert response.status_code == 200 and response.json == original
    assert module.db.session.get(module.ScanResult, 'old-archive').result == original


@pytest.mark.parametrize('final', [False, True], ids=['checkpoint', 'final'])
@pytest.mark.parametrize('replacement', [True, 1.0], ids=['boolean', 'float'])
def test_checkpoint_producer_cannot_change_catalog_count_types(checkpoint_store, identity, final, replacement):
    producer = identity.current_identity()
    producer['package_version'] = '0.7.2'
    producer['catalogs']['baseline'].update(categories=1, payloads=1)
    assert identity.saved_identity(producer) == producer
    original = checkpoint_report()
    original['producer_identity'] = producer
    assert save_checkpoint(checkpoint_store, original)
    newer = deepcopy(original)
    if not final:
        newer['checkpoint']['sequence'] = 2
    newer['producer_identity']['catalogs']['baseline']['categories'] = replacement
    assert identity.saved_identity(newer['producer_identity']) is None
    assert not save_checkpoint(checkpoint_store, newer, final=final)
    retained = stored_result(checkpoint_store[0], 'checkpoint')
    assert retained['checkpoint']['sequence'] == 1
    assert type(retained['producer_identity']['catalogs']['baseline']['categories']) is int


@pytest.mark.parametrize('kind', ['old-valid', 'old-malformed'])
def test_unchanged_historical_producer_survives_extension_and_terminalization(checkpoint_store, identity, kind):
    producer = identity.current_identity()
    producer['package_version'] = '0.7.2'
    producer['catalogs']['baseline'].update(categories=1, payloads=1)
    if kind == 'old-malformed':
        producer = {'unrecognized_historical_claim': {'count': 1}}
    original = checkpoint_report()
    original['producer_identity'] = producer
    assert save_checkpoint(checkpoint_store, original)
    newer = deepcopy(original)
    newer['checkpoint']['sequence'] = 2
    assert save_checkpoint(checkpoint_store, newer)
    checkpoint_store[0].finish('checkpoint', 'Owned synthetic interruption', owner='worker')
    retained = stored_result(checkpoint_store[0], 'checkpoint')
    assert retained['producer_identity'] == producer
    assert retained['checkpoint']['sequence'] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('marker', ['producer_identity', 'EXPORTER_IDENTITY'])
@pytest.mark.parametrize('mode', ['full', 'discovery_only'])
async def test_new_identity_outer_key_collisions_refuse_before_checkpoint(identity, marker, mode):
    discovery, security, risk = engines([{**asset(), 'system_prompt_canary': marker}])
    checkpoints = []
    async def checkpoint(report):
        checkpoints.append(report)
    with pytest.raises(ValueError) as raised:
        await pipeline.run_pipeline(discovery, security, risk, None, mode, checkpoint_callback=checkpoint)
    assert not checkpoints
    assert marker.casefold() not in str(raised.value).casefold()


@pytest.mark.parametrize('marker', ['producer_identity', 'EXPORTER_IDENTITY'])
def test_known_private_formatter_key_collision_is_refused(identity, marker):
    from src.reporting.sarif_output import generate_sarif
    metadata = {'system_prompt_canary': marker}
    with pytest.raises(ValueError):
        generate_sarif([], metadata)
    with pytest.raises(ValueError):
        ReportGenerator().generate_comprehensive_report(scan_metadata=metadata)


@pytest.mark.parametrize('adapter', ['pipeline', 'mcp'])
@pytest.mark.parametrize('producer', ['absent', 'valid-old'])
@pytest.mark.parametrize('field', ['source', 'version'])
def test_sarif_adapter_retains_private_basis_from_omitted_historical_fields(identity, adapter, producer, field):
    current = identity.current_identity()
    marker = current['source']['sha256'] if field == 'source' else current['package_version']
    historical = {'status': 'completed', 'summary': {}, 'agents': [{
        'id': 'historical-asset', 'checks': [], 'vulnerabilities': [], 'metadata': {'api_key': marker}}]}
    if producer == 'valid-old':
        old = deepcopy(current)
        old['package_version'] = '0.7.2'
        old['source']['sha256'] = 'a' * 64
        historical['producer_identity'] = old
    if adapter == 'mcp':
        historical = {**historical, 'findings': [], 'observations': [], 'limitations': [],
                      'metadata': {'api_key': marker}}
    original = deepcopy(historical)
    if adapter == 'mcp':
        from src.mcp.assessment import to_sarif
        output = to_sarif(historical)
    else:
        output = pipeline.to_sarif(historical)
    assert output['runs'][0]['properties']['producer_identity'] == historical.get('producer_identity')
    assert output['runs'][0]['properties']['exporter_identity'] is None
    assert marker not in json.dumps(output)
    assert historical == original


@pytest.mark.parametrize('secret', ['null', 'true', 'false', '70', '35', '7', ':', '{'])
def test_json_syntax_and_numeric_values_do_not_redact_an_unchanged_identity(identity, secret):
    from src.core.redaction import redact_secrets
    stamp = identity.current_identity()
    stamp['package_version'] = '9.9.9'
    stamp['source']['sha256'] = 'c' * 64
    stamp['catalogs']['baseline']['sha256'] = 'c' * 64
    stamp['catalogs']['protected_disclosure']['sha256'] = 'c' * 64
    stamp['catalogs']['protected_disclosure']['pin'] = 'd' * 64
    assert identity.saved_identity(stamp) == stamp
    assert redact_secrets(stamp, {secret}) == stamp
    assert identity.public_identity(stamp, {secret}) == stamp
