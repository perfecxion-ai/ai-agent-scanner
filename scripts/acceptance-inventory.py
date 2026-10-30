#!/usr/bin/env python3
"""Exercise a disposable schema-4 upgrade and real local inventory server.

The 10,000 rows are repeated observations of 12 synthetic assets, not distinct
deployments. No operator database, configuration, cloud, or target is accepted.
"""

import argparse
import base64
import asyncio
from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parents[1]
OBSERVATIONS = 10000
FORMAT_VERSION = 'inventory-acceptance-v4'
TARGET_SCHEMA_VERSION = 8
ORGANIZATIONS = ('inventory-a', 'inventory-b', 'inventory-c')
CATEGORIES = ('high', 'zero', 'unknown', 'historical')
RISK_FIELDS = ('risk_score', 'risk_level', 'risk_coverage_status', 'risk_scoring_policy',
               'risk_assessment_status', 'security_status')
OPERATOR_INDEX = ('CREATE INDEX operator_inventory_fixture ON discovered_agent '
                  '(provider DESC) WHERE provider IS NOT NULL')
REQUIRED_ASSERTIONS = (
    'private_environment_and_owned_schema4_fixture',
    'genuine_controlled_access_high_zero_and_unassessed_sources',
    'native_schema4_to8_policy_reconciliation_generation_indexes_and_triggers',
    'complete_ordered_inventory_and_canonical_filters',
    'signed_cursor_tenant_tampering_and_invalid_limits',
    'committed_source_writes_invalidate_cursors',
    'rollback_and_other_tenant_writes_preserve_cursors',
    'owned_stale_caches_restored_with_original_archives_rows_and_operator_index',
    'restart_preserves_stale_caches_full_traversal_and_cursor_generation',
    'no_active_scans_schedules_or_admissions',
    'real_server_exits_and_process_groups_reaped',
    'required_secret_and_log_privacy_checks',
    'private_fixture_and_socket_cleanup',
    'snapshot_target_mismatches_withhold_risk_and_normalized_endpoint_restores_it',
    'duplicate_source_members_refused_without_archive_changes',
)


class GateFailure(RuntimeError):
    """Messages are fixed public codes, never raw exception text."""


def require(condition, code):
    if not condition:
        raise GateFailure(code)


def owned_database(directory):
    directory = Path(directory)
    require(directory.is_absolute() and directory.resolve() == directory and not directory.is_symlink()
            and directory.parent == Path(tempfile.gettempdir()).resolve()
            and directory.name.startswith('ai-scanner-inventory-')
            and directory.is_dir() and directory.stat().st_mode & 0o777 == 0o700,
            'unowned_fixture_directory')
    database = directory / 'fixture.sqlite'
    require(not database.is_symlink() and database.resolve() == database, 'unowned_fixture_database')
    return database


def fresh_environment(directory, values):
    """An allowlist excludes profiles, proxies, cloud credentials and Gunicorn args."""
    database = owned_database(directory)
    return {'PATH': os.defpath, 'HOME': str(directory), 'TMPDIR': str(directory),
            'PYTHONPATH': str(ROOT), 'PYTHONUTF8': '1', 'LC_ALL': 'C',
            'SECRET_KEY': values['signing'], 'OPERATOR_API_KEY': values['operator'],
            'OPERATOR_ORGANIZATION_ID': ORGANIZATIONS[0], 'DATABASE_URL': 'sqlite:///' + str(database),
            'FLASK_DEBUG': 'false', 'SCAN_ALLOWED_NETWORKS': '', 'SCAN_ALLOWED_PATH_ROOTS': '',
            'SCAN_ALLOW_LOOPBACK': 'false', 'MAX_CONCURRENT_SCANS': '1',
            'XDG_CONFIG_HOME': str(directory), 'XDG_CACHE_HOME': str(directory)}


def guard_engine(engine, database):
    require(engine.dialect.name == 'sqlite' and not engine.url.query
            and engine.url.database == str(database) and database.is_absolute()
            and not database.is_symlink() and database.resolve() == database,
            'engine_not_owned_fixture')


def connection(directory, *, write=False):
    database = owned_database(directory)
    require(database.is_file(), 'missing_fixture_database')
    return sqlite3.connect(database.as_uri() + ('?mode=rw' if write else '?mode=ro'), uri=True, timeout=2)


def archive(directory):
    """Compare every original row, including untouched JSON text and scalar caches."""
    with closing(connection(directory)) as database:
        require(database.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'sqlite_integrity_failed')
        names = [row[0] for row in database.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            if row[0] not in {'schema_version', 'inventory_generation', 'sqlite_sequence',
                              'asset_group_index', 'asset_group_publication'}]
        result = {}
        for name in names:
            require(re.fullmatch(r'[a-z_]+', name) is not None, 'unexpected_fixture_table')
            result[name] = sorted(database.execute('SELECT * FROM "' + name + '"').fetchall(), key=repr)  # nosec B608
        return result


def definitions(directory):
    with closing(connection(directory)) as database:
        return set(database.execute('SELECT type,name,tbl_name,sql FROM sqlite_master').fetchall())


def without_caches(directory, rows):
    result = dict(rows)
    with closing(connection(directory)) as database:
        for name, omitted in [('scan_session', {'overall_risk_score'}),
                              ('discovered_agent', {'risk_score', 'risk_level'})]:
            columns = [row[1] for row in database.execute('PRAGMA table_info("' + name + '")')]
            result[name] = [tuple(value for column, value in zip(columns, row, strict=True)
                                  if column not in omitted) for row in rows[name]]
    return result


def restore_stale_caches(directory, original):
    """Restore only the original deliberate cache contradictions in this fixture."""
    with closing(connection(directory, write=True)) as database, database:
        scans = [row[1] for row in database.execute('PRAGMA table_info(scan_session)')]
        observations = [row[1] for row in database.execute('PRAGMA table_info(discovered_agent)')]
        database.executemany('UPDATE scan_session SET overall_risk_score=? WHERE id=?', [
            (row[scans.index('overall_risk_score')], row[scans.index('id')]) for row in original['scan_session']])
        database.executemany('UPDATE discovered_agent SET risk_score=?,risk_level=? WHERE id=?', [
            (row[observations.index('risk_score')], row[observations.index('risk_level')], row[observations.index('id')])
            for row in original['discovered_agent']])


def verify_upgrade_and_restore(directory, original, original_definitions, expected):
    """Prove policy reconciliation before restoring stale caches for API traversal."""
    from src.core.inventory_generation import INDEX_DEFINITIONS, TRIGGER_DEFINITIONS
    from src.core.asset_group_storage import INDEX_DEFINITIONS as group_indexes, TRIGGER_DEFINITIONS as group_triggers
    upgraded = archive(directory)
    require(without_caches(directory, upgraded) == without_caches(directory, original),
            'upgrade_changed_noncache_rows_or_archived_json')
    current_definitions = definitions(directory)
    require(original_definitions <= current_definitions, 'upgrade_changed_original_definitions')
    allowed = set(INDEX_DEFINITIONS) | set(TRIGGER_DEFINITIONS) | set(group_indexes) | set(group_triggers) | {
        'inventory_generation', 'sqlite_autoindex_inventory_generation_1',
        'asset_group_index', 'asset_group_publication',
        'sqlite_autoindex_asset_group_index_1', 'sqlite_autoindex_asset_group_publication_1'}
    require({row[1] for row in current_definitions - original_definitions} == allowed,
            'upgrade_added_unexpected_definitions')
    expected_scans = {organization + '-' + category: descriptor(category)['risk_score']
                      for organization in ORGANIZATIONS for category in CATEGORIES}
    expected_observations = {row['id']: (row['risk_score'], row['risk_level'])
                             for rows in expected.values() for row in rows}
    require(len(expected_observations) == OBSERVATIONS, 'upgrade_expected_observation_count_changed')
    with closing(connection(directory)) as database:
        scans = dict(database.execute('SELECT id,overall_risk_score FROM scan_session'))
        observations = {row[0]: row[1:] for row in database.execute('SELECT id,risk_score,risk_level FROM discovered_agent')}
    require(scans == expected_scans, 'upgrade_scan_cache_mismatch')
    require(observations == expected_observations, 'upgrade_snapshot_cache_mismatch')
    # The seed deliberately uses 99/critical for every cache, so every row must
    # change during reconciliation before that contradiction is reintroduced.
    with closing(connection(directory)) as database:
        scan_columns = [row[1] for row in database.execute('PRAGMA table_info(scan_session)')]
        asset_columns = [row[1] for row in database.execute('PRAGMA table_info(discovered_agent)')]
    require(all(row[scan_columns.index('overall_risk_score')] == 99 for row in original['scan_session'])
            and all((row[asset_columns.index('risk_score')], row[asset_columns.index('risk_level')]) == (99, 'critical')
                    for row in original['discovered_agent']), 'original_stale_caches_missing')
    generations = check_schema(directory)
    restore_stale_caches(directory, original)
    require(archive(directory) == original, 'owned_stale_cache_restore_changed_original_rows')
    restored_generations = check_schema(directory)
    require(all(restored_generations[owner] != token for owner, token in generations.items()),
            'stale_cache_restore_did_not_invalidate_owned_generations')
    return {'scan_caches_reconciled': len(scans), 'observation_caches_reconciled': len(observations),
            'original_stale_scan_caches_restored': len(original['scan_session']),
            'original_stale_observation_caches_restored': len(original['discovered_agent'])}


def descriptor(category):
    if category in {'high', 'zero'}:
        high = category == 'high'
        return dict(zip(RISK_FIELDS, (70 if high else 0, 'high' if high else 'minimal',
                                     'partial' if high else 'sampled', 'severity-floor-v2',
                                     'partial' if high else 'completed', 'failed' if high else 'completed')))
    return dict(zip(RISK_FIELDS, (None, 'unknown', 'not_assessed', None, 'not_assessed',
                                 'not_tested' if category == 'unknown' else 'unknown')))


def produce(scan_id, category, values):
    """Run actual pipeline/access producers with a transport that never opens sockets."""
    from src.core.pipeline import run_pipeline
    from src.core.risk_projection import project_report_risk
    from src.risk.risk_assessor import RiskAssessment
    from src.security.security_engine import SecurityTestEngine
    from tests import controlled_access

    async def execute():
        asset_id = scan_id + '-asset'
        if category in {'unknown', 'historical'}:
            asset = {'id': asset_id, 'name': 'Unassessed fixture', 'type': 'assistant',
                     'provider': 'fixture', 'metadata': {}}
            discovery = SimpleNamespace(discover_agents=AsyncMock(return_value=[asset]))
            return await run_pipeline(discovery, None, None, None, 'discovery_only')
        security = SecurityTestEngine()
        security.prompt_tester.test_agent = AsyncMock(return_value=[])
        security.access_tester.test_agent = security.access_tester._test_authentication_bypass
        security.privacy_tester.test_agent = (AsyncMock(side_effect=RuntimeError('Synthetic later failure'))
                                             if category == 'high' else AsyncMock(return_value=[]))
        with patch.object(controlled_access, 'MARKER', values['marker']), \
                patch.object(controlled_access, 'ISSUED', values['issued']), \
                controlled_access.transport(disclose=category == 'high'):
            return await run_pipeline(None, security, RiskAssessment(), None, 'security_only',
                                      agents=[controlled_access.target(id=asset_id)])

    output = asyncio.run(execute())
    output['scan_id'] = scan_id
    if category == 'historical':
        output.pop('check_schema_version')
        output['agents'][0].update(risk_score=99, risk_level='critical', risk_scoring_policy='severity-floor-v2')
    mapping = project_report_risk(output)[1]
    from src.core.risk_projection import project_agent_risk
    require(mapping.get(scan_id + '-asset', project_agent_risk()) == descriptor(category),
            'controlled_source_verdict_changed')
    return output


def seed(directory, values):
    require('app' not in sys.modules, 'cached_app_before_fixture_import')
    sys.path.insert(0, str(ROOT))
    import app as server
    from tests.historical_schema import historical_metadata
    database = owned_database(directory)
    expected = {organization: [] for organization in ORGANIZATIONS}
    sources = {}
    with server.app.app_context():
        engine = server.db.engine
        guard_engine(engine, database)
        require(not server._evidence_profiles._profiles, 'inherited_evidence_profile')
        metadata = historical_metadata(version=4)
        try:
            metadata.create_all(engine)
            with engine.begin() as transaction:
                transaction.execute(metadata.tables['schema_version'].insert().values(id=1, version=4))
                for organization in ORGANIZATIONS:
                    for category in CATEGORIES:
                        scan_id = organization + '-' + category
                        output = produce(scan_id, category, values)
                        require(len(output['agents']) == 1, 'controlled_source_target_count_changed')
                        sources[scan_id] = output['agents'][0]
                        transaction.execute(metadata.tables['scan_session'].insert().values(
                            id=scan_id, organization_id=organization, scan_name='Synthetic ' + category,
                            scan_type=output['scan_type'], status=output['status'], target_scope={}, scan_config={},
                            agents_discovered=1, overall_risk_score=99))
                        transaction.execute(metadata.tables['scan_result'].insert().values(scan_id=scan_id, result=output))
                        transaction.execute(metadata.tables['scan_job'].insert().values(scan_id=scan_id, status='completed'))
                rows = []
                for index in range(OBSERVATIONS):
                    organization = ORGANIZATIONS[index // 4 % 3]
                    category = CATEGORIES[index % 4]
                    scan_id = organization + '-' + category
                    timestamp = datetime(2019, 1, 1) if index == 0 else datetime(2026, 1, 1) + timedelta(seconds=index // 7)
                    identifier = f'observation-{index:05}'
                    kind = 'assistant' if index % 2 == 0 else 'mcp'
                    source = sources[scan_id]
                    rows.append(dict(id=identifier, scan_id=scan_id, agent_name='Repeated fixture observation',
                                     agent_type=kind, provider=source.get('provider'), model_name=source.get('model'),
                                     endpoint_url=source.get('endpoint'),
                                     discovery_method='synthetic', metadata={'asset_id': scan_id + '-asset'},
                                     risk_score=99, risk_level='critical', discovered_at=timestamp))
                    expected[organization].append({'id': identifier, 'asset_id': scan_id + '-asset',
                                                  'name': 'Repeated fixture observation', 'provider': source.get('provider'),
                                                  'type': kind, 'discovered_at': timestamp.isoformat(), **descriptor(category)})
                transaction.execute(metadata.tables['discovered_agent'].insert(), rows)
                transaction.exec_driver_sql(OPERATOR_INDEX)
        finally:
            server.db.session.remove()
            engine.dispose()
    for rows in expected.values():
        rows.sort(key=lambda row: (-datetime.fromisoformat(row['discovered_at']).timestamp(), row['id']))
    require(database.stat().st_mode & 0o777 == 0o600, 'fixture_database_permissions')
    with closing(connection(directory)) as fixture:
        require(fixture.execute('SELECT version FROM schema_version WHERE id=1').fetchone() == (4,)
                and fixture.execute("SELECT count(*) FROM sqlite_master WHERE name='inventory_generation' OR type='trigger'")
                    .fetchone() == (0,), 'fixture_not_genuine_schema4')
    return expected


class Server:
    def __init__(self, directory, environment, listener, phase, deadline, values):
        self.directory, self.environment, self.listener = directory, environment, listener
        self.phase, self.deadline, self.process, self.log = phase, deadline, None, None
        self.base = 'http://127.0.0.1:' + str(listener.getsockname()[1])
        self.opener = build_opener(ProxyHandler({}))
        self.tokens = {}
        self.private_values = values
        self.http_checked = 0

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'overall_timeout')
        return remaining

    def start(self):
        self.log = open(self.directory / (self.phase + '.log'), 'xb')
        # Official Gunicorn bind documentation specifies fd://FD support since
        # 20.0: https://gunicorn.org/reference/settings/#bind
        command = [sys.executable, '-m', 'gunicorn', '--config', str(ROOT / 'gunicorn.conf.py'),
                   '--workers', '1', '--bind', 'fd://' + str(self.listener.fileno()), '--timeout', '20',
                   '--graceful-timeout', '5', '--worker-tmp-dir', str(self.directory), 'app:app']
        pending, handlers = [], {}
        try:
            # Defer raising during Popen's fork/exec-to-handle window. A signal
            # then cannot orphan a child before self.process owns its handle.
            # No blocked signal mask is inherited by the Gunicorn process.
            for selected_signal in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
                handlers[selected_signal] = signal.signal(selected_signal, lambda signum, frame: pending.append(signum))
            self.process = subprocess.Popen(command, cwd=ROOT, env=self.environment,
                                            stdout=self.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                            start_new_session=True, pass_fds=(self.listener.fileno(),))
        finally:
            for selected_signal, handler in handlers.items():
                signal.signal(selected_signal, handler)
        if pending:
            raise GateFailure('overall_timeout' if signal.SIGALRM in pending else 'driver_interrupted')
        startup = min(self.deadline, time.monotonic() + 20)
        while time.monotonic() < startup:
            require(self.process.poll() is None, 'server_startup_exit')
            try:
                status, value = self.request('/health/ready', timeout=0.2)
                if status == 200 and value.get('status') == 'ready':
                    return
            except (URLError, TimeoutError, OSError, json.JSONDecodeError):
                pass
            time.sleep(0.02)
        raise GateFailure('server_startup_timeout')

    def request(self, path, *, organization=None, payload=None, timeout=5):
        self.remaining()
        headers = {'Authorization': 'Bearer ' + self.tokens[organization]} if organization else {}
        data = json.dumps(payload).encode() if payload is not None else None
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = Request(self.base + path, data=data, headers=headers)
        try:
            response = self.opener.open(req, timeout=min(timeout, self.remaining()))
        except HTTPError as error:
            response = error
        with response:
            raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, 'response_byte_limit')
            require(response.headers.get('Cache-Control') == 'no-store' or path.startswith('/health'),
                    'response_cache_boundary')
            value = json.loads(raw)
            headers_raw = str(response.headers).encode('utf-8')
            if path == '/api/auth/token' and response.status == 200:
                require(isinstance(value, dict) and set(value) == {'success', 'token'}
                        and value['success'] is True and isinstance(value['token'], str), 'unexpected_auth_response')
                # Only this successful authentication token field is allowed to
                # carry a credential. Response headers and all other fields are swept.
                assert_private_absent(headers_raw, {**self.private_values, 'auth_token': value['token']},
                                      'private_value_in_http_response')
                assert_private_absent(json.dumps({'success': value['success']}).encode(), self.private_values,
                                      'private_value_in_http_response')
            else:
                decoded = json.dumps(value, ensure_ascii=False).encode('utf-8')
                assert_private_absent(raw + headers_raw + decoded, self.private_values, 'private_value_in_http_response')
            self.http_checked += 1
            return response.status, value

    def authenticate(self, values):
        status, value = self.request('/api/auth/token', payload={'api_key': values['operator']})
        require(status == 200 and isinstance(value.get('token'), str), 'operator_authentication_failed')
        self.tokens[ORGANIZATIONS[0]] = value['token']
        from src.utils.auth import create_jwt_token
        for organization in ORGANIZATIONS[1:]:
            self.tokens[organization] = create_jwt_token({'user_id': 'synthetic-driver', 'organization_id': organization},
                                                       values['signing'])

    def stop(self):
        process = self.process
        try:
            if process is None:
                return None
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                raise GateFailure('server_forced_kill') from None
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                os.killpg(process.pid, signal.SIGKILL)
                raise GateFailure('server_process_group_survived')
            return code
        finally:
            try:
                if process is not None:
                    try:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
            finally:
                if self.log is not None:
                    self.log.close()


def check_schema(directory):
    from src.core.inventory_generation import INDEX_DEFINITIONS, TRIGGER_DEFINITIONS
    from src.core.asset_group_storage import INDEX_DEFINITIONS as group_indexes, TRIGGER_DEFINITIONS as group_triggers
    from src.core.schema import SCHEMA_VERSION
    require(SCHEMA_VERSION == TARGET_SCHEMA_VERSION, 'schema_policy_target_changed')
    with closing(connection(directory)) as database:
        require(database.execute('SELECT version FROM schema_version WHERE id=1').fetchone() == (TARGET_SCHEMA_VERSION,),
                'schema_not_upgraded')
        require([row[1:] for row in database.execute('PRAGMA table_info(inventory_generation)')] == [
            ('organization_id', 'VARCHAR(64)', 1, None, 1), ('generation', 'VARCHAR(32)', 1, None, 0)],
            'generation_table_changed')
        require(dict(database.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'"))
                == dict(TRIGGER_DEFINITIONS, **group_triggers),
                'generation_triggers_changed')
        indexes = dict(database.execute("SELECT name,sql FROM sqlite_master WHERE type='index'"))
        require(all(indexes.get(name) == sql for name, sql in INDEX_DEFINITIONS.items()), 'candidate_indexes_changed')
        require(all(indexes.get(name) == sql for name, sql in group_indexes.items()), 'group_indexes_changed')
        require(indexes.get('operator_inventory_fixture') == OPERATOR_INDEX, 'operator_index_changed')
        tokens = dict(database.execute('SELECT organization_id,generation FROM inventory_generation'))
        require(set(tokens) == set(ORGANIZATIONS) and all(re.fullmatch('[0-9a-f]{32}', value) for value in tokens.values()),
                'invalid_generation_values')
        return tokens


def expected_rows(rows, filters):
    return [row for row in rows if (not filters.get('risk_level') or row['risk_level'] == filters['risk_level'])
            and (not filters.get('agent_type') or row['type'] == filters['agent_type'])]


def traversal(server, organization, expected, filters):
    actual, cursor, evaluated = [], None, 0
    while True:
        query = {'limit': 100, **filters, **({'cursor': cursor} if cursor else {})}
        status, value = server.request('/api/agents?' + urlencode(query), organization=organization)
        require(status == 200 and value.get('success') is True, 'inventory_page_failed')
        coverage = value['coverage']
        require(0 <= coverage['evaluated_candidates'] <= 500 and coverage['projected_reports'] <= 32
                and coverage['interpreted_source_bytes'] <= 16 * 1024 * 1024, 'page_work_budget_exceeded')
        cursor_next = value['next_cursor']
        require(coverage['search_complete'] == (cursor_next is None)
                and (cursor_next is None or coverage['evaluated_candidates'] > 0), 'cursor_progress_failed')
        require(len(value['agents']) <= 100, 'page_result_limit_exceeded')
        require(all(row['risk_score'] is None or type(row['risk_score']) in {int, float}
                    for row in value['agents']), 'non_numeric_canonical_score')
        actual.extend(value['agents'])
        evaluated += coverage['evaluated_candidates']
        require(evaluated <= len(expected), 'pagination_repeated_candidates')
        if cursor_next is None:
            break
        require(cursor_next != cursor, 'nonprogress_cursor')
        cursor = cursor_next
    require(actual == expected_rows(expected, filters), 'inventory_order_or_canonical_verdict_mismatch')
    return len(actual)


def traverse_all(server, expected):
    counts = {}
    for organization in ORGANIZATIONS:
        for name, filters in (('all', {}), ('high', {'risk_level': 'high'}),
                              ('minimal', {'risk_level': 'minimal'}), ('critical', {'risk_level': 'critical'}),
                              ('unknown', {'risk_level': 'unknown'}), ('type', {'agent_type': 'assistant'}),
                              ('type_high', {'agent_type': 'assistant', 'risk_level': 'high'}),
                              ('type_high_empty', {'agent_type': 'mcp', 'risk_level': 'high'})):
            counts[organization + ':' + name] = traversal(server, organization, expected[organization], filters)
    return counts


def cursor_checks(server, directory):
    organization = ORGANIZATIONS[0]
    status, value = server.request('/api/agents?limit=1', organization=organization)
    require(status == 200 and value['next_cursor'], 'missing_test_cursor')
    cursor = value['next_cursor']
    path = '/api/agents?' + urlencode({'limit': 1, 'cursor': cursor})
    require(server.request(path, organization=ORGANIZATIONS[1])[0] == 400, 'cross_tenant_cursor_accepted')
    for query in ({'limit': 2, 'cursor': cursor}, {'limit': 1, 'cursor': cursor + 'x'},
                  {'limit': 101}, {'cursor': ''}, {'risk_level': 'invalid'}):
        require(server.request('/api/agents?' + urlencode(query), organization=organization)[0] == 400,
                'invalid_pagination_accepted')
    require(server.request('/api/scans/' + ORGANIZATIONS[1] + '-high/results', organization=organization)[0] == 404,
            'cross_tenant_scan_exposed')
    for statement, parameters in (
            ('UPDATE discovered_agent SET agent_name=agent_name WHERE id=?', ('observation-00000',)),
            ('UPDATE scan_result SET result=result WHERE scan_id=?', (organization + '-high',))):
        with closing(connection(directory, write=True)) as database, database:
            database.execute(statement, parameters)
        require(server.request(path, organization=organization)[0] == 409, 'committed_source_did_not_invalidate')
        status, value = server.request('/api/agents?limit=1', organization=organization)
        require(status == 200 and value['next_cursor'], 'missing_replacement_cursor')
        cursor = value['next_cursor']
        path = '/api/agents?' + urlencode({'limit': 1, 'cursor': cursor})
    with closing(connection(directory, write=True)) as database, database:
        database.execute('UPDATE scan_session SET organization_id=? WHERE id=?',
                         (ORGANIZATIONS[1], organization + '-high'))
    require(server.request(path, organization=organization)[0] == 409, 'ownership_move_did_not_invalidate')
    with closing(connection(directory, write=True)) as database, database:
        database.execute('UPDATE scan_session SET organization_id=? WHERE id=?', (organization, organization + '-high'))
    status, value = server.request('/api/agents?limit=1', organization=organization)
    require(status == 200 and value['next_cursor'], 'missing_restored_cursor')
    path = '/api/agents?' + urlencode({'limit': 1, 'cursor': value['next_cursor']})
    with closing(connection(directory, write=True)) as database:
        database.execute('BEGIN')
        database.execute('UPDATE discovered_agent SET agent_name=agent_name WHERE id=?', ('observation-00000',))
        database.rollback()
    require(server.request(path, organization=organization)[0] == 200, 'rollback_invalidated_cursor')
    with closing(connection(directory, write=True)) as database, database:
        database.execute('UPDATE discovered_agent SET agent_name=agent_name WHERE id=?', ('observation-00004',))
    require(server.request(path, organization=organization)[0] == 200, 'other_tenant_invalidated_cursor')
    return path


def source_binding_checks(server, directory, expected):
    """Changing a snapshot selector cannot borrow its alias's confirmed risk."""
    owner = ORGANIZATIONS[0]
    target = expected[owner][0]
    require(target['risk_level'] == 'high', 'binding_control_not_latest_high')
    identifier = target['id']
    with closing(connection(directory)) as database:
        source = database.execute('SELECT scan_id,provider,model_name,endpoint_url FROM discovered_agent WHERE id=?',
                                  (identifier,)).fetchone()
    require(source is not None and all(isinstance(value, str) for value in source),
            'binding_control_missing_target_selectors')
    scan_id, provider, model, endpoint = source

    def first(filters=None):
        status, value = server.request('/api/agents?' + urlencode({'limit': 1, **(filters or {})}),
                                       organization=owner)
        require(status == 200 and value.get('success') is True and len(value.get('agents', [])) == 1,
                'binding_control_page_failed')
        return value['agents'][0]

    def verdict(row, wanted):
        require(row['id'] == identifier and all(row.get(key) == value for key, value in wanted.items()),
                'binding_control_verdict_mismatch')

    verdict(first(), descriptor('high'))
    try:
        for statement, value in (
                ('UPDATE discovered_agent SET provider=? WHERE id=?', 'mismatched-provider'),
                ('UPDATE discovered_agent SET model_name=? WHERE id=?', 'mismatched-model'),
                ('UPDATE discovered_agent SET endpoint_url=? WHERE id=?', 'http://192.0.2.1/different-resource')):
            with closing(connection(directory, write=True)) as database, database:
                database.execute(statement, (value, identifier))
            verdict(first(), descriptor('historical'))
            verdict(first({'risk_level': 'unknown'}), descriptor('historical'))
            require(first({'risk_level': 'high'})['id'] != identifier, 'mismatched_target_retained_high')
            with closing(connection(directory, write=True)) as database, database:
                database.execute('UPDATE discovered_agent SET provider=?,model_name=?,endpoint_url=? WHERE id=?',
                                 (provider, model, endpoint, identifier))
            verdict(first(), descriptor('high'))
        require(endpoint == 'http://192.0.2.1/resource', 'binding_control_endpoint_changed')
        with closing(connection(directory, write=True)) as database, database:
            database.execute('UPDATE discovered_agent SET endpoint_url=? WHERE id=?',
                             ('http://192.0.2.1:80/resource', identifier))
        verdict(first(), descriptor('high'))
    finally:
        with closing(connection(directory, write=True)) as database, database:
            database.execute('UPDATE discovered_agent SET provider=?,model_name=?,endpoint_url=? WHERE id=?',
                             (provider, model, endpoint, identifier))
    assertions = [REQUIRED_ASSERTIONS[13]]
    with closing(connection(directory)) as database:
        original = database.execute('SELECT result FROM scan_result WHERE scan_id=?', (scan_id,)).fetchone()[0]
    require(isinstance(original, str) and original.startswith('{') and json.loads(original)['schema_version'] == '1.0',
            'binding_control_archive_shape_changed')
    try:
        with closing(connection(directory, write=True)) as database, database:
            database.execute('UPDATE scan_result SET result=? WHERE scan_id=?',
                             ('{"schema_version":"1.0",' + original[1:], scan_id))
        for filters in ({}, {'risk_level': 'critical'}):
            status, value = server.request('/api/agents?' + urlencode({'limit': 1, **filters}), organization=owner)
            require(status == 503 and value.get('code') == 'inventory_projection_unavailable',
                    'duplicate_source_member_accepted')
    finally:
        with closing(connection(directory, write=True)) as database, database:
            database.execute('UPDATE scan_result SET result=? WHERE scan_id=?', (original, scan_id))
    verdict(first(), descriptor('high'))
    assertions.append(REQUIRED_ASSERTIONS[14])
    return assertions


def no_work(directory):
    with closing(connection(directory)) as database:
        require(database.execute("SELECT count(*) FROM scan_job WHERE status!='completed'").fetchone() == (0,),
                'active_scan_found')
        for table in ('audit_event', 'scan_schedule', 'scan_occurrence', 'scan_template'):
            require(database.execute('SELECT count(*) FROM ' + table).fetchone() == (0,), 'unexpected_scan_or_schedule_work')  # nosec B608


def assert_private_absent(data, values, code):
    folded = data.lower()
    for value in values.values():
        require(isinstance(value, str) and len(value) >= 20, 'missing_required_secret_check')
        variants = {value, quote(value, safe=''), json.dumps(value)[1:-1],
                    base64.b64encode(value.encode()).decode(), base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')}
        require(all(variant.encode().lower() not in folded for variant in variants), code)


def privacy_check(surfaces, values, output):
    require(set(values) == {'signing', 'operator', 'marker', 'issued', 'jwt0', 'jwt1', 'jwt2'}
            and all(isinstance(value, str) and len(value) >= 20 for value in values.values())
            and len(set(values.values())) == len(values), 'missing_required_secret_check')
    require(len(surfaces) >= 5 and all(path.is_file() and not path.is_symlink()
                                     and path.stat().st_mode & 0o777 == 0o600 for path in surfaces),
            'missing_privacy_surface')
    for path in surfaces:
        try:
            data = path.read_bytes()
        except OSError:
            raise GateFailure('unreadable_privacy_surface') from None
        assert_private_absent(data, values, 'private_value_in_log_or_fixture')
    assert_private_absent(output, values, 'private_value_in_stdout')


def runtime_identity():
    import gunicorn
    from src.core.inventory import PROJECTION_POLICY
    revision = subprocess.run(['git', '--no-optional-locks', 'rev-parse', 'HEAD'], cwd=ROOT,
                               capture_output=True, timeout=5, check=False)
    require(revision.returncode == 0 and re.fullmatch(rb'[0-9a-f]{40}\n?', revision.stdout), 'revision_unavailable')
    modified = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                               'status', '--porcelain', '--untracked-files=no'], cwd=ROOT,
                               capture_output=True, timeout=5, check=False)
    require(modified.returncode == 0, 'worktree_identity_unavailable')
    return {'python': sys.version.split()[0], 'sqlite': sqlite3.sqlite_version, 'gunicorn': gunicorn.__version__,
            'source_revision': revision.stdout.decode().strip(), 'projection_policy': PROJECTION_POLICY,
            'tracked_source_modified': bool(modified.stdout),
            'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'app_sha256': hashlib.sha256((ROOT / 'app.py').read_bytes()).hexdigest(),
            'gunicorn_hooks_sha256': hashlib.sha256((ROOT / 'gunicorn.conf.py').read_bytes()).hexdigest()}


def execute(directory, environment, listener, values, output, deadline):
    original = archive(directory)
    original_definitions = definitions(directory)
    expected = output.pop('_expected')
    output['assertions'].extend(REQUIRED_ASSERTIONS[:2])
    first = Server(directory, environment, listener, 'initial', deadline, values)
    try:
        first.start()
        first.authenticate(values)
        values.update({'jwt' + str(index): first.tokens[organization] for index, organization in enumerate(ORGANIZATIONS)})
        check_schema(directory)
        output['cache_policy_upgrade'] = verify_upgrade_and_restore(directory, original, original_definitions, expected)
        output['schema_after'] = TARGET_SCHEMA_VERSION
        output['assertions'].append(REQUIRED_ASSERTIONS[2])
        counts = traverse_all(first, expected)
        output['traversal_counts'] = counts
        output['assertions'].append(REQUIRED_ASSERTIONS[3])
        output['_binding_assertions'] = source_binding_checks(first, directory, expected)
        restart_cursor = cursor_checks(first, directory)
        output['assertions'].extend(REQUIRED_ASSERTIONS[4:7])
        require(archive(directory) == original, 'original_rows_or_archived_json_changed')
        output['assertions'].append(REQUIRED_ASSERTIONS[7])
        generations = check_schema(directory)
    finally:
        try:
            code = first.stop()
        finally:
            output['server_exits'].append({'phase': 'initial',
                                           'returncode': first.process.returncode if first.process else None})
        require(code == 0, 'initial_server_exit_nonzero')
    second = Server(directory, environment, listener, 'restart', deadline, values)
    try:
        second.start()
        second.tokens = first.tokens.copy()
        require(second.request(restart_cursor, organization=ORGANIZATIONS[0])[0] == 200,
                'restart_invalidated_unchanged_cursor')
        require(traverse_all(second, expected) == counts and check_schema(directory) == generations,
                'restart_inventory_or_generation_changed')
        output['assertions'].append(REQUIRED_ASSERTIONS[8])
        require(archive(directory) == original, 'restart_changed_archives_or_rows')
        no_work(directory)
        output['assertions'].append(REQUIRED_ASSERTIONS[9])
    finally:
        try:
            code = second.stop()
        finally:
            output['server_exits'].append({'phase': 'restart',
                                           'returncode': second.process.returncode if second.process else None})
        require(code == 0, 'restart_server_exit_nonzero')
    for phase in ('initial', 'restart'):
        log = (directory / (phase + '.log')).read_bytes()
        require(log.count(b'Booting worker with pid:') == 1, 'server_worker_count_changed')
    output['assertions'].append(REQUIRED_ASSERTIONS[10])
    output['http_responses_checked'] = first.http_checked + second.http_checked


def timeout_value(value):
    number = float(value)
    if not math.isfinite(number) or not 5 <= number <= 300:
        raise argparse.ArgumentTypeError('Expected finite timeout 5..300 seconds')
    return number


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise GateFailure('invalid_arguments')


def main(argv=None):
    parser = SafeParser(prog='acceptance-inventory.py', description=__doc__)
    parser.add_argument('--timeout-seconds', type=timeout_value, default=120)
    output = {'format_version': FORMAT_VERSION, 'accepted': False, 'observation_count': OBSERVATIONS,
              'fixture_scope': 'repeated_observations_of_12_synthetic_assets',
              'schema_before': None, 'schema_after': None, 'schema_target': TARGET_SCHEMA_VERSION,
              'assertions': [], 'server_exits': []}
    failures, values = [], {}
    temporary, directory, listener, previous_mask = None, None, None, None
    previous_handlers = {}
    try:
        args = parser.parse_args(argv)
        require(os.name == 'posix', 'posix_required')
        require(importlib.util.find_spec('gunicorn') is not None, 'server_extra_missing_install_project_server_extra')
        require('app' not in sys.modules, 'cached_app_before_fixture_import')
        previous_mask = os.umask(0o077)
        temporary = tempfile.TemporaryDirectory(prefix='ai-scanner-inventory-')
        directory = Path(temporary.name).resolve(strict=True)
        values = {name: secrets.token_hex(32) for name in ('signing', 'operator', 'marker', 'issued')}
        environment = fresh_environment(directory, values)
        deadline = time.monotonic() + args.timeout_seconds
        def expired(signum, frame):
            raise GateFailure('overall_timeout' if signum == signal.SIGALRM else 'driver_interrupted')
        for selected_signal in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            previous_handlers[selected_signal] = signal.signal(selected_signal, expired)
        signal.setitimer(signal.ITIMER_REAL, args.timeout_seconds)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(128)
        require(listener.getsockname()[0] == '127.0.0.1', 'listener_not_loopback')
        with open(directory / 'driver.log', 'x', encoding='utf-8') as driver_log, \
                redirect_stdout(driver_log), redirect_stderr(driver_log), patch.dict(os.environ, environment, clear=True):
            output['_expected'] = seed(directory, values)
            output['schema_before'] = 4
            output['runtime'] = runtime_identity()
            execute(directory, environment, listener, values, output, deadline)
    except (Exception, KeyboardInterrupt) as error:
        failures.append(str(error) if isinstance(error, GateFailure) else 'unexpected_driver_failure')
    finally:
        output.pop('_expected', None)
        if previous_handlers:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
            except Exception:
                failures.append('signal_cleanup_failed')
        for selected_signal, previous_handler in previous_handlers.items():
            try:
                signal.signal(selected_signal, previous_handler)
            except Exception:
                failures.append('signal_cleanup_failed')
        if listener is not None:
            try:
                listener.close()
            except Exception:
                failures.append('socket_cleanup_failed')
        if temporary is not None:
            try:
                surfaces = [directory / (phase + '.log') for phase in ('driver', 'initial', 'restart')]
                require(owned_database(directory).is_file() and directory.stat().st_mode & 0o777 == 0o700,
                        'fixture_permissions_changed')
                require((directory / 'fixture.sqlite.dispatcher.lock').is_file(), 'missing_dispatcher_lock')
                surfaces.extend(path for path in directory.iterdir() if path.name.startswith('fixture.sqlite'))
                privacy_check(surfaces, values, json.dumps(output, sort_keys=True).encode())
                output['assertions'].append(REQUIRED_ASSERTIONS[11])
                output['privacy'] = {'required_values_checked': len(values), 'surfaces_checked': len(surfaces)}
            except Exception as error:
                failures.append(str(error) if isinstance(error, GateFailure) else 'privacy_check_failed')
            try:
                temporary.cleanup()
                require(not directory.exists() and (listener is None or listener.fileno() == -1), 'fixture_cleanup_failed')
                output['assertions'].append(REQUIRED_ASSERTIONS[12])
            except Exception:
                failures.append('fixture_cleanup_failed')
        if previous_mask is not None:
            try:
                os.umask(previous_mask)
            except Exception:
                failures.append('permission_mask_cleanup_failed')
    output['assertions'].extend(output.pop('_binding_assertions', []))
    if not failures and output['assertions'] != list(REQUIRED_ASSERTIONS):
        failures.append('missing_required_assertions')
    output['accepted'] = not failures
    if failures:
        output['failure_codes'] = failures
        if 'server_extra_missing_install_project_server_extra' in failures:
            output['hint'] = 'Install the server extra: pip install -e ".[server]"'
    raw = json.dumps(output, sort_keys=True)
    if any(value and value.casefold() in raw.casefold() for value in values.values()):
        output = {'format_version': FORMAT_VERSION, 'accepted': False, 'failure_codes': ['stdout_privacy_failed']}
    print(json.dumps(output, sort_keys=True))
    return 0 if output['accepted'] else (2 if 'invalid_arguments' in failures else 1)


if __name__ == '__main__':
    raise SystemExit(main())
