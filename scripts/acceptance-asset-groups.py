#!/usr/bin/env python3
"""Check owned schema-6 upgrade and conservative groups through a real server.

The 10,000 rows are repeated synthetic observations, not distinct deployments.
Controlled pipeline fixtures do not open target sockets. No operator paths or
configuration are accepted. This is a correctness gate, not detector sensitivity.
"""

import asyncio
from contextlib import closing, redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sys
import tempfile
import time
from types import SimpleNamespace
from urllib.parse import urlencode
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('asset_group_inventory_helpers', ROOT / 'scripts/acceptance-inventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
GateFailure, require = inventory.GateFailure, inventory.require
FORMAT_VERSION = 'asset-group-acceptance-v1'
OBSERVATIONS = 10000
ORGANIZATIONS = inventory.ORGANIZATIONS
CATEGORIES = ('high', 'unscored', 'zero', 'unknown', 'model', 'context', 'endpoint', 'redacted', 'ambiguous')
REQUIRED_ASSERTIONS = (
    'private_environment_and_owned_schema6_fixture',
    'genuine_pipeline_sources_with_scoped_and_unmergeable_targets',
    'schema6_to7_preserves_source_rows_caches_archives_and_definitions',
    'exhaustive_group_and_history_pagination_with_latest_risk_separate',
    'signed_cursor_ownership_group_limit_and_tampering',
    'rollback_and_other_organization_preserve_cursor',
    'committed_source_write_invalidates_cursor',
    'uninterpretable_source_blocks_groups_without_hiding_inventory',
    'exact_source_restore_rebuilds_complete_publication',
    'restart_preserves_publication_generation_and_complete_views',
    'no_active_scans_schedules_or_admissions',
    'real_server_exits_and_process_groups_reaped',
    'known_value_and_log_privacy_checks',
    'private_fixture_and_socket_cleanup',
)


def produce(category, values):
    """Bind public identity before execution; never rewrite produced evidence."""
    from src.core.pipeline import run_pipeline
    from src.core.risk_projection import project_report_risk
    from src.risk.risk_assessor import RiskAssessment
    from src.security.security_engine import SecurityTestEngine
    from tests import controlled_access

    async def execute():
        agent = controlled_access.target(id='source-' + category, protected_response_marker=values['marker'],
                                         protected_path_markers={'/admin': values['marker']})
        agent['name'] = 'Owned group source ' + category
        if category == 'model':
            agent['model'] = 'distinct-owned-model'
        elif category == 'context':
            agent['evidence_context_id'] = 'distinct-owned-context'
        elif category == 'endpoint':
            agent['endpoint'] += '/distinct'
        elif category == 'redacted':
            agent['endpoint_redacted'] = True
        if category not in {'high', 'unscored', 'zero', 'unknown'}:
            discovery = SimpleNamespace(discover_agents=AsyncMock(return_value=[agent]))
            return await run_pipeline(discovery, None, None, None, 'discovery_only')
        security = SecurityTestEngine()
        security.prompt_tester.test_agent = AsyncMock(return_value=[])
        security.access_tester.test_agent = security.access_tester._test_authentication_bypass
        security.privacy_tester.test_agent = AsyncMock(return_value=[])
        risk = (SimpleNamespace(assess_risks=AsyncMock(side_effect=RuntimeError('Owned risk phase failed')))
                if category == 'unscored' else RiskAssessment())
        reply_marker = 'Owned unseeded response' if category == 'unknown' else values['marker']
        with patch.object(controlled_access, 'MARKER', reply_marker), \
                patch.object(controlled_access, 'ISSUED', values['issued']), \
                controlled_access.transport(disclose=category != 'zero'):
            return await run_pipeline(None, security, risk, None, 'security_only', agents=[agent])

    report = asyncio.run(execute())
    risk = project_report_risk(report)[1]['source-' + category]
    require(type(risk['risk_score']) in {int, float} and risk['risk_score'] == (0 if category == 'zero' else 70)
            if category in {'high', 'zero'} else risk['risk_score'] is None, 'source_verdict_changed')
    require(len(report['agents']) == 1, 'source_asset_count_changed')
    if category == 'unscored':
        require(len(report['agents'][0]['vulnerabilities']) > 0, 'unscored_confirmation_missing')
    return report


def sources(directory, *, names=None):
    """Save all original rows and raw JSON strings, including contradictory caches."""
    with closing(inventory.connection(directory)) as database:
        if names is None:
            names = [row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")
                     if row[0] not in {'schema_version', 'sqlite_sequence', 'asset_group_index', 'asset_group_publication'}]
        return {name: sorted(database.execute('SELECT * FROM "' + name + '"').fetchall(), key=repr)  # nosec B608
                for name in names}


def seed(directory, values):
    require('app' not in sys.modules, 'cached_app_before_fixture_import')
    sys.path.insert(0, str(ROOT))
    import app as server
    from tests.historical_schema import historical_metadata
    reports = {category: produce(category, values) for category in CATEGORIES}
    expected = {organization: {} for organization in ORGANIZATIONS}
    with server.app.app_context():
        engine = server.db.engine
        inventory.guard_engine(engine, inventory.owned_database(directory))
        require(not server._evidence_profiles._profiles, 'inherited_evidence_profile')
        metadata = historical_metadata(version=6)
        try:
            metadata.create_all(engine)
            with engine.begin() as transaction:
                transaction.execute(metadata.tables['schema_version'].insert().values(id=1, version=6))
                for organization in ORGANIZATIONS:
                    for category, report in reports.items():
                        scan_id = organization + '-' + category
                        transaction.execute(metadata.tables['scan_session'].insert().values(
                            id=scan_id, organization_id=organization, scan_name='Owned group fixture',
                            scan_type=report['scan_type'], status=report['status'], target_scope={}, scan_config={},
                            agents_discovered=1, overall_risk_score=99))
                        transaction.execute(metadata.tables['scan_result'].insert().values(scan_id=scan_id, result=report))
                        transaction.execute(metadata.tables['scan_job'].insert().values(scan_id=scan_id, status='completed'))
                rows = []
                for index in range(OBSERVATIONS):
                    organization = ORGANIZATIONS[index % 3]
                    category = (CATEGORIES[index // 3] if index < 27 else
                                'redacted' if index < 30 else 'ambiguous' if index < 33 else
                                'zero' if index % 3 == 2 else 'unknown')
                    asset = reports[category]['agents'][0]
                    timestamp = datetime(2026, 1, 1) + timedelta(seconds=index // 3)
                    identifier, scan_id = f'group-observation-{index:05}', organization + '-' + category
                    row = dict(id=identifier, scan_id=scan_id, agent_name=asset['name'], agent_type=asset['type'],
                               provider=asset.get('provider'), model_name=asset.get('model'),
                               endpoint_url=asset.get('endpoint'), discovery_method='owned-controlled-pipeline',
                               metadata={'asset_id': None if category == 'ambiguous' else asset['id']},
                               risk_score=99, risk_level='critical', discovered_at=timestamp)
                    rows.append(row)
                    expected[organization][identifier] = {
                        'category': category, 'asset': deepcopy(asset), 'report': reports[category],
                        'scan_id': scan_id, 'discovered_at': timestamp.isoformat()}
                transaction.execute(metadata.tables['discovered_agent'].insert(), rows)
                transaction.exec_driver_sql(inventory.OPERATOR_INDEX)
        finally:
            server.db.session.remove()
            engine.dispose()
    with closing(inventory.connection(directory)) as database:
        require(database.execute('SELECT version FROM schema_version WHERE id=1').fetchone() == (6,),
                'fixture_not_schema6')
        require(database.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE 'asset_group_%'").fetchone() == (0,),
                'fixture_contains_new_group_storage')
    return expected


def wait_ready(server, organization):
    while True:
        status, value = server.request('/api/asset-groups?limit=100', organization=organization)
        if status == 200:
            require(value.get('success') is True, 'group_success_missing')
            return value
        require(status == 503 and value.get('code') == 'asset_group_projection_unavailable', 'unexpected_group_readiness')
        server.remaining()
        time.sleep(0.2)


def page_all(server, organization, path, field):
    values, visited, cursor, complete = [], set(), None, False
    while not complete:
        query = {'limit': 2 if field == 'asset_groups' else 100}
        if cursor:
            query['cursor'] = cursor
        status, page = server.request(path + '?' + urlencode(query), organization=organization)
        require(status == 200 and page.get('success') is True and type(page.get(field)) is list, 'page_failed')
        coverage = page.get('coverage', {})
        require(type(coverage.get('search_complete')) is bool, 'missing_completion_fact')
        complete, next_cursor = coverage['search_complete'], page.get('next_cursor')
        require((complete and next_cursor is None) or (not complete and type(next_cursor) is str
                and next_cursor and next_cursor not in visited), 'nonadvancing_or_false_completion')
        if next_cursor:
            visited.add(next_cursor)
        values.extend(page[field])
        cursor = next_cursor
    return values


def verify_views(server, expected):
    from src.core.risk_projection import project_agent_risk, project_report_risk
    reports = {id(row['report']): row['report'] for rows in expected.values() for row in rows.values()}
    risks = {key: project_report_risk(report)[1] for key, report in reports.items()}
    counts, all_group_ids = {}, set()
    for organization in ORGANIZATIONS:
        wait_ready(server, organization)
        groups = page_all(server, organization, '/api/asset-groups', 'asset_groups')
        require(len({group['id'] for group in groups}) == len(groups), 'duplicate_group')
        require(all_group_ids.isdisjoint(group['id'] for group in groups), 'cross_owner_group_identity')
        all_group_ids.update(group['id'] for group in groups)
        group_order = [(-datetime.fromisoformat(group['latest_observation']['discovered_at']).timestamp(), group['id'])
                       for group in groups]
        require(group_order == sorted(group_order), 'group_order_changed')
        observed = []
        main = None
        view_records = []
        for group in groups:
            require(set(group) == {'id', 'identity_status', 'unmerged_reason', 'target', 'latest_observation',
                                  'latest_observation_risk', 'observation_count', 'confirmation_history'}, 'invented_group_risk')
            history = page_all(server, organization, group['confirmation_history']['url'], 'history')
            keys = [(item['observation_id'], item['finding_ordinal']) for item in history]
            require(len(set(keys)) == len(keys), 'duplicate_history_occurrence')
            ids = set(item['observation_id'] for item in history)
            require(ids <= expected[organization].keys(), 'cross_organization_history')
            observed.extend(ids)
            expected_history = []
            for identifier in ids:
                row = expected[organization][identifier]
                alias = None if row['category'] == 'ambiguous' else row['asset']['id']
                risk = (project_agent_risk() if alias is None else
                        risks[id(row['report'])][alias])
                base = {'observation_id': identifier, 'asset_id': alias, 'scan_id': row['scan_id'],
                        'discovered_at': row['discovered_at'], 'remediation_status': 'not_evaluated'}
                claims = row['asset'].get('vulnerabilities', []) if alias is not None else []
                if claims:
                    expected_history.extend({**base, 'finding_ordinal': ordinal, 'finding_id': finding['id'],
                                             'classification': 'supported_confirmation', 'severity': finding['severity'],
                                             'rule_id': finding['rule_id']} for ordinal, finding in enumerate(claims))
                else:
                    expected_history.append({**base, 'finding_ordinal': 0, 'finding_id': None, 'classification': 'observation',
                                             'severity': None, 'rule_id': None, 'observation_risk': risk})
            expected_history.sort(key=lambda item: (-datetime.fromisoformat(item['discovered_at']).timestamp(),
                                                    item['observation_id'], item['finding_ordinal']))
            require(json.dumps(history, sort_keys=True, allow_nan=False)
                    == json.dumps(expected_history, sort_keys=True, allow_nan=False), 'history_occurrences_changed')
            latest = min(ids, key=lambda identifier: (-datetime.fromisoformat(
                expected[organization][identifier]['discovered_at']).timestamp(), identifier))
            row = expected[organization][latest]
            canonical = (project_agent_risk() if row['category'] == 'ambiguous' else
                         risks[id(row['report'])][row['asset']['id']])
            require(group['latest_observation'] == {'id': latest,
                    'asset_id': None if row['category'] == 'ambiguous' else row['asset']['id'],
                    'scan_id': row['scan_id'], 'name': row['asset']['name'], 'type': row['asset']['type'],
                    'provider': row['asset']['provider'], 'discovered_at': row['discovered_at'],
                    'security_status': canonical['security_status']}, 'incorrect_latest_observation')
            require(json.dumps(group['latest_observation_risk'], sort_keys=True, allow_nan=False)
                    == json.dumps(canonical, sort_keys=True, allow_nan=False), 'latest_risk_not_canonical')
            require(group['observation_count'] == len(ids), 'incorrect_group_observation_count')
            require(group['confirmation_history']['remediation_status'] == 'not_evaluated', 'invented_remediation')
            require(all(item.get('remediation_status') == 'not_evaluated' for item in history), 'history_invented_remediation')
            categories = {expected[organization][identifier]['category'] for identifier in ids}
            if categories & {'high', 'zero', 'unscored', 'unknown'}:
                require(categories == {'high', 'zero', 'unscored', 'unknown'}, 'target_scope_split')
                supported = [item for item in history if item['classification'] == 'supported_confirmation']
                require(supported and any(expected[organization][item['observation_id']]['category'] == 'unscored'
                                          for item in supported), 'unscored_eligible_confirmation_lost')
                require(group['latest_observation_risk']['risk_score'] == (0 if organization == ORGANIZATIONS[2] else None),
                        'history_promoted_to_latest_risk')
                require(group['confirmation_history']['supported_occurrences'] == len(supported), 'history_count_changed')
                require(group['confirmation_history']['complete'] is True
                        and group['confirmation_history']['archived_claims'] == 0, 'complete_source_history_weakened')
                main = group
            elif categories & {'redacted', 'ambiguous'}:
                require(len(ids) == 1 and group['identity_status'] == 'unmerged'
                        and group['confirmation_history']['complete'] is False
                        and group['confirmation_history']['supported_occurrences'] is None,
                        'unmergeable_target_claimed_complete')
            else:
                require(len(categories) == 1, 'different_public_scopes_merged')
            if not categories & {'redacted', 'ambiguous'}:
                require(group['identity_status'] == 'grouped' and group['unmerged_reason'] is None
                        and group['target'] == {'kind': 'http_target', 'endpoint': row['asset']['endpoint'],
                        'provider': row['asset']['provider'], 'model': row['asset']['model'],
                        'evidence_context_id': row['asset']['evidence_context_id']}, 'public_target_scope_changed')
            view_records.append({'group': group, 'history': history})
        require(main is not None and len(observed) == len(set(observed))
                and set(observed) == set(expected[organization]), 'missing_or_joined_observations')
        require(len(groups) == 8, 'unexpected_group_count')
        counts[organization] = {'groups': len(groups), 'observations': len(observed),
                                'view_sha256': hashlib.sha256(json.dumps(view_records, sort_keys=True,
                                    allow_nan=False, separators=(',', ':')).encode()).hexdigest()}
    return counts


def publication(directory):
    with closing(inventory.connection(directory)) as database:
        rows = database.execute('SELECT * FROM asset_group_publication ORDER BY organization_id').fetchall()
        require(len(rows) == 3, 'publication_owners_changed')
        for owner, build, generation, nonce, policy, row_count, group_count, *_ in rows:
            require(all(type(value) is str and value for value in (build, generation, nonce, policy)),
                    'publication_not_complete')
            total, sealed, heads = database.execute(
                'SELECT count(*),sum(publication_nonce=? AND source_generation=? AND projection_policy=?),'
                'sum(is_latest=1) FROM asset_group_index WHERE organization_id=? AND build_id=?',
                (nonce, generation, policy, owner, build)).fetchone()
            source_count = database.execute(
                'SELECT count(*) FROM discovered_agent d JOIN scan_session s ON s.id=d.scan_id '
                'WHERE s.organization_id=?', (owner,)).fetchone()[0]
            require(total == sealed == row_count == source_count and heads == group_count,
                    'publication_not_exhaustive_or_sealed')
            require(database.execute('SELECT generation FROM inventory_generation WHERE organization_id=?',
                                     (owner,)).fetchone() == (generation,), 'publication_generation_mismatch')
        return rows


def verify_upgrade(directory, original, old_definitions):
    require(sources(directory, names=original) == original, 'upgrade_changed_original_source_rows')
    definitions = inventory.definitions(directory)
    require(old_definitions <= definitions, 'upgrade_changed_old_definitions')
    added = {row[1]: row[0] for row in definitions - old_definitions}
    require(added == {
        'asset_group_index': 'table', 'asset_group_publication': 'table',
        'sqlite_autoindex_asset_group_index_1': 'index', 'sqlite_autoindex_asset_group_publication_1': 'index',
        'ux_asset_group_head': 'index', 'ix_asset_group_head_page': 'index', 'ix_asset_group_history': 'index',
        'aiscan_asset_group_index_insert': 'trigger', 'aiscan_asset_group_index_update': 'trigger',
        'aiscan_asset_group_index_delete': 'trigger'}, 'upgrade_added_unexpected_definitions')
    with closing(inventory.connection(directory)) as database:
        require(database.execute('SELECT version FROM schema_version WHERE id=1').fetchone() == (7,), 'schema_not_seven')
    publication(directory)


def execute(directory, environment, listener, values, output, deadline, expected):
    original, old_definitions = sources(directory), inventory.definitions(directory)
    output['assertions'].extend(REQUIRED_ASSERTIONS[:2])
    first = inventory.Server(directory, environment, listener, 'initial', deadline, values)
    try:
        first.start()
        first.authenticate(values)
        values.update({'jwt' + str(index): first.tokens[owner] for index, owner in enumerate(ORGANIZATIONS)})
        for organization in ORGANIZATIONS:
            wait_ready(first, organization)
        verify_upgrade(directory, original, old_definitions)
        output['schema_after'] = 7
        output['assertions'].append(REQUIRED_ASSERTIONS[2])
        output['traversal_counts'] = verify_views(first, expected)
        output['assertions'].append(REQUIRED_ASSERTIONS[3])
        source_checks(first, directory, expected, output)
        final_sources = sources(directory, names=original)
        require({key: value for key, value in final_sources.items() if key != 'inventory_generation'}
                == {key: value for key, value in original.items() if key != 'inventory_generation'},
                'source_restore_changed_original_rows')
        stamp = publication(directory)
    finally:
        try:
            code = first.stop()
        finally:
            output['server_exits'].append({'phase': 'initial', 'returncode': first.process.returncode if first.process else None})
        require(code == 0, 'initial_server_exit_nonzero')
    second = inventory.Server(directory, environment, listener, 'restart', deadline, values)
    try:
        second.start()
        second.tokens = first.tokens.copy()
        require(verify_views(second, expected) == output['traversal_counts'] and publication(directory) == stamp
                and sources(directory, names=original) == final_sources, 'restart_changed_complete_views_or_generation')
        output['assertions'].append(REQUIRED_ASSERTIONS[9])
        inventory.no_work(directory)
        output['assertions'].append(REQUIRED_ASSERTIONS[10])
    finally:
        try:
            code = second.stop()
        finally:
            output['server_exits'].append({'phase': 'restart', 'returncode': second.process.returncode if second.process else None})
        require(code == 0, 'restart_server_exit_nonzero')
    for phase in ('initial', 'restart'):
        require((directory / (phase + '.log')).read_bytes().count(b'Booting worker with pid:') == 1, 'worker_count_changed')
    output['http_responses_checked'] = first.http_checked + second.http_checked
    output['assertions'].append(REQUIRED_ASSERTIONS[11])


def wait_blocked(server, directory, organization):
    while True:
        server.remaining()
        with closing(inventory.connection(directory)) as database:
            row = database.execute(
                'SELECT p.building_generation,p.error_code,g.generation FROM asset_group_publication p '
                'JOIN inventory_generation g ON g.organization_id=p.organization_id '
                'WHERE p.organization_id=? AND p.building_build_id IS NOT NULL', (organization,)).fetchone()
        if row is not None and row[0] == row[2] and row[1] == 'source_unavailable':
            return
        time.sleep(0.02)


def source_checks(server, directory, expected, output):
    owner, other = ORGANIZATIONS[:2]
    status, first = server.request('/api/asset-groups?limit=1', organization=owner)
    require(status == 200 and first.get('next_cursor'), 'cursor_fixture_missing')
    cursor = first['next_cursor']
    continuation = '/api/asset-groups?' + urlencode({'limit': 1, 'cursor': cursor})
    for path, organization in [
            (continuation, other),
            ('/api/asset-groups?' + urlencode({'limit': 1, 'cursor': cursor + 'x'}), owner),
            ('/api/asset-groups?risk_level=high', owner), ('/api/asset-groups?limit=0', owner)]:
        require(server.request(path, organization=organization)[0] == 400, 'invalid_cursor_or_filter_accepted')
    history_url = first['asset_groups'][0]['confirmation_history']['url']
    status, history = server.request(history_url + '?limit=1', organization=owner)
    require(status == 200 and history.get('next_cursor'), 'history_cursor_fixture_missing')
    require(server.request(history_url + '?' + urlencode({'limit': 1, 'cursor': history['next_cursor']}),
                           organization=other)[0] == 400, 'cross_owner_history_cursor_accepted')
    output['assertions'].append(REQUIRED_ASSERTIONS[4])
    with closing(inventory.connection(directory, write=True)) as database:
        database.execute('BEGIN IMMEDIATE')
        database.execute('UPDATE scan_result SET result=result WHERE scan_id=?', (owner + '-high',))
        database.rollback()
    require(server.request(continuation, organization=owner)[0] == 200, 'rollback_invalidated_cursor')
    with closing(inventory.connection(directory, write=True)) as database, database:
        database.execute('UPDATE scan_result SET result=result WHERE scan_id=?', (other + '-high',))
    require(server.request(continuation, organization=owner)[0] == 200, 'other_owner_invalidated_cursor')
    output['assertions'].append(REQUIRED_ASSERTIONS[5])
    with closing(inventory.connection(directory, write=True)) as database, database:
        database.execute('UPDATE scan_result SET result=result WHERE scan_id=?', (owner + '-high',))
    require(server.request(continuation, organization=owner)[0] == 409, 'source_write_did_not_invalidate_cursor')
    output['assertions'].append(REQUIRED_ASSERTIONS[6])
    with closing(inventory.connection(directory, write=True)) as database, database:
        original = database.execute('SELECT result FROM scan_result WHERE scan_id=?', (owner + '-high',)).fetchone()[0]
        database.execute('UPDATE scan_result SET result=? WHERE scan_id=?', ('{', owner + '-high'))
    try:
        wait_blocked(server, directory, owner)
        status, blocked = server.request('/api/asset-groups?limit=1', organization=owner)
        require(status == 503 and blocked.get('code') == 'asset_group_projection_unavailable',
                'uninterpretable_source_published')
        require(server.request('/api/agents?limit=1', organization=owner)[0] == 200,
                'unrelated_latest_inventory_hidden_by_group_build')
        output['assertions'].append(REQUIRED_ASSERTIONS[7])
    finally:
        with closing(inventory.connection(directory, write=True)) as database, database:
            database.execute('UPDATE scan_result SET result=? WHERE scan_id=?', (original, owner + '-high'))
    for organization in ORGANIZATIONS:
        restored = wait_ready(server, organization)
        require(restored['coverage']['indexed_observations'] == len(expected[organization])
                and restored['coverage']['indexed_groups'] == 8 and restored['coverage']['search_complete'] is True,
                'restored_source_changed_publication')
    publication(directory)
    output['assertions'].append(REQUIRED_ASSERTIONS[8])


def main(argv=None):
    started = time.monotonic()
    parser = inventory.SafeParser(prog='acceptance-asset-groups.py', description=__doc__)
    parser.add_argument('--timeout-seconds', type=inventory.timeout_value, default=180)
    output = {'format_version': FORMAT_VERSION, 'accepted': False, 'observation_count': OBSERVATIONS,
              'fixture_scope': 'repeated_observations_over_controlled_no_socket_pipeline_sources',
              'schema_before': None, 'schema_after': None, 'schema_target': 7, 'assertions': [], 'server_exits': []}
    failures, values, handlers = [], {}, {}
    temporary = directory = listener = previous_mask = None
    try:
        args = parser.parse_args(argv)
        require(os.name == 'posix', 'posix_required')
        require(importlib.util.find_spec('gunicorn') is not None, 'server_extra_missing_install_project_server_extra')
        require('app' not in sys.modules, 'cached_app_before_fixture_import')
        previous_mask = os.umask(0o077)
        temporary = tempfile.TemporaryDirectory(prefix='ai-scanner-inventory-')
        directory = Path(temporary.name).resolve(strict=True)
        values = {name: secrets.token_hex(32) for name in ('signing', 'operator', 'marker', 'issued')}
        environment = inventory.fresh_environment(directory, values)
        deadline = time.monotonic() + args.timeout_seconds
        def expired(signum, frame):
            raise GateFailure('overall_timeout' if signum == signal.SIGALRM else 'driver_interrupted')
        for selected in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            handlers[selected] = signal.signal(selected, expired)
        signal.setitimer(signal.ITIMER_REAL, args.timeout_seconds)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(128)
        with open(directory / 'driver.log', 'x', encoding='utf-8') as log, redirect_stdout(log), redirect_stderr(log), \
                patch.dict(os.environ, environment, clear=True):
            expected = seed(directory, values)
            output['schema_before'] = 6
            output['runtime'] = inventory.runtime_identity()
            output['runtime']['inventory_helper_sha256'] = output['runtime'].pop('driver_sha256')
            output['runtime']['driver_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            from src.core.asset_groups import ASSET_GROUP_POLICY
            from src.core.build_identity import current_identity
            output['runtime']['asset_group_policy'] = ASSET_GROUP_POLICY
            output['runtime']['build'] = current_identity(component='library')
            require(output['runtime']['build']['source']['status'] == 'available', 'source_identity_unavailable')
            execute(directory, environment, listener, values, output, deadline, expected)
    except (Exception, KeyboardInterrupt) as error:
        failures.append(str(error) if isinstance(error, GateFailure) else 'unexpected_driver_failure')
    finally:
        if handlers:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
            except Exception:
                failures.append('signal_cleanup_failed')
        for selected, previous in handlers.items():
            try:
                signal.signal(selected, previous)
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
                require(directory.stat().st_mode & 0o777 == 0o700, 'fixture_directory_mode_changed')
                require((directory / 'fixture.sqlite.dispatcher.lock').is_file(), 'missing_dispatcher_lock')
                surfaces.extend(path for path in directory.iterdir() if path.name.startswith('fixture.sqlite'))
                inventory.privacy_check(surfaces, values, json.dumps(output, sort_keys=True).encode())
                from tests.controlled_access import REFERENCE
                for surface in surfaces:
                    inventory.assert_private_absent(surface.read_bytes(), {'reference': REFERENCE}, 'private_reference_in_fixture')
                inventory.assert_private_absent(json.dumps(output, sort_keys=True).encode(),
                                               {'reference': REFERENCE}, 'private_reference_in_stdout')
                output['privacy'] = {'required_values_checked': len(values), 'reference_names_checked': 1,
                                     'surfaces_checked': len(surfaces),
                                     'scope': 'known_values_and_encoded_forms_not_arbitrary_generated_request_data'}
                output['assertions'].append(REQUIRED_ASSERTIONS[12])
            except Exception as error:
                failures.append(str(error) if isinstance(error, GateFailure) else 'privacy_check_failed')
            try:
                temporary.cleanup()
                require(not directory.exists() and (listener is None or listener.fileno() == -1), 'fixture_cleanup_failed')
                output['assertions'].append(REQUIRED_ASSERTIONS[13])
            except Exception:
                failures.append('fixture_cleanup_failed')
        if previous_mask is not None:
            try:
                os.umask(previous_mask)
            except Exception:
                failures.append('permission_mask_cleanup_failed')
    if not failures and output['assertions'] != list(REQUIRED_ASSERTIONS):
        failures.append('missing_required_assertions')
    output['accepted'] = not failures
    output['elapsed_seconds'] = round(time.monotonic() - started, 3)
    if failures:
        output['failure_codes'] = failures
    raw = json.dumps(output, sort_keys=True)
    if any(value and value.casefold() in raw.casefold() for value in values.values()):
        output = {'format_version': FORMAT_VERSION, 'accepted': False, 'failure_codes': ['stdout_privacy_failed']}
    print(json.dumps(output, sort_keys=True))
    return 0 if output['accepted'] else (2 if 'invalid_arguments' in failures else 1)


if __name__ == '__main__':
    raise SystemExit(main())
