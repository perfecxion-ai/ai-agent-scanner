#!/usr/bin/env python3
"""Disposable stopped-SQLite backup, upgrade, and recovery acceptance only."""

import argparse
import asyncio
from collections import Counter
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
CASES = ("v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "rollback1", "rollback2", "rollback3", "rollback5",
         "future", "incomplete", "lock")
FILENAMES = {"source.sqlite", "backup.sqlite", "restore.sqlite", "old-copy.sqlite"}
CACHE_OUTCOMES = {'assessed-zero': 'completed', 'assessed-high': 'completed',
                  'retained-partial': 'partial', 'retained-tenant': 'partial',
                  'legacy-zero': 'completed', 'legacy-high': 'completed', 'legacy-partial': 'partial'}


def expected_assertions(case):
    assertions = ["stopped_readonly_backup_and_restore_integrity_schema_all_rows"]
    if case.startswith("v"):
        if case in {"v4", "v5", "v6", "v7", "v8"}:
            assertions.append("policy_refresh_preserves_sources_schema_and_unrelated_rows")
        assertions.extend(["upgrade_and_terminal_recovery", "queued_executed_once_without_active_replay",
                           "completed_evidence_audit_templates_preserved", "schedule_recovery_without_admission",
                           "access_policy_cache_preserves_legacy_unknown_current_zero_high_partial_and_tenant",
                           "inventory_generation_owners_shape_and_progress_stability",
                           "second_restart_idempotent"])
    else:
        assertions.append({"lock": "lock_rejected_before_initializer_without_database_changes",
                           "incomplete": "incomplete_restore_rejected_before_engine_initializer_and_dispatcher"}.get(
                               case, "upgrade_rejected_before_recovery_with_unchanged_schema_and_rows"))
    return assertions + ["independent_old_backup_restore_and_untouched_source_backup"]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def owned_path(directory, name):
    directory = Path(directory)
    parent = directory.parent
    require(directory.is_absolute() and directory.resolve() == directory and not directory.is_symlink()
            and parent.parent == Path(tempfile.gettempdir()).resolve()
            and parent.name.startswith("ai-scanner-backup-") and not parent.is_symlink()
            and directory.name in CASES and directory.is_dir(), "Not an owned acceptance directory")
    require(name in FILENAMES, "Not an acceptance database filename")
    path = directory / name
    require(not path.is_symlink() and path.resolve() == path, "Database symlinks are not accepted")
    return path


def guard_database(engine, database):
    actual = engine.url.database
    require(engine.dialect.name == "sqlite" and actual and actual != ":memory:"
            and not engine.url.query and Path(actual).is_absolute()
            and Path(actual).resolve() == database and not Path(actual).is_symlink(),
            "Engine does not target the owned temporary SQLite database")


def readonly(database):
    require(database.is_file() and not database.is_symlink(), "Missing regular source database")
    return sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=1)


def snapshot(database):
    with closing(readonly(database)) as connection:
        require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
                "SQLite integrity check failed")
        schema = connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY name").fetchall()
        names = [row[1] for row in schema if row[0] == "table" and not row[1].startswith("sqlite_")]
        rows = {}
        for name in names:
            quoted = '"' + name.replace('"', '""') + '"'
            # Owned fixture identifiers are escaped and double-quoted above.
            rows[name] = sorted(connection.execute("SELECT * FROM " + quoted).fetchall(), key=repr)  # nosec B608
        return {"schema": schema, "rows": rows}


def digest(database):
    return hashlib.sha256(database.read_bytes()).hexdigest()


def verify_restored(database, original):
    require(snapshot(database) == original, "Restored logical schema or rows differ")


def copy_database(source, destination, deadline):
    require(owned_path(source.parent, source.name) == source
            and owned_path(destination.parent, destination.name) == destination,
            "Backup paths must belong to the acceptance directory")
    require(source != destination and source.parent == destination.parent,
            "Backup must use distinct owned filenames")
    require(source.name in FILENAMES and destination.name in FILENAMES, "Unknown database filename")
    # Exclusive creation protects even an existing empty file or dangling symlink.
    with closing(readonly(source)) as origin:
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        def progress(status, remaining, total):
            require(time.monotonic() < deadline, "SQLite backup deadline exceeded")
        with closing(sqlite3.connect(destination, timeout=1)) as target:
            origin.backup(target, pages=16, progress=progress, sleep=0.01)


def report(scan_id):
    return {"schema_version": "1.0", "scan_id": scan_id, "scan_type": "discovery_only",
            "status": "completed", "agents": [], "security_results": [{"agent_id": "synthetic-asset",
                "vulnerabilities": [{"id": "retained-synthetic-finding", "evidence": "synthetic fixture only"}]}],
            "risk_assessments": [],
            "summary": {"agents_discovered": 1, "vulnerabilities_found": 1,
                        "critical_risks": 0, "overall_risk_score": None}}


def controlled_report(scan_id, *, disclose=False, partial=False):
    """Exercise real transport and current controls on an owned loopback fixture."""
    from tests.access_provenance_fixture import current_access_report
    value = asyncio.run(current_access_report(mode='partial' if partial else 'vulnerable' if disclose else 'protected'))
    value['scan_id'] = scan_id
    expected = 70 if disclose else 0
    require(value['summary']['overall_risk_score'] == expected, 'Controlled fixture lost its assessed score')
    require(value['status'] == ('partial' if partial else 'completed'), 'Controlled fixture status changed')
    return value


def cache_fixtures():
    """Keep genuine old archives beside current synthetic producer outputs."""
    from tests.legacy_access_fixtures import legacy_access_archive, legacy_access_report
    from tests.legacy_observation_fixtures import legacy_archive, legacy_report
    outputs = {
        'assessed-zero': (controlled_report('assessed-zero'), None),
        'assessed-high': (controlled_report('assessed-high', disclose=True), None),
        'retained-partial': (controlled_report('retained-partial', disclose=True, partial=True), None),
        'retained-tenant': (legacy_report('subject-partial-final'), legacy_archive('subject-partial-final')),
    }
    for name in ('zero', 'high', 'partial'):
        outputs['legacy-' + name] = (legacy_access_report(name), legacy_access_archive(name))
    return outputs


def seed(server, engine, version):
    from sqlalchemy import insert
    from src.core.schema import initialize_schema
    from tests.historical_schema import historical_metadata
    if version < 8:
        metadata = historical_metadata(version=version)
        metadata.create_all(engine)
    else:
        metadata = server.db.metadata
        initialize_schema(engine, metadata)
    controlled = cache_fixtures()
    with engine.begin() as connection:
        if version < 8:
            connection.execute(insert(metadata.tables["schema_version"]).values(id=1, version=version))
        for identifier, status in (("completed", "completed"), ("queued", "queued"),
                                   ("running", "running"), ("cancel", "cancel_requested")):
            connection.execute(insert(metadata.tables["scan_session"]).values(
                id=identifier, organization_id="backup-fixture", scan_name="Synthetic " + identifier,
                scan_type="discovery_only", status="running" if identifier == "cancel" else status,
                target_scope={}, scan_config={}, overall_risk_score=0.0 if version < 4 else None))
            connection.execute(insert(metadata.tables["scan_job"]).values(scan_id=identifier, status=status))
            connection.execute(insert(metadata.tables["audit_event"]).values(
                scan_id=identifier, organization_id="backup-fixture", event="admitted", status="queued"))
        connection.execute(insert(metadata.tables["audit_event"]).values(
            scan_id="completed", organization_id="backup-fixture", event="terminal",
            previous_status="running", status="completed"))
        connection.execute(insert(metadata.tables["scan_result"]).values(scan_id="completed", result=report("completed")))
        connection.execute(insert(metadata.tables["discovered_agent"]).values(
            id="completed-snapshot", scan_id="completed", agent_name="Retained synthetic asset",
            agent_type="fixture", discovery_method="synthetic", metadata={"retained": "asset-snapshot"},
            risk_score=0.0 if version < 4 else None))
        for identifier, (output, archived) in controlled.items():
            asset = output['agents'][0]
            from src.core.stored_risk import project_stored_risk
            summary, projected = project_stored_risk(output)
            score = (summary['overall_risk_score'] if version >= 6 else
                     output['summary']['overall_risk_score'])
            asset_score = (projected.get(asset['id'], {}).get('risk_score') if version >= 6 else asset['risk_score'])
            asset_level = (projected.get(asset['id'], {}).get('risk_level', 'unknown') if version >= 6 else
                           asset['risk_level'])
            connection.execute(insert(metadata.tables['scan_session']).values(
                id=identifier, organization_id='backup-fixture', scan_name='Synthetic ' + identifier,
                scan_type='security_only', status=output['status'], target_scope={}, scan_config={},
                overall_risk_score=score))
            connection.execute(insert(metadata.tables['scan_job']).values(scan_id=identifier, status=output['status']))
            for event_name in ('admitted', 'terminal'):
                connection.execute(insert(metadata.tables['audit_event']).values(
                    scan_id=identifier, organization_id='backup-fixture', event=event_name,
                    previous_status='running' if event_name == 'terminal' else None,
                    status=output['status'] if event_name == 'terminal' else 'queued'))
            connection.execute(insert(metadata.tables['scan_result']).values(scan_id=identifier, result=output))
            if archived is not None:
                connection.exec_driver_sql('UPDATE scan_result SET result=? WHERE scan_id=?', (archived, identifier))
            connection.execute(insert(metadata.tables['discovered_agent']).values(
                id=identifier + '-snapshot', scan_id=identifier, agent_name='Retained controlled asset',
                agent_type='fixture', discovery_method='synthetic', risk_score=asset_score,
                risk_level=asset_level, metadata={'asset_id': asset['id']},
                vulnerabilities=asset['vulnerabilities']))
        if version >= 2:
            connection.execute(insert(metadata.tables["scan_template"]).values(
                id="recipe", organization_id="backup-fixture", scan_name="Retained recipe",
                scan_type="discovery_only", target_scope={}, scan_config={}, revision=4))
        if version >= 3:
            from datetime import datetime
            for identifier, state in (("enabled", "enabled"), ("overdue", "enabled"), ("disabled", "disabled")):
                connection.execute(insert(metadata.tables["scan_schedule"]).values(
                    id=identifier, organization_id="backup-fixture", template_id="recipe", template_revision=4,
                    interval_seconds=60, total_runs=3, admitted_runs=1 if identifier == "enabled" else 0,
                    revision=7, state=state, next_due_at=datetime(2000, 1, 1) if state == "enabled" else None,
                    outstanding_scan_id="running" if identifier == "enabled" else None))
            connection.execute(insert(metadata.tables["scan_occurrence"]).values(
                id="enabled:1", schedule_id="enabled", organization_id="backup-fixture", scan_id="running", ordinal=1))


def wait_until(predicate, deadline):
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise RuntimeError("Recovery deadline exceeded")


def inventory_generation_state(server, engine):
    from sqlalchemy import inspect, select
    with engine.connect() as connection:
        columns = {column['name']: column for column in inspect(connection).get_columns('inventory_generation')}
        require(set(columns) == {'organization_id', 'generation'}
                and str(columns['organization_id']['type']) == 'VARCHAR(64)'
                and str(columns['generation']['type']) == 'VARCHAR(32)'
                and all(not column['nullable'] and column['default'] is None for column in columns.values())
                and inspect(connection).get_pk_constraint('inventory_generation')['constrained_columns']
                    == ['organization_id'], 'Inventory generation table shape changed')
        owners = set(connection.scalars(select(server.ScanSession.organization_id).distinct()))
        generations = dict(connection.exec_driver_sql(
            'SELECT organization_id,generation FROM inventory_generation').all())
    require(set(generations) == owners and all(isinstance(value, str) and re.fullmatch('[0-9a-f]{32}', value)
                                              for value in generations.values()),
            'Inventory generation ownership or token shape changed')
    return generations


def refresh_schema_preserved(before, after, version):
    """Only schema 7's nullable derived facts and one risk index may be added."""
    if version >= 8:
        return before == after
    if version < 7:
        return set(map(tuple, before)) <= set(map(tuple, after))
    old, new = {row[1]: tuple(row) for row in before}, {row[1]: tuple(row) for row in after}
    risk_name = 'ix_asset_group_head_risk_page'
    risk_sql = ('CREATE INDEX ix_asset_group_head_risk_page ON asset_group_index '
                '(organization_id, build_id, publication_nonce, source_generation, '
                'projection_policy, is_latest, risk_level, observed_at_us DESC, group_id) WHERE is_latest = 1')
    if set(new) != set(old) | {risk_name} or new[risk_name] != (
            'index', risk_name, 'asset_group_index', risk_sql):
        return False
    previous = old['asset_group_index']
    additions = (', risk_score FLOAT, risk_level VARCHAR(20), risk_coverage_status VARCHAR(32), '
                 'risk_assessment_status VARCHAR(32), risk_scoring_policy VARCHAR(64), security_status VARCHAR(32)')
    marker = 'projection_policy VARCHAR(64) NOT NULL'
    if previous[3].count(marker) != 1:
        return False
    expected = previous[:3] + (previous[3].replace(marker, marker + additions, 1),)
    return new['asset_group_index'] == expected and all(new[name] == row for name, row in old.items()
                                                       if name != 'asset_group_index')


def exercise(server, engine, directory, version, case, baseline, deadline, checks):
    from sqlalchemy import event, inspect, select
    from src.core.jobs import DispatcherLock, JobDispatcher, JobStore, current_claim_owner
    from src.core.schema import SchemaError, initialize_schema
    observed = {"initialized": 0, "recovered": 0, "executed": [], "preflight": 0, "admitted": 0}

    class ObservedStore(JobStore):
        def recover(self):
            observed["recovered"] += 1
            return super().recover()

    store = ObservedStore(engine, server.ScanJob.__table__, server.ScanSession.__table__,
                          server.ScanResult.__table__, server.AuditEvent.__table__)

    def initialize():
        observed["initialized"] += 1
        preserve_sources = version >= 4 and observed['initialized'] == 1
        statements = []
        def observe(_connection, _cursor, statement, _parameters, _context, _many):
            statements.append(statement)
        if preserve_sources:
            event.listen(engine, 'before_cursor_execute', observe)
        try:
            initialize_schema(engine, server.db.metadata)
        finally:
            if preserve_sources:
                event.remove(engine, 'before_cursor_execute', observe)
        if preserve_sources:
            upgraded = snapshot(owned_path(directory, 'restore.sqlite'))
            from src.core.schema import SCHEMA_VERSION
            def retained(values):
                result = dict(values)
                for table, omitted in [('scan_session', {'overall_risk_score'}),
                                       ('discovered_agent', {'risk_score', 'risk_level'})]:
                    columns = list(server.db.metadata.tables[table].columns.keys())
                    result[table] = [tuple(value for name, value in zip(columns, row, strict=True)
                                          if name not in omitted) for row in result[table]]
                result.pop('inventory_generation', None)
                for table in ('asset_group_index', 'asset_group_publication'):
                    require(not result.pop(table, []), 'Fresh derived projection must be empty')
                result['schema_version'] = [(1, SCHEMA_VERSION)]
                return result
            require(retained(upgraded['rows']) == retained(baseline['rows'])
                    and refresh_schema_preserved(baseline['schema'], upgraded['schema'], version)
                    and not any('DROP TABLE' in statement.upper() or '_aiscan_v4_' in statement
                                for statement in statements),
                    'Policy refresh changed existing sources, schema, or unrelated rows')
            if version >= 5:
                asset_columns = list(server.DiscoveredAgentModel.__table__.columns.keys())
                scan_columns = list(server.ScanSession.__table__.columns.keys())
                old_assets = {row[0]: dict(zip(asset_columns, row, strict=True))
                              for row in baseline['rows']['discovered_agent']}
                owners = {row[0]: row[scan_columns.index('organization_id')]
                          for row in baseline['rows']['scan_session']}
                changed_owners = set()
                for row in upgraded['rows']['discovered_agent']:
                    current = dict(zip(asset_columns, row, strict=True))
                    previous = old_assets[current['id']]
                    if any(current[key] != previous[key] for key in ('risk_score', 'risk_level')):
                        changed_owners.add(owners[current['scan_id']])
                previous = dict(baseline['rows']['inventory_generation'])
                current = dict(upgraded['rows']['inventory_generation'])
                require(set(previous) == set(current)
                        and {owner for owner in previous if previous[owner] != current[owner]} == changed_owners,
                        'Policy refresh invalidated unrelated inventory owners')
            checks.append('policy_refresh_preserves_sources_schema_and_unrelated_rows')

    def worker(identifier, cancelled):
        observed["executed"].append(identifier)
        require(identifier == "queued" and not cancelled.is_set(), "Unexpected synthetic execution")
        accepted = store.save_result(identifier, report(identifier), server.DiscoveredAgentModel.__table__, [],
                                     owner=current_claim_owner(identifier))
        require(accepted, "Claimed synthetic result was not accepted")

    def dispatcher():
        service = server._schedule_service()
        def preflight(candidate):
            observed["preflight"] += 1
            raise RuntimeError("Restart must not preflight a schedule")

        def admit(candidate, result, stop):
            observed["admitted"] += 1
            raise RuntimeError("Restart must not admit a schedule")

        service.preflight, service.admit = preflight, admit
        return JobDispatcher(store, worker, workers=1, poll_seconds=0.01, initialize=initialize, service=service)

    restored = owned_path(directory, "restore.sqlite")
    if case == "future" or case.startswith("rollback"):
        def fail_stamp(connection, cursor, statement, parameters, context, many):
            if statement.startswith("UPDATE schema_version"):
                raise RuntimeError("Injected version stamp failure")
        if case.startswith("rollback"):
            event.listen(engine, "before_cursor_execute", fail_stamp)
        process = dispatcher()
        rejected = False
        try:
            try:
                process.start()
            except (SchemaError, RuntimeError) as exc:
                messages = {"future": "Unsupported database schema version"}
                rejected = (isinstance(exc, SchemaError) and str(exc) == messages[case]) if case in messages else str(exc) == "Injected version stamp failure"
        finally:
            process.stop(timeout=1)
            if case.startswith("rollback"):
                event.remove(engine, "before_cursor_execute", fail_stamp)
        require(rejected, "Invalid or failed upgrade was not rejected")
        require(observed["initialized"] == 1 and observed["recovered"] == 0 and not observed["executed"],
                "Rejected upgrade reached recovery or execution")
        require(snapshot(restored) == baseline, "Rejected upgrade changed schema or rows")
        checks.append("upgrade_rejected_before_recovery_with_unchanged_schema_and_rows")
        return
    if case == "lock":
        ownership = DispatcherLock(engine)
        ownership.acquire()
        process = dispatcher()
        rejected = False
        try:
            try:
                process.start()
            except RuntimeError as exc:
                rejected = "Another dispatcher owns" in str(exc)
        finally:
            process.stop(timeout=1)
            ownership.release()
        require(rejected and observed["initialized"] == observed["recovered"] == 0
                and not observed["executed"], "Ownership failure reached initializer or recovery")
        require(snapshot(restored) == baseline, "Ownership rejection changed database")
        checks.append("lock_rejected_before_initializer_without_database_changes")
        return

    def settled():
        with engine.connect() as connection:
            jobs = dict(connection.execute(select(store.jobs.c.scan_id, store.jobs.c.status)).all())
            outstanding = connection.scalar(select(server.ScanSchedule.outstanding_scan_id).where(server.ScanSchedule.id == "enabled"))
        return jobs == {"completed": "completed", "queued": "completed", "running": "interrupted",
                        "cancel": "cancelled", **CACHE_OUTCOMES} and outstanding is None

    first = dispatcher()
    try:
        first.start()
        wait_until(settled, deadline)
        require(first.ready, "Recovered dispatcher is not ready")
    finally:
        first.stop(timeout=1)
    require(not first._thread.is_alive() and first._ownership.handle is None, "Dispatcher did not stop or release ownership")
    recovered = snapshot(restored)
    rows = recovered["rows"]
    original = baseline["rows"]
    from src.core.schema import SCHEMA_VERSION
    require(rows["schema_version"] == [(1, SCHEMA_VERSION)], "Schema upgrade did not reach the current version")
    require(observed["executed"] == ["queued"], "Queued work did not execute exactly once")
    asset_columns = list(server.DiscoveredAgentModel.__table__.columns.keys())
    scan_columns = list(server.ScanSession.__table__.columns.keys())

    def without_caches(values, columns, omitted):
        return [tuple(value for name, value in zip(columns, row, strict=True) if name not in omitted) for row in values]

    require(without_caches(rows['discovered_agent'], asset_columns, {'risk_score', 'risk_level'})
            == without_caches(original['discovered_agent'], asset_columns, {'risk_score', 'risk_level'}),
            'Agent snapshot fields outside score caches changed')
    for identifier in ('completed', *CACHE_OUTCOMES):
        before = [row for row in original['scan_session'] if row[0] == identifier]
        after = [row for row in rows['scan_session'] if row[0] == identifier]
        require(without_caches(before, scan_columns, {'overall_risk_score'})
                == without_caches(after, scan_columns, {'overall_risk_score'}),
                'Terminal scan metadata outside score cache changed')
    require(all(row in rows['scan_result'] for row in original['scan_result']), 'Completed finding/report changed')
    require(all(row in rows["audit_event"] for row in original["audit_event"]), "Existing audit history changed")
    require(rows["scan_template"] == original.get("scan_template", []), "Template rows changed")
    require(rows["scan_occurrence"] == original.get("scan_occurrence", []), "Schedule occurrence was added or changed")
    with engine.connect() as connection:
        jobs = dict(connection.execute(select(store.jobs.c.scan_id, store.jobs.c.status)).all())
        scans = dict(connection.execute(select(store.scans.c.id, store.scans.c.status)).all())
        reports = dict(connection.execute(select(store.results.c.scan_id, store.results.c.result)).all())
        events = connection.execute(select(store.audit)).mappings().all()
        schedules = {row["id"]: row for row in connection.execute(select(server.ScanSchedule.__table__)).mappings()}
        score_columns = {name: {column['name']: column for column in inspect(connection).get_columns(name)}
                         for name in ('scan_session', 'discovered_agent')}
        scan_scores = dict(connection.execute(select(server.ScanSession.id, server.ScanSession.overall_risk_score)).all())
        asset_scores = {row.id: (row.risk_score, row.risk_level) for row in connection.execute(select(
            server.DiscoveredAgentModel.id, server.DiscoveredAgentModel.risk_score, server.DiscoveredAgentModel.risk_level))}
    require(all(score_columns[table][column]['nullable'] and score_columns[table][column]['default'] is None
                for table, column in (('scan_session', 'overall_risk_score'), ('discovered_agent', 'risk_score'))),
            'Score columns are not nullable without SQL defaults')
    require(scan_scores == {'completed': None, 'queued': None, 'running': None, 'cancel': None,
                            'assessed-zero': 0.0, 'assessed-high': 70.0, 'retained-partial': 70.0,
                            'retained-tenant': 90.0, 'legacy-zero': None, 'legacy-high': None,
                            'legacy-partial': None}, 'Scan score caches lost canonical values')
    require(asset_scores == {'completed-snapshot': (None, 'unknown'), 'assessed-zero-snapshot': (0.0, 'minimal'),
                             'assessed-high-snapshot': (70.0, 'high'),
                             'retained-partial-snapshot': (70.0, 'high'), 'retained-tenant-snapshot': (90.0, 'critical'),
                             'legacy-zero-snapshot': (None, 'unknown'), 'legacy-high-snapshot': (None, 'unknown'),
                             'legacy-partial-snapshot': (None, 'unknown')}, 'Asset score caches lost canonical values')
    require(all(scans[key] == value == reports[key]["status"] for key, value in jobs.items()),
            "Recovered job/session/report states disagree")
    require(Counter(row["scan_id"] for row in events if row["event"] == "claimed") == {"queued": 1}, "Unexpected claim history")
    require(Counter(row["scan_id"] for row in events if row["event"] == "terminal") == {key: 1 for key in jobs}, "Duplicated or missing terminal history")
    if version >= 3:
        enabled = schedules["enabled"]
        require(enabled["state"] == "paused" and enabled["pause_reason"] == "restart_review"
                and enabled["next_due_at"] is None and enabled["outstanding_scan_id"] is None
                and enabled["revision"] == 9 and enabled["admitted_runs"] == 1
                and enabled["template_id"] == "recipe" and enabled["template_revision"] == 4,
                "Enabled schedule did not recover for explicit restart review")
        require(next(row for row in original["scan_schedule"] if row[0] == "disabled")
                in rows["scan_schedule"], "Disabled schedule changed")
        overdue = schedules["overdue"]
        require(overdue["state"] == "paused" and overdue["pause_reason"] == "restart_review"
                and overdue["next_due_at"] is None and overdue["outstanding_scan_id"] is None
                and overdue["revision"] == 8 and overdue["admitted_runs"] == 0,
                "Overdue schedule did not pause before candidate preflight")
    require(observed["preflight"] == observed["admitted"] == 0, "Restart scheduled new work")
    checks.extend(["upgrade_and_terminal_recovery", "queued_executed_once_without_active_replay",
                   "completed_evidence_audit_templates_preserved", "schedule_recovery_without_admission",
                   "access_policy_cache_preserves_legacy_unknown_current_zero_high_partial_and_tenant"])
    generations = inventory_generation_state(server, engine)
    with engine.begin() as connection:
        original_progress = connection.scalar(select(server.ScanSession.progress).where(server.ScanSession.id == 'completed'))
        connection.execute(server.ScanSession.__table__.update().where(server.ScanSession.id == 'completed').values(progress=25.0))
        require(inventory_generation_state(server, engine) == generations, 'Progress update changed inventory generation')
        connection.execute(server.ScanSession.__table__.update().where(server.ScanSession.id == 'completed').values(progress=original_progress))
    require(inventory_generation_state(server, engine) == generations, 'Progress restoration changed inventory generation')
    checks.append('inventory_generation_owners_shape_and_progress_stability')
    second = dispatcher()
    try:
        second.start()
        # Observe several real idle ticks before the second shutdown.
        wait_until(lambda: second.ready, deadline)
        time.sleep(0.05)
    finally:
        second.stop(timeout=1)
    require(not second._thread.is_alive() and second._ownership.handle is None, "Second dispatcher did not stop")
    require(snapshot(restored) == recovered and observed["executed"] == ["queued"]
            and observed["preflight"] == observed["admitted"] == 0, "Second restart changed evidence or replayed work")
    require(inventory_generation_state(server, engine) == generations, 'Second restart changed inventory generation')
    checks.append("second_restart_idempotent")


def run_case(directory, case, timeout):
    require(case in CASES and Path(directory).name == case, "Unknown acceptance case")
    source = owned_path(directory, "source.sqlite")
    require(not any(Path(directory).iterdir()), "Acceptance directory must start empty")
    os.environ.update(SECRET_KEY=secrets.token_hex(32), OPERATOR_API_KEY="", FLASK_DEBUG="false",
                      DATABASE_URL="sqlite:///" + str(source), SCAN_ALLOWED_NETWORKS="",
                      SCAN_ALLOWED_PATH_ROOTS="", SCAN_ALLOW_LOOPBACK="false")
    os.environ.pop("SCAN_EVIDENCE_PROFILES_FILE", None)
    sys.path.insert(0, str(ROOT))
    import app as server
    require(not server._evidence_profiles._profiles, "Backup acceptance requires an empty evidence registry")
    from sqlalchemy import create_engine
    deadline = time.monotonic() + timeout
    checks = []
    version = int(case[-1]) if case[-1].isdigit() else 3
    with server.app.app_context():
        engine = server.db.engine
        guard_database(engine, source)  # No connection or schema operation before this guard.
        seed(server, engine, version)
        if case == "future":
            with engine.begin() as connection:
                connection.exec_driver_sql("UPDATE schema_version SET version=99")
        server.db.session.remove()
        engine.dispose()
        original = snapshot(source)
        source_hash = digest(source)
        backup = owned_path(directory, "backup.sqlite")
        restored = owned_path(directory, "restore.sqlite")
        copy_database(source, backup, deadline)
        backup_hash = digest(backup)
        copy_database(backup, restored, deadline)
        require(snapshot(backup) == original == snapshot(restored), "Backup or restored logical schema/rows differ")
        checks.append("stopped_readonly_backup_and_restore_integrity_schema_all_rows")
        if case == "incomplete":
            # A logically incomplete copy can still pass SQLite integrity_check.
            # Lose evidence only in the restored copy, never the source or backup.
            with closing(sqlite3.connect(restored, timeout=1)) as connection:
                connection.execute("DELETE FROM scan_result WHERE scan_id='completed'")
                connection.commit()
            rejected = False
            try:
                verify_restored(restored, original)
            except RuntimeError as exc:
                rejected = str(exc) == "Restored logical schema or rows differ"
            require(rejected, "Incomplete restore was not rejected before startup")
            checks.append("incomplete_restore_rejected_before_engine_initializer_and_dispatcher")
        else:
            verify_restored(restored, original)
            engine = create_engine("sqlite:///" + str(restored))
            guard_database(engine, restored)
            server.db.engines[None] = engine
            try:
                exercise(server, engine, directory, version, case, original, deadline, checks)
            finally:
                server.db.session.remove()
                engine.dispose()
        old = owned_path(directory, "old-copy.sqlite")
        copy_database(backup, old, deadline)
        require(snapshot(old) == original, "Independent old backup restore changed version or content")
        require(digest(source) == source_hash and digest(backup) == backup_hash, "Source or untouched backup changed")
        checks.append("independent_old_backup_restore_and_untouched_source_backup")
    return {"case": case, "accepted": True, "assertions": checks}


def child_main():
    payload = {}
    try:
        payload = json.loads(sys.stdin.read(4096))
        require(isinstance(payload, dict), "Invalid child protocol")
        output = run_case(payload["directory"], payload["case"], payload["timeout"])
    except Exception as exc:
        output = {"case": payload.get("case") if isinstance(payload, dict) else None,
                  "accepted": False, "failure": type(exc).__name__ + ": " + str(exc)}
    print(json.dumps(output, sort_keys=True))
    return 0 if output["accepted"] else 1


def child_output(command, payload, environment, timeout):
    """Bound output in memory and always reap the child before parent cleanup."""
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=environment)
    deadline = time.monotonic() + timeout
    output = bytearray()
    try:
        process.stdin.write(json.dumps(payload).encode())
        process.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "Child process timeout")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        require(len(output) <= 16384, "Child output exceeded acceptance limit")
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return process.returncode, output.decode()
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()


def invoke_case(directory, case, timeout):
    code = "import runpy; raise SystemExit(runpy.run_path(" + repr(str(Path(__file__).resolve())) + ")[\"child_main\"]())"
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("SCAN_", "SQLALCHEMY_"))
                   and key not in {"DATABASE_URL", "SECRET_KEY", "OPERATOR_API_KEY", "FLASK_DEBUG", "OPERATOR_ORGANIZATION_ID", "MAX_CONCURRENT_SCANS", "ALLOWED_ORIGINS"}}
    try:
        optimize = ["-" + "O" * sys.flags.optimize] if sys.flags.optimize else []
        returncode, stdout = child_output([sys.executable, *optimize, "-c", code],
            {"directory": str(directory), "case": case, "timeout": timeout}, environment, timeout + 5)
        output = json.loads(stdout)
        require(isinstance(output, dict) and output.get("case") == case, "Child returned an invalid case result")
        if output.get("accepted") is False:
            failure = output.get("failure")
            return {"case": case, "accepted": False,
                    "failure": failure[:512] if isinstance(failure, str) else "Child rejected acceptance"}
        require(output.get("accepted") is True and returncode == 0
                and output.get("assertions") == expected_assertions(case),
                "Child failed acceptance or returned missing assertions")
        return output
    except Exception as exc:
        return {"case": case, "accepted": False, "failure": type(exc).__name__ + ": " + str(exc)[:512]}


def timeout_value(value):
    number = float(value)
    if not math.isfinite(number) or not 1 <= number <= 60:
        raise argparse.ArgumentTypeError("Expected a finite timeout from 1 to 60 seconds")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-seconds", type=timeout_value, default=15,
                        help="Cooperative work deadline per case; parent timeout adds 5 seconds for imports/cleanup")
    args = parser.parse_args()
    cases = []
    failure = None
    try:
        with tempfile.TemporaryDirectory(prefix="ai-scanner-backup-") as root:
            # macOS temporary ancestors may be aliases (/var -> /private/var).
            # Canonicalize the parent we created, not untrusted child paths.
            root = Path(root).resolve(strict=True)
            for case in CASES:
                directory = root / case
                directory.mkdir(mode=0o700)
                cases.append(invoke_case(directory, case, args.timeout_seconds))
    except Exception as exc:
        failure = type(exc).__name__ + ": " + str(exc)[:512]
    output = {"accepted": failure is None and len(cases) == len(CASES) and all(item["accepted"] for item in cases), "cases": cases,
              "scope": "Disposable stopped synthetic SQLite only; no deployed backup or crash-durability certification"}
    if failure:
        output["failure"] = failure
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
