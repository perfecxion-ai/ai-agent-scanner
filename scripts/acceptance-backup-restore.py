#!/usr/bin/env python3
"""Disposable stopped-SQLite backup, upgrade, and recovery acceptance only."""

import argparse
from collections import Counter
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
CASES = ("v1", "v2", "v3", "rollback1", "rollback2", "future", "incomplete", "lock")
FILENAMES = {"source.sqlite", "backup.sqlite", "restore.sqlite", "old-copy.sqlite"}


def expected_assertions(case):
    assertions = ["stopped_readonly_backup_and_restore_integrity_schema_all_rows"]
    if case.startswith("v"):
        assertions.extend(["upgrade_and_terminal_recovery", "queued_executed_once_without_active_replay",
                           "completed_evidence_audit_templates_preserved", "schedule_recovery_without_admission",
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
            rows[name] = sorted(connection.execute("SELECT * FROM " + quoted).fetchall(), key=repr)
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


def seed(server, engine, version):
    from sqlalchemy import MetaData, insert
    from src.core.schema import VERSION_ONE_TABLES, VERSION_TWO_TABLES, VERSION_THREE_TABLES
    layouts = {1: VERSION_ONE_TABLES, 2: VERSION_TWO_TABLES, 3: VERSION_THREE_TABLES}
    metadata = MetaData()
    for name in sorted(layouts[version]):
        server.db.metadata.tables[name].to_metadata(metadata)
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(metadata.tables["schema_version"]).values(id=1, version=version))
        for identifier, status in (("completed", "completed"), ("queued", "queued"),
                                   ("running", "running"), ("cancel", "cancel_requested")):
            connection.execute(insert(metadata.tables["scan_session"]).values(
                id=identifier, organization_id="backup-fixture", scan_name="Synthetic " + identifier,
                scan_type="discovery_only", status="running" if identifier == "cancel" else status,
                target_scope={}, scan_config={}))
            connection.execute(insert(metadata.tables["scan_job"]).values(scan_id=identifier, status=status))
            connection.execute(insert(metadata.tables["audit_event"]).values(
                scan_id=identifier, organization_id="backup-fixture", event="admitted", status="queued"))
        connection.execute(insert(metadata.tables["audit_event"]).values(
            scan_id="completed", organization_id="backup-fixture", event="terminal",
            previous_status="running", status="completed"))
        connection.execute(insert(metadata.tables["scan_result"]).values(scan_id="completed", result=report("completed")))
        connection.execute(insert(metadata.tables["discovered_agent"]).values(
            id="completed-snapshot", scan_id="completed", agent_name="Retained synthetic asset",
            agent_type="fixture", discovery_method="synthetic", metadata={"retained": "asset-snapshot"}))
        if version >= 2:
            connection.execute(insert(metadata.tables["scan_template"]).values(
                id="recipe", organization_id="backup-fixture", scan_name="Retained recipe",
                scan_type="discovery_only", target_scope={}, scan_config={}, revision=4))
        if version == 3:
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


def exercise(server, engine, directory, version, case, baseline, deadline, checks):
    from sqlalchemy import event, select
    from src.core.jobs import DispatcherLock, JobDispatcher, JobStore
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
        initialize_schema(engine, server.db.metadata)

    def worker(identifier, cancelled):
        observed["executed"].append(identifier)
        require(identifier == "queued" and not cancelled.is_set(), "Unexpected synthetic execution")
        store.save_result(identifier, report(identifier), server.DiscoveredAgentModel.__table__, [])

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
        return jobs == {"completed": "completed", "queued": "completed", "running": "interrupted", "cancel": "cancelled"} and outstanding is None

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
    require(rows["schema_version"] == [(1, 3)], "Schema upgrade did not reach version 3")
    require(observed["executed"] == ["queued"], "Queued work did not execute exactly once")
    require(rows["discovered_agent"] == original["discovered_agent"], "Agent snapshot changed")
    require(next(row for row in original["scan_session"] if row[0] == "completed") in rows["scan_session"],
            "Completed scan metadata changed")
    require(original["scan_result"][0] in rows["scan_result"], "Completed finding/report changed")
    require(all(row in rows["audit_event"] for row in original["audit_event"]), "Existing audit history changed")
    require(rows["scan_template"] == original.get("scan_template", []), "Template rows changed")
    require(rows["scan_occurrence"] == original.get("scan_occurrence", []), "Schedule occurrence was added or changed")
    with engine.connect() as connection:
        jobs = dict(connection.execute(select(store.jobs.c.scan_id, store.jobs.c.status)).all())
        scans = dict(connection.execute(select(store.scans.c.id, store.scans.c.status)).all())
        reports = dict(connection.execute(select(store.results.c.scan_id, store.results.c.result)).all())
        events = connection.execute(select(store.audit)).mappings().all()
        schedules = {row["id"]: row for row in connection.execute(select(server.ScanSchedule.__table__)).mappings()}
    require(all(scans[key] == value == reports[key]["status"] for key, value in jobs.items()),
            "Recovered job/session/report states disagree")
    require(Counter(row["scan_id"] for row in events if row["event"] == "claimed") == {"queued": 1}, "Unexpected claim history")
    require(Counter(row["scan_id"] for row in events if row["event"] == "terminal") == {key: 1 for key in jobs}, "Duplicated or missing terminal history")
    if version == 3:
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
                   "completed_evidence_audit_templates_preserved", "schedule_recovery_without_admission"])
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
    checks.append("second_restart_idempotent")


def run_case(directory, case, timeout):
    require(case in CASES and Path(directory).name == case, "Unknown acceptance case")
    source = owned_path(directory, "source.sqlite")
    require(not any(Path(directory).iterdir()), "Acceptance directory must start empty")
    os.environ.update(SECRET_KEY=secrets.token_hex(32), OPERATOR_API_KEY="", FLASK_DEBUG="false",
                      DATABASE_URL="sqlite:///" + str(source), SCAN_ALLOWED_NETWORKS="",
                      SCAN_ALLOWED_PATH_ROOTS="", SCAN_ALLOW_LOOPBACK="false")
    sys.path.insert(0, str(ROOT))
    import app as server
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
