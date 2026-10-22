#!/usr/bin/env python3
"""Bounded SQLite queue acceptance run using synthetic work and a disposable DB."""

import argparse
from collections import Counter
import json
import math
import os
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile
import threading
import time

from sqlalchemy import insert, select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.jobs import JobDispatcher, JobStore, TERMINAL_STATES  # noqa: E402
from src.core.schema import initialize_schema  # noqa: E402


def integer_between(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"Expected an integer from {low} to {high}")
        return number
    return parse


def number_between(low, high):
    def parse(value):
        number = float(value)
        if not math.isfinite(number) or not low <= number <= high:
            raise argparse.ArgumentTypeError(f"Expected a finite number from {low} to {high}")
        return number
    return parse


def run(args, database):
    # These are process-local synthetic settings, never the operator's database.
    os.environ.pop("SCAN_EVIDENCE_PROFILES_FILE", None)
    os.environ.update(SECRET_KEY="synthetic-queue-benchmark-key-" * 2,
                      OPERATOR_API_KEY="", FLASK_DEBUG="false",
                      DATABASE_URL=f"sqlite:///{database}")
    import app as server

    if server._evidence_profiles._profiles:
        raise ValueError("Queue benchmark requires an empty evidence registry")

    counters = {"active": 0, "peak": 0, "claims": []}
    lock = threading.Lock()

    class ObservedStore(JobStore):
        def claim(self, owner):
            scan_id = super().claim(owner)
            if scan_id is not None:
                with lock:
                    counters["claims"].append(scan_id)
            return scan_id

    with server.app.app_context():
        engine = server.db.engine
        actual_database = engine.url.database
        if (engine.dialect.name != "sqlite" or not actual_database or actual_database == ":memory:"
                or engine.url.query or Path(actual_database).resolve() != database.resolve()):
            raise ValueError("Benchmark engine does not target the requested temporary SQLite database")
        initialize_schema(engine, server.db.metadata)
        store = ObservedStore(engine, server.ScanJob.__table__, server.ScanSession.__table__,
                              server.ScanResult.__table__, server.AuditEvent.__table__)

    started = time.monotonic()
    deadline = started + args.timeout_seconds
    ids = [f"job-{number:05d}" for number in range(args.jobs)]
    with engine.begin() as connection:
        connection.execute(insert(store.scans), [{
            "id": scan_id, "organization_id": "benchmark", "scan_name": "Synthetic queue work",
            "scan_type": "discovery_only", "status": "queued", "target_scope": {}, "scan_config": {},
        } for scan_id in ids])
        connection.execute(insert(store.jobs), [{"scan_id": scan_id, "status": "queued"} for scan_id in ids])
        connection.execute(insert(store.audit), [{
            "scan_id": scan_id, "organization_id": "benchmark", "event": "admitted", "status": "queued",
        } for scan_id in ids])

    # Simulate persisted ownership after a crash, without replaying those jobs.
    interrupted = store.claim("previous-process")
    cancelled_active = store.claim("previous-process")
    store.cancel(cancelled_active)
    queued_cancellations = 0
    for scan_id in ids[10::10]:
        if scan_id not in {interrupted, cancelled_active}:
            if store.cancel(scan_id) != "cancelled":
                raise RuntimeError("Queued cancellation was not accepted")
            queued_cancellations += 1

    def worker(scan_id, cancelled):
        with lock:
            counters["active"] += 1
            counters["peak"] = max(counters["peak"], counters["active"])
        try:
            if cancelled.wait(args.latency_ms / 1000):
                store.finish(scan_id, "Synthetic worker stopped", status="interrupted")
                return
            store.save_result(scan_id, {
                "schema_version": "1.0", "scan_id": scan_id, "scan_type": "discovery_only",
                "status": "completed", "agents": [], "security_results": [], "risk_assessments": [],
                "summary": {"agents_discovered": 0, "vulnerabilities_found": 0,
                            "critical_risks": 0, "overall_risk_score": None},
            }, server.DiscoveredAgentModel.__table__, [])
        finally:
            with lock:
                counters["active"] -= 1

    dispatcher = JobDispatcher(store, worker, workers=args.workers, poll_seconds=0.01,
                               initialize=lambda: initialize_schema(engine, server.db.metadata))
    failures = []
    try:
        dispatcher.start()
        while time.monotonic() < deadline:
            with engine.connect() as connection:
                statuses = connection.scalars(select(store.jobs.c.status)).all()
            if all(status in TERMINAL_STATES for status in statuses):
                break
            time.sleep(min(0.02, max(0, deadline - time.monotonic())))
        else:
            failures.append("Run deadline exceeded")
    finally:
        dispatcher.stop(timeout=5)

    elapsed = time.monotonic() - started
    with engine.connect() as connection:
        jobs = dict(connection.execute(select(store.jobs.c.scan_id, store.jobs.c.status)).all())
        scans = dict(connection.execute(select(store.scans.c.id, store.scans.c.status)).all())
        reports = dict(connection.execute(select(store.results.c.scan_id, store.results.c.result)).all())
        events = connection.execute(select(store.audit).order_by(store.audit.c.id)).mappings().all()
    terminal_counts = Counter(jobs.values())
    terminal_events = Counter(row["scan_id"] for row in events if row["event"] == "terminal")
    claimed_events = Counter(row["scan_id"] for row in events if row["event"] == "claimed")
    observed_claims = Counter(counters["claims"])
    duplicate_claims = sum(count - 1 for count in observed_claims.values())
    consistent = all(scan_id in reports and jobs[scan_id] == scans[scan_id] == reports[scan_id].get("status")
                     for scan_id in ids)
    expected = {"completed": args.jobs - 2 - queued_cancellations,
                "cancelled": 1 + queued_cancellations, "interrupted": 1}
    if dict(terminal_counts) != expected:
        failures.append("Terminal counts differ from the deterministic workload")
    if not consistent:
        failures.append("Job, scan and report status mismatch or missing report")
    if terminal_events != Counter({scan_id: 1 for scan_id in ids}):
        failures.append("Missing or duplicated terminal audit event")
    if duplicate_claims or claimed_events != observed_claims:
        failures.append("Claim uniqueness or recorded claim history mismatch")
    if counters["peak"] > args.workers or counters["active"]:
        failures.append("Worker concurrency bound or shutdown failed")
    if any(row["organization_id"] != "benchmark" for row in events):
        failures.append("Audit tenant mismatch")
    with server.app.app_context():
        server.db.session.remove()
    engine.dispose()
    return {
        "accepted": not failures,
        "parameters": vars(args),
        "environment": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                        "platform": platform.platform(), "machine": platform.machine()},
        "elapsed_seconds": round(elapsed, 6),
        "completed_jobs_per_second": round(terminal_counts.get("completed", 0) / elapsed, 3),
        "peak_active_workers": counters["peak"], "claims": len(counters["claims"]),
        "duplicate_claims": duplicate_claims, "terminal_counts": dict(terminal_counts),
        "audit_event_count": len(events), "consistent_job_scan_report": consistent,
        "failures": failures,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=integer_between(4, 5000), default=200)
    parser.add_argument("--workers", type=integer_between(1, 32), default=2)
    parser.add_argument("--latency-ms", type=number_between(0, 1000), default=1.0)
    parser.add_argument("--timeout-seconds", type=number_between(1, 60), default=60.0)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix="ai-scanner-benchmark-") as directory:
            output = run(args, Path(directory) / "jobs.sqlite")
    except Exception as exc:
        output = {"accepted": False, "parameters": vars(args),
                  "failures": [f"Benchmark execution failed: {type(exc).__name__}"]}
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
