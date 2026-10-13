# Local queue acceptance

Run the bounded synthetic queue workload from the repository checkout with the
server dependencies installed:

```bash
python -m pip install '.[server]'
python scripts/benchmark-jobs.py
python scripts/benchmark-jobs.py --jobs 500 --workers 4 --latency-ms 5
```

The script creates and removes a private temporary SQLite database. Its synthetic
signing key and database URL are set only in that process. It does not open an
operator database, run discovery, contact HTTP targets, or call a model provider.
It exercises the actual schema initializer, `JobStore`, `JobDispatcher`, and
application table definitions on a POSIX host with local file-backed SQLite.

The workload inserts synthetic scans and admitted events directly, bypassing
HTTP queue admission and its separate request/queue limits. Before restarting
the dispatcher, it claims one job to represent interrupted work and another with
a persisted cancellation request. It cancels every tenth remaining queued job.
Workers complete the rest through the same atomic result persistence used by
the API. Restart recovery must not execute the previously claimed jobs again.

JSON output includes parameters, Python/SQLite/host versions, elapsed time,
completed jobs per second, peak active workers, terminal counts, audit event
count, duplicate claims, and job/session/report consistency. Acceptance requires
the deterministic expected counts, one terminal event per scan, recorded unique
claims, the configured concurrency ceiling, and consistent terminal states.
Exit code 0 means these invariants passed; 1 means acceptance failed; invalid
arguments return 2. No latency or throughput threshold is treated as acceptance.

Inputs are bounded to 4..5000 jobs, 1..32 workers, 0..1000 milliseconds of fixed
synthetic worker latency, and a 1..60 second execution deadline. Deadline expiry
stops claims and cooperatively interrupts workers. Shutdown waits up to five
seconds for the coordinator, then up to five seconds for workers. Cooperative
SQLite calls can finish later, so the execution deadline is an acceptance bound,
not a hard wall-clock termination guarantee. A deliberately insufficient deadline
provides a repeatable failure check:

```bash
python scripts/benchmark-jobs.py --jobs 200 --latency-ms 1000 --timeout-seconds 1
```

This must exit nonzero and report deadline/incomplete-state failures rather than
claiming a successful run. Keep benchmark output when comparing changes; storage,
filesystem durability, Python version, machine load, and SQLite contention affect
the measurement.

## Recorded local run

On October 13, 2026, the default workload (200 jobs, two workers, 1 ms synthetic
latency, 60-second deadline) completed on Linux 6.17.0-1026-nvidia, aarch64,
glibc 2.39, Python 3.10.20 and SQLite 3.53.1:

| Measurement | Observed |
| --- | --- |
| Elapsed, including admission and recovery | 8.511277 seconds |
| Completed jobs per second | 21.031 |
| Peak active workers | 2 |
| Terminal jobs | 179 completed, 20 cancelled, 1 interrupted |
| Claims | 181 |
| Duplicate claims | 0 |
| Audit events | 582 |
| Job/session/report consistency | Passed |

A four-job, one-worker run also passed. The one-second deadline fixture exited
1 with queued work remaining; oversized job counts and non-finite latency were
rejected before opening a database.

These are local queue correctness and synthetic load observations. They do not
establish production throughput, concurrent HTTP capacity, scan latency, model
accuracy, network performance, database migration rollback in deployment, or
release readiness. Real scans have additional discovery/probe costs and response
budgets. PostgreSQL, distributed workers, and network filesystem locking remain
unsupported.
