# Persistent scan jobs

The API commits a scan and its queue record in one database transaction, then
returns 202. A dispatcher claims queued jobs with a conditional database update
and executes at most `MAX_CONCURRENT_SCANS` jobs concurrently. `SCAN_MAX_QUEUED`
limits waiting jobs independently. A full queue returns 429. HTTP requests no
longer create individual background threads.

This release supports a single server process using file-backed SQLite on a
POSIX host and local filesystem. PostgreSQL, other databases, network filesystem
locking, multiple replicas, and distributed workers are not supported by this
dispatcher. Unsupported database configurations fail startup explicitly. The
CLI does not use the queue and is unaffected by these deployment constraints.

## Startup and shutdown

Gunicorn must load `gunicorn.conf.py`; the container already does so. Its worker
initialization hook takes exclusive ownership, validates or upgrades the schema,
recovers prior jobs, and starts the dispatcher. The development server starts the same
service and binds to localhost. Do not launch the server with the Flask reloader.

The dispatcher holds an OS lock on `<database>.dispatcher.lock` for its entire
lifetime, including outstanding workers. Do not delete or replace this lock file
while the server is running. A second dispatcher fails before it can recover or
modify the first process's jobs. Overlapping Gunicorn reloads are therefore not
supported: stop the old server gracefully, then start the replacement. A process
crash releases the OS lock automatically.

On startup, queued jobs resume. Previously running jobs become `interrupted`,
and previously requested cancellations become `cancelled`. Active security probes
are never automatically replayed. Legacy pending/running scans without a queue
record become `interrupted`. Operators can submit a new scan explicitly when
appropriate. Queued scopes are checked against the current allowlists and limits
before execution, so changed server policy can reject an older queued request.

During shutdown, the dispatcher stops claiming jobs and asks active asynchronous
work to stop. Synchronous code must return before cancellation takes effect.
Ownership remains held if workers do not stop within the grace period. Process
termination may still be needed for blocked external libraries; the next startup
records interrupted jobs without replaying them.

## Cancellation and status

`POST /api/scans/<id>/cancel` requires the same authenticated organization as the
scan. A queued job is cancelled immediately. A running job receives a persisted
cancellation request, observed cooperatively by its worker. Unknown and foreign
scan IDs both return 404. Already terminal scans return 409.

| State | Meaning |
| --- | --- |
| queued | Committed and waiting for worker capacity |
| running | Claimed and executing |
| completed | Requested phases finished; inspect per-asset test coverage |
| partial | Results exist but some work failed or was refused |
| failed | Execution or a deadline prevented completion |
| cancelled | Operator cancellation completed |
| interrupted | Server stopped before execution completed |

Terminal status is committed atomically in the job, scan metadata, versioned report,
and audit event. Agent snapshots and summary counts share that transaction.
Known findings already persisted are retained when a job is finalized. Work that
had not reached a persistence boundary cannot be reconstructed after a crash.

`GET /health/live` (also `/health`) checks process liveness. `GET /health/ready`
returns 200 only while the database schema is accessible and the dispatcher is
healthy; otherwise it returns 503. Health responses do not expose credentials,
database URLs, or queue contents.

## Schema upgrades

Stop the server and back up the SQLite database with a consistent SQLite backup
operation before upgrading. Startup validates schema version 1 while holding the
dispatcher lock. An empty database is initialized automatically. Recognized
unversioned layouts are the original `scan_session` and `discovered_agent` tables,
those tables plus `scan_result`, or those tables plus `scan_result` and `scan_job`.
Existing column definitions and primary keys must match the supported layout.
Extra indexes are accepted. Existing records are preserved; missing additive
tables and the version stamp are committed in one SQLite transaction.

Unknown tables, changed columns, missing versioned tables, or an unsupported
version stop startup without changing the database. Restore a backup or perform
an explicit reviewed migration; deleting the version stamp is not a repair.
This is an acceptance path for these known SQLite releases, not a general
migration engine or support for PostgreSQL.

## Audit history

`GET /api/scans/<id>/audit` requires the scan's authenticated organization.
History records successful admission, claim, cancellation request, and terminal
transitions in the same transaction as the corresponding state changes. Retried
cancellation requests or finalization do not duplicate events. Recovery emits
terminal events for work interrupted by a restart; it does not fabricate earlier
history for upgraded scans.

Events contain only an ID, scan ID, organization ID, event name, previous/next
state and UTC timestamp. Scan names, targets, endpoint queries, configuration,
credentials, prompts, responses, and exception details are excluded. The route
returns state fields and timestamps only, ordered by increasing event ID. Use
`limit` (default 100, maximum 200) and `after` (last returned ID) to paginate.
Foreign and missing scans both return 404. This is audit history, not a
tamper-proof record: an administrator with database access can modify it.
