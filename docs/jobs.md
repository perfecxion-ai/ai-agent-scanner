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
initialization hook creates missing tables, takes exclusive ownership, recovers
prior jobs, and starts the dispatcher. The development server starts the same
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

Terminal status is reflected in both scan metadata and the versioned report.
Known findings already persisted are retained when a job is finalized. Work that
had not reached a persistence boundary cannot be reconstructed after a crash.

`GET /health/live` (also `/health`) checks process liveness. `GET /health/ready`
returns 200 only while the database schema is accessible and the dispatcher is
healthy; otherwise it returns 503. Health responses do not expose credentials,
database URLs, or queue contents.

Back up the SQLite database with a consistent SQLite backup operation or while
the server is stopped. Table initialization adds missing queue tables but is not
a general schema migration system.
