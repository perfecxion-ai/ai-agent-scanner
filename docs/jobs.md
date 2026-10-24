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

The documented Gunicorn hooks and container entrypoint set a private worker
umask before state creation, so new SQLite databases and dispatcher locks are
owner-only. The image's default instance directory is created with mode 0700.
Native deployments must provision a private, service-owned parent directory
themselves, especially when preloading application code. The
[Gunicorn umask setting](https://docs.gunicorn.org/en/stable/settings.html#umask)
also affects its own Unix socket permissions; it is not a substitute for the
worker hook or a private parent directory. These defaults do not chmod existing
databases, directories, backups, reports, or mounted volumes. Review their
ownership and permissions separately before deploying an upgrade. Direct Flask
development startup is not the production permission boundary.

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

Finite schedules use one separate read-only preflight slot. Their final admission
runs in the dispatcher, without DNS/filesystem work in its cancellation loop.
Shutdown invalidates pending results so a late preflight cannot enqueue after
ownership release. Enabled schedules pause for explicit review on startup.
See [schedule scope and soft-deadline limits](scan-schedules.md).

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

## Finalized-check checkpoints

The worker saves redacted inventory, finalized check/finding pairs, and supported
prompt-disclosure and configured tenant receipts while the scan remains running.
Each checkpoint atomically updates the versioned report,
agent snapshots, and summary counts. A write must match the current claim owner
and advance the scan-local sequence; it cannot clear a cancellation request,
create a terminal event, or overwrite a terminal scan. Snapshot IDs and original
discovery timestamps stay stable across updates. Result and inventory API reads
use a consistent database snapshot while these writes are active.

A later timeout, cancellation, or server-process recovery retains the latest
acknowledged checkpoint. Earlier confirmed findings remain visible with partial
coverage. New evidence is saved before risk scoring, so a stalled scorer can
leave a confirmed finding with a null score. A successful score is reused only
while its evidence and scoring inputs are unchanged. Recovery never repeats a
probe to reconstruct evidence.

Checkpoints are bounded to 8 MiB each and 4,096 emissions. Cumulative serialization
is capped at 128 MiB per scan; server accounting includes both reports and snapshot
rows, but not SQLite page or WAL amplification. SQLite checkpoint lock waiting is
capped at one second. Validation, size, ownership, or persistence failure stops further probes
and retains any earlier committed checkpoint. These are execution limits, not a
guarantee that every inventory fits. Duplicate or redaction-colliding source IDs
are rejected before evidence can be associated with an ambiguous asset.

Prompt and tenant receipts preserve controlled confirmations before their
category finishes, without inventing a completed check. Their acknowledged ledger
prefix and execution identity cannot be removed or rewritten by a later checkpoint
or final result. The new checkpoint version cannot downgrade to finalized-only
coverage. See the [prompt](result-contracts.md#prompt-observation-receipts) and
[tenant](result-contracts.md#tenant-observation-receipts) contracts. Tenant private
input remains rejected by the server API; its persistence tests exercise a
library worker with explicitly prepared fixture configuration. Other unfinished
checks still need separate observation contracts. Process
termination before an acknowledged commit can lose that observation. This is server-process recovery on the
supported local SQLite deployment, not power-loss or storage-hardware validation.
The CLI retains the same public reports in memory and exports on orderly timeout
or cancellation with a nonzero exit. It does not persist a restartable checkpoint
file and cannot recover from a CLI process crash or forced termination.

`GET /health/live` (also `/health`) checks process liveness. `GET /health/ready`
returns 200 only while the database schema is accessible and the dispatcher is
healthy; otherwise it returns 503. Health responses do not expose credentials,
database URLs, or queue contents.

## Schema upgrades

Stop the server and back up the SQLite database with a consistent SQLite backup
operation before upgrading. Startup validates schema version 5 while holding the
dispatcher lock. An empty database is initialized automatically. Recognized
unversioned layouts are the original `scan_session` and `discovered_agent` tables,
those tables plus `scan_result`, or those tables plus `scan_result` and `scan_job`.
Existing column definitions and primary keys must match the supported layout.
Ordinary and partial non-unique indexes are accepted. Explicit historical
definitions validate old layouts independently of the current ORM. Missing
additive tables, the score-column migration, and the version stamp commit in one
SQLite transaction.

The exact version 1 layout contains `scan_session`, `discovered_agent`,
`scan_result`, `scan_job`, `audit_event`, and `schema_version`. Exact version 1
upgrades add `scan_template`, `scan_schedule`, and `scan_occurrence`. Exact version
2 already contains `scan_template` and adds only the two schedule tables. Version
3 already has all nine tables. Versions 1 through 3 then upgrade the two score
columns without recreating existing schedule tables. Schema 4 already has those
nullable columns. All recognized older layouts then install schema-5 inventory
generation metadata. Fresh and recognized unversioned layouts initialize to
version 5. An unstamped extra template/schedule table or a partial versioned
layout is not a recognized upgrade path. See [saved template boundaries](scan-templates.md)
and [finite schedule boundaries](scan-schedules.md).

Schema 4 stores unknown `scan_session.overall_risk_score` and
`discovered_agent.risk_score` as SQL `NULL`, without a zero default. Genuine
assessed zero remains `0.0`. Migration interprets saved evidence through the same
canonical risk projection used by the API, including supported partial findings.
Missing or unsupported evidence becomes null, and an unassessed snapshot's cached
level becomes `unknown`. Snapshot aliases follow the API's explicit `asset_id` or
row-ID fallback; malformed explicit aliases cannot supply a score.

Only the two score-bearing tables are rebuilt. SQL copying preserves IDs and
stored JSON/text bytes; archived reports, findings, job/audit records, and other
row fields are preserved. Accepted indexes are recreated from their original SQL.
A failure during copying, index recreation, cache projection, or version stamping
rolls the upgrade back. New writes use the canonical projection for scalar caches
and preserve null through checkpoint, terminal, cancellation, and recovery paths.
API reads and exports continue to use the saved report. Global inventory uses
[bounded canonical cursor traversal](inventory.md).

Migration bounds each report and snapshot-metadata interpretation to 8 MiB before
fetching its raw bytes and processes records incrementally. An explicit limit of
64 nested JSON containers applies before JSON parsing and to new cache projections,
independently of Python's recursion behavior. Stored JSON text must be UTF-8
(an optional UTF-8 BOM is accepted). Malformed, deeper, non-UTF-8, or oversized
evidence leaves the cache unknown while its stored bytes remain intact. This does
not repair a malformed archive. Startup performs this
upgrade before recovering jobs, under the existing exclusive dispatcher lock.

Schema 5 adds `inventory_generation`, three candidate indexes, and nine exact
recognized triggers. The schema-4 to 5 upgrade preserves existing rows, score
caches, archives, and accepted operator indexes without rebuilding the score
tables. Generation changes share report/observation/ownership transactions,
including direct ORM/Core writes. Progress-only scan-session updates do not
invalidate cursors; report and observation writes always invalidate them.
Startup validates the full trigger and reserved-index definitions; repeated
startup does not regenerate unchanged tokens. Candidate indexes can still require
cross-scan sorting, so the inventory reader also enforces work limits.

Unknown tables, views, additional or altered triggers, expression indexes, additional constraints or unique indexes,
`WITHOUT ROWID`/`STRICT` table options, explicit column collations or conflict policies,
database column defaults, changed columns,
missing versioned tables, or an unsupported
version stop startup without changing the database. Restore a backup or perform
an explicit reviewed migration; deleting the version stamp is not a repair.
This is an acceptance path for these known SQLite releases, not a general
migration engine or support for PostgreSQL.
Downgrading the version stamp is unsupported. To roll back a deployed upgrade,
stop the service and restore the untouched pre-upgrade backup with the prior
binary; keep that backup until deployment validation is complete.

## Disposable backup/restore acceptance

From the checkout with the server dependencies installed:

```bash
python scripts/acceptance-backup-restore.py
python scripts/acceptance-backup-restore.py --timeout-seconds 5
```

This command accepts no database source or destination paths. A parent-owned
private temporary directory contains synthetic databases only; each case runs in
a fresh child process. Existing `DATABASE_URL` and server settings are isolated,
and a cached or foreign application engine is rejected before connecting. The
parent bounds child output, kills/reaps timed-out children, and removes the
temporary databases after success or failure. JSON includes `accepted`, each
case's assertions, and bounded failure details; failure returns nonzero.

All eleven cases include frozen schema 1/2/3/4 fixtures and a schema-5 fixture
created through the real initializer. They contain completed evidence, agent snapshots, audit
history, queued work, and previously active work. Templates and schedules are
seeded where supported. After stopping and disposing seed connections, a read-only
SQLite backup is restored into absent files. Integrity, schema, and every logical
user row must match before the real initializer and dispatcher start. Synthetic
queued work executes once; prior active jobs recover without replay. Enabled
schedules require restart review, including an overdue schedule with no outstanding
scan. Existing occurrences remain intact and no schedule preflight/admission is
allowed. A second restart must not change rows, evidence, or audit history.

Successful upgrades assert null for unsupported cached scores, preserve a genuine
assessed zero and a retained confirmed partial score, and allow only the documented
score/level fields to change in existing completed rows. Archived report JSON and
all other completed fields stay exact.
The schema-4 case also proves no nullable-table rebuild occurs. Generation owners,
token shape, progress stability, and unchanged restart generations are asserted.

Negative cases verify exclusive ownership precedes initialization, schema 1/2/3
version-stamp failures roll back, future versions remain unchanged, and a restored
copy missing a report is rejected before initialization even though its SQLite
integrity check passes. An independent restore of the untouched backup must retain
the original version and content. Source and backup file hashes remain unchanged
through later upgrade/recovery work. This is content preservation, not old-binary
compatibility testing.

The per-case work deadline is cooperative; a separate parent process timeout adds
five seconds for imports, with a further bounded five-second kill/reap grace.
This command is not a deployed database
backup utility, online backup procedure, crash-durability test, or release sign-off.
It never opens a deployed database or scans a real target. Operators still need
separately authorized backup/restore and upgrade validation for their deployment.

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
