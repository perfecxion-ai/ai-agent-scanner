# Scoped nullable-score upgrade retest

Use the exact merged revision supplied with the handoff. This checks schema 3 to
4 on the lab's native Python/SQLite and real single-process server. The supplied
tenant reports have already passed an offline upgrade of disposable database
copies; repeating those tenant scans is unnecessary for this storage change.

Use an already-running authorized lab. Keep original databases, backup files,
private configuration, secrets, and original results outside the returned bundle.
No cloud startup or deployment outside the disposable lab is part of this gate.

## Native acceptance command

Start from a clean checkout. Set `AIS_STORAGE_REVISION` to the full merged SHA
from the handoff and create a fresh virtual environment:

```bash
set -eu
: "${AIS_STORAGE_REVISION:?Set the full merged SHA from the handoff}"
umask 077
test -z "$(git status --porcelain)"
git fetch origin
git checkout --detach "$AIS_STORAGE_REVISION"
test "$(git rev-parse HEAD)" = "$AIS_STORAGE_REVISION"
test ! -e .venv-storage-retest
python3 -m venv .venv-storage-retest
.venv-storage-retest/bin/python -m pip install '.[server]'
AIS_STORAGE_OUT=$(mktemp -d)
git rev-parse HEAD > "$AIS_STORAGE_OUT/revision.txt"
.venv-storage-retest/bin/python --version > "$AIS_STORAGE_OUT/python-version.txt" 2>&1
.venv-storage-retest/bin/python -c 'import sqlite3; print(sqlite3.sqlite_version)' > "$AIS_STORAGE_OUT/sqlite-version.txt"
.venv-storage-retest/bin/python -m pip list --format=json > "$AIS_STORAGE_OUT/dependencies.json"
if .venv-storage-retest/bin/python scripts/acceptance-backup-restore.py \
  --timeout-seconds 5 > "$AIS_STORAGE_OUT/backup-normal.json" 2> "$AIS_STORAGE_OUT/backup-normal.log"
then
  printf '0\n' > "$AIS_STORAGE_OUT/backup-normal.exit"
else
  AIS_STORAGE_EXIT=$?
  printf '%s\n' "$AIS_STORAGE_EXIT" > "$AIS_STORAGE_OUT/backup-normal.exit"
  exit "$AIS_STORAGE_EXIT"
fi
if .venv-storage-retest/bin/python -O scripts/acceptance-backup-restore.py \
  --timeout-seconds 5 > "$AIS_STORAGE_OUT/backup-optimized.json" 2> "$AIS_STORAGE_OUT/backup-optimized.log"
then
  printf '0\n' > "$AIS_STORAGE_OUT/backup-optimized.exit"
else
  AIS_STORAGE_EXIT=$?
  printf '%s\n' "$AIS_STORAGE_EXIT" > "$AIS_STORAGE_OUT/backup-optimized.exit"
  exit "$AIS_STORAGE_EXIT"
fi
```

Both commands must accept all ten cases. Their owned temporary fixtures cover
versions 1 through 4, unknown/null, genuine assessed zero, retained confirmed
partial risk, upgrade rollback, exclusive ownership, and untouched source/backup
hashes. They take no database paths and never inspect a deployed database.
The automated migration regressions also enforce the same 64-container nesting
limit across Python versions; excessive depth leaves an unknown cache without
changing the archived JSON.

## Real server upgrade and restart

Use a stopped, private, disposable schema-3 fixture database. It must have no
queued, running, or cancellation-requested jobs, legacy pending/running scans, or
enabled schedules, so this
storage check cannot admit active probes. Include completed discovery/unassessed
reports and supported assessed records when available from the existing lab.
Do not edit saved reports to fabricate evidence. If a supported assessed-zero or
positive case is unavailable in the lab, record that gap; the native acceptance
command separately exercises both with actual controlled-access producers.

1. Stop the lab server gracefully. Use a consistent SQLite backup operation to
   copy the stopped fixture database into a new owner-only directory. Retain the
   untouched source and backup. Record schema version, SQLite integrity, report
   byte hashes, non-cache row fields, and canonical expected risk privately.
2. Configure the new server to use only the disposable copy, a fresh private
   operator/session credential, the expected organization, and the existing
   restricted lab allowlists. Keep evidence-profile configuration private and
   valid, or omit it when only reading saved results. Bind to loopback using the
   [documented Gunicorn lifecycle configuration](jobs.md#startup-and-shutdown).
   Save real process exits and
   sanitized startup logs; propagate every startup or assertion failure.
3. Wait for `/health/ready`. Verify schema version 4; the two score columns must
   be nullable and have no zero default. SQL NULLs must represent unsupported or
   missing evidence. Within the documented cache interpretation bounds, supported
   assessed zero must remain 0.0 and supported partial or confirmed scores must
   match the current canonical report projection.
4. Authenticate through the normal API. Compare scan results, inventory, and
   JSON/SARIF exports with the saved report evidence. Snapshot aliases follow the
   existing API rules. Preserve archive bytes, findings, IDs, audit/template data,
   non-cache row fields, and accepted ordinary/partial indexes. Derive scalar
   expectations with `stored_json_text` before JSON parsing, then
   `project_stored_risk` and `snapshot_stored_risk`. Raw material rejected by the
   byte, encoding, syntax, or depth bounds leaves a null/unknown cache. API reads
   still use `project_report_risk` on saved reports, so an archive beyond the cache
   bounds can have a different API verdict. Ordinary supported lab reports should
   match both. Former scalar placeholders never supply the expected verdict.
5. Stop and restart the same copy once more. Readiness, API verdicts, scalar caches,
   schema, archives, and row identities must remain consistent. Verify database
   and dispatcher-lock permissions. Stop and reap the lab process when finished.
6. Independently restore the untouched backup into another absent file. Its old
   schema, rows, reports, and source/backup hashes must still match the baseline.
   Downgrading a schema-4 version stamp is not a rollback method.

## Return captures

Return the exact revision and interpreter/dependency/SQLite versions, both backup
command outputs and real exits, sanitized server startup/restart logs, and a
secret-free assertion table covering each step above. Include before/after score
values and coverage classifications under public fixture labels. Report absent
cases and genuine failures explicitly. Keep databases, credential files, tokens,
private paths, raw request headers, and protected values out of the bundle.

Check the final bundle against actual private values locally without printing
them. Record which files were checked and whether any logs were sanitized first.
Analysis, privacy, cleanup, and process failures must affect the job's final exit;
do not convert them into successful log messages.
