# Scoped protected-access retention retest

Run the exact merged revision supplied with the handoff on the existing native
runner. This gate creates synthetic loopback HTTP/HTTPS services and disposable
SQLite fixtures. It needs no model services, private target configuration, operator
database, tenant records, deployment changes or cloud startup.

This tests protected-access findings inside unfinished checks, ledger 3 and
checkpoint 4 on the runner's native Python/SQLite. It is not a model-sensitivity,
operator-migration, power-loss or enterprise-readiness gate. Earlier qualified
native access, tenant and inventory acceptances retain their original scope.

## Execution

Use a new clean isolated checkout and output directory. Run the following block
in Bash; its subshell keeps the trap and environment changes local. Set
`AIS_ACCESS_PROGRESS_REVISION` to the full merged SHA from the handoff. Keep prior
captures unchanged. Environment and output files below live outside the checkout.

```bash
(
set -eu
: "${AIS_ACCESS_PROGRESS_REVISION:?Set the full merged SHA from the handoff}"
umask 077
test -z "$(git status --porcelain)"
git checkout --detach "$AIS_ACCESS_PROGRESS_REVISION"
test "$(git rev-parse HEAD)" = "$AIS_ACCESS_PROGRESS_REVISION"
AIS_ACCESS_PROGRESS_ROOT=$(mktemp -d)
AIS_ACCESS_PROGRESS_ROOT=$(cd "$AIS_ACCESS_PROGRESS_ROOT" && pwd -P)
AIS_ACCESS_PROGRESS_OUT="$AIS_ACCESS_PROGRESS_ROOT/captures"
mkdir "$AIS_ACCESS_PROGRESS_OUT"
AIS_ACCESS_PROGRESS_FAILED=0
access_progress_finish() {
  AIS_ACCESS_PROGRESS_STATUS=$?
  trap - EXIT
  if [ "$AIS_ACCESS_PROGRESS_STATUS" -eq 0 ] && [ "$AIS_ACCESS_PROGRESS_FAILED" -ne 0 ]; then
    AIS_ACCESS_PROGRESS_STATUS=1
  fi
  printf '%s\n' "$AIS_ACCESS_PROGRESS_STATUS" > "$AIS_ACCESS_PROGRESS_OUT/driver.exit" || exit 7
  exit "$AIS_ACCESS_PROGRESS_STATUS"
}
trap access_progress_finish EXIT
printf 'Captures: %s\n' "$AIS_ACCESS_PROGRESS_OUT"
export SCAN_EVIDENCE_PROFILES_FILE="$AIS_ACCESS_PROGRESS_ROOT/no-operator-evidence-profiles.json"
python3 -m venv "$AIS_ACCESS_PROGRESS_ROOT/venv"
AIS_ACCESS_PROGRESS_PY="$AIS_ACCESS_PROGRESS_ROOT/venv/bin/python"
"$AIS_ACCESS_PROGRESS_PY" -m pip install '.[dev,server]'
git rev-parse HEAD > "$AIS_ACCESS_PROGRESS_OUT/revision.txt"
"$AIS_ACCESS_PROGRESS_ROOT/venv/bin/ai-agent-scanner" build-info --json \
  > "$AIS_ACCESS_PROGRESS_OUT/build.json"
"$AIS_ACCESS_PROGRESS_PY" -m pip list --format=json \
  > "$AIS_ACCESS_PROGRESS_OUT/dependencies.json"
"$AIS_ACCESS_PROGRESS_PY" -c 'import sys,sqlite3; print(sys.version); print(sqlite3.sqlite_version)' \
  > "$AIS_ACCESS_PROGRESS_OUT/runtime.txt"
if "$AIS_ACCESS_PROGRESS_PY" -m pytest -q -W error \
    tests/test_access_observation_contracts.py \
    tests/test_access_observation_retention.py \
    tests/test_access_progress_independent.py \
    tests/test_access_progress_https.py \
    tests/test_access_progress_compatibility.py \
    > "$AIS_ACCESS_PROGRESS_OUT/access-tests.log" 2>&1
then
  printf '0\n' > "$AIS_ACCESS_PROGRESS_OUT/access-tests.exit"
else
  AIS_ACCESS_PROGRESS_EXIT=$?
  printf '%s\n' "$AIS_ACCESS_PROGRESS_EXIT" > "$AIS_ACCESS_PROGRESS_OUT/access-tests.exit"
  AIS_ACCESS_PROGRESS_FAILED=1
fi
access_progress_python() {
  if [ "$AIS_ACCESS_PROGRESS_MODE" = optimized ]; then
    "$AIS_ACCESS_PROGRESS_PY" -O "$@"
  else
    "$AIS_ACCESS_PROGRESS_PY" "$@"
  fi
}
for AIS_ACCESS_PROGRESS_MODE in normal optimized
do
  for AIS_ACCESS_PROGRESS_GATE in backup-restore inventory
  do
    if [ "$AIS_ACCESS_PROGRESS_GATE" = backup-restore ]; then
      AIS_ACCESS_PROGRESS_LIMIT=5
    else
      AIS_ACCESS_PROGRESS_LIMIT=120
    fi
    AIS_ACCESS_PROGRESS_PREFIX="$AIS_ACCESS_PROGRESS_OUT/$AIS_ACCESS_PROGRESS_GATE-$AIS_ACCESS_PROGRESS_MODE"
    if access_progress_python "scripts/acceptance-$AIS_ACCESS_PROGRESS_GATE.py" \
        --timeout-seconds "$AIS_ACCESS_PROGRESS_LIMIT" \
        > "$AIS_ACCESS_PROGRESS_PREFIX.json" 2> "$AIS_ACCESS_PROGRESS_PREFIX.log"
    then
      printf '0\n' > "$AIS_ACCESS_PROGRESS_PREFIX.exit"
    else
      AIS_ACCESS_PROGRESS_EXIT=$?
      printf '%s\n' "$AIS_ACCESS_PROGRESS_EXIT" > "$AIS_ACCESS_PROGRESS_PREFIX.exit"
      AIS_ACCESS_PROGRESS_FAILED=1
    fi
  done
done
git status --porcelain > "$AIS_ACCESS_PROGRESS_OUT/source-status.txt"
test ! -s "$AIS_ACCESS_PROGRESS_OUT/source-status.txt" || AIS_ACCESS_PROGRESS_FAILED=1
test "$AIS_ACCESS_PROGRESS_FAILED" -eq 0
)
```

Keep genuine step exits and absent outputs. The trap records setup or captured
command failure once the output directory exists. Forced termination can prevent
the trap from running; an absent driver file is not success. Job wrappers must
preserve the final nonzero exit and report their own analysis, copy, sanitization
or cleanup failures. The public gates clean up their owned fixtures. Leave the
outer private environment/captures for review and remove them only after retaining
the requested evidence.

## Required results and captures

All five test files must pass with warnings as errors. The gate includes real
verified HTTPS CLI JSON/SARIF exports, vulnerable/defended and broken controls,
late 503, deadline and cancellation cases. Confirmed 70/high and 90/critical
findings must survive genuine unfinished checks with partial coverage. Receipt
IDs, actual control proof, target binding and prefixes must remain consistent;
failed controls and nonpositive disclosures cannot confirm or pass.

The two process cases wait for acknowledged SQLite evidence, reject a malformed
append by the actual owner without changing report/snapshots/audit/caches, kill
the dispatcher, then recover and read results through the authenticated API.
Require exact saved evidence, no active-probe replay and clean process cleanup.
Frozen original v3 archives retain 0/70/partial/90 canonical results and exact
bytes. Schema 6 remains unchanged; recognized schema initialization performs no
cache writes.

Both backup modes must exit zero and accept all thirteen cases. Both inventory
modes must exit zero with `inventory-acceptance-v2`, schema 4 to 6, all thirteen
assertion identities, 12 scan caches and 10,000 observation caches reconciled and
then deliberately restored within their own fixture. Check exact filter totals,
restart and cleanup. These are repeated observations of twelve synthetic assets.

Return captures, an assertion table, real job exit and honest failure notes.
Review every returned file for unexpected secrets, generated text, private paths
and unreadable data; record the actual file inventory and sanitizer coverage.
Distinguish fixed public fixture constants from generated values. Failed-test
logs can contain diagnostic fixture details and require review before sharing.
Do not include databases, virtual environments, private configuration, credentials,
certificates or unrelated lab outputs. Preserve original JSON bytes and document
any log sanitization. No broad model, tenant-cohort or MCP rerun is required.
