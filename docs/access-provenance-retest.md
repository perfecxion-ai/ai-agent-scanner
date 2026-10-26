# Scoped access provenance and cache upgrade retest

Run the exact merged revision supplied with the handoff on the existing lab
runner. This gate needs no model services, private configurations, tenant records,
operator databases or deployment changes. It creates its own synthetic HTTP/HTTPS
resources and disposable SQLite databases. It does not start cloud infrastructure.

This is native-platform correctness acceptance for four protected GET families
and the schema-6 policy upgrade. It is not a model-sensitivity or enterprise gate.
The earlier tenant retest remains accepted within its recorded scope.

## Execution

Use a clean isolated checkout. Set `AIS_ACCESS_REVISION` to the full merged SHA
from the handoff. Keep prior outputs unchanged and use a new private directory.
The environment and captures below live outside the checkout.

```bash
set -eu
: "${AIS_ACCESS_REVISION:?Set the full merged SHA from the handoff}"
umask 077
test -z "$(git status --porcelain)"
git checkout --detach "$AIS_ACCESS_REVISION"
test "$(git rev-parse HEAD)" = "$AIS_ACCESS_REVISION"
AIS_ACCESS_ROOT=$(mktemp -d)
AIS_ACCESS_OUT="$AIS_ACCESS_ROOT/captures"
mkdir "$AIS_ACCESS_OUT"
export SCAN_EVIDENCE_PROFILES_FILE="$AIS_ACCESS_ROOT/no-operator-evidence-profiles.json"
python3 -m venv "$AIS_ACCESS_ROOT/venv"
AIS_ACCESS_PY="$AIS_ACCESS_ROOT/venv/bin/python"
"$AIS_ACCESS_PY" -m pip install '.[dev,server]'
git rev-parse HEAD > "$AIS_ACCESS_OUT/revision.txt"
"$AIS_ACCESS_ROOT/venv/bin/ai-agent-scanner" build-info --json > "$AIS_ACCESS_OUT/build.json"
"$AIS_ACCESS_PY" -m pip list --format=json > "$AIS_ACCESS_OUT/dependencies.json"
"$AIS_ACCESS_PY" -c 'import sys,sqlite3; print(sys.version); print(sqlite3.sqlite_version)' \
  > "$AIS_ACCESS_OUT/runtime.txt"
AIS_ACCESS_FAILED=0
if "$AIS_ACCESS_PY" -m pytest -q -W error \
    tests/test_access_request_provenance.py \
    tests/test_access_provenance_independent.py \
    tests/test_access_cache_policy_upgrade.py \
    tests/test_access_log_privacy.py \
    tests/test_access_https_workflow.py > "$AIS_ACCESS_OUT/access-tests.log" 2>&1
then
  printf '0\n' > "$AIS_ACCESS_OUT/access-tests.exit"
else
  AIS_ACCESS_EXIT=$?
  printf '%s\n' "$AIS_ACCESS_EXIT" > "$AIS_ACCESS_OUT/access-tests.exit"
  AIS_ACCESS_FAILED=1
fi
access_gate_python() {
  if [ "$AIS_ACCESS_MODE" = optimized ]; then
    "$AIS_ACCESS_PY" -O "$@"
  else
    "$AIS_ACCESS_PY" "$@"
  fi
}
for AIS_ACCESS_MODE in normal optimized
do
  for AIS_ACCESS_GATE in backup-restore inventory
  do
    if [ "$AIS_ACCESS_GATE" = backup-restore ]; then
      AIS_ACCESS_LIMIT=5
    else
      AIS_ACCESS_LIMIT=120
    fi
    AIS_ACCESS_PREFIX="$AIS_ACCESS_OUT/$AIS_ACCESS_GATE-$AIS_ACCESS_MODE"
    if access_gate_python "scripts/acceptance-$AIS_ACCESS_GATE.py" --timeout-seconds "$AIS_ACCESS_LIMIT" \
        > "$AIS_ACCESS_PREFIX.json" 2> "$AIS_ACCESS_PREFIX.log"
    then
      printf '0\n' > "$AIS_ACCESS_PREFIX.exit"
    else
      AIS_ACCESS_EXIT=$?
      printf '%s\n' "$AIS_ACCESS_EXIT" > "$AIS_ACCESS_PREFIX.exit"
      AIS_ACCESS_FAILED=1
    fi
  done
done
git status --porcelain > "$AIS_ACCESS_OUT/source-status.txt"
test ! -s "$AIS_ACCESS_OUT/source-status.txt" || AIS_ACCESS_FAILED=1
printf '%s\n' "$AIS_ACCESS_FAILED" > "$AIS_ACCESS_OUT/driver.exit"
test "$AIS_ACCESS_FAILED" -eq 0
```

Preserve genuine nonzero exits and absent outputs. Setup failures exit before
`driver.exit` exists. When produced, that file must be nonzero if any captured
command fails, and the final shell test propagates the failure. Job wrappers must
preserve it; an outer shell completing is not acceptance. Do not turn a failed
analysis or cleanup into success. The profile-registry environment override points
only to an absent file in the disposable directory, never an operator registry.

## Required results

The five test files must pass with warnings as errors. They cover actual outbound
marker/credential injection, missing or wrong captures, pinned credentials,
disclosing or malformed denials, unchanged old archive bytes, conservative v2
risk/resolution, schema rollback and current scalar caches. The HTTPS cases use
real certificate and hostname verification through the CLI/pipeline/scorer and
JSON/SARIF exports, including genuine zero, high/critical and partial findings.
They do not add protected-access receipts inside unfinished checks.
The log cases verify normal CLI phase logging without exposing protected values
placed in an asset name.

Both backup modes must return exit zero and `accepted: true` for all thirteen
cases, including frozen schema 5, fresh schema 6 and rollback before stamping.
They preserve original sources/backup hashes and exact archived reports while
reconciling obsolete access-only scores to SQL NULL. Genuine current zero,
confirmed partial evidence and independent tenant risk remain supported.

Both inventory modes must return exit zero, format `inventory-acceptance-v2`,
`accepted: true`, schema before/after 4/6 and all thirteen required assertion
identities. The gate checks canonical caches before restoring its own deliberate
stale cache values, then traverses 10,000 repeated observations and restarts.
Require unchanged archives/non-cache fields, correct filter totals and clean
server-process exits. This is an owned fixture upgrade, not an operator database
migration or a distinct-asset benchmark.

Require exact revision, matching build identity and unchanged tracked source.
Capture the real exits separately from JSON status. Check every returned file
for unexpected fixture secrets, generated text, private paths and unreadable
content before bundling; distinguish public test constants from generated runtime
values. Reports/logs from failed tests can contain diagnostic fixture details and
must be reviewed before sharing. Do not return databases, virtual environments,
credentials, private configuration, certificates or unrelated prior lab outputs.

Return the capture directory, an assertion table and any honest failure notes.
Record exactly which files the final privacy sweep checked and whether logs were
sanitized. No broad model, MCP or tenant-cohort rerun is needed for this gate.
