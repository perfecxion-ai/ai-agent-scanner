# Scoped native asset-group retest

Use the full merged revision supplied with the handoff in a disposable clean
checkout. This gate needs Python, SQLite, and the server dependencies. It uses
owned synthetic data and its own loopback server. Existing lab services, secrets,
operator databases, profiles, schedules, and model calls are unnecessary.

The public script upgrades a frozen schema-6 fixture through real single-worker
Gunicorn, then checks grouping and finding history across 10,000 observations and
three organizations. Its producers use a complete-capture transport test double
without target sockets; the authenticated Gunicorn API uses real loopback HTTP.
These are
repeated observations, not 10,000 deployments or a sensitivity measurement.

## Run and capture

Set `AIS_ASSET_GROUP_REVISION` to the full merged SHA. Keep the environment and
captures outside the checkout. Run from a clean shell without sourcing lab
configuration:

```bash
set -eu
: "${AIS_ASSET_GROUP_REVISION:?Set the full merged SHA from the handoff}"
umask 077
test -z "$(git status --porcelain)"
git checkout --detach "$AIS_ASSET_GROUP_REVISION"
test "$(git rev-parse HEAD)" = "$AIS_ASSET_GROUP_REVISION"
AIS_GROUP_ROOT=$(mktemp -d)
AIS_GROUP_OUT="$AIS_GROUP_ROOT/captures"
mkdir "$AIS_GROUP_OUT"
python3 -m venv "$AIS_GROUP_ROOT/venv"
AIS_GROUP_PY="$AIS_GROUP_ROOT/venv/bin/python"
"$AIS_GROUP_PY" -m pip install '.[dev,server]' > "$AIS_GROUP_ROOT/install.log" 2>&1
export SCAN_EVIDENCE_PROFILES_FILE="$AIS_GROUP_ROOT/absent-operator-registry.json"
test ! -e "$SCAN_EVIDENCE_PROFILES_FILE"
git rev-parse HEAD > "$AIS_GROUP_OUT/revision.txt"
"$AIS_GROUP_PY" -m pip list --format=json > "$AIS_GROUP_OUT/dependencies.json"
"$AIS_GROUP_PY" -c 'import json, platform, sqlite3; print(json.dumps({"python": platform.python_version(), "sqlite": sqlite3.sqlite_version, "platform": platform.system()}))' > "$AIS_GROUP_OUT/runtime.json"
AIS_GROUP_FAILED=0
ais_group_capture() {
  AIS_GROUP_LABEL=$1
  shift
  if "$@" > "$AIS_GROUP_OUT/$AIS_GROUP_LABEL.json" 2> "$AIS_GROUP_OUT/$AIS_GROUP_LABEL.log"
  then
    printf '0\n' > "$AIS_GROUP_OUT/$AIS_GROUP_LABEL.exit"
  else
    AIS_GROUP_EXIT=$?
    printf '%s\n' "$AIS_GROUP_EXIT" > "$AIS_GROUP_OUT/$AIS_GROUP_LABEL.exit"
    AIS_GROUP_FAILED=1
  fi
}
ais_group_capture groups-normal "$AIS_GROUP_PY" scripts/acceptance-asset-groups.py --timeout-seconds 180
ais_group_capture groups-optimized "$AIS_GROUP_PY" -O scripts/acceptance-asset-groups.py --timeout-seconds 180
ais_group_capture backup-normal "$AIS_GROUP_PY" scripts/acceptance-backup-restore.py --timeout-seconds 5
ais_group_capture backup-optimized "$AIS_GROUP_PY" -O scripts/acceptance-backup-restore.py --timeout-seconds 5
if "$AIS_GROUP_PY" -Werror -m pytest -o asyncio_default_fixture_loop_scope=function \
  tests/test_asset_identity.py tests/test_asset_group_schema.py \
  tests/test_asset_groups.py tests/test_asset_group_review.py \
  tests/test_asset_group_prepared_reads.py tests/test_asset_group_prepared_review.py \
  tests/test_asset_group_api.py tests/test_asset_group_backup.py \
  tests/test_job_maintenance.py tests/test_asset_group_acceptance.py \
  -k 'not public_group_gate_runs_real_server' -q \
  > "$AIS_GROUP_OUT/focused-tests.log" 2>&1
then
  printf '0\n' > "$AIS_GROUP_OUT/focused-tests.exit"
else
  AIS_GROUP_EXIT=$?
  printf '%s\n' "$AIS_GROUP_EXIT" > "$AIS_GROUP_OUT/focused-tests.exit"
  AIS_GROUP_FAILED=1
fi
test -z "$(git status --porcelain)" || AIS_GROUP_FAILED=1
printf 'captured_gate_failure=%s\n' "$AIS_GROUP_FAILED" > "$AIS_GROUP_OUT/result.txt"
test "$AIS_GROUP_FAILED" -eq 0
```

All five exit captures must be zero. Both group receipts must report
`asset-group-acceptance-v1`, `accepted: true`, and 10,000 observations. Both backup
receipts must accept all fourteen cases. Preserve nonzero exits and diagnostics
when a gate fails. Do not replace a failed receipt with a successful retry.

## Acceptance boundary

The group gate checks complete group/history traversal, original occurrence
references, latest risk versus prior confirmations, tenant and cursor scope,
source changes, rollback, malformed-source refusal, exact source restoration,
and restart. Separate focused HTTP tests exercise cache changes followed by
publication-metadata restoration without racing background repair. The stopped
backup test includes a populated published cache.

Retain the receipts and focused test summary. They establish what the pinned
assertions checked; they do not independently attest target seeding or storage
durability under power loss. Review the captures for personal paths and secrets
before sharing. Return the captures and a brief report; exclude databases,
operator configuration, keys, evidence profiles, and the temporary environment.

This is a native SQLite and process-lifecycle retest. It does not measure model
detection sensitivity, prove credential or principal equivalence, or establish
PostgreSQL, distributed-server, or enterprise acceptance. Dashboard group views
and source-bound risk filtering remain separate increments.
