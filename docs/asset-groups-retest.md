# Scoped native asset-group retest

Use the full merged revision supplied with the handoff in a disposable clean
checkout. This gate needs Python, SQLite, and the server dependencies. It uses
owned synthetic data and its own loopback server. Existing lab services, secrets,
operator databases, profiles, schedules, and model calls are unnecessary.

The public script upgrades a frozen schema-6 fixture to schema 8 through real
single-worker Gunicorn, then checks grouping and finding history across the
original 10,000 observations, three organizations and 24 groups. A separate fourth
organization adds five risk-control observations and five groups: three supported
70/high targets, an assessed zero and an unknown. The original traversal oracle
and 180-second shared deadline remain in force. Its producers use a complete-capture transport test double
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
AIS_GROUP_STATUS=$(git status --porcelain)
test -z "$AIS_GROUP_STATUS"
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
  tests/test_asset_group_risk.py tests/test_asset_group_risk_schema.py \
  tests/test_asset_group_risk_review.py \
  tests/test_asset_groups.py tests/test_asset_group_review.py \
  tests/test_asset_group_prepared_reads.py tests/test_asset_group_prepared_review.py \
  tests/test_asset_group_source_reads.py tests/test_asset_group_source_review.py \
  tests/test_asset_group_gate_retries.py tests/test_asset_group_cleanup_contention.py \
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
if git status --porcelain > "$AIS_GROUP_OUT/source-status.txt"
then
  test ! -s "$AIS_GROUP_OUT/source-status.txt" || AIS_GROUP_FAILED=1
else
  AIS_GROUP_FAILED=1
fi
printf 'captured_gate_failure=%s\n' "$AIS_GROUP_FAILED" > "$AIS_GROUP_OUT/result.txt"
test "$AIS_GROUP_FAILED" -eq 0
```

All five exit captures must be zero. Both group receipts must report
`asset-group-acceptance-v2`, `accepted: true`, schema before 6 and after/target 8,
and `observation_count: 10000`. The three `traversal_counts` entries must still sum
to 10,000 observations and contain eight groups each. `risk_fixture_counts` must
separately report five observations and five groups. All seventeen assertion names
must match the pinned script. Both backup receipts must accept all fifteen cases,
including the distinct frozen schema-7 and current schema-8 cases. Preserve nonzero exits and diagnostics
when a gate fails. Do not replace a failed receipt with a successful retry.

The group receipts include numeric `page_retries` counts for `initial` and
`restart`. Pagination retries only the documented
`503/asset_group_projection_unavailable` failure envelope, using the identical
cursor and request within the shared 180-second deadline. Each page permits at
most 25 retries with at most 0.2 seconds of backoff. Other statuses, malformed
responses, stale cursors and transport failures remain failures. This checks
eventual complete traversal within the budget, not uninterrupted availability.

## Acceptance boundary

The group gate checks complete group/history traversal, original occurrence
references, latest risk versus prior confirmations, tenant and cursor scope,
source changes, rollback, malformed-source refusal, exact source restoration,
and restart. It additionally compares each of the six risk-level filters against
identities and latest canonical risk derived independently from the original
pipeline sources. Filtered pages must retain ordering and exact canonical risk;
unknown scores stay null and assessed zero remains zero. The fourth owner's
three high targets force positive filtered pagination. Normalized filters retain
the cursor scope; changing or omitting the filter, changing the page limit,
cross-owner reuse, duplicate filters and history filters are refused. Restart
must reproduce every filter's count and complete-view digest. Results appear in
`risk_filter_counts` for all four owners and six levels. The positive owner must
have counts `high: 3`, `minimal: 1`, `unknown: 1`, and zero for the other levels.
An unreadable older source must also block a filter that would otherwise be
empty. Separate focused HTTP tests exercise cache changes followed by
publication-metadata restoration without racing background repair. The stopped
backup test includes a populated published cache. Eight private values, including
all four owner tokens, are checked across the same response, log and fixture
surfaces. The original inventory helper's seven-value sweep remains intact, with
an additional sweep for the fourth token.

Retain the receipts and focused test summary. They establish what the pinned
assertions checked; they do not independently attest target seeding or storage
durability under power loss. Review the captures for personal paths and secrets
before sharing. Return the captures and a brief report; exclude databases,
operator configuration, keys, evidence profiles, and the temporary environment.

This is a native SQLite and process-lifecycle retest. It does not measure model
detection sensitivity, prove credential or principal equivalence, or establish
PostgreSQL, distributed-server, or enterprise acceptance. Observation-index
acceleration for `/api/agents`, dashboard group views and logical findings remain
separate increments. Readiness still proves publication-wide source and row
counts before using the risk index; this gate does not establish unlimited scale
or continuous availability.
