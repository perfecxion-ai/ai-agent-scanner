# Scoped tenant interruption retest

Use the exact merged revision supplied in the handoff, after all delivery checks
pass. Keep the original tenant runs unchanged. This gate checks observation
retention against the existing tenant-aware HTTPS lab, not model sensitivity or
enterprise readiness. It does not require another cohort run.

## Fixture cases

Use the existing authorized lab and its private CLI configuration workflow. Do
not start cloud resources as part of this procedure. Each variant needs two
genuine issued tenant credentials and independently seeded synthetic records,
with the tested principal unauthorized for the owner's record. Keep TLS
certificate and hostname verification enabled. Do not edit scanner reports or
database rows to supply findings or controls.

Prepare one private config per case, containing one explicit agent. Change the
fixture's actual behavior for the named case, and record its revision/reset
policy. All variants must answer the ordinary model requests preceding tenant
testing promptly. The stall must apply to the specified tenant request, not an
earlier prompt or access check.

| Private config | Tenant behavior | Required result |
| --- | --- | --- |
| `subject-stall.json` | Owner control succeeds; tested control returns both markers; invalid credential returns a clean 401/403; first attack stalls beyond the scan deadline. | One subject receipt with ordinal 2 and counters 3/3; 90/critical, partial coverage, unfinished tenant check. |
| `attack-stall.json` | All controls succeed without a subject leak; first attack discloses the owner's marker; second attack stalls beyond the scan deadline. | One attack receipt with index 0, ordinal 4 and counters 4/4; 90/critical, partial coverage, unfinished tenant check. |
| `held-rejected.json` | Tested control returns both markers, then the invalid credential incorrectly receives success or a marker-bearing denial. | No tenant finding or receipt; no tenant attacks; no tenant pass or numeric assessment from these controls. |
| `defended.json` | All controls succeed and all five attacks disclose no foreign record. | Eight tenant requests, inconclusive tenant outcome, no tenant finding/receipt/pass. |

The two stalled requests should remain blocked for at least 300 seconds, or until
the client disconnects. The scanner's outer 180-second deadline must cancel them
before its individual request timeout. Return secret-free fixture counters that
prove which requests actually arrived and which responses were sent. A run that
times out before reaching the intended tenant request does not pass this gate.

## Capture genuine process exits

Set the full revision and private config directory, then run from an isolated
checkout. Supply fixture credentials and markers through its private environment,
as in the original tenant retest. Keep those values out of shell history and
returned artifacts. A loopback tunnel additionally needs `--allow-loopback`;
non-loopback plaintext remains refused.

```bash
set -eu
: "${AIS_PROGRESS_REVISION:?Set the full merged SHA from the handoff}"
: "${AIS_PROGRESS_CONFIG_DIR:?Set the private configuration directory}"
umask 077
test -z "$(git status --porcelain)"
git checkout --detach "$AIS_PROGRESS_REVISION"
test "$(git rev-parse HEAD)" = "$AIS_PROGRESS_REVISION"
python3 -m venv .venv-tenant-progress
.venv-tenant-progress/bin/python -m pip install '.[dev,server]'
AIS_PROGRESS_OUT=$(mktemp -d)
git rev-parse HEAD > "$AIS_PROGRESS_OUT/revision.txt"
.venv-tenant-progress/bin/ai-agent-scanner build-info --json > "$AIS_PROGRESS_OUT/build.json"
.venv-tenant-progress/bin/python --version > "$AIS_PROGRESS_OUT/python.txt" 2>&1
.venv-tenant-progress/bin/python -m pip list --format=json > "$AIS_PROGRESS_OUT/dependencies.json"
for AIS_PROGRESS_CASE in subject-stall attack-stall held-rejected defended
do
  AIS_PROGRESS_PREFIX="$AIS_PROGRESS_OUT/$AIS_PROGRESS_CASE"
  if .venv-tenant-progress/bin/ai-agent-scanner scan \
      --config "$AIS_PROGRESS_CONFIG_DIR/$AIS_PROGRESS_CASE.json" \
      --max-requests 500 --max-response-bytes 1048576 \
      --timeout-seconds 180 --request-timeout-seconds 300 \
      --output "$AIS_PROGRESS_PREFIX.json" > "$AIS_PROGRESS_PREFIX.log" 2>&1
  then
    printf '0\n' > "$AIS_PROGRESS_PREFIX.exit"
  else
    AIS_PROGRESS_EXIT=$?
    printf '%s\n' "$AIS_PROGRESS_EXIT" > "$AIS_PROGRESS_PREFIX.exit"
  fi
done
if .venv-tenant-progress/bin/python -m pytest -q -W error \
    tests/test_tenant_progress_recovery.py > "$AIS_PROGRESS_OUT/recovery.log" 2>&1
then
  printf '0\n' > "$AIS_PROGRESS_OUT/recovery.exit"
else
  AIS_PROGRESS_EXIT=$?
  printf '%s\n' "$AIS_PROGRESS_EXIT" > "$AIS_PROGRESS_OUT/recovery.exit"
fi
```

These commands capture outcomes; they do not declare acceptance. Make the final
analysis and privacy gate fail with a nonzero exit when any required assertion
fails. Preserve missing reports and unexpected exits as failures. Do not infer
success from the outer shell completing.

## Acceptance and returned bundle

For each stalled case, require the real nonzero deadline exit and JSON status
`failed`, asset security status `partial`, checkpoint `3.0`, mixed ledger `2.0`,
90/critical with partial coverage, and `checks_unfinished: 1`. The tenant check
must have no invented terminal record. The receipt's original finding ID must
match the retained vulnerability. Its control proof must contain ordinals
`[1, 2, 3]` and the actual two successful statuses followed by 401/403. Only
configured tenant evidence should contribute the expected score in this fixture;
explain any independent finding rather than silently filtering it out.

Both negative cases should finish without a deadline. The deliberately failed
control in held-rejected produces a failed tenant check, partial report and CLI
exit 1. Defended should complete with an inconclusive tenant check and CLI exit 0
when no other phase fails. Missing controls, other failed requests or a different
partial outcome require investigation; absence of findings alone is insufficient.
No quiet outcome resolves a prior leak. Inspect tenant-specific evidence
separately from unrelated exposure observations produced by the ordinary CLI scan.

The two native recovery tests must pass. They exercise actual library workers,
acknowledged SQLite commits, process kills and authenticated reads of recovered
evidence. They do not enable private tenant inputs in the server API or establish
CLI recovery after forced process termination.

Return the four JSON reports, logs, genuine exit files, native recovery log/exit,
revision, build identity, dependency versions, secret-free fixture counters and a
brief assertion table. Reports must retain their original bytes and producer
identity. Never bundle private configs, environments, database files, keys,
canaries, principal labels, raw generated text or fixture authorization logs.

Before bundling, scan every returned file against the actual private values and
known URL/JSON/base64 forms, including environment references, principal labels
and generated invalid credentials available in private fixture captures. Check
generated-text fields and owner-only output modes too. Record the exact file
count, sweep scope and outcome without printing protected values. Unreadable
files, analysis failures, privacy failures and cleanup failures must not be
reported as a successful gate. Keep original captures and all prior bundles.
