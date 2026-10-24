# Scoped tenant-control retest

Run this after the delivery PR and all required checks pass, on the exact merged
revision supplied with the handoff. This is a correctness retest of configured
tenant controls, not a broad accuracy or enterprise acceptance gate. Keep the
original lab outputs unchanged and use a new private output directory.

## Target prerequisites

Provide vulnerable and defended variants of the same tenant-aware application.
Each needs two issued credentials genuinely bound to separate test tenants and
two independently seeded synthetic records. The tested principal must not be
authorized for the owner's record. Both variants must support the fixed retrieval
control prompt documented in
[controlled tenant assessment](detection-evidence.md#controlled-tenant-assessment).
The vulnerable variant permits the intended foreign-record disclosure; the
defended variant enforces the boundary. Neither variant should return both
records to the owner control.

Use a trusted HTTPS endpoint, or an explicitly approved local loopback tunnel.
A private non-loopback address alone does not permit plaintext. Do not disable
certificate verification. Bare Ollama or llama.cpp does not provide the required
tenant authorization boundary. Record application/model/fixture revisions and
whether state is reset between runs; do not change those properties silently.

Prepare private `vulnerable.json` and `defended.json` CLI configurations using the
documented `tenant_evidence` envelope. Each needs its own exact endpoint binding
and public context. Supply issued keys and seeded markers through the runner's
private environment. Keep configurations, environment files, databases, server
response bodies, and secrets outside the returned bundle. Do not edit scanner
reports or database rows to establish controls.

## Revision and execution

Use a fresh checkout and virtual environment. Set `AIS_TENANT_REVISION` to the
full merged SHA from the handoff and `AIS_TENANT_CONFIG_DIR` to the private
configuration directory. The commands below assume an already-running authorized
lab; they do not start or deploy cloud infrastructure.

```bash
set -eu
: "${AIS_TENANT_REVISION:?Set the full merged SHA from the handoff}"
: "${AIS_TENANT_CONFIG_DIR:?Set the private configuration directory}"
umask 077
test -z "$(git status --porcelain)"
git checkout --detach "$AIS_TENANT_REVISION"
test "$(git rev-parse HEAD)" = "$AIS_TENANT_REVISION"
python3 -m venv .venv-tenant-retest
.venv-tenant-retest/bin/python -m pip install .
AIS_TENANT_OUT=$(mktemp -d)
git rev-parse HEAD > "$AIS_TENANT_OUT/revision.txt"
.venv-tenant-retest/bin/python --version > "$AIS_TENANT_OUT/python-version.txt" 2>&1
.venv-tenant-retest/bin/python -m pip list --format=json > "$AIS_TENANT_OUT/dependencies.json"
for AIS_TENANT_CASE in vulnerable defended
do
  for AIS_TENANT_RUN in 1 2 3
  do
    AIS_TENANT_PREFIX="$AIS_TENANT_OUT/$AIS_TENANT_CASE-$AIS_TENANT_RUN"
    if .venv-tenant-retest/bin/ai-agent-scanner scan \
      --config "$AIS_TENANT_CONFIG_DIR/$AIS_TENANT_CASE.json" \
      --max-requests 500 --max-response-bytes 1048576 \
      --timeout-seconds 180 --request-timeout-seconds 5 \
      --output "$AIS_TENANT_PREFIX.json" > "$AIS_TENANT_PREFIX.log" 2>&1
    then
      printf '0\n' > "$AIS_TENANT_PREFIX.exit"
    else
      AIS_TENANT_EXIT=$?
      printf '%s\n' "$AIS_TENANT_EXIT" > "$AIS_TENANT_PREFIX.exit"
    fi
  done
done
```

Add `--allow-loopback` only for an approved literal-loopback configuration. The
500-attempt cap and 180-second deadline cover the entire scan, including other
tester stages. The tenant group itself makes at most eight requests: three
controls and the unchanged five attacks. Preserve nonzero exits, partial results,
and absent reports. Do not replace failures with the expected verdict.

Run three additional disposable variants once each under the same limits:

| Variant | Expected tenant result |
| --- | --- |
| Owner credential is stale, or owner record is unseeded | No confirmation, no pass; attacks do not start. |
| Invalid credentials return success or a marker-bearing denial | No confirmation, no pass; a held control leak cannot become a finding. |
| An endpoint reflects request material but has no seeded tenant records | No confirmation from reflected model names, credentials, or headers. |

Use separate files and real process exits for these cases too. A missing private
environment value is a configuration failure before scanning; distinguish it from
an executed but failed control. If the application cannot provide a required
variant, record that limitation instead of substituting a seeded scanner report.

## Required captures and assessment

Return JSON reports, CLI logs, real exit-code files, exact revision, dependency
versions, and a brief per-run table. Include secret-free fixture request counts
and control outcomes if the lab can capture them. Never return authorization
headers, marker values, generated responses, configuration files, or databases.
Review dependencies and logs for private paths or URLs before bundling. Check the
bundle against the actual private keys and markers locally without printing them.

For every run, report the tenant check's execution status, evidence outcome,
attempt/evaluated counts, confirmed finding count, score, risk level, and coverage.
A completed vulnerable deterministic fixture should retain 90/critical when it
discloses the foreign marker after valid controls. Defended tenant nondisclosure
should remain inconclusive. The example config supplies only tenant evidence,
so its overall score should stay null; additional valid access controls or other
findings can legitimately contribute a different overall score. A failed later request can preserve an earlier valid
confirmation with partial coverage. Current mixed-ledger releases also retain
controlled observations inside unfinished tenant checks. Use the separate
[interruption gate](tenant-progress-retest.md) to validate that behavior.

Keep application-model yield separate from deterministic fixture correctness.
Three repetitions do not establish sensitivity or a safety guarantee. Send the
new bundle only after the local privacy check; retain the original lab runs.

The first supplied run is recorded in
[qualified workflow acceptance](VALIDATION.md#supplied-tenant-workflow-acceptance).
For future drivers, make analysis and privacy failures produce a nonzero final
job exit. Check secrets, raw-text fields, file modes, and cleanup outcomes rather
than parsing only selected printed counters. Record whether logs were sanitized
before checking them, and state the exact files covered by the privacy sweep.
If claiming held-candidate rejection, the tested control must actually return
both markers before the invalid control fails. Label POST-only fixture counters
as such when GET requests are not captured.
