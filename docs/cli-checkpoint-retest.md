# Scoped native CLI checkpoint retest

Run this on the existing native runner at the full merged revision from the
handoff. It creates owned loopback HTTPS services, temporary scan configurations
and private checkpoint directories. It needs no model services, operator
configuration, database, target VM, deployment change or cloud startup.

The gate checks POSIX process-kill recovery, bounded private file handling and
offline export on the runner's interpreter and filesystem. It does not measure
model sensitivity or certify power loss, deployed storage or enterprise readiness.

## Execution

Use a clean isolated checkout and Bash. Set `AIS_CLI_CHECKPOINT_REVISION` to the
full merged SHA from the handoff, then run this block. Its environment and trap
remain inside the subshell. Keep prior captures unchanged.

```bash
(
set -eu
: "${AIS_CLI_CHECKPOINT_REVISION:?Set the full merged SHA from the handoff}"
umask 077
test -z "$(git status --porcelain)"
git checkout --detach "$AIS_CLI_CHECKPOINT_REVISION"
test "$(git rev-parse HEAD)" = "$AIS_CLI_CHECKPOINT_REVISION"
AIS_CLI_CHECKPOINT_ROOT=$(mktemp -d)
AIS_CLI_CHECKPOINT_ROOT=$(cd "$AIS_CLI_CHECKPOINT_ROOT" && pwd -P)
AIS_CLI_CHECKPOINT_OUT="$AIS_CLI_CHECKPOINT_ROOT/captures"
mkdir "$AIS_CLI_CHECKPOINT_OUT"
AIS_CLI_CHECKPOINT_FAILED=0
cli_checkpoint_finish() {
  AIS_CLI_CHECKPOINT_STATUS=$?
  trap - EXIT
  if [ "$AIS_CLI_CHECKPOINT_STATUS" -eq 0 ] && [ "$AIS_CLI_CHECKPOINT_FAILED" -ne 0 ]; then
    AIS_CLI_CHECKPOINT_STATUS=1
  fi
  printf '%s\n' "$AIS_CLI_CHECKPOINT_STATUS" > "$AIS_CLI_CHECKPOINT_OUT/driver.exit" || exit 7
  exit "$AIS_CLI_CHECKPOINT_STATUS"
}
trap cli_checkpoint_finish EXIT
printf 'Captures: %s\n' "$AIS_CLI_CHECKPOINT_OUT"
export SCAN_EVIDENCE_PROFILES_FILE="$AIS_CLI_CHECKPOINT_ROOT/no-operator-evidence-profiles.json"
python3 -m venv "$AIS_CLI_CHECKPOINT_ROOT/venv"
AIS_CLI_CHECKPOINT_PY="$AIS_CLI_CHECKPOINT_ROOT/venv/bin/python"
export PATH="$AIS_CLI_CHECKPOINT_ROOT/venv/bin:$PATH"
"$AIS_CLI_CHECKPOINT_PY" -m pip install '.[dev,server]'
git rev-parse HEAD > "$AIS_CLI_CHECKPOINT_OUT/revision.txt"
"$AIS_CLI_CHECKPOINT_ROOT/venv/bin/ai-agent-scanner" build-info --json \
  > "$AIS_CLI_CHECKPOINT_OUT/build.json"
"$AIS_CLI_CHECKPOINT_PY" -m pip list --format=json \
  > "$AIS_CLI_CHECKPOINT_OUT/dependencies.json"
"$AIS_CLI_CHECKPOINT_PY" -c 'import sys; print(sys.version)' \
  > "$AIS_CLI_CHECKPOINT_OUT/runtime.txt"
if "$AIS_CLI_CHECKPOINT_PY" -m pytest -q -W error \
    tests/test_cli_checkpoint_store.py \
    tests/test_cli_checkpoint_integration.py \
    tests/test_cli_checkpoint_process.py \
    --basetemp "$AIS_CLI_CHECKPOINT_ROOT/fixtures" \
    > "$AIS_CLI_CHECKPOINT_OUT/checkpoint-tests.log" 2>&1
then
  printf '0\n' > "$AIS_CLI_CHECKPOINT_OUT/checkpoint-tests.exit"
else
  AIS_CLI_CHECKPOINT_EXIT=$?
  printf '%s\n' "$AIS_CLI_CHECKPOINT_EXIT" > "$AIS_CLI_CHECKPOINT_OUT/checkpoint-tests.exit"
  AIS_CLI_CHECKPOINT_FAILED=1
fi
if "$AIS_CLI_CHECKPOINT_PY" -m build --outdir "$AIS_CLI_CHECKPOINT_ROOT/dist" \
    > "$AIS_CLI_CHECKPOINT_OUT/build.log" 2>&1
then
  printf '0\n' > "$AIS_CLI_CHECKPOINT_OUT/build.exit"
else
  AIS_CLI_CHECKPOINT_EXIT=$?
  printf '%s\n' "$AIS_CLI_CHECKPOINT_EXIT" > "$AIS_CLI_CHECKPOINT_OUT/build.exit"
  AIS_CLI_CHECKPOINT_FAILED=1
fi
if "$AIS_CLI_CHECKPOINT_PY" -m twine check "$AIS_CLI_CHECKPOINT_ROOT"/dist/* \
    > "$AIS_CLI_CHECKPOINT_OUT/distribution-check.log" 2>&1
then
  printf '0\n' > "$AIS_CLI_CHECKPOINT_OUT/distribution-check.exit"
else
  AIS_CLI_CHECKPOINT_EXIT=$?
  printf '%s\n' "$AIS_CLI_CHECKPOINT_EXIT" > "$AIS_CLI_CHECKPOINT_OUT/distribution-check.exit"
  AIS_CLI_CHECKPOINT_FAILED=1
fi
if sh scripts/package-smoke.sh "$AIS_CLI_CHECKPOINT_ROOT"/dist/*.whl \
    > "$AIS_CLI_CHECKPOINT_OUT/installed-smoke.log" 2>&1
then
  printf '0\n' > "$AIS_CLI_CHECKPOINT_OUT/installed-smoke.exit"
else
  AIS_CLI_CHECKPOINT_EXIT=$?
  printf '%s\n' "$AIS_CLI_CHECKPOINT_EXIT" > "$AIS_CLI_CHECKPOINT_OUT/installed-smoke.exit"
  AIS_CLI_CHECKPOINT_FAILED=1
fi
git status --porcelain > "$AIS_CLI_CHECKPOINT_OUT/source-status.txt"
test ! -s "$AIS_CLI_CHECKPOINT_OUT/source-status.txt" || AIS_CLI_CHECKPOINT_FAILED=1
test "$AIS_CLI_CHECKPOINT_FAILED" -eq 0
)
```

The trap records setup and captured-command failure after the capture directory
exists. An absent exit file or missing output is not success. Preserve the outer
job's genuine exit, including analysis, copy, sanitization or cleanup failures.
Keep the private outer environment and fixtures out of the returned bundle;
remove them after retaining and reviewing the requested captures.

## Required results

All 119 cases in the three test files must pass without skips or warnings. Four
cases run the unmodified production CLI against owned verified HTTPS fixtures.
They wait for
an on-disk finding and the next actual stalled request, kill and reap the CLI,
then recover through fresh production CLI processes. Require exact retained
receipts, finding IDs, control proof, producer identity and unchanged saved bytes.
Prompt and access-high cases retain 70/high; tenant and access-critical cases
retain 90/critical. Both JSON and SARIF exports stay partial and exit nonzero.
Recovery sends no more requests. Its network, database, process and private-input
guards have separate positive-control tests.

File and integration tests must reject malformed, oversized, unsafe or
inconsistent input, preserve evidence through write failures, refuse live-owner
recovery and keep cancellations truthful. Files remain owner-only, and optional
checkpoint handling must not change default execution.

Build, distribution check and installed-wheel smoke must each exit zero. The
installed CLI must preserve the completed owned discovery report through offline
recovery, with unknown risk and private file modes. No package is published.

Return the capture inventory, exact revision, build identity, runtime and
dependencies, test/build/smoke logs, real step and job exits, source status and an
assertion table with failures preserved. Review every returned file for fixture
secrets, generated text and private paths; record the actual sweep and sanitizer
coverage. Preserve original JSON bytes and record any log changes. Do not return
temporary configs, checkpoint fixtures, certificates, environments, databases or
unrelated outputs. No broad model, tenant-cohort, MCP, backup or inventory rerun
is needed for this file-only slice.
