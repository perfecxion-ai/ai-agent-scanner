# Scoped inventory upgrade and traversal retest

Use the exact merged revision supplied with the handoff in a disposable clean
checkout. Make that revision available through the normal code-transfer path.
The public gate creates its own private schema-4 database, upgrades it through
real single-worker Gunicorn, and exercises 10,000 observations across three
synthetic organizations. Version 4 of the gate checks schema 4 to 8 cache
reconciliation, then deliberately restores the owned fixture's stale caches
before traversal. Snapshot selectors come from each actual produced target;
matching an alias alone cannot attach a different target's risk. These are repeated observations of 12 synthetic assets,
not 10,000 deployments or a model-sensitivity measurement.

The command accepts no operator database or configuration paths. It clears
inherited operator settings, uses only its own loopback API and synthetic
controlled-access producers, and removes its temporary fixtures and processes.
Existing lab databases, evidence profiles, secrets, target services, schedules,
and model servers are unnecessary for this gate.

## Run and capture

Set `AIS_INVENTORY_REVISION` to the full merged SHA from the handoff. The virtual
environment and captures live outside the checkout:

```bash
set -eu
: "${AIS_INVENTORY_REVISION:?Set the full merged SHA from the handoff}"
umask 077
test -z "$(git status --porcelain)"
git checkout --detach "$AIS_INVENTORY_REVISION"
test "$(git rev-parse HEAD)" = "$AIS_INVENTORY_REVISION"
AIS_INVENTORY_ROOT=$(mktemp -d)
AIS_INVENTORY_OUT="$AIS_INVENTORY_ROOT/captures"
mkdir "$AIS_INVENTORY_OUT"
python3 -m venv "$AIS_INVENTORY_ROOT/venv"
AIS_INVENTORY_PY="$AIS_INVENTORY_ROOT/venv/bin/python"
"$AIS_INVENTORY_PY" -m pip install '.[server]'
git rev-parse HEAD > "$AIS_INVENTORY_OUT/revision.txt"
"$AIS_INVENTORY_PY" -m pip list --format=json > "$AIS_INVENTORY_OUT/dependencies.json"
if "$AIS_INVENTORY_PY" scripts/acceptance-inventory.py --timeout-seconds 120 \
  > "$AIS_INVENTORY_OUT/inventory-normal.json" 2> "$AIS_INVENTORY_OUT/inventory-normal.log"
then
  printf '0\n' > "$AIS_INVENTORY_OUT/inventory-normal.exit"
else
  AIS_INVENTORY_EXIT=$?
  printf '%s\n' "$AIS_INVENTORY_EXIT" > "$AIS_INVENTORY_OUT/inventory-normal.exit"
  exit "$AIS_INVENTORY_EXIT"
fi
if "$AIS_INVENTORY_PY" -O scripts/acceptance-inventory.py --timeout-seconds 120 \
  > "$AIS_INVENTORY_OUT/inventory-optimized.json" 2> "$AIS_INVENTORY_OUT/inventory-optimized.log"
then
  printf '0\n' > "$AIS_INVENTORY_OUT/inventory-optimized.exit"
else
  AIS_INVENTORY_EXIT=$?
  printf '%s\n' "$AIS_INVENTORY_EXIT" > "$AIS_INVENTORY_OUT/inventory-optimized.exit"
  exit "$AIS_INVENTORY_EXIT"
fi
"$AIS_INVENTORY_PY" - "$AIS_INVENTORY_OUT" "$AIS_INVENTORY_REVISION" <<'PY'
import json
from pathlib import Path
import sys

root, revision = Path(sys.argv[1]), sys.argv[2]
for mode in ('normal', 'optimized'):
    value = json.loads((root / ('inventory-' + mode + '.json')).read_text())
    valid = (value.get('accepted') is True
             and value.get('format_version') == 'inventory-acceptance-v4'
             and value.get('observation_count') == 10000
             and value.get('schema_before') == 4
             and value.get('schema_after') == 8
             and value.get('schema_target') == 8
             and value.get('runtime', {}).get('source_revision') == revision
             and value.get('runtime', {}).get('tracked_source_modified') is False
             and value.get('server_exits') == [
                 {'phase': 'initial', 'returncode': 0},
                 {'phase': 'restart', 'returncode': 0}])
    if not valid:
        raise SystemExit('Inventory acceptance output did not match the pinned gate')
PY
```

Also capture normal and optimized
[backup/restore acceptance](jobs.md#disposable-backuprestore-acceptance) on this
same revision. Both commands must accept all fifteen cases, including frozen
schema-5, schema-6 and schema-7 sources and a genuinely initialized schema-8 source.

## What the gate establishes

The command compares full ordered observation dictionaries across eight filter
profiles and three organizations on first start and restart. It checks older
confirmed findings, genuine zero, historical unknowns, contradictory scalar
caches, tenant/cursor isolation, source changes, rollback, and unchanged restart
cursors. It verifies archives, existing row fields, an operator-style index,
recognized generation definitions, and absence of admitted work. Before restoring
stale test caches it checks canonical risk for all 12 scan summaries and 10,000
observations. It then proves exact original stale rows, archive preservation and
unchanged schema-8 restart, so traversal still exercises contradictory caches.
Temporary provider, model and endpoint mismatches on the newest confirmed
observation must withhold its risk and move it from the high filter to unknown.
Exact restoration returns the supported high verdict; a normalized default-port
HTTP endpoint retains it too. A saved report with duplicate JSON members must
return the static unavailable response, including for an otherwise empty risk
filter. These controls restore the exact original rows and archive bytes before
restart. All fifteen assertion names must match the pinned script. The original
10,000-observation oracle, filter counts and 120-second shared deadline remain.

Real process exits and final assertion identities are part of the result. Privacy
checks cover the mandatory synthetic/runtime secret set, HTTP response bodies and
headers, owned private files, and final output. Acceptance is emitted only after
process, socket, privacy, and fixture cleanup succeeds. Failure codes are static
and do not echo credentials, cursor values, private paths, or raw responses.

The output records interpreter, SQLite, Gunicorn, source revision, source policy,
driver/app/hook hashes, and whether tracked source changed. Local development
runs can record modified source; operator acceptance requires the clean pinned
revision check above. Source correctness and synthetic workload behavior do not
certify a deployed operator database or detection sensitivity.

## Return captures

Return the `captures` directory with both JSON results, their real exit files and
stderr logs, the revision/dependency records, and both backup-mode results/exits.
Successful inventory stderr logs are empty. Preserve any genuine failures rather
than rewriting them as success. Do not include the virtual environment, databases,
credentials, private configuration, or unrelated lab artifacts.
