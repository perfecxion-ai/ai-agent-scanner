# Scoped native server HTTP retest

Run once after the reviewed merge passes required CI. Replace
`REVIEWED_MERGE_SHA` with the full 40-character merge SHA supplied in the
handoff. Use the same revision throughout; a branch name or older bundle is not
an acceptable substitute.

This is one actual Gunicorn and dispatcher gate over owned loopback HTTP and
verified HTTPS fixtures, with fresh private SQLite and registry inputs. It needs
POSIX, Python 3.10 or later, Git and package-index access for a fresh server venv.
It does not need existing models, GCP services, operator configuration, profiles,
credentials or databases. Do not source lab configuration, run older archive
scripts, repeat broad pytest/model gates or change the global certificate store.

Submit the following as a new native job, leaving earlier jobs unchanged. Keep
the job's actual outer `EXIT` capture in addition to `pinned-block.exit` and
`driver.exit`; the native jobloop must record the submitted script's genuine exit
and enforce its existing setup/job deadline. The driver itself has a 240-second
work limit and its unchanged shared cleanup cap of 20 seconds, with its outer
allowance below 300 seconds. No second watchdog or cleanup mode is added here.

```sh
#!/bin/sh
set -eu
umask 077
revision=REVIEWED_MERGE_SHA
case "$revision" in ''|*[!0-9a-f]*) exit 2;; esac
test "${#revision}" -eq 40
root=$(mktemp -d /tmp/aiscan-server-http-native.XXXXXX)
mkdir "$root/captures" "$root/work"
printf '%s\n' "$root/captures"
set +e
env -i PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin \
  TMPDIR="$root/work" PYTHONUTF8=1 PYTHONNOUSERSITE=1 \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
  SCAN_EVIDENCE_PROFILES_FILE=/tmp/aiscan-operator-registry-must-not-exist.json \
  /bin/sh -s -- "$revision" "$root" \
  > "$root/captures/pinned-block.stdout" \
  2> "$root/captures/pinned-block.stderr" <<'PINNED'
set -eu
revision=$1
root=$2
captures=$root/captures
source=$root/work/source
venv=$root/work/venv
printf '%s\n' "$revision" > "$captures/requested-revision.txt"
run() {
  name=$1
  shift
  set +e
  "$@" > "$captures/$name.stdout" 2> "$captures/$name.stderr"
  code=$?
  set -e
  printf '%s\n' "$code" > "$captures/$name.exit"
  return "$code"
}
run source-init git init "$source"
run source-fetch git -C "$source" -c credential.helper= \
  fetch --depth=1 --no-tags \
  https://github.com/perfecxion-ai/ai-agent-scanner.git "$revision"
run source-checkout git -C "$source" -c core.hooksPath=/dev/null \
  checkout --detach FETCH_HEAD
run source-head git -C "$source" rev-parse HEAD
test "$(cat "$captures/source-head.stdout")" = "$revision"
run venv python3 -I -Werror -m venv "$venv"
run install "$venv/bin/python" -I -Werror -m pip --isolated install \
  --no-input --no-cache-dir "$source[server]"
run dependencies "$venv/bin/python" -I -Werror -m pip --isolated list --format=json
cat > "$captures/runtime-source.py" <<'PY'
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import sqlite3
import ssl
import subprocess
import sys

root = Path(sys.argv[1]).resolve(strict=True)
status = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'])
assert status == b'', 'Source checkout must be clean'
files = ('app.py', 'gunicorn.conf.py', 'src/core/jobs.py', 'src/core/transport.py',
         'src/core/scope.py', 'src/core/evidence_profiles.py',
         'src/core/server_http_profiles.py', 'scripts/acceptance-server-http.py',
         'scripts/acceptance-http-assessment.py')
sys.path.insert(0, str(root))
from src.core.build_identity import current_identity
print(json.dumps({'python': sys.version, 'platform': platform.system(),
    'machine': platform.machine(), 'sqlite': sqlite3.sqlite_version,
    'openssl': ssl.OPENSSL_VERSION, 'source_status': status.decode(),
    'revision': subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
    'dependencies': {name: importlib.metadata.version(name) for name in
                     ('ai-agent-scanner', 'aiohttp', 'gunicorn', 'psutil')},
    'components': {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                   for name in files},
    'producer_identity': current_identity(component='server')}, sort_keys=True))
PY
run runtime-source-before "$venv/bin/python" -I -Werror \
  "$captures/runtime-source.py" "$source"
cd "$source"
driver_code=0
run driver "$venv/bin/python" -Werror scripts/acceptance-server-http.py \
  --timeout-seconds 240 || driver_code=$?
# Preserve the actual driver failure even when subsequent captures succeed.
post_code=0
run runtime-source-after "$venv/bin/python" -I -Werror \
  "$captures/runtime-source.py" "$source" || post_code=$?
if test "$post_code" -eq 0; then
  run unchanged-runtime-source cmp "$captures/runtime-source-before.stdout" \
    "$captures/runtime-source-after.stdout" || post_code=$?
fi
if test "$driver_code" -ne 0; then exit "$driver_code"; fi
if test "$post_code" -ne 0; then exit "$post_code"; fi
cd "$root"
# Only this fresh private work tree is removed, after the driver's clean exit.
# On failure, retain it privately for review; do not signal unrelated processes.
test ! -L "$root/work"
rm -rf "$root/work"
test ! -e "$root/work"
printf '%s\n' removed > "$captures/work-cleanup.txt"
PINNED
block_code=$?
set -e
printf '%s\n' "$block_code" > "$root/captures/pinned-block.exit"
exit "$block_code"
```

Keep the complete private capture directory, the exact submitted job script and
its enclosing job `EXIT`. Setup failures stop dependent steps; missing files,
nonzero exits or retained work require review. Do not overwrite raw stdout,
stderr or failed receipts with edited copies or a later retry. The dependency
inventory is an observation, not a lockfile or proof of an identical environment.
The setup commands rely on the native runner's job deadline and containment;
they are not separately certified by the scanner's bounded runtime gate.

Acceptance requires `driver.exit`, `pinned-block.exit` and the enclosing job exit
all zero; `driver.stdout` must contain `accepted: true` and all 15 exact ordered
assertion names from the pinned driver. Check every captured step exit, the empty
source status and equal before/after source manifests, and `work-cleanup.txt`.
Review `driver.stderr` as well as the receipt's warning and cleanup records. A
zero master exit alone cannot prove a clean worker exit. Preserve genuine
SIGKILL/recovery evidence as recorded by the driver; do not invent child wait
statuses. A failure remains failed even when earlier workflow assertions passed.

Share only a separately reviewed copy, with original/shared hashes if anything
is redacted. Do not include retained work, databases, registry inputs, private
keys, certificates or generated response excerpts. The driver's known-value
privacy sweep is scoped evidence, not proof that arbitrary secrets are absent.

This retest establishes the synthetic source/server workflow on the recorded
native runtime. Its API uses a private Unix socket; TCP/public/proxy deployment,
real-model sensitivity, stateful sessions and enterprise readiness remain
separate gates. See [the acceptance contract](server-http-acceptance.md).
