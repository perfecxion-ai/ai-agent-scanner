# Synthetic server HTTP acceptance

Run this gate from the reviewed source checkout after installing its server
dependencies. It starts an actual Gunicorn worker and dispatcher against fresh
private SQLite data and a synthetic startup registry. It does not use an operator
database, profile registry, credentials, model service or cloud target.

```bash
umask 077
SCAN_EVIDENCE_PROFILES_FILE=/tmp/aiscan-operator-registry-must-not-exist.json \
  python -Werror scripts/acceptance-server-http.py --timeout-seconds 240 \
  > server-http-acceptance.json
```

Retain the genuine command exit separately from the JSON receipt. Success
requires exit zero, `accepted: true` and every exact name in the pinned driver's
`REQUIRED_ASSERTIONS` list. A failed assertion, timeout, Python resource/runtime
warning, output limit, private-value observation, unknown process probe or
cleanup failure remains a failed gate. Never replace a failure with a later
successful command or a receipt from a different source revision.

A zero master exit cannot establish a clean worker exit. The gate also requires
one successful production cleanup-hook acknowledgement per observed normal
worker and checks bounded boot, signal, nonzero-exit, timeout and exception logs.
Only the single fresh-identity worker deliberately killed by this invocation
may omit its acknowledgement, with exactly its one matching SIGKILL event.
Duplicate, unowned or additional signals remain failures. Reaching the configured
graceful-shutdown boundary is conservatively unverified even if an earlier hook
acknowledgement exists, since a later master kill can lack a final reap log.
The shutdown clock starts before sending termination, so caller scheduling delay
after the signal cannot conceal that boundary.

The driver owns a short private directory under `/tmp` to keep its API socket
within POSIX pathname limits, including macOS. Its authenticated API requests
use HTTP over a private Unix socket. This avoids the inherited `fd://` listener
path's reproduced unclosed inspection socket in Gunicorn 26.2.0, without changing
scanner functions or suppressing warnings. The assessed application targets
still use actual loopback HTTP and verified HTTPS, including bearer
authentication and an explicitly untrusted certificate control. TCP, public and
reverse-proxy server deployment remain separate validation.

The finite workflow includes tenant-scoped previews, refused raw/mixed/forged
inputs, concurrent target contexts, complete vulnerable/defended samples,
partial unusable-response controls, API/inventory/JSON/SARIF consistency,
cancellation, outer timeout, and a real Gunicorn worker SIGKILL after an
acknowledged disclosure receipt. The master respawns its worker and the scanner
recovers without replay. Two later clean master restarts test queued removed
references and tightened current server scope before a target POST.

The work timeout is bounded to 30 through 240 seconds. All final cleanup shares
one deadline of at most 20 seconds, with an outer allowance capped below 300
seconds. The driver waits for actual owned master exits and verifies observed
descendants disappear. Forced or unverified cleanup cannot pass. Its small
receipt records source/build/helper identities, request counts, actual master
exits, process cleanup diagnostics and static warning metadata.
The separately recorded Gunicorn hook digest is checked before each start and
after execution; the library/app build identity does not cover that file.
Worker crash evidence records the signal and verified replacement; it does not invent a child
wait status unavailable to the driver.

Generated responses, registry files, keys, certificates, database contents and raw
logs are private temporary inputs and outputs removed afterward. The receipt
contains bounded known-value privacy checks, not a claim that arbitrary secrets
are absent. Preview checks observe zero target POSTs and unchanged admission
table rows; source/unit tests separately enforce the stronger no-DNS/no-database
preview contract. These deterministic fixtures establish a supported operator
workflow, not real-model sensitivity, stateful isolation or enterprise readiness.
