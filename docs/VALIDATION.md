# Engineering validation checkpoint

Date: 2026-10-21. This records the beta build-out, not a release certification.
The beta is now held following external lab validation of verdict accuracy,
mixed-network workflows, evidence privacy, and macOS temporary-path handling.
The historical green results below do not overrule those reproductions. Follow
the [remediation gate](BETA_REMEDIATION.md) for current acceptance requirements.
The first checkpoint followed PRs #1 through #14. PRs #15 through #22 add
discovery, check contracts, SQLite upgrades/audit history, local queue acceptance,
and dashboard evidence views. None of these merges publishes a package.
PRs #24 through #26 add cross-version timeout accounting, conservative network
inventories, and scoped read-only live MCP collection.
PR #28 updates current TGI recognition and its conservative historical boundary.
PRs #29 and #30 add controlled protected MCP inventory checks and tenant-owned
API templates with an exact SQLite version 1 to 2 upgrade.
PRs #32 and #33 add manual dashboard template controls and finite API schedules
with exact SQLite upgrades to schema version 3.
PR #35 adds reviewed-pin dashboard schedules and targeted keyboard acceptance.
PR #37 adds the remediated certifi dependency floor. PR #38 adds focused
accessibility improvements and a reusable optional Chromium smoke workflow.
PR #40 adds disposable stopped-SQLite backup/restore and recovery acceptance.
PR #41 fixes offline replay detection of protected canaries in argument keys.
PR #42 closes the local-beta acceptance slice with a real offline operator flow,
authenticated container restart checks, corrected setup, and a finite test guide.

## Automated checks

### Remediation infrastructure slice

The first remediation slice passes 1120 local Linux/Python 3.10 tests, Ruff, and
the configured Bandit gate. Fifty-seven focused cases cover report permissions,
atomic replacement, failed-write preservation, symlink rejection, and disposable
backup behavior. Both normal and optimized backup commands pass all eight cases.
A synthetic symlinked temporary ancestor passes in both modes and is cleaned up;
owned child/database symlinks remain rejected. A new native macOS CI job must
pass before claiming macOS acceptance. This slice alone does not repair risk
verdicts or lift the beta hold.

### Historical local-beta checkpoint

- Local Linux/Python 3.10.20: 1109 pytest cases passed. The suite invokes 78 Node
  controller tests, which also passed independently.
- Line coverage across `src`, `app`, and `scanner_cli`: 91%. The shared pipeline
  is 95%, transport 99%, durable jobs 92%, schema acceptance 94%, and API 95%.
  Mocked cloud inventory is 92%, traffic parsing 89%, and network discovery 97%.
  The live MCP client is 95% and the controlled policy module 96%; the small strict
  template projection helper is 100%; the schedule service is 97%. This measures executed
  source lines, not attack coverage or security effectiveness.
- Ruff and the configured medium/high-severity Bandit gate pass, including API
  source. Lower-severity static findings still require contextual review.
- Real loopback HTTP fixtures exercise provider request formats, rejected probes,
  canary disclosure versus refusal, and credential removal from JSON/SARIF output.
- Real SQLite transactions exercise competing claims, cancellation/finalization
  races, restart recovery, and exclusive dispatcher ownership.
- Known legacy schema upgrades preserve rows; unknown layouts, future versions,
  defaults, triggers, views, and unexpected unique constraints are rejected before
  writes. Interrupted upgrade transactions roll back. State changes and bounded
  tenant audit events persist atomically.
- Versioned check regressions distinguish passed/confirmed evidence from
  heuristic, inconclusive, failed, and skipped execution. New risk requires
  conclusive completed evidence; verified resolution requires exact probe,
  provider/model, and public evidence-context matches for every earlier occurrence.
- Offline replay ruleset 1.1.0 detects exact protected foreign canaries in string
  argument keys, including objects nested under arrays, without exposing names.
  Twenty-five new regressions cover numeric locations, existing value paths,
  depth limits, label independence, and versioned secret-safe IDs. All 48 replay
  cases passed independently on Python 3.10 and 3.12 with networking/execution
  blocked. Encoded key disclosures remain explicitly counted false negatives.
  REPLAY001/003 detection scope and the six built-in smoke fixtures are unchanged.
  The global version change changes IDs for every check, not just new detections.
- Distribution build, metadata validation, isolated installed-wheel commands,
  and offline evaluation smoke pass outside the checkout.
- Network fixtures exercise actual loopback HTTP and controlled DNS beneath the
  real connection-time policy. They distinguish protocol observations from vendor
  identity and incomplete sources from expected negatives. Native CI localhost
  address differences are controlled without relaxing scope.
  TGI fixtures require the router discriminator, version, model identity, and a
  positive input limit; current `max_input_tokens` takes precedence over the
  legacy field. Router-less historical responses stay unsupported and unidentified.
- Live MCP fixtures exercise JSON/request-scoped SSE, version/capability handling,
  strict envelopes, partial pages, cookies/redirect rejection, scope changes,
  escaped credentials, schema/pointer limits, and immutable timed-out validation.
  Failed or partial collection marks SARIF invocation unsuccessful. Security
  checks remain skipped or inconclusive; no tool is invoked.
- Controlled MCP fixtures require a complete authenticated protected inventory
  baseline before isolated authorization/Origin controls. They cover denied-status
  disclosure, denial-body/header echoes, canonical/encoded URL and cursor
  reflection, opaque cursors, secret/contract identity collisions, shared budgets,
  partial evidence, and policy output aliases. Findings apply only to the declared
  inventory policy; tool execution and browser exploitation are not assessed.
- Template fixtures cover tenant-scoped CRUD/list/run, quotas, optimistic revisions,
  recipe edit/delete races, commit rollback, source/model/endpoint prerequisites,
  queued snapshot independence, DNS/symlink changes, and current-policy worker
  validation. Real SQLite tests cover exact version 1 upgrade, transaction rollback,
  repeated initialization, and malformed/future layout rejection before writes.
  Manual dashboard template flows now have Node and browser acceptance; saving
  or editing a recipe never starts a scan.
- Schedule fixtures cover tenant/global quotas, pinned revisions, explicit enable/
  pause, finite terminal consumption, one outstanding scan, queue-full deferral,
  no catch-up/replay, restart review, source/config races, and atomic rollback.
  Fake-clock and real dispatcher tests cover soft timeout, readiness, cancellation,
  blocked preflight shutdown, and late-result rejection. Exact version 1/2 layouts
  upgrade to schema 3; unknown/future layouts fail before writes. Scheduling is
  available through dashboard and API, and no real target schedule was enabled.
- Explicit JSON nesting limits were checked on Python 3.10 and an isolated Python
  3.12 environment. Network exponent overflow is rejected. Request and streamed
  body timeouts each record one failure, including Python 3.10's distinct exception.
- Container build, readiness, and readiness after restart pass. The container
  smoke now also rejects missing/wrong operator keys and missing/invalid bearer
  tokens, verifies configured operator identity and authenticated empty history,
  and repeats after restart. It does not admit scans or validate a deployed volume.
- Thirteen mandatory tests cover the optional browser fixture's temporary-path
  and effective-engine guards, environment restoration, bounded startup messages,
  and parent-owned process/database cleanup. They do not require Playwright.
- Local pip check and dependency audit pass after upgrading certifi to 2026.10.19.
  The wheel carries the corresponding minimum requirement. This is not remediation
  of already deployed environments, images, or system trust stores.

CI repeats tests and wheel checks on Python 3.10 through 3.13, audits installed
dependencies including cloud/server extras, runs lint/source security checks,
and builds and starts the container. Check each PR's latest run for its exact
commit and dependency resolution; this document is not a substitute for CI.

## Browser verification

Chromium was exercised against a loopback Flask server with real authentication,
SQLite queue, history, cancellation, and export routes. Discovery and security
phases used synthetic fixtures; no external target was scanned.

The initial workflow covers invalid/valid login, memory-only session state, discovery,
source model selection, separate findings/observations, unassessed risk, history,
JSON/SARIF downloads, cancellation, missing scans, and logout. Desktop 1440-pixel
and mobile 390-pixel layouts were visually inspected without horizontal overflow.
The native fetch receiver failure found in this test now has a regression test.

The continuation fixture adds versioned check outcomes, skipped/failure reasons,
inconclusive and historical unassessed risk, cloud resource identities, real
transactional audit history, literal HTML-like fields, and exports despite an
unavailable audit route. It also verifies logout clearing and the absence of
page errors, external requests, and CSP violations. Discovery/security functions
remain synthetic; this does not validate a real model's behavior.

The template continuation exercises authenticated save/edit/run/delete, 25+2
paging, source/model/timeout preservation, stale revision conflicts, dirty-editor
discard, literal HTML names, denied targets, initial list 503 recovery, and 401
clearing. Fresh desktop 1440/mobile 390 screenshots were inspected with no
horizontal overflow, external requests, page errors, CSP violations, or browser
storage. Authentication, database, dispatcher, and API are real; scanning remains
synthetic.

The schedule continuation verifies reviewed saved pins, disabled creation with
no job, explicit enable/pause, real CAS and pin conflicts, policy/quota errors,
restart review, controlled due admission, outstanding-scan deletion rejection,
completed occurrence navigation, 25+2 schedule/occurrence paging, and deletion
preserving reports. It also covers initial list 503 recovery, logout, late
responses, 401 clearing, and literal HTML fields. Real desktop 1440/mobile 390
Chromium acceptance passed with no horizontal overflow, page errors, external
requests, CSP violations, or browser storage. Independent source review and 92
focused pytest cases passed on integrated head `9811587`.

Targeted real keyboard/API checks cover sign-in, create/open, enable/pause,
schedule/template deletion, logout, and 401. Focus moves to schedule identity
after explicit successful transitions, nearby Refresh after deletion, and the
operator key after sign-out. Background list/occurrence refresh does not move
focus. Labels, linked pin/bounds hints, polite notices, and 320/390/1440 layouts
were inspected. Stronger baseline control borders, linked scope/model hints,
named check/audit regions, final Show more focus, and completion announcements
were the next focused slice at that checkpoint. Screen-reader workflows and comprehensive
accessibility conformance were not evaluated. All fixture servers stopped;
the browser artifacts remain in `/tmp/ai-scanner-schedule-browser-rDbOYW`.

The accessibility continuation checks linked scope/model guidance, named scroll
regions, focus ownership at 36-record final pages and the 100-of-110 display cap,
unchanged terminal polling without report replacement or duplicate announcements,
all five terminal states, unavailable/historical reports, report recovery, stale
selection/logout/401, and unrelated notice preservation. Real Chromium reflow at
320/390/1440 pixels passes without horizontal overflow. Enabled borders measure
4.226:1 against white; the existing focus outline measures 3.407:1. No external
browser requests, CSP violations, page errors, or browser storage were observed.

The checked-in optional [browser workflow](DEVELOPMENT.md#optional-chromium-dashboard-checks)
uses actual Flask/authentication/SQLite with seeded synthetic reports, no real
provider calls, and no enabled schedules. Parent-owned temporary database cleanup
and fixture reaping passed on success, deliberate assertion failure, and browser
launch failure. Mandatory tests separately cover startup and forced cleanup paths.
Screenshots/logs are retained; fixture databases are removed. This is targeted
keyboard/DOM acceptance, not screen-reader interoperability or full WCAG conformance.

## Local queue acceptance

The default 200-job disposable SQLite workload passed with two workers:
179 completed, 20 cancelled, one interrupted, 181 unique claims, 582 audit events,
and consistent job/session/report states. A repeated integrated run took
8.227119 seconds (21.757 completed jobs/second) on schema version 3; no throughput
threshold is an acceptance criterion. Four-job acceptance passed and a deliberately insufficient
deadline reported failure. See [performance scope and reproducible commands](performance.md).

Installed AWS, Azure, and GCP SDK method signatures and resource/list schemas were
checked locally, including cloud extras. Tests use mocked responses without
provider credentials or real account requests. Use Python 3.11 or newer for cloud
inventory because the installed Google SDK warns about Python 3.10 support.

## Disposable backup/restore acceptance

The [local command](jobs.md#disposable-backuprestore-acceptance) passed all eight
cases with a five-second work deadline on Python 3.10 and 3.12. Normal and
optimized Python execution passed. Forty-two mandatory tests cover the command,
pre-connect engine/path guards, no-clobber copies, strict child results, bounded
output/deadlines, environment isolation, and process/database cleanup.

Stopped synthetic schema 1/2/3 databases retain exact schema and logical rows in
backup and restored files before initialization. The real initializer, job store,
dispatcher, and schedule recovery preserve completed evidence, agent snapshots,
audit history, templates, and existing occurrences. Synthetic queued work executes
once; active work becomes interrupted/cancelled without replay. Enabled schedules,
including an overdue schedule without outstanding work, pause for restart review
without preflight or admission. The second dispatcher restart leaves rows unchanged.

Injected version-stamp failures roll back schema 1/2 upgrades. Future versions and
competing dispatcher ownership fail before recovery without database changes.
A restored copy with a deleted report still passes SQLite integrity but is rejected
by logical comparison before startup. An independent copy of the untouched backup
retains original version/content; source and backup hashes remain unchanged.
Independent fault mutations also detected lost rows, changed completed metadata,
missing schedule recovery, and an improperly accepted future version.

No operator database was opened or target scanned. This covers local synthetic
content preservation, not deployed restore, online backup, old-binary compatibility,
crash durability, or release sign-off.

## Local-beta finish pass

The [beta guide](BETA_TESTING.md) defines a finite supported-scope gate and an
offline walkthrough using separate keys, a private fresh database, sanitized
settings, loopback binding, and the checked-in static SDK-import fixture.
CLI discovery of that fixture returns one OpenAI inventory observation, no
endpoint or finding, unexecuted security checks, and unassessed risk.

The new mandatory operator test uses actual authentication, current-policy
admission, template execution, repository discovery, the shared pipeline,
file-backed SQLite dispatcher, report/audit/JSON/SARIF routes, and one explicitly
enabled finite schedule occurrence. It verifies skipped security and unknown risk,
secret-free reports, and recipe/schedule deletion preserving reports. External
sockets, DNS, and process execution are forbidden; fixture source must never
execute. Independent Python 3.10/3.12 runs passed, alongside 200 focused author
tests. This is API-level acceptance, not a new full browser workflow.

The existing Chromium command passed normally with optimization disabled at
320/390/1440 pixels. Artifacts are in `/tmp/ai-scanner-browser-2p7pyzn4`.
Its fixture PID 2987229 was reaped and its temporary database directory removed.
Normal and optimized backup commands each passed all eight cases. Local build,
Twine, installed-wheel smoke, lint, configured Bandit gate, dependency audit, and
pip check passed. A focused independent security/correctness audit passed 314
cases and reproduced no must-fix blocker in the supported boundary; this is not
an exhaustive security certification.

The local Docker image built from unchanged application code at `647c6d1`
(`sha256:f90983133c6b11a8d6a02b17f261e75beb3bb57434bf07d91c3f6f444158ca52`)
passed authenticated checks before and after restart. The uniquely owned test
container was removed; no operator database, real target, or deployed volume was
used. CI repeats this behavior on the PR's exact source. The setup example now
passes the independent operator key instead of starting a server with login disabled.

Five sequential fresh-database queue runs passed on Linux/aarch64, Python 3.10.20,
SQLite 3.53.1. Every run had zero duplicate claims, consistent terminal states,
one terminal event per scan, and peak workers within its bound:

| Jobs | Workers | Synthetic latency (ms) | Elapsed (seconds) | Peak workers |
| --- | --- | --- | --- | --- |
| 200 | 2 | 1 | 8.823065 | 2 |
| 200 | 2 | 1 | 9.917252 | 1 |
| 200 | 2 | 1 | 8.919674 | 2 |
| 500 | 4 | 5 | 24.108064 | 4 |
| 500 | 4 | 5 | 22.384391 | 4 |

Totals: 1600 jobs, 1435 completed, 160 cancelled, five interrupted, 1445 unique
claims, and 4650 audit events. A separate 200-job/1000-ms case with a one-second
deadline exited 1 and reported incomplete state rather than success (1.083490
seconds). A parent-owned temporary root, sanitized environment, 90-second child
watchdog, and bounded kill/reap grace protected every run; all roots were removed.
The local driver is retained at `/tmp/ai-scanner-finish-queue-profile.py`.
This is finite queue regression repetition, not a long-duration soak, HTTP or
scheduler load test, production throughput claim, or performance threshold.

After the reviewed revision and merged commit pass all seven CI jobs, this gate
is ready for local operator beta testing. Stop feature expansion for that beta;
collect feedback under the guide's scope. M6 and the release-level gaps below
remain separate from that limited acceptance.

## Remaining validation gaps

The privacy cleanup excludes machine-local assistant instructions, lab setup, and
the legacy screenshot from the current Git tree, source distributions, and Docker
contexts. Two regressions check the public index and ignore policy. Fresh package
metadata has no personal author email; professional credit remains. Local originals
are retained. Repository and reachable-history pattern/context review found no
plausible live credentials, but is not proof that every possible secret is absent.
Existing history, published artifacts, and third-party copies were not rewritten
or erased. Future commits use the account's user-approved repository-local noreply
identity; global identity is unchanged.

- Real cloud account inventory and representative capture-format integration
  remain incomplete despite stronger mocked/format fixtures. Network samples
  three read-only protocol inventories and common ports, not all services. The
  API still normalizes domains to IPs and can miss hostname-dependent virtual
  hosts; TLS on nonstandard ports and authenticated inventories remain gaps.
- Provider fixtures do not establish compatibility with every live model or
  account configuration. No paid provider calls were made.
- Replay metrics describe synthetic or supplied labels, not representative
  production precision/recall. Passive MCP and read-only live inventory do not
  execute tools or test runtime authorization, Origin enforcement, or sandboxing.
  Controlled policy checks sample only explicit protected inventory fixtures and
  the first control page; they do not close those broader runtime gaps. Operator
  fixture provenance is trusted input, not independently verified attestation.
  The live client supports only MCP 2026-07-28 and its documented input-schema
  subset; legacy versions, OAuth acquisition, and broad interoperability remain gaps.
- PostgreSQL, distributed workers, network-filesystem locking, and overlapping
  server reloads are unsupported, not validated deployment options.
- Representative load/soak benchmarks, comprehensive accessibility evaluation,
  deployed upgrade/backup acceptance, enterprise identity, and tamper-resistant
  audit acceptance remain pending. Known SQLite upgrade tests and a synthetic
  queue workload do not close these release-level gaps.

See [engineering milestones](ENGINEERING_PLAN.md), [development checks](DEVELOPMENT.md),
and [persistent job constraints](jobs.md).
