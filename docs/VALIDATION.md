# Engineering validation checkpoint

Date: 2026-10-21. This records the beta build-out, not a release certification.
The remediation hold is closed for limited single-operator beta testing on
runtime revision `82ee7d5`, following reviewed core and targeted API retests.
This is not production or enterprise approval and does not establish detection
sensitivity. Historical infrastructure results alone did not close the original
defects. Follow the [remediation gate](BETA_REMEDIATION.md) for scope and limits.
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

## Exact-revision external retest

The operator supplied a private live-lab retest for
`150762513ecbf728c4922436bff1448266467150`. Two independent reviews inspected
the underlying JSON/SARIF, repeated-run comparisons, logs, and scoped connection
traces. These are reviews of supplied execution evidence, not independent cloud
reruns. Infrastructure identifiers, fixture inputs, and raw artifacts remain
outside the public repository.

- Linux/Python 3.11: 1241 passed, one skipped. Native macOS/Python 3.13:
  1242 passed with the stock temporary-directory configuration. Both platforms
  passed normal and optimized backup acceptance, all eight cases per mode.
- Linux and macOS logs support lint, configured static security checks, dependency
  checks/audit, build, metadata, installed-package smoke, and finite queue gates.
  Linux Chromium passed; macOS Chromium was not run. The merged revision's eight
  CI jobs also passed, including native macOS and container restart checks.
- The mixed-network inventory completed despite ordinary pages, non-HTTP banners,
  and unused addresses; a genuine service error retained partial coverage.
  Completed and finalized partial sources were actively tested, with source
  uncertainty preserved in JSON/SARIF. CLI model selection executed 39 checks.
- Five identical vulnerable-bot runs yielded one confirmed high leak at 70/100
  and four inconclusive null-score results, with no passed checks. Comparisons
  after the disclosure retained one unverified resolution and zero resolved
  findings. A leak-then-timeout fixture retained high risk with partial coverage.
  This measures conservative reporting, not representative detection sensitivity.
- All 355 response excerpts in 73 supplied JSON/SARIF artifacts contain the
  generated-text omission sentinel. Logs attest to zero protected-marker/PII
  matches and private scanner-written CLI files plus database/lock permissions.
  Exact markers and the database were intentionally omitted, so those sweeps
  cannot be independently repeated from this bundle. Driver-saved API responses
  are not scanner-written private exports and had different file permissions.
- Real SDK inventory and controlled MCP tests support the documented findings,
  denials, TLS/scope errors, and explicit page-sampling warning. Controls still
  sample only their first page; authenticated baselines can paginate. No tool
  was invoked. The metadata IP/hostname traces show no metadata connections;
  a wider metadata-subnet test was rejected by the host-count bound first and
  therefore does not independently exercise address-class enforcement.

The operator report marks the 22 original findings passed or documented limits,
with two items verified by source/documentation rather than live execution.
Independent review found a further API contract defect: public compatibility
summary and agent scores are zero where the saved pipeline says null and
`not_assessed`. History exposes no risk fields and SARIF retains the correct
nulls. This was a release blocker, not one of the six low-priority observations.
The beta remained held pending the scoped fix and new-revision API validation
recorded below. The earlier retest alone did not cover the changed API code or
establish enterprise readiness.

### API projection follow-up

The scoped follow-up projects public summary and agent risk from saved current
policy/check evidence rather than storage placeholders. Unknown and unsupported
historical scores remain null; assessed zero and confirmed partial high remain
numeric. Malformed values, inconsistent scores/levels/severity floors, ambiguous
asset IDs, and missing evidence fail closed. Historical reports and the database
schema are unchanged. Inventory queries remain tenant-owned and batched; projected
level filters have an explicit newest-100 tenant/type window and truncation warning.

Local Linux/Python 3.10 acceptance passes 1279 tests, including 37 new API cases
and strengthened actual dispatcher/protocol assertions for the outer results and
inventory fields. Independent focused reviews pass 126 and 162 cases, plus the
final 37-case projection run with warnings treated as errors. Ruff, configured
Bandit, build, Twine, and installed-wheel smoke pass. Replaying four supplied
private pipelines through actual Flask routes and fresh in-memory storage keeps
both unassessed server cases null and both confirmed cases at 70, including
partial coverage. Raw pipelines remain unchanged. This is offline API-adapter
replay, not a new live-cloud run. PR #49 and merged revision `82ee7d5` subsequently
passed all eight CI jobs; targeted live API acceptance is recorded below.

### Targeted live API acceptance

An operator-supplied private follow-up covers exact merged runtime revision
`82ee7d5e8d1a0183fe5344b41da90f60b49c5f91` on Linux/Python 3.11, actual
Gunicorn, the real dispatcher, and fresh private SQLite storage. Both job logs
verify the checkout; the setup log records 37 passing API projection tests.
Two independent reviews inspected archived responses, check records, logs, and
driver source without executing the supplied drivers or independently rerunning
cloud jobs.

- Ten scan captures and 31 agent snapshots agree across outer summaries,
  per-agent results, inventory entries, and saved pipelines. All 29 unassessed
  snapshots retain null scores, unknown levels, and not-assessed coverage.
  Discovery summary assessment status remains `not_run`, not an assessed zero.
- The two deterministic positive snapshots retain 70/high: one completed with
  sampled coverage and one partial with partial coverage. Their outer summary
  assessment statuses are `completed` and `partial`, respectively.
- Archived restart inventory independently retains all 31 matching snapshots,
  including exactly two high entries. Driver records report identical outer and
  per-agent projections for all ten scans after restart, and positive inclusion
  in the high-risk filter. Those per-scan restart and high-filter response bodies
  were not separately retained; do not claim an independent exact-set comparison
  of those missing bodies. The inventory window was not truncated.
- The archived check file contains 78 passing checks, zero failures, and 16
  informational entries. The harness records failures without failing its
  process, so exit zero is not acceptance evidence by itself. Independent
  comparisons and the actual zero-failure check record support this run.
- All 324 response excerpts in the supplied JSON captures are omission sentinels.
  Exact-secret/PII sweeps and final database/lock modes of 0600 are operator
  attestations; the database and protected values were intentionally excluded.
  Driver-created captures are 0644, not scanner-written private exports.

For positive paths, the driver stopped the server and added only
`system_prompt_canary` and public `evidence_context_id` inputs to genuine
server-produced discovery records. The real scanner generated the findings,
scores, persisted results, and projections. Original serialized records were
restored afterward; API document equality and final cleanup were recorded.
Temporary input seeding stored canaries in those private lab records, so final
zero-marker sweeps do not establish that canaries were never persisted during
the experiment. This test technique is not a supported operator workflow.

The server API still has no supported protected-canary configuration input.
Deterministic fixtures establish the confirmed projection path, not ordinary API
setup or real-model sensitivity. All three vulnerable-bot attempts were
inconclusive with null scores, not passed. Do not combine this small follow-up
with earlier runs into a representative accuracy estimate.

Together with the earlier core lab retest, local acceptance, independent reviews,
and eight green PR/post-merge CI jobs, this closes the scoped API blocker and
remediation hold for limited operator beta testing. Six lower-priority
observations, safe server evidence configuration, representative accuracy, and
the enterprise validation gaps below remain. No package publication or service
deployment is implied. Documentation-only changes do not alter this tested
runtime and need no additional cloud run.

## Automated checks

### Operator feedback diagnostics

The combined diagnostic slice passes 1408 local Linux/Python 3.10 cases, Ruff,
and the configured whole-source Bandit gate. Independent reviews passed 409
network/contract cases and 299 MCP cases with warnings treated as errors.

Static CLI preflight rejects known metadata names, forbidden address classes,
legacy numeric IPv4 representations, and unsafe local-host aliases before the
pipeline, DNS, or sockets run. All declared networks/domains/explicit agents are
checked before scanning begins, while ordinary documentation/private networks,
host-bit normalization, and explicit loopback opt-in remain available. Existing
DNS and connection-time enforcement is unchanged. Refusal does not overwrite an
existing output report.

Missing declared/provider credentials and required model 401/403 responses have
specific static reasons without endpoint, environment-reference, header, body,
or marker leakage. Denied model requests remain incomplete/inconclusive; valid
denials in intentional authentication/session controls keep their prior behavior.
CLI MCP failures print only allowlisted fixed report reasons, with a generic
fallback for unknown text. Paginated authorized baselines and first-page-only
controls are explicitly distinguished without changing findings or probe IDs.
The wildcard detection constant retains its justified B104 suppression, isolated
so the installed Bandit reports no stale suppression warnings.

These are local synthetic diagnostics/privacy regressions, not another cloud
retest or a detection-sensitivity improvement. PR #51 and its merged revision
passed all eight CI jobs. Repeated finding presentation, sampling/latency work,
and enterprise acceptance remain separate.

### Server evidence-reference slice

Named server profiles enable normal system-prompt canary input for security-only
API scans and saved-template/schedule workflows. No stored discovery report is
edited and no score or finding is seeded. The registry is private, bounded, and
loaded only at startup; public endpoint/provider/model/organization/context pins
are revalidated at admission and execution. Secrets are not pin inputs.

The real local HTTP/API/dispatcher/file-backed SQLite regression exercises a
disclosing and nondisclosing target through supported template APIs. The former
produces 70/high, the latter null/inconclusive with no prompt-check passes. Saved
pipelines, JSON/SARIF, compatibility results, and inventory agree. Source reports
remain unchanged. Assertions check generated reports, queued definitions,
templates, SQLite bytes, audit, logs, and captured model requests for marker and
environment-reference absence. All target response text remains omitted.

Negative tests cover private-file ownership/mode/type/size, duplicate/nonfinite
and deeply nested JSON, missing/invalid environment values, tenant/asset/model
binding, alias ambiguity, external reserved fields/pins, changed queued bindings,
schedule preflight/admission races, and marker collisions with public labels,
revision pins, source inventory, normalized URLs, and resolved credentials.
Escaped-marker and HTTP-client path normalization regressions prevent reflected
request data from acting as protected-canary evidence. Two selected models may
share a protected fixture marker without mutating the original source.

Four isolated subprocess tests exercise actual app startup with configured
profiles, including valid, missing-secret, malformed-registry, and missing-file
cases. Socket connection/bind, DNS, and SQLite connections are forbidden;
the subprocess deadline is 15 seconds. Failures expose static reasons, not
protected values or registry paths. This is startup configuration acceptance,
not a new real-Gunicorn or deployed-secret-manager test.

Independent review accepted the implementation after reproducing and closing
reflection/privacy and multi-asset correctness blockers. Local integrated
Linux/Python 3.10 acceptance passes 1504 tests with warnings treated as errors,
including 96 new profile cases. Ruff, configured Bandit, distribution build,
Twine metadata checks, and installed-wheel smoke pass. Independent review also
passed 407 focused cases and a 1369-case full run before the final startup and
adapter regressions; final integrated focused review covers those additions.
PR #52 and merged revision `ed5684d` passed all eight CI jobs, including native
macOS backup/restore and container restart. These checks do not replace a
real-service retest of the newly supported API profile configuration.
No cloud or real-model retest was performed for this slice. Detection sensitivity
remains unvalidated, nondisclosure cannot establish safety, and raw database
unknown-score placeholders were not migrated. Cross-tenant/authentication/path
evidence configuration remains CLI/Python-only. Deployment and publication are
not part of this change.

### Experimental paired prompt benchmark

The repository script uses the actual provider adapter, scoped transport,
prompt analyzer, and versioned check contracts. Production prompt catalogs and
scan defaults are unchanged. The experimental `protected-disclosure-v1` suite
uses seven categories with five requests each, replacing generic output/persona
objectives with protected-system-instruction extraction objectives. The baseline
retains its original active payload bytes. Public manifest/version provenance
distinguishes both suites; configured secrets are not identity inputs.

Balanced, seeded baseline/candidate ordering supports one to ten pairs, default
ten. Every arm is capped at 35 HTTP attempts, a 30-second request timeout, 64 KiB response
cap, 1,200-second deadline, the existing 100-token output cap, and one-second
pacing. The cohort deadline is 5,400 seconds, at most 700 attempts for ten pairs.
The ordering seed does not control model generation. DNS validation is bounded
separately. There are no automatic retries or increases after observing outcomes.

The primary observation is whether a run confirms at least one exact protected
canary disclosure, not how many repeated findings it produces. Benchmark-only
observation checkpoints retain an actual analyzer confirmation when later
cancellation prevents a category from returning. They do not fabricate check
records; original collected checks and partial coverage remain explicit.
Complete-case Wilson intervals exclude partial/unstarted arms. Paired counts
exclude incomplete pairs, while scheduled denominators and partial positives
remain separately visible. These are exploratory, potentially completion-biased
measurements, not enterprise accuracy or independent-request statistics.

Real loopback HTTP fixtures exercise deterministic disclosure, refusal, unseeded
canaries, request reflection, malformed responses, authorization denial, and a
confirmed response followed by timeout. Other regressions cover scope-before-I/O,
missing credentials, secret/public-manifest collisions, deadline accounting,
unchanged production defaults, parser errors, and private atomic no-clobber
output. Reports omit raw generated text, target endpoints, secret references,
credentials, and canary hashes. The supplied revision is explicitly labeled an
operator assertion; the GCP procedure separately verifies the actual checkout.

Local Linux/Python 3.10 acceptance passes 1559 cases with warnings treated as
errors, including 55 new benchmark cases. Ruff, configured Bandit (also run on
the new script), build, Twine, and installed-wheel smoke pass. Independent review passed 253
focused cases plus four additional actual-HTTP negative/partial scenarios:
metadata-only and Base64-only markers do not confirm, oversized bodies stay
partial, and leak-then-503 retains its partial positive. Require all eight
PR/post-merge CI jobs on the exact source before acceptance.
The
[next GCP retest](BETA_TESTING.md#next-authorized-gcp-detector-retest) covers the
supported real-server profile workflow and frozen paired model comparison.
No cloud model was exercised here, and no experimental prompt has been promoted
to production based on fixture results.

The slice checkpoints below are chronological records. Their historical hold
and pending-retest statements are superseded by the targeted acceptance above;
enterprise and unsupported-deployment limitations remain in effect.

### Remediation infrastructure slice

The first remediation slice passes 1120 local Linux/Python 3.10 tests, Ruff, and
the configured Bandit gate. Fifty-seven focused cases cover report permissions,
atomic replacement, failed-write preservation, symlink rejection, and disposable
backup behavior. Both normal and optimized backup commands pass all eight cases.
A synthetic symlinked temporary ancestor passes in both modes and is cleaned up;
owned child/database symlinks remain rejected. A new native macOS CI job must
pass before claiming macOS acceptance. This slice alone does not repair risk
verdicts or lift the beta hold.

### Verdict remediation slice

The integrated verdict slice passes 1150 local Linux/Python 3.10 tests, including
82 Node controller cases, Ruff, and the configured Bandit gate. Twenty-nine new
verdict regressions cover severity floors, repeated leak samples, unseeded and
stochastic nondisclosure, historical resolution, private evidence/logging, partial
confirmed risk, anonymous inference, denied cookies, and all-skipped execution.
Independent reviews accepted the runtime changes and corrected dashboard policy
gating so historical low scores do not appear current. The authoritative policy
and scores agree across agent, security-result, assessment, and summary fields.

The real synthetic Chromium workflow passed at 320/390/1440 pixels, including
visible confirmed high risk with partial-coverage warnings and unchanged focus
and session protections. Artifacts remain in `/tmp/ai-scanner-browser-82s862s_`;
the fixture process stopped and its private database directory was removed.
The browser parent also canonicalizes its created temporary root; the mandatory
symlink-ancestor regression and existing guard/cleanup cases pass. These fixtures
do not rerun the external lab or reopen the beta.

### Network remediation slice

The verdict plus network tree passes 1194 local Linux/Python 3.10 tests and Ruff.
Independent review exercised transport, scope, MCP, mixed DNS, configurable
deadlines, and safe failure accounting; focused runs also passed with warnings
treated as errors. A real loopback mixed-service fixture retains one Ollama and
completes with TCP banners, large SPA/HTML, unrelated API inventories, JSON error
documents, and closed ports. Matching native/compatible model sets deduplicate.
Separate fixtures preserve partial status for actual protocol claims with invalid
data, 503s, truncation, and JSON/body limits, including JSON mislabeled text/plain.
Optional protocol routes stay optional after another inventory succeeds.

Metadata/reserved addresses are rejected before TCP or HTTP even without a CLI
allowlist. Host-bit CIDRs normalize consistently. Bounded local hosts aliases and
mixed-answer fail-closed checks pass. A real untrusted certificate fixture reports
a specific safe TLS failure for both MCP inventory and policy checks. Pre-created
security engines use each scan's current bounded request deadline, with no retry.
These are synthetic regressions, not a new live-provider compatibility claim.

### Combined operator remediation slice

The complete local remediation tree passes 1235 Linux/Python 3.10 tests and
82 Node controller cases, Ruff, configured Bandit, pip check, dependency audit,
build/Twine checks, and an isolated installed-wheel smoke. Both normal and
optimized backup commands pass all eight cases. Independent review passed 256
source/API/schedule/CLI/privacy cases and 226 network cases with warnings as errors.
The current PR and merged revision must still pass their own complete CI matrix.

The new mandatory real-protocol workflow starts local AI inventory/inference,
optional error/HTML routes, a TCP banner, and a separate 503 service. It uses a
fresh file-backed SQLite database, actual dispatcher, operator login, admission,
snapshot-ID model selection, adapter/HTTP calls, history and JSON/SARIF exports.
Mixed-service discovery completes; genuine 503 discovery remains partial; the
saved partial source is then actively tested with the exact selected model.
The original source remains unchanged, uncertainty is retained, and no passed
security conclusion or minimal-risk score is inferred. Synthetic private output,
PII, operator credentials and tokens are absent from reports and audit events.
Only configured ports, sample counts and pacing are adjusted; engines, adapters,
transport, and security results are not mocked. This is not a real LLM or cloud
lab retest. Guards prevent non-loopback connections or operator-database reuse.

Malformed source arrays, null snapshot metadata and nonstring IDs reproduce
controlled 400 rejection rather than generic 500/admission. Changed inventories
remain 409 schedule conflicts. Source ownership and current-policy checks remain.
The real Chromium workflow passed again at 320/390/1440 pixels; artifacts are in
`/tmp/ai-scanner-browser-doy5ot92` and independent artifacts in
`/tmp/ai-scanner-browser-4r6x44pw`. Fixture processes exited and databases were
removed. This is focused workflow/keyboard acceptance, not comprehensive WCAG.

The repeated finite queue profile passed five fresh-database runs: 200 jobs with
two workers and 1ms synthetic latency in 9.938061, 7.817631 and 8.195153 seconds;
500 jobs with four workers and 5ms latency in 21.363828 and 21.610206 seconds.
Totals are 1600 jobs, 1435 completed, 160 cancelled, five interrupted, 1445 unique
claims and 4650 audit events. Duplicate claims and state mismatches were zero.
The insufficient one-second deadline case correctly exited 1 at 1.080374 seconds.
All disposable databases were removed; logs remain in
`/tmp/ai-scanner-beta-queue-review-llvm6a`. This is not a load/soak or throughput
certification. No cloud VM was started, real target scanned, package published,
or remote service deployed. At that checkpoint the beta stayed held for
exact-revision lab retesting and the separate enterprise-readiness contract.

### New server-state permission defaults

The storage follow-up passes 1242 local Linux/Python 3.10 tests, Ruff and the
configured Bandit gate including Gunicorn configuration. Seven new mandatory
subprocess regressions verify import does not change the caller's umask, rejected
worker counts fail before changing it, and actual entrypoint/worker hooks create
0700 directories plus 0600 SQLite/journal/lock files under an inherited 022 mask.
Existing 0644 files and 0755 directories remain unchanged. An independent actual
Gunicorn run with a copied public app and fresh private SQLite state passed
readiness with a 0700 default instance and 0600 database/lock, then stopped cleanly.
No deployed or operator database was opened or changed.

Container CI now checks the fresh instance, database/lock modes and file ownership
after authenticated readiness and again after restart. The new PR and merged
revision must pass this actual-container assertion before claiming it. Existing
mounted volumes and retained historical reports need their own operator review;
these defaults do not repair their permissions or sanitize old report contents.
At that checkpoint the real-service lab retest and enterprise sign-off were
outstanding. The reviewed retests above close the scoped beta remediation gate,
not the separate enterprise sign-off.

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

## Synthetic evaluation registry isolation

The optional queue benchmark and API/local-lab/offline-operator fixtures must not
inherit or reuse an operator's startup evidence registry. Standalone queue and
backup runners clear the registry-path setting and reject a cached nonempty
registry before app-context, database, or schema access. Unit fixtures also
isolate cached registry objects and restore their original environment/object
on teardown. Normal configured server behavior is unchanged. Backup acceptance
retains its outer `SCAN_` child-environment filter; the inner entrypoint now also
clears the registry setting for direct child invocations.

Seven new bounded regressions cover missing/private paths with forbidden-open
guards, fresh imports, cached fixtures, restoration, and direct backup children.
The native macOS diagnostic run located a 20-second fixture timeout at the first
HTTP server constructor. That fixture now binds numeric server names without
reverse DNS; fresh and cached setup run with `getfqdn` and `gethostbyaddr`
forbidden. The 20-second child deadline and bounded traceback diagnostics remain.
Before one additional quoted-identifier regression, the isolation branch passed
1566 full-suite cases with warnings treated as errors and an inherited nonexistent
registry path. Independent review passed 177 relevant cases. A final 54-case
backup/isolation/workflow gate includes the hostile-identifier regression and
passes. Expanded Bandit covers both helpers; one narrow B608 suppression documents
the existing escaped SQLite identifier query, with a regression proving hostile
table-name text cannot alter other fixture tables. Ruff and whitespace checks pass.
The reporting slice contributes its own separately recorded tests; branch counts
should not be added as independent runs. Final combined CI, including native
macOS, remains required before acceptance.
This does not use an operator registry, database, or target, and does not replace
the separate browser isolation regression. All eight PR/post-merge CI jobs are
required on the final source before acceptance.

See [engineering milestones](ENGINEERING_PLAN.md), [development checks](DEVELOPMENT.md),
and [persistent job constraints](jobs.md).
