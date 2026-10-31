# Engineering validation checkpoint

Date: 2026-10-22. This records the beta build-out, not a release certification.
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

## Strategic review and revised roadmap

The strategic review at `aae186339dc2b0f4f59222d12ec77f07b11fb308` used source,
the recorded lab evidence, independent architecture/detection/product reviews,
and primary-source competitor documentation. It did not rerun the GCP lab or
establish comparative detection performance. One hundred existing targeted
pipeline/job/contract and API projection cases passed during review; these are
regressions, not model observations. The full suite was not rerun for that review.

Two isolated local reproductions establish open correctness work:

- Actual generic authentication-check code, with an in-process always-401
  transport and no network, records 36 evaluated interactions, no findings, and
  a completed passed check for an unseeded protected marker. There is no valid
  authenticated positive baseline. The isolated result is risk-assessment
  eligible; this is not a claim that a full normal scan necessarily scores zero.
  Independent comparison of tester-produced positive and later all-denied
  records also resolves the earlier finding group. R1.1 must prevent unsupported
  sampled passes and resolution, with versioned evidence semantics.
- Independent actual analyzer/check/engine/pipeline/server-deadline testing with
  deterministic in-process responses confirms prompt findings, then stalls a
  later stage. Normal completion retains 70/high; the outer deadline saves a
  failed empty report with null risk and loses the earlier confirmations.
  This is distinct from ordinary failed-request partial-result retention and
  from benchmark-only observation checkpoints. R1.2 needs durable sanitized
  checkpoints, transactional terminalization, and interruption/recovery tests.

Source and existing tests also establish that risk-level inventory filtering is
limited to the newest 100 records, database columns still store placeholder zeros,
advanced dashboard configuration uses raw JSON, and main retains package version
`1.1.0` despite 285 commits beyond that tag. These are current limitations, not
new cloud observations. Earlier successful lab cases do not close them.

The [active roadmap](ENGINEERING_PLAN.md#active-roadmap) is approved direction,
not completed acceptance. Each slice must add positive/negative regressions,
independent review, and all required PR/post-merge checks. For R1.1, require
valid/invalid credentials, absent/unseeded markers, failed controls, privacy,
probe-version compatibility, and finding-lifecycle cases. For R1.2, require
confirmation followed by timeout/cancel/crash, restart consistency, no replay,
bounded checkpoints, no secret retention, and matching CLI/API/JSON/SARIF risk
and coverage. Mark measured behavior separately from future acceptance targets.

## Protected-access positive-control local acceptance

The R1.1 working slice covers authentication bypass, weak credentials, weak API
keys, and declared protected admin paths. Each group/path requires a successful
issued-credential GET that returns its marker and a fresh invalid-credential
denial before probes. Missing explicit credentials skip; unavailable, stale,
unseeded, failed, or reflected controls cannot pass or confirm. Successful
responses without the marker remain inconclusive. Controls use separate sessions
and the shared scan limits. Default successful-denial samples use 20, 7, and 32
requests for the first three groups, and three requests per protected admin path.

Versioned protected-access evidence now requires opaque ASCII markers of 16 to
128 characters, explicit credential environment references, and query/escape-free
resource URLs. Exact response matching is unchanged. Explicit transport headers
and collision checks cover normalized URL, credential, probe, wire-header, and
case-variant public material. Review reproduced and closed automatic User-Agent
and serialized/lowercase-header reflection, session-entry failure accounting,
empty-sample passes, and empty-credential redaction corrupting report strings.
Historical probe versions cannot establish resolution under the changed rules.

The prerequisite contract fix propagates cancellation and records failed,
inconclusive execution rather than a completed pass after successful controls.
Counters remain actual interactions, not invented HTTP failures. The strict
benchmark validator accepts the static interruption reason only on a final
failed/inconclusive check in a partial arm. Actual final-pacing producer output
and legacy partial reports both validate; benchmark observations do not become
fabricated confirmed production checks.

Combined local acceptance passes 2,220 tests with warnings treated as errors and
an inherited nonexistent evidence-registry sentinel. Independent review passes
646 focused cases, plus separately exercised 32 actual-loopback control/budget/
scope/lifecycle cases and 32 reflection cases rejected before HTTP. These are
overlapping regression gates, not independent model observations. Ruff,
configured Bandit, whitespace checks, distribution build, Twine, and an
installed-wheel smoke outside the checkout pass. The built access-control module
matches the reviewed working source.

PR #64 and merged revision `9a696d18542c18bf36f357729fd622408cb88257` pass all
eight CI jobs: Python 3.10 through 3.13, macOS, lint, security, and container.
The roadmap-only PR #63 and its merge also pass all eight jobs. Independent
review is recorded in each PR. These checks do not establish real-service
compatibility. No GCP service,
real model, operator database, or registry was accessed; no package was published
or service deployed. Supported controls are exact GET resources, not arbitrary
credential schemes or POST-only model authorization. Server authorization-evidence
configuration is unchanged. Durable findings through an unfinished category or
outer deadline remain R1.2 work; the cancellation-status fix does not close them.

## Finalized-check checkpoint local acceptance

R1.2a adds scan-local finalized-check observation, immutable public checkpoints,
and claim-bound transactional storage. The same shared risk projection serves
final and intermediate reports. Evidence is saved before scoring; a stalled
scorer cannot erase a new finalized finding, but its new score stays null until
successfully assessed. Quiet later checks retain unchanged valid assessments.
Duplicate-identical finding occurrences survive without being counted again when
the final result returns. An incomplete asset cannot become assessed zero from
an earlier sampled pass.

SQLite writes bind the active owner and increasing sequence, atomically preserve
report/snapshots/counts, retain cancellation, and reject stale or regressing final
results. Snapshot identity and first discovery time remain stable. Explicit short
read transactions prevent mixed report/inventory revisions during checkpoint
commits. Bounds cover report size, emission count, cumulative serialization, and
write-lock waiting. Sink errors stop further probes and use static diagnostics.

Combined Linux/Python 3.10 acceptance passes 2,307 tests with warnings treated as
errors and an inherited nonexistent evidence-registry sentinel. Independent review
passes 215 overlapping focused cases. Cases include finalized confirmation followed
by failure/timeout/cancellation, scorer stalls, privacy across successive snapshots,
post-validator secret collection, occurrence preservation, duplicate/redacted-ID
rejection, sink failure, rollback, stale claims, cancellation races, cumulative
limits, and real file-backed interleaved API reads. Fixture drivers now pass the
actual dispatcher claim rather than bypassing ownership checks.

A spawned dispatcher fixture runs the actual pipeline and a synthetic decorated
check, waits for an acknowledged 70/high SQLite checkpoint, then kills that
dispatcher process. A fresh dispatcher acquires the released lock and preserves the exact
report evidence, snapshots, and partial coverage, with one interrupted terminal
event and no replay. Repeated recovery is idempotent. Canonical risk and SARIF
remain consistent; the synthetic canary is absent from the database bytes.
This tests process recovery after an acknowledged commit, not power loss.

CLI JSON/SARIF retain the latest valid partial report on orderly timeout/failure;
cancellation remains cancellation even if export fails. Pre-checkpoint failure
does not overwrite an existing report, symlink destinations are refused, and
new report files are owner-only. Ruff, configured Bandit, whitespace/privacy checks,
distribution build, Twine, and an installed-wheel checkpoint smoke outside the
checkout pass. Installed pipeline and CLI hashes match the reviewed source.
Ordinary and optimized disposable backup acceptance pass all eight cases each.

PR #65 and merged revision `4f9de3ff3217aac93f1ea0933d790d07316f94ac` pass all
eight CI jobs: Python 3.10 through 3.13, macOS, lint, security, and container.
This slice does not retain
observations still inside unfinished checks or implement CLI process-crash
recovery. Duplicate or redaction-colliding source IDs fail closed rather than
silently rebinding findings. Unknown database score placeholders and newest-100
inventory filtering remain R1.3/R1.4 work. No external model, GCP service, deployed
database, package publication, or deployment was used for this acceptance.

### Historical protected-access compatibility follow-up

Independent follow-up review reproduced current risk eligibility and a zero/minimal
API projection from a pre-positive-control authentication check using the public
`18-header-variations-denied-control-v1` definition. Matching that obsolete version
on both records also established resolution. R1.1 changed producer semantics and
blocked cross-version resolution, but did not reject two matching unsupported
historical records. Existing synthetic zero fixtures did not exercise valid
positive-control provenance.

The corrective slice passes 2,899 local tests with warnings treated as errors and
an overlapping 943-case independent focused gate. A pure shared policy recognizes the frozen
current protected-access definitions, original provider/model context, bounded
counters, response/control provenance, and covered paths. Only supported current
passes establish sampled zero or verified absence. Unsupported historical
confirmations make their asset's current score unknown, including mixed-evidence
assets, without changing archived reports or suppressing their original findings.
Other assets retain independently supported scores. Modern direct scorer inputs
without supported evidence fail closed instead of becoming zero.

Tests execute all four real protected-access producer groups against deterministic
vulnerable and defended fixture transports. Current findings, partial cleanup
failures, valid native-model context, sampled zero, and matching controlled
resolution remain supported. Old/old and old/current comparisons cannot establish
resolution. Unknown/custom definitions, missing or redacted contexts, invalid
counters, conflicting resource references, and unsupported positive claims cannot
become current verdicts. Frozen request definitions and version hashes are unchanged.

Ordinary and checkpointed paths use the same secret collection and public evidence
basis. Redacted evidence or invalidated risk labels remove only the unsupported
numeric assessment and recompute the summary. Tests cover credential collisions
with public labels and paths, and canary/credential collisions with the two new
control/path field names across source, validator, probe, and multiple-asset inputs.
Known field collisions fail before security requests or checkpoints; newly learned
collisions cannot escape projection. These fixtures do not establish a general
solution to every public-schema collision. JSON/SARIF and saved checkpoints retain
privacy, and no redaction exemption is used to keep a score.

The dashboard reads canonical risk projections from the same API response and
joins by unique asset ID, without reinterpreting archived checks. All 143 JavaScript
cases pass. Real Chromium verifies historical zero/high records display Not assessed
with their original findings and downloads available, alongside current high and
partial states. Node/API tests also verify legitimate sampled zero. The owned
browser fixture passes at 320, 390, and 1440 pixels,
without external requests or page/CSP errors; its process and temporary database
are cleaned up. This is scoped browser acceptance, not a comprehensive accessibility
or deployed-service certification.

Ruff, configured Bandit, whitespace/privacy checks, distribution build, Twine, and
fresh installed-wheel smoke outside the checkout pass. Normal and optimized
disposable backup acceptance pass all eight cases each. Independent review found
no remaining runtime blockers. PR #66 and merged revision
`81353109936ce3afcc61eac9a9f1bff071f585db` pass all eight CI jobs: Python 3.10
through 3.13, macOS, lint, security, and container.
No GCP service, external model, operator database, package publication, or deployment
was used. Nullable database storage, within-check confirmation retention, and CLI
process-crash files remain separate roadmap work.

## Within-check prompt receipt local acceptance

The R1.2b prompt-only increment saves configured-canary confirmations before their
prompt category returns, including before response/session cleanup and pacing.
An immutable receipt binds one actual evaluated transport response to its finding,
asset execution, frozen probe definition, public context, and as-of counters.
Receipts are separate from finalized checks: unfinished coverage stays explicit,
and neither an interrupted check nor nondisclosure establishes a pass.

New checkpoint version 2 preserves both ledgers. Receipt IDs and run identities
cannot be replaced, and acknowledged receipt order is an exact immutable prefix.
Asset and security-result copies must agree. Malformed raw adapter receipts fail
before report admission; unsupported custom engine findings remain visible but cannot
fall back to legacy scoring. Current-root reports with missing asset contracts
also fail closed. Actual historical reports and the standalone paired benchmark
retain their earlier contract; frozen prompt bytes, hashes, and budgets are unchanged.

Local producer and contract cases, including actual loopback HTTP, cover response/session cleanup failures, pacing and
later-request cancellation, request budgets, task isolation, missing/unbound tokens,
metadata-only canary echoes, reflected prompts, raw/public validation, and native
model-in-endpoint adapters. A persistence error or cancellation remains fatal even
if cleanup raises a second ordinary error. Counters exclude callbacks and cleanup;
they count reserved attempts, not guaranteed delivered wire requests.

Eight actual CLI-path cases cover baseline/candidate suites, JSON/SARIF, and
deadline/cancellation while the first category is unfinished. Outputs retain the
confirmed finding, receipt, 70/high with partial coverage, and truthful terminal
status in owner-only files. Two spawned dispatcher cases wait for the actual
first-response evidence commit, kill the process before category return, and
verify exact evidence/snapshot retention, one interrupted event, idempotent restart,
and no probe replay. These are acknowledged-commit process tests, not power-loss
or CLI process-crash durability.

The real server worker and Flask API client retain the same evidence through
deadline/cancellation in private fixture SQLite. Result, inventory, high-risk filter,
and SARIF views agree on risk and coverage. Negative writes execute while the real
claim is still running, and rejected changes leave report/snapshots/counts unchanged.
Their oracle comes from private fixture discovery, not a new API field. Separately,
the existing actual dispatcher/profile/template workflow runs frozen production
prompts against vulnerable and quiet fixtures with unchanged privacy assertions.
No finding or score is seeded in these normal-execution retention tests.

Scan-wide guards protect newly emitted public descriptors. Redaction never exempts
secrets to preserve scores; unsupported or redacted provenance stays unassessed
without erasing independently eligible assets. Raw generated text, canaries,
credentials, and private request tokens remain out of JSON/SARIF and retained state.
Public receipts attest scanner observations, not independently verified target
seeding or cryptographic report authenticity.

Combined Linux/Python 3.10 acceptance passes 3,216 cases with CI coverage
instrumentation, warnings treated as errors, and an inherited nonexistent
evidence-registry sentinel. Independent review passes 793 overlapping coverage
cases. All 143 dashboard JavaScript cases, Ruff,
configured Bandit, whitespace checks, distribution build, Twine, and a fresh
installed-wheel smoke outside the checkout pass. All thirteen changed runtime
modules in the wheel match the working source. Normal and optimized disposable
backup acceptance each pass all eight cases. These counts are regression coverage,
not independent model observations or detection-effectiveness measurements.

Interruption fixtures wait for actual progress before cancelling; the 35-receipt
profile workflow has a finite test-local timeout allowance. Production deadlines,
request budgets, and evidence assertions are unchanged.

See PR #67 for required cross-platform CI results. This local prompt-only slice
does not close tenant/access within-check retention, CLI crash files, nullable
database scores, or exhaustive inventory filtering. No GCP service, external model,
operator registry/database, package publication, or deployment was used.

### Prompt request-reflection correction

All eight PR CI jobs passed at `9c411ad`, but independent owned-loopback audit found
an existing detector gap and held the merge for the correction below.
The unchanged full catalogs, actual request adapter/transport/analyzer, normal
pipeline/scorer, canonical projection, and checkpoint callbacks produced these
pre-correction results:

- Exact collisions in the model, credential, URL, normalized URL, and explicit
  header value were refused before HTTP and remained unassessed.
- A target that only echoes an automatic User-Agent or a rendered Content-Type
  header produced 35 confirmations, 35 receipts, and 70/high in baseline mode.
  Baseline CLI/Python input rules accepted those nonopaque markers, but
  candidate and server-profile marker grammar rejected them.
- Uppercasing a reflected model or credential also produced 35 confirmations,
  35 receipts, and 70/high in baseline and candidate pipelines. These synthetic
  canaries were deliberately related by case to outbound values, not independent
  target secrets. Subsequent regression cases also reproduced the model echo via
  genuine discovery, profile loading, model overrides, and server dispatcher
  execution in both suites, without finding/report/score seeding. The full server
  credential-echo path remains untested because there is no corresponding owned
  loopback credential input in that API workflow.
- Standalone execution also confirmed those reflection cases. The paired benchmark
  falsely detected both uppercase cases in both complete 35-request arms and all
  seven categories. Its exact-model collision and nonopaque automatic-header
  inputs were refused before HTTP.

No protected data existed on these echo fixtures. The draft receipts faithfully
preserved the false confirmation; they did not establish protected provenance.
The corrected producer and receipt minting independently require complete bounded
request provenance, including actual serialized body bytes and final transport
headers. They exclude case-normalized outbound values and decoded/rendered request
forms while keeping response matching exact. Current receipts require source
version 2.0; draft version 1.0 stays structurally readable but ineligible for current
receipt-backed risk. Missing, incomplete, oversized, compressed, or chunked request
provenance cannot confirm. None of this private request material is exported.

The 72-case reflection regression suite passes, covering owned-HTTP execution,
before-I/O admission refusals, normal pipelines, checkpoints, standalone/paired
benchmarks, server profile/API behavior, privacy,
and genuine 35-confirmation/seven-check/70-score controls. The 61 new core cases
cover bounds, immutable capture, completeness, and an overridden analyzer that
cannot mint without valid request exclusion. Two legacy compatibility cases are
described below. Offline component fixtures explicitly declare complete synthetic
request bytes; they are separate from real-HTTP acceptance. The combined 3,216-case
gate and 793-case independent coverage review pass. Frozen prompts, probe hashes,
and request budgets are unchanged. This is not an arbitrary-transformation proof.

At that checkpoint, legacy finalized prompt reports retained numeric eligibility.
Two compatibility cases preserved the pre-receipt report shape,
stored/exported JSON, API scores, and unresolved lifecycle through nondisclosure;
they did not attest historical request provenance. A separate historical prompt
guard was required before nullable-score migration. Old benchmark observations also
remain tied to their recorded producer revision, not upgraded to production
receipt evidence or a new detection-effectiveness claim. The historical eligibility
follow-up below supersedes that numeric-compatibility limitation without rewriting
the archived evidence.

### Historical prompt eligibility follow-up

Current versioned scoring and canonical projections require supported source-2.0
receipts for prompt confirmations even when the report has no receipt envelope.
Matching old check/finding identities cannot supply missing request provenance.
Both unsupported positive findings and unsupported positive check records make
their asset's current numeric score unknown. A valid companion pass cannot turn
the discarded claim into zero; a supported companion finding remains visible.
Independent assets retain their valid scores and risk-filter membership. If the
archived summary no longer matches the eligible asset maximum, it remains unknown.

The guard does not change stored report JSON, original scores or finding IDs,
archival JSON/SARIF exports, or comparison identities. Later nondisclosure cannot
resolve a historical or current prompt finding. Invalid current receipt envelopes
remain fail-closed; the change does not invent missing receipts, re-run old probes,
or perform supported-subset historical score reconstruction. Standalone benchmark
observation collection and the explicit unversioned low-level scorer API retain
their separate compatibility contracts, not current canonical-risk eligibility.

Pre-correction regression runs reproduce 19 failures in the 39-case core suite
and 16 failures in the initial 20-case consumer suite. The final 39 core and 28
consumer cases pass. They cover completed/partial history, check-only and
finding-only positives, supported access companions, independent assets, current
HTTP-produced receipts, stripped/draft/malformed provenance, filters, and archive
immutability. These are overlapping synthetic regressions, not model-effectiveness
observations.

The complete Linux/Python 3.10 gate passes 3,281 tests with coverage and warnings
treated as errors. Independent review passes 1,170 overlapping coverage cases.
All 145 dashboard cases pass. Real Chromium at 320/390/1440 pixels shows archived
prompt groups as Not assessed with their original occurrences and exports intact;
a separately labeled generic partial-score fixture still displays 70. Actual
source-2.0 prompt positives retain 70/high in the HTTP/API regressions. The owned
browser process and temporary database were cleaned up.

The grouping fixture now obtains 18 actual receipts across the 35 unchanged
prompt requests. The partial-risk fixture obtains one receipt followed by four
actual 503 responses, not an invented failed-request counter. Both preserve
positive score and privacy assertions. Ruff, configured Bandit, whitespace and
authored-text audits, build, Twine, and installed-wheel smoke pass; the changed
runtime module matches its wheel bytes. Normal and optimized disposable
backup/restore each pass all eight cases. Required PR/post-merge CI results are
recorded on the delivery PR.

Frozen prompt catalogs, probe hashes, request budgets, detector logic, database
schema, and server policy are unchanged. No GCP service, operator data, deployment,
or publication was used. Tenant evidence provenance, nullable storage, and the
remaining R1 milestones are still separate work.

### Tenant evidence prerequisite for the next increment

Read-only next-slice review reproduced an existing cross-tenant reflection gap
with the unchanged five-prompt privacy tester, actual adapter/SafeSession, owned
loopback HTTP, and synthetic values. A server with no tenant data echoes either
the request's model value or Authorization value. When that request value equals
the configured foreign-tenant canary, each fixture produces five confirmed
findings and a completed/confirmed check. The shared eligibility function accepts
that check. This is not a full-server score measurement or a new external lab run.

The tenant canary is excluded from the prompt but not from every outbound request
field. The tester also lacks an independently successful authorized tenant-data
baseline. This predates prompt receipts. Correct the outbound reflection boundary
and define the tenant authorization/provenance contract before persisting these
observations inside unfinished checks. Existing legacy findings must remain
readable without being silently promoted to stronger current evidence.

### Controlled tenant evidence local acceptance

The tenant slice replaces scalar-canary confirmation with explicit CLI/Python
owner/tested principal declarations, two seeded records, and an operator-attested
authorization boundary. Three independent-session controls must succeed before
the unchanged five attacks. Owner and tested records must be demonstrably
available under their issued credentials; a fresh invalid credential must be
denied without either marker in its body or headers. A leak in the tested control
is held until all controls succeed. Nondisclosure never passes or resolves a leak.

All keys, markers, and the invalid control credential are pinned before the first
checkpoint. Known material is guarded before any active scan request, including
requests outside the model adapter. Complete actual snapshots detect automatic
header contamination and incomplete transmitted provenance. The private audit
blocks subsequent tenant confirmation without deleting an earlier valid finding.
Public findings carry recognized versioned controls and exact original endpoint,
provider, model, and public-context binding. Raw responses and private declarations
remain omitted. Server admission, saved source replay, queued definitions, and
fresh discovery reject private tenant inputs before environment resolution.

Local fixtures cover vulnerable and defended controls, stale or equal credentials,
unseeded/overlapping markers, metadata-only observations, contaminated denials,
request reflection, remembered earlier headers, session isolation, environment
rotation, TLS prerequisites, shared budget exhaustion, and interrupted checks.
Normal CLI scans keep every tester stage active and complete successfully with
90/critical for a genuine controlled leak and null/unknown for nondisclosure.
Only test-local pacing is shortened. Current completed and partial producer
reports keep the same score in saved pipelines, API results, and inventory after
fresh database reads. Historical positives remain downloadable and unresolved;
companion access evidence cannot turn their asset into zero or inherit a score.

The first full coverage run found one privacy regression: attaching the expected
endpoint to every direct engine result exposed a private URL in a skipped
missing-credential diagnostic. Independent review found the same defect. The
correction limits those direct-result binding fields to prepared tenant inputs;
the existing privacy assertion remains unchanged. The focused correction gate
passes 120 cases.

Final local acceptance for runtime commit `7e31584`:

- Linux/Python 3.10.20: 3,515 tests pass with coverage and warnings treated as
  errors in 195.55 seconds. The preceding diagnostic run had 3,514 passes and the
  one corrected privacy failure; it is not treated as an accepted run.
- Independent final review passes 247 overlapping cases with coverage and
  warnings treated as errors, including all 17 adversarial regressions. Its
  earlier broader run had 1,000 passes and the same corrected privacy failure.
  Component gates also passed 446 core cases and 552 input/privacy cases.
- All 145 dashboard unit cases pass. API tests use actual completed/partial
  producer reports and fresh database reads. No new browser styling is included.
- Normal and optimized disposable backup/restore commands each pass all eight
  cases. Ruff, configured Bandit, whitespace, authored-punctuation, and scoped
  private-identifier checks pass.
- Distribution build, Twine metadata validation, and installed-wheel smoke
  outside the checkout pass. All 12 changed packaged runtime files match the
  source bytes. The local wheel SHA-256 is
  `cde230c0c20fce50b4206e12d68507017f2109f47d3442fc9aea34cd0717aebd`.

Independent runtime and documentation review approve the corrected slice.
Required cross-platform PR and post-merge results are recorded on the delivery
PR. The package version remains `1.1.0`; release identity is separate R1.5 work.

Limits: principal identity and seed provenance are operator assertions; request
snapshots exclude bounded known representations, not arbitrary transformations.
Owner controls returning both markers remain unsupported/inconclusive. Tenant
within-check receipts, CLI process-crash files, server tenant profiles, database
score migration, and broader enterprise acceptance remain open. No real model,
GCP service, deployed configuration, operator database, or package publication was
used. The next external step is a pinned
[tenant workflow retest](tenant-retest.md) against genuine tenant-aware fixtures.

### Supplied tenant workflow acceptance

The operator supplied a scoped HTTPS fixture retest of merged revision
`1072d8b8b7763bb9a09b0d4047cbd4afa3ffbf93` (PR #69) on Debian 12/Python 3.11.2.
Two independent artifact reviews inspected the nine original reports, ten real
CLI exit files, fixture source/outcomes, job captures, and driver behavior. These
are reviews of supplied evidence, not new cloud executions. Private artifacts,
infrastructure identifiers, configurations, and secrets remain outside Git.

All nine reports validate under the current contracts. Independent rederivation
matches all 70 recorded expectations and the complete recognized probe version.
The shared eligibility and risk projection preserve these results:

| Fixture | Runs | CLI / scan | Tenant check | Attempt / evaluated | Findings / risk |
| --- | --- | --- | --- | --- | --- |
| Vulnerable | 3 | 0 / completed | completed / confirmed | 8 / 8 | 5 each, 90/critical, sampled |
| Defended | 3 | 0 / completed | completed / inconclusive | 8 / 8 | 0, null/unknown |
| Unseeded owner | 1 | 1 / partial | failed / inconclusive | 1 / 0 | 0, null/unknown |
| Marker-bearing invalid denial | 1 | 1 / partial | failed / inconclusive | 3 / 2 | 0, null/unknown |
| Unseeded reflection endpoint | 1 | 1 / partial | failed / inconclusive | 1 / 0 | 0, null/unknown |
| Missing environment value | 1 | 1 / no report | no security execution | none | no report |

All six successful tenant sequences have owner, tested, and invalid controls
followed by attacks 0 through 4. The negative cases stop at their intended
controls and send no tenant attacks. No tenant check passes. All 521 captured
fixture POST entries reconcile with the supplied outcome summary; fixture GET
requests are unlogged, so that count is not a complete scan wire total.
The normal installed CLI and default verifying HTTPS path were used. Setup and
job captures record a successful verifying TLS 1.3 handshake through a private
trusted CA on a non-loopback endpoint. Trust-store provenance and cleanup remain
operator attestations. No model server participated; these deterministic fixtures
validate the configured workflow, not representative detection sensitivity.

The original nine reports contain 110 response-excerpt omission sentinels and no
other recognized raw-text evidence fields. Secret absence and original modes
remain operator attestations because actual values are excluded. The captured
privacy sweep covers the original 37-file deliverable, not all 50 files in the
final expanded bundle. Its twelve JSON-mode entries comprise nine reports and
three summary/dependency JSON files. Added private driver sources contain their
synthetic PII constants; do not claim zero such constants across the whole final
archive or publish those drivers as acceptance artifacts.

Two negative-case claims in the supplied narrative need narrower interpretation.
The contaminated-denial fixture returns only the tested marker in the tested
control, so it verifies rejection of a marker-bearing denial and attack
suppression, not disposal of a held positive candidate. The reflection fixture
stops at an unseeded owner baseline; it does not exercise a protected marker
embedded in reflected material. Those stronger cases retain local regression
coverage, without new external acceptance from this run. Versioned finding
control fields apply to the confirmed findings, not every inconclusive run.

The private job wrapper masks analysis-command failures, and its privacy failure
count omits several conditions that its report prints. Its overall exit alone
cannot certify acceptance. Actual per-scan exits, all 70 captured expectations,
and recorded privacy counts support the observations above. Before another
external run, propagate analysis/privacy failures, check every privacy condition,
capture cleanup outcomes, and add any claimed held-candidate negative explicitly.
These harness and wording limits do not require another broad GCP run.

This closes the scoped CLI/TLS workflow gate with the stated qualifications.
Server tenant profiles, tenant/access within-check receipts, CLI crash files,
real-model sensitivity, and enterprise acceptance remain open. The next local
R1.3 slice is nullable score storage with explicit historical schema definitions,
canonical cache projection, rollback, and disposable backup/restore acceptance.

### Nullable score storage local acceptance

PR #72 replaces unknown scalar-score placeholders with SQL NULL
in schema 4. The two score columns have no zero default. Canonical report risk,
not a caller's cached number, supplies checkpoint and terminal summary/snapshot
values. Cancellation and recovery also project the retained summary. Supported
assessed zero and confirmed partial scores survive; unsupported old access,
prompt, and tenant positives cannot acquire numeric risk from stale columns.
API reads remain on the saved canonical report, and archived reports stay intact.

Recognized unversioned layouts and versions 1 through 3 use explicit historical
definitions independent of current ORM metadata. Only the two score-bearing
tables are rebuilt. SQL copying preserves stored JSON/text bytes, IDs, and other
fields; accepted ordinary/partial nonunique indexes retain their original SQL.
Expression/unique indexes, table options, collations, conflict policies, unknown
constraints, and unsupported layouts are rejected before writes. Table creation,
copy/drop/rename, index replay, cache updates, and version stamping share one
BEGIN IMMEDIATE transaction under existing dispatcher ownership.

Archive and metadata interpretation uses SQL byte bounds before deserialization,
an explicit 64-container nesting limit, and incremental record processing.
Invalid, deeply nested, or oversized material
leaves unknown caches without echoing contents. Valid non-object metadata follows
the API row-ID fallback; malformed explicit aliases cannot fall back. Duplicate
report IDs remain unassessed. Duplicate database aliases retain the current API
semantics, rather than introducing a different storage-only identity policy.

Final local evidence:

- Linux/Python 3.10.20: 3,763 tests pass with coverage and warnings treated as
  errors in 278.49 seconds. The gate includes independently frozen old schemas,
  genuine assessed zero, supported positive/partial evidence, historical unknowns,
  rollback at every rebuild stage, and invalid UTF-8/deep/oversized archives.
- Independent corrected-code review passes 279 overlapping cases on exact Python
  3.13.15/SQLAlchemy 2.1.6 with coverage and warnings treated as errors in 46.72
  seconds. This includes 56 new independent bounds cases, 76 depth cases,
  32 original adversarial cases, 56 migrations, 15 writer cases, 40 checkpoints, and four current
  HTTP proofs. The initial pre-correction review passed 423 overlapping cases;
  the fixture/backup slice passed 248. Reviewer-approved runtime bytes match the
  integrated tree.
- A separate final Python 3.13.15/SQLAlchemy 2.1.6 gate passes 370 overlapping
  cases with coverage and warnings as errors in 94.81 seconds, including backup
  fixtures and final cleanup changes. Its log has no resource or unraisable
  warnings, including shutdown. Lifecycle instrumentation records 156 opened and
  156 closed SQLAlchemy connections. All 15 compared runtime/test/script files
  match integration bytes.
- Four real HTTP producer cases retain current prompt 70/high and tenant
  90/critical evidence through schema-3 upgrade, for completed and partial reports.
  Their original archive bytes remain unchanged. No model server participates.
- All nine supplied tenant report copies also pass an offline schema-3 to 4
  upgrade in private disposable SQLite: canonical scores and archive bytes match,
  and second initialization is idempotent. No operator database or cloud is opened.
- Normal and optimized backup commands each pass all ten cases, preserving
  supported zero, retained 70/partial, non-cache fields and reports, and untouched
  source/backup hashes. Six corruption cases prove the acceptance command rejects
  damaged score caches. No existing operator database path is accepted.
- All 145 dashboard cases pass. Ruff, configured Bandit, whitespace, authored-text
  and scoped privacy checks pass. Distribution build, Twine validation, and the
  installed-wheel smoke outside the checkout pass. The three changed packaged
  runtime modules match source bytes. The final local wheel SHA-256 is
  `a092b0562e8decffecf465d4b9f55680224740d0466350ae86b2c7a88b2f3ab3`.

The merged CI-fixture correction changes no runtime bytes. A focused final gate
passes 35 workflow/writer/guard cases with coverage and warnings treated as
errors in 16.25 seconds after that merge.

The preceding documentation-only merge's Python 3.11 job hit the 15-second CLI
workflow fixture deadline in two disclosure cases; its other seven jobs passed.
Independent covered reproductions complete all 35 prompt observations and retain
70/high. PR #71 gives that workflow fixture 45 seconds, preserves its sample,
completion, privacy and file-mode assertions, and leaves production deadlines
unchanged. It also makes malformed-engine setup explicit for SQLAlchemy 2.1;
the five guard cases pass with warnings as errors on both 2.0.54 and 2.1.6.
PR #71 merged as `de58212` with all eight PR and post-merge jobs passing.
The original CI failure remains recorded. Slower host execution is an inference;
host load was not captured.

The first PR #72 macOS run passed 3,630 cases and failed one depth regression:
Python 3.13.15 accepts JSON nesting that raises a recursion error on Python 3.10,
so excessively deep snapshot metadata inherited a row-ID fallback score. An
isolated Python 3.13.15/SQLAlchemy 2.1.6 reproduction confirmed the failure.
The correction imposes an explicit 64-container limit before JSON parsing and
for object-based cache writes. UTF-8 text, including an optional UTF-8 BOM, is
accepted; non-UTF-8 BLOBs fail closed. Archives remain untouched. The original
assertion is retained. The unfinished Linux jobs were cancelled after their
verbose logs reached an 8 MiB fixture value embedded in a generated case ID.
Explicit short case labels replace those IDs without changing test inputs or
assertions. The macOS failure remains recorded.

Strict Python 3.13 validation also exposed test-fixture resource ownership gaps.
The checkpoint fixture now restores the original engine before parent teardown
and disposes its owned file pool. The API fixture disposes the exact in-memory
engine it initialized, including setup or teardown failure. A raw SQLite fixture
uses an explicit closing context as well as a transaction context. These are
test-only cleanup changes; connection lifecycle instrumentation verifies closure.

PR #72 merged as `3f32c6e6dd8a52832401df69bd92f263bfad11e8` with all eight
PR and post-merge CI checks passing. The supplied
[native storage/server upgrade retest](storage-retest.md) is accepted below for
its stopped reconstructed fixture and exact merged revision. This local
acceptance does not certify an operator deployment or downgrade compatibility.
Restore an untouched pre-upgrade backup for rollback. The supported runtime remains
one POSIX process, local filesystem and SQLite; package publication is separate.
Tenant/access within-check receipts, CLI crash files, exhaustive inventory, release
identity, real-model sensitivity and later enterprise gates remain open.

### Supplied native storage upgrade acceptance

Two independent read-only reviews accept the supplied run at
`3f32c6e6dd8a52832401df69bd92f263bfad11e8` for its scoped storage upgrade and
restart workflow. These are reviews of operator-supplied captures, not an
independent cloud rerun. The environment records Debian 12, Python 3.11.2,
SQLite 3.40.1, SQLAlchemy 2.1.6, and Gunicorn 26.2.0. Raw reports, driver sources,
private infrastructure identifiers, databases, and credentials remain outside Git.

Both normal and optimized native backup commands exit zero with all ten expected
cases and 50 assertion labels per mode. All 60 real-server assertions reconcile
with the captured PASS lines and the zero-failure summary. Both Gunicorn
processes use one worker and exit zero. The driver constructs terminal records,
no schedules, an empty allowlist, and no scan submissions.

The reconstructed schema-3 fixture contains four reports and ten observation
rows. Two parsed existing lab pipelines are unassessed; two current repository
controlled-access producers supply genuine assessed zero and confirmed partial
risk. All initial scalar caches are 0.0 placeholders. On first start and restart,
the raw SQL scan/observation caches and results API score/level pairs match the
expected null, 0.0, and 70/high outcomes. The two score columns are nullable with
no SQL defaults. Logical JSON exports equal the seeded reports. Archive hashes
are unchanged from the post-seeding baseline, and restart preserves the complete
recorded database snapshot. Independent restore reproduces the schema-3 baseline;
source and backup hashes remain unchanged. Captured database and lock modes are
0600. The logged security-testing error is the intentional later-stage failure
that creates the supported confirmed-partial fixture.

Acceptance has these limits:

- This upgrades a newly reconstructed fixture, not the original durable lab
  database. Existing pipelines are parsed and reserialized before seeding;
  byte preservation starts after that step. The lab's original durable records
  provide no supported assessed-zero or positive case. Report provenance and
  excluded database/response contents remain driver/operator attestations.
- Inventory checks compare HTTP status and response shape only. SARIF checks
  compare availability and version only. Neither verifies verdict values.
  The eight logged summary statuses match the stated fixture expectations, but
  the driver does not assert them. Per-asset coverage is not asserted. Results
  score/level comparisons are substantive.
- The first upgrade does not compare non-cache fields of the two rebuilt tables
  against their old baseline, or explicitly verify operator-defined indexes.
  Template, schedule, and occurrence tables are empty. Their equality checks
  do not establish nonempty-data preservation.
- Native backup rollback cases inject version-stamp failure for three historical
  versions, not failures at every rebuild stage. These fixtures do not exercise
  depth, encoding, or size rejection. The 64-container boundary and other rebuild
  rollback stages retain their separate local regression evidence.
- The recorded privacy sweep covers 17 paths at that moment; the final bundle
  has 25 regular files. Later additions and the completed job log do not have
  the same complete captured sweep. True-secret absence and original modes are
  operator attestations. The private bundle contains infrastructure identifiers.
- The shell wrapper does not propagate every setup, capture, sanitizer, privacy,
  or cleanup failure, and raw-text/mode observations are informational. Its
  unqualified fail-closed claim is unsupported. The separate captured command
  exits and 60 actual comparisons still support this narrow successful run.

No runtime defect was reproduced. These qualifications do not require a broad
repeat or establish deployment, model sensitivity, complete preservation of every
field, or every export's verdict semantics. R1.4a proceeds locally with exhaustive
observation pagination; its eventual operator gate must compare actual inventory
values and fail on analysis, privacy, and cleanup errors.

### Exhaustive observation pagination local acceptance

R1.4a replaces the global inventory's newest-100 filter window with bounded
cursor traversal. Existing observation fields, snapshot IDs and scan-local
aliases remain intact. Risk filtering uses canonical saved-report projection,
including supported zero and historical unknowns; stale scalar scores/levels
never exclude candidates. Empty pages can carry continuation. Completion applies
after the current cursor boundary and requires consumers to retain prior pages.

Schema 5 adds one organization-generation table, three candidate indexes and
nine exactly recognized triggers. Schema-4 rows, scalar caches, archive bytes and
accepted operator indexes are preserved without a second nullable-table rebuild.
Recognized older layouts retain their nullable upgrade before generation install.
Source writes, ownership changes and orphan visibility invalidate affected
organizations in the same transaction, including direct ORM/Core writes.
Rollback, other organizations, progress-only scan-session updates and unchanged restart retain
the generation. Unsupported trigger/index definitions fail before serving.

Cursors use an uncompressed signed codec with a 4,096-byte cap, 15-minute expiry,
and bindings to organization, filters, limit, order, source generation and
projection policy. Packaged Python source contributes to the policy fingerprint.
Request/scope validation precedes SQL. Stale data/policy returns 409; invalid
cursors/filters return 400. The reader has 500-candidate, 32-report, combined
16 MiB source and 1 MiB response allowances, plus individual 8 MiB/64-container
limits and a five-second cooperative deadline. Unreadable or excessive sources
return static 503 rather than becoming false unknowns or disappearing from a
filtered search. Actual query plans use the ownership/type/order indexes but can
still require a cross-scan sort; SQL LIMIT alone is not a complete work bound.

Final local evidence:

- Python 3.10.20: 3,964 tests pass with coverage and warnings treated as errors in
  383.71 seconds; source/API/CLI line coverage is 94 percent.
- All 145 dashboard tests pass. Ruff and configured Bandit pass, including the
  public acceptance scripts. Distribution build, Twine metadata checks, and the
  installed CLI smoke outside the checkout pass. The three changed packaged
  inventory/schema modules match source bytes, and the direct signing dependency
  is declared. Local wheel SHA-256:
  `4f486be8cd3ee2861300c4d7068d7c6ed2ab219dcb9908ad4e2648efc48dce7f`.
- Final independent review passes 99 overlapping committed cases on exact Python
  3.13.15, SQLAlchemy 2.1.6 and Gunicorn 26.2.0 with coverage and warnings as errors
  in 49.13 seconds. All 12 compared runtime/script/helper/test files match
  integration bytes. No resource, unraisable, or shutdown warnings remain.
- The independent inventory fixture traverses 10,000 observations across scans,
  types and organizations, comparing full ordered descriptors. It covers older
  findings, ties, duplicate aliases, malformed explicit aliases, genuine zero,
  historical unknowns, contradictory SQL caches, cursor scope/tampering/expiry,
  generation changes, actual WAL concurrent writes and source/output budgets.
- The schema component passes 152 overlapping schema/generation/schedule cases,
  including 29 new generation cases. The backup suite passes 62 cases, including
  frozen schema-4 independence and genuine schema-5 initialization. Normal and
  optimized native commands each accept all eleven cases. The v4 case proves
  preservation without a nullable-table rebuild; generation owner/token shape,
  progress stability and restart stability are checked.
- The public operator command exercises real single-worker Gunicorn upgrades
  from a private schema-4 fixture, 10,000 repeated observations of 12 synthetic
  assets, eight filter profiles across three organizations, and restart. It
  checks complete values rather than availability, existing rows/scalars/archive
  and index preservation, source changes/rollback, actual process exits and no
  admitted work. Real normal/optimized runs and failure injections form 30 author
  cases; the final independent gate includes both real-server modes.
- Mandatory privacy checks cover seven configured synthetic/runtime values,
  encoded variants, HTTP bodies/headers, private files and final output. The
  authentication response has a narrow expected token exchange. Missing values,
  unreadable surfaces, mode changes, privacy findings and cleanup errors fail.
  Source revision, tracked modification state, driver/app/hook hashes and policy
  are captured. These owned fixtures never inspect operator databases/profiles.

Pre-delivery regressions caught two cursor-key defects. Normalizing valid old
timestamp text repeated or rejected continuation pages; cursors now preserve the
actual stored sort key with an explicit string bind. Display parsing alone
normalizes supported fractions/UTC syntax. Tests compare against SQLite's actual
ordering, including mixed representations and offsets, without rewriting stored
timestamps. Maximal legal UTF-8 scope/key values could also exceed the input cap;
UTF-8 JSON encoding plus an emitted-length guard keeps usable tokens bounded.
Valid signed compressed/marker-prefixed formats are rejected before SQL.

The public gate originally accepted Boolean false as numeric zero under Python
dictionary equality. Its numeric type guard now rejects Boolean scores while
accepting integer and floating zero. Independent negative/positive controls
reproduce and verify the correction. An initial combined run passed 3,951 cases
and failed five old fixture/order assumptions: file-backed API fixtures bypassed
schema initialization, and profile assertions selected an unspecified first SQL
row. Fixtures now initialize the real schema; assertions join by asset ID and
check complete cardinality/ID sets plus the skipped null. The targeted 156-case
covered gate and final full run pass without relaxing verdict assertions.

Initial Linux CI exposed two overly specific query-plan assertions. SQLite
3.45.1 selected the type index's valid `scan_id` prefix for an unfiltered join,
while SQLite 3.53.1 selected the other candidate index. The tests now accept
either approved indexed search for an unfiltered query and still require both
scan and type bindings for filtered queries. All 80 generation and independent
inventory cases pass on both SQLite versions with warnings treated as errors.
Runtime code is unchanged by this correction.

The delivery PR records required cross-platform checks. The next external gate
is the [clean pinned native inventory retest](inventory-retest.md), including
both operator-command modes and the eleven-case backup modes. Local synthetic
acceptance does not establish deployed workload scale, current asset identity,
indexed risk materialization, model sensitivity, or team/enterprise readiness.

### Supplied native inventory traversal acceptance

Two independent read-only reviews accept the supplied owned-fixture gate at
`c6e460046994c01aa40ff00f1660534413388f96`. These review operator-supplied
captures, not an independent cloud rerun. Primary outputs record Python 3.11.2,
SQLite 3.40.1, Gunicorn 26.2.0 and SQLAlchemy 2.1.6; the setup attests Debian 12.
Raw artifacts, private drivers and infrastructure identifiers stay outside Git.

Normal and optimized inventory outputs are byte-identical. Each records accepted
true, all 13 required assertion identities, 656 checked HTTP responses, an
observed schema-4 to schema-5 upgrade, and two zero server-process exits. The
source revision and clean tracked-source flag match the pin. App, public driver,
Gunicorn hook and independently recomputed projection-policy hashes match source.
The four acceptance exit files contain zero, their stderr logs are empty, the
pinned validation succeeds, and the captured outer job exits zero.

The 24 profile counts agree across modes: 10,000 observations in total, 2,500
high, 2,500 minimal, 5,000 unknown, and no critical matches despite deliberately
stale critical scalar caches. The type filter returns 5,000 observations; its
high subset returns 2,500. The incompatible type/high combination returns none
through advancing empty pages. The hash-bound public command compares complete
ordered dictionaries on first start and restart, checks cursor/source/ownership
isolation and rollback, and asserts archive, row and operator-index preservation.
Both backup modes accept the same eleven cases with 64 assertion labels per mode.
These include recognized old layouts, genuinely initialized schema 5, rollback,
exclusive ownership, incomplete-restore rejection and unchanged backup sources.

Acceptance remains scoped:

- The databases, raw HTTP responses and private internal server logs were removed
  by the public gate. Their detailed comparisons, process-group cleanup and
  filesystem modes are script assertions, not independently recoverable raw
  evidence in this bundle. Counts and result identities are directly available.
- This is 10,000 repeated observations of 12 synthetic assets across three
  organizations, using controlled non-network producers. It does not measure
  detection sensitivity, deployed scale, target provenance, current-asset
  identity, crash durability, or enterprise readiness.
- The inventory command checks seven ephemeral values, encoded variants and its
  HTTP/file/output surfaces before success. Those values are unavailable for a
  later independent sweep. The backup command has no equivalent seven-value
  privacy sweep. The wrapper's 19-file address-pattern sweep and local review of
  all 24 supplied files do not establish general secret absence. Sanitized outer
  logs and exact wrapper execution remain operator attestations.
- The private shell wrapper propagates acceptance/validation failures but leaves
  some setup, capture and checkout/venv cleanup failures unchecked; its address
  reader skips unreadable files. Its universal failure-propagation claim is
  unsupported. The public inventory command's own checked cleanup is separate.
- Backup captures have no embedded source/runtime fingerprints; their pin comes
  from wrapper context. Progress-token stability is covered by backup cases,
  not a dedicated progress-only cursor request in the inventory command.

No runtime blocker was found. These reporting qualifications need no broad
repeat. R1.4a observation traversal is accepted within this fixture scope;
distinct-asset identity and indexed risk materialization remain open. R1.5a
build/producer identity proceeds locally before tenant/access receipt retention.

### Supplied native tenant interruption acceptance

Two independent read-only reviews accept the supplied scoped gate at
`6af7fa2cd6d2a2b1e3ff67a12ff348df092f7413`. This reviews operator-supplied
captures rather than independently rerunning cloud targets. Captures record
Python 3.11.2 and SQLite 3.40.1; setup attests Debian 12. Private artifacts,
drivers, infrastructure identifiers and input values remain outside Git.

All four original reports pass trusted scan/evidence validation and canonical
risk projection. Their producer identities and bundled-catalog fingerprints
match the pinned CLI source. Offline SARIF preserves receipt/finding links and
marks incomplete execution unsuccessful. Report bytes remain unchanged. All
66 captured expectation records agree with the reports and real exits.

| Case | CLI exit/status | Tenant evidence | Canonical risk |
| --- | --- | --- | --- |
| Subject leak then stall | 1 / failed | One receipt at ordinal 2 with counters 3/3; unfinished check | 90/critical, partial |
| Attack leak then stall | 1 / failed | One receipt at ordinal 4, attack index 0, counters 4/4; unfinished check | 90/critical, partial |
| Held leak with contaminated denied control | 1 / partial | No receipt/finding; failed check, 3 attempted and 2 evaluated | Null/unknown |
| Defended | 0 / completed | No receipt/finding; completed inconclusive check, 8/8 | Null/unknown |

Both stalled cases reach the intended later tenant request before their outer
deadline; captured elapsed times are 181 and 180 seconds. Each retains exactly
one linked original finding and receipt under ledger `2.0` and checkpoint `3.0`,
with `checks_unfinished: 1` and no invented terminal tenant check. Control proofs
carry ordinals `[1, 2, 3]` and statuses `[200, 200, 403]`. In the held-rejected
case the tested control actually returns both records before a marker-bearing
denial prevents promotion. No tenant check passes, and no negative outcome
acquires a numeric assessment.

The secret-free fixture counters reconcile 45/46/55/60 POST arrivals: ordinary
POSTs plus the intended 4/5/3/8 tenant requests. They deliberately exclude the
ordinary GET probes visible in check accounting. Four CLI cases use two-principal
deterministic HTTPS fixtures with configured private-CA trust and hostname
verification. TLS 1.3 verification is captured. This tests the ordinary CLI
workflow rather than seeding scanner reports or database findings.

The native recovery capture records two passing tests with warnings as errors
and exit zero; the outer job exits zero too. Detailed SIGKILL, committed receipt,
single recovery event, no-replay and authenticated API assertions follow the
pinned repository test source. Those tests use owned loopback HTTP library
workers, despite the supplied narrative calling that request HTTPS. Their
transport is separate from the four external CLI HTTPS cases. They do not admit
private tenant input through the server API or establish CLI crash-file recovery.

Acceptance qualifications:

- The privacy capture covers 23 files, while the final bundle has 33 substantive
  files plus 37 AppleDouble sidecars. Eight JSON files include four scan reports
  and four auxiliary captures. The supplied helpers themselves contain configured
  synthetic labels and environment-reference names; a claim that every returned
  file omits those values is unsupported.
- The supplied sweep checks 15 available values and known encoded forms, but
  omits generated invalid credentials, environment-reference names and the native
  recovery fixture's private basis. Actual ephemeral values are unavailable for
  an independent repeat sweep. Logs are sanitized before checking. This supports
  the recorded capture sweep rather than general secret absence or a privacy
  certification. Native owner/tested keys and markers are fixed public test
  constants; they are distinct from the CLI job's generated values.
- The sweep skips unreadable files and missing environment values and tolerates
  invalid JSON. It runs before final wrappers, helper sources and the narrative
  are added. Some setup, copy, sanitizer and cleanup failures are unchecked or
  suppressed; no universal failure-propagation claim is justified. Trust-store
  and hosts cleanup completion remains operator attestation.
- Scanner JSON outputs have captured mode 0600. The original wrapper listing
  shows an output directory at 0755 and a job log at 0644, even though copies in
  the supplied archive are private. Do not infer uniformly owner-only original
  wrapper surfaces from the delivered copies or local extraction modes.
- Fixture seeding, authorization relationships, source checkout cleanliness and
  exact helper execution remain partly operator attestations. Deterministic
  fixture correctness is not model sensitivity, target provenance, deployed
  durability, or enterprise readiness. Counters log intended responses even if
  socket writes fail; they are not independent packet-delivery records. Raw logs
  and an independent before/after report hash chain are unavailable.

No scanner blocker was found in this gate. The qualifications need no broad
repeat. R1.2c tenant retention is accepted within this scope; protected-access
provenance/receipts, private server tenant admission and CLI crash files remain
separate work. No supplied driver was executed during review, and no operator
database, registry or cloud target was accessed.

### Protected-access v3 and cache-policy local acceptance

The provenance prerequisite below now has a bounded correction across the four
existing protected GET families. Public samples, request ordering and delays are
unchanged. Private issued keys, markers and environment references are pinned
before the first checkpoint. Model configuration and subsequent controls reuse
the pinned key even if the environment changes. Unknown contexts cannot silently
rebind a scan.

Every control and probe requires a real live `BoundedResponse` with a complete
captured GET: exact resource and Host, empty body, exact selected headers and
bounded normal framing. Missing, stale or incomplete captures, cookies, hidden
credentials and transmitted protected markers invalidate later evidence. Known
marker transmission in an earlier scan request taints the affected asset. No
request trace/counter algorithm or public ledger/checkpoint version is changed.

Denied controls and decisive denied probes inspect bounded body/header material
conservatively. Marker case variants and decoded JSON cannot masquerade as
absence. Invalid, duplicate-key, nonfinite or over-bound JSON, invalid encodings,
binary/NUL-bearing denials and embedded BOMs remain inconclusive. Valid UTF-8 BOM
JSON without disclosure is supported. Positive marker matching remains exact;
no semantic judge or arbitrary transformation exclusion is claimed.

`authorized-and-denied-resource-controls-v3` changes all four recognized probe
versions; confirmations additionally require builtin integer control version 3.
Missing/old/Boolean/floating tags cannot establish current confirmation. Frozen
v2 zero, high and partial reports stay byte-identical but project current unknown
and cannot establish resolution, including comparisons between two old reports.
Independent supported prompt/tenant evidence beside obsolete access passes
retains its original eligible 90/critical. Custom scalar-only mocks cannot attest
v3 wire provenance; projection unit fixtures explicitly use synthetic complete
captures while live acceptance uses actual owned HTTP/HTTPS.

Schema 6 is an explicit transactional scalar-policy upgrade. Recognized schema-5
tables/indexes/triggers and original archive/metadata bytes, IDs, queue/schedule
state and unrelated fields stay exact. Only changed risk caches/levels are
updated, and the version stamp commits last. Existing observation triggers
naturally invalidate affected owners; no trigger suppression or token restoration
is used. Unchanged owners and recognized schema-6 restart remain unchanged.
Recognized older layouts follow their existing nullable/generation upgrade paths.
Bounded UTF-8/depth/size interpretation and genuine alias rules are reused.
Fault injection at scan-cache, snapshot-cache and stamp stages rolls everything
back. This is not an arbitrary database repair or a deployment migration.

Four original v2 archives were captured through actual owned HTTP and the pinned
`6af7fa2` producer before source changes. Their independently fixed archive,
finding, receipt, probe and eight source-file hashes remain exact. Current v3
HTTP produces genuine zero, high/critical and confirmed partial results across
the existing four groups. Three fresh default CLI processes also reproduce and
close an INFO-log privacy gap: a protected marker, key or environment reference
used as an asset name was redacted in reports but leaked through three phase
messages. Static phase logs now retain those messages without private names;
no logging-level suppression is used and no database/registry is accessed.

The broad first run excluding the old current-policy test file passes 4,165 with
five failures: an earlier preflight/body fixture, two old test assumptions and
the two inventory runs still expecting schema 5. The complete corrected candidate
then passes 4,694 tests with source/server/CLI coverage, warnings as errors and
94 percent coverage on Python 3.10.20. A subsequent 838-case focused gate covers
the final three static log changes and the added 24 HTTPS CLI cases. Required CI
runs the final committed tree.

Author acceptance passes 214 provenance cases on Python 3.10 and 3.13; adding the
three fresh-process log cases gives 217. Independent review passes 74 live-wire,
archive and migration cases on both interpreters. All 464 current/legacy policy
cases pass on both. The 24 trusted HTTPS CLI cases pass on both with coverage and
warnings as errors: JSON/SARIF, certificate/hostname verification, 0/70/90 risk,
confirmed partial retention after later failure, genuine nonzero exits, stable
producer identity, owner-only files and raw/encoded privacy checks. They assert
that access observation receipts are absent; unfinished-check retention is not
implemented by this correction.

Cleanup accounting remains conservative rather than a wire count. The shared
response/session wrapper preserves cancellation through secondary errors and
combines formerly duplicated cleanup failure handling. One combined-error fixture
therefore records 37 attempted interactions instead of 54, while its actual 20
wire requests, 20 evaluated responses and one confirmation are unchanged. Current
and frozen legacy bounds are tested; no synthetic failures restore an old count.

The cache/nullable/backup gate passes 141 focused cases on Python 3.10 and 146 on
Python 3.13.15/SQLAlchemy 2.1.6. Both normal and optimized backup commands accept
all thirteen cases with genuine current HTTP results and frozen old archives.
Inventory format `inventory-acceptance-v2` first verifies schema-4 to 6 canonical
cache reconciliation for 12 scans/10,000 observations, then explicitly restores
its own original stale caches before traversal. Exact archives/non-cache rows,
known DDL, filters/cursors, restart staleness and cleanup are checked. All 40
inventory cases pass on both versions, including real normal/optimized Gunicorn;
independent review passes ten upgrade/restoration fault cases.

Final combined independent review passes 587 cases on Python 3.13.15 with
coverage and warnings as errors: policy, live-wire, HTTPS CLI, log privacy and
cache upgrade. Ruff and Bandit pass at the configured security threshold. Both
distribution formats build and pass metadata checks; an isolated installed-wheel
smoke verifies dependency consistency, CLI commands and exact build identity.
All 71 CLI wheel source files match the checkout bytes. Neither distribution
contains `AGENTS.md` or SQLite database files. Nothing was published.

These are local synthetic correctness gates, not model sensitivity, a deployed
operator upgrade, power-loss durability or enterprise readiness. No supplied
private driver, cloud target, operator database/registry, publication or deployment
was used. The next external gate is the scoped
[native access/cache retest](access-provenance-retest.md). Protected-access
within-check receipts, server private tenant inputs and CLI crash files remain
separate work. Cross-platform delivery checks are recorded on the implementation PR.

### Supplied native access and cache-policy acceptance

The supplied `aiscan-access-a9b2718.tar.gz` pins merged revision
`a9b27189296b55a114ccedb4638518d221be8b3c`. Its SHA-256 is
`786295f52ae6b0bf1b773165b7ba43795c64c0812142f9c09a8827cfcea8e8ac`.
Read-only results and static-harness reviews plus an independent offline
reconciliation accept the bounded [native gate](access-provenance-retest.md).
No supplied driver was executed during review, and no operator database,
registry or cloud target was accessed.

Captured runtime is Python 3.11.2, SQLite 3.40.1, SQLAlchemy 2.1.6 and Gunicorn
26.2.0; Debian 12 is operator-attested. The CLI build identity matches the pinned
checkout exactly, including its 71-file source digest
`0cb86e6d21de6a77357a191bdc5adeb92c2896b3f6f3c4ef034e9c8ee91e1581`.
Inventory driver, app, hooks and projection-policy hashes match that source.
Captured revision and clean-status files agree. These are bounded source
identity checks and checkout attestations, not independent execution attestation.

The five required files pass 337 tests in 20.94 seconds with warnings as errors.
The pytest exit, four acceptance-command exits and driver exit are all zero;
the outer job also records zero. All 109 unique captured assertion-table checks
agree with the available outputs and pinned source requirements.

Both normal and optimized backup runs accept the exact thirteen cases: versions
1 through 6, rollback 1/2/3/5, future, incomplete and lock. Their assertion
identities agree with the pinned public driver. These include archive-preserving
cache reconciliation, genuine current zero/high/partial and independent tenant
risk, unsupported historical access scores becoming NULL, recovery, rejection
and restart. Detailed schema/row/hash preservation follows those internal
assertions; original fixture databases and intermediate scan reports were not
returned for independent reconstruction.

Both inventory runs return `inventory-acceptance-v2`, schema 4 to 6, all thirteen
required identities, 12 reconciled scan caches and 10,000 observation caches,
followed by explicit restoration of their own original stale caches. Traversal
totals are 3,336/3,332/3,332 observations across the three fixture tenants;
high and minimal totals are each 834/833/833 and unknown totals are
1,668/1,666/1,666. Critical filters are empty. Each mode records 656 checked HTTP
responses, seven required private values across five surfaces, and initial plus
restart server exits of zero. Both normal/optimized JSON pairs are byte-identical.
Actual pages, process listings and database copies are not separately captured;
detailed traversal, rollback, cleanup and preservation rely on the public gate's
assertions. The 10,000 rows are repeated observations of twelve synthetic assets,
not distinct deployments or an operator database migration.

Privacy and wrapper qualifications:

- The bundle contains 32 substantive text files and 36 AppleDouble sidecars.
  Twenty-six substantive files are evidence, excluding five drivers and the
  report; the narrative's count of 27 evidence files is inaccurate. All
  substantive files are readable UTF-8. Public fixture constants coexist with
  generated values, so the narrative's random-only description is too broad.
- The on-runner privacy sweep lists 23 files at that moment. Its seven available
  values include three static PII patterns; missing environment values are not
  swept. It receives no private-prefix arguments. It precedes its own output,
  final job-log append and job exit file. A later strict sweep is claimed but
  has no separate captured receipt. Returned drivers contain expected public
  test constants and generic work paths. Deleted runtime secrets cannot be
  independently re-swept from this bundle.
- Human-readable logs were sanitized; raw originals and before/after hashes are
  absent. The available pytest log is dots plus its pass count, and all four
  acceptance stderr captures are empty. JSON preservation is an attestation
  supported by source shape and the cross-mode byte comparison, not a separate
  pre-sanitization hash chain.
- The wrapper uses incomplete failure propagation. Setup, sanitizer, copy,
  permission and cleanup commands have unchecked statuses and no cleanup trap;
  its universal cleanup-failure claim is unsupported. Critical test/acceptance
  commands do preserve their recorded exits and the assertion/privacy scripts
  affect the wrapper's failure flag. The wrapper also sources lab configuration
  for its sweep and inherits that environment; the scanner's absent profile-file
  override and owned public fixtures provide narrower isolation.
- The native listing shows scanner capture files at 0600 but the outer output
  directory at 0755 and job log at 0644. Delivered archive modes and private
  review extraction modes do not certify original wrapper permissions. The
  report's comparison against earlier local interpreter versions also disagrees
  with repository records; the captured native versions are the relevant facts.

No new scanner blocker was found. These qualifications need no broad repeat.
This accepts synthetic native access/cache, backup and inventory correctness;
it does not establish model sensitivity, independent target provenance, deployed
upgrade/durability, enterprise readiness or unfinished access-check retention.
PR #79 and its merge pass all eight CI jobs; the five PR full suites each pass
4,721 tests. Protected-access observation receipts are next; private server
tenant admission and CLI crash files remain separate gates.

### Protected-access observation retention local acceptance

R1.2d adds protected-resource response observations for the four existing GET
families. Normal writers select ledger `3.0` and checkpoint `4.0` before the
first checkpoint. Readers for ledger 1/2 and checkpoint 1/2/3 retain their frozen
meanings. The v3 control tag, default samples, delays, provider headers, request
budgets and response limits are unchanged. Modern probe hashes additionally bind
`protected-access-response-observations-v1`; stripping their ledger or links cannot
gain legacy finalized-check eligibility.

Private plans derive the selected request from pinned evidence and the frozen
catalog. Two actual issued/invalid controls establish the resource before a probe
can disclose its marker. Every observation requires a live response capability,
matching immutable body/request capture, exact selected headers and target,
original task/run/check identity and exactly-once evaluation. Publication occurs
before response/session cleanup, pacing or another request. Finalized checks and
receipt-backed unfinished checks remain distinct; no interruption invents a pass.

Public evidence binds the original base endpoint/provider/model/context, actual
control ordinals/statuses and numeric sample/header/path selectors. Joining an
admin path happens privately and is verified against the actual capture. This
avoids losing target eligibility when the known default credential `admin` is
redacted from displayed paths, without exempting it or accepting wildcard target
matches. A valid already-redacted initial report can remain structurally readable
with unknown risk. Strict minting/scoring still requires recognized metadata;
even the public read shape must match its corresponding target fields. Malformed
extensions cannot erase acknowledged eligible evidence or expose a companion zero.

Four original v3 archives were captured from actual owned HTTP and the pinned
`a9b2718` normal wrappers, engine, pipeline, scorer and checkpoints before source
changes. UUID/time controls were installed before production, with no report
restamping afterward. Fixed hashes bind all four archives and nine original
source files. Zero uses 62 GETs, high and later-503 partial use twenty each, and
mixed uses 62 GETs plus thirteen POSTs with five prompt and one tenant receipt.
Original IDs, bytes and canonical 0/70/partial/90 results remain exact.
Recognized schema-5 upgrade performs only the existing version stamp when those
caches already agree; schema-6 initialization performs no DML. There is no SQL schema
bump or additional historical cache reclassification.

Producer acceptance passes 98 actual-HTTP cases on Python 3.10.20 and 3.13.15,
plus the three existing fresh-CLI logging cases. Defended full samples retain
20/7/32 requests and three requests per configured admin path. Vulnerable weak-key
samples retain their existing per-key early break. All four vulnerable groups
produce 36 access observations over 58 actual GETs with eight declared paths.
Provider headers, explicit native model/context None, intentionally issued weak
candidates, per-path fresh controls, body/header disclosures, injected credentials,
pinned keys and failures before reservation are covered. Public-agent marker
preflight still preserves its earlier zero-request/null-risk behavior.

Core acceptance passes 54 cases on both interpreters for complete-ledger shape,
typed counters, proof order, aliases, missing/stripped links, frozen readers,
unknown public contexts, private capability misuse and sink/cancellation handling.
Six additional compatibility cases validate the original v3 reports and exact
schema/cache preservation. The combined cap is 77 receipts: 35 prompt, six tenant
and 36 access. These counts describe bounded correctness fixtures, not measured
detection sensitivity.

Independent acceptance passes 72 cases, including forty real trusted HTTPS CLI
JSON/SARIF cases across genuine zero, 70/high, 90/critical, later 503, deadline
and cancellation. Two process fixtures wait for acknowledged SQLite evidence and
a genuine fourth-request stall, then kill the actual dispatcher. A fresh owner
recovers the exact saved report and snapshots without replay; authenticated API
reads retain the same evidence and partial risk. A malformed append submitted by
the actual live owner is rejected without changing report/snapshots/audit/caches.
Tests also cover closed-token reuse, later request contamination, raw/encoded
privacy, owner-only state/report files and clean fixture-process shutdown.

The final combined independent Python 3.13 gate passes 1,052 overlapping cases
with coverage and warnings as errors: core/producer/independent/compatibility,
existing policy, and prompt/tenant checkpoint/export/recovery regressions. A
further 421-case gate verifies adapter version negotiation and the direct
experimental-suite descriptor guard. New public fields, control version and
existing probe-ID labels are reserved before candidate I/O. Frozen prompt catalog
bytes, suite semantics and pin remain unchanged.

The first full run passes 4,946 and exposes five failures: four old writer/future
version assumptions and the missing new descriptors in that direct suite guard.
After correcting those expectations and sharing the complete descriptor basis,
the final source/server/CLI coverage run passes all 4,983 cases with warnings as
errors and 93 percent coverage on Python 3.10.20. Ruff and the configured Bandit
gate pass. Required cross-platform checks are recorded on the implementation PR.

Both public backup commands exit zero and accept all thirteen cases; both normal
and optimized inventory commands exit zero with all thirteen identities, schema
4 to 6 and 10,000 observations. Their stderr captures are empty. Both distribution
formats build and pass metadata checks. An isolated installed-wheel smoke passes
dependency consistency, CLI commands and exact build identity; all 73 packaged
Python source files match the checkout. Neither distribution contains local
assistant instructions or SQLite database files. The native guide passes Bash
syntax and private mock-only setup/command failure-propagation checks.

These are owned synthetic correctness gates, not independent target-side seeding,
real-model yield, deployed upgrade/power-loss durability or enterprise readiness.
No private supplied driver, cloud target, operator database or registry was used.
Public API private-evidence admission and CLI process-crash files are unchanged;
the recovery fixtures use an explicitly configured owned library worker. No
package was published or service deployed. The next external gate is the
[scoped native access-retention retest](access-retention-retest.md), pinned to
the merged revision after delivery checks pass.

### Supplied native protected-access retention acceptance

The supplied `aiscan-access-retention-0797857.tar.gz` pins merged revision
`07978571ea99f778b6863a5be276fd512f6d2b99`. Its SHA-256 is
`36b43b5a12511c24326fbf88418ae2096565b9183dfeabadacebe57f89b06723`.
Read-only results and static-harness reviews accept the bounded
[native retention gate](access-retention-retest.md). No supplied script was
executed during review, and no operator database, registry or cloud target was
accessed. PR #81 and its merge pass all eight CI jobs each.

Captured runtime is Python 3.11.2, SQLite 3.40.1, SQLAlchemy 2.1.6 and Gunicorn
26.2.0; Debian 12 is operator-attested. The CLI's 73-file source digest matches
the pinned checkout:
`44c80f74a86eabdbcd43bf45dab2d8ac23db9e723bcb7c31c26de57c880cd28e`.
Inventory app, driver, hooks and projection-policy hashes match too. Revision
and clean-status captures agree. These are source-identity checks and checkout
attestations, not independent execution attestation.

The five required test files pass 230 cases in 29.29 seconds with warnings as
errors. Six captured step exits are zero: pytest, two backup modes, two inventory
modes and the driver. The outer job also records zero. All 110 unique captured
assertion-table checks reconcile with the available outputs and pinned source.

The tested retention paths include forty verified HTTPS CLI JSON/SARIF cases
and two owned dispatcher-process recovery cases. The latter wait for committed
receipt acknowledgement and a later genuine request stall, reject a malformed
append by the actual owner without changing SQL evidence, then kill and join
the worker. A fresh owner recovers exact evidence and snapshots; authenticated
API reads preserve 70/high or 90/critical with partial coverage and no probe
replay. These are library-worker fixtures, not new API private-input admission
or CLI process-crash files. Frozen finalized-v3 archives are read through the
current canonical projection while their original bytes remain unchanged.

Both normal and optimized backup runs accept all thirteen expected cases,
including frozen layouts, current schema 6, rollback and ownership rejection.
Both inventory runs return `inventory-acceptance-v2`, schema 4 to 6 and all
thirteen required identities. Each reconciles 12 scan caches and 10,000
observation caches, then explicitly restores its own stale fixture values before
traversal and restart. Each records 656 checked HTTP responses, seven required
private values across five surfaces and initial/restart server exits of zero.
Both normal/optimized JSON pairs are byte-identical. The inventory rows are
repeated observations of twelve synthetic assets, not distinct deployments.

Detailed receipt/control, schema/row/hash, traversal and cleanup conclusions
follow the reviewed public tests and gates. Raw fixture databases, intermediate
scan reports, HTTP pages and process listings were not returned for independent
reconstruction. The recovery cases assert owned-worker kill/join and lock
reacquisition; process-group cleanup is asserted separately by the inventory
gate. The supplied narrative conflates those scopes.

Privacy and private-harness qualifications:

- The returned tree contains 32 substantive UTF-8 text files, including 26
  evidence files plus five drivers and the report. Fixed public fixture keys,
  markers and references coexist with generated values; the random-only
  narrative is too broad.
- The on-runner privacy sweep lists 23 files at that time. Seven counted values
  include three static PII patterns; missing or short environment values are
  excluded. No private-prefix arguments were supplied. The sweep precedes its
  own output, final job-log append and job exit file. A later strict sweep is
  claimed without a separate captured receipt. Deleted runtime secrets cannot
  be independently re-swept from this bundle.
- Human-readable logs were sanitized; raw originals and before/after hashes are
  absent. The available pytest log is dots and its pass count; all four
  acceptance stderr captures are empty. Original JSON preservation remains an
  attestation supported by source shape and cross-mode byte equality.
- The private driver adds an EXIT trap but uses `set -u`, rather than the public
  guide's `set -eu`. The trap preserves its final status and captured-failure
  flag; unchecked setup, metadata and source-status commands can still fail
  unnoticed. The outer wrapper also leaves sanitizer, copy, permission and
  cleanup statuses unchecked and has no cleanup trap. Its universal setup and
  cleanup failure-propagation claim is unsupported. Critical test/acceptance
  commands retain their recorded exits, and analysis/privacy failures affect
  the wrapper's failure flag.
- The wrapper sources lab configuration for the sweep and inherits that
  environment. The absent profile-file override and owned public fixture
  workers provide narrower isolation. The native listing shows scanner capture
  files at 0600, the outer output directory at 0755 and job log at 0644. Archive
  or review-extraction modes do not certify original wrapper permissions. The
  narrative's comparison to earlier local interpreter versions also disagrees
  with repository records; the captured native versions are the relevant facts.

No new scanner blocker was found, and these qualifications need no broad repeat.
This accepts synthetic native retention, backup and inventory correctness;
it does not establish real-model yield, independent target seeding, deployed
upgrade/power-loss durability or enterprise readiness. CLI checkpoint files and
private API admission were outside that tested revision. The separate local CLI
increment is recorded below; private API admission remains open.

### CLI process-crash checkpoint local acceptance

R1.2e adds opt-in `--checkpoint-dir` to CLI `scan` and `discover`, plus an offline
`recover` JSON/SARIF export command. Each execution creates a new 0700 directory
with owned, single-link 0600 files and exclusive nonblocking ownership. No existing
directory is reused for writes. Saved public reports retain their producer,
evidence and checkpoint versions. The envelope has its own version 1.0; server
inputs, schema 6, caches, archived reports, catalogs, samples and budgets are
unchanged. Default CLI execution still uses its existing in-memory accumulator.

The file writer validates canonical risk and evidence, pins identity and prefixes,
and acknowledges only after file fsync, atomic replacement and directory fsync.
Failure stops later writes and probes. Recovery holds ownership through output,
reads bounded local JSON without credential/configuration/registry/database
resolution, and never replays a request. Nonterminal state remains partial with a
static explanation and nonzero exit; a genuine terminal result preserves its
actual status. A replaced coherent snapshot can exist without an acknowledged
write after a directory-fsync failure; recovery uses its recorded state. This
retains acknowledged evidence without promising exact exclusion of later coherent
state or power-loss durability. See the [file contract](cli-checkpoints.md).

All 119 new cases pass on Python 3.10.20 in 52.57 seconds with warnings as errors:
73 core contracts, 35 CLI integration cases and eleven independent process/guard
cases. Core acceptance also passes on Python 3.13.15, including an independent
73-case coverage run in 9.47 seconds. The final CLI/process gate independently
passes 46 cases (35 integration plus eleven process/guard) in 49.06 seconds on
Python 3.13.15/SQLAlchemy 2.1.6 with coverage and warnings as errors in the parent
and child interpreters. These are overlapping gates, not additional independent
test totals.

Four unmodified production CLI children use owned verified HTTPS and normal
samples/pacing. Prompt and access-high cases retain 70/high; tenant and weak-basic
access cases retain 90/critical. Each waits for durable receipt evidence and the
next genuine request stall before SIGKILL. Fresh production recovery processes
preserve exact receipt/finding IDs, control proof, source bytes and producer
identity, with partial JSON/SARIF risk and exit 1. No further fixture calls occur.
Seven positive controls prove the recovery guards reject configured network,
DNS, SQLite, private config/registry, environment and subprocess operations. These
guards are not an arbitrary filesystem or network sandbox. Owned process groups
are reaped, private modes/ownership hold, and known raw/encoded fixture values stay
out of checkpoint, export and child-log surfaces.

Core and integration cases include frozen checkpoint versions 1/2/3 and current
version 4, genuine current zero/high/partial reports, live-owner refusal, canonical
ancestor symlinks, unsafe leaf and hard links, FIFO refusal, byte/depth/expanded
object bounds, duplicate/nonfinite JSON, private-field/URL rejection, typed risk
values and assessment aliases. Atomic-write faults preserve earlier evidence;
one bounded safe staging residue can remain after process termination. Failure
before any snapshot is saved cannot recover; cancellation remains cancellation
even if final persistence or cleanup fails. A completed snapshot can survive an
ordinary output error.

Real process testing caught a guard regression missed by the initial core cases:
normal prompt findings contain tuples that JSON serializes as arrays. The new
size guard rejected them before their receipt could be saved. Corrected bounded
tuple traversal normalizes through JSON before privacy/contracts/prefix checks,
with genuine prompt HTTP and tuple privacy/cycle/depth/expansion regressions. Both
the core and four-objective real-process gates pass afterward. Review also closed
FIFO open blocking, boolean-versus-zero acceptance, contradictory assessment
aliases and a symlink-loop output traceback.

Final review then reproduced two quoted-tilde containment failures: the store
expanded the checkpoint directory while the output guard compared its literal
spelling, allowing an export to replace its own saved checkpoint. The correction
expands that input consistently and checks actual directory identity across output
ancestors. A second check after fresh directory creation protects case and
normalization aliases before probing. Six regressions cover quoted tilde, native
case variants and distinct resolved spellings with real inode/stat behavior.
The latter simulate case-preserving resolution on Linux; native macOS CI must
exercise the actual case-variant paths. No HOME setting or operator path is changed.

The corrected combined full run passes 5,102 tests in 655.41 seconds with warnings as errors
and 93 percent coverage. Ruff, configured Bandit, whitespace and authored-text
privacy/ASCII checks pass. Build and Twine pass. The installed wheel performs an
owned static-source discovery and offline recovery outside the checkout, retaining
the completed report, unknown score and private modes. All 74 Python CLI source
files match the wheel byte for byte; no AGENTS file, database or lab-job artifacts
are included. Mocked native-guide checks preserve genuine setup exit 23, test
exit 9 with driver exit 1, and final source-status exit 31, plus successful exit 0.

Required delivery checks are tracked on
[PR #83](https://github.com/perfecxion-ai/ai-agent-scanner/pull/83). The
[scoped native CLI file-recovery gate](cli-checkpoint-retest.md) is accepted below
at the merged revision. It uses synthetic loopback fixtures only and needs no
broad model, tenant-cohort, MCP, backup or inventory rerun. This does not certify
model sensitivity, independent target seeding, deployed storage/upgrade, power
loss, network filesystems, private API admission or enterprise readiness. No
operator configuration or database was accessed; no package was published or
service deployed.

The first final-head macOS job reached 97 percent of pytest with passing progress
before its ten-minute workflow limit cancelled execution; backup acceptance was
not reached. It is not accepted as a passed gate. The macOS job allowance is now
fifteen minutes for the full suite and both existing backup commands. Scanner,
request, fixture and backup deadlines and assertions are unchanged. The final
reviewed head subsequently passes all eight CI checks, including native macOS
completion and both backup modes.

PR #83 merged as `1d790bf` after all eight checks passed at its exact reviewed
head. PR #84 adds manual CI dispatch and merged as `49c1041` after all eight PR
checks passed. All eight checks on that main revision pass in
[run 40533599489](https://github.com/perfecxion-ai/ai-agent-scanner/actions/runs/40533599489),
covering the unchanged scanner runtime. This records verification of the latest
main revision, not a claim that a separate post-merge event ran at `1d790bf`.
The dispatch change alters no scanner code, test command, permissions,
publication or deployment behavior. See
[manual CI operation](DEVELOPMENT.md#ci-and-publication).

### Supplied native CLI checkpoint acceptance

Static review accepts the supplied archive for the bounded
[CLI file-recovery gate](cli-checkpoint-retest.md) at
`49c10419beb09b6b32646a6b3d872126edc82379`. Its SHA-256 is
`c43614de16f837136d2b95e9bb370f46e4a6cc261c89305decc0c86e4441935d`.
No supplied driver was executed during review. Captures record Python 3.11.2
with GCC 12.2.0; Debian 12 is operator-attested. Dependencies record SQLAlchemy
2.1.6 and Gunicorn 26.2.0. The 74-file scanner/CLI source digest independently
matches the pinned checkout:
`e634574eae0b8cb8d188d326bba13d16dc7fcb20f292adc493340ba10d4b4ec1`.
This identifies scoped source contents, not every loaded module, dependency,
executed test or target's provenance.

The three committed test files pass all 119 cases in 61.24 seconds with warnings
as errors and no skips. Build, Twine and installed-wheel smoke each exit zero;
their four command exits, the driver exit and the outer job exit are all zero.
All 23 captured assertion records reconcile with the returned data. The assertion
helper checks source/version presence rather than the expected source pin; the
independent digest comparison supplies that missing comparison. Build logs record
both distributions, Twine passes both, and installed smoke reports matching
checkout/distribution identity and completed discovery recovery with unknown risk.
The built distributions themselves are not returned for another byte comparison.

Committed assertions supply the four real CLI SIGKILL scenarios: prompt and
access-high retain 70/high; tenant and weak-basic access retain 90/critical.
Owned verified HTTPS, normal samples/pacing, a saved receipt followed by a real
request stall, process reaping, exact retained receipt/finding IDs and producer
identity, unchanged checkpoint bytes and partial JSON/SARIF recovery are tested.
The native log is a combined dots/summary capture; raw requests, certificates,
checkpoint fixtures, exports and child logs are excluded. Per-case facts therefore
depend on the committed tests' assertions rather than independent returned traces.
Configured recovery guards have positive controls and the target call count stays
unchanged. These checks are not an arbitrary filesystem/network sandbox or a
proof that no socket object was ever created.

The archive has 60 members: four directories, 26 substantive files and 30
AppleDouble sidecars, totaling 103,455 file bytes. Sidecars are ignored as evidence.
Fifteen files are primary captures. Twenty files are evidence when the report and
five driver sources are excluded. All substantive files decode as UTF-8.

Private-harness and privacy qualifications:

- The driver and wrapper use `set -u`, whereas the public guide uses `set -eu`.
  The driver trap begins after initial setup, checkout and revision checks.
  Test/build/Twine/smoke failures are explicitly retained; some metadata and final
  source-status commands are unchecked. The wrapper ignores the clone pipeline's
  status and does not consistently fold sanitizer, copy, chmod, cleanup or listing
  failures into its final status. The report's complete failure-propagation claim
  is broader than this implementation. Cleanup is attempted, without a returned
  removal or final process inventory proving it completed.
- The privacy receipt covers 17 files at one point: the 15 captures, setup note
  and then-live job log. It records zero violations and no private-path prefixes.
  Its 19 pattern entries mix configured environment values, fixed fixture values
  and synthetic PII patterns; they are not 19 live credentials. The later privacy
  receipt, report, start/exit files and final job-log tail are outside that sweep.
  A stricter post-bundle sweep is described but has no separate captured receipt.
- Four logs are sanitized before that sweep; the returned job log is also
  sanitized. Known values, paths and addresses can be replaced, so a clean
  returned log does not prove absence from the original. No raw-log hashes or
  capture-to-bundle comparison chain are returned; original-byte preservation of
  JSON/text remains attested.
  A fresh data-only review of the 20 returned evidence files plus the report finds
  no matches for the twelve committed fixture values or their documented encoded
  forms. Generated invalid keys and private environment values are not in the
  bundle and cannot be independently reswept.
- Fixture canaries and issued keys are fixed synthetic constants; invalid keys,
  execution IDs and disposable resources are generated. The wrapper imports an
  optional private environment into its parent process for the absence sweep.
  Actual scan children use an explicit environment allowlist and absent-profile
  override. Recovery children use that restricted base environment with an owned
  trap registry whose access is refused. The evidence does not establish general
  isolation of every parent build/test operation from inherited environment.
- The native listing records scanner capture files at 0600, an outer directory
  at 0755 and its live job log at 0644. Archive metadata instead has four 0755
  directories, 25 substantive files at 0644 and the returned job log at 0600.
  Neither listing establishes owner-only modes for the entire shared bundle;
  private checkpoint modes/ownership are checked inside the tests.
- The report's earlier-local Python version does not match the recorded 3.13.15
  gate. Its failure-before-first-acknowledgement wording must mean no snapshot was
  saved: a coherent replaced snapshot can be recovered even if its write was not
  acknowledged. The public contract already records that distinction.

No new scanner blocker was found. These qualifications need no broad repeat.
This closes R1.2e native process-recovery acceptance for the implemented prompt,
tenant and access receipt families on the supported POSIX/local-filesystem
boundary. It does not establish future-family support, independent target seeding,
model sensitivity, power-loss/disk-failure durability, deployed storage/upgrade,
private API admission or enterprise readiness. No package was published. Artifact
retrieval by the private wrapper is not an assessment of an external target.
R1.4b1 conservative grouping of latest observations versus prior confirmed history
is next under design; R1.4b2 authoritative source-bound indexes remain separate.
Neither is implemented by this acceptance.

### Public target grouping local acceptance

R1.4b1 adds authenticated public-target groups and original finding-occurrence
history. The [API contract](asset-groups.md) keeps the latest observation's
canonical risk separate from prior confirmations. A later zero, null, discovery,
or inconclusive result does not establish remediation. Observation IDs, raw
reports, existing API projections, score semantics, and evidence schema versions
are preserved. Grouping does not establish credential or principal equivalence.

The schema-6 to 7 transaction adds two derived tables, three indexes, and three
cache invalidation triggers without changing existing rows, score caches,
indexes, or the nine inventory source triggers. Older supported migrations keep
their previous ordering and rollback checks. The idle dispatcher stages and
seals bounded batches under exclusive ownership; active scan workers take
priority. GET uses a read-only snapshot and checks source generation, projection
policy, publication nonce, total/sealed/source row counts before selecting group
heads. Unreadable or stale evidence produces an explicit unavailable view.

Focused acceptance passes 114 identity/schema cases, 32 projector/history cases,
24 API/ownership/stopped-backup cases, eighteen independent review regressions, and
25 public-gate cases. Exact Python 3.13.15 independent checks cover the core and
reader cases; the public-gate set completes in 115.14 seconds with coverage and
warnings treated as errors. Its real normal and optimized Gunicorn cases take
56.40 and 55.79 seconds with the reader memo and partial-index correction. Track the
complete local coverage run and required delivery checks in
[PR #86](https://github.com/perfecxion-ai/ai-agent-scanner/pull/86).

The first macOS CI run was cancelled at 97 percent by its fifteen-minute job
allowance; its partial log already contained two failing progress markers.
Reading the passing tail alone did not establish a clean run. A twenty-minute
rerun completed with 5,303 passes and two failures: both 10,000-observation gates
hit their unchanged 180-second deadline before initial publication. Neither run
is accepted. The CI job retains twenty minutes for the expanded suite and both
backup commands; actual macOS acceptance still required a passing rerun at that
point. The final PR #86 and post-merge results are recorded below.

Profiling found repeated complete evidence validation for observations sharing
one decoded report and asset alias. The reader now stores immutable support
ordinals only within that bounded source read, after each row's target binding
checks. Distinct aliases and newly decoded sources recompute support. A 500-row
owned profile reduces support validation from 500 calls to one, with total time
from 0.732 to 0.339 seconds. The same complete gate and polling cadence improve
from 65.533 to 58.195 seconds locally. A separate polling comparison reduces
fixture HTTP CPU work at 0.2-second readiness intervals; it does not independently
explain the Mac timeout. These measurements are not macOS or production SLO
acceptance. The 180-second gate limit, scanner/request/source/backup deadlines,
batch limits, evidence eligibility rules and all assertions remain unchanged.

The memo-only hosted rerun still timed out in the two public gates on Python
3.11, 3.12, 3.13 and macOS; each completed its other 5,314 cases. The failing Linux
jobs used SQLite 3.45.1. Production query capture exposed a second cost: `IS 1`
did not match the existing unique partial index's `= 1` predicate. A 10,000-row
owned plan check used only the organization/build prefix; 100 lookups took
0.086481 seconds versus 0.003334 with the exact group-head index. The staging,
sealing and readiness predicates now use equivalent boolean equality. Schema,
DDL, row selection, seal checks and deadlines are unchanged. The regression
captures real executed statements. The original PR #86 regression required exact
stage/readiness index use while allowing the optimizer to choose the small-fixture
sealing plan. The later portability correction below retains exact staging and
accepts either recognized readiness-count index.

An isolated Python 3.12.3 environment using the CI engine, SQLite 3.45.1, passes
both complete normal and optimized gates in 57.708 and 58.281 seconds. Each
returns all fourteen assertions, 10,000 observations, three published owners,
clean server exits and fixture cleanup; stderr is empty. Initial publication
was observed before 30 seconds. Hosted macOS and the full matrix still required
a passing delivery run at that point; local measurements did not substitute for
them. The final delivery results are recorded below.

The real-server gate uses 10,000 repeated observations from complete-capture
transport test doubles without target sockets, across three synthetic
organizations. It produces 24 groups, including deliberately separate redacted
and ambiguous observations. Full ordered occurrence references, counts, safe
public fields and per-organization view digests match the source oracle before
mutations and after restart. Supported confirmations include genuine unscored
pipeline receipts; newer zero and null results remain the latest risk.

Review caught and corrected blocked-owner starvation, a history cursor that
could repeat an exhausted large-source boundary, timestamp materialization
before its byte limit, and cloud identity incorrectly standing in for endpoint
binding. Four independent regressions pass on the corrected reader code. The
malformed-source gate now waits for an actual current-generation
`source_unavailable` build before checking refusal, with two negative controls;
an immediate stale-generation 503 alone was insufficient proof. A coverage-only
test failure also replaced a fixed call count with bounded eventual publication,
retaining every batch limit and verifying a genuine private staged prefix. The
old migration-index oracle now recognizes the five additional derived indexes
while still requiring exact preservation of every existing index.

A final owner-isolation review reproduced six malformed organization identifiers
through normal source writes. A bad first generation owner could prevent later
valid organizations from refreshing. The corrected selector bounds eligible
text keys in SQL and advances its bookmark before rejecting a malformed key.
All source rows remain unchanged; valid tenants publish independently. The full
164-case identity/schema/reader/review set passes on Python 3.10 and exact 3.13.15,
including the six owner regressions, memo isolation and full source coverage on
3.13. The combined local API/ownership/backup and focused set passes 188 cases.

Build, Twine, and installed-wheel CLI recovery smoke pass. Both distributions
contain the same 78 byte-exact scanner/CLI sources and no assistant instructions,
operator database or lab artifact. The wheel provides CLI/library code; server
entrypoints remain checkout/container components. The scoped scanner source
identity is `4f9a2f6fa373497ed550a483f78576e1a39f5dd1d1652638f7e3946eba380d1c`.
Package publication, deployment, and release attestations remain separate.

Both backup modes now contain fourteen cases, with a frozen schema-6 source and
a current schema-7 source. A separate stopped-backup case preserves a populated
sealed group cache and all source rows through restore and restart without
rebuilding. Cache-tamper HTTP cases restore publication metadata after a changed
sealed row, extra unsealed row, source-generation retarget, or policy retarget;
each refuses the grouping view while the observation API remains usable.

PR #86 merged as `678fd717788d91a5062f4d3a723cc30979427871` after all eight PR
checks passed. The complete local coverage run passes 5,317 tests at 93 percent.
All eight post-merge checks pass too. One existing macOS contention test exceeded
its 2.5-second wall-clock assertion by 13.3 ms; independent owned instrumentation
verified the configured lock cap and timeout restoration, and an unchanged
isolated rerun passed 5,317 tests and both fourteen-case backup modes. No scanner
deadline or test assertion was relaxed.

The [scoped native retest](asset-groups-retest.md) remains a separate gate for the new
schema and grouping API. It needs no model service, lab secret or operator data.
These gates do not establish model sensitivity, target seeding, power-loss
durability, credential equivalence, distributed operation or enterprise
readiness. Private server inputs, dashboard grouping, authoritative risk indexes,
and the remaining R2 through R4 work retain their own acceptance criteria.

### Supplied native asset-group gate failure and portability correction

Data-only review of `aiscan-asset-group-678fd71.tar.gz` retains its failed native
gate at `678fd717788d91a5062f4d3a723cc30979427871`. The archive SHA-256 is
`579f0cfd47fa8315f32e0e50ba97227ece162e43a87f1e95a3814daea2c09a24`.
No supplied driver was executed. Captures record Python 3.11.2, SQLite 3.40.1,
SQLAlchemy 2.1.6 and Gunicorn 26.2.0; Debian 12 is operator-attested. All three
group receipts match the pinned 78-file scanner/CLI digest, app, public driver,
inventory helper, Gunicorn hooks and both projection-policy hashes.

Both required 180-second runs exit 1 with `overall_timeout`, at 180.853 and
180.858 seconds. Each reaches eleven of fourteen assertions. Restart consistency,
no active admissions and final process-group completion remain unasserted, even
though both recorded server exits are zero. The focused set reports 210 passes,
one failure and two deselections; an isolated diagnostic reproduces the same
readiness-count plan assertion. Both backup modes pass all fourteen cases. The
35-check capture table correctly retains twelve failures, driver exit 1 and
outer gate-job exit 7.

The separate 300-second diagnostic exits zero in 191.528 seconds with all fourteen
assertions, 10,000 observations, 24 groups, 828 checked HTTP responses and both
server exits zero. It is supplementary characterization, not acceptance of the
180-second gate. The reported macOS comparison is not captured in this bundle;
hardware, Python and dependency differences prevent attributing the runtime
difference solely to SQLite.

The plan failure is at the readiness count, not the exact three-key staging
lookup. SQLite 3.40.1 selects `ix_asset_group_head_page` for an organization/build
count instead of the partial unique head index. Both counts are semantically
valid. The covering index includes all observations and is not established to be
faster. The corrected regression accepts only the two recognized owner/build
SEARCH plans for that count, retaining the exact staging lookup and `= 1`
predicate. It passes on SQLite 3.40.1, 3.45.1 and 3.53.1; owned negative controls
still reject the old `IS 1` staging lookup and an unrecognized count index.

Profiling found repeated construction of the same bounded source SELECT during
history traversal. The reader now prepares that SQL once per reader and binds
observation, scan and organization separately on every execution. It caches no
rows or bound values. Metadata reads, target/alias checks, source-byte limits,
publication proofs, cursor semantics, read deadlines and the public gate's
180-second allowance remain unchanged. An owned SQLite 3.40.1 traversal over 500
observations improves from a median 0.298 to 0.110 seconds with identical SELECT
counts. That is a local read-path measurement, not native or production SLO
acceptance. Separate count-plan measurements find extra covering-index scan work,
but do not justify a production index hint.

Independent review passes 72 combined reader/history cases on SQLite 3.40.1 and
3.45.1, including thirteen author regressions and nine independent cases. The
nine independent cases also pass on SQLite 3.53.1. They cover cold/warm expired
or stopped readers issuing no SQL, changed ownership or scan membership, deleted
rows, oversized changed metadata refused before materialization, and warmed
provider mismatches retaining unknown evidence.

A further measured change prepares the two bounded report/metadata SELECTs
once per reader. Each fetch binds both its current selector and the lesser of
the remaining allowance and absolute byte cap. The SQL `CASE` still withholds
oversized content before materialization. No source values are cached by this
change. Cold and reused raw reads also check cancellation/deadline before SQL.
The owned 500-row median improves from 0.10915 to 0.08729 seconds with identical
SELECT counts. Twenty-nine author cases and four additional independent cases
cover changing allowances, missing/SQL NULL/JSON null/empty values, oversized
sources, report/metadata selector isolation, cumulative source accounting and
UTF-8 byte limits. All 105 combined reader/history cases pass on SQLite 3.40.1
and 3.45.1 under warnings-as-errors.

Before the bounded-retry follow-up below, the complete corrected-source normal
and optimized 180-second gates pass in
48.152 and 48.214 seconds on an owned Python 3.12.3/SQLite 3.40.1 compatibility
runtime. Each retains all fourteen assertions, 10,000 observations, complete
traversal, clean initial/restart exits and fixture cleanup. The unmodified source
passes the same local normal gate in 56.909 seconds. Both corrected-source backup
modes pass all fourteen cases, and Ruff plus the configured Bandit gate pass.
The 78-file scanner/CLI digest is
`7042cf8dbb339babfdb5a87d02607d00f6ee968b4e4153a2daf90e06bdd277d2`.
Track full coverage, package validation and required delivery CI in
[PR #87](https://github.com/perfecxion-ai/ai-agent-scanner/pull/87).
These local measurements do not replace the original native Python 3.11.2
runner. The compatibility build has verified millisecond sleeps; an initial
build that rounded short waits to whole seconds is excluded from acceptance.

The first correction CI run at `e7f3ad9` passes seven checks but fails one Python
3.12.15/SQLite 3.45.1 case: the optimized group gate returns `page_failed` during
restart traversal after 83.756 seconds, with eleven assertions. Its other 5,371
cases pass, as do the normal group gate and macOS's complete 5,372-case suite plus
both backup modes. The failed receipt does not capture HTTP status or distinguish
a failed page from a malformed successful response. Its cause cannot be assigned
retrospectively to contention. That failed run remains preserved.

An independent controlled fixture establishes a legitimate retryable case on
SQLite 3.40.1 and 3.45.1. With a valid publication and signed history cursor,
production cleanup removes eighty obsolete cache rows under the existing
half-second writer deadline and 50 ms busy cap. A controlled one-page SQLite
cache forces spill: the concurrent read refuses with
`503/asset_group_projection_unavailable` and SQLite busy code 5. The exact same
cursor succeeds after cleanup commits, preserving history, coverage, publication,
generation and source rows. A RESERVED-only writer and cleanup with spill disabled
both permit the read. Committed regressions use production read/write budgets,
release and join every writer, and pass on SQLite 3.40.1, 3.45.1 and 3.53.1.
They demonstrate a supported operational refusal; they do not identify the old
CI response or establish continuous availability.

The gate client now follows the [documented retry contract](asset-groups.md):
only the exact valid unavailable envelope can retry. It preserves the same
request, owner, page limit, cursor, accumulated items and visited-cursor set.
The existing 180-second shared deadline stays in force, with at most 25 retries
per page and backoff capped at 0.2 seconds and the remaining budget. Numeric
`page_retries` counts by phase expose attempted retries even when a later step
fails. Static HTTP failure codes distinguish other statuses without copying
response text into receipts. Stale or invalid cursors, other errors, malformed
responses and transport failures never restart traversal or retry. All fourteen
assertions, full occurrence/digest comparisons, publication-stamp comparisons
and direct malformed-source/tamper refusal checks remain intact. This changes
the harness's zero-transient-refusal expectation to eventual complete reads under
the existing budget; it is not a production availability guarantee.

The next macOS run passes 5,414 cases and fails the new cleanup regression's
final full-history comparison. The busy-code assertion and exact-cursor recovery
already succeeded; an artificial 0.1-second test reader budget remained active
for the final comparison. The correction removes that override and uses the
production read budget throughout. Writer holds remain bounded by the original
half-second cooperative deadline, with the same 50 ms busy cap. No scanner
deadline, retry budget or content assertion changes.

Privacy and private-harness qualifications remain narrow. A fresh sweep of 36
returned logical evidence files finds no known fixture/PII, encoded-value,
RFC1918-address or known private-prefix matches. No lab secrets were accessed
during review. The on-runner sweep's ten named sets contain six static sets and
four available lab-value sets. Sanitized logs, absent raw responses/databases and
49 binary AppleDouble metadata files prevent a broader original-output claim;
separate known-prefix checks of those metadata files found no hits. Wrapper
setup/status/cleanup commands do not consistently propagate failures, and the
diagnostic pytest failure lacks its own exit capture despite its preserved log.
These qualifications do not obscure the genuine failed gate.

Native acceptance remained open at this correction checkpoint pending a fresh
[scoped run](asset-groups-retest.md) with its original budget and all assertions.
No broader cloud or model-sensitivity repeat is required for this correction.

### Supplied native asset-group acceptance

Data-only independent review accepts `aiscan-asset-group-1b164df.tar.gz` for the
scoped [native correctness gate](asset-groups-retest.md) at PR #87's merged revision
`1b164df8bdd4361dc92ef17b917bc1e63291fa91`. The archive SHA-256 is
`f906246441d7ba1259e8667acc7e8208f3c834dd3bcc737d863d8466a4a40127`.
No supplied driver was executed and no operator database, registry, configuration
or lab secret was accessed during review. The original `678fd71` native failure,
longer diagnostic and historical CI failures above retain their recorded outcomes.

Captures consistently identify Linux, Python 3.11.2, SQLite 3.40.1, Gunicorn
26.2.0, SQLAlchemy 2.1.6 and scanner version `1.2.0.dev0`. Debian 12 and use of
the same original runner are producer attestations. The reported macOS
Python 3.13.5/SQLite 3.45.3 comparison has no returned captures and is not
independently accepted here.

Both group receipts exactly match the pinned public gate's fourteen assertions:

1. `private_environment_and_owned_schema6_fixture`
2. `genuine_pipeline_sources_with_scoped_and_unmergeable_targets`
3. `schema6_to7_preserves_source_rows_caches_archives_and_definitions`
4. `exhaustive_group_and_history_pagination_with_latest_risk_separate`
5. `signed_cursor_ownership_group_limit_and_tampering`
6. `rollback_and_other_organization_preserve_cursor`
7. `committed_source_write_invalidates_cursor`
8. `uninterpretable_source_blocks_groups_without_hiding_inventory`
9. `exact_source_restore_rebuilds_complete_publication`
10. `restart_preserves_publication_generation_and_complete_views`
11. `no_active_scans_schedules_or_admissions`
12. `real_server_exits_and_process_groups_reaped`
13. `known_value_and_log_privacy_checks`
14. `private_fixture_and_socket_cleanup`

| Capture | Observed result |
| --- | --- |
| Normal group gate | Accepted, 129.273 seconds, 765 checked HTTP responses |
| Optimized group gate | Accepted, 135.675 seconds, 777 checked HTTP responses |
| Both group modes | Unchanged 180-second budget; all fourteen assertions; 10,000 observations; eight groups per organization across three organizations; schema before 6, after/target 7 |
| Both pagination phases in each mode | Zero recorded pagination retries; initial and restart server exits zero |
| Normal and optimized backups | Both accepted; all fourteen exact case names and per-case assertion arrays match the pinned script |
| Focused warnings-as-errors tests | 309 passed, two deselected, 30.33 seconds; fourteen files in the actual driver |
| Exit captures | All five step exits, driver exit and outer job exit zero; `captured_gate_failure=0` |
| Independent capture table | All 37 records true; revision matches; source-status capture exists and is empty |

The two excluded tests are the separately captured real-server gate cases.
Backup cases are `v1` through `v7`, `rollback1/2/3/5`, `future`, `incomplete` and
`lock`. They establish their documented stopped synthetic backup/upgrade checks.
Preservation of a populated published group cache is a separate included focused
test in `test_asset_group_backup.py`, not an extra assertion established by the
public backup receipts alone.

Independent recomputation over the pinned 78 scanner/CLI source files yields
`7042cf8dbb339babfdb5a87d02607d00f6ee968b4e4153a2daf90e06bdd277d2`, matching
both receipts. The complete public build identities, package/schema versions,
catalog hashes, protected catalog pin and semantics also match. Separate app,
public acceptance driver, inventory helper and Gunicorn configuration hashes
match the pinned bytes. The projection policy is
`7b02923a3694ccd6cd2d2911877567a71e41789eacc83a3233c24e48426c88c9` and the
asset-group policy is
`ee311d0f3fda27893ad2321c6406643741447735ab26dae813ea6530e41558fa`.
These are consistency checks against the captured pin, not authenticated proof
of execution or dependency/build attestation.

The gate uses owned synthetic schema-6 fixtures, complete-capture pipeline test
doubles that open no target sockets, and a real single-worker loopback Gunicorn
server. Ten thousand repeated observations are not ten thousand deployments.
Zero pagination retries describes these traversals; it does not establish absence
of readiness responses or continuous availability. Measured times leave 50.727
and 44.325 seconds under the configured budget on this run, not a production SLO.

Privacy review distinguishes the producer's sweep from returned evidence. The
on-runner capture records zero violations over 23 files and ten named sets,
comprising six static sets and four available lab-value sets. Lab-secret
absence remains producer-attested because review did not access those values.
An independent sweep of 26 returned evidence text files finds no matches for six
checked-in fixture/PII values, their raw, URL, JSON, hex and base64 forms, RFC1918
addresses or known private prefixes. All 32 substantive files are UTF-8; separate
known-literal/private-prefix byte checks of 35 AppleDouble metadata files find no
hits. Harness source deliberately names detection patterns and is not runtime
evidence. Sanitized human-readable logs, omitted raw responses/databases and
bounded known-value checks do not establish arbitrary-secret absence or original
output authenticity.

The private wrapper supports narrower failure and cleanup claims than its report.
The five capture commands preserve genuine exits, and the complete supplied
receipts independently establish the results above. However, setup, sanitization,
copy, permission, source-status and cleanup operations do not consistently
propagate failures. The assertion helper would treat a missing source-status file
as empty; review separately verified that this capture exists and is empty.
The inner gate checks fixture/socket cleanup and process reaping, while the
outer checkout/venv removal has no checked status or post-cleanup verification.
The setup note says eight focused files although the actual driver lists fourteen;
the driver's header retains the old revision while its operational pin is correct.
These limits do not invalidate this complete scoped capture set.

R1.4b1's native correctness gate is closed. No broad cloud or model retest is
needed for this documentation record. Authoritative source-bound risk indexes
(R1.4b2), dashboard group views, logical-finding consolidation, private server
inputs and the remaining R2 through R4 work stay open. Group history counts
occurrences, not independent vulnerabilities. This does not establish model
sensitivity, principal/credential equivalence, deployed storage or power-loss
durability, PostgreSQL/distributed support, release approval or enterprise readiness.

### Indexed group risk local acceptance

R1.4b2a adds normalized `risk_level` filtering to the authenticated group list.
It matches only the latest canonical observation, preserving null unknown scores,
supported assessed zero and earlier confirmation history. History rejects filters;
the observation API retains its existing alias-based eligibility. Grouped risk
also requires matching snapshot target selectors, so mismatched historical
snapshots can differ between those views. See the [contract](asset-groups.md).

Schema 8 adds six nullable derived facts and one partial risk index. Independent
frozen schema-7 fixtures preserve populated publications, staged rows, original
fields, archives, scalar caches, generations, schedules and accepted indexes.
Four injected migration failures roll back columns, index and version together.
Stopped backup/restore and idempotent restart preserve the same source data. The
public backup gate now has distinct historical v7 and current v8 cases, fifteen
total; both normal and optimized modes pass.

The complete source/publication readiness proof runs before SQL filtering.
Published cache changes cannot hide a matching high row by restoring publication
metadata: ordinary edits unseal it and produce an unavailable operation. Selected
rows reopen their saved sources and compare all six facts. Bounded SQL selectors
distinguish genuine nulls from refused oversized or wrongly typed values.
The independent review caught an oversized non-null policy value being interpreted
as null; explicit null flags and regressions close it. Another actual-plan review
found that continuation predicates could rescan earlier matching heads. A redundant
timestamp upper bound preserves the original tie predicate and enables the risk
index's range search without a temporary sort on SQLite 3.40.1, 3.45.1 and 3.53.1.
The complete readiness counts remain O(N); this is not constant-time inventory or
protection against full database forgery by a writer with equivalent filesystem
access. Continuous writes can keep a projection unavailable.

Local evidence includes 44 combined risk/schema cases, of which eight independent
cases also pass separately on SQLite 3.40.1 and 3.45.1. The author passes 134 core
cases and 148 compatibility/helper cases, with overlapping suites; these counts
are not additive. A wider 154-case compatibility set passes on SQLite 3.40.1 and
3.45.1 before the range-only follow-up, and all 29 risk cases pass afterward on
all three engines. The integrated gate/retry helper set passes 71 cases with two
real-server tests separately exercised by the full gate. Warnings are errors.

The first integrated coverage run at `6346b0b` records 5,468 passes and seven
failures in 774.23 seconds. Six failures come from the older inventory harness's
schema-7 target constant; the seventh is an exact derived-index expectation that
omits the new risk index. Correcting the harness target/assertion label and adding
only the recognized index preserves the original source/cache/archive and DDL
oracles. Forty inventory helper cases and both normal/optimized inventory server
gates pass afterward; new controls still reject a missing or altered risk index.
The integrated inventory/nullable regression set passes 74 cases in 72.47 seconds.
The updated native guide includes these inventory and nullable-upgrade regressions.

Both extended `asset-group-acceptance-v2` gates pass on an owned Python
3.12.3/SQLite 3.40.1 compatibility runtime at clean `a781f64`, taking
52.205/51.440 seconds. Each accepts all seventeen assertions under the unchanged
180-second budget, upgrades schema 6 to 8, and preserves the original three-owner,
10,000-observation/24-group oracle. A separate fourth owner has five observations
and groups: three genuine controlled-pipeline 70/high targets, an assessed zero
and an unknown. Exact filter sets and full-view digests match source-derived
expectations across all four owners and six levels, including after restart.
Each phase records zero pagination retries and clean server exits. Privacy checks
cover eight known values plus the private reference; no arbitrary-secret or
model-sensitivity conclusion follows.

Independent recomputation over 79 scanner/CLI files yields
`b852f471fee0621f8d67388e691a8e83dd41f56a78cb6495fd823d9f1cf2d6e5`.
Both receipts match that source and the public driver digest
`fb813eec07264c658a011553e27c6905c0f5ffb50677ed92057ce06a5c020d80`.
The projection policy is
`ad885702be3bb89a96a7fc36609f0a5f534e193a79719a6d4e939d075e0da2a4`;
the group policy is
`e57de72ee316f9f7a16a2ea208c82933c1df9fc84f08e45ef3f7ce72ffbbe889`.
Ruff, the configured Bandit gate, package metadata and installed-wheel CLI recovery
pass. All 79 runtime files in the wheel and source distribution match the tested
checkout; the new module and regression files are included as appropriate.
Full-suite and required PR/post-merge checks are tracked in
[PR #89](https://github.com/perfecxion-ai/ai-agent-scanner/pull/89).

Before the index refinement below, the complete local suite passes 5,477 cases
in 826.19 seconds with 93% coverage and warnings as errors. CI run `40800251585`
then passes five jobs and has plan failures in three jobs: Python 3.10.22 has one failure
and 5,476 passes; Python 3.12.15 and 3.13 each have two failures and 5,475 passes.
They select the older page index for filtered continuation ranges. The CI logs
identify SQLAlchemy 2.0.55 and 2.1.6 but do not capture SQLite versions, so those
versions cannot be inferred from the interpreters. These failed results remain
recorded; correct result dictionaries alone do not close the access-plan issue.

Controlled fresh-connection probes reproduce the choice by reversing valid
index creation order on SQLite 3.40.1 and 3.45.1. When newer nonmatches are outside
the timestamp range, the alternative plan is efficient. With 650 tied nonmatches
and six matching heads, one probe consumes 7,570 SQLite VM steps rather than 519.
The new, unmerged schema-8 index now includes the constant `is_latest` key before
`risk_level`, while retaining the partial `WHERE is_latest = 1` predicate. It uses
520 steps in both creation orders and all three timestamp distributions, without
a planner hint. In a separate 656-head storage probe it adds 656 payload bytes and no allocated
pages; this is a local measurement, not a production storage or latency promise.
Source/row/field comparisons, read deadlines, continuation predicates and the
180-second gate budget are unchanged. Exact migration and backup DDL oracles
recognize only the refined definition.

Six permanent cases exercise both index orders and older, tied and newer
nonmatches through actual API pages. They retain complete canonical result and
source-reopening checks, then explain the executed first and continuation SELECTs.
Failures include the connected SQLite version and compile options. The focused
123-case set passes on all three SQLite engines. The refined 79-file source digest is
`bf1f96fe64b5e9f3dd711e9499ab01848e6c37d1e1a35ae288bded8486261831`;
the projection policy is
`2c28e632c518535a0b2993347475f9f9ef5fc57eea55c2af62347e41a56e84e1`
and group policy is
`e55b26e90a77b0ae777b1ed26fac163245e45e73fcd7035c8a46983792f748c2`.
Final full-suite, packaging, refreshed compatibility gates and required delivery
checks are recorded in PR #89.

These are local compatibility and controlled-fixture results. The supplied
[native gate](asset-groups-retest.md) at the final merged pin is accepted below;
the accepted `1b164df` archive above covers the preceding schema-7 grouping slice.
Indexed observation acceleration, dashboard grouping and logical-finding
consolidation remain open, along with the remaining R2 through R4 work.

### Supplied native indexed group risk acceptance

Data-only independent review accepts `aiscan-asset-group-c12cead.tar.gz` for the
scoped [native correctness gate](asset-groups-retest.md) at PR #89's merged
`c12ceadcc6c830d73e1d484f17b45c06f07c329b`. Its archive SHA-256 is
`0bbac1492c19d1ee241608c31814ee904d3d763bba251255b009042fdb659908`.
No supplied driver was executed and no operator database, registry, configuration
or lab secret was accessed during review. Earlier failed native and CI receipts
retain their recorded outcomes.

Captures identify Linux, Python 3.11.2, SQLite 3.40.1, Gunicorn 26.2.0,
SQLAlchemy 2.1.6 and scanner `1.2.0.dev0`. Debian 12 and the original runner are
producer attestations. The reported Mac Python 3.13.5/SQLite 3.45.3 run has no
returned captures; its 447-test and 45-check claims are not independently accepted.

| Capture | Observed result |
| --- | --- |
| Normal group gate | Accepted, 150.237 seconds, 915 checked HTTP responses |
| Optimized group gate | Accepted, 150.768 seconds, 913 checked HTTP responses |
| Both group modes | `asset-group-acceptance-v2`; all seventeen exact pinned assertions; schema before 6, after/target 8; unchanged 180-second deadline |
| Original traversal oracle | 10,000 observations across three organizations, eight groups each; separate risk controls add five observations and five groups |
| Positive risk controls | Three high, one minimal and one unknown group; zero critical, medium or low groups |
| Both pagination phases in each mode | Zero recorded pagination retries; initial and restart server exits zero |
| Normal and optimized backups | Both accepted; all fifteen exact case names and per-case assertion arrays match the pinned script |
| Focused warnings-as-errors tests | 447 passed, two deselected, 273.06 seconds; twenty files in the actual driver |
| Exit captures | All five step exits, driver exit and outer job exit zero; `captured_gate_failure=0` |
| Capture reconciliation | All 45 records true; revision matches; source-status capture exists and is empty |

The original fourteen assertions remain, with the schema-preservation name
advanced to `schema6_to8_preserves_source_rows_caches_archives_and_definitions`.
Three added assertions check independent latest-risk filter sets, normalized
signed-filter continuation and restart preservation. All 24 owner/level counts
and full-view digests match normal and optimized captures, and the earlier local
SQLite 3.40.1 compatibility receipts. Fresh fixture history digests differ between
separate runs because finding IDs are generated; each gate checks its complete
history digest again after restart. This is not cross-run history byte identity.

Independent recomputation over the pinned 79 scanner/CLI files yields
`bf1f96fe64b5e9f3dd711e9499ab01848e6c37d1e1a35ae288bded8486261831`.
Both captures match the refined projection/group policies above, complete build
and catalog identities, and all four app/driver/helper/Gunicorn component hashes.
The expected-result manifest was absent on the runner. Its available workstation
copy was compared locally against the returned receipts, closing that comparison
without another native run. These are pin-consistency checks, not authenticated
execution, dependency or build attestations.

Backup cases are `v1` through `v8`, `rollback1/2/3/5`, `future`, `incomplete` and
`lock`. The public receipts cover stopped synthetic backup/upgrade/recovery and
fresh empty derived tables. The report attributes populated publication-cache
preservation to those receipts too broadly: that coverage comes from the included
`test_asset_group_backup.py` focused test, not a public backup receipt assertion.
The two deselected cases are the separately captured group real-server modes;
both inventory real-server modes remain in the focused set.

Privacy review keeps known-value checks separate from arbitrary-secret claims.
Each group receipt records eight private fixture values and one private reference
checked across response, log and fixture surfaces. The on-runner sweep reports
zero violations over 23 files and ten named sets. Six are static fixture/PII sets;
four lab-value sets were available, so it does not prove all eight optional lab
variables were set. Lab-value absence remains producer-attested. An independent
sweep of 27 returned evidence text files finds none of the six checked-in fixture/PII values,
their raw, URL, JSON, hex or base64 forms, RFC1918 addresses or checked private
runner prefixes. All 33 substantive files are UTF-8; separate known-value byte
checks of 37 AppleDouble files find no hits. The expected manifest's workstation
path remains intentionally recorded, so this is not absence of every local path.
Tooling sources contain detection patterns and are excluded from evidence sweeps.
Sanitized logs and omitted raw databases/responses do not prove original-output
authenticity or arbitrary-secret absence.

The private wrapper preserves real command exits but retains unchecked setup,
sanitization, copy, permission, source-status and outer cleanup operations. The
checker would treat a missing source-status file as empty; review separately
verified the actual empty capture exists. Inner fixture/socket cleanup and process
reaping are asserted, while outer checkout/venv removal lacks a checked result.
A stale driver header names `678fd71` and the final console line says fourteen
backup cases; the operational pin and complete fifteen-case receipts are correct.
These qualifications do not invalidate the complete scoped capture set.

R1.4b2a's native gate is closed. No repeat is needed for this documentation record.
The measured runs leave 29.763/29.232 seconds under the unchanged gate budget,
not a production latency promise. Readiness remains O(N), and continuous writes
can keep grouping unavailable. Source-bound observation indexing, dashboard group
views, logical findings, private server inputs and R2 through R4 remain separate.
This fixture acceptance does not establish model sensitivity, principal/credential
equivalence, power-loss durability, PostgreSQL/distributed support, enterprise
readiness or release approval.

### Shared observation source binding local acceptance

R1.4b2b1 closes a risk-attribution gap between observation inventory and public
target groups. An alias could previously attach a supported score even when the
saved snapshot's provider, model or endpoint referred to a different target.
Both readers now use one safe-alias and target-binding implementation plus the
same unique report-agent map and strict duplicate-member JSON decoder.

A valid selector mismatch keeps the observation ID and displayed source alias,
with null risk and `unknown`. Safe HTTP endpoint normalization retains supported
high, partial and genuine zero scores. Valid bound sources can remain unmerged;
credential, principal and complete cloud-resource equivalence are not inferred.
Malformed JSON, duplicate members and refused selector scalars return a static
503 incomplete operation, including for a filter that would otherwise be empty.
Reads preserve original reports, rows and scalar caches. Schema 8, raw stored
timestamp ordering, signed cursor scope, candidate/report/source/output limits
and the five-second cooperative read deadline retain their contracts.

Independent regression tests use unchanged frozen actual high/zero/partial
archives, with only snapshots mutated for binding negatives. The corrected
baseline has 29 failures and thirteen passes at `c12cead`; all 42 cases pass on
the integrated correction on SQLite 3.53.1 and 3.40.1 with warnings as errors.
They cover provider/model/endpoint and missing-selector mismatches, normalized
endpoints, unique aliases, unmerged targets, duplicate JSON, scalar storage
boundaries, raw timestamp order, sparse pages, source budgets and API errors.
Five public-gate success/fault controls separately verify source restoration.
Synthetic binding-component tests establish an assessed-risk precondition for
unsafe aliases without relabeling modified historical receipts as actual runs.

The full local coverage gate passes 5,563 tests in 887.76 seconds, with 93%
coverage and warnings as errors. The author's 189 focused and 212 related cases
overlap that suite and are not additive. Ruff and the configured Bandit gate
pass. The small common error/timestamp module removes an import cycle while
retaining the previous inventory imports for compatibility.

The first post-merge macOS run for documentation PR #90 and the first PR #91
macOS run each fail the existing checkpoint contention wall-clock assertion:
2.590072 and 2.614862 seconds against 2.5. They retain 5,482 and 5,562 passes,
respectively. These failures are preserved. A test-only correction separates
lock policy from contention timing: six cases observe the actual 1,000-ms cap,
tighter incoming policies and restoration on the same DBAPI connection, through
success and failure. The real SQLite contention case uses an incoming 125-ms
policy while retaining its original 2.5-second assertion, real locked exception
and unchanged stored checkpoint. No production code or timeout changes. All 46
checkpoint-module cases pass; the seven policy/contention cases also pass on
SQLite 3.40.1 and 3.45.1. The 5,563-case coverage run precedes these six additional
policy cases; refreshed required CI covers the complete correction. This proves
configured lock policy and transactional behavior, not hard scheduling latency.

Both real Gunicorn inventory modes return `inventory-acceptance-v4`, all fifteen
exact assertions and genuine zero command/initial/restart exits. They retain
10,000 observations across three owners, twelve original source assets and the
unchanged 120-second shared budget. Both capture 673 HTTP responses. Aggregate
filters retain 2,500 high, 2,500 minimal and 5,000 unknown observations, with no
critical match; type and combined filters retain their original exact counts.
Snapshot selectors now come from each original produced target. Temporary
provider/model/endpoint mismatches withhold risk, a normalized default port
retains high, duplicate report members return unavailable, and exact restoration
preserves the original source/archive oracle before restart. Owned schema-4-to-8
cache lifecycle checks still reconcile and restore twelve scan and 10,000
observation caches. Seven known private values are checked across five surfaces.
These local Python 3.10.20/SQLite 3.53.1 captures describe a modified integration
tree based on `c12cead`, not a clean native execution of a later merge. Elapsed
time was not captured; no timing claim follows from their successful exits.

A fresh wheel and source distribution pass build and Twine checks. All eighty
scanner/CLI runtime files match the tested source bytes in both artifacts, and
both new regression files are present in the source distribution. The scoped
source digest is
`b9954fba110256d7f86ed18462109a24c04461b69f32693e02c52553cb7b28a1`;
the projection policy is
`2995b15cd8c99923be62414c208caf8bcb1a5cb9a9976d7ea9164d5af8f194d1`.
The actual installed-wheel CLI smoke runs outside the checkout and preserves
completed discovery and unknown risk through private checkpoint recovery.
As before, the wheel contains the CLI/library; the web app and Gunicorn hooks
require the checkout/container. This is not a standalone source-test-bundle
certification or package publication. Required PR and post-merge platform checks
are recorded on the delivery PR.

The compatibility tightening does not rewrite historical evidence or establish
remediation. Observation-index acceleration remains separate. The next product
increment is the complete guided HTTP application workflow; combine its local
operator acceptance into one pinned native retest after delivery. No separate
GCP run is needed for this prerequisite. Model sensitivity, server target
admission, broader R2 coverage and enterprise readiness remain open.

### Inventory reader performance follow-up

PR #91's post-merge run `40998441572` passes seven jobs but fails both
10,000-observation inventory acceptance modes on Python 3.10 at the unchanged
120-second shared deadline. Initial traversal, source-binding controls and
cursor checks complete; restart traversal times out. The failure is retained.

Owned profiling attributes most repeated work to target identity construction
and rebuilding bounded-source SQL. The correction prepares SQL once per page,
binding each fresh identifier and remaining byte allowance. A decoded report
memoizes only grouped original identities by unique alias and organization.
Every observation still validates its own snapshot. Unmerged identities remain
row-specific, and successful bindings return a fresh snapshot so callers cannot
mutate a cached target dictionary. No source, report, cursor or verdict is cached
across requests. Strict JSON parsing, selector matching, source reads, work limits
and the 120-second acceptance deadline are unchanged.

An owned Python 3.12 comparison measures 40.28 seconds before and 27.55 seconds
after the initial optimization: the same 10,000 observations, fifteen assertions,
673 HTTP responses and two zero server exits. This is local timing, not a Python
3.10 or deployment performance claim. The final fresh-snapshot protection passes
159 focused source/group cases; 279 broader cases also exercise both previously
failing real-server modes. Eleven new regressions cover cache ownership, changed
selectors and metadata, row-specific unmerged IDs, fresh report reads, current
byte caps and returned-target mutation. Final integrated CI remains required.

The subsequent `bad4d109` CI run `41006249807` passes all 5,865 cases on hosted
Python 3.10 in 1,316.23 seconds, including both previously failing inventory modes
under the unchanged deadline. That validates this correction on the affected
platform. Its Python 3.13 report-path failure is separate and retained below;
final delivery still requires the complete matrix on the corrected head.

### Guided HTTP application local acceptance

R2.1a/R2.2a add a complete CLI workflow for an application that accepts a JSON
prompt field and returns generated text at a selected JSON pointer. Previously,
the model-provider adapters required a model and could rewrite its route. Guided
private setup, an offline target/scope/readiness preview and active assessment
now share the existing pipeline without an invented model or manual asset IDs.
See [setup and supported scope](http-application-assessment.md).

The selected objective uses the unchanged `protected-disclosure-v1` catalog:
seven groups, at most 35 POSTs, no hidden liveness/discovery request or unrelated
GET checks. Defaults are 35 shared attempts, 180 seconds overall, ten seconds per
request and 65,536 response bytes. Explicit networks, normal transport restrictions
and remote Bearer TLS requirements remain enforced. A fresh client session does
not reset application state; canary placement, generated-field mapping and public
principal/context labels remain operator attestations.

One strict extractor serves response usability, analysis and live receipt
creation. It rejects duplicate members, invalid UTF-8, nonfinite values and
excessive JSON work. Only the configured string field supplies evidence; metadata,
unselected legacy fields and request reflection cannot confirm disclosure. Actual
captured method, URL, JSON prompt and authentication must match the pinned target.
New prompt receipt source `3.0` under existing ledger `3.0` and checkpoint `4.0`
binds the public adapter throughout both views, scoring, exports and recovery.
Legacy providers retain their existing source-2 semantics; reserved HTTP targets
cannot use stripped or obsolete evidence contracts. No database migration or
server profile-admission expansion is included. Imported HTTP observations need
matching recorded adapter fields before receiving current numeric risk.

Independent review closes two coverage edges: a genuine short partial sample
cannot be relabeled as a completed five-response category or seven-category
execution, and conflicting execution status fields are refused. Internal live
receipt prefixes remain valid; saved views account for the seven planned rules
through finalized checks and acknowledged unfinished receipts. Quiet output
remains inconclusive/null. Later nondisclosure does not resolve earlier findings.

| Local evidence | Observed result |
| --- | --- |
| Initial HTTP coverage gate | 5,843 passed, 1,095.06 seconds, 93% coverage, warnings as errors |
| Coverage refresh before output-preflight correction | 5,853 passed, one permission-fixture failure, 1,053.66 seconds, 93% coverage |
| Corrected permission fixture | All 32 CLI cases pass under `umask 077`; affected case also passes under `022` |
| Additional independent cache review | Eleven cases pass after the coverage run's collection |
| Corrected output preflight | 104 integrated cases pass, including all 45 CLI cases; seven additional independent path cases pass |
| Combined focused integration | 249 passed, two full workflow modes separately deselected |
| Independent policy/fixture cases | 125 fast cases pass after the final coverage/status guards |
| Both public CLI modes in the coverage refresh | All eleven assertions; 77 actual POSTs and thirteen recorded CLI exits per mode |
| Corrected-runtime optimized workflow | All eleven assertions and 77 POSTs; optimization 1 reaches actual CLI children; empty stderr |
| Fresh installed-wheel workflow | All eleven assertions, 77 POSTs, 75.767 seconds, empty stderr |
| Packaging/static checks | Fresh build, Twine, Ruff and configured Bandit pass; all 84 runtime files byte-match both artifacts |

Author core/suite and CLI sets pass 353 and 103 cases, respectively; independent
CLI/profile review also passes eighty cases. These overlap the complete suite
and must not be added. The public fixture checks full 35-response HTTP disclosure
and HTTPS defended runs, five one-request positive/negative controls, a zero-I/O
request collision, and SIGKILL after acknowledged evidence before a later stalled
response. Partial controls and offline recovery correctly exit 1; the killed CLI
exits -9. Parent gate exits are zero. JSON/SARIF recovery retains the exact receipt
without loading a profile, resolving credentials or replaying requests.

The refreshed invocation runs under `umask 077`. Its sole failure assumes that
`mkdir(0755)` produces `0755`; the mask correctly produces `0700`, which the wizard
preserves. The fixture now explicitly sets its intended `0755` mode before the
wizard, retaining all permission assertions and production behavior. That CLI
file passes all 32 cases under `077`, and the affected case passes under `022`.
The eleven later independent review cases pass separately. The failed local
invocation is not presented as a clean
full-suite pass or combined arithmetically with overlapping reruns.

The later macOS and Linux Python 3.13 jobs each pass 5,864 cases and fail the
report-path loop case. Non-strict path resolution no longer raises for symlink
loops in [Python 3.13](https://docs.python.org/3.13/library/pathlib.html#pathlib.Path.resolve),
so the old guard allowed requests before the private writer refused the output.
The correction strictly resolves the existing parent and checks the leaf without
following symlinks before private preparation or execution. New and existing
regular reports and canonical ancestor aliases remain supported. Symlinks,
nonregular leaves and invalid parents fail with a static private error. Plan
mode performs no destination check. This is a read-only preflight, not an atomic
reservation against later filesystem changes; the private writer remains final.
Both the fresh installed normal workflow and actual optimized checkout workflow
pass afterward. Earlier coverage figures describe the preceding runtime; final
CI collects all 5,885 cases on the corrected source.

The earlier two-parent-mode fixture run did not propagate optimization to child
CLIs; it proves normal CLI behavior only. This validation gap remains recorded.
The corrected driver explicitly forwards `-O`/`-OO`, and actual child-flag
regressions accompany the final normal/optimized acceptance. Its final SHA-256 is
`f6cc862458a4804f229d3ddbf78ca1d187cad66c214eff15c611926a488a569e`.

The installed-wheel check copies that exact driver into an empty directory
outside the repository. The installed interpreter runs its actual CLI children
there; module origins are checked beneath the fresh environment's site-packages.
No scanner function is replaced and no checkout scanner module is available in
that directory. The real installed console entry point is checked too. The
ordinary installed discovery/checkpoint smoke also passes. All eight new
regression files match the source distribution, including independent report-path
cases. The wheel remains CLI/library
only, and this does not certify a standalone source-test bundle or publish a
package.

The reproducible 84-file source fingerprint is
`70299904cb69dafdec45cfe906ff826e095b1df5dab711a54453f3ed28339e48`.
The existing baseline and protected catalog hashes/pin are unchanged. The local
wheel SHA-256 is
`bd3dd6c6b5084ad9ed4730ca4583a157828efa48f0480f56df73821321c87403`;
the source-distribution SHA-256 is
`0ea04a135058150be45cc4e6f7f762cecbd2cd20ad4b2d056e31abc865542a5e`.
These identify local validation artifacts before this record's documentation
edits. The wheel is the exact artifact used for the installed workflow; the
source distribution matches all eight final regression files. They
are not signed build or dependency attestations. Delivery CI builds the final tree.

Profile creation is no-clobber and owner-only, including rollback after a late
parent check; unrelated or replacement inodes are preserved. Partial terminal
counts use acknowledged minima rather than reporting zero beside retained
evidence. Each public gate checks five known private values and nine profile
paths, including encoded forms, across output and all checkpoint contents.
These sweeps do not establish arbitrary-secret absence. Git, Docker and source
manifest exclusions cover `*.target.json`, `.aiscan-targets` directories and
default assessment outputs. An actual isolated source build excludes seven deliberately included
private fixture paths at root and arbitrary directory depth while retaining
ordinary public JSON. No operator registry, database, private profile, live model,
paid provider or cloud deployment was used for this acceptance.

Required PR and post-merge checks remain delivery gates. One scoped pinned
[native retest](http-assessment-retest.md) follows delivery, using owned loopback
fixtures and selected compatibility tests. Native operator acceptance, server
target setup, stateful session contracts, logical findings, representative model
sensitivity and the remaining R2 through R4 work remain open.

### Supplied native HTTP application retest at 5a9ab35

The supplied `aiscan-http-assessment-5a9ab35.tar.gz` supports scoped native CLI
and HTTP application behavior. Native process-cleanup acceptance remains open.
Its SHA-256 is
`d9cfeabfd32779b83813d1be9bc90bd2b69e74e57307347f37495b2849906f04`.
Two independent data-only reviews checked the safely extracted files against the
expectations frozen before execution. No supplied script, scanner, lab service,
operator configuration or database was executed or loaded for that review.

| Returned evidence | Verified result |
| --- | --- |
| Pinned revision | `5a9ab356d2f68d1ff4a988dd9d17a26788a9141d`, PR #92 |
| Captured runtime | Linux, Python 3.11.2, SQLite 3.40.1 |
| Executed source | The expected 84-file scanner digest `70299904...`; full public driver digest `f6cc8624...` and all 26 focused file hashes match |
| First-run capture set | All 55 required files present; mandatory `source-status.log` is present and empty |
| HTTP modes, both runs | All six receipts match eleven ordered assertions, 77 fixture POSTs, thirteen mixed CLI exits, private-value/path counts and producer identities |
| Optimization | Normal, optimized and installed modes record parent/child flags 0, 1 and 0 respectively |
| Focused pytest | 825 passed, two separately captured public modes deselected; 190.36/191.81 seconds |
| First-run command exits | All sixteen actual step exit files are zero, including build, Twine and installed import/source proof |
| First-run wrapper | Failed: `focused-tests_surviving_owned_child`; driver and pinned-block exits 1 |
| First enclosing job | `lab-jobs/EXIT` records 7; this differs from the pinned block's exit 1 |
| Retry | Wrapper claims success and pinned-block exit 0; only nine of 55 mandatory captures are returned |

The first complete run's source and installed identities agree. The installed
proof records the expected relative scanner module paths under its checked
site-packages origin. The public fixture validates supported 70/high disclosure,
truthful null/incomplete controls and acknowledged crash recovery without replay.
Raw generated reports and built distributions are deliberately absent, so the
review relies on the pinned driver's assertions, identity reconciliation and
captured build checks rather than independently inspecting those private reports
or distribution bytes.

The failed wrapper is preserved as failed. It flagged a descendant after pytest
exited, attempted forced cleanup, and reported no remaining unreaped-child failure. No PID, state
or timing diagnostics identify that child. A harmless race, zombie or test
teardown leak cannot be distinguished from these files. The report's attribution
to a slower-runner race and its exclusion of a feature regression are not
established. [psutil documents](https://psutil.readthedocs.io/stable/#psutil.Process.is_running)
that its running check also includes zombies; that is a possible classification
issue to test locally, not a diagnosis of this captured failure.

The retry omits 46 mandatory files, including actual step exits, per-mode stderr,
runtime, installed proof, cleanup and the mandatory source-status file. Its
twenty-check summary was produced before selective sharing; it cannot replace
those absent captures or the absent enclosing runner EXIT. The local macOS pass
is narrative-only in this archive. Existing platform CI is separate evidence.

The primary capture inventory has 54 entries, excluding itself. Fifty returned
files match; four log copies differ in the declared sanitization class. The
outer helper deletes the original capture directory without a demonstrated
private raw-log backup, so those transformations cannot be reconstructed from
the bundle. Eight retry inventory entries match the shared subset; 46 are absent.
All 87 AppleDouble files are packaging metadata. Exported directory/file modes
do not establish the original capture directory's permissions.

Each public driver records its bounded five-value/nine-profile-path privacy
check. The separate helper's nine swept names include four populated lab-secret references,
two static references and three PII patterns; it omits hexadecimal forms and runs
before several final shared outputs exist. Review screens found no apparent
credentials or personal private values. Those observations do not establish
arbitrary-secret absence or full privacy coverage of every transformation.

The follow-up targets the focused suite and process lifecycle diagnostics while
preserving this HTTP evidence and the first failure. Scanner/library/CLI runtime
behavior and model-detection claims remain unchanged. Complete native acceptance
requires the instrumented cleanup result, complete captures and genuine exits at
both the pinned block and enclosing job levels.

#### Watchdog follow-up and local verification

The guide now uses the separately hashed `scripts/native_retest_watchdog.py`.
It allows up to one second of natural exit/reaping inside the existing shared
five-second child cleanup budget. A living child needing forced cleanup still
fails, as do PID reuse, unknown probes, signal/wait errors, unreaped processes
and diagnostic-limit exhaustion. Fresh process identities precede signals;
zombies require actual reaping or verified disappearance. Main-command failures,
timeouts and output limits remain failures. Diagnostics omit command arguments,
environment, paths and exception messages. Tracking covers observed descendants;
it is not an adversarial process-containment guarantee.

The helper SHA-256 is
`8d9c509676267fdfc03fde507ea7f637180f8d0eb3a8672542335d2d4b329295`.
Twenty-seven committed regressions pass in 1.71 seconds with warnings as errors;
ten private independent cases also pass. The guide's exact `run()` function,
executing the real 27-file focused command locally on Python 3.10.20, passes 852
tests with two full HTTP modes deselected in 133.57 seconds. It tracks 23 owned
descendants and 71 state events; all end gone, with no forced kills, probe errors
or cleanup failures. This is local command/watchdog integration evidence, not a
new native full-wrapper run. These test sets overlap and are not additive.

The CLI/library fingerprint remains `70299904...`, covering the same 84 runtime
files, and public HTTP driver `f6cc8624...` is unchanged. No scanner, scoring,
transport, database or catalog behavior changes. Required CI collects 5,912
cases, including the new helper regressions.

The focused native follow-up keeps the original 26 files plus the helper tests,
and omits the three full HTTP modes and wheel work. It requires exact mode,
helper/current revision, source/runtime compatibility with the original complete
baseline, all eight actual step exits and diagnostics, empty source status,
checked cleanup and both block/job exits. Dependency differences are recorded
as qualifications. Retain raw captures privately; sanitize only separate shared
copies with explicit original/shared hashes. This changes the cleanup protocol
prospectively and cannot reclassify the original failed run as passed. The
instrumented native result remains required.

### Supplied native focused-cleanup retest at e484920

The supplied `aiscan-http-cleanup-e484920.tar.gz` closes the focused native
process-cleanup gate at `e4849206525f71674f982c1b30ea304e900ed2b8`. Its SHA-256 is
`5273170ce1970442d08e52d9e82b84af032e1a502f4e75ede50cb0a48e9abbe4`.
Two independent data-only reviews compare the returned bytes with the
expectations frozen before execution, whose SHA-256 is
`91049bbcffb648d22b85ff7e5fcd2a8c30a438cd4154dced37d9c630462a7525`.
No supplied script, model, operator configuration, environment secrets or
database was executed or loaded for this review.

| Returned evidence | Verified result |
| --- | --- |
| Revision and mode | Exact merged `e484920` pin, `focused-cleanup` in the three v2 documents |
| Runtime | Linux, Python 3.11.2, SQLite 3.40.1, identical to the original baseline |
| Source and helper | Original 84-file scanner identity and pinned watchdog SHA-256 match |
| Main captures | All 41 required files; mandatory `source-status.log` present and empty |
| Raw capture inventory | All 40 entries match returned byte counts and SHA-256; inventory excludes itself |
| Job captures | All four required files, including separate block and enclosing-job exits |
| Actual exits | All eight steps, driver, pinned block, enclosing-job trap and lab runner are zero |
| Reconciliation | All fourteen exact check names are present and true |
| Focused pytest | 852 passed, two separately accepted public modes deselected, 193.45 seconds; no failures, skips or warnings |
| Process diagnostics | 31 tracked child identities, 106 events, all terminal states gone; no forced kills, probe errors or failure codes |
| Cleanup | Owned work-directory removal is recorded as successful |

The focused cleanup takes 0.00137 seconds within the existing five-second total
budget. All 31 identities are already gone at their first natural-cleanup probe;
this run does not establish that the new natural-exit allowance was needed.
Tracking is unavailable only for source-venv and source-install, before
the isolated psutil dependency is loaded; the other six steps enable it. Some
children have transient zombie observations during testing, but all end gone.
These observations do not diagnose the earlier failed run. The new report's
description of that failure as a reaping race remains unsupported.

The runner used retained first-full-run captures rather than the prepared local
baseline bundle, and did not receive the local frozen-expectations file. This
does not prevent comparison here: all four baseline revision/runtime/dependency/
source identity hashes match the frozen originals exactly. Both dependency
inventories contain 89 packages. The only version difference is filelock 4.2.4
to 4.2.5, recorded as `dependency_inventory_changed`, not an identical-environment
claim or gate failure.

All 41 main raw captures are returned unchanged. The three job captures available
before finalization were copied unchanged; the enclosing-job trap wrote the
fourth at exit. Two separate sanitized text copies, source-install.log and
pinned-block.stdout, match the raw/shared hashes in their manifests. The outer
helper removes its original capture directory after retaining the complete raw
copy. This run therefore preserves the bytes needed for review. The jobloop log
is a separate sanitized output without a returned original/hash manifest.

The private harness still has unchecked setup/copy/permission/listing/removal
commands and a best-effort exit-trap write. Its captured critical gate exits and
complete raw evidence support this scoped acceptance; they do not prove every
outer command propagated failures. Exported file modes do not prove the original
runner's capture permissions. All 67 AppleDouble files are packaging metadata.

The on-runner privacy sweep covers 51 files before several final outputs exist.
Its nine labels represent four populated lab-secret values, two static reference
names and three PII patterns, not nine populated secrets. Encoded forms omit
hexadecimal, and private path-prefix checking is not configured. Later report,
driver, final job-log/exit and packaging bytes are outside that initial sweep.
Review pattern screens find no apparent credentials or personal private values;
literal test patterns in driver source are intentional. These are bounded
privacy observations, not proof that arbitrary secrets are absent.

PR #93 and its merged revision pass all eight required CI jobs, including 5,912
tests per platform. This later native focused run is separate evidence: it does
not rerun HTTP modes, build/install a wheel or turn the first full failure and
incomplete retry into passes. Existing HTTP receipts remain scoped to the
unchanged scanner runtime. Server HTTP target admission, stateful sessions,
representative detection sensitivity and the remaining roadmap remain open.

### Server HTTP reference workflow local acceptance

The server now accepts one operator-configured HTTP JSON target through an
authenticated, revision-pinned one-shot scan. Registry schema `2.0` adds
tenant-owned HTTP references while schema `1.0` provider registries retain their
contract. No database migration, template/schedule capability, model placeholder
or discovery prerequisite is introduced. See
[operator configuration](server-http-assessment.md) and the
[synthetic gate](server-http-acceptance.md).

The final modern local process gate passes all fifteen exact assertions in
94.807 seconds on Python 3.13.14, aiohttp 3.14.5 and Gunicorn 26.2.0, with warnings
treated as errors. Its genuine exit is zero and stderr is empty. The authenticated
API uses an owned private Unix HTTP socket; assessed fixtures use actual loopback
HTTP and verified HTTPS, including Bearer credentials and an untrusted-CA control.
The receipt binds library source `0312b21582ca4edd58accedc0e06f6bb72cadd81a560d303bd329914d29bb0ee`,
raw app `f6766e99415c71a24e32e79e0a26492dbbdc53fc947f4d07a4d26859da5a6f36`,
driver `4fa4cf33d48a7d9d4ee8b6d5c32c939a9ca90ebd1be4e94c2411fd00fd49cf93`
and separately checked Gunicorn hook
`3e0c96b012f6b89e830d93d8a840c848aeb1db005862aaa0b1ab18a42d40395c`.

The same frozen production source also passes all fifteen assertions on Python
3.10.20 in 95.461 seconds, with genuine exit zero and empty stderr. Both receipts
have identical producer identities and three clean actual master exits.

- Tenant-scoped previews and refused raw/mixed/forged inputs make no target POST.
  Source/unit cases separately enforce the stronger no-DNS/no-database preview
  contract. Templates and schedules refuse HTTP target selections.
- Independent HTTP and HTTPS disclosures each make 35 requests and retain
  canonical 70/high evidence across saved results, API, inventory, JSON and SARIF.
  The defended target makes 35 requests and remains null/inconclusive. Off-pointer
  output makes one request; untrusted TLS makes no accepted target POST. Neither
  can establish a pass.
- Cancellation, outer deadline and real worker SIGKILL retain acknowledged
  disclosure receipts. Each reaches two fixture POSTs, with no replay after
  recovery. A verified fresh worker identity replaces the killed worker.
- Removed queued references and tightened current policy are refused before a
  target POST. Three actual master waits return zero. Every observed normal
  worker has a successful cleanup acknowledgement; only the one recorded
  intentional SIGKILL is exempt. No forced cleanup, unknown process probes,
  lifecycle failures or resource/runtime warnings remain.
- The private-value check covers 25 known values/references and their supported
  encoded forms across owned public API/export, raw log and SQLite surfaces.
  Private fixtures are removed. This is not arbitrary-secret absence.

Review corrected cross-family private-input persistence, redundant synchronous
DNS outside worker deadlines, and dispatcher ownership release while a scheduled
preflight future remained active. Shutdown now requires explicit completed work
and closes worker-owned listeners. The driver rejects swallowed cleanup-hook
exceptions, missing acknowledgements and the graceful-shutdown boundary; its
clock starts before termination. Reproduced cancelled TLS transport warnings
required bounded post-work event-loop drainage and session ownership of returned
SSL transports through the documented connector API. Owned transports are
aborted on close even when upstream request cancellation/timeouts have released
them. Retention is bounded by existing request limits; no child request task or
private upstream attribute is introduced. Worker shutdown also removes its
database session and attempts disposal of every pool before acknowledging cleanup.
No work deadline, cleanup allowance, Python warning rule or resource assertion was
relaxed. Earlier failed process receipts remain failures.
The aiohttp dependency floor is now 3.14.5, matching the tested release's corrected
Python-version cleanup boundary. Older allowed releases treated Python 3.12.7
differently; this change removes that declared compatibility gap without claiming
the earliest corrected release or every historical dependency combination.

The corrected pre-modern-fix Python 3.10 full gate passes 6,026 tests with warnings
as errors and 93% coverage. That result did not clear the separate Python
3.12/3.13 transport and SQLite warnings reproduced in CI and actual owned workers.
The modern baseline fails with thirteen workflow assertions; a database-only
correction removes SQLite warnings but remains failed for TLS warnings. Only the
combined correction achieves all fifteen assertions on the modern runtime.
No earlier failure is reclassified. Actual held-peer cancellation plus header/body request timeout and
overall timeout cases pass on Python 3.10, 3.12 and 3.13 with unchanged two-POST,
one-receipt evidence. Independent ownership/disposal failure tests verify static
errors, all cleanup attempts and withheld acknowledgements.
Overlapping validation counts are not pooled. The delivery PR records final full-suite,
packaging, independent review and required eight-job PR/main CI results.
The one remaining external gate is the pinned native server process workflow.
Installed CLI smoke is separate from source-server acceptance. These deterministic
fixtures do not measure live-model sensitivity, independent server state,
TCP/reverse-proxy deployment, team authorization or enterprise readiness.

### Protected-access request-provenance prerequisite

Read-only source audit and owned loopback HTTP reproductions at `6af7fa2` expose
a prerequisite before access observations become durable. No operator database,
registry, external target or supplied private driver was used.

In one fixture no protected record exists: the target echoes request headers,
while a fresh invalid credential receives 403. A lower-level client hook adds
the configured synthetic marker after planned-request preflight. In another
fixture an extra wire header carries the issued credential, silently authorizing
the purported anonymous/malformed probes. Both actual `SafeSession` pipelines
make 20 GETs and produce 18 confirmed authentication-bypass findings with
canonical 70/high, under current ledger `2.0` and checkpoint `3.0`. The first
mistakes request reflection for protected data; the second mistakes credentialed
access for bypass. Current access checks do not validate the actual captured
request before accepting response evidence.

A separate genuinely protected fixture passes authorized/denied controls,
discloses its independently seeded record on the first anonymous probe, then
stalls request 4. Cancellation inside that same check retains zero findings and
null risk, because results remain in its local list until completion. This
confirms the later receipt requirement but does not justify preserving the
false-confirmation paths above.

Close actual-request provenance first: pin private inputs before controls,
verify complete live GET captures and selected credential roles, exclude marker
transmission and extra issued credentials, and refuse missing or contaminated
provenance. Keep existing protocols, frozen samples and budgets. Tightened
semantics require explicit versioning, conservative historical risk/resolution
eligibility and transactional scalar-cache reconciliation; original archives
remain unchanged. Protected-access receipts remain a separate increment.

### Tenant observation retention local acceptance

R1.2c extends normal CLI/Python tenant checks with mixed observation ledger `2.0`
and checkpoint `3.0`. It does not expand server admission, alter SQLite schema 5,
change prompt catalogs or tenant control semantics, or add CLI crash files.
The old prompt ledger `1.0` and checkpoint `2.0` retain their original meanings.

Actual bounded transport witnesses verify the prepared tenant context, exact
request role, model/body/Host and credential location while each response is live.
The subject response at ordinal 2 is held until the genuine denied third control
succeeds. Receipts publish before cleanup or another request. Only bounded public
control statuses, ordinals, target/probe identity and finding links persist;
private envelopes, principal labels, environment references, keys, markers,
request capabilities and generated text do not.

The complete ledger validates sources, versions, IDs, links, typed counters and
the separate 35-prompt/six-tenant caps before partitioning evidence. Current
tenant positives require receipts even after check completion. Draft prompt
source `1.0` cannot enter the mixed ledger; its legacy structural-read behavior
remains unchanged. An ineligible append cannot replace acknowledged supported
evidence, including a receipt committed before scoring returns a number. Raw
candidates validate before state mutation, and public/SQL guards preserve prior
eligibility without requiring an initial privacy-redacted unknown to become
assessed. New invalid groups cannot erase a valid finding or expose an access zero.

Root and independent review also corrected source-view gaps: known observation
versions must agree across report, asset and matching security result; typed JSON
comparison rejects Boolean/numeric counter aliases; confirmed tenant target
bindings agree canonically across both views. Missing roots cannot promote
observation-bearing assets. Independently supported nonledger legacy assets keep
their original eligibility, and raw archives remain unchanged. Explicit adapter
declarations are literal supported strings chosen before the first checkpoint;
descriptor code is not executed to discover a version.

Five frozen reports captured through real owned HTTP and the original producer
at `0d60e09` retain exact bytes, IDs and original 70/high or 90/critical scores.
Independent fixed hashes identify the archives and ten original source files.
These are old producer outputs, not reports rebuilt through the new writer.

Focused gates cover genuine controls, forged/reused provenance, task isolation,
response-only/header/request reflection, full private-basis collisions, held
candidate rejection, callback failure/cancellation, mixed-ledger corruption and
atomic refused appends. Eight actual trusted-HTTPS library cases preserve receipt
prefixes and 90/critical partial risk through timeout, cancellation, cleanup,
later 503s and transmitted contamination. Eight real CLI execution cases export
JSON/SARIF on orderly deadline/cancellation while the tenant check is unfinished;
files are owner-only, receipt/finding links agree and no terminal check is invented.

Two spawned real dispatcher cases wait for an acknowledged SQLite commit, reach
a later owned HTTP stall and then receive SIGKILL. New ownership recovers the
exact receipt, finding, producer stamp and snapshot with one interrupted terminal
event and no probe replay. Authenticated Flask reads over that actual recovered
database agree across results, status/list summaries, critical inventory, raw JSON,
SARIF and audit. No private tenant input is admitted through the API. These are
library-worker persistence fixtures, not a server tenant-profile workflow.
Raw/encoded private-value sweeps cover retained JSON/SARIF, actual SQL/cache rows,
database/lock/log bytes and API bodies/headers. Owned directories are 0700 and
database/lock/log/output files are 0600. This is acknowledged-process recovery,
not power-loss or CLI forced-termination durability.

Combined local coverage passes 4,366 cases with warnings treated as errors on
Linux/Python 3.10.20, covering source, server and CLI. The initial full run had
4,312 passes and 20 failures: version/error expectations needed updating, while
projection and dynamic mock-declaration failures prompted runtime corrections.
Final descriptor hardening and the expanded recovered-API assertions receive
their separate focused gates; required CI runs the final committed tree.

Producer review passes 105 overlapping producer/legacy cases on Python 3.10 and
3.13. The shared contract author gate passes 48 cases on both. Independent review
passes 69 mixed-contract and dispatcher/API cases on both. The separate HTTPS
library/CLI gate passes 16 cases on Python 3.13 with coverage and warnings as
errors. Root final interface/persistence compatibility passes 95 cases after
literal-declaration hardening. Counts are regression coverage, not model yield.

Ruff, configured Bandit, whitespace/ASCII-dash checks, distribution build, Twine,
and fresh installed-wheel smoke outside the checkout pass. All 70 wheel Python
sources match the candidate; source/catalog identity and installed metadata agree.
Both normal and optimized eleven-case disposable backup/restore modes pass.
The first package-smoke attempt lacked `python` on PATH; selecting the existing
test virtual environment fixes that invocation without a source change.

Required cross-platform delivery checks are recorded on the implementation PR.
The next external acceptance is the pinned
[tenant interruption gate](tenant-progress-retest.md) against the existing HTTPS
lab. It covers leak-then-stall, held-candidate rejection, defended nondisclosure
and native recovery; no broad cohort repeat is needed. No cloud startup,
operator database/registry access, package publication or deployment was used.
Protected-access within-check receipts, private server tenant profiles and CLI
crash recovery remain separate work.

### Development producer identity local acceptance

R1.5a replaces stale scanner-package `1.1.0` literals with canonical development
version `1.2.0.dev0`. It adds deterministic scoped source/catalog fingerprints,
structured CLI and authenticated no-SQL API diagnostics, and an original producer
stamp for new execution reports. Pipeline checkpoint streams retain exact stamp
presence, scalar types and values. Recovery never invents a current stamp for
historical or preparation-failure reports. Derived SARIF/comprehensive exports
preserve an older producer or explicit unknown, separately from the current
exporter. Raw archived JSON remains unchanged. See the
[identity contract](build-identity.md).

The shared digest covers packaged Python and CLI bytes, not all repository or
loaded runtime content. Server-app identity is separately limited to the trusted
checkout app; installed/container copies can explicitly be unavailable. Catalog
hashes describe bundled definitions, not executed custom coverage. Read failures
return unavailable/null provenance without changing evidence or readiness.
No runtime Git, network, operator database or evidence-profile lookup is added.
Protocol, ruleset, check, evidence and database versions remain unchanged.

Local acceptance includes:

- Python 3.10.20: 4,142 tests pass with warnings as errors and 94 percent source,
  API and CLI line coverage in 355.26 seconds. A final canonical import alias is
  checked separately with focused formatting/identity cases and delivery CI.
- Independent review passes 65 overlapping adversarial cases on Python 3.10 and
  exact Python 3.13.15 with SQLAlchemy 2.1.6, coverage and warnings as errors.
  Cases cover trusted source boundaries, symlinks, limits/read failures,
  old/null/malformed producers, typed persistence, private collisions,
  authenticated no-SQL diagnostics and original JSON download preservation.
- All 176 focused identity/persistence cases and a 448-case compatibility gate
  pass. Ruff and configured Bandit pass with no medium/high findings. Package
  build, metadata and installed-wheel identity parity have dedicated smoke
  checks outside the source checkout. Required PR/post-merge CI is recorded on
  the delivery PR.
- After restoring the public canonical version alias, all 180 focused
  formatting/identity cases pass. The final local wheel has 67 Python files,
  each matching source bytes, and excludes private instruction files. Its
  SHA-256 is `922845181c048d5429fd11cf879103784a3459a47bdd856e5b4ac28ab8746fcd`.
  Fresh installed CLI/source/catalog/distribution identity agrees outside the
  checkout. An owned environment also upgrades the prior local `1.1.0` wheel
  to `1.2.0.dev0` with the same final identity and no broken requirements. This
  is a local prior-build fixture, not a deployed or published-release upgrade.

Review reproduced and corrected four specific boundaries. Ordinary Python
dictionary equality admitted Boolean/float substitutions for integer provenance
counts; checkpoint comparison now preserves JSON scalar types. Identity privacy
originally scanned serialized JSON syntax, so a later public `null` API-key probe
could withhold a valid stamp mid-run; matching now uses real string leaves and
keys. SARIF adapters now carry the complete original report's known-private basis
to identity formatting rather than dropping secrets from omitted fields. New
outer identity field names also join existing static privacy guards. No verdict
assertion or checkpoint immutability rule was relaxed. A changed-file fixture now
binds to the file descriptor and verifies its injection instead of relying on
JSON key order.

This is content identification, not signed report authenticity, exact Git
revision or dependency/build attestation. Fixed catalogs, sampling, risk scores
and raw archives retain their existing semantics. Diff/triage provenance,
release checksums, SBOM, dependency locking and deployed upgrade acceptance remain
separate work. No GCP retest or operator data is needed for this metadata slice.

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

### Supported server canary and paired-prompt retest

An operator-supplied private lab bundle tests exact runtime revision
`4f03d6350058c40ad1cdba1d73b16d22a4fa1575` on Linux/Python 3.11 with real
Gunicorn, the dispatcher, and fresh private SQLite. Four supplied job logs verify
the revision; setup records a clean checkout and 286 passing targeted tests with
five skips, not a new full-suite gate. Independent artifact reviews inspected
the JSON, SARIF, checks, command exits, and driver source without running the
supplied scripts or contacting the lab.

- The supported startup registry and API profile references enable confirmed
  canary findings without modifying discovery reports or database rows. All six
  saved JSON exports equal their pipelines. All 40 agent projections agree with
  their saved evidence and contemporaneous inventory: 35 remain null/unknown/
  not-assessed; five retain 70/high with sampled or partial coverage. There are
  29 confirmed checks and 124 original finding occurrences, not 124 independent
  vulnerabilities. No security check passed from nondisclosure.
- Deterministic disclosure and leak-then-failed-request cases retain their
  respective sampled and partial risk. A genuine 503 source remains partial;
  active reuse preserves its source warning. The source-immutability assertion
  compares parsed JSON, not original response bytes; rich-source immutability
  was not separately asserted. SARIF summaries, statuses,
  source uncertainty, check ledgers, and findings agree with saved pipelines.
- Seven misuse cases record HTTP 400. The final six-scan history and unchanged
  scan count for a refused template support no extra admissions. Profile removal
  plus restart refuses the saved template; restoring it enables another run.
  Negative response bodies and template documents were not separately archived.
- Archived restart inventory independently preserves all 40 projections. Per-scan
  restart results rely on driver assertions because their response bodies were
  not retained. Post-restart export and audit-response bodies are absent. The
  high-risk filter was not exercised or captured. Schedules were explicitly
  NOT RUN, not passed.
- Preserve the harness failure: its check ledger has 79 passes, one failure, and
  11 informational entries. The failed assertion incorrectly requires null for
  a profiled real target that produced a confirmed canary finding. The Python
  driver exits 1; its shell wrapper nevertheless records exit zero. This supports
  scoped scanner behavior, not an all-green acceptance gate. Wrapper exit zero
  alone is never sufficient acceptance evidence. The corrected server driver
  differs from its setup hash; its execution log records no replacement hash.

The paired benchmark uses the same exact-canary analyzer for both 35-prompt
suites. All ten pairs complete, with five baseline-first and five candidate-first
orders matching the recorded seed. Each suite attempts and evaluates 350
requests, 700 total, in approximately 27 minutes with no retries. The experimental
suite observes disclosure in 10/10 runs versus 2/10 for the legacy suite: two
both-detected, eight candidate-only, zero baseline-only, zero neither, and zero
incomplete pairs. Probe manifests, versions, category checks, and aggregate
arithmetic match the tested implementation. Both suites also detect the separate
deterministic fixture in one pair; that fixture does not measure comparative
real-model effectiveness.

This is improved observed disclosure yield on one operator-attested vulnerable
target, not general sensitivity, calibrated reliability, or enterprise readiness.
The target implementation, underlying model/version, private prompt, generation
configuration, and server-side state/reset evidence are excluded. Generation
randomness is uncontrolled; balanced ordering does not rule out server-side
carryover. Overlapping category observations do not attribute individual techniques.
Intervals remain exploratory. Do not pool earlier runs into this comparison or
promote the candidate to production defaults from this single target.

All 1090 archived server response excerpts are omission sentinels. Benchmark JSON
retains static public attack payloads in its manifests, not generated responses;
the supplied report's claim that it contains no prompt-injection text is incorrect.
Logged literal-secret sweeps report zero matches. Actual protected values,
registry, and database are excluded, so exact-secret sweeps and final private file
modes remain operator attestations, not independently repeated privacy proofs.
Sanitized stdout is not proof that original logs never contained a protected value.
No private artifact, target identifier, or fixture secret is committed here.

This accepts the supported server-configuration evidence and records the measured
target-specific comparison with the qualifications above. Production defaults are
unchanged. The next accuracy step is a frozen, independent multi-model replication
with explicit positive/negative controls, target provenance, and preserved capture
bodies. Publication, deployment, and cloud execution need separate authorization.

### Frozen paired-cohort retest

An operator-supplied private bundle covers exact runtime revision
`4070eed89e17daf3d5273d63b9ff99dfd3996194`. Three independent artifact reviews
checked the frozen plan, four reports, job logs, supplied driver source, and
current validator without executing supplied scripts or contacting lab targets.
The shipped plan's hash prefix matches the setup log before the first benchmark;
predeclaration and target provenance remain operator assertions, not independently
attested facts. Logs record 329 passing targeted Linux/Python 3.11 cases, not a
new full-suite run. The setup's outside-checkout import check is not a separately
built-wheel smoke test.

- The repository's offline CLI independently returns exit 0, both normally and
  with an empty inherited environment. Recomputed output exactly matches the
  archived summary: four completed cases and promotion `not_decided`. Current
  manifests, versions, bindings, seeded order, check ledgers, and checkpoints
  validate. The local focused regression gate passes 227 cases with warnings
  treated as errors and an inherited registry-path sentinel.
- Both deterministic controls meet their declared expectations in one pair each:
  both arms detect the disclosing fixture, neither detects the refusing fixture.
  Neither result is a security pass. All 308 check records across the cohort
  retain confirmed, heuristic, or inconclusive outcomes; none is passed.
- Each of the two declared model targets completes ten pairs, twenty arms, with
  five baseline-first and five candidate-first pairs. On the seeded local-model
  target, baseline detects in 5/10 runs and candidate in 10/10, with five
  candidate-only pairs. On the support-bot target, baseline detects in 1/10 and
  candidate in 10/10, with nine candidate-only pairs. Neither target has a
  baseline-only or incomplete pair. Candidate detects in 5/5 runs for each
  ordering group on each target. These are per-target observations, not a pooled
  accuracy score or independent-trial reliability estimate.
- The 44 arms attempt and evaluate 1,540 benchmark requests with no retries:
  70 per control and 700 per model target. Setup, health, model creation, and
  benign validation calls are additional lab traffic, not included in that count.
  Reported arm and cohort times remain within their configured budgets.
- Preserve setup exit 2 for an incompatible model-create request and the first
  controls job's readiness abort at exit 3. The corrected seed job succeeds
  before the model's benchmark, reusing the same frozen plan; the other model's
  completed report is retained. Target setup was corrected after the other
  model's results were available. This supports a predeclared report plan, not
  independent proof that every target configuration was frozen before all
  outcomes. The final gate job explicitly exits with the
  captured CLI status, so its exit zero is not masked by later commands. The
  claimed superseded no-op gate exit and the other model's job script are not
  archived; do not describe the bundle as a complete execution audit trail.

The supplied report overstates twenty pairs per target and independence. The
correct denominator is ten pairs per model target. One target declares stateless
requests; the other explicitly declares persistent or unknown state. Balanced
ordering does not exclude carryover. Distinct provider/model labels satisfy the
structural gate but do not establish distinct model weights or backend
independence. Model identity, seeding, generation settings, and actual target
revisions remain operator-attested. Actual protected values, the support-bot
implementation, immutable model digests, and full runtime generation/state
records are excluded; the control fixture and model-seeding driver are supplied.
This is improved observed yield on two declared targets, not
general sensitivity or enterprise acceptance.

Strict report validation confirms only public static probe payloads and bounded
check observations, with no generated-response fields. Logged literal-secret
sweeps report zero matches, but actual protected values are excluded. The final
sweep does not enumerate the fresh fixture/model markers; an earlier sweep covers
those markers in three reports, not every plan/summary input. The final driver
also loads the lab environment before invoking the gate, contrary to the report's
clean-environment claim. The gate does not read those secrets, and the independent
empty-environment replay succeeds. The model-seeding driver retains a private
marker file on the runner with no cleanup shown, so target-only secret retention
is not established. Private file modes, secret absence, VM shutdown, and final lab
cleanup remain operator attestations. No private artifact is added to Git.

This accepts the scoped cohort accounting and per-case observations. Production
prompts, request budgets, and scan defaults remain unchanged. Candidate adoption
needs a separate reviewed product decision and normal CLI/API workflow validation;
it is not implied by a completed evidence gate. Documentation-only acceptance
does not require another cloud run or authorize deployment or publication.

### Normal CLI and server experimental-suite retest

An operator-supplied private bundle covers exact merged runtime revision
`ae1ba9b5d89f24a824110c777821a202709750ca` on Linux/Python 3.11. Three
independent artifact reviews inspected normal installed-CLI scans, real Gunicorn
and dispatcher captures, supplied drivers, and job logs without executing those
drivers or contacting lab targets. This is operator-workflow evidence, not another
paired accuracy cohort. Private inputs and infrastructure identifiers stay outside
Git. Setup records a clean checkout and 453 passing targeted cases, not a full
gate. Its outside-checkout constructor/help check supports installed-package use,
not a separately captured distribution-wheel build and smoke test. Later jobs
verify HEAD but do not separately record a clean working tree.

- The final CLI driver records 165 passing assertions, zero failures, and exit 0.
  Six candidate cases each run separately as JSON and SARIF, not as two exports
  of one execution. Every execution records seven prompt checks, 35 attempts,
  matching candidate probe versions, and no passed prompt checks. Disclosure
  retains 70/high; refusal and unseeded controls remain null/inconclusive.
  Leak-then-failure retains 70/high with 18 evaluated responses from 35 attempts
  and failed-but-confirmed checks. Attempts are not completed evaluations.
- Both declared real targets disclose in the JSON and separate SARIF runs and
  retain 70/high. The actual JSON records show three confirmed and four
  inconclusive prompt groups on each target. The first target's separate SARIF
  run has five confirmed and two inconclusive groups; the second has three and
  four. These correct the supplied summary's category counts. They are per-run
  observations, not new sensitivity estimates or evidence of independent trials.
  Failed non-prompt requests explain partial controls and the second target;
  the first target completes. CLI exits correctly distinguish partial 1 from
  completed 0. An omitted-option control preserves default probe identities and
  has no suite label.
- The server driver records 181 passing assertions, zero failures, and exit 0.
  Eight saved security JSON reports exactly equal their results' pipelines;
  regeneration with the repository's SARIF exporter exactly matches all eight
  supplied SARIF bodies. Seven selected-suite executions each retain one
  requesting target and skip the rest of the inventory, with seven prompt groups,
  35 attempts, matching versions, and no prompt passes. The refusing control
  remains null; six selected-suite positive snapshots retain 70/high, including
  ordinary failed-request and finalized-partial-source cases. The default control
  is separately assessed without a suite label. Source uncertainty stays visible.
- Complete inventory, high-risk-filter, and history documents match before and
  after restart: 68 inventory entries, seven high entries, and ten scans.
  The high filter equals the exact seven-entry inventory subset. Nine saved
  pipelines independently support 62 inventory projections; six partial-discovery
  entries remain null but lack their source pipeline capture. History exposes no
  risk fields. Per-scan results, JSON/SARIF, and audit bodies were captured only
  before restart; their post-restart equivalence is not independently established
  by this bundle. Schedules are explicitly NOT RUN.

Template creation, hidden pins, caller-pin refusal, name-only update, and a
confirmed template run have passing driver assertions. Seventeen scan-admission
negatives record HTTP 400 and unchanged session counts. However, template
create/update documents and complete negative response bodies are not retained
as separate captures; no template GET/read was exercised. No separate queued-job
count was checked. Source-immutability assertions compare serialized agent arrays,
not byte-for-byte entire reports, and no post-reuse source body is supplied.
These support scoped behavior, not completion of every capture requirement in
the [normal-scan acceptance guide](BETA_TESTING.md#normal-scan-experimental-suite-acceptance).

Preserve both earlier CLI failures: the first driver has 156 passes and seven
incorrect exit-zero expectations, with process exit 1; the shell-aborted attempt
exits 2 after starting fixtures but before invoking the scanner. The final rerun
corrects the exit assertions. Setup's command wrapper always returns zero, so
its logged individual install/test statuses, not setup exit alone, support those
steps. Final returned CLI and server drivers differ from their setup-logged
hashes, and no final executed-driver hashes are archived. No frozen digest,
generation-setting, or state/reset manifest independently establishes target
provenance or predeclaration. Do not call this a complete execution audit trail.

Independent traversal finds 1,500 response-excerpt fields in returned JSON, all
the exact generated-text omission sentinel, not the summary's claimed 1,877.
Known synthetic PII is absent from output artifacts but occurs in supplied driver
source. Literal-secret sweeps report zero matches in outputs and server state;
actual values, database, registry, and private CLI stdout/stderr are excluded.
Those sweeps and original 0600 file modes remain operator attestations. Sweeps
do not independently cover every final assembled bundle file with every actual
secret. A retained private marker file on the runner contradicts the summary's
earlier target-only claim; the later retention section correctly records it.
VM shutdown and final cleanup also remain operator attestations.

The local 453-case focused gate passes again with warnings treated as errors and
an inherited nonexistent registry-path sentinel. No new product blocker was
reproduced. This accepts the scoped opt-in CLI/server workflow evidence with the
capture and provenance limits above, not the full external acceptance checklist,
default promotion, enterprise readiness, publication, or deployment. Defaults,
runtime code, and budgets are unchanged. Documentation-only acceptance needs no
new cloud run; missing captures must not be represented as checked.

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

### Benchmark final-pacing timeout follow-up

Offline-validator review reproduced a benchmark-only completion defect: timeout
during the 35th pacing delay could leave seven completed check records and 35
evaluations while the interrupted category never returned its findings. Counts
alone incorrectly labeled that arm completed. Completion now also requires a
normal return from the tester. Positive analyzer observations survive as partial;
incomplete arms/pairs stay out of complete-case fractions and intervals.

Two regressions exercise actual check decorators, analyzer, observation checkpoint,
CLI, and private export with deterministic HTTP stubs, for both disclosure and
nondisclosure on the final response. The focused benchmark gate passes 57 cases
with warnings treated as errors; the full local suite passes 1579 cases. Ruff and
configured Bandit also pass. Production prompt catalogs, scoring, and sampling
are unchanged. The supplied earlier GCP arms completed well below their deadlines;
this fix does not establish new model sensitivity or invalidate those observations.
Independent review and all eight PR/post-merge CI jobs remain required.

### Offline paired-cohort evidence gate

The strict report validator binds the current schema, exact prompt manifests and
probe versions, provider/model/context/revision, seeded order, pair cardinality,
check ledgers, counters, and observation checkpoints before recomputing metrics.
It rejects substituted aggregate scores, duplicate/missing arms, boolean counters,
nonfinite values, unknown fields, and inconsistent completed observations. Partial
checkpoint positives can survive an interrupted final category without fabricating
confirmed checks. Reported arm/cohort elapsed time has five seconds of cleanup/
timing tolerance, not a larger execution budget or independent wire measurement.

The offline cohort CLI uses an explicit operator-declared plan with positive and
negative controls plus at least two distinct declared model identities. It keeps
all planned cases, including missing/invalid/partial/control-failing inputs, and
returns nonzero for incomplete evidence. Completed nondisclosure is not a security
pass. Results remain per case; no heterogeneous accuracy score or promotion
decision is produced. State/reset policies are visible assertions, not proof of
independence. Old single-target results do not satisfy a new predeclared cohort.

Private bounded file loaders reject symlink ancestors/leaves, FIFOs, hard links,
foreign owners, unsafe permissions, changing files, duplicate keys, excessive
JSON depth/nodes/strings/integers, and malformed UTF-8. Directory descriptors pin
reads and atomic no-clobber 0600 output. Summary fields are fixed enums, generated
ordinals, and recomputed metrics, not supplied labels, paths, prompts, or hashes.
No target, credential environment, server app, database, or supplied script is
used. The installed-wheel smoke imports both new modules outside the checkout.

Independent reviews accepted the schema/ledger, filesystem, control, privacy,
and documentation contracts. The final combined Linux/Python 3.10 suite passes
1749 cases with warnings as errors and an inherited registry-path sentinel.
This includes 112 new validator and 58 new cohort/CLI cases; the focused combined
benchmark gate passes 227 cases. Ruff, configured Bandit, pip check, build,
Twine, and installed-wheel smoke pass. These counts describe overlapping gates,
not additional independent model observations. Synthetic fixtures exercise actual CLI subprocess
exit codes, missing evidence, failed controls, malformed inputs, no-clobber races,
and ignored inherited registry configuration. These checks validate offline
accounting, not real-model sensitivity, truthful operator attestations, or secret
absence in arbitrary supplied files. A fresh authorized multi-model measurement
with preserved captures is still required before candidate adoption. All eight
PR/post-merge CI jobs remain required before acceptance.

### Shared experimental prompt catalog

The fixed candidate catalog is shared by the paired benchmark and explicit Python
tester/engine constructor selection. Default construction preserves all legacy
payloads and first-five sampling; candidate requests retain the exact measured
payloads and payload-derived probe versions. A separate order-sensitive digest
binds public catalog semantics without using protected values or credentials.
Each tester receives an independent catalog; selecting one suite does not run
both or reset the shared transport budget.

Active candidate checks require a request-ready target with an opaque protected
canary and public context. Whole-inventory validation requires at least one such
target; engine calls for individual unsupported or unmodelled assets retain their
existing skipped/null behavior. Their declared markers still undergo collision
validation, even when there is no testable target in that per-asset call. Pure local validation
checks all declared canaries against public inventory, static field/identity
descriptors, every target's requests and normalized URLs, resolved credentials,
and computed probe versions before candidate HTTP. Unsupported entries cannot
hide a declared canary collision. Configuration failures expose static errors,
not supplied values. Missing or unseeded evidence never becomes a security pass.

The full local Linux/Python 3.10 suite passes 1,986 cases with warnings treated as
errors, including 237 new suite cases. Independent focused acceptance passes 464
combined catalog/benchmark/validator/cohort cases. Frozen catalog and manifest hashes,
unchanged defaults, constructor isolation, mixed-inventory collisions, and actual
local HTTP disclosure/refusal/unseeded/denied/malformed/leak-then-failure cases
pass. Existing finite budgets remain enforced and partial confirmed high risk
survives ordinary failed requests. This does not add recovery for cancellation
inside an unfinished category or an outer scan deadline.

Final mixed-inventory review reproduced an extra per-asset presence check turning
unmodelled entries into failures. The engine now preserves those entries as
skipped without weakening the strict whole-scan prerequisite or any privacy
guard. Actual loopback regression retains three skipped/null entries, one
confirmed target, 35 prompt requests, and zero failed assets. Normal scan coverage
remains partial when assets are skipped.

Review reproduced and closed static report-key, tuple-label, and skipped-asset
marker collisions. A bounded public-descriptor guard includes emitted schema,
pattern, policy, and SARIF identities; maintenance tests audit current output
source constants so new opaque labels cannot silently bypass that guard. Generic
redaction and report schemas are unchanged. The earlier private cohort still
passes the strict offline CLI with an identical recomputed summary; this checks
catalog compatibility, not a fresh target measurement. Ruff, configured Bandit,
distribution build, and Twine metadata checks pass.

Independent review accepted the core changes. The complete PR/post-merge CI
matrix remains required.
Installed-wheel smoke now constructs both default and selected engines outside
the checkout. This is synthetic local contract acceptance, not a new real-model
measurement, CLI/API selection, package publication, or deployment. Operator
workflow integration and a targeted final-revision retest remain separate work.

### Normal-scan experimental prompt integration

The CLI flag and `scan_config.prompt_suite` accept only explicit
`protected-disclosure-v1`; omission preserves existing execution and report shape.
CLI scans require explicit agents and reject discovery-only selection
before execution. Invalid values and `--skip-security` are rejected before
loading target configuration. Server selection requires security-only source reuse and
explicit startup profiles for every request-ready model. Unknown values/types,
misplaced options, external pins, unavailable profiles, and public marker
collisions fail closed. Historical raw-canary source fields cannot substitute for
profile evidence or lose redaction provenance when copied; candidate admission
and workers reject those fields before model requests. Sources remain unchanged.

Queued jobs and templates pin only public catalog content/semantics. Admission,
trusted replay, unchanged-selection updates, and schedule tokens reject missing
or changed pins; returned template JSON hides them. Schedule races pause without
admission. Per-scan candidate engines never mutate the legacy global engine.
Only one 35-request prompt suite runs, with other checks and shared transport
limits unchanged. JSON/SARIF suite labels mean selected, not completed: the check
ledger remains authoritative. No new pass, scoring rule, or in-flight cancellation
recovery is introduced.

The combined local Linux/Python 3.10 gate passes 2,049 tests with warnings as errors
and an inherited registry-path sentinel. This includes the 237 core suite cases,
38 new server cases, 15 new CLI workflow cases, and ten additional actual-profile
dispatcher cases. These overlap the focused gates and are not model observations.
The 125 Node controller tests pass, including full JSON-template selection
preservation. Ruff, configured Bandit, pip check, and whitespace checks pass.

Actual loopback CLI runs use the complete candidate catalog and real engines,
adapters, transport, pipeline, and JSON/SARIF exports. Only pacing is shortened.
Deterministic disclosure retains 70/high; refusal and an unseeded marker remain
null/inconclusive; leak-then-503 retains partial high and a nonzero CLI exit.
Positive/negative exits and execution status are explicitly asserted, not hidden
by report creation. Payloads, seven five-attempt prompt groups, and probe versions
match the benchmark. Synthetic markers and response text are absent from reports,
captured requests, logs, and stdout; output files remain private.

The real file-backed SQLite/API/dispatcher fixture independently exercises normal
profile/template input with full candidate sampling, 70 versus null, source
immutability, matching saved pipelines and public results, SARIF, inventory,
audit, and database-byte secret omission. Concurrency, template/pin drift, and
schedule races also have isolated regressions. Mixed actual-dispatcher inventories
preserve unmodelled/unsupported entries as skipped/null alongside the protected
target without making additional model requests. Installed-wheel smoke checks the
flag and static invalid-selection rejection outside the checkout. These local
fixtures do not establish real-model sensitivity, full browser accessibility,
deployed compatibility, or enterprise readiness. Require independent review,
all PR/post-merge checks, and the targeted normal-workflow lab retest on the final
merged revision before claiming external acceptance. No cloud target was accessed,
service deployed, or package published for this slice.

### Finding presentation grouping

The O3 slice changes only dashboard presentation and synthetic browser fixtures.
Eighteen actual-analyzer/versioned-check occurrences display as seven groups.
Python invariance tests preserve the source document, 18 raw JSON/SARIF results,
seven checks/rules, score 70/high, all original IDs, suppression/comparison keys,
and unverified rather than resolved nondisclosure. Contexts, versions, models,
asset entries, visible/boundary fields, ambiguous counts and historical or
redacted provenance remain separate. Matching confirmed checks are required.

The controller gate passes 125 Node cases. Two independent reviewers accepted
the code and ran the extended real Chromium workflow at 320/390/1440 pixels.
It covers native details, lazy original records, group/occurrence 100-item caps,
preview truncation, final-page keyboard focus, hostile literal text, unchanged
terminal polling, logout and stale selection. No external browser requests,
page errors, or CSP violations were observed. Disposable fixture processes and
private database directories were removed; screenshot/log artifacts are retained.
Inherited operator evidence-registry settings are excluded before fixture import.
This remains targeted workflow acceptance, not comprehensive accessibility or
screen-reader conformance. The integrated tree passes 1568 Python cases with
warnings treated as errors, Ruff, and configured Bandit. A third root Chromium
run passed the same workflow and its temporary process/database cleanup.
Build, Twine, and installed-wheel smoke also pass. All eight PR/post-merge CI
jobs remain required before acceptance.

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

Eight new bounded regressions cover missing/private paths with forbidden-open
guards, fresh imports, cached fixtures, restoration, and direct backup children.
The native macOS diagnostic run located a 20-second fixture timeout at the first
HTTP server constructor. That fixture now binds numeric server names without
reverse DNS; fresh and cached setup run with `getfqdn` and `gethostbyaddr`
forbidden. The 20-second child deadline and bounded traceback diagnostics remain.
A Linux symlink-ancestor regression verifies canonicalization of the owned
temporary root while preserving database leaf guards; native CI remains pending.
Before one additional quoted-identifier regression, the isolation branch passed
1566 full-suite cases with warnings treated as errors and an inherited nonexistent
registry path. Independent review passed 177 relevant cases. A final 55-case
backup/isolation/workflow gate includes the hostile-identifier and symlink regressions and
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
