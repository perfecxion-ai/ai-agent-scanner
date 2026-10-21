# Beta remediation and readiness gate

Status: remediation gate closed for limited single-operator beta testing on
runtime revision `82ee7d5e8d1a0183fe5344b41da90f60b49c5f91`. Reviewed external
retests cover the prior verdict, evidence privacy, mixed-network, portability,
and API projection defects. This is not production or enterprise approval, nor
validation of representative detection sensitivity.

The source lab report, infrastructure identifiers, and raw outputs remain local.
This tracker contains only generalized defect descriptions and acceptance criteria.
The original findings are numbered below so fixes remain traceable without
publishing private lab details.

## Remediation slices

| Findings | Slice | Required evidence |
| --- | --- | --- |
| 1, 2, 3 | Verdict correctness | Consistent 0-100 risk policy; confirmed severity cannot become minimal; absent or unseeded canaries and stochastic nondisclosure cannot prove safety or resolve earlier leaks |
| 7, 8, 9, 10, 19 | Honest execution and private evidence | Anonymous inference distinguished from proven bypass; no raw model-output persistence; confirmed findings survive partial execution; denied session probes evaluated correctly; all-skipped active assessments not presented as clean completion |
| 4, 11, 12, 13, 17, 20 | Network and transport | Mixed non-AI, non-HTTP, unused and genuine AI fixtures; expected negatives separated from real failures; safe diagnostics; CIDR normalization; identity-preserving deduplication; metadata blocked before I/O; OS-hostname and TLS errors verified |
| 5, 6, 14, 15, 18, 21, 22 | Operator workflows | Partial-source inventory safely reusable without erasing source uncertainty; CLI model binding and bounded budgets; canonical and snapshot IDs unambiguous; explicit MCP sampling limits; accurate commands and documentation; no misleading legacy CLI |
| 16 | Portability | Default symlinked temporary ancestors work in normal and optimized acceptance; owned child and database symlink protections remain; native macOS CI |

Each slice required a reproducing regression, negative controls, independent
review, and a scoped PR. Actual acceptance results and their limits are recorded
in [validation](VALIDATION.md); the table alone is not evidence of acceptance.

## Local remediation checkpoint

The implementation now addresses all 22 reported items through scoped fixes or
honest supported limitations. PRs #44-#46 cover portability/private exports,
verdicts, and mixed-network transport. PR #47 covers operator workflows:
source reuse, CLI model/budget controls, identity aliases, and accurate guidance.
MCP controls still sample one page; a missing protected tool now emits an explicit
warning and stays inconclusive, not passed. The reviewed external retests below
provide acceptance beyond these local regressions, within their stated limits.
A related storage follow-up protects new server files and tests actual container
ownership/permissions across restart, without modifying existing mounted data.

## Exact-revision external retest review

An operator-supplied private retest bundle covers merged revision
`150762513ecbf728c4922436bff1448266467150` with real inference services,
the real MCP SDK, controlled vulnerable/secure fixtures, mixed-network negatives,
and native macOS acceptance. Two independent artifact reviews support the core
verdict, transport, source-reuse, privacy-omission, and portability fixes. The
underlying reports, logs, and traces were inspected; the cloud jobs were not
independently rerun here. Private fixture definitions and the database were not
included, so exact-secret sweeps and database checks remain operator attestations.

The report labels all 22 original findings passed, with explicit no-retry and
MCP first-control-page limitations and two source/documentation checks. Review
found an additional blocker: the server's compatibility summary and per-agent
API fields exposed storage placeholder scores of zero even when the authoritative
pipeline reported null and `not_assessed`. PR #49 corrected that adapter. Its
independent review, eight PR/post-merge CI jobs, and the targeted external retest
below close this blocker. The earlier live retest did not automatically cover
the follow-up source change.

The five fixed-configuration vulnerable-bot runs produced one confirmed leak
and four inconclusive results, with no passes or verified resolutions. This
supports honest uncertainty, not reliable detection sensitivity or general
absence-of-vulnerability claims. See [validation](VALIDATION.md) for measurements.

The operator-diagnostics follow-up addresses O1, O2, O4, O5, and O6 with upfront
forbidden-target refusal, static authorization/MCP failure reasons, a correctly
scoped static-analysis suppression, and clearer baseline/control-page wording.
Local combined acceptance is 1408 tests. The suppression is necessary for a
wildcard-detection constant, not a listener; it was not removed or used to weaken
the static gate. O3 finding presentation is addressed separately below. No diagnostic
change expands MCP control sampling, retries, or security passes.

The subsequent server evidence-reference slice supplies supported named
system-prompt canary input for security-only API scans, templates, and schedules.
Private startup configuration and environment values replace the earlier lab's
input-seeding workaround. Local fixtures exercise real HTTP, API, dispatcher,
SQLite, and output projections without editing source reports. Bindings and
public pins are revalidated before execution; canaries are memory-only inputs.
See [configuration and limits](detection-evidence.md#server-system-prompt-canary-profiles)
and [local acceptance](VALIDATION.md#server-evidence-reference-slice).
This does not improve or validate real-model hit rates. No cloud retest, broader
server authorization inputs, raw-score schema migration, or enterprise approval
is implied. Measured sensitivity remains a priority.

The dashboard-only O3 slice groups compatible modern prompt occurrences while
preserving original findings, IDs, scores, check counts, raw JSON/SARIF,
suppression keys, and resolution rules. Synthetic 18-occurrence evidence renders
as seven groups with bounded expandable original records. Historical or ambiguous
provenance is not grouped. Independent Chromium acceptance covers keyboard,
literal text, lazy/capped rendering, and desktop/mobile reflow. This improves
readability, not detection yield or attribution to a shared root cause. See
[presentation details](dashboard-evidence.md#finding-groups-and-original-occurrences).

## Targeted API acceptance

The operator supplied a second private bundle for exact runtime revision
`82ee7d5`. Two independent reviews compared ten scan responses and 31 snapshots
with their saved pipelines and archived inventory captures. All 29 unassessed
snapshots retained null/unknown/not-assessed risk; both confirmed snapshots
retained 70/high, with sampled and partial coverage respectively. Restart
inventory retained all 31 matching snapshots. The check artifact contains 78
passes, zero failures, and 16 informational entries. All 324 response excerpts
are omission sentinels. See [validation](VALIDATION.md#targeted-live-api-acceptance).

The positive cases used deterministic fixtures and controlled canary/context
input seeding into server-produced discovery records while the server was
stopped. Findings and scores were generated by the real server, not seeded.
This validates downstream execution, scoring, storage, and projection; it does
not establish a supported server canary-configuration workflow. Direct report
or database modification is not an operator setup method. Real-model runs
confirmed zero of three attempts and remained inconclusive, not passed.

Final database privacy and file-mode checks remain operator attestations because
the database and exact secrets were correctly excluded. Restart per-scan and
high-filter response bodies were not retained separately; their assertions are
in the logs, while restart inventory was independently inspected. The harness
does not propagate failed assertions to its exit code, so acceptance rests on
the archived checks and independent comparisons, not exit zero alone.

Together with the prior reviewed lab evidence and merged CI, this closes the
reported remediation hold for the documented limited beta. No publication,
deployment, comprehensive accuracy claim, or enterprise sign-off is implied.

## Regression requirements

1. All 22 reported findings have a tested fix or an explicit supported limitation
   that no longer misrepresents a result. Do not close a defect solely by hiding
   its warning or weakening scope, bounds, or execution-completeness checks.
2. Full tests, lint, static security checks, dependency audit, installed-package
   smoke, container restart, browser workflows, queue profiles, and both backup
   modes pass. Include native macOS acceptance, not only a Linux path simulation.
3. Reproduce mixed-network discover-then-test and repeated leak/nondisclosure
   sequences with synthetic local services. Every report must preserve uncertainty,
   findings, sampling bounds, and privacy across JSON, SARIF, API and history.
4. Retest an explicitly authorized real-service lab on the exact merged revision.
   A source fix or synthetic fixture does not itself constitute this retest.
   No cloud start, deployment, paid target, or real schedule is implied by this plan.

These requirements were met for the scoped remediation with the qualifications
above. Runtime changes require relevant revalidation; documentation-only changes
do not require another cloud run.

## Enterprise readiness is a separate decision

Closing these defects does not establish enterprise readiness. Before production
use, agree a supported deployment and threat model, then validate enterprise
identity and authorization, representative provider/attack accuracy, operational
load and soak, deployed backup/upgrade recovery, accessibility, audit integrity,
secret handling, incident response, and dependency/release maintenance.
The current supported server remains one process on POSIX, local file-backed
SQLite, and a local filesystem. PostgreSQL, distributed workers, and overlapping
reloads are unsupported. Publication and remote deployment require separate
authorization. Keep those gaps visible instead of labeling a green unit suite
as production sign-off.
