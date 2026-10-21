# Beta remediation and readiness gate

Status: held. External lab validation found verdict correctness, evidence privacy,
mixed-network workflow, and macOS acceptance defects in the prior beta. Passing
the infrastructure suite did not establish trustworthy risk conclusions.

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

Each slice requires a reproducing regression, negative controls, independent
review, and a scoped PR. This table is a work plan, not a claim that the fixes have
passed. Record actual acceptance results in [validation](VALIDATION.md).

## Local remediation checkpoint

The implementation now addresses all 22 reported items through scoped fixes or
honest supported limitations. PRs #44-#46 cover portability/private exports,
verdicts, and mixed-network transport. PR #47 covers operator workflows:
source reuse, CLI model/budget controls, identity aliases, and accurate guidance.
MCP controls still sample one page; a missing protected tool now emits an explicit
warning and stays inconclusive, not passed. Local regressions are not a closure
of the external lab findings until the exact merged revision is retested there.
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
API fields expose storage placeholder scores of zero even when the authoritative
pipeline reports null and `not_assessed`. This still misrepresents unknown risk
for API consumers. Keep the beta held until that adapter is corrected, independently
reviewed, and validated on the new merged revision. The prior live retest does
not automatically cover later source changes.

The five fixed-configuration vulnerable-bot runs produced one confirmed leak
and four inconclusive results, with no passes or verified resolutions. This
supports honest uncertainty, not reliable detection sensitivity or general
absence-of-vulnerability claims. See [validation](VALIDATION.md) for measurements.

Six reported lower-priority observations remain follow-up work: upfront refusal
for forbidden CLI target classes, clearer missing-credential diagnostics, grouped
repeated leak findings, specific MCP stderr reasons, a stale static-analysis
suppression, and clearer MCP baseline-page wording. They do not replace the API
score blocker or expand the supported MCP control sample.

## Reopening the beta

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
