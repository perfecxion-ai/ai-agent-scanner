# Versioned scan and check contracts

Scan reports retain `schema_version: "1.0"`. New reports also carry
`check_schema_version: "1.0"`, typed asset and finding records, and an explicit
`checks` array on each asset and security result. Existing version 1.0 reports
without check records remain readable. Their missing evidence cannot establish
that a finding was resolved.

Each check has `rule_id`, `probe_id`, `probe_version`, execution `status`,
evidence `outcome`, `requests_attempted`, `responses_evaluated`, and an
optional safe `reason`. The engine accounts for 19 planned groups: seven
prompt injection categories, seven access/exposure checks, and five privacy checks.
Groups omitted from a configured test suite are explicitly skipped.

| Execution status | Meaning |
| --- | --- |
| completed | At least one usable response was evaluated and required interactions succeeded. |
| skipped | The oracle or adapter was unavailable, the group was omitted, or no response was evaluated. |
| failed | A required interaction failed, was refused, or returned an unusable response. |

Evidence outcomes are independent of execution status:

- `passed`: Protected access probes were explicitly denied after successful
  authorized and denied controls. This is sampled evidence for the declared
  boundary, not target safety.
- `confirmed`: A protected marker was disclosed; a failed group can retain
  confirmed evidence from interactions that succeeded.
- `heuristic`: A sampled response matched an observation requiring review.
- `inconclusive`: Responses were evaluated without a valid negative oracle,
  or the group failed before a reliable negative conclusion.
- `not_evaluated`: The group was skipped.

Prompt and tenant nondisclosure never produce a pass. A canary that was not
seeded, or a stochastic target that does not leak in this finite sample, cannot
establish absence of a vulnerability. Nondisclosure remains inconclusive even
after an earlier confirmed leak. These rules cannot automatically resolve a
historical disclosure, including older reports with a recorded sampled pass.
Probe semantics and versions changed to prevent comparison across this boundary.

The supported model adapters require JSON containing nonempty generated text.
HTTP success with an HTML login page, empty model output, or an error envelope
does not establish a passed check. Intentional HTTP 401/403 responses in access
probes count as evaluated denials, rather than failed model calls, only when
their response bodies do not contain the configured protected marker. A
denied control leaking the marker invalidates the negative oracle.

Probe versions contain a SHA-256 digest of the selected public samples,
provider, and model. Actual credentials and protected canaries are excluded.
Changing the selected model, provider, or samples changes the probe version.
Authorization versions also bind the actual public path keys with configured
protected markers, so a passed different path cannot resolve an earlier finding.
Static built-in sample definitions must increment their named version
when their contents or evaluation semantics change.

CLI agent configuration can supply `evidence_context_id`, an operator-assigned
nonsecret policy/seed revision, such as `lab-policy-v3`. The value must be
nonempty, at most 128 characters, and contain no square brackets. Rotate the
context whenever protected canaries, protected path sets, policy baselines, or
oracle assumptions change. This is an explicit operator provenance assertion;
the scanner cannot independently verify that the context correctly describes
the target's protected seed or policy. Check records and findings retain this
public value. Missing, different, or redacted contexts cannot prove resolution.
Passed sampled evidence is still recorded without a context, but it remains
insufficient for verified report comparison.

JSON and SARIF preserve check records and summary counts. A failed required check
makes the asset partial, but confirmed findings with matching versioned check
evidence remain eligible for risk assessment. Such assessments carry partial
coverage and are visible in the dashboard with that warning. Optional checks
without prerequisites remain skipped. An active assessment where every check
was skipped is partial, not a clean completed scan. Completion is execution
accounting, not a claim that every rule passed or that the asset is safe.

Modern results require a confirmed finding matched to its confirmed check or a
supported prompt-disclosure receipt, or a completed protected-access sampled pass,
before risk assessment. An execution
containing only heuristic/inconclusive responses and skipped oracles has unknown
risk and a null score; it must not infer minimal risk from missing evidence.
`risk_assessment_status` is `not_assessed` or `not_run` when none qualifies,
and `partial` when an eligible asset has incomplete execution. Summary fields
`agents_risk_assessed` and `agents_risk_not_assessed` expose this distinction.
New executions, including older engine adapters, require the known check
schema and validated conclusive records before risk assessment. Existing
version 1.0 files remain readable with their persisted scores; reading them
does not trigger a retrospective assessment or change their recorded values.
Missing legacy check evidence cannot prove finding resolution.

Current protected-access verdicts additionally require recognized positive-control
probe definitions bound to the original provider/model context. Only the four
supported protected-access groups can establish sampled zero or verified absence.
Unknown/custom definitions, missing context, incomplete sample counts, and older
control semantics cannot establish these claims. An explicitly recorded absent
model is distinct from missing context. Current confirmations require matching
control provenance, response status, and covered resource in addition to the
matching check. Failed checks may retain genuine findings despite cleanup errors;
their recorded interaction counters are not guaranteed wire-request totals.
New findings carry integer `protected_control_version: 2` so the fixed control
description remains verifiable when a known candidate credential redacts part of
that description. The reference requires a recognized probe and compatible literal
redaction, not arbitrary text. Existing exact control descriptions remain valid
without this additive field; altered descriptions without it stay unverified.
New authorization findings include a nonsecret `protected_path_index` into the
frozen eight-path sample. The recognized probe version binds the catalog and
selected subset. This reference preserves resource identity when privacy filtering
redacts part of a fixed path; conflicting paths or invalid indices are rejected.
Older findings without the reference still require an exact, unredacted covered
path. The reference neither records a secret nor changes which requests execute.

Security scans reject configured protected values that collide with either new
field name before their first checkpoint or security probe. The check includes
source, validator-added, resolved, and predictable probe secrets across assets;
later-discovered collisions also stop report projection. The error is static and
does not echo the protected value. Discovery-only runs do not emit these fields.
This guard covers these two additive fields, not every possible public-schema
collision. Redaction never exempts a secret to preserve evidence eligibility.

Archived protected-access confirmations with unsupported provenance make that
asset's current score unknown, even beside supported evidence: the saved number
may include unsupported contributions. Other assets remain independently eligible.
Unsupported old passes alone do not invalidate independently supported evidence.
Original report bodies, scores, and findings remain unchanged. The dashboard uses
the API's canonical risk fields joined by unique asset identity, not the archived
report's numeric values or a separate browser evidence evaluator. Missing or
ambiguous mappings display Not assessed; original evidence stays downloadable.
New reports also withhold numeric assessments when privacy redaction removes
context needed to validate their evidence or invalidates public risk metadata.
Other eligible assets still contribute to the recomputed summary. Redaction is
not weakened to retain a score. Modern direct scorer inputs without eligible evidence are rejected;
they do not silently become numeric zero.

The `severity-floor-v2` policy uses a single 0-100 scale. Confirmed severity floors
are critical 90, high 70, medium 40, low 15, and informational 1. The base is the
highest severity, not a sum of repeated samples. Documented exposure/business
context may raise the score, capped at 100, but cannot dilute that floor. This
policy is not CVSS, a probability, or a safety/compliance guarantee. The agent's
`risk_scoring_policy` identifies the assessed policy. Old persisted scores are not
silently recalculated and do not appear as current dashboard risk verdicts.
Anonymous inference is a reviewable exposure
observation unless separate protected-resource evidence proves a bypass; it does
not create a confirmed vulnerability or a zero-risk verdict.

Generated response bodies and excerpts are omitted from new prompt, privacy, and
access evidence. Reports retain rule/probe identity, status, sample counts and
safe detection metadata rather than arbitrary target text or customer PII.
Existing saved reports and exported copies are not retroactively sanitized.

## Incremental report envelope

Normal CLI/server security executions add a `checkpoint` object with
`version: "2.0"`, a positive `sequence`, and
`coverage: "confirmed_observations_and_finalized_checks"`. Older finalized-only
and discovery-only checkpoints retain version `1.0` and
`coverage: "finalized_checks_only"`. Intermediate reports
are partial; the final report keeps the last acknowledged sequence and its actual
execution status. JSON and SARIF retain the envelope. It identifies persistence
coverage, not a passed security control or an accuracy measurement.

A finalized check and its provenance-stamped findings are retained together.
Actual records are immutable, while `1:unexecuted` placeholders may be replaced
by later evidence. Unstarted or unfinished assets stay incomplete. A completed
sampled pass cannot establish zero risk for an asset still being tested.
Confirmed evidence remains eligible for the shared scorer with partial coverage.
If newly changed evidence has not been scored successfully, its score remains
null even though the finding is retained. Unchanged valid assessments survive
later quiet checks.

Initial inventory alone is a valid checkpoint, not proof that any security check
ran. Failed validation or persistence stops execution without weakening prior
evidence. Missing or duplicate source IDs, including collisions after redaction,
cannot be used to join security results to inventory. Historical reports are not
rewritten to introduce this envelope. See [storage and recovery limits](jobs.md#finalized-check-checkpoints).

### Prompt observation receipts

New engine security reports advertise `check_evidence_schema_version: "1.0"`.
Each asset and its matching security result carry an independent `check_evidence`
array and, once assigned, an immutable `check_evidence_run_id`. Pending empty
inventory may omit that run ID. A receipt does not mark a check completed, failed,
or passed. `summary.checks_unfinished` counts distinct receipt-backed checks with
no terminal check record; the count can remain nonzero after recovery.

An actual successful model response containing the configured protected system
canary can produce a prompt-disclosure receipt. It binds a finding UUID to the
asset, execution UUID, rule/probe version, public evidence context, zero-based
sample index, per-check observation sequence, and actual reserved-request and
evaluated-response counters as of that observation. The source is
`protected_system_canary_match`, version `2.0`. These counters exclude report
callbacks and cleanup failures; reserved attempts are not guaranteed delivered
wire requests. A private task-bound transport token prevents a
generic finding dictionary or an unbound response from supplying this provenance;
tokens, raw responses, and protected canaries are never exported.
The same token binds a private immutable capture of the actual outbound method,
URL, complete headers, and serialized body bytes. Confirmation excludes the marker
from case-normalized request values, decoded URL forms, and header/request-line
renderings; response matching remains exact and case-sensitive. Known adapter
collisions are refused before HTTP. Missing, incomplete, oversized, compressed,
or chunked request provenance cannot establish a confirmation. Capture is bounded
to 128 KiB of body bytes, 64 KiB of header text, 256 headers, and 16,384 URL
characters. None of this private request material is exported.
Draft source version `1.0` remains structurally readable but cannot establish
current receipt-backed risk. These guards do not exclude arbitrary transformations.
Receipts attest scanner observations, not independently verified target-side
canary seeding or cryptographic report authenticity.

Only the frozen first-five baseline and opt-in protected-disclosure catalogs are
supported. Their prompt bytes, probe versions, and request budgets are unchanged.
New engine prompt confirmations require supported receipts even after their check
finishes. Unsupported custom findings remain visible but cannot fall back to
legacy numeric scoring. Historical reports and explicit legacy-only standalone
adapters keep their earlier finalized-check contract; mixed adapter modes are
rejected. Pre-receipt finalized prompt scores retain their prior numeric eligibility,
an open historical-compatibility limitation, not reverified request-exclusion proof.
Their findings remain unresolved after nondisclosure. Standalone benchmarks use
the guarded analyzer but do not acquire production receipts; archived observations
remain tied to their recorded producer revision. This is not a general plugin
evidence protocol.

The producer publishes before response/session cleanup or the next prompt await.
Receipts and findings are immutable, append-only, and saved before asynchronous
scoring. A receipt-backed finding may therefore have a null score until scoring
succeeds; an acknowledged high finding retains its score and partial coverage
through later interruption. No skipped placeholder is invented for its unfinished
check. Final check counters must reconcile with the retained receipts.

New public descriptors have scan-wide secret-collision guards. Privacy redaction
never exempts protected values; redacted or unsupported provenance cannot establish
current numeric risk. Other independently eligible assets remain assessed. JSON
retains the ledger on each asset; SARIF stores per-asset ledgers in run properties
and links each receipt's `finding_id` to a result's `vulnerability_id`.
Tenant/access observations inside unfinished checks and CLI process-crash files
are not covered by this prompt-only increment.

Report comparison resolves an absent finding only when the same unambiguous,
unredacted endpoint has explicit completed, passed evidence for every earlier
occurrence's exact rule, probe ID, and probe version. Changed versions,
changed models or providers, unknown/changed evidence contexts, inconclusive
responses, failed or skipped checks, and legacy versionless
findings remain `resolution_unverified`.
Both the previous confirmation and the new pass must satisfy current supported
control semantics. Two matching obsolete versions cannot resolve each other.

Cloud assets preserve bounded `metadata.resource_id` and a cloud
identifier (`aws`, `azure`, or `gcp`). Inventory identity uses cloud, provider,
and resource ID before considering an HTTP endpoint, so identical display names
and shared regional endpoints across accounts remain distinct. Repeated
observations of the same cloud resource merge during discovery. Observations
without valid cloud resource metadata continue to use endpoint identity.
Repeated resource identities in imported reports are marked ambiguous.
Cloud resource identity still cannot establish verified finding resolution,
even when the resource has an HTTP endpoint.
