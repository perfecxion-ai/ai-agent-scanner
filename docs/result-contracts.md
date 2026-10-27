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
their bounded bodies and headers satisfy the current marker-absence guard. A
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

Modern results require a supported confirmed finding matched to its finalized
check or prompt, tenant or protected-access observation receipt, or a completed
protected-access sampled pass, before risk assessment. An execution
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
Unknown/custom definitions, missing binding metadata, incomplete sample counts,
and older control semantics cannot establish these claims. Explicit model/context
None is distinct from missing binding fields and remains valid for supported
scoring; verified resolution still needs a nonempty stable public context.
Frozen finalized-v3 confirmations require matching control provenance, response
status, resource and confirmed check. Their cleanup-inflated legacy counters are
not wire-request totals. Modern confirmations instead require the receipt below,
with actual reserved/evaluated counts. Both can retain genuine findings despite
later failures, without inventing successful coverage.
New findings require integer `protected_control_version: 3` so the fixed control
description remains verifiable when a known candidate credential redacts part of
that description. The reference requires a recognized probe and compatible literal
redaction, not arbitrary text. Missing, obsolete, Boolean and floating-point tags
cannot establish current confirmation. Old v2 claims remain structurally readable
with their original archived values; current risk and resolution require v3
semantics. Unsupported old positives leave their asset's current risk unknown;
old passes alone do not erase independent supported prompt/tenant evidence.
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

Current tenant confirmations additionally require `tenant_control_version: 1`,
the recognized `configured-tenant-controls-v1` probe definition, and successful
owner, tested-principal, and invalid-credential controls. The public
`tenant_target` binds the canonical endpoint, provider, model, and public context
to the original asset fields. Consistent check/finding labels alone cannot supply
that expected binding. A confirmation identifies `subject_control` or an `attack`
with its zero-based index into the frozen five-prompt sample. The finalized check
must account for those controls and observations within its eight-request limit.
Failed checks can retain a supported earlier confirmation with partial coverage.

Tenant controls attest observations under configured principals. The operator
asserts the identity and authorization relationship; the fields are not signed
proof of distinct tenants. Private request snapshots exclude bounded known
marker representations, and earlier transmitted contamination prevents later
confirmation. Arbitrary transformed echoes are outside this proof. The
[configuration contract](detection-evidence.md#controlled-tenant-assessment)
describes prerequisites and conservative control failures.

Unsupported historical tenant positives in either checks or findings make that
asset's current numeric assessment unknown. Filtering out an unsupported tenant
claim cannot expose a zero from a companion access pass. Independently supported
findings remain selectable, and other assets keep their eligible scores. Original
archives, findings, and stored numeric columns remain untouched. Quiet tenant
samples cannot resolve a prior leak. New mixed-ledger reports require the
[tenant observation receipts](#tenant-observation-receipts) below, including after
the check finishes. Supported older finalized tenant evidence remains readable
under its original contract; changing its header cannot manufacture receipts.

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

## Scalar cache storage

SQLite schemas 4 through 6 store unknown scan and snapshot scores as SQL NULL, with no zero
default. Supported assessed zero remains 0.0. New checkpoint and terminal writers
derive these scalar caches from the same canonical report projection used by API
reads. Recognized layouts predating schema 4 migrate the caches transactionally while
preserving archived report bytes, findings, IDs and other non-cache fields.
Unsupported historical positives remain current unknowns; reading or upgrading
the database does not rewrite their archived report scores or resolve findings.
Cache interpretation also applies byte, UTF-8, and depth limits. Rejected
material leaves unknown scalar values while API reads continue to project the
saved report. Scalar caches alone cannot establish a finding or exhaustive filter.
See [schema and rollback boundaries](jobs.md#schema-upgrades).
Schema 6 explicitly reconciles older access-policy caches. It changes only
necessary scalar risk/level values and the version stamp; existing observation
triggers naturally invalidate affected owners' cursor generations. Reports,
metadata, IDs and unrelated rows remain exact. Restarting recognized schema 6
does not run another cache reconciliation or repair arbitrary direct writes.

## Inventory observations

The global inventory endpoint lists saved observations. Snapshot IDs and
scan-local asset aliases retain their meanings; repeated observations are not
collapsed into a current asset verdict. Canonical saved-report evidence supplies
risk, including supported zero and unknown historical claims. Scalar caches can
be stale and never serve as a risk prefilter.

Cursor pages bind organization, filters, ordering, policy, and transactionally
invalidated source generations. An empty page can have more candidates. A final
`search_complete` applies after its boundary; retain every preceding page before
claiming a complete result set. Uninterpretable sources fail the operation with
503 rather than disappearing from a risk search. See the
[inventory contract](inventory.md) and [operator gate](inventory-retest.md).

## Incremental report envelope

Normal CLI/server security executions add a `checkpoint` object with
`version: "4.0"`, a positive `sequence`, and
`coverage: "confirmed_observations_and_finalized_checks"`. Older finalized-only
and discovery-only checkpoints retain version `1.0` and
`coverage: "finalized_checks_only"`. Checkpoint `2.0` continues to mean the older
prompt-only ledger `1.0`; checkpoint `3.0` requires mixed ledger `2.0`; checkpoint
`4.0` requires mixed ledger `3.0`. Writers
select the supported ledger before their first checkpoint and cannot switch it
within that execution. Intermediate reports
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
rewritten to introduce this envelope. See [storage and recovery limits](jobs.md#finalized-check-checkpoints)
and the opt-in [CLI checkpoint-file envelope](cli-checkpoints.md#storage-contract).

### Prompt observation receipts

New engine security reports advertise `check_evidence_schema_version: "3.0"`.
Older prompt-only and prompt/tenant reports keep ledger `1.0` and `2.0` without
rewriting their archives. Their source rules and 35/41 receipt bounds stay frozen.
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
Draft prompt source version `1.0` in legacy ledger `1.0` remains structurally
readable but cannot establish current receipt-backed risk. These guards do not
exclude arbitrary transformations.
Receipts attest scanner observations, not independently verified target-side
canary seeding or cryptographic report authenticity.

Only the frozen first-five baseline and opt-in protected-disclosure catalogs are
supported. Their prompt bytes, probe versions, and request budgets are unchanged.
Current versioned prompt assessments require supported source-2.0 receipts even
after their check finishes, including when reading pre-receipt reports. Matching
historical check/finding versions cannot substitute for missing request evidence.
An unsupported positive prompt finding or check makes that asset's current numeric
assessment unknown, even beside a valid protected-access pass or confirmation.
Filtering an old positive must not turn it into zero, and a stored score may include
unsupported contributions. Supported companion findings remain selectable in legacy
mixed assets; malformed current receipt envelopes remain fail-closed. Independently
eligible assets keep their scores. An archived aggregate inconsistent with the
remaining supported scores stays unknown rather than being recalculated on read.

Original report bodies, scores, finding IDs, JSON/SARIF exports, and unresolved
lifecycle records remain unchanged. No historical receipt is synthesized. The
dashboard uses canonical API projections, not archived numeric values. Standalone
benchmarks still collect guarded analyzer observations without production receipts;
their archived observations remain tied to the recorded producer revision. The
explicit unversioned low-level scorer compatibility API is unchanged and does not
establish current canonical risk. Mixed adapter evidence modes remain rejected.
This is not a general plugin evidence protocol.

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
Protected-access observations use the separate contract below. CLI process-crash
files remain unimplemented.

### Tenant observation receipts

Mixed ledger `2.0` supports at most 35 prompt receipts and six tenant receipts
per asset. Current ledger `3.0` preserves these source meanings and additionally
supports protected-access receipts. Every receipt is validated before source-specific filtering. Unknown
sources, malformed counters, duplicate IDs and missing finding links invalidate
the asset's current assessment rather than exposing a companion zero score.

Tenant source `controlled_tenant_response`, version `1.0`, binds a finding to the
actual request role, fixed probe, target, run and asynchronous task. The private
verifier checks the complete transmitted request, the expected credential
location and generated text while the response token is live. It excludes both
protected markers and credentials belonging to other roles from request material.
Raw text, keys, markers, principal labels and private witnesses are omitted.

A subject-control leak at request 2 is held privately until the genuine denied
control at request 3 succeeds. Its public receipt then has `request_ordinal: 2`
and attempted/evaluated counters of 3. Attack receipts use ordinals 4 through 8
and their zero-based `tenant_attack_index`. All receipts carry
`control_proof: {"request_ordinals": [1, 2, 3], "status_codes": [200, 200, 403]}`
with the actual successful 2xx and denied 401/403 statuses. These are observed
control facts, not signed proof of the operator's tenant-authorization claims.

Findings publish before response cleanup, pacing or a later request. A stalled
or interrupted unfinished check can retain confirmed 90/critical evidence with
partial coverage after successful scoring. No completed check or pass is invented.
Later cleanup or request failures cannot erase an acknowledged receipt prefix.
Persistence failure and cancellation stop further probing. Private tenant inputs
remain supported only through the explicit CLI/Python configuration workflow;
the server API still rejects them.

### Protected-access observation receipts

Ledger `3.0` adds source `controlled_access_response`, version `1.0`, for the
four existing protected GET families. Its combined per-asset limit is 77:
35 prompt, six tenant and at most 36 access receipts. Access limits are eighteen
authentication-bypass, five weak-credential, five weak-key and eight declared
admin-path occurrences. These are bounds on observed occurrences, not additional
requests or detection-effectiveness measurements.

A private execution plan derives the selected resource and headers from pinned
controls and the frozen samples. An issued-credential response must disclose the
protected marker, and a separate fresh invalid-credential response must deny it
without disclosure. Every control and probe uses a live task-bound response,
complete actual request capture and exactly-once evaluated body. Missing, stale,
reused, wrong-task or mismatched capabilities cannot mint evidence.

Each receipt links one finding UUID to its run, asset, check/probe/context,
per-check sequence, actual request ordinal and attempted/evaluated counts. It
carries `control_proof` with the two actual control ordinals and statuses. Each
admin path has fresh controls; earlier path failures can change later ordinals.
Probe selection uses numeric `sample_index`, `header_index` for weak keys, or
`protected_path_index` for admin paths. Session-entry failures reserve no request;
cleanup does not invent attempts or evaluated responses.

The public `access_target` binds the original base endpoint, provider, model and
context. The numeric path index identifies a declared catalog resource, whose
actual joined URL is independently verified privately. This keeps resource
binding verifiable when a default credential such as `admin` is redacted from
displayed paths. No secret is exempted from redaction. Raw bodies, transmitted
credentials, protected markers, private plans and response tokens are omitted.

Findings publish before response/session cleanup, pacing or the next request.
A later failure cannot erase the acknowledged receipt/finding prefix. The check
remains unfinished until a genuine terminal record exists, and confirmed risk
can retain partial coverage after scoring. A sink failure or cancellation stops
further probes. CLI timeout/cancellation exports the retained report with a
nonzero exit; server recovery preserves committed evidence without replay.

Modern probe hashes add `protected-access-response-observations-v1` around the
unchanged v3 control definition. Their confirmations require valid receipts,
including after a check finishes or if an envelope is stripped. Their sampled
passes require ledger 3 and the complete successful sample. Frozen finalized
v3 hashes remain supported under their existing controls and counters, and
obsolete v2 claims remain unsupported. No archive, SQL schema or historical
cache reclassification is needed for this additive contract; schema 6 remains.

Malformed or unsupported public evidence can remain readable with unknown risk.
It cannot invalidate an acknowledged eligible prefix or expose a companion zero.
The complete ledger and target bindings are validated before writes or scoring.
Receipts attest the scanner's observations, not independent target seeding or
cryptographic report authenticity. Arbitrary custom sample catalogs, server
private tenant inputs and CLI process-crash files remain separate work.

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
