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

- `passed`: Protected access probes were explicitly denied after a valid denied
  control. This is sampled evidence for the declared boundary, not target safety.
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

Modern results require a confirmed finding matched to its confirmed check, or a
completed protected-access sampled pass, before risk assessment. An execution
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

Report comparison resolves an absent finding only when the same unambiguous,
unredacted endpoint has explicit completed, passed evidence for every earlier
occurrence's exact rule, probe ID, and probe version. Changed versions,
changed models or providers, unknown/changed evidence contexts, inconclusive
responses, failed or skipped checks, and legacy versionless
findings remain `resolution_unverified`.

Cloud assets preserve bounded `metadata.resource_id` and a cloud
identifier (`aws`, `azure`, or `gcp`). Inventory identity uses cloud, provider,
and resource ID before considering an HTTP endpoint, so identical display names
and shared regional endpoints across accounts remain distinct. Repeated
observations of the same cloud resource merge during discovery. Observations
without valid cloud resource metadata continue to use endpoint identity.
Repeated resource identities in imported reports are marked ambiguous.
Cloud resource identity still cannot establish verified finding resolution,
even when the resource has an HTTP endpoint.
