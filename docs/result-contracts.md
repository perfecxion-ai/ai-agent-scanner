# Versioned scan and check contracts

Scan reports retain `schema_version: "1.0"`. New reports also carry
`check_schema_version: "1.0"`, typed asset and finding records, and an explicit
`checks` array on each asset and security result. Existing version 1.0 reports
without check records remain readable. Their missing evidence cannot establish
that a finding was resolved.

Each check has `rule_id`, `probe_id`, `probe_version`, execution `status`,
evidence `outcome`, `requests_attempted`, `responses_evaluated`, and an
optional safe `reason`. The engine accounts for 18 planned groups: seven
prompt injection categories, six access checks, and five privacy checks.
Groups omitted from a configured test suite are explicitly skipped.

| Execution status | Meaning |
| --- | --- |
| completed | At least one usable response was evaluated and required interactions succeeded. |
| skipped | The oracle or adapter was unavailable, the group was omitted, or no response was evaluated. |
| failed | A required interaction failed, was refused, or returned an unusable response. |

Evidence outcomes are independent of execution status:

- `passed`: A configured protected canary was absent from usable generated
  output and absent from all attack requests, or protected access probes were
  explicitly denied after a denied control.
- `confirmed`: A protected marker was disclosed; a failed group can retain
  confirmed evidence from interactions that succeeded.
- `heuristic`: A sampled response matched an observation requiring review.
- `inconclusive`: Responses were evaluated without a valid negative oracle,
  or the group failed before a reliable negative conclusion.
- `not_evaluated`: The group was skipped.

The supported model adapters require JSON containing nonempty generated text.
HTTP success with an HTML login page, empty model output, or an error envelope
does not establish a passed check. Intentional HTTP 401/403 responses in access
probes count as evaluated denials, rather than failed model calls, only when
their response bodies do not contain the configured protected marker. A
denied control leaking the marker invalidates the negative oracle.

Probe versions contain a SHA-256 digest of the selected public samples,
provider, and model. Actual credentials and protected canaries are excluded.
Changing the selected model, provider, or samples changes the probe version.
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

JSON and SARIF preserve the check records and summary counts. A failed required
check makes the asset partial, retains any confirmed findings, and prevents a
completed risk assessment for that asset. Optional checks without prerequisites
remain skipped. Completion describes executed coverage; it is not a claim that
every rule passed or that the asset has no vulnerabilities.

Report comparison resolves an absent finding only when the same unambiguous,
unredacted endpoint has explicit completed, passed evidence for every earlier
occurrence's exact rule, probe ID, and probe version. Changed versions,
changed models or providers, unknown/changed evidence contexts, inconclusive
responses, failed or skipped checks, and legacy versionless
findings remain `resolution_unverified`.

Endpointless cloud assets preserve bounded `metadata.resource_id` and a cloud
identifier (`aws`, `azure`, or `gcp`). Inventory identity uses cloud, provider,
and resource ID so identical display names across accounts remain distinct.
Repeated resource identities are marked ambiguous. Endpointless identity still
cannot establish verified finding resolution.
