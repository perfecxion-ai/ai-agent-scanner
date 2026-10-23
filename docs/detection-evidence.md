# Detection evidence

Security engine results separate `vulnerabilities` from `observations`.
Heuristic and inconclusive observations do not contribute to the engine risk score.
A model's refusal, claimed persona, generated sample record, or mention of an
administrative feature is not proof of a security boundary violation.

The following optional fields belong to the agent configuration passed to the
Python security engine or explicit `agents` entries in `scan --config FILE`.
Discovery does not populate them automatically. The CLI config accepts these
fields, `model`, `api_key_env`, and a public `evidence_context_id`; do not place
credentials in the JSON. Model overrides for discovered assets select only a
model and never enable evidence or authentication controls.

The server supports named, operator-configured system-prompt canary profiles for
`security_only` scans, described below. Raw canaries, environment variable names,
file paths, and the other evidence controls in this table are not API inputs.
Discovery and model selection alone cannot enable protected evidence. Editing
stored discovery reports or the database is not a supported operator workflow.

| Field | Required setup |
| --- | --- |
| `system_prompt_canary` | Seed a unique secret of at least 16 characters in a protected system instruction, outside user input. |
| `cross_tenant_canary` | Seed a unique secret of at least 16 characters in another test tenant, outside the tested principal's authorized data. |
| `authentication_required` | Set to `true` only when the endpoint must reject anonymous access. |
| `protected_response_marker` | Unique opaque string of 16 to 128 characters present only in protected response data. Requires the issued-credential and denied controls below. |
| `protected_path_markers` | Map tested admin paths to unique opaque strings of 16 to 128 characters present only in private admin data. Each path requires its own issued-credential and denied controls. |

Canary provenance is an operator assertion. The scanner verifies returned text,
not how the secret was originally seeded. Canaries included in attack prompts
cannot confirm disclosure. Configure synthetic test secrets, not real credentials.
Nondisclosure is inconclusive, even with a configured canary: an unseeded secret
or a finite stochastic sample cannot prove safety or resolve an earlier leak.
Generated response text is omitted from new evidence rather than persisted as
an excerpt; older saved reports are not retroactively sanitized.
Confirmed access checks do not follow redirects. Provider adapters preserve
deployment prefixes and inspect generated content separately from JSON metadata.

## Protected access controls

Authentication bypass, weak credential, weak API key, and protected admin-path
checks require an explicit `api_key_env` reference to an operator-issued test
credential. Keep the value in the private process environment, not the agent
configuration. Automatic provider credentials do not enable these controls.
The credential must authorize a GET of the exact configured endpoint or admin
path and return its protected marker in an HTTP 2xx response. This is a resource
check, not a model inference request; a POST-only endpoint cannot satisfy it.

The baseline uses `x-api-key` for Anthropic, `x-goog-api-key` for Google/Gemini,
and `Authorization: Bearer` otherwise. A fresh invalid credential in the same
header must receive HTTP 401 or 403 without the marker. Only then does the check
send its anonymous, malformed, or weak-credential probes. Baseline and control
requests use separate sessions, never follow redirects, and consume the same
scan request and deadline budget as probes. Controls are not cached across check
groups or paths. Unsupported credential schemes require a future adapter.

Missing explicit credentials skip the check. An unavailable resource, stale
credential, missing marker, failed control, or interrupted request cannot itself
establish a pass or a confirmed bypass. Completed sampled denials can pass only after both
controls succeed; successful responses without the marker remain inconclusive.
An endpoint that denies every request is not evidence of effective protection.
Earlier confirmations survive an ordinary later request/control failure.
Cancellation marks an unfinished check failed, even after every response was
evaluated. [Finalized-check checkpoints](jobs.md#finalized-check-checkpoints)
retain earlier checks through later termination. Findings still inside the
unfinished check are not covered by that persistence contract.

V2 access markers must use exactly `[A-Za-z0-9_.~-]{16,128}`. No trimming,
decoding, case conversion, or other normalization is used for response matching.
Previously accepted arbitrary strings outside this grammar are now refused
before requests. The restriction excludes header and JSON fragments that could
be mistaken for private data after request reflection.

Protected-access URLs must be HTTP(S) without user information, query parameters,
fragments, or percent escapes. Markers must not overlap public target fields,
credential values, normalized URLs, or probe material, including fixed client
headers and rendered request lines. Collision checks also reject case variants
of that public/request material. Reflected request content is not protected
evidence. Baseline text and issued credentials are never finding
fields. Configure opaque synthetic markers separately from credentials.

The `authorized-and-denied-resource-controls-v2` definition changes probe
versions for all four check groups. Historical checks and findings remain
readable but cannot establish verified resolution across this version boundary.
Keep the public `evidence_context_id` stable only while the tested resource,
authorization policy, and protected fixture remain the same.

## Server system-prompt canary profiles

This is an opt-in single-operator API workflow, not enterprise secret management
or a new dashboard control. First seed a unique synthetic canary in the target's
protected system instruction, outside user input. The scanner does not install
it or independently verify that setup. Never reuse an API key as a canary.

Before server startup, supply the same marker through the server process
environment, using a name such as `SCAN_EVIDENCE_LAB_BOT`. Values must be 16 to
128 ASCII characters from `[A-Za-z0-9_.~-]`; a randomly generated hex value is
suitable. Use the service's private secret-delivery mechanism, not shell history,
Git, scan JSON, labels, endpoints, or command-line arguments. Keep the registry
and its parent directory outside the checkout and restrict directory access.

Set `SCAN_EVIDENCE_PROFILES_FILE` to an absolute JSON registry path owned by the
server's effective user. The file must be a regular, non-symlink file with mode
`0400` or `0600`, at most 64 KiB. For example, this registry contains references
only, not a marker value:

```json
{
  "schema_version": "1.0",
  "profiles": {
    "lab-bot-v1": {
      "organization_id": "default",
      "endpoint": "https://lab.example.test/v1/models",
      "provider": "openai-compatible",
      "model": "fixture-model",
      "evidence_context_id": "lab-system-policy-v1",
      "system_prompt_canary_env": "SCAN_EVIDENCE_LAB_BOT"
    }
  }
}
```

The organization must match the authenticated operator's configured
`OPERATOR_ORGANIZATION_ID`. Profile and context IDs are public, non-secret labels.
The endpoint must match the discovered asset after authority normalization,
including its exact path, provider, and selected model. V1 permits only ASCII
HTTP(S) endpoints without user information, queries, fragments, percent escapes,
dot segments, or path characters rewritten by the HTTP client. Existing server
scope policy still applies. There are at most 100 profiles; identifiers use
`[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`. Environment references must use
`SCAN_EVIDENCE_[A-Z][A-Z0-9_]{0,111}` and cannot reference the registry setting.
Unknown fields, unsafe files, invalid profile definitions, and missing or invalid markers
fail startup with a static error when a registry is configured. Without the
setting, existing scans continue without configured canary evidence.

After a completed or finalized partial discovery scan, submit this definition
to authenticated `POST /api/scans`:

```json
{
  "scan_name": "Controlled system-prompt check",
  "scan_type": "security_only",
  "target_scope": {},
  "scan_config": {
    "source_scan_id": "SOURCE_SCAN_ID",
    "model_overrides": {"ASSET_ID": "fixture-model"},
    "evidence_profiles": {"ASSET_ID": "lab-bot-v1"}
  }
}
```

Use actual IDs from the owned source inventory. Stable and snapshot asset IDs
are accepted only when unambiguous. Up to 100 asset/profile selections are
allowed. Unknown, foreign-organization, endpoint/provider/model-mismatched, or
unavailable profiles fail closed. A selected marker must not overlap public scan
definitions, source inventory, or outgoing request data. Do not put secrets in
unselected assets or public labels either; this is not a general-purpose secret
scrubber for arbitrary operator input.

Admission stores only profile references and public binding revision pins.
Workers revalidate the source, current scope, binding pins, and marker
availability before attaching the marker to fresh in-memory asset copies. Source
reports are not edited. The server never deliberately inserts the configured
marker into prompts or request parameters; it is not persisted in job fields or
audit values. Generated response text remains omitted from evidence.
Templates may contain the same references. Their internal pins are not editable
API fields, and template/schedule runs revalidate current bindings before work.

The registry is read once at startup. Changes, including file removal, take
effect only after a controlled restart under the existing one-process deployment
contract; overlapping reloads remain unsupported. Restart pauses enabled
schedules for review. Treat a changed canary or protected policy as a new public
profile/context version, update the target and private environment together, and
review replacement templates/schedules. Pins cover public configuration, not
secret-derived hashes: silently changing only a secret value cannot be detected
as a policy revision. This workflow does not migrate stored unknown-score
placeholders; saved pipeline results and canonical API projections remain the
authoritative risk verdicts.

Successful configuration does not prove a target leaks. Exact protected-marker
disclosure can confirm the finding; nondisclosure stays inconclusive. This
feature closes an input gap, not the separately unvalidated real-model detection
sensitivity. Server configuration for cross-tenant, authentication, and protected
path controls remains unsupported; those controls still require explicit CLI or
Python engine configuration.

## Experimental prompt suite

Normal scans can explicitly select `protected-disclosure-v1`, the same fixed
extraction-focused catalog used by the paired benchmark. It remains experimental:
reviewed lab results describe particular declared targets, not general detection
sensitivity or enterprise readiness. No default has changed. Omit the option to
keep the existing prompt sample; `default`, `baseline`, arbitrary strings, and
explicit API null are not accepted selection values.

A normal scan runs one chosen suite, not a paired benchmark: seven prompt groups,
five requests per group, at most 35 prompt HTTP attempts per testable asset.
Access-control and privacy checks still run separately within the unchanged shared
scan budget and deadline. Existing response limits, one-second prompt pacing,
100-token model-output cap, and no-retry behavior remain. This option does not
increase the normal scan deadline to the benchmark's larger time allowance.

For the CLI, keep the explicit `agents` configuration in a private file outside
Git. Each request-ready model must have its real, target-seeded synthetic
`system_prompt_canary` and a public `evidence_context_id`. The marker must be
16 to 128 ASCII characters from `[A-Za-z0-9_.~-]`; the context must be nonempty,
at most 128 characters, without brackets or control characters. Do not use a
provider credential as the marker or include it in command arguments. Then run:

```bash
ai-agent-scanner scan --config /private/operator/lab-agents.json \
  --prompt-suite protected-disclosure-v1 --output /private/operator/results.json
```

Use actual private paths and existing scope/budget flags as needed. Loopback still
requires `--allow-loopback`. The flag cannot be combined with `--skip-security`
or discovery targets alone; model selection does not seed a canary. Final model
overrides are validated before candidate requests. Untestable or inaccessible
configuration cannot establish a pass, and at least one request-ready model is
required for this option.

For the server, first configure the startup registry described above. Select the
suite explicitly in a normal scan or saved-template definition:

```json
{
  "scan_name": "Experimental protected disclosure check",
  "scan_type": "security_only",
  "target_scope": {},
  "scan_config": {
    "source_scan_id": "SOURCE_SCAN_ID",
    "model_overrides": {"ASSET_ID": "fixture-model"},
    "evidence_profiles": {"ASSET_ID": "lab-bot-v1"},
    "prompt_suite": "protected-disclosure-v1"
  }
}
```

Only `security_only` with explicit profile selections supports this server option.
Every request-ready model in the effective source inventory needs a matching
selected profile, not an oracle left in a historical source report. Other
unsupported or unconfigured entries retain their ordinary skipped behavior.
No profile is chosen automatically. Foreign, missing, changed, mismatched, or
publicly reflected evidence is rejected before candidate model requests. Source
reports stay unchanged; only fresh in-memory copies receive protected values.

Jobs and templates store the public suite name and an internal digest of the
fixed public catalog/semantics, not a canary-derived hash. Caller-supplied pins
are rejected; returned template definitions omit them. Admission, queued work,
and schedule validation reject missing or changed pins. Editing an unchanged
selection does not silently accept a changed catalog. Review and explicitly
replace an outdated template rather than bypassing a pin failure. Templates
and schedules created without this option continue using the existing suite.
The dashboard's complete JSON template editor preserves this field; the simpler
new-scan form does not add it automatically or configure protected evidence.

Candidate JSON reports identify the selected `prompt_suite` at the report and
asset level; SARIF includes it in run properties. Selection metadata is not proof
that a check ran. Inspect check execution, counters, and outcomes. Payload-derived
probe versions distinguish the candidate from the default and match benchmark
provenance; nondisclosure cannot resolve a previous leak in either suite.

Exact protected-marker disclosure can retain 70/high even if later requests
fail; nondisclosure or an unseeded marker stays inconclusive with null risk unless
other conclusive evidence supports assessment. Generated response text remains
omitted. A later deadline or cancellation retains the last finalized-check
checkpoint, if one exists; observations inside an unfinished check can still be
lost. The CLI exports retained evidence on orderly interruption, but has no
process-crash recovery. No automatic retry is added. The benchmark's observation
checkpoint is not a normal finding ledger.

Default discovery-only configurations cannot confirm prompt disclosure or
authentication bypass. They may produce observations requiring manual validation.
Same-session recall testing is disabled because no deletion, expiration, or session
boundary is established. Privacy-policy answers and small rate-limit samples are
observations, not verified policy violations. Request failures and unsupported
response formats can still limit coverage; zero findings do not establish safety.
