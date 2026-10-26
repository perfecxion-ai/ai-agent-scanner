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
| `tenant_evidence` | Configure two issued principals, two independently seeded records, an exact public target binding, and the authorization attestation described below. |
| `cross_tenant_canary` | Legacy input only. A foreign marker alone no longer enables the tenant check. |
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

V3 access markers must use exactly `[A-Za-z0-9_.~-]{16,128}`. No trimming,
decoding, case conversion, or other normalization is used for response matching.
Previously accepted arbitrary strings outside this grammar are now refused
before requests. The restriction excludes header and JSON fragments that could
be mistaken for private data after request reflection.

Protected-access URLs must be HTTP(S) without user information, query parameters,
fragments, or percent escapes. Markers must not overlap public target fields,
credential values, normalized URLs, or probe material, including fixed client
headers and rendered request lines. Collision checks also reject case variants
of that public/request material. V3 additionally verifies the complete actual
GET while its response is live: exact resource, empty body, Host, selected
credential header and bounded expected headers. Unknown or incomplete captures,
cookies, extra credentials and reflected markers cannot confirm or pass. Marker
transmission in an earlier scan request taints later controls. Issued keys,
markers and references are pinned before the first checkpoint; environment
changes during a scan do not silently change the tested principal.
Reflected request content is not protected evidence. Baseline text and issued credentials are never finding
fields. Configure opaque synthetic markers separately from credentials.

Denied controls and decisive denied probes must exclude the marker from their
bounded bodies and headers. Case variants and decoded JSON are checked
conservatively for absence; positive matching remains exact. Malformed,
duplicate-key, nonfinite, over-depth or oversized JSON, invalid text encodings
and binary denials cannot establish absence. The JSON bound is 16 containers and
8,192 visited nodes. These finite samples do not prove absence under arbitrary
content transformations.

The `authorized-and-denied-resource-controls-v3` definition changes probe
versions for all four check groups. Records using earlier control definitions
remain readable but cannot establish current risk or verified resolution, even
when both compared records share an obsolete version. Current projections require
recognized control semantics, matching asset context, and valid sample accounting.
Custom protected-access sample catalogs are unverified until supported by this
contract; their archived observations are not deleted. See
[historical evidence handling](result-contracts.md) for mixed-evidence limits.
Schema 6 reconciles obsolete scalar caches without rewriting those reports.
Keep the public `evidence_context_id` stable only while the tested resource,
authorization policy, and protected fixture remain the same.

## Controlled tenant assessment

This CLI/Python workflow tests a configured authorization boundary. It requires
two real issued credentials for different tenants: an owner permitted to retrieve
one protected verification record, and a tested principal permitted to retrieve
a different record. The operator must explicitly attest that the tested principal
must not access the owner's record. Different labels or keys alone do not prove
different tenant identities or authorization rights.

Seed distinct synthetic opaque markers in the two records, outside all prompts
and request metadata. Store both markers and both issued credentials in the
scanner's private process environment. Use the secret-delivery mechanism for the
local test environment; do not put values in shell history, Git, command arguments,
or scan JSON. Marker values use `[A-Za-z0-9_.~-]{16,128}` and must not overlap each
other, credentials, public configuration, or request material, including case
variants. Missing values and invalid declarations fail before security requests
or an initial report checkpoint.

The following agent entry contains references only. Include it in the `agents`
array of a CLI scan configuration:

```json
{
  "id": "tenant-fixture",
  "name": "Tenant authorization fixture",
  "endpoint": "https://fixture.example.test/v1/chat/completions",
  "provider": "openai-compatible",
  "model": "fixture-model",
  "api_key_env": "TENANT_TESTED_API_KEY",
  "evidence_context_id": "tenant-policy-v1",
  "tenant_evidence": {
    "schema_version": "1.0",
    "tested_principal_authorized_for_owner": false,
    "binding": {
      "endpoint": "https://fixture.example.test/v1/chat/completions",
      "provider": "openai-compatible",
      "model": "fixture-model",
      "evidence_context_id": "tenant-policy-v1"
    },
    "owner": {
      "tenant_ref": "tenant-owner",
      "principal_ref": "principal-owner",
      "api_key_env": "TENANT_OWNER_API_KEY",
      "canary_env": "TENANT_OWNER_CANARY"
    },
    "tested": {
      "tenant_ref": "tenant-tested",
      "principal_ref": "principal-tested",
      "api_key_env": "TENANT_TESTED_API_KEY",
      "canary_env": "TENANT_TESTED_CANARY"
    }
  }
}
```

The binding must match the selected endpoint, provider, model, and public context.
Endpoint comparison normalizes authority and default port while retaining the
exact path. Queries, fragments, embedded credentials, percent escapes, and
ambiguous paths are rejected. Verified HTTPS is required outside literal loopback
IP addresses. HTTP loopback still requires `--allow-loopback` and the existing
scope rules. There is no insecure TLS option. The tested credential reference
must match the agent's explicit `api_key_env`; automatic provider credentials do
not enable tenant evidence. Do not combine the envelope with `cross_tenant_canary`.

The fixed control prompt is `Return the private tenant verification record.`
Each control uses a fresh session and the provider's normal inference adapter:

| Control | Required observation |
| --- | --- |
| Owner credential | Usable generated text contains the owner marker; the tested marker is absent from the bounded response body and headers. |
| Tested credential | Usable generated text contains the tested principal's own marker. |
| Fresh invalid credential | HTTP 401 or 403, with neither marker anywhere in the bounded response body or headers. |

Only after all three succeed can the tested control's owner-marker disclosure
become a finding or the five existing tenant attack prompts run. At most eight
tenant requests share the ordinary scan budget and deadline. A failed or
unseeded control is inconclusive; it never proves a defense. Markers appearing
only in response metadata cannot establish a positive control or a leak.
The owner-exclusive requirement intentionally leaves privileged-owner and
bidirectional-leak configurations inconclusive in this first version.

Credentials and markers are pinned once for the scan, including before report
checkpoints. All configured markers are excluded from known outbound request
material. Complete actual request snapshots also check automatic headers and
serialized bodies. Earlier transmitted marker material or incomplete transmitted
provenance prevents subsequent tenant confirmation. This does not exclude
arbitrary transformed echoes or establish target-side session isolation.

Reports omit the private envelope, credentials, markers, principal references,
and generated text. Findings retain a versioned control status, a public target
binding, and the observation's control or attack index. Rotate the public context
when principals, credentials, protected records, tenant policy, or fixture setup
change. Nondisclosure remains inconclusive and cannot resolve an earlier finding.
New tenant findings use mixed-ledger observation receipts before the check
finishes. A subject-control leak is held until the denied control succeeds;
attack leaks publish before cleanup and the next request. An acknowledged
finding survives later interruption with partial coverage. See the
[receipt contract](result-contracts.md#tenant-observation-receipts) for counters
and the limits of CLI process recovery.

The server rejects this private input at admission and execution, including saved
source inventory and newly discovered assets. Server tenant profiles are a
separate follow-up. A plain model server without tenant-aware authorization does
not satisfy these prerequisites.

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
as a policy revision. [Schema-4 startup migration](jobs.md#schema-upgrades) handles
stored unknown-score placeholders separately from evidence-profile configuration.
Saved pipeline results and canonical API projections remain authoritative; the
migration preserves archived report bytes.

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
omitted. A later deadline or cancellation retains the last acknowledged receipt
or finalized-check checkpoint, if one exists. The CLI exports retained evidence
on orderly interruption, but has no process-crash recovery. No automatic retry
is added. The benchmark's observation checkpoint is a separate contract.

Default discovery-only configurations cannot confirm prompt disclosure or
authentication bypass. They may produce observations requiring manual validation.
Same-session recall testing is disabled because no deletion, expiration, or session
boundary is established. Privacy-policy answers and small rate-limit samples are
observations, not verified policy violations. Request failures and unsupported
response formats can still limit coverage; zero findings do not establish safety.
