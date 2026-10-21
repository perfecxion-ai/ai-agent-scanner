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
| `protected_response_marker` | Unique string of at least 16 characters present only in protected response data. Authentication probes also require a random credential to receive HTTP 401 or 403. |
| `protected_path_markers` | Map tested admin paths to unique strings of at least 16 characters present only in private admin data. |

Canary provenance is an operator assertion. The scanner verifies returned text,
not how the secret was originally seeded. Canaries included in attack prompts
cannot confirm disclosure. Configure synthetic test secrets, not real credentials.
Nondisclosure is inconclusive, even with a configured canary: an unseeded secret
or a finite stochastic sample cannot prove safety or resolve an earlier leak.
Generated response text is omitted from new evidence rather than persisted as
an excerpt; older saved reports are not retroactively sanitized.
Confirmed access checks do not follow redirects. Provider adapters preserve
deployment prefixes and inspect generated content separately from JSON metadata.

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

Default discovery-only configurations cannot confirm prompt disclosure or
authentication bypass. They may produce observations requiring manual validation.
Same-session recall testing is disabled because no deletion, expiration, or session
boundary is established. Privacy-policy answers and small rate-limit samples are
observations, not verified policy violations. Request failures and unsupported
response formats can still limit coverage; zero findings do not establish safety.
