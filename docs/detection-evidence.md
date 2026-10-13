# Detection evidence

Security engine results separate `vulnerabilities` from `observations`.
Heuristic and inconclusive observations do not contribute to the engine risk score.
A model's refusal, claimed persona, generated sample record, or mention of an
administrative feature is not proof of a security boundary violation.

The following optional fields belong to the agent configuration passed to the
Python security engine. Discovery does not populate them automatically, and the
CLI does not yet expose an evidence configuration file.

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
Confirmed access checks do not follow redirects. Provider adapters preserve
deployment prefixes and inspect generated content separately from JSON metadata.

Default discovery-only configurations cannot confirm prompt disclosure or
authentication bypass. They may produce observations requiring manual validation.
Same-session recall testing is disabled because no deletion, expiration, or session
boundary is established. Privacy-policy answers and small rate-limit samples are
observations, not verified policy violations. Request failures and unsupported
response formats can still limit coverage; zero findings do not establish safety.
