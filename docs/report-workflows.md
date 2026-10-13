# Offline report comparison and triage

These commands read saved version 1.0 JSON scan reports and write a separate derived file.
They do not modify the scan database or source reports, and perform no network requests.

```bash
ai-agent-scanner diff --before previous.json --after current.json --output difference.json
ai-agent-scanner triage --report current.json --policy suppressions.json --output triaged.json
```

Diff identifies cloud assets by cloud, provider, and resource ID before considering
their endpoint. Other assets use a normalized endpoint. Endpointless assets use source path plus
provider/name/type when available, otherwise a labeled provider/name fallback. Random snapshot
IDs, finding IDs, and timestamps do not determine identity. Findings are grouped by asset,
rule, category, test name, and path. Repeated observations count once but every occurrence
is retained in the group's `occurrences` array.
Identity collisions are labeled ambiguous and cannot support automatic suppression or resolution.

`newly_observed` means absent from the prior report, not necessarily newly introduced.
`resolved` requires a complete current security run of the same unambiguous endpoint asset
and explicit versioned `checks` with `status: completed`, `outcome: passed`, and
evaluated responses. Every earlier occurrence must match the current rule, probe
ID, probe version, and nonempty, nonredacted `evidence_context_id`; the asset's
provider and model must also match. See [check contracts](result-contracts.md).
Missing or changed contexts, changed probe versions, and legacy findings without
check provenance remain unverified. Disappearance alone cannot establish a pass.
Missing assets, incomplete runs, redacted endpoints, cloud resource identities,
and endpointless identities leave disappeared
findings in `resolution_unverified`. `inventory_not_observed` does not assert asset deletion.
Completeness is based on the report's recorded status; it does not establish coverage of every
possible attack or prove that a service is secure.

Start with an empty policy (`{"suppressions":[]}`) to obtain inventory `asset_key` values in
triage output. Each suppression must name an exact asset key and rule, explain its rationale,
and expire at a timezone-qualified ISO 8601 timestamp:

```json
{"suppressions":[{
  "asset_key":"COPY_THE_64_CHARACTER_ASSET_KEY_FROM_INVENTORY",
  "rule_id":"prompt_injection",
  "rationale":"Accepted lab finding while remediation is tested",
  "expires_at":"2026-12-01T00:00:00Z"
}]}
```

Expired rules are recorded but do not suppress findings. Wildcard asset selectors are rejected.
Triage keeps suppressed evidence in `suppressed_findings` and active evidence in `active_findings`;
it does not lower original risk scores or convert the source scan status to clean.
Policy files are local operator input, not a centrally authorized approval mechanism.
