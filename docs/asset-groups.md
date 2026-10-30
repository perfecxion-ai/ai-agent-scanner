# Public target groups

The authenticated group API links repeated observations of the same public target.
It keeps the latest observation's risk separate from earlier finding occurrences.
Grouping does not establish that two credentials, users, or tenants have the same
authorization. It does not determine whether a finding has been remediated.

`GET /api/asset-groups` lists groups for the authenticated organization.
`GET /api/asset-groups/{id}/history` lists their finding occurrences. Both accept
`limit` (1 through 100) and an opaque `cursor`. The list also accepts `risk_level`:
`critical`, `high`, `medium`, `low`, `minimal`, or `unknown`, with surrounding
whitespace and case normalized. It matches only the latest observation's canonical
risk. An empty normalized value means no filter. An earlier high confirmation
does not make a currently unknown group match
`risk_level=high`; that confirmation remains in its history. History rejects risk
filters. Duplicate parameters, unsupported levels, type/coverage filters and other
parameters are rejected. The existing `/api/agents` endpoint still lists individual
observations with its original IDs and exhaustive traversal.

A group has a credential-free public target, its latest observation, an
`observation_count`, and `confirmation_history`. Its `latest_observation_risk`
uses the same canonical saved-evidence interpretation as the observation API.
An unassessed score remains null. A newer assessed zero or discovery observation
can change the latest risk without deleting an earlier supported confirmation.
`remediation_status` remains `not_evaluated`.

Both APIs require the same unique report alias and matching snapshot provider,
model and endpoint selectors before assigning risk. A mismatched historical
snapshot remains available with null risk and `unknown`; its original report and
earlier findings remain unchanged. This is not remediation or resolution. Valid
bound evidence can retain risk even when its public target cannot be grouped.

History entries identify the scan, observation, original asset, and finding
ordinal. They distinguish `supported_confirmation` from `archived_claim`.
`supported_occurrences` counts supported occurrences, including repeated findings
from repeated scans. It is not a count of independent vulnerabilities. A source
with no findings contributes an `observation` entry. The original report remains
the source for heuristic observations and full finding details. The history API
does not return raw model output or finding descriptions.

Incomplete history has `complete: false` and null occurrence counts. An archived
claim is not promoted merely because a database scalar says high or confirmed.
Supported receipt evidence can remain in history before a numeric risk assessment
has completed.

## Identity

A group ID hashes a versioned public identity and organization ID. It is stable
across signing-key rotation. HTTP identity uses the endpoint, provider, model,
and evidence context. Missing model or context values match only the same missing
value. Host and scheme normalization removes default ports, while path differences
remain significant. Cloud identity requires a complete supported public resource
identifier. No DNS request is needed to calculate an identity.

Credential-bearing URLs, redacted or ambiguous targets, and incomplete identity
remain separate observations with `identity_status: unmerged`, a static
`unmerged_reason`, and a null target. Names and credentials never define identity.
The snapshot must bind uniquely to its saved report asset, with matching target
selectors, before it can share a target group. A singleton can retain its own
supported evidence when its source binding is valid.

## Readiness and pagination

The dispatcher refreshes a derived index while it has exclusive ownership and no
active scan workers. It builds a new version separately and publishes only after
all observations have been considered. GET requests do not rebuild or repair it.
The source generation, policy, and sealed row counts must match before the API
selects a page. Source changes invalidate existing cursors and make a stale
projection unavailable until a new build is published.

Clients should retain the same page limit and normalized risk filter when following
a cursor. Cursors bind the organization, route, filter, group when applicable,
publication, policy, and ordering.
A stale cursor returns `409` with `stale_cursor`; restart traversal from the first
page. An invalid cursor or unsupported request returns `400`.

`503` with `asset_group_projection_unavailable` means the projection is building,
stale, blocked by unreadable source evidence, or cannot be read within its limits.
Retry after maintenance has progressed. An unknown group in a current projection
returns `404` with `asset_group_not_found`, including groups owned by another
organization. Group readiness is separate from scan queue readiness.

Each refresh step considers at most 500 observations and 32 reports, with a 16 MiB
source budget and a cooperative 0.5 second deadline. Individual saved JSON sources
are limited to 8 MiB and depth 64. Reads use the same source bounds, a five second
query deadline, and a 1 MiB response limit. A stalled or oversized source produces
an unavailable projection instead of an apparently complete empty inventory.

## Storage boundary

Schema 8 adds six nullable canonical risk facts and a partial group-head risk
index to the schema-7 derived storage. The additive upgrade preserves existing
rows, reports, observation IDs, score caches, indexes and invalidation triggers.
Old derived rows cannot serve the new policy until idle maintenance rebuilds
their publication. Unknown scores remain SQL NULL; an unbuilt descriptor is not
treated as unknown evidence.

Risk filters use the sealed source-derived index after the complete readiness
proof, then reopen each selected observation and compare all six risk facts with
its saved source. Existing scalar score caches never exclude candidates. Readiness
still counts the complete source and publication, so it is O(N); indexed candidate
selection does not make the whole request constant time. Continuous writes can
keep the projection unavailable. The background projection does not execute
probes, resume scans, or create schedules.

The server still supports one process, file-backed SQLite, POSIX, and a local
filesystem. Run it from the supported checkout or container; the wheel provides
the CLI and library, without the server entrypoint. The cache checks detect
ordinary stale or altered projection rows;
they do not authenticate a database against a malicious writer with the same
filesystem access. Indexed observation filtering, dashboard group views and
logical-finding consolidation remain separate work.
