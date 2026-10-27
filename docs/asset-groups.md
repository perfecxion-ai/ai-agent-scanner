# Public target groups

The authenticated group API links repeated observations of the same public target.
It keeps the latest observation's risk separate from earlier finding occurrences.
Grouping does not establish that two credentials, users, or tenants have the same
authorization. It does not determine whether a finding has been remediated.

`GET /api/asset-groups` lists groups for the authenticated organization.
`GET /api/asset-groups/{id}/history` lists their finding occurrences. Both accept
`limit` (1 through 100) and an opaque `cursor`. Other parameters, including risk
filters, are rejected. The existing `/api/agents` endpoint still lists individual
observations with their original IDs.

A group has a credential-free public target, its latest observation, an
`observation_count`, and `confirmation_history`. Its `latest_observation_risk`
uses the same canonical saved-evidence interpretation as the observation API.
An unassessed score remains null. A newer assessed zero or discovery observation
can change the latest risk without deleting an earlier supported confirmation.
`remediation_status` remains `not_evaluated`.

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

Clients should retain the exact page limit when following a cursor. Cursors bind
the organization, route, group when applicable, publication, policy, and ordering.
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

Schema 7 adds two derived tables, their indexes, and invalidation triggers. The
upgrade from schema 6 preserves reports, observation IDs, score caches, existing
indexes, and the nine inventory source triggers. The background projection can
be rebuilt from saved sources. It does not execute probes, resume scans, or create
schedules.

The server still supports one process, file-backed SQLite, POSIX, and a local
filesystem. Run it from the supported checkout or container; the wheel provides
the CLI and library, without the server entrypoint. The cache checks detect
ordinary stale or altered projection rows;
they do not authenticate a database against a malicious writer with the same
filesystem access. Source-bound risk filtering and dashboard group views remain
separate work.
