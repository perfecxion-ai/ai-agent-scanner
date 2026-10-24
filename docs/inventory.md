# Inventory traversal

`GET /api/agents` lists saved observations owned by the authenticated organization.
Risk belongs to each saved observation. Several observations can refer to the
same target, including an earlier confirmation and a later inconclusive run.
Snapshot `id` and scan-local `asset_id` retain their existing meanings.

The endpoint reads current canonical risk from saved reports. Database score and
level columns never exclude candidates. Unsupported historical evidence remains
unknown, and supported assessed zero remains numeric zero.

## Pages and filters

| Parameter | Meaning |
| --- | --- |
| `limit` | Positive decimal integer from 1 through 100; defaults to 100 |
| `agent_type` | Exact type after trimming surrounding whitespace |
| `risk_level` | `critical`, `high`, `medium`, `low`, `minimal`, or `unknown`; surrounding whitespace and case are normalized |
| `cursor` | Opaque continuation from the preceding response |

Keep the same filters and limit on every request in a traversal. Duplicate known
parameters are rejected. Ordering is stored `discovered_at DESC, id ASC`; cursors
preserve the original timestamp representation used by SQLite's sort key.

Responses retain `success`, the existing observation fields, and `coverage`.
They add `next_cursor` and `coverage.search_complete`. An empty page with a
continuation cursor means more observations remain to inspect. Follow every
cursor and retain preceding pages. `search_complete` means no candidates remain
after the current boundary; a consumer needs all preceding pages for the full set.

The legacy `window_limit` and `window_truncated` fields now describe the page
limit and remaining traversal, respectively. The filter scope is
`tenant_type_assets_cursor_pages`. `evaluated_candidates` counts candidates
consumed by traversal progress. `projected_reports`, `projected_report_bytes`,
and `interpreted_source_bytes` count work performed by this response and can
include source decoded for an entry deferred to the next page.

For example, this client retains all high-risk observations while keeping its
credential out of the URL:

```python
import json
import os
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

base = "http://127.0.0.1:5000"
query = {"risk_level": "high", "limit": "100"}
opener = build_opener(ProxyHandler({}))
observations = []
while True:
    request = Request(base + "/api/agents?" + urlencode(query), headers={
        "Authorization": "Bearer " + os.environ["AIS_INVENTORY_TOKEN"],
    })
    with opener.open(request, timeout=10) as response:
        page = json.load(response)
    observations.extend(page["agents"])
    cursor = page["next_cursor"]
    if cursor is None:
        if not page["coverage"]["search_complete"]:
            raise RuntimeError("Incomplete inventory traversal")
        break
    query["cursor"] = cursor
print(json.dumps({"matching_observations": len(observations)}))
```

## Consistency and errors

Cursors use an uncompressed codec with a 4,096-byte cap and expire after 15 minutes.
A signature binds organization, normalized
filters, page limit, ordering, projection policy, inventory generation, and the
last evaluated key. Source changes and code deployments can invalidate a cursor.
The policy includes a fingerprint of packaged Python source, so an unrelated
source edit can also require a fresh traversal.

| HTTP status/code | Action |
| --- | --- |
| 400, `invalid_inventory_request` | Correct the limit or filters |
| 400, `invalid_cursor` | Start again with a fresh cursor and unchanged filters |
| 409, `stale_cursor` | Discard accumulated pages and restart after relevant writes settle |
| 503, `inventory_projection_unavailable` | Treat the operation as incomplete; inspect source format/size or retry a timed-out read |

Generation changes share the writer transaction. Report and observation writes,
including direct ORM/Core writes and ownership moves, invalidate affected
organizations. Rollback, changes in other organizations, and progress-only
scan-session updates preserve the cursor. Report and observation writes always
invalidate it. An unchanged inventory also retains its generation
through restart. Continuous source changes can prevent a complete traversal.

## Work bounds

Each response evaluates at most 500 candidates and projects at most 32 reports.
Reports and observation metadata share a 16 MiB raw interpretation allowance;
each individual source is limited to 8 MiB and 64 nested containers. Returned JSON
has a 1 MiB limit, including a reserved allowance for its envelope and cursor.
The reader checks a five-second cooperative work deadline and installs a scoped
SQLite progress handler. A single interpretation completes before its next
deadline check; this is not a hard latency guarantee.

A sparse filter, exhausted source allowance, or full output page can return an
advancing continuation with fewer matches. Unreadable or individually excessive
source material returns a static 503 instead of advancing past a potential match.
Valid but unsupported evidence follows normal canonical unknown semantics.
Stored archives are preserved. Accepted indexes help candidate selection, while
SQLite can still sort across scans; SQL `LIMIT` alone does not bound query work.

Schema 5 adds the generation table, three candidate indexes, and nine recognized
triggers. Existing schema-4 rows and score caches are preserved. Startup validates
the complete trigger/index definitions before serving. See
[schema upgrades](jobs.md#schema-upgrades) and the
[owned-fixture operator gate](inventory-retest.md).
