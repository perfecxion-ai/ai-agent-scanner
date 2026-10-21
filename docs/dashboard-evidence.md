# Evidence and audit views

The dashboard shows check execution separately from evidence outcome. Each asset
has completed, skipped, and failed check records with their evaluated response
counts and any prerequisite or failure reason. Expand the asset's check records
to inspect them. The report summary totals execution states across all assets;
a completed check can still be inconclusive.

Current numeric risk requires matching conclusive evidence and a current-policy
stored assessment. A confirmed finding can retain high risk with partial or
failed active coverage; an incomplete run is not a clean verdict. Otherwise the
dashboard shows `Not assessed`. Historical reports
without versioned checks explain that check evidence is unavailable. Their
existing numeric data remains available through JSON and SARIF exports.
Cloud resource identities are displayed alongside any observed HTTP endpoint.

## Finding groups and original occurrences

The metric counts finding occurrences, not distinct root causes. Repeated modern
confirmed prompt findings may share a display group only within one asset entry,
with matching rule/probe/version, public evidence context, boundary and visible
text fields, and one matching confirmed check. Records with historical, malformed,
redacted, ambiguous, or unsupported provenance remain separate. Different asset entries,
models, contexts, and versions are not combined.

For example, 18 sample occurrences from seven checked prompt categories can
display as `7 finding groups / 18 sample occurrences`. This is a presentation
choice, not proof of seven underlying vulnerabilities. Grouping does not rewrite
raw findings, IDs, check counts, scores, JSON, SARIF, suppressions, or finding
comparison/resolution behavior. A later quiet sample cannot resolve a leak.

The dashboard initially shows up to 18 groups; `Show more finding groups` pages up to
100. Counts still cover the complete report, with explicit download guidance
when display is capped. Native details controls reveal the original occurrence
records lazily. Occurrences also page 18 at a time up to 100 per group; large
record previews are truncated with a notice. Download JSON for complete original
records. All text is rendered literally. The focused final-page button returns
focus to its named group or occurrence region, without moving another control's
focus. Polling, scan selection, logout, and session guards remain unchanged.

## Checks and audit

Check lists initially show 18 records. `Show more checks` adds another page,
up to 100 displayed records per asset. Download JSON for the complete record.
The check and audit lists support keyboard scrolling and wrap long identifiers.
Each scroll region has an accessible name. When a focused `Show more checks`
button disappears at the final page or 100-record limit, focus returns to that
asset's check region. Programmatic updates do not move focus from another control.

Terminal scan feedback uses a polite status region and distinguishes completed,
partial, failed, cancelled, and interrupted execution. It reports missing or
unavailable versioned evidence without claiming a security pass. Unchanged polls
do not repeat the announcement or replace an already loaded immutable report;
report-access recovery updates the message once. Selection changes, logout, and
expired sessions clear the feedback and reject late results.

Selecting a scan loads its authenticated audit history independently of report
loading. The timeline lists state changes oldest first with their UTC timestamps.
`Refresh audit` reloads from the beginning; `More events` requests the next page
using the last returned event ID. Pages contain at most 100 events and the view
stops at 500 displayed events. Earlier upgraded scans can have no recorded
history. This operational history is not a tamper-resistant audit trail.

Audit failures remain local to the timeline and do not disable valid report
exports. Responses from previous selections, sessions, or superseded audit
requests cannot populate the current view. Switching scans or signing out clears
the timeline. Tokens remain in page memory and all report and audit text is
rendered as text, including fields containing HTML-like strings.
