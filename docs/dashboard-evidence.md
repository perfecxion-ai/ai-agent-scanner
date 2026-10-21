# Evidence and audit views

The dashboard shows check execution separately from evidence outcome. Each asset
has completed, skipped, and failed check records with their evaluated response
counts and any prerequisite or failure reason. Expand the asset's check records
to inspect them. The report summary totals execution states across all assets;
a completed check can still be inconclusive.

Current numeric risk requires conclusive, completed check evidence and a stored
assessment. Otherwise the dashboard shows `Not assessed`. Historical reports
without versioned checks explain that check evidence is unavailable. Their
existing numeric data remains available through JSON and SARIF exports.
Cloud resource identities are displayed alongside any observed HTTP endpoint.

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
