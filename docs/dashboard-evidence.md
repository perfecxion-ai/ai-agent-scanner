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
