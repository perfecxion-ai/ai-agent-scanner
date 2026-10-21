# Operator authentication

The web application supports one operator and one configured organization.
It does not provide user enrollment, SSO, role management, or production multi-tenant identity provisioning.

Set `SECRET_KEY` and `OPERATOR_API_KEY` to independent random secrets before starting the app.
Generate each with `openssl rand -hex 32`. Set `OPERATOR_ORGANIZATION_ID` to the organization
that owns this deployment's scans. Keep `FLASK_DEBUG=false` outside local development.
An unset operator key disables token issuance and protected API routes, including in debug mode.

Open the dashboard and enter the operator key to sign in. The dashboard keeps the issued token
only in memory. Reloading the page or signing out clears it from the browser application.
Sign out does not revoke a copied token: tokens expire after one hour. Rotating `SECRET_KEY`
invalidates all existing tokens. Rotating only `OPERATOR_API_KEY` prevents subsequent logins
with the old key but does not revoke existing tokens.

API clients send `POST /api/auth/token` with a JSON object containing `api_key`, then send
`Authorization: Bearer <token>` on protected endpoints. The server assigns `user_id=operator`
and the configured organization; caller-supplied identity fields have no effect. Old tokens
without the required issuer, audience, identity, and expiry claims are rejected.

Use HTTPS for remote access. Restrict access to trusted operators behind a private network
or authenticated reverse proxy, and enforce login rate limits there. The application does
not currently provide login throttling. Do not expose the development server to the internet.
The dashboard serves its scripts locally; its content security policy restricts scripts to that origin.
Scan status, results, and agent listings are scoped to the token's organization.

## API risk projections and inventory bounds

`GET /api/scans/<scan_id>/results` and `GET /api/agents` project current risk
from the saved pipeline's versioned check evidence and `severity-floor-v2`
policy, not numeric database compatibility defaults. Unknown or unsupported
historical risk is `null` with level `unknown`; it is not an assessed zero.
An evidence-backed zero and a confirmed high score with partial coverage remain
numeric. Agent projections include `risk_assessment_status`,
`risk_coverage_status`, and `risk_scoring_policy`. The results summary also
includes `risk_assessment_status`. Raw historical pipeline reports and exports
are retained unchanged, not recalculated or retroactively sanitized.

`GET /api/agents` considers at most the newest 100 assets in the authenticated
organization after the optional `agent_type` filter. The optional `risk_level`
filter applies to those assets' projected risk, not stored legacy levels or
the full inventory. The additive `coverage` object reports `window_limit`,
`window_truncated`, `risk_level_filter_scope`, and a warning when older assets
were omitted. A filtered empty list with a truncated window does not establish
that the full inventory contains no matching assets. This bounded compatibility
listing is not an exhaustive inventory export or a paginated search API.
