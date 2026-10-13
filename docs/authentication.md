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
The dashboard loads third-party scripts, so use only trusted hosting and browser environments.
Scan status, results, and agent listings are scoped to the token's organization.
