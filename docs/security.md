# Security

caswhois has no login accounts or browser sessions. Public lookup endpoints use IP-based rate limits. Operator-only operations use the bearer token generated into `secrets.yml` on first run.

## Operator token

Send the token in an authorization header:

```http
Authorization: Bearer <operator-token>
```

The server compares a SHA-256 digest of the presented value in constant time.
Never place the token in a URL, source control, issue, or log. Rotate the
operator token in `secrets.yml` and restart the service. Anonymous owner identities
use a separate primary token and optional linked tokens, managed from
`/server/preferences/tokens`; those tokens do not replace the operator token.

## Secret rotation

The operator token authorizes sensitive maintenance operations; root may run
them without prompting. Rotate generated application secrets with:

```bash
caswhois --maintenance 'secret rotate installation_secret'
caswhois --maintenance 'secret rotate encryption_key'
```

Each rotation requires root or the operator token, a non-empty reason, and the
typed confirmation `ROTATE installation_secret` or `ROTATE encryption_key`.
Stop the server first; rotation refuses to proceed while a configured local
listener is active, which prevents a running process from continuing to write
with stale in-memory keys. The audit entry records the operator's local IP
address and reason, never a secret value.

Installation-secret rotation re-encrypts the stored PGP private key and accepts
previously issued contact and security-report signatures for seven days.
Encryption-key rotation re-encrypts stored owner tokens and AES-encrypted
security report bodies and contacts in batches. PGP-encrypted report bodies are
left unchanged. The previous encryption key is wrapped by the new key and kept
for 30 days; startup resumes an interrupted re-encryption before serving
requests.
Rotations are audited without recording secret values. A second rotation is
refused while the prior key remains in its grace period.

The server also rotates the cookie-signing key every 90 days and the HMAC key
used to sign CSRF tokens every 180 days. CSRF signing keys rotate immediately
when an owner API token is regenerated. Previous automatic keys remain valid
for seven days so already-open browser forms can finish.

## Access levels

Public access includes WHOIS lookups, service information, and health checks. The operator token is required for bulk lookups, scheduler controls, backup controls, and security-report maintenance. Metrics access follows the configured metrics token policy. There is no admin web UI or configuration mutation API.

## Request handling

HTTP input is treated as untrusted. Lookup strings and batch entries are validated before dispatch. Upstream WHOIS/RDAP dispatch uses the service's known registry servers; callers cannot provide arbitrary WHOIS server names. RDAP is preferred, with WHOIS fallback. Registry results are relayed and are not cryptographically authenticated by those protocols.

## Data and logging

Successful lookup records are stored in the local SQLite/libsql dataset. Audit logs may contain client IP addresses; raw operator tokens and submitted secrets must not be logged. Protect the configuration, secret, database, log, and backup directories with operating-system permissions appropriate to the service account.

## Transport security

Use HTTPS whenever requests cross an untrusted network. caswhois supports manual TLS certificates and Let's Encrypt configuration. Security response headers and request limits are applied by the server.

## Security reporting

The primary vulnerability channel is GitHub private vulnerability reporting. The
server also publishes `/.well-known/security.txt` with that URL, a short-lived
`/server/contact?security_id=...` report link, the optional security email
address, a policy URL, and an expiry date. The same public contact information
is rendered at `/server/security` and is available from
`GET /api/v1/server/security`. The contact form is noindex and is not linked
from general site navigation.

The repository URL is controlled by `web.security.report_url` and defaults to
GitHub private vulnerability reporting. `web.security.policy` customizes the
policy shown at `/server/security/policy`; an empty value uses the built-in
policy. `/server/contact` offers abuse, DMCA, and privacy forms. A valid
`security_id` selects the security report form. Every submission has a review
and confirm step and server-side CAPTCHA; invalid IDs fall back to the
non-security chooser.

Security reports are encrypted before database storage. When the project PGP
key is configured, the report body and maintainer notification use PGP;
otherwise the body uses AES-256-GCM and the maintainer notice clearly identifies
the encrypted fallback. Researcher acknowledgments are encrypted to a validated
researcher key when one is supplied. The emailed public status link has the
form `/server/security/report/{tracking_id}?token={one-time-status-token}`.
The tracking ID selects the report and the query token authorizes the status
view. It shows only triage status, a maintainer comment, and the expected
disclosure date; this private status view has no API mirror. Its token is
accepted once per UTC day and expires 30 days after a report is closed.
Disclosed reports may appear on `/server/security/thanks` when the
researcher opted in; the same list is returned by
`GET /api/v1/server/security/thanks`.

Operators manage report metadata from the CLI:

```bash
caswhois --maintenance 'security list'
caswhois --maintenance 'security show sec_<tracking-id>'
caswhois --maintenance 'security update sec_<tracking-id> --status triaged'
caswhois --maintenance 'security export sec_<tracking-id> --output report.asc'
```

`show` displays metadata and the researcher's status comment, not the report
body. `export` writes the encrypted report only; it never prints decrypted
content. Run maintenance as root or provide the operator token when prompted.
