# Security

caswhois has no login accounts or browser sessions. Public lookup endpoints use IP-based rate limits. Operator-only operations use the bearer token generated into `secrets.yml` on first run.

## Operator token

Send the token in an authorization header:

```http
Authorization: Bearer <operator-token>
```

The server compares a SHA-256 digest of the presented value in constant time.
Never place the token in a URL, source control, issue, or log. Rotate it by
updating the secret file and restarting the service. Anonymous owner identities
use a separate primary token and optional linked tokens, managed from
`/server/preferences/tokens`; those tokens do not replace the operator token.

## Access levels

Public access includes WHOIS lookups, service information, and health checks. The operator token is required for bulk lookups, scheduler controls, backup controls, and security-report maintenance. Metrics access follows the configured metrics token policy. There is no admin web UI or configuration mutation API.

## Request handling

HTTP input is treated as untrusted. Lookup strings and batch entries are validated before dispatch. Upstream WHOIS/RDAP dispatch uses the service's known registry servers; callers cannot provide arbitrary WHOIS server hosts. RDAP is preferred, with WHOIS fallback. Registry results are relayed and are not cryptographically authenticated by those protocols.

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

Security reports are encrypted before database storage. The public status link
shows only triage status, a maintainer comment, and the expected disclosure
date. Its token is accepted once per UTC day and expires 30 days after a report
is closed. Disclosed reports may appear on `/server/security/thanks` when the
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
