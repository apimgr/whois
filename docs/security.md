# Security

caswhois has no login accounts or browser sessions. Public lookup endpoints use IP-based rate limits. Operator-only operations use the bearer token generated into `secrets.yml` on first run.

## Operator token

Send the token in an authorization header:

```http
Authorization: Bearer <operator-token>
```

The server compares a SHA-256 digest of the presented value in constant time. Never place the token in a URL, source control, issue, or log. Rotate it by updating the secret configuration and restarting the service.

## Access levels

Public access includes WHOIS lookups, service information, and health checks. The operator token is required for bulk lookups, scheduler controls, and backup controls. Metrics access follows the configured metrics token policy. There is no admin web UI or configuration mutation API.

## Request handling

HTTP input is treated as untrusted. Lookup strings and batch entries are validated before dispatch. Upstream WHOIS/RDAP dispatch uses the service's known registry servers; callers cannot provide arbitrary WHOIS server hosts. RDAP is preferred, with WHOIS fallback. Registry results are relayed and are not cryptographically authenticated by those protocols.

## Data and logging

Successful lookup records are stored in the local SQLite/libsql dataset. Audit logs may contain client IP addresses; raw operator tokens and submitted secrets must not be logged. Protect the configuration, secret, database, log, and backup directories with operating-system permissions appropriate to the service account.

## Transport security

Use HTTPS whenever requests cross an untrusted network. caswhois supports manual TLS certificates and Let's Encrypt configuration. Security response headers and request limits are applied by the server.

## Security reporting

The server publishes `/.well-known/security.txt` with the repository's private vulnerability reporting URL, the policy URL, and an expiry date. If `server.contact.security.email` is configured, that address is listed as an additional contact. The same information is available on `/server/security` and through `GET /api/v1/server/security`. Do not include an operator token or other secret in a report.

The repository reporting URL is controlled by `web.security.report_url` and defaults to GitHub private vulnerability reporting. `web.security.policy` customizes the policy shown at `/server/security/policy`; an empty value uses the built-in policy. The general `/server/contact` form is separately controlled by `server.pages.contact.enabled` and is not presented as a security-report channel.
