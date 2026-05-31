# Security

## Authentication

caswhois uses token-only authentication. There are no user accounts, no passwords, and no browser sessions.

### Server Token

A single operator token is auto-generated on first run and written to `server.yml`:

```yaml
server_token: tok_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

The token format is `tok_` followed by 32 base-62 characters. It is stored plaintext in `server.yml` (the config file is root-only, 0600). Incoming bearer tokens are validated by SHA-256 hashing the inbound value and comparing with `subtle.ConstantTimeCompare` — the raw token is never retained in memory beyond the comparison.

### Using the Token

Pass the token as a Bearer header:

```
Authorization: Bearer tok_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Protected endpoints return `401 UNAUTHORIZED` if the header is absent or the token does not match.

### Token Rotation

Replace `server_token` in `server.yml` and restart the server. Old tokens are immediately invalid.

## Public Endpoints

These endpoints require no authentication:

| Endpoint | Purpose |
|----------|---------|
| `GET /` | WHOIS lookup homepage |
| `GET /whois` | WHOIS form result (no-JS path) |
| `GET /api/v1/whois/{query}` | Generic WHOIS lookup |
| `GET /api/v1/whois/domain/{domain}` | Domain WHOIS |
| `GET /api/v1/whois/ip/{ip}` | IP address WHOIS |
| `GET /api/v1/whois/asn/{asn}` | ASN WHOIS |
| `GET /api/v1/whois/validate/{query}` | Validate query without lookup |
| `GET /api/v1/whois-servers` | List known WHOIS servers |
| `GET /api/v1/server/stats` | Service statistics |
| `GET /server/healthz` | Health check |
| `GET /about` | About page |
| `GET /docs` | API docs page |
| `GET /metrics` | Prometheus metrics (token-protected if `metrics_token` set) |

## Protected Endpoints

These endpoints require the server token:

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/whois/bulk` | Bulk WHOIS lookup |
| `GET /api/v1/server/schedulers` | List scheduled tasks |
| `POST /api/v1/server/schedulers/run` | Trigger a scheduled task |
| `GET /api/v1/server/backups` | List backups |
| `POST /api/v1/server/backups/run` | Trigger a backup |

## Security Headers

Every response includes:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Content-Security-Policy` | Restricts inline scripts/styles; self-origin only |

## Rate Limiting

All public endpoints are rate-limited. Default: 120 requests per minute per IP. Configure in `server.yml`:

```yaml
rate_limit_enabled: true
rate_limit_requests: 120
rate_limit_window: 1m
```

Clients that exceed the limit receive `429 RATE_LIMITED`.

## Path Security

The `PathSecurityMiddleware` rejects requests containing:

- Directory traversal sequences (`../`, `..\`)
- Null bytes
- Encoded traversal attempts

## TLS

Let's Encrypt certificates are obtained automatically via lego when `fqdn` is set. HTTP-01 and TLS-ALPN-01 challenge types are supported. Certificates renew automatically 30 days before expiry. Minimum TLS version is 1.2.

## Well-Known Endpoints

### `/.well-known/security.txt`

Machine-readable security contact file per [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116):

```
Contact: mailto:security@{fqdn}
Expires: {one year from generation}
Canonical: https://{fqdn}/.well-known/security.txt
```

Configure the contact address and preferred languages in `server.yml`.

## Backup Encryption

When `backup_encryption_enabled: true`, backup archives are encrypted with Argon2id key derivation. The encryption password is prompted at restore time. Plain-text backups are never written to disk when encryption is enabled.

## Sensitive Data Policy

- **Never** commit `server.yml` to version control — it contains the server token
- **Never** expose `server_token` via any API endpoint
- Logs never contain raw token values
- SQL queries are always parameterized — no string interpolation in SQL
- Audit events (config changes, security events) are written to `audit.log`
