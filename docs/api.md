# API Reference

caswhois exposes a versioned REST API, an OpenAPI document, and a GraphQL
endpoint. Public WHOIS lookups do not require a token. The bulk lookup and
server-operation routes require the operator bearer token from `secrets.yml`.

## Base URL and authentication

The default API base is `/api/v1`; the configured version is exposed by the server. For a deployed service, prepend its origin, for example `https://whois.example.net/api/v1`.

```http
Authorization: Bearer <server-token>
```

Do not place a token in a URL or share it. The operator token is required for bulk lookup, scheduler operations, and backup operations. Anonymous requests to public lookup endpoints are rate limited.

## WHOIS lookups

| Method | Path | Access | Purpose |
|--------|------|--------|---------|
| GET | `/api/v1/whois/{query}` | Public | Detect and look up a domain, IP address, or ASN |
| GET | `/api/v1/whois/domain/{domain}` | Public | Domain lookup |
| GET | `/api/v1/whois/ip/{ip}` | Public | IPv4 or IPv6 lookup |
| GET | `/api/v1/whois/asn/{asn}` | Public | ASN lookup |
| GET | `/api/v1/whois/validate/{query}` | Public | Validate a query without looking it up |
| GET | `/api/v1/whois/search?owner={text}` | Public | Search the local registrant dataset |
| POST | `/api/v1/whois/bulk` | Operator | Look up a batch of queries |
| GET | `/api/v1/whois-servers` | Public | List known WHOIS servers |

Example:

```bash
curl -H 'Accept: application/json' 'https://whois.example.net/api/v1/whois/example.com'
curl -H 'Accept: application/json' 'https://whois.example.net/api/v1/whois/ip/2001:4860:4860::8888'
```

WHOIS retrieval prefers RDAP and falls back to WHOIS. Successful normalized records are retained in the local database. Upstream data is public registry data and may be incomplete or stale.

## Server endpoints

| Method | Path | Access | Purpose |
|--------|------|--------|---------|
| GET | `/api/v1/server/healthz` | Public | Health and build information |
| GET | `/api/v1/server/stats` | Public | Lookup and service statistics |
| GET | `/api/v1/server/schedulers` | Operator | Scheduler status |
| POST | `/api/v1/server/schedulers/run` | Operator | Trigger a scheduler task |
| GET | `/api/v1/server/backups` | Operator | Backup status |
| POST | `/api/v1/server/backups/run` | Operator | Trigger a backup |
| GET | `/api/v1/server/about` | Public | About-page content |
| GET | `/api/v1/server/privacy` | Public | Privacy policy data |
| GET, POST | `/api/v1/server/contact` | Public | Contact form description and submission |
| GET | `/api/v1/server/help` | Public | Help content |
| GET | `/api/v1/server/terms` | Public | Terms of service |
| GET | `/api/v1/server/dpo` | Public | Data protection contact |
| GET | `/api/v1/server/security` | Public | Security policy/contact data |
| GET | `/api/v1/server/security/policy` | Public | Security policy content |

The browser pages use unversioned paths such as `/server/healthz` and
`/server/contact`; their API counterparts use the versioned prefix shown in
the table. `/api/healthz` is a direct health alias. `/api/swagger` is an alias
for the OpenAPI document. GraphQL is available at `/api/v1/server/graphql`
and the `/api/graphql` alias. The API response does not honor cookies as
credentials.

The metrics endpoint is configured by `server.metrics.endpoint` and is
available when `server.metrics.enabled` is true. If `server.metrics.token` is
configured, send that metrics token as a bearer token; it is separate from the
operator token. Rate-limit counters use bounded `limit` and `status` labels;
they never expose client IP addresses or token values.

## Responses and limits

JSON responses use an `ok` boolean and a `data` or `error` member. Use the
HTTP status code as the primary success or failure signal. Requests are rate
limited by endpoint class; bulk operations also require operator
authentication. Add `.txt` to a versioned endpoint path or send
`Accept: text/plain` to request a plain-text success response. API routes
return JSON errors so clients retain the standard error envelope. Curl and
other non-interactive HTTP tools receive text by default; send
`Accept: application/json` to force JSON.

## Interactive documentation

- Swagger UI: `/server/docs/swagger`; its JavaScript and CSS assets are served locally, so the page does not depend on a third-party CDN
- OpenAPI JSON: `/api/v1/server/swagger` (also `/api/swagger`)
- GraphQL UI: `/server/docs/graphql`
- GraphQL POST: `/api/v1/server/graphql` (also `/api/graphql`)

## Command line client

The companion `caswhois-cli` client supports lookup and query validation. See
[CLI Reference](cli.md) for its commands and options. Owner-token management
and the MCP endpoint are not currently implemented.
