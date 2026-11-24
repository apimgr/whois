# API Reference

caswhois exposes a versioned REST API, an OpenAPI document, and a GraphQL endpoint. Public WHOIS lookups do not require a token. Operator operations require the bearer token from `secrets.yml`.

## Base URL and authentication

The default API base is `/api/v1`; the configured version is exposed by the server. For a deployed service, prepend its origin, for example `https://whois.example.net/api/v1`.

```http
Authorization: Bearer <server-token>
```

Do not place a token in a URL or share it. The operator token is required for bulk lookup, scheduler operations, and backup operations. Anonymous requests to public lookup endpoints are rate limited.

## WHOIS lookups

| Method | Path | Access | Purpose |
|--------|------|--------|---------|
| GET | `/whois/{query}` | Public | Detect and look up a domain, IP address, or ASN |
| GET | `/whois/domain/{domain}` | Public | Domain lookup |
| GET | `/whois/ip/{ip}` | Public | IPv4 or IPv6 lookup |
| GET | `/whois/asn/{asn}` | Public | ASN lookup |
| GET | `/whois/validate/{query}` | Public | Validate a query without looking it up |
| GET | `/whois/search?owner={text}` | Public | Search the local registrant dataset |
| POST | `/whois/bulk` | Operator | Look up a batch of queries |
| GET | `/whois-servers` | Public | List known WHOIS servers |

Example:

```bash
curl 'https://whois.example.net/api/v1/whois/example.com'
curl 'https://whois.example.net/api/v1/whois/ip/2001:4860:4860::8888'
```

WHOIS retrieval prefers RDAP and falls back to WHOIS. Successful normalized records are retained in the local database. Upstream data is public registry data and may be incomplete or stale.

## Server endpoints

| Method | Path | Access | Purpose |
|--------|------|--------|---------|
| GET | `/server/healthz` | Public | Health and build information |
| GET | `/server/stats` | Public | Lookup and service statistics |
| GET | `/server/schedulers` | Operator | Scheduler status |
| POST | `/server/schedulers/run` | Operator | Trigger a scheduler task |
| GET | `/server/backups` | Operator | Backup status |
| POST | `/server/backups/run` | Operator | Trigger a backup |
| GET | `/server/privacy` | Public | Privacy policy data |
| GET | `/server/contact` | Public | Contact form description and challenge |
| POST | `/server/contact` | Public | Submit a contact report |
| GET | `/server/help` | Public | Help content |
| GET | `/server/terms` | Public | Terms of service |
| GET | `/server/dpo` | Public | Data protection contact |

The same paths are under the versioned API base. `/api/healthz` is a direct health alias. `/api/swagger` is an alias for the OpenAPI document. GraphQL is available at `/api/v1/server/graphql` and the `/api/graphql` alias.

The metrics endpoint is configured by `server.metrics.endpoint` and, when enabled, requires its configured bearer token.

## Responses and limits

JSON responses use an `ok` boolean and a `data` or `error` member. Use the HTTP status code as the primary success or failure signal. Requests are rate limited by endpoint class; bulk operations also require operator authentication. Add `.txt` to a versioned endpoint path or send `Accept: text/plain` to request its plain-text representation. Errors remain JSON so clients retain the standard error envelope.

## Interactive documentation

- Swagger UI: `/server/docs/swagger`; its JavaScript and CSS assets are served locally, so the page does not depend on a third-party CDN
- OpenAPI JSON: `/api/v1/server/swagger` (also `/api/swagger`)
- GraphQL UI: `/server/docs/graphql`
- GraphQL POST: `/api/v1/server/graphql` (also `/api/graphql`)

## Command line client

The companion `caswhois-cli` client supports lookup, configuration, and interactive use. See [CLI Reference](cli.md) for its commands and options.
