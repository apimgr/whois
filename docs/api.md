# API Reference

caswhois exposes a versioned REST API, an OpenAPI document, a GraphQL
endpoint, and an MCP endpoint. Public WHOIS lookups do not require a token.
Bulk lookup and server-operation routes require the operator bearer token from
`secrets.yml`; MCP accepts an owner token or the operator token.

## Base URL and authentication

The public service API base is `https://caswhois.apimgr.dev/api/v1`. For a
service you operate, replace that origin with your server's URL. The configured
API version is exposed by the server.

```http
Authorization: Bearer <server-token>
```

Do not place a token in a URL or share it. The operator token is required for bulk lookup, scheduler operations, and backup operations. Anonymous requests to public lookup endpoints are rate limited.

## WHOIS lookups

| Method | Path | Access | Purpose |
|--------|------|--------|---------|
| GET | `https://caswhois.apimgr.dev/api/v1/whois/{query}` | Public | Detect and look up a domain, IP address, or ASN |
| GET | `https://caswhois.apimgr.dev/api/v1/whois/domain/{domain}` | Public | Domain lookup |
| GET | `https://caswhois.apimgr.dev/api/v1/whois/ip/{ip}` | Public | IPv4 or IPv6 lookup |
| GET | `https://caswhois.apimgr.dev/api/v1/whois/asn/{asn}` | Public | ASN lookup |
| GET | `https://caswhois.apimgr.dev/api/v1/whois/validate/{query}` | Public | Validate a query without looking it up |
| GET | `https://caswhois.apimgr.dev/api/v1/whois/search?owner={text}` | Public | Search the local registrant dataset |
| POST | `https://caswhois.apimgr.dev/api/v1/whois/bulk` | Operator | Look up a batch of queries |
| GET | `https://caswhois.apimgr.dev/api/v1/whois-servers` | Public | List known WHOIS servers |

Example:

```bash
curl -q -LSsf -H 'Accept: application/json' 'https://caswhois.apimgr.dev/api/v1/whois/example.com'
curl -q -LSsf -H 'Accept: application/json' 'https://caswhois.apimgr.dev/api/v1/whois/ip/2001:4860:4860::8888'
```

WHOIS retrieval prefers RDAP and falls back to WHOIS. Successful normalized records are retained in the local database. Upstream data is public registry data and may be incomplete or stale.

## Server endpoints

| Method | Path | Access | Purpose |
|--------|------|--------|---------|
| GET | `https://caswhois.apimgr.dev/api/v1/server/healthz` | Public | Health and build information |
| GET | `https://caswhois.apimgr.dev/api/v1/server/stats` | Public | Lookup and service statistics |
| GET | `https://caswhois.apimgr.dev/api/v1/server/schedulers` | Operator | Scheduler status |
| POST | `https://caswhois.apimgr.dev/api/v1/server/schedulers/run` | Operator | Trigger a scheduler task |
| GET | `https://caswhois.apimgr.dev/api/v1/server/backups` | Operator | Backup status |
| POST | `https://caswhois.apimgr.dev/api/v1/server/backups/run` | Operator | Trigger a backup |
| POST | `https://caswhois.apimgr.dev/api/v1/server/mcp` | Owner or operator | MCP Streamable HTTP endpoint; aliases: `/api/mcp`, `/mcp` |
| GET | `https://caswhois.apimgr.dev/api/v1/server/about` | Public | About-page content |
| GET | `https://caswhois.apimgr.dev/api/v1/server/privacy` | Public | Privacy policy data |
| GET, POST | `https://caswhois.apimgr.dev/api/v1/server/contact` | Public | Contact form descriptors and two-step submission |
| GET | `https://caswhois.apimgr.dev/api/v1/server/help` | Public | Help content |
| GET | `https://caswhois.apimgr.dev/api/v1/server/terms` | Public | Terms of service |
| GET | `https://caswhois.apimgr.dev/api/v1/server/dpo` | Public | Data protection contact |
| GET | `https://caswhois.apimgr.dev/api/v1/server/security` | Public | Security policy/contact data |
| GET | `https://caswhois.apimgr.dev/api/v1/server/security/policy` | Public | Security policy content |
| GET | `https://caswhois.apimgr.dev/api/v1/server/security/thanks` | Public | Disclosed-researcher acknowledgments |
| GET | `https://caswhois.apimgr.dev/api/v1/server/preferences/tokens` | Owner | List tokens belonging to the bearer token's owner |
| POST | `https://caswhois.apimgr.dev/api/v1/server/preferences/tokens/primary` | Public or owner | Create a primary owner token |
| POST | `https://caswhois.apimgr.dev/api/v1/server/preferences/tokens/primary/reveal` | Owner | Reveal the primary token once |
| POST | `https://caswhois.apimgr.dev/api/v1/server/preferences/tokens/primary/rotate` | Owner | Rotate the primary token |
| DELETE | `https://caswhois.apimgr.dev/api/v1/server/preferences/tokens/primary` | Owner | Revoke the primary token and its owner |
| POST | `https://caswhois.apimgr.dev/api/v1/server/preferences/tokens` | Owner | Create a linked token |
| POST | `https://caswhois.apimgr.dev/api/v1/server/preferences/tokens/{id}/reveal` | Owner | Reveal a linked token once |
| POST | `https://caswhois.apimgr.dev/api/v1/server/preferences/tokens/{id}/rotate` | Owner | Rotate a linked token |
| PATCH | `https://caswhois.apimgr.dev/api/v1/server/preferences/tokens/{id}` | Owner | Rename a linked token or change its expiry |
| DELETE | `https://caswhois.apimgr.dev/api/v1/server/preferences/tokens/{id}` | Owner | Revoke a linked token |
| GET, POST | `https://caswhois.apimgr.dev/api/v1/server/preferences` | Public | Read or update this browser's appearance, language, consent, and privacy preferences |
| GET | `https://caswhois.apimgr.dev/api/v1/server/preferences/sync` | Public | Export the current appearance, language, and privacy preferences as a URL and code |
| GET | `https://caswhois.apimgr.dev/api/v1/server/preferences/sync/import` | Public | Apply preferences supplied as query values or a sync code |

Preference updates accept JSON or form data. Only supported values are applied;
unknown or invalid values are returned in the `ignored` list. Updating a
preference requires the visitor to have granted preferences consent. Sync links contain the selected preferences and should be shared only with
the intended recipient.

The browser pages use unversioned paths such as `/server/healthz` and
`/server/contact`; their API counterparts use the versioned prefix shown in
the table. `/api/healthz` is a direct health alias. `/api/swagger` is an alias
for the OpenAPI document. GraphQL is available at `/api/v1/server/graphql`
and the `/api/graphql` alias. The API response does not honor cookies as
credentials.

### Contact and security reports

`GET /api/v1/server/contact` returns the public form description, available
report types, a CAPTCHA descriptor, and a signed `form_token`. Submit a report
with `step=submit` first; that response contains a review summary and a
single-use `review_token`, and does not deliver the report. Repeat the report
fields with `step=confirm`, the token, and `confirmed=true` to complete the
submission. Every submission needs a valid CAPTCHA at the first step.

Security submissions require a currently valid `security_id` supplied by
`/server/security` or `/.well-known/security.txt`. Their response includes a
tracking ID. When email is configured, the researcher receives a status link
at `/server/security/report/{tracking_id}?token={one-time-status-token}`. The
browser route exposes only the report's triage status, maintainer comment, and
expected disclosure date; it has no API mirror. Its query token is accepted
once per UTC day and expires 30 days after the report is closed.

## Model Context Protocol

MCP uses the same owner and operator bearer tokens as the REST API. Create a
linked owner token for each client at `/server/preferences/tokens`; token
management itself is never exposed as a tool. Each request is JSON-RPC 2.0
with `MCP-Protocol-Version: 2026-07-28` and a matching `Mcp-Method` header.
`tools/list` exposes the caller's available OpenAPI operations, and
`tools/call` dispatches through the matching API handler. The endpoint accepts
POST only, keeps no sessions, and validates browser `Origin` headers.

```bash
curl -q -LSsf -X POST https://caswhois.apimgr.dev/api/v1/server/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/list' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}'
```

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
[CLI Reference](cli.md) for its commands and options. Anonymous owner tokens can
be created, listed, revealed, rotated, and revoked through the server-rendered
`/server/preferences/tokens` page or the corresponding authenticated API routes.
The MCP endpoint is documented at `/server/help/mcp` and supports public and
operator tools according to the supplied bearer token.
