# Integrations

## Autodiscovery

`GET https://caswhois.apimgr.dev/api/autodiscover` provides service metadata
and the client release information used by the companion CLI updater. For a
self-hosted service, replace the official origin with your server's public URL.

```bash
curl -q -LSsf https://caswhois.apimgr.dev/api/autodiscover
```

## Health checks

The health handler is available at
`https://caswhois.apimgr.dev/server/healthz` and
`https://caswhois.apimgr.dev/api/v1/server/healthz`.
`https://caswhois.apimgr.dev/api/healthz` is an unversioned alias;
`https://caswhois.apimgr.dev/healthz` is available when enabled in
configuration. Browser requests to the web route
render HTML; send `Accept: application/json` or `Accept: text/plain` for
machine-readable JSON or text. Frontend text responses use the human-readable
health layout; API text responses use dotted keys. API JSON is the default.

The JSON response reports Tor and I2P lifecycle information under
`features.tor` and `features.i2p`, including whether each service is enabled,
running, its current state/status, and its published hostname when available.
When enabled, `checks.tor` and `checks.i2p` report `ok` or `degraded`; a
missing local Tor executable or unavailable I2P provider degrades that check
without stopping the HTTP server. Disabled features omit their component check.
Enabled GeoIP databases are listed as `geoip_asn`, `geoip_country`,
`geoip_city_ipv4`, and `geoip_city_ipv6` checks when configured. Dataset results
are cached and refreshed in the background at most once per minute and after a
successful data update. Missing or invalid data reports `error`; stale data
reports `degraded`. `unhealthy`, `maintenance`, and `shutting_down` responses
use HTTP 503, while healthy and degraded responses use HTTP 200.

## Metrics

Metrics are served at the configured `server.metrics.endpoint` when metrics
are enabled (default `/metrics`). When a metrics token is configured, send it
as a bearer token. Keep this endpoint on a trusted network and do not expose
operator credentials in scrape configuration.

## Well-known and crawler endpoints

| Path | Purpose |
|------|---------|
| `https://caswhois.apimgr.dev/.well-known/security.txt` | Security disclosure contacts |
| `https://caswhois.apimgr.dev/.well-known/llms.txt` and `https://caswhois.apimgr.dev/llms.txt` | Machine-readable service guidance |
| `https://caswhois.apimgr.dev/sitemap.xml` | Public page sitemap |
| `https://caswhois.apimgr.dev/robots.txt` | Crawler policy |

## API documentation

- Swagger UI: `https://caswhois.apimgr.dev/server/docs/swagger`
- OpenAPI JSON: `https://caswhois.apimgr.dev/api/v1/server/swagger` and `https://caswhois.apimgr.dev/api/swagger`
- GraphiQL: `https://caswhois.apimgr.dev/server/docs/graphql`
- GraphQL POST: `https://caswhois.apimgr.dev/api/v1/server/graphql` and `https://caswhois.apimgr.dev/api/graphql`
- GraphQL query GET: those same paths with `query`, optional JSON `variables`, and `operationName` parameters; GET is query-only
- Token validation: `GET https://caswhois.apimgr.dev/api/v1/server/auth/check`
  with a bearer token; the response reports only its kind
- Optional PGP key: `GET https://caswhois.apimgr.dev/.well-known/pgp-key.asc`
  (404 when no keypair exists)

## Progressive web app

The web interface can be installed from `/manifest.json`. Its service worker is served from `/sw.js` and uses a versioned cache for static assets. Navigation is network-first; a public, form-free page may be available offline after it has been visited online. Pages with forms, cookies, or visitor-specific content are not stored. When no cached public page is available, the worker renders a localized offline message. WHOIS lookups and other API requests remain online-only.

## WHOIS data sources

Lookup uses IANA RDAP bootstrap data when available, preferring public RDAP endpoints and falling back to WHOIS. The server does not accept a caller-supplied upstream server name. Upstream services can rate-limit or fail; cached data may be returned where available.

## Tor

The server attempts to start a Tor hidden service when the local `tor` binary
is available; missing Tor or a startup failure does not stop the HTTP server.
Health output reports `features.tor.status` as `starting`, `healthy`, or
`unavailable` while enabled, and reports `checks.tor` as `ok` or `degraded`.
Outbound WHOIS-over-Tor behavior is controlled by `server.tor.use_network`.
The MCP endpoint is available at `/api/v1/server/mcp` (with `/api/mcp` and
`/mcp` aliases). See [API Reference](api.md#model-context-protocol) and
`/server/help/mcp` for setup and tool details.

## I2P eepsite

I2P eepsite support is available through SAMv3. Enable `server.i2p.enabled`
to serve the same HTTP pages over I2P; set `server.i2p.expose` to publish its
`.b32.i2p` address in autodiscovery. The router must expose its SAM endpoint at
`server.i2p.sam_address` (default `127.0.0.1:7656`). The eepsite uses a
separate loopback listener and persistent destination data under `data_dir`.

## Bulk lookup

`POST /api/v1/whois/bulk` requires the operator bearer token. The batch limit and request body limits are enforced by the server. See [API Reference](api.md) for the request path and authentication format.
