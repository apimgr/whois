# Integrations

## Autodiscovery

`GET /api/autodiscover` provides service metadata and the client release information used by the companion CLI updater.

```bash
curl https://whois.example.net/api/autodiscover
```

## Health checks

The health handler is available at `/server/healthz` and `/api/v1/server/healthz`. `/api/healthz` is an unversioned alias; `/healthz` is available when enabled in configuration. JSON is the default response. Send `Accept: text/plain` for a text response.

## Metrics

Metrics are served at the configured `server.metrics.endpoint` when metrics are enabled. When a metrics token is configured, send it as a bearer token. Keep this endpoint on a trusted network and do not expose operator credentials in scrape configuration.

## Well-known and crawler endpoints

| Path | Purpose |
|------|---------|
| `/.well-known/security.txt` | Security disclosure contacts |
| `/.well-known/llms.txt` and `/llms.txt` | Machine-readable service guidance |
| `/sitemap.xml` | Public page sitemap |
| `/robots.txt` | Crawler policy |

## WHOIS data sources

Lookup uses IANA RDAP bootstrap data when available, preferring public RDAP endpoints and falling back to WHOIS. The server does not accept a caller-supplied upstream host. Upstream services can rate-limit or fail; cached data may be returned where available.

## Tor

Tor support is optional. When configured and available, the service can publish an onion address. It shares the WHOIS API and web interface; see `server.tor` in the generated configuration and the service's help page for current status.

## Bulk lookup

`POST /api/v1/whois/bulk` requires the operator bearer token. The batch limit and request body limits are enforced by the server. See [API Reference](api.md) for the request path and authentication format.
