# Integrations

## Machine-Readable Endpoints

### Autodiscovery

`GET /api/autodiscover` returns a JSON document describing the service capabilities. This endpoint is intended for automated clients and platform integrations that need to discover available API versions, endpoints, and features without prior configuration.

```bash
curl https://your-domain.com/api/autodiscover
```

```json
{
  "ok": true,
  "data": {
    "service": "caswhois",
    "version": "0.1.0",
    "api_versions": ["v1"],
    "endpoints": {
      "whois": "/api/v1/whois/{query}",
      "health": "/server/healthz",
      "metrics": "/metrics",
      "stats": "/api/v1/server/stats"
    },
    "features": {
      "geoip": true,
      "metrics": true,
      "email": false,
      "tor": false
    }
  }
}
```

### Health Check

`GET /server/healthz` returns structured health data for monitoring systems and load balancers. Also available at `/api/v1/server/healthz` and `/healthz`.

Content negotiation:

- `Accept: application/json` → JSON response
- `Accept: text/plain` → plain-text key=value response (suitable for shell scripts)
- Default (browser) → JSON

### Prometheus Metrics

`GET /metrics` exposes Prometheus-format metrics. Optionally token-protected via `metrics_token` in `server.yml`.

Scraped metrics include:

- HTTP request counters and latency histograms by method, path, and status
- System metrics: CPU usage, memory allocation
- Go runtime metrics: goroutines, GC pauses
- WHOIS-specific: total queries, domain/IP/ASN breakdown, cache hit ratio

### Well-Known Namespace

| Path | Standard | Purpose |
|------|---------|---------|
| `/.well-known/security.txt` | RFC 9116 | Security contact and disclosure policy |

### SEO Files

| Path | Purpose |
|------|---------|
| `/sitemap.xml` | XML sitemap for search engines |
| `/robots.txt` | Crawler directive file |

## Tor Hidden Service

When `tor_binary` is set in `server.yml` and the `tor` binary is available on PATH, caswhois automatically creates a v3 onion service on startup. The `.onion` address is logged at startup and persists across restarts (key stored in `{data_dir}/tor/`).

No additional configuration is required. The onion service forwards to the same HTTP listener as the clearnet service.

To enable:

```yaml
tor_binary: "/usr/bin/tor"
tor_use_network: true
```

## WHOIS Server List

`GET /api/v1/whois-servers` returns the list of WHOIS servers used by the lookup engine, organized by TLD and registry. Useful for auditing or building custom lookup tools.

## Bulk Lookup (Authenticated)

`POST /api/v1/whois/bulk` accepts up to 100 queries in a single request. Requires the server token:

```bash
curl -X POST https://your-domain.com/api/v1/whois/bulk \
  -H "Authorization: Bearer tok_xxx" \
  -H "Content-Type: application/json" \
  -d '{"queries": ["example.com", "8.8.8.8", "AS15169"]}'
```

## No Other Integrations

caswhois does not currently support:

- OAuth / OIDC provider or client
- WebSockets or server-sent events
- Webhooks
- Federation protocols
- Native app association files (Apple App Site Association, Android Asset Links)
- GraphQL

These are not part of the current feature set and have no planned implementation.
