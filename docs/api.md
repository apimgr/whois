# API Reference

## Overview

CASWHOIS provides three API interfaces:

1. **REST API** - Standard HTTP endpoints
2. **OpenAPI/Swagger** - Interactive documentation and testing
3. **GraphQL** - Flexible query interface

All three APIs provide the same functionality with different access patterns.

## Base URL

```
https://your-domain.com/api/v1
```

## Authentication

### API Tokens

API tokens are required for most endpoints. Tokens are prefixed by type:

| Prefix | Type | Access Level |
|--------|------|--------------|
| `adm_` | Admin token | Full server access |
| `usr_` | User token | User-specific access |
| `org_` | Organization token | Org-specific access |

**Authentication Header:**

```http
Authorization: Bearer adm_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

### Token Management

Create tokens via the admin panel or API:

```http
POST /api/v1/admin/tokens
Content-Type: application/json
Authorization: Bearer {existing_token}

{
  "name": "ci-cd",
  "scope": "read-write",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

## REST API

### WHOIS Endpoints

#### Lookup Domain

```http
GET /api/v1/whois/domain/{domain}
```

**Example:**

```bash
curl https://your-domain.com/api/v1/whois/domain/example.com
```

**Response:**

```json
{
  "success": true,
  "data": {
    "query": "example.com",
    "type": "domain",
    "server": "whois.verisign-grs.com",
    "timestamp": "2025-02-05T16:00:00Z",
    "raw": "Domain Name: EXAMPLE.COM\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN\n..."
  }
}
```

#### Lookup IP Address

```http
GET /api/v1/whois/ip/{ip}
```

**Example:**

```bash
curl https://your-domain.com/api/v1/whois/ip/8.8.8.8
```

#### Lookup ASN

```http
GET /api/v1/whois/asn/{asn}
```

**Example:**

```bash
curl https://your-domain.com/api/v1/whois/asn/AS15169
```

#### Auto-detect Query Type

```http
GET /api/v1/whois/{query}
```

Automatically detects whether the query is a domain, IP, or ASN.

### Admin Endpoints

#### Server Status

```http
GET /api/v1/admin/server/status
Authorization: Bearer adm_...
```

#### Backup Management

```http
POST /api/v1/admin/server/backup
Authorization: Bearer adm_...

{
  "type": "full",
  "encrypt": true
}
```

#### System Settings

```http
GET /api/v1/admin/server/settings
PUT /api/v1/admin/server/settings
Authorization: Bearer adm_...
```

### Health Check

```http
GET /healthz
GET /api/v1/healthz
```

Returns server health status. No authentication required.

**Response:**

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "go_version": "go1.21.0",
  "build_date": "Mon Feb 05, 2025 at 16:00:00 UTC",
  "uptime": "24h30m15s",
  "features": {
    "multi_user": false,
    "organizations": false,
    "tor": {
      "enabled": true,
      "running": true,
      "status": "healthy",
      "hostname": "abcd1234efgh5678.onion"
    },
    "geoip": true,
    "metrics": true
  },
  "checks": {
    "database": "healthy",
    "cache": "healthy",
    "disk": "healthy",
    "scheduler": "healthy"
  },
  "stats": {
    "requests_total": 12345,
    "requests_24h": 890,
    "active_connections": 5
  }
}
```

## OpenAPI/Swagger

### Interactive Documentation

Visit `https://your-domain.com/openapi` for interactive API documentation.

The Swagger UI allows you to:

- Browse all endpoints
- View request/response schemas
- Test API calls directly
- Download OpenAPI specification

### OpenAPI Specification

```http
GET /openapi.json
```

Download the complete OpenAPI 3.0 specification.

## GraphQL

### GraphQL Endpoint

```http
POST /graphql
Content-Type: application/json
```

### GraphQL Playground

Visit `https://your-domain.com/graphql` for the interactive GraphQL playground.

### Example Queries

#### Query Domain WHOIS

```graphql
query {
  whois(query: "example.com", type: DOMAIN) {
    success
    data {
      query
      type
      server
      timestamp
      raw
    }
  }
}
```

#### Query Server Status

```graphql
query {
  serverStatus {
    status
    version
    uptime
    features {
      tor {
        enabled
        running
        hostname
      }
    }
  }
}
```

#### Mutation: Create Backup

```graphql
mutation {
  createBackup(input: {
    type: FULL
    encrypt: true
  }) {
    success
    path
    size
  }
}
```

## Response Formats

### Success Response

```json
{
  "success": true,
  "data": { ... }
}
```

### Error Response

```json
{
  "success": false,
  "error": {
    "code": "INVALID_DOMAIN",
    "message": "The provided domain is invalid"
  }
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `INVALID_QUERY` | Query format is invalid |
| `RATE_LIMIT_EXCEEDED` | Too many requests |
| `UNAUTHORIZED` | Missing or invalid authentication |
| `FORBIDDEN` | Insufficient permissions |
| `NOT_FOUND` | Resource not found |
| `SERVER_ERROR` | Internal server error |

## Rate Limiting

Default rate limits:

- **Anonymous requests:** 30/minute
- **Authenticated requests:** 60/minute
- **Admin requests:** 120/minute

Rate limit headers:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1612553400
```

## Content Negotiation

The API supports multiple response formats:

```http
Accept: application/json     # JSON (default)
Accept: application/xml      # XML
Accept: text/plain           # Plain text
```

## Pagination

List endpoints support pagination:

```http
GET /api/v1/resource?limit=20&offset=40
```

**Response:**

```json
{
  "success": true,
  "data": [...],
  "pagination": {
    "total": 150,
    "limit": 20,
    "offset": 40,
    "has_more": true
  }
}
```

## Filtering and Sorting

```http
GET /api/v1/resource?filter=status:active&sort=created_at:desc
```

## Webhooks

Configure webhooks to receive notifications:

```http
POST /api/v1/admin/webhooks
Authorization: Bearer adm_...

{
  "url": "https://your-app.com/webhook",
  "events": ["whois.lookup", "backup.completed"],
  "secret": "your-webhook-secret"
}
```

## Client Libraries

### CLI Client

```bash
caswhois-cli domain example.com --server https://your-domain.com
```

### HTTP Clients

```bash
# curl
curl -H "Authorization: Bearer adm_..." \
  https://your-domain.com/api/v1/whois/domain/example.com

# httpie
http https://your-domain.com/api/v1/whois/domain/example.com \
  Authorization:"Bearer adm_..."
```

### Programming Languages

```python
# Python
import requests

response = requests.get(
    'https://your-domain.com/api/v1/whois/domain/example.com',
    headers={'Authorization': 'Bearer adm_...'}
)
data = response.json()
```

```javascript
// JavaScript
const response = await fetch(
  'https://your-domain.com/api/v1/whois/domain/example.com',
  {
    headers: {
      'Authorization': 'Bearer adm_...'
    }
  }
);
const data = await response.json();
```

```go
// Go
req, _ := http.NewRequest("GET", 
  "https://your-domain.com/api/v1/whois/domain/example.com", nil)
req.Header.Set("Authorization", "Bearer adm_...")
resp, _ := http.DefaultClient.Do(req)
```

## API Versioning

The API uses URL-based versioning: `/api/v1/`

Major version changes (v1 → v2) indicate breaking changes. Minor updates maintain backwards compatibility.

## Best Practices

1. **Always include User-Agent** - Helps identify your application
2. **Handle rate limits** - Implement exponential backoff
3. **Cache responses** - Respect Cache-Control headers
4. **Use HTTPS** - Never send tokens over HTTP
5. **Rotate tokens regularly** - Create new tokens periodically
6. **Monitor token usage** - Check last_used_at timestamp

## Support

- **Interactive Docs:** [https://your-domain.com/openapi](https://your-domain.com/openapi)
- **GraphQL Playground:** [https://your-domain.com/graphql](https://your-domain.com/graphql)
- **GitHub Issues:** Report bugs and feature requests
