package server

import (
	"html/template"
	"net/http"
)

// AboutPageData holds the dynamic data for the /about and /server/about pages.
// Content is sourced from branding config (which defaults to IDEA.md values) per AI.md PART 16.
type AboutPageData struct {
	Name        string
	Tagline     string
	Description string
	Version     string
	BuildDate   string
	OfficialSite string
}

// DocsPageData holds the dynamic data for the /docs and /server/docs pages.
type DocsPageData struct {
	Name        string
	Tagline     string
	APIVersion  string
	RateLimitRead int
	OfficialSite string
}

// aboutTmpl is the template for the /about page.
// Content sourced from branding config (defaults to IDEA.md values) per AI.md PART 16.
var aboutTmpl = template.Must(template.New("about").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="About {{.Name}} — {{.Tagline}}">
<title>About — {{.Name}}</title>
<link rel="stylesheet" href="/static/css/main.css">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#007bff">
<link rel="apple-touch-icon" href="/static/icons/icon-192.png">
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>
<a class="skip-link" href="#navigation">Skip to navigation</a>

<nav id="navigation" class="site-nav" aria-label="Site navigation">
  <div class="nav-inner">
    <a href="/" class="nav-brand" aria-label="{{.Name}} home">{{.Name}}</a>
    <ul class="nav-links" role="list">
      <li><a href="/about" aria-current="page">About</a></li>
      <li><a href="/docs">API Docs</a></li>
    </ul>
    <div class="nav-actions">
      <button id="theme-toggle" class="btn-theme" aria-label="Toggle colour scheme">
        <span class="icon-sun" aria-hidden="true">&#9788;</span>
        <span class="icon-moon" aria-hidden="true">&#9790;</span>
      </button>
    </div>
  </div>
</nav>

<main id="main-content">
  <header class="page-header">
    <div class="container">
      <h1>About {{.Name}}</h1>
      <p class="tagline">{{.Tagline}}</p>
    </div>
  </header>

  <div class="container about-content">

    <section class="card" aria-labelledby="about-description">
      <h2 id="about-description">About</h2>
      <p>{{.Description}}</p>
    </section>

    <section class="card" aria-labelledby="who-uses">
      <h2 id="who-uses">Who uses {{.Name}}?</h2>
      <ul class="check-list">
        <li><strong>Sysadmins &amp; network engineers</strong> — investigate IP ownership, routing, and registrar details quickly.</li>
        <li><strong>Security researchers</strong> — gather reconnaissance data on domains and infrastructure.</li>
        <li><strong>Domain investors</strong> — check registration and expiry dates before acquisition.</li>
        <li><strong>Developers</strong> — integrate WHOIS data into scripts and applications via the REST API.</li>
      </ul>
    </section>

    <section class="card" aria-labelledby="features">
      <h2 id="features">Features</h2>
      <div class="feature-grid">
        <div class="feature-card">
          <h3>Domain WHOIS</h3>
          <p>Registrar, registrant, name servers, creation date, expiry, and status for any registered domain.</p>
        </div>
        <div class="feature-card">
          <h3>IP WHOIS</h3>
          <p>Network block ownership, CIDR notation, RIR assignment data for IPv4 and IPv6 addresses.</p>
        </div>
        <div class="feature-card">
          <h3>ASN WHOIS</h3>
          <p>Autonomous system name, description, and routing policy for any AS number.</p>
        </div>
        <div class="feature-card">
          <h3>Multi-format output</h3>
          <p>JSON, XML, and plain text — all via content negotiation or a <code>?format=</code> parameter.</p>
        </div>
        <div class="feature-card">
          <h3>Caching</h3>
          <p>In-memory cache with per-type TTLs: 24 h for domains, 7 days for IPs and ASNs.</p>
        </div>
        <div class="feature-card">
          <h3>Rate limiting</h3>
          <p>60 requests/minute for anonymous callers; higher limits for authenticated API tokens.</p>
        </div>
      </div>
    </section>

    <section class="card" aria-labelledby="tech-stack">
      <h2 id="tech-stack">Technology</h2>
      <ul class="check-list">
        <li><strong>Go</strong> — single static binary, zero runtime dependencies, CGO disabled.</li>
        <li><strong>SQLite</strong> — embedded database for caching metadata and audit logs.</li>
        <li><strong>Built-in scheduler</strong> — GeoIP updates, token cleanup, log rotation, and backups — no external cron required.</li>
        <li><strong>Docker</strong> — multi-arch images for linux/amd64 and linux/arm64.</li>
        <li><strong>MIT licence</strong> — free for any use, commercial or otherwise.</li>
      </ul>
    </section>

    <nav class="about-nav" aria-label="Page navigation">
      <a href="/" class="btn-primary">New lookup</a>
      <a href="/docs" class="btn-secondary">API documentation</a>
    </nav>

  </div>
</main>

<footer class="site-footer">
  <p>
    <a href="/">{{.Name}}</a> &mdash;
    <a href="/about">About</a> &middot;
    <a href="/docs">API Docs</a> &middot;
    <a href="/server/healthz">Health</a>
  </p>
</footer>

<script src="/static/js/main.js" defer></script>
</body>
</html>`))

// docsTmpl is the template for the /docs API documentation page.
var docsTmpl = template.Must(template.New("docs").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="{{.Name}} REST API documentation — endpoints, authentication, and response formats.">
<title>API Documentation — {{.Name}}</title>
<link rel="stylesheet" href="/static/css/main.css">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#007bff">
<link rel="apple-touch-icon" href="/static/icons/icon-192.png">
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>
<a class="skip-link" href="#navigation">Skip to navigation</a>

<nav id="navigation" class="site-nav" aria-label="Site navigation">
  <div class="nav-inner">
    <a href="/" class="nav-brand" aria-label="{{.Name}} home">{{.Name}}</a>
    <ul class="nav-links" role="list">
      <li><a href="/about">About</a></li>
      <li><a href="/docs" aria-current="page">API Docs</a></li>
    </ul>
    <div class="nav-actions">
      <button id="theme-toggle" class="btn-theme" aria-label="Toggle colour scheme">
        <span class="icon-sun" aria-hidden="true">&#9788;</span>
        <span class="icon-moon" aria-hidden="true">&#9790;</span>
      </button>
    </div>
  </div>
</nav>

<main id="main-content">
  <header class="page-header">
    <div class="container">
      <h1>{{.Name}} API Documentation</h1>
      <p>RESTful WHOIS API — all endpoints are free, rate-limited, and require no account.</p>
    </div>
  </header>

  <div class="container docs-layout">

    <aside class="docs-toc" aria-label="Table of contents">
      <nav>
        <p class="toc-heading">Contents</p>
        <ul>
          <li><a href="#base-url">Base URL</a></li>
          <li><a href="#auth">Authentication</a></li>
          <li><a href="#formats">Response Formats</a></li>
          <li><a href="#endpoints">Endpoints</a></li>
          <li><a href="#response-schema">Response Schema</a></li>
          <li><a href="#rate-limits">Rate Limits</a></li>
          <li><a href="#errors">Error Codes</a></li>
        </ul>
      </nav>
    </aside>

    <article class="docs-body">

      <section class="card" id="base-url" aria-labelledby="h-base-url">
        <h2 id="h-base-url">Base URL</h2>
        <pre class="code-block"><code>/api/{{.APIVersion}}</code></pre>
        <p>All API endpoints are versioned and prefixed with <code>/api/{{.APIVersion}}</code>.</p>
      </section>

      <section class="card" id="auth" aria-labelledby="h-auth">
        <h2 id="h-auth">Authentication</h2>
        <p>
          Most endpoints are public and require no authentication. Bulk lookups and
          server operations require a server token passed as a bearer header.
        </p>
        <pre class="code-block"><code>Authorization: Bearer tok_&lt;your-token&gt;</code></pre>
        <p>
          The server token is auto-generated on first run and written to
          <code>server.yml</code>. No user accounts or sessions are involved.
        </p>
      </section>

      <section class="card" id="formats" aria-labelledby="h-formats">
        <h2 id="h-formats">Response Formats</h2>
        <p>
          Format is determined by the <code>Accept</code> header or the
          <code>?format=</code> query parameter. JSON is the default.
        </p>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Format</th><th>Accept header</th><th>Query param</th></tr>
            </thead>
            <tbody>
              <tr><td>JSON (default)</td><td><code>application/json</code></td><td><code>?format=json</code></td></tr>
              <tr><td>XML</td><td><code>application/xml</code></td><td><code>?format=xml</code></td></tr>
              <tr><td>Plain text</td><td><code>text/plain</code></td><td><code>?format=text</code></td></tr>
              <tr><td>HTML</td><td><code>text/html</code></td><td><code>?format=html</code></td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card" id="endpoints" aria-labelledby="h-endpoints">
        <h2 id="h-endpoints">Endpoints</h2>

        <div class="endpoint">
          <div class="endpoint-header">
            <span class="method method-get">GET</span>
            <code class="endpoint-path long-string">/server/healthz</code>
          </div>
          <p class="endpoint-desc">Health check. Returns service status, version, uptime, and feature flags. No auth required.</p>
        </div>

        <div class="endpoint">
          <div class="endpoint-header">
            <span class="method method-get">GET</span>
            <code class="endpoint-path long-string">/api/v1/whois/{query}</code>
          </div>
          <p class="endpoint-desc">Generic WHOIS lookup — auto-detects query type (domain, IPv4, IPv6, or ASN).</p>
          <pre class="code-block"><code>GET /api/v1/whois/example.com
GET /api/v1/whois/8.8.8.8
GET /api/v1/whois/AS15169</code></pre>
        </div>

        <div class="endpoint">
          <div class="endpoint-header">
            <span class="method method-get">GET</span>
            <code class="endpoint-path long-string">/api/v1/whois/domain/{domain}</code>
          </div>
          <p class="endpoint-desc">Domain-specific WHOIS lookup. Returns registrar, registrant, name servers, dates, and status.</p>
          <pre class="code-block"><code>GET /api/v1/whois/domain/github.com</code></pre>
        </div>

        <div class="endpoint">
          <div class="endpoint-header">
            <span class="method method-get">GET</span>
            <code class="endpoint-path long-string">/api/v1/whois/ip/{ip}</code>
          </div>
          <p class="endpoint-desc">IP address WHOIS lookup. Accepts IPv4 and IPv6.</p>
          <pre class="code-block"><code>GET /api/v1/whois/ip/1.1.1.1
GET /api/v1/whois/ip/2001:4860:4860::8888</code></pre>
        </div>

        <div class="endpoint">
          <div class="endpoint-header">
            <span class="method method-get">GET</span>
            <code class="endpoint-path long-string">/api/v1/whois/asn/{asn}</code>
          </div>
          <p class="endpoint-desc">ASN WHOIS lookup. Use the <code>AS</code> prefix.</p>
          <pre class="code-block"><code>GET /api/v1/whois/asn/AS13335</code></pre>
        </div>

        <div class="endpoint">
          <div class="endpoint-header">
            <span class="method method-get">GET</span>
            <code class="endpoint-path long-string">/api/v1/whois/validate/{query}</code>
          </div>
          <p class="endpoint-desc">Validate a query without performing the lookup. Returns detected type and validity.</p>
          <pre class="code-block"><code>GET /api/v1/whois/validate/example.com

{
  "ok": true,
  "data": {
    "query": "example.com",
    "valid": true,
    "type": "domain"
  }
}</code></pre>
        </div>

        <div class="endpoint">
          <div class="endpoint-header">
            <span class="method method-post">POST</span>
            <code class="endpoint-path long-string">/api/v1/whois/bulk</code>
            <span class="auth-badge">auth required</span>
          </div>
          <p class="endpoint-desc">Bulk WHOIS lookup — up to 100 queries in a single request. Requires server token.</p>
          <pre class="code-block"><code>POST /api/v1/whois/bulk
Authorization: Bearer tok_&lt;server-token&gt;
Content-Type: application/json

{
  "queries": ["example.com", "8.8.8.8", "AS15169"]
}</code></pre>
        </div>

        <div class="endpoint">
          <div class="endpoint-header">
            <span class="method method-get">GET</span>
            <code class="endpoint-path long-string">/api/v1/whois-servers</code>
          </div>
          <p class="endpoint-desc">List all configured WHOIS servers by TLD and IP range.</p>
        </div>

        <div class="endpoint">
          <div class="endpoint-header">
            <span class="method method-get">GET</span>
            <code class="endpoint-path long-string">/api/v1/server/stats</code>
          </div>
          <p class="endpoint-desc">Service statistics — total queries, cache hit rate, uptime, and per-type breakdown.</p>
        </div>

      </section>

      <section class="card" id="response-schema" aria-labelledby="h-schema">
        <h2 id="h-schema">Response Schema</h2>

        <h3>Success</h3>
        <pre class="code-block"><code>{
  "ok": true,
  "data": {
    "query":     "example.com",
    "type":      "domain",
    "server":    "whois.iana.org",
    "timestamp": "2026-05-28T14:00:00Z",
    "raw":       "Domain Name: EXAMPLE.COM\n..."
  }
}</code></pre>

        <h3>Error</h3>
        <pre class="code-block"><code>{
  "ok":      false,
  "error":   "VALIDATION_FAILED",
  "message": "Invalid domain format"
}</code></pre>
      </section>

      <section class="card" id="rate-limits" aria-labelledby="h-rate">
        <h2 id="h-rate">Rate Limits</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Caller</th><th>Limit</th></tr>
            </thead>
            <tbody>
              <tr><td>Anonymous (read)</td><td>{{.RateLimitRead}} requests / minute</td></tr>
              <tr><td>Authenticated (server token)</td><td>Higher limits — no account required</td></tr>
            </tbody>
          </table>
        </div>
        <p>Rate-limited responses use HTTP 429 with <code>Retry-After</code> header.</p>
      </section>

      <section class="card" id="errors" aria-labelledby="h-errors">
        <h2 id="h-errors">Error Codes</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Code</th><th>HTTP status</th><th>Meaning</th></tr>
            </thead>
            <tbody>
              <tr><td><code>BAD_REQUEST</code></td><td>400</td><td>Malformed request or missing parameter.</td></tr>
              <tr><td><code>VALIDATION_FAILED</code></td><td>400</td><td>Query failed format validation.</td></tr>
              <tr><td><code>UNAUTHORIZED</code></td><td>401</td><td>Token required but not provided.</td></tr>
              <tr><td><code>FORBIDDEN</code></td><td>403</td><td>Token present but lacks permission.</td></tr>
              <tr><td><code>NOT_FOUND</code></td><td>404</td><td>Resource does not exist.</td></tr>
              <tr><td><code>RATE_LIMITED</code></td><td>429</td><td>Too many requests — back off and retry.</td></tr>
              <tr><td><code>SERVER_ERROR</code></td><td>500</td><td>Internal error — WHOIS server unreachable or unexpected failure.</td></tr>
              <tr><td><code>MAINTENANCE</code></td><td>503</td><td>Service temporarily unavailable.</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <nav style="margin-top:0.5rem">
        <a href="/" class="btn-primary-inline">New lookup &rarr;</a>
      </nav>

    </article>
  </div>
</main>

<footer class="site-footer">
  <p>
    <a href="/">{{.Name}}</a> &mdash;
    <a href="/about">About</a> &middot;
    <a href="/docs">API Docs</a> &middot;
    <a href="/server/healthz">Health</a>
  </p>
</footer>

<script src="/static/js/main.js" defer></script>
</body>
</html>`))

// handleAboutPage serves the about page.
// Content is sourced from branding config (defaults to IDEA.md values) per AI.md PART 16.
// GET /about, /server/about
func (s *Server) handleAboutPage(w http.ResponseWriter, r *http.Request) {
	name := s.config.BrandingTitle
	if name == "" {
		name = "caswhois"
	}
	tagline := s.config.BrandingTagline
	if tagline == "" {
		tagline = "Self-hosted WHOIS lookup service"
	}
	description := s.config.BrandingDescription
	if description == "" {
		description = "caswhois is a self-hosted WHOIS lookup service for domain names, IP addresses, and ASNs."
	}
	data := AboutPageData{
		Name:         name,
		Tagline:      tagline,
		Description:  description,
		Version:      Version,
		BuildDate:    BuildDate,
		OfficialSite: s.config.FQDN,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := aboutTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleDocsPage serves the API documentation page.
// Content uses branding config and live config values (rate limits, API version) per AI.md PART 16.
// GET /docs, /server/docs
func (s *Server) handleDocsPage(w http.ResponseWriter, r *http.Request) {
	name := s.config.BrandingTitle
	if name == "" {
		name = "caswhois"
	}
	data := DocsPageData{
		Name:          name,
		Tagline:       s.config.BrandingTagline,
		APIVersion:    "v1",
		RateLimitRead: s.config.RateLimit.Read.Requests,
		OfficialSite:  s.config.FQDN,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := docsTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}
