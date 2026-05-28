package server

import (
	"html/template"
	"net/http"
)

// aboutTmpl is the template for the /about page.
// Content sourced from IDEA.md per AI.md PART 16.
var aboutTmpl = template.Must(template.New("about").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="About caswhois — a WHOIS lookup service for domains, IP addresses, and ASNs.">
<title>About — caswhois</title>
<style>` + sharedCSS + aboutExtraCSS + `</style>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>

<nav class="site-nav" aria-label="Site navigation">
  <div class="nav-inner">
    <a href="/" class="nav-brand" aria-label="caswhois home">caswhois</a>
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
      <h1>About caswhois</h1>
      <p>A WHOIS lookup service that provides comprehensive information about domain names,
         IP addresses, and ASN (Autonomous System Numbers).</p>
    </div>
  </header>

  <div class="container about-content">

    <section class="card" aria-labelledby="what-is-whois">
      <h2 id="what-is-whois">What is WHOIS?</h2>
      <p>
        WHOIS is a query-and-response protocol used to query databases that store the registered
        users or assignees of an Internet resource — domain names, IP address blocks, and
        autonomous system numbers (ASNs).
      </p>
      <p>
        caswhois provides a fast, reliable interface to query WHOIS data from registrars and
        Regional Internet Registries (RIRs) worldwide, with built-in caching, rate limiting,
        and multi-format output.
      </p>
    </section>

    <section class="card" aria-labelledby="who-uses">
      <h2 id="who-uses">Who uses caswhois?</h2>
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
    <a href="/">caswhois</a> &mdash;
    <a href="/about">About</a> &middot;
    <a href="/docs">API Docs</a> &middot;
    <a href="/server/healthz">Health</a>
  </p>
</footer>

<style>.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border-width:0}</style>
<script>` + themeToggleJS + `</script>
</body>
</html>`))

// aboutExtraCSS contains styles specific to the about page.
const aboutExtraCSS = `
.about-content{
  display:flex;flex-direction:column;gap:1.5rem;
  padding-bottom:2rem;
}
.about-content .card{margin:0}
.check-list{list-style:none;padding:0;display:flex;flex-direction:column;gap:0.5rem}
.check-list li{padding-left:1.5rem;position:relative;color:var(--fg-muted);line-height:1.6}
.check-list li::before{
  content:"✓";position:absolute;left:0;
  color:var(--color-success-fg);font-weight:700;
}
.feature-grid{
  display:grid;grid-template-columns:1fr;gap:1rem;margin-top:1rem;
}
.feature-card{
  background:var(--bg-subtle);border:1px solid var(--border);
  border-radius:6px;padding:1rem;
  border-left:3px solid var(--accent);
}
.feature-card h3{font-size:1rem;font-weight:600;margin-bottom:0.375rem}
.feature-card p{font-size:0.9375rem;color:var(--fg-muted);margin:0;line-height:1.5}
.feature-card code{
  font-family:'SF Mono','Fira Code',monospace;font-size:0.875em;
  background:var(--bg-inset);color:var(--fg);padding:0.125rem 0.375rem;border-radius:4px;
}
.about-nav{
  display:flex;flex-wrap:wrap;gap:0.75rem;
  padding-top:0.5rem;
}
.btn-secondary{
  padding:0.75rem 1.5rem;font-size:1rem;font-weight:600;
  font-family:inherit;cursor:pointer;min-height:44px;
  background:var(--bg-elevated);color:var(--accent);
  border:1px solid var(--accent);border-radius:6px;
  text-decoration:none;display:inline-flex;align-items:center;
  transition:background 150ms,color 150ms;
}
.btn-secondary:hover{background:var(--accent-subtle)}
.about-nav .btn-primary{text-decoration:none;display:inline-flex;align-items:center}
@media(min-width:768px){
  .feature-grid{grid-template-columns:repeat(2,1fr)}
  .about-content{padding-top:0.5rem}
}
@media(min-width:1024px){
  .feature-grid{grid-template-columns:repeat(3,1fr)}
}
`

// docsTmpl is the template for the /docs API documentation page.
var docsTmpl = template.Must(template.New("docs").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="caswhois REST API documentation — endpoints, authentication, and response formats.">
<title>API Documentation — caswhois</title>
<style>` + sharedCSS + docsExtraCSS + `</style>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>

<nav class="site-nav" aria-label="Site navigation">
  <div class="nav-inner">
    <a href="/" class="nav-brand" aria-label="caswhois home">caswhois</a>
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
      <h1>API Documentation</h1>
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
        <pre class="code-block"><code>/api/v1</code></pre>
        <p>All API endpoints are versioned and prefixed with <code>/api/v1</code>.</p>
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
              <tr><td>Anonymous</td><td>60 requests / minute</td></tr>
              <tr><td>Authenticated (server token)</td><td>600 requests / minute</td></tr>
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
    <a href="/">caswhois</a> &mdash;
    <a href="/about">About</a> &middot;
    <a href="/docs">API Docs</a> &middot;
    <a href="/server/healthz">Health</a>
  </p>
</footer>

<style>.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border-width:0}</style>
<script>` + themeToggleJS + `</script>
</body>
</html>`))

// docsExtraCSS contains styles specific to the docs page.
const docsExtraCSS = `
.docs-layout{
  display:flex;flex-direction:column;gap:1.5rem;
  padding-bottom:2.5rem;
}
.docs-toc{
  background:var(--bg-elevated);border:1px solid var(--border);border-radius:8px;
  padding:1.25rem;align-self:start;
}
.toc-heading{
  font-size:0.75rem;font-weight:600;text-transform:uppercase;
  letter-spacing:.06em;color:var(--fg-muted);margin-bottom:0.75rem;
}
.docs-toc ul{list-style:none;display:flex;flex-direction:column;gap:0.25rem}
.docs-toc a{
  font-size:0.9375rem;color:var(--fg-muted);text-decoration:none;
  display:block;padding:0.25rem 0;transition:color 150ms;
}
.docs-toc a:hover{color:var(--accent)}
.docs-body{display:flex;flex-direction:column;gap:1.5rem;min-width:0}
.docs-body .card{margin:0}
.docs-body h2{font-size:1.375rem;font-weight:700;margin-bottom:1rem}
.docs-body h3{font-size:1rem;font-weight:600;margin:1rem 0 0.5rem}
.docs-body p{color:var(--fg-muted);line-height:1.65;margin-bottom:0.75rem}
.docs-body p:last-child{margin-bottom:0}
.code-block{
  background:var(--bg-inset);color:var(--fg);
  border:1px solid var(--border);border-radius:6px;
  padding:0.875rem 1rem;overflow-x:auto;
  font-family:'SF Mono','Fira Code','Fira Mono',monospace;
  font-size:0.8125rem;line-height:1.65;
  white-space:pre;word-break:normal;
  margin:0.75rem 0;
}
.code-block code{background:none;padding:0;color:inherit;font-size:inherit}
.docs-body code{
  font-family:'SF Mono','Fira Code',monospace;font-size:0.875em;
  background:var(--bg-inset);color:var(--fg);
  padding:0.125rem 0.375rem;border-radius:4px;
}
.endpoint{
  border:1px solid var(--border);border-radius:6px;
  padding:1rem;margin-bottom:1rem;
  border-left:3px solid var(--accent);
  background:var(--bg-subtle);
}
.endpoint:last-child{margin-bottom:0}
.endpoint-header{display:flex;flex-wrap:wrap;align-items:center;gap:0.5rem;margin-bottom:0.5rem}
.method{
  display:inline-flex;align-items:center;
  padding:0.125rem 0.5rem;border-radius:4px;
  font-size:0.75rem;font-weight:700;letter-spacing:.04em;flex-shrink:0;
}
.method-get{background:var(--color-success-bg);color:var(--color-success-fg)}
.method-post{background:var(--color-info-bg);color:var(--color-info-fg)}
.endpoint-path{
  font-family:'SF Mono','Fira Code',monospace;font-size:0.9375rem;
  color:var(--fg);word-break:break-all;background:none;padding:0;
}
.endpoint-desc{color:var(--fg-muted);font-size:0.9375rem;margin:0.25rem 0 0.5rem}
.auth-badge{
  font-size:0.75rem;font-weight:600;
  padding:0.125rem 0.5rem;border-radius:4px;
  background:var(--color-warning-bg);color:var(--color-warning-fg);
}
.table-wrap{overflow-x:auto;margin:0.75rem 0}
table{width:100%;border-collapse:collapse;font-size:0.9375rem}
th,td{text-align:left;padding:0.625rem 0.75rem;border-bottom:1px solid var(--border)}
th{background:var(--bg-subtle);color:var(--fg);font-weight:600}
td{color:var(--fg-muted)}
td code{font-size:0.875em}
.btn-primary-inline{
  display:inline-flex;align-items:center;
  padding:0.625rem 1.25rem;font-size:0.9375rem;font-weight:600;
  background:var(--accent);color:var(--fg-on-accent);
  border-radius:6px;text-decoration:none;transition:background 150ms;
}
.btn-primary-inline:hover{background:var(--accent-hover);color:var(--fg-on-accent)}
@media(min-width:1024px){
  .docs-layout{flex-direction:row;align-items:flex-start}
  .docs-toc{width:14rem;flex-shrink:0;position:sticky;top:1rem}
  .docs-body{flex:1}
}
`

// handleAboutPage serves the about page.
// GET /about, /server/about
func (s *Server) handleAboutPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := aboutTmpl.Execute(w, nil); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleDocsPage serves the API documentation page.
// GET /docs, /server/docs
func (s *Server) handleDocsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := docsTmpl.Execute(w, nil); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}
