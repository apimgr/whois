package server

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/casapps/caswhois/src/whois"
)

// homepageTmpl is the template for the WHOIS homepage (/).
var homepageTmpl = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Look up domain names, IP addresses, and ASN information — fast, free, and accurate.">
<title>caswhois — WHOIS Lookup</title>
<link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>
<a class="skip-link" href="#navigation">Skip to navigation</a>

<nav id="navigation" class="site-nav" aria-label="Site navigation">
  <div class="nav-inner">
    <a href="/" class="nav-brand" aria-label="caswhois home">caswhois</a>
    <ul class="nav-links" role="list">
      <li><a href="/about">About</a></li>
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
  <section class="search-section" aria-labelledby="search-heading">
    <div class="container">
      <div class="card search-card">
        <div class="search-hero">
          <h1 id="search-heading">WHOIS Lookup</h1>
          <p>Query domain names, IP addresses, and autonomous system numbers.</p>
        </div>

        <form id="whois-form" class="search-form-wrap" action="/whois" method="GET" novalidate>
          <div class="search-row">
            <label for="q" class="sr-only">Query — domain, IP address, or ASN</label>
            <input
              id="q" name="q" type="text"
              class="search-input"
              placeholder="example.com, 8.8.8.8, AS15169 …"
              autocomplete="off" autocorrect="off" autocapitalize="none"
              spellcheck="false"
              value="{{.Query}}"
              aria-label="Domain, IP address, or ASN"
              required
            >
            <button type="submit" class="btn-primary" aria-label="Run WHOIS lookup">
              Look up
            </button>
          </div>
        </form>

        <div class="examples" aria-label="Example queries">
          <div class="examples-label">Try an example</div>
          <div class="example-chips">
            <a href="/whois?q=example.com"   class="example-chip" data-query="example.com">example.com</a>
            <a href="/whois?q=8.8.8.8"       class="example-chip" data-query="8.8.8.8">8.8.8.8</a>
            <a href="/whois?q=1.1.1.1"       class="example-chip" data-query="1.1.1.1">1.1.1.1</a>
            <a href="/whois?q=2001%3A4860%3A4860%3A%3A8888" class="example-chip" data-query="2001:4860:4860::8888">2001:4860:4860::8888</a>
            <a href="/whois?q=AS15169"        class="example-chip" data-query="AS15169">AS15169</a>
            <a href="/whois?q=AS13335"        class="example-chip" data-query="AS13335">AS13335</a>
          </div>
        </div>

        {{/* Loading indicator — hidden until JS shows it */}}
        <div id="js-loading" class="state-loading result-area" hidden aria-live="polite" aria-busy="true">
          <span class="spinner" role="status" aria-label="Loading"></span>
          <span>Looking up WHOIS information…</span>
        </div>

        {{/* JS-rendered result */}}
        <div id="js-result" class="result-area" hidden aria-live="polite">
          <div class="result-meta">
            <div class="meta-item">
              <div class="meta-label">Query</div>
              <div id="r-query" class="meta-value long-string"></div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Type</div>
              <div id="r-type" class="meta-value"><span class="type-badge"></span></div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Server</div>
              <div id="r-server" class="meta-value long-string"></div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Looked up</div>
              <div id="r-ts" class="meta-value"></div>
            </div>
          </div>
          <pre id="r-raw" class="whois-raw" aria-label="Raw WHOIS data"></pre>
        </div>

        {{/* JS error */}}
        <div id="js-error" class="state-box state-error result-area" role="alert" hidden></div>

        {{/* Server-side result (no-JS path) */}}
        {{if .Result}}
        <div class="server-result" aria-label="WHOIS result">
          <div class="result-meta">
            <div class="meta-item">
              <div class="meta-label">Query</div>
              <div class="meta-value long-string">{{.Result.Query}}</div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Type</div>
              <div class="meta-value"><span class="type-badge">{{.Result.Type}}</span></div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Server</div>
              <div class="meta-value long-string">{{.Result.Server}}</div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Looked up</div>
              <div class="meta-value"><time datetime="{{.Result.Timestamp}}">{{.Result.Timestamp}}</time></div>
            </div>
          </div>
          <pre class="whois-raw" aria-label="Raw WHOIS data">{{.Result.Raw}}</pre>
        </div>
        {{end}}

        {{/* Server-side error (no-JS path) */}}
        {{if .Err}}
        <div class="state-box state-error" role="alert">
          {{.Err}}
        </div>
        {{end}}
      </div>
    </div>
  </section>
</main>

<footer class="site-footer">
  <p>
    <a href="/">caswhois</a> &mdash;
    <a href="/about">About</a> &middot;
    <a href="/docs">API Docs</a> &middot;
    <a href="/server/healthz">Health</a>
  </p>
</footer>

<script src="/static/js/main.js" defer></script>
</body>
</html>`))

// whoisPageTmpl is the template for GET /whois?q=... (no-JS server-rendered result page).
// Browsers with JS active will never navigate here; they see results inline on /.
var whoisPageTmpl = template.Must(template.New("whois-page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="WHOIS result for {{.Query}}">
<title>{{.Query}} — caswhois</title>
<link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>
<a class="skip-link" href="#navigation">Skip to navigation</a>

<nav id="navigation" class="site-nav" aria-label="Site navigation">
  <div class="nav-inner">
    <a href="/" class="nav-brand" aria-label="caswhois home">caswhois</a>
    <ul class="nav-links" role="list">
      <li><a href="/about">About</a></li>
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
  <div class="container" style="padding-top:2rem;padding-bottom:2rem">

    <form id="whois-form" class="search-form-wrap" action="/whois" method="GET" style="margin-bottom:1.5rem" novalidate>
      <div class="search-row">
        <label for="q" class="sr-only">Query — domain, IP address, or ASN</label>
        <input
          id="q" name="q" type="text"
          class="search-input"
          placeholder="example.com, 8.8.8.8, AS15169 …"
          autocomplete="off" autocorrect="off" autocapitalize="none"
          spellcheck="false"
          value="{{.Query}}"
          aria-label="Domain, IP address, or ASN"
        >
        <button type="submit" class="btn-primary">Look up</button>
      </div>
    </form>

    {{if .Err}}
    <div class="state-box state-error" role="alert">{{.Err}}</div>
    {{else if .Result}}
    <div class="card">
      <div class="result-meta" style="margin-bottom:1rem">
        <div class="meta-item">
          <div class="meta-label">Query</div>
          <div class="meta-value long-string">{{.Result.Query}}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Type</div>
          <div class="meta-value"><span class="type-badge">{{.Result.Type}}</span></div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Server</div>
          <div class="meta-value long-string">{{.Result.Server}}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Looked up</div>
          <div class="meta-value">
            <time datetime="{{.Result.Timestamp}}">{{.Result.Timestamp}}</time>
          </div>
        </div>
      </div>
      <pre class="whois-raw" aria-label="Raw WHOIS data">{{.Result.Raw}}</pre>
    </div>
    {{else if .Query}}
    <div class="state-box state-error" role="alert">No result returned for "{{.Query}}".</div>
    {{end}}

    <p style="margin-top:1rem"><a href="/">&larr; New lookup</a></p>
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

<script src="/static/js/main.js" defer></script>
</body>
</html>`))

// homePageData holds template data for the homepage.
type homePageData struct {
	Query  string
	Result *whoisResultView
	Err    string
}

// whoisResultView is a presentation-layer view of a WHOISResult.
type whoisResultView struct {
	Query     string
	Type      string
	Server    string
	Timestamp string
	Raw       string
}

// whoisPageData holds template data for the /whois result page.
type whoisPageData struct {
	Query  string
	Result *whoisResultView
	Err    string
}

// handlePublicWHOISPage serves the public WHOIS lookup homepage at /.
// GET /
func (s *Server) handlePublicWHOISPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// JSON API clients get the API info response.
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		s.handleRootAPI(w, r)
		return
	}

	data := homePageData{}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := homepageTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleWHOISPage handles the form-submission fallback at GET /whois?q=...
// Browsers with JS never reach this — the fetch intercepts first.
// Browsers without JS (and curl with Accept: text/html) do reach it.
func (s *Server) handleWHOISPage(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	clientType := DetectClientType(r)

	// Plain-text clients (curl, wget, etc.) get raw WHOIS output.
	if clientType == ClientTypeText || strings.Contains(r.Header.Get("Accept"), "text/plain") {
		if q == "" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Usage: GET /whois?q=<domain|ip|asn>\n"))
			return
		}
		result, err := whois.QueryWHOISWithCache(r.Context(), q, s.cache)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("WHOIS lookup failed: " + err.Error() + "\n"))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(result.Raw))
		return
	}

	// JSON clients get the structured response.
	if clientType == ClientTypeJSON || strings.Contains(r.Header.Get("Accept"), "application/json") {
		if q == "" {
			SendError(w, ErrBadRequest, "Query parameter q is required")
			return
		}
		result, err := whois.QueryWHOISWithCache(r.Context(), q, s.cache)
		if err != nil {
			SendError(w, ErrServerError, "WHOIS lookup failed: "+err.Error())
			return
		}
		SendSuccess(w, map[string]interface{}{
			"query":     result.Query,
			"type":      result.Type.String(),
			"server":    result.Server,
			"timestamp": result.Timestamp.Format(time.RFC3339),
			"raw":       result.Raw,
		})
		return
	}

	// HTML clients — render the server-side result page.
	data := whoisPageData{Query: q}

	if q != "" {
		result, err := whois.QueryWHOISWithCache(r.Context(), q, s.cache)
		if err != nil {
			data.Err = "WHOIS lookup failed: " + err.Error()
		} else {
			data.Result = &whoisResultView{
				Query:     result.Query,
				Type:      result.Type.String(),
				Server:    result.Server,
				Timestamp: result.Timestamp.Format(time.RFC3339),
				Raw:       result.Raw,
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := whoisPageTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleRootAPI returns API information for root endpoint when Accept: application/json.
func (s *Server) handleRootAPI(w http.ResponseWriter, r *http.Request) {
	SendSuccess(w, map[string]interface{}{
		"service":     "caswhois",
		"description": "WHOIS lookup service — query domains, IPs, and ASNs",
		"version":     "0.1.0",
		"endpoints": []string{
			"GET /api/v1/whois/{query}         — generic lookup",
			"GET /api/v1/whois/domain/{domain} — domain lookup",
			"GET /api/v1/whois/ip/{ip}         — IP lookup",
			"GET /api/v1/whois/asn/{asn}       — ASN lookup",
			"GET /api/v1/whois/validate/{q}    — validate without lookup",
			"POST /api/v1/whois/bulk           — bulk lookup (auth required)",
			"GET /api/v1/whois-servers         — list WHOIS servers",
			"GET /api/v1/server/stats          — service statistics",
			"GET /server/healthz               — health check",
		},
	})
}
