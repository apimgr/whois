package server

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/apimgr/whois/src/common/i18n"
	"github.com/apimgr/whois/src/whois"
	"github.com/apimgr/whois/src/whois/records"
	"github.com/apimgr/whois/src/whois/reverse"
)

// handleWHOISDomainLookup handles domain-specific WHOIS lookups
// GET /api/{version}/whois/domain/:domain
func (s *Server) handleWHOISDomainLookup(w http.ResponseWriter, r *http.Request) {
	// Extract domain from path — use config-driven API base path
	prefix := s.config.APIBasePath() + "/whois/domain/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	domain := strings.TrimSpace(path)

	if domain == "" {
		SendError(w, ErrBadRequest, "Domain parameter required")
		return
	}

	// Validate domain query
	queryType := whois.DetectQueryType(domain)
	if queryType != whois.QueryTypeDomain {
		SendError(w, ErrValidationFailed, "Invalid domain format")
		return
	}

	s.stats.domainQueries.Add(1)

	// Perform lookup
	s.performWHOISLookup(w, r, domain)
}

// handleWHOISIPLookup handles IP address WHOIS lookups
// GET /api/{version}/whois/ip/:ip
func (s *Server) handleWHOISIPLookup(w http.ResponseWriter, r *http.Request) {
	// Extract IP from path — use config-driven API base path
	prefix := s.config.APIBasePath() + "/whois/ip/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	ip := strings.TrimSpace(path)

	if ip == "" {
		SendError(w, ErrBadRequest, "IP address parameter required")
		return
	}

	// Validate IP address
	queryType := whois.DetectQueryType(ip)
	if queryType != whois.QueryTypeIPv4 && queryType != whois.QueryTypeIPv6 {
		SendError(w, ErrValidationFailed, "Invalid IP address format")
		return
	}

	s.stats.ipQueries.Add(1)

	// Perform lookup
	s.performWHOISLookup(w, r, ip)
}

// handleWHOISASNLookup handles ASN WHOIS lookups
// GET /api/{version}/whois/asn/:asn
func (s *Server) handleWHOISASNLookup(w http.ResponseWriter, r *http.Request) {
	// Extract ASN from path — use config-driven API base path
	prefix := s.config.APIBasePath() + "/whois/asn/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	asn := strings.TrimSpace(path)

	if asn == "" {
		SendError(w, ErrBadRequest, "ASN parameter required")
		return
	}

	// Validate ASN format
	queryType := whois.DetectQueryType(asn)
	if queryType != whois.QueryTypeASN {
		SendError(w, ErrValidationFailed, "Invalid ASN format (use AS prefix, e.g., AS15169)")
		return
	}

	s.stats.asnQueries.Add(1)

	// Perform lookup
	s.performWHOISLookup(w, r, asn)
}

// handleWHOISValidate validates a WHOIS query without performing the lookup
// GET /api/{version}/whois/validate/:query
func (s *Server) handleWHOISValidate(w http.ResponseWriter, r *http.Request) {
	// Extract query from path — use config-driven API base path
	prefix := s.config.APIBasePath() + "/whois/validate/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	query := strings.TrimSpace(path)

	if query == "" {
		SendError(w, ErrBadRequest, "Query parameter required")
		return
	}

	// Validate query
	if err := whois.ValidateQuery(query); err != nil {
		data := map[string]interface{}{
			"query":   query,
			"valid":   false,
			"type":    "unknown",
			"message": err.Error(),
		}
		SendSuccess(w, data)
		return
	}

	// Detect query type
	queryType := whois.DetectQueryType(query)
	data := map[string]interface{}{
		"query": query,
		"valid": true,
		"type":  queryType.String(),
	}

	SendSuccess(w, data)
}

// handleWHOISBulkLookup handles bulk WHOIS lookups (authenticated)
// POST /api/v1/whois/bulk
func (s *Server) handleWHOISBulkLookup(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req struct {
		Queries []string `json:"queries"`
		Format  string   `json:"format,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, ErrBadRequest, "Invalid request body")
		return
	}

	// Validate request
	if len(req.Queries) == 0 {
		SendError(w, ErrBadRequest, "Queries array required")
		return
	}

	// Limit bulk queries to prevent abuse
	maxBulkQueries := 100
	if len(req.Queries) > maxBulkQueries {
		SendError(w, ErrBadRequest, fmt.Sprintf("Maximum %d queries allowed per bulk request", maxBulkQueries))
		return
	}

	// Perform lookups
	results := make([]map[string]interface{}, 0, len(req.Queries))
	for _, query := range req.Queries {
		query = strings.TrimSpace(query)
		if query == "" {
			continue
		}

		// Validate query
		if err := whois.ValidateQuery(query); err != nil {
			results = append(results, map[string]interface{}{
				"query":   query,
				"success": false,
				"error":   err.Error(),
			})
			continue
		}

		// Perform WHOIS lookup with cache
		result, err := whois.QueryWHOISWithCache(r.Context(), query, s.cache)
		if err != nil {
			results = append(results, map[string]interface{}{
				"query":   query,
				"success": false,
				"error":   err.Error(),
			})
			continue
		}

		// Add result
		results = append(results, map[string]interface{}{
			"query":     result.Query,
			"success":   true,
			"type":      result.Type.String(),
			"server":    result.Server,
			"timestamp": result.Timestamp.Format(time.RFC3339),
			"raw":       result.Raw,
		})
	}

	// Return results
	data := map[string]interface{}{
		"count":   len(results),
		"results": results,
	}

	SendSuccess(w, data)
}

// performWHOISLookup performs a WHOIS lookup with content negotiation
func (s *Server) performWHOISLookup(w http.ResponseWriter, r *http.Request, query string) {
	// Validate query
	if err := whois.ValidateQuery(query); err != nil {
		SendError(w, ErrValidationFailed, fmt.Sprintf("Invalid query: %v", err))
		return
	}

	// Perform WHOIS lookup with cache
	result, err := whois.QueryWHOISWithCache(r.Context(), query, s.cache)
	if err != nil {
		SendError(w, ErrServerError, fmt.Sprintf("WHOIS lookup failed: %v", err))
		return
	}

	// Persist domain registrant data permanently for reverse owner search (fire-and-forget).
	if result.Domain != nil && s.database != nil {
		go func() {
			if saveErr := records.UpsertRecord(r.Context(), s.database.Server, query, result.Type.String(), result.Domain); saveErr != nil {
				_ = saveErr
			}
		}()
	}

	// Determine response format
	format := determineResponseFormat(r)

	// Build response data
	data := map[string]interface{}{
		"query":     result.Query,
		"type":      result.Type.String(),
		"server":    result.Server,
		"timestamp": result.Timestamp.Format(time.RFC3339),
		"raw":       result.Raw,
	}

	// Send response in requested format
	switch format {
	case "xml":
		sendXMLResponse(w, data)
	case "text":
		sendTextResponse(w, result)
	case "html":
		sendHTMLResponse(w, r, result)
	default:
		// Default to JSON
		SendSuccess(w, data)
	}
}

// determineResponseFormat determines the output format from Accept header or query parameter
func determineResponseFormat(r *http.Request) string {
	// Check query parameter first (?format=json|xml|text|html)
	format := r.URL.Query().Get("format")
	if format != "" {
		format = strings.ToLower(format)
		if format == "json" || format == "xml" || format == "text" || format == "html" {
			return format
		}
	}

	// Check Accept header
	accept := r.Header.Get("Accept")
	accept = strings.ToLower(accept)

	if strings.Contains(accept, "application/xml") || strings.Contains(accept, "text/xml") {
		return "xml"
	}
	if strings.Contains(accept, "text/plain") {
		return "text"
	}
	if strings.Contains(accept, "text/html") {
		return "html"
	}

	// Default to JSON
	return "json"
}

// sendXMLResponse sends a WHOIS response in XML format
func sendXMLResponse(w http.ResponseWriter, data map[string]interface{}) {
	type XMLResponse struct {
		XMLName   xml.Name `xml:"whois"`
		Query     string   `xml:"query"`
		Type      string   `xml:"type"`
		Server    string   `xml:"server"`
		Timestamp string   `xml:"timestamp"`
		Raw       string   `xml:"raw"`
	}

	response := XMLResponse{
		Query:     data["query"].(string),
		Type:      data["type"].(string),
		Server:    data["server"].(string),
		Timestamp: data["timestamp"].(string),
		Raw:       data["raw"].(string),
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(response)
}

// sendTextResponse sends a WHOIS response in plain text format
func sendTextResponse(w http.ResponseWriter, result *whois.WHOISResult) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Write header
	fmt.Fprintf(w, "Query: %s\n", result.Query)
	fmt.Fprintf(w, "Type: %s\n", result.Type.String())
	fmt.Fprintf(w, "Server: %s\n", result.Server)
	fmt.Fprintf(w, "Timestamp: %s\n\n", result.Timestamp.Format(time.RFC3339))

	// Write raw WHOIS data
	fmt.Fprint(w, result.Raw)
}

// sendHTMLResponse sends a WHOIS response in HTML format using the shared stylesheet.
// lang and dir are derived from the request context (AI.md PART 16, PART 30).
func sendHTMLResponse(w http.ResponseWriter, r *http.Request, result *whois.WHOISResult) {
	lang := LangFromContext(r.Context())
	dir := i18n.Dir(lang)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="%s" dir="%s">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WHOIS: %s — caswhois</title>
<link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
<nav class="site-nav" aria-label="Site navigation">
  <div class="nav-inner">
    <a href="/" class="nav-brand" aria-label="caswhois home">caswhois</a>
    <ul class="nav-links" role="list">
      <li><a href="/about">About</a></li>
      <li><a href="/docs">API Docs</a></li>
    </ul>
  </div>
</nav>
<main id="main-content">
  <div class="container" style="padding-top:2rem;padding-bottom:2rem">
    <div class="card">
      <div class="result-meta" style="margin-bottom:1rem">
        <div class="meta-item">
          <div class="meta-label">Query</div>
          <div class="meta-value long-string">%s</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Type</div>
          <div class="meta-value"><span class="type-badge">%s</span></div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Server</div>
          <div class="meta-value long-string">%s</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Timestamp</div>
          <div class="meta-value">%s</div>
        </div>
      </div>
      <pre class="whois-raw" aria-label="Raw WHOIS data">%s</pre>
      <p style="margin-top:1rem"><a href="/">&larr; New lookup</a></p>
    </div>
  </div>
</main>
<footer class="site-footer">
  <p><a href="/">caswhois</a> &mdash; <a href="/about">About</a> &middot; <a href="/docs">API Docs</a></p>
</footer>
<script src="/static/js/main.js" defer></script>
</body>
</html>`,
		lang,
		dir,
		result.Query,
		template.HTMLEscapeString(result.Query),
		template.HTMLEscapeString(result.Type.String()),
		template.HTMLEscapeString(result.Server),
		template.HTMLEscapeString(result.Timestamp.Format(time.RFC3339)),
		template.HTMLEscapeString(result.Raw),
	)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// handleWHOISOwnerSearch serves reverse-WHOIS / owner search.
// It searches the local whois_records table first (no API key required).
// When no local results are found it falls back to the external provider
// configured via server.yml or via the X-Provider-Name / X-Provider-Key
// request headers (user-supplied key, never stored server-side).
//
// GET /whois/search?owner=…&page=1&limit=100
// GET /api/v1/whois/search?owner=…&page=1&limit=100
func (s *Server) handleWHOISOwnerSearch(w http.ResponseWriter, r *http.Request) {
	owner := strings.TrimSpace(r.URL.Query().Get("owner"))
	if owner == "" {
		SendError(w, ErrBadRequest, "owner query parameter is required")
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	offset := (page - 1) * limit

	// 1. Search local permanent records (always; no API key needed).
	localRecords, err := records.SearchByOwner(r.Context(), s.database.Server, owner, limit, offset)
	if err != nil {
		SendError(w, ErrServerError, fmt.Sprintf("owner search failed: %v", err))
		return
	}

	// Convert local records to result slice for unified response.
	type ownerResult struct {
		Domain          string `json:"domain"`
		Source          string `json:"source"`
		RegistrantName  string `json:"registrant_name,omitempty"`
		RegistrantOrg   string `json:"registrant_org,omitempty"`
		RegistrantEmail string `json:"registrant_email,omitempty"`
		Registrar       string `json:"registrar,omitempty"`
		ExpiryDate      string `json:"expiry_date,omitempty"`
		FirstSeen       string `json:"first_seen"`
		LastSeen        string `json:"last_seen"`
	}

	results := make([]ownerResult, 0, len(localRecords))
	for _, rec := range localRecords {
		results = append(results, ownerResult{
			Domain:          rec.Query,
			Source:          "local",
			RegistrantName:  rec.RegistrantName,
			RegistrantOrg:   rec.RegistrantOrg,
			RegistrantEmail: rec.RegistrantEmail,
			Registrar:       rec.Registrar,
			ExpiryDate:      rec.ExpiryDate,
			FirstSeen:       time.Unix(rec.FirstSeen, 0).UTC().Format(time.RFC3339),
			LastSeen:        time.Unix(rec.LastSeen, 0).UTC().Format(time.RFC3339),
		})
	}

	// 2. If no local results, try external provider (page 1 only to avoid
	//    redundant external calls on subsequent pages).
	providerName := strings.TrimSpace(r.Header.Get("X-Provider-Name"))
	providerKey := strings.TrimSpace(r.Header.Get("X-Provider-Key"))

	// Fall back to server-level operator defaults when headers are absent.
	if providerName == "" {
		providerName = s.config.ReverseWHOIS.Provider
	}
	if providerKey == "" {
		providerKey = s.config.ReverseWHOIS.APIKey
	}

	maxExt := s.config.ReverseWHOIS.MaxResults
	if maxExt <= 0 {
		maxExt = 100
	}

	if len(results) == 0 && page == 1 && providerName != "" && providerKey != "" {
		extResults, extErr := reverse.SearchByOwner(r.Context(), providerName, providerKey, owner, maxExt)
		if extErr == nil {
			for _, er := range extResults {
				results = append(results, ownerResult{
					Domain: er.Domain,
					Source: er.Provider,
				})
			}
		}
	}

	SendSuccess(w, map[string]interface{}{
		"owner":   owner,
		"results": results,
		"meta": map[string]interface{}{
			"page":     page,
			"limit":    limit,
			"count":    len(results),
		},
	})
}
