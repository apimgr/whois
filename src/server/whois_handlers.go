package server

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/casapps/caswhois/src/whois"
)

// handleWHOISDomainLookup handles domain-specific WHOIS lookups
// GET /api/v1/whois/domain/:domain
func (s *Server) handleWHOISDomainLookup(w http.ResponseWriter, r *http.Request) {
	// Extract domain from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/whois/domain/")
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
// GET /api/v1/whois/ip/:ip
func (s *Server) handleWHOISIPLookup(w http.ResponseWriter, r *http.Request) {
	// Extract IP from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/whois/ip/")
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
// GET /api/v1/whois/asn/:asn
func (s *Server) handleWHOISASNLookup(w http.ResponseWriter, r *http.Request) {
	// Extract ASN from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/whois/asn/")
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
// GET /api/v1/whois/validate/:query
func (s *Server) handleWHOISValidate(w http.ResponseWriter, r *http.Request) {
	// Extract query from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/whois/validate/")
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
		sendHTMLResponse(w, result)
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

// sendHTMLResponse sends a WHOIS response in HTML format
func sendHTMLResponse(w http.ResponseWriter, result *whois.WHOISResult) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WHOIS Lookup: %s</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            padding: 2rem;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 2rem;
        }
        h1 {
            color: #2d3748;
            margin-bottom: 1rem;
            font-size: 1.75rem;
        }
        .meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
            padding: 1rem;
            background: #f7fafc;
            border-radius: 6px;
        }
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        .meta-label {
            color: #718096;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }
        .meta-value {
            color: #2d3748;
            font-size: 1rem;
        }
        .raw-data {
            background: #2d3748;
            color: #e2e8f0;
            padding: 1.5rem;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 0.875rem;
            line-height: 1.6;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .back-link {
            display: inline-block;
            margin-top: 1.5rem;
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        .back-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>WHOIS Lookup Result</h1>
        
        <div class="meta">
            <div class="meta-item">
                <span class="meta-label">Query</span>
                <span class="meta-value">%s</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Type</span>
                <span class="meta-value">%s</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Server</span>
                <span class="meta-value">%s</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Timestamp</span>
                <span class="meta-value">%s</span>
            </div>
        </div>
        
        <pre class="raw-data">%s</pre>
        
        <a href="/" class="back-link">&larr; Back to Search</a>
    </div>
</body>
</html>`,
		result.Query,
		result.Query,
		result.Type.String(),
		result.Server,
		result.Timestamp.Format(time.RFC3339),
		result.Raw,
	)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}
