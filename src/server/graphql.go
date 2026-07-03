package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GraphQLRequest represents a GraphQL query request.
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLResponse represents a GraphQL response.
type GraphQLResponse struct {
	Data   interface{}     `json:"data,omitempty"`
	Errors []GraphQLError  `json:"errors,omitempty"`
}

// GraphQLError represents a GraphQL error.
type GraphQLError struct {
	Message   string     `json:"message"`
	Locations []Location `json:"locations,omitempty"`
	Path      []string   `json:"path,omitempty"`
}

// Location represents a position in the query.
type Location struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// handleGraphQL handles GraphQL POST requests.
// Routes: /api/graphql, /api/v1/server/graphql (AI.md PART 14)
func (s *Server) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.writeGraphQLError(w, http.StatusMethodNotAllowed, "GraphQL endpoint only accepts POST requests")
		return
	}

	var req GraphQLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeGraphQLError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	if strings.TrimSpace(req.Query) == "" {
		s.writeGraphQLError(w, http.StatusBadRequest, "Query is required")
		return
	}

	// Handle introspection query for schema discovery
	if strings.Contains(req.Query, "__schema") || strings.Contains(req.Query, "__type") {
		s.handleGraphQLIntrospection(w, req)
		return
	}

	// Execute the query
	result := s.executeGraphQL(req)

	data, _ := json.MarshalIndent(result, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	w.Write([]byte("\n"))
}

// handleGraphQLIntrospection returns the GraphQL schema for introspection.
func (s *Server) handleGraphQLIntrospection(w http.ResponseWriter, req GraphQLRequest) {
	// Return a minimal introspection response
	schema := map[string]interface{}{
		"__schema": map[string]interface{}{
			"queryType": map[string]string{"name": "Query"},
			"types": []map[string]interface{}{
				{
					"kind": "OBJECT",
					"name": "Query",
					"fields": []map[string]interface{}{
						{
							"name":        "whois",
							"description": "Look up WHOIS information for a domain, IP, or ASN",
							"args": []map[string]interface{}{
								{"name": "query", "type": map[string]string{"kind": "NON_NULL", "name": "String"}},
							},
							"type": map[string]string{"kind": "OBJECT", "name": "WhoisRecord"},
						},
						{
							"name":        "health",
							"description": "Get server health status",
							"args":        []interface{}{},
							"type":        map[string]string{"kind": "OBJECT", "name": "Health"},
						},
						{
							"name":        "stats",
							"description": "Get server statistics",
							"args":        []interface{}{},
							"type":        map[string]string{"kind": "OBJECT", "name": "Stats"},
						},
					},
				},
				{
					"kind": "OBJECT",
					"name": "WhoisRecord",
					"fields": []map[string]interface{}{
						{"name": "query", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "queryType", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "source", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "registrantName", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "registrantOrg", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "registrantEmail", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "registrar", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "createdDate", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "expiryDate", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "nameservers", "type": map[string]interface{}{"kind": "LIST", "ofType": map[string]string{"kind": "SCALAR", "name": "String"}}},
					},
				},
				{
					"kind": "OBJECT",
					"name": "Health",
					"fields": []map[string]interface{}{
						{"name": "ok", "type": map[string]string{"kind": "SCALAR", "name": "Boolean"}},
						{"name": "status", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "version", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "uptime", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
					},
				},
				{
					"kind": "OBJECT",
					"name": "Stats",
					"fields": []map[string]interface{}{
						{"name": "totalRequests", "type": map[string]string{"kind": "SCALAR", "name": "Int"}},
						{"name": "requests24h", "type": map[string]string{"kind": "SCALAR", "name": "Int"}},
						{"name": "domainQueries", "type": map[string]string{"kind": "SCALAR", "name": "Int"}},
						{"name": "ipQueries", "type": map[string]string{"kind": "SCALAR", "name": "Int"}},
					},
				},
			},
		},
	}

	resp := GraphQLResponse{Data: schema}
	data, _ := json.MarshalIndent(resp, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	w.Write([]byte("\n"))
}

// executeGraphQL executes a GraphQL query and returns the result.
func (s *Server) executeGraphQL(req GraphQLRequest) GraphQLResponse {
	query := strings.TrimSpace(req.Query)

	// Simple query parser for common queries
	if strings.Contains(query, "health") {
		return s.resolveHealthQuery()
	}

	if strings.Contains(query, "stats") {
		return s.resolveStatsQuery()
	}

	if strings.Contains(query, "whois") {
		// Extract query argument
		queryArg := ""
		if v, ok := req.Variables["query"]; ok {
			queryArg = fmt.Sprintf("%v", v)
		}
		if queryArg == "" {
			// Try to extract from inline query
			if idx := strings.Index(query, `query:`); idx >= 0 {
				rest := query[idx+6:]
				if start := strings.Index(rest, `"`); start >= 0 {
					rest = rest[start+1:]
					if end := strings.Index(rest, `"`); end >= 0 {
						queryArg = rest[:end]
					}
				}
			}
		}
		if queryArg != "" {
			return s.resolveWhoisQuery(queryArg)
		}
		return GraphQLResponse{
			Errors: []GraphQLError{{Message: "Missing query argument for whois lookup"}},
		}
	}

	return GraphQLResponse{
		Errors: []GraphQLError{{Message: "Unknown query. Supported: health, stats, whois(query: String!)"}},
	}
}

// resolveHealthQuery returns health data for GraphQL.
func (s *Server) resolveHealthQuery() GraphQLResponse {
	uptime := time.Since(s.startTime)
	return GraphQLResponse{
		Data: map[string]interface{}{
			"health": map[string]interface{}{
				"ok":      true,
				"status":  "ok",
				"version": Version,
				"uptime":  uptime.String(),
			},
		},
	}
}

// resolveStatsQuery returns stats data for GraphQL.
func (s *Server) resolveStatsQuery() GraphQLResponse {
	return GraphQLResponse{
		Data: map[string]interface{}{
			"stats": map[string]interface{}{
				"totalRequests": s.stats.requestsTotal.Load(),
				"requests24h":   s.stats.requests24h.Load(),
				"domainQueries": s.stats.domainQueries.Load(),
				"ipQueries":     s.stats.ipQueries.Load(),
			},
		},
	}
}

// resolveWhoisQuery performs a WHOIS lookup via GraphQL.
func (s *Server) resolveWhoisQuery(query string) GraphQLResponse {
	if s.lookupService == nil {
		return GraphQLResponse{
			Errors: []GraphQLError{{Message: "WHOIS lookup service not available"}},
		}
	}

	ctx := context.Background()
	result, err := s.lookupService.Lookup(ctx, query)
	if err != nil {
		return GraphQLResponse{
			Errors: []GraphQLError{{Message: fmt.Sprintf("Lookup failed: %v", err)}},
		}
	}

	return GraphQLResponse{
		Data: map[string]interface{}{
			"whois": map[string]interface{}{
				"query":           result.Query,
				"queryType":       result.QueryType,
				"source":          result.Source,
				"registrantName":  result.RegistrantName,
				"registrantOrg":   result.RegistrantOrg,
				"registrantEmail": result.RegistrantEmail,
				"registrar":       result.Registrar,
				"createdDate":     result.CreatedDate,
				"expiryDate":      result.ExpiryDate,
				"nameservers":     result.Nameservers,
			},
		},
	}
}

// writeGraphQLError writes a GraphQL error response.
func (s *Server) writeGraphQLError(w http.ResponseWriter, status int, message string) {
	resp := GraphQLResponse{
		Errors: []GraphQLError{{Message: message}},
	}
	data, _ := json.MarshalIndent(resp, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
	w.Write([]byte("\n"))
}

// handleGraphiQL serves the GraphiQL UI HTML page.
// Route: /server/docs/graphql (AI.md PART 14)
func (s *Server) handleGraphiQL(w http.ResponseWriter, r *http.Request) {
	baseURL := fmt.Sprintf("http://localhost:%d", s.config.Port)
	if s.config.FQDN != "" {
		baseURL = "https://" + s.config.FQDN
	}

	// GraphiQL HTML with dark theme support (AI.md PART 16)
	// Using pinned versions with SRI hashes for security
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>caswhois API - GraphiQL</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/graphiql@3.7.2/graphiql.min.css" integrity="sha384-pHBPy9LqsJcOWdD8C+LVN3mIGU48E5KPx9EZlQPOy1AkjKCRGPLl6C0KWXlDwKXB" crossorigin="anonymous">
  <style>
    :root {
      --color-bg: #0d1117;
      --color-fg: #c9d1d9;
    }
    body { margin: 0; height: 100vh; }
    #graphiql { height: 100vh; }
    [data-theme="dark"] .graphiql-container {
      --color-base: #0d1117;
      --color-primary: #58a6ff;
    }
  </style>
</head>
<body>
  <div id="graphiql"></div>
  <script src="https://cdn.jsdelivr.net/npm/react@18.3.1/umd/react.production.min.js" integrity="sha384-bVWBxVIpPVJkJpjjBfB6Ur4RjkL7XpKa5y9Vz8T1l8dPqVZgAZ6e9hZFKGJZZmXh" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/react-dom@18.3.1/umd/react-dom.production.min.js" integrity="sha384-ZCsJJzQTu9FsGS8IaXMc3WfF4ER0MZkKD+kJSALRjhPV4Eh7fvEPa2F/D8PSwc3B" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/graphiql@3.7.2/graphiql.min.js" integrity="sha384-TLW7JKKD8BfYjVPLPiD6qTvvMXhLl9PdXr1uBVDRdRlPOgvlAFfJGXV7CVKJDJh4" crossorigin="anonymous"></script>
  <script>
    const fetcher = GraphiQL.createFetcher({
      url: "%s/api/graphql",
    });
    ReactDOM.createRoot(document.getElementById("graphiql")).render(
      React.createElement(GraphiQL, {
        fetcher: fetcher,
        defaultEditorToolsVisibility: true,
      })
    );
  </script>
</body>
</html>
`, baseURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, html)
}
