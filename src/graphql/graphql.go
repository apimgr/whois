// Package graphql implements the GraphQL query engine for caswhois: request
// and response types, query execution, and resolvers (AI.md PART 3, PART 14).
package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/apimgr/whois/src/whois"
)

// GraphQLRequest represents a GraphQL query request.
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLResponse represents a GraphQL response.
type GraphQLResponse struct {
	Data   interface{}    `json:"data,omitempty"`
	Errors []GraphQLError `json:"errors,omitempty"`
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

// HealthInfo holds the health data exposed to the "health" GraphQL query.
type HealthInfo struct {
	OK      bool
	Status  string
	Version string
	Uptime  string
}

// StatsInfo holds the aggregate stats exposed to the "stats" GraphQL query.
type StatsInfo struct {
	TotalRequests int64
	Requests24h   int64
	DomainQueries int64
	IPQueries     int64
}

// LookupFunc performs a WHOIS lookup for the "whois" GraphQL query. It is
// supplied by the caller so this package stays decoupled from the server.
type LookupFunc func(ctx context.Context, query string) (*whois.UnifiedResult, error)

// IsIntrospectionQuery reports whether the query requests schema introspection.
func IsIntrospectionQuery(query string) bool {
	return strings.Contains(query, "__schema") || strings.Contains(query, "__type")
}

// Execute runs a GraphQL query and returns the result. Introspection queries
// are handled internally; "health", "stats", and "whois" are the only
// supported operations (AI.md PART 14).
func Execute(ctx context.Context, req GraphQLRequest, health HealthInfo, stats StatsInfo, lookup LookupFunc) GraphQLResponse {
	query := strings.TrimSpace(req.Query)

	if IsIntrospectionQuery(query) {
		return GraphQLResponse{Data: buildIntrospectionSchema()}
	}

	if strings.Contains(query, "health") {
		return resolveHealthQuery(health)
	}

	if strings.Contains(query, "stats") {
		return resolveStatsQuery(stats)
	}

	if strings.Contains(query, "whois") {
		queryArg := ""
		if v, ok := req.Variables["query"]; ok {
			queryArg = fmt.Sprintf("%v", v)
		}
		if queryArg == "" {
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
		if queryArg == "" {
			return GraphQLResponse{
				Errors: []GraphQLError{{Message: "Missing query argument for whois lookup"}},
			}
		}
		return resolveWhoisQuery(ctx, queryArg, lookup)
	}

	return GraphQLResponse{
		Errors: []GraphQLError{{Message: "Unknown query. Supported: health, stats, whois(query: String!)"}},
	}
}

// WriteResponse writes a GraphQL response as JSON with the given status code.
func WriteResponse(w http.ResponseWriter, status int, resp GraphQLResponse) {
	data, _ := json.MarshalIndent(resp, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
	w.Write([]byte("\n"))
}

// WriteError writes a GraphQL error response with the given status code.
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteResponse(w, status, GraphQLResponse{
		Errors: []GraphQLError{{Message: message}},
	})
}
