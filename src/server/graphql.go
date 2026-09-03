package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/graphql"
	"github.com/apimgr/whois/src/whois"
)

// handleGraphQL handles GraphQL POST requests.
// Routes: /api/graphql, /api/v1/server/graphql (AI.md PART 14)
func (s *Server) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.writeGraphQLError(w, http.StatusMethodNotAllowed, "GraphQL endpoint only accepts POST requests")
		return
	}

	var req graphql.GraphQLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeGraphQLError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	if strings.TrimSpace(req.Query) == "" {
		s.writeGraphQLError(w, http.StatusBadRequest, "Query is required")
		return
	}

	resp := s.executeGraphQL(r.Context(), req)
	graphql.WriteResponse(w, http.StatusOK, resp)
}

// executeGraphQL validates and runs a GraphQL request against the graphql
// package's query engine, supplying server-specific health/stats/lookup data.
func (s *Server) executeGraphQL(ctx context.Context, req graphql.GraphQLRequest) graphql.GraphQLResponse {
	if strings.TrimSpace(req.Query) == "" {
		return graphql.GraphQLResponse{
			Errors: []graphql.GraphQLError{{Message: "Query is required"}},
		}
	}

	return graphql.Execute(ctx, req, s.graphqlHealth(), s.graphqlStats(), s.graphqlLookup)
}

// graphqlHealth builds the health data exposed to the "health" GraphQL query.
func (s *Server) graphqlHealth() graphql.HealthInfo {
	return graphql.HealthInfo{
		OK:      true,
		Status:  "ok",
		Version: Version,
		Uptime:  time.Since(s.startTime).String(),
	}
}

// graphqlStats builds the stats data exposed to the "stats" GraphQL query.
func (s *Server) graphqlStats() graphql.StatsInfo {
	return graphql.StatsInfo{
		TotalRequests: s.stats.requestsTotal.Load(),
		Requests24h:   s.stats.requests24h.Load(),
		DomainQueries: s.stats.domainQueries.Load(),
		IPQueries:     s.stats.ipQueries.Load(),
	}
}

// graphqlLookup performs a WHOIS lookup for the "whois" GraphQL query.
func (s *Server) graphqlLookup(ctx context.Context, query string) (*whois.UnifiedResult, error) {
	if s.lookupService == nil {
		return nil, fmt.Errorf("WHOIS lookup service not available")
	}
	return s.lookupService.Lookup(ctx, query)
}

// graphqlTmpl is the server-side template for the GraphQL explorer UI (AI.md PART 16).
// No external CDN or JavaScript framework - progressive enhancement only.
var graphqlTmpl = mustParseTemplate("graphql", "graphql.html")

// graphqlPageData is the view model for the GraphQL explorer template.
type graphqlPageData struct {
	translatablePageData
	// Name is the operator-configured brand name (falls back to constants.InternalName).
	Name string
	// EndpointURL is the absolute URL of the GraphQL API endpoint.
	EndpointURL string
	// Query is the GraphQL query pre-filled in the editor (from ?query= param or server-side POST echo).
	Query string
	// Variables is the JSON variables string echoed back after a POST submission.
	Variables string
	// OperationName is the operation name echoed back after a POST submission.
	OperationName string
	// Response is the raw JSON response string shown in the response pane after a no-JS POST.
	Response string
	// ErrorMsg is a user-visible error message (e.g. invalid JSON variables).
	ErrorMsg string
}

// writeGraphQLError writes a GraphQL error response.
func (s *Server) writeGraphQLError(w http.ResponseWriter, status int, message string) {
	graphql.WriteError(w, status, message)
}

// handleGraphiQL serves the GraphQL explorer page (server-side Go template, no external CDN).
// Route: /server/docs/graphql (AI.md PART 14)
// Supports both GET (display form) and POST (no-JS query submission).
func (s *Server) handleGraphiQL(w http.ResponseWriter, r *http.Request) {
	baseURL := fmt.Sprintf("http://localhost:%d", s.config.Port)
	if s.config.FQDN != "" {
		baseURL = "https://" + s.config.FQDN
	}
	endpointURL := baseURL + "/api/graphql"

	brandName := s.config.Branding.Title
	if brandName == "" {
		brandName = constants.InternalName
	}

	pd := graphqlPageData{
		translatablePageData: s.newPageData(w, r),
		Name:                 brandName,
		EndpointURL:          endpointURL,
	}

	// No-JS POST: forward the form submission to the GraphQL endpoint and echo the response.
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			pd.ErrorMsg = "Bad request: " + err.Error()
		} else {
			pd.Query = r.FormValue("query")
			pd.Variables = r.FormValue("variables")
			pd.OperationName = r.FormValue("operationName")

			gqlReq := graphql.GraphQLRequest{
				Query:         pd.Query,
				OperationName: pd.OperationName,
			}
			if pd.Variables != "" {
				if err := json.Unmarshal([]byte(pd.Variables), &gqlReq.Variables); err != nil {
					pd.ErrorMsg = "Variables must be valid JSON: " + err.Error()
				}
			}

			if pd.ErrorMsg == "" {
				ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
				defer cancel()
				gqlResp := s.executeGraphQL(ctx, gqlReq)
				out, _ := json.MarshalIndent(gqlResp, "", "  ")
				pd.Response = string(out)
			}
		}
	} else {
		pd.Query = r.URL.Query().Get("query")
		pd.Variables = r.URL.Query().Get("variables")
		pd.OperationName = r.URL.Query().Get("operationName")
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := graphqlTmpl.Execute(w, pd); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
