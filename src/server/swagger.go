package server

import (
	"fmt"
	"net/http"

	"github.com/apimgr/whois/src/swagger"
)

// handleSwaggerJSON serves the OpenAPI specification as JSON.
// Routes: /api/swagger, /api/v1/server/swagger (AI.md PART 14)
func (s *Server) handleSwaggerJSON(w http.ResponseWriter, r *http.Request) {
	swagger.WriteJSON(w, s.swaggerBaseURL(), Version)
}

// handleSwaggerUI serves the Swagger UI HTML page.
// Route: /server/docs/swagger (AI.md PART 14)
func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	swagger.WriteUI(w, s.swaggerBaseURL())
}

// swaggerBaseURL computes the absolute server URL used in the OpenAPI spec
// and Swagger UI, from the configured port or FQDN.
func (s *Server) swaggerBaseURL() string {
	baseURL := fmt.Sprintf("http://localhost:%d", s.config.Port)
	if s.config.FQDN != "" {
		baseURL = "https://" + s.config.FQDN
	}
	return baseURL
}
