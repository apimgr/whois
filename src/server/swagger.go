package server

import (
	"net/http"

	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/swagger"
)

type swaggerPageData struct {
	translatablePageData
	Name    string
	SpecURL string
}

var swaggerTmpl = mustParseTemplate("swagger", "page/swagger.tmpl")

// handleSwaggerJSON serves the OpenAPI specification as JSON.
// Routes: /api/swagger, /api/{api_version}/server/swagger (AI.md PART 14)
func (s *Server) handleSwaggerJSON(w http.ResponseWriter, r *http.Request) {
	swagger.WriteJSONFromRoutes(w, s.swaggerBaseURL(r), Version, s.config.APIBasePath(), s.apiRoutes())
}

// handleSwaggerUI serves the Swagger UI HTML page.
// Route: /server/docs/swagger (AI.md PART 14)
func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	name := s.config.Branding.Title
	if name == "" {
		name = constants.InternalName
	}
	data := swaggerPageData{
		translatablePageData: s.newPageData(w, r),
		Name:                 name,
		SpecURL:              s.BuildURL(r, "/api/swagger"),
	}
	if err := s.renderTemplate(swaggerTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

// swaggerBaseURL computes the request-aware absolute URL used in OpenAPI and Swagger UI.
func (s *Server) swaggerBaseURL(r *http.Request) string {
	return s.BuildURL(r, "/")
}
