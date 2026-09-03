// Package swagger generates the OpenAPI 3.0 specification and serves the
// Swagger UI for caswhois (AI.md PART 3, PART 14).
package swagger

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// OpenAPISpec represents the OpenAPI 3.0 specification structure.
type OpenAPISpec struct {
	OpenAPI    string              `json:"openapi"`
	Info       OpenAPIInfo         `json:"info"`
	Servers    []OpenAPIServer     `json:"servers"`
	Paths      map[string]PathItem `json:"paths"`
	Components Components          `json:"components,omitempty"`
}

// OpenAPIInfo holds API metadata.
type OpenAPIInfo struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Version     string         `json:"version"`
	Contact     OpenAPIContact `json:"contact,omitempty"`
	License     OpenAPILicense `json:"license,omitempty"`
}

// OpenAPIContact holds contact information.
type OpenAPIContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

// OpenAPILicense holds license information.
type OpenAPILicense struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// OpenAPIServer defines a server endpoint.
type OpenAPIServer struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// PathItem describes operations on a single path.
type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Put    *Operation `json:"put,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
}

// Operation describes a single API operation.
type Operation struct {
	Summary     string              `json:"summary"`
	Description string              `json:"description,omitempty"`
	OperationID string              `json:"operationId,omitempty"`
	Tags        []string            `json:"tags,omitempty"`
	Parameters  []Parameter         `json:"parameters,omitempty"`
	RequestBody *RequestBody        `json:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses"`
	Security    []SecurityReq       `json:"security,omitempty"`
}

// Parameter describes an API parameter.
type Parameter struct {
	Name        string `json:"name"`
	In          string `json:"in"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Schema      Schema `json:"schema"`
}

// RequestBody describes a request body.
type RequestBody struct {
	Description string               `json:"description,omitempty"`
	Required    bool                 `json:"required,omitempty"`
	Content     map[string]MediaType `json:"content"`
}

// Response describes an API response.
type Response struct {
	Description string               `json:"description"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

// MediaType describes a media type response.
type MediaType struct {
	Schema Schema `json:"schema"`
}

// Schema describes a JSON schema.
type Schema struct {
	Type       string            `json:"type,omitempty"`
	Format     string            `json:"format,omitempty"`
	Items      *Schema           `json:"items,omitempty"`
	Properties map[string]Schema `json:"properties,omitempty"`
	Ref        string            `json:"$ref,omitempty"`
}

// SecurityReq defines a security requirement.
type SecurityReq map[string][]string

// Components holds reusable components.
type Components struct {
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty"`
	Schemas         map[string]Schema         `json:"schemas,omitempty"`
}

// SecurityScheme defines an authentication scheme.
type SecurityScheme struct {
	Type         string `json:"type"`
	Scheme       string `json:"scheme,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty"`
	Description  string `json:"description,omitempty"`
}

// BuildSpec constructs the OpenAPI 3.0 specification for the WHOIS API.
// baseURL is the absolute server URL (e.g. "https://whois.example.com") and
// version is the running server version (AI.md PART 13 "version").
func BuildSpec(baseURL, version string) OpenAPISpec {
	return OpenAPISpec{
		OpenAPI: "3.0.3",
		Info: OpenAPIInfo{
			Title:       "caswhois API",
			Description: "WHOIS lookup service with domain, IP, and ASN queries. Supports RDAP-first with WHOIS fallback.",
			Version:     version,
			Contact: OpenAPIContact{
				Name:  "CasJay",
				Email: "casjay@yahoo.com",
			},
			License: OpenAPILicense{
				Name: "MIT",
				URL:  "https://opensource.org/licenses/MIT",
			},
		},
		Servers: []OpenAPIServer{
			{URL: baseURL, Description: "Current server"},
		},
		Paths:      buildPaths(),
		Components: buildComponents(),
	}
}

// WriteJSON writes the OpenAPI specification as a JSON response.
// Routes: /api/swagger, /api/v1/server/swagger (AI.md PART 14).
func WriteJSON(w http.ResponseWriter, baseURL, version string) {
	spec := BuildSpec(baseURL, version)

	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		http.Error(w, `{"ok":false,"error":"INTERNAL_ERROR","message":"Failed to generate spec"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	w.Write([]byte("\n"))
}

// WriteUI writes the Swagger UI HTML page.
// Route: /server/docs/swagger (AI.md PART 14).
func WriteUI(w http.ResponseWriter, baseURL string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>caswhois API - Swagger UI</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui.css" integrity="sha384-nF9R21t+/xRDFn2V5S2VvFbX12Xw2PPqNxvBwgKBWHqYcPLp6mGlnWWTJWqJfuXK" crossorigin="anonymous">
  <style>
%s
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui-bundle.js" integrity="sha384-lSvdQYfIpnJDyDnX5F0v4Teb2k5jnMMRZLGkAVsR4WO9RRg0VQCqjsT8D9wpJZ0i" crossorigin="anonymous"></script>
  <script>
    const ui = SwaggerUIBundle({
      url: "%s/api/swagger",
      dom_id: "#swagger-ui",
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: "StandaloneLayout"
    });
  </script>
</body>
</html>
`, ThemeCSS(ThemeDark), baseURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, html)
}
