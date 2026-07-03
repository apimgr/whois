package server

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

// handleSwaggerJSON serves the OpenAPI specification as JSON.
// Routes: /api/swagger, /api/v1/server/swagger (AI.md PART 14)
func (s *Server) handleSwaggerJSON(w http.ResponseWriter, r *http.Request) {
	baseURL := fmt.Sprintf("http://localhost:%d", s.config.Port)
	if s.config.FQDN != "" {
		baseURL = "https://" + s.config.FQDN
	}

	spec := s.buildOpenAPISpec(baseURL)

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

// buildOpenAPISpec constructs the OpenAPI 3.0 specification for the WHOIS API.
func (s *Server) buildOpenAPISpec(baseURL string) OpenAPISpec {
	return OpenAPISpec{
		OpenAPI: "3.0.3",
		Info: OpenAPIInfo{
			Title:       "caswhois API",
			Description: "WHOIS lookup service with domain, IP, and ASN queries. Supports RDAP-first with WHOIS fallback.",
			Version:     Version,
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
		Paths: map[string]PathItem{
			"/api/v1/server/healthz": {
				Get: &Operation{
					Summary:     "Health check",
					Description: "Returns server health status and component checks.",
					OperationID: "getHealth",
					Tags:        []string{"Server"},
					Responses: map[string]Response{
						"200": {
							Description: "Server is healthy",
							Content: map[string]MediaType{
								"application/json": {Schema: Schema{Ref: "#/components/schemas/HealthResponse"}},
							},
						},
					},
				},
			},
			"/api/v1/whois/{query}": {
				Get: &Operation{
					Summary:     "Auto-detect WHOIS lookup",
					Description: "Performs a WHOIS lookup, auto-detecting whether the query is a domain, IP address, or ASN.",
					OperationID: "whoisLookup",
					Tags:        []string{"WHOIS"},
					Parameters: []Parameter{
						{Name: "query", In: "path", Description: "Domain, IP address, or ASN to look up", Required: true, Schema: Schema{Type: "string"}},
					},
					Responses: map[string]Response{
						"200": {
							Description: "WHOIS data retrieved",
							Content: map[string]MediaType{
								"application/json": {Schema: Schema{Ref: "#/components/schemas/WhoisResponse"}},
							},
						},
						"400": {Description: "Invalid query format"},
						"404": {Description: "No WHOIS data found"},
						"429": {Description: "Rate limit exceeded"},
					},
				},
			},
			"/api/v1/whois/domain/{domain}": {
				Get: &Operation{
					Summary:     "Domain WHOIS lookup",
					Description: "Performs a WHOIS lookup for a domain name.",
					OperationID: "domainLookup",
					Tags:        []string{"WHOIS"},
					Parameters: []Parameter{
						{Name: "domain", In: "path", Description: "Domain name to look up", Required: true, Schema: Schema{Type: "string"}},
					},
					Responses: map[string]Response{
						"200": {Description: "Domain WHOIS data"},
						"400": {Description: "Invalid domain"},
						"404": {Description: "Domain not found"},
					},
				},
			},
			"/api/v1/whois/ip/{ip}": {
				Get: &Operation{
					Summary:     "IP WHOIS lookup",
					Description: "Performs a WHOIS lookup for an IP address (IPv4 or IPv6).",
					OperationID: "ipLookup",
					Tags:        []string{"WHOIS"},
					Parameters: []Parameter{
						{Name: "ip", In: "path", Description: "IP address to look up", Required: true, Schema: Schema{Type: "string"}},
					},
					Responses: map[string]Response{
						"200": {Description: "IP WHOIS data"},
						"400": {Description: "Invalid IP address"},
						"404": {Description: "No data found"},
					},
				},
			},
			"/api/v1/whois/asn/{asn}": {
				Get: &Operation{
					Summary:     "ASN WHOIS lookup",
					Description: "Performs a WHOIS lookup for an Autonomous System Number.",
					OperationID: "asnLookup",
					Tags:        []string{"WHOIS"},
					Parameters: []Parameter{
						{Name: "asn", In: "path", Description: "ASN (with or without AS prefix)", Required: true, Schema: Schema{Type: "string"}},
					},
					Responses: map[string]Response{
						"200": {Description: "ASN WHOIS data"},
						"400": {Description: "Invalid ASN"},
						"404": {Description: "ASN not found"},
					},
				},
			},
			"/api/v1/whois/validate/{query}": {
				Get: &Operation{
					Summary:     "Validate query without lookup",
					Description: "Validates a query and returns the detected type without performing the actual lookup.",
					OperationID: "validateQuery",
					Tags:        []string{"WHOIS"},
					Parameters: []Parameter{
						{Name: "query", In: "path", Description: "Query to validate", Required: true, Schema: Schema{Type: "string"}},
					},
					Responses: map[string]Response{
						"200": {Description: "Query is valid"},
						"400": {Description: "Query is invalid"},
					},
				},
			},
			"/api/v1/whois/search": {
				Get: &Operation{
					Summary:     "Search by owner/registrant",
					Description: "Searches the local WHOIS database by registrant name, org, or email.",
					OperationID: "ownerSearch",
					Tags:        []string{"WHOIS"},
					Parameters: []Parameter{
						{Name: "owner", In: "query", Description: "Owner/registrant to search for", Required: true, Schema: Schema{Type: "string"}},
						{Name: "page", In: "query", Description: "Page number", Schema: Schema{Type: "integer"}},
						{Name: "limit", In: "query", Description: "Results per page (max 250)", Schema: Schema{Type: "integer"}},
					},
					Responses: map[string]Response{
						"200": {Description: "Search results"},
						"400": {Description: "Invalid search parameters"},
					},
				},
			},
			"/api/v1/whois/bulk": {
				Post: &Operation{
					Summary:     "Bulk WHOIS lookup",
					Description: "Performs WHOIS lookups for multiple queries. Requires server token.",
					OperationID: "bulkLookup",
					Tags:        []string{"WHOIS"},
					Security:    []SecurityReq{{"bearerAuth": {}}},
					RequestBody: &RequestBody{
						Required: true,
						Content: map[string]MediaType{
							"application/json": {Schema: Schema{Ref: "#/components/schemas/BulkRequest"}},
						},
					},
					Responses: map[string]Response{
						"200": {Description: "Bulk lookup results"},
						"401": {Description: "Missing or invalid token"},
						"400": {Description: "Invalid request body"},
					},
				},
			},
			"/api/v1/whois-servers": {
				Get: &Operation{
					Summary:     "List WHOIS servers",
					Description: "Returns the list of known WHOIS servers by TLD.",
					OperationID: "listWhoisServers",
					Tags:        []string{"Server"},
					Responses: map[string]Response{
						"200": {Description: "WHOIS server list"},
					},
				},
			},
			"/api/v1/server/stats": {
				Get: &Operation{
					Summary:     "Server statistics",
					Description: "Returns aggregate server statistics (public-safe).",
					OperationID: "getStats",
					Tags:        []string{"Server"},
					Responses: map[string]Response{
						"200": {Description: "Server statistics"},
					},
				},
			},
			"/api/v1/server/schedulers": {
				Get: &Operation{
					Summary:     "List scheduler tasks",
					Description: "Returns configured scheduler tasks and their status. Requires server token.",
					OperationID: "listSchedulerTasks",
					Tags:        []string{"Server"},
					Security:    []SecurityReq{{"bearerAuth": {}}},
					Responses: map[string]Response{
						"200": {Description: "Scheduler task list"},
						"401": {Description: "Missing or invalid token"},
					},
				},
			},
			"/api/v1/server/backups": {
				Get: &Operation{
					Summary:     "List backups",
					Description: "Returns backup history. Requires server token.",
					OperationID: "listBackups",
					Tags:        []string{"Server"},
					Security:    []SecurityReq{{"bearerAuth": {}}},
					Responses: map[string]Response{
						"200": {Description: "Backup list"},
						"401": {Description: "Missing or invalid token"},
					},
				},
			},
			"/api/autodiscover": {
				Get: &Operation{
					Summary:     "Server autodiscovery",
					Description: "Returns server info and CLI version for auto-update.",
					OperationID: "autodiscover",
					Tags:        []string{"Server"},
					Responses: map[string]Response{
						"200": {Description: "Server autodiscovery info"},
					},
				},
			},
		},
		Components: Components{
			SecuritySchemes: map[string]SecurityScheme{
				"bearerAuth": {
					Type:         "http",
					Scheme:       "bearer",
					BearerFormat: "token",
					Description:  "Server token (Authorization: Bearer {server.token})",
				},
			},
			Schemas: map[string]Schema{
				"HealthResponse": {
					Type: "object",
					Properties: map[string]Schema{
						"ok":         {Type: "boolean"},
						"status":     {Type: "string"},
						"version":    {Type: "string"},
						"commit":     {Type: "string"},
						"build_date": {Type: "string"},
						"uptime":     {Type: "string"},
						"mode":       {Type: "string"},
						"database":   {Type: "string"},
						"cache":      {Type: "string"},
					},
				},
				"WhoisResponse": {
					Type: "object",
					Properties: map[string]Schema{
						"ok":   {Type: "boolean"},
						"data": {Ref: "#/components/schemas/WhoisRecord"},
					},
				},
				"WhoisRecord": {
					Type: "object",
					Properties: map[string]Schema{
						"query":              {Type: "string"},
						"query_type":         {Type: "string"},
						"source":             {Type: "string"},
						"registrant_name":    {Type: "string"},
						"registrant_org":     {Type: "string"},
						"registrant_email":   {Type: "string"},
						"registrant_country": {Type: "string"},
						"registrar":          {Type: "string"},
						"created_date":       {Type: "string", Format: "date-time"},
						"updated_date":       {Type: "string", Format: "date-time"},
						"expiry_date":        {Type: "string", Format: "date-time"},
						"nameservers":        {Type: "array", Items: &Schema{Type: "string"}},
						"status":             {Type: "array", Items: &Schema{Type: "string"}},
					},
				},
				"BulkRequest": {
					Type: "object",
					Properties: map[string]Schema{
						"queries": {Type: "array", Items: &Schema{Type: "string"}},
					},
				},
			},
		},
	}
}

// handleSwaggerUI serves the Swagger UI HTML page.
// Route: /server/docs/swagger (AI.md PART 14)
func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	baseURL := fmt.Sprintf("http://localhost:%d", s.config.Port)
	if s.config.FQDN != "" {
		baseURL = "https://" + s.config.FQDN
	}

	// Swagger UI HTML with dark theme support (AI.md PART 16)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>caswhois API - Swagger UI</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui.css" integrity="sha384-nF9R21t+/xRDFn2V5S2VvFbX12Xw2PPqNxvBwgKBWHqYcPLp6mGlnWWTJWqJfuXK" crossorigin="anonymous">
  <style>
    :root {
      --color-bg: #0d1117;
      --color-fg: #c9d1d9;
    }
    [data-theme="dark"] body {
      background: var(--color-bg);
    }
    [data-theme="dark"] .swagger-ui {
      filter: invert(88%%) hue-rotate(180deg);
    }
    [data-theme="dark"] .swagger-ui img {
      filter: invert(100%%) hue-rotate(180deg);
    }
    .swagger-ui .topbar { display: none; }
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
`, baseURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, html)
}
