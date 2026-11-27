package swagger

import (
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

// APIResponseModel is the standard JSON response envelope.
type APIResponseModel struct {
	OK      bool           `json:"ok"`
	Data    any            `json:"data,omitempty"`
	Error   string         `json:"error,omitempty"`
	Message string         `json:"message,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// Route is the shared API contract used to mount a handler and generate
// OpenAPI, llms.txt, MCP tools, and text responses.
type Route struct {
	Method        string
	Path          string
	OperationID   string
	Summary       string
	Auth          string
	Listed        bool
	Internal      bool
	DebugOnly     bool
	Request       any
	Response      any
	Primary       string
	Message       string
	Binary        string
	SuccessStatus int
	Handler       http.Handler
}

// Registry stores routes in registration order and rejects ambiguous contracts.
type Registry struct {
	routes []Route
	keys   map[string]struct{}
	ids    map[string]struct{}
}

func NewRegistry() *Registry {
	return &Registry{keys: make(map[string]struct{}), ids: make(map[string]struct{})}
}

// Add records one route definition. Mounting and generated API surfaces use
// the resulting registry rather than maintaining separate route lists.
func (r *Registry) Add(route Route) error {
	route.Method = strings.ToUpper(strings.TrimSpace(route.Method))
	if route.Method == "" || route.Path == "" || route.Handler == nil || route.OperationID == "" || route.Summary == "" {
		return fmt.Errorf("route requires method, path, operation ID, summary, and handler")
	}
	switch route.Auth {
	case "none", "owner", "operator", "token", "service":
	default:
		return fmt.Errorf("route %s has unsupported auth mode %q", route.Path, route.Auth)
	}
	key := route.Method + " " + route.Path
	if _, exists := r.keys[key]; exists {
		return fmt.Errorf("duplicate route %s", key)
	}
	if _, exists := r.ids[route.OperationID]; exists {
		return fmt.Errorf("duplicate operation ID %s", route.OperationID)
	}
	r.keys[key] = struct{}{}
	r.ids[route.OperationID] = struct{}{}
	r.routes = append(r.routes, route)
	return nil
}

func (r *Registry) Routes() []Route {
	return append([]Route(nil), r.routes...)
}

// ListedRoutes returns public and authenticated API entries that may be
// published to general API discovery surfaces.
func (r *Registry) ListedRoutes() []Route {
	var listed []Route
	for _, route := range r.routes {
		if route.Listed && !route.Internal && route.Auth != "operator" && route.Auth != "service" {
			listed = append(listed, route)
		}
	}
	return listed
}

func (r *Registry) Match(method, path string) (Route, bool) {
	for _, route := range r.routes {
		if route.Method != method || !routePatternMatches(route.Path, path) {
			continue
		}
		return route, true
	}
	return Route{}, false
}

func routePatternMatches(pattern, path string) bool {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	if len(patternParts) != len(pathParts) {
		return false
	}
	for i, part := range patternParts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			continue
		}
		if part != pathParts[i] {
			return false
		}
	}
	return true
}

// BuildSpecFromRoutes derives OpenAPI paths from the mounted route contract.
func BuildSpecFromRoutes(baseURL, version, apiBase string, routes []Route) OpenAPISpec {
	paths := make(map[string]PathItem)
	for _, route := range routes {
		if route.Internal || route.Auth == "service" || !strings.HasPrefix(route.Path, "/api/") {
			continue
		}
		path := configuredAPIPath(route.Path, apiBase)
		item := paths[path]
		status := route.SuccessStatus
		if status == 0 {
			status = http.StatusOK
		}
		description := "Successful response"
		if status == http.StatusCreated {
			description = "Resource created"
		}
		response := Response{Description: description, Content: map[string]MediaType{"application/json": {Schema: schemaFor(route.Response)}}}
		operation := &Operation{Summary: route.Summary, OperationID: route.OperationID, Responses: map[string]Response{strconv.Itoa(status): response}}
		if route.Auth == "owner" || route.Auth == "token" || route.Auth == "operator" {
			operation.Security = []SecurityReq{{"bearerAuth": {}}}
		}
		for _, part := range strings.Split(path, "/") {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				name := strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
				operation.Parameters = append(operation.Parameters, Parameter{Name: name, In: "path", Required: true, Schema: Schema{Type: "string"}})
			}
		}
		if route.Request != nil && route.Method == http.MethodGet {
			requestSchema := schemaFor(route.Request)
			for name, schema := range requestSchema.Properties {
				required := false
				for _, requiredName := range requestSchema.Required {
					if requiredName == name {
						required = true
						break
					}
				}
				operation.Parameters = append(operation.Parameters, Parameter{Name: name, In: "query", Required: required, Schema: schema})
			}
		} else if route.Request != nil {
			operation.RequestBody = &RequestBody{Required: true, Content: map[string]MediaType{"application/json": {Schema: schemaFor(route.Request)}}}
		}
		item.setOperation(route.Method, operation)
		paths[path] = item
	}
	components := Components{SecuritySchemes: map[string]SecurityScheme{"bearerAuth": {Type: "http", Scheme: "bearer", BearerFormat: "token", Description: "Bearer token"}}}
	return OpenAPISpec{
		OpenAPI:    "3.0.3",
		Info:       OpenAPIInfo{Title: "caswhois API", Description: "WHOIS lookup service with domain, IP, and ASN queries. Supports RDAP-first with WHOIS fallback.", Version: version},
		Servers:    []OpenAPIServer{{URL: baseURL, Description: "Current server"}},
		Paths:      paths,
		Components: components,
	}
}

func configuredAPIPath(path, apiBase string) string {
	if !strings.HasPrefix(path, "/api/") {
		return path
	}
	rest := strings.TrimPrefix(path, "/api/")
	versionEnd := strings.IndexByte(rest, '/')
	if versionEnd < 0 || !strings.HasPrefix(rest[:versionEnd], "v") {
		return path
	}
	return strings.TrimRight(apiBase, "/") + rest[versionEnd:]
}

func (p *PathItem) setOperation(method string, operation *Operation) {
	switch strings.ToUpper(method) {
	case http.MethodGet:
		p.Get = operation
	case http.MethodPost:
		p.Post = operation
	case http.MethodPut:
		p.Put = operation
	case http.MethodPatch:
		p.Patch = operation
	case http.MethodDelete:
		p.Delete = operation
	}
}

func schemaFor(value any) Schema {
	if value == nil {
		return Schema{Type: "object", Properties: map[string]Schema{}}
	}
	typeOf := reflect.TypeOf(value)
	for typeOf.Kind() == reflect.Pointer {
		typeOf = typeOf.Elem()
	}
	switch typeOf.Kind() {
	case reflect.Struct:
		properties := make(map[string]Schema)
		var required []string
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			if field.PkgPath != "" {
				continue
			}
			tag := field.Tag.Get("json")
			name := strings.Split(tag, ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			properties[name] = schemaFor(reflect.New(field.Type).Elem().Interface())
			if !strings.Contains(tag, "omitempty") {
				required = append(required, name)
			}
		}
		return Schema{Type: "object", Properties: properties, Required: required}
	case reflect.Slice, reflect.Array:
		return Schema{Type: "array", Items: refSchema(typeOf.Elem())}
	case reflect.Map:
		return Schema{Type: "object"}
	case reflect.Bool:
		return Schema{Type: "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return Schema{Type: "integer"}
	case reflect.Float32, reflect.Float64:
		return Schema{Type: "number"}
	case reflect.String:
		return Schema{Type: "string"}
	default:
		return Schema{Type: "object"}
	}
}

func refSchema(typeOf reflect.Type) *Schema {
	value := reflect.New(typeOf).Elem().Interface()
	schema := schemaFor(value)
	return &schema
}
