package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRegisteredRoutesDispatch(t *testing.T) {
	s := newTestServer(t)
	root := t.TempDir()
	s.config.ConfigDir = filepath.Join(root, "config")
	s.config.DataDir = filepath.Join(root, "data")
	s.config.CacheDir = filepath.Join(root, "cache")
	s.config.LogDir = filepath.Join(root, "log")
	s.config.Backup.Dir = filepath.Join(root, "backup")
	if err := os.MkdirAll(s.config.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.config.ConfigDir, "server.yml"), []byte("server:\n  port: 8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.config.Debug = true
	s.config.ServerToken = "adm_route_inventory_test_token"
	handler := s.setupMiddleware(s.setupRoutes())

	var routes []struct {
		method string
		path   string
	}
	if err := chi.Walk(s.apiRouter, func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, struct {
			method string
			path   string
		}{method: method, path: path})
		return nil
	}); err != nil {
		t.Fatalf("walk registered routes: %v", err)
	}
	if len(routes) < 100 {
		t.Fatalf("route inventory contains %d method/path pairs, want at least 100", len(routes))
	}

	for _, route := range routes {
		t.Run(fmt.Sprintf("%s %s", route.method, route.path), func(t *testing.T) {
			path := sampleRoutePath(route.path)
			if route.path == "/debug/pprof/profile" || route.path == "/debug/pprof/trace" {
				path += "?seconds=1"
			}
			request := httptest.NewRequest(route.method, path, nil)
			request.Header.Set("Accept", "application/json")
			request.Header.Set("Authorization", "Bearer "+s.config.ServerToken)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code == 0 {
				t.Fatalf("%s %s wrote no HTTP response", route.method, path)
			}
		})
	}
}

func TestIDEAProjectAPIRoutesAreRegistered(t *testing.T) {
	idea, err := os.ReadFile(filepath.Join("..", "..", "IDEA.md"))
	if err != nil {
		t.Fatal(err)
	}
	declared := parseProjectAPIRoutes(string(idea))
	if len(declared) == 0 {
		t.Fatal("IDEA.md must define a non-empty ### API routes inventory")
	}
	s := newTestServer(t)
	_ = s.setupRoutes()
	var registered []struct{ method, path string }
	if err := chi.Walk(s.apiRouter, func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		registered = append(registered, struct{ method, path string }{method, path})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	declaredSet := make(map[projectAPIRoute]bool, len(declared))
	for _, route := range declared {
		route.path = strings.ReplaceAll(route.path, "{api_version}", s.config.APIVersion)
		declaredSet[route] = true
	}
	registeredSet := make(map[projectAPIRoute]bool)
	for _, route := range registered {
		if !strings.HasPrefix(route.path, s.config.APIBasePath()+"/whois") {
			continue
		}
		registeredSet[projectAPIRoute{method: route.method, path: route.path}] = true
	}
	for route := range declaredSet {
		if !registeredSet[route] {
			t.Errorf("IDEA.md API route %s %s is not registered", route.method, route.path)
		}
	}
	for route := range registeredSet {
		if !declaredSet[route] {
			t.Errorf("registered project API route %s %s is missing from IDEA.md", route.method, route.path)
		}
	}
}

func TestAPIRegistryDrivesOpenAPIAndDiscovery(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()
	registered := s.apiRoutes()
	if len(registered) == 0 {
		t.Fatal("API route registry is empty")
	}
	mounted := make(map[projectAPIRoute]bool)
	if err := chi.Walk(s.apiRouter, func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		mounted[projectAPIRoute{method: method, path: path}] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, route := range registered {
		if !mounted[projectAPIRoute{method: route.Method, path: route.Path}] {
			t.Errorf("registered route %s %s was not mounted from the registry", route.Method, route.Path)
		}
	}
	openAPIRecorder := httptest.NewRecorder()
	openAPIRequest := httptest.NewRequest(http.MethodGet, "/api/swagger", nil)
	openAPIRequest.Header.Set("Accept", "application/json")
	handler.ServeHTTP(openAPIRecorder, openAPIRequest)
	if openAPIRecorder.Code != http.StatusOK {
		t.Fatalf("OpenAPI status = %d", openAPIRecorder.Code)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			OperationID string                     `json:"operationId"`
			Responses   map[string]json.RawMessage `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(openAPIRecorder.Body.Bytes(), &spec); err != nil {
		t.Fatalf("decode generated OpenAPI: %v", err)
	}
	for _, route := range registered {
		if route.Internal || route.Auth == "operator" || route.Auth == "service" || !route.Listed || !strings.HasPrefix(route.Path, "/api/") {
			continue
		}
		path := strings.Replace(route.Path, "/api/v1", s.config.APIBasePath(), 1)
		operations, exists := spec.Paths[path]
		if !exists {
			t.Errorf("listed route %s %s missing from OpenAPI", route.Method, path)
			continue
		}
		method := strings.ToLower(route.Method)
		operation, exists := operations[method]
		if !exists || operation.OperationID != route.OperationID {
			t.Errorf("listed route %s %s has no matching OpenAPI operation ID %q", route.Method, path, route.OperationID)
			continue
		}
		status := route.SuccessStatus
		if status == 0 {
			status = http.StatusOK
		}
		if _, exists := operation.Responses[fmt.Sprint(status)]; !exists {
			t.Errorf("OpenAPI %s %s omits success status %d", route.Method, path, status)
		}
	}
	llmsRecorder := httptest.NewRecorder()
	llmsRequest := httptest.NewRequest(http.MethodGet, "/llms.txt", nil)
	handler.ServeHTTP(llmsRecorder, llmsRequest)
	for _, route := range registered {
		if route.Listed && !route.Internal && route.Auth != "operator" && route.Auth != "service" && strings.HasPrefix(route.Path, "/api/") && !strings.Contains(llmsRecorder.Body.String(), route.Path) {
			t.Errorf("listed route %s %s missing from llms.txt", route.Method, route.Path)
		}
	}
}

type projectAPIRoute struct{ method, path string }

func parseProjectAPIRoutes(idea string) []projectAPIRoute {
	lines := strings.Split(idea, "\n")
	start, end := -1, len(lines)
	for i, line := range lines {
		if strings.TrimSpace(line) == "### API routes" {
			start = i + 1
			continue
		}
		if start >= 0 && (strings.HasPrefix(strings.TrimSpace(line), "### ") || strings.HasPrefix(strings.TrimSpace(line), "## ")) {
			end = i
			break
		}
	}
	if start < 0 {
		return nil
	}
	var headers []string
	var routes []projectAPIRoute
	for _, line := range lines[start:end] {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(headers) == 0 {
			headers = make([]string, len(cells))
			for i, cell := range cells {
				headers[i] = strings.ToLower(strings.TrimSpace(cell))
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(cells[0]), "-") {
			continue
		}
		methodCol, pathCol := -1, -1
		for i, header := range headers {
			if header == "method" || header == "methods" {
				methodCol = i
			}
			if header == "path" || header == "route" || header == "endpoint" {
				pathCol = i
			}
		}
		if methodCol < 0 || pathCol < 0 || methodCol >= len(cells) || pathCol >= len(cells) {
			continue
		}
		method, path := strings.TrimSpace(cells[methodCol]), strings.TrimSpace(cells[pathCol])
		if len(path) < 3 || path[0] != '`' || path[len(path)-1] != '`' {
			continue
		}
		path = path[1 : len(path)-1]
		for _, part := range strings.FieldsFunc(method, func(r rune) bool { return r == '/' || r == ',' }) {
			routes = append(routes, projectAPIRoute{strings.TrimSpace(part), path})
		}
	}
	return routes
}

func sampleRoutePath(pattern string) string {
	path := strings.ReplaceAll(pattern, "/*", "/invalid..example")
	for {
		start := strings.IndexByte(path, '{')
		if start < 0 {
			return path
		}
		end := strings.IndexByte(path[start:], '}')
		if end < 0 {
			return path
		}
		path = path[:start] + "test-id" + path[start+end+1:]
	}
}
