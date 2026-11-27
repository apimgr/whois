package server

import (
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
