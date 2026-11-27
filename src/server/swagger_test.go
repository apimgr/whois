package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apimgr/whois/src/swagger"
)

// TestHandleSwaggerJSON verifies /api/swagger returns valid OpenAPI JSON.
func TestHandleSwaggerJSON(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/swagger", nil)
	rr := httptest.NewRecorder()

	s.handleSwaggerJSON(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var spec swagger.OpenAPISpec
	if err := json.Unmarshal(rr.Body.Bytes(), &spec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if spec.OpenAPI != "3.0.3" {
		t.Errorf("openapi = %q, want 3.0.3", spec.OpenAPI)
	}

	if spec.Info.Title != "caswhois API" {
		t.Errorf("info.title = %q, want caswhois API", spec.Info.Title)
	}

	if len(spec.Paths) == 0 {
		t.Error("paths is empty, expected endpoints")
	}
}

// TestHandleSwaggerJSONUsesRequestHost verifies the server URL uses the request host.
func TestHandleSwaggerJSONUsesRequestHost(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/swagger", nil)
	rr := httptest.NewRecorder()

	s.handleSwaggerJSON(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "http://example.com") {
		t.Error("spec should contain request-host-based server URL")
	}
}

// TestHandleSwaggerUI verifies /server/docs/swagger returns HTML.
func TestHandleSwaggerUI(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/server/docs/swagger", nil)
	rr := httptest.NewRecorder()

	s.handleSwaggerUI(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "swagger-ui") {
		t.Error("HTML should contain swagger-ui reference")
	}

	if !strings.Contains(body, "/api/swagger") {
		t.Error("HTML should reference /api/swagger endpoint")
	}
}

// TestBuildOpenAPISpec verifies the spec structure.
func TestBuildOpenAPISpec(t *testing.T) {
	s := newTestServer(t)
	_ = s.setupRoutes()
	recorder := httptest.NewRecorder()
	s.handleSwaggerJSON(recorder, httptest.NewRequest(http.MethodGet, "/api/swagger", nil))
	var spec swagger.OpenAPISpec
	if err := json.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}

	// Check required endpoints exist
	requiredPaths := []string{
		"/api/v1/server/healthz",
		"/api/v1/whois/{query}",
		"/api/v1/whois/domain/{domain}",
		"/api/v1/whois/ip/{ip}",
		"/api/v1/whois/asn/{asn}",
	}

	for _, path := range requiredPaths {
		if _, ok := spec.Paths[path]; !ok {
			t.Errorf("missing path: %s", path)
		}
	}

	// Check security scheme
	if _, ok := spec.Components.SecuritySchemes["bearerAuth"]; !ok {
		t.Error("missing bearerAuth security scheme")
	}

	if _, ok := spec.Paths["/api/v1/server/schedulers"]; ok {
		t.Error("operator-only routes must not appear in public OpenAPI")
	}
}
