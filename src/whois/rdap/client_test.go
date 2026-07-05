package rdap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewClient verifies a client is constructed with a valid httpClient.
func TestNewClient(t *testing.T) {
	b := NewBootstrap(t.TempDir())
	c := NewClient(b)
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.httpClient == nil {
		t.Error("NewClient: httpClient is nil")
	}
	if c.bootstrap != b {
		t.Error("NewClient: bootstrap not set")
	}
}

// TestQueryDomain_NoEndpoints verifies QueryDomain returns an error when bootstrap
// has no endpoints for the given domain.
func TestQueryDomain_NoEndpoints(t *testing.T) {
	b := NewBootstrap(t.TempDir())
	c := NewClient(b)

	_, _, err := c.QueryDomain(context.Background(), "example.com")
	if err == nil {
		t.Error("QueryDomain() with no endpoints should return error")
	}
}

// TestQueryIP_NoEndpoints_IPv4 verifies QueryIP returns an error when bootstrap
// has no IPv4 endpoints.
func TestQueryIP_NoEndpoints_IPv4(t *testing.T) {
	b := NewBootstrap(t.TempDir())
	c := NewClient(b)

	_, _, err := c.QueryIP(context.Background(), "8.8.8.8", false)
	if err == nil {
		t.Error("QueryIP(IPv4) with no endpoints should return error")
	}
}

// TestQueryIP_NoEndpoints_IPv6 verifies QueryIP returns an error when bootstrap
// has no IPv6 endpoints.
func TestQueryIP_NoEndpoints_IPv6(t *testing.T) {
	b := NewBootstrap(t.TempDir())
	c := NewClient(b)

	_, _, err := c.QueryIP(context.Background(), "2001:4860:4860::8888", true)
	if err == nil {
		t.Error("QueryIP(IPv6) with no endpoints should return error")
	}
}

// TestQueryASN_NoEndpoints verifies QueryASN returns an error when bootstrap
// has no ASN endpoints.
func TestQueryASN_NoEndpoints(t *testing.T) {
	b := NewBootstrap(t.TempDir())
	c := NewClient(b)

	_, _, err := c.QueryASN(context.Background(), 15169)
	if err == nil {
		t.Error("QueryASN() with no endpoints should return error")
	}
}

// TestDoRequest_Success exercises doRequest via a real httptest server that returns 200.
func TestDoRequest_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"objectClassName":"domain"}`))
	}))
	defer srv.Close()

	b := NewBootstrap(t.TempDir())
	c := NewClient(b)

	body, err := c.doRequest(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("doRequest() error = %v", err)
	}
	if len(body) == 0 {
		t.Error("doRequest() returned empty body")
	}
}

// TestDoRequest_Unauthorized verifies doRequest returns an error on 401.
func TestDoRequest_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	b := NewBootstrap(t.TempDir())
	c := NewClient(b)

	_, err := c.doRequest(context.Background(), srv.URL)
	if err == nil {
		t.Error("doRequest() with 401 should return error")
	}
}

// TestDoRequest_Forbidden verifies doRequest returns an error on 403.
func TestDoRequest_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	b := NewBootstrap(t.TempDir())
	c := NewClient(b)

	_, err := c.doRequest(context.Background(), srv.URL)
	if err == nil {
		t.Error("doRequest() with 403 should return error")
	}
}

// TestDoRequest_NotFound verifies doRequest returns an error on 404.
func TestDoRequest_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	b := NewBootstrap(t.TempDir())
	c := NewClient(b)

	_, err := c.doRequest(context.Background(), srv.URL)
	if err == nil {
		t.Error("doRequest() with 404 should return error")
	}
}

// TestDoRequest_ErrorJSON verifies doRequest parses structured RDAP error responses.
func TestDoRequest_ErrorJSON(t *testing.T) {
	errBody, _ := json.Marshal(ErrorResponse{ErrorCode: 404, Title: "not found"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write(errBody)
	}))
	defer srv.Close()

	b := NewBootstrap(t.TempDir())
	c := NewClient(b)

	_, err := c.doRequest(context.Background(), srv.URL)
	if err == nil {
		t.Error("doRequest() with JSON error body should return error")
	}
}

// TestQueryDomain_AllEndpointsFail verifies the "all endpoints failed" error path.
func TestQueryDomain_AllEndpointsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	b := NewBootstrap(t.TempDir())
	b.dnsServices["com"] = []string{srv.URL + "/"}
	c := NewClient(b)

	_, _, err := c.QueryDomain(context.Background(), "example.com")
	if err == nil {
		t.Error("QueryDomain() with failing endpoint should return error")
	}
}

// TestQueryASN_AllEndpointsFail verifies the "all endpoints failed" error path for ASN.
func TestQueryASN_AllEndpointsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	b := NewBootstrap(t.TempDir())
	b.asnServices = append(b.asnServices, asnRange{start: 15169, end: 15169, services: []string{srv.URL + "/"}})
	c := NewClient(b)

	_, _, err := c.QueryASN(context.Background(), 15169)
	if err == nil {
		t.Error("QueryASN() with failing endpoint should return error")
	}
}
