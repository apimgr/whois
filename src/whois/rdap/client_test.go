package rdap

import (
	"context"
	"encoding/json"
	"net"
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

// TestQueryDomain_Success verifies QueryDomain returns a valid DomainResponse from a mock server.
func TestQueryDomain_Success(t *testing.T) {
	t.Parallel()
	resp := DomainResponse{
		ObjectClassName: "domain",
		LDHName:         "example.com",
		Handle:          "2336799_DOMAIN_COM-VRSN",
	}
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	b := NewBootstrap(t.TempDir())
	b.dnsServices["com"] = []string{srv.URL + "/"}
	c := NewClient(b)

	got, endpoint, err := c.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain() error = %v", err)
	}
	if got.LDHName != "example.com" {
		t.Errorf("LDHName = %q, want %q", got.LDHName, "example.com")
	}
	if endpoint == "" {
		t.Error("QueryDomain() returned empty endpoint")
	}
}

// TestQueryIP_Success_IPv4 verifies QueryIP succeeds for an IPv4 address injected
// into the bootstrap directly.
func TestQueryIP_Success_IPv4(t *testing.T) {
	t.Parallel()
	resp := IPResponse{
		ObjectClassName: "ip network",
		Name:            "ARIN-NET",
		StartAddress:    "8.0.0.0",
		EndAddress:      "8.255.255.255",
	}
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	_, network, _ := net.ParseCIDR("8.0.0.0/8")
	b := NewBootstrap(t.TempDir())
	b.ipv4Services = append(b.ipv4Services, ipv4Range{network: network, services: []string{srv.URL + "/"}})
	c := NewClient(b)

	got, _, err := c.QueryIP(context.Background(), "8.8.8.8", false)
	if err != nil {
		t.Fatalf("QueryIP(IPv4) error = %v", err)
	}
	if got.Name != "ARIN-NET" {
		t.Errorf("Name = %q, want %q", got.Name, "ARIN-NET")
	}
}

// TestQueryIP_Success_IPv6 verifies QueryIP succeeds for an IPv6 address injected
// into the bootstrap directly.
func TestQueryIP_Success_IPv6(t *testing.T) {
	t.Parallel()
	resp := IPResponse{
		ObjectClassName: "ip network",
		Name:            "APNIC-V6",
		IPVersion:       "v6",
	}
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	_, network, _ := net.ParseCIDR("2001:4860::/32")
	b := NewBootstrap(t.TempDir())
	b.ipv6Services = append(b.ipv6Services, ipv6Range{network: network, services: []string{srv.URL + "/"}})
	c := NewClient(b)

	got, _, err := c.QueryIP(context.Background(), "2001:4860::1", true)
	if err != nil {
		t.Fatalf("QueryIP(IPv6) error = %v", err)
	}
	if got.Name != "APNIC-V6" {
		t.Errorf("Name = %q, want %q", got.Name, "APNIC-V6")
	}
}

// TestQueryASN_Success verifies QueryASN succeeds when an ASN range is injected.
func TestQueryASN_Success(t *testing.T) {
	t.Parallel()
	resp := ASNResponse{
		ObjectClassName: "autnum",
		StartAutnum:     15169,
		EndAutnum:       15169,
		Name:            "GOOGLE",
	}
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	b := NewBootstrap(t.TempDir())
	b.asnServices = append(b.asnServices, asnRange{start: 15169, end: 15169, services: []string{srv.URL + "/"}})
	c := NewClient(b)

	got, _, err := c.QueryASN(context.Background(), 15169)
	if err != nil {
		t.Fatalf("QueryASN() error = %v", err)
	}
	if got.Name != "GOOGLE" {
		t.Errorf("Name = %q, want %q", got.Name, "GOOGLE")
	}
}

// TestQueryIP_AllEndpointsFail_IPv4 verifies the "all endpoints failed" error path for IPv4.
func TestQueryIP_AllEndpointsFail_IPv4(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, network, _ := net.ParseCIDR("8.0.0.0/8")
	b := NewBootstrap(t.TempDir())
	b.ipv4Services = append(b.ipv4Services, ipv4Range{network: network, services: []string{srv.URL + "/"}})
	c := NewClient(b)

	_, _, err := c.QueryIP(context.Background(), "8.8.8.8", false)
	if err == nil {
		t.Error("QueryIP(IPv4) with failing endpoint should return error")
	}
}

// TestQueryIP_AllEndpointsFail_IPv6 verifies the "all endpoints failed" error path for IPv6.
func TestQueryIP_AllEndpointsFail_IPv6(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, network, _ := net.ParseCIDR("2001:4860::/32")
	b := NewBootstrap(t.TempDir())
	b.ipv6Services = append(b.ipv6Services, ipv6Range{network: network, services: []string{srv.URL + "/"}})
	c := NewClient(b)

	_, _, err := c.QueryIP(context.Background(), "2001:4860::1", true)
	if err == nil {
		t.Error("QueryIP(IPv6) with failing endpoint should return error")
	}
}
