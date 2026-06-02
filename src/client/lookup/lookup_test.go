package lookup

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- helpers ---

// makeWhoisJSON builds a valid apiResponse JSON string wrapping a whoisData payload.
func makeWhoisJSON(query, typ, server, timestamp, raw string) string {
	inner, _ := json.Marshal(whoisData{
		Query:     query,
		Type:      typ,
		Server:    server,
		Timestamp: timestamp,
		Raw:       raw,
	})
	outer, _ := json.Marshal(apiResponse{
		Ok:   true,
		Data: json.RawMessage(inner),
	})
	return string(outer)
}

// makeErrorJSON builds an apiResponse JSON string with ok=false.
func makeErrorJSON(code, message string) string {
	b, _ := json.Marshal(apiResponse{
		Ok:      false,
		Error:   code,
		Message: message,
	})
	return string(b)
}

// --- TestNew ---

// TestNew verifies that New strips trailing slashes and stores all fields.
func TestNew(t *testing.T) {
	cases := []struct {
		name      string
		serverURL string
		token     string
		version   string
		wantURL   string
	}{
		{
			name:      "trailing slash stripped",
			serverURL: "http://example.com/",
			token:     "tok_abc",
			version:   "1.0.0",
			wantURL:   "http://example.com",
		},
		{
			name:      "multiple trailing slashes stripped",
			serverURL: "http://example.com///",
			token:     "",
			version:   "",
			wantURL:   "http://example.com",
		},
		{
			name:      "no trailing slash unchanged",
			serverURL: "http://example.com",
			token:     "tok_xyz",
			version:   "2.3.4",
			wantURL:   "http://example.com",
		},
		{
			name:      "empty token and version stored as-is",
			serverURL: "http://example.com",
			token:     "",
			version:   "",
			wantURL:   "http://example.com",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.serverURL, tc.token, tc.version)
			if c.ServerURL != tc.wantURL {
				t.Errorf("ServerURL = %q, want %q", c.ServerURL, tc.wantURL)
			}
			if c.Token != tc.token {
				t.Errorf("Token = %q, want %q", c.Token, tc.token)
			}
			if c.Version != tc.version {
				t.Errorf("Version = %q, want %q", c.Version, tc.version)
			}
			if c.http == nil {
				t.Error("http client is nil")
			}
		})
	}
}

// --- TestLookup ---

// TestLookup exercises the generic /whois/{query} endpoint through a fake server.
func TestLookup(t *testing.T) {
	body := makeWhoisJSON("example.com", "domain", "whois.verisign-grs.com", "2024-01-01T00:00:00Z", "raw text")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/whois/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	c := New(srv.URL, "tok_test", "1.0.0")
	result, err := c.Lookup("example.com")
	if err != nil {
		t.Fatalf("Lookup error: %v", err)
	}
	if result.Query != "example.com" {
		t.Errorf("Query = %q, want %q", result.Query, "example.com")
	}
	if result.Type != "domain" {
		t.Errorf("Type = %q, want %q", result.Type, "domain")
	}
	if result.Server != "whois.verisign-grs.com" {
		t.Errorf("Server = %q, want %q", result.Server, "whois.verisign-grs.com")
	}
	if result.Raw != "raw text" {
		t.Errorf("Raw = %q, want %q", result.Raw, "raw text")
	}
}

// --- TestDomain ---

// TestDomain exercises the /whois/domain/{domain} endpoint.
func TestDomain(t *testing.T) {
	body := makeWhoisJSON("github.com", "domain", "whois.verisign-grs.com", "2024-01-01T00:00:00Z", "domain raw")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	c := New(srv.URL, "", "")
	result, err := c.Domain("github.com")
	if err != nil {
		t.Fatalf("Domain error: %v", err)
	}
	if result.Query != "github.com" {
		t.Errorf("Query = %q, want %q", result.Query, "github.com")
	}
}

// --- TestIP ---

// TestIP exercises the /whois/ip/{ip} endpoint.
func TestIP(t *testing.T) {
	body := makeWhoisJSON("8.8.8.8", "ip", "whois.arin.net", "2024-01-01T00:00:00Z", "ip raw")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	c := New(srv.URL, "tok_ip", "0.1.0")
	result, err := c.IP("8.8.8.8")
	if err != nil {
		t.Fatalf("IP error: %v", err)
	}
	if result.Type != "ip" {
		t.Errorf("Type = %q, want %q", result.Type, "ip")
	}
}

// --- TestASN ---

// TestASN exercises the /whois/asn/{asn} endpoint.
func TestASN(t *testing.T) {
	body := makeWhoisJSON("AS15169", "asn", "whois.radb.net", "2024-01-01T00:00:00Z", "asn raw")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	c := New(srv.URL, "", "1.2.3")
	result, err := c.ASN("AS15169")
	if err != nil {
		t.Fatalf("ASN error: %v", err)
	}
	if result.Query != "AS15169" {
		t.Errorf("Query = %q, want %q", result.Query, "AS15169")
	}
}

// --- TestDo (via Lookup) — error branch coverage ---

// TestDoErrorBranches drives all error paths inside do() using table-driven subtests.
func TestDoErrorBranches(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       string
		wantErrSub string
	}{
		{
			name:       "non-200 with JSON error body containing message",
			statusCode: http.StatusBadRequest,
			body:       makeErrorJSON("BAD_REQUEST", "query is invalid"),
			wantErrSub: "query is invalid",
		},
		{
			name:       "non-200 with JSON body but empty message falls through to HTTP status",
			statusCode: http.StatusForbidden,
			body:       makeErrorJSON("FORBIDDEN", ""),
			wantErrSub: "HTTP 403",
		},
		{
			name:       "non-200 with non-JSON body returns HTTP NNN",
			statusCode: http.StatusInternalServerError,
			body:       "internal server error plain text",
			wantErrSub: "HTTP 500",
		},
		{
			name:       "non-200 with empty body returns HTTP NNN",
			statusCode: http.StatusServiceUnavailable,
			body:       "",
			wantErrSub: "HTTP 503",
		},
		{
			name:       "200 with invalid JSON body returns unmarshal error",
			statusCode: http.StatusOK,
			body:       "not json at all",
			wantErrSub: "",
		},
		{
			name:       "200 with ok=false returns formatted error",
			statusCode: http.StatusOK,
			body:       makeErrorJSON("NOT_FOUND", "domain not found"),
			wantErrSub: "domain not found",
		},
		{
			name:       "200 with ok=true but invalid Data field returns unmarshal error",
			statusCode: http.StatusOK,
			body:       `{"ok":true,"data":"this is not a whoisData object"}`,
			wantErrSub: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()

			c := New(srv.URL, "", "")
			_, err := c.Lookup("example.com")
			if err == nil {
				t.Fatalf("expected error, got nil (body=%q status=%d)", tc.body, tc.statusCode)
			}
			if tc.wantErrSub != "" && !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrSub)
			}
		})
	}
}

// TestDoHTTPError verifies that a transport-level error (server closed before
// response) surfaces as a non-nil error from do().
func TestDoHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection to force a transport error.
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer srv.Close()

	c := New(srv.URL, "", "")
	_, err := c.Lookup("example.com")
	if err == nil {
		t.Fatal("expected transport error, got nil")
	}
}

// --- TestValidate ---

// TestValidate covers all branches of the Validate method.
func TestValidate(t *testing.T) {
	cases := []struct {
		name        string
		statusCode  int
		body        string
		wantErr     bool
		wantErrSub  string
		wantMessage string
	}{
		{
			name:        "ok=true returns message",
			statusCode:  http.StatusOK,
			body:        `{"ok":true,"message":"domain"}`,
			wantErr:     false,
			wantMessage: "domain",
		},
		{
			name:       "ok=false returns error with code and message",
			statusCode: http.StatusOK,
			body:       `{"ok":false,"error":"VALIDATION_FAILED","message":"not a valid query"}`,
			wantErr:    true,
			wantErrSub: "not a valid query",
		},
		{
			name:        "non-JSON body returns body as string",
			statusCode:  http.StatusOK,
			body:        "plain text response",
			wantErr:     false,
			wantMessage: "plain text response",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()

			c := New(srv.URL, "tok_v", "1.0.0")
			msg, err := c.Validate("example.com")

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.wantErrSub != "" && !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if msg != tc.wantMessage {
				t.Errorf("message = %q, want %q", msg, tc.wantMessage)
			}
		})
	}
}

// TestValidateHTTPError verifies that a transport-level failure in Validate
// surfaces as an error.
func TestValidateHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer srv.Close()

	c := New(srv.URL, "", "")
	_, err := c.Validate("example.com")
	if err == nil {
		t.Fatal("expected transport error, got nil")
	}
}

// --- TestHealthCheck ---

// TestHealthCheck covers the 200 OK path and non-200 path.
func TestHealthCheck(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		wantErr    bool
		wantErrSub string
	}{
		{
			name:       "200 OK returns nil",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "503 returns error with status code",
			statusCode: http.StatusServiceUnavailable,
			wantErr:    true,
			wantErrSub: "503",
		},
		{
			name:       "404 returns error with status code",
			statusCode: http.StatusNotFound,
			wantErr:    true,
			wantErrSub: "404",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer srv.Close()

			c := New(srv.URL, "", "")
			err := c.HealthCheck()

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.wantErrSub != "" && !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestHealthCheckHTTPError verifies a transport-level failure is surfaced.
func TestHealthCheckHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer srv.Close()

	c := New(srv.URL, "", "")
	err := c.HealthCheck()
	if err == nil {
		t.Fatal("expected transport error, got nil")
	}
}

// --- TestNewRequest (header behaviour) ---

// TestNewRequestHeaders verifies User-Agent and Authorization headers across
// all combinations of token/version presence.
func TestNewRequestHeaders(t *testing.T) {
	cases := []struct {
		name          string
		token         string
		version       string
		wantUserAgent string
		wantAuthSet   bool
	}{
		{
			name:          "token and version set",
			token:         "tok_abc123",
			version:       "1.2.3",
			wantUserAgent: "caswhois-cli/1.2.3",
			wantAuthSet:   true,
		},
		{
			name:          "token only, no version",
			token:         "tok_xyz",
			version:       "",
			wantUserAgent: "caswhois-cli",
			wantAuthSet:   true,
		},
		{
			name:          "version only, no token",
			token:         "",
			version:       "0.9.0",
			wantUserAgent: "caswhois-cli/0.9.0",
			wantAuthSet:   false,
		},
		{
			name:          "neither token nor version",
			token:         "",
			version:       "",
			wantUserAgent: "caswhois-cli",
			wantAuthSet:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var capturedReq *http.Request
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedReq = r
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			c := New(srv.URL, tc.token, tc.version)
			req, err := c.newRequest("GET", srv.URL)
			if err != nil {
				t.Fatalf("newRequest error: %v", err)
			}

			if got := req.Header.Get("User-Agent"); got != tc.wantUserAgent {
				t.Errorf("User-Agent = %q, want %q", got, tc.wantUserAgent)
			}

			authHeader := req.Header.Get("Authorization")
			if tc.wantAuthSet {
				wantAuth := fmt.Sprintf("Bearer %s", tc.token)
				if authHeader != wantAuth {
					t.Errorf("Authorization = %q, want %q", authHeader, wantAuth)
				}
			} else {
				if authHeader != "" {
					t.Errorf("Authorization should be absent, got %q", authHeader)
				}
			}

			if got := req.Header.Get("Accept"); got != "application/json" {
				t.Errorf("Accept = %q, want %q", got, "application/json")
			}

			// Suppress "declared but not used" — captured for future assertion expansion.
			_ = capturedReq
		})
	}
}

// TestNewRequestInvalidURL verifies that a URL containing a null byte causes
// newRequest to return a non-nil error.
func TestNewRequestInvalidURL(t *testing.T) {
	c := New("http://example.com", "", "")
	_, err := c.newRequest("GET", "http://example.com/\x00bad")
	if err == nil {
		t.Fatal("expected error for URL with null byte, got nil")
	}
}

// TestHealthCheckInvalidURL verifies that an unparseable server URL in HealthCheck
// surfaces as an error via newRequest.
func TestHealthCheckInvalidURL(t *testing.T) {
	c := &Client{
		ServerURL: "http://\x00invalid",
		http:      &http.Client{},
	}
	err := c.HealthCheck()
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

// TestValidateInvalidURL verifies that an unparseable server URL in Validate
// surfaces as an error via newRequest.
func TestValidateInvalidURL(t *testing.T) {
	c := &Client{
		ServerURL: "http://\x00invalid",
		http:      &http.Client{},
	}
	_, err := c.Validate("example.com")
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

// TestLookupInvalidURL verifies that an unparseable server URL in Lookup
// surfaces as an error via newRequest inside do().
func TestLookupInvalidURL(t *testing.T) {
	c := &Client{
		ServerURL: "http://\x00invalid",
		http:      &http.Client{},
	}
	_, err := c.Lookup("example.com")
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

// TestResultFields verifies every field on Result is populated correctly from
// a successful do() round-trip, including Timestamp.
func TestResultFields(t *testing.T) {
	const ts = "2024-06-01T12:34:56Z"
	body := makeWhoisJSON("192.0.2.1", "ip", "whois.arin.net", ts, "raw whois output")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	c := New(srv.URL, "", "")
	result, err := c.IP("192.0.2.1")
	if err != nil {
		t.Fatalf("IP error: %v", err)
	}
	if result.Timestamp != ts {
		t.Errorf("Timestamp = %q, want %q", result.Timestamp, ts)
	}
	if result.Raw != "raw whois output" {
		t.Errorf("Raw = %q, want %q", result.Raw, "raw whois output")
	}
	if result.Server != "whois.arin.net" {
		t.Errorf("Server = %q, want %q", result.Server, "whois.arin.net")
	}
}
