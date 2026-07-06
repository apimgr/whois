package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// RequestIDMiddleware / RequestIDFromContext
// ---------------------------------------------------------------------------

// TestRequestIDMiddleware_GeneratesID verifies that a unique X-Request-ID header
// is added to the response and stored in the request context.
func TestRequestIDMiddleware_GeneratesID(t *testing.T) {
	handler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := RequestIDFromContext(r.Context())
		if id == "" {
			t.Error("RequestIDFromContext returned empty string inside handler")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	hdr := rr.Header().Get("X-Request-ID")
	if hdr == "" {
		t.Error("X-Request-ID response header must be set")
	}
	if len(hdr) != 32 {
		t.Errorf("X-Request-ID length = %d, want 32 (hex-encoded 16 bytes)", len(hdr))
	}
}

// TestRequestIDMiddleware_ReusesTrustedHeader verifies that an upstream
// X-Request-ID header is passed through unchanged.
func TestRequestIDMiddleware_ReusesTrustedHeader(t *testing.T) {
	const upstreamID = "upstream-request-id-12345"

	handler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := RequestIDFromContext(r.Context())
		if id != upstreamID {
			t.Errorf("context ID = %q, want %q", id, upstreamID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", upstreamID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	hdr := rr.Header().Get("X-Request-ID")
	if hdr != upstreamID {
		t.Errorf("response X-Request-ID = %q, want %q", hdr, upstreamID)
	}
}

// TestRequestIDFromContext_Empty verifies that an empty context returns an empty string.
func TestRequestIDFromContext_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id := RequestIDFromContext(req.Context())
	if id != "" {
		t.Errorf("RequestIDFromContext with no ID set = %q, want empty", id)
	}
}

// ---------------------------------------------------------------------------
// PathSecurityMiddleware
// ---------------------------------------------------------------------------

// TestPathSecurityMiddleware_BlocksTraversal verifies that ".." paths return 400.
func TestPathSecurityMiddleware_BlocksTraversal(t *testing.T) {
	handler := PathSecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	paths := []string{
		"/../etc/passwd",
		"/api/../admin",
	}

	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("PathSecurityMiddleware(%q) = %d, want %d", p, rr.Code, http.StatusBadRequest)
		}
	}
}

// TestPathSecurityMiddleware_AllowsNormalPaths verifies that normal paths pass through.
func TestPathSecurityMiddleware_AllowsNormalPaths(t *testing.T) {
	handler := PathSecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	paths := []string{
		"/",
		"/api/v1/health",
		"/robots.txt",
		"/.well-known/security.txt",
		"/Server/Healthz",
	}

	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("PathSecurityMiddleware(%q) = %d, want %d (should pass through)", p, rr.Code, http.StatusOK)
		}
	}
}

// ---------------------------------------------------------------------------
// AllowlistMiddleware / BlocklistMiddleware
// ---------------------------------------------------------------------------

// TestAllowlistMiddleware_PassThrough verifies that the framework placeholder passes all requests.
func TestAllowlistMiddleware_PassThrough(t *testing.T) {
	handler := AllowlistMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("AllowlistMiddleware = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestBlocklistMiddleware_PassThrough verifies that the framework placeholder passes all requests.
func TestBlocklistMiddleware_PassThrough(t *testing.T) {
	handler := BlocklistMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("BlocklistMiddleware = %d, want %d", rr.Code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// extractClientIP
// ---------------------------------------------------------------------------

// TestExtractClientIP_XForwardedFor verifies that XFF is honored when the peer is trusted.
func TestExtractClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	// 10.0.0.2 is RFC 1918 — always trusted.
	req.RemoteAddr = "10.0.0.2:12345"

	ip := extractClientIP(req, nil)
	if ip != "203.0.113.5" {
		t.Errorf("extractClientIP (XFF) = %q, want %q", ip, "203.0.113.5")
	}
}

// TestExtractClientIP_XRealIP verifies that X-Real-IP is used when XFF is absent and peer is trusted.
func TestExtractClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "203.0.113.7")
	req.RemoteAddr = "10.0.0.2:12345"

	ip := extractClientIP(req, nil)
	if ip != "203.0.113.7" {
		t.Errorf("extractClientIP (X-Real-IP) = %q, want %q", ip, "203.0.113.7")
	}
}

// TestExtractClientIP_RemoteAddr verifies fallback to RemoteAddr when no proxy headers.
func TestExtractClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:54321"

	ip := extractClientIP(req, nil)
	if ip != "192.0.2.1" {
		t.Errorf("extractClientIP (RemoteAddr) = %q, want %q", ip, "192.0.2.1")
	}
}

// TestExtractClientIP_InvalidXFF verifies that an invalid XFF falls through to X-Real-IP.
func TestExtractClientIP_InvalidXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	req.Header.Set("X-Real-IP", "203.0.113.9")
	req.RemoteAddr = "10.0.0.2:12345"

	ip := extractClientIP(req, nil)
	if ip != "203.0.113.9" {
		t.Errorf("extractClientIP (invalid XFF, valid X-Real-IP) = %q, want %q", ip, "203.0.113.9")
	}
}

// TestExtractClientIP_UntrustedPeer_IgnoresXFF verifies that an untrusted peer
// (public IP) cannot spoof its IP via X-Forwarded-For (AI.md PART 12).
func TestExtractClientIP_UntrustedPeer_IgnoresXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8")
	// 203.0.113.1 is a public IP — not trusted.
	req.RemoteAddr = "203.0.113.1:12345"

	ip := extractClientIP(req, nil)
	if ip != "203.0.113.1" {
		t.Errorf("extractClientIP (untrusted peer) = %q, want %q (peer IP, not XFF)", ip, "203.0.113.1")
	}
}

// TestExtractClientIP_AdditionalTrusted verifies that a public IP listed in additional
// causes XFF to be honored (AI.md PART 12).
func TestExtractClientIP_AdditionalTrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	req.RemoteAddr = "203.0.113.50:12345"

	additional := []string{"203.0.113.50"}
	ip := extractClientIP(req, additional)
	if ip != "9.9.9.9" {
		t.Errorf("extractClientIP (additional trusted) = %q, want %q", ip, "9.9.9.9")
	}
}

// ---------------------------------------------------------------------------
// GeoIPMiddleware
// ---------------------------------------------------------------------------

// TestGeoIPMiddleware_NilManager verifies that a nil GeoIP manager passes all requests.
func TestGeoIPMiddleware_NilManager(t *testing.T) {
	mw := GeoIPMiddleware(nil, []string{"CN"}, nil, nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("GeoIPMiddleware(nil) = %d, want %d", rr.Code, http.StatusOK)
	}
}
