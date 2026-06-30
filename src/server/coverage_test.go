package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// --- content negotiation (content.go) ---

// TestRespondWithFormatJSON verifies RespondWithFormat sends JSON when Accept: application/json.
func TestRespondWithFormatJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()

	RespondWithFormat(rr, req, map[string]string{"key": "val"})

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestRespondWithFormatText verifies RespondWithFormat sends plain text when Accept: text/plain.
func TestRespondWithFormatText(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/plain")
	rr := httptest.NewRecorder()

	RespondWithFormat(rr, req, "hello world")

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if !strings.Contains(rr.Body.String(), "hello world") {
		t.Errorf("body missing text, got: %s", rr.Body.String())
	}
}

// TestRespondWithFormatHTML verifies RespondWithFormat sends HTML when Accept: text/html.
func TestRespondWithFormatHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()

	RespondWithFormat(rr, req, "hello")

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// TestRespondError covers all three format branches of RespondError.
func TestRespondError(t *testing.T) {
	cases := []struct {
		name        string
		accept      string
		wantCTMatch string
	}{
		{"json error", "application/json", "application/json"},
		{"text error", "text/plain", "text/plain"},
		{"html error", "text/html", "text/html"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept", tc.accept)
			rr := httptest.NewRecorder()

			RespondError(rr, req, http.StatusBadRequest, "test error message")

			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rr.Code)
			}
			ct := rr.Header().Get("Content-Type")
			if !strings.Contains(ct, tc.wantCTMatch) {
				t.Errorf("Content-Type = %q, want %q", ct, tc.wantCTMatch)
			}
		})
	}
}

// stringerVal is a local type that implements fmt.Stringer for testing.
type stringerVal struct{ s string }

func (sv stringerVal) String() string { return sv.s }

// TestRespondTextStringer verifies respondText calls .String() on fmt.Stringer values.
func TestRespondTextStringer(t *testing.T) {
	rr := httptest.NewRecorder()
	respondText(rr, http.StatusOK, stringerVal{"stringer test"})
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "stringer test") {
		t.Errorf("body = %q, want to contain 'stringer test'", rr.Body.String())
	}
}

// TestRespondTextNonString verifies respondText handles non-string, non-Stringer values.
func TestRespondTextNonString(t *testing.T) {
	rr := httptest.NewRecorder()
	respondText(rr, http.StatusOK, 42)
	if !strings.Contains(rr.Body.String(), "42") {
		t.Errorf("body = %q, want to contain '42'", rr.Body.String())
	}
}

// --- errors.go ---

// TestWriteJSONTrailingNewline ensures writeJSON always appends exactly one newline.
func TestWriteJSONTrailingNewline(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusOK, map[string]string{"x": "y"})
	body := rr.Body.String()
	if !strings.HasSuffix(body, "\n") {
		t.Errorf("body does not end with newline: %q", body)
	}
	trimmed := strings.TrimRight(body, "\n")
	if strings.HasSuffix(trimmed, "\n") {
		t.Error("body ends with more than one newline")
	}
}

// TestSendSuccessWithMetadata verifies SendSuccess encodes nested data correctly.
func TestSendSuccessWithMetadata(t *testing.T) {
	rr := httptest.NewRecorder()
	SendSuccess(rr, map[string]interface{}{
		"count":   3,
		"results": []string{"a", "b", "c"},
	})
	var resp APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK {
		t.Error("resp.OK = false, want true")
	}
}

// TestSendErrorRetryAfterHeader verifies ErrRateLimited sets Retry-After header.
func TestSendErrorRetryAfterHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	SendError(rr, ErrRateLimited, "rate limited")
	if rr.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing on 429")
	}
}

// TestSendErrorTokenCodes verifies TOKEN_EXPIRED and TOKEN_INVALID map to 401.
func TestSendErrorTokenCodes(t *testing.T) {
	for _, code := range []string{ErrTokenExpired, ErrTokenInvalid} {
		t.Run(code, func(t *testing.T) {
			rr := httptest.NewRecorder()
			SendError(rr, code, "token error")
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("SendError(%q) = %d, want 401", code, rr.Code)
			}
		})
	}
}

// TestStatusToErrorCode covers all mapping branches.
func TestStatusToErrorCode(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusBadRequest, ErrBadRequest},
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrForbidden},
		{http.StatusNotFound, ErrNotFound},
		{http.StatusMethodNotAllowed, ErrMethodNotAllowed},
		{http.StatusConflict, ErrConflict},
		{http.StatusTooManyRequests, ErrRateLimited},
		{http.StatusServiceUnavailable, ErrMaintenance},
		{http.StatusInternalServerError, ErrServerError},
		{599, ErrServerError},
	}

	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			got := statusToErrorCode(tc.status)
			if got != tc.want {
				t.Errorf("statusToErrorCode(%d) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

// TestMapErrorCodeToStatusAllCodes ensures every defined error constant maps correctly.
func TestMapErrorCodeToStatusAllCodes(t *testing.T) {
	cases := []struct {
		code string
		want int
	}{
		{ErrBadRequest, http.StatusBadRequest},
		{ErrValidationFailed, http.StatusBadRequest},
		{ErrUnauthorized, http.StatusUnauthorized},
		{ErrTokenExpired, http.StatusUnauthorized},
		{ErrTokenInvalid, http.StatusUnauthorized},
		{ErrForbidden, http.StatusForbidden},
		{ErrNotFound, http.StatusNotFound},
		{ErrMethodNotAllowed, http.StatusMethodNotAllowed},
		{ErrConflict, http.StatusConflict},
		{ErrRateLimited, http.StatusTooManyRequests},
		{ErrMaintenance, http.StatusServiceUnavailable},
		{ErrServerError, http.StatusInternalServerError},
		{"UNKNOWN_CODE", http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			got := mapErrorCodeToStatus(tc.code)
			if got != tc.want {
				t.Errorf("mapErrorCodeToStatus(%q) = %d, want %d", tc.code, got, tc.want)
			}
		})
	}
}

// TestHandleNotFoundHTMLContainsDOCTYPE checks the HTML 404 body has DOCTYPE.
func TestHandleNotFoundHTMLContainsDOCTYPE(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/some-page", nil)
	rr := httptest.NewRecorder()

	s.handleNotFound(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// --- middleware.go ---

// TestURLNormalizeMiddlewareRoot verifies the root path is passed through unchanged.
func TestURLNormalizeMiddlewareRoot(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != "/" {
			t.Errorf("path = %q, want /", r.URL.Path)
		}
	})
	h := URLNormalizeMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next handler was not called")
	}
}

// TestURLNormalizeMiddlewareTrailingSlashRedirect verifies trailing slashes trigger 301.
func TestURLNormalizeMiddlewareTrailingSlashRedirect(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called on redirect")
	})
	h := URLNormalizeMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/about/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/about" {
		t.Errorf("Location = %q, want /about", loc)
	}
}

// TestURLNormalizeMiddlewareFileExtNoRedirect verifies paths ending in a filename (no trailing slash)
// pass through without redirect. The exception only applies to the last path segment containing ".".
func TestURLNormalizeMiddlewareFileExtNoRedirect(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	h := URLNormalizeMiddleware(next)
	// No trailing slash — passes through unchanged.
	req := httptest.NewRequest(http.MethodGet, "/dir/index.html", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next should be called for path without trailing slash")
	}
}

// TestURLNormalizeMiddlewarePreservesQueryString verifies the redirect preserves query params.
func TestURLNormalizeMiddlewarePreservesQueryString(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := URLNormalizeMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/about/?foo=bar", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "foo=bar") {
		t.Errorf("Location = %q, want to contain query string", loc)
	}
}

// TestPathSecurityMiddlewareSafePath verifies safe paths pass through.
func TestPathSecurityMiddlewareSafePath(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	h := PathSecurityMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next handler not called for safe path")
	}
}

// TestPathSecurityMiddlewareTraversalBlocked verifies .. traversal returns 400.
func TestPathSecurityMiddlewareTraversalBlocked(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called on traversal")
	})
	h := PathSecurityMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/api/../etc/passwd", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for traversal attempt", rr.Code)
	}
}

// TestSecurityHeadersMiddleware verifies all required security headers are set.
func TestSecurityHeadersMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := SecurityHeadersMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for header, want := range headers {
		got := rr.Header().Get(header)
		if got != want {
			t.Errorf("header %q = %q, want %q", header, got, want)
		}
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy header missing")
	}
}

// TestRateLimitMiddlewareNilLimiter verifies nil limiter passes all requests through.
func TestRateLimitMiddlewareNilLimiter(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := RateLimitMiddleware(nil, 0, 0)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next not called with nil limiter")
	}
}

// TestAuthMiddlewarePassThrough verifies AuthMiddleware is a pass-through.
func TestAuthMiddlewarePassThrough(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := AuthMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next not called by AuthMiddleware")
	}
}

// TestLoggingMiddlewareRecordsStats verifies stats counters update through LoggingMiddleware.
func TestLoggingMiddlewareRecordsStats(t *testing.T) {
	s := newTestServer(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.LoggingMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := s.stats.requestsTotal.Load(); got != 1 {
		t.Errorf("requestsTotal = %d, want 1", got)
	}
}

// TestCORSMiddlewareDisabled verifies empty cors value skips CORS headers.
func TestCORSMiddlewareDisabled(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := CORSMiddleware("")(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS headers set when cors = empty string")
	}
}

// TestCORSMiddlewareWildcard verifies * cors allows all origins.
func TestCORSMiddlewareWildcard(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := CORSMiddleware("*")(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestCORSMiddlewareSpecificOriginMatch verifies specific origin is reflected and credentials allowed.
func TestCORSMiddlewareSpecificOriginMatch(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	origin := "https://app.example.com"
	h := CORSMiddleware(origin)(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Origin", origin)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Header().Get("Access-Control-Allow-Origin") != origin {
		t.Errorf("Allow-Origin = %q, want %q", rr.Header().Get("Access-Control-Allow-Origin"), origin)
	}
	if rr.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("Allow-Credentials not set for specific origin match")
	}
}

// TestCORSMiddlewarePreflight verifies OPTIONS returns 204 with CORS headers.
func TestCORSMiddlewarePreflight(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called on OPTIONS preflight")
	})
	h := CORSMiddleware("*")(next)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rr.Code)
	}
}

// TestCORSMiddlewareNonAPIPathSkipped verifies non-API paths don't get CORS headers.
func TestCORSMiddlewareNonAPIPathSkipped(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := CORSMiddleware("*")(next)
	req := httptest.NewRequest(http.MethodGet, "/about", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next not called for non-API path")
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS headers set on non-API path")
	}
}

// --- middleware_i18n.go ---

// TestLanguageMiddlewareQueryParam verifies ?lang= sets the language in context and cookie.
func TestLanguageMiddlewareQueryParam(t *testing.T) {
	var gotLang string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLang = LangFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := LanguageMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/?lang=es", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if gotLang != "es" {
		t.Errorf("lang in context = %q, want es", gotLang)
	}
	var cookieSet bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "lang" && c.Value == "es" {
			cookieSet = true
		}
	}
	if !cookieSet {
		t.Error("lang cookie not set")
	}
}

// TestLanguageMiddlewareCookie verifies the lang cookie sets context language.
func TestLanguageMiddlewareCookie(t *testing.T) {
	var gotLang string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLang = LangFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := LanguageMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "fr"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if gotLang != "fr" {
		t.Errorf("lang in context = %q, want fr", gotLang)
	}
}

// TestLanguageMiddlewareAcceptLanguageHeader verifies Accept-Language header fallback.
func TestLanguageMiddlewareAcceptLanguageHeader(t *testing.T) {
	var gotLang string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLang = LangFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := LanguageMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "de,en;q=0.9")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if gotLang != "de" {
		t.Errorf("lang in context = %q, want de", gotLang)
	}
}

// TestLanguageMiddlewareDefaultFallback verifies default lang is "en" when nothing set.
func TestLanguageMiddlewareDefaultFallback(t *testing.T) {
	var gotLang string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLang = LangFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := LanguageMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if gotLang != "en" {
		t.Errorf("lang in context = %q, want en as default", gotLang)
	}
}

// TestLanguageMiddlewareUnsupportedLangIgnored verifies unsupported lang reverts to default.
func TestLanguageMiddlewareUnsupportedLangIgnored(t *testing.T) {
	var gotLang string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLang = LangFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := LanguageMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/?lang=xx", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if gotLang == "xx" {
		t.Error("unsupported lang 'xx' should not be used")
	}
}

// TestLangFromContextEmpty verifies LangFromContext returns "en" when context has no lang.
func TestLangFromContextEmpty(t *testing.T) {
	lang := LangFromContext(context.Background())
	if lang != "en" {
		t.Errorf("LangFromContext(empty) = %q, want en", lang)
	}
}

// --- token_auth.go ---

// TestExtractBearerToken verifies token extraction from Authorization header.
func TestExtractBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"valid bearer", "Bearer mytoken123", "mytoken123"},
		{"missing bearer", "Basic xyz", ""},
		{"empty header", "", ""},
		{"bearer only no token", "Bearer ", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			got := extractBearerToken(req)
			if got != tc.want {
				t.Errorf("extractBearerToken() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTokenHash verifies SHA-256 hash produces consistent hex output.
func TestTokenHash(t *testing.T) {
	h1 := TokenHash("mysecret")
	h2 := TokenHash("mysecret")
	if h1 != h2 {
		t.Error("TokenHash: same input produced different outputs")
	}
	if len(h1) != 64 {
		t.Errorf("TokenHash length = %d, want 64 hex chars", len(h1))
	}
	h3 := TokenHash("othersecret")
	if h1 == h3 {
		t.Error("TokenHash: different inputs produced same output")
	}
}

// TestTokenPrefix verifies prefix truncation.
func TestTokenPrefix(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"short", "short"},
		{"exactly12chars", "exactly12cha"},
		{"this_is_a_very_long_token_string", "this_is_a_ve"},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got := TokenPrefix(tc.raw)
			if got != tc.want {
				t.Errorf("TokenPrefix(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// resetTokenOnce resets the package-level sync.Once so requireToken tests
// can inject a fresh server token. Tests that need a specific token must
// call this helper and then set s.config.ServerToken before calling requireToken.
func resetTokenOnce(token string) {
	serverTokenHashOnce = sync.Once{}
	serverTokenHashVal = nil
	_ = token
}

// TestRequireTokenMissing verifies 401 when Authorization header is absent.
// Missing header is independent of the cached token hash — no reset needed.
func TestRequireTokenMissing(t *testing.T) {
	s := newTestServer(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	protected := s.requireToken(inner)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()
	protected(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when no token", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("WWW-Authenticate header missing on 401")
	}
}

// TestRequireTokenInvalid verifies 401 when a non-matching token is sent.
// Resets the singleton so we can set a known server token.
func TestRequireTokenInvalid(t *testing.T) {
	resetTokenOnce("knowntoken")
	s := newTestServer(t)
	s.config.ServerToken = "knowntoken"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	protected := s.requireToken(inner)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer wrongtoken")
	rr := httptest.NewRecorder()
	protected(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for wrong token", rr.Code)
	}
}

// TestRequireTokenValid verifies 200 when the correct token is provided.
// Resets the singleton so we can set a known server token.
func TestRequireTokenValid(t *testing.T) {
	const tok = "my-valid-test-token"
	resetTokenOnce(tok)
	s := newTestServer(t)
	s.config.ServerToken = tok

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	protected := s.requireToken(inner)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	protected(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with correct token", rr.Code)
	}
}

// --- pwa.go ---

// TestHandleManifest verifies /manifest.json returns valid JSON with required fields.
func TestHandleManifest(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
	rr := httptest.NewRecorder()

	s.handleManifest(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "manifest") {
		t.Errorf("Content-Type = %q, want application/manifest+json", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "start_url") {
		t.Error("manifest missing start_url")
	}
	if !strings.Contains(body, "icons") {
		t.Error("manifest missing icons")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
}

// TestHandleManifestBrandingFallback verifies empty branding uses defaults.
func TestHandleManifestBrandingFallback(t *testing.T) {
	s := newTestServer(t)
	s.config.Branding.Title = ""
	s.config.Branding.Description = ""
	s.config.Branding.AccentColor = ""

	req := httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
	rr := httptest.NewRecorder()
	s.handleManifest(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "caswhois") {
		t.Error("manifest should use 'caswhois' as default name")
	}
}

// TestHandleServiceWorker verifies /sw.js returns JavaScript.
func TestHandleServiceWorker(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/sw.js", nil)
	rr := httptest.NewRecorder()

	s.handleServiceWorker(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want application/javascript", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "CACHE_NAME") {
		t.Error("service worker missing CACHE_NAME constant")
	}
	if rr.Header().Get("Service-Worker-Allowed") != "/" {
		t.Error("Service-Worker-Allowed header missing or wrong value")
	}
	if rr.Header().Get("Cache-Control") != "no-cache" {
		t.Error("Cache-Control should be no-cache for service worker")
	}
}

// TestHandleOfflinePage verifies /offline.html returns valid HTML.
func TestHandleOfflinePage(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/offline.html", nil)
	rr := httptest.NewRecorder()

	s.handleOfflinePage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("offline page missing DOCTYPE")
	}
	if !strings.Contains(body, "offline") {
		t.Error("offline page missing offline text")
	}
}

// --- autodiscover.go ---

// TestHandleAutodiscoverGet verifies GET /api/autodiscover returns the expected structure.
func TestHandleAutodiscoverGet(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/autodiscover", nil)
	req.Host = "localhost:8080"
	rr := httptest.NewRecorder()

	s.handleAutodiscover(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}

	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Errorf("resp.OK = false, want true")
	}

	data := decodeDataMap(t, resp)
	if data["api_version"] != "v1" {
		t.Errorf("api_version = %v, want v1", data["api_version"])
	}
	if data["base_url"] == nil || data["base_url"] == "" {
		t.Error("base_url missing from autodiscover response")
	}
}

// TestHandleAutodiscoverMethodNotAllowed verifies POST returns 405.
func TestHandleAutodiscoverMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/autodiscover", nil)
	rr := httptest.NewRecorder()

	s.handleAutodiscover(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestHandleAutodiscoverXForwardedProto verifies X-Forwarded-Proto sets https in base_url.
func TestHandleAutodiscoverXForwardedProto(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/autodiscover", nil)
	req.Host = "example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()

	s.handleAutodiscover(rr, req)

	resp := decodeAPIResponse(t, rr.Body.String())
	data := decodeDataMap(t, resp)
	baseURL, _ := data["base_url"].(string)
	if !strings.HasPrefix(baseURL, "https://") {
		t.Errorf("base_url = %q, want https:// prefix when X-Forwarded-Proto: https", baseURL)
	}
}

// --- content_pages.go ---

// TestHandleAboutPage verifies the about page returns HTML with expected content.
func TestHandleAboutPage(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/about", nil)
	rr := httptest.NewRecorder()

	s.handleAboutPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// TestHandleAboutPageBrandingFallback verifies defaults applied when branding is empty.
func TestHandleAboutPageBrandingFallback(t *testing.T) {
	s := newTestServer(t)
	s.config.Branding.Title = ""
	s.config.Branding.Tagline = ""
	s.config.Branding.Description = ""

	req := httptest.NewRequest(http.MethodGet, "/about", nil)
	rr := httptest.NewRecorder()

	s.handleAboutPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (branding defaults applied)", rr.Code)
	}
}

// TestHandleDocsPage verifies the docs page returns HTML.
func TestHandleDocsPage(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rr := httptest.NewRecorder()

	s.handleDocsPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// TestHandleDocsPageBrandingFallback verifies fallback when branding title is empty.
func TestHandleDocsPageBrandingFallback(t *testing.T) {
	s := newTestServer(t)
	s.config.Branding.Title = ""

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rr := httptest.NewRecorder()

	s.handleDocsPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (branding fallback)", rr.Code)
	}
}

// --- ops_handlers.go ---

// TestHandleSchedulerStatusMethodNotAllowed verifies POST returns 405.
func TestHandleSchedulerStatusMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/schedulers", nil)
	rr := httptest.NewRecorder()

	s.handleSchedulerStatus(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestHandleSchedulerStatusWithScheduler verifies GET returns tasks list.
func TestHandleSchedulerStatusWithScheduler(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/schedulers", nil)
	rr := httptest.NewRecorder()

	s.handleSchedulerStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Error("resp.OK = false, want true")
	}
}

// TestHandleSchedulerRunMethodNotAllowed verifies GET returns 405.
func TestHandleSchedulerRunMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/schedulers/run", nil)
	rr := httptest.NewRecorder()

	s.handleSchedulerRun(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestHandleSchedulerRunMissingTask verifies POST without task param returns 400.
func TestHandleSchedulerRunMissingTask(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/schedulers/run", nil)
	rr := httptest.NewRecorder()

	s.handleSchedulerRun(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing task", rr.Code)
	}
}

// TestHandleSchedulerRunUnknownTask verifies unknown task ID returns 404.
func TestHandleSchedulerRunUnknownTask(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/schedulers/run?task=does-not-exist", nil)
	rr := httptest.NewRecorder()

	s.handleSchedulerRun(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for unknown task", rr.Code)
	}
}

// TestHandleBackupStatusMethodNotAllowed verifies POST returns 405.
func TestHandleBackupStatusMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/backups", nil)
	rr := httptest.NewRecorder()

	s.handleBackupStatus(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestHandleBackupStatusNoDir verifies empty backup dir returns empty list (not an error).
func TestHandleBackupStatusNoDir(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/backups", nil)
	rr := httptest.NewRecorder()

	s.handleBackupStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when backup dir missing", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Error("resp.OK = false, want true when backup dir missing")
	}
}

// TestHandleBackupRunMethodNotAllowed verifies GET returns 405.
func TestHandleBackupRunMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/backups/run", nil)
	rr := httptest.NewRecorder()

	s.handleBackupRun(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestHandleBackupRunPost verifies POST triggers backup asynchronously and returns 200.
func TestHandleBackupRunPost(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/backups/run", nil)
	rr := httptest.NewRecorder()

	s.handleBackupRun(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Error("resp.OK = false on backup run trigger")
	}
	data := decodeDataMap(t, resp)
	started, _ := data["started"].(bool)
	if !started {
		t.Error("data.started = false, want true")
	}
}

// --- api.go ---

// TestHandleWhoisServers verifies GET /api/v1/whois-servers returns a list.
func TestHandleWhoisServers(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois-servers", nil)
	rr := httptest.NewRecorder()

	s.handleWhoisServers(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Error("resp.OK = false for whois-servers")
	}
	data := decodeDataMap(t, resp)
	if _, ok := data["count"]; !ok {
		t.Error("response missing count field")
	}
}

// TestHandleStats verifies GET /api/v1/stats returns cache and uptime data.
func TestHandleStats(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	rr := httptest.NewRecorder()

	s.handleStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Error("resp.OK = false for stats")
	}
	data := decodeDataMap(t, resp)
	if _, ok := data["uptime"]; !ok {
		t.Error("stats response missing uptime field")
	}
	if _, ok := data["cache"]; !ok {
		t.Error("stats response missing cache field")
	}
}

// --- health.go ---

// TestGetOverallStatusHealthy verifies all-ok checks return "healthy".
func TestGetOverallStatusHealthy(t *testing.T) {
	checks := ChecksInfo{
		Database:  "ok",
		Cache:     "ok",
		Disk:      "ok",
		Scheduler: "ok",
	}
	if got := getOverallStatus(checks); got != "healthy" {
		t.Errorf("getOverallStatus = %q, want healthy", got)
	}
}

// TestGetOverallStatusUnhealthy verifies any "error" check returns "unhealthy".
func TestGetOverallStatusUnhealthy(t *testing.T) {
	checks := ChecksInfo{
		Database:  "error",
		Cache:     "ok",
		Disk:      "ok",
		Scheduler: "ok",
	}
	if got := getOverallStatus(checks); got != "unhealthy" {
		t.Errorf("getOverallStatus = %q, want unhealthy", got)
	}
}

// TestGetOverallStatusDegraded verifies any "warn" check returns "degraded" (not unhealthy).
func TestGetOverallStatusDegraded(t *testing.T) {
	checks := ChecksInfo{
		Database:  "warn",
		Cache:     "ok",
		Disk:      "ok",
		Scheduler: "ok",
	}
	if got := getOverallStatus(checks); got != "degraded" {
		t.Errorf("getOverallStatus = %q, want degraded", got)
	}
}

// TestGetOverallStatusTorError verifies Tor error field contributes to overall status.
func TestGetOverallStatusTorError(t *testing.T) {
	checks := ChecksInfo{
		Database:  "ok",
		Cache:     "ok",
		Disk:      "ok",
		Scheduler: "ok",
		Tor:       "error",
	}
	if got := getOverallStatus(checks); got != "unhealthy" {
		t.Errorf("getOverallStatus with tor=error = %q, want unhealthy", got)
	}
}

// TestCheckDatabaseNilReturnsError verifies nil database returns "error".
func TestCheckDatabaseNilReturnsError(t *testing.T) {
	s := newTestServer(t)
	s.database = nil
	if got := s.checkDatabase(); got != "error" {
		t.Errorf("checkDatabase(nil db) = %q, want error", got)
	}
}

// TestCheckDatabaseConnected verifies live database returns "ok".
func TestCheckDatabaseConnected(t *testing.T) {
	s := newTestServer(t)
	if got := s.checkDatabase(); got != "ok" {
		t.Errorf("checkDatabase(live db) = %q, want ok", got)
	}
}

// TestCheckSchedulerNilReturnsError verifies nil scheduler returns "error".
func TestCheckSchedulerNilReturnsError(t *testing.T) {
	s := newTestServer(t)
	s.scheduler = nil
	if got := s.checkScheduler(); got != "error" {
		t.Errorf("checkScheduler(nil) = %q, want error", got)
	}
}

// TestCheckSchedulerReturnsOK verifies real scheduler returns "ok".
func TestCheckSchedulerReturnsOK(t *testing.T) {
	s := newTestServer(t)
	if got := s.checkScheduler(); got != "ok" {
		t.Errorf("checkScheduler(live) = %q, want ok", got)
	}
}

// TestBuildTorInfoNilService verifies nil torService returns disabled info.
func TestBuildTorInfoNilService(t *testing.T) {
	s := newTestServer(t)
	info := s.buildTorInfo()
	if info.Enabled {
		t.Error("torInfo.Enabled = true with nil torService")
	}
	if info.Running {
		t.Error("torInfo.Running = true with nil torService")
	}
	if info.Status != "disabled" {
		t.Errorf("torInfo.Status = %q, want disabled", info.Status)
	}
}

// TestBuildHealthResponse verifies the health response fields are populated.
func TestBuildHealthResponse(t *testing.T) {
	s := newTestServer(t)
	resp := s.buildHealthResponse()

	if resp.Status == "" {
		t.Error("health response missing Status")
	}
	if resp.Version == "" {
		t.Error("health response missing Version")
	}
	if resp.Uptime == "" {
		t.Error("health response missing Uptime")
	}
	if resp.GoVersion == "" {
		t.Error("health response missing GoVersion")
	}
	if resp.Checks.Database != "ok" {
		t.Errorf("health checks.database = %q, want ok", resp.Checks.Database)
	}
}

// --- whois_handlers.go ---

// TestHandleWHOISDomainLookupEmptyDomain verifies empty domain returns 400.
func TestHandleWHOISDomainLookupEmptyDomain(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/", nil)
	rr := httptest.NewRecorder()

	s.handleWHOISDomainLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty domain", rr.Code)
	}
}

// TestHandleWHOISDomainLookupInvalidType verifies IP address rejected in domain handler.
func TestHandleWHOISDomainLookupInvalidType(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/8.8.8.8", nil)
	rr := httptest.NewRecorder()

	s.handleWHOISDomainLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for IP in domain handler", rr.Code)
	}
}

// TestHandleWHOISIPLookupEmpty verifies empty IP returns 400.
func TestHandleWHOISIPLookupEmpty(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/ip/", nil)
	rr := httptest.NewRecorder()

	s.handleWHOISIPLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty IP", rr.Code)
	}
}

// TestHandleWHOISIPLookupInvalidType verifies domain string rejected in IP handler.
func TestHandleWHOISIPLookupInvalidType(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/ip/example.com", nil)
	rr := httptest.NewRecorder()

	s.handleWHOISIPLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for domain in IP handler", rr.Code)
	}
}

// TestHandleWHOISASNLookupEmpty verifies empty ASN returns 400.
func TestHandleWHOISASNLookupEmpty(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/asn/", nil)
	rr := httptest.NewRecorder()

	s.handleWHOISASNLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty ASN", rr.Code)
	}
}

// TestHandleWHOISASNLookupInvalidType verifies domain rejected in ASN handler.
func TestHandleWHOISASNLookupInvalidType(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/asn/example.com", nil)
	rr := httptest.NewRecorder()

	s.handleWHOISASNLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for domain in ASN handler", rr.Code)
	}
}

// TestDetermineResponseFormat covers all format detection branches.
func TestDetermineResponseFormat(t *testing.T) {
	cases := []struct {
		name        string
		queryFormat string
		acceptHdr   string
		want        string
	}{
		{"json query param", "json", "", "json"},
		{"xml query param", "xml", "", "xml"},
		{"text query param", "text", "", "text"},
		{"html query param", "html", "", "html"},
		{"invalid query param falls back to accept", "invalid", "text/plain", "text"},
		{"accept application/xml", "", "application/xml", "xml"},
		{"accept text/xml", "", "text/xml", "xml"},
		{"accept text/plain", "", "text/plain", "text"},
		{"accept text/html", "", "text/html", "html"},
		{"default json", "", "", "json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/"
			if tc.queryFormat != "" {
				url = "/?format=" + tc.queryFormat
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			if tc.acceptHdr != "" {
				req.Header.Set("Accept", tc.acceptHdr)
			}
			got := determineResponseFormat(req)
			if got != tc.want {
				t.Errorf("determineResponseFormat() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHandleWHOISBulkEmptyBody verifies empty body returns 400.
func TestHandleWHOISBulkEmptyBody(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whois/bulk", strings.NewReader("invalid json"))
	rr := httptest.NewRecorder()

	s.handleWHOISBulkLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid JSON", rr.Code)
	}
}

// TestHandleWHOISBulkEmptyQueries verifies empty queries array returns 400.
func TestHandleWHOISBulkEmptyQueries(t *testing.T) {
	s := newTestServer(t)
	body := `{"queries":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whois/bulk", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleWHOISBulkLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty queries", rr.Code)
	}
}

// TestHandleWHOISBulkTooManyQueries verifies 101+ queries returns 400.
func TestHandleWHOISBulkTooManyQueries(t *testing.T) {
	s := newTestServer(t)
	queries := make([]string, 101)
	for i := range queries {
		queries[i] = `"example.com"`
	}
	body := `{"queries":[` + strings.Join(queries, ",") + `]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whois/bulk", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleWHOISBulkLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for >100 queries", rr.Code)
	}
}

// TestHandleWHOISOwnerSearchMissingOwner verifies missing owner param returns 400.
func TestHandleWHOISOwnerSearchMissingOwner(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/search", nil)
	rr := httptest.NewRecorder()

	s.handleWHOISOwnerSearch(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing owner", rr.Code)
	}
}

// TestHandleWHOISOwnerSearchEmptyResult verifies owner search with no matches returns 200.
func TestHandleWHOISOwnerSearchEmptyResult(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/search?owner=nobody", nil)
	rr := httptest.NewRecorder()

	s.handleWHOISOwnerSearch(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for valid empty owner search", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Error("resp.OK = false on valid owner search")
	}
}

// TestHandleWHOISOwnerSearchPagination verifies page/limit query params are accepted.
func TestHandleWHOISOwnerSearchPagination(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/search?owner=acme&page=2&limit=50", nil)
	rr := httptest.NewRecorder()

	s.handleWHOISOwnerSearch(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with pagination params", rr.Code)
	}
}

// TestHandleWHOISPageTextClientNoQuery verifies text client with no ?q returns 400.
func TestHandleWHOISPageTextClientNoQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois", nil)
	req.Header.Set("Accept", "text/plain")
	rr := httptest.NewRecorder()

	s.handleWHOISPage(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for text client with no query", rr.Code)
	}
}

// TestHandleWHOISPageJSONClientNoQuery verifies JSON client with no ?q returns 400.
func TestHandleWHOISPageJSONClientNoQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()

	s.handleWHOISPage(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for JSON client with no query", rr.Code)
	}
}

// TestHandleWHOISPageHTMLClientNoQuery verifies HTML client with no query renders the page.
func TestHandleWHOISPageHTMLClientNoQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()

	s.handleWHOISPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for HTML client with no query (renders empty form)", rr.Code)
	}
}

// TestHandleRootAPI verifies JSON API info response for root endpoint.
func TestHandleRootAPI(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	s.handleRootAPI(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Error("resp.OK = false for root API")
	}
	data := decodeDataMap(t, resp)
	if data["service"] != "caswhois" {
		t.Errorf("service = %v, want caswhois", data["service"])
	}
	if _, ok := data["endpoints"]; !ok {
		t.Error("root API missing endpoints list")
	}
}

// --- debug.go ---

// TestHandleDebugConfigReturnsJSON verifies /debug/config returns JSON.
func TestHandleDebugConfigReturnsJSON(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/debug/config", nil)
	rr := httptest.NewRecorder()

	s.handleDebugConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// TestHandleDebugRoutesReturnsRouteList verifies /debug/routes includes count and routes.
func TestHandleDebugRoutesReturnsRouteList(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/debug/routes", nil)
	rr := httptest.NewRecorder()

	s.handleDebugRoutes(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["count"]; !ok {
		t.Error("debug/routes missing count")
	}
	if _, ok := body["routes"]; !ok {
		t.Error("debug/routes missing routes")
	}
}

// TestHandleDebugMemoryReturnsStats verifies /debug/memory returns memory fields.
func TestHandleDebugMemoryReturnsStats(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/debug/memory", nil)
	rr := httptest.NewRecorder()

	s.handleDebugMemory(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["alloc_mb"]; !ok {
		t.Error("debug/memory missing alloc_mb")
	}
	if _, ok := body["goroutines"]; !ok {
		t.Error("debug/memory missing goroutines")
	}
}

// TestHandleDebugGoroutinesReturnsText verifies /debug/goroutines returns text/plain stack traces.
func TestHandleDebugGoroutinesReturnsText(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/debug/goroutines", nil)
	rr := httptest.NewRecorder()

	s.handleDebugGoroutines(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if rr.Body.Len() == 0 {
		t.Error("goroutines response has empty body")
	}
}

// TestHandleDebugCacheReturnsStats verifies /debug/cache returns cache stats.
func TestHandleDebugCacheReturnsStats(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/debug/cache", nil)
	rr := httptest.NewRecorder()

	s.handleDebugCache(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestHandleDebugDBReturnsStats verifies /debug/db returns connection pool stats.
func TestHandleDebugDBReturnsStats(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/debug/db", nil)
	rr := httptest.NewRecorder()

	s.handleDebugDB(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["open_connections"]; !ok {
		t.Error("debug/db missing open_connections")
	}
}

// TestHandleDebugDBNilDatabase verifies nil database returns 503.
func TestHandleDebugDBNilDatabase(t *testing.T) {
	s := newTestServer(t)
	s.database = nil
	req := httptest.NewRequest(http.MethodGet, "/debug/db", nil)
	rr := httptest.NewRecorder()

	s.handleDebugDB(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 for nil database", rr.Code)
	}
}

// TestHandleDebugSchedulerReturnsStatus verifies /debug/scheduler returns task status.
func TestHandleDebugSchedulerReturnsStatus(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/debug/scheduler", nil)
	rr := httptest.NewRecorder()

	s.handleDebugScheduler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestHandleDebugSchedulerNilReturns503 verifies nil scheduler returns 503.
func TestHandleDebugSchedulerNilReturns503(t *testing.T) {
	s := newTestServer(t)
	s.scheduler = nil
	req := httptest.NewRequest(http.MethodGet, "/debug/scheduler", nil)
	rr := httptest.NewRecorder()

	s.handleDebugScheduler(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 for nil scheduler", rr.Code)
	}
}

// --- responseWriter (middleware.go) ---

// TestResponseWriterCapturesStatus verifies WriteHeader captures status code.
func TestResponseWriterCapturesStatus(t *testing.T) {
	inner := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: inner, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusCreated)

	if rw.statusCode != http.StatusCreated {
		t.Errorf("statusCode = %d, want 201", rw.statusCode)
	}
}

// TestResponseWriterCapturesBytesWritten verifies Write accumulates bytes.
func TestResponseWriterCapturesBytesWritten(t *testing.T) {
	inner := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: inner, statusCode: http.StatusOK}

	n1, _ := rw.Write([]byte("hello"))
	n2, _ := rw.Write([]byte(" world"))

	if rw.bytesWritten != n1+n2 {
		t.Errorf("bytesWritten = %d, want %d", rw.bytesWritten, n1+n2)
	}
}

// TestResponseWriterDefaultsStatus verifies Write without WriteHeader records 200.
func TestResponseWriterDefaultsStatus(t *testing.T) {
	inner := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: inner}

	rw.Write([]byte("data"))

	if rw.statusCode != http.StatusOK {
		t.Errorf("statusCode = %d, want 200 (default)", rw.statusCode)
	}
}
