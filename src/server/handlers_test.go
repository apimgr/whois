package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/whois/src/cache"
	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/db"
	"github.com/apimgr/whois/src/ratelimit"
	"github.com/apimgr/whois/src/scheduler"
)

// newTestServer builds the minimal *Server needed for handler unit tests.
// It wires up a real in-memory SQLite database and scheduler so all health
// checks return accurate status rather than hard-coded strings.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Default()
	dataDir := t.TempDir()
	cfg.Database.Dir = dataDir
	cfg.LogDir = t.TempDir()
	database, err := db.New(context.Background(), &db.DatabaseConfig{
		Driver: "sqlite",
		Path:   dataDir,
	})
	if err != nil {
		t.Fatalf("newTestServer: create db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	sched, schedErr := scheduler.New(database.Read(), "America/New_York", 0)
	if schedErr != nil {
		t.Fatalf("newTestServer: create scheduler: %v", schedErr)
	}

	readLimit := ratelimit.New(cfg.RateLimit.Read.Requests, time.Duration(cfg.RateLimit.Read.Window)*time.Second)
	writeLimit := ratelimit.New(cfg.RateLimit.Write.Requests, time.Duration(cfg.RateLimit.Write.Window)*time.Second)
	healthLimit := ratelimit.New(cfg.RateLimit.Health.Requests, time.Duration(cfg.RateLimit.Health.Window)*time.Second)
	globalLimit := ratelimit.New(cfg.RateLimit.GlobalBurst, time.Minute)
	strictLimit := ratelimit.New(cfg.RateLimit.Strict.Requests, time.Duration(cfg.RateLimit.Strict.Window)*time.Second)
	authLimit := ratelimit.New(cfg.RateLimit.AuthFailures.Requests, time.Duration(cfg.RateLimit.AuthFailures.Window)*time.Second)
	t.Cleanup(func() {
		readLimit.Close()
		writeLimit.Close()
		healthLimit.Close()
		globalLimit.Close()
		strictLimit.Close()
		authLimit.Close()
	})
	return &Server{
		config:             cfg,
		cache:              cache.NewMemoryCache(1*1024*1024, 5*time.Minute),
		ratelimit:          readLimit,
		writeLimiter:       writeLimit,
		healthLimiter:      healthLimit,
		globalBurstLimiter: globalLimit,
		strictLimiter:      strictLimit,
		authFailureLimiter: authLimit,
		database:           database,
		scheduler:          sched,
		startTime:          time.Now(),
	}
}

func TestAPITextExtension(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/healthz.txt", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	s.setupRoutes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
	if !strings.Contains(rr.Body.String(), "status: healthy") {
		t.Fatalf("plain text health response missing status: %s", rr.Body.String())
	}
}

// decodeAPIResponse is a helper that decodes the response body into an APIResponse
// and fails the test if decoding fails.
func decodeAPIResponse(t *testing.T, body string) APIResponse {
	t.Helper()
	var resp APIResponse
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&resp); err != nil {
		t.Fatalf("json.Decode APIResponse: %v\nBody: %s", err, body)
	}
	return resp
}

// decodeDataMap decodes APIResponse.Data into map[string]interface{}.
// Data arrives from json.Decoder as map[string]interface{}, so this cast is safe.
func decodeDataMap(t *testing.T, resp APIResponse) map[string]interface{} {
	t.Helper()
	m, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("resp.Data is %T, want map[string]interface{}", resp.Data)
	}
	return m
}

// --- handleHealth ---

// TestHandleHealth verifies that GET /server/healthz returns 200 with ok:true
// and data.status == "healthy".
func TestHandleHealth(t *testing.T) {
	cases := []struct {
		name           string
		acceptHeader   string
		wantStatus     int
		wantOK         bool
		wantDataStatus string
	}{
		{
			name:           "JSON response",
			acceptHeader:   "application/json",
			wantStatus:     http.StatusOK,
			wantOK:         true,
			wantDataStatus: "healthy",
		},
	}

	s := newTestServer(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/server/healthz", nil)
			if tc.acceptHeader != "" {
				req.Header.Set("Accept", tc.acceptHeader)
			}
			rr := httptest.NewRecorder()

			s.handleHealth(rr, req)

			if rr.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tc.wantStatus)
			}

			ct := rr.Header().Get("Content-Type")
			if !strings.Contains(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			// The health handler writes HealthResponse directly, not APIResponse.
			var health HealthResponse
			if err := json.NewDecoder(rr.Body).Decode(&health); err != nil {
				t.Fatalf("decode HealthResponse: %v\nBody: %s", err, rr.Body.String())
			}

			if health.Status != "healthy" {
				t.Errorf("health.Status = %q, want %q", health.Status, "healthy")
			}
		})
	}
}

func TestHandleHealthCurlGetsHumanReadableFrontendText(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/server/healthz", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	response := httptest.NewRecorder()
	s.handleHealth(response, req)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("curl health response = %d %q", response.Code, response.Header().Get("Content-Type"))
	}
	for _, want := range []string{"Status:", "Features", "Checks", "Statistics"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("human health text missing %q: %s", want, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), "project.name:") {
		t.Fatal("frontend text response used API dotted keys")
	}
}

func TestHandleHealthUnhealthyUsesServiceUnavailableForEveryFormat(t *testing.T) {
	s := newTestServer(t)
	s.database = nil
	for _, accept := range []string{"application/json", "text/plain", "text/html"} {
		t.Run(accept, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/server/healthz", nil)
			req.Header.Set("Accept", accept)
			rr := httptest.NewRecorder()
			s.handleHealth(rr, req)
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("health status for %s = %d, want %d", accept, rr.Code, http.StatusServiceUnavailable)
			}
		})
	}
}

// TestHandleHealthTextFormat verifies API text uses the dotted key format.
func TestHandleHealthTextFormat(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/healthz", nil)
	// Accept: text/plain triggers the text branch via content negotiation (AI.md PART 14).
	req.Header.Set("Accept", "text/plain")

	rr := httptest.NewRecorder()
	s.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "status:") || !strings.Contains(rr.Body.String(), "checks.database:") {
		t.Errorf("API text response missing dotted fields, body:\n%s", rr.Body.String())
	}
}

// TestHandleHealthNilEmailAndMetrics confirms no panic when s.email and s.metrics are nil.
func TestHandleHealthNilEmailAndMetrics(t *testing.T) {
	s := newTestServer(t)
	// Both are nil by default from newTestServer.

	req := httptest.NewRequest(http.MethodGet, "/server/healthz", nil)
	rr := httptest.NewRecorder()

	// Must not panic.
	s.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// --- handlePublicWHOISPage ---

// TestHandlePublicWHOISPage verifies GET / returns 200 with text/html body.
func TestHandlePublicWHOISPage(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		wantStatus int
		wantHTML   bool
	}{
		{
			name:       "root path returns HTML",
			path:       "/",
			wantStatus: http.StatusOK,
			wantHTML:   true,
		},
		{
			name:       "non-root path returns 404",
			path:       "/notfound-path",
			wantStatus: http.StatusNotFound,
			wantHTML:   false,
		},
	}

	s := newTestServer(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rr := httptest.NewRecorder()

			s.handlePublicWHOISPage(rr, req)

			if rr.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (path %q)", rr.Code, tc.wantStatus, tc.path)
			}

			if tc.wantHTML {
				ct := rr.Header().Get("Content-Type")
				if !strings.Contains(ct, "text/html") {
					t.Errorf("Content-Type = %q, want text/html", ct)
				}
				if !strings.Contains(rr.Body.String(), "<!DOCTYPE html>") {
					t.Error("response body missing DOCTYPE declaration")
				}
			}
		})
	}
}

// TestHandlePublicWHOISPageJSONAccept verifies that Accept: application/json
// on the root path returns a JSON API response, not an HTML page.
func TestHandlePublicWHOISPageJSONAccept(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()

	s.handlePublicWHOISPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// --- handleWHOISValidate ---

// TestHandleWHOISValidate covers valid and invalid query validation without
// performing a real WHOIS lookup.
func TestHandleWHOISValidate(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		wantOK    bool
		wantValid bool
		wantType  string
	}{
		{
			name:      "valid domain",
			path:      "/api/v1/whois/validate/example.com",
			wantOK:    true,
			wantValid: true,
			wantType:  "domain",
		},
		{
			name:      "valid IPv4",
			path:      "/api/v1/whois/validate/8.8.8.8",
			wantOK:    true,
			wantValid: true,
			wantType:  "ipv4",
		},
		{
			name:      "valid IPv6",
			path:      "/api/v1/whois/validate/2001:4860:4860::8888",
			wantOK:    true,
			wantValid: true,
			wantType:  "ipv6",
		},
		{
			name:      "valid ASN",
			path:      "/api/v1/whois/validate/AS15169",
			wantOK:    true,
			wantValid: true,
			wantType:  "asn",
		},
		{
			// Double-dot makes the query fail validation; handler still returns 200 ok:true.
			name:      "invalid double-dot domain",
			path:      "/api/v1/whois/validate/notvalid..query",
			wantOK:    true,
			wantValid: false,
			wantType:  "unknown",
		},
		{
			// Label with leading hyphen is invalid.
			name:      "invalid leading hyphen",
			path:      "/api/v1/whois/validate/-bad.example.com",
			wantOK:    true,
			wantValid: false,
		},
	}

	s := newTestServer(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rr := httptest.NewRecorder()

			s.handleWHOISValidate(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rr.Code)
			}

			resp := decodeAPIResponse(t, rr.Body.String())
			if resp.OK != tc.wantOK {
				t.Errorf("resp.OK = %v, want %v", resp.OK, tc.wantOK)
			}

			data := decodeDataMap(t, resp)

			valid, _ := data["valid"].(bool)
			if valid != tc.wantValid {
				t.Errorf("data.valid = %v, want %v", valid, tc.wantValid)
			}

			if tc.wantType != "" {
				qtype, _ := data["type"].(string)
				if qtype != tc.wantType {
					t.Errorf("data.type = %q, want %q", qtype, tc.wantType)
				}
			}
		})
	}
}

// TestHandleWHOISValidateEmptyQuery verifies that an empty query path segment
// returns a 400 BAD_REQUEST JSON error.
func TestHandleWHOISValidateEmptyQuery(t *testing.T) {
	s := newTestServer(t)

	// Path strips "/api/v1/whois/validate/" leaving empty query.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/validate/", nil)
	rr := httptest.NewRecorder()

	s.handleWHOISValidate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if resp.OK {
		t.Error("resp.OK = true on empty query, want false")
	}
	if resp.Error != ErrBadRequest {
		t.Errorf("resp.Error = %q, want %q", resp.Error, ErrBadRequest)
	}
}

// --- handleNotFound ---

// TestHandleNotFound verifies JSON error for /api/* paths and HTML for others.
func TestHandleNotFound(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		wantStatus  int
		wantJSON    bool
		wantErrCode string
	}{
		{
			name:        "API path returns JSON 404",
			path:        "/api/v1/nonexistent",
			wantStatus:  http.StatusNotFound,
			wantJSON:    true,
			wantErrCode: ErrNotFound,
		},
		{
			name:       "non-API path returns HTML 404",
			path:       "/nonexistent",
			wantStatus: http.StatusNotFound,
			wantJSON:   false,
		},
		{
			name:        "api prefix without trailing slash",
			path:        "/api",
			wantStatus:  http.StatusNotFound,
			wantJSON:    true,
			wantErrCode: ErrNotFound,
		},
	}

	s := newTestServer(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rr := httptest.NewRecorder()

			s.handleNotFound(rr, req)

			if rr.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tc.wantStatus)
			}

			if tc.wantJSON {
				ct := rr.Header().Get("Content-Type")
				if !strings.Contains(ct, "application/json") {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
				resp := decodeAPIResponse(t, rr.Body.String())
				if resp.OK {
					t.Error("resp.OK = true on 404, want false")
				}
				if tc.wantErrCode != "" && resp.Error != tc.wantErrCode {
					t.Errorf("resp.Error = %q, want %q", resp.Error, tc.wantErrCode)
				}
			} else {
				ct := rr.Header().Get("Content-Type")
				if !strings.Contains(ct, "text/html") {
					t.Errorf("Content-Type = %q, want text/html for non-API 404", ct)
				}
			}
		})
	}
}

// --- SendSuccess / SendError helpers ---

// TestSendSuccess verifies the APIResponse wrapper sets ok:true and encodes data.
func TestSendSuccess(t *testing.T) {
	rr := httptest.NewRecorder()
	SendSuccess(rr, map[string]string{"key": "value"})

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Errorf("resp.OK = false, want true")
	}
}

// TestSendError verifies that each error code maps to the expected HTTP status.
func TestSendError(t *testing.T) {
	cases := []struct {
		code       string
		wantStatus int
	}{
		{ErrBadRequest, http.StatusBadRequest},
		{ErrValidationFailed, http.StatusBadRequest},
		{ErrUnauthorized, http.StatusUnauthorized},
		{ErrForbidden, http.StatusForbidden},
		{ErrNotFound, http.StatusNotFound},
		{ErrMethodNotAllowed, http.StatusMethodNotAllowed},
		{ErrConflict, http.StatusConflict},
		{ErrRateLimited, http.StatusTooManyRequests},
		{ErrServerError, http.StatusInternalServerError},
		{ErrMaintenance, http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			rr := httptest.NewRecorder()
			SendError(rr, tc.code, "test message")

			if rr.Code != tc.wantStatus {
				t.Errorf("SendError(%q): status = %d, want %d", tc.code, rr.Code, tc.wantStatus)
			}
			resp := decodeAPIResponse(t, rr.Body.String())
			if resp.OK {
				t.Errorf("SendError(%q): resp.OK = true, want false", tc.code)
			}
			if resp.Error != tc.code {
				t.Errorf("SendError(%q): resp.Error = %q, want %q", tc.code, resp.Error, tc.code)
			}
		})
	}
}

// TestSendErrorUnknownCode verifies that an unrecognised code defaults to 500.
func TestSendErrorUnknownCode(t *testing.T) {
	rr := httptest.NewRecorder()
	SendError(rr, "TOTALLY_UNKNOWN", "unknown error")
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

func TestSendErrorUsesResolvedLocale(t *testing.T) {
	rr := httptest.NewRecorder()
	rr.Header().Set("Content-Language", "de")
	SendError(rr, ErrNotFound, "untranslated caller message")
	response := decodeAPIResponse(t, rr.Body.String())
	if response.Message != "Nicht gefunden" {
		t.Fatalf("localized message = %q, want German not-found message", response.Message)
	}
}

// --- formatUptime ---

// TestFormatUptime validates the human-readable uptime string for each branch.
func TestFormatUptime(t *testing.T) {
	cases := []struct {
		name  string
		input time.Duration
		want  string
	}{
		{name: "minutes only", input: 45 * time.Minute, want: "45m"},
		{name: "hours and minutes", input: 2*time.Hour + 30*time.Minute, want: "2h 30m"},
		{name: "days hours minutes", input: 26*time.Hour + 15*time.Minute, want: "1d 2h 15m"},
		{name: "zero", input: 0, want: "0m"},
		{name: "exactly one hour", input: time.Hour, want: "1h 0m"},
		{name: "exactly one day", input: 24 * time.Hour, want: "1d 0h 0m"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatUptime(tc.input)
			if got != tc.want {
				t.Errorf("formatUptime(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// --- DetectClientType ---

// TestDetectClientType verifies client-type detection from Accept header and User-Agent.
func TestDetectClientType(t *testing.T) {
	cases := []struct {
		name      string
		accept    string
		userAgent string
		want      HTTPClientType
	}{
		{name: "text/html accept", accept: "text/html", want: ClientTypeHTML},
		{name: "application/json accept", accept: "application/json", want: ClientTypeJSON},
		{name: "text/plain accept", accept: "text/plain", want: ClientTypeText},
		{name: "browser user-agent", userAgent: "Mozilla/5.0", want: ClientTypeHTML},
		{name: "curl user-agent", userAgent: "curl/7.88.0", want: ClientTypeText},
		{name: "wget user-agent", userAgent: "Wget/1.21", want: ClientTypeText},
		{name: "empty user-agent", userAgent: "", want: ClientTypeText},
		{name: "accept overrides UA", accept: "application/json", userAgent: "Mozilla/5.0", want: ClientTypeJSON},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			if tc.userAgent != "" {
				req.Header.Set("User-Agent", tc.userAgent)
			}

			got := DetectClientType(req)
			if got != tc.want {
				t.Errorf("DetectClientType() = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- serverStats ---

// TestServerStatsRecordRequest verifies atomic counters increment correctly and
// the 24h counter resets on a simulated day change.
func TestServerStatsRecordRequest(t *testing.T) {
	var st serverStats

	st.recordRequest()
	st.recordRequest()
	st.recordRequest()

	if got := st.requestsTotal.Load(); got != 3 {
		t.Errorf("requestsTotal = %d, want 3", got)
	}
	if got := st.requests24h.Load(); got != 3 {
		t.Errorf("requests24h = %d, want 3", got)
	}
}

// TestServerStatsConnOpenClose verifies the active-connections gauge increments and decrements.
func TestServerStatsConnOpenClose(t *testing.T) {
	var st serverStats

	st.connOpen()
	st.connOpen()
	if got := st.activeConns.Load(); got != 2 {
		t.Errorf("activeConns after 2 opens = %d, want 2", got)
	}

	st.connClose()
	if got := st.activeConns.Load(); got != 1 {
		t.Errorf("activeConns after 1 close = %d, want 1", got)
	}
}
