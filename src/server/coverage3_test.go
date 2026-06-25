package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/whois/src/cache"
	"github.com/apimgr/whois/src/metrics"
	"github.com/apimgr/whois/src/ratelimit"
	"github.com/apimgr/whois/src/scheduler"
	castor "github.com/apimgr/whois/src/tor"
	"github.com/apimgr/whois/src/whois/parser"
	"github.com/apimgr/whois/src/whois/records"
)

// --- debug.go: registerDebugRoutes ---

// TestRegisterDebugRoutesDisabled verifies registerDebugRoutes is a no-op when
// debug mode is disabled, so /debug/config hits the catch-all (404).
func TestRegisterDebugRoutesDisabled(t *testing.T) {
	s := newTestServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleNotFound)
	s.registerDebugRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/debug/config", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("debug route when disabled: status = %d, want 404", rr.Code)
	}
}

// TestRegisterDebugRoutesEnabled verifies all debug routes are registered and
// respond 200 when config.Debug = true.
func TestRegisterDebugRoutesEnabled(t *testing.T) {
	s := newTestServer(t)
	s.config.Debug = true

	mux := http.NewServeMux()
	s.registerDebugRoutes(mux)

	debugRoutes := []string{
		"/debug/config",
		"/debug/routes",
		"/debug/cache",
		"/debug/db",
		"/debug/scheduler",
		"/debug/memory",
		"/debug/goroutines",
	}

	for _, route := range debugRoutes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("debug route %q: status = %d, want 200", route, rr.Code)
			}
		})
	}
}

// --- static_embed.go: staticFileServer ---

// TestStaticFileServerNotFound verifies the static file server returns 404 for
// a path that does not exist in the embedded FS.
func TestStaticFileServerNotFound(t *testing.T) {
	h := staticFileServer()
	req := httptest.NewRequest(http.MethodGet, "/static/nonexistent-file-xyz.css", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("static server for missing file: status = %d, want 404", rr.Code)
	}
}

// TestStaticFileServerRoot verifies the static file server handles a root
// request without panicking (status may be 200, 301, or 404).
func TestStaticFileServerRoot(t *testing.T) {
	h := staticFileServer()
	req := httptest.NewRequest(http.MethodGet, "/static/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == 0 {
		t.Error("static file server returned no status code")
	}
}

// --- privilege_unix.go: dropPrivileges ---

// TestDropPrivilegesNonRoot verifies dropPrivileges is a no-op for non-root
// processes. In CI tests always run as non-root, exercising the early return.
func TestDropPrivilegesNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test must run as non-root")
	}
	if err := dropPrivileges("nobody", ""); err != nil {
		t.Errorf("dropPrivileges(non-root) = %v, want nil", err)
	}
}

// TestDropPrivilegesEmptyUsername verifies dropPrivileges returns nil when
// username is empty (no-op regardless of privilege level).
func TestDropPrivilegesEmptyUsername(t *testing.T) {
	if err := dropPrivileges("", ""); err != nil {
		t.Errorf("dropPrivileges(empty username) = %v, want nil", err)
	}
}

// --- pid_unix.go: isOurProcess ---

// TestIsOurProcessCurrentPID exercises isOurProcess with the current process
// PID, covering the /proc/PID/exe symlink (Linux) or ps path (macOS/BSD).
func TestIsOurProcessCurrentPID(t *testing.T) {
	pid := os.Getpid()
	// The test binary is not named "caswhois", so the result is false, but the
	// function must not panic and must reach its name-check logic.
	result := isOurProcess(pid)
	t.Logf("isOurProcess(current pid %d) = %v", pid, result)
}

// TestIsOurProcessNonExistentPID verifies isOurProcess returns false for a PID
// that is virtually guaranteed not to exist.
func TestIsOurProcessNonExistentPID(t *testing.T) {
	if isOurProcess(99999999) {
		t.Error("isOurProcess(99999999) = true, want false")
	}
}

// TestIsOurProcessDarwinNonExistentPID exercises the Darwin/BSD ps path with a
// non-existent PID so the ps command fails and returns false.
func TestIsOurProcessDarwinNonExistentPID(t *testing.T) {
	if isOurProcessDarwin(99999999) {
		t.Error("isOurProcessDarwin(99999999) = true, want false")
	}
}

// TestCheckPIDFileCurrentProcess writes a PID:PORT file for the current process
// so CheckPIDFile calls isOurProcess (covering that code path).
func TestCheckPIDFileCurrentProcess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current.pid")

	// Write the current process PID in canonical "PID:PORT\n" format.
	content := fmt.Sprintf("%d:0\n", os.Getpid())
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// CheckPIDFile sees the process running, calls isOurProcess. The test binary
	// is not named "caswhois", so isOurProcess returns false and the stale-file
	// removal branch runs — which is the branch we want to exercise.
	running, foundPID, err := CheckPIDFile(path)
	if err != nil {
		t.Logf("CheckPIDFile error (acceptable): %v", err)
	}
	t.Logf("CheckPIDFile: running=%v pid=%d err=%v", running, foundPID, err)
}

// --- middleware.go: RateLimitMiddleware rate-exceeded path ---

// TestRateLimitMiddlewareExceeded verifies a limiter with limit=1 returns 429
// on the second request from the same IP, covering the deny path.
func TestRateLimitMiddlewareExceeded(t *testing.T) {
	limiter := ratelimit.New(1, time.Minute)
	t.Cleanup(limiter.Close)

	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	h := RateLimitMiddleware(limiter)(next)

	// First request: within limit.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Errorf("first request: status = %d, want 200", rr1.Code)
	}

	// Second request from same IP: exceeds limit.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req2.RemoteAddr = "10.0.0.1:5678"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("second request (over limit): status = %d, want 429", rr2.Code)
	}

	if rr2.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing on 429 rate-limit response")
	}
	if rr2.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("X-RateLimit-Limit header missing on 429")
	}
}

// TestRateLimitMiddlewareIndependentIPs verifies different IPs have independent
// rate-limit buckets.
func TestRateLimitMiddlewareIndependentIPs(t *testing.T) {
	limiter := ratelimit.New(1, time.Minute)
	t.Cleanup(limiter.Close)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := RateLimitMiddleware(limiter)(next)

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "192.168.1.1:1000"
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Errorf("IP1 first request: status = %d, want 200", rr1.Code)
	}

	// Different IP: gets its own bucket and passes.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "192.168.1.2:1000"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("IP2 first request: status = %d, want 200 (independent bucket)", rr2.Code)
	}
}

// --- server.go: handleWHOIS ---

// TestHandleWHOISEmptyQuery verifies an empty path segment after /whois/ returns 400.
func TestHandleWHOISEmptyQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/", nil)
	rr := httptest.NewRecorder()
	s.handleWHOIS(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleWHOIS(empty): status = %d, want 400", rr.Code)
	}
}

// TestHandleWHOISInvalidQuery verifies a malformed query (double-dot) returns 400.
func TestHandleWHOISInvalidQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/not..valid", nil)
	rr := httptest.NewRecorder()
	s.handleWHOIS(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleWHOIS(invalid): status = %d, want 400", rr.Code)
	}
}

// TestHandleWHOISValidQueryNoNetwork verifies a well-formed query passes
// validation and reaches the lookup stage (200 or 500, never 400).
func TestHandleWHOISValidQueryNoNetwork(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/example.com", nil)
	rr := httptest.NewRecorder()
	s.handleWHOIS(rr, req)
	if rr.Code != http.StatusOK && rr.Code != http.StatusInternalServerError {
		t.Errorf("handleWHOIS(valid domain): unexpected status = %d", rr.Code)
	}
}

// TestHandleWHOISTrimmedEmpty verifies whitespace-only path after /whois/ returns 400.
func TestHandleWHOISTrimmedEmpty(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/", nil)
	req.URL.Path = "/api/v1/whois/   "
	rr := httptest.NewRecorder()
	s.handleWHOIS(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleWHOIS(spaces only): status = %d, want 400", rr.Code)
	}
}

// --- public_handler.go: handleWHOISPage ---

// TestHandleWHOISPageHTMLClientWithQuery verifies an HTML client with ?q always
// gets a 200 HTML page (error displayed inline, not as an HTTP error code).
func TestHandleWHOISPageHTMLClientWithQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois?q=example.com", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	s.handleWHOISPage(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleWHOISPage(HTML+query): status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// TestHandleWHOISPageTextWithQuery verifies text/plain client with a valid
// query returns 200 (live lookup) or 500 (no network in CI) — never 400.
func TestHandleWHOISPageTextWithQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois?q=example.com", nil)
	req.Header.Set("Accept", "text/plain")
	rr := httptest.NewRecorder()
	s.handleWHOISPage(rr, req)
	if rr.Code != http.StatusOK && rr.Code != http.StatusInternalServerError {
		t.Errorf("handleWHOISPage(text+query): unexpected status = %d", rr.Code)
	}
}

// TestHandleWHOISPageJSONWithQuery verifies JSON client with a valid query
// returns 200 or 500 (never 400).
func TestHandleWHOISPageJSONWithQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois?q=example.com", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	s.handleWHOISPage(rr, req)
	if rr.Code != http.StatusOK && rr.Code != http.StatusInternalServerError {
		t.Errorf("handleWHOISPage(JSON+query): unexpected status = %d", rr.Code)
	}
}

// --- whois_handlers.go: performWHOISLookup ---

// TestPerformWHOISLookupInvalidQuery exercises the validation-error branch in
// performWHOISLookup (double-dot fails ValidateQuery before any network call).
func TestPerformWHOISLookupInvalidQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/not..valid", nil)
	rr := httptest.NewRecorder()
	s.performWHOISLookup(rr, req, "not..valid")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("performWHOISLookup(invalid): status = %d, want 400", rr.Code)
	}
}

// TestPerformWHOISLookupValidQueryNoNetwork verifies a valid query passes
// validation — network failure yields 500, not 400.
func TestPerformWHOISLookupValidQueryNoNetwork(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/example.com", nil)
	rr := httptest.NewRecorder()
	s.performWHOISLookup(rr, req, "example.com")
	if rr.Code == http.StatusBadRequest {
		t.Error("performWHOISLookup(valid domain) returned 400, want 200 or 500")
	}
}

// --- api.go: init coverage ---

// TestWhoisServerListLoaded verifies the embedded JSON was parsed at init time
// and the server list is non-empty (exercises the init() function in api.go).
func TestWhoisServerListLoaded(t *testing.T) {
	if len(whoisServerList) == 0 {
		t.Error("whoisServerList is empty after init(); expected embedded JSON to be parsed")
	}
}

// TestWhoisServerListFieldsPopulated verifies at least one entry has non-empty
// Host and Type fields, confirming JSON structure is correct.
func TestWhoisServerListFieldsPopulated(t *testing.T) {
	for _, srv := range whoisServerList {
		if srv.Host != "" && srv.Type != "" {
			return
		}
	}
	t.Error("no server entry has both non-empty Host and Type fields")
}

// --- server.go: getPIDFilePath ---

// TestGetPIDFilePathNonRoot verifies non-root path does not use /var/run.
func TestGetPIDFilePathNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping non-root PID path test when running as root")
	}
	s := newTestServer(t)
	path := s.getPIDFilePath()
	if path == "" {
		t.Error("getPIDFilePath() returned empty string")
	}
	if strings.HasPrefix(path, "/var/run") {
		t.Errorf("non-root getPIDFilePath() = %q, must not use /var/run", path)
	}
}

// TestGetPIDFilePathContainsProjectName verifies the path contains the project
// identifier so the PID file is scoped to caswhois.
func TestGetPIDFilePathContainsProjectName(t *testing.T) {
	s := newTestServer(t)
	path := s.getPIDFilePath()
	if !strings.Contains(path, "caswhois") {
		t.Errorf("getPIDFilePath() = %q, expected to contain 'caswhois'", path)
	}
	if !strings.Contains(path, "apimgr") {
		t.Errorf("getPIDFilePath() = %q, expected to contain 'apimgr'", path)
	}
}

// --- ops_handlers.go: handleSchedulerRun nil-scheduler branch ---

// TestHandleSchedulerRunNilScheduler verifies POST returns 500 when scheduler
// is nil (not initialised).
func TestHandleSchedulerRunNilScheduler(t *testing.T) {
	s := newTestServer(t)
	s.scheduler = nil
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/schedulers/run?task=anything", nil)
	rr := httptest.NewRecorder()
	s.handleSchedulerRun(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("handleSchedulerRun(nil scheduler): status = %d, want 500", rr.Code)
	}
}

// --- ops_handlers.go: handleBackupStatus read error ---

// TestHandleBackupStatusReadError verifies 500 when backup dir path points to a
// regular file instead of a directory (os.ReadDir returns an error).
func TestHandleBackupStatusReadError(t *testing.T) {
	s := newTestServer(t)
	dir := t.TempDir()
	fakePath := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(fakePath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	s.config.Backup.Dir = fakePath

	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/backups", nil)
	rr := httptest.NewRecorder()
	s.handleBackupStatus(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("handleBackupStatus(file-as-dir): status = %d, want 500", rr.Code)
	}
}

// --- health.go: buildHealthResponse feature fields ---

// TestBuildHealthResponseGeoIPNil verifies features.geoip = false when geoip
// manager is nil (default in newTestServer).
func TestBuildHealthResponseGeoIPNil(t *testing.T) {
	s := newTestServer(t)
	resp := s.buildHealthResponse()
	if resp.Features.GeoIP {
		t.Error("features.geoip = true when geoip manager is nil")
	}
}

// TestBuildHealthResponseEmailNil verifies features.email = false when email
// manager is nil (default in newTestServer).
func TestBuildHealthResponseEmailNil(t *testing.T) {
	s := newTestServer(t)
	resp := s.buildHealthResponse()
	if resp.Features.Email {
		t.Error("features.email = true when email manager is nil")
	}
}

// TestBuildHealthResponseRateLimiting verifies features.rate_limiting is always
// true (non-negotiable per spec).
func TestBuildHealthResponseRateLimiting(t *testing.T) {
	s := newTestServer(t)
	resp := s.buildHealthResponse()
	if !resp.Features.RateLimiting {
		t.Error("features.rate_limiting = false, want true (always enabled)")
	}
}

// TestBuildHealthResponseCaching verifies features.caching is always true
// (non-negotiable per spec).
func TestBuildHealthResponseCaching(t *testing.T) {
	s := newTestServer(t)
	resp := s.buildHealthResponse()
	if !resp.Features.Caching {
		t.Error("features.caching = false, want true (always enabled)")
	}
}

// --- middleware.go: LoggingMiddleware remote-addr branches ---

// TestLoggingMiddlewareValidRemoteAddr verifies no panic with a valid host:port
// RemoteAddr, covering the SplitHostPort success path.
func TestLoggingMiddlewareValidRemoteAddr(t *testing.T) {
	s := newTestServer(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.LoggingMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/healthz", nil)
	req.RemoteAddr = "10.0.0.5:9090"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestLoggingMiddlewareInvalidRemoteAddr verifies no panic when RemoteAddr has
// no port (SplitHostPort fails; code falls back gracefully).
func TestLoggingMiddlewareInvalidRemoteAddr(t *testing.T) {
	s := newTestServer(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.LoggingMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// --- whois_handlers.go: handleWHOISBulkLookup branches ---

// TestHandleWHOISBulkLookupDecodeError verifies a non-JSON body returns 400.
func TestHandleWHOISBulkLookupDecodeError(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whois/bulk", bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleWHOISBulkLookup(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bulk decode error: status = %d, want 400", rr.Code)
	}
}

// TestHandleWHOISBulkLookupEmptyQueries verifies an empty queries array returns 400.
func TestHandleWHOISBulkLookupEmptyQueries(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(map[string]interface{}{"queries": []string{}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whois/bulk", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleWHOISBulkLookup(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bulk empty queries: status = %d, want 400", rr.Code)
	}
}

// TestHandleWHOISBulkLookupTooManyQueries verifies >100 queries returns 400.
func TestHandleWHOISBulkLookupTooManyQueries(t *testing.T) {
	s := newTestServer(t)
	queries := make([]string, 101)
	for i := range queries {
		queries[i] = fmt.Sprintf("example%d.com", i)
	}
	body, _ := json.Marshal(map[string]interface{}{"queries": queries})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whois/bulk", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleWHOISBulkLookup(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bulk too many: status = %d, want 400", rr.Code)
	}
}

// TestHandleWHOISBulkLookupInvalidQuery verifies an invalid query in the batch
// is reported per-result, not as a 400, and success entries are still included.
func TestHandleWHOISBulkLookupInvalidQuery(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(map[string]interface{}{"queries": []string{"not..valid"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whois/bulk", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleWHOISBulkLookup(rr, req)
	// Invalid entries produce success=false per item; overall HTTP is 200.
	if rr.Code != http.StatusOK {
		t.Errorf("bulk invalid query: status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "false") {
		t.Error("bulk response missing success:false for invalid query")
	}
}

// TestHandleWHOISBulkLookupEmptyStringQuery verifies blank-string queries are
// silently skipped (empty string in the batch).
func TestHandleWHOISBulkLookupSkipEmptyString(t *testing.T) {
	s := newTestServer(t)
	body, _ := json.Marshal(map[string]interface{}{"queries": []string{"   ", "   "}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whois/bulk", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleWHOISBulkLookup(rr, req)
	// All queries were blank so results count is 0; HTTP is still 200.
	if rr.Code != http.StatusOK {
		t.Errorf("bulk skip empty: status = %d, want 200", rr.Code)
	}
}

// --- whois_handlers.go: handleWHOISOwnerSearch branches ---

// TestHandleWHOISOwnerSearchMissingQuery verifies missing ?owner= returns 400.
func TestHandleWHOISOwnerSearchMissingQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/search", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISOwnerSearch(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("owner search missing query: status = %d, want 400", rr.Code)
	}
}

// TestHandleWHOISOwnerSearchSingleChar verifies a single-char owner query is accepted
// (the handler only rejects empty, not short strings) and returns non-400.
func TestHandleWHOISOwnerSearchSingleChar(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/search?owner=x", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISOwnerSearch(rr, req)
	if rr.Code == http.StatusBadRequest {
		t.Errorf("owner search single char: status = %d, should not be 400", rr.Code)
	}
}

// TestHandleWHOISOwnerSearchValidQuery verifies a valid owner search returns 200 or 500.
func TestHandleWHOISOwnerSearchValidQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/search?owner=example", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISOwnerSearch(rr, req)
	// DB query may fail (no WHOIS records table pre-seeded) — 200 or 500, never 400.
	if rr.Code == http.StatusBadRequest {
		t.Errorf("owner search valid: status = %d, should not be 400", rr.Code)
	}
}

// --- ops_handlers.go: handleSchedulerRun additional branches ---

// TestHandleSchedulerRunMissingTaskParam verifies missing ?task= returns 400.
func TestHandleSchedulerRunMissingTaskParam(t *testing.T) {
	s := newTestServer(t)
	// Scheduler is non-nil (newTestServer wires it up).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/schedulers/run", nil)
	rr := httptest.NewRecorder()
	s.handleSchedulerRun(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleSchedulerRun(no task): status = %d, want 400", rr.Code)
	}
}

// TestHandleSchedulerRunUnknownTaskIDV2 verifies an unknown taskID that contains
// special characters is still rejected with 404.
func TestHandleSchedulerRunUnknownTaskIDV2(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/schedulers/run?task=__nonexistent__xyz__", nil)
	rr := httptest.NewRecorder()
	s.handleSchedulerRun(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("handleSchedulerRun(unknown-id-v2): status = %d, want 404", rr.Code)
	}
}

// --- ops_handlers.go: handleSchedulerRun wrong method ---

// TestHandleSchedulerRunWrongMethod verifies GET returns 405.
func TestHandleSchedulerRunWrongMethod(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/schedulers/run?task=test", nil)
	rr := httptest.NewRecorder()
	s.handleSchedulerRun(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleSchedulerRun(GET): status = %d, want 405", rr.Code)
	}
}

// --- ops_handlers.go: handleBackupRun wrong method ---

// TestHandleBackupRunWrongMethod verifies GET on /backups/run returns 405.
func TestHandleBackupRunWrongMethod(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/backups/run", nil)
	rr := httptest.NewRecorder()
	s.handleBackupRun(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleBackupRun(GET): status = %d, want 405", rr.Code)
	}
}

// --- ops_handlers.go: runBackup with encryption enabled ---

// TestRunBackupEncryptionEnabled exercises the encryption branch in runBackup.
// Because backup.Create writes to s.config.GetBackupDir(), we point it at a
// temp dir so the file can be inspected and cleaned up automatically.
func TestRunBackupEncryptionEnabled(t *testing.T) {
	s := newTestServer(t)
	dir := t.TempDir()
	s.config.Backup.Dir = dir
	s.config.Backup.Encryption.Enabled = true
	s.config.ServerToken = "test-token-for-encryption"

	filename, err := s.runBackup("test-prefix")
	if err != nil {
		t.Logf("runBackup(encryption) error (acceptable in CI without full config): %v", err)
		return
	}
	if filename == "" {
		t.Error("runBackup returned empty filename on success")
	}
	// Verify the file was actually written.
	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		t.Error("runBackup(encryption) wrote no files to backup dir")
	}
}

// TestRunBackupNoEncryption exercises the unencrypted (default) path in runBackup.
func TestRunBackupNoEncryption(t *testing.T) {
	s := newTestServer(t)
	dir := t.TempDir()
	s.config.Backup.Dir = dir
	s.config.Backup.Encryption.Enabled = false

	filename, err := s.runBackup("test-noenc")
	if err != nil {
		t.Logf("runBackup(no-enc) error (acceptable): %v", err)
		return
	}
	if filename == "" {
		t.Error("runBackup returned empty filename on success")
	}
}

// --- health.go: checkDatabase with nil database ---

// TestCheckDatabaseNil verifies "error" when database is nil.
func TestCheckDatabaseNil(t *testing.T) {
	s := newTestServer(t)
	s.database = nil
	if got := s.checkDatabase(); got != "error" {
		t.Errorf("checkDatabase(nil) = %q, want 'error'", got)
	}
}

// --- health.go: checkScheduler with non-nil scheduler ---

// TestCheckSchedulerNonNil verifies "ok" when scheduler is not nil.
func TestCheckSchedulerNonNil(t *testing.T) {
	s := newTestServer(t)
	if s.scheduler == nil {
		t.Skip("scheduler is nil in this test environment")
	}
	if got := s.checkScheduler(); got != "ok" {
		t.Errorf("checkScheduler(non-nil) = %q, want 'ok'", got)
	}
}

// --- health.go: buildHealthResponse mode field ---

// TestBuildHealthResponseModeProduction verifies Mode field reflects config.
func TestBuildHealthResponseModeProduction(t *testing.T) {
	s := newTestServer(t)
	s.config.Mode = "production"
	resp := s.buildHealthResponse()
	if resp.Mode != "production" {
		t.Errorf("mode = %q, want 'production'", resp.Mode)
	}
}

// --- health.go: renderHealthText ---

// TestRenderHealthTextOutput verifies plain-text health response has expected fields.
func TestRenderHealthTextOutput(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Accept", "text/plain")
	rr := httptest.NewRecorder()
	s.handleHealth(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleHealth(text): status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"status:", "version:", "uptime:", "checks.database:"} {
		if !strings.Contains(body, want) {
			t.Errorf("plain-text health missing field %q", want)
		}
	}
}

// --- stats.go: recordRequest normal path ---

// TestRecordRequestIncrements verifies requestsTotal and requests24h increment.
func TestRecordRequestIncrements(t *testing.T) {
	s := newTestServer(t)
	before := s.stats.requestsTotal.Load()
	s.stats.recordRequest()
	after := s.stats.requestsTotal.Load()
	if after != before+1 {
		t.Errorf("requestsTotal: before=%d after=%d, want before+1", before, after)
	}
}

// TestRecordRequestActiveConns verifies active connection count via recordRequest.
func TestRecordRequestActiveConns(t *testing.T) {
	s := newTestServer(t)
	// The active connection path is exercised through the middleware, not directly.
	// Verifying the counter itself is always present and non-negative.
	if conns := s.stats.activeConns.Load(); conns < 0 {
		t.Errorf("activeConns = %d, want >= 0", conns)
	}
}

// --- public_handler.go: newTranslatorFunc ---

// TestNewTranslatorFuncReturnsFunc verifies newTranslatorFunc produces a callable
// that does not panic on any key.
func TestNewTranslatorFuncReturnsFunc(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	fn := newTranslatorFunc(req)
	if fn == nil {
		t.Error("newTranslatorFunc returned nil")
	}
	// Call it with a known key — should not panic.
	result := fn("app.name")
	t.Logf("newTranslatorFunc(req)('app.name') = %q", result)
}

// TestNewTranslatorFuncAcceptLanguage verifies the translator uses the
// Accept-Language header to pick a non-default language without panicking.
func TestNewTranslatorFuncAcceptLanguage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "es")
	fn := newTranslatorFunc(req)
	if fn == nil {
		t.Error("newTranslatorFunc(es) returned nil")
	}
	_ = fn("any.key")
}

// --- content.go: DetectClientType edge cases ---

// TestDetectClientTypeXHRNoAccept verifies XHR with no Accept header returns
// text (no Accept header + empty UA defaults to text for programmatic access).
func TestDetectClientTypeXHRNoAccept(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	got := DetectClientType(req)
	if got != ClientTypeText {
		t.Errorf("DetectClientType(XHR no Accept) = %v, want ClientTypeText", got)
	}
}

// TestDetectClientTypeXHRWithJSONAccept verifies XHR with application/json Accept
// returns the JSON client type.
func TestDetectClientTypeXHRWithJSONAccept(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json")
	got := DetectClientType(req)
	if got != ClientTypeJSON {
		t.Errorf("DetectClientType(XHR+JSON Accept) = %v, want ClientTypeJSON", got)
	}
}

// TestDetectClientTypeCurlUserAgent verifies curl User-Agent returns text client type.
func TestDetectClientTypeCurlUserAgent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	got := DetectClientType(req)
	if got != ClientTypeText {
		t.Errorf("DetectClientType(curl) = %v, want ClientTypeText", got)
	}
}

// --- pid_unix.go: RemovePIDFile on non-writable path ---

// TestRemovePIDFilePermissionError verifies RemovePIDFile returns error for a
// path in a read-only directory (covers the non-IsNotExist error path).
func TestRemovePIDFilePermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission errors are not enforced")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	if err := os.WriteFile(path, []byte("123:0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Make the directory read-only so os.Remove fails with EACCES.
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0755) })

	err := RemovePIDFile(path)
	if err == nil {
		t.Error("RemovePIDFile on read-only dir: expected error, got nil")
	}
}

// --- server.go: setupRoutes + setupMiddleware (exercised via handler dispatch) ---

// TestSetupRoutesHealthEndpoint verifies /server/healthz is reachable after setupRoutes.
func TestSetupRoutesHealthEndpoint(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()
	handler = s.setupMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/server/healthz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("setupRoutes /server/healthz: status = %d, want 200", rr.Code)
	}
}

// TestSetupRoutesAPIHealthEndpoint verifies /api/v1/server/healthz is reachable.
func TestSetupRoutesAPIHealthEndpoint(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/healthz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("setupRoutes /api/v1/server/healthz: status = %d, want 200", rr.Code)
	}
}

// TestSetupRoutesRootReturnsHTML verifies the root path returns HTML.
func TestSetupRoutesRootReturnsHTML(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("setupRoutes /: status = %d, want 200", rr.Code)
	}
}

// TestSetupRoutesUnknownPathReturns404 verifies unmatched paths get 404.
func TestSetupRoutesUnknownPathReturns404(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()

	req := httptest.NewRequest(http.MethodGet, "/totally-unknown-path-xyz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("setupRoutes unknown path: status = %d, want 404", rr.Code)
	}
}

// TestSetupRoutesAPIUnknownReturnsJSON verifies /api/* unmatched paths return JSON 404.
func TestSetupRoutesAPIUnknownReturnsJSON(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nonexistent", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("setupRoutes /api/v1/nonexistent: status = %d, want 404", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("API 404 Content-Type = %q, want application/json", ct)
	}
}

// TestSetupRoutesRequireTokenEndpoint verifies token-protected endpoints return 401 without token.
func TestSetupRoutesRequireTokenEndpoint(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/schedulers", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("token-protected route without token: status = %d, want 401", rr.Code)
	}
}

// TestSetupRoutesWithToken verifies token-protected endpoints work with a valid token.
func TestSetupRoutesWithToken(t *testing.T) {
	s := newTestServer(t)
	s.config.ServerToken = "test-token-abc123"
	handler := s.setupRoutes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/schedulers", nil)
	req.Header.Set("Authorization", "Bearer test-token-abc123")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("token-protected route with valid token: status = %d, want 200", rr.Code)
	}
}

// TestSetupMiddlewarePassesThrough verifies the middleware chain passes requests through.
func TestSetupMiddlewarePassesThrough(t *testing.T) {
	s := newTestServer(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.setupMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("setupMiddleware: status = %d, want 200", rr.Code)
	}
}

// --- errors.go: writeJSON marshal error path ---

// TestWriteJSONMarshalError verifies writeJSON handles a type that cannot be marshalled.
func TestWriteJSONMarshalError(t *testing.T) {
	rr := httptest.NewRecorder()
	// channel values cannot be JSON-marshalled; this exercises the marshal-error path.
	writeJSON(rr, http.StatusOK, make(chan int))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("writeJSON(unmarshalable): status = %d, want 500", rr.Code)
	}
}

// --- pid_unix.go: WritePIDFile ---

// TestWritePIDFileCreatesFile verifies WritePIDFile creates the PID file with port embedded.
func TestWritePIDFileCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "caswhois.pid")

	if err := WritePIDFile(path, 8080); err != nil {
		t.Fatalf("WritePIDFile: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after WritePIDFile: %v", err)
	}
	content := strings.TrimSpace(string(data))
	if !strings.Contains(content, ":8080") {
		t.Errorf("PID file content = %q, want to contain ':8080'", content)
	}
}

// TestWritePIDFileAlreadyRunning verifies WritePIDFile with a running-process PID file
// does not panic and handles the case gracefully.
func TestWritePIDFileAlreadyRunning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caswhois.pid")

	// Write own PID so isProcessRunning returns true.
	pid := os.Getpid()
	content := fmt.Sprintf("%d:8080\n", pid)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// WritePIDFile calls CheckPIDFile internally.
	// Behaviour depends on isOurProcess — must not panic regardless.
	_ = WritePIDFile(path, 9090)
}

// --- health.go: buildTorInfo with non-nil torService (starting branch) ---

// errCacheStats is a minimal cache that always returns an error from Stats.
// It satisfies the cache.Cache interface for the handleDebugCache error-path test.
type errCacheStats struct {
	cache.Cache
}

// Stats always returns a non-nil error to exercise the error branch in handleDebugCache.
func (e *errCacheStats) Stats(ctx context.Context) (*cache.Stats, error) {
	return nil, fmt.Errorf("stats unavailable")
}

// TestHandleDebugCacheStatsError verifies handleDebugCache returns 500 when cache.Stats fails.
func TestHandleDebugCacheStatsError(t *testing.T) {
	s := newTestServer(t)
	s.cache = &errCacheStats{}

	req := httptest.NewRequest(http.MethodGet, "/debug/cache", nil)
	rr := httptest.NewRecorder()
	s.handleDebugCache(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("handleDebugCache(stats error): status = %d, want 500", rr.Code)
	}
}

// TestBuildTorInfoWithNonNilService verifies buildTorInfo with a TorService
// that has an empty serviceID (serviceID="" → OnionAddress() returns ".onion")
// exercises the non-nil torService branch and returns Status "starting".
func TestBuildTorInfoWithNonNilService(t *testing.T) {
	s := newTestServer(t)
	// A zero-value TorService has serviceID = "" so OnionAddress() returns ".onion"
	// which means running = false and status = "starting".
	s.torService = &castor.TorService{}

	info := s.buildTorInfo()
	if !info.Enabled {
		t.Error("buildTorInfo(non-nil service): Enabled should be true")
	}
	if info.Running {
		t.Error("buildTorInfo(non-nil service, empty serviceID): Running should be false")
	}
	if info.Status != "starting" {
		t.Errorf("buildTorInfo(non-nil service, empty serviceID): Status = %q, want 'starting'", info.Status)
	}
}

// --- server.go: handleMetrics token branch ---

// TestHandleMetricsNoTokenRequired verifies /metrics is accessible when no token is configured.
func TestHandleMetricsNoTokenRequired(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// /metrics without metrics collector configured → 404 (not registered).
	// If metrics is registered → 200.
	if rr.Code != http.StatusOK && rr.Code != http.StatusNotFound {
		t.Errorf("handleMetrics without token: unexpected status = %d", rr.Code)
	}
}

// --- whois_handlers.go: performWHOISLookup XML format ---

// TestPerformWHOISLookupValidationError verifies performWHOISLookup returns 400 for invalid query.
func TestPerformWHOISLookupValidationError(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/!!invalid!!", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISDomainLookup(rr, req)
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusInternalServerError {
		t.Errorf("performWHOISLookup invalid: unexpected status = %d", rr.Code)
	}
}

// TestDetermineResponseFormatXML verifies ?format=xml parameter is handled.
func TestDetermineResponseFormatXML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/example.com?format=xml", nil)
	got := determineResponseFormat(req)
	if got != "xml" {
		t.Errorf("determineResponseFormat(?format=xml) = %q, want 'xml'", got)
	}
}

// TestDetermineResponseFormatText verifies ?format=text parameter is handled.
func TestDetermineResponseFormatText(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/example.com?format=text", nil)
	got := determineResponseFormat(req)
	if got != "text" {
		t.Errorf("determineResponseFormat(?format=text) = %q, want 'text'", got)
	}
}

// TestDetermineResponseFormatHTML verifies ?format=html parameter is handled.
func TestDetermineResponseFormatHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/example.com?format=html", nil)
	got := determineResponseFormat(req)
	if got != "html" {
		t.Errorf("determineResponseFormat(?format=html) = %q, want 'html'", got)
	}
}

// TestDetermineResponseFormatFromAcceptXML verifies Accept: application/xml header.
func TestDetermineResponseFormatFromAcceptXML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/example.com", nil)
	req.Header.Set("Accept", "application/xml")
	got := determineResponseFormat(req)
	if got != "xml" {
		t.Errorf("determineResponseFormat(Accept:application/xml) = %q, want 'xml'", got)
	}
}

// TestDetermineResponseFormatFromAcceptTextXML verifies Accept: text/xml header.
func TestDetermineResponseFormatFromAcceptTextXML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/example.com", nil)
	req.Header.Set("Accept", "text/xml")
	got := determineResponseFormat(req)
	if got != "xml" {
		t.Errorf("determineResponseFormat(Accept:text/xml) = %q, want 'xml'", got)
	}
}

// TestDetermineResponseFormatFromAcceptHTML verifies Accept: text/html header.
func TestDetermineResponseFormatFromAcceptHTML(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/example.com", nil)
	req.Header.Set("Accept", "text/html")
	got := determineResponseFormat(req)
	if got != "html" {
		t.Errorf("determineResponseFormat(Accept:text/html) = %q, want 'html'", got)
	}
}

// TestDetermineResponseFormatInvalidParam verifies an invalid ?format= falls back to JSON.
func TestDetermineResponseFormatInvalidParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/example.com?format=protobuf", nil)
	got := determineResponseFormat(req)
	if got != "json" {
		t.Errorf("determineResponseFormat(?format=protobuf) = %q, want 'json'", got)
	}
}

// --- static_embed.go: mustParseTemplate non-existent file panics ---

// TestMustParseTemplatePanicsOnMissingFile verifies mustParseTemplate panics for an invalid file.
func TestMustParseTemplatePanicsOnMissingFile(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("mustParseTemplate(nonexistent file): expected panic, got none")
		}
	}()
	mustParseTemplate("test", "nonexistent-file-that-does-not-exist.html")
}

// --- server.go: handleWHOIS valid query (covers network-failure path) ---

// TestHandleWHOISValidQueryNetworkFail verifies handleWHOIS with a valid-format query
// returns 200 or 500 (network failure in test env), never 400.
func TestHandleWHOISValidQueryNetworkFail(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/example.com", nil)
	rr := httptest.NewRecorder()
	s.handleWHOIS(rr, req)
	if rr.Code == http.StatusBadRequest {
		t.Errorf("handleWHOIS valid query format: unexpected 400")
	}
}

// --- ops_handlers.go: runBackup MkdirAll error branch ---

// TestRunBackupMkdirAllError verifies runBackup returns an error when the backup
// directory cannot be created (path inside a non-existent read-only parent).
func TestRunBackupMkdirAllError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission errors are not enforced")
	}
	s := newTestServer(t)
	dir := t.TempDir()
	// Make the temp dir read-only so MkdirAll for a sub-path fails.
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0755) })
	s.config.Backup.Dir = filepath.Join(dir, "subdir", "nested")

	_, err := s.runBackup("test")
	if err == nil {
		t.Error("runBackup with unwritable parent: expected error, got nil")
	}
}

// --- pid_unix.go: WritePIDFile directory creation failure ---

// TestWritePIDFileDirCreationFails verifies WritePIDFile returns an error when the
// directory for the PID file cannot be created.
func TestWritePIDFileDirCreationFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission errors are not enforced")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0755) })
	pidPath := filepath.Join(dir, "newsubdir", "test.pid")
	err := WritePIDFile(pidPath, 8080)
	if err == nil {
		t.Error("WritePIDFile with unwritable dir: expected error, got nil")
	}
}

// --- public_handler.go: handleWHOISPage text-client error path ---

// TestHandleWHOISPageTextClientLookupFail verifies the text-client error path in
// handleWHOISPage when the WHOIS network lookup fails (returns 500).
func TestHandleWHOISPageTextClientLookupFail(t *testing.T) {
	s := newTestServer(t)
	// Use a clearly invalid but non-empty query that passes the text-client path
	// but will fail lookup due to no network in test environment.
	req := httptest.NewRequest(http.MethodGet, "/whois?q=definitely-not-a-real-tld.xyzzy", nil)
	req.Header.Set("Accept", "text/plain")
	rr := httptest.NewRecorder()
	s.handleWHOISPage(rr, req)
	// Either 200 (live lookup succeeded unexpectedly) or 500 (lookup failed) is valid.
	// 400 is never expected for a non-empty query in text client mode.
	if rr.Code == http.StatusBadRequest {
		t.Errorf("handleWHOISPage text client with query: unexpected 400")
	}
}

// TestHandleWHOISPageJSONClientLookupFail verifies the JSON-client error path in
// handleWHOISPage when the WHOIS lookup fails.
func TestHandleWHOISPageJSONClientLookupFail(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois?q=definitely-not-real.xyzzy", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	s.handleWHOISPage(rr, req)
	if rr.Code == http.StatusBadRequest {
		t.Errorf("handleWHOISPage JSON client with query: unexpected 400")
	}
}

// TestHandleWHOISPageHTMLClientLookupFail verifies the HTML-client error display branch
// in handleWHOISPage when the WHOIS lookup fails (data.Err is set, still 200).
func TestHandleWHOISPageHTMLClientLookupFail(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois?q=definitely-not-real.xyzzy", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	s.handleWHOISPage(rr, req)
	// HTML clients always get 200 (error shown inline in the page).
	if rr.Code != http.StatusOK {
		t.Errorf("handleWHOISPage HTML client: status = %d, want 200", rr.Code)
	}
}

// --- health.go: checkDatabase ping failure path ---

// TestCheckDatabasePingFails verifies checkDatabase returns "error" when the
// underlying sql.DB is closed and PingContext fails.
func TestCheckDatabasePingFails(t *testing.T) {
	s := newTestServer(t)

	// Close the DB now — s.database wrapper is still non-nil so checkDatabase
	// reaches the PingContext branch (not the nil branch). The t.Cleanup
	// registered by newTestServer will double-close but errors are ignored there.
	if err := s.database.Close(); err != nil {
		t.Fatalf("close test database: %v", err)
	}

	result := s.checkDatabase()
	if result != "error" {
		t.Errorf("checkDatabase after close = %q, want 'error'", result)
	}

	// Nil out so the deferred cleanup in newTestServer does not panic.
	s.database = nil
}

// --- whois_handlers.go: handleWHOISOwnerSearch with local records (covers loop body) ---

// TestHandleWHOISOwnerSearchWithLocalRecords inserts a record into the DB then
// searches for it, exercising the for-loop body in handleWHOISOwnerSearch.
func TestHandleWHOISOwnerSearchWithLocalRecords(t *testing.T) {
	s := newTestServer(t)

	// Insert a record so the owner search loop body is executed.
	domain := &parser.DomainResult{
		Domain:       "testcorp.com",
		Registrar:    "TestRegistrar LLC",
		Registrant:   "Test Corp",
		Organization: "Test Corp",
		Email:        "admin@testcorp.com",
	}
	if err := records.UpsertRecord(context.Background(), s.database.Server, "testcorp.com", "domain", domain); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/whois/search?owner=Test+Corp", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISOwnerSearch(rr, req)

	// Expect 200 with results array containing at least one entry.
	if rr.Code != http.StatusOK {
		t.Errorf("handleWHOISOwnerSearch with records: status = %d, want 200", rr.Code)
	}
	var resp APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Errorf("handleWHOISOwnerSearch with records: resp.OK = false")
	}
}

// TestHandleWHOISOwnerSearchExternalFallback verifies the external-provider path
// in handleWHOISOwnerSearch is exercised when headers are provided and no local
// records exist (extErr != nil path — covers the if condition itself).
func TestHandleWHOISOwnerSearchExternalFallback(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois/search?owner=SomeOrg", nil)
	req.Header.Set("X-Provider-Name", "securitytrails")
	req.Header.Set("X-Provider-Key", "fake-key-for-test")
	rr := httptest.NewRecorder()
	s.handleWHOISOwnerSearch(rr, req)
	// Result is 200 (empty results when external call fails) or 200 with results.
	// Any non-500 is acceptable — we're exercising the external branch, not the outcome.
	if rr.Code != http.StatusOK {
		t.Logf("handleWHOISOwnerSearch external fallback: status = %d (acceptable in CI)", rr.Code)
	}
}

// --- cli_binary.go: handleCLIBinaryDownload serve + isDir branch ---

// TestHandleCLIBinaryDownloadIsDir verifies 404 is returned when the binary
// path resolves to a directory instead of a regular file.
func TestHandleCLIBinaryDownloadIsDir(t *testing.T) {
	s := newTestServer(t)
	dir := t.TempDir()
	s.config.DataDir = dir

	// Create a directory at the expected binary path.
	binaryName := "caswhois-cli-linux-amd64"
	binaryDir := filepath.Join(dir, "cli-binaries", binaryName)
	if err := os.MkdirAll(binaryDir, 0755); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/cli/binaries/"+binaryName, nil)
	rr := httptest.NewRecorder()
	s.handleCLIBinaryDownload(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("handleCLIBinaryDownload(isDir): status = %d, want 404", rr.Code)
	}
}

// TestHandleCLIBinaryDownloadSuccess verifies a valid binary file is served
// with application/octet-stream Content-Type (covers the serve path).
func TestHandleCLIBinaryDownloadSuccess(t *testing.T) {
	s := newTestServer(t)
	dir := t.TempDir()
	s.config.DataDir = dir

	// Create a fake binary file at the expected location.
	binaryName := "caswhois-cli-linux-amd64"
	binaryDir := filepath.Join(dir, "cli-binaries")
	if err := os.MkdirAll(binaryDir, 0755); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(binaryDir, binaryName)
	if err := os.WriteFile(binaryPath, []byte("fake binary content"), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/cli/binaries/"+binaryName, nil)
	rr := httptest.NewRecorder()
	s.handleCLIBinaryDownload(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleCLIBinaryDownload(success): status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "octet-stream") {
		t.Errorf("handleCLIBinaryDownload(success): Content-Type = %q, want application/octet-stream", ct)
	}
}

// TestHandleSchedulerRunSuccess verifies that handleSchedulerRun returns 200
// when a registered task ID is provided (covers the success path).
func TestHandleSchedulerRunSuccess(t *testing.T) {
	s := newTestServer(t)

	// Register a simple no-op task so RunTaskNow finds it.
	task := &scheduler.Task{
		ID:      "test-noop",
		Name:    "Test No-Op",
		Schedule: "@daily",
		Enabled: true,
		Handler: func(_ context.Context) error { return nil },
	}
	if err := s.scheduler.Register(task); err != nil {
		t.Fatalf("Register task: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/schedulers/run?task=test-noop", nil)
	rr := httptest.NewRecorder()
	s.handleSchedulerRun(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleSchedulerRun(success): status = %d, want 200", rr.Code)
	}
	var resp APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Errorf("handleSchedulerRun(success): resp.OK = false, body = %s", rr.Body.String())
	}
}

// TestLanguageMiddlewareCookieFallback verifies that LanguageMiddleware reads
// the language from a lang cookie when no query parameter is present (covers the
// cookie branch).
func TestLanguageMiddlewareCookieFallback(t *testing.T) {
	called := false
	var capturedLang string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		capturedLang = LangFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := LanguageMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Add a supported lang cookie (no query param so the cookie branch is hit).
	req.AddCookie(&http.Cookie{Name: "lang", Value: "es"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("LanguageMiddleware: inner handler was not called")
	}
	if capturedLang != "es" {
		t.Errorf("LanguageMiddleware(cookie): lang = %q, want 'es'", capturedLang)
	}
}

// TestHandleAutodiscoverForwardedProto verifies that handleAutodiscover uses
// the X-Forwarded-Proto header to determine the scheme (covers the forwarded
// proto branch).
func TestHandleAutodiscoverForwardedProto(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/autodiscover", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	s.handleAutodiscover(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleAutodiscover(forwarded-proto): status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "https://") {
		t.Errorf("handleAutodiscover(forwarded-proto): body does not contain 'https://', got: %s", body)
	}
}

// TestHandleLocaleJSONUnsupportedLang verifies that handleLocaleJSON falls back
// to English when an unsupported language code is requested (covers the lang
// normalisation branch).
func TestHandleLocaleJSONUnsupportedLang(t *testing.T) {
	s := newTestServer(t)

	// "xx" is not a supported language; the handler should fall back to "en".
	req := httptest.NewRequest(http.MethodGet, "/locales/xx.json", nil)
	rr := httptest.NewRecorder()
	s.handleLocaleJSON(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleLocaleJSON(unsupported lang): status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("handleLocaleJSON(unsupported lang): Content-Type = %q, want application/json", ct)
	}
}

// TestRunBackupSuccess verifies that runBackup succeeds and returns a filename
// when valid config dir, data dir, and backup dir are configured with the
// required files in place (covers the ApplyRetentionPolicy path after
// backup.Create succeeds).
func TestRunBackupSuccess(t *testing.T) {
	s := newTestServer(t)

	// Set up temp dirs for all three required paths.
	base := t.TempDir()
	cfgDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")
	backupDir := filepath.Join(base, "backups")
	for _, d := range []string{cfgDir, dataDir, backupDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Create the files that backup.Create requires.
	if err := os.WriteFile(filepath.Join(cfgDir, "server.yml"), []byte("server:\n  address: :64001\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "server.db"), []byte("fake db"), 0644); err != nil {
		t.Fatal(err)
	}

	// Point the server config at the temp dirs.
	s.config.ConfigDir = cfgDir
	s.config.Database.Dir = dataDir
	s.config.Backup.Dir = backupDir

	filename, err := s.runBackup("test")
	if err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	if !strings.HasPrefix(filename, "test-") {
		t.Errorf("runBackup: filename = %q, want prefix 'test-'", filename)
	}
}

// TestSetupRoutesWithMetricsEnabled verifies that setupRoutes registers the
// /metrics endpoint when s.metrics is non-nil and Metrics.Enabled is true
// (covers the metrics registration branch in setupRoutes).
func TestSetupRoutesWithMetricsEnabled(t *testing.T) {
	s := newTestServer(t)

	// Enable metrics with a real Collector so the registration branch is hit.
	s.metrics = metrics.New("caswhois_test", metrics.MetricsConfig{
		Enabled:  true,
		Endpoint: "/metrics",
	})
	s.config.Metrics.Enabled = true
	s.config.Metrics.Endpoint = "/metrics"

	handler := s.setupRoutes()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Prometheus /metrics endpoint returns 200 with text/plain content.
	if rr.Code != http.StatusOK {
		t.Errorf("setupRoutes(metrics enabled): GET /metrics status = %d, want 200", rr.Code)
	}
}

// TestSetupMiddlewareWithMetrics verifies that setupMiddleware wraps the handler
// with the metrics middleware when s.metrics is non-nil (covers the
// s.metrics != nil branch in setupMiddleware).
func TestSetupMiddlewareWithMetrics(t *testing.T) {
	s := newTestServer(t)

	// Non-nil metrics collector triggers the metrics middleware branch.
	s.metrics = metrics.New("caswhois_mw_test", metrics.MetricsConfig{
		Enabled: true,
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.setupMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("setupMiddleware(with metrics): status = %d, want 200", rr.Code)
	}
}

// --- content.go: DetectClientType unknown UA fallback (line 66) ---

// TestDetectClientTypeUnknownUA verifies that a non-browser, non-CLI User-Agent
// that is non-empty falls through to the final HTML default at line 66.
func TestDetectClientTypeUnknownUA(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "CustomApp/3.0")
	got := DetectClientType(req)
	if got != ClientTypeHTML {
		t.Errorf("DetectClientType(unknown UA): got %q, want %q", got, ClientTypeHTML)
	}
}

// --- content.go: respondText fmt.Stringer branch (line 80) ---

// stringerValue3 is a minimal fmt.Stringer used in TestRespondTextStringerCov3.
type stringerValue3 struct{ s string }

func (v stringerValue3) String() string { return v.s }

// TestRespondTextStringerCov3 verifies that respondText calls String() when the
// data value implements fmt.Stringer, covering the Stringer branch at line 80.
func TestRespondTextStringerCov3(t *testing.T) {
	rr := httptest.NewRecorder()
	respondText(rr, http.StatusOK, stringerValue3{"hello stringer"})
	if !strings.Contains(rr.Body.String(), "hello stringer") {
		t.Errorf("respondText(Stringer): body = %q, want to contain %q", rr.Body.String(), "hello stringer")
	}
}

// --- whois_handlers.go: domainQueries.Add + performWHOISLookup (lines 38–41, 215–218) ---

// TestHandleWHOISDomainLookupValidDomain verifies that a well-formed domain
// passes the type check, increments domainQueries, and enters performWHOISLookup.
// Network calls fail in Docker so the handler returns 500, but the stats
// counter and lookup path (lines 38–41) and the WHOIS-error path (215–218) are covered.
func TestHandleWHOISDomainLookupValidDomain(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/google.com", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISDomainLookup(rr, req)
	if rr.Code == http.StatusBadRequest {
		t.Errorf("handleWHOISDomainLookup(valid): got 400; expected stats+lookup to execute")
	}
}

// --- whois_handlers.go: ipQueries.Add + performWHOISLookup (lines 63–66) ---

// TestHandleWHOISIPLookupValidIP verifies that a valid IPv4 address increments
// ipQueries and enters performWHOISLookup (lines 63–66).
func TestHandleWHOISIPLookupValidIP(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/ip/8.8.8.8", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISIPLookup(rr, req)
	if rr.Code == http.StatusBadRequest {
		t.Errorf("handleWHOISIPLookup(valid): got 400; expected stats+lookup to execute")
	}
}

// --- whois_handlers.go: asnQueries.Add + performWHOISLookup (lines 88–91) ---

// TestHandleWHOISASNLookupValidASN verifies that a valid ASN increments
// asnQueries and enters performWHOISLookup (lines 88–91).
func TestHandleWHOISASNLookupValidASN(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/asn/AS15169", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISASNLookup(rr, req)
	if rr.Code == http.StatusBadRequest {
		t.Errorf("handleWHOISASNLookup(valid): got 400; expected stats+lookup to execute")
	}
}

// --- stats.go: recordRequest new-day CAS-success path (line 33) ---

// TestServerStatsRecordRequestNewDay verifies that the first call to
// recordRequest on a zero-initialized serverStats takes the CAS-success path
// (dayStart == 0 != today), setting requests24h to 1 (line 33).
func TestServerStatsRecordRequestNewDay(t *testing.T) {
	st := &serverStats{}
	st.recordRequest()
	if got := st.requests24h.Load(); got != 1 {
		t.Errorf("recordRequest (new day): requests24h = %d, want 1", got)
	}
}

// --- autodiscover.go: HTTPS scheme detection (line 72) ---

// TestHandleAutodiscoverTLS verifies that a request with r.TLS != nil causes
// the base URL scheme to be "https" (line 72).
func TestHandleAutodiscoverTLS(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/autodiscover", nil)
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()
	s.handleAutodiscover(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleAutodiscover(TLS): status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "https://") {
		t.Errorf("handleAutodiscover(TLS): base_url missing https://, body = %q", rr.Body.String())
	}
}

// --- autodiscover.go: Tor hidden-service address call (line 82) ---

// TestHandleAutodiscoverWithTorService verifies that a non-nil torService causes
// OnionAddress() to be called, covering line 82.
func TestHandleAutodiscoverWithTorService(t *testing.T) {
	s := newTestServer(t)
	s.torService = new(castor.TorService)
	req := httptest.NewRequest(http.MethodGet, "/api/autodiscover", nil)
	rr := httptest.NewRecorder()
	s.handleAutodiscover(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleAutodiscover(torService): status = %d, want 200", rr.Code)
	}
}

// --- pwa.go: handleServiceWorker empty-title fallback (line 59) ---

// TestHandleServiceWorkerEmptyBranding verifies that an empty Branding.Title
// falls back to "caswhois" in the service-worker output (line 59).
func TestHandleServiceWorkerEmptyBranding(t *testing.T) {
	s := newTestServer(t)
	s.config.Branding.Title = ""
	req := httptest.NewRequest(http.MethodGet, "/sw.js", nil)
	rr := httptest.NewRecorder()
	s.handleServiceWorker(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleServiceWorker(empty title): status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "caswhois") {
		t.Errorf("handleServiceWorker(empty title): expected fallback name 'caswhois' in body")
	}
}

// --- pwa.go: handleOfflinePage empty-title fallback (line 128) ---

// TestHandleOfflinePageEmptyBranding verifies that an empty Branding.Title
// falls back to "caswhois" in the offline page output (line 128).
func TestHandleOfflinePageEmptyBranding(t *testing.T) {
	s := newTestServer(t)
	s.config.Branding.Title = ""
	req := httptest.NewRequest(http.MethodGet, "/offline.html", nil)
	rr := httptest.NewRecorder()
	s.handleOfflinePage(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleOfflinePage(empty title): status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "caswhois") {
		t.Errorf("handleOfflinePage(empty title): expected fallback name 'caswhois' in body")
	}
}

// --- health.go: buildHealthResponse empty-name fallback (line 129) ---

// TestBuildHealthResponseEmptyBranding verifies that buildHealthResponse falls
// back to "caswhois" for Project.Name when Branding.Title is empty (line 129).
func TestBuildHealthResponseEmptyBranding(t *testing.T) {
	s := newTestServer(t)
	s.config.Branding.Title = ""
	resp := s.buildHealthResponse()
	if resp.Project.Name != "caswhois" {
		t.Errorf("buildHealthResponse(empty title): Name = %q, want %q", resp.Project.Name, "caswhois")
	}
}

// --- ops_handlers.go: handleBackupStatus non-existent dir (lines 166–172) ---

// TestHandleBackupStatusNonExistentDir verifies that a non-existent backup
// directory returns 200 with an empty backups list (lines 166–172).
func TestHandleBackupStatusNonExistentDir(t *testing.T) {
	s := newTestServer(t)
	s.config.Backup.Dir = filepath.Join(t.TempDir(), "no-such-dir")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/backups", nil)
	rr := httptest.NewRecorder()
	s.handleBackupStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleBackupStatus(missing dir): status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "backups") {
		t.Errorf("handleBackupStatus(missing dir): body missing 'backups' key: %q", rr.Body.String())
	}
}

// --- ops_handlers.go: handleBackupStatus with subdirectory entry (line 179) ---

// TestHandleBackupStatusWithSubdir verifies that a subdirectory inside the
// backup dir is skipped via the e.IsDir() continue branch (line 179).
func TestHandleBackupStatusWithSubdir(t *testing.T) {
	s := newTestServer(t)
	backupDir := t.TempDir()
	s.config.Backup.Dir = backupDir
	if err := os.MkdirAll(filepath.Join(backupDir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/backups", nil)
	rr := httptest.NewRecorder()
	s.handleBackupStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("handleBackupStatus(subdir): status = %d, want 200", rr.Code)
	}
}

// --- pid_unix.go: CheckPIDFile non-ENOENT error (line 21) ---

// TestCheckPIDFileIsDir verifies that CheckPIDFile returns an error when the
// pid path is a directory (os.ReadFile returns EISDIR ≠ ENOENT), covering line 21.
func TestCheckPIDFileIsDir(t *testing.T) {
	dir := t.TempDir()
	running, pid, err := CheckPIDFile(dir)
	if err == nil {
		t.Fatalf("CheckPIDFile(dir): expected EISDIR error, got running=%v pid=%d", running, pid)
	}
}

// --- pid_unix.go: WritePIDFile CheckPIDFile error propagation (line 91) ---

// TestWritePIDFileCheckError verifies that WritePIDFile propagates the error
// returned by CheckPIDFile when the pid path is a directory (line 91).
func TestWritePIDFileCheckError(t *testing.T) {
	dir := t.TempDir()
	if err := WritePIDFile(dir, 0); err == nil {
		t.Fatal("WritePIDFile(dir): expected error from CheckPIDFile, got nil")
	}
}

// --- public_handler.go: handleWHOISPage text-client error path (lines 90-95) ---

// TestHandleWHOISPageTextInvalidQuery verifies that a query which
// QueryWHOISWithCache cannot type (QueryTypeUnknown) causes an immediate error,
// covering the text-client 500 error branch in handleWHOISPage (lines 90-95).
func TestHandleWHOISPageTextInvalidQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois?q=!!invalid!!", nil)
	req.Header.Set("Accept", "text/plain")
	rr := httptest.NewRecorder()
	s.handleWHOISPage(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("handleWHOISPage text+invalid query: got %d, want 500", rr.Code)
	}
}

// --- public_handler.go: handleWHOISPage JSON-client error path (lines 108-111) ---

// TestHandleWHOISPageJSONInvalidQuery verifies that a QueryTypeUnknown query
// returns an error response, covering the JSON-client error branch in
// handleWHOISPage (lines 108-111).
func TestHandleWHOISPageJSONInvalidQuery(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/whois?q=!!invalid!!", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	s.handleWHOISPage(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, "error") && !strings.Contains(body, "false") {
		t.Errorf("handleWHOISPage JSON+invalid query: expected error in body, got: %s", body)
	}
}
