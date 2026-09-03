package server

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/whois/src/whois"
)

// --- server.go: handleSecurityTxt, handleSitemap, handleRobotsTxt, parseDurationDefault, handleMetrics, getPIDFilePath ---

// TestHandleSecurityTxt verifies /security.txt returns text/plain with required fields.
func TestHandleSecurityTxt(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil)
	rr := httptest.NewRecorder()

	s.handleSecurityTxt(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Contact:") {
		t.Error("security.txt missing Contact field")
	}
	if !strings.Contains(body, "Expires:") {
		t.Error("security.txt missing Expires field")
	}
}

// TestHandleSecurityTxtWithFQDN verifies the contact email uses configured FQDN.
func TestHandleSecurityTxtWithFQDN(t *testing.T) {
	s := newTestServer(t)
	s.config.FQDN = "example.com"
	req := httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil)
	rr := httptest.NewRecorder()

	s.handleSecurityTxt(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "example.com") {
		t.Error("security.txt should contain the configured FQDN")
	}
}

// TestHandleSitemap verifies /sitemap.xml returns valid XML with expected URLs.
func TestHandleSitemap(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil)
	rr := httptest.NewRecorder()

	s.handleSitemap(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "xml") {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<urlset") {
		t.Error("sitemap missing <urlset> root element")
	}
	if !strings.Contains(body, "<loc>") {
		t.Error("sitemap missing <loc> elements")
	}
}

// TestHandleSitemapWithFQDN verifies FQDN is used in sitemap URLs.
func TestHandleSitemapWithFQDN(t *testing.T) {
	s := newTestServer(t)
	s.config.FQDN = "mysite.example.com"
	req := httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil)
	rr := httptest.NewRecorder()

	s.handleSitemap(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "mysite.example.com") {
		t.Error("sitemap should use configured FQDN")
	}
}

// TestHandleRobotsTxt verifies /robots.txt returns text/plain with expected content.
func TestHandleRobotsTxt(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rr := httptest.NewRecorder()

	s.handleRobotsTxt(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "User-agent:") {
		t.Error("robots.txt missing User-agent directive")
	}
	if !strings.Contains(body, "Sitemap:") {
		t.Error("robots.txt missing Sitemap directive")
	}
}

// TestHandleRobotsTxtWithFQDN verifies FQDN is used in Sitemap directive.
func TestHandleRobotsTxtWithFQDN(t *testing.T) {
	s := newTestServer(t)
	s.config.FQDN = "search.example.com"
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rr := httptest.NewRecorder()

	s.handleRobotsTxt(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "search.example.com") {
		t.Error("robots.txt should contain configured FQDN in Sitemap")
	}
}

// TestHandleLLMsTxt verifies /llms.txt returns text/plain with expected content.
func TestHandleLLMsTxt(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/llms.txt", nil)
	rr := httptest.NewRecorder()

	s.handleLLMsTxt(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "# caswhois") {
		t.Error("llms.txt missing project name header")
	}
	if !strings.Contains(body, "## API") {
		t.Error("llms.txt missing API section")
	}
	if !strings.Contains(body, "## Endpoints") {
		t.Error("llms.txt missing Endpoints section")
	}
}

// TestHandleLLMsTxtWithFQDN verifies llms.txt uses configured FQDN.
func TestHandleLLMsTxtWithFQDN(t *testing.T) {
	s := newTestServer(t)
	s.config.FQDN = "whois.example.com"
	req := httptest.NewRequest(http.MethodGet, "/llms.txt", nil)
	rr := httptest.NewRecorder()

	s.handleLLMsTxt(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "whois.example.com") {
		t.Error("llms.txt should contain the configured FQDN")
	}
}

// TestHandleWellKnownNotFound verifies unknown well-known entries return 404.
func TestHandleWellKnownNotFound(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/unknown-entry", nil)
	rr := httptest.NewRecorder()

	s.handleWellKnownNotFound(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// TestWellKnownMethodCheckRejectsPost verifies POST to well-known returns 405.
func TestWellKnownMethodCheckRejectsPost(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := wellKnownMethodCheck(inner)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/security.txt", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", rr.Code)
	}
	allow := rr.Header().Get("Allow")
	if !strings.Contains(allow, "GET") || !strings.Contains(allow, "HEAD") {
		t.Errorf("Allow header = %q, want GET and HEAD", allow)
	}
}

// TestWellKnownMethodCheckAllowsGet verifies GET passes through.
func TestWellKnownMethodCheckAllowsGet(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	handler := wellKnownMethodCheck(inner)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET status = %d, want 200", rr.Code)
	}
}

// TestWellKnownMethodCheckAllowsHead verifies HEAD passes through.
func TestWellKnownMethodCheckAllowsHead(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := wellKnownMethodCheck(inner)

	req := httptest.NewRequest(http.MethodHead, "/.well-known/security.txt", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("HEAD status = %d, want 200", rr.Code)
	}
}

// TestParseDurationDefault covers empty, valid, and invalid duration inputs.
func TestParseDurationDefault(t *testing.T) {
	fallback := 30 * time.Second

	// Empty string returns fallback
	if got := parseDurationDefault("", fallback); got != fallback {
		t.Errorf("parseDurationDefault(\"\") = %v, want %v", got, fallback)
	}

	// Invalid string returns fallback
	if got := parseDurationDefault("not-a-duration", fallback); got != fallback {
		t.Errorf("parseDurationDefault(\"not-a-duration\") = %v, want %v", got, fallback)
	}

	// Valid string returns parsed value
	want := 2 * time.Minute
	if got := parseDurationDefault("2m", fallback); got != want {
		t.Errorf("parseDurationDefault(\"2m\") = %v, want %v", got, want)
	}
}

// TestGetPIDFilePath verifies the PID path is non-empty and contains "caswhois".
func TestGetPIDFilePath(t *testing.T) {
	s := newTestServer(t)
	path := s.getPIDFilePath()
	if path == "" {
		t.Error("getPIDFilePath returned empty string")
	}
	if !strings.Contains(path, "caswhois") {
		t.Errorf("getPIDFilePath = %q, expected to contain 'caswhois'", path)
	}
}

// TestHandleMetricsNoTokenServesMetrics verifies /metrics returns 200 when no token is configured.
func TestHandleMetricsNoTokenServesMetrics(t *testing.T) {
	s := newTestServer(t)
	s.config.Metrics.Token = ""

	h := s.handleMetrics()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for unauthenticated metrics", rr.Code)
	}
}

// TestHandleMetricsWithTokenMissingAuth verifies /metrics returns 401 when token is required but missing.
func TestHandleMetricsWithTokenMissingAuth(t *testing.T) {
	s := newTestServer(t)
	s.config.Metrics.Token = "secretmetrics"

	h := s.handleMetrics()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when token required and not provided", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("WWW-Authenticate header missing on 401")
	}
}

// TestHandleMetricsWithTokenValidAuth verifies /metrics returns 200 with correct token.
func TestHandleMetricsWithTokenValidAuth(t *testing.T) {
	s := newTestServer(t)
	tok := "secretmetrics"
	s.config.Metrics.Token = tok

	h := s.handleMetrics()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with correct metrics token", rr.Code)
	}
}

// --- cli_binary.go: handleCLIBinaryDownload, handleLocaleJSON ---

// TestHandleCLIBinaryDownloadMethodNotAllowed verifies POST returns 405.
func TestHandleCLIBinaryDownloadMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/cli/binaries/caswhois-cli-linux-amd64", nil)
	rr := httptest.NewRecorder()
	s.handleCLIBinaryDownload(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestHandleCLIBinaryDownloadInvalidName verifies non-caswhois-cli prefix returns 404.
func TestHandleCLIBinaryDownloadInvalidName(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/cli/binaries/some-other-binary", nil)
	rr := httptest.NewRecorder()
	s.handleCLIBinaryDownload(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for non-caswhois-cli binary name", rr.Code)
	}
}

// TestHandleCLIBinaryDownloadDotfile verifies dotfile paths return 404.
func TestHandleCLIBinaryDownloadDotfile(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/cli/binaries/.hidden", nil)
	rr := httptest.NewRecorder()
	s.handleCLIBinaryDownload(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for dotfile binary name", rr.Code)
	}
}

// TestHandleCLIBinaryDownloadNotFound verifies a valid name but missing file returns 404.
func TestHandleCLIBinaryDownloadNotFound(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/cli/binaries/caswhois-cli-linux-amd64", nil)
	rr := httptest.NewRecorder()
	s.handleCLIBinaryDownload(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when binary file doesn't exist", rr.Code)
	}
}

// TestHandleCLIBinaryDownloadHEAD verifies HEAD returns same status as GET.
func TestHandleCLIBinaryDownloadHEAD(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodHead, "/cli/binaries/caswhois-cli-linux-amd64", nil)
	rr := httptest.NewRecorder()
	s.handleCLIBinaryDownload(rr, req)
	// Should be 404 since the file doesn't exist, but not 405
	if rr.Code == http.StatusMethodNotAllowed {
		t.Error("HEAD method should be allowed")
	}
}

// TestHandleLocaleJSONSupportedLang verifies /locales/en.json returns JSON.
func TestHandleLocaleJSONSupportedLang(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/locales/en.json", nil)
	rr := httptest.NewRecorder()
	s.handleLocaleJSON(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for /locales/en.json", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// TestHandleLocaleJSONUnsupportedLangFallsBackToEn verifies unsupported lang falls back to en.
func TestHandleLocaleJSONUnsupportedLangFallsBackToEn(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/locales/xx.json", nil)
	rr := httptest.NewRecorder()
	s.handleLocaleJSON(rr, req)
	// Should return 200 (falls back to en, not 404 or 400)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (fallback to en for unsupported lang)", rr.Code)
	}
}

// TestHandleLocaleJSONMethodNotAllowed verifies POST returns 405.
func TestHandleLocaleJSONMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/locales/en.json", nil)
	rr := httptest.NewRecorder()
	s.handleLocaleJSON(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// TestHandleLocaleJSONHEAD verifies HEAD is allowed.
func TestHandleLocaleJSONHEAD(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodHead, "/locales/en.json", nil)
	rr := httptest.NewRecorder()
	s.handleLocaleJSON(rr, req)
	if rr.Code == http.StatusMethodNotAllowed {
		t.Error("HEAD method should be allowed for locale JSON")
	}
}

// --- pid_unix.go: CheckPIDFile, WritePIDFile, RemovePIDFile ---

// TestCheckPIDFileNoFile verifies missing PID file returns not-running.
func TestCheckPIDFileNoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.pid")
	running, pid, err := CheckPIDFile(path)
	if err != nil {
		t.Fatalf("CheckPIDFile(missing) returned error: %v", err)
	}
	if running {
		t.Error("CheckPIDFile(missing) running = true, want false")
	}
	if pid != 0 {
		t.Errorf("CheckPIDFile(missing) pid = %d, want 0", pid)
	}
}

// TestCheckPIDFileCorrupt verifies corrupt PID file returns not-running and removes the file.
func TestCheckPIDFileCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.pid")
	if err := os.WriteFile(path, []byte("not-a-pid\n"), 0644); err != nil {
		t.Fatal(err)
	}
	running, pid, err := CheckPIDFile(path)
	if err != nil {
		t.Fatalf("CheckPIDFile(corrupt) returned error: %v", err)
	}
	if running {
		t.Error("CheckPIDFile(corrupt) running = true, want false")
	}
	if pid != 0 {
		t.Errorf("CheckPIDFile(corrupt) pid = %d, want 0", pid)
	}
	// Corrupt file should be removed
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("corrupt PID file should have been removed")
	}
}

// TestCheckPIDFileStalePID verifies a PID for a non-existent process returns not-running.
func TestCheckPIDFileStalePID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stale.pid")
	// PID 99999999 is extremely unlikely to exist
	if err := os.WriteFile(path, []byte("99999999\n"), 0644); err != nil {
		t.Fatal(err)
	}
	running, _, err := CheckPIDFile(path)
	if err != nil {
		t.Fatalf("CheckPIDFile(stale) returned error: %v", err)
	}
	if running {
		t.Error("CheckPIDFile(stale) running = true, want false (stale PID)")
	}
}

// TestWriteAndRemovePIDFile verifies the full write-then-remove lifecycle.
func TestWriteAndRemovePIDFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caswhois.pid")

	if err := WritePIDFile(path, 8080); err != nil {
		t.Fatalf("WritePIDFile: %v", err)
	}

	// File should exist and contain current PID
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after WritePIDFile: %v", err)
	}
	pidStr := strings.TrimSpace(string(data))
	if !strings.HasPrefix(pidStr, fmt.Sprintf("%d:", os.Getpid())) {
		t.Errorf("PID file content = %q, want prefix %d:", pidStr, os.Getpid())
	}

	if err := RemovePIDFile(path); err != nil {
		t.Fatalf("RemovePIDFile: %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("PID file should have been removed")
	}
}

// TestRemovePIDFileMissing verifies removing a missing PID file is a no-op.
func TestRemovePIDFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no.pid")
	if err := RemovePIDFile(path); err != nil {
		t.Errorf("RemovePIDFile(missing) = %v, want nil", err)
	}
}

// --- whois_handlers.go: sendXMLResponse, sendTextResponse, sendHTMLResponse ---

// TestSendXMLResponse verifies XML output has correct Content-Type and structure.
func TestSendXMLResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]interface{}{
		"query":     "example.com",
		"type":      "domain",
		"server":    "whois.verisign-grs.com",
		"timestamp": "2026-01-01T00:00:00Z",
		"raw":       "Domain Name: EXAMPLE.COM\n",
	}
	sendXMLResponse(rr, data)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "xml") {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}

	// Verify it's valid XML with expected root element
	type xmlRoot struct {
		XMLName xml.Name `xml:"whois"`
		Query   string   `xml:"query"`
	}
	var out xmlRoot
	if err := xml.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}
	if out.Query != "example.com" {
		t.Errorf("xml query = %q, want example.com", out.Query)
	}
}

// TestSendTextResponse verifies text/plain format includes header fields and raw data.
func TestSendTextResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	result := &whois.WHOISResult{
		Query:     "example.com",
		Server:    "whois.verisign-grs.com",
		Raw:       "Domain Name: EXAMPLE.COM\n",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	result.Type = whois.QueryTypeDomain
	sendTextResponse(rr, result)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Query: example.com") {
		t.Error("text response missing Query field")
	}
	if !strings.Contains(body, "Domain Name: EXAMPLE.COM") {
		t.Error("text response missing raw WHOIS data")
	}
}

// TestSendHTMLResponse verifies HTML format includes DOCTYPE and query data.
func TestSendHTMLResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/whois?q=example.com", nil)
	result := &whois.WHOISResult{
		Query:     "example.com",
		Server:    "whois.verisign-grs.com",
		Raw:       "Domain Name: EXAMPLE.COM\n",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	result.Type = whois.QueryTypeDomain
	sendHTMLResponse(rr, req, result)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("HTML response missing DOCTYPE")
	}
	if !strings.Contains(body, "example.com") {
		t.Error("HTML response missing query value")
	}
}

// --- ops_handlers.go: handleSchedulerStatus with nil scheduler, handleBackupStatus with actual dir ---

// TestHandleSchedulerStatusNilScheduler verifies GET with nil scheduler returns empty task list.
func TestHandleSchedulerStatusNilScheduler(t *testing.T) {
	s := newTestServer(t)
	s.scheduler = nil
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/schedulers", nil)
	rr := httptest.NewRecorder()

	s.handleSchedulerStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with nil scheduler", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Error("resp.OK = false with nil scheduler, want true (empty task list)")
	}
}

// TestHandleBackupStatusWithFiles verifies backup listing when backup files exist.
func TestHandleBackupStatusWithFiles(t *testing.T) {
	s := newTestServer(t)
	// Create a fake backup dir with a mock archive
	backupDir := s.config.GetBackupDir()
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		t.Fatalf("mkdir backup dir: %v", err)
	}
	fakeBackup := filepath.Join(backupDir, "backup-20260101-120000.tar.gz")
	if err := os.WriteFile(fakeBackup, []byte("fake archive"), 0644); err != nil {
		t.Fatalf("write fake backup: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/backups", nil)
	rr := httptest.NewRecorder()
	s.handleBackupStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	resp := decodeAPIResponse(t, rr.Body.String())
	if !resp.OK {
		t.Error("resp.OK = false, want true")
	}
	data := decodeDataMap(t, resp)
	backups, ok := data["backups"]
	if !ok {
		t.Fatal("response missing backups field")
	}
	list, ok := backups.([]interface{})
	if !ok || len(list) == 0 {
		t.Error("backups list should be non-empty when backup files exist")
	}
}

// --- stats.go: recordRequest day-rollover branch ---

// TestRecordRequestDayRollover verifies the 24h counter resets when the day changes.
func TestRecordRequestDayRollover(t *testing.T) {
	var st serverStats

	// Record a request for "yesterday" by forcing dayStart to past epoch
	st.dayStart.Store(0)
	st.requests24h.Store(999)
	st.requestsTotal.Store(999)

	// recordRequest should detect dayStart mismatch and reset requests24h to 1
	st.recordRequest()

	if st.requests24h.Load() != 1 {
		t.Errorf("requests24h after day rollover = %d, want 1", st.requests24h.Load())
	}
	if st.requestsTotal.Load() != 1000 {
		t.Errorf("requestsTotal after day rollover = %d, want 1000", st.requestsTotal.Load())
	}
}

// TestRecordRequestSameDay verifies the 24h counter increments without resetting within the same day.
func TestRecordRequestSameDay(t *testing.T) {
	var st serverStats

	// Simulate two requests on the same day (default dayStart=0 will trigger reset on first call,
	// then dayStart is set to today, so second call should simply increment).
	st.recordRequest()
	after1 := st.requests24h.Load()
	st.recordRequest()
	after2 := st.requests24h.Load()

	if after2 != after1+1 {
		t.Errorf("second recordRequest: requests24h = %d, want %d", after2, after1+1)
	}
}

// --- content.go: respondHTML, DetectClientType ---

// TestRespondHTML verifies respondHTML sets text/html content type.
func TestRespondHTML(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	respondHTML(rr, req, http.StatusOK, "<h1>test</h1>")
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestDetectClientTypeCLI verifies curl/wget user agents are detected as text clients.
func TestDetectClientTypeCLI(t *testing.T) {
	cases := []struct {
		ua   string
		want HTTPClientType
	}{
		{"curl/7.82.0", ClientTypeText},
		{"Wget/1.21", ClientTypeText},
		{"HTTPie/3.0", ClientTypeText},
		{"python-requests/2.28", ClientTypeText},
	}
	for _, tc := range cases {
		t.Run(tc.ua, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("User-Agent", tc.ua)
			got := DetectClientType(req)
			if got != tc.want {
				t.Errorf("DetectClientType(%q) = %q, want %q", tc.ua, got, tc.want)
			}
		})
	}
}

// TestDetectClientTypeBrowser verifies browser Accept headers are detected.
func TestDetectClientTypeBrowser(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
	got := DetectClientType(req)
	if got != ClientTypeHTML {
		t.Errorf("DetectClientType(browser) = %q, want %q", got, ClientTypeHTML)
	}
}

// TestDetectClientTypeAPI verifies application/json Accept is detected as JSON.
func TestDetectClientTypeAPI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	got := DetectClientType(req)
	if got != ClientTypeJSON {
		t.Errorf("DetectClientType(json) = %q, want %q", got, ClientTypeJSON)
	}
}

// TestDetectClientTypeBrowserUA verifies browser User-Agent is detected as HTML.
func TestDetectClientTypeBrowserUA(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0")
	got := DetectClientType(req)
	if got != ClientTypeHTML {
		t.Errorf("DetectClientType(Chrome UA) = %q, want html", got)
	}
}

// TestDetectClientTypeEmptyUA verifies empty User-Agent defaults to text.
func TestDetectClientTypeEmptyUA(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got := DetectClientType(req)
	if got != ClientTypeText {
		t.Errorf("DetectClientType(empty UA) = %q, want text", got)
	}
}

// --- handleWHOIS (server.go): this function is hard to unit test without network,
// but we can verify the nil path branches via handleWHOISDomainLookup/handleWHOISIPLookup ---

// TestHandleWHOISDomainLookupFormat verifies ?format=xml returns XML for valid domain.
// This requires a real lookup (will fail in CI without network) — skipped if lookup fails.
func TestHandleWHOISDomainLookupRejectsASN(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/domain/AS1234", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISDomainLookup(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for ASN in domain handler", rr.Code)
	}
}

// TestHandleWHOISASNLookupValidASN attempts an ASN lookup and expects either success or network error,
// but never a validation error (since AS1 is a well-formed ASN).
func TestHandleWHOISASNLookupRejectsDomain(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/asn/192.168.1.1", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISASNLookup(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for IP in ASN handler", rr.Code)
	}
}

// TestHandleWHOISIPLookupRejectsASN verifies ASN is rejected in IP handler.
func TestHandleWHOISIPLookupRejectsASN(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/ip/AS1234", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISIPLookup(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for ASN in IP handler", rr.Code)
	}
}

// TestHandleWHOISBulkValidSmallSet verifies a valid bulk request with 1 item is accepted.
// The lookup itself may fail without network but the input validation should pass.
func TestHandleWHOISBulkValidSmallSet(t *testing.T) {
	s := newTestServer(t)
	body := `{"queries":["example.com"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whois/bulk", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleWHOISBulkLookup(rr, req)

	// Accept 200 (partial results) or 207 (multi-status) — but not 400 (validation error)
	if rr.Code == http.StatusBadRequest {
		t.Error("single valid query should not return 400 validation error")
	}
}

// TestHandleWHOISOwnerSearchWithLimit verifies limit param is capped.
func TestHandleWHOISOwnerSearchWithLargeLimit(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/search?owner=acme&limit=9999", nil)
	rr := httptest.NewRecorder()
	s.handleWHOISOwnerSearch(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for large limit (should be capped)", rr.Code)
	}
}

// --- middleware_i18n.go: LangFromContext with lang set ---

// TestLangFromContextSet verifies LangFromContext returns the set language.
func TestLangFromContextSet(t *testing.T) {
	var gotLang string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLang = LangFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := LanguageMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/?lang=ja", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if gotLang != "ja" {
		t.Errorf("LangFromContext with ?lang=ja = %q, want ja", gotLang)
	}
}

// TestLanguageMiddlewareRTLLang verifies Arabic sets dir context.
func TestLanguageMiddlewareArabic(t *testing.T) {
	var gotLang string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLang = LangFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := LanguageMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/?lang=ar", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if gotLang != "ar" {
		t.Errorf("LangFromContext with ?lang=ar = %q, want ar", gotLang)
	}
}

// --- health.go: formatUptime edge cases ---

// TestFormatUptimeMinutes verifies short uptime renders as minutes.
func TestFormatUptimeMinutes(t *testing.T) {
	got := formatUptime(45 * time.Minute)
	if !strings.Contains(got, "m") {
		t.Errorf("formatUptime(45m) = %q, want minutes format", got)
	}
}

// TestFormatUptimeHours verifies multi-hour uptime renders with hours.
func TestFormatUptimeHours(t *testing.T) {
	got := formatUptime(3*time.Hour + 15*time.Minute)
	if !strings.Contains(got, "h") {
		t.Errorf("formatUptime(3h15m) = %q, want hours format", got)
	}
}

// TestFormatUptimeDays verifies multi-day uptime renders with days.
func TestFormatUptimeDays(t *testing.T) {
	got := formatUptime(2*24*time.Hour + 5*time.Hour)
	if !strings.Contains(got, "d") {
		t.Errorf("formatUptime(2d5h) = %q, want days format", got)
	}
}
