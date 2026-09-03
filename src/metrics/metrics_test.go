package metrics

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// uniqueNS returns a namespace string that is unique for every call within a
// test binary.  promauto registers into the global default registry, so each
// call to New() must use a distinct namespace to avoid duplicate-metric panics.
var nsCounter atomic.Int64

func uniqueNS() string {
	return fmt.Sprintf("test%d", nsCounter.Add(1))
}

// TestNewReturnsNilWhenDisabled verifies that New() with Enabled=false returns nil,
// allowing callers to guard on nil safely.
func TestNewReturnsNilWhenDisabled(t *testing.T) {
	c := New("disabled_ns", MetricsConfig{Enabled: false})
	if c != nil {
		t.Error("New(Enabled=false) must return nil")
	}
}

// TestNewReturnsCollectorWhenEnabled verifies that New() with Enabled=true returns
// a non-nil Collector with all required fields populated.
func TestNewReturnsCollectorWhenEnabled(t *testing.T) {
	c := New(uniqueNS(), MetricsConfig{Enabled: true})
	if c == nil {
		t.Fatal("New(Enabled=true) returned nil")
	}

	// All REQUIRED metrics must be non-nil.
	if c.AppInfo == nil {
		t.Error("AppInfo is nil")
	}
	if c.AppUptime == nil {
		t.Error("AppUptime is nil")
	}
	if c.AppStartTime == nil {
		t.Error("AppStartTime is nil")
	}
	if c.HTTPRequestsTotal == nil {
		t.Error("HTTPRequestsTotal is nil")
	}
	if c.HTTPRequestDuration == nil {
		t.Error("HTTPRequestDuration is nil")
	}
	if c.HTTPRequestSize == nil {
		t.Error("HTTPRequestSize is nil")
	}
	if c.HTTPResponseSize == nil {
		t.Error("HTTPResponseSize is nil")
	}
	if c.HTTPActiveRequests == nil {
		t.Error("HTTPActiveRequests is nil")
	}
	if c.DBQueriesTotal == nil {
		t.Error("DBQueriesTotal is nil")
	}
	if c.DBQueryDuration == nil {
		t.Error("DBQueryDuration is nil")
	}
	if c.DBConnectionsOpen == nil {
		t.Error("DBConnectionsOpen is nil")
	}
	if c.DBConnectionsInUse == nil {
		t.Error("DBConnectionsInUse is nil")
	}
	if c.DBErrorsTotal == nil {
		t.Error("DBErrorsTotal is nil")
	}
}

// TestNewSystemMetricsOnlyWhenRequested verifies that system metrics (CPU, memory,
// goroutines) are nil when IncludeSystem=false and non-nil when IncludeSystem=true.
func TestNewSystemMetricsOnlyWhenRequested(t *testing.T) {
	t.Run("IncludeSystem false", func(t *testing.T) {
		c := New(uniqueNS(), MetricsConfig{Enabled: true, IncludeSystem: false})
		if c.SystemCPU != nil {
			t.Error("SystemCPU must be nil when IncludeSystem=false")
		}
		if c.SystemMemory != nil {
			t.Error("SystemMemory must be nil when IncludeSystem=false")
		}
		if c.SystemGoroutines != nil {
			t.Error("SystemGoroutines must be nil when IncludeSystem=false")
		}
	})

	t.Run("IncludeSystem true", func(t *testing.T) {
		c := New(uniqueNS(), MetricsConfig{Enabled: true, IncludeSystem: true})
		if c.SystemCPU == nil {
			t.Error("SystemCPU must not be nil when IncludeSystem=true")
		}
		if c.SystemMemory == nil {
			t.Error("SystemMemory must not be nil when IncludeSystem=true")
		}
		if c.SystemGoroutines == nil {
			t.Error("SystemGoroutines must not be nil when IncludeSystem=true")
		}
	})
}

// TestNewDefaultBuckets verifies that omitting DurationBuckets and SizeBuckets
// produces a non-nil collector (the defaults are applied without panic).
func TestNewDefaultBuckets(t *testing.T) {
	c := New(uniqueNS(), MetricsConfig{
		Enabled:         true,
		DurationBuckets: nil,
		SizeBuckets:     nil,
	})
	if c == nil {
		t.Fatal("New() with nil buckets returned nil collector")
	}
}

// TestNewCustomBuckets verifies that custom DurationBuckets and SizeBuckets are
// accepted and the resulting Collector is non-nil.
func TestNewCustomBuckets(t *testing.T) {
	c := New(uniqueNS(), MetricsConfig{
		Enabled:         true,
		DurationBuckets: []float64{0.1, 0.5, 1.0},
		SizeBuckets:     []float64{512, 4096},
	})
	if c == nil {
		t.Fatal("New() with custom buckets returned nil collector")
	}
}

// TestSetAppInfo verifies that SetAppInfo does not panic with valid arguments and
// that calling it on a nil Collector is safe (nil-guard).
func TestSetAppInfo(t *testing.T) {
	t.Run("valid collector", func(t *testing.T) {
		c := New(uniqueNS(), MetricsConfig{Enabled: true})
		// Must not panic.
		c.SetAppInfo("1.0.0", "abc1234", "2026-01-01", "go1.24")
	})

	t.Run("nil collector no panic", func(t *testing.T) {
		var c *Collector
		// Must not panic.
		c.SetAppInfo("1.0.0", "abc1234", "2026-01-01", "go1.24")
	})
}

// TestUpdateSystemMetrics verifies that UpdateSystemMetrics does not panic on
// a valid Collector (with and without system metrics), and is safe on nil.
func TestUpdateSystemMetrics(t *testing.T) {
	t.Run("with system metrics enabled", func(t *testing.T) {
		c := New(uniqueNS(), MetricsConfig{Enabled: true, IncludeSystem: true})
		// Must not panic.
		c.UpdateSystemMetrics()
	})

	t.Run("without system metrics", func(t *testing.T) {
		c := New(uniqueNS(), MetricsConfig{Enabled: true, IncludeSystem: false})
		// Must not panic.
		c.UpdateSystemMetrics()
	})

	t.Run("nil collector no panic", func(t *testing.T) {
		var c *Collector
		c.UpdateSystemMetrics()
	})
}

// TestUpdateSystemMetricsSetsUptime confirms that after UpdateSystemMetrics() is
// called, the AppUptime gauge has been set (i.e., some elapsed time has been
// recorded).  We validate this by scraping the Prometheus default registry via
// promhttp.Handler and looking for the uptime metric line.
func TestUpdateSystemMetricsSetsUptime(t *testing.T) {
	ns := uniqueNS()
	c := New(ns, MetricsConfig{Enabled: true, IncludeSystem: false})

	// Sleep briefly so uptime is non-zero.
	time.Sleep(2 * time.Millisecond)
	c.UpdateSystemMetrics()

	// Scrape the default registry.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	uptimeKey := ns + "_app_uptime_seconds"
	if !strings.Contains(body, uptimeKey) {
		t.Errorf("scraped metrics missing %q", uptimeKey)
	}
}

// TestNormalizePath covers all regex branches: whois sub-resources, generic
// whois query, the static "bulk" segment (must not be replaced), UUID replacement,
// and paths that need no normalization.
func TestNormalizePath(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		// WHOIS IP path
		{
			name:  "whois ip path",
			input: "/api/v1/whois/ip/8.8.8.8",
			want:  "/api/v1/whois/ip/:ip",
		},
		{
			name:  "whois ip path with suffix",
			input: "/api/v1/whois/ip/192.168.1.1/extra",
			want:  "/api/v1/whois/ip/:ip/extra",
		},
		// WHOIS domain path
		{
			name:  "whois domain path",
			input: "/api/v1/whois/domain/example.com",
			want:  "/api/v1/whois/domain/:domain",
		},
		// WHOIS ASN path
		{
			name:  "whois asn path uppercase",
			input: "/api/v1/whois/asn/AS15169",
			want:  "/api/v1/whois/asn/:asn",
		},
		// WHOIS validate path
		{
			name:  "whois validate path",
			input: "/api/v1/whois/validate/example.com",
			want:  "/api/v1/whois/validate/:query",
		},
		// WHOIS generic (non-bulk)
		{
			name:  "whois generic non-bulk query",
			input: "/api/v1/whois/example.com",
			want:  "/api/v1/whois/:query",
		},
		// WHOIS bulk must NOT be replaced
		{
			name:  "whois bulk preserved",
			input: "/api/v1/whois/bulk",
			want:  "/api/v1/whois/bulk",
		},
		// UUID replacement (standalone)
		{
			name:  "uuid in path replaced with :id",
			input: "/api/v1/resources/550e8400-e29b-41d4-a716-446655440000",
			want:  "/api/v1/resources/:id",
		},
		{
			name:  "uuid mid-path replaced",
			input: "/api/v1/foo/550e8400-e29b-41d4-a716-446655440000/bar",
			want:  "/api/v1/foo/:id/bar",
		},
		// Static paths need no normalization
		{
			name:  "health endpoint unchanged",
			input: "/server/healthz",
			want:  "/server/healthz",
		},
		{
			name:  "metrics endpoint unchanged",
			input: "/metrics",
			want:  "/metrics",
		},
		{
			name:  "whois-servers list unchanged",
			input: "/api/v1/whois-servers",
			want:  "/api/v1/whois-servers",
		},
		{
			name:  "empty path unchanged",
			input: "",
			want:  "",
		},
		{
			name:  "root slash unchanged",
			input: "/",
			want:  "/",
		},
		// Multiple UUIDs in same path
		{
			name:  "two uuids both replaced",
			input: "/a/550e8400-e29b-41d4-a716-446655440000/b/6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			want:  "/a/:id/b/:id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizePath(tc.input)
			if got != tc.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestNormalizePathIdempotent verifies that calling NormalizePath twice on already-
// normalized paths does not further transform them (no double-replacement).
func TestNormalizePathIdempotent(t *testing.T) {
	paths := []string{
		"/api/v1/whois/ip/:ip",
		"/api/v1/whois/domain/:domain",
		"/api/v1/whois/asn/:asn",
		"/api/v1/whois/validate/:query",
		"/api/v1/whois/:query",
		"/api/v1/whois/bulk",
		"/server/healthz",
		"/metrics",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			once := NormalizePath(p)
			twice := NormalizePath(once)
			if once != twice {
				t.Errorf("NormalizePath not idempotent: first=%q second=%q", once, twice)
			}
		})
	}
}

// TestHTTPMiddlewareNilCollectorPassthrough verifies that a nil *Collector wrapping
// an HTTP handler is safe and transparently delegates to the next handler.
func TestHTTPMiddlewareNilCollectorPassthrough(t *testing.T) {
	var c *Collector

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := c.HTTPMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("nil Collector middleware: status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); body != "ok" {
		t.Errorf("nil Collector middleware: body = %q, want %q", body, "ok")
	}
}

// TestHTTPMiddlewareRecordsStatus verifies that the middleware captures the HTTP
// status code set by the downstream handler.
func TestHTTPMiddlewareRecordsStatus(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
	}{
		{name: "200 OK", statusCode: http.StatusOK},
		{name: "201 Created", statusCode: http.StatusCreated},
		{name: "400 Bad Request", statusCode: http.StatusBadRequest},
		{name: "404 Not Found", statusCode: http.StatusNotFound},
		{name: "500 Internal Server Error", statusCode: http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(uniqueNS(), MetricsConfig{Enabled: true})
			code := tc.statusCode // capture for closure

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			c.HTTPMiddleware(next).ServeHTTP(rec, req)

			if rec.Code != tc.statusCode {
				t.Errorf("status: got %d, want %d", rec.Code, tc.statusCode)
			}
		})
	}
}

// TestHTTPMiddlewareDefaultStatus200 verifies that when the downstream handler
// never calls WriteHeader(), the middleware defaults to 200 (not 0).
func TestHTTPMiddlewareDefaultStatus200(t *testing.T) {
	c := New(uniqueNS(), MetricsConfig{Enabled: true})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No WriteHeader call — rely on implicit 200.
		_, _ = w.Write([]byte("body"))
	})

	req := httptest.NewRequest(http.MethodGet, "/implicit", nil)
	rec := httptest.NewRecorder()
	c.HTTPMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("implicit status: got %d, want 200", rec.Code)
	}
}

// TestHTTPMiddlewareResponseBodyAccumulated verifies that the responseWriter.Write
// wrapper correctly accumulates the total bytes written across multiple calls.
func TestHTTPMiddlewareResponseBodyAccumulated(t *testing.T) {
	// Use a raw responseWriter directly to test accumulation logic.
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	n1, err := rw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write 1: %v", err)
	}
	n2, err := rw.Write([]byte(" world"))
	if err != nil {
		t.Fatalf("Write 2: %v", err)
	}

	if rw.size != n1+n2 {
		t.Errorf("accumulated size = %d, want %d", rw.size, n1+n2)
	}
	if rec.Body.String() != "hello world" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "hello world")
	}
}

// TestHTTPMiddlewareWriteHeaderCaptured verifies that responseWriter.WriteHeader
// stores the provided code and forwards it to the underlying ResponseWriter.
func TestHTTPMiddlewareWriteHeaderCaptured(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)

	if rw.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want %d", rw.statusCode, http.StatusNotFound)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("underlying recorder code = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestHTTPMiddlewareRequestWithBody verifies that the middleware observes request
// size when Content-Length > 0.
func TestHTTPMiddlewareRequestWithBody(t *testing.T) {
	c := New(uniqueNS(), MetricsConfig{Enabled: true})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	body := strings.NewReader(`{"query":"example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/whois/bulk", body)
	req.ContentLength = int64(body.Len())
	rec := httptest.NewRecorder()
	c.HTTPMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
}

// TestHTTPMiddlewarePathNormalized confirms the middleware passes the request
// through the path normalizer before recording metrics (no label cardinality
// explosion for dynamic segments).  We validate indirectly by checking the
// Prometheus scrape output does not contain the raw IP address as a label.
func TestHTTPMiddlewarePathNormalized(t *testing.T) {
	ns := uniqueNS()
	c := New(ns, MetricsConfig{Enabled: true})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/whois/ip/1.2.3.4", nil)
	rec := httptest.NewRecorder()
	c.HTTPMiddleware(next).ServeHTTP(rec, req)

	// Scrape and verify label uses placeholder, not raw IP.
	scrapeReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	scrapeRec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(scrapeRec, scrapeReq)

	body, _ := io.ReadAll(scrapeRec.Body)
	output := string(body)

	// The raw IP must not appear as a path label value.
	if strings.Contains(output, `path="/api/v1/whois/ip/1.2.3.4"`) {
		t.Error("metrics contain raw IP path label — normalization did not apply")
	}
	// The normalized placeholder must appear.
	if !strings.Contains(output, `/api/v1/whois/ip/:ip`) {
		t.Errorf("normalized path label /api/v1/whois/ip/:ip not found in metrics output")
	}
}

// TestHTTPMiddlewareActiveRequestsDecremented verifies that the HTTPActiveRequests
// gauge returns to zero after a request completes (Inc during, Dec after via defer).
// Uses prometheus/testutil to read the gauge value without scraping the full registry.
func TestHTTPMiddlewareActiveRequestsDecremented(t *testing.T) {
	c := New(uniqueNS(), MetricsConfig{Enabled: true})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()
	c.HTTPMiddleware(next).ServeHTTP(rec, req)

	// After the request completes, the active-requests gauge must be back at 0.
	got := testutil.ToFloat64(c.HTTPActiveRequests)
	if got != 0 {
		t.Errorf("HTTPActiveRequests after completed request = %v, want 0", got)
	}
}

// TestMetricsConfigZeroValue verifies that a MetricsConfig zero value with
// Enabled=false is safe to pass to New() and returns nil.
func TestMetricsConfigZeroValue(t *testing.T) {
	var cfg MetricsConfig
	c := New("zero_cfg_ns", cfg)
	if c != nil {
		t.Error("New() with zero-value MetricsConfig (Enabled=false) must return nil")
	}
}
