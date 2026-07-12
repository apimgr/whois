package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewBootstrap(t *testing.T) {
	dataDir := t.TempDir()
	b := NewBootstrap(dataDir)

	if b == nil {
		t.Fatal("NewBootstrap returned nil")
	}
	if b.dataDir != dataDir {
		t.Errorf("dataDir = %s, want %s", b.dataDir, dataDir)
	}
	if b.dnsServices == nil {
		t.Error("dnsServices is nil")
	}
}

// TestBootstrap_GetIPv4Endpoints verifies that GetIPv4Endpoints returns nil for unloaded data.
func TestBootstrap_GetIPv4Endpoints(t *testing.T) {
	dataDir := t.TempDir()
	b := NewBootstrap(dataDir)

	// Without data loaded, should return nil
	endpoints := b.GetIPv4Endpoints("8.8.8.8")
	if endpoints != nil {
		t.Error("GetIPv4Endpoints() with no data should return nil")
	}
}

// TestBootstrap_GetIPv6Endpoints verifies that GetIPv6Endpoints returns nil for unloaded data.
func TestBootstrap_GetIPv6Endpoints(t *testing.T) {
	dataDir := t.TempDir()
	b := NewBootstrap(dataDir)

	// Without data loaded, should return nil
	endpoints := b.GetIPv6Endpoints("2001:4860:4860::8888")
	if endpoints != nil {
		t.Error("GetIPv6Endpoints() with no data should return nil")
	}
}

// TestBootstrap_GetASNEndpoints verifies that GetASNEndpoints returns nil for unloaded data.
func TestBootstrap_GetASNEndpoints(t *testing.T) {
	dataDir := t.TempDir()
	b := NewBootstrap(dataDir)

	// Without data loaded, should return nil
	endpoints := b.GetASNEndpoints(15169)
	if endpoints != nil {
		t.Error("GetASNEndpoints() with no data should return nil")
	}
}

// TestBootstrap_GetDomainEndpoints verifies that GetDomainEndpoints returns nil for unloaded data.
func TestBootstrap_GetDomainEndpoints(t *testing.T) {
	dataDir := t.TempDir()
	b := NewBootstrap(dataDir)

	// Without data loaded, should return nil
	endpoints := b.GetDomainEndpoints("example.com")
	if endpoints != nil {
		t.Error("GetDomainEndpoints() with no data should return nil")
	}
}

func TestBootstrap_HasData(t *testing.T) {
	dataDir := t.TempDir()
	b := NewBootstrap(dataDir)

	// Before loading, should have no data
	if b.HasData() {
		t.Error("HasData() = true before loading")
	}
}

func TestBootstrap_Load_Empty(t *testing.T) {
	dataDir := t.TempDir()
	b := NewBootstrap(dataDir)

	// Load from empty directory should succeed (no files)
	if err := b.Load(); err != nil {
		t.Errorf("Load() error = %v", err)
	}
}

func TestBootstrap_Load_DNS(t *testing.T) {
	dataDir := t.TempDir()
	rdapDir := filepath.Join(dataDir, "rdap")
	if err := os.MkdirAll(rdapDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Write a minimal DNS bootstrap file
	dnsJSON := `{
		"version": "1.0",
		"publication": "2025-01-01T00:00:00Z",
		"services": [
			[["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
			[["org"], ["https://rdap.publicinterestregistry.org/rdap/"]]
		]
	}`
	if err := os.WriteFile(filepath.Join(rdapDir, "dns.json"), []byte(dnsJSON), 0644); err != nil {
		t.Fatal(err)
	}

	b := NewBootstrap(dataDir)
	if err := b.Load(); err != nil {
		t.Errorf("Load() error = %v", err)
	}

	// Verify data was loaded
	if !b.HasData() {
		t.Error("HasData() = false after loading DNS")
	}

	// Test endpoint lookup
	endpoints := b.GetDomainEndpoints("example.com")
	if len(endpoints) == 0 {
		t.Error("GetDomainEndpoints(example.com) returned empty")
	} else if endpoints[0] != "https://rdap.verisign.com/com/v1/" {
		t.Errorf("GetDomainEndpoints(example.com) = %v", endpoints)
	}

	endpoints = b.GetDomainEndpoints("example.org")
	if len(endpoints) == 0 {
		t.Error("GetDomainEndpoints(example.org) returned empty")
	}

	// Non-existent TLD
	endpoints = b.GetDomainEndpoints("example.xyz")
	if len(endpoints) != 0 {
		t.Errorf("GetDomainEndpoints(example.xyz) = %v, want empty", endpoints)
	}
}

func TestBootstrap_Load_IPv4(t *testing.T) {
	dataDir := t.TempDir()
	rdapDir := filepath.Join(dataDir, "rdap")
	if err := os.MkdirAll(rdapDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Write a minimal IPv4 bootstrap file
	ipv4JSON := `{
		"version": "1.0",
		"publication": "2025-01-01T00:00:00Z",
		"services": [
			[["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]]
		]
	}`
	if err := os.WriteFile(filepath.Join(rdapDir, "ipv4.json"), []byte(ipv4JSON), 0644); err != nil {
		t.Fatal(err)
	}

	b := NewBootstrap(dataDir)
	if err := b.Load(); err != nil {
		t.Errorf("Load() error = %v", err)
	}

	// Test endpoint lookup
	endpoints := b.GetIPv4Endpoints("8.8.8.8")
	if len(endpoints) == 0 {
		t.Error("GetIPv4Endpoints(8.8.8.8) returned empty")
	}

	// Non-matching IP
	endpoints = b.GetIPv4Endpoints("1.1.1.1")
	if len(endpoints) != 0 {
		t.Errorf("GetIPv4Endpoints(1.1.1.1) = %v, want empty", endpoints)
	}
}

func TestBootstrap_Load_ASN(t *testing.T) {
	dataDir := t.TempDir()
	rdapDir := filepath.Join(dataDir, "rdap")
	if err := os.MkdirAll(rdapDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Write a minimal ASN bootstrap file
	asnJSON := `{
		"version": "1.0",
		"publication": "2025-01-01T00:00:00Z",
		"services": [
			[["1-1000"], ["https://rdap.arin.net/registry/"]],
			[["15169"], ["https://rdap.arin.net/registry/"]]
		]
	}`
	if err := os.WriteFile(filepath.Join(rdapDir, "asn.json"), []byte(asnJSON), 0644); err != nil {
		t.Fatal(err)
	}

	b := NewBootstrap(dataDir)
	if err := b.Load(); err != nil {
		t.Errorf("Load() error = %v", err)
	}

	// Test endpoint lookup
	endpoints := b.GetASNEndpoints(100)
	if len(endpoints) == 0 {
		t.Error("GetASNEndpoints(100) returned empty")
	}

	// Google's ASN
	endpoints = b.GetASNEndpoints(15169)
	if len(endpoints) == 0 {
		t.Error("GetASNEndpoints(15169) returned empty")
	}

	// Non-matching ASN
	endpoints = b.GetASNEndpoints(999999)
	if len(endpoints) != 0 {
		t.Errorf("GetASNEndpoints(999999) = %v, want empty", endpoints)
	}
}

// TestBootstrap_Load_IPv6 verifies that IPv6 bootstrap data is loaded and
// endpoint lookup works for an IPv6 address within the loaded range.
func TestBootstrap_Load_IPv6(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	rdapDir := filepath.Join(dataDir, "rdap")
	if err := os.MkdirAll(rdapDir, 0755); err != nil {
		t.Fatal(err)
	}

	ipv6JSON := `{
		"version": "1.0",
		"publication": "2025-01-01T00:00:00Z",
		"services": [
			[["2001:4860::/32"], ["https://rdap.arin.net/registry/"]]
		]
	}`
	if err := os.WriteFile(filepath.Join(rdapDir, "ipv6.json"), []byte(ipv6JSON), 0644); err != nil {
		t.Fatal(err)
	}

	b := NewBootstrap(dataDir)
	if err := b.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	endpoints := b.GetIPv6Endpoints("2001:4860::1")
	if len(endpoints) == 0 {
		t.Error("GetIPv6Endpoints(2001:4860::1) returned empty, want ARIN endpoint")
	}

	// Non-matching IPv6 should return nothing
	endpoints = b.GetIPv6Endpoints("2002::1")
	if len(endpoints) != 0 {
		t.Errorf("GetIPv6Endpoints(2002::1) = %v, want empty", endpoints)
	}
}

// TestBootstrap_DownloadFile verifies downloadFile writes the response body to
// disk atomically and leaves no leftover .tmp file.
func TestBootstrap_DownloadFile(t *testing.T) {
	t.Parallel()

	want := `{"version":"1.0","publication":"2025-01-01T00:00:00Z","services":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(want))
	}))
	defer srv.Close()

	dataDir := t.TempDir()
	dest := filepath.Join(dataDir, "dns.json")

	b := NewBootstrap(dataDir)
	ctx := context.Background()
	if err := b.downloadFile(ctx, &http.Client{}, srv.URL, dest); err != nil {
		t.Fatalf("downloadFile() error = %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != want {
		t.Errorf("file content = %q, want %q", string(got), want)
	}

	// Temp file must be gone
	if _, err := os.Stat(dest + ".tmp"); !os.IsNotExist(err) {
		t.Error("downloadFile() left behind .tmp file")
	}
}

// TestBootstrap_DownloadFile_HTTPError verifies downloadFile returns an error
// when the server responds with a non-200 status code.
func TestBootstrap_DownloadFile_HTTPError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dataDir := t.TempDir()
	dest := filepath.Join(dataDir, "dns.json")

	b := NewBootstrap(dataDir)
	ctx := context.Background()
	err := b.downloadFile(ctx, &http.Client{}, srv.URL, dest)
	if err == nil {
		t.Error("downloadFile() with 404 response should return error")
	}
}

func TestBootstrap_Update_NoNetwork(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping network test in CI")
	}

	dataDir := t.TempDir()
	b := NewBootstrap(dataDir)

	// This may fail without network, but should not panic
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// We don't check the error since network may not be available
	_ = b.Update(ctx)
}
