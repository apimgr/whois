package whois

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apimgr/whois/src/cache"
)

func TestNewLookupService(t *testing.T) {
	dataDir := t.TempDir()
	svc := NewLookupService(dataDir, nil)

	if svc == nil {
		t.Fatal("NewLookupService returned nil")
	}

	// Should not have RDAP data yet (no bootstrap files)
	if svc.HasRDAPData() {
		t.Error("HasRDAPData() = true before loading bootstrap")
	}
}

func TestLookupService_LoadBootstrap_Empty(t *testing.T) {
	dataDir := t.TempDir()
	svc := NewLookupService(dataDir, nil)

	// Load from empty directory should succeed
	if err := svc.LoadBootstrap(); err != nil {
		t.Errorf("LoadBootstrap() error = %v", err)
	}

	// Still no data
	if svc.HasRDAPData() {
		t.Error("HasRDAPData() = true after loading empty dir")
	}
}

func TestParseASNNumber(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
	}{
		{"15169", 15169},
		{"AS15169", 15169},
		{"as15169", 15169},
		{"  AS15169  ", 15169},
		{"0", 0},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		got := parseASNNumber(tt.input)
		if got != tt.want {
			t.Errorf("parseASNNumber(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// TestLookupService_HasRDAPData_AfterLoad verifies HasRDAPData returns true once a
// valid DNS bootstrap file is loaded from disk.
func TestLookupService_HasRDAPData_AfterLoad(t *testing.T) {
	t.Parallel()
	dataDir := t.TempDir()
	rdapDir := filepath.Join(dataDir, "rdap")
	if err := os.MkdirAll(rdapDir, 0755); err != nil {
		t.Fatal(err)
	}

	dnsJSON := `{
		"version": "1.0",
		"publication": "2025-01-01T00:00:00Z",
		"services": [
			[["com", "net"], ["https://rdap.verisign.com/com/v1/"]]
		]
	}`
	if err := os.WriteFile(filepath.Join(rdapDir, "dns.json"), []byte(dnsJSON), 0644); err != nil {
		t.Fatal(err)
	}

	svc := NewLookupService(dataDir, nil)
	if err := svc.LoadBootstrap(); err != nil {
		t.Fatalf("LoadBootstrap() error = %v", err)
	}

	if !svc.HasRDAPData() {
		t.Error("HasRDAPData() = false after loading dns.json, want true")
	}
}

// TestLookupService_Lookup_UnknownType verifies that Lookup returns an error
// immediately for inputs that cannot be classified as domain, IP, or ASN.
// No network calls are made in this path.
func TestLookupService_Lookup_UnknownType(t *testing.T) {
	t.Parallel()
	svc := NewLookupService(t.TempDir(), nil)

	_, err := svc.Lookup(context.Background(), "!invalid!")
	if err == nil {
		t.Error("Lookup(!invalid!) should return error for unknown query type")
	}
}

// TestLookupService_Lookup_FailureCache verifies that a previously failed query
// is rejected from the failure cache without making any RDAP or WHOIS calls.
func TestLookupService_Lookup_FailureCache(t *testing.T) {
	t.Parallel()
	c := cache.NewMemoryCache(1024*1024, time.Minute)
	ctx := context.Background()

	// Seed the failure cache for example.com
	failureKey := cache.WHOISFailureKey("example.com")
	_ = c.Set(ctx, failureKey, []byte("1"), time.Minute)

	svc := NewLookupService(t.TempDir(), c)
	_, err := svc.Lookup(ctx, "example.com")
	if err == nil {
		t.Error("Lookup() with failure cache entry should return error")
	}
}

// TestLookupService_Lookup_CacheHit verifies that a previously cached result is
// returned directly from the cache without any RDAP or WHOIS calls.
func TestLookupService_Lookup_CacheHit(t *testing.T) {
	t.Parallel()
	c := cache.NewMemoryCache(1024*1024, time.Minute)
	ctx := context.Background()

	// Pre-populate cache with a minimal valid UnifiedResult
	cached := UnifiedResult{
		Query:     "example.com",
		QueryType: QueryTypeDomain,
		Source:    SourceWHOIS,
		Timestamp: time.Now(),
	}
	data, err := json.Marshal(cached)
	if err != nil {
		t.Fatal(err)
	}
	cacheKey := cache.WHOISKey("example.com")
	_ = c.Set(ctx, cacheKey, data, time.Minute)

	svc := NewLookupService(t.TempDir(), c)
	result, err := svc.Lookup(ctx, "example.com")
	if err != nil {
		t.Fatalf("Lookup() with cache hit error = %v", err)
	}
	if result.Query != "example.com" {
		t.Errorf("result.Query = %q, want %q", result.Query, "example.com")
	}
	if result.QueryType != QueryTypeDomain {
		t.Errorf("result.QueryType = %q, want %q", result.QueryType, QueryTypeDomain)
	}
}

// TestLookupService_LookupDomain_InvalidInput verifies LookupDomain propagates
// the error from Lookup when the input cannot be classified.
func TestLookupService_LookupDomain_InvalidInput(t *testing.T) {
	t.Parallel()
	svc := NewLookupService(t.TempDir(), nil)

	_, err := svc.LookupDomain(context.Background(), "!invalid!")
	if err == nil {
		t.Error("LookupDomain(!invalid!) should return error")
	}
}

// TestLookupService_LookupIP_InvalidInput verifies LookupIP propagates the error
// from Lookup when the input is not a valid IP address.
func TestLookupService_LookupIP_InvalidInput(t *testing.T) {
	t.Parallel()
	svc := NewLookupService(t.TempDir(), nil)

	_, err := svc.LookupIP(context.Background(), "!invalid!")
	if err == nil {
		t.Error("LookupIP(!invalid!) should return error")
	}
}

// TestLookupService_LookupASN_InvalidInput verifies LookupASN propagates the error
// from Lookup when the input is not a valid ASN.
func TestLookupService_LookupASN_InvalidInput(t *testing.T) {
	t.Parallel()
	svc := NewLookupService(t.TempDir(), nil)

	_, err := svc.LookupASN(context.Background(), "!invalid!")
	if err == nil {
		t.Error("LookupASN(!invalid!) should return error")
	}
}
