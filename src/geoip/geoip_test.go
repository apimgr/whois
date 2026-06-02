package geoip

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newDisabledManager returns a GeoIPManager with Enabled: false via the public constructor.
func newDisabledManager(t *testing.T) *GeoIPManager {
	t.Helper()
	m, err := NewGeoIPManager(GeoIPConfig{Enabled: false, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewGeoIPManager(disabled) returned error: %v", err)
	}
	return m
}

// TestNewGeoIPManager_Disabled verifies that a disabled manager is created without error.
func TestNewGeoIPManager_Disabled(t *testing.T) {
	m := newDisabledManager(t)
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

// TestEnabled_False confirms Enabled() reports false when configured as disabled.
func TestEnabled_False(t *testing.T) {
	m := newDisabledManager(t)
	if m.Enabled() {
		t.Error("Enabled() = true, want false")
	}
}

// TestLookup_DisabledReturnsError verifies Lookup returns the sentinel error when disabled.
func TestLookup_DisabledReturnsError(t *testing.T) {
	m := newDisabledManager(t)
	_, err := m.Lookup("1.2.3.4")
	if err == nil {
		t.Fatal("expected error from Lookup on disabled manager, got nil")
	}
	if err.Error() != "GeoIP is disabled" {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

// TestLookup_Disabled_IPv6 confirms the disabled guard fires for IPv6 addresses too.
func TestLookup_Disabled_IPv6(t *testing.T) {
	m := newDisabledManager(t)
	_, err := m.Lookup("::1")
	if err == nil {
		t.Fatal("expected error from Lookup (IPv6) on disabled manager, got nil")
	}
	if err.Error() != "GeoIP is disabled" {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

// TestLastUpdate_Zero confirms lastUpdate is zero time on a fresh manager.
func TestLastUpdate_Zero(t *testing.T) {
	m := newDisabledManager(t)
	if !m.LastUpdate().IsZero() {
		t.Errorf("LastUpdate() = %v, want zero time", m.LastUpdate())
	}
}

// TestClose_EmptyManager confirms Close on a no-DB manager returns nil.
func TestClose_EmptyManager(t *testing.T) {
	m := newDisabledManager(t)
	if err := m.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

// TestClose_Idempotent confirms Close can be called twice without panic.
func TestClose_Idempotent(t *testing.T) {
	m := newDisabledManager(t)
	if err := m.Close(); err != nil {
		t.Errorf("first Close() error = %v", err)
	}
	if err := m.Close(); err != nil {
		t.Errorf("second Close() error = %v", err)
	}
}

// TestNewGeoIPManager_EnabledNoDBs creates an enabled manager pointing at an
// empty temp directory. No databases exist, so the download will fail (offline
// or rate-limited in CI) and all DB readers stay nil — but the constructor must
// still return a non-nil manager without a hard error.
func TestNewGeoIPManager_EnabledNoDBs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in short mode")
	}
	dir := t.TempDir()
	cfg := GeoIPConfig{
		Enabled: true,
		Dir:     dir,
		Databases: DatabaseConfig{
			ASN:     false,
			Country: false,
			City:    false,
			WHOIS:   false,
		},
	}
	m, err := NewGeoIPManager(cfg)
	if err != nil {
		t.Fatalf("NewGeoIPManager(enabled, no DBs) returned error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if !m.Enabled() {
		t.Error("Enabled() = false, want true")
	}
	m.Close()
}

// TestLookup_InvalidIP confirms an invalid IP string returns an error when the
// manager is enabled (but has no DB readers loaded).
func TestLookup_InvalidIP(t *testing.T) {
	dir := t.TempDir()
	cfg := GeoIPConfig{
		Enabled:   true,
		Dir:       dir,
		Databases: DatabaseConfig{},
	}
	m, err := NewGeoIPManager(cfg)
	if err != nil {
		t.Fatalf("NewGeoIPManager: %v", err)
	}
	defer m.Close()

	_, err = m.Lookup("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP, got nil")
	}
}

// TestLookup_NilDBs confirms that an enabled manager with no DB readers loaded
// still returns a valid (empty) LookupResult without error.
func TestLookup_NilDBs(t *testing.T) {
	dir := t.TempDir()
	cfg := GeoIPConfig{
		Enabled:   true,
		Dir:       dir,
		Databases: DatabaseConfig{},
	}
	m, err := NewGeoIPManager(cfg)
	if err != nil {
		t.Fatalf("NewGeoIPManager: %v", err)
	}
	defer m.Close()

	result, err := m.Lookup("192.168.1.1")
	if err != nil {
		t.Fatalf("Lookup returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.IP != "192.168.1.1" {
		t.Errorf("result.IP = %q, want %q", result.IP, "192.168.1.1")
	}
	if result.ASN != nil {
		t.Error("expected nil ASN with no DB loaded")
	}
	if result.Country != nil {
		t.Error("expected nil Country with no DB loaded")
	}
	if result.City != nil {
		t.Error("expected nil City with no DB loaded")
	}
	if result.WHOIS != nil {
		t.Error("expected nil WHOIS with no DB loaded")
	}
}

// TestLookup_IPv6_NilDBs verifies IPv6 addresses parse and return cleanly
// when no database readers are loaded.
func TestLookup_IPv6_NilDBs(t *testing.T) {
	dir := t.TempDir()
	m, err := NewGeoIPManager(GeoIPConfig{Enabled: true, Dir: dir})
	if err != nil {
		t.Fatalf("NewGeoIPManager: %v", err)
	}
	defer m.Close()

	result, err := m.Lookup("2001:db8::1")
	if err != nil {
		t.Fatalf("Lookup(IPv6): unexpected error: %v", err)
	}
	if result.IP != "2001:db8::1" {
		t.Errorf("result.IP = %q, want %q", result.IP, "2001:db8::1")
	}
}

// TestUpdateDatabases_NoDB verifies UpdateDatabases updates lastUpdate even
// when all database flags are disabled (no actual downloads).
func TestUpdateDatabases_NoDB(t *testing.T) {
	dir := t.TempDir()
	m, err := NewGeoIPManager(GeoIPConfig{Enabled: true, Dir: dir})
	if err != nil {
		t.Fatalf("NewGeoIPManager: %v", err)
	}
	defer m.Close()

	before := time.Now()
	ctx := context.Background()
	err = m.UpdateDatabases(ctx, DatabaseConfig{})
	after := time.Now()

	if err != nil {
		t.Fatalf("UpdateDatabases(no DBs) returned error: %v", err)
	}
	lu := m.LastUpdate()
	if lu.Before(before) || lu.After(after) {
		t.Errorf("LastUpdate() = %v, expected between %v and %v", lu, before, after)
	}
}

// TestEnsureDatabases_ExistingFileSkipped verifies that ensureDatabases does not
// re-download a file that already exists on disk.
func TestEnsureDatabases_ExistingFileSkipped(t *testing.T) {
	dir := t.TempDir()
	asnPath := filepath.Join(dir, "asn.mmdb")

	sentinel := []byte("existing-content")
	if err := os.WriteFile(asnPath, sentinel, 0644); err != nil {
		t.Fatalf("writing sentinel file: %v", err)
	}

	m := &GeoIPManager{dbDir: dir, enabled: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ensureDatabases must not overwrite an existing file.
	_ = m.ensureDatabases(ctx, DatabaseConfig{ASN: true})

	data, err := os.ReadFile(asnPath)
	if err != nil {
		t.Fatalf("reading file after ensureDatabases: %v", err)
	}
	if string(data) != string(sentinel) {
		t.Errorf("file content changed; got %q, want %q", data, sentinel)
	}
}

// TestLookupResult_Fields verifies the exported struct fields are addressable
// (compile-time check that field names and types are stable).
func TestLookupResult_Fields(t *testing.T) {
	r := LookupResult{
		IP:      "10.0.0.1",
		ASN:     &ASNResult{Number: 64512, Organization: "Test-AS"},
		Country: &CountryResult{Code: "US"},
		City: &CityResult{
			City:       "Raleigh",
			Region:     "NC",
			PostalCode: "27601",
			Latitude:   35.77,
			Longitude:  -78.63,
			Timezone:   "America/New_York",
		},
		WHOIS: &WHOISResult{
			Registrant:  "Test Org",
			ASN:         64512,
			CountryCode: "US",
		},
	}

	if r.IP != "10.0.0.1" {
		t.Errorf("IP = %q", r.IP)
	}
	if r.ASN.Number != 64512 {
		t.Errorf("ASN.Number = %d", r.ASN.Number)
	}
	if r.Country.Code != "US" {
		t.Errorf("Country.Code = %q", r.Country.Code)
	}
	if r.City.Timezone != "America/New_York" {
		t.Errorf("City.Timezone = %q", r.City.Timezone)
	}
	if r.WHOIS.Registrant != "Test Org" {
		t.Errorf("WHOIS.Registrant = %q", r.WHOIS.Registrant)
	}
}

// TestGeoIPConfig_Defaults verifies zero-value DatabaseConfig does not panic in
// loadDatabases (all flags false → nothing attempted).
func TestGeoIPConfig_Defaults(t *testing.T) {
	m := &GeoIPManager{dbDir: t.TempDir(), enabled: true}
	if err := m.loadDatabases(DatabaseConfig{}); err != nil {
		t.Errorf("loadDatabases(zero config) returned error: %v", err)
	}
}

// TestNewGeoIPManager_DirCreation verifies that NewGeoIPManager creates the
// database directory when enabled and it does not already exist.
func TestNewGeoIPManager_DirCreation(t *testing.T) {
	base := t.TempDir()
	newDir := filepath.Join(base, "subdir", "geoip")

	m, err := NewGeoIPManager(GeoIPConfig{
		Enabled:   true,
		Dir:       newDir,
		Databases: DatabaseConfig{},
	})
	if err != nil {
		t.Fatalf("NewGeoIPManager: %v", err)
	}
	defer m.Close()

	if _, statErr := os.Stat(newDir); os.IsNotExist(statErr) {
		t.Errorf("expected directory %q to be created", newDir)
	}
}
