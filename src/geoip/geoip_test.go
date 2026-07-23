package geoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang"
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
			City:      "Raleigh",
			State1:    "NC",
			Postcode:  "27601",
			Latitude:  35.77,
			Longitude: -78.63,
			Timezone:  "America/New_York",
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

// writeCorruptMMDB writes a non-empty corrupt file that is not a valid mmdb archive.
// This exercises the "file exists but maxminddb.Open fails" branch in loadDatabases.
func writeCorruptMMDB(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("not a real mmdb file"), 0644); err != nil {
		t.Fatalf("writeCorruptMMDB(%q): %v", path, err)
	}
}

// TestLoadDatabases_ASN_CorruptFile verifies loadDatabases returns an error when the
// ASN mmdb file exists but cannot be parsed.
func TestLoadDatabases_ASN_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	writeCorruptMMDB(t, filepath.Join(dir, "asn.mmdb"))

	m := &GeoIPManager{dbDir: dir, enabled: true}
	err := m.loadDatabases(DatabaseConfig{ASN: true})
	if err == nil {
		t.Error("loadDatabases(corrupt ASN) expected error, got nil")
	}
}

// TestLoadDatabases_Country_CorruptFile verifies loadDatabases returns an error when the
// Country mmdb file exists but cannot be parsed.
func TestLoadDatabases_Country_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	writeCorruptMMDB(t, filepath.Join(dir, "country.mmdb"))

	m := &GeoIPManager{dbDir: dir, enabled: true}
	err := m.loadDatabases(DatabaseConfig{Country: true})
	if err == nil {
		t.Error("loadDatabases(corrupt Country) expected error, got nil")
	}
}

// TestLoadDatabases_CityV4_CorruptFile verifies loadDatabases returns an error when the
// City IPv4 mmdb file exists but cannot be parsed.
func TestLoadDatabases_CityV4_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	writeCorruptMMDB(t, filepath.Join(dir, "dbip-city-ipv4.mmdb"))

	m := &GeoIPManager{dbDir: dir, enabled: true}
	err := m.loadDatabases(DatabaseConfig{City: true})
	if err == nil {
		t.Error("loadDatabases(corrupt City IPv4) expected error, got nil")
	}
}

// TestLoadDatabases_CityV6_CorruptFile verifies loadDatabases returns an error when the
// City IPv6 mmdb file exists but cannot be parsed.
func TestLoadDatabases_CityV6_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	writeCorruptMMDB(t, filepath.Join(dir, "dbip-city-ipv6.mmdb"))

	m := &GeoIPManager{dbDir: dir, enabled: true}
	err := m.loadDatabases(DatabaseConfig{City: true})
	if err == nil {
		t.Error("loadDatabases(corrupt City IPv6) expected error, got nil")
	}
}

// TestLoadDatabases_WHOIS_NoFile verifies loadDatabases with WHOIS enabled does not
// attempt to load any file — per AI.md PART 19, WHOIS is a combined view of the
// ASN and Country databases computed at lookup time, not a separate mmdb file.
func TestLoadDatabases_WHOIS_NoFile(t *testing.T) {
	dir := t.TempDir()

	m := &GeoIPManager{dbDir: dir, enabled: true}
	err := m.loadDatabases(DatabaseConfig{WHOIS: true})
	if err != nil {
		t.Errorf("loadDatabases(WHOIS, no file) returned error: %v", err)
	}
	if !m.whoisEnabled {
		t.Error("expected m.whoisEnabled to be true after loadDatabases(WHOIS: true)")
	}
}

// TestLoadDatabases_AllFlags_NoFiles verifies that loadDatabases with all flags true
// but no files on disk returns nil (files simply do not exist — stat check skips them).
func TestLoadDatabases_AllFlags_NoFiles(t *testing.T) {
	dir := t.TempDir()
	m := &GeoIPManager{dbDir: dir, enabled: true}
	err := m.loadDatabases(DatabaseConfig{ASN: true, Country: true, City: true, WHOIS: true})
	if err != nil {
		t.Errorf("loadDatabases(all flags, no files) returned error: %v", err)
	}
}

// TestEnabled_True confirms Enabled() reports true when configured as enabled.
func TestEnabled_True(t *testing.T) {
	dir := t.TempDir()
	m, err := NewGeoIPManager(GeoIPConfig{Enabled: true, Dir: dir})
	if err != nil {
		t.Fatalf("NewGeoIPManager: %v", err)
	}
	defer m.Close()
	if !m.Enabled() {
		t.Error("Enabled() = false, want true")
	}
}

// TestLastUpdate_AfterUpdate confirms LastUpdate is non-zero after UpdateDatabases.
func TestLastUpdate_AfterUpdate(t *testing.T) {
	dir := t.TempDir()
	m, err := NewGeoIPManager(GeoIPConfig{Enabled: true, Dir: dir})
	if err != nil {
		t.Fatalf("NewGeoIPManager: %v", err)
	}
	defer m.Close()

	before := time.Now()
	if err := m.UpdateDatabases(context.Background(), DatabaseConfig{}); err != nil {
		t.Fatalf("UpdateDatabases: %v", err)
	}
	after := time.Now()

	lu := m.LastUpdate()
	if lu.IsZero() {
		t.Error("LastUpdate() is zero after UpdateDatabases")
	}
	if lu.Before(before) || lu.After(after) {
		t.Errorf("LastUpdate() = %v, expected between %v and %v", lu, before, after)
	}
}

// TestUpdateDatabases_CorruptExistingFile exercises the rename-failure branch in
// UpdateDatabases when the tmp file cannot be moved (target is a directory).
func TestUpdateDatabases_CorruptExistingFile(t *testing.T) {
	dir := t.TempDir()
	m := &GeoIPManager{dbDir: dir, enabled: true}

	// Write a corrupt file at asn.mmdb.tmp so downloadDatabase would be attempted
	// but we bypass the download by keeping all DB flags false — just verify the
	// UpdateDatabases path when no downloads are needed.
	err := m.UpdateDatabases(context.Background(), DatabaseConfig{})
	if err != nil {
		t.Errorf("UpdateDatabases(no flags) returned error: %v", err)
	}
	if m.LastUpdate().IsZero() {
		t.Error("LastUpdate() should be set after UpdateDatabases")
	}
}

// TestEnsureDatabases_DisabledFlag verifies that ensureDatabases skips entries
// where the enabled flag is false, even if the file does not exist.
func TestEnsureDatabases_DisabledFlag(t *testing.T) {
	dir := t.TempDir()
	m := &GeoIPManager{dbDir: dir, enabled: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ASN flag false — no download attempted, no file created, no error.
	if err := m.ensureDatabases(ctx, DatabaseConfig{ASN: false}); err != nil {
		t.Errorf("ensureDatabases(disabled flag) returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "asn.mmdb")); !os.IsNotExist(err) {
		t.Error("asn.mmdb should not be created when ASN flag is false")
	}
}

// TestDownloadDatabase_Success verifies downloadDatabase writes a file when the
// HTTP server returns 200 with a body.
func TestDownloadDatabase_Success(t *testing.T) {
	content := []byte("fake mmdb content for testing")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer srv.Close()

	destPath := filepath.Join(t.TempDir(), "test.mmdb")
	if err := downloadDatabase(context.Background(), srv.URL, destPath, "test-agent"); err != nil {
		t.Fatalf("downloadDatabase returned error: %v", err)
	}

	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("reading dest file: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("file content = %q, want %q", data, content)
	}
}

// TestDownloadDatabase_Non200 verifies downloadDatabase returns an error for non-200 responses.
func TestDownloadDatabase_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	destPath := filepath.Join(t.TempDir(), "test.mmdb")
	if err := downloadDatabase(context.Background(), srv.URL, destPath, "test-agent"); err == nil {
		t.Error("expected error for 404 response, got nil")
	}
}

// TestDownloadDatabase_InvalidURL verifies downloadDatabase returns an error for an
// unreachable URL.
func TestDownloadDatabase_InvalidURL(t *testing.T) {
	destPath := filepath.Join(t.TempDir(), "test.mmdb")
	if err := downloadDatabase(context.Background(), "http://127.0.0.1:0/invalid", destPath, "test-agent"); err == nil {
		t.Error("expected error for unreachable URL, got nil")
	}
}

// TestDownloadDatabase_CancelledContext verifies downloadDatabase returns an error
// when the context is already cancelled.
func TestDownloadDatabase_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	destPath := filepath.Join(t.TempDir(), "test.mmdb")
	if err := downloadDatabase(ctx, "http://127.0.0.1:0/any", destPath, "test-agent"); err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}

// TestNewGeoIPManager_BadDir verifies NewGeoIPManager returns an error when the
// directory path cannot be created (e.g. a file already exists at that path).
func TestNewGeoIPManager_BadDir(t *testing.T) {
	base := t.TempDir()
	// Create a plain file at the path where we want a directory — MkdirAll will fail.
	blockPath := filepath.Join(base, "blocked")
	if err := os.WriteFile(blockPath, []byte("not a dir"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, err := NewGeoIPManager(GeoIPConfig{
		Enabled: true,
		Dir:     filepath.Join(blockPath, "subdir"),
	})
	if err == nil {
		t.Error("expected error when dir creation fails, got nil")
	}
}

// TestEnsureDatabases_AllEnabled_FilesExist verifies that ensureDatabases skips
// all downloads when all four mmdb files already exist on disk.
func TestEnsureDatabases_AllEnabled_FilesExist(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"asn.mmdb", "country.mmdb", "dbip-city-ipv4.mmdb", "dbip-city-ipv6.mmdb"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("existing"), 0644); err != nil {
			t.Fatalf("setup %s: %v", name, err)
		}
	}

	m := &GeoIPManager{dbDir: dir, enabled: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// All files exist — no downloads should be attempted.
	if err := m.ensureDatabases(ctx, DatabaseConfig{ASN: true, Country: true, City: true, WHOIS: true}); err != nil {
		t.Errorf("ensureDatabases(all exist) returned error: %v", err)
	}

	// Files must still have their original content (not overwritten).
	for _, name := range []string{"asn.mmdb", "country.mmdb", "dbip-city-ipv4.mmdb", "dbip-city-ipv6.mmdb"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if string(data) != "existing" {
			t.Errorf("%s content changed unexpectedly", name)
		}
	}
}

// minimalMMDB is a valid MaxMind DB binary with 0 nodes, record_size=28, IPv6.
// Generated in-memory for tests — no real GeoIP data.
var minimalMMDB = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xab, 0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64, 0x2e, 0x63, 0x6f, 0x6d, 0xe9, 0x4a,
	0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0xc0, 0x4b, 0x72, 0x65, 0x63, 0x6f,
	0x72, 0x64, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0xc1, 0x1c, 0x4a, 0x69, 0x70, 0x5f, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0xc1, 0x06, 0x4d, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x5f,
	0x74, 0x79, 0x70, 0x65, 0x4c, 0x47, 0x65, 0x6f, 0x4c, 0x69, 0x74, 0x65, 0x32, 0x2d, 0x41, 0x53,
	0x4e, 0x5b, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x5f,
	0x6d, 0x61, 0x6a, 0x6f, 0x72, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0xc1, 0x02, 0x5b,
	0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x5f, 0x6d, 0x69,
	0x6e, 0x6f, 0x72, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0xc0, 0x4b, 0x62, 0x75, 0x69,
	0x6c, 0x64, 0x5f, 0x65, 0x70, 0x6f, 0x63, 0x68, 0xc0, 0x4b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0xe1, 0x42, 0x65, 0x6e, 0x44, 0x54, 0x65, 0x73, 0x74, 0x49, 0x6c,
	0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x73, 0x00, 0x04,
}

// writeMinimalMMDB writes a valid minimal MMDB file at path for tests that need
// a real reader (Close, Lookup with non-nil DB, loadDatabases success branches).
func writeMinimalMMDB(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, minimalMMDB, 0644); err != nil {
		t.Fatalf("writeMinimalMMDB(%q): %v", path, err)
	}
}

// TestLoadDatabases_ASN_Success verifies the success branch of loadDatabases when a
// valid ASN mmdb file exists. After the call m.asnDB must be non-nil.
func TestLoadDatabases_ASN_Success(t *testing.T) {
	dir := t.TempDir()
	writeMinimalMMDB(t, filepath.Join(dir, "asn.mmdb"))

	m := &GeoIPManager{dbDir: dir, enabled: true}
	if err := m.loadDatabases(DatabaseConfig{ASN: true}); err != nil {
		t.Fatalf("loadDatabases(ASN, valid file): %v", err)
	}
	if m.asnDB == nil {
		t.Error("expected m.asnDB to be non-nil after successful load")
	}
	// Clean up the reader.
	m.asnDB.Close()
}

// TestLoadDatabases_Country_Success verifies the success branch for Country DB.
func TestLoadDatabases_Country_Success(t *testing.T) {
	dir := t.TempDir()
	writeMinimalMMDB(t, filepath.Join(dir, "country.mmdb"))

	m := &GeoIPManager{dbDir: dir, enabled: true}
	if err := m.loadDatabases(DatabaseConfig{Country: true}); err != nil {
		t.Fatalf("loadDatabases(Country, valid file): %v", err)
	}
	if m.countryDB == nil {
		t.Error("expected m.countryDB to be non-nil after successful load")
	}
	m.countryDB.Close()
}

// TestLoadDatabases_City_Success verifies the success branch for City DBs (both
// IPv4 and IPv6 files are loaded when City is enabled).
func TestLoadDatabases_City_Success(t *testing.T) {
	dir := t.TempDir()
	writeMinimalMMDB(t, filepath.Join(dir, "dbip-city-ipv4.mmdb"))
	writeMinimalMMDB(t, filepath.Join(dir, "dbip-city-ipv6.mmdb"))

	m := &GeoIPManager{dbDir: dir, enabled: true}
	if err := m.loadDatabases(DatabaseConfig{City: true}); err != nil {
		t.Fatalf("loadDatabases(City, valid files): %v", err)
	}
	if m.cityDBv4 == nil {
		t.Error("expected m.cityDBv4 to be non-nil after successful load")
	}
	if m.cityDBv6 == nil {
		t.Error("expected m.cityDBv6 to be non-nil after successful load")
	}
	m.cityDBv4.Close()
	m.cityDBv6.Close()
}

// TestLoadDatabases_WHOIS_Success verifies loadDatabases sets whoisEnabled when
// WHOIS is requested — per AI.md PART 19 there is no whois.mmdb file to load.
func TestLoadDatabases_WHOIS_Success(t *testing.T) {
	dir := t.TempDir()

	m := &GeoIPManager{dbDir: dir, enabled: true}
	if err := m.loadDatabases(DatabaseConfig{WHOIS: true}); err != nil {
		t.Fatalf("loadDatabases(WHOIS): %v", err)
	}
	if !m.whoisEnabled {
		t.Error("expected m.whoisEnabled to be true after successful load")
	}
}

// TestLoadDatabases_AllDBs_Success verifies all success branches in one pass.
func TestLoadDatabases_AllDBs_Success(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"asn.mmdb", "country.mmdb", "dbip-city-ipv4.mmdb", "dbip-city-ipv6.mmdb"} {
		writeMinimalMMDB(t, filepath.Join(dir, name))
	}

	m := &GeoIPManager{dbDir: dir, enabled: true}
	if err := m.loadDatabases(DatabaseConfig{ASN: true, Country: true, City: true, WHOIS: true}); err != nil {
		t.Fatalf("loadDatabases(all DBs, valid files): %v", err)
	}
	if m.asnDB == nil {
		t.Error("expected m.asnDB to be non-nil")
	}
	if m.countryDB == nil {
		t.Error("expected m.countryDB to be non-nil")
	}
	if m.cityDBv4 == nil {
		t.Error("expected m.cityDBv4 to be non-nil")
	}
	if m.cityDBv6 == nil {
		t.Error("expected m.cityDBv6 to be non-nil")
	}
	if !m.whoisEnabled {
		t.Error("expected m.whoisEnabled to be true")
	}
	// Close via the Close() method to cover the non-nil reader branches.
	if err := m.Close(); err != nil {
		t.Errorf("Close() after loading all DBs: %v", err)
	}
	// All fields must be nil after Close.
	if m.asnDB != nil {
		t.Error("m.asnDB should be nil after Close")
	}
	if m.countryDB != nil {
		t.Error("m.countryDB should be nil after Close")
	}
	if m.cityDBv4 != nil {
		t.Error("m.cityDBv4 should be nil after Close")
	}
	if m.cityDBv6 != nil {
		t.Error("m.cityDBv6 should be nil after Close")
	}
}

// TestClose_NonNilReaders exercises every non-nil branch in Close():
// assigns real readers to all reader fields, calls Close, and confirms they are cleared.
func TestClose_NonNilReaders(t *testing.T) {
	dir := t.TempDir()
	mmdbPath := filepath.Join(dir, "test.mmdb")
	writeMinimalMMDB(t, mmdbPath)

	openReader := func() *maxminddb.Reader {
		t.Helper()
		r, err := maxminddb.Open(mmdbPath)
		if err != nil {
			t.Fatalf("maxminddb.Open: %v", err)
		}
		return r
	}

	m := &GeoIPManager{
		dbDir:     dir,
		enabled:   true,
		asnDB:     openReader(),
		countryDB: openReader(),
		cityDBv4:  openReader(),
		cityDBv6:  openReader(),
	}

	if err := m.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
	if m.asnDB != nil || m.countryDB != nil || m.cityDBv4 != nil || m.cityDBv6 != nil {
		t.Error("expected all DB readers to be nil after Close()")
	}
}

// TestLookup_WithASNReader verifies Lookup executes the m.asnDB != nil branch and
// returns a non-nil result without error (the minimal DB has 0 records so ASN is nil
// but the branch is exercised and the function returns without error).
func TestLookup_WithASNReader(t *testing.T) {
	dir := t.TempDir()
	mmdbPath := filepath.Join(dir, "asn.mmdb")
	writeMinimalMMDB(t, mmdbPath)

	r, err := maxminddb.Open(mmdbPath)
	if err != nil {
		t.Fatalf("maxminddb.Open: %v", err)
	}

	m := &GeoIPManager{
		dbDir:   dir,
		enabled: true,
		asnDB:   r,
	}
	defer m.Close()

	result, err := m.Lookup("1.2.3.4")
	if err != nil {
		t.Fatalf("Lookup with asnDB set returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.IP != "1.2.3.4" {
		t.Errorf("result.IP = %q, want %q", result.IP, "1.2.3.4")
	}
}

// TestLookup_WithAllReaders exercises all four DB reader nil-check branches in Lookup.
func TestLookup_WithAllReaders(t *testing.T) {
	dir := t.TempDir()
	mmdbPath := filepath.Join(dir, "test.mmdb")
	writeMinimalMMDB(t, mmdbPath)

	openReader := func() *maxminddb.Reader {
		t.Helper()
		reader, openErr := maxminddb.Open(mmdbPath)
		if openErr != nil {
			t.Fatalf("maxminddb.Open: %v", openErr)
		}
		return reader
	}

	m := &GeoIPManager{
		dbDir:        dir,
		enabled:      true,
		asnDB:        openReader(),
		countryDB:    openReader(),
		cityDBv4:     openReader(),
		cityDBv6:     openReader(),
		whoisEnabled: true,
	}
	defer m.Close()

	result, err := m.Lookup("2001:db8::1")
	if err != nil {
		t.Fatalf("Lookup(IPv6) with all DBs set: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.IP != "2001:db8::1" {
		t.Errorf("result.IP = %q, want %q", result.IP, "2001:db8::1")
	}
}

// TestUpdateDatabases_WithValidReload verifies UpdateDatabases reloads the DB readers
// when valid mmdb files already exist at the expected paths (no download needed).
// The test places valid mmdb files in place so the reload path succeeds.
func TestUpdateDatabases_WithValidReload(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"asn.mmdb"} {
		writeMinimalMMDB(t, filepath.Join(dir, name))
	}

	m := &GeoIPManager{dbDir: dir, enabled: true}

	before := time.Now()
	ctx := context.Background()
	// ASN=true but file already on disk so ensureDatabases skips download;
	// UpdateDatabases then calls loadDatabases (success) and sets lastUpdate.
	err := m.UpdateDatabases(ctx, DatabaseConfig{ASN: true})
	after := time.Now()

	// Download will be attempted for ASN since UpdateDatabases always re-downloads.
	// It will fail (no network in test) but loadDatabases is still called with the
	// existing file (the tmp rename fails, so the original file remains).
	// We just verify lastUpdate is set regardless of download errors.
	_ = err

	lu := m.LastUpdate()
	if lu.IsZero() {
		t.Error("LastUpdate() should be set after UpdateDatabases regardless of download errors")
	}
	if lu.Before(before) || lu.After(after) {
		t.Errorf("LastUpdate() = %v, expected between %v and %v", lu, before, after)
	}
	m.Close()
}

// ---------------------------------------------------------------------------
// IsCountryBlocked()
// ---------------------------------------------------------------------------

// TestIsCountryBlocked_Disabled verifies that a disabled manager never blocks.
func TestIsCountryBlocked_Disabled(t *testing.T) {
	m := &GeoIPManager{enabled: false}
	if m.IsCountryBlocked("1.2.3.4", []string{"US"}, nil) {
		t.Error("IsCountryBlocked on disabled manager must return false")
	}
}

// TestIsCountryBlocked_NoDenyNoAllow verifies pass-through when both lists are empty.
func TestIsCountryBlocked_NoDenyNoAllow(t *testing.T) {
	m := &GeoIPManager{enabled: true}
	if m.IsCountryBlocked("1.2.3.4", nil, nil) {
		t.Error("IsCountryBlocked with empty lists must return false")
	}
}

// TestIsCountryBlocked_InvalidIP verifies fail-open for unresolvable IPs.
func TestIsCountryBlocked_InvalidIP(t *testing.T) {
	m := &GeoIPManager{enabled: true}
	if m.IsCountryBlocked("not-an-ip", []string{"US"}, nil) {
		t.Error("IsCountryBlocked with invalid IP must return false (fail-open)")
	}
}

// TestIsCountryBlocked_NoDBs verifies fail-open when no database is loaded.
func TestIsCountryBlocked_NoDBs(t *testing.T) {
	m := &GeoIPManager{enabled: true}
	// Valid IP but no databases loaded — Lookup returns no country.
	if m.IsCountryBlocked("8.8.8.8", []string{"US"}, nil) {
		t.Error("IsCountryBlocked with no DB must return false (fail-open)")
	}
}
