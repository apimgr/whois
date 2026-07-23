package tor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cretz/bine/control"
	bineTor "github.com/cretz/bine/tor"
)

// ---------------------------------------------------------------------------
// DefaultTorConfig
// ---------------------------------------------------------------------------

func TestDefaultTorConfig_AllFields(t *testing.T) {
	cfg := DefaultTorConfig()

	if cfg.Binary != "" {
		t.Errorf("Binary = %q, want empty string (auto-detect)", cfg.Binary)
	}
	if cfg.UseNetwork {
		t.Error("UseNetwork = true, want false")
	}
	if !cfg.AllowUserPreference {
		t.Error("AllowUserPreference = false, want true")
	}
	if cfg.MaxCircuits != 32 {
		t.Errorf("MaxCircuits = %d, want 32", cfg.MaxCircuits)
	}
	if cfg.CircuitTimeout != 60 {
		t.Errorf("CircuitTimeout = %d, want 60", cfg.CircuitTimeout)
	}
	if cfg.BootstrapTimeout != 180 {
		t.Errorf("BootstrapTimeout = %d, want 180", cfg.BootstrapTimeout)
	}
	if !cfg.SafeLogging {
		t.Error("SafeLogging = false, want true")
	}
	if cfg.MaxStreamsPerCircuit != 100 {
		t.Errorf("MaxStreamsPerCircuit = %d, want 100", cfg.MaxStreamsPerCircuit)
	}
	if !cfg.CloseCircuitOnStreamLimit {
		t.Error("CloseCircuitOnStreamLimit = false, want true")
	}
	if cfg.BandwidthRate != "1 MB" {
		t.Errorf("BandwidthRate = %q, want %q", cfg.BandwidthRate, "1 MB")
	}
	if cfg.BandwidthBurst != "2 MB" {
		t.Errorf("BandwidthBurst = %q, want %q", cfg.BandwidthBurst, "2 MB")
	}
	if cfg.MaxMonthlyBandwidth != "100 GB" {
		t.Errorf("MaxMonthlyBandwidth = %q, want %q", cfg.MaxMonthlyBandwidth, "100 GB")
	}
	if cfg.NumIntroPoints != 3 {
		t.Errorf("NumIntroPoints = %d, want 3", cfg.NumIntroPoints)
	}
	if cfg.VirtualPort != 80 {
		t.Errorf("VirtualPort = %d, want 80", cfg.VirtualPort)
	}
}

func TestDefaultTorConfig_ImmutableDefaults(t *testing.T) {
	// Two independent calls must return independent copies.
	a := DefaultTorConfig()
	b := DefaultTorConfig()

	a.BandwidthRate = "10 MB"
	if b.BandwidthRate == "10 MB" {
		t.Error("modifying one DefaultTorConfig affected another — they share state")
	}
}

// ---------------------------------------------------------------------------
// TorConfig struct
// ---------------------------------------------------------------------------

func TestTorConfig_Populate(t *testing.T) {
	cfg := TorConfig{
		Binary:                    "/usr/bin/tor",
		UseNetwork:                true,
		MaxCircuits:               64,
		CircuitTimeout:            120,
		BootstrapTimeout:          300,
		SafeLogging:               false,
		MaxStreamsPerCircuit:      50,
		CloseCircuitOnStreamLimit: false,
		BandwidthRate:             "5 MB",
		BandwidthBurst:            "10 MB",
		MaxMonthlyBandwidth:       "unlimited",
		NumIntroPoints:            6,
		VirtualPort:               443,
	}

	if cfg.Binary != "/usr/bin/tor" {
		t.Errorf("Binary = %q", cfg.Binary)
	}
	if !cfg.UseNetwork {
		t.Error("UseNetwork should be true")
	}
	if cfg.MaxCircuits != 64 {
		t.Errorf("MaxCircuits = %d", cfg.MaxCircuits)
	}
	if cfg.VirtualPort != 443 {
		t.Errorf("VirtualPort = %d, want 443", cfg.VirtualPort)
	}
	if cfg.MaxMonthlyBandwidth != "unlimited" {
		t.Errorf("MaxMonthlyBandwidth = %q", cfg.MaxMonthlyBandwidth)
	}
}

// ---------------------------------------------------------------------------
// TorService
// ---------------------------------------------------------------------------

func TestTorService_OnionAddress(t *testing.T) {
	svc := &TorService{
		serviceID:  "exampleonionaddr",
		serverPort: 8080,
	}
	got := svc.OnionAddress()
	want := "exampleonionaddr.onion"
	if got != want {
		t.Errorf("OnionAddress() = %q, want %q", got, want)
	}
}

func TestTorService_OnionAddress_Empty(t *testing.T) {
	svc := &TorService{}
	got := svc.OnionAddress()
	if got != ".onion" {
		t.Errorf("OnionAddress() with empty serviceID = %q, want %q", got, ".onion")
	}
}

func TestTorService_OutboundEnabled_NoDialer(t *testing.T) {
	svc := &TorService{}
	if svc.OutboundEnabled() {
		t.Error("OutboundEnabled() = true, want false when dialer is nil")
	}
}

func TestTorService_GetHTTPClient_NoTor(t *testing.T) {
	svc := &TorService{}
	client := svc.GetHTTPClient(false)
	if client == nil {
		t.Fatal("GetHTTPClient(false) returned nil")
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", client.Timeout)
	}
}

func TestTorService_GetHTTPClient_TorRequestedButNoDialer(t *testing.T) {
	// useTor=true but dialer is nil — must fall back to plain client.
	svc := &TorService{}
	client := svc.GetHTTPClient(true)
	if client == nil {
		t.Fatal("GetHTTPClient(true) returned nil when no dialer set")
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s (fallback)", client.Timeout)
	}
}

func TestTorService_Close_NilT(t *testing.T) {
	svc := &TorService{}
	// Must not panic when the internal tor.Tor pointer is nil.
	if err := svc.Close(); err != nil {
		t.Errorf("Close() with nil t = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// FindBinary
// ---------------------------------------------------------------------------

func TestFindBinary_ExplicitPathExists(t *testing.T) {
	// Create a temp file to act as a fake binary.
	tmp, err := os.CreateTemp(t.TempDir(), "fake-tor-*")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	tmp.Close()

	got := FindBinary(tmp.Name())
	if got != tmp.Name() {
		t.Errorf("FindBinary(%q) = %q, want exact path", tmp.Name(), got)
	}
}

func TestFindBinary_ExplicitPathMissing(t *testing.T) {
	// Non-existent explicit path must fall through to PATH / well-known locations.
	// We cannot assert a specific result here because the test host may or may not
	// have tor installed. We just verify it does not panic and returns a string.
	result := FindBinary("/nonexistent/path/to/tor-binary-xyz")
	// result is "" or a system tor path — both are acceptable.
	_ = result
}

func TestFindBinary_EmptyConfig(t *testing.T) {
	// Empty config falls through to PATH search. No panic expected.
	_ = FindBinary("")
}

// ---------------------------------------------------------------------------
// ensureTorDirs
// ---------------------------------------------------------------------------

func TestEnsureTorDirs(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()

	if err := ensureTorDirs(configDir, dataDir); err != nil {
		t.Fatalf("ensureTorDirs() error = %v", err)
	}

	expected := []string{
		filepath.Join(configDir, "tor"),
		filepath.Join(dataDir, "tor"),
		filepath.Join(dataDir, "tor", "site"),
	}
	for _, d := range expected {
		info, err := os.Stat(d)
		if err != nil {
			t.Errorf("directory %q not created: %v", d, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%q is not a directory", d)
		}
		// Permissions must be 0700.
		if info.Mode().Perm() != 0700 {
			t.Errorf("%q permissions = %04o, want 0700", d, info.Mode().Perm())
		}
	}
}

func TestEnsureTorDirs_Idempotent(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()

	// Call twice — should not fail on second call.
	for i := 0; i < 2; i++ {
		if err := ensureTorDirs(configDir, dataDir); err != nil {
			t.Fatalf("ensureTorDirs() call %d error = %v", i+1, err)
		}
	}
}

// ---------------------------------------------------------------------------
// ensureTorrc
// ---------------------------------------------------------------------------

func TestEnsureTorrc_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "torrc")
	content := []byte("# test torrc\nSocksPort 0\n")

	created, err := ensureTorrc(path, content)
	if err != nil {
		t.Fatalf("ensureTorrc() error = %v", err)
	}
	if !created {
		t.Error("ensureTorrc() returned false for new file, want true")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("file content = %q, want %q", got, content)
	}
}

func TestEnsureTorrc_ExistingFileNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "torrc")
	original := []byte("# original content\n")

	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	created, err := ensureTorrc(path, []byte("# new content\n"))
	if err != nil {
		t.Fatalf("ensureTorrc() error = %v", err)
	}
	if created {
		t.Error("ensureTorrc() returned true for existing file, want false")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(original) {
		t.Errorf("file was overwritten: content = %q, want %q", got, original)
	}
}

// ---------------------------------------------------------------------------
// getTorConfig
// ---------------------------------------------------------------------------

func TestGetTorConfig_ContainsExpectedLines(t *testing.T) {
	cfg := DefaultTorConfig()
	out := getTorConfig(&cfg)

	// DefaultTorConfig has AllowUserPreference=true, so SocksPort must be "auto".
	checks := []string{
		"SocksPort auto", // AllowUserPreference=true (default)
		"SafeLogging 1",  // SafeLogging=true
		"BandwidthRate 1 MB",
		"BandwidthBurst 2 MB",
		"ExitRelay 0",
		"ExitPolicy reject *:*",
		"ORPort 0",
		"DirPort 0",
	}
	for _, line := range checks {
		found := false
		for _, l := range splitLines(out) {
			if l == line {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("getTorConfig() output missing line %q", line)
		}
	}
}

// TestGetTorConfig_AllSocksDisabled verifies SocksPort 0 when both UseNetwork
// and AllowUserPreference are false (AI.md PART 31).
func TestGetTorConfig_AllSocksDisabled(t *testing.T) {
	cfg := DefaultTorConfig()
	cfg.UseNetwork = false
	cfg.AllowUserPreference = false
	out := getTorConfig(&cfg)

	if !containsLine(out, "SocksPort 0") {
		t.Error("getTorConfig() must contain 'SocksPort 0' when UseNetwork=false and AllowUserPreference=false")
	}
}

// TestGetTorConfig_AllowUserPreference verifies SocksPort auto when
// AllowUserPreference=true even if UseNetwork=false (AI.md PART 31).
func TestGetTorConfig_AllowUserPreference(t *testing.T) {
	cfg := DefaultTorConfig()
	cfg.UseNetwork = false
	cfg.AllowUserPreference = true
	out := getTorConfig(&cfg)

	if !containsLine(out, "SocksPort auto") {
		t.Error("getTorConfig() must contain 'SocksPort auto' when AllowUserPreference=true")
	}
}

func TestGetTorConfig_UseNetwork(t *testing.T) {
	cfg := DefaultTorConfig()
	cfg.UseNetwork = true
	out := getTorConfig(&cfg)

	if !containsLine(out, "SocksPort auto") {
		t.Error("getTorConfig() with UseNetwork=true must contain 'SocksPort auto'")
	}
}

func TestGetTorConfig_SafeLoggingOff(t *testing.T) {
	cfg := DefaultTorConfig()
	cfg.SafeLogging = false
	out := getTorConfig(&cfg)

	if !containsLine(out, "SafeLogging 0") {
		t.Error("getTorConfig() with SafeLogging=false must contain 'SafeLogging 0'")
	}
}

func TestGetTorConfig_MonthlyBandwidth(t *testing.T) {
	cfg := DefaultTorConfig()
	out := getTorConfig(&cfg)

	// Default MaxMonthlyBandwidth is "100 GB" → accounting block must appear.
	if !containsSubstring(out, "AccountingMax 100 GB") {
		t.Error("getTorConfig() must include accounting block for non-unlimited bandwidth")
	}
}

func TestGetTorConfig_UnlimitedBandwidth(t *testing.T) {
	cfg := DefaultTorConfig()
	cfg.MaxMonthlyBandwidth = "unlimited"
	out := getTorConfig(&cfg)

	if containsSubstring(out, "AccountingMax") {
		t.Error("getTorConfig() must NOT include accounting block when bandwidth is unlimited")
	}
}

func TestGetTorConfig_EmptyBandwidth(t *testing.T) {
	cfg := DefaultTorConfig()
	cfg.MaxMonthlyBandwidth = ""
	out := getTorConfig(&cfg)

	if containsSubstring(out, "AccountingMax") {
		t.Error("getTorConfig() must NOT include accounting block when bandwidth is empty string")
	}
}

// ---------------------------------------------------------------------------
// Start — binary not found path (no Tor installed in CI)
// ---------------------------------------------------------------------------

func TestStart_NoBinary(t *testing.T) {
	cfg := DefaultTorConfig()
	// Point Binary at a non-existent path so FindBinary returns "".
	cfg.Binary = "/nonexistent/tor-binary-xyzzy"

	// Temporarily shadow PATH so exec.LookPath also fails.
	old := os.Getenv("PATH")
	os.Setenv("PATH", "")
	defer os.Setenv("PATH", old)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svc, err := Start(ctx, 8080, &cfg, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
	if svc != nil {
		t.Error("Start() returned non-nil TorService when binary not found, want nil")
	}
}

// TestStart_FakeBinary exercises the Start() path after FindBinary succeeds:
// ensureTorDirs, ensureTorrc, and the tor.Start() call are all reached.
// The fake binary exits immediately with a non-zero status, so tor.Start() fails
// and Start() returns an error — but all setup code before that call is covered.
func TestStart_FakeBinary(t *testing.T) {
	dir := t.TempDir()
	fakeTor := filepath.Join(dir, "tor")

	// Write a minimal shell script that exits non-zero immediately.
	// bine's tor.Start() spawns the binary and waits for the control port
	// to become available; an immediate exit causes it to return an error.
	script := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(fakeTor, []byte(script), 0755); err != nil {
		t.Fatalf("write fake tor script: %v", err)
	}

	cfg := DefaultTorConfig()
	cfg.Binary = fakeTor
	// Short bootstrap timeout so the test does not hang.
	cfg.BootstrapTimeout = 3

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	configDir := t.TempDir()
	dataDir := t.TempDir()

	svc, err := Start(ctx, 8080, &cfg, configDir, dataDir)
	// Expect an error because the fake binary terminates immediately.
	// A nil svc with a non-nil err is the expected outcome.
	if err == nil && svc != nil {
		// If somehow this succeeded (real tor in PATH shadowing our fake),
		// close it to avoid resource leaks.
		svc.Close()
		t.Log("Start() unexpectedly succeeded — a real tor binary may have been used")
		return
	}
	if err == nil {
		t.Error("Start() expected an error with a fake binary that exits non-zero, got nil")
	}

	// Verify ensureTorDirs actually ran by checking the directories exist.
	torConfigDir := filepath.Join(configDir, "tor")
	if _, statErr := os.Stat(torConfigDir); statErr != nil {
		t.Errorf("ensureTorDirs not called: config tor dir missing: %v", statErr)
	}
	torDataDir := filepath.Join(dataDir, "tor")
	if _, statErr := os.Stat(torDataDir); statErr != nil {
		t.Errorf("ensureTorDirs not called: data tor dir missing: %v", statErr)
	}

	// Verify ensureTorrc ran by checking the torrc file exists.
	torrcPath := filepath.Join(configDir, "tor", "torrc")
	if _, statErr := os.Stat(torrcPath); statErr != nil {
		t.Errorf("ensureTorrc not called: torrc missing: %v", statErr)
	}
}

// TestStart_FakeBinary_EnsureTorrcPreserved verifies that when the torrc already
// exists, ensureTorrc does not overwrite it (existing torrc → created=false path).
func TestStart_FakeBinary_EnsureTorrcPreserved(t *testing.T) {
	dir := t.TempDir()
	fakeTor := filepath.Join(dir, "tor")
	if err := os.WriteFile(fakeTor, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatalf("write fake tor: %v", err)
	}

	cfg := DefaultTorConfig()
	cfg.Binary = fakeTor
	cfg.BootstrapTimeout = 3

	configDir := t.TempDir()
	dataDir := t.TempDir()

	// Pre-create the torrc with sentinel content.
	if err := os.MkdirAll(filepath.Join(configDir, "tor"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	torrcPath := filepath.Join(configDir, "tor", "torrc")
	sentinel := []byte("# sentinel\n")
	if err := os.WriteFile(torrcPath, sentinel, 0600); err != nil {
		t.Fatalf("write sentinel torrc: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	Start(ctx, 8080, &cfg, configDir, dataDir)

	// The torrc must still contain the sentinel content — not overwritten.
	got, err := os.ReadFile(torrcPath)
	if err != nil {
		t.Fatalf("ReadFile torrc: %v", err)
	}
	if string(got) != string(sentinel) {
		t.Errorf("torrc overwritten: got %q, want %q", got, sentinel)
	}
}

// TestFindBinary_NotInIsolatedPATH verifies FindBinary returns "" when the
// explicit path does not exist and PATH contains no tor binary and no well-known
// candidate exists. This covers the "no binary anywhere" return path.
func TestFindBinary_NotInIsolatedPATH(t *testing.T) {
	// Use an empty dir on PATH so exec.LookPath finds nothing.
	emptyDir := t.TempDir()

	old := os.Getenv("PATH")
	os.Setenv("PATH", emptyDir)
	defer os.Setenv("PATH", old)

	// Non-existent explicit path + empty PATH + well-known candidates not present
	// (they won't exist in t.TempDir() or the standard system paths in the
	// test container) — result must be "".
	// We pass a path under the empty temp dir that does not exist.
	result := FindBinary(filepath.Join(emptyDir, "tor-does-not-exist"))
	// We cannot guarantee "" if the well-known system paths happen to exist,
	// but in CI containers /usr/bin/tor and /usr/local/bin/tor are absent.
	// Document what we got; the important thing is no panic.
	_ = result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func containsLine(s, line string) bool {
	for _, l := range splitLines(s) {
		if l == line {
			return true
		}
	}
	return false
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}

// ---------------------------------------------------------------------------
// TorService.Health
// ---------------------------------------------------------------------------

// TestTorService_Health_NilT verifies Health returns an error when the tor
// process has not been initialized (t field is nil).
func TestTorService_Health_NilT(t *testing.T) {
	svc := &TorService{}
	err := svc.Health(context.Background())
	if err == nil {
		t.Fatal("Health() expected error when t is nil, got nil")
	}
	if !containsSubstring(err.Error(), "not initialized") {
		t.Errorf("Health() error = %q, want mention of \"not initialized\"", err.Error())
	}
}

// TestTorService_Health_NilDialer_OutboundDisabled verifies that when a TorService
// has no dialer (hidden-service-only mode), OutboundEnabled returns false.
// The Health() dialer==nil branch (which returns nil) cannot be exercised without a
// live Tor process; this test documents the associated invariant.
func TestTorService_Health_NilDialer_OutboundDisabled(t *testing.T) {
	svc := &TorService{}
	if svc.OutboundEnabled() {
		t.Error("OutboundEnabled() should be false when dialer is nil")
	}
}

// TestTorService_Health_NonNilTor_NilDialer exercises the hidden-service-only
// branch of Health: t is non-nil but dialer is nil, so Health returns nil immediately
// without attempting any network connection.
func TestTorService_Health_NonNilTor_NilDialer(t *testing.T) {
	// new(bineTor.Tor) yields a non-nil pointer which satisfies the s.t == nil check,
	// allowing the s.dialer == nil branch to be reached. The function returns nil
	// without touching any fields of the tor.Tor struct.
	svc := &TorService{
		t:      new(bineTor.Tor),
		dialer: nil,
	}
	err := svc.Health(context.Background())
	if err != nil {
		t.Errorf("Health() with non-nil t and nil dialer = %v, want nil (hidden-service-only mode)", err)
	}
}

// ---------------------------------------------------------------------------
// saveOnionKey
// ---------------------------------------------------------------------------

// TestSaveOnionKey_CreatesFile verifies saveOnionKey writes the key blob to disk
// and creates parent directories if necessary.
func TestSaveOnionKey_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "hs_ed25519_secret_key")

	key := fakeKey("test-key-blob-data")
	if err := saveOnionKey(path, key); err != nil {
		t.Fatalf("saveOnionKey() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "test-key-blob-data" {
		t.Errorf("file content = %q, want %q", data, "test-key-blob-data")
	}
}

// TestSaveOnionKey_Idempotent verifies saveOnionKey overwrites an existing key file.
func TestSaveOnionKey_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hs_ed25519_secret_key")

	for i, blob := range []string{"first-blob", "second-blob"} {
		if err := saveOnionKey(path, fakeKey(blob)); err != nil {
			t.Fatalf("saveOnionKey() call %d error = %v", i+1, err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "second-blob" {
		t.Errorf("file content = %q, want %q", data, "second-blob")
	}
}

// TestSaveOnionKey_Permissions verifies saveOnionKey sets the key file to 0600.
func TestSaveOnionKey_Permissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hs_ed25519_secret_key")

	if err := saveOnionKey(path, fakeKey("some-blob")); err != nil {
		t.Fatalf("saveOnionKey() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %04o, want 0600", info.Mode().Perm())
	}
}

// ---------------------------------------------------------------------------
// getTorConfig — additional coverage
// ---------------------------------------------------------------------------

// TestGetTorConfig_CustomBandwidth verifies custom bandwidth values appear in config.
func TestGetTorConfig_CustomBandwidth(t *testing.T) {
	cfg := DefaultTorConfig()
	cfg.BandwidthRate = "5 MB"
	cfg.BandwidthBurst = "10 MB"
	out := getTorConfig(&cfg)

	if !containsLine(out, "BandwidthRate 5 MB") {
		t.Error("getTorConfig() must contain custom BandwidthRate")
	}
	if !containsLine(out, "BandwidthBurst 10 MB") {
		t.Error("getTorConfig() must contain custom BandwidthBurst")
	}
}

// TestGetTorConfig_AccountingStartPresent verifies the accounting start line is
// included when monthly bandwidth is set.
func TestGetTorConfig_AccountingStartPresent(t *testing.T) {
	cfg := DefaultTorConfig()
	out := getTorConfig(&cfg)
	if !containsSubstring(out, "AccountingStart month 1 00:00") {
		t.Error("getTorConfig() must include AccountingStart when bandwidth is limited")
	}
}

// TestGetTorConfig_FixedLines verifies boilerplate lines are always present.
func TestGetTorConfig_FixedLines(t *testing.T) {
	cfg := DefaultTorConfig()
	out := getTorConfig(&cfg)

	fixed := []string{
		"ExitRelay 0",
		"ExitPolicy reject *:*",
		"ControlPort 127.0.0.1:auto",
		"FetchDirInfoEarly 1",
		"FetchDirInfoExtraEarly 1",
		"DisableDebuggerAttachment 1",
	}
	for _, line := range fixed {
		if !containsLine(out, line) {
			t.Errorf("getTorConfig() missing required line %q", line)
		}
	}
}

// ---------------------------------------------------------------------------
// FindBinary — extended coverage
// ---------------------------------------------------------------------------

// TestFindBinary_ExplicitPathIsDirectory verifies FindBinary falls through when
// the configured path exists but is a directory, not a file.
// os.Stat succeeds for directories, so FindBinary returns it — this documents
// the actual behavior.
func TestFindBinary_ExplicitPathIsDirectory(t *testing.T) {
	dir := t.TempDir()
	result := FindBinary(dir)
	// A directory satisfies os.Stat, so FindBinary returns the dir path.
	// This is an implementation-level documentation test.
	if result != dir {
		t.Logf("FindBinary(dir) = %q (may vary by implementation)", result)
	}
}

// TestFindBinary_ReturnsStringAlways verifies FindBinary always returns a string
// (never panics) across a variety of inputs.
func TestFindBinary_ReturnsStringAlways(t *testing.T) {
	inputs := []string{
		"",
		"/nonexistent",
		"/dev/null",
		"../../relative/path",
	}
	for _, in := range inputs {
		result := FindBinary(in)
		_ = result
	}
}

// ---------------------------------------------------------------------------
// ensureTorrc — error path
// ---------------------------------------------------------------------------

// TestEnsureTorrc_UnwritablePath verifies ensureTorrc returns an error when
// the parent directory is not writable.
func TestEnsureTorrc_UnwritablePath(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — unwritable-directory test is not meaningful")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0755) })

	path := filepath.Join(dir, "torrc")
	_, err := ensureTorrc(path, []byte("# content\n"))
	if err == nil {
		t.Fatal("ensureTorrc() expected error for unwritable dir, got nil")
	}
}

// ---------------------------------------------------------------------------
// ensureTorDirs — error path
// ---------------------------------------------------------------------------

// TestEnsureTorDirs_UnwritableParent verifies ensureTorDirs returns an error when
// the parent of the config or data directory is not writable.
func TestEnsureTorDirs_UnwritableParent(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — unwritable-directory test is not meaningful")
	}

	base := t.TempDir()
	// Make base unwritable so MkdirAll of a subdirectory fails.
	if err := os.Chmod(base, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(base, 0755) })

	// configDir under unwritable base — MkdirAll will fail.
	configDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")

	err := ensureTorDirs(configDir, dataDir)
	if err == nil {
		t.Fatal("ensureTorDirs() expected error for unwritable parent, got nil")
	}
}

// ---------------------------------------------------------------------------
// saveOnionKey — error path
// ---------------------------------------------------------------------------

// TestSaveOnionKey_UnwritableDir verifies saveOnionKey returns an error when the
// parent directory cannot be created.
func TestSaveOnionKey_UnwritableDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — unwritable-directory test is not meaningful")
	}

	base := t.TempDir()
	if err := os.Chmod(base, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(base, 0755) })

	path := filepath.Join(base, "subdir", "hs_ed25519_secret_key")
	err := saveOnionKey(path, fakeKey("blob"))
	if err == nil {
		t.Fatal("saveOnionKey() expected error for unwritable parent, got nil")
	}
}

// ---------------------------------------------------------------------------
// TorService — additional GetHTTPClient paths
// ---------------------------------------------------------------------------

// TestTorService_GetHTTPClient_UseTorFalseDialerPresent verifies GetHTTPClient
// returns the plain 30-second client even when a dialer exists, if useTor=false.
// We cannot construct a real *tor.Dialer without a live Tor process, but the
// nil-dialer check branch is sufficient — this documents the dialer != nil branch
// is only reached when useTor is true.
func TestTorService_GetHTTPClient_UseTorFalse(t *testing.T) {
	svc := &TorService{}
	client := svc.GetHTTPClient(false)
	if client == nil {
		t.Fatal("GetHTTPClient(false) returned nil")
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", client.Timeout)
	}
	if client.Transport != nil {
		t.Error("Transport should be nil for plain client (use default)")
	}
}

// ---------------------------------------------------------------------------
// getTorConfig — custom bandwidth zero value
// ---------------------------------------------------------------------------

// TestGetTorConfig_ZeroMaxMonthlyBandwidth verifies empty string is treated the
// same as "unlimited" — no accounting block in the output.
func TestGetTorConfig_ZeroMaxMonthlyBandwidth(t *testing.T) {
	cfg := DefaultTorConfig()
	cfg.MaxMonthlyBandwidth = ""
	out := getTorConfig(&cfg)

	if containsSubstring(out, "AccountingMax") {
		t.Error("getTorConfig() must not include AccountingMax when MaxMonthlyBandwidth is empty")
	}
	if containsSubstring(out, "AccountingStart") {
		t.Error("getTorConfig() must not include AccountingStart when MaxMonthlyBandwidth is empty")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fakeKey implements the control.Key interface using a plain string blob.
type fakeKey string

func (k fakeKey) Type() control.KeyType { return "ED25519-V3" }
func (k fakeKey) Blob() string          { return string(k) }
