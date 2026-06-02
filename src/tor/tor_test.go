package tor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
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
		MaxStreamsPerCircuit:       50,
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

	checks := []string{
		"SocksPort 0",        // UseNetwork=false
		"SafeLogging 1",      // SafeLogging=true
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
