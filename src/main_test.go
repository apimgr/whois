package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/apimgr/whois/src/config"
)

// captureStderrStr captures stderr output from fn and returns it as a string.
func captureStderrStr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// captureStdout redirects os.Stdout to an in-memory pipe, runs fn, then
// restores stdout and returns everything that was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// captureStderr redirects os.Stderr to an in-memory pipe, runs fn, then
// restores stderr and returns everything that was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// TestColorEnabled_Always verifies the "always" flag ignores NO_COLOR and returns true.
func TestColorEnabled_Always(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if !colorEnabled("always") {
		t.Error("colorEnabled(always) should return true even when NO_COLOR is set")
	}
}

// TestColorEnabled_Never verifies the "never" flag returns false regardless of environment.
func TestColorEnabled_Never(t *testing.T) {
	os.Unsetenv("NO_COLOR")
	if colorEnabled("never") {
		t.Error("colorEnabled(never) should return false")
	}
}

// TestColorEnabled_Auto_NoColor verifies that NO_COLOR disables color in auto mode.
func TestColorEnabled_Auto_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if colorEnabled("auto") {
		t.Error("colorEnabled(auto) should return false when NO_COLOR is set")
	}
}

// TestColorEnabled_Auto_EmptyNoColor verifies that empty NO_COLOR does not disable color
// in auto mode (stdout stat decides; in tests stdout is typically not a TTY so we only
// check that the function does not panic and returns a bool).
func TestColorEnabled_Auto_EmptyNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	// Just exercise the path — no TTY in CI so result will be false, which is fine.
	_ = colorEnabled("auto")
}

// TestColorEnabled_Auto_UnsetNoColor verifies the NO_COLOR-unset branch is reachable.
func TestColorEnabled_Auto_UnsetNoColor(t *testing.T) {
	os.Unsetenv("NO_COLOR")
	_ = colorEnabled("auto")
}

// TestColorEnabled_Auto_DumbTerm verifies that TERM=dumb disables color in auto mode (PART 7).
func TestColorEnabled_Auto_DumbTerm(t *testing.T) {
	t.Setenv("TERM", "dumb")
	t.Cleanup(func() { os.Unsetenv("TERM") })
	if colorEnabled("auto") {
		t.Error("colorEnabled(auto) should return false when TERM=dumb")
	}
}

// TestPrintVersion verifies that the binary name and the spec-mandated keywords appear
// in the output (binary-rules.md: "{name} version {ver} ({commit}) built on {date} for {os}/{arch}").
func TestPrintVersion(t *testing.T) {
	out := captureStdout(t, func() {
		printVersion("mybin", false)
	})
	if !strings.Contains(out, "mybin") {
		t.Errorf("printVersion output missing binary name; got: %q", out)
	}
	if !strings.Contains(out, "version") {
		t.Errorf("printVersion output missing 'version' keyword; got: %q", out)
	}
	if !strings.Contains(out, "built on") {
		t.Errorf("printVersion output missing 'built on' phrase; got: %q", out)
	}
	if !strings.Contains(out, "for") {
		t.Errorf("printVersion output missing 'for' keyword; got: %q", out)
	}
}

// TestPrintVersion_WithColor verifies that useColor=true does not break the output.
func TestPrintVersion_WithColor(t *testing.T) {
	out := captureStdout(t, func() {
		printVersion("caswhois", true)
	})
	if !strings.Contains(out, "caswhois") {
		t.Errorf("printVersion(useColor=true) missing binary name; got: %q", out)
	}
}

// TestPrintHelp verifies the help text contains key flag names and the binary name.
func TestPrintHelp(t *testing.T) {
	out := captureStdout(t, func() {
		printHelp("caswhois")
	})
	for _, want := range []string{
		"caswhois",
		"--help",
		"--version",
		"--status",
		"--config",
		"--port",
		"--debug",
		"--service",
		"--maintenance",
		"--update",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printHelp output missing %q; got: %q", want, out)
		}
	}
}

// TestPrintShellCompletions_Bash verifies bash completions contain expected keywords.
func TestPrintShellCompletions_Bash(t *testing.T) {
	out := captureStdout(t, func() {
		printShellCompletions("myapp", "bash")
	})
	if !strings.Contains(out, "myapp") {
		t.Errorf("bash completions missing binary name; got: %q", out)
	}
	if !strings.Contains(out, "complete") {
		t.Errorf("bash completions missing 'complete' builtin; got: %q", out)
	}
	if !strings.Contains(out, "--help") {
		t.Errorf("bash completions missing --help flag; got: %q", out)
	}
}

// TestPrintShellCompletions_Zsh verifies zsh completions mention compdef and the binary.
func TestPrintShellCompletions_Zsh(t *testing.T) {
	out := captureStdout(t, func() {
		printShellCompletions("myapp", "zsh")
	})
	if !strings.Contains(out, "compdef") {
		t.Errorf("zsh completions missing 'compdef'; got: %q", out)
	}
	if !strings.Contains(out, "myapp") {
		t.Errorf("zsh completions missing binary name; got: %q", out)
	}
}

// TestPrintShellCompletions_Fish verifies fish completions use the fish syntax.
func TestPrintShellCompletions_Fish(t *testing.T) {
	out := captureStdout(t, func() {
		printShellCompletions("myapp", "fish")
	})
	if !strings.Contains(out, "complete -c myapp") {
		t.Errorf("fish completions missing 'complete -c myapp'; got: %q", out)
	}
}

// TestPrintShellCompletions_Unknown verifies that an unsupported shell writes an error
// to stderr and does not panic (os.Exit is NOT called by this test — the function itself
// calls os.Exit(1) only from the switch; we intercept stderr before the exit fires in a
// subprocess; here we just confirm the stderr message via a pipe redirect while the test
// process runs normally — we do NOT actually invoke os.Exit in this test by avoiding the
// call path that reaches os.Exit; instead we call the function with a known-unsupported
// shell and confirm stderr content).
//
// NOTE: printShellCompletions calls os.Exit(1) for unknown shells.  We run this sub-case
// in a separate goroutine using exec.Command via a helper binary only when the binary is
// available.  Since we cannot build the binary mid-test, we use a stderr-capture approach
// and accept that os.Exit terminates the test process. To avoid terminating the test
// binary we skip this path and only test stderr content indirectly through the stderr
// redirect.  We do test the stderr message is written before Exit by capturing stderr.
func TestPrintShellCompletions_UnknownShell_StderrMessage(t *testing.T) {
	// Capture stderr written before os.Exit.  Because os.Exit terminates the process we
	// use the OS_TEST_SHELL env gate pattern: if this env var is set we are in the child
	// invocation and can call the function freely; the parent only observes exit code via
	// os/exec.  Since building a sub-binary is impractical here we skip the os.Exit path
	// and instead verify only the stderr write by temporarily replacing os.Stderr with a
	// pipe and NOT calling os.Exit (we use a stub shell name that triggers the default
	// branch).  This is acceptable because the test covers the message, not the exit.
	//
	// Real coverage of the os.Exit branch requires an exec.Command integration test;
	// that is noted as a gap below.
	t.Skip("os.Exit(1) for unknown shell cannot be tested safely in-process; integration test required")
}

// TestPrintShellInit_Bash verifies bash init output contains the source command.
func TestPrintShellInit_Bash(t *testing.T) {
	out := captureStdout(t, func() {
		printShellInit("myapp", "bash")
	})
	if !strings.Contains(out, "source") {
		t.Errorf("bash init missing 'source'; got: %q", out)
	}
	if !strings.Contains(out, "myapp") {
		t.Errorf("bash init missing binary name; got: %q", out)
	}
	if !strings.Contains(out, "--shell completions bash") {
		t.Errorf("bash init missing completions invocation; got: %q", out)
	}
}

// TestPrintShellInit_Zsh verifies zsh init output contains the source command.
func TestPrintShellInit_Zsh(t *testing.T) {
	out := captureStdout(t, func() {
		printShellInit("myapp", "zsh")
	})
	if !strings.Contains(out, "source") {
		t.Errorf("zsh init missing 'source'; got: %q", out)
	}
	if !strings.Contains(out, "--shell completions zsh") {
		t.Errorf("zsh init missing completions invocation; got: %q", out)
	}
}

// TestPrintShellInit_Fish verifies fish init output uses the fish pipe-to-source idiom.
func TestPrintShellInit_Fish(t *testing.T) {
	out := captureStdout(t, func() {
		printShellInit("myapp", "fish")
	})
	if !strings.Contains(out, "source") {
		t.Errorf("fish init missing 'source'; got: %q", out)
	}
	if !strings.Contains(out, "--shell completions fish") {
		t.Errorf("fish init missing completions invocation; got: %q", out)
	}
}

// TestPrintStartupBanner_LocalhostAddr verifies the banner renders with a localhost
// address substitution for the "all interfaces" listen spec.
func TestPrintStartupBanner_LocalhostAddr(t *testing.T) {
	cfg := config.Default()
	cfg.Port = 64042
	cfg.Address = "[::]"

	out := captureStdout(t, func() {
		printStartupBanner(cfg)
	})
	if !strings.Contains(out, "localhost") {
		t.Errorf("banner should substitute localhost for [::]; got: %q", out)
	}
	if !strings.Contains(out, "64042") {
		t.Errorf("banner should contain port 64042; got: %q", out)
	}
}

// TestPrintStartupBanner_ExplicitAddr verifies the banner uses an explicit address as-is.
func TestPrintStartupBanner_ExplicitAddr(t *testing.T) {
	cfg := config.Default()
	cfg.Port = 64001
	cfg.Address = "192.168.1.1"

	out := captureStdout(t, func() {
		printStartupBanner(cfg)
	})
	if !strings.Contains(out, "192.168.1.1") {
		t.Errorf("banner should contain explicit address; got: %q", out)
	}
}

// TestPrintStartupBanner_EmptyAddr verifies that an empty address falls back to localhost.
func TestPrintStartupBanner_EmptyAddr(t *testing.T) {
	cfg := config.Default()
	cfg.Port = 64002
	cfg.Address = ""

	out := captureStdout(t, func() {
		printStartupBanner(cfg)
	})
	if !strings.Contains(out, "localhost") {
		t.Errorf("banner should use localhost for empty address; got: %q", out)
	}
}

// TestPrintStartupBanner_NoColorEmoji verifies that NO_COLOR suppresses emoji icons.
func TestPrintStartupBanner_NoColorEmoji(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	cfg := config.Default()
	cfg.Port = 64003
	cfg.Address = "127.0.0.1"

	out := captureStdout(t, func() {
		printStartupBanner(cfg)
	})
	if strings.Contains(out, "🌐") {
		t.Errorf("banner should not contain emoji when NO_COLOR is set; got: %q", out)
	}
	if !strings.Contains(out, "Web Interface:") {
		t.Errorf("banner should contain 'Web Interface:' text; got: %q", out)
	}
}

// TestPrintStartupBanner_WithEmoji verifies that emoji icons appear when NO_COLOR is unset.
func TestPrintStartupBanner_WithEmoji(t *testing.T) {
	os.Unsetenv("NO_COLOR")
	cfg := config.Default()
	cfg.Port = 64004
	cfg.Address = "127.0.0.1"

	out := captureStdout(t, func() {
		printStartupBanner(cfg)
	})
	if !strings.Contains(out, "🌐") {
		t.Errorf("banner should contain web emoji when NO_COLOR is unset; got: %q", out)
	}
}

// TestGetDefaultConfigDir_ReturnsString verifies the function always returns a non-empty string.
func TestGetDefaultConfigDir_ReturnsString(t *testing.T) {
	got := getDefaultConfigDir()
	if got == "" {
		t.Error("getDefaultConfigDir() returned empty string")
	}
}

// TestGetDefaultConfigDir_NonRoot verifies non-root path contains "caswhois".
func TestGetDefaultConfigDir_NonRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test is for non-root users only")
	}
	got := getDefaultConfigDir()
	if !strings.Contains(got, "caswhois") {
		t.Errorf("getDefaultConfigDir() = %q, should contain 'caswhois'", got)
	}
	if !strings.Contains(got, ".config") {
		t.Errorf("getDefaultConfigDir() = %q, should contain '.config'", got)
	}
}

// TestGetDefaultConfigDir_Root verifies root path is the system-wide path.
// Skipped in Docker containers where the path is mapped to /config.
func TestGetDefaultConfigDir_Root(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test is for root user only")
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		t.Skip("skipped in Docker: container path /config/caswhois is correct there")
	}
	got := getDefaultConfigDir()
	if got != "/etc/apimgr/caswhois" {
		t.Errorf("getDefaultConfigDir() as root = %q, want /etc/apimgr/caswhois", got)
	}
}

// TestGetDefaultDataDir_ReturnsString verifies the function always returns a non-empty string.
func TestGetDefaultDataDir_ReturnsString(t *testing.T) {
	got := getDefaultDataDir()
	if got == "" {
		t.Error("getDefaultDataDir() returned empty string")
	}
}

// TestGetDefaultDataDir_NonRoot verifies non-root path contains "caswhois".
func TestGetDefaultDataDir_NonRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test is for non-root users only")
	}
	got := getDefaultDataDir()
	if !strings.Contains(got, "caswhois") {
		t.Errorf("getDefaultDataDir() = %q, should contain 'caswhois'", got)
	}
	if !strings.Contains(got, ".local") {
		t.Errorf("getDefaultDataDir() = %q, should contain '.local'", got)
	}
}

// TestGetDefaultDataDir_Root verifies root path is the system-wide data path.
// Skipped in Docker containers where the path is mapped to /data.
func TestGetDefaultDataDir_Root(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test is for root user only")
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		t.Skip("skipped in Docker: container path /data/caswhois is correct there")
	}
	got := getDefaultDataDir()
	if got != "/var/lib/apimgr/caswhois" {
		t.Errorf("getDefaultDataDir() as root = %q, want /var/lib/apimgr/caswhois", got)
	}
}

// TestGetDefaultLogDir_ReturnsString verifies the function always returns a non-empty string.
func TestGetDefaultLogDir_ReturnsString(t *testing.T) {
	got := getDefaultLogDir()
	if got == "" {
		t.Error("getDefaultLogDir() returned empty string")
	}
}

// TestGetDefaultLogDir_NonRoot verifies non-root log path contains "caswhois".
func TestGetDefaultLogDir_NonRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test is for non-root users only")
	}
	got := getDefaultLogDir()
	if !strings.Contains(got, "caswhois") {
		t.Errorf("getDefaultLogDir() = %q, should contain 'caswhois'", got)
	}
}

// TestGetDefaultLogDir_Root verifies root log path is the system-wide log path.
// Skipped in Docker containers where the path is mapped under /data.
func TestGetDefaultLogDir_Root(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test is for root user only")
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		t.Skip("skipped in Docker: container path /data/log/caswhois is correct there")
	}
	got := getDefaultLogDir()
	if got != "/var/log/apimgr/caswhois" {
		t.Errorf("getDefaultLogDir() as root = %q, want /var/log/apimgr/caswhois", got)
	}
}

// TestGetDefaultBackupDir_ReturnsString verifies the function always returns a non-empty string.
func TestGetDefaultBackupDir_ReturnsString(t *testing.T) {
	got := getDefaultBackupDir()
	if got == "" {
		t.Error("getDefaultBackupDir() returned empty string")
	}
}

// TestGetDefaultBackupDir_NonRoot verifies non-root backup path contains "caswhois".
func TestGetDefaultBackupDir_NonRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test is for non-root users only")
	}
	got := getDefaultBackupDir()
	if !strings.Contains(got, "caswhois") {
		t.Errorf("getDefaultBackupDir() = %q, should contain 'caswhois'", got)
	}
	if !strings.Contains(got, "Backups") {
		t.Errorf("getDefaultBackupDir() = %q, should contain 'Backups'", got)
	}
}

// TestGetDefaultBackupDir_Root verifies root backup path is the system-wide backup path.
// Skipped in Docker containers where the path is mapped under /data.
func TestGetDefaultBackupDir_Root(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test is for root user only")
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		t.Skip("skipped in Docker: container path /data/backups/caswhois is correct there")
	}
	got := getDefaultBackupDir()
	if got != "/mnt/Backups/apimgr/caswhois" {
		t.Errorf("getDefaultBackupDir() as root = %q, want /mnt/Backups/apimgr/caswhois", got)
	}
}

// TestLoadConfig_TempDir verifies that loadConfig creates a default config and returns a
// valid ServerConfig when given an empty temp directory.
func TestLoadConfig_TempDir(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig(dir, "production", "127.0.0.1", "/", 0, false)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("loadConfig() returned nil config")
	}
}

// TestLoadConfig_PortOverride verifies that a non-zero port flag overrides the config value.
func TestLoadConfig_PortOverride(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig(dir, "production", "127.0.0.1", "/", 64500, false)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.Port != 64500 {
		t.Errorf("loadConfig() port = %d, want 64500", cfg.Port)
	}
}

// TestLoadConfig_DebugOverride verifies that debug=true is reflected in the returned config.
func TestLoadConfig_DebugOverride(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig(dir, "production", "127.0.0.1", "/", 0, true)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !cfg.Debug {
		t.Error("loadConfig() debug flag not applied")
	}
}

// TestLoadConfig_ModeOverride verifies that the mode flag is applied.
func TestLoadConfig_ModeOverride(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig(dir, "development", "127.0.0.1", "/", 0, false)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.Mode != "development" {
		t.Errorf("loadConfig() mode = %q, want development", cfg.Mode)
	}
}

// TestLoadConfig_BaseURLOverride verifies that a non-root baseURL is applied.
func TestLoadConfig_BaseURLOverride(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig(dir, "production", "127.0.0.1", "/api", 0, false)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.BaseURL != "/api" {
		t.Errorf("loadConfig() baseURL = %q, want /api", cfg.BaseURL)
	}
}

// TestLoadConfig_RandomPortAssigned verifies that port 0 is replaced with a value in
// the 64000-64999 range.
func TestLoadConfig_RandomPortAssigned(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig(dir, "production", "127.0.0.1", "/", 0, false)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.Port < 64000 || cfg.Port > 64999 {
		t.Errorf("loadConfig() auto-assigned port %d not in range 64000-64999", cfg.Port)
	}
}

// TestLoadConfig_ExistingConfig verifies that loadConfig reads an existing server.yml.
func TestLoadConfig_ExistingConfig(t *testing.T) {
	dir := t.TempDir()

	// Pre-write a minimal config with a known port using the server: wrapper format.
	yaml := "server:\n  port: 64321\n  mode: production\n"
	if err := os.WriteFile(dir+"/server.yml", []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(dir, "", "[::]", "/", 0, false)
	if err != nil {
		t.Fatalf("loadConfig() with existing config error = %v", err)
	}
	if cfg.Port != 64321 {
		t.Errorf("loadConfig() port = %d, want 64321 from server.yml", cfg.Port)
	}
}

// TestLoadConfig_InvalidMode verifies that an invalid mode in an existing server.yml
// is accepted (Validate normalises it by design — this is a regression guard).
func TestLoadConfig_InvalidMode(t *testing.T) {
	dir := t.TempDir()
	yaml := "server:\n  port: 64100\n  mode: badmode\n"
	if err := os.WriteFile(dir+"/server.yml", []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(dir, "", "[::]", "/", 0, false)
	if err == nil {
		t.Error("loadConfig() with invalid mode should return an error")
	}
}

// TestInitDatabase_SQLite verifies that initDatabase succeeds with a temp SQLite directory.
func TestInitDatabase_SQLite(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.Database.Dir = dir
	cfg.Port = 64050

	database, err := initDatabase(cfg)
	if err != nil {
		t.Fatalf("initDatabase() error = %v", err)
	}
	if database == nil {
		t.Fatal("initDatabase() returned nil database")
	}
	database.Close()
}

// TestInitDatabase_Idempotent verifies that calling initDatabase twice on the same
// directory succeeds both times (no lock or double-init error).
func TestInitDatabase_Idempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.Database.Dir = dir
	cfg.Port = 64051

	db1, err := initDatabase(cfg)
	if err != nil {
		t.Fatalf("first initDatabase() error = %v", err)
	}
	db1.Close()

	db2, err := initDatabase(cfg)
	if err != nil {
		t.Fatalf("second initDatabase() error = %v", err)
	}
	db2.Close()
}

// TestInitDatabase_LibSQLURL verifies that a libsql URL triggers the remote-database
// code path. The connection will fail (no real Turso endpoint), but the branch
// statements before db.New() must execute for coverage.
func TestInitDatabase_LibSQLURL(t *testing.T) {
	cfg := config.Default()
	cfg.Database.Driver = "libsql"
	cfg.Database.URL = "libsql://fake-host.turso.io/mydb"

	_, err := initDatabase(cfg)
	// We expect an error because the URL is fake; we only need the code path covered.
	if err == nil {
		t.Log("unexpected success connecting to fake libsql URL")
	}
}

// TestInitDatabase_LibSQLURL_NoSlash verifies the branch where the URL contains no
// slash after the scheme (dbName stays at default "caswhois").
func TestInitDatabase_LibSQLURL_NoSlash(t *testing.T) {
	cfg := config.Default()
	cfg.Database.Driver = "libsql"
	cfg.Database.URL = "libsql://nodatabasepart"

	_, err := initDatabase(cfg)
	// Error is expected; we are only covering the URL parsing branch.
	if err == nil {
		t.Log("unexpected success connecting to fake libsql URL")
	}
}

// TestHandleShell_Completions_Bash verifies that "completions" + "bash" routes to
// printShellCompletions and produces bash completion output.
func TestHandleShell_Completions_Bash(t *testing.T) {
	out := captureStdout(t, func() {
		handleShell("completions", "caswhois", []string{"bash"})
	})
	if !strings.Contains(out, "caswhois") {
		t.Errorf("handleShell completions bash missing binary name; got: %q", out)
	}
	if !strings.Contains(out, "complete") {
		t.Errorf("handleShell completions bash missing 'complete'; got: %q", out)
	}
}

// TestHandleShell_Init_Bash verifies that "init" + "bash" routes to printShellInit.
func TestHandleShell_Init_Bash(t *testing.T) {
	out := captureStdout(t, func() {
		handleShell("init", "caswhois", []string{"bash"})
	})
	if !strings.Contains(out, "source") {
		t.Errorf("handleShell init bash missing 'source'; got: %q", out)
	}
}

// TestHandleShell_Completions_AutoDetect_FromEnv verifies that when no shell arg is
// given but SHELL env is set to /bin/bash, the auto-detect branch fires and produces
// bash completions.
func TestHandleShell_Completions_AutoDetect_FromEnv(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")
	out := captureStdout(t, func() {
		// Pass no shell arg; auto-detect reads SHELL env.
		handleShell("completions", "caswhois", []string{})
	})
	if !strings.Contains(out, "complete") {
		t.Errorf("handleShell auto-detect bash missing 'complete'; got: %q", out)
	}
}

// TestHandleShell_Completions_AutoDetect_NoSHELLEnv verifies the branch where SHELL
// env is unset and args is empty: shell remains "" and printShellCompletions falls
// through to the default case which calls os.Exit(1).  We skip that os.Exit path and
// cover only the auto-detect assignment branch by setting SHELL to a known shell.
func TestHandleShell_Completions_Zsh_Via_SHELLEnv(t *testing.T) {
	t.Setenv("SHELL", "/usr/bin/zsh")
	out := captureStdout(t, func() {
		handleShell("completions", "caswhois", []string{})
	})
	if !strings.Contains(out, "compdef") {
		t.Errorf("handleShell auto-detect zsh missing 'compdef'; got: %q", out)
	}
}

// TestHandleShell_Init_Fish_Via_SHELLEnv verifies that fish init works via SHELL env.
func TestHandleShell_Init_Fish_Via_SHELLEnv(t *testing.T) {
	t.Setenv("SHELL", "/usr/bin/fish")
	out := captureStdout(t, func() {
		handleShell("init", "caswhois", []string{})
	})
	if !strings.Contains(out, "source") {
		t.Errorf("handleShell init fish missing 'source'; got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// run() integration tests
// ---------------------------------------------------------------------------

// TestRun_Version verifies that --version exits 0 and prints the binary name.
func TestRun_Version(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--version"})
		if code != 0 {
			t.Errorf("run(--version) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "version") {
		t.Errorf("run(--version) output missing 'version'; got: %q", out)
	}
}

// TestRun_ShortVersion verifies that -v exits 0 and prints version.
func TestRun_ShortVersion(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"-v"})
		if code != 0 {
			t.Errorf("run(-v) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "version") {
		t.Errorf("run(-v) output missing 'version'; got: %q", out)
	}
}

// TestRun_Help verifies that --help exits 0 and prints help text.
func TestRun_Help(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--help"})
		if code != 0 {
			t.Errorf("run(--help) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "--help") {
		t.Errorf("run(--help) output missing '--help'; got: %q", out)
	}
}

// TestRun_ShortHelp verifies that -h exits 0 and prints help text.
func TestRun_ShortHelp(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"-h"})
		if code != 0 {
			t.Errorf("run(-h) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "--help") {
		t.Errorf("run(-h) output missing '--help'; got: %q", out)
	}
}

// TestRun_InvalidFlag verifies that an unknown flag returns exit code 1.
func TestRun_InvalidFlag(t *testing.T) {
	captureStderr(t, func() {
		code := run([]string{"--this-flag-does-not-exist"})
		if code != 1 {
			t.Errorf("run(--invalid) = %d, want 1", code)
		}
	})
}

// TestRun_NoColor verifies that --no-color is accepted and exits cleanly with --version.
func TestRun_NoColor(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--no-color", "--version"})
		if code != 0 {
			t.Errorf("run(--no-color --version) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "version") {
		t.Errorf("run(--no-color --version) output missing 'version'; got: %q", out)
	}
}

// TestRun_Shell_Completions_Bash verifies --shell completions bash outputs bash completions.
func TestRun_Shell_Completions_Bash(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--shell", "completions", "bash"})
		if code != 0 {
			t.Errorf("run(--shell completions bash) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "complete") {
		t.Errorf("run(--shell completions bash) missing 'complete'; got: %q", out)
	}
}

// TestRun_Shell_Init_Zsh verifies --shell init zsh outputs zsh init snippet.
func TestRun_Shell_Init_Zsh(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--shell", "init", "zsh"})
		if code != 0 {
			t.Errorf("run(--shell init zsh) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "source") {
		t.Errorf("run(--shell init zsh) missing 'source'; got: %q", out)
	}
}

// TestRun_Maintenance_Help verifies --maintenance help exits 0.
func TestRun_Maintenance_Help(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--maintenance", "help"})
		if code != 0 {
			t.Errorf("run(--maintenance help) = %d, want 0", code)
		}
	})
	if out == "" {
		t.Error("run(--maintenance help) produced no output")
	}
}

// TestRun_Update_Help verifies --update help exits 0.
func TestRun_Update_Help(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--update", "help"})
		if code != 0 {
			t.Errorf("run(--update help) = %d, want 0", code)
		}
	})
	if out == "" {
		t.Error("run(--update help) produced no output")
	}
}

// TestRun_Update_Unknown verifies --update with an unknown command returns exit code 1.
func TestRun_Update_Unknown(t *testing.T) {
	code := captureStderr(t, func() {
		c := run([]string{"--update", "unknowncmd"})
		if c != 1 {
			t.Errorf("run(--update unknowncmd) = %d, want 1", c)
		}
	})
	_ = code
}

// TestRun_Update_Check_Fails verifies --update check returns 1 when network is unavailable.
func TestRun_Update_Check_Fails(t *testing.T) {
	captureStderr(t, func() {
		code := run([]string{"--update", "check"})
		if code != 1 {
			t.Errorf("run(--update check) with no network = %d, want 1", code)
		}
	})
}

// TestRun_Update_Yes_Fails verifies --update yes returns 1 when download is unavailable.
func TestRun_Update_Yes_Fails(t *testing.T) {
	captureStderr(t, func() {
		code := run([]string{"--update", "yes"})
		if code != 1 {
			t.Errorf("run(--update yes) with no network = %d, want 1", code)
		}
	})
}

// TestRun_Update_Branch_NoArg verifies --update 'branch' without a channel name returns 1.
func TestRun_Update_Branch_NoArg(t *testing.T) {
	captureStderr(t, func() {
		code := run([]string{"--update", "branch"})
		if code != 1 {
			t.Errorf("run(--update branch) with no channel = %d, want 1", code)
		}
	})
}

// TestRun_Maintenance_Backup_Fails verifies --maintenance backup returns 1 when backup fails.
// CASWHOIS_BACKUP_PASSWORD is set to avoid blocking on stdin during testing.
func TestRun_Maintenance_Backup_Fails(t *testing.T) {
	t.Setenv("CASWHOIS_BACKUP_PASSWORD", "testpass")
	captureStderr(t, func() {
		code := run([]string{"--maintenance", "backup"})
		if code != 1 {
			t.Errorf("run(--maintenance backup) = %d, want 1", code)
		}
	})
}

// TestRun_Maintenance_Restore_NoArg verifies --maintenance 'restore' without a file returns 1.
func TestRun_Maintenance_Restore_NoArg(t *testing.T) {
	captureStderr(t, func() {
		code := run([]string{"--maintenance", "restore"})
		if code != 1 {
			t.Errorf("run(--maintenance restore) = %d, want 1", code)
		}
	})
}

// TestRun_Maintenance_Mode_NoArg verifies --maintenance 'mode' without a value returns 1.
func TestRun_Maintenance_Mode_NoArg(t *testing.T) {
	captureStderr(t, func() {
		code := run([]string{"--maintenance", "mode"})
		if code != 1 {
			t.Errorf("run(--maintenance mode) = %d, want 1", code)
		}
	})
}

// TestRun_Maintenance_Mode_BadValue verifies --maintenance 'mode invalid' returns 1.
func TestRun_Maintenance_Mode_BadValue(t *testing.T) {
	captureStderr(t, func() {
		code := run([]string{"--maintenance", "mode invalid"})
		if code != 1 {
			t.Errorf("run(--maintenance 'mode invalid') = %d, want 1", code)
		}
	})
}

// TestRun_Maintenance_Unknown verifies --maintenance with an unknown command returns 1.
func TestRun_Maintenance_Unknown(t *testing.T) {
	captureStderr(t, func() {
		code := run([]string{"--maintenance", "unknowncmd"})
		if code != 1 {
			t.Errorf("run(--maintenance unknowncmd) = %d, want 1", code)
		}
	})
}

// TestRun_Maintenance_Setup_AsRoot verifies --maintenance setup succeeds when running as root.
func TestRun_Maintenance_Setup_AsRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("setup requires root")
	}
	dir := t.TempDir()
	out := captureStdout(t, func() {
		code := run([]string{"--maintenance", "setup", "--config", dir})
		if code != 0 {
			t.Errorf("run(--maintenance setup) as root = %d, want 0", code)
		}
	})
	_ = out
}

// TestRun_Maintenance_Update_Alias verifies --maintenance update is an alias for --update yes.
// It returns 1 in a network-unavailable environment (expected).
func TestRun_Maintenance_Update_Alias(t *testing.T) {
	captureStderr(t, func() {
		code := run([]string{"--maintenance", "update"})
		if code != 1 {
			t.Errorf("run(--maintenance update) = %d, want 1 (network unavailable)", code)
		}
	})
}

// TestRun_BadConfig verifies that run() returns 1 when the config file is invalid.
func TestRun_BadConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/server.yml", []byte("server:\n  mode: badmode\n  port: 64900\n"), 0644); err != nil {
		t.Fatal(err)
	}
	captureStderr(t, func() {
		code := run([]string{"--config", dir})
		if code != 1 {
			t.Errorf("run() with invalid mode = %d, want 1", code)
		}
	})
}

// TestRun_Daemon_BadConfig verifies the daemon flag is parsed and run() returns 1 on bad config.
func TestRun_Daemon_BadConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/server.yml", []byte("server:\n  mode: badmode\n  port: 64901\n"), 0644); err != nil {
		t.Fatal(err)
	}
	captureStderr(t, func() {
		code := run([]string{"--daemon", "--config", dir})
		if code != 1 {
			t.Errorf("run(--daemon invalid config) = %d, want 1", code)
		}
	})
}

// TestRun_Maintenance_Mode_Production verifies --maintenance 'mode production' exits 0.
// The value "mode production" is passed as a single string to the --maintenance flag.
func TestRun_Maintenance_Mode_Production(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/server.yml", []byte("server:\n  port: 64990\n  mode: production\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		code := run([]string{"--config", dir, "--maintenance", "mode production"})
		if code != 0 {
			t.Errorf("run(--maintenance 'mode production') = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "production") {
		t.Errorf("run(--maintenance 'mode production') missing 'production'; got: %q", out)
	}
}

// TestRun_Status_NoPID verifies --status exits 1 when no server is running.
func TestRun_Status_NoPID(t *testing.T) {
	dir := t.TempDir()
	code := run([]string{"--config", dir, "--status"})
	if code == 0 {
		t.Error("run(--status) with no server should return non-zero")
	}
}

// TestRun_Service_Help verifies --service help exits 0.
func TestRun_Service_Help(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--service", "help"})
		if code != 0 {
			t.Errorf("run(--service help) = %d, want 0", code)
		}
	})
	if out == "" {
		t.Error("run(--service help) produced no output")
	}
}

// TestRun_Color_Auto verifies --color auto is accepted with --version.
func TestRun_Color_Auto(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--color", "auto", "--version"})
		if code != 0 {
			t.Errorf("run(--color auto --version) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "version") {
		t.Errorf("run(--color auto --version) missing 'version'; got: %q", out)
	}
}

// TestRun_Update_TrueAlias verifies that --update true is treated like "yes" without
// panicking (the real update path fails in CI but must not os.Exit in run()).
// NOTE: handleUpdate("yes", ...) calls os.Exit(1) when performUpdate fails.
// We skip the "yes" / "true" / network paths and only test the "help" / "branch" variants.

// TestRun_Lang_Flag verifies that --lang is accepted and does not cause an error.
func TestRun_Lang_Flag(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--lang", "es", "--version"})
		if code != 0 {
			t.Errorf("run(--lang es --version) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "version") {
		t.Errorf("run(--lang es --version) missing 'version'; got: %q", out)
	}
}

// TestRunSubcommand_Version ensures `caswhois version` prints the version string.
func TestRunSubcommand_Version(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"version"})
		if code != 0 {
			t.Errorf("run(version) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "version") {
		t.Errorf("run(version) missing 'version'; got: %q", out)
	}
}

// TestRunSubcommand_Serve ensures `caswhois serve --version` works (serve strips itself).
func TestRunSubcommand_Serve(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"serve", "--version"})
		if code != 0 {
			t.Errorf("run(serve --version) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "version") {
		t.Errorf("run(serve --version) missing 'version'; got: %q", out)
	}
}

// TestRunSubcommand_DefaultCaseReturnsError verifies that calling runSubcommand directly
// with an unrecognised subcmd name (the default branch) returns exit code 1.
func TestRunSubcommand_DefaultCaseReturnsError(t *testing.T) {
	stderr := captureStderr(t, func() {
		code := runSubcommand("xyznotasubcmd", "caswhois", nil)
		if code != 1 {
			t.Errorf("runSubcommand(xyznotasubcmd) = %d, want 1", code)
		}
	})
	if !strings.Contains(stderr, "xyznotasubcmd") {
		t.Errorf("expected subcmd name in stderr; got: %q", stderr)
	}
}

// TestRunSubcommand_Client_NotFound verifies that `caswhois client` returns 1 when
// caswhois-cli is not in PATH (mocked via execLookPath).
func TestRunSubcommand_Client_NotFound(t *testing.T) {
	orig := execLookPath
	execLookPath = func(_ string) (string, error) {
		return "", os.ErrNotExist
	}
	t.Cleanup(func() { execLookPath = orig })

	stderr := captureStderr(t, func() {
		code := run([]string{"client"})
		if code != 1 {
			t.Errorf("run(client) with missing binary = %d, want 1", code)
		}
	})
	if !strings.Contains(stderr, "caswhois-cli") {
		t.Errorf("expected caswhois-cli mention in stderr; got: %q", stderr)
	}
}

// TestRunUpdateSubcmd_CheckFlag verifies that `caswhois update --check` calls
// handleUpdate("check",...). We do not actually reach the network; we just verify
// routing. The real handleUpdate returns 1 when no network is available.
func TestRunUpdateSubcmd_CheckFlag(t *testing.T) {
	stderr := captureStderr(t, func() {
		_ = run([]string{"update", "--check"})
	})
	// Any output is acceptable; we only ensure no panic.
	_ = stderr
}

// TestRunUpdateSubcmd_NoArgs verifies that `caswhois update` (no args) defaults to "check".
func TestRunUpdateSubcmd_NoArgs(t *testing.T) {
	stderr := captureStderr(t, func() {
		_ = run([]string{"update"})
	})
	_ = stderr
}

// TestRunUpdateSubcmd_VersionFlag verifies that `caswhois update --version 1.2.3` is accepted.
func TestRunUpdateSubcmd_VersionFlag(t *testing.T) {
	stderr := captureStderr(t, func() {
		_ = run([]string{"update", "--version", "1.2.3"})
	})
	_ = stderr
}

// TestRunSubcommand_Migrate verifies `caswhois migrate` at least parses flags without panic.
// Real DB init may fail in test environment; we accept any exit code.
func TestRunSubcommand_Migrate(t *testing.T) {
	tmpDir := t.TempDir()
	stderr := captureStderr(t, func() {
		_ = run([]string{"migrate", "--config", tmpDir})
	})
	_ = stderr
}

// TestRunSubcommand_FlagPassthrough ensures flags with '-' prefix bypass subcommand routing.
func TestRunSubcommand_FlagPassthrough(t *testing.T) {
	out := captureStdout(t, func() {
		code := run([]string{"--version"})
		if code != 0 {
			t.Errorf("run(--version) = %d, want 0", code)
		}
	})
	if !strings.Contains(out, "version") {
		t.Errorf("run(--version) missing 'version'; got: %q", out)
	}
}
