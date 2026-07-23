package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConfigPathNonEmpty verifies ConfigPath always returns a non-empty string.
func TestConfigPathNonEmpty(t *testing.T) {
	got := ConfigPath()
	if got == "" {
		t.Error("ConfigPath() returned empty string")
	}
}

// TestConfigPathXDGConfigHome verifies XDG_CONFIG_HOME is honoured on non-Windows.
func TestConfigPathXDGConfigHome(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	got := ConfigPath()
	want := filepath.Join(dir, "apimgr", "caswhois", "cli.yml")
	if got != want {
		t.Errorf("ConfigPath() = %q, want %q", got, want)
	}
}

// TestConfigPathXDGEmpty verifies the HOME/.config fallback when XDG_CONFIG_HOME is unset.
func TestConfigPathXDGEmpty(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	t.Setenv("XDG_CONFIG_HOME", "")

	got := ConfigPath()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("os.UserHomeDir() error: %v", err)
	}
	want := filepath.Join(home, ".config", "apimgr", "caswhois", "cli.yml")
	if got != want {
		t.Errorf("ConfigPath() with empty XDG_CONFIG_HOME = %q, want %q", got, want)
	}
}

// TestConfigPathWindowsAPPDATA verifies the Windows APPDATA branch via injection.
func TestConfigPathWindowsAPPDATA(t *testing.T) {
	old := getOS
	getOS = func() string { return "windows" }
	defer func() { getOS = old }()

	t.Setenv("APPDATA", `C:\Users\TestUser\AppData\Roaming`)
	got := ConfigPath()
	if got == "" {
		t.Error("ConfigPath() returned empty string on Windows path")
	}
}

// TestConfigPathWindowsUSERPROFILE verifies the APPDATA-empty fallback to USERPROFILE.
func TestConfigPathWindowsUSERPROFILE(t *testing.T) {
	old := getOS
	getOS = func() string { return "windows" }
	defer func() { getOS = old }()

	t.Setenv("APPDATA", "")
	t.Setenv("USERPROFILE", `C:\Users\TestUser`)
	got := ConfigPath()
	if got == "" {
		t.Error("ConfigPath() returned empty string when falling back to USERPROFILE")
	}
}

// TestLoadNoFileReturnsDefaults verifies Load returns defaults when no config file exists.
func TestLoadNoFileReturnsDefaults(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
	if cfg.Format != "table" {
		t.Errorf("Load().Format = %q, want %q", cfg.Format, "table")
	}
}

// TestLoadValidYAML verifies Load parses a well-formed cli.yml.
func TestLoadValidYAML(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "apimgr", "caswhois")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	content := "server: https://whois.example.com\ntoken: tok_abc123\nformat: json\nlang: en\nupdate_channel: beta\ndebug: true\n"
	if err := os.WriteFile(filepath.Join(configDir, "cli.yml"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	checks := []struct {
		field string
		got   string
		want  string
	}{
		{"Server", cfg.Server, "https://whois.example.com"},
		{"Token", cfg.Token, "tok_abc123"},
		{"Format", cfg.Format, "json"},
		{"Lang", cfg.Lang, "en"},
		{"UpdateChannel", cfg.UpdateChannel, "beta"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("Load().%s = %q, want %q", c.field, c.got, c.want)
		}
	}
	if !cfg.Debug {
		t.Error("Load().Debug = false, want true")
	}
}

// TestLoadEmptyFormatDefaultsToTable verifies that format: "" defaults to "table".
func TestLoadEmptyFormatDefaultsToTable(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "apimgr", "caswhois")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	if err := os.WriteFile(filepath.Join(configDir, "cli.yml"), []byte("server: https://x.com\nformat: \"\"\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.Format != "table" {
		t.Errorf("Load().Format with empty YAML field = %q, want %q", cfg.Format, "table")
	}
}

// TestLoadInvalidYAML verifies malformed YAML returns a non-nil error.
func TestLoadInvalidYAML(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "apimgr", "caswhois")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	if err := os.WriteFile(filepath.Join(configDir, "cli.yml"), []byte("format: [\nbroken"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load()
	if err == nil {
		t.Error("Load() with invalid YAML expected error, got nil")
	}
}

// TestLoadReadFileError covers the non-IsNotExist os.ReadFile error path via injection.
func TestLoadReadFileError(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	oldRead := readFile
	readFile = func(name string) ([]byte, error) {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrPermission}
	}
	defer func() { readFile = oldRead }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "apimgr", "caswhois")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	if err := os.WriteFile(filepath.Join(configDir, "cli.yml"), []byte("server: x\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load()
	if err == nil {
		t.Error("Load() with injected read error expected non-nil error, got nil")
	}
}

// TestSaveWritesFile verifies Save creates the config file with non-zero content.
func TestSaveWritesFile(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg := &CLIConfig{
		Server: "https://whois.example.com",
		Token:  "tok_test",
		Format: "json",
	}

	if err := Save(cfg); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}

	info, err := os.Stat(ConfigPath())
	if err != nil {
		t.Fatalf("Stat after Save: %v", err)
	}
	if info.Size() == 0 {
		t.Error("Save() wrote empty file")
	}
}

// TestSaveThenLoadRoundTrip verifies Save → Load returns the original values.
func TestSaveThenLoadRoundTrip(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	original := &CLIConfig{
		Server:        "https://api.example.com",
		Token:         "tok_roundtrip99",
		Format:        "json",
		Lang:          "fr",
		UpdateChannel: "beta",
		Debug:         true,
	}

	if err := Save(original); err != nil {
		t.Fatalf("Save(): %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() after Save: %v", err)
	}

	if loaded.Server != original.Server {
		t.Errorf("Server: got %q, want %q", loaded.Server, original.Server)
	}
	if loaded.Token != original.Token {
		t.Errorf("Token: got %q, want %q", loaded.Token, original.Token)
	}
	if loaded.Format != original.Format {
		t.Errorf("Format: got %q, want %q", loaded.Format, original.Format)
	}
	if loaded.Lang != original.Lang {
		t.Errorf("Lang: got %q, want %q", loaded.Lang, original.Lang)
	}
	if loaded.UpdateChannel != original.UpdateChannel {
		t.Errorf("UpdateChannel: got %q, want %q", loaded.UpdateChannel, original.UpdateChannel)
	}
	if loaded.Debug != original.Debug {
		t.Errorf("Debug: got %v, want %v", loaded.Debug, original.Debug)
	}
}

// TestSaveMkdirAllError verifies Save propagates MkdirAll failure.
func TestSaveMkdirAllError(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	dir := t.TempDir()

	// Place a regular file where the apimgr/ directory must be created.
	blockingFile := filepath.Join(dir, "apimgr")
	if err := os.WriteFile(blockingFile, []byte("block"), 0644); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}

	t.Setenv("XDG_CONFIG_HOME", dir)

	if err := Save(&CLIConfig{Format: "text"}); err == nil {
		t.Error("Save() expected error when MkdirAll fails, got nil")
	}
}

// TestResolveConfigPathEmpty verifies an empty flag resolves to the default cli.yml path.
func TestResolveConfigPathEmpty(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	got := ResolveConfigPath("")
	want := ConfigPath()
	if got != want {
		t.Errorf("ResolveConfigPath(\"\") = %q, want %q", got, want)
	}
}

// TestResolveConfigPathBareName verifies a bare name resolves to {config_dir}/name.yml.
func TestResolveConfigPathBareName(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	got := ResolveConfigPath("test")
	want := filepath.Join(dir, "apimgr", "caswhois", "test.yml")
	if got != want {
		t.Errorf("ResolveConfigPath(\"test\") = %q, want %q", got, want)
	}
}

// TestResolveConfigPathExplicitExtension verifies a name with an existing extension
// is used as-is (relative to config dir), including non-.yml extensions like .yaml.
func TestResolveConfigPathExplicitExtension(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	got := ResolveConfigPath("dev.yml")
	want := filepath.Join(dir, "apimgr", "caswhois", "dev.yml")
	if got != want {
		t.Errorf("ResolveConfigPath(\"dev.yml\") = %q, want %q", got, want)
	}

	got = ResolveConfigPath("test.yaml")
	want = filepath.Join(dir, "apimgr", "caswhois", "test.yaml")
	if got != want {
		t.Errorf("ResolveConfigPath(\"test.yaml\") = %q, want %q", got, want)
	}
}

// TestResolveConfigPathAbsolute verifies an absolute path is used verbatim (with
// yaml-extension resolution applied when no extension is present).
func TestResolveConfigPathAbsolute(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	abs := filepath.Join(dir, "prod.yml")
	got := ResolveConfigPath(abs)
	if got != abs {
		t.Errorf("ResolveConfigPath(%q) = %q, want %q", abs, got, abs)
	}
}

// TestResolveConfigPathHomeExpansion verifies "~/..." expands to the home directory.
func TestResolveConfigPathHomeExpansion(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory available")
	}

	got := ResolveConfigPath("~/testing/app.yml")
	want := filepath.Join(home, "testing", "app.yml")
	if got != want {
		t.Errorf("ResolveConfigPath(\"~/testing/app.yml\") = %q, want %q", got, want)
	}
}

// TestResolveConfigPathAutoDetectYaml verifies auto-detection prefers an existing
// .yaml file over the .yml default when no extension is given and only .yaml exists.
func TestResolveConfigPathAutoDetectYaml(t *testing.T) {
	old := getOS
	getOS = func() string { return "linux" }
	defer func() { getOS = old }()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	confDir := filepath.Join(dir, "apimgr", "caswhois")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	yamlPath := filepath.Join(confDir, "found.yaml")
	if err := os.WriteFile(yamlPath, []byte("server: x\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got := ResolveConfigPath("found")
	if got != yamlPath {
		t.Errorf("ResolveConfigPath(\"found\") = %q, want %q", got, yamlPath)
	}
}

// TestLoadFromMissingFile verifies LoadFrom returns defaults when the file does not exist.
func TestLoadFromMissingFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadFrom(filepath.Join(dir, "missing.yml"))
	if err != nil {
		t.Fatalf("LoadFrom() unexpected error: %v", err)
	}
	if cfg.Format != "table" {
		t.Errorf("LoadFrom() Format = %q, want %q", cfg.Format, "table")
	}
}

// TestLoadFromExisting verifies LoadFrom reads and unmarshals an existing config file.
func TestLoadFromExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yml")
	if err := os.WriteFile(path, []byte("server: http://example.com\ntoken: abc\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() unexpected error: %v", err)
	}
	if cfg.Server != "http://example.com" {
		t.Errorf("LoadFrom() Server = %q, want %q", cfg.Server, "http://example.com")
	}
	if cfg.Token != "abc" {
		t.Errorf("LoadFrom() Token = %q, want %q", cfg.Token, "abc")
	}
}

// TestSaveToWritesFile verifies SaveTo creates parent directories and writes the config.
func TestSaveToWritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "custom.yml")

	if err := SaveTo(path, &CLIConfig{Server: "http://example.com", Format: "text"}); err != nil {
		t.Fatalf("SaveTo() unexpected error: %v", err)
	}

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() unexpected error: %v", err)
	}
	if cfg.Server != "http://example.com" {
		t.Errorf("LoadFrom() Server = %q, want %q", cfg.Server, "http://example.com")
	}
}
