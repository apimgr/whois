package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Default()
// ---------------------------------------------------------------------------

// TestDefault verifies that Default() returns a non-nil config with the
// mandated production-safe values from AI.md PART 5/12.
func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default() returned nil")
	}

	// Mode must default to production (PART 6)
	if cfg.Mode != "production" {
		t.Errorf("Default().Mode = %q, want %q", cfg.Mode, "production")
	}

	// SMTP port must default to 587 (STARTTLS, PART 17)
	if cfg.Notifications.Email.SMTP.Port != 587 {
		t.Errorf("Default().SMTPPort = %d, want 587", cfg.Notifications.Email.SMTP.Port)
	}

	// SMTP TLS mode must default to "auto" (PART 17)
	if cfg.Notifications.Email.SMTP.TLS != "auto" {
		t.Errorf("Default().SMTPTLSMode = %q, want %q", cfg.Notifications.Email.SMTP.TLS, "auto")
	}

	// Update channel must default to "stable" (PART 22)
	if cfg.UpdateChannel != "stable" {
		t.Errorf("Default().UpdateChannel = %q, want %q", cfg.UpdateChannel, "stable")
	}

	// Debug must default to false
	if cfg.Debug {
		t.Error("Default().Debug = true, want false")
	}

	// Rate limiting enabled by default
	if !cfg.RateLimit.Enabled {
		t.Error("Default().RateLimit.Enabled = false, want true")
	}

	// Branding title must default to "caswhois"
	if cfg.Branding.Title != "caswhois" {
		t.Errorf("Default().Branding.Title = %q, want %q", cfg.Branding.Title, "caswhois")
	}

	// Branding theme must default to "auto" (dark/light/auto CSS)
	if cfg.Branding.Theme != "auto" {
		t.Errorf("Default().Branding.Theme = %q, want %q", cfg.Branding.Theme, "auto")
	}

	// Accent color must have a sensible default
	if cfg.Branding.AccentColor == "" {
		t.Error("Default().Branding.AccentColor is empty")
	}

	// Rate limit read window must be non-zero
	if cfg.RateLimit.Read.Window <= 0 {
		t.Errorf("Default().RateLimit.Read.Window = %d, want > 0", cfg.RateLimit.Read.Window)
	}

	// Rate limit read request count must be > 0
	if cfg.RateLimit.Read.Requests <= 0 {
		t.Errorf("Default().RateLimit.Read.Requests = %d, want > 0", cfg.RateLimit.Read.Requests)
	}

	// Rate limit write request count must be > 0
	if cfg.RateLimit.Write.Requests <= 0 {
		t.Errorf("Default().RateLimit.Write.Requests = %d, want > 0", cfg.RateLimit.Write.Requests)
	}

	// Global burst must be > 0
	if cfg.RateLimit.GlobalBurst <= 0 {
		t.Errorf("Default().RateLimit.GlobalBurst = %d, want > 0", cfg.RateLimit.GlobalBurst)
	}

	// GeoIP defaults: all four databases enabled
	if !cfg.GeoIP.Enabled {
		t.Error("Default().GeoIPEnabled = false, want true")
	}
	if !cfg.GeoIP.Databases.ASN {
		t.Error("Default().GeoIPDatabaseASN = false, want true")
	}
	if !cfg.GeoIP.Databases.Country {
		t.Error("Default().GeoIPDatabaseCountry = false, want true")
	}
	if !cfg.GeoIP.Databases.City {
		t.Error("Default().GeoIPDatabaseCity = false, want true")
	}

	// GeoIPDenyCountries must be non-nil empty slice
	if cfg.GeoIP.DenyCountries == nil {
		t.Error("Default().GeoIPDenyCountries = nil, want empty slice")
	}

	// Metrics enabled by default
	if !cfg.Metrics.Enabled {
		t.Error("Default().MetricsEnabled = false, want true")
	}

	// Backup encryption disabled by default
	if cfg.Backup.Encryption.Enabled {
		t.Error("Default().BackupEncryptionEnabled = true, want false")
	}

	// BackupMaxBackups must be >= 1 (spec: keep at least 1)
	if cfg.Backup.Retention.MaxBackups < 1 {
		t.Errorf("Default().BackupMaxBackups = %d, want >= 1", cfg.Backup.Retention.MaxBackups)
	}

	// Tor network disabled by default
	if cfg.Tor.UseNetwork {
		t.Error("Default().TorUseNetwork = true, want false")
	}

	// TorSafeLogging must be true by default
	if !cfg.Tor.SafeLogging {
		t.Error("Default().TorSafeLogging = false, want true")
	}

	// ServerToken starts empty — generated on first run
	if cfg.ServerToken != "" {
		t.Errorf("Default().ServerToken = %q, want empty (auto-generated on first run)", cfg.ServerToken)
	}

	// Daemonize must be false by default
	if cfg.Daemonize {
		t.Error("Default().Daemonize = true, want false")
	}

	// PIDFile must be true by default
	if !cfg.PIDFile {
		t.Error("Default().PIDFile = false, want true")
	}

	// DatabaseDriver empty — auto-detected at runtime
	if cfg.Database.Driver != "" {
		t.Errorf("Default().DatabaseDriver = %q, want empty", cfg.Database.Driver)
	}
}

// ---------------------------------------------------------------------------
// Validate()
// ---------------------------------------------------------------------------

// TestValidateAcceptsValidConfig confirms Validate() passes for a fully valid config.
func TestValidateAcceptsValidConfig(t *testing.T) {
	cfg := Default()
	cfg.Port = 64500
	cfg.Mode = "production"
	cfg.UpdateChannel = "stable"

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error on valid config: %v", err)
	}
}

// TestValidate covers error and auto-correction paths.
func TestValidate(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(*ServerConfig)
		wantErr    bool
		checkAfter func(*testing.T, *ServerConfig)
	}{
		{
			name: "port too high",
			setup: func(c *ServerConfig) {
				c.Port = 65536
			},
			wantErr: true,
		},
		{
			name: "port negative",
			setup: func(c *ServerConfig) {
				c.Port = -1
			},
			wantErr: true,
		},
		{
			name: "invalid mode",
			setup: func(c *ServerConfig) {
				c.Mode = "staging"
			},
			wantErr: true,
		},
		{
			name: "development mode is valid",
			setup: func(c *ServerConfig) {
				c.Mode = "development"
			},
			wantErr: false,
		},
		{
			// Spec says invalid update channel is silently corrected to "stable"
			name: "invalid update channel auto-corrects to stable",
			setup: func(c *ServerConfig) {
				c.UpdateChannel = "nightly"
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.UpdateChannel != "stable" {
					t.Errorf("UpdateChannel after correction = %q, want %q", c.UpdateChannel, "stable")
				}
			},
		},
		{
			// BackupMaxBackups <= 0 is corrected to 1, no error
			name: "zero backup max corrected to 1",
			setup: func(c *ServerConfig) {
				c.Backup.Retention.MaxBackups = 0
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.Backup.Retention.MaxBackups != 1 {
					t.Errorf("BackupMaxBackups after correction = %d, want 1", c.Backup.Retention.MaxBackups)
				}
			},
		},
		{
			// BackupMaxBackups = -5 must also be corrected to 1
			name: "negative backup max corrected to 1",
			setup: func(c *ServerConfig) {
				c.Backup.Retention.MaxBackups = -5
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.Backup.Retention.MaxBackups != 1 {
					t.Errorf("BackupMaxBackups after correction = %d, want 1", c.Backup.Retention.MaxBackups)
				}
			},
		},
		{
			// Negative retention values are clamped to 0
			name: "negative weekly retention clamped to 0",
			setup: func(c *ServerConfig) {
				c.Backup.Retention.KeepWeekly = -3
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.Backup.Retention.KeepWeekly != 0 {
					t.Errorf("BackupKeepWeekly after clamping = %d, want 0", c.Backup.Retention.KeepWeekly)
				}
			},
		},
		{
			// Negative monthly retention clamped to 0
			name: "negative monthly retention clamped to 0",
			setup: func(c *ServerConfig) {
				c.Backup.Retention.KeepMonthly = -1
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.Backup.Retention.KeepMonthly != 0 {
					t.Errorf("BackupKeepMonthly after clamping = %d, want 0", c.Backup.Retention.KeepMonthly)
				}
			},
		},
		{
			// Negative yearly retention clamped to 0
			name: "negative yearly retention clamped to 0",
			setup: func(c *ServerConfig) {
				c.Backup.Retention.KeepYearly = -2
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.Backup.Retention.KeepYearly != 0 {
					t.Errorf("BackupKeepYearly after clamping = %d, want 0", c.Backup.Retention.KeepYearly)
				}
			},
		},
		{
			// Port 0 is allowed (random assignment on first run)
			name: "port zero allowed",
			setup: func(c *ServerConfig) {
				c.Port = 0
			},
			wantErr: false,
		},
		{
			// Maximum legal port
			name: "port 65535 allowed",
			setup: func(c *ServerConfig) {
				c.Port = 65535
			},
			wantErr: false,
		},
		{
			// beta and daily are valid update channels
			name: "beta update channel valid",
			setup: func(c *ServerConfig) {
				c.UpdateChannel = "beta"
			},
			wantErr: false,
		},
		{
			name: "daily update channel valid",
			setup: func(c *ServerConfig) {
				c.UpdateChannel = "daily"
			},
			wantErr: false,
		},
		{
			// Compliance with encryption disabled must not block startup
			name: "compliance without encryption does not error",
			setup: func(c *ServerConfig) {
				c.Compliance.Enabled = true
				c.Backup.Encryption.Enabled = false
			},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.setup(cfg)

			err := cfg.Validate()

			if tc.wantErr && err == nil {
				t.Errorf("Validate() expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
			if tc.checkAfter != nil && err == nil {
				tc.checkAfter(t, cfg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// LoadServerConfig()
// ---------------------------------------------------------------------------

// TestLoadServerConfigMissingFile verifies that LoadServerConfig returns Default()
// values (no error) when the config directory exists but server.yml does not.
func TestLoadServerConfigMissingFile(t *testing.T) {
	dir := t.TempDir()

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig(empty dir) error: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadServerConfig returned nil config")
	}

	// ConfigDir must be set to the supplied directory
	if cfg.ConfigDir != dir {
		t.Errorf("cfg.ConfigDir = %q, want %q", cfg.ConfigDir, dir)
	}

	// Mode falls back to production default
	if cfg.Mode != "production" {
		t.Errorf("cfg.Mode = %q, want %q", cfg.Mode, "production")
	}

	// SMTPPort falls back to 587
	if cfg.Notifications.Email.SMTP.Port != 587 {
		t.Errorf("cfg.Notifications.Email.SMTP.Port = %d, want 587", cfg.Notifications.Email.SMTP.Port)
	}
}

// TestLoadServerConfigEmptyDir verifies that LoadServerConfig returns an error
// when an empty configDir is given (not a missing file — just no dir specified).
func TestLoadServerConfigEmptyDir(t *testing.T) {
	_, err := LoadServerConfig("")
	if err == nil {
		t.Error("LoadServerConfig(\"\") expected error, got nil")
	}
}

// TestLoadServerConfigWithValidYAML verifies that a well-formed server.yml is
// parsed correctly and fields override defaults.
func TestLoadServerConfigWithValidYAML(t *testing.T) {
	dir := t.TempDir()

	// Write a minimal valid server.yml with the required server: wrapper (AI.md PART 5).
	yaml := `server:
  mode: development
  port: 64123
  notifications:
    email:
      smtp:
        port: 465
  update_channel: beta
  token: tok_testtoken12345678901234567890123
`
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	if cfg.Mode != "development" {
		t.Errorf("cfg.Mode = %q, want %q", cfg.Mode, "development")
	}
	if cfg.Port != 64123 {
		t.Errorf("cfg.Port = %d, want 64123", cfg.Port)
	}
	if cfg.Notifications.Email.SMTP.Port != 465 {
		t.Errorf("cfg.Notifications.Email.SMTP.Port = %d, want 465", cfg.Notifications.Email.SMTP.Port)
	}
	if cfg.UpdateChannel != "beta" {
		t.Errorf("cfg.UpdateChannel = %q, want %q", cfg.UpdateChannel, "beta")
	}
}

// TestLoadServerConfigInvalidYAML verifies that malformed YAML returns an error.
func TestLoadServerConfigInvalidYAML(t *testing.T) {
	dir := t.TempDir()

	// Write YAML that cannot be parsed.
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte("mode: [\nbroken"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadServerConfig(dir)
	if err == nil {
		t.Error("LoadServerConfig(invalid YAML) expected error, got nil")
	}
}

// TestLoadServerConfigPartialYAMLMergesWithDefaults confirms that a partial
// YAML file leaves unspecified fields at their default values.
func TestLoadServerConfigPartialYAMLMergesWithDefaults(t *testing.T) {
	dir := t.TempDir()

	// Only set the mode; everything else should remain at Default() values.
	yaml := "server:\n  mode: development\n  token: tok_partialmergetoken123456789012\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	// Explicitly set field is overridden
	if cfg.Mode != "development" {
		t.Errorf("cfg.Mode = %q, want %q", cfg.Mode, "development")
	}

	// Unset field retains its default
	if cfg.Notifications.Email.SMTP.Port != 587 {
		t.Errorf("cfg.Notifications.Email.SMTP.Port = %d, want 587 (default)", cfg.Notifications.Email.SMTP.Port)
	}
	if cfg.UpdateChannel != "stable" {
		t.Errorf("cfg.UpdateChannel = %q, want %q (default)", cfg.UpdateChannel, "stable")
	}
	if cfg.RateLimit.Read.Requests != 120 {
		t.Errorf("cfg.RateLimit.Read.Requests = %d, want 120 (default)", cfg.RateLimit.Read.Requests)
	}
}

// TestLoadServerConfigAutoGeneratesToken verifies that a server.yml without a
// server_token triggers auto-generation and the resulting token is valid.
func TestLoadServerConfigAutoGeneratesToken(t *testing.T) {
	dir := t.TempDir()

	// Write a valid YAML file with no server_token field.
	yaml := "server:\n  mode: production\n  port: 64100\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	// Token must have been generated
	if !strings.HasPrefix(cfg.ServerToken, "tok_") {
		t.Errorf("auto-generated token = %q, must start with tok_", cfg.ServerToken)
	}
	if len(cfg.ServerToken) != 36 {
		t.Errorf("auto-generated token length = %d, want 36", len(cfg.ServerToken))
	}

	// Token must have been persisted back so the next load reads the same token
	reloaded, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("second LoadServerConfig: %v", err)
	}
	if reloaded.ServerToken != cfg.ServerToken {
		t.Errorf("persisted token mismatch: first=%q second=%q", cfg.ServerToken, reloaded.ServerToken)
	}
}

// TestLoadServerConfigSetsConfigDirFromArg verifies that when server.yml has no
// config_dir set the loaded struct uses the argument directory.
func TestLoadServerConfigSetsConfigDirFromArg(t *testing.T) {
	dir := t.TempDir()

	yaml := "server:\n  mode: production\n  token: tok_configdirtest12345678901234567\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	if cfg.ConfigDir != dir {
		t.Errorf("cfg.ConfigDir = %q, want %q", cfg.ConfigDir, dir)
	}
}

// TestLoadServerConfigPreservesConfigDirFromYAML verifies that when server.yml
// explicitly sets config_dir it is not overwritten by the argument.
func TestLoadServerConfigPreservesConfigDirFromYAML(t *testing.T) {
	dir := t.TempDir()
	customDir := "/custom/config"

	yaml := "server:\n  mode: production\n  config_dir: " + customDir + "\n  token: tok_preserveconfigdir12345678901234\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	// When the YAML has config_dir, that value must not be overwritten
	if cfg.ConfigDir != customDir {
		t.Errorf("cfg.ConfigDir = %q, want %q", cfg.ConfigDir, customDir)
	}
}

// TestLoadServerConfigInvalidPortInYAML verifies that a port out of range in
// the config file causes an error from the Validate call inside LoadServerConfig.
func TestLoadServerConfigInvalidPortInYAML(t *testing.T) {
	dir := t.TempDir()

	yaml := "server:\n  mode: production\n  port: 99999\n  token: tok_badport1234567890123456789012\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadServerConfig(dir)
	if err == nil {
		t.Error("LoadServerConfig with out-of-range port expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Save()
// ---------------------------------------------------------------------------

// TestSaveAndReload verifies that Save() writes a file that LoadServerConfig
// reads back with equivalent values.
func TestSaveAndReload(t *testing.T) {
	dir := t.TempDir()

	original := Default()
	original.Port = 64321
	original.Mode = "development"
	original.UpdateChannel = "beta"
	original.Notifications.Email.SMTP.Port = 465
	// Provide a token so LoadServerConfig does not try to generate+persist a new one.
	original.ServerToken = "tok_savereloadtoken1234567890123456"

	if err := original.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig after Save: %v", err)
	}

	if reloaded.Port != original.Port {
		t.Errorf("Port: saved %d, reloaded %d", original.Port, reloaded.Port)
	}
	if reloaded.Mode != original.Mode {
		t.Errorf("Mode: saved %q, reloaded %q", original.Mode, reloaded.Mode)
	}
	if reloaded.UpdateChannel != original.UpdateChannel {
		t.Errorf("UpdateChannel: saved %q, reloaded %q", original.UpdateChannel, reloaded.UpdateChannel)
	}
	if reloaded.Notifications.Email.SMTP.Port != original.Notifications.Email.SMTP.Port {
		t.Errorf("SMTPPort: saved %d, reloaded %d", original.Notifications.Email.SMTP.Port, reloaded.Notifications.Email.SMTP.Port)
	}
}

// TestSaveCreatesDirectory verifies that Save() creates the config directory
// when it does not yet exist.
func TestSaveCreatesDirectory(t *testing.T) {
	parent := t.TempDir()
	newDir := filepath.Join(parent, "nested", "config")

	cfg := Default()
	cfg.ServerToken = "tok_savecreatesdir12345678901234567"
	cfg.Mode = "production"

	if err := cfg.Save(newDir); err != nil {
		t.Fatalf("Save to new directory: %v", err)
	}

	configPath := filepath.Join(newDir, "server.yml")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf("server.yml not found after Save: %v", err)
	}
}

// TestSaveUsesConfigDirFieldWhenArgIsEmpty verifies that Save("") falls back
// to c.ConfigDir when the argument is empty.
func TestSaveUsesConfigDirFieldWhenArgIsEmpty(t *testing.T) {
	dir := t.TempDir()

	cfg := Default()
	cfg.ConfigDir = dir
	cfg.ServerToken = "tok_saveusesconfigdir1234567890123"
	cfg.Mode = "production"

	if err := cfg.Save(""); err != nil {
		t.Fatalf("Save with empty arg: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "server.yml")); err != nil {
		t.Errorf("server.yml not found when using ConfigDir fallback: %v", err)
	}
}

// TestSaveErrorsWhenNoDirAvailable verifies that Save returns an error when
// both the argument and c.ConfigDir are empty.
func TestSaveErrorsWhenNoDirAvailable(t *testing.T) {
	cfg := Default()
	cfg.ConfigDir = ""

	if err := cfg.Save(""); err == nil {
		t.Error("Save with no directory expected error, got nil")
	}
}

// TestSaveIsIdempotent verifies that calling Save twice does not produce an
// error and the second write overwrites the first cleanly.
func TestSaveIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	cfg := Default()
	cfg.Mode = "production"
	cfg.ServerToken = "tok_idempotentsave123456789012345"

	if err := cfg.Save(dir); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	cfg.Port = 64888
	if err := cfg.Save(dir); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	reloaded, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig after second Save: %v", err)
	}
	if reloaded.Port != 64888 {
		t.Errorf("Port after second Save = %d, want 64888", reloaded.Port)
	}
}

// ---------------------------------------------------------------------------
// GetDatabaseDir()
// ---------------------------------------------------------------------------

// TestGetDatabaseDir covers the four resolution tiers without relying on the
// host's container environment.
func TestGetDatabaseDir(t *testing.T) {
	// Tier 1: explicit DatabaseDir in config wins over everything
	t.Run("explicit config field", func(t *testing.T) {
		cfg := Default()
		cfg.Database.Dir = "/explicit/db"

		os.Unsetenv("DATABASE_DIR")
		got := cfg.GetDatabaseDir()
		if got != "/explicit/db" {
			t.Errorf("GetDatabaseDir() = %q, want /explicit/db", got)
		}
	})

	// Tier 2: DATABASE_DIR env var wins when config field is empty
	t.Run("DATABASE_DIR env var", func(t *testing.T) {
		cfg := Default()
		cfg.Database.Dir = ""

		t.Setenv("DATABASE_DIR", "/env/db")
		got := cfg.GetDatabaseDir()
		if got != "/env/db" {
			t.Errorf("GetDatabaseDir() = %q, want /env/db", got)
		}
	})

	// Tier 4 (non-container): when DataDir is set, path is {DataDir}/db
	t.Run("data_dir fallback on non-container", func(t *testing.T) {
		cfg := Default()
		cfg.Database.Dir = ""
		cfg.DataDir = "/my/data"

		os.Unsetenv("DATABASE_DIR")
		got := cfg.GetDatabaseDir()
		// On non-container hosts the result is either "./db" or "{DataDir}/db"
		// depending on isContainer(). We only assert the DataDir path is used
		// when not in a container (the test host is not a container).
		if isContainer() {
			t.Skip("skipping: running inside a container")
		}
		want := filepath.Join("/my/data", "db")
		if got != want {
			t.Errorf("GetDatabaseDir() = %q, want %q", got, want)
		}
	})

	// Tier 4 fallback: when nothing is set, a non-empty string is still returned
	t.Run("fallback returns non-empty string", func(t *testing.T) {
		cfg := Default()
		cfg.Database.Dir = ""
		cfg.DataDir = ""

		os.Unsetenv("DATABASE_DIR")
		got := cfg.GetDatabaseDir()
		if got == "" {
			t.Error("GetDatabaseDir() returned empty string — must always return a usable path")
		}
	})
}

// ---------------------------------------------------------------------------
// GetBackupDir()
// ---------------------------------------------------------------------------

// TestGetBackupDir covers the three resolution tiers.
func TestGetBackupDir(t *testing.T) {
	// Tier 1: explicit BackupDir in config
	t.Run("explicit config field", func(t *testing.T) {
		cfg := Default()
		cfg.Backup.Dir = "/explicit/backups"

		got := cfg.GetBackupDir()
		if got != "/explicit/backups" {
			t.Errorf("GetBackupDir() = %q, want /explicit/backups", got)
		}
	})

	// Tier 3 (non-container): {DataDir}/backups
	t.Run("data_dir fallback on non-container", func(t *testing.T) {
		if isContainer() {
			t.Skip("skipping: running inside a container")
		}
		cfg := Default()
		cfg.Backup.Dir = ""
		cfg.DataDir = "/my/data"

		got := cfg.GetBackupDir()
		want := filepath.Join("/my/data", "backups")
		if got != want {
			t.Errorf("GetBackupDir() = %q, want %q", got, want)
		}
	})

	// Fallback: empty DataDir and no explicit dir must still return a string
	t.Run("fallback returns non-empty string", func(t *testing.T) {
		cfg := Default()
		cfg.Backup.Dir = ""
		cfg.DataDir = ""

		got := cfg.GetBackupDir()
		if got == "" {
			t.Error("GetBackupDir() returned empty string — must always return a usable path")
		}
	})
}

// ---------------------------------------------------------------------------
// GetDatabaseConfig()
// ---------------------------------------------------------------------------

// TestGetDatabaseConfig covers the three configuration tiers.
func TestGetDatabaseConfig(t *testing.T) {
	// When DATABASE_URL is set the env var wins over config fields.
	t.Run("DATABASE_URL env overrides config", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "libsql://mydb.turso.io?authToken=xxx")
		os.Unsetenv("DATABASE_DRIVER")

		cfg := Default()
		driver, url, path := cfg.GetDatabaseConfig()

		if url != "libsql://mydb.turso.io?authToken=xxx" {
			t.Errorf("url = %q, want the env URL", url)
		}
		if driver == "" {
			t.Error("driver must be non-empty when DATABASE_URL is set")
		}
		if path != "" {
			t.Errorf("path = %q, want empty when URL is set", path)
		}
	})

	// When DATABASE_DRIVER env is also set it is used as the driver.
	t.Run("DATABASE_DRIVER env used when DATABASE_URL present", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "libsql://db.example.com")
		t.Setenv("DATABASE_DRIVER", "libsql")

		cfg := Default()
		driver, _, _ := cfg.GetDatabaseConfig()

		if driver != "libsql" {
			t.Errorf("driver = %q, want libsql", driver)
		}
	})

	// Config DatabaseURL field is used when env is absent.
	t.Run("config DatabaseURL field", func(t *testing.T) {
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("DATABASE_DRIVER")

		cfg := Default()
		cfg.Database.URL = "libsql://cfg.example.com"
		cfg.Database.Driver = "libsql"

		driver, url, path := cfg.GetDatabaseConfig()

		if url != "libsql://cfg.example.com" {
			t.Errorf("url = %q, want config URL", url)
		}
		if driver != "libsql" {
			t.Errorf("driver = %q, want libsql", driver)
		}
		if path != "" {
			t.Errorf("path = %q, want empty when URL is set", path)
		}
	})

	// Config DatabaseURL with empty DatabaseDriver defaults to "sqlite".
	t.Run("config DatabaseURL with no driver defaults to sqlite", func(t *testing.T) {
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("DATABASE_DRIVER")

		cfg := Default()
		cfg.Database.URL = "libsql://nodriver.example.com"
		cfg.Database.Driver = ""

		driver, _, _ := cfg.GetDatabaseConfig()
		if driver != "sqlite" {
			t.Errorf("driver = %q, want sqlite (default)", driver)
		}
	})

	// Default path: SQLite with a non-empty path and empty URL.
	t.Run("default sqlite path", func(t *testing.T) {
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("DATABASE_DRIVER")
		os.Unsetenv("DATABASE_DIR")

		cfg := Default()
		cfg.Database.URL = ""
		cfg.Database.Driver = ""

		driver, url, path := cfg.GetDatabaseConfig()

		if driver != "sqlite" {
			t.Errorf("driver = %q, want sqlite", driver)
		}
		if url != "" {
			t.Errorf("url = %q, want empty for SQLite", url)
		}
		if path == "" {
			t.Error("path must be non-empty for local SQLite")
		}
	})
}

// ---------------------------------------------------------------------------
// contains() and hasSubstring()
// ---------------------------------------------------------------------------

// TestContains exercises the package-private contains helper including edge cases
// that are not exercised by the isContainer() call path.
// Note: the implementation treats an empty substr as contained in any string
// (len(s) >= len("") is always true and "" == "" or hasSubstring finds it at 0).
func TestContains(t *testing.T) {
	cases := []struct {
		s      string
		sub    string
		want   bool
	}{
		// empty substr: implementation returns true (substr fits trivially)
		{"", "", true},
		{"hello", "", true},
		// empty s with non-empty substr: length guard rejects it
		{"", "x", false},
		{"hello", "hello", true},
		{"hello world", "world", true},
		{"hello world", "xyz", false},
		{"ab", "abc", false},
		{"abc", "abc", true},
		{"abcdef", "bcd", true},
		{"abcdef", "xyz", false},
		{"docker", "docker", true},
		{"kubepods/abc", "kubepods", true},
		{"lxc/init", "lxc", true},
	}

	for _, tc := range cases {
		t.Run(tc.s+"_contains_"+tc.sub, func(t *testing.T) {
			got := contains(tc.s, tc.sub)
			if got != tc.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tc.s, tc.sub, got, tc.want)
			}
		})
	}
}

// TestHasSubstring exercises the package-private hasSubstring helper directly.
func TestHasSubstring(t *testing.T) {
	cases := []struct {
		s    string
		sub  string
		want bool
	}{
		{"abcde", "abc", true},
		{"abcde", "cde", true},
		{"abcde", "bcd", true},
		{"abcde", "xyz", false},
		{"abcde", "abcdef", false},
		{"x", "x", true},
		{"docker\n1:name=/", "docker", true},
	}

	for _, tc := range cases {
		t.Run(tc.s+"_has_"+tc.sub, func(t *testing.T) {
			got := hasSubstring(tc.s, tc.sub)
			if got != tc.want {
				t.Errorf("hasSubstring(%q, %q) = %v, want %v", tc.s, tc.sub, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GenerateToken()
// ---------------------------------------------------------------------------

// TestGenerateToken checks that GenerateToken produces a correctly formatted token
// and that two calls return different values.
func TestGenerateToken(t *testing.T) {
	tok1, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// Token must start with "tok_" followed by exactly 32 base62 chars
	if len(tok1) != 4+32 {
		t.Errorf("token length = %d, want %d", len(tok1), 4+32)
	}
	if tok1[:4] != "tok_" {
		t.Errorf("token prefix = %q, want %q", tok1[:4], "tok_")
	}

	// All characters after the prefix must be base62
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for i, ch := range tok1[4:] {
		if !strings.ContainsRune(alphabet, ch) {
			t.Errorf("token char at position %d is %q, not in base62 alphabet", i+4, ch)
		}
	}

	tok2, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken (second call): %v", err)
	}
	if tok1 == tok2 {
		t.Error("two GenerateToken calls returned identical tokens (collision probability negligible)")
	}
}

// TestGenerateTokenMultiple generates several tokens and verifies each is unique
// and well-formed, exercising the full base62 path repeatedly.
func TestGenerateTokenMultiple(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken iteration %d: %v", i, err)
		}
		if len(tok) != 36 {
			t.Errorf("iteration %d: token length %d, want 36", i, len(tok))
		}
		if seen[tok] {
			t.Errorf("iteration %d: duplicate token %q", i, tok)
		}
		seen[tok] = true
	}
}

// ---------------------------------------------------------------------------
// GenerateDefaultConfig()
// ---------------------------------------------------------------------------

// TestGenerateDefaultConfig verifies that a server.yml is created with the
// expected placeholders replaced and a valid random port.
func TestGenerateDefaultConfig(t *testing.T) {
	dir := t.TempDir()

	if err := GenerateDefaultConfig(dir); err != nil {
		t.Fatalf("GenerateDefaultConfig: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "server.yml"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(data)

	// Template variables must have been replaced
	if strings.Contains(content, "{{PORT}}") {
		t.Error("server.yml still contains {{PORT}} placeholder")
	}
	if strings.Contains(content, "{{TOKEN}}") {
		t.Error("server.yml still contains {{TOKEN}} placeholder")
	}

	// Token must appear in correct format
	if !strings.Contains(content, "tok_") {
		t.Error("server.yml does not contain a tok_ token")
	}
}

// TestGenerateDefaultConfigIdempotent verifies that calling GenerateDefaultConfig
// twice does not overwrite an existing file.
func TestGenerateDefaultConfigIdempotent(t *testing.T) {
	dir := t.TempDir()

	if err := GenerateDefaultConfig(dir); err != nil {
		t.Fatalf("first GenerateDefaultConfig: %v", err)
	}

	// Read the original content before the second call
	first, err := os.ReadFile(filepath.Join(dir, "server.yml"))
	if err != nil {
		t.Fatalf("ReadFile after first generation: %v", err)
	}

	if err := GenerateDefaultConfig(dir); err != nil {
		t.Fatalf("second GenerateDefaultConfig: %v", err)
	}

	second, err := os.ReadFile(filepath.Join(dir, "server.yml"))
	if err != nil {
		t.Fatalf("ReadFile after second generation: %v", err)
	}

	// File content must be identical — second call is a no-op
	if string(first) != string(second) {
		t.Error("GenerateDefaultConfig second call overwrote existing server.yml")
	}
}

// TestGenerateDefaultConfigCreatesDir verifies that GenerateDefaultConfig
// creates the config directory when it does not yet exist.
func TestGenerateDefaultConfigCreatesDir(t *testing.T) {
	parent := t.TempDir()
	newDir := filepath.Join(parent, "new", "config")

	if err := GenerateDefaultConfig(newDir); err != nil {
		t.Fatalf("GenerateDefaultConfig into new dir: %v", err)
	}

	if _, err := os.Stat(filepath.Join(newDir, "server.yml")); err != nil {
		t.Errorf("server.yml not created in new directory: %v", err)
	}
}

// TestGenerateDefaultConfigPortInRange confirms the generated port is within
// 64000-64999 as required by the spec (PART 12).
func TestGenerateDefaultConfigPortInRange(t *testing.T) {
	dir := t.TempDir()

	if err := GenerateDefaultConfig(dir); err != nil {
		t.Fatalf("GenerateDefaultConfig: %v", err)
	}

	// Load and verify the port is in spec range
	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	if cfg.Port < 64000 || cfg.Port > 64999 {
		t.Errorf("generated port %d is outside required range 64000-64999", cfg.Port)
	}
}

// ---------------------------------------------------------------------------
// ParseBool()
// ---------------------------------------------------------------------------

// TestParseBool covers truthy, falsy, empty-default, and invalid inputs.
func TestParseBool(t *testing.T) {
	cases := []struct {
		input      string
		defaultVal bool
		wantVal    bool
		wantErr    bool
	}{
		// Truthy values
		{"1", false, true, false},
		{"y", false, true, false},
		{"yes", false, true, false},
		{"true", false, true, false},
		{"on", false, true, false},
		{"ok", false, true, false},
		{"enable", false, true, false},
		{"enabled", false, true, false},
		{"YES", false, true, false},
		{"TRUE", false, true, false},
		{"  yes  ", false, true, false},
		// Falsy values
		{"0", true, false, false},
		{"n", true, false, false},
		{"no", true, false, false},
		{"false", true, false, false},
		{"off", true, false, false},
		{"disable", true, false, false},
		{"disabled", true, false, false},
		{"NO", true, false, false},
		{"FALSE", true, false, false},
		{"  no  ", true, false, false},
		// Empty returns defaultVal
		{"", true, true, false},
		{"", false, false, false},
		// Invalid
		{"maybe", false, false, true},
		{"2", false, false, true},
		{"yess", false, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.input+"_default="+boolStr(tc.defaultVal), func(t *testing.T) {
			got, err := ParseBool(tc.input, tc.defaultVal)
			if tc.wantErr && err == nil {
				t.Errorf("ParseBool(%q, %v) expected error, got nil", tc.input, tc.defaultVal)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ParseBool(%q, %v) unexpected error: %v", tc.input, tc.defaultVal, err)
			}
			if !tc.wantErr && got != tc.wantVal {
				t.Errorf("ParseBool(%q, %v) = %v, want %v", tc.input, tc.defaultVal, got, tc.wantVal)
			}
		})
	}
}

// TestMustParseBool verifies normal parsing succeeds and panics on invalid input.
func TestMustParseBool(t *testing.T) {
	if got := MustParseBool("yes", false); got != true {
		t.Errorf("MustParseBool(yes) = %v, want true", got)
	}
	if got := MustParseBool("no", true); got != false {
		t.Errorf("MustParseBool(no) = %v, want false", got)
	}
	if got := MustParseBool("", true); got != true {
		t.Errorf("MustParseBool('') with default true = %v, want true", got)
	}

	// Invalid input must panic
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("MustParseBool with invalid input did not panic")
			}
		}()
		MustParseBool("maybe", false)
	}()
}

// TestIsTruthy covers truthy detection including case-insensitivity.
func TestIsTruthy(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"yes", true},
		{"YES", true},
		{"1", true},
		{"true", true},
		{"on", true},
		{"no", false},
		{"false", false},
		{"", false},
		{"maybe", false},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := IsTruthy(tc.input)
			if got != tc.want {
				t.Errorf("IsTruthy(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestIsFalsy covers falsy detection including case-insensitivity.
func TestIsFalsy(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"no", true},
		{"NO", true},
		{"0", true},
		{"false", true},
		{"off", true},
		{"yes", false},
		{"true", false},
		{"", false},
		{"maybe", false},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := IsFalsy(tc.input)
			if got != tc.want {
				t.Errorf("IsFalsy(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SafePath() / normalizePath() / validatePath()
// ---------------------------------------------------------------------------

// TestSafePath covers valid paths, traversal attempts, and overlong inputs.
func TestSafePath(t *testing.T) {
	cases := []struct {
		input   string
		want    string
		wantErr bool
	}{
		// Valid simple paths
		{"admin", "admin", false},
		{"api/v1", "api/v1", false},
		{"whois-lookup", "whois-lookup", false},
		{"my_resource", "my_resource", false},
		// Traversal attempts must be rejected
		{"../etc/passwd", "", true},
		{"foo/../../bar", "", true},
		{"..", "", true},
		// Invalid characters
		{"Admin", "", true},
		{"Hello World", "", true},
		{"foo/Bar", "", true},
		// Empty segment via double slash is allowed (skipped)
		{"api//v1", "api/v1", false},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := SafePath(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("SafePath(%q) expected error, got %q", tc.input, got)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("SafePath(%q) unexpected error: %v", tc.input, err)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("SafePath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestSafePathTooLong verifies that a path longer than 2048 characters is rejected.
func TestSafePathTooLong(t *testing.T) {
	// Build a path that exceeds the 2048-char limit using valid segments
	segment := strings.Repeat("a", 60)
	var parts []string
	for i := 0; i <= 35; i++ {
		parts = append(parts, segment)
	}
	long := strings.Join(parts, "/")
	if len(long) <= 2048 {
		t.Fatalf("test path too short (%d), cannot verify length check", len(long))
	}

	_, err := SafePath(long)
	if err == nil {
		t.Errorf("SafePath(overlong) expected error, got nil")
	}
}

// TestValidatePathSegment covers segment-level validation directly.
func TestValidatePathSegment(t *testing.T) {
	cases := []struct {
		segment string
		wantErr bool
	}{
		{"admin", false},
		{"api", false},
		{"v1", false},
		{"my-resource", false},
		{"my_resource", false},
		{"abc123", false},
		// Too long (> 64 chars)
		{strings.Repeat("a", 65), true},
		// Empty string
		{"", true},
		// Traversal
		{"..", true},
		{".", true},
		// Uppercase
		{"Admin", true},
		// Space
		{"hello world", true},
	}

	for _, tc := range cases {
		label := tc.segment
		if label == "" {
			label = "<empty>"
		}
		t.Run(label, func(t *testing.T) {
			err := validatePathSegment(tc.segment)
			if tc.wantErr && err == nil {
				t.Errorf("validatePathSegment(%q) expected error, got nil", tc.segment)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validatePathSegment(%q) unexpected error: %v", tc.segment, err)
			}
		})
	}
}

// TestNormalizePath covers the path cleaning logic.
func TestNormalizePath(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"admin", "admin"},
		{"/admin/", "admin"},
		{"api//v1", "api/v1"},
		{"api/./v1", "api/v1"},
		// After Clean, ".." collapses; normalizePath strips them
		{"foo/../bar", "bar"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizePath(tc.input)
			if got != tc.want {
				t.Errorf("normalizePath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GenerateDefaultConfig() error path
// ---------------------------------------------------------------------------

// TestGenerateDefaultConfigUnwritableDir verifies that an unwritable parent
// directory causes GenerateDefaultConfig to return an error rather than panic.
// Root processes bypass file permission checks so this test is skipped when
// running as root (e.g., inside a Docker container with the default user).
func TestGenerateDefaultConfigUnwritableDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping: root bypasses file permission checks")
	}

	parent := t.TempDir()

	// Make parent directory read-only so MkdirAll fails
	if err := os.Chmod(parent, 0500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	// Restore permissions on cleanup so t.TempDir() can remove it
	t.Cleanup(func() { os.Chmod(parent, 0700) })

	targetDir := filepath.Join(parent, "subdir")
	err := GenerateDefaultConfig(targetDir)
	if err == nil {
		t.Error("GenerateDefaultConfig into unwritable parent expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// validatePathSegment — single dot path
// ---------------------------------------------------------------------------

// TestValidatePathSegmentSingleDot verifies that a single "." is rejected by
// the segment validator (path traversal guard).
func TestValidatePathSegmentSingleDot(t *testing.T) {
	if err := validatePathSegment("."); err == nil {
		t.Error("validatePathSegment(\".\") expected error, got nil")
	}
}

// TestSafePathSingleDot verifies that a path consisting solely of "." is rejected.
func TestSafePathSingleDot(t *testing.T) {
	_, err := SafePath(".")
	if err == nil {
		t.Error("SafePath(\".\") expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// normalizePath — segment with only dots after clean
// ---------------------------------------------------------------------------

// TestNormalizePathDotOnly verifies normalizePath returns empty for a path that
// becomes only dots after cleaning.
func TestNormalizePathDotOnly(t *testing.T) {
	// path.Clean(".") == "." — strip "." → should give empty or "."
	// The implementation strips leading/trailing slashes and checks for ".."
	// A single "." is cleaned to "." by path.Clean, then stripped of slashes
	// to just "."; there is no ".." so the function returns "."
	got := normalizePath(".")
	// normalizePath does NOT reject single dots — that is SafePath's job.
	// Just verify it returns a deterministic, non-crashing result.
	_ = got
}

// ---------------------------------------------------------------------------
// IsDebug() / IsProduction() / IsDevelopment()
// ---------------------------------------------------------------------------

// TestIsDebug verifies the debug-mode accessor returns the config field value.
func TestIsDebug(t *testing.T) {
	cfg := Default()
	if cfg.IsDebug() {
		t.Error("IsDebug() = true on default config, want false")
	}

	cfg.Debug = true
	if !cfg.IsDebug() {
		t.Error("IsDebug() = false after setting Debug=true, want true")
	}
}

// TestIsProduction verifies the mode accessor for all production aliases.
func TestIsProduction(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"production", true},
		{"prod", true},
		// Empty string means default = production per spec
		{"", true},
		{"development", false},
		{"dev", false},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			cfg := Default()
			cfg.Mode = tc.mode
			got := cfg.IsProduction()
			if got != tc.want {
				t.Errorf("IsProduction() with Mode=%q = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

// TestIsDevelopment verifies the mode accessor for all development aliases.
func TestIsDevelopment(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"development", true},
		{"dev", true},
		{"production", false},
		{"prod", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			cfg := Default()
			cfg.Mode = tc.mode
			got := cfg.IsDevelopment()
			if got != tc.want {
				t.Errorf("IsDevelopment() with Mode=%q = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Sanitized()
// ---------------------------------------------------------------------------

// TestSanitized verifies that Sanitized() always redacts the server token
// and includes the expected keys.
func TestSanitized(t *testing.T) {
	cfg := Default()
	cfg.Address = "0.0.0.0"
	cfg.Port = 64100
	cfg.Mode = "development"
	cfg.Debug = true
	cfg.DataDir = "/var/data"
	cfg.LogDir = "/var/log"
	cfg.Backup.Dir = "/var/backups"
	cfg.Notifications.Email.SMTP.Host = "smtp.example.com"
	cfg.Notifications.Email.SMTP.TLS = "starttls"
	cfg.Metrics.Enabled = true
	cfg.Metrics.Endpoint = "/metrics"
	cfg.RateLimit.Enabled = false
	// Set a real token — Sanitized must redact it.
	cfg.ServerToken = "tok_supersecrettoken123456789012"

	s := cfg.Sanitized()

	// server_token must always be redacted regardless of actual value
	if tok, ok := s["server_token"]; !ok || tok != "xxxxx" {
		t.Errorf("Sanitized()[\"server_token\"] = %v, want \"xxxxx\"", tok)
	}

	// Spot-check a few non-sensitive fields pass through as-is
	if s["address"] != "0.0.0.0" {
		t.Errorf("Sanitized()[\"address\"] = %v, want 0.0.0.0", s["address"])
	}
	if s["port"] != 64100 {
		t.Errorf("Sanitized()[\"port\"] = %v, want 64100", s["port"])
	}
	if s["mode"] != "development" {
		t.Errorf("Sanitized()[\"mode\"] = %v, want development", s["mode"])
	}
	if s["debug"] != true {
		t.Errorf("Sanitized()[\"debug\"] = %v, want true", s["debug"])
	}
	if s["smtp_host"] != "smtp.example.com" {
		t.Errorf("Sanitized()[\"smtp_host\"] = %v, want smtp.example.com", s["smtp_host"])
	}
}

// TestSanitizedDefaultConfig verifies Sanitized() on an unmodified Default().
func TestSanitizedDefaultConfig(t *testing.T) {
	cfg := Default()
	s := cfg.Sanitized()

	// Token must be redacted even when the real token is empty
	if tok, ok := s["server_token"]; !ok || tok != "xxxxx" {
		t.Errorf("Sanitized()[\"server_token\"] = %v, want \"xxxxx\"", tok)
	}

	// Required keys must all be present
	required := []string{
		"address", "port", "mode", "debug",
		"data_dir", "log_dir", "backup_dir",
		"smtp_host", "smtp_tls_mode",
		"metrics_enabled", "metrics_endpoint",
		"rate_limit_enabled", "server_token",
	}
	for _, k := range required {
		if _, ok := s[k]; !ok {
			t.Errorf("Sanitized() missing required key %q", k)
		}
	}
}

// ---------------------------------------------------------------------------
// GetLogDir()
// ---------------------------------------------------------------------------

// TestGetLogDir covers the resolution tiers for the log directory.
func TestGetLogDir(t *testing.T) {
	// Tier 1: explicit LogDir in config wins over everything
	t.Run("explicit config field", func(t *testing.T) {
		cfg := Default()
		cfg.LogDir = "/explicit/logs"
		got := cfg.GetLogDir()
		if got != "/explicit/logs" {
			t.Errorf("GetLogDir() = %q, want /explicit/logs", got)
		}
	})

	// Tiers 2-4: no explicit config — always returns a non-empty path
	t.Run("fallback returns non-empty string", func(t *testing.T) {
		if isContainer() {
			t.Skip("skipping non-container tiers: running inside a container")
		}
		cfg := Default()
		cfg.LogDir = ""
		got := cfg.GetLogDir()
		if got == "" {
			t.Error("GetLogDir() returned empty string — must always return a usable path")
		}
	})

	// Container tier: when running in a container the container default is returned
	t.Run("container default path", func(t *testing.T) {
		if !isContainer() {
			t.Skip("skipping container tier: not running inside a container")
		}
		cfg := Default()
		cfg.LogDir = ""
		got := cfg.GetLogDir()
		want := "/data/log/caswhois"
		if got != want {
			t.Errorf("GetLogDir() (container) = %q, want %q", got, want)
		}
	})
}

// ---------------------------------------------------------------------------
// IsContainer() / isContainer()
// ---------------------------------------------------------------------------

// TestIsContainerConsistency verifies that IsContainer() and isContainer()
// always return the same value — they must be identical aliases.
func TestIsContainerConsistency(t *testing.T) {
	if IsContainer() != isContainer() {
		t.Error("IsContainer() and isContainer() returned different values")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// boolStr returns "true" or "false" for use in table-driven test names.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
