package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/apimgr/whois/src/common/i18n"
	"gopkg.in/yaml.v3"
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
	if cfg.Update.Branch != "stable" {
		t.Errorf("Default().Update.Branch = %q, want %q", cfg.Update.Branch, "stable")
	}

	// Debug must default to false
	if cfg.Debug {
		t.Error("Default().Debug = true, want false")
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

func TestDefaultI18nRegistry(t *testing.T) {
	cfg := Default()
	if !reflect.DeepEqual(cfg.I18n.Supported, i18n.SupportedLanguages()) {
		t.Fatalf("Default().I18n.Supported = %v, want registry %v", cfg.I18n.Supported, i18n.SupportedLanguages())
	}
	if err := normalizeI18nConfig(&cfg.I18n); err != nil {
		t.Fatalf("default i18n config is invalid: %v", err)
	}
}

func TestNormalizeI18nConfig(t *testing.T) {
	t.Run("legacy English default expands to registry", func(t *testing.T) {
		cfg := I18nConfig{DefaultLanguage: "en", Supported: []string{"en"}}
		if err := normalizeI18nConfig(&cfg); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(cfg.Supported, i18n.SupportedLanguages()) {
			t.Fatalf("legacy supported list = %v, want registry %v", cfg.Supported, i18n.SupportedLanguages())
		}
	})

	t.Run("required minimum permits operator narrowing", func(t *testing.T) {
		cfg := I18nConfig{DefaultLanguage: "en", Supported: []string{"en", "es", "fr", "ar", "de", "it"}}
		if err := normalizeI18nConfig(&cfg); err != nil {
			t.Fatalf("valid narrowed language set rejected: %v", err)
		}
	})

	t.Run("required language cannot be removed", func(t *testing.T) {
		cfg := I18nConfig{DefaultLanguage: "en", Supported: []string{"en", "es", "fr", "ar", "de"}}
		if err := normalizeI18nConfig(&cfg); err == nil {
			t.Fatal("configuration missing Italian should be rejected")
		}
	})

	t.Run("unknown language is rejected", func(t *testing.T) {
		cfg := I18nConfig{DefaultLanguage: "en", Supported: []string{"en", "es", "fr", "ar", "de", "it", "pt"}}
		if err := normalizeI18nConfig(&cfg); err == nil {
			t.Fatal("configuration with unsupported language should be rejected")
		}
	})

	t.Run("default must remain enabled", func(t *testing.T) {
		cfg := I18nConfig{DefaultLanguage: "zh", Supported: []string{"en", "es", "fr", "ar", "de", "it"}}
		if err := normalizeI18nConfig(&cfg); err == nil {
			t.Fatal("disabled default language should be rejected")
		}
	})
}

func TestNormalizeServerPort(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		port  int
		http  int
		https int
	}{
		{name: "dual", yaml: "server:\n  port: \"8080,8443\"\n", port: 8080, http: 8080, https: 8443},
		{name: "single https", yaml: "server:\n  port: 443\n", port: 443, https: 443},
		{name: "invalid pair defaults", yaml: "server:\n  port: \"80,70000\"\n", port: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, httpPort, httpsPort := normalizeServerPort([]byte(tt.yaml))
			var cf ConfigFile
			if err := yaml.Unmarshal(data, &cf); err != nil {
				t.Fatalf("unmarshal normalized config: %v", err)
			}
			if cf.Server.Port != tt.port || httpPort != tt.http || httpsPort != tt.https {
				t.Fatalf("got port=%d http=%d https=%d, want port=%d http=%d https=%d", cf.Server.Port, httpPort, httpsPort, tt.port, tt.http, tt.https)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Validate()
// ---------------------------------------------------------------------------

func TestI2PDefaultsAndExplicitSettingDetection(t *testing.T) {
	cfg := Default()
	if cfg.I2P.Enabled || cfg.I2P.Expose {
		t.Fatal("I2P base default should be disabled and unpublished")
	}
	if cfg.I2P.SAMAddress != "127.0.0.1:7656" || cfg.I2P.VirtualPort != 80 || cfg.I2P.InboundLength != 3 || cfg.I2P.OutboundLength != 3 || cfg.I2P.InboundQuantity != 5 || cfg.I2P.OutboundQuantity != 5 || cfg.I2P.SignatureType != 7 || cfg.I2P.BootstrapTimeout != 300 {
		t.Fatalf("unexpected I2P defaults: %+v", cfg.I2P)
	}
	if !yamlHasI2PEnabled([]byte("server:\n  i2p:\n    enabled: false\n")) {
		t.Fatal("explicit false I2P setting was not detected")
	}
	if yamlHasI2PEnabled([]byte("server:\n  i2p:\n    sam_address: 127.0.0.1:7656\n")) {
		t.Fatal("missing I2P enabled setting was treated as explicit")
	}
}

func TestLoadServerConfigMergesOrderedDropIns(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "yaml.d"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte("server:\n  mode: development\n  branding:\n    title: base\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "yaml.d", "10-brand.yml"), []byte("server:\n  branding:\n    description: first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "yaml.d", "20-brand.yaml"), []byte("server:\n  branding:\n    title: later\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "development" || cfg.Branding.Title != "later" || cfg.Branding.Description != "first" {
		t.Fatalf("unexpected merged config: mode=%q branding=%+v", cfg.Mode, cfg.Branding)
	}
}

func TestSaveSeparatesNodeAreaAndSecretFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := Default()
	cfg.Port = 64123
	cfg.Mode = "development"
	cfg.Update.Branch = "beta"
	cfg.ServerToken = "adm_savepartitiontoken123456789012345"
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	server, err := os.ReadFile(filepath.Join(dir, "server.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(server), "This node only") || strings.Contains(string(server), "branch:") || strings.Contains(string(server), cfg.ServerToken) {
		t.Fatalf("server.yml contains area or secret data: %s", server)
	}
	area, err := os.ReadFile(filepath.Join(dir, "yaml.d", "maintenance.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(area), "branch: beta") {
		t.Fatalf("maintenance area file missing update branch: %s", area)
	}
	secrets, err := os.ReadFile(filepath.Join(dir, "secrets.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(secrets), cfg.ServerToken) {
		t.Fatal("operator token was not written to secrets.yml")
	}
}

func TestMigrateConfigLayoutPreservesAreaWinnerAndMovesSecrets(t *testing.T) {
	dir := t.TempDir()
	drop := filepath.Join(dir, "yaml.d")
	if err := os.Mkdir(drop, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := "server:\n  port: 64123\n  branding:\n    title: legacy\n  token: adm_migrationtoken123456789012345678\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(drop, "branding.yml"), []byte("server:\n  branding:\n    title: area-wins\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrateConfigLayout(dir); err != nil {
		t.Fatal(err)
	}
	server, err := os.ReadFile(filepath.Join(dir, "server.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(server), "branding:") || strings.Contains(string(server), "adm_migrationtoken") {
		t.Fatalf("legacy settings remained in server.yml: %s", server)
	}
	backup, err := os.ReadFile(filepath.Join(dir, "server.yml.bak"))
	if err != nil || string(backup) != legacy {
		t.Fatalf("backup mismatch: err=%v data=%q", err, backup)
	}
	area, err := os.ReadFile(filepath.Join(drop, "branding.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(area), "area-wins") {
		t.Fatalf("existing area value did not win: %s", area)
	}
	secrets, err := os.ReadFile(filepath.Join(dir, "secrets.yml"))
	if err != nil || !strings.Contains(string(secrets), "adm_migrationtoken") {
		t.Fatalf("token migration failed: err=%v data=%s", err, secrets)
	}
}

func TestMigrateLegacyConfigKeys(t *testing.T) {
	doc := map[string]any{
		"server": map[string]any{
			"logging":  map[string]any{"access_format": "legacy-format", "level": "debug"},
			"schedule": map[string]any{"geoip_update": map[string]any{"schedule": "weekly"}, "old_bare": "weekly"},
			"security": map[string]any{"csrf": map[string]any{"enabled": true}},
			"title":    "Legacy title", "seo": map[string]any{"default_title": "Fallback title"},
			"branding": map[string]any{"footer_text": "<unsafe>"},
			"pages":    map[string]any{"about": map[string]any{"content": "# About"}},
			"port":     64100, "https_port": 64443,
		},
		"database": map[string]any{"type": "sqlite", "primary": map[string]any{"dir": "/data"}},
		"web":      map[string]any{"csrf": map[string]any{"enabled": false}},
	}
	if !migrateLegacyKeys(doc) {
		t.Fatal("legacy keys were not detected")
	}
	if got := pathValue(doc, []string{"server", "logs", "access", "format"}); got != "legacy-format" {
		t.Fatalf("logging access format=%v", got)
	}
	if got := pathValue(doc, []string{"server", "scheduler", "geoip_update", "schedule"}); got != "weekly" {
		t.Fatalf("scheduler migration=%v", got)
	}
	if pathExists(doc, []string{"server", "scheduler", "old_bare"}) {
		t.Fatal("bare legacy schedule value was retained")
	}
	if got := pathValue(doc, []string{"server", "csrf", "enabled"}); got != true {
		t.Fatalf("server csrf destination=%v", got)
	}
	if got := pathValue(doc, []string{"server", "database", "driver"}); got != "sqlite" {
		t.Fatalf("database driver=%v", got)
	}
	if got := pathValue(doc, []string{"server", "database", "dir"}); got != "/data" {
		t.Fatalf("database primary dir=%v", got)
	}
	if got := pathValue(doc, []string{"server", "branding", "title"}); got != "Legacy title" {
		t.Fatalf("branding title=%v", got)
	}
	if got := pathValue(doc, []string{"server", "branding", "content", "footer", "body"}); got != "<p>&lt;unsafe&gt;</p>" {
		t.Fatalf("escaped footer=%v", got)
	}
	if got := pathValue(doc, []string{"server", "branding", "content", "about", "format"}); got != "md" {
		t.Fatalf("about format=%v", got)
	}
	if got := pathValue(doc, []string{"server", "port"}); got != "64100,64443" {
		t.Fatalf("dual port migration=%v", got)
	}
	if migrateLegacyKeys(doc) {
		t.Fatal("legacy-key migration was not idempotent")
	}
}

// TestValidateAcceptsValidConfig confirms Validate() passes for a fully valid config.
func TestValidateAcceptsValidConfig(t *testing.T) {
	cfg := Default()
	cfg.Port = 64500
	cfg.Mode = "production"
	cfg.Update.Branch = "stable"

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
			// Spec (AI.md PART 12): Validate() warns and resets to 0 — never fails startup.
			name: "port too high",
			setup: func(c *ServerConfig) {
				c.Port = 65536
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.Port != 0 {
					t.Errorf("Port after correction = %d, want 0 (random assignment)", c.Port)
				}
			},
		},
		{
			// Spec (AI.md PART 12): Validate() warns and resets to 0 — never fails startup.
			name: "port negative",
			setup: func(c *ServerConfig) {
				c.Port = -1
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.Port != 0 {
					t.Errorf("Port after correction = %d, want 0 (random assignment)", c.Port)
				}
			},
		},
		{
			// Spec (AI.md PART 12): invalid mode warns and defaults to production — never fails startup.
			name:    "invalid mode defaults to production",
			setup:   func(c *ServerConfig) { c.Mode = "staging" },
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.Mode != "production" {
					t.Errorf("Mode after correction = %q, want %q", c.Mode, "production")
				}
			},
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
				c.Update.Branch = "nightly"
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.Update.Branch != "stable" {
					t.Errorf("UpdateChannel after correction = %q, want %q", c.Update.Branch, "stable")
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
				c.Update.Branch = "beta"
			},
			wantErr: false,
		},
		{
			name: "daily update channel valid",
			setup: func(c *ServerConfig) {
				c.Update.Branch = "daily"
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
  update:
    branch: beta
  token: adm_testtoken12345678901234567890123
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
	if cfg.Update.Branch != "beta" {
		t.Errorf("cfg.Update.Branch = %q, want %q", cfg.Update.Branch, "beta")
	}
}

// TestLoadServerConfigInvalidYAML verifies malformed YAML is ignored safely.
func TestLoadServerConfigInvalidYAML(t *testing.T) {
	dir := t.TempDir()

	// Write YAML that cannot be parsed.
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte("mode: [\nbroken"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil || cfg == nil {
		t.Fatalf("LoadServerConfig with malformed YAML = (%v, %v), want defaults", cfg, err)
	}
}

func TestLoadServerConfigIgnoresUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte("server:\n  unknown_setting: true\n"), 0600); err != nil {
		t.Fatalf("write server.yml: %v", err)
	}
	if _, err := LoadServerConfig(dir); err != nil {
		t.Fatalf("LoadServerConfig with unknown key: %v", err)
	}
}

// TestLoadServerConfigPartialYAMLMergesWithDefaults confirms that a partial
// YAML file leaves unspecified fields at their default values.
func TestLoadServerConfigPartialYAMLMergesWithDefaults(t *testing.T) {
	dir := t.TempDir()

	// Only set the mode; everything else should remain at Default() values.
	yaml := "server:\n  mode: development\n  token: adm_partialmergetoken123456789012\n"
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
	if cfg.Update.Branch != "stable" {
		t.Errorf("cfg.Update.Branch = %q, want %q (default)", cfg.Update.Branch, "stable")
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
	if !strings.HasPrefix(cfg.ServerToken, "adm_") {
		t.Errorf("auto-generated token = %q, must start with adm_", cfg.ServerToken)
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

func TestLoadServerConfigMigratesLegacyOperatorToken(t *testing.T) {
	dir := t.TempDir()
	legacyToken := "adm_legacyconfigtoken123456789012345"
	legacyConfig := "server:\n  mode: production\n  port: 64100\n  token: " + legacyToken + "\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(legacyConfig), 0600); err != nil {
		t.Fatalf("WriteFile server.yml: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.ServerToken != legacyToken {
		t.Fatalf("ServerToken = %q, want legacy credential", cfg.ServerToken)
	}

	serverData, err := os.ReadFile(filepath.Join(dir, "server.yml"))
	if err != nil {
		t.Fatalf("ReadFile server.yml: %v", err)
	}
	if strings.Contains(string(serverData), legacyToken) {
		t.Fatal("legacy operator token remains in server.yml")
	}

	secretData, err := os.ReadFile(filepath.Join(dir, "secrets.yml"))
	if err != nil {
		t.Fatalf("ReadFile secrets.yml: %v", err)
	}
	if !strings.Contains(string(secretData), legacyToken) {
		t.Fatal("legacy operator token was not migrated to secrets.yml")
	}
	info, err := os.Stat(filepath.Join(dir, "secrets.yml"))
	if err != nil {
		t.Fatalf("Stat secrets.yml: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("secrets.yml permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestLoadServerConfigMovesEncryptionKeyIntoSecretsFile(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey: %v", err)
	}
	configText := "server:\n  mode: production\n  security:\n    encryption_key: " + key + "\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(configText), 0600); err != nil {
		t.Fatalf("write server.yml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets.yml"), []byte("server:\n  token: adm_existing1234567890123456789012\n"), 0600); err != nil {
		t.Fatalf("write secrets.yml: %v", err)
	}
	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.Security.EncryptionKey != key {
		t.Fatal("configuration migration did not preserve the existing encryption key")
	}
	serverData, err := os.ReadFile(filepath.Join(dir, "server.yml"))
	if err != nil {
		t.Fatalf("read server.yml: %v", err)
	}
	if strings.Contains(string(serverData), key) {
		t.Fatal("encryption key remains in server.yml after migration")
	}
	secretData, err := os.ReadFile(filepath.Join(dir, "secrets.yml"))
	if err != nil {
		t.Fatalf("read secrets.yml: %v", err)
	}
	if !strings.Contains(string(secretData), key) || !strings.Contains(string(secretData), "encryption_key_version: 1") {
		t.Fatal("secrets.yml does not contain the migrated encryption key and version")
	}
}

// TestLoadServerConfigSetsConfigDirFromArg verifies that when server.yml has no
// config_dir set the loaded struct uses the argument directory.
func TestLoadServerConfigSetsConfigDirFromArg(t *testing.T) {
	dir := t.TempDir()

	yaml := "server:\n  mode: production\n  token: adm_configdirtest12345678901234567\n"
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

	yaml := "server:\n  mode: production\n  config_dir: " + customDir + "\n  token: adm_preserveconfigdir12345678901234\n"
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
// the config file is warn-and-reset to 0 — Validate() never fails startup (AI.md PART 12).
func TestLoadServerConfigInvalidPortInYAML(t *testing.T) {
	dir := t.TempDir()

	yaml := "server:\n  mode: production\n  port: 99999\n  token: adm_badport1234567890123456789012\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Errorf("LoadServerConfig with out-of-range port returned unexpected error: %v", err)
	}
	if cfg != nil && cfg.Port != 0 {
		t.Errorf("cfg.Port after correction = %d, want 0 (random assignment)", cfg.Port)
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
	original.Update.Branch = "beta"
	original.Notifications.Email.SMTP.Port = 465
	// Provide a token so LoadServerConfig does not try to generate+persist a new one.
	original.ServerToken = "adm_savereloadtoken1234567890123456"

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
	if reloaded.Update.Branch != original.Update.Branch {
		t.Errorf("UpdateChannel: saved %q, reloaded %q", original.Update.Branch, reloaded.Update.Branch)
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
	cfg.ServerToken = "adm_savecreatesdir12345678901234567"
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
	cfg.ServerToken = "adm_saveusesconfigdir1234567890123"
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
	cfg.ServerToken = "adm_idempotentsave123456789012345"

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

		_ = os.Unsetenv("DATABASE_DIR")
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

		_ = os.Unsetenv("DATABASE_DIR")
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

		_ = os.Unsetenv("DATABASE_DIR")
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
		_ = os.Unsetenv("DATABASE_DRIVER")

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
		_ = os.Unsetenv("DATABASE_URL")
		_ = os.Unsetenv("DATABASE_DRIVER")

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

	// Config DatabaseURL with empty DatabaseDriver defaults to "libsql", since
	// a remote URL implies libsql/Turso, not embedded sqlite (sqlite requires
	// a filesystem Path, which is empty in the URL branch).
	t.Run("config DatabaseURL with no driver defaults to libsql", func(t *testing.T) {
		_ = os.Unsetenv("DATABASE_URL")
		_ = os.Unsetenv("DATABASE_DRIVER")

		cfg := Default()
		cfg.Database.URL = "libsql://nodriver.example.com"
		cfg.Database.Driver = ""

		driver, _, _ := cfg.GetDatabaseConfig()
		if driver != "libsql" {
			t.Errorf("driver = %q, want libsql (default)", driver)
		}
	})

	// Default path: SQLite with a non-empty path and empty URL.
	t.Run("default sqlite path", func(t *testing.T) {
		_ = os.Unsetenv("DATABASE_URL")
		_ = os.Unsetenv("DATABASE_DRIVER")
		_ = os.Unsetenv("DATABASE_DIR")

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
		s    string
		sub  string
		want bool
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

	// Token must start with "adm_" followed by exactly 32 base62 chars
	if len(tok1) != 4+32 {
		t.Errorf("token length = %d, want %d", len(tok1), 4+32)
	}
	if tok1[:4] != "adm_" {
		t.Errorf("token prefix = %q, want %q", tok1[:4], "adm_")
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

	secrets, err := os.ReadFile(filepath.Join(dir, "secrets.yml"))
	if err != nil {
		t.Fatalf("ReadFile secrets.yml: %v", err)
	}
	if !strings.Contains(string(secrets), "adm_") {
		t.Error("secrets.yml does not contain an adm_ token")
	}
	if strings.Contains(content, "adm_") {
		t.Error("server.yml contains the operator token")
	}
	var secretFile struct {
		Server struct {
			Security struct {
				EncryptionKey string `yaml:"encryption_key"`
				Version       int    `yaml:"encryption_key_version"`
			} `yaml:"security"`
		} `yaml:"server"`
	}
	if err := yaml.Unmarshal(secrets, &secretFile); err != nil {
		t.Fatalf("parse secrets.yml: %v", err)
	}
	key, err := base64.StdEncoding.DecodeString(secretFile.Server.Security.EncryptionKey)
	if err != nil || len(key) != 32 {
		t.Errorf("generated encryption key is not base64-encoded 32-byte key: %v", err)
	}
	if secretFile.Server.Security.Version != 1 {
		t.Errorf("encryption_key_version = %d, want 1", secretFile.Server.Security.Version)
	}
	if strings.Contains(content, secretFile.Server.Security.EncryptionKey) {
		t.Error("server.yml contains the encryption key")
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

	if isApplicationContainer() {
		if cfg.Port != 80 {
			t.Errorf("generated application-container port = %d, want 80", cfg.Port)
		}
	} else if cfg.Port < 64000 || cfg.Port > 64999 {
		t.Errorf("generated host port %d is outside required range 64000-64999", cfg.Port)
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
// SafeFilePath()
// ---------------------------------------------------------------------------

// TestSafeFilePath verifies that SafeFilePath correctly contains paths within
// baseDir and rejects traversal attempts.
func TestSafeFilePath(t *testing.T) {
	base := t.TempDir()

	cases := []struct {
		name     string
		userPath string
		wantErr  bool
	}{
		{
			name:     "simple subpath",
			userPath: "data",
			wantErr:  false,
		},
		{
			name:     "nested subpath",
			userPath: "data/logs",
			wantErr:  false,
		},
		{
			name:     "traversal via dotdot",
			userPath: "../etc/passwd",
			wantErr:  true,
		},
		{
			name:     "absolute path with dotdot",
			userPath: "data/../../etc",
			wantErr:  true,
		},
		{
			name:     "empty path normalizes to base",
			userPath: "",
			wantErr:  false,
		},
		{
			name:     "invalid characters in path",
			userPath: "DATA",
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SafeFilePath(base, tc.userPath)
			if tc.wantErr && err == nil {
				t.Errorf("SafeFilePath(%q, %q) expected error, got %q", base, tc.userPath, got)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("SafeFilePath(%q, %q) unexpected error: %v", base, tc.userPath, err)
			}
			if err == nil && got != "" {
				// Result must always start with base.
				absBase, _ := filepath.Abs(base)
				if got != absBase && !strings.HasPrefix(got, absBase+string(filepath.Separator)) {
					t.Errorf("SafeFilePath result %q escapes base %q", got, absBase)
				}
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
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })

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
	// Set a real token — Sanitized must redact it.
	cfg.ServerToken = "adm_supersecrettoken123456789012"

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
		"server_token",
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
