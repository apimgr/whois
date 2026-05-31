package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
	if cfg.SMTPPort != 587 {
		t.Errorf("Default().SMTPPort = %d, want 587", cfg.SMTPPort)
	}

	// SMTP TLS mode must default to "auto" (PART 17)
	if cfg.SMTPTLSMode != "auto" {
		t.Errorf("Default().SMTPTLSMode = %q, want %q", cfg.SMTPTLSMode, "auto")
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
	if !cfg.RateLimitEnabled {
		t.Error("Default().RateLimitEnabled = false, want true")
	}

	// APITokens must be an empty slice, not nil (avoid JSON null)
	if cfg.APITokens == nil {
		t.Error("Default().APITokens = nil, want empty slice")
	}
}

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
			// BackupMaxBackups ≤ 0 is corrected to 1, no error
			name: "zero backup max corrected to 1",
			setup: func(c *ServerConfig) {
				c.BackupMaxBackups = 0
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.BackupMaxBackups != 1 {
					t.Errorf("BackupMaxBackups after correction = %d, want 1", c.BackupMaxBackups)
				}
			},
		},
		{
			// Negative retention values are clamped to 0
			name: "negative weekly retention clamped to 0",
			setup: func(c *ServerConfig) {
				c.BackupKeepWeekly = -3
			},
			wantErr: false,
			checkAfter: func(t *testing.T, c *ServerConfig) {
				t.Helper()
				if c.BackupKeepWeekly != 0 {
					t.Errorf("BackupKeepWeekly after clamping = %d, want 0", c.BackupKeepWeekly)
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

// TestLoadServerConfigMissingFile verifies that LoadServerConfig returns Default()
// values (no error) when the config directory exists but server.yml does not.
func TestLoadServerConfigMissingFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-config-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

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
	if cfg.SMTPPort != 587 {
		t.Errorf("cfg.SMTPPort = %d, want 587", cfg.SMTPPort)
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
	dir, err := os.MkdirTemp("", "caswhois-config-yaml-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	// Write a minimal valid server.yml that sets a few well-known fields.
	yaml := `mode: development
port: 64123
smtp_port: 465
update_channel: beta
server_token: tok_testtoken12345678901234567890123
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
	if cfg.SMTPPort != 465 {
		t.Errorf("cfg.SMTPPort = %d, want 465", cfg.SMTPPort)
	}
	if cfg.UpdateChannel != "beta" {
		t.Errorf("cfg.UpdateChannel = %q, want %q", cfg.UpdateChannel, "beta")
	}
}

// TestLoadServerConfigInvalidYAML verifies that malformed YAML returns an error.
func TestLoadServerConfigInvalidYAML(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-config-bad-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	// Write YAML that cannot be parsed.
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte("mode: [\nbroken"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = LoadServerConfig(dir)
	if err == nil {
		t.Error("LoadServerConfig(invalid YAML) expected error, got nil")
	}
}

// TestSaveAndReload verifies that Save() writes a file that LoadServerConfig
// reads back with equivalent values.
func TestSaveAndReload(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-save-reload-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	original := Default()
	original.Port = 64321
	original.Mode = "development"
	original.UpdateChannel = "beta"
	original.SMTPPort = 465
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
	if reloaded.SMTPPort != original.SMTPPort {
		t.Errorf("SMTPPort: saved %d, reloaded %d", original.SMTPPort, reloaded.SMTPPort)
	}
}

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

	tok2, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken (second call): %v", err)
	}
	if tok1 == tok2 {
		t.Error("two GenerateToken calls returned identical tokens (collision probability negligible)")
	}
}
