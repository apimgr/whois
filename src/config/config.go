package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ServerConfig holds all server configuration
type ServerConfig struct {
	// Server settings
	Port      int    `yaml:"port"`
	Address   string `yaml:"address"`
	Mode      string `yaml:"mode"`
	FQDN      string `yaml:"fqdn"`
	Daemonize bool   `yaml:"daemonize"`
	PIDFile   bool   `yaml:"pidfile"`

	// Path settings
	ConfigDir   string `yaml:"config_dir"`
	DataDir     string `yaml:"data_dir"`
	LogDir      string `yaml:"log_dir"`
	DatabaseDir string `yaml:"database_dir"` // SQLite database directory

	// Database settings
	DatabaseDriver string `yaml:"database_driver"` // sqlite, postgres, mysql
	DatabaseURL    string `yaml:"database_url"`    // Connection string for remote DB

	// Admin path
	AdminPath string `yaml:"admin_path"`

	// Branding settings
	BrandingTitle       string `yaml:"branding_title"`
	BrandingTagline     string `yaml:"branding_tagline"`
	BrandingDescription string `yaml:"branding_description"`
	BrandingTheme       string `yaml:"branding_theme"`        // auto, light, dark
	BrandingAccentColor string `yaml:"branding_accent_color"` // hex color

	// Rate limiting settings
	RateLimitEnabled  bool   `yaml:"rate_limit_enabled"`
	RateLimitRequests int    `yaml:"rate_limit_requests"`
	RateLimitWindow   string `yaml:"rate_limit_window"`

	// GeoIP settings (PART 20)
	GeoIPEnabled          bool   `yaml:"geoip_enabled"`
	GeoIPDir              string `yaml:"geoip_dir"`
	GeoIPDatabaseASN      bool   `yaml:"geoip_database_asn"`
	GeoIPDatabaseCountry  bool   `yaml:"geoip_database_country"`
	GeoIPDatabaseCity     bool   `yaml:"geoip_database_city"`
	GeoIPDatabaseWHOIS    bool   `yaml:"geoip_database_whois"`
	GeoIPDenyCountries    []string `yaml:"geoip_deny_countries"`

	// Metrics settings (PART 21)
	MetricsEnabled        bool   `yaml:"metrics_enabled"`
	MetricsEndpoint       string `yaml:"metrics_endpoint"`
	MetricsIncludeSystem  bool   `yaml:"metrics_include_system"`
	MetricsIncludeRuntime bool   `yaml:"metrics_include_runtime"`
	MetricsToken          string `yaml:"metrics_token"`

	// Backup settings (PART 22)
	BackupDir              string `yaml:"backup_dir"`              // Backup directory
	BackupEncryptionEnabled bool   `yaml:"backup_encryption_enabled"` // Encryption enabled
	BackupMaxBackups       int    `yaml:"backup_max_backups"`        // Daily full backups to keep (≥1)
	BackupKeepWeekly       int    `yaml:"backup_keep_weekly"`        // Weekly backups (Sunday) - 0 = disabled
	BackupKeepMonthly      int    `yaml:"backup_keep_monthly"`       // Monthly backups (1st) - 0 = disabled
	BackupKeepYearly       int    `yaml:"backup_keep_yearly"`        // Yearly backups (Jan 1st) - 0 = disabled

	// Compliance settings (PART 22)
	ComplianceEnabled bool `yaml:"compliance_enabled"` // HIPAA, SOC2, etc. - requires encrypted backups

	// Update settings (PART 23)
	UpdateChannel string `yaml:"update_channel"` // stable, beta, daily

	// Debug mode
	Debug bool `yaml:"debug"`

	// Security
	APITokens []string `yaml:"api_tokens"`
}

// Default returns a ServerConfig with sane defaults
func Default() *ServerConfig {
	return &ServerConfig{
		Port:                0, // Random port 64000-64999 on first run
		Address:             "127.0.0.1",
		Mode:                "production",
		FQDN:                "",
		Daemonize:           false,
		PIDFile:             true,
		ConfigDir:           "", // Will be determined by OS
		DataDir:             "", // Will be determined by OS
		LogDir:              "", // Will be determined by OS
		DatabaseDir:         "", // Will be determined by OS
		DatabaseDriver:      "", // Auto-detect: sqlite or postgres from DATABASE_URL
		DatabaseURL:         "", // From DATABASE_URL env var
		AdminPath:           "admin",
		BrandingTitle:       "caswhois",
		BrandingTagline:     "",
		BrandingDescription: "",
		BrandingTheme:       "auto",
		BrandingAccentColor: "#007bff",
		RateLimitEnabled:    true,
		RateLimitRequests:   120,
		RateLimitWindow:     "1m",
		GeoIPEnabled:        true,
		GeoIPDir:            "",  // Will be determined by OS ({config_dir}/security/geoip)
		GeoIPDatabaseASN:    true,
		GeoIPDatabaseCountry: true,
		GeoIPDatabaseCity:   true,
		GeoIPDatabaseWHOIS:  true,
		GeoIPDenyCountries:  []string{},
		MetricsEnabled:        true,
		MetricsEndpoint:       "/metrics",
		MetricsIncludeSystem:  true,
		MetricsIncludeRuntime: true,
		MetricsToken:          "", // No token by default (use firewall)
		BackupDir:              "",  // Will be determined by OS ({data_dir}/backups)
		BackupEncryptionEnabled: false, // Set during setup or in admin panel
		BackupMaxBackups:       1,   // Keep 1 daily full backup (default per spec)
		BackupKeepWeekly:       0,   // 0 = disabled (default per spec)
		BackupKeepMonthly:      0,   // 0 = disabled (default per spec)
		BackupKeepYearly:       0,   // 0 = disabled (default per spec)
		ComplianceEnabled:     false, // HIPAA, SOC2, etc. - requires encrypted backups
		UpdateChannel:         "stable", // stable, beta, daily (default per spec)
		Debug:               false,
		APITokens:           []string{},
	}
}

// LoadServerConfig reads server.yml from the specified directory
func LoadServerConfig(configDir string) (*ServerConfig, error) {
	if configDir == "" {
		return nil, fmt.Errorf("config directory not specified")
	}

	configPath := filepath.Join(configDir, "server.yml")

	// If config doesn't exist, return defaults
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		cfg := Default()
		cfg.ConfigDir = configDir
		return cfg, nil
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Parse YAML
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set config dir if not specified
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = configDir
	}

	// Validate paths
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *ServerConfig) Validate() error {
	// Validate admin path
	if c.AdminPath != "" {
		safe, err := SafePath(c.AdminPath)
		if err != nil {
			return fmt.Errorf("invalid admin_path: %w", err)
		}
		c.AdminPath = safe
	}

	// Port range
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("port must be between 0 and 65535")
	}

	// Mode validation
	if c.Mode != "production" && c.Mode != "development" {
		return fmt.Errorf("mode must be 'production' or 'development'")
	}

	// Backup retention validation (warn, don't error - server must start per spec)
	if c.BackupMaxBackups <= 0 {
		// Warn and use default
		c.BackupMaxBackups = 1
	}
	if c.BackupKeepWeekly < 0 {
		c.BackupKeepWeekly = 0
	}
	if c.BackupKeepMonthly < 0 {
		c.BackupKeepMonthly = 0
	}
	if c.BackupKeepYearly < 0 {
		c.BackupKeepYearly = 0
	}

	// Compliance mode validation
	if c.ComplianceEnabled && !c.BackupEncryptionEnabled {
		// This will be caught at backup time and user will be prompted
		// Don't block server startup
	}

	// Update channel validation
	if c.UpdateChannel != "stable" && c.UpdateChannel != "beta" && c.UpdateChannel != "daily" {
		c.UpdateChannel = "stable"
	}

	return nil
}

// GetDatabaseDir returns the SQLite database directory
// Priority: Explicit config -> DATABASE_DIR env -> Container default -> Native default
func (c *ServerConfig) GetDatabaseDir() string {
	// 1. Explicit configuration
	if c.DatabaseDir != "" {
		return c.DatabaseDir
	}

	// 2. DATABASE_DIR environment variable
	if envDir := os.Getenv("DATABASE_DIR"); envDir != "" {
		return envDir
	}

	// 3. Container default: /data/db/sqlite
	if isContainer() {
		return "/data/db/sqlite"
	}

	// 4. Native default: {data_dir}/db/
	if c.DataDir != "" {
		return filepath.Join(c.DataDir, "db")
	}

	// Fallback to current directory
	return "./db"
}

// GetBackupDir returns the backup directory
// Priority: Explicit config -> Container default -> Native default
func (c *ServerConfig) GetBackupDir() string {
	// 1. Explicit configuration
	if c.BackupDir != "" {
		return c.BackupDir
	}

	// 2. Container default: /data/backups
	if isContainer() {
		return "/data/backups"
	}

	// 3. Native default: {data_dir}/backups
	if c.DataDir != "" {
		return filepath.Join(c.DataDir, "backups")
	}

	// Fallback to current directory
	return "./backups"
}

// GetDatabaseConfig returns database configuration from environment and config
func (c *ServerConfig) GetDatabaseConfig() (driver, url, path string) {
	// Check DATABASE_URL first (for PostgreSQL/MySQL)
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		// Parse driver from URL or use DATABASE_DRIVER env
		driver = os.Getenv("DATABASE_DRIVER")
		if driver == "" {
			// Auto-detect from URL prefix
			if len(dbURL) > 10 {
				if dbURL[:8] == "postgres" || dbURL[:4] == "pg://" {
					driver = "postgres"
				} else if dbURL[:5] == "mysql" {
					driver = "mysql"
				}
			}
			if driver == "" {
				driver = "postgres" // Default to postgres for remote
			}
		}
		return driver, dbURL, ""
	}

	// Check config values
	if c.DatabaseURL != "" {
		driver = c.DatabaseDriver
		if driver == "" {
			driver = "postgres"
		}
		return driver, c.DatabaseURL, ""
	}

	// Default to SQLite
	driver = "sqlite"
	path = c.GetDatabaseDir()
	return driver, "", path
}

// isContainer detects if running in a container
func isContainer() bool {
	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check for container in cgroup
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if len(content) > 0 && (contains(content, "docker") || contains(content, "lxc") || contains(content, "kubepods")) {
			return true
		}
	}

	return false
}

// contains checks if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && hasSubstring(s, substr))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Save writes the configuration to server.yml
func (c *ServerConfig) Save(configDir string) error {
	if configDir == "" {
		configDir = c.ConfigDir
	}
	if configDir == "" {
		return fmt.Errorf("config directory not specified")
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(configDir, "server.yml")

	// Marshal to YAML
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
