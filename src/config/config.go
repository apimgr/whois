package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LogFileConfig holds per-log-file settings from server.yml (AI.md PART 11).
type LogFileConfig struct {
	// Enabled controls whether this log file is written (false = discard).
	Enabled  bool   `yaml:"enabled"`
	Filename string `yaml:"filename"`
	// Format selects the output format (apache/nginx/json for access; text/json for server/error).
	Format   string `yaml:"format"`
	Custom   string `yaml:"custom"`
	// Rotate is the rotation policy: daily, weekly, monthly, yearly, NMB, NGB, or combined.
	Rotate   string `yaml:"rotate"`
	// Keep is the retention policy: none, N, Nd, Nw, Nm, forever.
	Keep     string `yaml:"keep"`
	// Compress rotated files (only useful when keep > 0).
	Compress bool   `yaml:"compress"`
}

// LogsConfig mirrors the server.logs block in server.yml (AI.md PART 11).
type LogsConfig struct {
	// Level is the global log level: debug, info, warn, error.
	Level    string       `yaml:"level"`
	Access   LogFileConfig `yaml:"access"`
	Server   LogFileConfig `yaml:"server"`
	Error    LogFileConfig `yaml:"error"`
	Audit    LogFileConfig `yaml:"audit"`
	Security LogFileConfig `yaml:"security"`
	Debug    LogFileConfig `yaml:"debug"`
}

// DefaultLogsConfig returns the spec-default logging configuration.
func DefaultLogsConfig() LogsConfig {
	return LogsConfig{
		Level: "warn",
		Access: LogFileConfig{
			Enabled:  true,
			Filename: "access.log",
			Format:   "apache",
			Rotate:   "monthly",
			Keep:     "none",
		},
		Server: LogFileConfig{
			Enabled:  true,
			Filename: "server.log",
			Format:   "text",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
		Error: LogFileConfig{
			Enabled:  true,
			Filename: "error.log",
			Format:   "text",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
		Audit: LogFileConfig{
			Enabled:  true,
			Filename: "audit.log",
			Format:   "json",
			Rotate:   "daily",
			Keep:     "none",
			Compress: false,
		},
		Security: LogFileConfig{
			Enabled:  true,
			Filename: "security.log",
			Format:   "fail2ban",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
		Debug: LogFileConfig{
			Enabled:  false,
			Filename: "debug.log",
			Format:   "text",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
	}
}

// RateLimitEndpointConfig holds per-endpoint-class rate-limit settings (AI.md PART 12).
type RateLimitEndpointConfig struct {
	// Requests is the max number of requests allowed per window.
	Requests int `yaml:"requests"`
	// Window is the sliding window length in seconds.
	Window int `yaml:"window"`
}

// RateLimitConfig holds rate-limiting settings for each endpoint class (AI.md PART 12).
type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"`
	// Read covers GET/HEAD endpoints.
	Read RateLimitEndpointConfig `yaml:"read"`
	// Write covers POST/PUT/PATCH/DELETE endpoints.
	Write RateLimitEndpointConfig `yaml:"write"`
	// Health covers /healthz, /readyz, /livez.
	Health RateLimitEndpointConfig `yaml:"health"`
	// GlobalBurst is the absolute per-IP ceiling across all endpoint types per minute.
	GlobalBurst int `yaml:"global_burst"`
}

// ContactWebhooksConfig holds webhook delivery URLs for a contact role (AI.md PART 12).
type ContactWebhooksConfig struct {
	Telegram string `yaml:"telegram"`
	Discord  string `yaml:"discord"`
	Slack    string `yaml:"slack"`
	Generic  string `yaml:"generic"`
}

// ContactRoleConfig holds the email address and webhooks for a single contact role.
type ContactRoleConfig struct {
	Email    string                `yaml:"email"`
	Webhooks ContactWebhooksConfig `yaml:"webhooks"`
}

// ContactConfig mirrors the server.contact block in server.yml (AI.md PART 12).
// Three roles: admin (server-internal alerts), security (vuln reports), general (contact form).
type ContactConfig struct {
	Admin    ContactRoleConfig `yaml:"admin"`
	Security ContactRoleConfig `yaml:"security"`
	General  ContactRoleConfig `yaml:"general"`
}

// LimitsConfig holds request size and timeout settings (AI.md PART 12).
type LimitsConfig struct {
	// MaxBodySize is the maximum allowed request body (e.g. "10MB").
	MaxBodySize string `yaml:"max_body_size"`
	// ReadTimeout is the HTTP read timeout (e.g. "30s").
	ReadTimeout string `yaml:"read_timeout"`
	// WriteTimeout is the HTTP write timeout (e.g. "30s").
	WriteTimeout string `yaml:"write_timeout"`
	// IdleTimeout is the HTTP idle connection timeout (e.g. "120s").
	IdleTimeout string `yaml:"idle_timeout"`
}

// CompressionConfig holds response compression settings (AI.md PART 12).
type CompressionConfig struct {
	Enabled bool `yaml:"enabled"`
	// Level is 1–9 (1=fastest, 9=best compression).
	Level int      `yaml:"level"`
	Types []string `yaml:"types"`
}

// TrustedProxiesConfig holds trusted reverse-proxy settings (AI.md PART 12).
type TrustedProxiesConfig struct {
	// Additional is a list of IP addresses, CIDRs, or DNS names to trust for X-Forwarded headers.
	Additional []string `yaml:"additional"`
}

// I18nConfig holds internationalization settings (AI.md PART 12).
type I18nConfig struct {
	DefaultLanguage string   `yaml:"default_language"`
	Supported       []string `yaml:"supported"`
}

// SchedulerConfig holds scheduler settings (AI.md PART 18).
type SchedulerConfig struct {
	// Timezone for scheduled tasks (IANA timezone name, e.g. "America/New_York")
	Timezone string `yaml:"timezone"`
	// CatchUpWindow is how far back the scheduler replays missed tasks on restart ("1h", "30m", etc.)
	CatchUpWindow string `yaml:"catch_up_window"`
}

// ServerConfig holds all server configuration
type ServerConfig struct {
	// Server settings
	Port      int    `yaml:"port"`
	Address   string `yaml:"address"`
	Mode      string `yaml:"mode"`
	FQDN      string `yaml:"fqdn"`
	Daemonize bool   `yaml:"daemonize"`
	PIDFile   bool   `yaml:"pidfile"`
	// BaseURL is the URL path prefix for all routes (AI.md PART 12 — baseurl).
	BaseURL string `yaml:"baseurl"`

	// Path settings.
	ConfigDir string `yaml:"config_dir"`
	DataDir   string `yaml:"data_dir"`
	LogDir    string `yaml:"log_dir"`
	CacheDir  string `yaml:"cache_dir"`
	// DatabaseDir is the SQLite database directory.
	DatabaseDir string `yaml:"database_dir"`

	// Database settings (PART 10 — SQLite or libsql/Turso only; never PostgreSQL or MySQL).
	// DatabaseDriver is "sqlite" (default) or "libsql"; empty means auto-detect from URL.
	DatabaseDriver string `yaml:"database_driver"`
	// DatabaseURL is the libsql/Turso connection string when using a remote database.
	DatabaseURL string `yaml:"database_url"`

	// Branding settings
	BrandingTitle       string `yaml:"branding_title"`
	BrandingTagline     string `yaml:"branding_tagline"`
	BrandingDescription string `yaml:"branding_description"`
	BrandingTheme       string `yaml:"branding_theme"`        // auto, light, dark
	BrandingAccentColor string `yaml:"branding_accent_color"` // hex color

	// Request size and timeout limits (AI.md PART 12)
	Limits LimitsConfig `yaml:"limits"`

	// Response compression settings (AI.md PART 12)
	Compression CompressionConfig `yaml:"compression"`

	// Trusted reverse-proxy settings (AI.md PART 12)
	TrustedProxies TrustedProxiesConfig `yaml:"trusted_proxies"`

	// Internationalization settings (AI.md PART 12)
	I18n I18nConfig `yaml:"i18n"`

	// Rate limiting settings (AI.md PART 12 — nested per endpoint class)
	RateLimit RateLimitConfig `yaml:"rate_limit"`

	// GeoIP settings (AI.md PART 19)
	GeoIPEnabled          bool   `yaml:"geoip_enabled"`
	GeoIPDir              string `yaml:"geoip_dir"`
	GeoIPDatabaseASN      bool   `yaml:"geoip_database_asn"`
	GeoIPDatabaseCountry  bool   `yaml:"geoip_database_country"`
	GeoIPDatabaseCity     bool   `yaml:"geoip_database_city"`
	GeoIPDatabaseWHOIS    bool   `yaml:"geoip_database_whois"`
	// GeoIPDenyCountries blocks requests from listed countries (ISO 3166-1 alpha-2).
	GeoIPDenyCountries    []string `yaml:"geoip_deny_countries"`
	// GeoIPAllowCountries allows only requests from listed countries; takes precedence over deny list.
	// Empty = allowlist mode disabled (all countries allowed unless in deny list).
	GeoIPAllowCountries   []string `yaml:"geoip_allow_countries"`

	// Metrics settings (AI.md PART 20)
	MetricsEnabled        bool   `yaml:"metrics_enabled"`
	MetricsEndpoint       string `yaml:"metrics_endpoint"`
	MetricsIncludeSystem  bool   `yaml:"metrics_include_system"`
	MetricsIncludeRuntime bool   `yaml:"metrics_include_runtime"`
	MetricsToken          string `yaml:"metrics_token"`

	// Backup settings (AI.md PART 21)
	BackupDir              string `yaml:"backup_dir"`              // Backup directory
	BackupEncryptionEnabled bool   `yaml:"backup_encryption_enabled"` // Encryption enabled
	BackupMaxBackups       int    `yaml:"backup_max_backups"`        // Daily full backups to keep (≥1)
	BackupKeepWeekly       int    `yaml:"backup_keep_weekly"`        // Weekly backups (Sunday) - 0 = disabled
	BackupKeepMonthly      int    `yaml:"backup_keep_monthly"`       // Monthly backups (1st) - 0 = disabled
	BackupKeepYearly       int    `yaml:"backup_keep_yearly"`        // Yearly backups (Jan 1st) - 0 = disabled

	// Compliance settings (AI.md PART 21)
	ComplianceEnabled bool `yaml:"compliance_enabled"` // HIPAA, SOC2, etc. - requires encrypted backups

	// Update settings (PART 23)
	UpdateChannel string `yaml:"update_channel"` // stable, beta, daily

	// Tor hidden service settings (PART 31)
	TorBinary                    string `yaml:"tor_binary"`
	TorUseNetwork                bool   `yaml:"tor_use_network"`
	TorMaxCircuits               int    `yaml:"tor_max_circuits"`
	TorCircuitTimeout            int    `yaml:"tor_circuit_timeout"`
	TorBootstrapTimeout          int    `yaml:"tor_bootstrap_timeout"`
	TorSafeLogging               bool   `yaml:"tor_safe_logging"`
	TorMaxStreamsPerCircuit       int    `yaml:"tor_max_streams_per_circuit"`
	TorCloseCircuitOnStreamLimit bool   `yaml:"tor_close_circuit_on_stream_limit"`
	TorBandwidthRate             string `yaml:"tor_bandwidth_rate"`
	TorBandwidthBurst            string `yaml:"tor_bandwidth_burst"`
	TorMaxMonthlyBandwidth       string `yaml:"tor_max_monthly_bandwidth"`
	TorNumIntroPoints            int    `yaml:"tor_num_intro_points"`
	TorVirtualPort               int    `yaml:"tor_virtual_port"`

	// SMTP / Email settings (PART 17)
	// If host is empty, SMTP auto-detection runs on startup.
	SMTPHost      string `yaml:"smtp_host"`
	SMTPPort      int    `yaml:"smtp_port"`
	SMTPUsername  string `yaml:"smtp_username"`
	SMTPPassword  string `yaml:"smtp_password"`
	// SMTPTLSMode: auto, starttls, tls, none
	SMTPTLSMode   string `yaml:"smtp_tls"`
	EmailFromName  string `yaml:"email_from_name"`
	EmailFromEmail string `yaml:"email_from_email"`

	// Contact configuration (AI.md PART 12)
	Contact ContactConfig `yaml:"contact"`

	// Logging configuration (AI.md PART 11)
	Logs LogsConfig `yaml:"logs"`

	// Scheduler configuration (AI.md PART 18)
	Scheduler SchedulerConfig `yaml:"scheduler"`

	// Debug mode
	Debug bool `yaml:"debug"`

	// Security
	// ServerToken is the global operator token (auto-generated on first run if empty).
	// Stored as-is in server.yml; validated by SHA-256-hashing the inbound bearer
	// token and comparing with subtle.ConstantTimeCompare — never written to the DB.
	ServerToken string   `yaml:"server_token"`
	APITokens   []string `yaml:"api_tokens"`
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
		DatabaseDriver:      "", // Auto-detect: sqlite or libsql from DATABASE_URL
		DatabaseURL:         "", // From DATABASE_URL env var
		BaseURL:             "/",
		BrandingTitle:       "caswhois",
		BrandingTagline:     "",
		BrandingDescription: "",
		BrandingTheme:       "auto",
		BrandingAccentColor: "#007bff",
		Limits: LimitsConfig{
			MaxBodySize:  "10MB",
			ReadTimeout:  "30s",
			WriteTimeout: "30s",
			IdleTimeout:  "120s",
		},
		Compression: CompressionConfig{
			Enabled: true,
			Level:   5,
			Types: []string{
				"text/html",
				"text/css",
				"text/javascript",
				"application/json",
				"application/xml",
			},
		},
		TrustedProxies: TrustedProxiesConfig{
			Additional: []string{},
		},
		I18n: I18nConfig{
			DefaultLanguage: "en",
			Supported:       []string{"en"},
		},
		RateLimit: RateLimitConfig{
			Enabled:     true,
			Read:        RateLimitEndpointConfig{Requests: 120, Window: 60},
			Write:       RateLimitEndpointConfig{Requests: 10, Window: 60},
			Health:      RateLimitEndpointConfig{Requests: 120, Window: 60},
			GlobalBurst: 240,
		},
		GeoIPEnabled:        true,
		GeoIPDir:            "",  // Will be determined by OS ({data_dir}/security/geoip)
		GeoIPDatabaseASN:    true,
		GeoIPDatabaseCountry: true,
		GeoIPDatabaseCity:   true,
		GeoIPDatabaseWHOIS:  true,
		GeoIPDenyCountries:  []string{},
		GeoIPAllowCountries: []string{},
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
		UpdateChannel:                "stable",
		TorBinary:                    "",
		TorUseNetwork:                false,
		TorMaxCircuits:               32,
		TorCircuitTimeout:            60,
		TorBootstrapTimeout:          180,
		TorSafeLogging:               true,
		TorMaxStreamsPerCircuit:       100,
		TorCloseCircuitOnStreamLimit: true,
		TorBandwidthRate:             "1 MB",
		TorBandwidthBurst:            "2 MB",
		TorMaxMonthlyBandwidth:       "100 GB",
		TorNumIntroPoints:            3,
		TorVirtualPort:               80,
		SMTPHost:      "",     // empty = auto-detect on startup
		SMTPPort:      587,
		SMTPUsername:  "",
		SMTPPassword:  "",
		SMTPTLSMode:   "auto",
		EmailFromName:  "",    // default: branding title
		EmailFromEmail: "",    // default: no-reply@{fqdn}
		Contact: ContactConfig{
			Admin:    ContactRoleConfig{Email: ""},
			Security: ContactRoleConfig{Email: ""},
			General:  ContactRoleConfig{Email: ""},
		},
		Logs: DefaultLogsConfig(),
		Scheduler: SchedulerConfig{
			Timezone:      "America/New_York",
			CatchUpWindow: "1h",
		},
		Debug:               false,
		ServerToken:         "", // auto-generated on first run
		APITokens:           []string{},
	}
}

// LoadServerConfig reads server.yml from the specified directory
func LoadServerConfig(configDir string) (*ServerConfig, error) {
	if configDir == "" {
		return nil, fmt.Errorf("config directory not specified")
	}

	configPath := filepath.Join(configDir, "server.yml")

	// If config doesn't exist, write defaults to disk and return them (first-run experience).
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		cfg := Default()
		cfg.ConfigDir = configDir
		// Generate server token on first run.
		tok, genErr := GenerateToken()
		if genErr == nil {
			cfg.ServerToken = tok
		}
		// Write the default config so the operator can inspect and edit it.
		if saveErr := cfg.Save(configDir); saveErr != nil {
			fmt.Printf("WARNING: could not write default config to %s: %v\n", configPath, saveErr)
		}
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

	// Auto-generate server token on first run if absent
	if cfg.ServerToken == "" {
		tok, err := GenerateToken()
		if err != nil {
			return nil, fmt.Errorf("generate server token: %w", err)
		}
		cfg.ServerToken = tok
		// Persist token back to server.yml so it survives restarts
		if saveErr := cfg.Save(configDir); saveErr != nil {
			// Non-fatal: token still works this session but won't persist
			fmt.Printf("WARNING: could not persist server token: %v\n", saveErr)
		}
	}

	// Validate paths
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *ServerConfig) Validate() error {
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

	// 4. Native default derived from DataDir when explicitly set
	if c.DataDir != "" {
		return filepath.Join(c.DataDir, "db")
	}

	// 5. Root native: /var/lib/casapps/caswhois/db (AI.md PART 4)
	if os.Getuid() == 0 {
		return "/var/lib/casapps/caswhois/db"
	}

	// 6. User native: ~/.local/share/casapps/caswhois/db (AI.md PART 4)
	home, err := os.UserHomeDir()
	if err != nil {
		return "./db"
	}
	return filepath.Join(home, ".local", "share", "casapps", "caswhois", "db")
}

// GetBackupDir returns the backup directory per AI.md PART 4.
// Priority: Explicit config → Container default → Root native → User native
func (c *ServerConfig) GetBackupDir() string {
	// 1. Explicit configuration (server.yml backup_dir or --backup CLI flag)
	if c.BackupDir != "" {
		return c.BackupDir
	}

	// 2. Container default: /data/backups/caswhois (AI.md PART 4)
	if isContainer() {
		return "/data/backups/caswhois"
	}

	// 3. Root native: /mnt/Backups/casapps/caswhois (AI.md PART 4)
	if os.Getuid() == 0 {
		return "/mnt/Backups/casapps/caswhois"
	}

	// 4. User native: ~/.local/share/Backups/casapps/caswhois (AI.md PART 4)
	home, err := os.UserHomeDir()
	if err != nil {
		return "./backups"
	}
	return filepath.Join(home, ".local", "share", "Backups", "casapps", "caswhois")
}

// GetLogDir returns the log directory per AI.md PART 4.
// Priority: Explicit config → Container default → Root native → User native
func (c *ServerConfig) GetLogDir() string {
	// 1. Explicit configuration (server.yml log_dir or --log CLI flag)
	if c.LogDir != "" {
		return c.LogDir
	}

	// 2. Container default: /data/log/caswhois (AI.md PART 4)
	if isContainer() {
		return "/data/log/caswhois"
	}

	// 3. Root native: /var/log/casapps/caswhois (AI.md PART 4)
	if os.Getuid() == 0 {
		return "/var/log/casapps/caswhois"
	}

	// 4. User native: ~/.local/log/casapps/caswhois (AI.md PART 4)
	home, err := os.UserHomeDir()
	if err != nil {
		return "./logs"
	}
	return filepath.Join(home, ".local", "log", "casapps", "caswhois")
}

// GetDatabaseConfig returns database configuration from environment and config
func (c *ServerConfig) GetDatabaseConfig() (driver, url, path string) {
	// Check DATABASE_URL first (for libsql/Turso remote)
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		driver = os.Getenv("DATABASE_DRIVER")
		if driver == "" {
			driver = "sqlite" // libsql-compatible
		}
		return driver, dbURL, ""
	}

	// Check config values
	if c.DatabaseURL != "" {
		driver = c.DatabaseDriver
		if driver == "" {
			driver = "sqlite"
		}
		return driver, c.DatabaseURL, ""
	}

	// Default to SQLite
	driver = "sqlite"
	path = c.GetDatabaseDir()
	return driver, "", path
}

// IsContainer detects if running in a container (Docker, LXC, Kubernetes).
func IsContainer() bool {
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

// isContainer is the unexported alias used internally.
func isContainer() bool { return IsContainer() }

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
// IsDebug returns true when debug mode is active (--debug flag or DEBUG env var).
func (c *ServerConfig) IsDebug() bool {
	return c.Debug
}

// IsProduction returns true when the server is running in production mode.
func (c *ServerConfig) IsProduction() bool {
	return c.Mode == "" || c.Mode == "production" || c.Mode == "prod"
}

// IsDevelopment returns true when the server is running in development mode.
func (c *ServerConfig) IsDevelopment() bool {
	return c.Mode == "development" || c.Mode == "dev"
}

// Sanitized returns a copy of the config with sensitive values redacted.
func (c *ServerConfig) Sanitized() map[string]any {
	return map[string]any{
		"address":            c.Address,
		"port":               c.Port,
		"mode":               c.Mode,
		"debug":              c.Debug,
		"data_dir":           c.DataDir,
		"log_dir":            c.LogDir,
		"backup_dir":         c.BackupDir,
		"smtp_tls_mode":      c.SMTPTLSMode,
		"metrics_enabled":    c.MetricsEnabled,
		"metrics_endpoint":   c.MetricsEndpoint,
		"rate_limit_enabled": c.RateLimit.Enabled,
		"server_token":       "xxxxx",
		"api_tokens":         "[redacted]",
	}
}

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
