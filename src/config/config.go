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

// WebConfig holds top-level web-layer settings (AI.md PART 16).
// In server.yml this lives under the top-level web: key (sibling to server:).
type WebConfig struct {
	// CORS is a comma-separated list of allowed origins.
	// "*" = allow all (default); "" = no CORS headers (same-origin only).
	CORS string `yaml:"cors"`
}

// ConfigFile is the top-level structure of server.yml (AI.md PART 5).
// server: holds all server settings; web: is a sibling section.
type ConfigFile struct {
	Server ServerConfig `yaml:"server"`
	Web    WebConfig    `yaml:"web"`
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

// BackupEncryptionConfig holds backup encryption settings (AI.md PART 21).
type BackupEncryptionConfig struct {
	// Enabled is true when a backup password has been set.
	Enabled bool `yaml:"enabled"`
}

// BackupRetentionConfig holds backup retention policy (AI.md PART 21).
type BackupRetentionConfig struct {
	// MaxBackups is the number of daily full backups to keep (≥1).
	MaxBackups int `yaml:"max_backups"`
	// KeepWeekly is the number of Sunday backups to retain (0 = disabled).
	KeepWeekly int `yaml:"keep_weekly"`
	// KeepMonthly is the number of 1st-of-month backups to retain (0 = disabled).
	KeepMonthly int `yaml:"keep_monthly"`
	// KeepYearly is the number of January-1st backups to retain (0 = disabled).
	KeepYearly int `yaml:"keep_yearly"`
}

// BackupConfig holds backup settings (AI.md PART 21 — server.backup.*).
type BackupConfig struct {
	// Dir is the backup directory (defaults to {data_dir}/backups per PART 4).
	Dir        string                 `yaml:"dir"`
	Encryption BackupEncryptionConfig `yaml:"encryption"`
	Retention  BackupRetentionConfig  `yaml:"retention"`
}

// ComplianceConfig holds compliance mode settings (AI.md PART 21).
type ComplianceConfig struct {
	// Enabled activates compliance mode (HIPAA, SOC2, etc.) — requires encrypted backups.
	Enabled bool `yaml:"enabled"`
}

// TorConfig holds Tor hidden service settings (AI.md PART 31 — server.tor.*).
type TorConfig struct {
	Binary                    string `yaml:"binary"`
	UseNetwork                bool   `yaml:"use_network"`
	MaxCircuits               int    `yaml:"max_circuits"`
	CircuitTimeout            int    `yaml:"circuit_timeout"`
	BootstrapTimeout          int    `yaml:"bootstrap_timeout"`
	SafeLogging               bool   `yaml:"safe_logging"`
	MaxStreamsPerCircuit       int    `yaml:"max_streams_per_circuit"`
	CloseCircuitOnStreamLimit bool   `yaml:"close_circuit_on_stream_limit"`
	BandwidthRate             string `yaml:"bandwidth_rate"`
	BandwidthBurst            string `yaml:"bandwidth_burst"`
	MaxMonthlyBandwidth       string `yaml:"max_monthly_bandwidth"`
	NumIntroPoints            int    `yaml:"num_intro_points"`
	VirtualPort               int    `yaml:"virtual_port"`
}

// MetricsConfig holds Prometheus metrics settings (AI.md PART 20 — server.metrics.*).
type MetricsConfig struct {
	Enabled        bool    `yaml:"enabled"`
	Endpoint       string  `yaml:"endpoint"`
	IncludeSystem  bool    `yaml:"include_system"`
	IncludeRuntime bool    `yaml:"include_runtime"`
	// Token is the optional Bearer token required to scrape /metrics.
	// Empty = no auth (rely on firewall).
	Token string `yaml:"token"`
}

// DatabaseConfig holds database connection settings (AI.md PART 10 — server.database.*).
type DatabaseConfig struct {
	// Driver is the database driver: "sqlite" (default) or "libsql"/"turso".
	// Empty = auto-detect from URL.
	Driver string `yaml:"driver"`
	// URL is the libsql/Turso remote connection string.
	// When set, remote mode is used. Takes precedence over Dir.
	URL string `yaml:"url"`
	// Token is the Turso auth token (used when URL is set without an embedded authToken).
	Token string `yaml:"token"`
	// Dir is the directory containing SQLite files (sqlite driver only).
	Dir string `yaml:"dir"`
}

// BrandingConfig holds branding and SEO settings (AI.md PART 16 — server.branding.*).
type BrandingConfig struct {
	Title       string `yaml:"title"`
	Tagline     string `yaml:"tagline"`
	Description string `yaml:"description"`
	Theme       string `yaml:"theme"`
	AccentColor string `yaml:"accent_color"`
}

// GeoIPDatabasesConfig holds which MMDB databases to enable (AI.md PART 19).
type GeoIPDatabasesConfig struct {
	ASN     bool `yaml:"asn"`
	Country bool `yaml:"country"`
	City    bool `yaml:"city"`
	WHOIS   bool `yaml:"whois"`
}

// GeoIPConfig holds GeoIP settings (AI.md PART 19 — server.geoip.*).
type GeoIPConfig struct {
	Enabled bool   `yaml:"enabled"`
	// Dir is the directory for downloaded MMDB files (defaults to {data_dir}/security/geoip).
	Dir     string `yaml:"dir"`
	// DenyCountries lists ISO 3166-1 alpha-2 country codes to block.
	DenyCountries  []string             `yaml:"deny_countries"`
	// AllowCountries allows ONLY listed countries; takes precedence over DenyCountries when both set.
	AllowCountries []string             `yaml:"allow_countries"`
	Databases      GeoIPDatabasesConfig `yaml:"databases"`
}

// TLSConfig holds Let's Encrypt / TLS settings (AI.md PART 15).
type TLSConfig struct {
	// Enabled activates TLS. When true, the server requests a cert on startup if
	// none is found at the certificate lookup paths (PART 15).
	Enabled bool `yaml:"enabled"`
	// Domain overrides the FQDN used for the certificate (defaults to server.fqdn).
	Domain string `yaml:"domain"`
	// Email is the ACME account contact email required for Let's Encrypt registration.
	Email string `yaml:"email"`
	// Challenge is the ACME challenge type: "http-01" (default), "tls-alpn-01", "dns-01".
	Challenge string `yaml:"challenge"`
	// MinVersion is the minimum TLS version: "1.2" (default) or "1.3".
	MinVersion string `yaml:"min_version"`
	// Staging selects the Let's Encrypt staging environment (for testing).
	Staging bool `yaml:"staging"`
	// DNSProvider is the lego DNS provider name used for DNS-01 challenges (e.g., "cloudflare").
	DNSProvider string `yaml:"dns_provider"`
	// DNSCredentials holds provider-specific credential key-value pairs for DNS-01.
	DNSCredentials map[string]string `yaml:"dns_credentials"`
}

// SMTPConfig holds SMTP connection settings (AI.md PART 17).
type SMTPConfig struct {
	// Host is the SMTP server hostname. Empty = auto-detect on startup.
	Host string `yaml:"host"`
	// Port is the SMTP server port (default 587).
	Port int `yaml:"port"`
	// Username for SMTP auth (optional).
	Username string `yaml:"username"`
	// Password for SMTP auth (optional).
	Password string `yaml:"password"`
	// TLS is the TLS mode: auto, starttls, tls, none (default: auto).
	TLS string `yaml:"tls"`
}

// EmailFromConfig holds the sender identity for outgoing mail (AI.md PART 17).
type EmailFromConfig struct {
	// Name is the display name shown in From: header (defaults to app title).
	Name string `yaml:"name"`
	// Email is the From: address (defaults to no-reply@{fqdn}).
	Email string `yaml:"email"`
}

// EmailNotificationsConfig holds email notification settings (AI.md PART 17).
type EmailNotificationsConfig struct {
	SMTP SMTPConfig      `yaml:"smtp"`
	From EmailFromConfig `yaml:"from"`
}

// NotificationsConfig holds all notification channel settings (AI.md PART 17).
type NotificationsConfig struct {
	Email EmailNotificationsConfig `yaml:"email"`
}

// SchedulerConfig holds scheduler settings (AI.md PART 18).
type SchedulerConfig struct {
	// Timezone for scheduled tasks (IANA timezone name, e.g. "America/New_York")
	Timezone string `yaml:"timezone"`
	// CatchUpWindow is how far back the scheduler replays missed tasks on restart ("1h", "30m", etc.)
	CatchUpWindow string `yaml:"catch_up_window"`
}

// ServerConfig holds all server configuration
// ReverseWHOISConfig holds settings for the owner-search / reverse WHOIS feature (AI.md PART 14).
// Local history is always searched first; an external provider is queried only when configured
// and no local results are found.
type ReverseWHOISConfig struct {
	// Provider selects the external reverse-WHOIS service: "securitytrails", "whoxy", "viewdns", or "" (none).
	Provider string `yaml:"provider"`
	// APIKey is the operator-default API key for the configured provider. Never logged.
	// Never persisted from per-request X-Provider-Key headers.
	APIKey string `yaml:"api_key"`
	// MaxResults caps the total number of results returned per search (default 100).
	MaxResults int `yaml:"max_results"`
}

type ServerConfig struct {
	// Server settings
	Port      int    `yaml:"port"`
	Address   string `yaml:"address"`
	Mode      string `yaml:"mode"`
	FQDN      string `yaml:"fqdn"`
	Daemonize bool   `yaml:"daemonize"`
	PIDFile   bool   `yaml:"pidfile"`
	// User and Group are the unprivileged service account the server drops to
	// after binding a privileged port when started as root (AI.md PART 23).
	// Defaults to the frozen internal name "caswhois". Ignored on Windows
	// (which uses a Virtual Service Account) and when not running as root.
	User  string `yaml:"user"`
	Group string `yaml:"group"`
	// BaseURL is the URL path prefix for all routes (AI.md PART 12 — baseurl).
	BaseURL string `yaml:"baseurl"`

	// Path settings.
	ConfigDir string `yaml:"config_dir"`
	DataDir   string `yaml:"data_dir"`
	LogDir    string `yaml:"log_dir"`
	CacheDir  string `yaml:"cache_dir"`
	// Database settings (AI.md PART 10 — server.database.*)
	Database DatabaseConfig `yaml:"database"`

	// Branding settings (AI.md PART 16 — server.branding.*)
	Branding BrandingConfig `yaml:"branding"`

	// TLS / Let's Encrypt settings (AI.md PART 15 — server.ssl.*)
	TLS TLSConfig `yaml:"ssl"`

	// Web is populated from the top-level web: key by ConfigFile;
	// stored here so handlers can access it via s.config.Web.CORS.
	Web WebConfig `yaml:"-"`

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

	// GeoIP settings (AI.md PART 19 — server.geoip.*)
	GeoIP GeoIPConfig `yaml:"geoip"`

	// Metrics settings (AI.md PART 20 — server.metrics.*)
	Metrics MetricsConfig `yaml:"metrics"`

	// Backup settings (AI.md PART 21 — server.backup.*)
	Backup BackupConfig `yaml:"backup"`

	// Compliance settings (AI.md PART 21 — server.compliance.*)
	Compliance ComplianceConfig `yaml:"compliance"`

	// Update settings (AI.md PART 22)
	UpdateChannel string `yaml:"update_channel"` // stable, beta, daily

	// Tor hidden service settings (AI.md PART 31 — server.tor.*)
	Tor TorConfig `yaml:"tor"`

	// Notifications settings (AI.md PART 17 — server.notifications.email.smtp.*)
	Notifications NotificationsConfig `yaml:"notifications"`

	// Contact configuration (AI.md PART 12)
	Contact ContactConfig `yaml:"contact"`

	// Logging configuration (AI.md PART 11)
	Logs LogsConfig `yaml:"logs"`

	// Scheduler configuration (AI.md PART 18)
	Scheduler SchedulerConfig `yaml:"scheduler"`

	// Reverse WHOIS settings — local history + optional external provider (AI.md PART 14)
	ReverseWHOIS ReverseWHOISConfig `yaml:"reverse_whois"`

	// Debug mode
	Debug bool `yaml:"debug"`

	// ServerToken is the global operator token (AI.md PART 12).
	// Auto-generated on first run (tok_ + 32 base62 chars); stored in server.yml as "token:".
	// Validated by SHA-256-hashing the inbound bearer and using subtle.ConstantTimeCompare.
	// NEVER written to the DB. Config yaml key is "token" (server.token per spec).
	ServerToken string `yaml:"token"`
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
		User:                "caswhois",
		Group:               "caswhois",
		ConfigDir:           "", // Will be determined by OS
		DataDir:             "", // Will be determined by OS
		LogDir:              "", // Will be determined by OS
		Database: DatabaseConfig{
			Driver: "", // Auto-detect: sqlite or libsql from DATABASE_URL env var
			URL:    "", // From DATABASE_URL env var
			Token:  "", // From TURSO_AUTH_TOKEN env var
			Dir:    "", // Applied at runtime (AI.md PART 4)
		},
		BaseURL: "/",
		TLS: TLSConfig{
			Enabled:    false,
			Challenge:  "http-01",
			MinVersion: "1.2",
			Staging:    false,
		},
		Web: WebConfig{
			CORS: "*",
		},
		Branding: BrandingConfig{
			Title:       "caswhois",
			Tagline:     "",
			Description: "",
			Theme:       "auto",
			AccentColor: "#007bff",
		},
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
		GeoIP: GeoIPConfig{
			Enabled:        true,
			Dir:            "",    // Applied at runtime: {data_dir}/security/geoip (AI.md PART 4)
			DenyCountries:  []string{},
			AllowCountries: []string{},
			Databases: GeoIPDatabasesConfig{
				ASN:     true,
				Country: true,
				City:    true,
				WHOIS:   true,
			},
		},
		Metrics: MetricsConfig{
			Enabled:        true,
			Endpoint:       "/metrics",
			IncludeSystem:  true,
			IncludeRuntime: true,
			Token:          "", // No token by default — restrict by firewall
		},
		Backup: BackupConfig{
			Dir: "", // Applied at runtime: {data_dir}/backups (AI.md PART 4)
			Encryption: BackupEncryptionConfig{Enabled: false},
			Retention: BackupRetentionConfig{
				MaxBackups:  1, // Keep 1 daily full backup (default per spec)
				KeepWeekly:  0, // 0 = disabled
				KeepMonthly: 0, // 0 = disabled
				KeepYearly:  0, // 0 = disabled
			},
		},
		Compliance: ComplianceConfig{Enabled: false},
		UpdateChannel: "stable",
		Tor: TorConfig{
			Binary:                    "",
			UseNetwork:                false,
			MaxCircuits:               32,
			CircuitTimeout:            60,
			BootstrapTimeout:          180,
			SafeLogging:               true,
			MaxStreamsPerCircuit:       100,
			CloseCircuitOnStreamLimit: true,
			BandwidthRate:             "1 MB",
			BandwidthBurst:            "2 MB",
			MaxMonthlyBandwidth:       "100 GB",
			NumIntroPoints:            3,
			VirtualPort:               80,
		},
		Notifications: NotificationsConfig{
			Email: EmailNotificationsConfig{
				SMTP: SMTPConfig{
					Host:     "",   // empty = auto-detect on startup
					Port:     587,
					Username: "",
					Password: "",
					TLS:      "auto",
				},
				From: EmailFromConfig{
					Name:  "",  // default: branding title
					Email: "", // default: no-reply@{fqdn}
				},
			},
		},
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

	// Parse YAML — server.yml uses a top-level server: wrapper (AI.md PART 5).
	// The web: sibling section is merged into cfg.Web after unmarshaling.
	cfgDefault := Default()
	cf := ConfigFile{Server: *cfgDefault}
	cf.Web.CORS = "*" // default CORS
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	cfg := &cf.Server
	// Propagate web: section into ServerConfig so handlers can access cfg.Web.
	cfg.Web = cf.Web

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
	if c.Backup.Retention.MaxBackups <= 0 {
		// Warn and use default
		c.Backup.Retention.MaxBackups = 1
	}
	if c.Backup.Retention.KeepWeekly < 0 {
		c.Backup.Retention.KeepWeekly = 0
	}
	if c.Backup.Retention.KeepMonthly < 0 {
		c.Backup.Retention.KeepMonthly = 0
	}
	if c.Backup.Retention.KeepYearly < 0 {
		c.Backup.Retention.KeepYearly = 0
	}

	// Compliance mode validation
	if c.Compliance.Enabled && !c.Backup.Encryption.Enabled {
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
	if c.Database.Dir != "" {
		return c.Database.Dir
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
	if c.Backup.Dir != "" {
		return c.Backup.Dir
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
	if c.Database.URL != "" {
		driver = c.Database.Driver
		if driver == "" {
			driver = "sqlite"
		}
		return driver, c.Database.URL, ""
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
		"backup_dir":         c.Backup.Dir,
		"smtp_host":          c.Notifications.Email.SMTP.Host,
		"smtp_tls_mode":      c.Notifications.Email.SMTP.TLS,
		"metrics_enabled":    c.Metrics.Enabled,
		"metrics_endpoint":   c.Metrics.Endpoint,
		"rate_limit_enabled": c.RateLimit.Enabled,
		"server_token":       "xxxxx",
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

	// Marshal via ConfigFile wrapper so the file uses the server: top-level key
	// matching the AI.md PART 5 format. web: defaults to CORS "*".
	cf := ConfigFile{
		Server: *c,
		Web:    c.Web,
	}
	if cf.Web.CORS == "" {
		cf.Web.CORS = "*"
	}
	data, err := yaml.Marshal(cf)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
