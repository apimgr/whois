package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/apimgr/whois/src/common/constants"
	"gopkg.in/yaml.v3"
)

// LogFileConfig holds per-log-file settings from server.yml (AI.md PART 11).
type LogFileConfig struct {
	// Enabled controls whether this log file is written (false = discard).
	Enabled  bool   `yaml:"enabled"`
	Filename string `yaml:"filename"`
	// Format selects the output format (apache/nginx/json for access; text/json for server/error).
	Format string `yaml:"format"`
	Custom string `yaml:"custom"`
	// Rotate is the rotation policy: daily, weekly, monthly, yearly, NMB, NGB, or combined.
	Rotate string `yaml:"rotate"`
	// Keep is the retention policy: none, N, Nd, Nw, Nm, forever.
	Keep string `yaml:"keep"`
	// Compress rotated files (only useful when keep > 0).
	Compress bool `yaml:"compress"`
}

// LogsConfig mirrors the server.logs block in server.yml (AI.md PART 11).
type LogsConfig struct {
	// Level is the global log level: debug, info, warn, error.
	Level    string        `yaml:"level"`
	Access   LogFileConfig `yaml:"access"`
	Server   LogFileConfig `yaml:"server"`
	Error    LogFileConfig `yaml:"error"`
	App      LogFileConfig `yaml:"app"`
	Auth     LogFileConfig `yaml:"auth"`
	Audit    LogFileConfig `yaml:"audit"`
	Security LogFileConfig `yaml:"security"`
	Debug    LogFileConfig `yaml:"debug"`
}

// DefaultLogsConfig returns the spec-default logging configuration.
func DefaultLogsConfig() LogsConfig {
	return LogsConfig{
		Level: "info",
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
		App: LogFileConfig{
			Enabled:  true,
			Filename: "app.log",
			Format:   "logfmt",
			Rotate:   "weekly,50MB",
			Keep:     "none",
		},
		Auth: LogFileConfig{
			Enabled:  true,
			Filename: "auth.log",
			Format:   "syslog",
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
	Telegram   string `yaml:"telegram"`
	Discord    string `yaml:"discord"`
	Slack      string `yaml:"slack"`
	Mattermost string `yaml:"mattermost"`
	Pushover   string `yaml:"pushover"`
	Gotify     string `yaml:"gotify"`
	Generic    string `yaml:"generic"`
}

// ContactRoleConfig holds the email address and webhooks for a single contact role.
type ContactRoleConfig struct {
	Email    string                `yaml:"email"`
	Webhooks ContactWebhooksConfig `yaml:"webhooks"`
}

// TrackingConfig holds analytics tracking settings (AI.md PART 12 — server.tracking.*).
type TrackingConfig struct {
	// Type selects the analytics provider: "umami", "simple", "cloudflare", or "" (none).
	Type string `yaml:"type"`
	// ID is the site token or beacon ID (provider-specific).
	ID string `yaml:"id"`
	// URL is the custom endpoint for self-hosted analytics (e.g., Umami).
	URL string `yaml:"url"`
}

// ContactConfig mirrors the server.contact block in server.yml (AI.md PART 12).
// Four roles: admin (server-internal alerts), security (vuln reports), abuse (abuse reports), general (contact form).
type ContactConfig struct {
	Admin    ContactRoleConfig `yaml:"admin"`
	Security ContactRoleConfig `yaml:"security"`
	Abuse    ContactRoleConfig `yaml:"abuse"`
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
	// Footer holds footer customization settings (AI.md PART 16 — web.footer.*).
	Footer FooterConfig `yaml:"footer"`
	// Announcements holds site-wide announcement banner settings (AI.md PART 16 — web.announcements.*).
	Announcements AnnouncementConfig `yaml:"announcements"`
}

// CORSConfig holds cross-origin resource sharing settings
// (AI.md PART 16 — CORS, server.cors.*).
type CORSConfig struct {
	// AllowedOrigins: ["*"] = allow all (default); [""] = disable CORS
	// headers entirely; otherwise an explicit origin list.
	AllowedOrigins []string `yaml:"allowed_origins"`
	// AllowCredentials is honored only when AllowedOrigins is an explicit
	// list — never sent alongside "*" (AI.md PART 16 — CORS Allow-list
	// Resolution Order).
	AllowCredentials bool `yaml:"allow_credentials"`
	// MaxAge is the Access-Control-Max-Age value in seconds.
	MaxAge int `yaml:"max_age"`
}

// FooterConfig holds footer customization settings (AI.md PART 16 — web.footer.*).
type FooterConfig struct {
	// CustomHTML is sanitized branding HTML shown above the application footer.
	// "" = default branding; " " = disable branding row; otherwise sanitized custom HTML.
	CustomHTML string `yaml:"custom_html"`
}

// AnnouncementConfig holds site-wide announcement banner settings (AI.md PART 16 — web.announcements.*).
type AnnouncementConfig struct {
	Enabled  bool                  `yaml:"enabled"`
	Messages []AnnouncementMessage `yaml:"messages"`
}

// AnnouncementMessage describes a single announcement banner entry
// (AI.md PART 16 — Announcements → Announcement Structure).
type AnnouncementMessage struct {
	ID string `yaml:"id"`
	// Type is one of: warning, info, error, success.
	Type    string `yaml:"type"`
	Title   string `yaml:"title"`
	Message string `yaml:"message"`
	// Start and End are ISO 8601 timestamps; empty means unbounded.
	Start string `yaml:"start"`
	End   string `yaml:"end"`
	// Dismissible allows the user to hide the banner (persisted client-side).
	Dismissible bool `yaml:"dismissible"`
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
	// MaxTotalSize is a hard cap on total backup volume: percent of device ("10%")
	// or absolute size ("50G", "500M"). "0" or empty disables the cap.
	// Overrides count limits: oldest backups are deleted first until under cap.
	MaxTotalSize string `yaml:"max_total_size"`
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

// UpdateConfig holds self-update settings (AI.md PART 22 — server.update.*).
type UpdateConfig struct {
	// Branch selects the release channel: stable, beta, or daily.
	Branch string `yaml:"branch"`
	// AutoInstall runs the full update flow from the update_check scheduler
	// task when an eligible release is found. Default OFF: the task only
	// notifies; installing is always an explicit operator decision.
	AutoInstall bool `yaml:"auto_install"`
	// DeferDays is the defer window in days (0-365): a release is only
	// eligible for the update_check task once it is this many days old.
	// 0 = adopt releases immediately. Manual `--update check`/`--update yes`
	// always ignore this window.
	DeferDays int `yaml:"defer_days"`
}

// MaintenanceSelfHealingConfig controls automatic recovery from critical
// errors (DB connection loss, disk write failures) — AI.md PART 5.
type MaintenanceSelfHealingConfig struct {
	// Enabled turns on automatic retry/recovery attempts.
	Enabled bool `yaml:"enabled"`
	// RetryInterval is the delay between recovery attempts (Go duration string).
	RetryInterval string `yaml:"retry_interval"`
	// MaxAttempts caps recovery attempts before giving up (0 = unlimited).
	MaxAttempts int `yaml:"max_attempts"`
}

// MaintenanceCleanupConfig controls automatic housekeeping thresholds used
// while the server is in maintenance mode (AI.md PART 5).
type MaintenanceCleanupConfig struct {
	// DiskThreshold is the disk usage percent that triggers cleanup.
	DiskThreshold int `yaml:"disk_threshold"`
	// LogRetentionDays is how many days of logs to keep during cleanup.
	LogRetentionDays int `yaml:"log_retention_days"`
	// BackupKeepCount is how many backups to keep during cleanup.
	BackupKeepCount int `yaml:"backup_keep_count"`
}

// MaintenanceNotifyConfig controls notifications sent when maintenance mode
// is entered or exited (AI.md PART 5).
type MaintenanceNotifyConfig struct {
	// OnEnter sends a notification when maintenance mode activates.
	OnEnter bool `yaml:"on_enter"`
	// OnExit sends a notification when maintenance mode deactivates.
	OnExit bool `yaml:"on_exit"`
}

// MaintenanceConfig holds maintenance-mode settings (AI.md PART 5 — server.maintenance.*).
type MaintenanceConfig struct {
	SelfHealing MaintenanceSelfHealingConfig `yaml:"self_healing"`
	Cleanup     MaintenanceCleanupConfig     `yaml:"cleanup"`
	Notify      MaintenanceNotifyConfig      `yaml:"notify"`
}

// TorConfig holds Tor hidden service settings (AI.md PART 31 — server.tor.*).
type TorConfig struct {
	Binary     string `yaml:"binary"`
	UseNetwork bool   `yaml:"use_network"`
	// AllowUserPreference enables SOCKS proxy port so end-users can route their
	// own traffic through Tor even when server UseNetwork is false (AI.md PART 31).
	AllowUserPreference       bool   `yaml:"allow_user_preference"`
	MaxCircuits               int    `yaml:"max_circuits"`
	CircuitTimeout            int    `yaml:"circuit_timeout"`
	BootstrapTimeout          int    `yaml:"bootstrap_timeout"`
	SafeLogging               bool   `yaml:"safe_logging"`
	MaxStreamsPerCircuit      int    `yaml:"max_streams_per_circuit"`
	CloseCircuitOnStreamLimit bool   `yaml:"close_circuit_on_stream_limit"`
	BandwidthRate             string `yaml:"bandwidth_rate"`
	BandwidthBurst            string `yaml:"bandwidth_burst"`
	MaxMonthlyBandwidth       string `yaml:"max_monthly_bandwidth"`
	NumIntroPoints            int    `yaml:"num_intro_points"`
	VirtualPort               int    `yaml:"virtual_port"`
	// OnionAddress is the .onion hostname for this service (without http:// prefix).
	// Set by the operator after first run; used by BuildURL and privacy rules (AI.md PART 12).
	// When set, requests whose Host matches this value are treated as Tor requests.
	OnionAddress string `yaml:"onion_address"`
	// ContactEmail is the contact address shown exclusively in Tor responses (security.txt,
	// contact pages). When unset, no email appears in Tor responses — never falls back to
	// the clearnet contact email (AI.md PART 12 — Tor privacy rules).
	ContactEmail string `yaml:"contact_email"`
}

// PrivacyConfig holds privacy/consent settings for GDPR/CCPA compliance,
// including the cookie consent banner (AI.md PART 12 — server.privacy.*).
type PrivacyConfig struct {
	Data       DataPolicy       `yaml:"data"`
	Retention  RetentionPolicy  `yaml:"retention"`
	Consent    ConsentConfig    `yaml:"consent"`
	Cookies    CookieCategories `yaml:"cookies"`
	ThirdParty ThirdPartyConfig `yaml:"third_party"`
	Content    PrivacyContent   `yaml:"content"`
}

// DataPolicy controls data handling and CCPA compliance (AI.md PART 12).
type DataPolicy struct {
	// Sold defaults to false — we do NOT sell data (MIT users can enable).
	Sold bool `yaml:"sold"`
	// StoredOnServer is always true — all data stays on this server.
	StoredOnServer bool               `yaml:"stored_on_server"`
	Sharing        []SharingCondition `yaml:"sharing"`
}

// SharingCondition documents one scenario where data MAY be shared.
type SharingCondition struct {
	// Condition is one of: analytics, email, user_initiated.
	Condition string `yaml:"condition"`
	When      string `yaml:"when"`
	Data      string `yaml:"data"`
}

// RetentionPolicy documents how long user data is kept.
type RetentionPolicy struct {
	Period            string `yaml:"period"`
	ExportAvailable   bool   `yaml:"export_available"`
	DeletionAvailable bool   `yaml:"deletion_available"`
}

// ConsentConfig configures the cookie consent banner (AI.md PART 12).
type ConsentConfig struct {
	ShowUntilAcknowledged bool `yaml:"show_until_acknowledged"`
	DefaultEnabled        bool `yaml:"default_enabled"`
	// Message is used when Data.Sold is false.
	Message string `yaml:"message"`
	// MessageIfSold is used when Data.Sold is true.
	MessageIfSold string `yaml:"message_if_sold"`
	Policy        struct {
		Text string `yaml:"text"`
		URL  string `yaml:"url"`
	} `yaml:"policy"`
	Buttons struct {
		Decline string `yaml:"decline"`
		Accept  string `yaml:"accept"`
	} `yaml:"buttons"`
	// Position is "top" or "bottom".
	Position        string `yaml:"position"`
	ShowPreferences bool   `yaml:"show_preferences"`
	PreferencesText string `yaml:"preferences_text"`
}

// CookieCategories describes the cookie categories shown in the consent banner.
type CookieCategories struct {
	Essential   CookieCategory  `yaml:"essential"`
	Preferences CookieCategory  `yaml:"preferences"`
	Analytics   AnalyticsCookie `yaml:"analytics"`
}

// CookieCategory describes one cookie category.
type CookieCategory struct {
	Enabled     bool   `yaml:"enabled"`
	Description string `yaml:"description"`
}

// AnalyticsCookie extends CookieCategory with sold/not-sold description suffixes.
type AnalyticsCookie struct {
	CookieCategory           `yaml:",inline"`
	DescriptionSuffixNotSold string `yaml:"description_suffix_not_sold"`
	DescriptionSuffixSold    string `yaml:"description_suffix_sold"`
}

// ThirdPartyConfig lists third-party services that receive data.
type ThirdPartyConfig struct {
	Services []ThirdPartyService `yaml:"services"`
}

// ThirdPartyService describes one third-party data recipient.
type ThirdPartyService struct {
	Name      string `yaml:"name"`
	Purpose   string `yaml:"purpose"`
	DataSent  string `yaml:"data_sent"`
	PolicyURL string `yaml:"policy_url"`
}

// PrivacyContent holds the Markdown body sections of the privacy page,
// with sold/not-sold variants for data usage (AI.md PART 12).
type PrivacyContent struct {
	DataCollection string `yaml:"data_collection"`
	// DataUsage is shown when Data.Sold is false.
	DataUsage string `yaml:"data_usage"`
	// DataUsageIfSold is shown when Data.Sold is true.
	DataUsageIfSold string `yaml:"data_usage_if_sold"`
	DataSecurity    string `yaml:"data_security"`
}

// GetConsentMessage returns the banner message appropriate for the Sold setting.
func (p *PrivacyConfig) GetConsentMessage() string {
	if p.Data.Sold {
		return p.Consent.MessageIfSold
	}
	return p.Consent.Message
}

// GetAnalyticsDescription returns the analytics cookie description with the
// suffix appropriate for the Sold setting.
func (p *PrivacyConfig) GetAnalyticsDescription() string {
	base := p.Cookies.Analytics.Description
	if p.Data.Sold {
		return base + " " + p.Cookies.Analytics.DescriptionSuffixSold
	}
	return base + " " + p.Cookies.Analytics.DescriptionSuffixNotSold
}

// GetDataUsageContent returns the privacy page data-usage section
// appropriate for the Sold setting.
func (p *PrivacyConfig) GetDataUsageContent() string {
	if p.Data.Sold {
		return p.Content.DataUsageIfSold
	}
	return p.Content.DataUsage
}

// IsCCPAApplicable returns true if CCPA "Do Not Sell" disclosure is required.
func (p *PrivacyConfig) IsCCPAApplicable() bool {
	return p.Data.Sold
}

// TypeName returns the human-readable name of the configured analytics
// provider for display on the privacy page (AI.md PART 16 — /server/privacy).
func (t *TrackingConfig) TypeName() string {
	switch t.Type {
	case "umami":
		return "Umami"
	case "simple":
		return "Simple Analytics"
	case "cloudflare":
		return "Cloudflare Web Analytics"
	default:
		return ""
	}
}

// PagesConfig holds per-page content overrides for the standard /server/*
// content pages (AI.md PART 16 — Standard Pages → Configuration).
type PagesConfig struct {
	About   AboutPageConfig   `yaml:"about"`
	Privacy PrivacyPageConfig `yaml:"privacy"`
	Contact ContactPageConfig `yaml:"contact"`
	Help    HelpPageConfig    `yaml:"help"`
	Terms   TermsPageConfig   `yaml:"terms"`
}

// AboutPageConfig holds additional Markdown content for the about page.
type AboutPageConfig struct {
	Content string `yaml:"content"`
}

// PrivacyPageConfig holds a full Markdown override for the privacy policy page.
// Empty uses the default template built from PrivacyConfig.
type PrivacyPageConfig struct {
	Content string `yaml:"content"`
}

// ContactPageConfig controls the /server/contact form.
type ContactPageConfig struct {
	Enabled bool `yaml:"enabled"`
	// Captcha selects the spam-prevention method: recaptcha, hcaptcha, simple.
	Captcha string `yaml:"captcha"`
	// SuccessMessage is shown after a successful form submission.
	SuccessMessage string `yaml:"success_message"`
}

// HelpPageConfig holds project-specific Markdown content for the help page.
type HelpPageConfig struct {
	Content string `yaml:"content"`
}

// TermsPageConfig holds a full Markdown override for the terms of service page.
// Empty uses the default template.
type TermsPageConfig struct {
	Content string `yaml:"content"`
}

// CacheConfig holds cache backend settings (AI.md PART 12 — server.cache.*).
// Cache is optional and defaults to in-process memory; Valkey/Redis is
// supported for persistence across restarts.
type CacheConfig struct {
	// Type is one of: none, memory (default), valkey, redis.
	Type string `yaml:"type"`
	// URL takes precedence over host/port/username/password/db when set.
	// Format: redis://user:password@host:port/db or valkey://...
	URL           string `yaml:"url"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	Username      string `yaml:"username"`
	Password      string `yaml:"password"`
	DB            int    `yaml:"db"`
	TLS           bool   `yaml:"tls"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify"`
	PoolSize      int    `yaml:"pool_size"`
	MinIdle       int    `yaml:"min_idle"`
	Timeout       string `yaml:"timeout"`
	Prefix        string `yaml:"prefix"`
	TTL           string `yaml:"ttl"`
}

// MetricsConfig holds Prometheus metrics settings (AI.md PART 20 — server.metrics.*).
type MetricsConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Endpoint       string `yaml:"endpoint"`
	IncludeSystem  bool   `yaml:"include_system"`
	IncludeRuntime bool   `yaml:"include_runtime"`
	// Token is the optional Bearer token required to scrape /metrics.
	// Empty = no auth (rely on firewall).
	Token string `yaml:"token"`
	// DurationBuckets are the Prometheus histogram buckets (seconds) used for
	// request/task duration metrics. Empty = built-in PART 20 defaults.
	DurationBuckets []float64 `yaml:"duration_buckets"`
	// SizeBuckets are the Prometheus histogram buckets (bytes) used for
	// request/response size metrics. Empty = built-in PART 20 defaults.
	SizeBuckets []float64 `yaml:"size_buckets"`
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
	Enabled bool `yaml:"enabled"`
	// Dir is the directory for downloaded MMDB files (defaults to {data_dir}/security/geoip).
	Dir string `yaml:"dir"`
	// DenyCountries lists ISO 3166-1 alpha-2 country codes to block.
	DenyCountries []string `yaml:"deny_countries"`
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

// CSRFConfig holds CSRF protection settings (AI.md PART 16 — CSRF Protection).
// Uses the stateless double-submit cookie pattern; no server-side session storage.
type CSRFConfig struct {
	// Enabled activates CSRF validation. Default true; set false only for
	// API-only deployments with no browser forms at all.
	Enabled bool `yaml:"enabled"`
	// TokenLength is the number of random bytes used to generate each token.
	TokenLength int `yaml:"token_length"`
	// CookieName is the name of the CSRF token cookie.
	CookieName string `yaml:"cookie_name"`
	// HeaderName is the header carrying the token on XHR/fetch requests.
	HeaderName string `yaml:"header_name"`
	// Secure controls the cookie's Secure attribute: "auto" (Secure when the
	// request is HTTPS), "true", or "false".
	Secure string `yaml:"secure"`
	// ExemptPaths lists glob patterns exempt from CSRF validation (e.g.,
	// webhook receivers, external callbacks).
	ExemptPaths []string `yaml:"exempt_paths"`
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

// EmailEventsConfig controls which lifecycle events trigger an email notification
// (AI.md PART 17 — server.notifications.email.events.*).
type EmailEventsConfig struct {
	Startup          bool `yaml:"startup"`
	Shutdown         bool `yaml:"shutdown"`
	BackupComplete   bool `yaml:"backup_complete"`
	BackupFailed     bool `yaml:"backup_failed"`
	SSLExpiring      bool `yaml:"ssl_expiring"`
	SSLRenewed       bool `yaml:"ssl_renewed"`
	SSLRenewalFailed bool `yaml:"ssl_renewal_failed"`
	SecurityAlert    bool `yaml:"security_alert"`
	SchedulerError   bool `yaml:"scheduler_error"`
	UpdateAvailable  bool `yaml:"update_available"`
	UpdateInstalled  bool `yaml:"update_installed"`
}

// EmailNotificationsConfig holds email notification settings (AI.md PART 17).
type EmailNotificationsConfig struct {
	SMTP   SMTPConfig        `yaml:"smtp"`
	From   EmailFromConfig   `yaml:"from"`
	Events EmailEventsConfig `yaml:"events"`
}

// WebUINotificationsConfig holds in-browser toast/notification settings
// (AI.md PART 17 — server.notifications.webui.*).
type WebUINotificationsConfig struct {
	// Position is the on-screen placement: top-right, top-left, bottom-right, bottom-left.
	Position string `yaml:"position"`
	// Duration is how long a notification stays visible, in seconds.
	Duration int `yaml:"duration"`
}

// NotificationsConfig holds all notification channel settings (AI.md PART 17).
type NotificationsConfig struct {
	WebUI WebUINotificationsConfig `yaml:"webui"`
	Email EmailNotificationsConfig `yaml:"email"`
}

// TaskConfig holds per-task overrides for a built-in scheduler task
// (AI.md PART 18 — server.scheduler.tasks.<id>.*). Zero values mean
// "use the task's built-in default from src/scheduler/tasks.go".
type TaskConfig struct {
	// Schedule is a cron expression overriding the task's built-in schedule.
	Schedule string `yaml:"schedule"`
	// Enabled overrides whether the task runs. Persisted enable/disable state
	// (via the "scheduler enable/disable" CLI or scheduler_tasks table) wins
	// after first run.
	Enabled bool `yaml:"enabled"`
	// RetryOnFail overrides whether a failed run is retried. nil = keep the
	// task's built-in retry policy.
	RetryOnFail *bool `yaml:"retry_on_fail"`
	// RetryDelay overrides the delay before the first retry (e.g. "5m").
	RetryDelay string `yaml:"retry_delay"`
	// Verify requests a post-run integrity check (used by backup_daily/backup_hourly).
	Verify bool `yaml:"verify"`
	// Retention overrides backup retention (used by backup_daily/backup_hourly).
	Retention *BackupRetentionConfig `yaml:"retention"`
	// RestartOnFail requests a service restart on repeated failure (used by tor_health).
	RestartOnFail bool `yaml:"restart_on_fail"`
}

// SchedulerConfig holds scheduler settings (AI.md PART 18).
type SchedulerConfig struct {
	// Timezone for scheduled tasks (IANA timezone name, e.g. "America/New_York")
	Timezone string `yaml:"timezone"`
	// CatchUpWindow is how far back the scheduler replays missed tasks on restart ("1h", "30m", etc.)
	CatchUpWindow string `yaml:"catch_up_window"`
	// MaxRetries is the default retry count applied when a task's TaskConfig
	// enables retry_on_fail without specifying its own count (default 3).
	MaxRetries int `yaml:"max_retries"`
	// RetryDelay is the default delay before the first retry (default "5m").
	RetryDelay string `yaml:"retry_delay"`
	// Backoff is the default retry backoff strategy: "linear" or "exponential"
	// (default "exponential" — e.g. 5m, 10m, 20m).
	Backoff string `yaml:"backoff"`
	// Tasks holds per-task overrides keyed by task ID (e.g. "backup_daily").
	Tasks map[string]TaskConfig `yaml:"tasks"`
}

// HealthzRootConfig controls the optional /healthz root alias (AI.md PART 13).
type HealthzRootConfig struct {
	// Enabled controls whether /healthz (root alias) is registered.
	// When false, only /server/healthz and /api/{version}/server/healthz are available.
	Enabled bool `yaml:"enabled"`
}

// HealthzConfig holds health endpoint settings (AI.md PART 13).
type HealthzConfig struct {
	// Root controls the optional /healthz root alias.
	Root HealthzRootConfig `yaml:"root"`
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
	// APIVersion is the API version prefix (default "v1"). Used in route registration.
	APIVersion string `yaml:"api_version"`
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

	// CSRF protection settings (AI.md PART 16 — server.csrf.*)
	CSRF CSRFConfig `yaml:"csrf"`

	// CORS settings (AI.md PART 16 — server.cors.*)
	Cors CORSConfig `yaml:"cors"`

	// Web is populated from the top-level web: key by ConfigFile;
	// stored here so handlers can access it via s.config.Web.
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

	// Update settings (AI.md PART 22 — server.update.*)
	Update UpdateConfig `yaml:"update"`

	// Tor hidden service settings (AI.md PART 31 — server.tor.*)
	Tor TorConfig `yaml:"tor"`

	// Maintenance-mode settings — self-healing, cleanup, notify (AI.md PART 5 — server.maintenance.*)
	Maintenance MaintenanceConfig `yaml:"maintenance"`

	// Privacy/consent settings — GDPR/CCPA (AI.md PART 12 — server.privacy.*)
	Privacy PrivacyConfig `yaml:"privacy"`

	// Cache backend settings (AI.md PART 12 — server.cache.*)
	Cache CacheConfig `yaml:"cache"`

	// Notifications settings (AI.md PART 17 — server.notifications.email.smtp.*)
	Notifications NotificationsConfig `yaml:"notifications"`

	// Contact configuration (AI.md PART 12)
	Contact ContactConfig `yaml:"contact"`

	// Analytics tracking configuration (AI.md PART 12 — server.tracking.*)
	Tracking TrackingConfig `yaml:"tracking"`

	// Logging configuration (AI.md PART 11)
	Logs LogsConfig `yaml:"logs"`

	// Scheduler configuration (AI.md PART 18)
	Scheduler SchedulerConfig `yaml:"scheduler"`

	// Healthz endpoint configuration (AI.md PART 13)
	Healthz HealthzConfig `yaml:"healthz"`

	// Reverse WHOIS settings — local history + optional external provider (AI.md PART 14)
	ReverseWHOIS ReverseWHOISConfig `yaml:"reverse_whois"`

	// Pages settings for the standard /server/* content pages (AI.md PART 16 — Standard Pages).
	Pages PagesConfig `yaml:"pages"`

	// Debug mode
	Debug bool `yaml:"debug"`

	// ServerToken is the global operator token (AI.md PART 12).
	// Auto-generated on first run (tok_ + 32 base62 chars); stored in server.yml as "token:".
	// Validated by SHA-256-hashing the inbound bearer and using subtle.ConstantTimeCompare.
	// NEVER written to the DB. Config yaml key is "token" (server.token per spec).
	ServerToken string `yaml:"token"`

	// InstallationSecret is the root secret from which all derived material hangs (AI.md PART 11).
	// Auto-generated on first run as 64 random hex chars; stored in server.yml as "installation_secret:".
	// Used as the KDF input for PGP private-key encryption and future derived material.
	// Loss of this field makes encrypted PGP private keys unrecoverable.
	InstallationSecret string `yaml:"installation_secret"`
}

// Default returns a ServerConfig with sane defaults
func Default() *ServerConfig {
	// APPLICATION_NAME and APPLICATION_TAGLINE are init-only env vars
	// (AI.md PART 5): only consulted while building the config generated
	// on first run — later runs read the persisted server.yml values.
	title := constants.InternalName
	if envTitle := os.Getenv("APPLICATION_NAME"); envTitle != "" {
		title = envTitle
	}
	tagline := ""
	if envTagline := os.Getenv("APPLICATION_TAGLINE"); envTagline != "" {
		tagline = envTagline
	}
	return &ServerConfig{
		// Port 0 triggers random selection in range 64000-64999 on first run
		Port:       0,
		Address:    "0.0.0.0",
		Mode:       "production",
		FQDN:       "",
		Daemonize:  false,
		PIDFile:    true,
		APIVersion: "v1",
		User:       constants.InternalName,
		Group:      constants.InternalName,
		// ConfigDir, DataDir, LogDir are resolved to OS-appropriate paths at runtime
		ConfigDir: "",
		DataDir:   "",
		LogDir:    "",
		// Database defaults: driver auto-detected from DATABASE_URL; paths resolved at runtime
		Database: DatabaseConfig{
			Driver: "",
			URL:    "",
			Token:  "",
			Dir:    "",
		},
		BaseURL: "/",
		TLS: TLSConfig{
			Enabled:    false,
			Challenge:  "http-01",
			MinVersion: "1.2",
			Staging:    false,
		},
		Cors: CORSConfig{
			AllowedOrigins:   []string{"*"},
			AllowCredentials: false,
			MaxAge:           86400,
		},
		Branding: BrandingConfig{
			Title:       title,
			Tagline:     tagline,
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
			Enabled: true,
			// Applied at runtime: {data_dir}/security/geoip (AI.md PART 4)
			Dir:            "",
			DenyCountries:  []string{},
			AllowCountries: []string{},
			Databases: GeoIPDatabasesConfig{
				ASN:     true,
				Country: true,
				City:    true,
				WHOIS:   true,
			},
		},
		CSRF: CSRFConfig{
			Enabled:     true,
			TokenLength: 32,
			CookieName:  "csrf_token",
			HeaderName:  "X-CSRF-Token",
			Secure:      "auto",
			ExemptPaths: []string{},
		},
		Metrics: MetricsConfig{
			Enabled:        true,
			Endpoint:       "/metrics",
			IncludeSystem:  true,
			IncludeRuntime: true,
			// No token by default — restrict by firewall
			Token:           "",
			DurationBuckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			SizeBuckets:     []float64{100, 1000, 10000, 100000, 1000000, 10000000},
		},
		Backup: BackupConfig{
			// Applied at runtime: {data_dir}/backups (AI.md PART 4)
			Dir:        "",
			Encryption: BackupEncryptionConfig{Enabled: false},
			Retention: BackupRetentionConfig{
				// Keep 1 daily full backup (default per spec)
				MaxBackups: 1,
				// 0 = disabled
				KeepWeekly: 0,
				// 0 = disabled
				KeepMonthly: 0,
				// 0 = disabled
				KeepYearly:   0,
				MaxTotalSize: "10%",
			},
		},
		Compliance: ComplianceConfig{Enabled: false},
		Update: UpdateConfig{
			Branch:      "stable",
			AutoInstall: false,
			DeferDays:   0,
		},
		Maintenance: MaintenanceConfig{
			SelfHealing: MaintenanceSelfHealingConfig{
				Enabled:       true,
				RetryInterval: "30s",
				MaxAttempts:   0,
			},
			Cleanup: MaintenanceCleanupConfig{
				DiskThreshold:    90,
				LogRetentionDays: 7,
				BackupKeepCount:  5,
			},
			Notify: MaintenanceNotifyConfig{
				OnEnter: true,
				OnExit:  true,
			},
		},
		Tor: TorConfig{
			Binary:                    "",
			UseNetwork:                false,
			AllowUserPreference:       true,
			MaxCircuits:               32,
			CircuitTimeout:            60,
			BootstrapTimeout:          180,
			SafeLogging:               true,
			MaxStreamsPerCircuit:      100,
			CloseCircuitOnStreamLimit: true,
			BandwidthRate:             "1 MB",
			BandwidthBurst:            "2 MB",
			MaxMonthlyBandwidth:       "100 GB",
			NumIntroPoints:            3,
			VirtualPort:               80,
			OnionAddress:              "",
			ContactEmail:              "",
		},
		Privacy: PrivacyConfig{
			Data: DataPolicy{
				// We do NOT sell data by default (MIT users can enable).
				Sold:           false,
				StoredOnServer: true,
				Sharing: []SharingCondition{
					{
						Condition: "analytics",
						When:      "Tracking configured (server.tracking.type set) AND user consents",
						Data:      "Anonymized: page views, browser type, country",
					},
					{
						Condition: "email",
						When:      "SMTP configured for sending emails",
						Data:      "Email address, message content",
					},
					{
						Condition: "user_initiated",
						When:      "User explicitly shares content (social buttons, exports)",
						Data:      "Whatever user chooses to share",
					},
				},
			},
			Retention: RetentionPolicy{
				Period:            "Account data is retained while your account is active. Upon account deletion, all personal data is permanently deleted within 30 days. Anonymized analytics data may be retained for up to 12 months.",
				ExportAvailable:   true,
				DeletionAvailable: true,
			},
			Consent: ConsentConfig{
				ShowUntilAcknowledged: true,
				DefaultEnabled:        true,
				Message:               "In accordance with the EU GDPR law this message is being displayed. We use cookies for essential site functionality and, with your consent, for preferences and analytics. Your data is stored on our servers and is never sold.",
				MessageIfSold:         "In accordance with the EU GDPR law this message is being displayed. We use cookies for essential site functionality and, with your consent, for preferences and analytics. Your data may be shared with or sold to third parties as described in our Privacy Policy.",
				Policy: struct {
					Text string `yaml:"text"`
					URL  string `yaml:"url"`
				}{Text: "Privacy Policy", URL: "/server/privacy"},
				Buttons: struct {
					Decline string `yaml:"decline"`
					Accept  string `yaml:"accept"`
				}{Decline: "Decline", Accept: "I Agree"},
				Position:        "bottom",
				ShowPreferences: true,
				PreferencesText: "Manage Preferences",
			},
			Cookies: CookieCategories{
				Essential: CookieCategory{
					Enabled:     true,
					Description: "Required for the site to function. Includes security tokens (CSRF) and site preferences. These cookies are strictly necessary and cannot be disabled.",
				},
				Preferences: CookieCategory{
					Enabled:     true,
					Description: "Remember your settings such as theme (dark/light), language, and UI preferences. Disabling will reset to defaults on each visit.",
				},
				Analytics: AnalyticsCookie{
					CookieCategory: CookieCategory{
						Enabled:     true,
						Description: "Help us understand how visitors use our site to improve the experience.",
					},
					DescriptionSuffixNotSold: "Analytics data is anonymized and never sold.",
					DescriptionSuffixSold:    "Analytics data may be shared with third parties.",
				},
			},
			ThirdParty: ThirdPartyConfig{Services: []ThirdPartyService{}},
		},
		Cache: CacheConfig{
			Type:          "memory",
			URL:           "",
			Host:          "localhost",
			Port:          6379,
			Username:      "",
			Password:      "",
			DB:            0,
			TLS:           false,
			TLSSkipVerify: false,
			PoolSize:      10,
			MinIdle:       2,
			Timeout:       "5s",
			Prefix:        constants.InternalName + ":",
			TTL:           "1h",
		},
		Notifications: NotificationsConfig{
			WebUI: WebUINotificationsConfig{
				Position: "top-right",
				Duration: 5,
			},
			Email: EmailNotificationsConfig{
				SMTP: SMTPConfig{
					// empty = auto-detect on startup
					Host:     "",
					Port:     587,
					Username: "",
					Password: "",
					TLS:      "auto",
				},
				From: EmailFromConfig{
					// default: branding title
					Name: "",
					// default: no-reply@{fqdn}
					Email: "",
				},
				Events: EmailEventsConfig{
					Startup:          false,
					Shutdown:         false,
					BackupComplete:   false,
					BackupFailed:     true,
					SSLExpiring:      true,
					SSLRenewed:       false,
					SSLRenewalFailed: true,
					SecurityAlert:    true,
					SchedulerError:   true,
					UpdateAvailable:  false,
					UpdateInstalled:  true,
				},
			},
		},
		Contact: ContactConfig{
			Admin:    ContactRoleConfig{Email: ""},
			Security: ContactRoleConfig{Email: ""},
			Abuse:    ContactRoleConfig{Email: ""},
			General:  ContactRoleConfig{Email: ""},
		},
		Tracking: TrackingConfig{
			Type: "",
			ID:   "",
			URL:  "",
		},
		Pages: PagesConfig{
			About:   AboutPageConfig{Content: ""},
			Privacy: PrivacyPageConfig{Content: ""},
			Contact: ContactPageConfig{
				Enabled:        true,
				Captcha:        "simple",
				SuccessMessage: "Thank you for your message. We'll respond soon.",
			},
			Help:  HelpPageConfig{Content: ""},
			Terms: TermsPageConfig{Content: ""},
		},
		Logs: DefaultLogsConfig(),
		Scheduler: SchedulerConfig{
			Timezone:      "America/New_York",
			CatchUpWindow: "1h",
			MaxRetries:    3,
			RetryDelay:    "5m",
			Backoff:       "exponential",
			Tasks: map[string]TaskConfig{
				"ssl_renewal":      {Schedule: "0 3 * * *", Enabled: true},
				"geoip_update":     {Schedule: "0 3 * * 0", Enabled: true},
				"blocklist_update": {Schedule: "0 4 * * *", Enabled: true, RetryOnFail: boolPtr(true), RetryDelay: "1h"},
				"cve_update":       {Schedule: "0 5 * * *", Enabled: true, RetryOnFail: boolPtr(true), RetryDelay: "1h"},
				"update_check":     {Schedule: "0 6 * * *", Enabled: true},
				"token_cleanup":    {Schedule: "@every 15m", Enabled: true},
				"log_rotation":     {Schedule: "0 0 * * *", Enabled: true},
				"backup_daily": {
					Schedule: "0 2 * * *",
					Enabled:  true,
					Verify:   true,
					Retention: &BackupRetentionConfig{
						MaxBackups:   1,
						KeepWeekly:   0,
						KeepMonthly:  0,
						KeepYearly:   0,
						MaxTotalSize: "10%",
					},
				},
				"backup_hourly":    {Schedule: "@hourly", Enabled: false},
				"healthcheck_self": {Schedule: "@every 5m", Enabled: true},
				"tor_health":       {Schedule: "@every 10m", Enabled: true, RestartOnFail: true},
			},
		},
		Debug: false,
		// auto-generated on first run
		ServerToken: "",
	}
}

// LoadServerConfig reads server.yml from the specified directory
func LoadServerConfig(configDir string) (*ServerConfig, error) {
	if configDir == "" {
		return nil, fmt.Errorf("config directory not specified")
	}

	configPath := filepath.Join(configDir, "server.yml")

	// Auto-migrate a legacy server.yaml to server.yml (AI.md PART 5 "Migration":
	// "If server.yaml found, auto-migrate to server.yml on startup"). Only runs
	// when server.yml is absent so an existing server.yml is never overwritten.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		legacyPath := filepath.Join(configDir, "server.yaml")
		if _, legacyErr := os.Stat(legacyPath); legacyErr == nil {
			if renameErr := os.Rename(legacyPath, configPath); renameErr != nil {
				return nil, fmt.Errorf("migrate server.yaml to server.yml: %w", renameErr)
			}
		}
	}

	// If config doesn't exist, write the annotated default template to disk
	// (AI.md "Configuration File > Design Rules": server.yml must be
	// "Comprehensive" — all options present, commented/defaulted) and fall
	// through to the normal read-and-parse path below.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if genErr := GenerateDefaultConfig(configDir); genErr != nil {
			return nil, fmt.Errorf("failed to write default config: %w", genErr)
		}
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
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	cfg := &cf.Server
	// Propagate web: section into ServerConfig so handlers can access cfg.Web.
	cfg.Web = cf.Web

	// Allow MODE env var to override server.mode (AI.md PART 6).
	if m := os.Getenv("MODE"); m != "" {
		cfg.Mode = m
	}
	// Allow DEBUG env var to set debug mode (AI.md PART 6).
	if dbg := os.Getenv("DEBUG"); dbg == "1" || dbg == "true" || dbg == "yes" {
		cfg.Debug = true
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

	// Auto-generate installation secret on first run if absent (AI.md PART 11)
	if cfg.InstallationSecret == "" {
		secret, err := GenerateInstallationSecret()
		if err != nil {
			return nil, fmt.Errorf("generate installation secret: %w", err)
		}
		cfg.InstallationSecret = secret
		if saveErr := cfg.Save(configDir); saveErr != nil {
			fmt.Printf("WARNING: could not persist installation secret: %v\n", saveErr)
		}
	}

	// Validate paths
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration. Invalid settings are warned about and
// replaced with safe defaults; startup is never blocked on config (AI.md PART 12).
func (c *ServerConfig) Validate() error {
	// Port range — warn and reset to 0 (random assignment on first run) if invalid.
	if c.Port < 0 || c.Port > 65535 {
		fmt.Printf("WARN: invalid port %d — resetting to 0 (random assignment)\n", c.Port)
		c.Port = 0
	}

	// Mode validation — warn and default to production; never fail startup (AI.md PART 12).
	if c.Mode != "" && c.Mode != "production" && c.Mode != "development" {
		fmt.Printf("WARN: invalid mode %q — defaulting to production\n", c.Mode)
		c.Mode = "production"
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

	// Update branch validation (AI.md PART 22)
	if c.Update.Branch != "stable" && c.Update.Branch != "beta" && c.Update.Branch != "daily" {
		c.Update.Branch = "stable"
	}
	if c.Update.DeferDays < 0 || c.Update.DeferDays > 365 {
		c.Update.DeferDays = 0
	}

	// API version validation — default to v1 if empty
	if c.APIVersion == "" {
		c.APIVersion = "v1"
	}

	return nil
}

// APIBasePath returns the API base path (e.g., "/api/v1").
// AI.md PART 14: never hardcode v1 — always use this method.
func (c *ServerConfig) APIBasePath() string {
	return "/api/" + c.APIVersion
}

// windowsProgramData returns %ProgramData% (system-wide writable data), falling
// back to the documented default if the environment variable is unset.
func windowsProgramData() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return v
	}
	return `C:\ProgramData`
}

// windowsLocalAppData returns %LocalAppData% (per-user local data), falling
// back to a best-effort path under the user's home directory if unset.
func windowsLocalAppData() string {
	if v := os.Getenv("LocalAppData"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, "AppData", "Local")
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

	// 5. Root/user native, branched by OS (AI.md PART 4)
	switch runtime.GOOS {
	case "windows":
		if os.Getuid() == 0 {
			return filepath.Join(windowsProgramData(), constants.InternalOrg, constants.InternalName, "db")
		}
		return filepath.Join(windowsLocalAppData(), constants.InternalOrg, constants.InternalName, "db")
	case "darwin":
		if os.Getuid() == 0 {
			return filepath.Join("/Library", "Application Support", constants.InternalOrg, constants.InternalName, "db")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "./db"
		}
		return filepath.Join(home, "Library", "Application Support", constants.InternalOrg, constants.InternalName, "db")
	case "freebsd", "openbsd", "netbsd":
		if os.Getuid() == 0 {
			return filepath.Join("/var", "db", constants.InternalOrg, constants.InternalName, "db")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "./db"
		}
		return filepath.Join(home, ".local", "share", constants.InternalOrg, constants.InternalName, "db")
	default:
		if os.Getuid() == 0 {
			return "/var/lib/" + constants.InternalOrg + "/" + constants.InternalName + "/db"
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return "./db"
		}
		return filepath.Join(home, ".local", "share", constants.InternalOrg, constants.InternalName, "db")
	}
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

	// 3. Root/user native, branched by OS (AI.md PART 4)
	switch runtime.GOOS {
	case "windows":
		if os.Getuid() == 0 {
			return filepath.Join(windowsProgramData(), "Backups", constants.InternalOrg, constants.InternalName)
		}
		return filepath.Join(windowsLocalAppData(), "Backups", constants.InternalOrg, constants.InternalName)
	case "darwin":
		if os.Getuid() == 0 {
			return filepath.Join("/Library", "Backups", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "./backups"
		}
		return filepath.Join(home, "Library", "Backups", constants.InternalOrg, constants.InternalName)
	case "freebsd", "openbsd", "netbsd":
		if os.Getuid() == 0 {
			return filepath.Join("/var", "backups", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "./backups"
		}
		return filepath.Join(home, ".local", "share", "Backups", constants.InternalOrg, constants.InternalName)
	default:
		if os.Getuid() == 0 {
			return "/mnt/Backups/" + constants.InternalOrg + "/" + constants.InternalName
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return "./backups"
		}
		return filepath.Join(home, ".local", "share", "Backups", constants.InternalOrg, constants.InternalName)
	}
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

	// 3. Root/user native, branched by OS (AI.md PART 4)
	switch runtime.GOOS {
	case "windows":
		if os.Getuid() == 0 {
			return filepath.Join(windowsProgramData(), constants.InternalOrg, constants.InternalName, "logs")
		}
		return filepath.Join(windowsLocalAppData(), constants.InternalOrg, constants.InternalName, "logs")
	case "darwin":
		if os.Getuid() == 0 {
			return filepath.Join("/Library", "Logs", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "./logs"
		}
		return filepath.Join(home, "Library", "Logs", constants.InternalOrg, constants.InternalName)
	case "freebsd", "openbsd", "netbsd":
		if os.Getuid() == 0 {
			return filepath.Join("/var", "log", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "./logs"
		}
		return filepath.Join(home, ".local", "log", constants.InternalOrg, constants.InternalName)
	default:
		if os.Getuid() == 0 {
			return "/var/log/" + constants.InternalOrg + "/" + constants.InternalName
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return "./logs"
		}
		return filepath.Join(home, ".local", "log", constants.InternalOrg, constants.InternalName)
	}
}

// GetDatabaseConfig returns database configuration from environment and config
func (c *ServerConfig) GetDatabaseConfig() (driver, url, path string) {
	// Check DATABASE_URL first (for libsql/Turso remote)
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		driver = os.Getenv("DATABASE_DRIVER")
		if driver == "" {
			// A remote URL implies libsql/Turso, not embedded sqlite
			driver = "libsql"
		}
		return driver, dbURL, ""
	}

	// Check config values
	if c.Database.URL != "" {
		driver = c.Database.Driver
		if driver == "" {
			// A remote URL implies libsql/Turso, not embedded sqlite
			driver = "libsql"
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

// boolPtr returns a pointer to the given bool, for optional TaskConfig fields.
func boolPtr(b bool) *bool {
	return &b
}

// Save writes the configuration to server.yml
// IsDebug returns true when debug mode is active (--debug flag or DEBUG env var).
func (c *ServerConfig) IsDebug() bool {
	if c.Debug {
		return true
	}
	dbg := os.Getenv("DEBUG")
	return dbg == "1" || dbg == "true" || dbg == "yes"
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
	// matching the AI.md PART 5 format. server.cors defaults to allowed_origins: ["*"].
	cf := ConfigFile{
		Server: *c,
		Web:    c.Web,
	}
	if len(cf.Server.Cors.AllowedOrigins) == 0 {
		cf.Server.Cors.AllowedOrigins = []string{"*"}
	}
	data, err := yaml.Marshal(cf)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write with restrictive permissions — the file contains the operator token
	// and installation secret (AI.md PART 11). Matches GenerateDefaultConfig.
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
