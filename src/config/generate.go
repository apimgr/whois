package config

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

const tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GenerateToken generates a spec-compliant token: "tok_" + 32 base62 chars.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(tokenAlphabet))))
		if err != nil {
			return "", err
		}
		b[i] = tokenAlphabet[n.Int64()]
	}
	return "tok_" + string(b), nil
}

// defaultConfigTemplate returns the default server.yml template.
// All YAML comments go ABOVE their setting (PART 5 style rule).
func defaultConfigTemplate() string {
	return `# =============================================================================
# caswhois — Server Configuration
# =============================================================================
# Auto-generated on first run. Edit this file to change settings.
# All changes require a server restart.
# =============================================================================

# =============================================================================
# SERVER
# =============================================================================

# Random port in 64000-64999 range; set manually to a fixed value if preferred
port: {{PORT}}

# Listen on all interfaces (IPv4 + IPv6)
address: "[::]"

# production or development (development enables pprof and verbose logging)
mode: production

# Debug logging (overrides mode; use --debug flag or set here)
debug: false

# Operator bearer token — auto-generated on first run; NEVER share this
# Format: tok_<32 base62 chars>
# Used for: bulk WHOIS, scheduler management, backup operations
server_token: "{{TOKEN}}"

# Daemonize: detach from terminal (set true for manual launch without systemd)
daemonize: false

# PID file written to data directory on start
pidfile: true

# =============================================================================
# BRANDING
# =============================================================================

branding_title: "caswhois"
branding_tagline: "WHOIS Lookup Service"
branding_description: "Domain, IP, and ASN WHOIS lookup service"

# Theme: auto, light, dark
branding_theme: "auto"

# =============================================================================
# RATE LIMITING
# =============================================================================

rate_limit_enabled: true

# Requests allowed per window per IP
rate_limit_requests: 120

# Rolling window length
rate_limit_window: "1m"

# =============================================================================
# DATABASE — SQLite only (no PostgreSQL, no MySQL)
# =============================================================================

# Override database directory (default: {data_dir})
database_dir: ""

# =============================================================================
# SSL / TLS (PART 15)
# =============================================================================

# SSL/TLS settings (see PART 15 for full Let's Encrypt configuration)

# =============================================================================
# GEOIP (PART 19)
# =============================================================================

geoip_enabled: true

# Directory for MaxMind GeoLite2 databases (default: {config_dir}/security/geoip)
geoip_dir: ""

geoip_database_asn: true
geoip_database_country: true
geoip_database_city: true
geoip_database_whois: true

# ISO 3166-1 alpha-2 country codes to deny
geoip_deny_countries: []

# =============================================================================
# METRICS — Prometheus-compatible (PART 20)
# =============================================================================

metrics_enabled: true
metrics_endpoint: "/metrics"
metrics_include_system: true
metrics_include_runtime: true

# Token to protect /metrics (leave empty to allow unauthenticated access)
metrics_token: ""

# =============================================================================
# EMAIL / SMTP (PART 17)
# =============================================================================

# Email settings (sendmail → msmtp → ssmtp → SMTP direct, auto-detected)

# =============================================================================
# BACKUP & RESTORE (PART 21)
# =============================================================================

# Backup directory (default: {data_dir}/backups)
backup_dir: ""

# Encrypt backups with Argon2id key derivation
backup_encryption_enabled: false

# Daily full backups to retain
backup_max_backups: 7

# Weekly backups to retain (Sunday; 0 = disabled)
backup_keep_weekly: 4

# Monthly backups to retain (1st of month; 0 = disabled)
backup_keep_monthly: 12

# Yearly backups to retain (Jan 1; 0 = disabled)
backup_keep_yearly: 3

# =============================================================================
# UPDATES (PART 22)
# =============================================================================

# Update channel: stable, beta, daily
update_channel: "stable"

# =============================================================================
# TOR HIDDEN SERVICE (PART 31)
# =============================================================================

# Path to tor binary (leave empty for auto-detection from PATH)
tor_binary: ""

# Route outbound WHOIS requests through Tor for anonymity
tor_use_network: false

# Bootstrap timeout in seconds (wait for Tor network)
tor_bootstrap_timeout: 180

# Scrub sensitive info from Tor logs
tor_safe_logging: true

# Bandwidth rate per second (e.g. "1 MB", "500 KB")
tor_bandwidth_rate: "1 MB"

# Bandwidth burst per second
tor_bandwidth_burst: "2 MB"

# Monthly bandwidth limit (e.g. "100 GB", "unlimited")
tor_max_monthly_bandwidth: "100 GB"

# Virtual port users connect to (.onion:PORT → server port)
tor_virtual_port: 80

# Maximum circuits to keep open
tor_max_circuits: 32

# Maximum concurrent streams per circuit
tor_max_streams_per_circuit: 100

# =============================================================================
# LOGGING
# =============================================================================

# Log files are written to {log_dir}: access.log, server.log, error.log, audit.log

# =============================================================================
# WHOIS CACHE TTLs
# =============================================================================

# (Configured in code; TTLs: domain=24h, ip/asn=168h, failure=5m)
`
}

// GenerateDefaultConfig creates default server.yml if it doesn't exist
func GenerateDefaultConfig(configDir string) error {
	configPath := filepath.Join(configDir, "server.yml")

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		return nil
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate random port in 64000-64999 range
	port, err := randomPort()
	if err != nil {
		port = 64580
	}

	// Generate server token on first run
	token, err := GenerateToken()
	if err != nil {
		return fmt.Errorf("failed to generate server token: %w", err)
	}

	// Replace template variables
	config := defaultConfigTemplate()
	config = strings.Replace(config, "{{PORT}}", fmt.Sprintf("%d", port), 1)
	config = strings.Replace(config, "{{TOKEN}}", token, 1)

	// Write config file with restrictive permissions (contains token)
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// randomPort generates a random port in the 64000-64999 range
func randomPort() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + 64000, nil
}
