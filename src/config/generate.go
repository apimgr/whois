package config

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// defaultConfigTemplate returns the default server.yml template
func defaultConfigTemplate() string {
	return `# =============================================================================
# SERVER CONFIGURATION - caswhois
# =============================================================================
# This file is auto-generated on first run with sane defaults.
# All settings can be changed via admin panel or by editing this file.

server:
  # Port: Random unused port in 64000-64999 range
  # Change via admin panel or set manually (requires restart)
  port: {{PORT}}

  # Address: [::] listens on all interfaces (IPv4 + IPv6)
  address: "[::]"

  # Mode: production or development
  # Development mode enables debug features (pprof, verbose logging)
  mode: production

  # Admin panel path (default: admin)
  # Access at http://localhost:{{PORT}}/admin
  admin_path: admin

  # API version prefix (default: v1)
  # Used in /api/v1/ routes
  api_version: v1

  # Branding
  branding:
    title: "caswhois"
    tagline: "WHOIS Lookup Service"
    description: "Domain, IP, and ASN WHOIS lookup service"

  # SEO
  seo:
    keywords: []

  # System user/group (auto-detected)
  user: ""
  group: ""

  # PID file (created in data directory)
  pidfile: true

  # Daemonize: detach from terminal on start
  # Default: false (systemd/launchd prefer foreground)
  daemonize: false

  # Admin account
  admin:
    email: "admin@localhost"
    # Note: Password set on first run or via --admin-setup flag

  # SSL/TLS
  ssl:
    enabled: false
    cert: ""
    key: ""
    min_version: "TLS1.2"

    letsencrypt:
      enabled: false
      email: "admin@localhost"
      challenge: "http-01"
      staging: false

  # Scheduler - background tasks
  scheduler:
    enabled: true
    tasks:
      # Session cleanup
      session_cleanup:
        enabled: true
        schedule: "@hourly"

      # Log rotation
      log_rotation:
        enabled: true
        schedule: "0 0 * * *"
        max_age: "30d"
        max_size: "100MB"

      # Backup
      backup:
        enabled: true
        schedule: "0 2 * * *"
        retention: 4

      # Health check
      health_check:
        enabled: true
        schedule: "*/5 * * * *"

  # Rate limiting
  rate_limit:
    enabled: true
    # 60 requests per minute per IP
    requests: 60
    window: 60

  # Cache settings
  cache:
    enabled: true
    # Cache type: memory, valkey, redis
    type: "memory"
    # Maximum cache size (memory only)
    max_size: "100MB"
    # Default TTL
    ttl: "1h"

  # Database
  database:
    driver: "file"
    # SQLite databases created in data directory

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

logging:
  # Log level: debug, info, warn, error
  level: "info"

  # Access log (HTTP requests)
  access:
    enabled: true
    filename: "access.log"
    format: "apache"
    rotate: "daily"
    keep: "7d"

  # Server log (application events)
  server:
    enabled: true
    filename: "server.log"
    format: "text"
    rotate: "weekly"
    keep: "4w"

  # Error log
  error:
    enabled: true
    filename: "error.log"
    format: "text"
    rotate: "weekly"
    keep: "4w"

  # Audit log (security events)
  audit:
    enabled: true
    filename: "audit.log"
    format: "json"
    rotate: "monthly"
    keep: "6m"

# =============================================================================
# WHOIS-SPECIFIC CONFIGURATION
# =============================================================================

whois:
  # Cache TTLs
  cache_ttl:
    domain: "24h"
    ip: "168h"      # 7 days
    asn: "168h"     # 7 days
    failure: "5m"

  # Query timeouts
  timeouts:
    connect: "10s"
    total: "30s"

  # Server registry
  servers:
    # RIR servers
    iana: "whois.iana.org:43"
    arin: "whois.arin.net:43"
    ripe: "whois.ripe.net:43"
    apnic: "whois.apnic.net:43"
    lacnic: "whois.lacnic.net:43"
    afrinic: "whois.afrinic.net:43"
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

	// Replace template variables
	config := defaultConfigTemplate()
	config = strings.Replace(config, "{{PORT}}", fmt.Sprintf("%d", port), -1)

	// Write config file
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
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
