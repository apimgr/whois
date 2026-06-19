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

// defaultConfigTemplate returns the default server.yml template (AI.md PART 5).
// The file uses a top-level server: key with nested sections matching the
// ServerConfig yaml tags. All comments go ABOVE their setting (PART 5 rule).
func defaultConfigTemplate() string {
	return `# =============================================================================
# caswhois — Server Configuration (AI.md PART 5)
# =============================================================================
# Auto-generated on first run. Edit this file to change settings.
# All changes require a server restart.
# =============================================================================

server:
  # ===========================================================================
  # CORE
  # ===========================================================================

  # Random port in 64000-64999 range; change to a fixed value if preferred
  port: {{PORT}}

  # Listen on all interfaces (IPv4 + IPv6)
  address: "[::]"

  # production or development
  mode: production

  # Debug endpoints and logging (use --debug flag or set here)
  debug: false

  # Operator bearer token — auto-generated on first run; NEVER share this
  # Format: tok_<32 base62 chars>
  # Used for: bulk WHOIS, scheduler management, backup operations
  token: "{{TOKEN}}"

  # Daemonize: detach from terminal (set true for manual launch without systemd)
  daemonize: false

  # PID file written to data directory on start
  pidfile: true

  # ===========================================================================
  # BRANDING (PART 16)
  # ===========================================================================

  branding:
    title: "caswhois"
    tagline: "WHOIS Lookup Service"
    description: "Domain, IP, and ASN WHOIS lookup service"
    # Theme: auto, light, dark
    theme: "auto"
    accent_color: "#007bff"

  # ===========================================================================
  # DATABASE — SQLite only (PART 10)
  # ===========================================================================

  database:
    # driver: sqlite (default) or libsql/turso for remote
    driver: ""
    # url: libsql://your-db.turso.io?authToken=TOKEN (for remote mode)
    url: ""
    # dir: override SQLite data directory (default: auto from OS context)
    dir: ""

  # ===========================================================================
  # SSL / TLS (PART 15)
  # ===========================================================================

  ssl:
    enabled: false
    # challenge: http-01 (default), tls-alpn-01, dns-01
    challenge: "http-01"
    # email: ACME account contact for Let's Encrypt
    email: ""
    min_version: "1.2"
    staging: false
    dns_provider: ""

  # ===========================================================================
  # RATE LIMITING (PART 12)
  # ===========================================================================

  rate_limit:
    enabled: true
    read:
      requests: 120
      window: 60
    write:
      requests: 10
      window: 60
    health:
      requests: 120
      window: 60
    global_burst: 240

  # ===========================================================================
  # GEOIP (PART 19)
  # ===========================================================================

  geoip:
    enabled: true
    # dir: override GeoIP database directory (default: {data_dir}/security/geoip)
    dir: ""
    deny_countries: []
    allow_countries: []
    databases:
      asn: true
      country: true
      city: true
      whois: true

  # ===========================================================================
  # METRICS — Prometheus-compatible (PART 20)
  # ===========================================================================

  metrics:
    enabled: true
    endpoint: "/metrics"
    include_system: true
    include_runtime: true
    # token: leave empty to allow unauthenticated access (restrict by firewall)
    token: ""

  # ===========================================================================
  # EMAIL / SMTP (PART 17)
  # ===========================================================================

  notifications:
    email:
      smtp:
        # host: empty = auto-detect loopback/Docker/gateway SMTP on startup
        host: ""
        # port: 587 = STARTTLS, 465 = TLS, 25 = plain
        port: 587
        username: ""
        password: ""
        # tls: auto, starttls, tls, none
        tls: "auto"
      from:
        # name: empty = branding title
        name: ""
        # email: empty = no-reply@{fqdn}
        email: ""

  # ===========================================================================
  # BACKUP & RESTORE (PART 21)
  # ===========================================================================

  backup:
    # dir: empty = auto from OS context ({data_dir}/backups)
    dir: ""
    encryption:
      enabled: false
    retention:
      max_backups: 1
      keep_weekly: 0
      keep_monthly: 0
      keep_yearly: 0

  compliance:
    enabled: false

  # ===========================================================================
  # UPDATES (PART 22)
  # ===========================================================================

  # update_channel: stable, beta, daily
  update_channel: "stable"

  # ===========================================================================
  # TOR HIDDEN SERVICE (PART 31)
  # ===========================================================================

  tor:
    # binary: empty = auto-detect from PATH
    binary: ""
    use_network: false
    bootstrap_timeout: 180
    safe_logging: true
    bandwidth_rate: "1 MB"
    bandwidth_burst: "2 MB"
    max_monthly_bandwidth: "100 GB"
    virtual_port: 80
    max_circuits: 32
    max_streams_per_circuit: 100

  # ===========================================================================
  # SCHEDULER (PART 18)
  # ===========================================================================

  scheduler:
    timezone: "America/New_York"
    catch_up_window: "1h"

# =============================================================================
# WEB LAYER (PART 16)
# =============================================================================

web:
  # cors: "*" = allow all origins (default); "" = no CORS; or comma-separated list
  cors: "*"
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
