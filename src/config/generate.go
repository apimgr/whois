package config

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/apimgr/whois/src/common/constants"
)

const tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GenerateInstallationSecret generates a 64-char hex installation secret (AI.md PART 11).
// This is the root KDF input for PGP private-key encryption and derived material.
func GenerateInstallationSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate installation secret: %w", err)
	}
	result := make([]byte, 64)
	const hexChars = "0123456789abcdef"
	for i, byt := range b {
		result[i*2] = hexChars[byt>>4]
		result[i*2+1] = hexChars[byt&0xf]
	}
	return string(result), nil
}

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
# {{INTERNAL_NAME}} — Server Configuration (AI.md PART 5)
# =============================================================================
# Auto-generated on first run. Edit this file to change settings.
# Most settings hot-reload automatically (checked every 5s, AI.md PART 8).
# Only server.address, server.port, ssl.*, server.daemonize, database.*, and
# tor.* require a full server restart to take effect.
# =============================================================================

server:
  # ===========================================================================
  # CORE
  # ===========================================================================

  # Random port in 64000-64999 range; change to a fixed value if preferred
  port: {{PORT}}

  # Listen on all interfaces
  address: "0.0.0.0"

  # production or development
  mode: production

  # Debug endpoints and logging (use --debug flag or set here)
  debug: false

  # Operator bearer token — auto-generated on first run; NEVER share this
  # Format: tok_<32 base62 chars>
  # Used for: bulk WHOIS, scheduler management, backup operations
  token: "{{TOKEN}}"

  # Installation secret — root KDF input for PGP private-key encryption
  # (AI.md PART 11). Auto-generated on first run; NEVER share or lose this.
  installation_secret: "{{SECRET}}"

  # Daemonize: detach from terminal (set true for manual launch without systemd)
  daemonize: false

  # PID file written to data directory on start
  pidfile: true

  # ===========================================================================
  # BRANDING (PART 16)
  # ===========================================================================

  branding:
    title: "{{INTERNAL_NAME}}"
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
  # CACHE (PART 12) — optional; defaults to in-process memory
  # ===========================================================================

  cache:
    # type: none (disabled), memory (default), valkey, redis
    type: "memory"
    # url: redis://user:pass@host:port/db — takes precedence over host/port below
    url: ""
    host: "localhost"
    port: 6379
    username: ""
    password: ""
    db: 0
    tls: false
    tls_skip_verify: false
    pool_size: 10
    min_idle: 2
    timeout: "5s"
    prefix: "{{INTERNAL_NAME}}:"
    ttl: "1h"

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
      max_total_size: "10%"

  compliance:
    enabled: false

  # ===========================================================================
  # UPDATES (PART 22)
  # ===========================================================================

  update:
    # branch: stable, beta, daily (also settable via --update branch)
    branch: "stable"
    # auto_install: default OFF — the update_check task only notifies;
    # installing is always an explicit operator decision
    auto_install: false
    # defer_days: a release is only eligible once it is this many days old
    # (0-365); 0 = adopt releases immediately. Manual --update always ignores this.
    defer_days: 0

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
    # onion_address: set automatically once the hidden service is created
    onion_address: ""
    # contact_email: shown in the hidden service descriptor (optional)
    contact_email: ""

  # ===========================================================================
  # PRIVACY & CONSENT (PART 12) — GDPR/CCPA cookie consent banner
  # ===========================================================================

  privacy:
    data:
      # sold: MIT license allows others to change this; default false
      sold: false
      stored_on_server: true
      sharing:
        - condition: "analytics"
          when: "Tracking configured (server.tracking.type set) AND user consents"
          data: "Anonymized: page views, browser type, country"
        - condition: "email"
          when: "SMTP configured for sending emails"
          data: "Email address, message content"
        - condition: "user_initiated"
          when: "User explicitly shares content (social buttons, exports)"
          data: "Whatever user chooses to share"

    retention:
      period: "Account data is retained while your account is active. Upon account deletion, all personal data is permanently deleted within 30 days. Anonymized analytics data may be retained for up to 12 months."
      export_available: true
      deletion_available: true

    consent:
      show_until_acknowledged: true
      # default_enabled: opt-out model — user must click Decline
      default_enabled: true
      message: "In accordance with the EU GDPR law this message is being displayed. We use cookies for essential site functionality and, with your consent, for preferences and analytics. Your data is stored on our servers and is never sold."
      message_if_sold: "In accordance with the EU GDPR law this message is being displayed. We use cookies for essential site functionality and, with your consent, for preferences and analytics. Your data may be shared with or sold to third parties as described in our Privacy Policy."
      policy:
        text: "Privacy Policy"
        url: "/server/privacy"
      buttons:
        decline: "Decline"
        accept: "I Agree"
      # position: bottom or top
      position: "bottom"
      show_preferences: true
      preferences_text: "Manage Preferences"

    cookies:
      essential:
        enabled: true
        description: "Required for the site to function. Includes security tokens (CSRF) and site preferences. These cookies are strictly necessary and cannot be disabled."
      preferences:
        enabled: true
        description: "Remember your settings such as theme (dark/light), language, and UI preferences. Disabling will reset to defaults on each visit."
      analytics:
        enabled: true
        description: "Help us understand how visitors use our site to improve the experience."
        description_suffix_not_sold: "Analytics data is anonymized and never sold."
        description_suffix_sold: "Analytics data may be shared with third parties."

    # third_party.services: auto-populated from server.tracking config + manual entries
    third_party:
      services: []

    content:
      data_collection: |
        We collect only what is necessary to provide our service: usage information
        (with consent), technical information (IP address, hashed API tokens). We do
        NOT collect payment information, precise location, or data from other sites.
      data_usage: |
        Your data is used solely to provide the service, improve the experience,
        ensure security, and communicate with you. It is never sold, used for
        targeted advertising, or shared without consent except as required by law.
      data_usage_if_sold: |
        Your data may be used to provide the service, improve the experience, ensure
        security, communicate with you, and for third-party sharing as described
        below. You can opt out of data sales and request deletion at any time.
      data_security: |
        All data is stored on our servers. API tokens are stored as SHA-256 hashes.
        All connections are encrypted (HTTPS/TLS). We perform regular security
        audits and maintain access controls and audit logging for operator actions.

  # ===========================================================================
  # SCHEDULER (PART 18)
  # ===========================================================================

  scheduler:
    timezone: "America/New_York"
    catch_up_window: "1h"

    # Built-in tasks — adjust schedule and enabled per PART 18; critical tasks cannot be disabled
    tasks:

      # Daily at 03:00 — renew certs 7 days before expiry
      ssl_renewal:
        schedule: "0 3 * * *"
        enabled: true

      # Weekly Sunday at 03:00 — download/update GeoIP databases
      geoip_update:
        schedule: "0 3 * * 0"
        enabled: true

      # Daily at 04:00 — download/update IP/domain blocklists
      blocklist_update:
        schedule: "0 4 * * *"
        enabled: true
        retry_on_fail: true
        retry_delay: "1h"

      # Daily at 05:00 — download/update CVE/security databases
      cve_update:
        schedule: "0 5 * * *"
        enabled: true
        retry_on_fail: true
        retry_delay: "1h"

      # Daily at 06:00 — check release channel; auto-install only if update.auto_install is true
      update_check:
        schedule: "0 6 * * *"
        enabled: true

      # Every 15 minutes — remove expired API tokens and sessions (critical — cannot disable)
      token_cleanup:
        schedule: "@every 15m"
        enabled: true

      # Daily at midnight — rotate and compress old logs (critical — cannot disable)
      log_rotation:
        schedule: "0 0 * * *"
        enabled: true

      # Daily at 02:00 — full backup (operator can disable in server.yml)
      backup_daily:
        schedule: "0 2 * * *"
        enabled: true
        verify: true
        retention:
          max_backups: 1
          keep_weekly: 0
          keep_monthly: 0
          keep_yearly: 0
          max_total_size: "10%"

      # Hourly incremental backup (disabled by default)
      backup_hourly:
        schedule: "@hourly"
        enabled: false

      # Every 5 minutes — self-health verification (critical — cannot disable)
      healthcheck_self:
        schedule: "@every 5m"
        enabled: true

      # Every 10 minutes — check Tor connectivity, restart if needed
      tor_health:
        schedule: "@every 10m"
        enabled: true
        restart_on_fail: true

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

	// Generate installation secret on first run (AI.md PART 11).
	secret, err := GenerateInstallationSecret()
	if err != nil {
		return fmt.Errorf("failed to generate installation secret: %w", err)
	}

	// Replace template variables
	config := defaultConfigTemplate()
	config = strings.Replace(config, "{{PORT}}", fmt.Sprintf("%d", port), 1)
	config = strings.Replace(config, "{{TOKEN}}", token, 1)
	config = strings.Replace(config, "{{SECRET}}", secret, 1)
	config = strings.ReplaceAll(config, "{{INTERNAL_NAME}}", constants.InternalName)

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
