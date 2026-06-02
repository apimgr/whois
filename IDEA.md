## Project description

caswhois is a self-hosted WHOIS lookup service that provides fast, cached information about domain names, IP addresses, and Autonomous System Numbers (ASNs). It ships as a single static binary with an embedded SQLite database, a web interface, a REST API, and a companion CLI client. No external dependencies are required for first-run.

Target users include system administrators, network engineers, security researchers, domain investors, and developers who need programmatic access to WHOIS data. The service is fully free — no feature gating, no premium tiers, no telemetry without explicit opt-in.

## Project variables

project_name:      caswhois
project_org:       casapps
internal_name:     caswhois
app_name:          caswhois
binary:            caswhois
binary_cli:        caswhois-cli
module:            github.com/casapps/caswhois
api_version:       v1
official_site:     https://caswhois.casapps.dev
maintainer_name:   CasJay
maintainer_email:  casjay@yahoo.com

## Business logic

**Target users:**
- System administrators and network engineers
- Security researchers and analysts
- Domain investors and registrars
- Developers building applications that need WHOIS data
- Anyone needing domain/IP/ASN ownership information

**Features:**

- **WHOIS Lookup**: Auto-detect query type (domain, IPv4, IPv6, ASN); query upstream WHOIS servers (IANA, RIRs, TLD-specific); parse structured data from raw responses; fallback to alternate servers on failure
- **Caching**: In-memory cache (default) or Valkey/Redis (optional); TTL 24h domain, 7d IP/ASN, 5m failures
- **Rate Limiting**: 60 req/min per IP (configurable in server.yml); never blocks operators via API token
- **GeoIP**: MaxMind GeoLite2 ASN/Country/City; weekly scheduler update
- **Tor Hidden Service**: Optional onion address via built-in Tor integration
- **Email/Notifications**: SMTP auto-detection (sendmail→msmtp→ssmtp→direct); explicit SMTP config optional
- **Bulk Lookup**: POST /api/v1/whois/bulk — batch queries (server-token required)
- **Metrics**: Prometheus-compatible /metrics endpoint; token-protected when configured
- **Backup/Restore**: Argon2id-encrypted backups; daily/hourly retention; --maintenance backup/restore
- **Self-Update**: --update check/yes/branch for in-place binary replacement with SHA-256 verification
- **Service Manager**: systemd/OpenRC/runit/s6 (Linux), launchd (macOS), SCM (Windows)
- **Scheduler**: Built-in; no external cron; tasks: ssl_renewal, geoip_update, token_cleanup, log_rotation, backup_daily, backup_hourly, healthcheck_self
- **TLS/HTTPS**: Let's Encrypt via lego (HTTP-01/TLS-ALPN-01/DNS-01); auto-renewal at 30d before expiry
- **Internationalization**: 7 languages (en/es/zh/fr/ar/de/ja); embedded via go:embed; language cookie
- **CLI Client**: caswhois-cli with TUI (bubbletea), setup wizard, --update, --lang, --color flags
- **Shell Completions**: bash, zsh, fish, powershell via --shell completions

**Data models:**

- **config**: key, value (JSON-encoded), type, updated_at (KV store for runtime-readable config; no mutation via API)
- **config_meta**: id (single-row), version (auto-incremented on any config change), updated_at
- **rate_limits**: key, count, window_start, updated_at
- **audit_log**: id, timestamp, level, category, action, actor_ip, target_type, target_id, details, success
- **scheduler_tasks**: id, name, enabled, schedule, last_run, next_run, last_status, last_error, run_count, fail_count
- **scheduler_history**: id, task_id → scheduler_tasks, started_at, finished_at, status, error, duration_ms
- **backups**: id, filename, filepath, size_bytes, type, created_at, checksum, notes
- **api_tokens**: id, token_hash (SHA-256), token_prefix, resource_type, resource_id, created_at, expires_at, last_used_at, revoked_at, revoked_reason

**Business rules:**

- All configuration via server.yml only — no admin web UI, no runtime mutation via API
- Token-only auth: tok_ + 32 base62 chars; SHA-256 stored; constant-time compare; never in DB plain
- SQLite only (default) or libsql/Turso — no PostgreSQL, no MySQL
- CGO_ENABLED=0 always — single static binary
- No feature gating — all features free
- Backup passwords use Argon2id only — never bcrypt, never plaintext
- WHOIS cache TTLs: domain 24h, IP 7d, ASN 7d, failure 5m
- Rate limit: 60 req/min per IP (configurable); bypassed by server token
- Server token auto-generated on first run if absent; stored in server.yml never in DB
- Anonymous GET allowed on all public endpoints, rate-limited
- Port: random 64000–64999 on first run; persisted to server.yml
- Parameterized queries always — no string concatenation in SQL

**Endpoints (WHAT — see AI.md PART 14 for paths):**

- Generic WHOIS lookup (auto-detect domain/IP/ASN)
- Domain-specific WHOIS lookup
- IP-specific WHOIS lookup (v4 and v6)
- ASN-specific WHOIS lookup
- Query validation (without performing lookup)
- Bulk lookup (POST, server-token required)
- WHOIS server list
- Server statistics
- Scheduler task list and trigger (server-token required)
- Backup list and trigger (server-token required)
- Health check (public, no auth)
- Metrics (Prometheus format, token-protected when configured)
- Autodiscovery (server info + CLI version/sha256 for auto-update)
- CLI binary download (public by default)
- /.well-known/security.txt
- /sitemap.xml and /robots.txt
- /about and /docs pages (server-side rendered)

**Data sources:**

- IANA WHOIS: whois.iana.org (TLD/ASN root)
- ARIN (North America): whois.arin.net
- RIPE NCC (Europe): whois.ripe.net
- APNIC (Asia Pacific): whois.apnic.net
- LACNIC (Latin America): whois.lacnic.net
- AFRINIC (Africa): whois.afrinic.net
- TLD-specific WHOIS servers (per-domain, queried on-demand)
- MaxMind GeoLite2 (ASN, Country, City) — updated weekly by scheduler
- No local database of all domains; queries are proxied with caching
