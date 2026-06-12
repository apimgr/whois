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

### Product scope & non-goals

**In scope:**

- WHOIS lookup for domains, IPv4, IPv6, and ASNs — auto-detect query type
- Proxied queries to upstream WHOIS servers (IANA, RIRs, TLD-specific)
- Caching of WHOIS results (TTL: domain 24h, IP/ASN 7d, failure 5m)
- Rate-limited anonymous access; unlimited for server-token holders
- Bulk lookup (POST, server-token required)
- GeoIP enrichment (ASN, Country, City) from MaxMind GeoLite2
- Tor hidden service support (optional, auto-enabled if Tor detected)
- Prometheus-compatible metrics endpoint
- Argon2id-encrypted backup and restore
- In-place self-update via GitHub releases
- Service manager integration (systemd, OpenRC, runit, s6, launchd, SCM)
- Built-in scheduler for ssl_renewal, geoip_update, token_cleanup, log_rotation, backup_daily, backup_hourly, healthcheck_self, blocklist_update, cve_update, tor_health
- TLS via Let's Encrypt (HTTP-01, TLS-ALPN-01, DNS-01)
- CLI client (caswhois-cli) with TUI, setup wizard, auto-update
- Shell completions (bash, zsh, fish, powershell)

**Non-goals:**

- This service does NOT register or modify domain records
- This service does NOT store WHOIS data long-term beyond configurable TTL
- No user accounts, no sessions, no cookies — bearer token only
- No admin web UI — all configuration via server.yml only
- No PostgreSQL or MySQL — SQLite/libsql only
- No external cron — built-in scheduler only
- This service is NOT a registrar API; it is a read-only lookup proxy

**Endpoints (WHAT — see AI.md PART 14 for paths):**

- Generic WHOIS lookup (auto-detect domain/IP/ASN)
- Domain-specific WHOIS lookup
- IP-specific WHOIS lookup (v4 and v6)
- ASN-specific WHOIS lookup
- Query validation without performing lookup
- Bulk lookup (POST, server-token required)
- WHOIS server list
- Server statistics
- Scheduler task list and manual trigger (server-token required)
- Backup list and trigger (server-token required)
- Health check (public, no auth)
- Metrics (Prometheus format, token-protected when configured)
- Autodiscovery (server info + CLI version/sha256 for auto-update)
- CLI binary download (public by default)
- Security disclosure policy (well-known)
- Sitemap and robots policy
- About and API documentation pages (server-side rendered)

### Roles & permissions

**Two tiers — no user accounts, no sessions:**

| Role | How identified | Access |
|------|---------------|--------|
| Anonymous | No Authorization header | Public GET endpoints (lookup, stats, health); rate-limited per IP |
| Operator | `Authorization: Bearer {server.token}` | All endpoints including bulk, scheduler, backups, metrics (if configured) |

**server.token rules:**
- Auto-generated on first run (`tok_` + 32 base62 chars) and stored in server.yml
- Never stored in the database
- Validated by SHA-256-hashing the inbound bearer and comparing with `subtle.ConstantTimeCompare`
- Bypasses rate limiting; allows bulk lookup

**api_tokens (per-resource tokens):**
- Stored as SHA-256 hash + prefix only in the `api_tokens` table
- Used for resource-owner access; scoped to a specific resource_type/resource_id
- Never stored plain

### Data model & sensitivity

**Tables (SQLite/libsql — see AI.md PART 10):**

- **config**: key, value (JSON-encoded), type, updated_at — KV store for runtime-readable config; no mutation via API
- **config_meta**: id (single-row), version (auto-incremented on any config change), updated_at
- **rate_limits**: key, count, window_start, updated_at — per-IP sliding window counters
- **audit_log**: id, timestamp, level, category, action, actor_ip, target_type, target_id, details, success
- **scheduler_tasks**: id, name, enabled, schedule, last_run, next_run, last_status, last_error, run_count, fail_count
- **scheduler_history**: id, task_id → scheduler_tasks, started_at, finished_at, status, error, duration_ms
- **backups**: id, filename, filepath, size_bytes, type, created_at, checksum, notes
- **api_tokens**: id, token_hash (SHA-256), token_prefix, resource_type, resource_id, created_at, expires_at, last_used_at, revoked_at, revoked_reason
- **whois_cache_meta**: query, type, server, cached_at, expires_at, hit_count

**Sensitivity classification:**

| Data | Sensitivity | Notes |
|------|-------------|-------|
| server.token (server.yml) | HIGH | Operator secret; SHA-256 compared; never logged raw |
| api_token hashes (DB) | HIGH | Stored as SHA-256 only; prefix for identification |
| WHOIS results (cache) | LOW | Publicly available data; no PII beyond what WHOIS exposes |
| audit_log.actor_ip | MEDIUM | IP addresses are PII in some jurisdictions; not exposed via API |
| rate_limits | LOW | Counters only; no content |
| backup password (server.yml) | HIGH | Argon2id KDF; never stored plain |

### Trust boundaries & external services

**Trusted (operator-controlled):**
- `server.yml` config file (filesystem, root-owned or user-owned)
- Local SQLite database file
- Docker volume mounts

**Untrusted (require validation):**
- All HTTP request bodies, query strings, headers, path segments
- WHOIS query strings (validated against allowed character set and length before dispatch)
- Bulk lookup payloads (max batch size enforced; each query validated individually)

**External services (upstream WHOIS servers):**

| Server | Trust level | Failure mode |
|--------|-------------|-------------|
| whois.iana.org (root) | Accept results as-is; no authentication | Return cached data if available; log error and return degraded response |
| ARIN, RIPE, APNIC, LACNIC, AFRINIC (RIRs) | Accept results as-is | Same as above |
| TLD-specific servers (queried by IANA referral) | Accept results as-is | Return raw response; parse best-effort |
| MaxMind GeoLite2 CDN (weekly update) | Trusted source; checksum verified | Retain existing DB on download failure; log warning |
| GitHub Releases (self-update) | SHA-256 verified before replacing binary | Abort update on checksum mismatch; log error |
| Let's Encrypt ACME (TLS provisioning) | Standard ACME protocol | Retain existing cert; schedule retry |
| Tor network (hidden service) | Optional; operator-opt-in | Disable hidden service on Tor failure; HTTP still serves |

**SSRF prevention:** The server only dispatches WHOIS queries to the static upstream server list (derived from IANA referrals and hardcoded RIRs). No operator or user can inject an arbitrary hostname into the WHOIS dispatch path. DNS resolution for WHOIS servers happens at query time, not at config time.

### Threat model & abuse cases

**Primary assets being protected:**
- The `server.token` operator secret in server.yml
- API token hashes in the database
- The upstream WHOIS server quota (ARIN, RIPE, etc. may rate-limit the server's IP)
- The server's CPU, memory, and network bandwidth

**Trusted vs untrusted inputs:**
- Trusted: filesystem paths set at startup, server.yml, SQLite DB, Docker environment
- Untrusted: all HTTP inputs (path, query string, headers, body), WHOIS query strings, bulk payloads
- Conditionally trusted: Bearer tokens — trusted only after SHA-256 hash comparison passes

**Main attacker / abuser goals:**
1. Enumerate or extract the server.token to gain operator access
2. Use caswhois as a free WHOIS proxy to bypass upstream rate limits (amplification)
3. Exhaust server resources (memory/CPU/network) via high-volume or pathological queries
4. Cache poisoning — inject false WHOIS data
5. SSRF via crafted queries targeting internal network hosts
6. Timing side-channel to infer whether a domain is cached (information disclosure)

**Defenses required per threat:**

| Threat | Defense |
|--------|---------|
| Token enumeration | SHA-256 hash stored; `subtle.ConstantTimeCompare` always; no token in logs |
| WHOIS amplification | Rate limiting per IP (read: 120 req/min, write: 10 req/min); bulk requires server token; TTL caching reduces upstream queries |
| Resource exhaustion | Request size limits (10MB body max); read/write/global-burst rate limits; query length validation |
| Cache poisoning | WHOIS results accepted from upstream only; no user-supplied data written to cache |
| SSRF | Upstream server list is static; no user-controlled server selection; path traversal middleware blocks `..` in paths |
| Cache timing oracle | Same response structure for hit and miss; no `X-Cache-Hit` header exposed publicly |
| Bulk abuse | POST `/api/v1/whois/bulk` requires server token; batch size capped |

**Explicit non-goals for security:**
- mTLS between caswhois and upstream WHOIS servers — not supported by upstream protocol
- Proof of WHOIS result authenticity — upstream provides none; we relay as-is

### Security decisions & exceptions

**Intentional security decisions (documented here per AI.md PART 1):**

- **No admin web UI**: All configuration is file-only (server.yml). This eliminates an entire class of CSRF/XSS/privilege-escalation risks. Operators who need to change config must have filesystem access — this is a feature, not a limitation.
- **Bearer token only; no sessions**: PART 1 requires no session cookies, no user accounts. This is by design — the threat model for a WHOIS service does not benefit from user sessions; it only adds attack surface.
- **server.token stored plaintext in server.yml**: The token is a secret known to the operator; the file is assumed to be accessible only to the operator (root-owned or 600 permissions). Hash-only storage in the DB is the actual protection; the server.yml is the operator's own config file.
- **Anonymous GET allowed on all public endpoints**: WHOIS data is publicly available. Blocking anonymous access adds friction with no security value. Rate limiting is the appropriate abuse control.
- **Upstream WHOIS result accepted without cryptographic verification**: Upstream WHOIS protocol (RFC 3912) has no signing mechanism. Results are proxied as-is; cache invalidation on TTL expiry is the integrity mechanism.
- **Port chosen randomly (64000–64999) on first run**: Avoids well-known port conflicts; not a security measure. Operators behind a reverse proxy map to port 80 inside the container.
- **Parameterized queries always; no raw SQL string building**: Enforced in all database access. Violation of this rule is a bug.
- **Argon2id for backup encryption key derivation**: bcrypt and PBKDF2 are explicitly forbidden. Argon2id (winner of the Password Hashing Competition) is required.
