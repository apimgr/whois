## Project description

caswhois is a self-hosted WHOIS lookup service that provides fast, cached information about domain names, IP addresses, and Autonomous System Numbers (ASNs). It ships as a single static binary with an embedded SQLite database, a web interface, a REST API, and a companion CLI client. No external dependencies are required for first-run.

Target users include system administrators, network engineers, security researchers, domain investors, and developers who need programmatic access to WHOIS data. The service is fully free — no feature gating, no premium tiers, no telemetry without explicit opt-in.

## Project variables

project_name:      caswhois
project_org:       apimgr
internal_name:     caswhois
internal_org:      apimgr
app_name:          caswhois
binary:            caswhois
binary_cli:        caswhois-cli
module:            github.com/apimgr/whois
api_version:       v1
official_site:     https://caswhois.apimgr.dev
maintainer_name:   CasJay
maintainer_email:  casjay@yahoo.com

## Business logic

### Product scope & non-goals

**In scope:**

- WHOIS lookup for domains, IPv4, IPv6, and ASNs — auto-detect query type
- Dual-protocol data retrieval: RDAP (preferred) with WHOIS fallback
- Proxied queries to upstream WHOIS servers (IANA, RIRs, TLD-specific)
- In-memory cache for hot queries (TTL: domain 24h, IP/ASN 7d, failure 5m) — fast path only
- Persistent WHOIS record database — every successful lookup is stored permanently in SQLite; builds a free, comprehensive, self-hosted WHOIS dataset over time
- Rate-limited anonymous access; unlimited for server-token holders
- Bulk lookup (POST, server-token required)
- Owner/registrant reverse search — `GET /whois/search?owner=...`; searches the persistent local database by registrant name, org, or email; no external API key required; quality grows with usage
- External reverse WHOIS seeding (optional) — supported providers: securitytrails, whoxy, viewdns; when an owner search returns no local results, optionally query the configured provider AND import its results into the local database via background WHOIS lookups, permanently enriching the dataset; provider key stored in browser localStorage (web), cli.yml (CLI), or server.yml (operator default); server never persists user-supplied per-request keys
- GeoIP enrichment (ASN, Country, City) from MaxMind GeoLite2
- Tor hidden service support (optional, auto-enabled if Tor detected)
- Prometheus-compatible metrics endpoint
- Argon2id-encrypted backup and restore
- In-place self-update via GitHub releases
- Service manager integration (systemd, OpenRC, runit, s6, launchd, SCM)
- Built-in scheduler for ssl_renewal, geoip_update, token_cleanup, log_rotation, backup_daily, backup_hourly, healthcheck_self, blocklist_update, cve_update, tor_health, whois_records_refresh (re-queries stale records older than configurable threshold, default 30d), rdap_bootstrap_update (weekly refresh of IANA RDAP bootstrap files)
- TLS via Let's Encrypt (HTTP-01, TLS-ALPN-01, DNS-01)
- CLI client (caswhois-cli) with TUI, setup wizard, auto-update
- Shell completions (bash, zsh, fish, powershell)

**RDAP support (RFC 7480-7485):**

- RDAP is the preferred data source — structured JSON over HTTPS, easier to parse than freeform WHOIS text
- Use IANA bootstrap files to discover RDAP endpoints for domains, IPs, and ASNs
- Prefer unauthenticated RDAP endpoints — if an endpoint requires OAuth or returns 401/403, skip it and fall back to WHOIS
- Query strategy: RDAP first → WHOIS fallback → error
- No OAuth/token storage for RDAP endpoints — the service only uses publicly accessible RDAP data

**Standardized data model (WHAT must be captured):**

Both RDAP and WHOIS responses must be normalized into a unified structure. The API response and database storage use the same fields regardless of which protocol returned the data.

Required fields for all query types:
- Query string, query type (domain/ipv4/ipv6/asn), data source (rdap/whois)
- Registrant: name, org, email, country
- Registrar name
- Dates: created, updated, expiry
- Nameservers (list), status codes (list)
- Raw response preserved (WHOIS text and/or RDAP JSON)
- Timestamps: first_seen, last_seen, last_updated

Additional fields for IP/ASN queries:
- Network: name, CIDR range, allocation type
- ASN: number, name
- RIR (ARIN, RIPE, APNIC, LACNIC, AFRINIC)

Field-level parsing rules and RDAP-to-WHOIS mappings are implementation details defined in src/whois/.

**Non-goals:**

- This service does NOT register or modify domain records
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
- Owner/registrant search — `GET /whois/search?owner=...` (web) + `GET /api/v1/whois/search?owner=...` (API); searches local history then optional external provider
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
- **whois_records**: id, query, query_type, source (`rdap`|`whois`), registrant_name, registrant_org, registrant_email, registrant_country, registrar, created_date, updated_date, expiry_date, nameservers (JSON array), status (JSON array), whois_server, rdap_server, raw_whois (full text, nullable), raw_rdap (JSON, nullable), network_name, network_range, network_type, asn_number, asn_name, rir, first_seen, last_seen, last_updated — permanent record; upserted (last_seen + raw updated) on every successful lookup; indexed on all registrant fields + expiry_date + network_range + asn_number; never auto-deleted (operators can configure max_age for pruning old stale records; default: keep forever); forms the free, open, self-hosted WHOIS/RDAP dataset

**Sensitivity classification:**

| Data | Sensitivity | Notes |
|------|-------------|-------|
| server.token (server.yml) | HIGH | Operator secret; SHA-256 compared; never logged raw |
| api_token hashes (DB) | HIGH | Stored as SHA-256 only; prefix for identification |
| WHOIS/RDAP results (in-memory cache) | LOW | Publicly available data; no PII beyond what WHOIS/RDAP exposes |
| whois_records (persistent DB) | LOW | Publicly available data aggregated from upstream RDAP/WHOIS; intended to be an open dataset |
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

**External services (upstream RDAP/WHOIS servers):**

| Server | Trust level | Failure mode |
|--------|-------------|-------------|
| RDAP bootstrap (IANA JSON files) | Trusted; fetched weekly via scheduler | Retain existing bootstrap on failure; log warning |
| RDAP endpoints (RIRs, TLD registries) | Prefer unauthenticated; accept results as-is | Fall back to WHOIS on RDAP failure or auth-required response |
| whois.iana.org (root) | Accept results as-is; no authentication | Return cached data if available; log error and return degraded response |
| ARIN, RIPE, APNIC, LACNIC, AFRINIC (RIRs) | Accept results as-is | Same as above |
| TLD-specific servers (queried by IANA referral) | Accept results as-is | Return raw response; parse best-effort |
| MaxMind GeoLite2 CDN (weekly update) | Trusted source; checksum verified | Retain existing DB on download failure; log warning |
| GitHub Releases (self-update) | SHA-256 verified before replacing binary | Abort update on checksum mismatch; log error |
| SecurityTrails / WHOXY / ViewDNS (reverse WHOIS) | User-supplied key forwarded per-request; server never stores user keys | Return local-only results on provider error; log warning |
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
- **Upstream RDAP/WHOIS results accepted without cryptographic verification**: Neither RDAP nor WHOIS protocols have signing mechanisms. Results are proxied as-is; cache invalidation on TTL expiry is the integrity mechanism. RDAP is preferred because it returns structured JSON (easier to parse reliably), not because it is more trustworthy.
- **Port chosen randomly (64000–64999) on first run**: Avoids well-known port conflicts; not a security measure. Operators behind a reverse proxy map to port 80 inside the container.
- **Parameterized queries always; no raw SQL string building**: Enforced in all database access. Violation of this rule is a bug.
- **Argon2id for backup encryption key derivation**: bcrypt and PBKDF2 are explicitly forbidden. Argon2id (winner of the Password Hashing Competition) is required.
- **Persistent WHOIS record database is the primary dataset**: Every successful lookup is stored permanently. The external provider is a seeding mechanism only — results from it trigger real WHOIS lookups that populate the local database. The database is the asset; the provider is optional bootstrap fuel.
- **Reverse WHOIS API keys never stored server-side from requests**: User-supplied keys sent via `X-Provider-Key` / `X-Provider-Name` request headers are used only for that request and immediately discarded. Only operator-configured keys (server.yml) and user-local keys (CLI cli.yml, browser localStorage) are persisted — and only by the party who owns that storage.
- **Owner search rate-limited same as read endpoints**: No special exemption; the feature should not be abused to enumerate the registrant dataset at scale.
- **External provider seeding is async and best-effort**: When a provider returns domain names for an owner search, those domains are queued for background WHOIS lookup and DB insertion. The API response returns immediately with local results; seeded results appear in subsequent searches.
