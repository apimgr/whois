# Project Audit

Started: 2026-06-02

## Pass 9: Spec Compliance (PART 15, additional)

All open violations resolved.

## Completed
- docker/Dockerfile: builder switched from `golang:alpine` to `casjaysdev/go:latest` (AI.md PART 26)
- docker/Dockerfile: HEALTHCHECK timing switched to `--start-period=10m --interval=5m --timeout=15s --retries=3` (AI.md PART 26)
- docker/Dockerfile: HEALTHCHECK command switched from `wget` to `/usr/local/bin/caswhois --status` (AI.md PART 26)
- docker/Dockerfile: build now consumes `ARG TARGETARCH` so `docker buildx --platform linux/amd64,linux/arm64` produces matching binaries (AI.md PART 26)
- docker/Dockerfile: mkdir -p now creates correct PART 4 container paths (/config/caswhois, /data/caswhois, /data/log/caswhois, /data/backups/caswhois, /data/db/sqlite)
- src/config/config.go: GetBackupDir() container path fixed from /data/backups → /data/backups/caswhois (AI.md PART 4)
- src/config/config.go: GetLogDir() added returning /data/log/caswhois in containers, {data_dir}/logs on native (AI.md PART 4)
- src/config/config.go: IsContainer() exported for use in main.go
- src/main.go: getDefaultConfigDir() now returns /config/caswhois in containers, /etc/casapps/caswhois as root, ~/.config/casapps/caswhois for users
- src/logger/: new package implementing all five required log files (PART 11): access.log (Apache Combined), server.log (logfmt), error.log (logfmt), audit.log (JSON), security.log (Fail2ban)
- src/server/server.go: logger field wired; LogRotateHook connected; SIGUSR1 reopens log files
- src/server/middleware.go: LoggingMiddleware writes Apache Combined Log Format to access.log; responseWriter captures bytesWritten
- .claude/rules/docker-rules.md: corrected to match actual AI.md PART 26
- src/config/config.go: RateLimitEnabled/Requests/Window replaced with nested RateLimitConfig{Enabled, Read, Write, Health, GlobalBurst} per AI.md PART 12
- src/config/config.go: ContactConfig, ContactRoleConfig, ContactWebhooksConfig added for PART 12 contact routing (admin/security/general roles with email + webhooks)
- src/config/config.go: LoadServerConfig now writes default server.yml on first run (PART 12 first-run experience)
- src/server/health.go: PendingRestart bool and RestartReason []string added to HealthResponse (PART 13 canonical struct)
- src/server/health.go: FeaturesInfo field order fixed — Tor and GeoIP first (non-negotiable), then app-specific
- src/server/health.go: getOverallStatus(checks ChecksInfo) implemented — derives "unhealthy"/"degraded"/"healthy" from component checks (PART 13)
- src/server/handlers_test.go: newTestServer wired with real SQLite db and scheduler so health checks return accurate status in tests
- src/server/content_pages.go: /about and /docs templates now source name, tagline, description, API version, and rate limits from branding config (IDEA.md via server.yml) per PART 16
- src/server/server.go: metrics token comparison switched from plain != to subtle.ConstantTimeCompare (PART 11 constant-time comparison requirement)
- src/server/server.go: handleMetrics comment corrected from PART 21 to PART 20
- src/status.go: handleMaintenance now handles `mode` (change production/development mode) and `setup` (reset config to defaults, requires root) subcommands per PART 8 spec
- src/main.go: --maintenance flag description and help text updated to list all six subcommands per PART 8
- Makefile: removed dead src/agent build blocks from build, local, and dev targets (PART 25 — spec defines server + client only, no agent binary)

## Verified Compliant (no violations found)
- PART 9: Error codes (BAD_REQUEST, VALIDATION_FAILED, UNAUTHORIZED, FORBIDDEN, NOT_FOUND, METHOD_NOT_ALLOWED, CONFLICT, RATE_LIMITED, SERVER_ERROR, MAINTENANCE) all present
- PART 10: Database schema tables (config, config_meta, rate_limits, audit_log, scheduler_tasks, scheduler_history, backups, api_tokens) all present with correct indexes
- PART 14: All required API routes registered (whois, domain, ip, asn, validate, bulk, whois-servers, stats, schedulers, backups); rate limiting applied globally via middleware chain
- PART 25: Makefile has exactly 7 required targets (build, local, release, docker, test, dev, clean); uses casjaysdev/go:latest; enforces 100% test coverage
- PART 32: CLI client (caswhois-cli) in src/client/ with --server, --token, --lang, --color, --update, --debug, --version flags
- src/email/email.go: PART reference corrected from PART 18 to PART 17 (PART 18 is Scheduler)
- src/config/config.go: GeoIPAllowCountries field added (PART 19 — allowlist mode takes precedence over deny list)
- src/config/config.go: PART comments corrected (GeoIP PART 19, Backup/Compliance PART 21, Metrics PART 20)
- src/service/daemon.go: OpenRC detection added (/sbin/openrc-run binary + RC_SVCNAME env) before SysVinit check (PART 24)
- src/service/install_unix.go: installOpenRC(), uninstallOpenRC(), disable case "openrc" added (PART 24 — Alpine/Gentoo/Devuan)
- src/service/manager.go: isSystemServiceInstalled() now checks /etc/init.d/{name} for OpenRC (PART 24)
- src/ssl/ssl.go: DNS-01 challenge now wired via lego factory (legodns.NewDNSChallengeProviderByName) — was a stub error (PART 15)
- go.mod/go.sum: updated (go mod tidy) for lego DNS provider dependencies

## Verified Compliant (PART 15, 22, 31)
- PART 15: SSL — HTTP-01, TLS-ALPN-01, DNS-01 all wired via lego; auto-renewal at 30d before expiry; min TLS 1.2
- PART 22: Update command — --update check/yes/branch implemented with SHA-256 verification; --maintenance update is alias for --update yes
- PART 31: Tor hidden service — implemented via cretz/bine; v3 onion (ed25519); ADD_ONION; CGO_ENABLED=0 compatible

## Verified Compliant (PART 17, 19, 21 specifics)
- PART 17: SMTP auto-detection is TCP handshake to 127.0.0.1/172.17.0.1/gateway/fqdn on ports 25,465,587 — spec-compliant; no binary (sendmail/msmtp) detection required
- PART 19: City MMDB uses dbip-city-ipv4.mmdb — correct per spec; spec lists IPv4-only city URL
- PART 21: BackupMaxBackups default of 1 is correct per spec (spec table shows Default: 1)
