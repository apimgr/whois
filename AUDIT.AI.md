# Project Audit

Started: 2026-06-02

## Pass 6: Spec Compliance (PART 12, 13, 16)

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
