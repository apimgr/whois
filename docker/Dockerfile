# Multi-stage Dockerfile for caswhois
# Build stage: casjaysdev/go:latest (AI.md PART 26)
# Runtime stage: alpine:latest

ARG VERSION=dev
ARG BUILD_DATE=unknown
ARG COMMIT_ID=unknown

# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM casjaysdev/go:latest AS builder

# Install build dependencies
RUN apk add --no-cache git bash

# Set working directory
WORKDIR /build

# Copy go.mod and go.sum first (better caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY src/ ./src/

# Build arguments for version info (set via docker build --build-arg)
# TARGETARCH is automatically set by docker buildx (amd64 or arm64)
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT_ID=unknown
ARG BUILD_DATE=unknown
ARG OFFICIAL_SITE=

# Build the binary (multi-arch via TARGETARCH per AI.md PART 26)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags="-s -w \
      -X 'main.Version=${VERSION}' \
      -X 'main.CommitID=${COMMIT_ID}' \
      -X 'main.BuildDate=${BUILD_DATE}' \
      -X 'main.OfficialSite=${OFFICIAL_SITE}'" \
    -o caswhois \
    ./src

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM alpine:latest

# Install runtime dependencies
# git: version control (update command)
# curl: HTTP client (health checks, downloads)
# bash: shell scripting (entrypoint.sh)
# tini: init system (proper signal handling)
# tor: Tor hidden service support (auto-enabled if Tor binary found)
RUN apk add --no-cache \
    git \
    curl \
    bash \
    tini \
    tor \
    ca-certificates \
    tzdata

# Create non-root user
RUN addgroup -S caswhois && adduser -S caswhois -G caswhois

# Create directories per AI.md PART 4 container paths.
# /config/caswhois — server.yml and runtime config
# /data/caswhois   — application data
# /data/log/caswhois — log files (access.log, server.log, error.log, audit.log)
# /data/backups/caswhois — encrypted backup archives
# /data/db/sqlite  — SQLite database directory
RUN mkdir -p \
      /config/caswhois \
      /data/caswhois \
      /data/log/caswhois \
      /data/backups/caswhois \
      /data/db/sqlite && \
    chown -R caswhois:caswhois /config /data

# Copy binary from builder
COPY --from=builder /build/caswhois /usr/local/bin/caswhois

# Copy entrypoint script
COPY docker/rootfs/usr/local/bin/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# No LABEL blocks — all OCI image metadata is applied as annotations at build
# time via `docker buildx build --annotation` / the docker.yml workflow (AI.md PART 26).

# Set volumes (logs and backups live inside /data per AI.md PART 4).
VOLUME ["/config", "/data"]

# Set default timezone (override with TZ env var)
ENV TZ=America/New_York

# Default internal port (override with PORT env var)
ENV PORT=80

# Expose the configured HTTP port (AI.md PART 26).
EXPOSE 80

# Container health check (AI.md PART 26: --status exit code 0=healthy, 1=unhealthy).
HEALTHCHECK --start-period=10m --interval=5m --timeout=15s --retries=3 \
    CMD /usr/local/bin/caswhois --status || exit 1

# Use caswhois user
USER caswhois

# Use tini as init (proper signal handling)
# STOPSIGNAL: SIGRTMIN+3 (graceful shutdown)
STOPSIGNAL SIGRTMIN+3

# Entrypoint: tini manages signals
ENTRYPOINT ["tini", "-p", "SIGTERM", "--", "/usr/local/bin/entrypoint.sh"]

# Default command: run the server (default behavior with no flags). Mode defaults
# to production; override at runtime with `--mode development` (AI.md PART 6).
CMD []
