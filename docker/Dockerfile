# Multi-stage Dockerfile for caswhois
# Build stage: golang:alpine
# Runtime stage: alpine:latest

# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /build

# Copy go.mod and go.sum first (better caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY src/ ./src/

# Build arguments for version info (set via docker build --build-arg)
ARG VERSION=dev
ARG COMMIT_ID=unknown
ARG BUILD_DATE=unknown
ARG OFFICIAL_SITE=https://github.com/casapps/caswhois

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
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

# Create directories
RUN mkdir -p /config /data /logs && \
    chown -R caswhois:caswhois /config /data /logs

# Copy binary from builder
COPY --from=builder /build/caswhois /usr/local/bin/caswhois

# Copy entrypoint script
COPY docker/file_system/usr/local/bin/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set volumes
VOLUME ["/config", "/data", "/logs"]

# Set default timezone (override with TZ env var)
ENV TZ=America/New_York

# Default internal port (override with PORT env var)
ENV PORT=80

# Use caswhois user
USER caswhois

# Use tini as init (proper signal handling)
# STOPSIGNAL: SIGRTMIN+3 (graceful shutdown)
STOPSIGNAL SIGRTMIN+3

# Entrypoint: tini manages signals
ENTRYPOINT ["tini", "-p", "SIGTERM", "--", "/usr/local/bin/entrypoint.sh"]

# Default command: run server
CMD ["--mode", "production"]
