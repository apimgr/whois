#!/usr/bin/env bash
# shellcheck shell=bash
# @@License          :  WTFPL
# @@Description      :  Run the on-demand Chromium end-to-end suite.
# @@Resource         :  AI.md PART 28

set -eo pipefail

PROJECT_DIR="$(git rev-parse --show-toplevel)"
PROJECT_NAME="$(sed -n 's/^project_name:[[:space:]]*//p' "$PROJECT_DIR/IDEA.md" | head -n1 | tr -d '[:space:]')"
PROJECT_ORG="$(sed -n 's/^project_org:[[:space:]]*//p' "$PROJECT_DIR/IDEA.md" | head -n1 | tr -d '[:space:]')"
INTERNAL_NAME="$(sed -n 's/^internal_name:[[:space:]]*//p' "$PROJECT_DIR/IDEA.md" | head -n1 | tr -d '[:space:]')"
RUN_ID="${RANDOM}${RANDOM}"
CHROME_NAME="${PROJECT_NAME}-chromium-${RUN_ID}"
PORT="${E2E_PORT:-$((64000 + RANDOM % 1000))}"
TEMP_ROOT="${TMPDIR:-/tmp}/${PROJECT_ORG}"
ARTIFACT_DIR=""
DOCKER_MEM="${DOCKER_MEM:-4g}"
DOCKER_CPUS="${DOCKER_CPUS:-2}"
DOCKER_CPU_SHARES="${DOCKER_CPU_SHARES:-256}"
DOCKER_TIMEOUT="${DOCKER_TIMEOUT:-3600}"

cleanup() {
    docker rm -f "$CHROME_NAME" >/dev/null 2>&1 || true
    if [ -n "$ARTIFACT_DIR" ] && [ "${KEEP_E2E_ARTIFACTS:-0}" != 1 ]; then
        rm -rf -- "$ARTIFACT_DIR"
    fi
}
trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker is required for the browser E2E suite" >&2
    exit 69
fi
if [ "$PORT" -lt 64000 ] || [ "$PORT" -gt 64999 ]; then
    echo "ERROR: E2E_PORT must be in the range 64000-64999" >&2
    exit 2
fi

mkdir -p "$TEMP_ROOT"
ARTIFACT_DIR="$(mktemp -d "$TEMP_ROOT/${INTERNAL_NAME}-e2e-XXXXXX")"
chmod 0700 "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR/config" "$ARTIFACT_DIR/data" "$ARTIFACT_DIR/log" "$ARTIFACT_DIR/artifacts"
chmod 0700 "$ARTIFACT_DIR/config" "$ARTIFACT_DIR/data" "$ARTIFACT_DIR/log" "$ARTIFACT_DIR/artifacts"

cd "$PROJECT_DIR"
echo "Building server and CLI binaries for E2E..."
make BINDIR="$ARTIFACT_DIR/binaries" RELDIR="$ARTIFACT_DIR/releases" PLATFORMS=linux/amd64 build

echo "Starting headless Chromium sidecar..."
timeout -k 30 "$DOCKER_TIMEOUT" docker run -d --rm --no-healthcheck --name "$CHROME_NAME" \
    --memory="$DOCKER_MEM" --cpus="$DOCKER_CPUS" --cpu-shares="$DOCKER_CPU_SHARES" \
    --network host --shm-size=1g \
    chromedp/headless-shell:latest >/dev/null

echo "Running SSR, no-JavaScript, and full-browser scenarios..."
# The single-quoted script is intentionally evaluated inside the Go container.
# shellcheck disable=SC2016
timeout -k 30 "$DOCKER_TIMEOUT" docker run --rm --no-healthcheck --network host --name "${PROJECT_NAME}-e2e-${RUN_ID}" \
    --memory="$DOCKER_MEM" --cpus="$DOCKER_CPUS" --cpu-shares="$DOCKER_CPU_SHARES" \
    -v "$PROJECT_DIR:/app" \
    -v "$ARTIFACT_DIR:/e2e" \
    -v "$ARTIFACT_DIR/binaries:/binaries:ro" \
    -v "$HOME/go/pkg/mod:/usr/local/share/go/pkg/mod" \
    -v "$HOME/.cache/go-build/${PROJECT_NAME}:/usr/local/share/go/cache" \
    -w /app -e CGO_ENABLED=0 -e GOFLAGS='-buildvcs=false -mod=mod' \
    -e INTERNAL_NAME="$INTERNAL_NAME" \
    -e E2E_CONFIG_DIR=/e2e/config \
    -e E2E_PORT="$PORT" -e E2E_CDP_URL=http://127.0.0.1:9222 \
    -e E2E_ARTIFACT_DIR=/e2e/artifacts \
    casjaysdev/go:latest bash -euc '
        SERVER="/binaries/$INTERNAL_NAME"
        printf "%s\n" "server:" "  geoip:" "    enabled: false" "  scheduler:" "    tasks:" "      update_check:" "        enabled: false" "      geoip_update:" "        enabled: false" "      blocklist_update:" "        enabled: false" "      cve_update:" "        enabled: false" > /e2e/config/server.yml
        if ! id "$INTERNAL_NAME" >/dev/null 2>&1; then
            useradd --system --no-create-home --shell /usr/sbin/nologin "$INTERNAL_NAME"
        fi
        chown -R "$INTERNAL_NAME:$INTERNAL_NAME" /e2e/config /e2e/data /e2e/log
        "$SERVER" --mode development --debug --config /e2e/config --data /e2e/data --log /e2e/log \
            --address 127.0.0.1 --port "$E2E_PORT" >/e2e/server.log 2>&1 &
        SERVER_PID=$!
        cleanup_server() { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
        trap cleanup_server EXIT INT TERM
        BASE_URL="http://127.0.0.1:$E2E_PORT"
        ready=0
        for _ in $(seq 1 60); do
            if curl -q -LSsf --max-time 2 "$BASE_URL/server/healthz" >/dev/null 2>&1; then ready=1; break; fi
            sleep 1
        done
        if [ "$ready" -ne 1 ]; then
            sed -E "s/adm_[A-Za-z0-9]{32,}/[REDACTED]/g" /e2e/server.log >&2
            echo "ERROR: E2E server did not become healthy" >&2
            exit 1
        fi
        if E2E_BASE_URL="$BASE_URL" go test -tags e2e -count=1 -v ./tests/e2e/... >/e2e/e2e-test.log 2>&1; then
            cat /e2e/e2e-test.log
        else
            status=$?
            sed -E "s/adm_[A-Za-z0-9]{32,}/[REDACTED]/g" /e2e/e2e-test.log >&2
            exit "$status"
        fi
    '
