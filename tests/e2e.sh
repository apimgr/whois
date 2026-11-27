#!/usr/bin/env bash
# shellcheck shell=bash
# @@License          :  WTFPL
# @@Description      :  Run the on-demand Chromium end-to-end suite.
# @@Resource         :  AI.md PART 28

set -eo pipefail

PROJECT_DIR="$(git rev-parse --show-toplevel)"
PROJECT_NAME="$(awk -F: '/^project_name:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$PROJECT_DIR/IDEA.md")"
PROJECT_ORG="$(awk -F: '/^project_org:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$PROJECT_DIR/IDEA.md")"
INTERNAL_NAME="$(awk -F: '/^internal_name:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$PROJECT_DIR/IDEA.md")"
RUN_ID="${RANDOM}${RANDOM}"
CHROME_NAME="${PROJECT_NAME}-chromium-${RUN_ID}"
RUNNER_NAME="${PROJECT_NAME}-e2e-${RUN_ID}"
NETWORK_NAME="${PROJECT_NAME}-e2e-net-${RUN_ID}"
PORT="${E2E_PORT:-$((64000 + RANDOM % 1000))}"
TEMP_ROOT="${TMPDIR:-/tmp}/${PROJECT_ORG}"
ARTIFACT_DIR=""
DOCKER_MEM="${DOCKER_MEM:-4g}"
DOCKER_CPUS="${DOCKER_CPUS:-2}"
DOCKER_CPU_SHARES="${DOCKER_CPU_SHARES:-256}"
DOCKER_TIMEOUT="${DOCKER_TIMEOUT:-3600}"

cleanup() {
  if docker container inspect "$RUNNER_NAME" >/dev/null 2>&1; then
    docker logs "$RUNNER_NAME" 2>&1 | sed -E 's/adm_[A-Za-z0-9]{32,}/[REDACTED]/g; s/security_id=[^ &"]+/security_id=[REDACTED]/g' >"$ARTIFACT_DIR/docker-runner.log" || true
    docker rm -f "$RUNNER_NAME" >/dev/null 2>&1 || true
  fi
  docker rm -f "$CHROME_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
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
timeout -k 30 "$DOCKER_TIMEOUT" docker network create --internal "$NETWORK_NAME" >/dev/null
NETWORK_GATEWAY="$(docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "$NETWORK_NAME")"
NETWORK_PREFIX="${NETWORK_GATEWAY%.*}"
CHROME_IP="$NETWORK_PREFIX.2"
RUNNER_IP="$NETWORK_PREFIX.3"
timeout -k 30 "$DOCKER_TIMEOUT" docker run -d --rm --no-healthcheck --name "$CHROME_NAME" \
  --memory="$DOCKER_MEM" --cpus="$DOCKER_CPUS" --cpu-shares="$DOCKER_CPU_SHARES" \
  --network "$NETWORK_NAME" --ip "$CHROME_IP" --shm-size=1g \
  chromedp/headless-shell:latest --ignore-certificate-errors >/dev/null

echo "Running SSR, no-JavaScript, and full-browser scenarios..."
# The single-quoted script is intentionally evaluated inside the Go container.
# shellcheck disable=SC2016
if timeout -k 30 "$DOCKER_TIMEOUT" docker run --no-healthcheck --network "$NETWORK_NAME" --name "$RUNNER_NAME" \
  --ip "$RUNNER_IP" \
  --memory="$DOCKER_MEM" --cpus="$DOCKER_CPUS" --cpu-shares="$DOCKER_CPU_SHARES" \
  -v "$PROJECT_DIR:/app" \
  -v "$ARTIFACT_DIR:/e2e" \
  -v "$ARTIFACT_DIR/binaries:/binaries:ro" \
  -v "$HOME/go/pkg/mod:/usr/local/share/go/pkg/mod" \
  -v "$HOME/.cache/go-build/${PROJECT_NAME}:/usr/local/share/go/cache" \
  -w /app -e CGO_ENABLED=0 -e GOFLAGS='-buildvcs=false -mod=mod' \
  -e INTERNAL_NAME="$INTERNAL_NAME" \
  -e E2E_FQDN="$RUNNER_IP" \
  -e DATABASE_DIR=/e2e/data/db/sqlite \
  -e E2E_CONFIG_DIR=/e2e/config \
  -e E2E_TLS_CA="/e2e/config/ssl/local/$RUNNER_IP/cert.pem" \
  -e E2E_PORT="$PORT" -e E2E_CDP_URL="http://$CHROME_IP:9222" \
  -e E2E_ARTIFACT_DIR=/e2e/artifacts \
  -e E2E_RUN="${E2E_RUN:-}" -e E2E_PAGE="${E2E_PAGE:-}" \
  casjaysdev/go:latest bash -euc '
        printf "%s\n" "container-started" > /e2e/runner-stage.log
        SERVER="/binaries/$INTERNAL_NAME"
        printf "%s\n" "server:" "  config_dir: /e2e/config" "  data_dir: /e2e/data" "  log_dir: /e2e/log" "  fqdn: $E2E_FQDN" "  port: $E2E_PORT" "  database:" "    dir: /e2e/data/db/sqlite" "  geoip:" "    enabled: false" "  ssl:" "    enabled: true" "  rate_limit:" "    read:" "      requests: 10000" "      window: 60" "    write:" "      requests: 1000" "      window: 60" "    health:" "      requests: 1000" "      window: 60" "    strict:" "      requests: 100" "      window: 900" "    auth_failures:" "      requests: 100" "      window: 900" "    global_burst: 12000" > /e2e/config/server.yml
        printf "%s\n" "config-written" >> /e2e/runner-stage.log
        mkdir -p "/e2e/config/ssl/local/$E2E_FQDN"
        openssl req -x509 -newkey rsa:2048 -nodes -keyout "/e2e/config/ssl/local/$E2E_FQDN/key.pem" -out "/e2e/config/ssl/local/$E2E_FQDN/cert.pem" -days 2 -subj "/CN=$E2E_FQDN" -addext "basicConstraints=critical,CA:TRUE" -addext "subjectAltName=IP:$E2E_FQDN" >/dev/null 2>&1
        chmod 0600 "/e2e/config/ssl/local/$E2E_FQDN/key.pem"
        chmod 0644 "/e2e/config/ssl/local/$E2E_FQDN/cert.pem"
        if ! id "$INTERNAL_NAME" >/dev/null 2>&1; then
            useradd --system --no-create-home --shell /usr/sbin/nologin "$INTERNAL_NAME"
        fi
        mkdir -p /e2e/data/rdap
        cat > /e2e/data/rdap/dns.json <<RDAPJSON
{"services":[[["test"],["http://127.0.0.1:65001/"]]]}
RDAPJSON
        go build -buildvcs=false -o /e2e/rdap-fixture ./tests/e2e/fixtures/rdap
        /e2e/rdap-fixture >/e2e/rdap-fixture.log 2>&1 &
        RDAP_PID=$!
        SERVER_PID=""
        cleanup_server() {
            if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
            kill "$RDAP_PID" 2>/dev/null || true
            if [ -n "$SERVER_PID" ]; then wait "$SERVER_PID" 2>/dev/null || true; fi
            wait "$RDAP_PID" 2>/dev/null || true
        }
        trap cleanup_server EXIT INT TERM
        fixture_ready=0
        for _ in $(seq 1 30); do
            if curl -q -LSsf --max-time 1 http://127.0.0.1:65001/healthz >/dev/null 2>&1; then fixture_ready=1; break; fi
            sleep 1
        done
        if [ "$fixture_ready" -ne 1 ]; then
            sed -E "s/adm_[A-Za-z0-9]{32,}/[REDACTED]/g" /e2e/rdap-fixture.log >&2
            echo "ERROR: local RDAP fixture did not become healthy" >&2
            exit 1
        fi
        printf "%s\n" "service-account-ready" >> /e2e/runner-stage.log
        chown "$INTERNAL_NAME:$INTERNAL_NAME" /e2e
        chown -R "$INTERNAL_NAME:$INTERNAL_NAME" /e2e/config /e2e/data /e2e/log
        "$SERVER" --mode development --debug --config /e2e/config --data /e2e/data --log /e2e/log \
            --address 0.0.0.0 --port "$E2E_PORT" >/e2e/server.log 2>&1 &
        SERVER_PID=$!
        printf "%s\n" "server-launched" >> /e2e/runner-stage.log
        BASE_URL="https://$E2E_FQDN:$E2E_PORT"
        BROWSER_BASE_URL="$BASE_URL"
        ready=0
        for _ in $(seq 1 60); do
            if curl -q -k -LSsf --max-time 2 "$BASE_URL/server/healthz" >/dev/null 2>&1; then ready=1; break; fi
            sleep 1
        done
        if [ "$ready" -ne 1 ]; then
            curl -q -k -LSs --max-time 2 -H "Accept: application/json" "$BASE_URL/server/healthz" >&2 || true
            sed -E "s/adm_[A-Za-z0-9]{32,}/[REDACTED]/g; s/security_id=[^[:space:]]+/security_id=[REDACTED]/g" /e2e/server.log >&2
            echo "ERROR: E2E server did not become healthy" >&2
            exit 1
        fi
        printf "%s\n" "server-ready" >> /e2e/runner-stage.log
        go_test_args=(-tags e2e -count=1 -v)
        if [ -n "$E2E_RUN" ]; then go_test_args+=(-run "$E2E_RUN"); fi
        if E2E_BASE_URL="$BASE_URL" E2E_BROWSER_BASE_URL="$BROWSER_BASE_URL" SSL_CERT_FILE="$E2E_TLS_CA" go test "${go_test_args[@]}" ./tests/e2e/... >/e2e/e2e-test.log 2>&1; then
            printf "%s\n" "tests-passed" >> /e2e/runner-stage.log
            cat /e2e/e2e-test.log
        else
            status=$?
            printf "%s\n" "tests-failed-$status" >> /e2e/runner-stage.log
            sed -E "s/adm_[A-Za-z0-9]{32,}/[REDACTED]/g; s/security_id=[^[:space:]]+/security_id=[REDACTED]/g" /e2e/e2e-test.log >&2
            exit "$status"
        fi
    '; then
  docker inspect --format '{{json .State}}' "$RUNNER_NAME" >"$ARTIFACT_DIR/docker-runner-state.json"
  docker logs "$RUNNER_NAME" 2>&1 | sed -E 's/adm_[A-Za-z0-9]{32,}/[REDACTED]/g; s/security_id=[^ &"]+/security_id=[REDACTED]/g'
else
  runner_exit=$?
  docker inspect --format '{{json .State}}' "$RUNNER_NAME" >"$ARTIFACT_DIR/docker-runner-state.json" 2>/dev/null || true
  docker logs "$RUNNER_NAME" 2>&1 | sed -E 's/adm_[A-Za-z0-9]{32,}/[REDACTED]/g; s/security_id=[^ &"]+/security_id=[REDACTED]/g' >&2 || true
  exit "$runner_exit"
fi
