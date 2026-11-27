#!/usr/bin/env bash
# shellcheck disable=SC1078,SC1079,SC1083,SC2102
# @@License          :  WTFPL
# @@Description      :  Run Docker binary and HTTP integration checks.
# @@Resource         :  AI.md PART 28

set -euo pipefail

PROJECT_DIR="$(git rev-parse --show-toplevel)"
PROJECT_NAME="$(sed -n 's/^project_name:[[:space:]]*//p' "$PROJECT_DIR/IDEA.md" | head -n1 | tr -d '[:space:]')"
PROJECT_ORG="$(sed -n 's/^project_org:[[:space:]]*//p' "$PROJECT_DIR/IDEA.md" | head -n1 | tr -d '[:space:]')"
INTERNAL_NAME="$(sed -n 's/^internal_name:[[:space:]]*//p' "$PROJECT_DIR/IDEA.md" | head -n1 | tr -d '[:space:]')"
CONTAINER_NAME="${PROJECT_NAME}-$(date +%s%N | sha256sum | cut -c1-8)"

image_check() {
    local image_ref port elapsed tor_status outbound
    image_ref="${1:?Usage: tests/docker.sh --image-check IMAGE}"
    CONTAINER_NAME="${PROJECT_NAME}-image-check-$(date +%s%N | sha256sum | cut -c1-8)"
    docker run --rm --entrypoint sh "$image_ref" -c 'for c in bash curl tor i2pd tini; do command -v "$c" || exit 1; done'
    docker run -d --name "$CONTAINER_NAME" -p 127.0.0.1::80 "$image_ref" >/dev/null
    port="$(docker port "$CONTAINER_NAME" 80/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | head -n1)"
    if [ -z "$port" ]; then
        echo "ERROR: unable to determine mapped health port for $image_ref" >&2
        return 1
    fi

    elapsed=0
    tor_status=""
    while [ "$elapsed" -lt "${TOR_BOOTSTRAP_TIMEOUT:-180}" ]; do
        tor_status="$(curl -q -fsS --connect-timeout 2 --max-time 5 "http://127.0.0.1:$port/server/healthz" 2>/dev/null | sed -n '/"tor": {/,/}/p' | sed -n 's/.*"status":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1 || true)"
        if [ "$tor_status" = healthy ]; then
            echo "PASS image contract and Tor health: $image_ref"
            return 0
        fi
        if [ "$tor_status" = error ]; then
            echo "ERROR: Tor reported error in $image_ref" >&2
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    if [ "${REQUIRE_OVERLAY:-0}" = 1 ]; then
        echo "ERROR: Tor did not become healthy within ${TOR_BOOTSTRAP_TIMEOUT:-180}s (status: ${tor_status:-unknown})" >&2
        return 1
    fi
    outbound=0
    if command -v curl >/dev/null 2>&1 && curl -q -fsS --connect-timeout 5 --max-time 10 https://check.torproject.org/ >/dev/null 2>&1; then
        outbound=1
    fi
    if [ "$outbound" -eq 0 ] && { [ "$tor_status" = starting ] || [ "$tor_status" = unavailable ]; }; then
        echo "SKIP: no outbound network" >&2
        return 0
    fi
    echo "ERROR: Tor did not become healthy within ${TOR_BOOTSTRAP_TIMEOUT:-180}s (status: ${tor_status:-unknown})" >&2
    return 1
}

if [ "${1:-}" = --image-check ]; then
    trap 'docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true' EXIT INT TERM
    image_check "${2:-}"
    exit $?
fi

DOCKER_MEM="${DOCKER_MEM:-4g}"
DOCKER_CPUS="${DOCKER_CPUS:-2}"
DOCKER_CPU_SHARES="${DOCKER_CPU_SHARES:-256}"
DOCKER_TIMEOUT="${DOCKER_TIMEOUT:-3600}"
ARTIFACT_DIR=""

cleanup() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    if [ -n "$ARTIFACT_DIR" ]; then
        rm -rf -- "$ARTIFACT_DIR"
    fi
}
trap cleanup EXIT INT TERM

TEMP_PARENT="${TMPDIR:-/tmp}/$PROJECT_ORG"
mkdir -p "$TEMP_PARENT"
ARTIFACT_DIR="$(mktemp -d "$TEMP_PARENT/$INTERNAL_NAME-XXXXXX")"
chmod 0700 "$ARTIFACT_DIR"
BIN_DIR="$ARTIFACT_DIR/binaries"
RELEASE_DIR="$ARTIFACT_DIR/releases"
mkdir -p "$BIN_DIR" "$RELEASE_DIR"

cd "$PROJECT_DIR"
echo "Building server and CLI binaries in Docker..."
make build BINDIR="$BIN_DIR" RELDIR="$RELEASE_DIR"

if [ ! -x "$BIN_DIR/$INTERNAL_NAME" ]; then
    echo "ERROR: server binary missing: $BIN_DIR/$INTERNAL_NAME" >&2
    exit 1
fi

timeout -k 30 "$DOCKER_TIMEOUT" docker run --rm --no-healthcheck --name "$CONTAINER_NAME" \
    --memory="$DOCKER_MEM" --cpus="$DOCKER_CPUS" --cpu-shares="$DOCKER_CPU_SHARES" \
    -v "$BIN_DIR:/binaries:ro" \
    -e PROJECT_NAME="$PROJECT_NAME" \
    -e PROJECT_ORG="$PROJECT_ORG" \
    -e INTERNAL_NAME="$INTERNAL_NAME" \
    alpine:latest sh -eu -c "$(cat <<'CONTAINER_SCRIPT'
        apk add --no-cache curl bash file jq tor i2pd tzdata ca-certificates >/dev/null
        mkdir -p "/tmp/$PROJECT_ORG"
        TEST_ROOT=$(mktemp -d "/tmp/$PROJECT_ORG/$INTERNAL_NAME-XXXXXX")
        chmod 0700 "$TEST_ROOT"
        CONFIG_DIR="$TEST_ROOT/config"
        DATA_DIR="$TEST_ROOT/data"
        LOG_DIR="$TEST_ROOT/log"
        mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
        chmod 0700 "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
        adduser -D -H -s /sbin/nologin "$INTERNAL_NAME"
        chown -R "$INTERNAL_NAME:$INTERNAL_NAME" "$TEST_ROOT"
        SERVER="/binaries/$INTERNAL_NAME"
        CLI="/binaries/$INTERNAL_NAME-cli"
        PORT=64580
        BASE="http://127.0.0.1:$PORT"

        "$SERVER" --version
        "$SERVER" --help | grep -F -- "$PROJECT_NAME" >/dev/null
        file "$SERVER"
        if [ -x "$CLI" ]; then
            "$CLI" --version
            "$CLI" --help >/dev/null
        fi

        cp "$SERVER" "$TEST_ROOT/renamed-server"
        chmod 0700 "$TEST_ROOT/renamed-server"
        "$TEST_ROOT/renamed-server" --help | grep -F renamed-server >/dev/null
        if [ -x "$CLI" ]; then
            cp "$CLI" "$TEST_ROOT/renamed-cli"
            chmod 0700 "$TEST_ROOT/renamed-cli"
            "$TEST_ROOT/renamed-cli" --help | grep -F renamed-cli >/dev/null
        fi

        "$SERVER" --mode development --config "$CONFIG_DIR" --data "$DATA_DIR" --log "$LOG_DIR" --address 127.0.0.1 --port "$PORT" >"$TEST_ROOT/server.log" 2>&1 &
        SERVER_PID=$!
        trap "kill $SERVER_PID 2>/dev/null || true; wait $SERVER_PID 2>/dev/null || true; rm -rf \"$TEST_ROOT\"" EXIT INT TERM

        ready=0
        for _ in $(seq 1 60); do
            if curl -q -LSsf "$BASE/server/healthz" >/dev/null 2>&1; then
                ready=1
                break
            fi
            sleep 1
        done
        if [ "$ready" -ne 1 ]; then
            sed -E 's/adm_[A-Za-z0-9-]{32,}/[REDACTED]/g' "$TEST_ROOT/server.log" >&2
            echo "ERROR: server did not become healthy" >&2
            exit 1
        fi

        FAILURES=0
        check() {
            label=$1
            shift
            if "$@" >/dev/null; then
                printf "PASS %s\n" "$label"
            else
                printf "FAIL %s\n" "$label" >&2
                FAILURES=$((FAILURES + 1))
            fi
        }

        curl_checked() {
            command curl -q -LSsf --connect-timeout 5 --max-time 10 "$@"
        }

        http_status() {
            command curl -q -LSs --connect-timeout 5 --max-time 10 -o /dev/null -w "%{http_code}" "$@"
        }

        api_health_json() {
            curl -q -LSsf -H 'Accept: application/json' "$BASE/api/v1/server/healthz" | jq -e '.status == "healthy" or .status == "degraded"' >/dev/null
        }

        api_health_text() {
            curl -q -LSsf -H 'Accept: text/plain' "$BASE/api/v1/server/healthz" | grep 'status: ' >/dev/null
        }

        api_html_prefers_json() {
            curl -q -LSsf -H 'Accept: text/html' "$BASE/api/v1/server/healthz" | jq -e '.status == "healthy" or .status == "degraded"' >/dev/null
        }

        homepage_html() {
            curl -q -LSsf --connect-timeout 5 --max-time 10 -H 'Accept: text/html' "$BASE/" | grep -i '<html' >/dev/null
        }

        browser_homepage_html() {
            curl -q -LSsf -A 'Mozilla/5.0' "$BASE/" | grep -i '<html' >/dev/null
        }

        cli_homepage_text() {
            curl -q -LSsf "$BASE/" | grep -i WHOIS >/dev/null
        }

        whois_page_html() {
            curl -q -LSsf --connect-timeout 5 --max-time 10 -H 'Accept: text/html' "$BASE/whois" | grep -i '<html' >/dev/null
        }

        operator_bulk() {
            curl -q -LSsf --connect-timeout 5 --max-time 10 -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"queries":["!!!"]}' "$BASE/api/v1/whois/bulk" >/dev/null
        }

        check "health JSON" curl_checked -H "Accept: application/json" "$BASE/api/v1/server/healthz"
        check "health text" curl_checked -H "Accept: text/plain" "$BASE/server/healthz"
        check "API health .txt" curl_checked "$BASE/api/v1/server/healthz.txt"
        check "API health JSON Accept" api_health_json
        check "API health text Accept" api_health_text
        check "API HTML Accept defaults to JSON" api_html_prefers_json
        check "homepage HTML" homepage_html
        check "browser user agent receives HTML" browser_homepage_html
        check "curl user agent receives formatted text" cli_homepage_text
        check "WHOIS form HTML" whois_page_html
        check "WHOIS validation" curl_checked "$BASE/api/v1/whois/validate/example.com"
        check "WHOIS owner search" curl_checked "$BASE/api/v1/whois/search?owner=example"
        check "WHOIS server list" curl_checked "$BASE/api/v1/whois-servers"
        check "server stats" curl_checked "$BASE/api/v1/server/stats"
        check "about page" curl_checked -H "Accept: text/html" "$BASE/server/about"
        check "docs page" curl_checked -H "Accept: text/html" "$BASE/server/docs"
        check "privacy page" curl_checked -H "Accept: text/html" "$BASE/server/privacy"
        check "security policy" curl_checked -H "Accept: text/html" "$BASE/server/security/policy"
        check "security.txt" curl_checked "$BASE/.well-known/security.txt"
        check "robots.txt" curl_checked "$BASE/robots.txt"
        check "sitemap.xml" curl_checked "$BASE/sitemap.xml"
        check "manifest.json" curl_checked "$BASE/manifest.json"
        check "service worker" curl_checked "$BASE/sw.js"

        TOKEN=$(awk '/^server:/{inside=1;next} inside && /^    token:/{sub(/^    token:[[:space:]]*/, ""); print; exit}' "$CONFIG_DIR/secrets.yml" | tr -d "\047\042")
        if [ -z "$TOKEN" ]; then
            find "$CONFIG_DIR" -maxdepth 2 -type f -print >&2
            awk '/token:/{print FNR ": token: [REDACTED]"}' "$CONFIG_DIR/secrets.yml" >&2 || true
            echo "ERROR: server.token was not generated in secrets.yml" >&2
            exit 1
        fi
        check "operator-only bulk route rejects anonymous access" test "$(http_status -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/v1/whois/bulk")" = 401
        check "operator-only bulk route rejects invalid token" test "$(http_status -X POST -H 'Authorization: Bearer invalid' -H 'Content-Type: application/json' -d '{}' "$BASE/api/v1/whois/bulk")" = 401
        check "operator-only scheduler route accepts operator token" curl_checked -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/server/schedulers"
        check "operator-only bulk route accepts operator token" operator_bulk
        check "metrics endpoint" curl_checked "$BASE/metrics"
        if [ "$FAILURES" -ne 0 ]; then
            echo "ERROR: $FAILURES Docker integration check(s) failed" >&2
            exit 1
        fi
        echo "PASS Docker binary integration tests"
CONTAINER_SCRIPT
)"
