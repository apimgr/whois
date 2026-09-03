#!/bin/bash
# Incus full OS integration tests for caswhois — 100% endpoint/route coverage
# Tests in a real Ubuntu environment (preferred over Docker)
# See AI.md PART 28 for testing rules

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "========================================"
echo "caswhois Incus Integration Tests"
echo "========================================"
echo "Project root: $PROJECT_ROOT"
echo

# Check for incus
if ! command -v incus &>/dev/null; then
    echo -e "${RED}✗ Incus not found${NC}"
    echo "Install Incus: https://linuxcontainers.org/incus/"
    exit 1
fi

# Instance name — unique per run so parallel runs do not conflict
INSTANCE_NAME="caswhois-test-$$"
BASE_URL="http://localhost:8080"

# Cleanup function — only deletes this run's instance
cleanup() {
    echo
    echo "Cleaning up..."
    incus delete -f "$INSTANCE_NAME" 2>/dev/null || true
}

trap cleanup EXIT

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=""

# run_test NAME COMMAND
run_test() {
    local test_name="$1"
    local test_command="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    printf "[%d] %s... " "$TESTS_RUN" "$test_name"

    if eval "$test_command" &>/dev/null; then
        echo -e "${GREEN}PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}FAIL${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS="${FAILED_TESTS}  - ${test_name}\n"
    fi
}

# run_test_status NAME EXPECTED_CODE URL [EXTRA_CURL_ARGS]
run_test_status() {
    local test_name="$1"
    local expected="$2"
    local url="$3"
    shift 3
    local extra_args="$*"

    TESTS_RUN=$((TESTS_RUN + 1))
    printf "[%d] %s... " "$TESTS_RUN" "$test_name"

    local got
    got=$(incus exec "$INSTANCE_NAME" -- curl -s -o /dev/null -w '%{http_code}' $extra_args "$url" 2>/dev/null)
    if [ "$got" = "$expected" ]; then
        echo -e "${GREEN}PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}FAIL (got $got, want $expected)${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS="${FAILED_TESTS}  - ${test_name}\n"
    fi
}

# Shorthand: run curl inside the instance
icurl() {
    incus exec "$INSTANCE_NAME" -- curl "$@"
}

# Start tests
echo "Creating Incus instance (Ubuntu 24.04)..."
incus launch images:ubuntu/24.04 "$INSTANCE_NAME"
echo

echo "Waiting for instance to be ready..."
sleep 5

# Get instance IP
INSTANCE_IP=$(incus list "$INSTANCE_NAME" -c 4 -f csv | cut -d' ' -f1)
echo "Instance IP: $INSTANCE_IP"
echo

# Install dependencies in instance
echo "Installing dependencies in instance..."
incus exec "$INSTANCE_NAME" -- apt-get update -qq
incus exec "$INSTANCE_NAME" -- apt-get install -y -qq curl ca-certificates
echo

# Build caswhois binary (linux/amd64)
echo "Building caswhois binary..."
cd "$PROJECT_ROOT"
make dev
echo

# Find the built binary
BINARY_PATH=$(find /tmp -name "caswhois" -type f 2>/dev/null | head -1)
if [ -z "$BINARY_PATH" ]; then
    echo -e "${RED}✗ Binary not found in /tmp — did make dev succeed?${NC}"
    exit 1
fi

echo "Copying binary to instance..."
incus file push "$BINARY_PATH" "$INSTANCE_NAME/usr/local/bin/caswhois"
incus exec "$INSTANCE_NAME" -- chmod +x /usr/local/bin/caswhois
echo

# Start caswhois in development mode (binds 0.0.0.0:8080)
echo "Starting caswhois service..."
incus exec "$INSTANCE_NAME" -- sh -c \
    'nohup caswhois serve --mode development --debug --address 0.0.0.0:8080 >/var/log/caswhois.log 2>&1 &'
sleep 5
echo

# Check if caswhois is running
run_test "caswhois process running" \
    "incus exec $INSTANCE_NAME -- pgrep -x caswhois"

# Wait for service to be ready
echo "Waiting for service to be ready (max 30s)..."
TIMEOUT=30
ELAPSED=0
while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
    if icurl -f -s "$BASE_URL/server/healthz" &>/dev/null; then
        echo -e "${GREEN}Service is ready${NC}"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    printf "."
done
echo

if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    echo -e "${RED}Service failed to start${NC}"
    incus exec "$INSTANCE_NAME" -- cat /var/log/caswhois.log
    exit 1
fi

# Extract server token from generated server.yml
TOKEN=$(icurl -f -s "$BASE_URL/server/healthz" >/dev/null 2>&1; \
    incus exec "$INSTANCE_NAME" -- sh -c \
    'grep "^  token:" /etc/apimgr/caswhois/server.yml 2>/dev/null || grep "^  token:" "$HOME/.config/apimgr/caswhois/server.yml" 2>/dev/null || true' \
    | awk '{print $2}')

echo "Running integration tests against $BASE_URL"
echo

# -----------------------------------------------------------------------
echo "--- Health endpoints ---"
# -----------------------------------------------------------------------

run_test "GET /healthz → 200" \
    "icurl -f -s $BASE_URL/healthz"

run_test "GET /server/healthz → 200" \
    "icurl -f -s $BASE_URL/server/healthz"

run_test "GET /server/healthz returns ok:true" \
    "icurl -f -s $BASE_URL/server/healthz | grep -q -- '\"ok\":true'"

run_test "GET /api/v1/server/healthz → 200 (JSON)" \
    "icurl -f -s -H 'Accept: application/json' $BASE_URL/api/v1/server/healthz | grep -q -- '\"ok\":true'"

run_test "GET /api/v1/server/healthz → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' $BASE_URL/api/v1/server/healthz"

# -----------------------------------------------------------------------
echo
echo "--- Text-only / fixed-format endpoints ---"
# -----------------------------------------------------------------------

run_test "GET /.well-known/security.txt → 200" \
    "icurl -f -s $BASE_URL/.well-known/security.txt"

run_test "GET /robots.txt → 200" \
    "icurl -f -s $BASE_URL/robots.txt"

run_test "GET /sitemap.xml → 200" \
    "icurl -f -s $BASE_URL/sitemap.xml"

run_test "GET /manifest.json → 200 (JSON)" \
    "icurl -f -s $BASE_URL/manifest.json | grep -q -- 'name'"

run_test "GET /sw.js → 200" \
    "icurl -f -s $BASE_URL/sw.js"

run_test "GET /offline.html → 200 (text/html)" \
    "icurl -f -s -H 'Accept: text/html' $BASE_URL/offline.html | grep -qi '<html'"

run_test "GET /offline.html → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' $BASE_URL/offline.html"

# -----------------------------------------------------------------------
echo
echo "--- Metrics endpoint ---"
# -----------------------------------------------------------------------

run_test "GET /metrics → 200" \
    "icurl -f -s $BASE_URL/metrics | grep -q -- 'caswhois_'"

# -----------------------------------------------------------------------
echo
echo "--- Frontend routes (text/html + text/plain required per PART 28) ---"
# -----------------------------------------------------------------------

run_test "GET / → 200 (text/html)" \
    "icurl -f -sL -H 'Accept: text/html' $BASE_URL/ | grep -qi '<html'"

run_test "GET / → 200 (text/plain)" \
    "icurl -f -sL -H 'Accept: text/plain' $BASE_URL/"

run_test "GET /about → 200 (text/html)" \
    "icurl -f -sL -H 'Accept: text/html' $BASE_URL/about | grep -qi '<html'"

run_test "GET /about → 200 (text/plain)" \
    "icurl -f -sL -H 'Accept: text/plain' $BASE_URL/about"

run_test "GET /server/about → 200 (text/html)" \
    "icurl -f -sL -H 'Accept: text/html' $BASE_URL/server/about | grep -qi '<html'"

run_test "GET /server/about → 200 (text/plain)" \
    "icurl -f -sL -H 'Accept: text/plain' $BASE_URL/server/about"

run_test "GET /docs → 200 (text/html)" \
    "icurl -f -sL -H 'Accept: text/html' $BASE_URL/docs | grep -qi '<html'"

run_test "GET /docs → 200 (text/plain)" \
    "icurl -f -sL -H 'Accept: text/plain' $BASE_URL/docs"

run_test "GET /server/docs → 200 (text/html)" \
    "icurl -f -sL -H 'Accept: text/html' $BASE_URL/server/docs | grep -qi '<html'"

run_test "GET /server/docs → 200 (text/plain)" \
    "icurl -f -sL -H 'Accept: text/plain' $BASE_URL/server/docs"

run_test "GET /whois → 200 (text/html)" \
    "icurl -f -sL -H 'Accept: text/html' $BASE_URL/whois | grep -qi '<html'"

run_test "GET /whois → 200 (text/plain)" \
    "icurl -f -sL -H 'Accept: text/plain' $BASE_URL/whois"

run_test "GET /whois/search → 200 (text/html)" \
    "icurl -f -sL -H 'Accept: text/html' $BASE_URL/whois/search | grep -qi '<html'"

run_test "GET /whois/search → 200 (text/plain)" \
    "icurl -f -sL -H 'Accept: text/plain' $BASE_URL/whois/search"

# -----------------------------------------------------------------------
echo
echo "--- WHOIS API endpoints (application/json + text/plain per PART 28) ---"
# -----------------------------------------------------------------------

run_test "GET /api/v1/whois/example.com → 200 (JSON)" \
    "icurl -f -s -H 'Accept: application/json' $BASE_URL/api/v1/whois/example.com | grep -q 'ok'"

run_test "GET /api/v1/whois/example.com → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' $BASE_URL/api/v1/whois/example.com"

run_test "GET /api/v1/whois/domain/example.com → 200 (JSON)" \
    "icurl -f -s -H 'Accept: application/json' $BASE_URL/api/v1/whois/domain/example.com | grep -q 'ok'"

run_test "GET /api/v1/whois/domain/example.com → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' $BASE_URL/api/v1/whois/domain/example.com"

run_test "GET /api/v1/whois/ip/8.8.8.8 → 200 (JSON)" \
    "icurl -f -s -H 'Accept: application/json' $BASE_URL/api/v1/whois/ip/8.8.8.8 | grep -q 'ok'"

run_test "GET /api/v1/whois/ip/8.8.8.8 → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' $BASE_URL/api/v1/whois/ip/8.8.8.8"

run_test "GET /api/v1/whois/asn/AS15169 → 200 (JSON)" \
    "icurl -f -s -H 'Accept: application/json' $BASE_URL/api/v1/whois/asn/AS15169 | grep -q 'ok'"

run_test "GET /api/v1/whois/asn/AS15169 → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' $BASE_URL/api/v1/whois/asn/AS15169"

run_test "GET /api/v1/whois/validate/example.com → 200 (JSON)" \
    "icurl -f -s -H 'Accept: application/json' $BASE_URL/api/v1/whois/validate/example.com | grep -q 'ok'"

run_test "GET /api/v1/whois/validate/example.com → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' $BASE_URL/api/v1/whois/validate/example.com"

run_test "GET /api/v1/whois/search?q=example → 200 (JSON)" \
    "icurl -f -s -H 'Accept: application/json' '$BASE_URL/api/v1/whois/search?q=example' | grep -q 'ok'"

run_test "GET /api/v1/whois/search?q=example → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' '$BASE_URL/api/v1/whois/search?q=example'"

# -----------------------------------------------------------------------
echo
echo "--- Other API endpoints ---"
# -----------------------------------------------------------------------

run_test "GET /api/v1/whois-servers → 200 (JSON)" \
    "icurl -f -s -H 'Accept: application/json' $BASE_URL/api/v1/whois-servers | grep -q -- 'servers'"

run_test "GET /api/v1/whois-servers → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' $BASE_URL/api/v1/whois-servers"

run_test "GET /api/v1/server/stats → 200 (JSON)" \
    "icurl -f -s -H 'Accept: application/json' $BASE_URL/api/v1/server/stats | grep -q 'ok'"

run_test "GET /api/v1/server/stats → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' $BASE_URL/api/v1/server/stats"

run_test "GET /api/autodiscover → 200 (JSON)" \
    "icurl -f -s -H 'Accept: application/json' $BASE_URL/api/autodiscover | grep -q 'api'"

run_test "GET /api/autodiscover → 200 (text/plain)" \
    "icurl -f -s -H 'Accept: text/plain' $BASE_URL/api/autodiscover"

# -----------------------------------------------------------------------
echo
echo "--- Locale / i18n endpoints ---"
# -----------------------------------------------------------------------

run_test "GET /locales/en.json → 200" \
    "icurl -f -s $BASE_URL/locales/en.json | grep -q '{'"

# -----------------------------------------------------------------------
echo
echo "--- Token-protected endpoints ---"
# -----------------------------------------------------------------------

run_test_status "GET /api/v1/server/schedulers → 401 (no token)" \
    "401" "$BASE_URL/api/v1/server/schedulers"

run_test_status "GET /api/v1/server/backups → 401 (no token)" \
    "401" "$BASE_URL/api/v1/server/backups"

run_test_status "POST /api/v1/whois/bulk → 401 (no token)" \
    "401" "$BASE_URL/api/v1/whois/bulk" -X POST -H 'Content-Type: application/json' -d '{"queries":[]}'

if [ -n "$TOKEN" ]; then
    run_test "GET /api/v1/server/schedulers → 200 (JSON, with token)" \
        "icurl -f -s -H 'Accept: application/json' -H 'Authorization: Bearer $TOKEN' $BASE_URL/api/v1/server/schedulers | grep -q 'ok'"

    run_test "GET /api/v1/server/schedulers → 200 (text/plain, with token)" \
        "icurl -f -s -H 'Accept: text/plain' -H 'Authorization: Bearer $TOKEN' $BASE_URL/api/v1/server/schedulers"

    run_test "GET /api/v1/server/backups → 200 (JSON, with token)" \
        "icurl -f -s -H 'Accept: application/json' -H 'Authorization: Bearer $TOKEN' $BASE_URL/api/v1/server/backups | grep -q 'ok'"

    run_test "GET /api/v1/server/backups → 200 (text/plain, with token)" \
        "icurl -f -s -H 'Accept: text/plain' -H 'Authorization: Bearer $TOKEN' $BASE_URL/api/v1/server/backups"

    run_test "POST /api/v1/whois/bulk → 200 (with token)" \
        "icurl -f -s -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"queries\":[\"example.com\"]}' $BASE_URL/api/v1/whois/bulk | grep -q 'ok'"
else
    echo -e "  ${YELLOW}Skipping authenticated tests — token not available${NC}"
fi

# -----------------------------------------------------------------------
echo
echo "--- Error handling ---"
# -----------------------------------------------------------------------

run_test_status "GET /nonexistent → 404" \
    "404" "$BASE_URL/nonexistent-route-xyz"

# -----------------------------------------------------------------------
echo
echo "--- Security headers ---"
# -----------------------------------------------------------------------

run_test "CORS headers present" \
    "icurl -s -I $BASE_URL/api/v1/server/healthz | grep -qi -- 'access-control'"

run_test "CSP header present" \
    "icurl -s -I $BASE_URL/ | grep -qi 'content-security-policy'"

# -----------------------------------------------------------------------
echo
echo "--- Service management (systemd) ---"
# -----------------------------------------------------------------------

run_test "caswhois install (systemd)" \
    "incus exec $INSTANCE_NAME -- caswhois install"

run_test "systemd service is enabled" \
    "incus exec $INSTANCE_NAME -- systemctl is-enabled caswhois"

run_test "systemd service starts" \
    "incus exec $INSTANCE_NAME -- systemctl start caswhois"

run_test "systemd service is active" \
    "incus exec $INSTANCE_NAME -- systemctl is-active caswhois"

run_test "systemd service stops" \
    "incus exec $INSTANCE_NAME -- systemctl stop caswhois"

run_test "caswhois uninstall" \
    "incus exec $INSTANCE_NAME -- caswhois uninstall"

# -----------------------------------------------------------------------
echo
echo "--- Binary version / help ---"
# -----------------------------------------------------------------------

run_test "Binary --version flag" \
    "incus exec $INSTANCE_NAME -- caswhois --version 2>&1 | grep -q 'caswhois version'"

run_test "Binary --help flag" \
    "incus exec $INSTANCE_NAME -- caswhois --help 2>&1 | grep -qi 'usage'"

# -----------------------------------------------------------------------
echo
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Total:  $TESTS_RUN"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
if [ "$TESTS_FAILED" -gt 0 ]; then
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    echo
    echo "Failed tests:"
    printf "%b" "$FAILED_TESTS"
else
    echo "Failed: 0"
fi
echo

# Show logs if any tests failed
if [ "$TESTS_FAILED" -gt 0 ]; then
    echo "Service logs:"
    echo "========================================"
    incus exec "$INSTANCE_NAME" -- cat /var/log/caswhois.log 2>/dev/null || true
    echo "========================================"
    exit 1
fi

echo -e "${GREEN}All $TESTS_RUN tests passed!${NC}"
exit 0
