#!/bin/bash
# Docker integration tests for caswhois — 100% endpoint/route coverage
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
DOCKER_DIR="$PROJECT_ROOT/docker"

echo "========================================"
echo "caswhois Docker Integration Tests"
echo "========================================"
echo "Project root: $PROJECT_ROOT"
echo

# Cleanup function — only removes this project's test resources, never a broad sweep
cleanup() {
    echo
    echo "Cleaning up..."
    docker compose --project-directory "$DOCKER_DIR" -f "$DOCKER_DIR/docker-compose.test.yml" down -v 2>/dev/null || true
}

trap cleanup EXIT

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=""

# run_test NAME COMMAND
# Eval COMMAND; pass/fail is determined by exit code
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

# run_test_status NAME EXPECTED_CODE COMMAND
# Checks HTTP status code equals EXPECTED_CODE
run_test_status() {
    local test_name="$1"
    local expected="$2"
    local url="$3"
    shift 3
    local extra_args="$*"

    TESTS_RUN=$((TESTS_RUN + 1))
    printf "[%d] %s... " "$TESTS_RUN" "$test_name"

    local got
    got=$(curl -s -o /dev/null -w '%{http_code}' $extra_args "$url" 2>/dev/null)
    if [ "$got" = "$expected" ]; then
        echo -e "${GREEN}PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}FAIL (got $got, want $expected)${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS="${FAILED_TESTS}  - ${test_name}\n"
    fi
}

# Build and start test container
echo "Building test container..."
docker compose --project-directory "$DOCKER_DIR" -f "$DOCKER_DIR/docker-compose.test.yml" build
echo

echo "Starting test container..."
docker compose --project-directory "$DOCKER_DIR" -f "$DOCKER_DIR/docker-compose.test.yml" up -d
echo

# Wait for container to be healthy (max 90s)
echo "Waiting for container to be healthy (max 90s)..."
TIMEOUT=90
ELAPSED=0
while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
    if docker compose --project-directory "$DOCKER_DIR" -f "$DOCKER_DIR/docker-compose.test.yml" ps | grep -q -- "healthy"; then
        echo -e "${GREEN}Container is healthy${NC}"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    printf "."
done
echo

if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    echo -e "${RED}Container failed to become healthy in ${TIMEOUT}s${NC}"
    docker compose --project-directory "$DOCKER_DIR" -f "$DOCKER_DIR/docker-compose.test.yml" logs
    exit 1
fi

# Base URL
PORT=64581
BASE="http://localhost:$PORT"

# Extract server token from the running container's generated server.yml
TOKEN=$(docker exec caswhois-test sh -c 'grep "^  token:" /config/caswhois/server.yml 2>/dev/null | awk "{print \$2}"' 2>/dev/null || true)
if [ -z "$TOKEN" ]; then
    echo -e "${YELLOW}⚠ Could not read server token — token-protected tests will verify 401${NC}"
fi

echo "Running integration tests against $BASE"
echo

# -----------------------------------------------------------------------
echo "--- Health endpoints ---"
# -----------------------------------------------------------------------

run_test "GET /healthz → 200" \
    "curl -f -s $BASE/healthz"

run_test "GET /server/healthz → 200" \
    "curl -f -s $BASE/server/healthz"

run_test "GET /server/healthz returns ok:true" \
    "curl -f -s $BASE/server/healthz | grep -q -- '\"ok\":true'"

run_test "GET /api/v1/server/healthz → 200 (JSON)" \
    "curl -f -s -H 'Accept: application/json' $BASE/api/v1/server/healthz | grep -q -- '\"ok\":true'"

run_test "GET /api/v1/server/healthz → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' $BASE/api/v1/server/healthz"

# -----------------------------------------------------------------------
echo
echo "--- Text-only / fixed-format endpoints ---"
# -----------------------------------------------------------------------

run_test "GET /.well-known/security.txt → 200" \
    "curl -f -s $BASE/.well-known/security.txt"

run_test "GET /robots.txt → 200" \
    "curl -f -s $BASE/robots.txt"

run_test "GET /sitemap.xml → 200" \
    "curl -f -s $BASE/sitemap.xml"

run_test "GET /manifest.json → 200 (JSON)" \
    "curl -f -s $BASE/manifest.json | grep -q -- 'name'"

run_test "GET /sw.js → 200" \
    "curl -f -s $BASE/sw.js"

run_test "GET /offline.html → 200 (text/html)" \
    "curl -f -s -H 'Accept: text/html' $BASE/offline.html | grep -qi '<html'"

run_test "GET /offline.html → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' $BASE/offline.html"

# -----------------------------------------------------------------------
echo
echo "--- Metrics endpoint ---"
# -----------------------------------------------------------------------

run_test "GET /metrics → 200" \
    "curl -f -s $BASE/metrics | grep -q -- 'caswhois_'"

# -----------------------------------------------------------------------
echo
echo "--- Frontend routes (text/html + text/plain required per PART 28) ---"
# -----------------------------------------------------------------------

run_test "GET / → 200 (text/html)" \
    "curl -f -sL -H 'Accept: text/html' $BASE/ | grep -qi '<html'"

run_test "GET / → 200 (text/plain)" \
    "curl -f -sL -H 'Accept: text/plain' $BASE/"

run_test "GET /about → 200 (text/html)" \
    "curl -f -sL -H 'Accept: text/html' $BASE/about | grep -qi '<html'"

run_test "GET /about → 200 (text/plain)" \
    "curl -f -sL -H 'Accept: text/plain' $BASE/about"

run_test "GET /server/about → 200 (text/html)" \
    "curl -f -sL -H 'Accept: text/html' $BASE/server/about | grep -qi '<html'"

run_test "GET /server/about → 200 (text/plain)" \
    "curl -f -sL -H 'Accept: text/plain' $BASE/server/about"

run_test "GET /docs → 200 (text/html)" \
    "curl -f -sL -H 'Accept: text/html' $BASE/docs | grep -qi '<html'"

run_test "GET /docs → 200 (text/plain)" \
    "curl -f -sL -H 'Accept: text/plain' $BASE/docs"

run_test "GET /server/docs → 200 (text/html)" \
    "curl -f -sL -H 'Accept: text/html' $BASE/server/docs | grep -qi '<html'"

run_test "GET /server/docs → 200 (text/plain)" \
    "curl -f -sL -H 'Accept: text/plain' $BASE/server/docs"

run_test "GET /whois → 200 (text/html)" \
    "curl -f -sL -H 'Accept: text/html' $BASE/whois | grep -qi '<html'"

run_test "GET /whois → 200 (text/plain)" \
    "curl -f -sL -H 'Accept: text/plain' $BASE/whois"

run_test "GET /whois/search → 200 (text/html)" \
    "curl -f -sL -H 'Accept: text/html' $BASE/whois/search | grep -qi '<html'"

run_test "GET /whois/search → 200 (text/plain)" \
    "curl -f -sL -H 'Accept: text/plain' $BASE/whois/search"

# -----------------------------------------------------------------------
echo
echo "--- WHOIS API endpoints (application/json + text/plain per PART 28) ---"
# -----------------------------------------------------------------------

run_test "GET /api/v1/whois/example.com → 200 (JSON)" \
    "curl -f -s -H 'Accept: application/json' $BASE/api/v1/whois/example.com | grep -q 'ok'"

run_test "GET /api/v1/whois/example.com → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' $BASE/api/v1/whois/example.com"

run_test "GET /api/v1/whois/domain/example.com → 200 (JSON)" \
    "curl -f -s -H 'Accept: application/json' $BASE/api/v1/whois/domain/example.com | grep -q 'ok'"

run_test "GET /api/v1/whois/domain/example.com → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' $BASE/api/v1/whois/domain/example.com"

run_test "GET /api/v1/whois/ip/8.8.8.8 → 200 (JSON)" \
    "curl -f -s -H 'Accept: application/json' $BASE/api/v1/whois/ip/8.8.8.8 | grep -q 'ok'"

run_test "GET /api/v1/whois/ip/8.8.8.8 → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' $BASE/api/v1/whois/ip/8.8.8.8"

run_test "GET /api/v1/whois/asn/AS15169 → 200 (JSON)" \
    "curl -f -s -H 'Accept: application/json' $BASE/api/v1/whois/asn/AS15169 | grep -q 'ok'"

run_test "GET /api/v1/whois/asn/AS15169 → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' $BASE/api/v1/whois/asn/AS15169"

run_test "GET /api/v1/whois/validate/example.com → 200 (JSON)" \
    "curl -f -s -H 'Accept: application/json' $BASE/api/v1/whois/validate/example.com | grep -q 'ok'"

run_test "GET /api/v1/whois/validate/example.com → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' $BASE/api/v1/whois/validate/example.com"

run_test "GET /api/v1/whois/search?q=example → 200 (JSON)" \
    "curl -f -s -H 'Accept: application/json' '$BASE/api/v1/whois/search?q=example' | grep -q 'ok'"

run_test "GET /api/v1/whois/search?q=example → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' '$BASE/api/v1/whois/search?q=example'"

# -----------------------------------------------------------------------
echo
echo "--- Other API endpoints ---"
# -----------------------------------------------------------------------

run_test "GET /api/v1/whois-servers → 200 (JSON)" \
    "curl -f -s -H 'Accept: application/json' $BASE/api/v1/whois-servers | grep -q -- 'servers'"

run_test "GET /api/v1/whois-servers → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' $BASE/api/v1/whois-servers"

run_test "GET /api/v1/server/stats → 200 (JSON)" \
    "curl -f -s -H 'Accept: application/json' $BASE/api/v1/server/stats | grep -q 'ok'"

run_test "GET /api/v1/server/stats → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' $BASE/api/v1/server/stats"

run_test "GET /api/autodiscover → 200 (JSON)" \
    "curl -f -s -H 'Accept: application/json' $BASE/api/autodiscover | grep -q 'api'"

run_test "GET /api/autodiscover → 200 (text/plain)" \
    "curl -f -s -H 'Accept: text/plain' $BASE/api/autodiscover"

# -----------------------------------------------------------------------
echo
echo "--- Locale / i18n endpoints ---"
# -----------------------------------------------------------------------

run_test "GET /locales/en.json → 200" \
    "curl -f -s $BASE/locales/en.json | grep -q '{'"

# -----------------------------------------------------------------------
echo
echo "--- Token-protected endpoints ---"
# -----------------------------------------------------------------------

# Verify 401 when no token is provided
run_test_status "GET /api/v1/server/schedulers → 401 (no token)" \
    "401" "$BASE/api/v1/server/schedulers"

run_test_status "GET /api/v1/server/backups → 401 (no token)" \
    "401" "$BASE/api/v1/server/backups"

run_test_status "POST /api/v1/whois/bulk → 401 (no token)" \
    "401" "$BASE/api/v1/whois/bulk" -X POST -H 'Content-Type: application/json' -d '{"queries":[]}'

if [ -n "$TOKEN" ]; then
    run_test "GET /api/v1/server/schedulers → 200 (JSON, with token)" \
        "curl -f -s -H 'Accept: application/json' -H 'Authorization: Bearer $TOKEN' $BASE/api/v1/server/schedulers | grep -q 'ok'"

    run_test "GET /api/v1/server/schedulers → 200 (text/plain, with token)" \
        "curl -f -s -H 'Accept: text/plain' -H 'Authorization: Bearer $TOKEN' $BASE/api/v1/server/schedulers"

    run_test "GET /api/v1/server/backups → 200 (JSON, with token)" \
        "curl -f -s -H 'Accept: application/json' -H 'Authorization: Bearer $TOKEN' $BASE/api/v1/server/backups | grep -q 'ok'"

    run_test "GET /api/v1/server/backups → 200 (text/plain, with token)" \
        "curl -f -s -H 'Accept: text/plain' -H 'Authorization: Bearer $TOKEN' $BASE/api/v1/server/backups"

    run_test "POST /api/v1/whois/bulk → 200 (with token)" \
        "curl -f -s -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"queries\":[\"example.com\"]}' $BASE/api/v1/whois/bulk | grep -q 'ok'"
else
    echo -e "  ${YELLOW}Skipping authenticated tests — token not available${NC}"
fi

# -----------------------------------------------------------------------
echo
echo "--- Error handling ---"
# -----------------------------------------------------------------------

run_test_status "GET /nonexistent → 404" \
    "404" "$BASE/nonexistent-route-xyz"

# -----------------------------------------------------------------------
echo
echo "--- Security headers ---"
# -----------------------------------------------------------------------

run_test "CORS headers present" \
    "curl -s -I $BASE/api/v1/server/healthz | grep -qi 'access-control'"

run_test "CSP header present" \
    "curl -s -I $BASE/ | grep -qi 'content-security-policy'"

# -----------------------------------------------------------------------
echo
echo "--- Binary version/help ---"
# -----------------------------------------------------------------------

run_test "Binary version flag" \
    "docker exec caswhois-test caswhois --version 2>&1 | grep -q 'caswhois version'"

run_test "Binary help flag" \
    "docker exec caswhois-test caswhois --help 2>&1 | grep -qi 'usage'"

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

# Show container logs if any tests failed
if [ "$TESTS_FAILED" -gt 0 ]; then
    echo "Container logs:"
    echo "========================================"
    docker compose --project-directory "$DOCKER_DIR" -f "$DOCKER_DIR/docker-compose.test.yml" logs
    echo "========================================"
    exit 1
fi

echo -e "${GREEN}All $TESTS_RUN tests passed!${NC}"
exit 0
