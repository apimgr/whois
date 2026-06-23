#!/bin/bash
# Docker integration tests for caswhois
# Tests build, health, API endpoints

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKER_DIR="$PROJECT_ROOT/docker"

echo "========================================"
echo "caswhois Docker Integration Tests"
echo "========================================"
echo "Project root: $PROJECT_ROOT"
echo

# Cleanup function (only remove this project's test resources, never a broad sweep)
cleanup() {
    echo
    echo "Cleaning up..."
    cd "$DOCKER_DIR"
    docker compose -f docker-compose.test.yml down -v 2>/dev/null || true
}

# Set trap for cleanup
trap cleanup EXIT

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test function
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "[$TESTS_RUN] $test_name... "
    
    if eval "$test_command" &>/dev/null; then
        echo -e "${GREEN}PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Start tests
echo "Starting tests..."
echo

# Build and start test container
echo "Building test container..."
cd "$DOCKER_DIR"
docker compose -f docker-compose.test.yml build
echo

echo "Starting test container..."
docker compose -f docker-compose.test.yml up -d
echo

# Wait for container to be healthy
echo "Waiting for container to be healthy (max 60s)..."
TIMEOUT=60
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if docker compose -f docker-compose.test.yml ps | grep -q "healthy"; then
        echo -e "${GREEN}Container is healthy${NC}"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo -n "."
done
echo

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo -e "${RED}Container failed to become healthy${NC}"
    docker compose -f docker-compose.test.yml logs
    exit 1
fi

# Get container port
PORT=64581

echo "Running API tests against http://localhost:$PORT"
echo

# Test: Health endpoint
run_test "Health check (/healthz)" \
    "curl -f -s http://localhost:$PORT/healthz"

run_test "Health check (/api/v1/healthz)" \
    "curl -f -s http://localhost:$PORT/api/v1/healthz"

# Test: WHOIS endpoints (may fail if no network, that's OK)
run_test "Domain WHOIS (example.com)" \
    "curl -f -s http://localhost:$PORT/api/v1/whois/example.com | grep -q example"

run_test "IP WHOIS (8.8.8.8)" \
    "curl -f -s http://localhost:$PORT/api/v1/whois/8.8.8.8"

run_test "ASN WHOIS (AS15169)" \
    "curl -f -s http://localhost:$PORT/api/v1/whois/AS15169"

# Test: Stats endpoint
run_test "Stats endpoint" \
    "curl -f -s http://localhost:$PORT/api/v1/stats"

# Test: WHOIS servers list
run_test "WHOIS servers list" \
    "curl -f -s http://localhost:$PORT/api/v1/whois-servers | grep -q servers"

# Test: Metrics endpoint
run_test "Metrics endpoint" \
    "curl -f -s http://localhost:$PORT/metrics | grep -q 'caswhois_'"

# Test: Admin panel (redirect to login)
run_test "Admin panel" \
    "curl -s -o /dev/null -w '%{http_code}' http://localhost:$PORT/admin | grep -q -E '(200|302)'"

# Test: Format negotiation (JSON)
run_test "JSON format (Accept header)" \
    "curl -f -s -H 'Accept: application/json' http://localhost:$PORT/api/v1/stats"

# Test: Format negotiation (XML)
run_test "XML format (Accept header)" \
    "curl -f -s -H 'Accept: application/xml' http://localhost:$PORT/api/v1/stats | grep -q xml"

# Test: Format negotiation (text)
run_test "Text format (Accept header)" \
    "curl -f -s -H 'Accept: text/plain' http://localhost:$PORT/api/v1/stats"

# Test: Frontend content negotiation (PART 28 requires text/html AND text/plain)
run_test "Frontend HTML (Accept: text/html)" \
    "curl -f -sL -H 'Accept: text/html' http://localhost:$PORT/ | grep -q -i '<html'"

run_test "Frontend plain text (Accept: text/plain)" \
    "curl -f -sL -H 'Accept: text/plain' http://localhost:$PORT/"

# Test: Canonical health routes (PART 13)
run_test "Health check (/server/healthz)" \
    "curl -f -s http://localhost:$PORT/server/healthz"

run_test "Health check (/api/v1/server/healthz)" \
    "curl -f -s http://localhost:$PORT/api/v1/server/healthz"

# Test: Rate limiting headers
run_test "Rate limit headers present" \
    "curl -s -I http://localhost:$PORT/api/v1/healthz | grep -q -i 'x-ratelimit'"

# Test: CORS headers
run_test "CORS headers present" \
    "curl -s -I http://localhost:$PORT/api/v1/healthz | grep -q -i 'access-control'"

# Summary
echo
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Total:  $TESTS_RUN"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
else
    echo "Failed: 0"
fi
echo

# Show container logs if any tests failed
if [ $TESTS_FAILED -gt 0 ]; then
    echo "Container logs:"
    echo "========================================"
    docker compose -f docker-compose.test.yml logs
    echo "========================================"
    exit 1
fi

echo -e "${GREEN}All tests passed!${NC}"
exit 0
