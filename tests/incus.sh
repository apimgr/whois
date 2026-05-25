#!/bin/bash
# Incus full OS integration tests for caswhois
# Tests in a real Ubuntu environment (preferred over Docker)

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "========================================"
echo "caswhois Incus Integration Tests"
echo "========================================"
echo "Project root: $PROJECT_ROOT"
echo

# Check for incus
if ! command -v incus &> /dev/null; then
    echo -e "${RED}✗ Incus not found${NC}"
    echo "Install Incus: https://linuxcontainers.org/incus/"
    exit 1
fi

# Instance name
INSTANCE_NAME="caswhois-test-$$"

# Cleanup function
cleanup() {
    echo
    echo "Cleaning up..."
    incus delete -f "$INSTANCE_NAME" 2>/dev/null || true
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
incus exec "$INSTANCE_NAME" -- apt-get install -y -qq curl wget ca-certificates
echo

# Copy binary to instance
echo "Building caswhois binary..."
cd "$PROJECT_ROOT"
make dev
echo

# Find the built binary
BINARY_PATH=$(find /tmp -name "caswhois" -type f 2>/dev/null | head -1)
if [ -z "$BINARY_PATH" ]; then
    echo -e "${RED}✗ Binary not found${NC}"
    exit 1
fi

echo "Copying binary to instance..."
incus file push "$BINARY_PATH" "$INSTANCE_NAME/usr/local/bin/caswhois"
incus exec "$INSTANCE_NAME" -- chmod +x /usr/local/bin/caswhois
echo

# Start caswhois in instance
echo "Starting caswhois service..."
incus exec "$INSTANCE_NAME" -- sh -c 'nohup caswhois --mode development --address 0.0.0.0 --port 8080 > /var/log/caswhois.log 2>&1 &'
sleep 5
echo

# Check if caswhois is running
run_test "caswhois process running" \
    "incus exec $INSTANCE_NAME -- pgrep -x caswhois"

# Wait for service to be ready
echo "Waiting for service to be ready..."
TIMEOUT=30
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if incus exec "$INSTANCE_NAME" -- curl -f -s http://localhost:8080/healthz &>/dev/null; then
        echo -e "${GREEN}Service is ready${NC}"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo -n "."
done
echo

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo -e "${RED}Service failed to start${NC}"
    incus exec "$INSTANCE_NAME" -- cat /var/log/caswhois.log
    exit 1
fi

# Run tests against the instance
echo "Running API tests..."
echo

# Test: Health endpoint
run_test "Health check (/healthz)" \
    "incus exec $INSTANCE_NAME -- curl -f -s http://localhost:8080/healthz"

run_test "Health check (/api/v1/healthz)" \
    "incus exec $INSTANCE_NAME -- curl -f -s http://localhost:8080/api/v1/healthz"

# Test: WHOIS endpoints
run_test "Domain WHOIS (example.com)" \
    "incus exec $INSTANCE_NAME -- curl -f -s http://localhost:8080/api/v1/whois/example.com | grep -q example"

run_test "IP WHOIS (8.8.8.8)" \
    "incus exec $INSTANCE_NAME -- curl -f -s http://localhost:8080/api/v1/whois/8.8.8.8"

run_test "ASN WHOIS (AS15169)" \
    "incus exec $INSTANCE_NAME -- curl -f -s http://localhost:8080/api/v1/whois/AS15169"

# Test: Stats endpoint
run_test "Stats endpoint" \
    "incus exec $INSTANCE_NAME -- curl -f -s http://localhost:8080/api/v1/stats"

# Test: WHOIS servers list
run_test "WHOIS servers list" \
    "incus exec $INSTANCE_NAME -- curl -f -s http://localhost:8080/api/v1/whois-servers | grep -q servers"

# Test: Metrics endpoint
run_test "Metrics endpoint" \
    "incus exec $INSTANCE_NAME -- curl -f -s http://localhost:8080/metrics | grep -q 'caswhois_'"

# Test: Admin panel
run_test "Admin panel" \
    "incus exec $INSTANCE_NAME -- curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/admin | grep -q -E '(200|302)'"

# Test: Format negotiation (JSON)
run_test "JSON format (Accept header)" \
    "incus exec $INSTANCE_NAME -- curl -f -s -H 'Accept: application/json' http://localhost:8080/api/v1/stats"

# Test: Format negotiation (XML)
run_test "XML format (Accept header)" \
    "incus exec $INSTANCE_NAME -- curl -f -s -H 'Accept: application/xml' http://localhost:8080/api/v1/stats | grep -q xml"

# Test: Format negotiation (text)
run_test "Text format (Accept header)" \
    "incus exec $INSTANCE_NAME -- curl -f -s -H 'Accept: text/plain' http://localhost:8080/api/v1/stats"

# Test: Service installation (requires root)
echo
echo "Testing service installation..."
run_test "Install systemd service" \
    "incus exec $INSTANCE_NAME -- caswhois --service --install"

run_test "Start service" \
    "incus exec $INSTANCE_NAME -- systemctl start caswhois"

run_test "Service is active" \
    "incus exec $INSTANCE_NAME -- systemctl is-active caswhois"

run_test "Stop service" \
    "incus exec $INSTANCE_NAME -- systemctl stop caswhois"

run_test "Uninstall service" \
    "incus exec $INSTANCE_NAME -- caswhois --service --uninstall"

# Test: Binary version
run_test "Version flag" \
    "incus exec $INSTANCE_NAME -- caswhois --version"

# Test: Help output
run_test "Help flag" \
    "incus exec $INSTANCE_NAME -- caswhois --help"

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

# Show logs if any tests failed
if [ $TESTS_FAILED -gt 0 ]; then
    echo "Service logs:"
    echo "========================================"
    incus exec "$INSTANCE_NAME" -- cat /var/log/caswhois.log
    echo "========================================"
    exit 1
fi

echo -e "${GREEN}All tests passed!${NC}"
exit 0
