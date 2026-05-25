#!/bin/bash
# Main test runner - auto-detects incus or docker and runs tests
# See AI.md PART 29 for testing rules

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
echo "caswhois Test Runner"
echo "========================================"
echo "Project root: $PROJECT_ROOT"
echo

# Check for incus (preferred)
if command -v incus &> /dev/null; then
    echo -e "${GREEN}✓ Incus detected (preferred)${NC}"
    echo "Running full OS integration tests..."
    exec "$SCRIPT_DIR/incus.sh"
fi

# Check for docker (fallback)
if command -v docker &> /dev/null; then
    echo -e "${YELLOW}⚠ Docker detected (fallback - Incus preferred for full testing)${NC}"
    echo "Running Docker integration tests..."
    exec "$SCRIPT_DIR/docker.sh"
fi

# No container runtime found
echo -e "${RED}✗ No container runtime found${NC}"
echo
echo "Please install one of the following:"
echo "  - Incus (preferred): https://linuxcontainers.org/incus/"
echo "  - Docker (fallback): https://docs.docker.com/get-docker/"
echo
exit 1
