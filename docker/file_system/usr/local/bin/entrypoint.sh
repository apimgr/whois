#!/bin/bash
# Container entrypoint script for caswhois
# This script runs BEFORE the main binary starts

set -e

# Configure timezone
export TZ="${TZ:-America/New_York}"
if [ -f /usr/share/zoneinfo/$TZ ]; then
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime || true
    echo $TZ > /etc/timezone || true
fi

# Display startup info
echo "=========================================="
echo "caswhois Container Starting"
echo "=========================================="
echo "Timezone: $TZ"
echo "Port: ${PORT:-80}"
echo "Mode: ${MODE:-production}"
echo "=========================================="

# Note: Tor startup is controlled by the caswhois binary itself
# The binary detects if /usr/bin/tor exists and starts it if needed
# See AI.md PART 32 for Tor Hidden Service implementation

# Start the application
# Pass all arguments to the binary
exec /usr/local/bin/caswhois "$@"
