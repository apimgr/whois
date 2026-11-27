#!/usr/bin/env bash
# scripts/verify-licenses.sh

set -eo pipefail

echo "Checking for incompatible licenses..."

# Require go-licenses — it is pre-installed in casjaysdev/go:latest; never install inline.
command -v go-licenses >/dev/null 2>&1 || {
    echo "ERROR: go-licenses not found — run inside casjaysdev/go:latest"
    exit 1
}

# Check for copyleft licenses
echo "Scanning dependencies..."
if go-licenses csv ./... | grep -iE 'GPL|AGPL|LGPL'; then
    echo "ERROR: Copyleft license detected!"
    echo "Remove the dependency or find an alternative."
    exit 1
fi

echo "✓ All licenses are compatible"

# Reports are working files and must never be written into the repository.
TEMP_PARENT="${TMPDIR:-/tmp}/apimgr"
mkdir -p "$TEMP_PARENT"
LICDIR=$(mktemp -d "$TEMP_PARENT/whois-XXXXXX")
chmod 0700 "$LICDIR"
trap 'rm -rf -- "$LICDIR"' EXIT
echo "Generating license report in a private temporary directory..."
go-licenses csv ./... > "$LICDIR/licenses.csv"
go-licenses save ./... --save_path="$LICDIR/third_party_licenses"

echo "✓ License report generated and removed after verification"
