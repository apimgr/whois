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

# Generate license report
echo "Generating license report..."
go-licenses csv ./... > licenses.csv
go-licenses save ./... --save_path=third_party_licenses

echo "✓ License report saved to licenses.csv and third_party_licenses/"
echo ""
echo "Next steps:"
echo "1. Review licenses.csv"
echo "2. Update LICENSE.md with any new dependencies"
echo "3. Commit the changes"
