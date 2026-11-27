#!/usr/bin/env bash
# scripts/verify-licenses.sh

set -eo pipefail

echo "Checking for incompatible licenses..."

# Require go-licenses — it is pre-installed in casjaysdev/go:latest; never install inline.
command -v go-licenses >/dev/null 2>&1 || {
  echo "ERROR: go-licenses not found — run inside casjaysdev/go:latest" >&2
  exit 69
}

# Check for copyleft licenses
echo "Scanning dependencies..."
IGNORE=()
OVERRIDE_ROWS=()
if [ -f .github/license-overrides.txt ]; then
  while read -r module spdx _; do
    case "$module" in
    "" | \#*) continue ;;
    esac
    IGNORE+=(--ignore "$module")
    OVERRIDE_ROWS+=("$module,$spdx")
  done <.github/license-overrides.txt
fi
LICENSES=$(go-licenses csv ./src/... "${IGNORE[@]}")
for row in "${OVERRIDE_ROWS[@]}"; do
  LICENSES="$LICENSES"$'\n'"$row"
done
if printf '%s\n' "$LICENSES" | grep -iE 'GPL|AGPL|LGPL'; then
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
printf '%s\n' "$LICENSES" >"$LICDIR/licenses.csv"
go-licenses save ./src/... "${IGNORE[@]}" --save_path="$LICDIR/third_party_licenses"

echo "✓ License report generated and removed after verification:"
cat "$LICDIR/licenses.csv"
