## [x] Increase test coverage to ≥80%

Makefile gate is 80% (not 100% as previously stated). Current coverage: 83.1% total.
All packages pass. Coverage verified via Docker with casjaysdev/go:latest.

Read: AI.md PART 28

## [x] Create GitHub Actions workflows

Created:
- `.github/workflows/ci.yml` — lint + test (60% gate) + build + vuln-check; push/PR to main/master
- `.github/workflows/release.yml` — 8-platform matrix build; tag push (v*, *.*.*)
All Actions pinned to full 40-char SHA. casjaysdev/go:latest container; no Makefile.

Read: AI.md PART 27

## [x] Refactor main.go to use positional subcommands

Completed: positional subcommand routing added in `runSubcommand()` with tests.
Subcommands: serve, migrate, client, version, install, uninstall, start, stop, restart, status, update.
Flag interface retained for backward compatibility.
