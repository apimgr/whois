## [ ] Increase test coverage to 100%

Current coverage is 47.1%. The `make test` target enforces 100% coverage and will fail.
Packages needing coverage:
- `src/server` — 16.8%
- `src/service` — 10.2%
- `src/scheduler` — 40.4%
- `src/tor` — 38.1%
- `src/ssl` — 49.0%
- `src/email` — 44.3%
- `src/geoip` — 40.6%
- `src/client/setup` — 71.8%
- `src/logger` — 79.3%
- `src/config` — 76.1%
- `src/runtime` — 78.6%

Read: AI.md PART 28

## [ ] Create GitHub Actions workflows

Must be created AFTER all code is complete and `make test` passes (100% coverage).
Required workflows (in order):
1. `.github/workflows/ci.yml` — push/PR to main/master
2. `.github/workflows/release.yml` — tag push (v*, *.*.*)
3. Optional: `.github/workflows/beta.yml`, `daily.yml`, `docker.yml`

All third-party Actions must be pinned to full commit SHA (not tags).
CI must use `casjaysdev/go:latest` container, NOT Makefile targets (explicit go commands).

Read: AI.md PART 27

## [ ] Remove docker/file_system/ directory

The spec requires `docker/rootfs/` for the container filesystem overlay.
The `docker/file_system/` directory is the old non-spec path.
The Dockerfile has been updated to reference `docker/rootfs/`.
The `docker/file_system/` directory should be deleted from the repository.

Read: AI.md PART 26

## [ ] Refactor main.go to use positional subcommands

Spec (binary-rules.md) requires positional subcommands: `serve` (default), `migrate`, `client`, `version`.
Current implementation uses flags (`--service`, `--maintenance`, etc.) instead.
Required subcommand routing:
- `caswhois serve [flags]` — start the server (current default behaviour)
- `caswhois migrate` — run database migrations
- `caswhois client` — launch caswhois-cli
- `caswhois version` — print version (same as --version)
- `caswhois install / uninstall / start / stop / restart / status` — service management
- `caswhois update [--check] [--version X]` — self-update
The flag interface must remain for backward compatibility; add subcommand routing on top.

Read: AI.md PART 7, 8
