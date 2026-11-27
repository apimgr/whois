# Development

caswhois is a Go project. Builds and tests run inside Docker through the repository Makefile; do not run Go build or test commands directly on the local machine.

## Prerequisites

- Latest stable Go release (used inside the project's Go container)
- Make
- Docker for the Makefile build and test targets

## Repository layout

- `src/` contains the server, CLI, configuration, database, WHOIS/RDAP, and supporting packages.
- `docker/` contains the image, compose files, and container entrypoint.
- `docs/` contains MkDocs/ReadTheDocs documentation.
- `src/server/template/` contains embedded server-rendered HTML pages.

## Build

```bash
make dev       # quick binaries in a project-scoped temporary directory
make local     # current-platform binaries in binaries/ (clean removes build dirs)
make build     # release binaries for the configured platform matrix
make docker    # build the production container image
```

Build outputs are generated artifacts and should not be committed. Run build commands from the repository root; the Makefile runs Go tooling inside Docker.

## Validation

```bash
make test      # Go quality gates, unit tests, coverage, locale checks, and basic Docker integration
```

`make test` runs `go fmt`, `go vet`, `staticcheck`, `govulncheck`, ShellCheck, `shfmt -d`, license verification, the Go tests, the coverage threshold, and locale parity validation inside the Go container. It then runs the basic Docker binary and HTTP integration suite. Test output stays in the project-scoped temporary directory.

License verification scans the Go packages shipped from `src/` and rejects GPL, AGPL, and LGPL dependencies. A reviewed exception must be recorded in `.github/license-overrides.txt`; the generated license report and third-party license texts are kept in a private temporary directory and removed when the check finishes. GitHub, GitLab, Gitea, and Forgejo CI run the same verification script.

The basic binary suite can also be run on its own, and the full browser E2E and init-system suites remain explicit:

```bash
./tests/run_tests.sh   # basic Docker tier
./tests/docker.sh      # same tier directly
./tests/incus.sh       # full init-system integration, both modes by default
./tests/incus.sh systemd  # Debian with systemd only
./tests/incus.sh openrc   # Alpine with OpenRC only
```

After building or pulling an image, check its required runtime packages and Tor
health with `./tests/docker.sh --image-check IMAGE`. `make docker` builds and
loads the host-platform image locally without publishing it, then runs this
check. Image CI jobs publish multi-architecture standard and development images
and run the same check. The check waits up to `TOR_BOOTSTRAP_TIMEOUT` seconds (default `180`); set
`REQUIRE_OVERLAY=1` when Tor must become healthy even without outbound network.

The Go test suite is colocated with packages under `src/`. Browser E2E checks
are available through `./tests/e2e.sh`; they require Docker and Chromium. The
suite runs SSR, no-JavaScript, and full-browser tiers against a fresh database
and a local RDAP fixture, with the runner network isolated from the internet. It
checks real WHOIS results, primary and linked owner-token issue/list/reveal/
rotate/revoke behavior, MCP calls with primary and linked tokens, language
switching, API documentation parity, CSRF rejection, internal-link crawling,
themed error pages, static assets, responsive layout, and accessibility through
the vendored axe-core script. The layout contract visits registered pages in
dark, light, and auto themes, in both text directions, at mobile and desktop
viewports; component-gallery checks cover the full breakpoint matrix. Optional
filters are available for focused investigation:

```bash
E2E_RUN=TestTier2NoJavaScriptWHOISForm ./tests/e2e.sh
E2E_PAGE=/server/docs ./tests/e2e.sh
```

Keep test and build output in the project-scoped temporary locations selected by
the Makefile and E2E runner.

## Running locally

Use the development compose file from a project-scoped temporary directory so runtime config and data stay out of the source tree:

```bash
mkdir -p "${TMPDIR:-/tmp}/apimgr"
TASK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/apimgr/caswhois-XXXXXX")
mkdir -p "$TASK_DIR/volumes/config" "$TASK_DIR/volumes/data"
cp docker/docker-compose.dev.yml "$TASK_DIR/docker-compose.yml"
cd "$TASK_DIR" && docker compose up
```

## Documentation

The documentation site uses MkDocs Material and ReadTheDocs. Keep `mkdocs.yml` navigation aligned with the files in `docs/`. See [Translating](translating.md) before changing locale strings and [API Reference](api.md) when routes or response behavior change.
