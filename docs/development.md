# Development

caswhois is a Go project. Builds and tests run inside Docker through the repository Makefile; do not run Go build or test commands directly on the host.

## Repository layout

- `src/` contains the server, CLI, configuration, database, WHOIS/RDAP, and supporting packages.
- `docker/` contains the image, compose files, and container entrypoint.
- `docs/` contains MkDocs/ReadTheDocs documentation.
- `src/server/template/` contains embedded server-rendered HTML pages.

## Build

```bash
make dev       # quick binaries in a project-scoped temporary directory
make local     # current-platform binaries in binaries/
make build     # release binaries for the configured platform matrix
make docker    # build the production container image
```

`make build` and `make local` also update Go module metadata as part of their workflow. Build outputs are generated artifacts and should not be committed.

## Validation

```bash
make test      # Go tests, coverage threshold, and locale parity validation
make lint      # go vet and staticcheck in Docker
```

The project test suite is colocated with packages under `src/`. Keep test and build output in the project-scoped temporary locations selected by the Makefile.

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
