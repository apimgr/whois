# Development Guide

## Getting Started

### Prerequisites

- **Docker** (required — NEVER build on host)
- **Git** (for version control)
- **Make** (for build automation)

**Important:** All Go builds MUST use Docker (`casjaysdev/go:latest`). Never install Go locally or run `go build`/`go test`/`go run` on the host machine.

### Clone Repository

```bash
git clone https://github.com/apimgr/whois.git
cd whois
```

### Project Structure

```
caswhois/
├── .github/workflows/    # CI/CD workflows
├── .claude/rules/        # AI assistant rules
├── docker/               # Docker configuration
│   ├── Dockerfile        # Production image (Alpine, :latest)
│   ├── docker-compose.yml      # Production compose (HUMAN USE ONLY)
│   ├── docker-compose.dev.yml  # Development compose (HUMAN USE ONLY)
│   ├── docker-compose.test.yml # Test compose (AI/AUTOMATED ONLY)
│   └── rootfs/           # Build-time container filesystem overlay
├── docs/                 # MkDocs documentation
├── src/                  # Go source code
│   ├── main.go           # Server entry point
│   ├── client/           # CLI client (caswhois-cli)
│   ├── config/           # Configuration
│   ├── server/           # HTTP server
│   ├── db/               # Database
│   ├── security/         # Authentication and crypto
│   └── ...
├── tests/                # Integration test scripts
│   ├── run_tests.sh      # Main test runner
│   ├── docker.sh         # Docker-based tests
│   └── incus.sh          # Incus/VM-based tests
├── AI.md                 # Complete specification
├── IDEA.md               # Project-specific details
├── README.md             # Project overview
├── Makefile              # Build automation
└── go.mod                # Go dependencies
```

## Building

All builds run inside `casjaysdev/go:latest` via Makefile targets. Never run `go build` directly.

### Quick Dev Build

Fast build with no version info, output to a temp directory:

```bash
make dev
```

Output: `/tmp/apimgr/caswhois-XXXXXX/caswhois` (random temp dir, printed on completion)

### Local Platform Build

Build for the current platform with full version info:

```bash
make local
```

Output: `binaries/caswhois`

### Full Release Build

Build for all 8 platforms:

```bash
make build
```

Output: `binaries/caswhois-{os}-{arch}` for:

- linux/amd64, linux/arm64
- darwin/amd64, darwin/arm64
- windows/amd64, windows/arm64 (.exe)
- freebsd/amd64, freebsd/arm64

### Docker Image

Build the production container image locally (current arch):

```bash
make docker
```

Builds `ghcr.io/apimgr/caswhois:{version}` using the multi-stage `docker/Dockerfile`.
Multi-arch push to the registry is handled by the CI workflow on release.

## Testing

### Run Tests

Always use the Makefile — tests run inside Docker:

```bash
make test
```

Runs `go test ./...` with coverage measurement inside `casjaysdev/go:latest`. Coverage output
goes to `/tmp/apimgr/caswhois-XXXXXX/coverage.out` (never in the project tree).

### Test Structure

```
src/
└── *_test.go             # Unit tests (co-located with packages)

tests/
├── run_tests.sh          # Main test runner (orchestrates all scripts)
├── docker.sh             # Docker-based integration tests
└── incus.sh              # Incus/VM-based tests (service install, systemd)
```

Unit tests cover package logic, pure functions, validation, parsing, config loading,
and handler logic via `net/http/httptest`. Integration tests run a real server and
make HTTP requests against it.

### Test Coverage

Coverage gate: ≥80%. `make test` exits non-zero if coverage falls below threshold.

### Writing Unit Tests

```go
package whois_test

import (
    "testing"
    "github.com/apimgr/whois/src/whois"
)

func TestParseDomain(t *testing.T) {
    domain := "example.com"
    result, err := whois.ParseDomain(domain)
    if err != nil {
        t.Fatalf("ParseDomain failed: %v", err)
    }
    if result.Domain != domain {
        t.Errorf("expected %s, got %s", domain, result.Domain)
    }
}
```

## Running the Server

**Never run the binary directly on the host.** Use Docker or Incus.

### Using Docker Compose (Development)

Copy compose file to a temp directory first — never run from the project directory:

```bash
mkdir -p "${TMPDIR:-/tmp}/apimgr"
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/apimgr/caswhois-XXXXXX")
mkdir -p "$TEMP_DIR/volumes/config" "$TEMP_DIR/volumes/data"
cp docker/docker-compose.dev.yml "$TEMP_DIR/docker-compose.yml"
cd "$TEMP_DIR" && docker compose up
```

The server listens on `http://172.17.0.1:64580` (Docker bridge). Access it via:

```bash
curl -LSsf http://172.17.0.1:64580/server/healthz
```

### Using Docker Run

```bash
mkdir -p "${TMPDIR:-/tmp}/apimgr"
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/apimgr/caswhois-XXXXXX")
mkdir -p "$TEMP_DIR/config" "$TEMP_DIR/data"

docker run --rm -it \
  -v "$TEMP_DIR/config:/config:z" \
  -v "$TEMP_DIR/data:/data:z" \
  -p 172.17.0.1:64580:80 \
  ghcr.io/apimgr/caswhois:latest
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODE` | `development` | `production` or `development` |
| `DEBUG` | `false` | Enable debug endpoints |
| `TZ` | `America/New_York` | Timezone |
| `PORT` | `80` | Listen port (inside container) |
| `CONFIG_DIR` | `/config/caswhois` | Config directory |
| `DATA_DIR` | `/data/caswhois` | Data directory |
| `DATABASE_DIR` | `/data/db/sqlite` | SQLite directory |

## Code Style

### Go Code Standards

1. **Format:** `gofmt` (enforced in CI)
2. **Naming:** camelCase for unexported, PascalCase for exported; intent-revealing names (`GetUserByID` not `Get`)
3. **Comments:** Above the code, never inline; every exported symbol documented
4. **Error handling:** Always check errors; wrap with context: `fmt.Errorf("finding user: %w", err)`
5. **SQL:** Parameterized queries only — never string concatenation
6. **CGO:** Always `CGO_ENABLED=0` — no CGO permitted

### Example Function

```go
// HashPassword generates an Argon2id hash of the password.
// Returns error if password is empty or hashing fails.
func HashPassword(password string) (string, error) {
    if password == "" {
        return "", errors.New("password cannot be empty")
    }

    salt := make([]byte, SaltLen)
    if _, err := rand.Read(salt); err != nil {
        return "", fmt.Errorf("generate salt: %w", err)
    }

    hash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
    return formatPHC(salt, hash), nil
}
```

### Code Review Checklist

- [ ] `CGO_ENABLED=0` enforced
- [ ] No bcrypt — use Argon2id
- [ ] No hardcoded secrets
- [ ] Errors properly wrapped
- [ ] Tests added and updated
- [ ] Documentation updated
- [ ] Linter passes (`make lint`)

## Database Migrations

Migrations are embedded in the binary:

```go
//go:embed migrations/*.sql
var migrations embed.FS
```

Create a new migration file: `src/db/migrations/001_create_tables.sql`

```sql
-- Migration 001: Create initial tables

CREATE TABLE IF NOT EXISTS admins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE,
    email       TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_admins_username ON admins(username);
CREATE INDEX idx_admins_email ON admins(email);
```

Migrations run automatically on server start. Rollback by creating a new forward migration.

## Debugging

### Profiling

Enable in development mode (`DEBUG=true`). Access endpoints:

```
/debug/pprof/          # Index
/debug/pprof/heap      # Memory allocation
/debug/pprof/goroutine # Goroutines
/debug/pprof/profile   # CPU profile
```

Analyze:

```bash
go tool pprof http://172.17.0.1:64580/debug/pprof/heap
```

### Delve Debugger

Run inside `casjaysdev/go:latest`:

```bash
docker run --rm -it \
  -v $PWD:/app \
  -w /app \
  -p 172.17.0.1:2345:2345 \
  -e CGO_ENABLED=0 \
  casjaysdev/go:latest \
  sh -c "go install github.com/go-delve/delve/cmd/dlv@latest && dlv debug --headless --listen=:2345 --api-version=2 ./src"
```

Connect from VS Code (`launch.json`):

```json
{
  "type": "go",
  "request": "attach",
  "mode": "remote",
  "remotePath": "/app",
  "port": 2345,
  "host": "172.17.0.1"
}
```

### Structured Logging

```go
import "log/slog"

slog.Debug("processing request",
    "method", r.Method,
    "path", r.URL.Path,
    "user_agent", r.UserAgent(),
)
```

## Contributing

### Workflow

1. Fork repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Make changes following the spec in `AI.md`
4. Test: `make test` (must pass, ≥80% coverage)
5. Lint: `make lint`
6. Commit with descriptive message
7. Push and open pull request

### Pull Request Guidelines

- Title: clear and descriptive
- Description: what, why, how
- All tests pass
- No coverage decrease
- Documentation updated
- Breaking changes clearly marked
- Spec compliance: follows `AI.md` exactly

## Continuous Integration

Four workflows run automatically:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR | Build and test all platforms |
| `release.yml` | Version tag (`v*`, `*.*.*`) | Release builds, checksums, GitHub release |
| `docker.yml` | All branches + tags | Multi-arch container images to GHCR |
| `security.yml` | Push/PR | Secret scan, dependency audit, license check |

### Local CI Testing

Test workflows locally with `act`:

```bash
act push -W .github/workflows/ci.yml
```

## Documentation

### Building Docs Locally

```bash
pip install -r docs/requirements.txt
mkdocs serve
# Visit http://localhost:8000
```

### Updating API Docs

When adding or changing endpoints:

1. Update `docs/api.md`
2. Update Swagger annotations in handler source
3. Add request/response examples

## Useful Commands

```bash
make dev       # Quick build to temp dir
make local     # Build current platform to binaries/
make build     # Cross-platform build (all 8 targets)
make test      # Run tests with coverage gate
make lint      # Run linters (staticcheck, golangci-lint)
make docker    # Build production Docker image
make clean     # Remove binaries/ and releases/
```

## Resources

- **Specification:** `AI.md` (complete implementation spec)
- **Project details:** `IDEA.md` (project-specific features)
- **API docs:** `/server/docs/swagger` (interactive Swagger)
- **Metrics:** `/metrics` (Prometheus format)

## Common Issues

### Port already in use

```bash
lsof -i :64580
kill $PID
```

### Build fails

```bash
make clean
make build
```

### Tests fail in CI but pass locally

- Verify you ran tests inside Docker (`make test`), not on the host
- Check for timezone issues (container uses `TZ=America/New_York`)
- Check for missing environment variables

## License

MIT License — see `LICENSE.md` for details.
