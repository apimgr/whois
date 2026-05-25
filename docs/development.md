# Development Guide

## Getting Started

### Prerequisites

- **Docker** (required - NEVER build on host)
- **Git** (for version control)
- **Make** (for build automation)
- **Text editor** (VS Code, Vim, etc.)

**Important:** All Go builds MUST use Docker. Never install Go locally or run `go build` on the host machine.

### Clone Repository

```bash
git clone https://github.com/casapps/caswhois.git
cd caswhois
```

### Project Structure

```
caswhois/
├── .github/workflows/    # CI/CD workflows
├── .claude/rules/        # AI assistant rules
├── docker/               # Docker configuration
│   ├── Dockerfile        # Standard image
│   └── docker-compose.*.yml
├── docs/                 # ReadTheDocs documentation
├── src/                  # Go source code
│   ├── main.go          # Server entry point
│   ├── client/          # CLI client
│   ├── config/          # Configuration
│   ├── server/          # HTTP server
│   ├── db/              # Database
│   ├── security/        # Authentication & crypto
│   └── ...
├── tests/               # Test files
├── scripts/             # Utility scripts
├── AI.md                # Complete specification (55k+ lines)
├── IDEA.md              # Project-specific details
├── README.md            # Project overview
├── Makefile             # Build automation
└── go.mod               # Go dependencies
```

## Building

### Development Build

Quick build for testing (no version info):

```bash
make dev
```

Output: `binaries/caswhois` (local platform only)

### Local Platform Build

Build for local platform with version info:

```bash
make local
```

Output: `binaries/caswhois-{os}-{arch}`

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

```bash
make docker
```

Builds both standard (Alpine) and AIO (all-in-one) images.

## Testing

### Run Tests

**Always use containers for testing:**

```bash
make test
```

This runs tests in a Docker container with:
- CGO_ENABLED=0
- Coverage measurement
- Race detection

### Test Structure

```
tests/
├── run_tests.sh       # Main test runner (auto-detects environment)
├── docker.sh          # Docker-based tests
├── incus.sh           # Incus-based tests (full OS testing)
└── integration/       # Integration tests
```

### Writing Tests

```go
package whois_test

import (
    "testing"
    "github.com/casapps/caswhois/src/whois"
)

func TestParseDomain(t *testing.T) {
    domain := "example.com"
    result, err := whois.ParseDomain(domain)
    
    if err != nil {
        t.Fatalf("ParseDomain failed: %v", err)
    }
    
    if result.Domain != domain {
        t.Errorf("Expected %s, got %s", domain, result.Domain)
    }
}
```

### Test Coverage

Coverage is automatically measured during `make test`:

```bash
# View coverage report
make test
# Output: PASS coverage: 82.5% of statements
```

Target: >80% coverage

## Running the Server

### Development Mode

```bash
# Using Docker Compose
docker compose -f docker/docker-compose.dev.yml up

# Using binaries (in container)
docker run --rm -it \
  -v $(pwd)/binaries:/app \
  -v /tmp/caswhois-dev:/config \
  -p 64580:64580 \
  alpine:latest \
  /app/caswhois --mode development --config /config
```

### Debug Mode

```bash
caswhois --debug --mode development
```

Enables:
- Verbose logging
- Debug endpoints (`/debug/pprof/`)
- Stack traces in errors
- Request/response logging

## Code Style

### Go Code Standards

Follow these conventions:

1. **Format code:** `gofmt` (automatic in CI)
2. **Naming:** camelCase for unexported, PascalCase for exported
3. **Comments:** Document all exported functions
4. **Error handling:** Always check errors, wrap with context
5. **No naked returns:** Always explicit `return`

### Example Function

```go
// HashPassword generates an Argon2id hash of the password.
// Returns error if password is empty or hashing fails.
func HashPassword(password string) (string, error) {
    if password == "" {
        return "", errors.New("password cannot be empty")
    }
    
    // Generate salt
    salt := make([]byte, SaltLen)
    if _, err := rand.Read(salt); err != nil {
        return "", fmt.Errorf("generate salt: %w", err)
    }
    
    // Hash with Argon2id
    hash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
    
    // Return PHC format
    return formatPHC(salt, hash), nil
}
```

### Code Review Checklist

- [ ] CGO_ENABLED=0 enforced
- [ ] No bcrypt usage (use Argon2id)
- [ ] No hardcoded secrets
- [ ] Errors properly wrapped
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Linter passes

## Database Migrations

### Migration Files

Migrations are embedded in the binary:

```go
//go:embed migrations/*.sql
var migrations embed.FS
```

### Create Migration

1. Create file: `src/db/migrations/001_create_tables.sql`
2. Write migration:

```sql
-- Migration 001: Create initial tables
-- Date: 2025-02-05

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_admins_username ON admins(username);
CREATE INDEX idx_admins_email ON admins(email);
```

3. Migrations run automatically on server start

### Rollback

Migrations do NOT support automatic rollback. Create a new migration to reverse changes:

```sql
-- Migration 002: Rollback migration 001
DROP TABLE IF EXISTS admins;
```

## Configuration

### Development Config

Create `config/dev.yml`:

```yaml
server:
  port: 64580
  address: 127.0.0.1
  mode: development
  admin_path: admin

database:
  type: sqlite
  path: /data/dev.db

logging:
  level: debug
  format: text
  output: stdout

ssl:
  enabled: false

email:
  enabled: false
```

### Environment Variables

```bash
export CASWHOIS_SERVER_MODE=development
export CASWHOIS_SERVER_PORT=8080
export CASWHOIS_DATABASE_PATH=/tmp/dev.db
export CASWHOIS_LOGGING_LEVEL=debug
```

## Debugging

### Using Delve (Go Debugger)

```bash
# In Docker container
docker run --rm -it \
  -v $(pwd):/app \
  -p 64580:64580 \
  -p 2345:2345 \
  golang:alpine \
  sh -c "cd /app && go install github.com/go-delve/delve/cmd/dlv@latest && dlv debug --headless --listen=:2345 --api-version=2 ./src"
```

Connect from VS Code:

```json
{
  "type": "go",
  "request": "attach",
  "mode": "remote",
  "remotePath": "/app",
  "port": 2345,
  "host": "localhost"
}
```

### Logging

Add debug logging:

```go
import "log/slog"

slog.Debug("Processing request",
    "method", r.Method,
    "path", r.URL.Path,
    "user_agent", r.UserAgent(),
)
```

### Profiling

Enable profiling in development mode:

```
/debug/pprof/          # Index
/debug/pprof/heap      # Memory allocation
/debug/pprof/goroutine # Goroutines
/debug/pprof/profile   # CPU profile
```

Analyze with `go tool pprof`:

```bash
go tool pprof http://localhost:64580/debug/pprof/heap
```

## Contributing

### Workflow

1. **Fork repository**
2. **Create feature branch:** `git checkout -b feature/my-feature`
3. **Make changes** (follow spec in AI.md)
4. **Test:** `make test`
5. **Commit:** Clear, descriptive messages
6. **Push:** `git push origin feature/my-feature`
7. **Create pull request**

### Commit Messages

Format:

```
type(scope): short description

Longer description if needed.

Fixes #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring
- `chore`: Build/tooling

Example:

```
feat(whois): add ASN lookup support

Implements ASN WHOIS lookup with automatic server detection.
Supports AS prefix and bare number formats.

Fixes #45
```

### Pull Request Guidelines

- **Title:** Clear, descriptive
- **Description:** What, why, how
- **Tests:** All tests pass
- **Coverage:** No decrease in coverage
- **Documentation:** Updated if needed
- **Breaking changes:** Clearly marked
- **Spec compliance:** Follows AI.md exactly

## Continuous Integration

### GitHub Actions

Four workflows run automatically:

1. **Release** (tags): Build all platforms, create release
2. **Beta** (beta branch): Pre-release builds
3. **Daily** (main/master + schedule): Nightly builds
4. **Docker** (all branches + tags): Multi-arch images

### Local CI Testing

Test workflows locally with `act`:

```bash
# Install act
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run release workflow
act push -W .github/workflows/release.yml
```

## Documentation

### Building Docs Locally

```bash
# Install dependencies
pip install -r docs/requirements.txt

# Serve docs
mkdocs serve

# Visit http://localhost:8000
```

### Writing Documentation

- Use Markdown
- Follow MkDocs Material conventions
- Include code examples
- Keep language clear and concise
- Test all examples

### Updating API Docs

When adding/changing endpoints:

1. Update `docs/api.md`
2. Update OpenAPI spec (auto-generated)
3. Update GraphQL schema
4. Add examples

## Performance Optimization

### Profiling

```bash
# CPU profile (30 seconds)
curl http://localhost:64580/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

# Memory profile
curl http://localhost:64580/debug/pprof/heap > mem.prof
go tool pprof mem.prof
```

### Benchmarks

```go
func BenchmarkHashPassword(b *testing.B) {
    password := "testpassword123"
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        security.HashPassword(password)
    }
}
```

Run benchmarks:

```bash
go test -bench=. -benchmem ./src/security
```

## Common Issues

### "Port already in use"

```bash
# Find process using port
lsof -i :64580

# Kill process
kill -9 <PID>
```

### "Permission denied"

Ensure Docker has proper permissions:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### "Build fails"

1. Clean build cache: `make clean`
2. Update dependencies: `go mod tidy` (in Docker)
3. Check Go version matches CI

### "Tests fail in CI but pass locally"

- Check timezone issues (use UTC)
- Check file system differences
- Check environment variables

## Useful Commands

```bash
# Clean all build artifacts
make clean

# Run linter
make lint

# Generate mocks
make mocks

# Update dependencies
make deps

# Format code
make fmt

# Security scan
make security
```

## Resources

- **Specification:** `AI.md` (complete implementation spec)
- **Project Details:** `IDEA.md` (project-specific features)
- **API Docs:** `/openapi` (interactive Swagger)
- **GraphQL:** `/graphql` (interactive playground)
- **Metrics:** `/metrics` (Prometheus format)

## Getting Help

- **Read the spec:** AI.md has 55k+ lines covering everything
- **Check existing code:** Look for similar implementations
- **Ask questions:** Create GitHub issue or discussion
- **Review PRs:** See how others implement features

## License

MIT License - see LICENSE.md for details.
