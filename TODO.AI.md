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

## [x] Implement well-known routes (AI.md PART 14)

Completed:
- `/.well-known/security.txt` - security disclosure policy
- `/.well-known/llms.txt` and `/llms.txt` - AI agent discovery
- `handleWellKnownNotFound` - 404 for unknown entries
- `wellKnownMethodCheck` - GET/HEAD enforcement (405 for others)

## [ ] Implement Swagger/OpenAPI endpoints (AI.md PART 14)

Required routes:
- `/server/docs/swagger` - Swagger UI (HTML, interactive REST explorer)
- `/api/swagger` - OpenAPI JSON spec (unversioned alias, direct serve not redirect)
- `/api/v1/server/swagger` - OpenAPI JSON spec (versioned)

Implementation:
- Generate OpenAPI 3.0 spec from handler annotations or manual spec
- Embed Swagger UI assets in binary
- Serve JSON spec at `/api/swagger` and `/api/v1/server/swagger`
- Serve Swagger UI at `/server/docs/swagger`

Read: AI.md PART 14

## [ ] Implement GraphQL endpoints (AI.md PART 14)

Required routes:
- `/server/docs/graphql` - GraphiQL UI (HTML, interactive explorer)
- `/api/graphql` - GraphQL POST endpoint (unversioned alias)
- `/api/v1/server/graphql` - GraphQL POST endpoint (versioned)

Implementation:
- Define GraphQL schema matching REST API
- Implement resolvers for whois queries
- Embed GraphiQL UI assets
- Serve GraphQL at `/api/graphql` and `/api/v1/server/graphql`
- Serve GraphiQL at `/server/docs/graphql`

Read: AI.md PART 14
