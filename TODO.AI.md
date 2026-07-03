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

## [x] Implement Swagger/OpenAPI endpoints (AI.md PART 14)

Completed:
- `src/server/swagger.go` — OpenAPI 3.0.3 spec generation and Swagger UI handler
- `/server/docs/swagger` — Swagger UI with dark theme (CDN with SRI hashes)
- `/api/swagger` — OpenAPI JSON spec (unversioned)
- `/api/v1/server/swagger` — OpenAPI JSON spec (versioned)
- `src/server/swagger_test.go` — unit tests for spec generation and handlers

Read: AI.md PART 14

## [x] Implement GraphQL endpoints (AI.md PART 14)

Completed:
- `src/server/graphql.go` — GraphQL POST handler with introspection support
- `/server/docs/graphql` — GraphiQL UI with dark theme (CDN with SRI hashes)
- `/api/graphql` — GraphQL POST endpoint (unversioned)
- `/api/v1/server/graphql` — GraphQL POST endpoint (versioned)
- Resolvers: health, stats, whois queries
- `src/server/graphql_test.go` — unit tests for all query types

Read: AI.md PART 14
