# Project Audit

Started: 2026-11-27
Spec version: 87a390c7928e

## Issues Found

- [ ] Backup restore replaces the destination operator token with the sanitized blank value.
- [ ] MCP does not enforce linked-token read scope when listing or invoking tools.
- [ ] Container startup changes ownership of the `/config` and `/data` mount roots.
- [ ] IDEA route conformance checks miss unlisted routes and wildcard registrations hide route drift.
- [ ] Static assets lack the required CSS split, shared stamped template helper, and stamp-aware cache headers.
- [ ] HTML pages lack build-stamp ETags, no-store cache directives, and version-change cache purge behavior.
- [ ] Server page templates and shared CSS need a full PART 16 conformance pass.
- [ ] Database reconnect/migration retry and health registry aggregation need verification against the current requirements.
- [ ] Provider workflows, Docker files, Renovate settings, docs, and localization require final spec sync and verification.

## Sync Required

- [ ] Review README.md and docs/ against shipped behavior.
- [ ] Review Swagger/OpenAPI and GraphQL descriptions against current routes and auth behavior.

## Completed
