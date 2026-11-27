# AI implementation backlog

AI.md remains authoritative; this file tracks implementation work only.

## P1 — Test and delivery requirements

- [ ] Verify all provider workflows, Docker files, and Renovate configuration against AI.md PART 26–27.
- [ ] Keep the listener available when database startup or migrations fail; retry connection and schema migrations through the configured self-healing loop.
- [ ] Implement cached dataset/dependency health checks and the PART 13 status aggregation and output ordering.
- [ ] Verify API token scopes, backup secret sanitization/restore, toast timing, asset versioning, local Docker behavior, compose mounts, Windows SQLite paths, and schema/route conformance against the exact AI.md requirements.
- [ ] Complete page/template and documentation alignment, then run the full Docker-backed build, test, lint, and provider CI checks.
