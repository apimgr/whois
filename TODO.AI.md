# AI implementation backlog

AI.md remains authoritative; this file tracks implementation work only.

## P1 — Test and delivery requirements

- [ ] Verify all provider workflows, Docker files, and Renovate configuration against AI.md PART 26–27.
- [ ] Retry failed database migrations from the self-healing reconnect path and implement the health registry and aggregation rules.
- [ ] Resolve the PART 21 API-project restore conflict recorded in `~/Projects/github/apimgr/TODO.API.md`, then implement the applicable restore contract.
- [ ] Verify API token scopes, backup secret sanitization/restore, toast timing, local Docker behavior, compose mounts, Windows SQLite paths, and schema/route conformance against the exact AI.md requirements.
