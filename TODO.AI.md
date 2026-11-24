# AI implementation backlog

The following applicable AI.md requirements remain after comparing the specification with the repository. AI.md remains authoritative; this file tracks implementation work only.

## P0 — Data integrity and security

- [ ] Design and implement the AI.md owner/token model (`owners`, encrypted token copies, primary/linked scopes, ownership-aware resources, token management API and pages). Resolve legacy `api_tokens` migration before changing persisted token behavior: the existing schema binds tokens to individual resources and contains no owner identity.
- [ ] Move generated installation/application secrets to `app_secrets` and complete secret generation, rotation, audit, backup, and restore behavior in AI.md PART 10–11.
- [ ] Implement the coordinated security disclosure flow from AI.md PART 11, including `security.txt`, one-shot security IDs, typed security reports, encrypted storage, operator review, and thank-you page.

## P1 — Required server behavior and pages

- [ ] Implement the AI.md token preferences page and API routes, owner-cookie lifecycle, CSRF-protected actions, one-use reveal flow, and linked token lifecycle.
- [ ] Implement required privacy preferences and synchronization routes/pages, and reconcile all server-rendered pages with the shared AI.md PART 16 shell, accessibility, localization, consent, themes, and responsive layout requirements.
- [ ] Implement the AI.md contact/report workflows, including typed submissions, anti-spam controls, configured captcha/review paths, and email delivery; preserve the project's documented contact behavior.
- [ ] Implement the AI.md MCP endpoint, auth requirements, tool surface, and MCP help page.

## P1 — Test and delivery requirements

- [ ] Reconcile `tests/run_tests.sh`, `tests/docker.sh`, and `tests/incus.sh` with AI.md PART 28; add the required standalone `tests/e2e.sh` and supported systemd/OpenRC coverage.
- [ ] Complete the Makefile requirements in AI.md PART 25, including the required target behavior and release checks.
- [ ] Validate and reconcile all provider workflows, Docker files, and Renovate configuration with AI.md PART 26–27.

## P2 — Documentation and cross-cutting requirements

- [ ] Reconcile README.md and every current `docs/*.md` page with AI.md PART 29 and the implemented product behavior; ensure the MkDocs navigation covers all required documentation.
- [ ] Verify every applicable AI.md requirement across the remaining applicable parts (project structure, paths, config, CLI/client, error handling, API, TLS, email, scheduler, GeoIP, metrics, backup/restore, update, service support, i18n/accessibility, and Tor/I2P) against current code and implement verified gaps.
- [ ] Reconcile stale project audit/backlog artifacts against AI.md and actual behavior; remove or correct only items verified as stale under the project's TODO rules.
