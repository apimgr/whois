# AI implementation backlog

The following applicable AI.md requirements remain after comparing the specification with the repository. AI.md remains authoritative; this file tracks implementation work only.

## P0 — Data integrity and security

- [ ] Verify generated-secret lifecycle against AI.md PART 10–11, including rotation, audit, backup, restore, and expiry behavior; secret generation and rotation are implemented in `app_secrets`.
- [ ] Verify the implemented AI.md PART 11 security disclosure flow end to end, including `security.txt`, rotating security IDs, typed reports, encrypted storage, operator review, status links, retention, and thank-you page.
- [ ] Verify the implemented AI.md PART 10 SQLite concurrency contract, including independent writer/read-only handles, serialized writes with bounded retries, buffered hot counters, busy-wait metrics, and concurrent reader/writer behavior.
- [ ] Verify the implemented AI.md PART 31.2 I2P support end to end, including container-sensitive defaults, i2pd/SAM provider resolution, persisted eepsite identity, health/status, help-page content, scheduler health task, and image packages.

## P1 — Required server behavior and pages

- [ ] Verify token management, privacy preferences, and synchronization routes/pages against AI.md PART 8/16; implementations exist, but require full conformance and end-to-end coverage review.
- [ ] Reconcile all server-rendered pages with the shared AI.md PART 16 shell, accessibility, localization, consent, themes, and responsive layout requirements.
- [ ] Verify the implemented AI.md contact/report workflows end to end, including typed submissions, anti-spam controls, configured captcha/review paths, and email delivery; preserve the project's documented contact behavior.
- [ ] Verify the implemented MCP endpoint, authentication, tool surface, and help page against AI.md PART 16, including the required conformance and end-to-end checks.

## P1 — Test and delivery requirements

- [ ] Reconcile `tests/run_tests.sh`, `tests/docker.sh`, `tests/incus.sh`, and the added `tests/e2e.sh` with AI.md PART 28; verify required supported systemd/OpenRC coverage.
- [ ] Verify the Makefile requirements in AI.md PART 25, including target behavior and release checks.
- [ ] Verify all provider workflows, Docker files, and Renovate configuration against AI.md PART 26–27.

## P2 — Documentation and cross-cutting requirements

- [ ] Complete reconciliation of README.md and every current `docs/*.md` page with AI.md PART 29 and implemented behavior; verify MkDocs navigation covers all required documentation.
- [ ] Verify every applicable AI.md requirement across the remaining applicable parts (project structure, paths, config, CLI/client, error handling, API, TLS, email, scheduler, GeoIP, metrics, backup/restore, update, service support, i18n/accessibility, and Tor/I2P) against current code and implement verified gaps.
- [ ] Reconcile stale project audit/backlog artifacts against AI.md and actual behavior; remove or correct only items verified as stale under the project's TODO rules.
