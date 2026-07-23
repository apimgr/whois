# TODO.AI.md

Line-by-line audit vs AI.md (source of truth). Track until each item is fixed
and verified. Delete this file once everything below is complete and committed.

## Done (this pass, mechanical)
- [x] PART 2: added missing LICENSE.md attributions (ProtonMail/go-crypto,
      redis/go-redis/v9, tursodatabase/libsql-client-go)
- [x] PART 3: untracked `vendor/` from git, added to `.gitignore`

## Wave 1 — DONE, verified via git diff + Docker build (gofmt clean, go build ./... exit 0)
- [x] PART 4: OS-specific path resolution (macOS/BSD/Windows branches added
      in `src/config/config.go`, `src/main.go`)
- [x] PART 13-15: `/api/healthz` alias, `DetectClientType` structure,
      pagination envelope field names, swagger/graphql moved to own packages
      (`src/graphql/`, `src/swagger/`)
- [x] PART 17-22: email template set, scheduler CLI subcommand + config +
      retry policy — metrics config buckets: NEEDS FOLLOW-UP, see below
- [x] PART 23-27: privilege escalation fallback chain (su/pkexec/doas),
      SysVinit installer, OpenRC/SysV service control, Dockerfile `ENV MODE`,
      production compose DEBUG/MODE, ci.yml job graph, secret-scan tool,
      image-scan job (beta.yml/daily.yml correctly left out — AI.md line
      32982 marks them optional)

### Follow-up (resolved)
- [x] PART 20: `src/metrics/metrics.go` confirmed already wired to
      `cfg.DurationBuckets`/`cfg.SizeBuckets` with spec-matching defaults —
      no action needed

## Wave 2 — dispatched to fix agents (in progress)
- [x] PART 16a (agent a8157f6dcb2ec037c): PWA (manifest/service worker/
      icons), toast/modal system, theme CSS custom-property mechanism
      (dark default), accessibility (skip link, focus, alt, ARIA),
      lang/dir attribute mechanism — verified via git diff, real changes
- [x] PART 16b round 2 (agent acaefc972328a04af): verified via git diff —
      footer now wired into all 6 templates, csrf.go added + wired into
      graphql form, AnnouncementConfig struct added to config.go. Still
      missing after 2 rounds: standard pages (privacy/contact/help/terms),
      cookie consent banner, announcement rendering (struct exists but
      never read/rendered). Handed off to a fresh agent (a93899345c3845669)
      for these 3 remaining items — in progress.
- [x] PART 5 remainder + PART 32 client (agent adfe265ca9097af2d): DONE,
      verified via git diff (956 insertions across 8 files). Client
      --output json/table/plain, --token-file, --shell completions/init/
      help all wired; config.go Format default fixed to "table". PART 5
      maintenance/server.yaml→.yml/init-only-env/SSL-hot-reload done in
      an earlier segment. CORS config-shape fix deliberately deferred by
      the agent (overlaps PART 16 middleware.go) — tracked below as Wave 3.

## Wave 3 — CORS config-shape fix — DONE, verified via Docker gofmt/build/vet/test
- [x] `src/config/config.go`, `src/config/generate.go`, `src/server/middleware.go`,
      `src/server/server.go`, `src/server/coverage_test.go`: `Web.CORS string`
      replaced with `server.cors.allowed_origins []string` + `allow_credentials`
      + `max_age` per AI.md lines 24924-24993, including the 4-step allow-list
      resolution order and credentials-only-with-explicit-origin rule.

## PART 16 — static pages, cookie consent banner, announcement rendering — DONE

## Bugs found while verifying the CORS refactor via `make test` (AI.md is source
      of truth — code fixed to match, not the other way around)
- [x] `src/db/sqlite.go`, `src/scheduler/scheduler.go`: `scheduler_tasks` table
      used non-spec columns `task_id`/`task_name`; AI.md PART 10 (lines
      11628-11646) specifies `id`/`name`. Renamed schema + all queries.
      `scheduler_history.task_id` (its own column, FK to `scheduler_tasks.id`)
      was already correct and left unchanged.
- [x] `src/scheduler/scheduler_test.go`: test fixture was missing the
      `scheduler_history` table, causing WARN noise; added.
- [x] `src/server/graphql.go`: `handleGraphQL` always returned HTTP 200 even
      when the request `query` field was empty; now returns 400 with the
      standard `{"ok":false,...}` error envelope for an empty/missing query,
      per PART 14 Error Response Format, before falling through to
      `executeGraphQL`/`WriteResponse` for well-formed queries.
- [x] i18n: propagated `consent.preferences_heading`, `consent.essential_label`,
      `consent.essential_desc`, `consent.always_on`, `consent.preferences_label`,
      `consent.preferences_desc`, `consent.analytics_label`,
      `consent.analytics_desc`, `consent.save_preferences`, and
      `site_banner.dismiss_aria` to `es`/`zh`/`fr`/`ar`/`de`/`ja` locale files
      (previously only in `en.json`). Verified key-set parity against `en.json`.

## Still open — not yet fixed (found but out of scope for this pass)
- [ ] `src/server/errors.go:138`: `htmlResponseTmpl.Execute(w, "404 — page not
      found")` passes a raw string instead of the expected `responsePageData`
      struct — likely renders incorrectly or panics; needs its own fix pass.
- [ ] `src/config/generate.go`: generated `web:` config section doesn't
      document the `footer`/`announcements` keys that `config.go` now supports.

## Awaiting audit results (not yet fixable — spec comparison incomplete;
      dispatched audits never returned a result across multiple sessions)
- [ ] PART 6-8 (remainder of original PART 5-8 dispatch)
- [ ] PART 28 (Testing)
- [ ] PART 29-30 (Docs/i18n/a11y)

## Judgment calls flagged by auditors (spec wins per standing directive — fix
      to match AI.md unless noted otherwise)
- PART 32 `--output`: spec says `json|table|plain`; code has
  `json|raw|text` — fixing to match spec exactly
