# Project SPEC

Project: caswhois
Role: Efficient loader for AI.md

⚠️ **THIS FILE IS AUTO-LOADED EVERY CONVERSATION. FOLLOW IT EXACTLY.** ⚠️

Purpose:
- This file is a short loader for the most important rules
- `AI.md` is the full source of truth
- For complete details, read the referenced PARTs in `AI.md`

## Asking Questions

- **Default to continuing work** — do not stop just to ask whether to continue; if the next step is implied by spec, current task, or findings, continue
- **Never guess** — if the answer cannot be determined from `AI.md`, `IDEA.md`, the codebase, or repo state **and** the missing information materially changes behavior, scope, or safety, ASK
- **Do NOT ask for permission to keep going** — continue until the task is complete, blocked by a real decision, or the user explicitly asks to pause
- **Question mark = question** — when user ends with `?`, answer/clarify, don't execute

**Ask only when at least one of these is true:**
1. A required business/product decision is missing
2. Two or more reasonable implementations would produce materially different behavior
3. The action is destructive, irreversible, or impacts production/user data
4. The spec explicitly says to ask or confirm
5. The user explicitly requested a plan, pause, or checkpoint before execution

## Before ANY Code Change

1. Have I read the relevant PART in AI.md? (If no → read it)
2. Does this follow the spec EXACTLY? (If unsure → check spec)
3. Am I guessing or do I KNOW from the spec? (If guessing → read spec)
4. Would this pass the compliance checklist? (AI.md FINAL section)

**WHEN IN DOUBT: READ THE SPEC. DO NOT GUESS.**

## Binary Terminology
- **server** = `caswhois` (main binary, runs as service)
- **client** = `caswhois-cli` (REQUIRED companion, CLI/TUI)

## Key Placeholders
- `{project_name}` = caswhois
- `{project_org}` = casapps
- `{binary}` = caswhois
- `{binary_cli}` = caswhois-cli
- `{module}` = github.com/casapps/caswhois
- `{api_version}` = v1

## NEVER Do (Top 19) — VIOLATIONS ARE BUGS
1. Use bcrypt for config/backup passwords → Use Argon2id
2. Put Dockerfile in root → `docker/Dockerfile`
3. Use CGO → CGO_ENABLED=0 always
4. Hardcode dev values → Detect at runtime
5. Use external cron → Internal scheduler (PART 18)
6. Store config/backup passwords plaintext → Argon2id (API tokens use SHA-256)
7. Create premium tiers → All features free, no paywalls
8. Use Makefile in CI/CD → Explicit commands only
9. Guess or assume values a command can produce → Run the command or read spec
10. Skip platforms → Build all 8 (linux/darwin/windows × amd64/arm64)
11. Client-side rendering (React/Vue) → Server-side Go templates
12. Require JavaScript for core features → Progressive enhancement only
13. Let long strings break mobile → Use word-break CSS
14. Skip validation → Server validates EVERYTHING
15. Implement without reading spec → Read relevant PART first
16. Modify AI.md content → READ-ONLY SPEC; project changes go in IDEA.md
17. Edit `## Project variables` in IDEA.md without confirming with the user
18. Read an image larger than 1000×1000 directly → Resize first
19. Use a non-conforming IDEA.md → Migrate it before doing anything else

## ALWAYS Do — NON-NEGOTIABLE
1. Read AI.md before implementing ANY feature
2. Server-side processing (server does the work, client displays)
3. Mobile-first responsive CSS
4. All features work without JavaScript
5. Tor hidden service support (auto-enabled if Tor found)
6. Built-in scheduler, GeoIP, metrics, email, backup, update
7. All settings configurable via config file (server.yml)
8. Client binary for ALL projects
9. Commit often via `gitcommit --dir {dir} all` — small, focused commits

## File Locations
- Config: `{config_dir}/server.yml`
- Data: `{data_dir}/`
- Logs: `{log_dir}/`
- Source: `src/`
- Docker: `docker/`
- Full spec: `AI.md` ← **SOURCE OF TRUTH**

## Where to Find Details
- AI behavior rules: `.claude/rules/ai-rules.md` (PART 0, 1)
- Project structure: `.claude/rules/project-rules.md` (PART 2, 3, 4)
- Config rules: `.claude/rules/config-rules.md` (PART 5, 6, 12)
- Binary/build rules: `.claude/rules/binary-rules.md` (PART 7, 8)
- Backend/DB/security: `.claude/rules/backend-rules.md` (PART 9, 10, 11)
- API routes: `.claude/rules/api-rules.md` (PART 13, 14, 15)
- Frontend/templates: `.claude/rules/frontend-rules.md` (PART 16)
- Features (email/scheduler/geoip/metrics/backup/update): `.claude/rules/features-rules.md` (PART 17–22)
- Service/daemon: `.claude/rules/service-rules.md` (PART 23, 24)
- Makefile: `.claude/rules/makefile-rules.md` (PART 25)
- Docker: `.claude/rules/docker-rules.md` (PART 26)
- CI/CD: `.claude/rules/cicd-rules.md` (PART 27 — SKIPPED until user says otherwise)
- Testing/docs/i18n: `.claude/rules/testing-rules.md` (PART 28, 29, 30)
- Tor hidden service: `AI.md` PART 31 (no rules file yet)
- CLI client (caswhois-cli): `AI.md` PART 32 (no rules file yet)

## Current Project State
- Last read AI.md: 2026-06-02
- Current task: Spec compliance — CLAUDE.md + IDEA.md + Makefile fixes
- Relevant PARTs: 0, 1, 7, 8, 18, 25, 33
- Test coverage: below 100% target (make test enforces 100%)
- Build image: casjaysdev/go:latest (NOT golang:alpine)
- PART 27: Skipped — no CI/CD workflow files
