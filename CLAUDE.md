# caswhois — Claude Code Loader

> **Source of truth:** `AI.md` (read-only spec). This file is an efficient loader only.
> Never modify AI.md content. All implementation decisions come from AI.md.

## Quick Reference

| Need | Go to |
|------|-------|
| Project overview, features | `IDEA.md` |
| Full spec & rules | `AI.md` |
| Rule files (by topic) | `.claude/rules/` |
| Open tasks | `TODO.AI.md` (if present) |

## Non-Negotiable Rules (from AI.md PART 1)

- **File-Only Configuration** — no admin web UI, no runtime config mutation via API
- **Token-only auth** — no passwords, no sessions, no user accounts
- **SQLite/libsql only** — no PostgreSQL, no MySQL
- **CGO_ENABLED=0** — always; single static binary
- **No feature gating** — all features free, no premium tier
- **Built-in scheduler** — no external cron, no systemd timers for tasks
- **Server-side templates** — no client-side rendering (React, Vue, etc.)
- **PART 27 skipped** — no CI/CD workflow files until user says otherwise

## Project Variables

| Variable | Value |
|----------|-------|
| `{project_name}` | `caswhois` |
| `{project_org}` | `casapps` |
| `{module}` | `github.com/casapps/caswhois` |
| `{binary}` | `caswhois` |
| `{api_version}` | `v1` |

## Key Paths

```
src/            Go source (main.go at root, packages in subdirs)
src/config/     ServerConfig + file-only config loading
src/db/         SQLite only (server.db, schema in sqlite.go)
src/server/     HTTP handlers, routes, middleware
src/whois/      WHOIS lookup engine
src/scheduler/  Built-in task scheduler
docker/         Dockerfile (NEVER at project root)
AI.md           Full spec (45k+ lines — grep before reading)
```

## Read Before Implementing

Always `grep -n "^# PART N" AI.md` to find the relevant slice, then read only that slice.
Never load the full AI.md into context.

---
See AI.md PART 0 for complete session initialization rules.
