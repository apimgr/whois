# TODO.AI.md

## Convention violations

- [ ] `src/scheduler/scheduler.go`: uses external cron library `github.com/go-co-op/gocron/v2` instead of a built-in scheduler. Forbidden per CasjaysDev Go conventions (no external cron/scheduling dependency). Flagged by `go-lint` agent on 2026-09-17 as pre-existing (not introduced by the `golang.org/x/crypto`/`google.golang.org/grpc` dependency bump in the same session). Needs a dedicated fix: replace `gocron/v2` with an in-process ticker/scheduler implementation and remove the dependency from `go.mod`.
