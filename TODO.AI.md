# TODO.AI.md

No known implementation work remains from the existing scheduler convention
finding. The scheduler now uses Go's time and timer primitives directly,
implements cron/interval schedule parsing in project source, persists next-run
state, catches up missed work, and isolates task panics.

AI.md PART 18 specifically requires an in-process scheduler with no external
scheduler dependency; that requirement takes precedence over the generic
library list's gocron example.
