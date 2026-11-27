# Backend Rules (PART 9, 10, 11, 31)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never interpolate untrusted input into SQL or log secrets. Use idempotent SQLite/libsql schema, parameterized queries, security controls, and optional overlay daemons only when available.

## CRITICAL - ALWAYS DO

- Read the assigned AI.md PARTs completely before implementation.
- Preserve existing user changes and keep project edits inside the repository.

## Key rules

- AI.md is read-only and authoritative for implementation behavior.
- Update user-facing documentation when shipped behavior changes.

For complete details, see AI.md PART 9, 10, 11, 31.

## KEY DECISIONS (pre-answered)

| Question | Answer | Spec Reference |
|----------|--------|----------------|
| What is authoritative? | SQLite schemas are idempotent; queries are parameterized; cache and upstream failures have explicit bounded behavior. | See PART references above |

## TERMINOLOGY

| Term | Meaning |
|------|---------|
| Source of truth | The applicable AI.md requirement, with IDEA.md defining project behavior | PART 0, 1 |
| Required path | A route, file, or operation explicitly required by the applicable PART | Relevant PARTs |

## QUICK REFERENCE

- Secrets never enter logs or normal database tables. Security-sensitive comparisons use constant-time checks where specified.
- Preserve existing user changes and update paired documentation when behavior changes.
