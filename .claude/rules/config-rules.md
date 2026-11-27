# Configuration Rules (PART 5, 6, 12)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never add runtime configuration mutation or silently ignore unknown keys. Use server.yml, secrets.yml for secrets, and CLI > environment > file > defaults.

## CRITICAL - ALWAYS DO

- Read the assigned AI.md PARTs completely before implementation.
- Preserve existing user changes and keep project edits inside the repository.

## Key rules

- AI.md is read-only and authoritative for implementation behavior.
- Update user-facing documentation when shipped behavior changes.

For complete details, see AI.md PART 5, 6, 12.

## KEY DECISIONS (pre-answered)

| Question | Answer | Spec Reference |
|----------|--------|----------------|
| What is authoritative? | Configuration precedence is CLI, environment, config file, then defaults; secret values live in secrets.yml. | See PART references above |

## TERMINOLOGY

| Term | Meaning |
|------|---------|
| Source of truth | The applicable AI.md requirement, with IDEA.md defining project behavior | PART 0, 1 |
| Required path | A route, file, or operation explicitly required by the applicable PART | Relevant PARTs |

## QUICK REFERENCE

- Unknown keys and invalid values are surfaced according to the config contract. Generated secrets are written atomically with restrictive permissions.
- Preserve existing user changes and update paired documentation when behavior changes.
