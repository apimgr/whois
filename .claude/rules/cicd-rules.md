# CI/CD Rules (PART 27)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never use unpinned third-party workflow actions or grant broad workflow permissions. Match workflows to the selected provider and build/test in the prescribed container.

## CRITICAL - ALWAYS DO

- Read the assigned AI.md PARTs completely before implementation.
- Preserve existing user changes and keep project edits inside the repository.

## Key rules

- AI.md is read-only and authoritative for implementation behavior.
- Update user-facing documentation when shipped behavior changes.

For complete details, see AI.md PART 27.

## KEY DECISIONS (pre-answered)

| Question | Answer | Spec Reference |
|----------|--------|----------------|
| What is authoritative? | Workflow actions are pinned to verified immutable revisions and use least privilege. | See PART references above |

## TERMINOLOGY

| Term | Meaning |
|------|---------|
| Source of truth | The applicable AI.md requirement, with IDEA.md defining project behavior | PART 0, 1 |
| Required path | A route, file, or operation explicitly required by the applicable PART | Relevant PARTs |

## QUICK REFERENCE

- CI uses provider-specific prescribed jobs and direct Go commands inside the documented container; do not use local Makefile targets in CI.
- Preserve existing user changes and update paired documentation when behavior changes.
