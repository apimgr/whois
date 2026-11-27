# AI Assistant Rules (PART 0, 1)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never guess, edit AI.md, or add report files. Read relevant PARTs before changes; preserve user work; surface defects and fix them unless asked for report-only work.

## CRITICAL - ALWAYS DO

- Read the assigned AI.md PARTs completely before implementation.
- Preserve existing user changes and keep project edits inside the repository.

## Key rules

- AI.md is read-only and authoritative for implementation behavior.
- Update user-facing documentation when shipped behavior changes.

For complete details, see AI.md PART 0, 1.

## KEY DECISIONS (pre-answered)

| Question | Answer | Spec Reference |
|----------|--------|----------------|
| What is authoritative? | AI.md is read-only, IDEA.md specifies product behavior, and implementation follows the session-init read order. | See PART references above |

## TERMINOLOGY

| Term | Meaning |
|------|---------|
| Source of truth | The applicable AI.md requirement, with IDEA.md defining project behavior | PART 0, 1 |
| Required path | A route, file, or operation explicitly required by the applicable PART | Relevant PARTs |

## QUICK REFERENCE

- PART 0 sections are read before coding; after compaction, reread only the applicable spec section. AI.md contradictions are reported with line references; AI.md itself is never edited.
- Preserve existing user changes and update paired documentation when behavior changes.
