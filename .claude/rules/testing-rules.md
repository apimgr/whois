# Testing, Documentation and Accessibility Rules (PART 28, 29, 30)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never put runtime test artifacts in the repository. Run required checks in Docker/Incus as specified, keep docs current, and maintain locale parity and WCAG accessibility.

## CRITICAL - ALWAYS DO

- Read the assigned AI.md PARTs completely before implementation.
- Preserve existing user changes and keep project edits inside the repository.

## Key rules

- AI.md is read-only and authoritative for implementation behavior.
- Update user-facing documentation when shipped behavior changes.

For complete details, see AI.md PART 28, 29, 30.

## KEY DECISIONS (pre-answered)

| Question | Answer | Spec Reference |
|----------|--------|----------------|
| What is authoritative? | Tests cover behavior and required conformance; documentation and all locale keys stay in sync. | See PART references above |

## TERMINOLOGY

| Term | Meaning |
|------|---------|
| Source of truth | The applicable AI.md requirement, with IDEA.md defining project behavior | PART 0, 1 |
| Required path | A route, file, or operation explicitly required by the applicable PART | Relevant PARTs |

## QUICK REFERENCE

- Run project checks only through prescribed commands. Do not leave test artifacts, and include accessibility and translation parity in frontend validation.
- Preserve existing user changes and update paired documentation when behavior changes.
