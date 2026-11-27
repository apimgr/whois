# Frontend Rules (PART 16)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never make core functionality depend on JavaScript or add inline CSS. Use server-rendered accessible HTML, progressive enhancement, theme support, and the shared page components.

## CRITICAL - ALWAYS DO

- Read the assigned AI.md PARTs completely before implementation.
- Preserve existing user changes and keep project edits inside the repository.

## Key rules

- AI.md is read-only and authoritative for implementation behavior.
- Update user-facing documentation when shipped behavior changes.

For complete details, see AI.md PART 16.

## KEY DECISIONS (pre-answered)

| Question | Answer | Spec Reference |
|----------|--------|----------------|
| What is authoritative? | Every user-facing page is server-rendered, uses the shared shell, and works without JavaScript for essential actions. | See PART references above |

## TERMINOLOGY

| Term | Meaning |
|------|---------|
| Source of truth | The applicable AI.md requirement, with IDEA.md defining project behavior | PART 0, 1 |
| Required path | A route, file, or operation explicitly required by the applicable PART | Relevant PARTs |

## QUICK REFERENCE

- Forms use CSRF protection; content from configuration is sanitized Markdown; translations and accessible labels are required.
- Preserve existing user changes and update paired documentation when behavior changes.
