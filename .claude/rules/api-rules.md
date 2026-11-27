# API Rules (PART 13, 14, 15)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never preserve project-owned legacy endpoints or compatibility shims. Use versioned API routes, stable response shapes, health/version behavior, and configured TLS.

## CRITICAL - ALWAYS DO

- Read the assigned AI.md PARTs completely before implementation.
- Preserve existing user changes and keep project edits inside the repository.

## Key rules

- AI.md is read-only and authoritative for implementation behavior.
- Update user-facing documentation when shipped behavior changes.

For complete details, see AI.md PART 13, 14, 15.

## KEY DECISIONS (pre-answered)

| Question | Answer | Spec Reference |
|----------|--------|----------------|
| What is authoritative? | Versioned API paths use the configured API base; stable aliases call the same handler without redirects. | See PART references above |

## TERMINOLOGY

| Term | Meaning |
|------|---------|
| Source of truth | The applicable AI.md requirement, with IDEA.md defining project behavior | PART 0, 1 |
| Required path | A route, file, or operation explicitly required by the applicable PART | Relevant PARTs |

## QUICK REFERENCE

- Health, API errors, authentication, content negotiation, CORS, and OpenAPI behavior must follow the corresponding PART. API handlers never return HTML and API auth uses bearer headers only.
- Preserve existing user changes and update paired documentation when behavior changes.
