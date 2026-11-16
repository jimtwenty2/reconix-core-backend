---
name: api-documentation
description: Write and revise backend API documentation in services/api — endpoint docstrings and Pydantic schema field descriptions — in clear, professional English with a fixed section order. Use for any new or changed route or schema, or a documentation pass over existing endpoints.
---

# Document an API endpoint

API docs live in two places and are exported to `docs/openapi.json`:

- **Route docstrings** in `api/<resource>.py`. The whole docstring becomes the OpenAPI `description`. FastAPI derives the `summary` from the function name; pass `summary=` on the decorator to override it.
- **Schema fields** in `schemas/<resource>.py`: `Field(..., description="...")` for each request/response property.

After editing docs, regenerate the contract with the `sync-openapi` skill. Never hand-edit `openapi.json`.

Improve wording only. Do not change API behavior while documenting it.

## Section order (fixed)

Write the description as a short prose paragraph, then add these sections as bullet lists, in this order. Omit a section that has nothing to say — never pad it.

1. **Description** — prose. What the endpoint does, in one or two sentences.
2. **Business Rules** — conditions and constraints (e.g. what requires approval).
3. **Execution Behavior** — what the endpoint runs or calls.
4. **State Changes** — what it creates, updates, or deletes.
5. **Security** — auth and permission requirements.
6. **Operational Considerations** — only when relevant (latency, side effects, limits).

## Writing rules

- Plain verbs: Retrieves, Creates, Updates, Deletes, Validates, Activates — not "performs the creation of".
- Active voice, present tense, one idea per sentence, main action first.
- American English, neutral and factual. Easy to understand on first read.
- Consistent terms: "LLM provider", "approval request", "active provider", "response latency". Reuse ERD V3 and contract words; don't invent terminology.
- Match the implementation exactly. Don't present assumptions as facts.

## Avoid

"In order to", "for the purpose of", "utilize/leverage/facilitate" (use "use"), "perform the operation of", "conduct the process of", "it is important to note that", "successfully completed successfully", excess "shall/hereby/thereof/aforementioned", and filler sentences that add no technical fact.

## Examples

- Bad: "This endpoint is utilized for the purpose of retrieving all provider configurations." → Good: "Retrieves the configured LLM providers."
- Bad: "Activation cannot be performed in case the provider has not obtained approval." → Good: "Remote providers require approval before activation."
- Bad: "The selected provider will undergo a modification of its activation status." → Good: "Sets the selected provider as active."
- Bad: "Authentication verification must be completed by the requesting user." → Good: "Requires an authenticated session."

## Before you finish

Review every description for: technical accuracy, grammar, natural American English, consistent terms, conciseness, correct section order, valid OpenAPI, and no unsupported claims. Do not change API behavior while improving docs. Do not claim a grammar checker or linter ran unless it actually did.
