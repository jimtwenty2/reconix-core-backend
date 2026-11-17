---
name: write-simple-code
description: House style for all Reconix-Core code. Use whenever writing or changing Python or TypeScript in this repo, so code stays simple enough for any team member to read and review.
---

# Write simple code

Reconix-Core is built by a small team on a short schedule. Code must be easy to read, review and fix on the same day.

## Rules

- Prefer plain functions and dataclasses/Pydantic models over class hierarchies, metaclasses or clever decorators.
- One job per function. If a function needs a comment to explain *what* it does, split it.
- Name things with the words from ERD V3 and the API contract (`assessment`, `tool_run`, `finding`, `approval`), never synonyms.
- Enum values are UPPERCASE strings everywhere (`ACTIVE`, `FALSE_POSITIVE`, `TIMED_OUT`). Never lowercase or free text.
- No new dependency without a reason in the PR description. Use what the stack already has (FastAPI, SQLAlchemy, Pydantic, httpx, Textual, Typer, LiteLLM, LangGraph, Next.js).
- Fail loudly: raise a clear error with the shared error shape instead of returning `None` or swallowing exceptions.
- Never build shell commands from strings. Arguments are always a `list[str]`.
- Never log, print or return a secret. Mask first (see the `add-guardrail-check` skill).
- Type hints on every Python function. `ruff check` and `ruff format` must pass.

## Layout

- Python packages use the `src/` layout. Files and folders are `snake_case`.
- Tests mirror source: `tests/unit/x/` tests `src/<pkg>/x/`.
- Only change files in your own part. Parts talk only through `services/api/src/reconix_api/core/interfaces.py` and `docs/openapi.json`. If the other side is not ready, use its fake.

## Before you finish

1. `uv run ruff check . && uv run ruff format --check .`
2. `uv run pytest` for the package you touched.
3. Re-read the diff once as if you were the reviewer.
