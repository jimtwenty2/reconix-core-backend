# AGENTS.md — Backend API

Owner: Vanneth (`parsers/`, `findings/`, `clients/` MCP client: Youlong)

Read the root `AGENTS.md` first. These rules add to it.

Scope: routes (api) → services (logic) → repositories (database) → models (tables).

## Folders

| Folder | Holds |
|---|---|
| `core/` | config, errors, security, `interfaces.py` (the 6 shared functions) |
| `api/` | routes, one file per resource |
| `services/` | business logic: approvals, status changes, safety checks |
| `repositories/` | database queries only, no rules |
| `models/` | SQLAlchemy tables (ERD V3, 16 tables) |
| `schemas/` | Pydantic requests and responses |
| `clients/` | MCP client, AI Service client |
| `parsers/` | raw tool output: nmap XML, nuclei JSONL, ZAP, semgrep, gitleaks JSON |
| `findings/` | one finding shape, `dedupe_key` |
| `alembic/` | migrations |
| `tests/` | `fakes/`, `unit/`, `contract/`, `security/`, `e2e/` (full flow) |

## Rules

- A route never touches the database; a repository never holds business rules.
- Errors use one shape: `{"code": "...", "message": "...", "details": {...}}` with UPPERCASE codes.
- The API binds to `127.0.0.1` only, rejects an unknown `Host`, and allows CORS only for the local web.
- A **viewer** may only read. Every endpoint that changes data returns 403 for a viewer, with a test in `tests/security/`.
- Every state change writes one audit event with `assessment_id`, `session_id`, `role`, `actor`.
- Actions: run the harness `check()` first. `BLOCKED` → 422, `LOW` → run now, `MEDIUM`/`HIGH` → approval. Store the masked action and its SHA-256 hash, and re-hash before running. Approvals expire after 30 minutes and are single-use; `HIGH` needs the person to type the target.
- Tools are called only through the MCP client with a fresh one-time job token.
- AI provider API keys are encrypted with Fernet and only the last 4 characters are ever shown.
- Schema changes go through Alembic (see the `add-db-migration` skill). After any route or schema change, regenerate `docs/openapi.json` in the same PR.

## Done when

`uv run --package reconix-api pytest` passes, including the viewer-403 and contract tests.
