---
name: add-endpoint
description: Add or change a backend API endpoint in services/api (route, service, repository, schema, tests, openapi.json). Use for any new REST route, WebSocket or change to a request/response shape.
---

# Add an endpoint

Code is split by job: **api** (route) → **services** (logic) → **repositories** (database) → **models** (tables). A route never touches the database directly, and a repository never contains business rules.

## Steps

1. **Schema** — add request/response Pydantic models in `services/api/src/reconix_api/schemas/<resource>.py`. Field names and UPPERCASE enum values come from ERD V3 / Data Dictionary V3.
2. **Repository** — add queries in `repositories/<resource>.py`. Takes a session, returns models. No HTTP, no rules.
3. **Service** — add logic in `services/<resource>.py`. This is where approvals, status changes and safety checks happen.
4. **Route** — add the handler in `api/<resource>.py` (one file per resource) and register it in `main.py`.
5. **Tests** — unit tests for the service in `tests/unit/`, and the security/contract tests below.
6. **Contract** — export `docs/openapi.json` (see the `sync-openapi` skill) and commit it in the same PR.

## Every endpoint must

- Return errors in the one shared shape: `{"code": "...", "message": "...", "details": {...}}`. Use UPPERCASE codes such as `SCOPE_VIOLATION`, `APPROVAL_EXPIRED`.
- Need the session token: take `CurrentOperator`, so a request without a valid token gets **401**. There are no roles: a valid token may do everything. `tests/security/test_api_protections.py` checks every route by itself; never add to its `OPEN` set (only `GET /health` and `POST /sessions`) without the lead.
- Write an audit event (through the shared audit function) for every state change, with `assessment_id`, `session_id`, `actor`.
- Mask secrets before anything is saved or returned.
- Stay behind the app-wide protections: bind to `127.0.0.1` only, reject an unknown `Host` header, CORS only for the local web origin.

## Actions and tool runs (extra rules)

If the endpoint can lead to a tool running:

- Run the harness `check()` first. `BLOCKED` → 422. `LOW` → run now. `MEDIUM`/`HIGH` → create an approval and wait.
- Store a masked copy of the action and its SHA-256 hash. Before running, re-hash and refuse if it changed after approval.
- Approvals expire after 30 minutes and are single-use. `HIGH` requires the person to type the target.
- Call tools only through the MCP client with a freshly signed one-time job token.

## Done when

- `uv run pytest services/api` passes, including the no-token (401) test.
- `docs/openapi.json` is updated and the contract tests pass.
