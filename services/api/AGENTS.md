# AGENTS.md — Backend API

Owner: Vanneth (`parsers/`, `findings/`, `clients/` MCP client: Youlong) · Last reviewed: 28 Oct 2026

Read the root [`AGENTS.md`](../../AGENTS.md) first. These rules add to it; if they disagree, the
root file wins.

Package: `reconix_api` (`src/` layout). Depends on `reconix-ai` for the harness (check, masking,
audit log). The API calls the AI Service as a Python package, not over HTTP.

**Plan:** [`docs/reconix-plan-v2.md`](../../docs/reconix-plan-v2.md), section "Yann Vanneth" in each
week. **Deadline: the backend is 100% on Mon 2 Nov.** After Tue 17 Nov (feature freeze), only bug
fixes go in.

## Layering

```
api/ (routes) → services/ (rules) → repositories/ (queries) → models/ (tables)
```

- A route parses the request, checks the role, calls one service and returns a schema. It never
  queries the database.
- A service holds the rules. A repository holds queries only, no rules.
- Routes get the shared functions through the `CurrentInterfaces` dependency, never by importing
  the other part directly.

## Folders (`src/reconix_api/`)

| Folder | Holds |
|---|---|
| `main.py` | `create_app()`: middleware (Host check, CORS), error handlers, routers |
| `core/` | `config.py`, `db.py`, `errors.py`, `security.py`, `session_tokens.py`, `job_token.py`, `masking.py`, `interfaces.py` (the 6 shared functions), `wiring.py` (wires the real ones) |
| `api/` | Routes, one file per resource: `system`, `sessions`, `scopes`, `assessments`, `approvals`, `actions`, `findings`, `messages` |
| `services/` | Rules: actions, approvals, decisions, tool runs, findings, scopes, sessions, messages, audit |
| `repositories/` | Database queries only |
| `models/` | SQLAlchemy tables from ERD V3 (all 16; the 2 join tables are plain `Table`s); enums in `models/enums.py` |
| `schemas/` | Pydantic requests and responses |
| `clients/` | `mcp.py`: the only way to reach the Kali container |
| `parsers/` | Raw tool output → records (`nmap.py`, `json_report.py`) |
| `findings/` | One finding shape (`shape.py`), mapping and `dedupe_key` |

Outside `src/`: `alembic/` (migrations, `alembic.ini` in this folder) and `tests/`.

## Rules

- **Errors** use one shape: `{"code": "UPPER_CASE", "message": "...", "details": {...}}`. Raise the
  errors from `core/errors.py`; never return `None` to hide a failure.
- **Network:** the API binds to `127.0.0.1` only, rejects an unknown `Host`, and allows CORS only
  for the local web (`RECONIX_WEB_ORIGINS`).
- **Roles:** the role (`OPERATOR` or `VIEWER`) lives with the session token, not in the database.
  A viewer may only read. Every endpoint that changes data returns 403 for a viewer, with a test in
  `tests/security/test_viewer_read_only.py`.
- **Audit:** every decision and state change writes exactly one audit event with `assessment_id`,
  `session_id`, `role` and `actor`.
- **Actions:** run the harness `check()` first. `BLOCKED` → 422, `LOW` → run now,
  `MEDIUM`/`HIGH` → approval. Store the masked action and its SHA-256 hash; re-run `check()` and
  re-hash right before the tool runs. No path may skip this second check.
- **Approvals** have 5 kinds (ERD V3 `approvals.kind`): `scope`, `action`, `disclosure`,
  `configuration`, `review`. Each one stores a masked `subject_snapshot` and its SHA-256
  `subject_hash`, expires after `RECONIX_APPROVAL_TTL_MINUTES` (30) and is single use
  (`consumed_at`). `HIGH` needs the person to type the target (`confirmation_verified`). Use the
  `add-approval-flow` skill.
- **Scope flow:** submitting a scope creates a `scope` approval and a `DRAFT` assessment with a code
  like `RCX-2026-0001`; approving it makes the assessment `ACTIVE`.
- **Tool runs:** after approval, check the action did not change, save a new tool run, sign a
  one-time job token, call the tool, and save the masked output, the masked-secret count, the
  request count and the final status. Then hand the output to `parsers/` and `findings/`.
- **Tools** are called only through `clients/mcp.py` with a fresh one-time job token
  (`core/job_token.py`). Commands are `list[str]`, never strings.
- **Secrets:** mask before saving, logging or returning anything. AI provider API keys are
  encrypted with Fernet (`RECONIX_FERNET_KEY`) and only the last 4 characters are ever shown.
- **Schema changes** go through Alembic (`add-db-migration` skill).
- **Routes or schemas changed** → regenerate `docs/openapi.json` in the same PR (`sync-openapi`
  skill). New endpoints follow the `add-endpoint` skill.

## Plan status (28 Oct 2026)

Keep this table true; update the row in the PR that changes it.

| Plan item | Week | Status |
|---|---|---|
| 6 shared functions + fakes, Compose, safe API (Host, CORS, error shape), `/health`, `/me` | 1 | Done |
| Models + one Alembic migration | 1 | Done: all 16 tables, upgrade and downgrade work, no model drift |
| Sessions, messages, scopes (draft, edit, submit, approve) | 1 | Done |
| `POST /assessments/{id}/actions`, approvals, tool run through MCP, findings saved | 1 | Done |
| `ask_agent` wired to the real AI Service (LangGraph checkpoints in Postgres) | 1 | Not started: still the not-ready stub in `core/wiring.py` |
| Planning endpoint and AI runs (running → waiting for approval → completed, failed or cancelled) | 2 | To do |
| Read endpoints: actions and findings done; finding detail, masked evidence, check runs, AI runs | 2 | Partly done |
| 6 AI provider endpoints (Fernet, one active, `configuration` approval for cloud providers) | 2 | To do |
| Reports: locked masked copy + hash, `GENERATING` → `READY`/`FAILED`, multi-assessment, `review` sign-off, download | 2 | To do |
| Pojim's parts in the API: disclosure, limit settings, timeline, web role check | 2 | To do |
| API in Docker Compose, `install.sh`, uv install steps | 2 | To do: API runs on the host; `install.sh` is a placeholder |
| Full flow test on Sat 31 Oct, final `openapi.json` on Mon 2 Nov | 2 | To do (`run-full-flow-test` skill) |
| Terminal WebSocket (operators only), `GET /stream` live updates | 3 | To do |
| Security tests (rate limit, Host, CORS, viewer), contract tests against `openapi.json`, list indexes | 3 | Partly done: Host, CORS and viewer tests exist |
| Release `v0.1.0` on Tue 3 Nov, `v1.0.0` on Fri 20 Nov | 3, 4 | To do (`cut-release` skill) |

**Plan vs. code:** the plan adds `sessions.role`; the team instead keeps the role with the session
token, and ERD V3 has no such column. Follow the code and the root `AGENTS.md`.

## Tests (`tests/`)

| Folder | What it proves |
|---|---|
| `unit/` | One function or class, no network, no database; mirrors `src/reconix_api/` |
| `security/` | Viewer gets 403 on every write; Host and CORS protections |
| `integration/` | Real database and repositories: scope, action, findings and messages flows; the real harness; the live MCP client |
| `contract/` | Responses match `docs/openapi.json` (empty, to add) |
| `e2e/` | The full flow, scope to download (empty, to add) |
| `fakes/` | `fake_core.py`, `fake_mcp.py`, `fake_ai.py`, used when the real part is not ready |
| `fixtures/` | Raw tool output per tool (nmap, nuclei, semgrep, gitleaks, trivy) |

## Commands

Run from the repo root.

```bash
uv run --package reconix-api pytest                              # all API tests
uv run --package reconix-api pytest services/api/tests/unit -q
uv run --package reconix-api pytest services/api/tests/security -q

cd services/api && uv run alembic upgrade head && cd -           # migrate
uv run --package reconix-api python -m reconix_api.main          # http://127.0.0.1:8000/docs
```

Integration tests skip unless `RECONIX_TEST_DATABASE_URL` points at a PostgreSQL 16 database (see
`tests/integration/conftest.py`). The live MCP test also needs `RECONIX_TEST_MCP_URL` and
`RECONIX_TEST_MCP_ACCESS_KEY` (the Kali container, started with `deploy/docker-compose.dev.yml`).

## Done when

- `uv run ruff check . && uv run ruff format --check .` pass.
- `uv run --package reconix-api pytest` passes, including the viewer-403 tests.
- A new write endpoint has a viewer-403 test; a bug fix has a test that failed before the fix.
- `docs/openapi.json` is regenerated if routes or schemas changed, and a migration exists if the
  schema changed.
- The "Plan status" table above is updated if the change finishes a plan item.

**Week goals from the plan:** week 1, curl can open a session, approve a scope, send an action,
approve it, run nmap and save findings. Week 2, the full flow passes: scope, plan, approve, run,
analyze, validate, report, download.
