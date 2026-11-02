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

- A route parses the request, checks the session token, calls one service and returns a schema.
  It never queries the database.
- A service holds the rules. A repository holds queries only, no rules.
- Routes get the shared functions through the `CurrentInterfaces` dependency, never by importing
  the other part directly.

## Folders (`src/reconix_api/`)

| Folder | Holds |
|---|---|
| `main.py` | `create_app()`: middleware (Host check, CORS), error handlers, routers |
| `core/` | `config.py`, `db.py`, `errors.py`, `security.py`, `session_tokens.py`, `job_token.py`, `masking.py`, `interfaces.py` (the 6 shared functions), `wiring.py` (wires the real ones), `agent.py` (the real `ask_agent`), `report_files.py`, `provider_urls.py` (AI provider address check), `provider_keys.py` (Fernet for API keys), `knowledge_add_ons.py` (add-ons in Qdrant), `knowledge_files.py` (an uploaded file's text), `provider_checks.py` (test a provider, list a local Ollama's models), `timeline.py` (calls the harness's `read_timeline`), `code_files.py` (VS Code source code: safe paths, sync, tar.gz unpack). Only `core/` imports `reconix_ai` |
| `api/` | Routes, one file per resource: `system`, `sessions`, `code`, `code_scans`, `messages`, `scopes`, `assessments`, `actions`, `approvals`, `findings`, `evidence`, `plans`, `analysis`, `agent_runs`, `reports`, `llm_providers`, `knowledge_add_ons`, `knowledge`, `timeline` |
| `services/` | Rules: actions, approvals, decisions, tool runs, findings, scopes, sessions, code (VS Code uploads), code scans, messages, plans, analysis, agent runs, reports, AI providers, knowledge add-ons, audit |
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
- **Session token:** every endpoint except `/health`, `POST /sessions` and
  `POST /sessions/web-sign-in` (it checks a one-time code instead) uses `CurrentOperator`, so
  a request without a valid token gets 401. There are no roles: a valid token may do
  everything. `tests/security/test_api_protections.py` reads every route from the app and
  checks each one gets 401 without a token; only the three above are in its `OPEN` set.
- **Audit:** every decision and state change writes exactly one audit event with `assessment_id`,
  `session_id` and `actor`.
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
- **Tool runs:** after approval, check the action did not change and run `ensure_can_act` and
  `check()` again (S2; a refusal ends the action and the approval), save a new tool run, sign a
  one-time job token, call the tool, and save the masked output, the masked-secret count, the
  request count and the final status. Then hand the output to `parsers/` and `findings/`.
- **Tools** are called only through `clients/mcp.py` with a fresh one-time job token
  (`core/job_token.py`). Commands are `list[str]`, never strings.
- **Secrets:** mask before saving, logging or returning anything. AI provider API keys are
  encrypted with Fernet (`RECONIX_FERNET_KEY`) and only the last 4 characters are ever shown.
- **Schema changes** go through Alembic (`add-db-migration` skill).
- **Routes or schemas changed** → regenerate `docs/openapi.json` in the same PR (`sync-openapi`
  skill). New endpoints follow the `add-endpoint` skill.

## Plan status (30 Oct 2026)

Keep this table true; update the row in the PR that changes it.

| Plan item | Week | Status |
|---|---|---|
| 6 shared functions + fakes, Compose, safe API (Host, CORS, error shape), `/health`, `/me` | 1 | Done |
| Models + one Alembic migration | 1 | Done: all 16 tables, upgrade and downgrade work, no model drift |
| Sessions, messages, scopes (draft, edit, submit, approve) | 1 | Done |
| `POST /assessments/{id}/actions`, approvals, tool run through MCP, findings saved | 1 | Done |
| `ask_agent` wired to the real AI Service (LangGraph checkpoints in Postgres) | 1 | Done: PLAN, SUGGEST, ANALYZE and resume, with the run's own provider (`core/agent.py`) |
| Planning endpoint and AI runs (running → waiting for approval → completed, failed or cancelled) | 2 | Done: `POST /assessments/{id}/plan` (the step goes through `send_action`), resume after the decision, `GET /sessions/{id}/agent-runs` |
| Read endpoints: actions and findings done; finding detail, masked evidence, check runs, AI runs | 2 | Partly done: check runs to do. Also done: `POST /assessments/{id}/analyze` (suggestions saved in the run) |
| 6 AI provider endpoints (Fernet, one active, `configuration` approval for cloud providers) | 2 | Done: `/llm-providers` list, add, read, edit, remove and `/activate`. A provider on this computer is active at once, any other after its `configuration` approval. Each agent request carries its run's provider and model, and `core/agent.py` calls the agent with that run's settings (`services/agent_runs.make_provider_for_run`, key decrypted). A run whose provider is no longer active gets 409 `PROVIDER_CHANGED`, because an inactive row can be edited with no approval |
| Reports: locked masked copy + hash, `GENERATING` → `READY`/`FAILED`, multi-assessment, `review` sign-off, download | 2 | Done except multi-assessment: one assessment per report, files in `RECONIX_REPORTS_DIR`, `review` sign-off before download |
| Pojim's parts in the API: disclosure, limit settings, timeline, web sign-in | 2 | Web sign-in done: `POST /sessions/web-sign-in-codes` (needs a token) gives a one-time code that works for 2 minutes, and `POST /sessions/web-sign-in` (open) trades it for a normal `web` session token. Disclosure, limit settings and timeline to do |
| VS Code: `vscode` sessions, `path` scope targets, code sync and upload, code scans | 3 | Done: `POST /sessions/{id}/code/sync` and `PUT /sessions/{id}/code` (tar.gz, `RECONIX_CODE_DIR`, `RECONIX_MAX_UPLOAD_MB`); a `path` target (`/workspace/code/<session>`) becomes `repo_paths`; `POST /assessments/{id}/code-scans` runs SEMGREP then GITLEAKS through `send_action` in the background (an agent run with `plan.task = CODE_SCAN`), then ANALYZE (excluded `path` targets inside the code are deleted from it first, and never stored once the scope is approved); `GET /code-scans/{id}`, `/cancel` and `/findings` (relative path, line, rule, masked snippet, file hash). Closing a session deletes its code |
| API in Docker Compose, `install.sh`, uv install steps | 2 | To do: API runs on the host; `install.sh` is a placeholder |
| Full flow test on Sat 31 Oct, final `openapi.json` on Mon 2 Nov | 2 | To do (`run-full-flow-test` skill) |
| Terminal WebSocket (the handshake checks the token and `Origin`; the Host middleware does not cover WebSockets), `GET /stream` live updates | 3 | To do |
| Security tests (rate limit, Host, CORS, no token), contract tests against `openapi.json`, list indexes | 3 | Partly done: Host, CORS and no-token tests exist |
| Release `v0.1.0` on Tue 3 Nov, `v1.0.0` on Fri 20 Nov | 3, 4 | To do (`cut-release` skill) |

**No roles:** Reconix has no OPERATOR/VIEWER split (decided 30 Oct 2026). ERD V3 has no
`sessions.role`, and the plan no longer asks for one.

## Tests (`tests/`)

| Folder | What it proves |
|---|---|
| `unit/` | One function or class, no network, no database; mirrors `src/reconix_api/` |
| `security/` | Every endpoint needs a session token (401); Host and CORS protections |
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
- `uv run --package reconix-api pytest` passes, including the no-token (401) tests.
- A new endpoint needs the token (the no-token test checks it by itself); a bug fix has a test
  that failed before the fix.
- `docs/openapi.json` is regenerated if routes or schemas changed, and a migration exists if the
  schema changed.
- The "Plan status" table above is updated if the change finishes a plan item.

**Week goals from the plan:** week 1, curl can open a session, approve a scope, send an action,
approve it, run nmap and save findings. Week 2, the full flow passes: scope, plan, approve, run,
analyze, validate, report, download.
