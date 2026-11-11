---
name: integrate-apps-with-api
description: Move the TUI (apps/tui) and the local web (apps/web) off their own in-memory data, saved files and direct model calls and onto the local Core API (services/api), one flow step at a time. Use when starting the "switch over to the real API" work, when deciding what the backend must add first, or when mapping a TUI store function or web view to a real endpoint.
---

# Integrate the apps with the Core API

Today there are two separate systems. The apps never call the API, and the API has no
frontend:

```
apps/tui  ── LiteLLM ──▶ model provider        (direct, reconix/llm/client.py)
   │ saves snapshots to ~/.reconix/assessments
   ▼
apps/web  ── reads those files (src/lib/data/store.ts); its chat calls an LLM directly

services/api ── imports ──▶ reconix_ai (check, agent, masking) ── MCP ──▶ Kali container
```

The target (`docs/reconix-plan-v2.md`, week 2) is: the TUI talks only to the API and makes no
model calls; after a TUI run, the web shows the same findings through the API. Then the backend
decides everything and the safety rules S1–S11 cover what app users do.

## Who does what

| Work | Folder | Owner | Run Claude from |
|---|---|---|---|
| Backend prerequisites (step 2) | `services/api/` | Vanneth | repo root |
| TUI wiring | `apps/tui/` | Sokpiseth | `apps/` (`wire-backend` skill, `backend-integrator` agent) |
| Web wiring | `apps/web/` | Sokpiseth | `apps/` (same) |
| Turning API calls on in `apps/.claude/` | `apps/.claude/` | the app owners | `apps/` |
| This skill, `AGENTS.md` | `.claude/`, root | Pojim | repo root |

The `stay-in-apps` hook blocks changes outside `apps/` when Claude runs from `apps/`, so backend
work and app work are always separate PRs.

## Steps

### 1. Agree on the open decisions (stop and ask)

Each of these changes what gets built. Get the lead and the app owners to decide before
anyone writes code:

- **Chat.** Both apps call a model directly today. `POST /sessions/{id}/messages` only saves the
  masked message: the agent sends no reply, and the AI Service has no CHAT task yet. Either
  leave chat out of the first cut, or the AI owner adds CHAT and the API returns the reply.
- **The web's token.** `POST /sessions` only gives OPERATOR tokens, and nothing gives out a
  VIEWER token. The plan has `/web` print a sign-in link with a token. Decide which role that
  token has and how the API gives it out.
- **Where the web calls from.** Recommended: only from the Next server (`src/lib/api/`, marked
  server-only), so the token never reaches the browser and CORS doesn't apply. If the browser
  calls the API instead, CORS must allow the web's port (step 2).
- **What stays local.** These TUI features have no endpoint: test logins and the vault
  (`store/vault.py`, `store/tools.py`), knowledge files, the API spec attached to the API
  template (`store/openapi.py`), retest, and the template list. Triage is only partly covered:
  `PATCH /findings/{id}` takes only `finding_status` (`open` → OPEN, `false-positive` →
  FALSE_POSITIVE, `fixed` → FIXED). The TUI's `accepted` status, severity override and note
  have no API field. Decide for each one whether it stays local or needs an endpoint.
- **The AI's reason on the approval card.** The plan's approval card shows why the AI wants to
  run the step, but no endpoint returns that. `ApprovalOut.reason` is the person's reason for
  rejecting, and a plan step has only `order`, `title` and `action`. Either the API owner adds
  the reason, or the card leaves it out for now.
- **Validate.** There is no validate endpoint, and the `ValidationRun` model is unused. The
  first cut skips the validate step.

### 2. Backend prerequisites (`services/api/`, from the repo root)

Do these first. Each one is its own PR (`add-endpoint` or `add-approval-flow`, plus tests):

- [x] **Second check after approval (S2).** `actions.approve_action` runs `ensure_can_act` and
  `interfaces.check()` again before the run; tests cover a cancelled assessment, a closed scope
  window and a risk that rose (branch `fix/approval-recheck`).
- [ ] **CORS origin.** `core/config.py` allows `:3000`, but the web runs on `:3100`
  (`apps/web/scripts/serve.mjs`). This matters only if the browser calls the API.
- [ ] **Viewer token**, if step 1 asks for one. Add viewer-403 tests in `tests/security/`.
- [ ] **Contract.** Regenerate `docs/openapi.json` (`sync-openapi`). Add a contract test that
  responses match it; there is none yet.
- [ ] **How to run it.** Write down how an app owner starts the API:
  `uv run --package reconix-api python -m reconix_api.main` serves 127.0.0.1:8000 against
  Postgres after `alembic upgrade head`. `RECONIX_KALI_MCP_URL` has a default and
  `RECONIX_MCP_AUTH_TOKEN` is optional, but without `RECONIX_JOB_TOKEN_SECRET` (already listed
  in `.env.example`) actions cannot run.

### 3. Turn API calls on in the apps (app owners, from `apps/`)

- The lead and the app owners agree to lift the "static data only" rule. That rule lives in
  three places: `apps/CLAUDE.md` ("Data: static only"), the "Not now" notes in `wire-backend` and
  `backend-integrator`, and the no-API check in `apps/.claude/hooks/post-edit-check.sh`. Keep a
  mock mode (`RECONIX_MOCK=1`) so the demo and the current tests still run offline.
- New dependencies: ask the lead first (`AGENTS.md` section 10), then give the reason in the PR.
  That means `httpx` for the TUI and `openapi-typescript` for the web's `gen-api-types` script.
  Neither is installed today.
- Fix two parts of `wire-backend` before using it:
  - The approval section: the API takes no confirmation token and no hash from the client (see
    Rules).
  - The config layer: it reads `RECONIX_TOKEN` from the environment, but the token comes from
    `POST /sessions` and stays in memory (see Rules).

### 4. Wire one flow step per PR, in this order

Follow `wire-backend` for the layers, the workers, the errors and mock mode. The table maps
today's TUI store functions (`apps/tui/reconix/store/__init__.py`) to the API (`/api/v1`).

| Step | TUI store today | API call |
|---|---|---|
| Start | `new_assessment`, `current_operator` | `POST /sessions` (the token is shown once), `GET /operator` |
| Scope | `select_template`, `edit_scope`, `get_scope` | `POST /sessions/{id}/scope-manifests`, `PATCH /scope-manifests/{id}`, `GET /scope-manifests/{id}` |
| Approve scope | `approve_scope`, `reject_scope` | `POST /scope-manifests/{id}/submit` creates a scope approval, then `POST /approvals/{id}/approve` or `/reject`. The assessment becomes ACTIVE. |
| Plan | `run_plan`, `plan_tasks`, `plan_overview` | `POST /assessments/{id}/plan`. The steps are in `agent_runs.plan` (`GET /sessions/{id}/agent-runs`). |
| Approve action | `get_approval`, `request_confirmation`, `approve`, `reject` | `GET /approvals`, `GET /approvals/{id}`, `GET /actions/{action_id}` (for `guardrail_report`), `POST /approvals/{id}/approve` (with `typed_target` for HIGH), `POST /approvals/{id}/reject` |
| Run | `advance`, `get_run`, `step_states`, `counters` | Poll `GET /assessments/{id}/actions` and `GET /actions/{id}` every 2 s. There is no WebSocket yet. The tool runs inside the request for an approval (`POST /approvals/{id}/approve`) and for a LOW action (`POST /assessments/{id}/actions`), so make those calls in a worker with a long timeout. |
| Analyze | a run phase | `POST /assessments/{id}/analyze` |
| Findings | `list_findings`, `get_finding`, `triage_finding` | `GET /findings?assessment_id=`, `GET /findings/{id}`, `PATCH /findings/{id}` (`finding_status` only, see step 1), `GET /evidence/{id}` |
| Report | `generate_report`, `report_data` | `POST /assessments/{id}/reports`, `GET /reports/{id}`, `POST /reports/{id}/review-requests`, `GET /reports/{id}/download?format=PDF\|DOCX\|JSON` |
| Providers | `list_providers`, `set_provider`, `activate` | `GET`/`POST /llm-providers`, `PATCH`/`DELETE /llm-providers/{id}`, `POST /llm-providers/{id}/activate`. A provider that runs off this computer answers with a `configuration` approval and becomes active only after `POST /approvals/{id}/approve`. The TUI's `activate()` is immediate today. |
| Close | `close_session` | `POST /sessions/{id}/close` |

**Web:** start with Assessments, Overview and Findings, then finding detail (masked evidence and
check result), the approved scope, and report download. Replace the reads in
`src/lib/data/store.ts` with server-only calls in `src/lib/api/`. Adapt the responses to the
view types in `src/lib/data/adapt.ts` so the components don't change. The web stays read-only
for assessments.

### 5. Test each step

- **Backend:**
  - `uv run --package reconix-api pytest services/api/tests`
  - on merge day, the full-flow test (`run-full-flow-test`, `services/api/tests/e2e/`)
- **TUI:**
  - tests for success, 401, 403, 409, 422 and network failure, with `httpx` mocked
  - mock mode still runs the whole demo
  - run with `uv run --package reconix-tui pytest apps/tui/tests`
- **Web:**
  - vitest with `fetch` mocked
  - `npm run lint && npm run typecheck && npm test`
  - then `npm run build && npm run e2e`
- **Reviews:**
  - root `security-reviewer` for every backend PR
  - the apps `security-reviewer` for app PRs that touch approvals, tokens or scope
  - `contract-reviewer` before every PR
- **Leaks:** after the first full run against the real API, run `run-leak-test`.

## Rules

- **The API decides; the apps ask.** The TUI's `store/scope.py`, `store/approvals.py` and
  `store/policy.py` may still pre-check to show a quick message, but the API's answer is final.
  Show 403, 409 and 422 to the person. Never retry around them or fall back to the local
  decision.
- **Approvals belong to the API.** The API owns the 30-minute expiry, single use and the SHA-256
  hash. The TUI builds the card from `GET /approvals/{id}` (`subject_snapshot` gives the tool,
  target and arguments; `risk_level` gives the risk) and `GET /actions/{action_id}` (the check
  result in `guardrail_report`). For HIGH, the person types the target and the TUI sends it as
  `typed_target`.
  In API mode, drop the local `request_confirmation()` token and the client-side hash. Never mark
  anything approved locally.
- **The apps never run a tool.** A run starts only through `POST /assessments/{id}/actions` or
  the plan, and always goes through the API's check.
- **ERD names and UPPERCASE enums.** The apps know only four severities (CRITICAL, HIGH,
  MEDIUM, LOW). The TUI filters out anything else (`store/findings.py`), and the web drops it
  (`src/lib/data/schema.ts`). The API also returns `UNKNOWN` and `NONE`, so the adapter must keep
  them and the views need a place to show them; otherwise those findings vanish from lists and
  counts. Run statuses are title case in the apps (`"Running"`, `"Awaiting input"`) and TUI
  triage statuses are lowercase (`open`, `false-positive`), while the API uses UPPERCASE.
  Translate in one adapter only: the TUI endpoint layer or the web's `src/lib/api/`. Then plan a
  follow-up PR that moves the views to the API values (`AGENTS.md` section 4).
- **Tokens.** The session token is shown once. Keep it in memory in the TUI and on the server in
  the web. Never put it in logs, snapshots, `~/.reconix/`, report files or a URL after sign-in.
- **Model calls move with their step.** When a step moves to the API, remove its direct model
  call in the same PR: in the TUI, the users of `reconix/llm/client.py`; in the web,
  `src/lib/assistant/llm.ts` and `src/lib/assistant/models/remote.ts`. Never leave two paths that
  can disagree.
- **The contract is `docs/openapi.json`.** Read it; never edit it. If the apps need a field the
  API doesn't have, ask the API owner. Don't work around it in the client.

## Done when

- The plan's week-2 flow (scope → plan → approve → run → findings) runs from the TUI alone
  against the real API.
- After a TUI run, the web shows the same findings, read from the API.
- No step that moved still calls a model directly, and mock mode still runs the demo.
- All suites pass, `docs/openapi.json` is current, and `run-leak-test` finds no secret.
- `AGENTS.md` section 11 (Known gaps) no longer lists the TUI and web static-data items. Remove
  each one in the PR that closes it.
