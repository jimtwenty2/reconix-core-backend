---
name: reconix-architecture
description: Explain how Reconix-Core is built — the parts (API, AI Service and harness, Kali container, TUI, web), the services in Docker Compose, the layers inside the API, how one action flows from the AI to a real tool, where the data lives, and how the REST API's resources and ids link together. Use when someone asks how Reconix works, where a piece of code belongs, or how the parts talk to each other, and before calling or reading responses from the Core API (curl, httpx, a client) so each call and id is understood in context.
---

# Reconix architecture

Answer from this map, then open the files it names to confirm details before quoting them.
Rules and owners are in the root `AGENTS.md`; this skill only explains how the parts fit.

## The big picture

```
 tester ──► TUI (apps/tui) ─┐
            Web (apps/web) ─┼──► Core API  (services/api, FastAPI, 127.0.0.1:8000)
            VS Code ────────┘        │  imports, in the same process
                                     ├──► AI Service + harness (services/ai, a library)
                                     │       ├─ LiteLLM ──► the chosen model provider
                                     │       └─ Qdrant + embeddings (knowledge search)
                                     ├──► PostgreSQL (all records, agent checkpoints)
                                     ├──► audit log (one JSON line per decision)
                                     └──► MCP client ──► Kali container (reconix-kali-container)
                                                            runs nmap, nuclei, zap, semgrep, ...
```

**The main rule: the AI suggests, the backend decides.** The AI never runs a tool. It proposes
an action, the harness checks it, a person approves it when needed, and only the API calls Kali.

**Main flow:** scope → plan → approve → run → analyze → validate → report → download.

## The parts

| Part | Folder | What it is |
|---|---|---|
| Core API | `services/api/` (`reconix_api`) | FastAPI + SQLAlchemy + Alembic. The only web server. Owns the database, approvals, tool runs, findings and reports. |
| AI Service | `services/ai/` (`reconix_ai`) | A Python library the API imports (no server of its own): `agent/` (LangGraph), `providers/` (LiteLLM, the only place model calls happen), `knowledge/` (Qdrant search), `analysis/`, `reports/`, `prompts/`, `policies/`. |
| Harness | `services/ai/src/reconix_ai/harness/` | The safety checks, masking and audit writer. Used by both the agent and the API. |
| Kali container | separate repo **Reconix-Kali-MCP** | An MCP server in a locked-down Kali image. Its tool list and risk rules are copied into `reconix_ai/tool_specs/` (`tool_specs.json`, `risk_ops.json`). |
| TUI | `apps/tui/` (`reconix`) | Textual + Typer terminal app. Still on in-memory data. |
| Local web | `apps/web/` | Next.js + xterm.js. Still on static data. |

## Docker Compose (`deploy/docker-compose.yml`)

| Service | Image | Job |
|---|---|---|
| `api` | `reconix-api:local` | The Core API, published on `127.0.0.1:8000` only; runs the migrations when it starts |
| `postgres` | `postgres:16` | All tables (ERD V3) and the LangGraph checkpoints |
| `qdrant` | `qdrant/qdrant` | Vector store for the tool guides and knowledge add-ons |
| `embeddings` | text-embeddings-inference | Turns text into vectors for Qdrant |
| `reconix-kali-container` | `dannygg02/reconix-kali-container` | Runs the tools over MCP; sees source code read-only at `/workspace/code` |
| `lab` | `deploy/lab/` | The only network targets may be tested on during development |

## Inside the API

```
api/  (routes, one file per resource)  →  services/  (the rules)
      →  repositories/  (queries)  →  models/  (tables)
core/     config, errors, security, session tokens, interfaces.py, wiring.py
schemas/  Pydantic request and response models
clients/  MCP client to Kali          parsers/ + findings/  raw tool output → findings
```

A route never queries the database; a repository holds no rules.

**The 6 shared functions** (`core/interfaces.py`, wired in `core/wiring.py`, faked in
`services/api/tests/fakes/`): `get_operator`, `check`, `get_approved_scope`, `write_audit`,
`ask_agent`, `call_tool`. Parts meet only through these, `docs/openapi.json`, the ERD names
and the Kali tool catalog. A part that is not wired answers `503 NOT_READY`.

## How one action runs

1. The person writes a scope; approving it fixes the targets, exclusions, time window,
   allowed tools, ports and `max_risk` (`scope_manifests`, `scope_targets`).
2. The agent (`ask_agent`) plans and proposes an action: a tool plus `list[str]` args.
3. **Check 1** — the harness `check()` runs in order **input → scope → command → risk → loop**
   (`harness/pipeline.py`). The first block stops it; the action is saved as `BLOCKED` (422 `ACTION_BLOCKED`).
4. `LOW` runs now. `MEDIUM` and `HIGH` wait for an approval (30 minutes, single use; `HIGH`
   needs the target typed). Above `max_risk` is blocked the same way.
5. **Check 2** — right before running, the API re-checks the action and re-hashes it against
   the approval (`services/actions.py`). No path skips this.
6. `call_tool` sends it to Kali over MCP with a fresh one-time job token; a `tool_runs` row
   records the try.
7. Output is masked, parsed into `findings` and `evidences` (`parsers/`, `findings/`), then
   analyzed, validated (`validation_runs`) and frozen into a `reports` snapshot.
8. Every decision writes exactly one audit line.

## Where the data lives

| Data | Where |
|---|---|
| Sessions, scopes, actions, tool runs, approvals, findings, reports | PostgreSQL — see `docs/erd/reconix-erd-v3-final.md`; schema from the Alembic migrations in `services/api/alembic/versions/` (readable copy: `docs/erd/reconix_schema.sql`) |
| Agent state for resume | PostgreSQL (LangGraph checkpointer, `agent_runs.checkpoint_id`) |
| Tool guides, knowledge add-ons | Qdrant (`services/ai/data/tool-guides/`) |
| Audit log | JSON lines file, one per decision |
| Uploaded or cloned source code | `RECONIX_CODE_DIR/<session>/` |
| Report files | the reports folder (`reports.exports`) |
| Provider API keys | `llm_providers.api_key_encrypted` (Fernet); only the last 4 shown |

## Calling the API: how the resources connect

Base URL `http://127.0.0.1:8000/api/v1`. Every route except `GET /health`, `POST /sessions`
and `POST /sessions/web-sign-in` needs `Authorization: Bearer <token>`. The full contract is
`docs/openapi.json` (generated; read it for exact fields). Errors always look like
`{"code": "UPPER_CASE", "message": "...", "details": {...}}` — read `code` first.

### Ids chain from one call to the next

```
POST /sessions {interface: web|cli|vscode, operator?}      → session_id + token (shown once)
 └─ POST /sessions/{session_id}/scope-manifests {targets, allowed_tools, max_risk, ...}
     → manifest_id  (DRAFT; edit with PATCH /scope-manifests/{manifest_id})
     └─ POST /scope-manifests/{manifest_id}/submit {name, type}
         → assessment.assessment_id (DRAFT, one per session) + approval_id (kind scope)
         └─ POST /approvals/{approval_id}/approve       → assessment ACTIVE, scope APPROVED
             ├─ POST /assessments/{assessment_id}/plan or /next-step  → agent_run.agent_run_id, plan, action
             └─ POST /assessments/{assessment_id}/actions {tool, target, arguments, purpose}
                 → action_id (201). Read action_status and approval_id in the answer:
                   LOW        → ran already; tool_runs[] holds the tool_run_id and masked output
                   MEDIUM/HIGH → PENDING + approval_id
                                 → POST /approvals/{approval_id}/approve {typed_target for HIGH}
                                   (runs it after check 2) or /reject
                   above max_risk / any check fails → 422 ACTION_BLOCKED, details.blocked_by
                 └─ findings: GET /findings?…, GET /findings/{finding_id}
                     ├─ GET /evidence/{evidence_id} (masked; real value only after a
                     │   disclosure approval: POST /evidence/{evidence_id}/disclosures → approve →
                     │   POST /evidence/{evidence_id}/disclosures/{approval_id}/reveal)
                     ├─ POST /findings/{finding_id}/validation-runs → validation_run_id
                     └─ PATCH /findings/{finding_id} (person's review, e.g. FALSE_POSITIVE)
             ├─ POST /assessments/{assessment_id}/analyze          → AI analysis of findings
             └─ POST /assessments/{assessment_id}/reports           → report_id (GENERATING→READY)
                 ├─ POST /reports/{report_id}/review-requests       → approval (kind review)
                 │   → POST /approvals/{approval_id}/approve
                 └─ GET  /reports/{report_id}/download   (only the exact copy that was reviewed)
```

### Which id belongs to which table

| Id in a response | Table (ERD V3) | Comes from |
|---|---|---|
| `session_id` | `sessions` | `POST /sessions` |
| `manifest_id` | `scope_manifests` (+ `scope_targets`) | `POST /sessions/{id}/scope-manifests` |
| `assessment_id` | `assessments` | scope submit |
| `approval_id` | `approvals` — `kind` says what it is for: scope, action, disclosure, configuration, review | submit, a MEDIUM/HIGH action, a disclosure, a review request, `POST /limit-settings` or a provider change |
| `agent_run_id` | `agent_runs` | plan, next step, chat, and every code scan (`/code-scans/{agent_run_id}`) |
| `action_id` | `actions` | `POST /assessments/{id}/actions`, or the agent |
| `tool_run_id` | `tool_runs` | running an action (one row per try) |
| `finding_id`, `evidence_id` | `findings`, `evidences` | parsing a tool run's output |
| `validation_run_id` | `validation_runs` | `POST /findings/{id}/validation-runs` |
| `report_id` | `reports` (+ `report_assessments`) | `POST /assessments/{id}/reports` or `/combined-reports` |
| `llm_provider_id` | `llm_providers` | `/llm-providers`; one is active and every agent run uses it |

### Other routes, by what they connect to

- **Chat and the AI:** `POST /sessions/{id}/chat` (and `/chat/stream`, `/vscode-chat`) talks
  to the agent through `ask_agent`; messages are in `GET /sessions/{id}/messages`.
- **Watching:** `GET /stream` (Server-Sent Events of every audit event),
  `GET /assessments/{id}/timeline` and `/overview`. `WS /terminal` runs the TUI for the web.
- **Knowledge:** `GET /knowledge/search` and `/knowledge-add-ons` read and write Qdrant.
- **Settings:** `/llm-providers` (keys shown as the last 4 only), `/limit-settings` (a change
  needs a configuration approval), `GET /operator` (who the token belongs to).
- **Code:** the `/sessions/{id}/code*` and `/code-scans/*` routes below; the same features
  as MCP tools at `http://127.0.0.1:8000/mcp`.

### Reading answers right

- A 201 on `POST .../actions` does not mean the tool ran: check `action_status`,
  `approval_id` and `tool_runs`.
- `422 ACTION_BLOCKED` is the harness saying no. It is a result, not a bug:
  `details.blocked_by` names the check (`INPUT`, `SCOPE`, `COMMAND`, `RISK` or `LOOP`), with
  `reason` and `risk`.
- `409` usually means state moved on: `SCOPE_CHANGED`, `ASSESSMENT_NOT_DRAFT`,
  `ACTION_NOT_PENDING`, `APPROVAL_ALREADY_DECIDED`, `APPROVAL_EXPIRED` (30 minutes) or
  `APPROVAL_ALREADY_USED`.
- `503 NOT_READY` means a shared function is not wired (`core/wiring.py`), e.g. no Kali URL.
- Values in answers are already masked. Never try to get a secret back except through the
  disclosure approval flow.
- Only call the API against targets in `deploy/lab/` or ones the person says they are
  authorized to test.

## Source code scans (a second flow)

Code goes in by upload, GitHub clone or local folder (`api/code.py`), then
`POST /sessions/{id}/code-scans` runs SEMGREP, GITLEAKS, TRIVY, GRYPE, OSV_SCANNER, SYFT and
SONAR_SCAN through the same check and `call_tool` path, incrementally, with an AI review per
finding (`services/code_review.py`). The same features are also an MCP server at `/mcp`
(`api/code_mcp.py`). Details: root `AGENTS.md`, "Source code scan".

## How to answer

- Lead with the part and the file, then explain. Quote paths as `path:line` after opening them.
- If the question is "where should this code go", answer with the part, the layer and the
  owner from the repository map in `AGENTS.md`.
- If something here disagrees with the code, the code wins — say so and point to the gap.
- Today vs. the plan: check "Known gaps" in `AGENTS.md` before saying a feature works.
