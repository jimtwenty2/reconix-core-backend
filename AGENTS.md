# AGENTS.md — Reconix-Core (whole repo)

Owner: Pojim (lead)

Rules for AI coding agents (Claude Code, Codex, Cursor) working in this repo. Each part also has its own short `AGENTS.md`; read it before changing files there.

Scope: backend API, AI Service, guardrails, database, terminal app, local web, shared contracts.

## What Reconix is

An AI-assisted pentest tool. **The main rule: the AI suggests, the backend decides.** The AI never runs a tool itself. Every action goes through the safety checks, stays inside the approved scope, and waits for a person to approve it when the risk is MEDIUM or HIGH.

See `docs/project-context.md` for the 4 repos and who owns what.

## Layout

| Folder | Part | Owner |
|---|---|---|
| `services/api/` | Backend API (FastAPI, SQLAlchemy, Alembic) | Vanneth |
| `services/api/.../parsers/`, `findings/`, `clients/` (MCP) | Tool output → findings | Youlong |
| `services/ai/` | AI Service (LiteLLM, LangGraph, Qdrant) | Sakphearoth |
| `services/ai/src/reconix_ai/harness/` | Safety checks, masking, audit log | Pojim |
| `apps/tui/` | Terminal app (Textual, Typer) | Vanhong |
| `apps/web/` | Local web (Next.js, xterm.js) | Sokpiseth |
| `apps/sample-data/` | Shared fake data for the TUI and the web | shared |
| `deploy/` | Docker Compose, lab, seed data, `install.sh` | Vanneth |
| `docs/` | Project context, `openapi.json`, ERD V3 | Pojim |

The Kali tool container and its MCP server live in a separate repo, **Reconix-Kali-MCP**. The backend only talks to it through MCP and pulls its image by tag.

## Rules

- **Stay in your part.** Parts talk only through `services/api/src/reconix_api/core/interfaces.py` (the 6 shared functions) and `docs/openapi.json`. If the other side is not ready, use its fake (see the `add-fake` skill). Call out any change outside your part so its owner reviews it.
- **Names come from ERD V3.** Table, column and field names match ERD V3 and Data Dictionary V3. Enum values are UPPERCASE everywhere. Severity uses `NONE` (not `INFO`); uncertain results use `UNKNOWN` (not `NEEDS_REVIEW`).
- **Layering in the API:** api (routes) → services (logic) → repositories (database) → models (tables).
- **Never weaken the harness.** Do not add a path that skips `check()`, reorders the checks, or runs a tool without the API re-checking it.
- **No secrets anywhere.** Mask before saving, logging, showing, sending to the AI or storing in Qdrant. Only `.env.example` is committed; never read or commit `.env`.
- **Shell commands are lists.** Never build a command from a string.
- **`docs/openapi.json` is generated.** Never edit it by hand; export it from the FastAPI app (see the `sync-openapi` skill).
- **Keep code simple.** Follow the `write-simple-code` skill: plain functions, type hints, one job per function, no new dependency without a reason in the PR.
- Python packages use the `src/` layout; files and folders are `snake_case`. Tests mirror the source: `tests/unit/x/` tests `src/<pkg>/x/`.

## Commands

```bash
uv sync                                   # install the workspace
uv run ruff check . && uv run ruff format --check .
uv run --package reconix-api pytest       # or reconix-ai, reconix-tui
cd apps/web && npm ci && npm run lint && npm run test
```

## Skills

Use the skill that fits the task: `add-endpoint`, `add-db-migration`, `add-approval-flow`, `add-guardrail-check`, `add-tool-parser`, `add-fake`, `sync-openapi`, `run-full-flow-test`, `run-leak-test`, `cut-release`, `write-simple-code`. Before opening a PR, run the `contract-reviewer` agent; for changes to the API, harness, approvals, parsers, reports or AI providers, also run `security-reviewer`.

## Git

- `main` always works. Nobody pushes to `main` or `Develop` directly.
- Branch name: `<name>/<task>`, for example `pojim/scope-check`.
- Every pull request needs green CI and one review.
- Merge days: Tue 27 Oct, Sat 31 Oct, Tue 10 Nov. Tags: `v0.1.0` on Tue 3 Nov, `v1.0.0` on Fri 20 Nov.
- `plan.md` (your own tasks and rehearsal notes) stays on your computer and is never pushed.
