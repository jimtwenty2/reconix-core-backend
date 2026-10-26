# AGENTS.md — Terminal app (Textual, Typer)

Owner: Vanhong

Read the root `AGENTS.md` first. These rules add to it.

Scope: UI only; no agent logic.

## Folders

| Folder | Holds |
|---|---|
| `app.py` | the Textual app |
| `commands/` | Typer commands (`reconix start`, `reconix web`) and slash commands |
| `shell/` | chat input, slash-command parser, history |
| `flow/` | which screen comes next (UI flow only) |
| `screens/` | start, template, scope, plan, approval, execution, findings, reports, provider |
| `widgets/` | approval card, finding row, status badge |
| `state/` | in-memory UI state; saves nothing |
| `api/` | httpx client and models from `docs/openapi.json`, plus fake mode |
| `scripts/export_commands.py` | command list for the docs site |

## Rules

- Talk to the backend only through `api/` over HTTP. Never import `reconix_api` or `reconix_ai`.
- No agent logic, no safety decisions and no database access in the TUI; the backend decides.
- Fake mode reads `apps/sample-data/` and must match the real API shapes.
- Never print or store a secret or token. Show masked values as the API returns them.
- Approval screens show the risk level; a `HIGH` approval asks the person to type the target.

## Done when

`uv run --package reconix-tui pytest` passes (Textual pilot tests).
