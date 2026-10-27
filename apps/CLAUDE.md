# CLAUDE.md: Reconix apps (TUI + local web)

Guidance for Claude Code working in `apps/`. Start it from this folder (`cd apps && claude`) so
`.claude/` (subagents, skills, hooks, permissions) is loaded. How to run everything: `README.md`.
Read `tui/README.md` and `web/README.md` before changing either app, and `web/AGENTS.md` before
writing Next.js code (this Next.js version differs from older ones: check
`web/node_modules/next/dist/docs/`).

## Scope

- Work only in `apps/tui/` and `apps/web/`. `services/`, `deploy/` and `docs/` belong to other
  team members: the `guard-paths` hook refuses edits there. Call out anything that needs them.
- The TUI does not import the backend. Agent mode (`/assess`) imports the `harness` package
  lazily; without it the scripted demo runs.
- Never run real scanners (nmap, nuclei, nikto, sqlmap, …) from here: the `guard-bash` hook
  refuses them. Execution belongs to the backend, behind scope checks and human approval.

## TUI (`tui/`)

Flow: **Start → Template → Plan → Approval → Execution → Findings → Finding Detail → Report.**

```
tui/reconix/
├── app.py         # ReconixApp: bindings, command line (mixes in shell/)
├── shell/         # navigation (FLOW), run_host, actions, dialogs, llm, agent, knowledge, web
├── flow/          # RunController, gates.py (gate → screen), phases
├── store/         # the only backend seam and the security boundary (templates/, knowledge/)
├── models/        # dataclasses
├── llm/           # providers, Fernet keys, LiteLLM client (no UI)
├── knowledge/     # `python -m reconix.knowledge` (the web's Security knowledge page calls it)
├── commands/      # slash commands: registry.py + builtin.py (COMMANDS)
├── widgets/       # reusable UI
├── screens/       # one file per flow frame; forms/ (FormScreen), choice.py (ChoiceScreen)
├── theme.py       # color tokens (CSS_TOKENS, WEB_TOKENS)
└── reconix.tcss   # stylesheet: $variables only, no hex
```

Rules that keep it safe:

- **The store decides; screens ask.** Every decision goes through a store function that
  validates it and raises `StoreValidationError`. Screens never touch `store.lists`, never hold
  data literals; getters return copies.
- **Never weaken the gates.** Testing starts only after the scope is approved and the plan is
  run. HIGH-risk actions need the double check: the single-use token from
  `request_confirmation()` and the matching command hash (`approve()` enforces both). The
  confirmation dialog defaults to "No, go back". Edit params/steps go through `edit_approval()`.
- **Secrets never reach** chat, logs, reports or saved copies (`snapshot.py` + `redact.py`).
  `TEST_PASSWORD` must never show up in output.
- **Never put user, tool or scope text into markup**: build `rich.text.Text`.
- Navigation only through `app.goto()/go_next()/go_prev()`; `FLOW` lives in
  `shell/navigation.py`. Dialogs open with `app.open_dialog(dialog, callback)`.
- Colors only from tokens (`theme.*`, `$vars`). A new subpackage goes in `pyproject.toml`'s
  `packages` list. Python 3.9-compatible (`Optional[X]`), lines ≤ 100, module docstrings.

## Web (`web/`)

- One viewer page (`/`) whose views switch via `?view=`; `/docs` inside the same frame.
- **Read-only for assessments**: no route writes what the TUI reads. The only writes are the
  assistant's own conversation/model files and knowledge changes through
  `python -m reconix.knowledge` (`src/lib/knowledge/cli.ts`, fixed args, no shell).
- Every page and route but sign-in needs a session (`src/proxy.ts`, and handlers check again).
  The server binds to 127.0.0.1, refuses other Host headers and checks every change's Origin.
- The model never supplies numbers (cards come from the saved data); questions are masked by
  `src/lib/assistant/redact.ts`, a port of the TUI's `store/redact.py`: change both, the
  vectors in `web/tests/redact-vectors.json` check both.
- `web/src/lib/data/schema.ts` mirrors `tui/reconix/store/snapshot.py`: change them together,
  then rerun `make_sample_data.py`.
- Colors only from `src/styles/tokens.css`, which is generated: never edit it.

## Commands

```bash
cd tui && source .venv/bin/activate
pytest -q                                  # or one file: pytest -q tests/test_store_run.py
python -m compileall -q reconix
uvx ruff check --line-length 100 --select E,F,W,B reconix tests
python scripts/export_commands.py --check

cd web
npm run lint && npx next typegen && npm run typecheck && npm test
```

## Team setup (`.claude/`)

| Subagent | Use it for |
|---|---|
| `tui-engineer` | TUI screens, widgets, bindings, TCSS |
| `web-engineer` | Web views, components, routes, styles |
| `backend-integrator` | Moving one TUI/web data source onto the Core API |
| `qa-tester` | Pilot tests (TUI), vitest / Playwright (web) |
| `security-reviewer` | Scope, approval gate, secrets, auth, anything risky (read-only) |
| `code-reviewer` | Final review against these rules (read-only) |

Skills: `add-screen`, `add-widget`, `theme-tokens`, `write-tui-test`, `write-web-test`,
`wire-backend`, `sync-generated`.

Guardrail hooks (`.claude/hooks/`): `guard-paths` (no edits outside `apps/`, no hand edits of
generated files, no `.env`), `guard-bash` (no real scanners, no push to `main`/`Develop`, no
force push, no `--no-verify`, no reading key files), `scan-staged-secrets` (on `git commit`),
`post-edit-check` (ruff + compile on Python edits, a security-review reminder on safety files).

## Git

Branch `<name>/<task>` from `Develop`; open a pull request (green CI, one review). Conventional
commit subjects: `feat(tui): …`, `fix(web): …`, `test(tui): …`, `docs(apps): …`.
