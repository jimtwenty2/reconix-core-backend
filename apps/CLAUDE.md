# CLAUDE.md: Reconix apps (TUI + local web)

Guidance for Claude Code working in `apps/`. Start it from this folder (`cd apps && claude`) so
`.claude/` (subagents, skills, hooks, permissions) is loaded. How to run everything: `README.md`.
Read `tui/README.md` and `web/README.md` before changing either app, and `web/AGENTS.md` before
writing Next.js code (this Next.js version differs from older ones: check
`web/node_modules/next/dist/docs/`).

## Scope

- **Read the whole project, change `apps/` only.** Claude may read anything in this repo
  (`services/`, `deploy/`, `docs/`, …) to understand it, but change, create, delete or run
  things only in `apps/`. In Bash, a command that runs in or reaches a folder outside `apps/`
  must be read-only (`cat`, `ls`, `grep`, `find`, `git log/diff/show`, …: no `>`, `rm`,
  `sed -i`, `npm`, `python`, `git commit`). Nothing outside the project is open (home folder,
  system), and `.env`, `*.key` and `*.pem` files are never read. The `stay-in-apps` hook
  enforces this for every tool and every subagent. Call out a change another part needs; its
  owner makes it.
- The TUI does not import the backend. Agent mode (`/assess`) imports the `harness` package
  lazily; without it the scripted demo runs.
- Never run real scanners (nmap, nuclei, nikto, sqlmap, …) from here: the `guard-bash` hook
  refuses them. Execution belongs to the backend, behind scope checks and human approval.

## Data: real data from the Core API (no mock data)

Decided 2026-11-05 (Sokpiseth; lead and TUI owner review in the PR): the apps show only real
data. Everything comes from the local Core API (`services/api`, 127.0.0.1:8000), which runs
the checks and approvals and calls Kali over MCP. The apps never call Kali or a tool
themselves (rule S7), and there is no mock model, sample run or seed data in product code.

- **One client per app.** The TUI calls the API only from `tui/reconix/core_api/` (stdlib
  `urllib`, loopback only, the session token in memory). The web calls it only from
  server-only code in `web/src/lib/api/`, so the token never reaches the browser. The
  `post-edit-check` hook refuses API addresses anywhere else.
- **The contract is `docs/openapi.json`.** Read it, never edit it. If the apps need a field the
  API doesn't have, tell its owner (Vanneth); never work around it in the client.
- **The API decides; the apps ask.** Show its 401, 409, 422 and 429 answers to the person.
  Never retry around them, and never fall back to a local decision, a model call or made-up
  data. Without the API the apps say so ("Core API not running: start it with
  `./deploy/dev.sh`").
- **Translate values in one place**: `core_api/adapt.py` (TUI), `web/src/lib/api/adapt.ts`
  (web). UPPERCASE ERD V3 enums stay UPPERCASE; `NONE` and `UNKNOWN` severities are shown,
  never dropped.
- **Tests** use the fake API in `tui/tests/fakes/` (web: `web/tests/fakes/`), built in the
  exact response shapes. That is test code only; product code never imports it.
- **Still local** (no endpoint yet): test logins and the vault, local knowledge files, the
  `accepted` triage status, severity override and note, retest, and the template list.

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
- `web/src/lib/data/thinking.ts` (the Run log's thinking blocks) is a port of the TUI's
  `store/thinking.py`: change both, the vectors in `web/tests/thinking-vectors.json` check both.
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
| `backend-integrator` | Moving a data source onto the Core API |
| `qa-tester` | Pilot tests (TUI), vitest / Playwright (web) |
| `security-reviewer` | Scope, approval gate, secrets, auth, anything risky (read-only) |
| `code-reviewer` | Final review against these rules (read-only) |

Skills: `wire-backend` (move a data source onto the Core API), `make-static-data` (test
fixtures in the API's exact shape, for `tests/fakes/` only), `add-screen`, `add-widget`,
`theme-tokens`, `write-tui-test`, `write-web-test`, `sync-generated`.

Guardrail hooks (`.claude/hooks/`): `stay-in-apps` (read the project, change `apps/` only, see Scope),
`guard-paths` (no hand edits of generated files, no `.env` or key files), `guard-bash` (no real scanners, no push to `main`/`Develop`, no
force push, no `--no-verify`, no reading key files), `scan-staged-secrets` (on `git commit`),
`post-edit-check` (ruff + compile on Python edits, Core API calls only in the client, a security-review
reminder on safety files).

## Git

Branch `<name>/<task>` from `Develop`; open a pull request (green CI, one review). Conventional
commit subjects: `feat(tui): …`, `fix(web): …`, `test(tui): …`, `docs(apps): …`.
