# Reconix apps: terminal (TUI) and local web

| Folder | What it is |
|---|---|
| `tui/` | The Reconix terminal app (Textual + Rich, Python ≥ 3.9). Runs a whole assessment: Start → Template → Plan → Approval → Execution → Findings → Report. |
| `web/` | The local web dashboard (Next.js 16, React 19). Read-only views of the runs the TUI saved, the AI Assistant and the docs. |
| `sample-data/` | Shared fake data (team scaffold). |

The TUI saves each run (secrets removed) to `~/.reconix/assessments/`; the web reads those files.
Nothing here needs the backend services: without them the TUI plays a realistic demo run.

## Run after cloning

```bash
git clone git@github.com:14th-Generation-Advanced-Course/reconix-core-backend.git
cd reconix-core-backend
git checkout Develop
```

### TUI

Needs Python 3.9 or newer (3.12 matches the workspace).

```bash
cd apps/tui
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt        # requirements-dev.txt also installs pytest
python -m reconix                      # or: python run.py
```

Keep the `.venv` inside `apps/tui`: the web's Security knowledge page looks for that Python first
(then the workspace's `.venv`, then `python3`; `RECONIX_PYTHON` overrides it).

To use a real model, add a provider with `/provider` and pick it with `/model` in the TUI.

### Web

Needs Node.js 20+ and npm.

**From the TUI:** type `/web`. The first time it installs the packages, then starts the
dashboard in the background and opens your browser, already signed in (log:
`~/.reconix/web.log`).

**By hand:**

```bash
cd apps/web
npm install
npm run dev                                   # the runs the TUI saved (~/.reconix/assessments)
RECONIX_DATA_DIR=sample-data npm run dev      # or the demo runs that ship with the web
npm run dev -- --no-open                      # don't open a browser
```

It prints a one-time sign-in link in the terminal; open it to sign in. The dashboard listens on
`127.0.0.1` only (port 3100 by default, `RECONIX_WEB_PORT` changes it). Models for the AI
Assistant are added in the web itself, with the composer's **+ Model** chip.

## Tests

```bash
# TUI
cd apps/tui && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q                                     # store + Textual Pilot tests
uvx ruff check --line-length 100 --select E,F,W,B reconix tests

# web
cd apps/web
npm run lint && npx next typegen && npm run typecheck
npm test                                      # vitest
npm run build && npm run e2e                  # Playwright on sample-data (needs Chromium)
```

The agent-mode tests need the backend `harness` package. It is not part of `apps/`, so those
tests skip (`needs_harness` in `tui/tests/support.py`) until it is installed.

## Generated files (never edit by hand)

| File | Made by (run in `apps/tui`) |
|---|---|
| `web/src/styles/tokens.css` | `python scripts/export_tokens.py` (from `reconix/theme.py`) |
| `web/src/content/docs/commands.json` | `python scripts/export_commands.py` (`--check` exits 1 when stale) |
| `web/sample-data/*.json` | `python scripts/make_sample_data.py` |
| `web/tests/knowledge-vectors.json` | `python scripts/make_knowledge_vectors.py` |

## Working with Claude Code

Start Claude Code **from this folder** (`cd apps && claude`) so it loads `apps/CLAUDE.md` and
`apps/.claude/`: the subagents, skills, guardrail hooks and permissions for the TUI and the web.
Started there, Claude stays inside `apps/`: it cannot read, change or run anything outside it
(the `stay-in-apps` hook; only the team rules and `docs/openapi.json` are open, read-only).
