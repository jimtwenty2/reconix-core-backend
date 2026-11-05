# AGENTS.md — Reconix-Core (whole repo)

Owner: Pojim (lead) · Last reviewed: 30 Oct 2026

Rules for AI coding agents (Claude Code, Codex, Cursor) and the people who review their work.
`CLAUDE.md` imports this file, so Claude Code reads it on every session.

**Read order:** this file → the `AGENTS.md` of the part you change → the skill for the task.

| Part | Its own rules |
|---|---|
| Backend API | [`services/api/AGENTS.md`](services/api/AGENTS.md) |
| AI Service and harness | [`services/ai/AGENTS.md`](services/ai/AGENTS.md) |
| Terminal app | [`apps/tui/AGENTS.md`](apps/tui/AGENTS.md) |
| Local web | [`apps/web/AGENTS.md`](apps/web/AGENTS.md) |
| Deploy (Compose, lab, installer) | [`deploy/AGENTS.md`](deploy/AGENTS.md) |

A part's file adds to this one. If the two disagree, this file wins; flag the conflict to the lead.

---

## 1. What Reconix is

Reconix is an AI-assisted pentest tool that runs on the tester's own computer, against targets the
tester is authorized to test. A person writes a scope, the AI agent plans the test and suggests each
step, approved steps run real tools in a locked-down Kali container, and the results become
findings, analysis and a report.

**Main flow:** scope → plan → approve → run → analyze → validate → report → download.

**The main rule: the AI suggests, the backend decides.** The AI never runs a tool. It proposes
actions; the backend checks them, asks a person when needed, and only then calls the Kali
container.

Background: [`docs/reconix-plan-v2.md`](docs/reconix-plan-v2.md) (the 4 repos, team rules, owners,
weekly tasks per member, deadlines and the project structure) and
[`docs/erd/reconix-erd-v3-final.md`](docs/erd/reconix-erd-v3-final.md) (the data model).

---

## 2. Safety rules (never break these)

These rules are the product. A change that weakens one is a bug, even if every test passes.

| # | Rule | Enforced in |
|---|---|---|
| S1 | Every action runs the harness `check()` in this fixed order: **input → scope → command → risk → loop**. The first block stops it. | `services/ai/src/reconix_ai/harness/pipeline.py` |
| S2 | The check runs twice: once in the agent when it suggests a step, and again in the API right before the tool runs. No path may skip the second one. | `services/api/src/reconix_api/services/actions.py` |
| S3 | Nothing runs outside the approved scope (targets, exclusions, time window, allowed tools, max risk). | `harness/checks/scope.py` |
| S4 | `LOW` runs now. `MEDIUM` and `HIGH` wait for a person. Above the scope's `max_risk` is `BLOCKED` (HTTP 422). | `harness/checks/risk.py`, `services/actions.py` |
| S5 | Approvals expire after 30 minutes and are single use. The API re-hashes the action (SHA-256) before running it. `HIGH` needs the person to type the target. | `services/api/src/reconix_api/services/approvals.py` |
| S6 | Only tools in the Kali catalog (`tool_specs.json`) may run. Commands are `list[str]`, never strings; control and shell characters are blocked (free-shell tools — run_command, proxychains, msfconsole, smbclient — are exempt from the shell block and pinned to HIGH). Baseline risk comes from `tool_specs.json`, per-call escalation from `risk_ops.json`, and destructive tools gate at HIGH. | `harness/checks/command.py`, `harness/checks/risk.py`, `harness/catalog.py` |
| S7 | Tools are called only through the MCP client, with a fresh one-time job token. | `clients/`, `core/job_token.py` |
| S8 | Secrets are masked before anything is saved, logged, shown, sent to the AI or stored in Qdrant. Provider API keys are Fernet-encrypted and shown as the last 4 characters only. | `harness/masking.py`, `core/masking.py` |
| S9 | Every decision writes **exactly one** audit line. | `harness/audit.py`, `services/audit.py` |
| S10 | The API binds to `127.0.0.1`, rejects an unknown `Host`, and allows CORS only for the local web. Inside its Docker container it listens on `0.0.0.0` (`RECONIX_IN_CONTAINER=1`, set only there) and Compose publishes it on `127.0.0.1` only. | `main.py`, `core/config.py`, `deploy/docker-compose.yml` |

Paths without a prefix are under `services/api/src/reconix_api/` or
`services/ai/src/reconix_ai/` (`harness/`).

If a task seems to need breaking one of these, **stop and ask** (see section 10). Do not look for a
workaround.

---

## 3. Repository map

One uv workspace (Python 3.12) plus one npm app.

| Folder | What it holds | Owner |
|---|---|---|
| `services/api/` | Backend API: FastAPI, SQLAlchemy, Alembic. Package `reconix_api`. | Vanneth |
| `services/api/src/reconix_api/{parsers,findings,clients}/` | Raw tool output → findings; the MCP client | Youlong |
| `services/ai/` | AI Service: LiteLLM, LangGraph, Qdrant. Package `reconix_ai`. No web server of its own. | Sakphearoth |
| `services/ai/src/reconix_ai/harness/` | Safety checks, masking, audit log | Pojim |
| `services/ai/data/tool-guides/` | One Markdown guide per tool for the knowledge search | Youlong |
| `apps/tui/` | Terminal app: Textual, Typer. Package `reconix` (see section 11). | Vanhong |
| `apps/web/` | Local web: Next.js, xterm.js | Sokpiseth |
| `apps/sample-data/` | Fake data for the TUI and web, built from `deploy/seed.sql` | shared |
| `deploy/` | Docker Compose (`docker-compose.yml`, `kali-standalone.yml`), `lab/`, `seed.sql`, `install.sh` | Vanneth |
| `docs/` | `reconix-plan-v2.md`, `openapi.json` (generated), `erd/` | Pojim |
| `.claude/`, `AGENTS.md` files | Agent rules, skills, subagents, hooks (section 9) | Pojim |

Inside `reconix_api`: `api/` (routes, one file per resource) → `services/` (rules) →
`repositories/` (queries) → `models/` (tables). `core/` holds config, errors, security and
`interfaces.py`. `schemas/` holds the Pydantic request and response models.

The Kali container and its MCP server live in a separate repo, **Reconix-Kali-MCP**
(`reconix-kali-backend`). This repo talks to it only through MCP and pulls its image by tag.

---

## 4. Contracts between parts

Parts never import each other's internals. They meet only at these four contracts:

| Contract | File | Changed by |
|---|---|---|
| The 6 shared functions | `services/api/src/reconix_api/core/interfaces.py` | Lead approval + whole-team notice |
| The HTTP API | `docs/openapi.json` | **Generated** from the FastAPI app (`sync-openapi` skill). Never hand-edited. |
| Data names | ERD V3 and Data Dictionary V3 (`docs/erd/`) | Lead approval |
| Tool catalog + risk | `tool_specs.json` and `risk_ops.json` from Reconix-Kali-MCP, copied into `services/ai/src/reconix_ai/tool_specs/` | Copy from the Kali repo (`sync-kali-backend` skill); never hand-edit |

**The 6 shared functions** (`Interfaces` dataclass): `get_operator`, `check`,
`get_approved_scope`, `write_audit`, `ask_agent`, `call_tool`. `core/wiring.py` wires the real ones and
tests wire the fakes in `services/api/tests/fakes/`. If the other side is not ready, use its fake
(`add-fake` skill) and don't wait.

**Names and values:**

- Table, column and field names match ERD V3 exactly. Use its words (`assessment`, `tool_run`,
  `finding`, `approval`), never synonyms.
- Enum values are UPPERCASE everywhere: Python, SQL, TypeScript, sample data.
- Severity uses `NONE`, not `INFO`. Uncertain results use `UNKNOWN`, not `NEEDS_REVIEW`.
- There are no roles: anyone with a valid session token may do everything. ERD V3 has no
  `sessions.role`.
- Errors use one shape: `{"code": "UPPER_CASE", "message": "...", "details": {...}}`.

### Source code scan

Code goes into `RECONIX_CODE_DIR/<session>/` (Kali sees it read-only at
`/workspace/code/<session>`). Every input replaces the session's code, and every one drops
`.git/`, links, non-regular files and the folders `node_modules .venv venv __pycache__ dist
build target .idea .vscode`, with the upload limits (`RECONIX_MAX_UPLOAD_MB`, 20 000 files).

| Input | Route (under `/api/v1`) | Notes |
|---|---|---|
| Upload | `POST /sessions/{id}/code/sync`, then `PUT /sessions/{id}/code` (tar.gz) | Sync says which files (by sha256) the upload must hold |
| GitHub URL | `POST /sessions/{id}/code/clone {url, token?}` | Only `https://github.com/<owner>/<repo>`. A clone under `RECONIX_LOCAL_REPO_ROOTS` (comma-separated, searched 4 levels deep, matched on `origin` in `.git/config`) is copied first, never pulled. Otherwise `git clone --depth 1` over https only, 300 s. A local clone the deny list refuses (Reconix's own repo, a dotfiles repo at `~`) is cloned from GitHub instead. A private repo: pass `token` (sent to git through the environment only; never stored, logged, audited or echoed in errors); without one, this computer's git credential helper applies (ssh `insteadOf` rules do not, since only https is allowed). git gets no `RECONIX_*` variable, no hooks and no password prompt. Audit `CODE_CLONED {url, source: LOCAL_CLONE\|GITHUB, files}` |
| Local folder | `POST /sessions/{id}/code/folder {path}` | Absolute, resolved, must be a folder. **Deny list** (refused when inside one, or holding one): `~/.ssh ~/.gnupg ~/.aws ~/.azure ~/.config/gh ~/.config/gcloud ~/.config/google-chrome ~/.config/chromium ~/.mozilla ~/.kube ~/.docker ~/.password-store ~/.local/share/keyrings ~/.claude /etc /proc /sys /dev /root /boot /var /run`, and `RECONIX_CODE_DIR`, the reports folder and the audit log folder (so Reconix's own repo, with its `.env`). Audit `CODE_COPIED {path, files}`, or `CODE_FOLDER_REFUSED {code}`. A copy that cannot be stored leaves the old code |

**Scan:** `POST /sessions/{id}/code-scans {paths?, tools?, analyze=true}` (202). The first one
approves a scope that is only the session's code folder by itself (one `SCOPE_APPROVED` line,
`reason: CODE_SESSION_FOLDER`, also kept on the approval) and reuses it later. That scope takes
only the code scan's own tool calls, with no options: any other action on it is BLOCKED
`CODE_SCAN_ONLY`. `POST /assessments/{id}/code-scans` still
works on a scope written by hand. Then `GET /code-scans/{id}`, `POST /code-scans/{id}/cancel`,
`GET /code-scans/{id}/findings?include_false_positives=` (path, line, rule, masked snippet,
`verdict`, `explanation`, `fix_recommendation`) and `GET /code-scans/{id}/logs/{tool}` (a tool's
masked output as text, e.g. the `sonar_scan` log). Each tool is one `send_action` on a
per-scan copy (`<session>/_reconix_scan_<run8>/`: every file in `reconix-<session hex>/`, the
SonarQube project name, and the changed files in `changed/`; removed afterwards):

| Tool | Reads | Runs when |
|---|---|---|
| SEMGREP, GITLEAKS | `changed/` | some file is new or changed |
| TRIVY, GRYPE, OSV_SCANNER, SYFT | every file | a full scan, or a manifest or lockfile changed |
| SONAR_SCAN | every file | anything changed |

- **Incremental:** a full scan runs the first time, when Kali's tool versions (`tools_info`)
  change or the tool set grows. Otherwise only the due tools run, and earlier findings of
  unchanged files carry over (`plan.carried`). A rescan with no change makes no Kali call.
  A `paths` scan compares only the files under its paths; the rest keep what the last scan
  knew. A tool that was due and failed keeps its earlier findings on a changed file.
  Dependency findings are one per vulnerability, package and manifest.
- **Notes, not failures:** a BLOCKED or failed tool becomes a note (`"GRYPE FAILED"`,
  `"TRIVY BLOCKED TOO_MANY_ACTIONS"`); the scan
  fails only when every due tool failed. A scan cut off by an API restart ends FAILED
  `INTERRUPTED` at the next start. SYFT gives a note `SYFT <n> packages`, SONAR_SCAN a
  note `SONAR_SCAN OK|FAILED`; neither gives findings. GITLEAKS findings are HIGH.
- **AI review** (`services/code_review.py`): a verdict per finding (`CONFIRMED` only from a
  validation), cached per finding, file hash and model in `plan.reviews`. The prompt holds a
  masked ±20-line window inside a random `<data X>` fence; lines of secret findings are
  `[MASKED]`, and a file no gitleaks run read as it is now (GITLEAKS not selected, or it
  failed on the changed files) sends no code at all. `include_false_positives=false` hides an
  AI `likely_false_positive` only below HIGH and never for GITLEAKS; a person's FALSE_POSITIVE
  always.
- **The 200-runs cap** (harness loop check) is per assessment, and a session keeps one
  assessment: about 28 full 7-tool scans, more when rescans are incremental. Close the
  session and start a new one past it. The loop check's 20 actions a minute also applies.
- **Core MCP server** at `http://127.0.0.1:<api port>/mcp` (streamable HTTP, not under
  `/api/v1`, not in `openapi.json`), same session bearer token as REST, a thin wrapper over the
  same services (`api/code_mcp.py`). Tools: `sync_code`, `clone_repo`, `copy_folder`,
  `start_code_scan`, `get_code_scan`, `watch_code_scan` (progress each change, 10 s heartbeat),
  `cancel_code_scan`, `list_code_findings`, `get_code_scan_log`. The upload itself stays REST
  `PUT /sessions/{id}/code`. Errors are `CODE: message`.
- **Kali for code scans** is `reconix-kali-container` in `deploy/docker-compose.yml`. With the
  API on the host, run it standalone instead (`deploy/kali-standalone.yml`, see
  `deploy/AGENTS.md`): `RECONIX_KALI_MCP_URL=http://127.0.0.1:8096/mcp` and an absolute
  `RECONIX_CODE_DIR`.

---

## 5. Code rules

The full house style is the `write-simple-code` skill. The short version:

- **Stay in your part.** If a change must touch another part, keep it small and name that part's
  owner in the PR so they review it.
- **Layering:** a route never queries the database; a repository holds no business rules; services
  hold the rules.
- **Simple code:** plain functions, Pydantic models or dataclasses, one job per function, type hints
  on every Python function. No new dependency without a reason in the PR description.
- **Fail loudly:** raise the shared error shape; never return `None` to hide a failure or swallow an
  exception.
- **No secrets:** only `.env.example` is committed. Never read, print or commit `.env`, keys or
  tokens. Test fixtures use obvious fake values.
- **Model calls** go only through `services/ai/src/reconix_ai/providers/` (LiteLLM). Never import a
  model SDK anywhere else.
- **Schema changes** go through Alembic (`add-db-migration` skill), never by editing tables by hand.
- **Layout:** Python packages use the `src/` layout; files and folders are `snake_case`. Tests
  mirror the source: `tests/unit/x/` tests `src/<pkg>/x/`.
- **Lint:** ruff, line length 100, rules `E F I B UP S`. `S` (bandit) is on: fix security warnings
  instead of adding `noqa`. Tests may use `assert` and fake tokens.

---

## 6. Commands

Run from the repo root unless noted.

```bash
# setup
uv sync                                         # install the whole workspace
cp .env.example .env                            # then fill it in; never commit it

# lint and format (must pass before any PR)
uv run ruff check . && uv run ruff format --check .

# tests, one package at a time
uv run --package reconix-api pytest services/api/tests
uv run --package reconix-ai  pytest services/ai/tests             # includes evals and harness tests
uv run --package reconix-tui pytest apps/tui/tests             # Textual pilot tests

# narrower runs
uv run --package reconix-api pytest services/api/tests/security -q
uv run --package reconix-api pytest services/api/tests/contract -q

# database: the api service migrates it when it starts. By hand, against a database you can
# reach (alembic.ini lives in services/api/):
uv run --package reconix-api alembic -c services/api/alembic.ini upgrade head

# local web
cd apps/web && npm ci && npm run lint && npm run test    # e2e: npm run e2e

# full stack
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml --env-file .env ps
```

Export the API contract after any route or schema change: see the `sync-openapi` skill.

---

## 7. Tests and "done"

| Folder (`services/api/tests/`) | What it proves |
|---|---|
| `unit/` | One function or class, no network, no database |
| `contract/` | Responses match `docs/openapi.json`; fakes match the real interfaces |
| `security/` | Every endpoint needs a session token (401), Host and CORS protections, no secret leaks |
| `integration/` | Real database and repositories |
| `e2e/` | The full flow, scope to download |
| `fakes/`, `fixtures/` | Shared fakes (`fake_core.py`, `fake_mcp.py`, `fake_ai.py`) and test data |

`services/ai/tests/` has `unit/` and `evals/` (20 questions with expected answers, run on every
prompt or policy change).

**A task is done when all of these are true:**

1. Lint and format pass.
2. The tests for every package you touched pass. New behaviour has a new test; a bug fix has a test
   that failed before the fix.
3. A new endpoint needs the session token. The no-token test in
   `services/api/tests/security/test_api_protections.py` checks every route by itself; only
   `GET /health`, `POST /sessions` and `POST /sessions/web-sign-in` are open, and adding to
   that list needs the lead.
4. If routes or schemas changed, `docs/openapi.json` is regenerated **in the same PR**.
5. If the schema changed, there is an Alembic migration and it upgrades from an empty database.
6. No secret, `.env` or local-only file (section 9) is staged.
7. You re-read the diff once as the reviewer would.

Report results honestly. If a test fails or a step was skipped, say so in the PR with the output.

---

## 8. Git and pull requests

- `Main` always works. Nobody changes `Main` directly: it moves only through a reviewed PR that a
  person merges. Changes normally reach `Develop` through a PR too, but you (and Claude) may
  also commit, push and merge on `Develop` directly; force-push is denied everywhere.
  `.claude/settings.json` and `hooks/protect-main.sh` enforce this.
- Open PRs against `Develop`. Every PR needs green CI and one review.
- Branch name: `<name>/<task>` (for example `pojim/scope-check`), or `feat/`, `fix/`, `chore/` plus
  a short name.
- Commit messages: conventional style with the part, for example
  `feat(api): chat messages per session` or `fix(harness): block IPv6 scope escape`.
- One topic per PR. Keep generated files (`openapi.json`, migrations) with the change that caused them.
- **Before opening a PR**, run the `contract-reviewer` agent. If the change touches the API, the
  harness, approvals, parsers, reports or AI provider settings, also run `security-reviewer`.
- PR description: what changed, why, which parts are touched, how it was tested, and any breaking
  change to `openapi.json` (tell the TUI, web and VS Code owners).
- Never force-push, never skip hooks (`--no-verify`), never rewrite shared history.

---

## 9. Claude Code setup (`.claude/`)

An overview of the folder is in [`.claude/README.md`](.claude/README.md).

### Skills: use the one that fits the task

| Task | Skill |
|---|---|
| Add or change a route, WebSocket, request or response | `add-endpoint` |
| Add or change a table, column, index, enum value or seed row | `add-db-migration` |
| Anything a person must approve; expiry, single use, action hash | `add-approval-flow` |
| A safety check, masking rule or audit event | `add-guardrail-check` |
| Parse nmap, nuclei, ZAP, semgrep or gitleaks output into findings | `add-tool-parser` |
| Blocked on another part; need a fake | `add-fake` |
| Regenerate `docs/openapi.json` and client types | `sync-openapi` |
| Move the TUI or web onto the Core API (what the backend adds first, store → endpoint map) | `integrate-apps-with-api` |
| Prove the main flow still works (merge day, pre-release) | `run-full-flow-test` |
| Prove no secret leaks after a run | `run-leak-test` |
| Tag a release | `cut-release` |
| Any code change (house style) | `write-simple-code` |
| How the parts connect; how API resources and ids link (before calling the API) | `reconix-architecture` |

### Subagents (read-only reviewers; they report and never edit)

| Agent | Use it |
|---|---|
| `contract-reviewer` | Before every PR: ERD names, enums, interfaces, openapi, layering, ownership |
| `security-reviewer` | Before merging changes to the API, harness, approvals, parsers, reports, AI providers |
| `flow-debugger` | When the full flow, Docker Compose run or a demo fails |

### Hooks and permissions (`.claude/settings.json`)

| Guard | When | What it does |
|---|---|---|
| `hooks/protect-openapi.sh` | Before Write/Edit | Denies hand edits to `docs/openapi.json` |
| `hooks/scan-staged-secrets.sh` | Before `git commit` | Denies a commit with a staged `.env` or secret (gitleaks, else a regex fallback) |
| ruff post-edit hook | After Write/Edit of a `.py` file | Runs `ruff format` and `ruff check --fix` on that file |
| `hooks/protect-main.sh` | Before any Bash command | Denies commit, merge, push, reset and the like while `Main` is checked out, and merging a PR whose base is `Main` |
| `permissions.deny` | Always | No reading `.env`, keys or `secrets/`; no force-push; nothing that pushes to, switches to, renames or opens a PR against `Main` |

If a hook denies an action, fix the cause. Never disable or bypass a hook to get past it.

### Local-only files (never stage or commit)

`plan.md`, `CLAUDE.local.md`, `.claude/settings.local.json` and `.claude/docs/`. A local hook
refuses any git command that would stage them.

`apps/` has its own `.claude/` folder with the TUI and web agents, skills and hooks. Use it when
working inside `apps/`.

---

## 10. When to stop and ask

Stop, explain what you found, and ask the owner or the lead before you:

- change `core/interfaces.py`, ERD V3 names or an enum value;
- make a breaking change to `docs/openapi.json` (a field removed or renamed, an enum changed);
- change the order or behaviour of a harness check, or add a way to run a tool;
- edit files owned by another part beyond a small, clearly flagged fix;
- add a dependency, a new service or a new external network call;
- run any tool against something outside the lab network (`deploy/lab/`).

When unsure whether something counts, ask. A short question costs less than a reverted PR.

---

## 11. Known gaps (today vs. the plan)

Keep this list true; remove an item in the PR that closes it.

- **CI skips part of `apps/`.** Ruff in `.github/workflows/ci.yml` leaves out `apps/tui` (194
  files need `ruff format`) and `apps/.claude` (17 lint errors in `hooks/stay-in-apps.py`) until
  their owners fix them.
- **The TUI does not use the `src/` layout yet.** Its package is `apps/tui/reconix/`, and it uses
  in-memory and static data (`reconix/store/`), not the API. The `api/` client in its AGENTS.md is
  the plan.
- **The web uses static data** (`apps/web/src/lib/data/`). The generated API types and the
  `gen-api-types` script are not set up yet.
- **The automated leak test** (`services/api/tests/security/test_no_secret_leaks.py`) covers
  the database, logs, audit log, AI requests, API answers and report files, but not Qdrant
  (the API writes nothing there yet) or disclosure. Check those by hand with `run-leak-test`.
- Imported findings and finding categories: decision pending.
- **Kali standalone does not check job tokens.** The `dannygg02/reconix-kali-container` image
  checks only `KALI_MCP_AUTH_TOKEN`; whoever holds `RECONIX_MCP_AUTH_TOKEN` can call any Kali
  tool on `127.0.0.1:8096` and skip core's checks. It also keeps `NET_ADMIN`/`NET_RAW`, has
  internet and uses the `latest` tag (see `deploy/AGENTS.md`).
- **Kali's semgrep default rules (`p/default`) miss Jinja `| safe` XSS** (vuln-lab
  `posts.view.html:23`); only `r/python.flask` finds it. Adding rule sets is a decision pending.
- **Dependency findings only change when a manifest changes.** New advisories in the trivy and
  grype databases show up on the next scan that changes a manifest or Kali's tool versions.
- **An excluded path does not stop a tool on the folder around it.** The harness scope check
  blocks a target *inside* an excluded path, but not one that *contains* it, so a manual
  SEMGREP or GITLEAKS action on `/workspace/code/<s>` still reads `/workspace/code/<s>/secrets`
  when only that subfolder is excluded. Code scans are safe: they delete the excluded
  folders from the stored code first, and sync and upload never store them once the scope
  is approved. The harness fix belongs in `harness/checks/scope.py`.
- **ZAP runs give no findings yet.** The ZAP reader reads SARIF (`findings/sarif.py`), but
  Reconix-Kali-MCP's `zap_scan` returns a text summary and `zap_report` only returns the path
  of the SARIF file inside the container. Until Kali returns the JSON, a ZAP run is kept with
  an `OUTPUT_UNREADABLE` note.
- **The web Terminal page does not work with the API in Docker.** `WS /api/v1/terminal` runs
  the TUI inside the API, and the API image (`services/api/Dockerfile`) does not include it, so
  the terminal closes with `1011 TERMINAL_APP_MISSING`. It works when the API runs on the host
  (`services/api/README.md`, "Run it manually") with `uv tool install ./apps/tui`.
- **A code scan left RUNNING by an API restart stays RUNNING** (the scan is an in-process task).
  Cancel it with `POST /code-scans/{id}/cancel`.

---

## 12. Key dates

The full schedule, weekly tasks and what to cut first if we fall behind are in
[`docs/reconix-plan-v2.md`](docs/reconix-plan-v2.md). If a date here and the plan disagree, the plan wins.

| Date | Milestone |
|---|---|
| Tue 27 Oct, Sat 31 Oct, Tue 10 Nov | Merge days |
| Mon 2 Nov | Backend, AI Service and Kali container 100% |
| Tue 3 Nov | Release `v0.1.0` |
| Tue 17 Nov | Feature freeze |
| Fri 20 Nov | Release `v1.0.0` |
| Fri 27 Nov | Testing and deployment done |
