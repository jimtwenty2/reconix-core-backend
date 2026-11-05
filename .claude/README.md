# .claude/ — Claude Code setup for Reconix-Core

Owner: Pojim. The rules themselves are in the root [`AGENTS.md`](../AGENTS.md); this folder holds
the tools that help agents follow them. `CLAUDE.md` at the repo root imports `AGENTS.md`.

## What is here

```
.claude/
├── settings.json          # shared permissions + hooks (committed)
├── settings.local.json    # your own overrides (local only, never committed)
├── agents/                # read-only reviewer subagents
├── skills/                # step-by-step guides, one per kind of task
├── hooks/                 # scripts the hooks in settings.json run
└── docs/                  # private planning notes (local only, never committed)
```

## Skills

Each skill is a `SKILL.md` with a `name` and a `description`. Claude Code picks a skill from its
description, so the description must say **what** the skill covers and **when** to use it.

| Skill | Use when |
|---|---|
| `add-endpoint` | Adding or changing a route, WebSocket, request or response |
| `add-db-migration` | Changing a table, column, index, enum value or seed row |
| `add-approval-flow` | Anything a person must approve; expiry, single use, action hash |
| `add-guardrail-check` | A harness check, masking rule or audit event |
| `add-tool-parser` | Turning nmap, nuclei, ZAP, semgrep or gitleaks output into findings |
| `add-fake` | Blocked on another part and need a fake |
| `sync-openapi` | After any route or schema change, after every merge, before a release |
| `integrate-apps-with-api` | Moving the TUI and web off their own data and model calls onto the Core API |
| `run-full-flow-test` | Merge day, before a release, or to prove the main flow still works |
| `run-leak-test` | After changing masking, parsers, evidence, reports or AI providers |
| `cut-release` | Tagging `vX.Y.Z` |
| `write-simple-code` | Every code change (house style) |
| `reconix-architecture` | Explaining how the parts connect, or before calling the Core API (reference only, no steps) |

## Subagents

All three are read-only (`Read, Grep, Glob, Bash`). They report findings with `file:line` and a
fix; they never edit code.

| Agent | Run it |
|---|---|
| `contract-reviewer` | Before every PR |
| `security-reviewer` | Before merging changes to the API, harness, approvals, parsers, reports or AI providers |
| `flow-debugger` | When the full flow, a Docker Compose run or a demo fails |

## Hooks (`settings.json`)

| Event | Hook | Effect |
|---|---|---|
| PreToolUse `Write\|Edit` | `hooks/protect-openapi.sh` | Denies hand edits to `docs/openapi.json` |
| PreToolUse `Bash` | `hooks/protect-main.sh` | Denies commit, merge, push, reset and the like while `Main` is checked out, and merging a PR whose base is `Main` |
| PreToolUse `Bash(git commit*)` | `hooks/scan-staged-secrets.sh` | Denies a commit that stages `.env` or a secret (gitleaks if installed, else a regex fallback that skips `deploy/lab/` and test fixtures) |
| PostToolUse `Write\|Edit` | inline ruff command | Runs `ruff format` and `ruff check --fix` on the edited `.py` file |

Hooks need `jq` on the `PATH`. The secret scan is stronger with `gitleaks` installed.

## Permissions (`settings.json`)

- **Allowed without a prompt:** uv sync/lock, pytest, ruff, alembic, the sample-data builder,
  read-only `docker compose` (ps, logs, config), npm lint/test/build, Playwright, read-only git and
  `gh pr` commands.
- **Denied:** reading `.env`, `*.pem`, `*.key` and `secrets/`; force-push; pushing to, switching
  to, renaming or opening a PR against `Main`. Commit, push and merge on `Develop` are allowed.
  `hooks/protect-main.sh` also blocks changes while `Main` is checked out and merging a PR into
  `Main`.

## Changing this folder

- A new skill: copy the shape of an existing one (front matter, then "Steps", "Rules", "Done
  when"). Add it to the tables here and in `AGENTS.md` section 9.
- A new hook: keep it a small shell script that reads the hook JSON with `jq`, prints a
  `permissionDecision` only when it must deny, and always `exit 0` otherwise.
- Never commit `settings.local.json` or `docs/`. A local hook refuses to stage them.
- `apps/.claude/` is a separate setup for the TUI and web, owned by the app owners.
