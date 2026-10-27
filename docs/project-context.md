# Project context

One page: what Reconix is, the main rule, the 4 repos, who owns what.

## What Reconix is

Reconix is an AI-assisted pentest tool that runs on the tester's own computer. A person writes a scope, the AI agent plans the test and suggests each step, approved steps run real tools (nmap, nuclei, ZAP, semgrep, gitleaks) in a locked-down Kali container, and the results become findings, AI analysis and a downloadable report.

The person drives it from the terminal app, the local web, or the VS Code extension. All three talk to the same local backend.

Main flow: **scope → plan → approve → run → analyze → validate → report → download.**

## The main rule

**The AI suggests, the backend decides.**

- The AI agent never runs a tool. It only proposes actions.
- Every action passes the safety checks (input → scope → command → risk → loop), first in the agent and again in the API just before it runs.
- Nothing runs outside the approved scope. LOW actions run right away; MEDIUM and HIGH wait for a person to approve them; anything above the scope's max risk is blocked.
- Secrets are masked before anything is saved, shown, logged, sent to the AI or stored in Qdrant.
- Every decision writes one line to the audit log.

## The 4 repos

| Repo | Local clone | What it holds |
|---|---|---|
| **Reconix-Core** | `reconix-core-backend` | Backend API, AI Service, safety checks, database, terminal app, local web, shared contracts. One uv workspace. |
| **Reconix-Kali-MCP** | `reconix-kali-backend` | Kali tool container and its MCP server, cut down to our 5 tools. The backend pulls its image by tag. |
| **Reconix-Public-Web** | `reconix-public-web-frontend` | Public website and docs (static Next.js on GitHub Pages). |
| **Reconix-Vscode** | `reconix-vscode-extension` | VS Code extension. Talks only to the local Core API. |

GitHub org: `14th-Generation-Advanced-Course`.

## Who owns what

| Member | Role | Owns |
|---|---|---|
| Chhim Pojim | Project lead, safety checks, Kali MCP safety | Core `services/ai/src/reconix_ai/harness/`, `docs/`, agent files · Kali-MCP (with Youlong) · Vscode |
| Yann Vanneth | Backend API, database, release | Core `services/api/`, `deploy/` |
| Nut Youlong | Kali tool container, parsers and findings, main presenter | Kali-MCP · Core `parsers/`, `findings/`, MCP client · `data/tool-guides/` · Vscode |
| Khin Sakphearoth | AI Service, backup presenter | Core `services/ai/` (except `harness/`) · Public-Web |
| Horn Vanhong | Terminal app | Core `apps/tui/` |
| Nhoeun Sokpiseth | Local web | Core `apps/web/` |
| Choeng Sreyleak | Book, docs, public website, VS Code extension | Public-Web · Vscode |

## Day-one decisions

- **The 6 shared functions** live in `services/api/src/reconix_api/core/interfaces.py`, each with a fake so nobody waits on anyone: who the operator is, the safety check, reading the approved scope, writing to the audit log, asking the AI agent, and calling a tool.
- **Names come from ERD V3** (`docs/erd/`) and Data Dictionary V3. Enum values are UPPERCASE everywhere.
- ERD gaps closed: add `sessions.role` (`OPERATOR` or `VIEWER`); severity uses `NONE`, not `INFO`; use `UNKNOWN` wherever workflow v5 says `NEEDS_REVIEW`.
- Imported findings and finding categories: decision pending.
- **The API contract** is `docs/openapi.json`, exported from the FastAPI app after every merge. The other repos copy it from here.
- **Tool options** come from `tool_specs.json` in Reconix-Kali-MCP. The command check and the AI tool list both copy it from there.

## Naming and workflow

- Python packages use the `src/` layout; files and folders are `snake_case`.
- Branch name: `<name>/<task>`, for example `pojim/scope-check`. `main` always works; nobody pushes to it directly.
- Every pull request needs green CI and one review.
- Your own tasks and rehearsal notes go in a local `plan.md`, which is ignored by Git.

## Key dates

| Date | Milestone |
|---|---|
| Tue 27 Oct, Sat 31 Oct, Tue 10 Nov | Merge days |
| Mon 2 Nov | Backend, AI Service and Kali container 100% |
| Tue 3 Nov | Release `v0.1.0` |
| Wed 4 Nov | Implementation 50% check |
| Tue 17 Nov | Feature freeze |
| Fri 20 Nov | Implementation 100%, release `v1.0.0` |
| Fri 27 Nov | Testing and deployment done |

The full plan, to-do list and board are in the **Reconix Plan v2** artifact.
