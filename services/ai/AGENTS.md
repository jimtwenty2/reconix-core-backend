# AGENTS.md — AI Service

Owner: Sakphearoth (harness/: Pojim; data/tool-guides/: Youlong)

Read the root `AGENTS.md` first. These rules add to it.

Scope: Python package called directly by the API; no web server of its own.

## Folders

| Folder | Holds |
|---|---|
| `contracts.py` | `Plan`, `ProposedAction`: the shapes the API receives |
| `prompts/` | Reconix agent prompts, one file per step |
| `policies/agent-rules.md` | suggest only, never run, never leave scope |
| `tool_specs/` | tool schemas the model may call, copied from `tool_specs.json` in Reconix-Kali-MCP |
| `providers/` | the only place that calls a model, through LiteLLM. Default: RECONIX on local Ollama |
| `knowledge/` | ingest (LlamaIndex), Qdrant hybrid search (BGE-M3 + keywords), `search_knowledge()` |
| `agent/` | LangGraph graph and nodes, progress saved in Postgres |
| `analysis/` | the 8 parts of workflow v5, severity and OWASP mapping |
| `reports/` | text, PDF, DOCX, JSON |
| `harness/` | safety checks, masking, audit log (see below) |
| `data/tool-guides/` | one Markdown guide per tool, loaded into the knowledge search |
| `tests/evals/` | 20 test questions with expected answers |

## Rules

- The agent only **suggests**. It never runs a tool and never calls the Kali container.
- Every model call goes through `providers/`. Never import a model SDK anywhere else.
- Mask secrets before text reaches a prompt, a log or Qdrant.
- Prompts, policies and tool guides are plain Markdown changed by PR; the evals run on every change.
- Do not edit `tool_specs/` by hand; copy it from the Kali repo.

## harness/ (owner: Pojim)

- `pipeline.py` runs the checks in a fixed order: **input → scope → command → risk → loop**. The first block stops it.
- Checks are pure functions and never read the database; the API passes in what they need.
- The agent runs `check()` on every step it suggests, and the API runs it again before any tool runs.
- Each decision writes exactly one JSON audit line.
- Follow the `add-guardrail-check` skill for the current rules and the tests each check needs.

## Done when

`uv run --package reconix-ai pytest` passes, including the evals and the harness tests.
