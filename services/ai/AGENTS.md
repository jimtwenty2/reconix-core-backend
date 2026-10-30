# AGENTS.md — AI Service

Owner: Sakphearoth, with Vanneth (`harness/`: Pojim; `data/tool-guides/`: Youlong) · Last reviewed:
28 Oct 2026

Read the root [`AGENTS.md`](../../AGENTS.md) first. These rules add to it; if they disagree, the
root file wins.

Package: `reconix_ai` (`src/` layout). A Python package the API calls directly; it has **no web
server of its own**.

**Plan:** [`docs/reconix-plan-v2.md`](../../docs/reconix-plan-v2.md), sections "Khin Sakphearoth"
(AI Service) and "Chhim Pojim" (harness) in each week. **Deadline: the AI Service is 100% on
Mon 2 Nov.** After Tue 17 Nov (feature freeze), only bug fixes and prompt tuning go in.

## Folders (`src/reconix_ai/`)

| Folder | Holds |
|---|---|
| `contracts.py` | `Plan`, `ProposedAction`: field names match `AgentResponse`, `PlanStep` and `Action` in the API's `core/interfaces.py` |
| `agent/` | LangGraph graph `understand → find → (reflect ×1–5, with tool results) → plan → suggest → wait`; `ask_agent()` and `resume_agent()`; progress saved in Postgres (`checkpoints.py`). The run id is `agent_runs.agent_run_id` and the LangGraph thread id |
| `prompts/` | Markdown prompts, one per step: `system`, `understand`, `reflect`, `plan`, `analyze`, `report`, `chat` |
| `policies/agent-rules.md` | Suggest only, never run, never leave scope |
| `tool_specs/tool_specs.json` | The 5 tool schemas, copied from Reconix-Kali-MCP |
| `providers/` | The only place that calls a model, through LiteLLM (`client.py`); the 6 provider types (`settings.py`); safe base URLs (`base_url.py`); embeddings |
| `knowledge/` | Ingest (LlamaIndex), Qdrant hybrid search (BGE-M3 + keywords), `search_knowledge(query, filters)`, add-ons (`add_ons.py`: a person's own documents as `USER_DOC`, uploaded through the API; the ingest keeps them) |
| `analysis/` | The 8 parts of workflow v5, severity and OWASP mapping (empty, to build) |
| `reports/` | Report text (`answers.py`) and the PDF, DOCX and JSON files (`files.py`, `report.html`) |
| `memory/` | Accepted findings in Qdrant (empty, to build) |
| `harness/` | Safety checks, masking, audit log (see below) |

Outside `src/`: `data/knowledge-sample/` (CVE, CWE, OWASP, API Top 10, ATT&CK samples),
`data/tool-guides/` (one Markdown guide per tool), `models/Modelfile` (the built-in RECONIX model on
Ollama) and `tests/`.

## Rules

- **The agent only suggests.** It never runs a tool and never calls the Kali container. It may
  reason over results (ReflAct, up to 5 times) only with tools that read, never with tools that
  change anything.
- **Model calls** go only through `providers/`. Never import a model SDK anywhere else. Default: the
  built-in `RECONIX` model on local Ollama.
- **Providers:** `RECONIX`, `OLLAMA`, `OPENAI`, `ANTHROPIC`, `DEEPSEEK`, `OPENAI_API_COMPATIBLE`.
  Use the one set active in the API. Never show an API key, only its last 4 characters. Save which
  provider and model each run used.
- **Mask secrets** before text reaches a prompt, a log or Qdrant.
- **Limits:** cap the steps and the token budget. On a bad model answer, retry once; when the model
  is down, raise a clear error.
- **Uncertain results** use `UNKNOWN` (not `NEEDS_REVIEW`), and a person makes the call. Severity
  uses `NONE`, not `INFO`.
- **Knowledge:** keep each CVE or CWE in its own chunk; cut long guides at their headings.
- **Text files, not code:** prompts, policies and tool guides are plain Markdown changed by PR. The
  evals run on every prompt or policy change.
- **Do not edit `tool_specs/`** by hand; copy it from the Kali repo.
- Keep `contracts.py` in step with `core/interfaces.py`. A change to either needs the lead's
  approval and a notice to the API owner.

## harness/ (owner: Pojim)

- `pipeline.py` `check()` runs the checks in a fixed order: **input → scope → command → risk →
  loop**. The first block stops it.
- Checks are pure functions and never read the database; the API passes in what they need.
- The agent runs `check()` on every step it suggests, and the API runs it again before any tool
  runs.
- Plan limits:
  - input: at most 4,000 characters, no hidden characters or prompt injection;
  - scope: allowed IPs, domains, URL starts and paths; no `..`; exclusions always win;
  - command: only the 5 tools and their options from `tool_specs.json`; no shell characters;
    arguments as a list;
  - risk: unknown counts as `HIGH`; checking a finding is at least `MEDIUM`; above the scope's
    `max_risk` is blocked;
  - loop: the same command on the same target at most 3 times in 10 minutes, at most 20 actions a
    minute and 200 runs per assessment.
- `masking.py` replaces secrets with a label such as `[MASKED:password]` and counts them.
- `audit.py` writes exactly one JSON line per decision, with `assessment_id`, `session_id`,
  `actor` and the event types the web timeline needs. There are no roles, so a line has no `role`.
- Follow the `add-guardrail-check` skill for the current rules and the tests each check needs.

## Plan status (28 Oct 2026)

Keep this table true; update the row in the PR that changes it.

| Plan item | Week | Status |
|---|---|---|
| Package with LiteLLM in one place, RECONIX on Ollama by default | 1 | Done; base model in `Modelfile` is a placeholder until the speed check |
| Qdrant hybrid search, LlamaIndex ingest, `search_knowledge()` | 1 | Done |
| Agent: understand, find, plan, suggest, wait; progress in Postgres | 1 | Done; wired into the API as `ask_agent` (`core/agent.py`) |
| Prompts and agent rules as Markdown; tool specs copied from the Kali repo | 1 | Done |
| Harness: 5 checks, pipeline, masking, audit log | 1 | Done |
| ReflAct step (up to 5 times, read-only tools) | 2 | Done: `reflect` runs between find and plan when there are tool results; one masked line each time, its only tool is the knowledge search; stops at 5, when it asks for no lookup, or at half the token budget. The latest line opens the answer text. Not yet tried on the live model |
| The 8 parts of the workflow v5 analysis | 2 | Done: ANALYZE (find → analyze, no wait); `analysis/answers.py` enforces the 8 rules, and `check()` drops a blocked next step. Tested on 10 saved tool outputs with a scripted model; not yet tried on the live model |
| Use the active provider; all 6 provider types | 2 | Client done: all 6 types call through LiteLLM (cloud types need a key; OpenAI-compatible needs its address, `/v1` allowed). The API still sends only RECONIX until the `/llm-providers` endpoints pick the active row |
| Step and token limits, one retry, clear error when the model is down | 2 | Done: a bad answer is asked once more; `max_tokens` 2,000 per call; no call starts once an ask has used 20,000 tokens (the last call may go past it); 25 steps per ask; a model that is down is a clear `MODEL_UNAVAILABLE` (503 in the API), not retried |
| Report text and PDF, DOCX, JSON files | 2 | Done: REPORT writes the executive summary and methodology; `reports/files.py` makes the 3 files from the locked copy. PDF needs Pango (WeasyPrint) |
| Accepted findings in Qdrant | 2 | To do (`memory/` is empty) |
| Harness: disclosure, settings approvals, provider URL safety, timeline reader | 2 | Provider URL safety done; the rest to do |
| 20 eval questions, top-3 score | 3 | To do (`tests/evals/` is empty) |
| Hypothesis and hard-case tests for scope and command checks | 3 | To do |
| Time one full step on the demo laptop | 3 | To do |

## Tests (`tests/`)

| Folder | What it proves |
|---|---|
| `unit/agent/` | Graph, state, prompts, answers, checkpoints (with fakes in `fakes.py`) |
| `unit/harness/` | Each check, the pipeline order, masking and the audit line |
| `unit/knowledge/` | Chunks, items, keywords, paths, download, search and add-ons |
| `unit/providers/` | Client, base URL safety, embeddings |
| `evals/` | 20 questions with expected answers (empty, to add) |

## Commands

Run from the repo root.

```bash
uv run --package reconix-ai pytest                              # all AI tests
uv run --package reconix-ai pytest services/ai/tests/unit/harness -q

ollama pull qwen2.5:7b-instruct                                 # the built-in RECONIX model
ollama create reconix -f services/ai/models/Modelfile
```

## Done when

- `uv run ruff check . && uv run ruff format --check .` pass.
- `uv run --package reconix-ai pytest` passes, including the harness tests and, once they exist,
  the evals.
- A prompt or policy change has the eval results in the PR.
- The "Plan status" table above is updated if the change finishes a plan item.

**Week goals from the plan:** week 1, for an approved scope the agent suggests one step and waits.
Week 2, on 10 saved tool outputs the AI follows all 8 analysis rules and a report exports as PDF,
DOCX and JSON. Harness week 2: the leak test finds no secret anywhere.
