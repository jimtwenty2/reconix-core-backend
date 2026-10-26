---
name: run-full-flow-test
description: Run the end-to-end Reconix flow (scope, plan, approve, run, analyze, validate, report, download) against the API, with fakes or the real stack. Use on merge days, before a release, or to prove a change did not break the main flow.
---

# Run the full-flow test

The full test is **never cut**. It must pass from the API, the terminal app and the web Terminal page.

## The flow

1. Open a session (`OPERATOR`).
2. Draft, submit and approve a scope → `scope` approval, a `DRAFT` assessment (`RCX-YYYY-NNNN`) that becomes `ACTIVE`.
3. Ask for a plan → the AI run goes `RUNNING` → waiting for approval → `COMPLETED` / `FAILED` / `CANCELLED`.
4. Send an action → harness check → `LOW` runs, `MEDIUM`/`HIGH` wait; approve it (type the target for `HIGH`).
5. Tool runs through MCP → masked output saved → parsed into findings and evidence.
6. AI analysis of the results.
7. Validate a finding (PoC action) → a `validation_runs` row, shown as the finding's newest check.
8. Generate a report → `GENERATING` → `READY`; sign off with a `review` approval; download PDF / DOCX / JSON.

## Two modes

**Fast (fakes)** — no Docker needed. Uses the fakes in `services/api/tests/fakes/` (fake MCP server, fake AI, fake checks):

```bash
uv run pytest services/api/tests/e2e -q
```

**Real stack** — PostgreSQL, Qdrant, Ollama, API and the Kali container against the lab (Juice Shop + test repo on the `reconix-lab` network):

```bash
docker compose -f deploy/docker-compose.yml up -d
uv run pytest services/api/tests/e2e -q --real
```

To drive it by hand, use curl against `http://127.0.0.1:<port>` with the paths from `docs/openapi.json`. Never point it at anything outside the lab.

## Also check

- A wrong or reused job token is refused by the Kali container.
- A viewer session gets 403 on every step that changes data.
- The assessment timeline shows one audit line per decision.
- Nothing is stuck: a down container ends as `TIMED_OUT` or `FAILED`.

## When it fails

Use the `flow-debugger` subagent with the failing step and the output. Report which part (API, harness, MCP/parsers, AI, TUI, web) broke, so its owner fixes it the same day.
