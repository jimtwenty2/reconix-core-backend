---
name: add-fake
description: Add or update a fake version of a shared interface, the MCP server, the AI agent, or the sample data, so a part can be built and tested before its real dependency is ready. Use when you are blocked by another part.
---

# Add a fake

Rule: if someone's part is not ready, use its fake. The real one replaces it on merge day without changing callers.

## Where fakes live

| Fake of | Location |
|---|---|
| the 6 shared functions in `core/interfaces.py` | `services/api/tests/fakes/` |
| the Kali MCP server | `services/api/tests/fakes/fake_mcp.py` |
| the AI agent / model provider | `services/api/tests/fakes/fake_ai.py` |
| the API, for the TUI | today: in-memory store in `apps/tui/reconix/store/`. Planned: fake mode in the TUI `api/` client, reading `apps/sample-data/` |
| the API, for the web | today: static data in `apps/web/src/lib/data/`. Planned: fake API in `apps/web/src/lib/api/`, reading `apps/sample-data/` |

## Rules

- A fake implements **exactly** the same interface (same function names, arguments, return types, errors) as the real one. If the interface must change, change `core/interfaces.py` first and tell the team.
- Fakes are deterministic: no randomness, no network, no clock surprises (pass the time in).
- Fakes still mask secrets and still return realistic UPPERCASE statuses, so tests catch the same bugs.
- A fake MCP server must still refuse a wrong or reused job token.
- Sample data comes from `deploy/seed.sql` via `apps/sample-data/make_sample_data.py`. Edit the seed, then rebuild; never hand-edit the JSON. Only the 5 tools may appear, and each run has its own code.
- Never ship a fake as the default in production config. Select it with an explicit setting or test fixture.
