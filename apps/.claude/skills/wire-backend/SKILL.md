---
name: wire-backend
description: Procedure for moving one data source of the Reconix TUI (tui/reconix/store/) or local web (web/src/lib/data/) onto the local Core API described by docs/openapi.json, with a layered client, workers, backend validation and an offline fallback. Use when connecting any screen or view to the backend.
---

# Wire one data source to the Core API

One resource at a time (scope, plan, approval, execution, findings, report). The contract is
`docs/openapi.json` at the repo root: read it, never edit it. If the API lacks something, tell
its owner (see the root `AGENTS.md`); do not change `services/`.

## 1. Plan
Write down before coding:
- Endpoint, method, auth, and the roles allowed (OPERATOR / VIEWER).
- Request and response JSON, and the model it maps to (names from ERD V3, UPPERCASE enums).
- Which screens or views consume it; what they show while loading and on error.
- Which validation the backend performs (the UI never replaces it).

## 2. TUI layers (create if missing)

| Layer | File | Responsibility |
|---|---|---|
| config | `tui/reconix/config.py` | `RECONIX_API_URL`, `RECONIX_TOKEN`, `RECONIX_MOCK` from env |
| client | `tui/reconix/api/client.py` | one `httpx.AsyncClient`, timeouts, bearer header, typed errors |
| errors | `tui/reconix/api/errors.py` | `ApiError`, `AuthError` (401), `ForbiddenError` (403), `ValidationError` (422) |
| endpoint | `tui/reconix/api/endpoints/<resource>.py` | thin functions: path, params, JSON |
| store | `tui/reconix/store/<resource>.py` | calls the endpoint, or keeps today's body when `RECONIX_MOCK=1` |

Add `reconix.api` and `reconix.api.endpoints` to `tui/pyproject.toml` (`packages`) and `httpx` to both
`requirements.txt` and `pyproject.toml`.

Load in a worker, never in `compose()`:
```python
@work(exclusive=True)
async def load_findings(self) -> None:
    try:
        findings = await store.list_findings()
    except ForbiddenError:
        self.notify("Your role cannot view findings.", severity="error")
        return
    except ApiError as exc:
        self.notify(Text(f"Backend error: {exc}"), severity="error")
        return
    self._populate(findings)
```

## 3. Web
Server-only code in `web/src/lib/api/` calls the Core API with the token kept on the server;
adapt responses to the existing view types so components don't change. Routes still check the
session and Origin.

## 4. Security rules
- Approval: two calls. Request a confirmation (single-use token), then send the command hash
  **and** the token; the backend verifies both and the role. Never mark a step approved locally.
- Execution starts only from a backend response confirming approval and scope.
- Untrusted strings become `rich.text.Text` (TUI) or plain text nodes (web).
- Never log or display tokens.

## 5. Finish
- [ ] Offline/mock mode still runs the full demo; existing tests pass.
- [ ] Tests for success, 401/403/422 and network failure (mock `httpx` / `fetch`).
- [ ] Ask the `security-reviewer` subagent to check scope, approval or auth changes.
