---
name: make-static-data
description: Make static JSON data for the Reconix TUI and local web in the exact shape of a Core API response, by reading the backend (docs/openapi.json, services/api schemas and routes, ERD enums) instead of calling it. Use whenever a screen or view needs data the apps don't have yet, or when asked for sample, fake, demo or static data.
---

# Make static data in the API's shape

The apps don't call the Core API yet: they use static data only. Read the backend to learn what
a response looks like, then write that response as a JSON file. When the API is wired later,
the same shapes come from the network and the screens don't change.

## 1. Read the response shape (read-only)

| Read | For |
|---|---|
| `docs/openapi.json` (`paths`, `components.schemas`) | the endpoint, its response schema, required fields, enums |
| `services/api/src/reconix_api/schemas/<resource>.py` | the Pydantic models behind the schema (field types, defaults, examples) |
| `services/api/src/reconix_api/api/<resource>.py` | the route: method, path, status code, `response_model`, list vs one |
| `services/api/src/reconix_api/models/enums.py` | the allowed UPPERCASE enum values (ERD V3) |
| `services/api/tests/` | real request/response examples |
| `deploy/seed.sql` | the team's seed rows, to keep ids and names consistent |

Quick look at a schema:
```bash
jq '.components.schemas.ScopeOut' ../docs/openapi.json
jq '.paths["/scopes/{manifest_id}"].get.responses["200"]' ../docs/openapi.json
```

Never edit anything there, and never run the backend to get the data.

## 2. Write the file

Put it in `apps/sample-data/api/<resource>/<operation>.json`, the response body only:

```
apps/sample-data/api/
├── health/get.json                 # GET  /health
├── me/get.json                     # GET  /me
├── sessions/create.json            # POST /sessions          (201 body)
├── scopes/list.json                # GET  /scopes            (a JSON array)
├── scopes/get.json                 # GET  /scopes/{manifest_id}
├── scopes/submit.json              # POST /scopes/{manifest_id}/submit
├── assessments/get.json            # GET  /assessments/{assessment_id}
├── approvals/list.json             # GET  /approvals
├── approvals/get.json              # GET  /approvals/{approval_id}
├── approvals/approve.json          # POST /approvals/{approval_id}/approve
└── approvals/reject.json           # POST /approvals/{approval_id}/reject
```

An error case gets its own file with the API's error shape, for example
`approvals/approve.403.json` or `scopes/submit.422.json`.

Rules for the values:
- **Every required field, exact names and types** from the schema; no extra fields.
- **Enums UPPERCASE** from ERD V3: severity uses `NONE` (not `INFO`), uncertain results
  `UNKNOWN` (not `NEEDS_REVIEW`), roles `OPERATOR` / `VIEWER`.
- **Ids consistent across files**: the approval in `approvals/get.json` belongs to the
  assessment in `assessments/get.json`, which uses a scope from `scopes/get.json`.
- **Safe demo data only**: reserved domains (`example.com`, `.test`, `.invalid`), documentation
  IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), masked secrets (`••••`), fake
  evidence. Never a real host, credential or token.
- Dates in ISO 8601 UTC (`2026-10-27T09:00:00Z`).

## 3. Use it in the apps

- **TUI**: the store stays the only seam. Load the file in `tui/reconix/store/` (or seed the
  in-memory lists from it); screens keep calling store functions and never read files.
- **Web**: read it on the server side (`web/src/lib/data/` style: zod-validate, then adapt);
  components never fetch it themselves.
- Never add `httpx`, `requests`, `RECONIX_API_URL` or `localhost:8000` calls: the
  `post-edit-check` hook refuses them until the team wires the API.

## 4. Check

```bash
for f in sample-data/api/**/*.json; do jq empty "$f" || echo "bad JSON: $f"; done
```
Compare each file's keys with the schema's `properties` and `required`:
```bash
jq -r '.components.schemas.ApprovalOut.required[]' ../docs/openapi.json | sort
jq -r 'keys[]' sample-data/api/approvals/get.json | sort
```
Then run the suite of the app that reads it (`cd tui && pytest -q`, `cd web && npm test`).
