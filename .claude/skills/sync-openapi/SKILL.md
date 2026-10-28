---
name: sync-openapi
description: Export docs/openapi.json from the FastAPI app and regenerate the TUI and web API types from it. Use after any endpoint change, after every merge, and before a release.
---

# Sync the API contract

`docs/openapi.json` is the contract between all parts and all 4 repos. The TUI, the local web and the VS Code extension generate their types from it; the other repos copy it from Reconix-Core.

## Steps

1. Export from the app (no server needed):
   ```bash
   uv run --package reconix-api python -c "import json; from reconix_api.main import app; print(json.dumps(app.openapi(), indent=2, sort_keys=True))" > docs/openapi.json
   ```
2. Check the diff. Every removed or renamed field is a **breaking change**: tell the TUI, web and VS Code owners before merging.
3. Regenerate clients (once they exist; today both apps use static data, so skip this step and
   tell the TUI and web owners about the change instead):
   - Web: `cd apps/web && npm run gen-api-types` (openapi-typescript → `src/lib/api/`). The script
     is not in `apps/web/package.json` yet.
   - TUI: regenerate the models in the TUI `api/` client from the same file.
4. Update `apps/sample-data/` if response shapes changed, so both fake modes still match the real API.
5. Run the contract tests: `uv run pytest services/api/tests/contract -q`.
6. Commit `docs/openapi.json` together with the endpoint change.

## Rules

- Never hand-edit `docs/openapi.json`. It always comes from the code.
- Use `sort_keys=True` so diffs stay small.
