# Sample data

Static data for the TUI and the local web. The apps don't call the Core API yet: they use static
data only.

| Folder | What it holds |
|---|---|
| `api/<resource>/<operation>.json` | One Core API response body each, in the exact shape of `docs/openapi.json` (for example `scopes/get.json` for `GET /scopes/{manifest_id}`; `<operation>.<status>.json` for an error case). Made by reading the backend, never by calling it: see the `make-static-data` skill in `apps/.claude/skills/`. |
| `make_sample_data.py` | Team placeholder: builds sample files from `deploy/seed.sql`. |

The web dashboard's demo runs live in `web/sample-data/` (the TUI's saved-run format, made by
`tui/scripts/make_sample_data.py`).

Values: UPPERCASE enums from ERD V3 (`NONE`, not `INFO`; `UNKNOWN`, not `NEEDS_REVIEW`),
reserved domains and documentation IPs only, masked secrets, ISO 8601 UTC dates, and ids that
match across files.
