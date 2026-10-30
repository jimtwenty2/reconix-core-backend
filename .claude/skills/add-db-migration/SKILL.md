---
name: add-db-migration
description: Change the database schema (SQLAlchemy models + Alembic) in services/api. Use when adding or altering a table, column, index, enum value or seed row.
---

# Add a database migration

The schema follows **ERD V3** (16 tables) and **Data Dictionary V3** exactly. If a change is not in the ERD, agree it with the team first and update `docs/erd/` in the same PR.

## Rules

- Table and column names are exactly as in ERD V3. Enum values are UPPERCASE (`DRAFT`, `ACTIVE`, `NONE`, `UNKNOWN`, `TIMED_OUT`, ...).
- Severity uses `NONE` (not `INFO`). Uncertain results use `UNKNOWN` (not `NEEDS_REVIEW`).
- `sessions` has no `role` column (ERD V3 final), and Reconix has no roles.
- The built-in `RECONIX` AI provider is seed data.
- The schema starts as **one initial migration**. Ask the backend owner before adding a second revision. After a release tag, never edit an old revision; add a new one.
- Never store a secret in plain text. API keys are Fernet-encrypted; only the last 4 characters are ever shown.

## Steps

1. Edit or add the model in `services/api/src/reconix_api/models/`.
2. Generate the revision: `uv run --package reconix-api alembic revision --autogenerate -m "<short change>"`.
3. Read the generated file. Fix anything autogenerate got wrong (enum types, server defaults, index names).
4. Apply and roll back once to prove both ways work:
   `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`
5. Add indexes for columns used by list filters (`assessment_id`, `status`, `severity`, `created_at`).
6. Update `deploy/seed.sql` if the change affects sample data, then rebuild `apps/sample-data/` with `uv run python apps/sample-data/make_sample_data.py`, so the TUI and web fakes stay in sync.

## Done when

- Upgrade and downgrade both work on an empty PostgreSQL 16 database.
- `uv run pytest services/api` passes.
