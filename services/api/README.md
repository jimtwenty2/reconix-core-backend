# Reconix API

The backend of Reconix: a FastAPI app that stores everything in PostgreSQL, asks the AI Service for
plans and analysis, runs the safety checks, and is the only part allowed to call the Kali tool
container. The terminal app, the local web and the VS Code extension all talk to it.

Package: `reconix_api` (Python 3.12, `src/` layout). It imports the AI Service (`reconix-ai`) as a
Python package, not over HTTP.

Rules for changing this code: [`AGENTS.md`](AGENTS.md). Whole-repo rules: [`../../AGENTS.md`](../../AGENTS.md).

## Run it

The API runs in Docker with the rest of the stack. From the repo root:

```bash
cp .env.example .env          # first time: fill in the empty values
./deploy/dev.sh               # builds the API image and starts everything
```

Then open http://127.0.0.1:8000/docs. The API migrates the database each time it starts.

| Task | Command (from the repo root) |
|---|---|
| Rebuild after a code change | `docker compose -f deploy/docker-compose.yml --env-file .env up -d --build api` |
| Follow the logs | `docker compose -f deploy/docker-compose.yml --env-file .env logs -f api` |
| Stop everything | `docker compose -f deploy/docker-compose.yml --env-file .env down` |

The image is built from [`Dockerfile`](Dockerfile) with the repo root as its build context.

## Run it manually

### Step by step in Docker

`./deploy/dev.sh` does the same as these commands. From the repo root:

```bash
cp .env.example .env                  # first time: fill in the empty values
mkdir -p data/code                    # Kali mounts it; create it so Docker does not own it

docker compose -f deploy/docker-compose.yml --env-file .env up -d postgres                     # 1. the database
docker compose -f deploy/docker-compose.yml --env-file .env up -d qdrant embeddings            # 2. knowledge search and its embedding model
docker compose -f deploy/docker-compose.yml --env-file .env up -d reconix-kali-container       # 3. the tool container
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build api                  # 4. the API: migrates the database, then serves

docker compose -f deploy/docker-compose.yml --env-file .env ps                                 # all five should be running
curl http://127.0.0.1:8000/api/v1/health
```

### On your computer, without Docker for the API

Useful for quick debugging with your own Python. The other containers keep no port on your
computer, so in this mode the API **cannot run tools** (Kali) or use the knowledge search (Qdrant
and the embedding server). It needs a database it can reach, so start one with a port:

```bash
uv sync
docker run -d --name reconix-dev-db -e POSTGRES_USER=reconix -e POSTGRES_PASSWORD=<password> \
  -e POSTGRES_DB=reconix -p 127.0.0.1:5433:5432 postgres:16
```

Set `RECONIX_DATABASE_URL` in `.env` to
`postgresql+psycopg://reconix:<password>@127.0.0.1:5433/reconix`, then:

```bash
uv run --package reconix-api alembic -c services/api/alembic.ini upgrade head
uv run --package reconix-api python -m reconix_api.main      # http://127.0.0.1:8000/docs
```

The AI Service reads `RECONIX_MODEL_URL` and `RECONIX_MODEL_API_KEY` from the environment, not
from `.env`, so export them in this shell to use the RECONIX model. Stop the Docker `api` service first (`docker compose -f deploy/docker-compose.yml --env-file .env stop api`), since both use port 8000. Remove the
database when you are done: `docker rm -f reconix-dev-db`.

## Use it

Every route is under `/api/v1`. Only `GET /health`, `POST /sessions` and
`POST /sessions/web-sign-in` are open; everything else needs a session token.

```bash
curl http://127.0.0.1:8000/api/v1/health                      # {"status":"OK"}

TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/sessions \
  -H "Content-Type: application/json" -d '{"interface":"cli"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/v1/assessments
```

In the Swagger UI, click **Authorize** and paste the token. The full contract is
[`docs/openapi.json`](../../docs/openapi.json), generated from this app.

## How a request flows

```
api/ (routes) → services/ (rules) → repositories/ (queries) → models/ (tables)
```

The main flow is scope → plan → approve → run → analyze → validate → report → download:

1. A person drafts a scope, submits it and approves it. The assessment becomes `ACTIVE`.
2. The AI suggests steps; a person can also send an action directly.
3. Every action goes through the harness checks. `BLOCKED` answers 422, `LOW` runs at once,
   `MEDIUM` and `HIGH` wait for an approval (single use, 30 minutes).
4. Right before a tool runs, the checks run again and the action's hash is compared with the
   approved one. The tool runs in the Kali container through `clients/mcp.py`.
5. The masked output becomes findings and evidence, which the AI analyzes and the report uses.

Every decision writes one line to the audit log (`data/audit/audit.jsonl`).

## Folders

| Folder | Holds |
|---|---|
| `src/reconix_api/main.py` | The app: Host check, CORS, error handlers, routers |
| `src/reconix_api/api/` | Routes, one file per resource |
| `src/reconix_api/services/` | Business rules |
| `src/reconix_api/repositories/` | Database queries |
| `src/reconix_api/models/` | The 16 tables of ERD V3, and the enums |
| `src/reconix_api/schemas/` | Request and response models |
| `src/reconix_api/core/` | Settings, database, errors, session and job tokens, masking, the 6 shared functions (`interfaces.py`) and their wiring |
| `src/reconix_api/clients/` | `mcp.py`: the only way to reach the Kali container |
| `src/reconix_api/parsers/`, `findings/` | Raw tool output into findings |
| `alembic/` | Database migrations (`alembic.ini` is in this folder) |
| `tests/` | `unit/`, `security/`, `integration/`, `contract/`, `e2e/`, plus `fakes/` and `fixtures/` |

## Settings

Read from the environment or the repo's `.env`, all with the prefix `RECONIX_`. The list with
explanations is [`.env.example`](../../.env.example); the defaults are in
[`src/reconix_api/core/config.py`](src/reconix_api/core/config.py). Inside Docker, Compose sets the
addresses of the other services (database, Kali, Qdrant, the embedding server) itself.

## Test it

Tests run on your computer with uv, from the repo root:

```bash
uv sync
uv run --package reconix-api pytest services/api/tests                          # all API tests
uv run --package reconix-api pytest services/api/tests/unit -q
```

Integration tests need a PostgreSQL 16 database of their own and are skipped without one:

```bash
docker run -d --rm --name reconix-test-db -e POSTGRES_PASSWORD=test \
  -p 127.0.0.1:55432:5432 postgres:16
RECONIX_TEST_DATABASE_URL=postgresql+psycopg://postgres:test@127.0.0.1:55432/postgres \
  uv run --package reconix-api pytest services/api/tests/integration
```

After changing a route or a schema, regenerate `docs/openapi.json` in the same pull request
(the `sync-openapi` skill).
