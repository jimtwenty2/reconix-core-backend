# Reconix AI Service

The AI side of Reconix: the agent that plans a test and suggests each step, the safety harness
that checks every action, the knowledge search, and the report writer.

Package: `reconix_ai` (Python 3.12, `src/` layout). It has **no web server of its own**: the API
imports it as a Python package, so it runs inside the API's container.

Rules for changing this code: [`AGENTS.md`](AGENTS.md). Whole-repo rules: [`../../AGENTS.md`](../../AGENTS.md).

## The main rule

**The AI suggests, the backend decides.** The agent never runs a tool and never talks to the Kali
container. It proposes actions; the harness checks them, a person approves them when needed, and
only then does the API run them.

## What is inside

| Part | Folder | What it does |
|---|---|---|
| Agent | `src/reconix_ai/agent/` | A LangGraph graph: understand → find → reflect (with tool results) → plan → suggest → wait. Its progress is saved in PostgreSQL, so a run can resume after an approval |
| Prompts and policy | `src/reconix_ai/prompts/`, `policies/` | One Markdown prompt per step, and the agent's rules |
| Harness | `src/reconix_ai/harness/` | The safety checks in a fixed order (input → scope → command → risk → loop), secret masking, the audit log |
| Tool catalog | `src/reconix_ai/tool_specs/` | `tool_specs.json` and `risk_ops.json`, copied from Reconix-Kali-MCP. Never edit them by hand |
| Model providers | `src/reconix_ai/providers/` | The only place that calls a model, through LiteLLM |
| Knowledge | `src/reconix_ai/knowledge/` | CVE, CWE, OWASP and ATT&CK search in Qdrant (BGE-M3 vectors plus keywords), and people's own uploaded documents |
| Finding memory | `src/reconix_ai/memory/` | Accepted findings, searchable per assessment |
| Reports | `src/reconix_ai/reports/` | Report text and the PDF, DOCX and JSON files |
| Data | `data/` | `knowledge-sample/` (a small committed sample) and `tool-guides/` (one Markdown guide per tool) |

## AI providers

Six provider types, chosen and saved in the API:

- `RECONIX`, the default: the built-in model, served by the Reconix team on an OpenAI-compatible
  server. Its address and key come from `.env` (`RECONIX_MODEL_URL`, `RECONIX_MODEL_API_KEY`,
  `RECONIX_MODEL_NAME`); without `RECONIX_MODEL_URL` the AI features answer `PROVIDER_URL_MISSING`.
- `OLLAMA`, `OPENAI`, `ANTHROPIC`, `DEEPSEEK` and `OPENAI_API_COMPATIBLE`, added by a person in the
  API. Their API keys are stored encrypted and only the last 4 characters are ever shown.

The knowledge search does not use these providers. It turns text into vectors with BGE-M3, which
runs on CPU in the stack's `embeddings` container (no Ollama needed).

## Set up the AI and the knowledge

The stack runs in Docker (`./deploy/dev.sh` from the repo root).

1. **The AI model:** set `RECONIX_MODEL_URL` (and `RECONIX_MODEL_API_KEY` if needed) in `.env`,
   then restart the API: `docker compose -f deploy/docker-compose.yml --env-file .env up -d api`.
2. **The embedding model** downloads by itself (~2.3 GB) the first time the `embeddings`
   container starts. Wait until it is ready:
   ```bash
   docker compose -f deploy/docker-compose.yml --env-file .env logs -f embeddings      # ready when it says "Ready"
   ```
3. **The knowledge:** load it into Qdrant from the API container, which reaches both:
   ```bash
   docker compose -f deploy/docker-compose.yml --env-file .env exec api python -m reconix_ai.knowledge.ingest
   ```

The ingest uses the committed sample unless the full download is there. To get the full public
knowledge, download it on your computer (it needs internet), rebuild the API image so it is
included, and ingest again:

```bash
uv run --package reconix-ai python -m reconix_ai.knowledge.download
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build api
docker compose -f deploy/docker-compose.yml --env-file .env exec api python -m reconix_ai.knowledge.ingest
```

## Run it manually

The AI Service is not a server, so there is nothing to start on its own: it runs inside the API.
What you can run by hand are its scripts.

### In Docker (the usual way)

Run them in the API container, where they reach Qdrant and the embedding server:

```bash
docker compose -f deploy/docker-compose.yml --env-file .env exec api python -m reconix_ai.knowledge.ingest            # load the knowledge
docker compose -f deploy/docker-compose.yml --env-file .env exec api python -m reconix_ai.knowledge.ingest --rebuild  # drop and rebuild the collection
```

### On your computer, without Docker for the API

The stack's Qdrant and embedding server have no port on your computer, so start your own with a
port, then point the scripts at them:

```bash
uv sync
docker run -d --name reconix-dev-qdrant -p 127.0.0.1:6334:6333 qdrant/qdrant:v1.13.2
docker run -d --name reconix-dev-embeddings -p 127.0.0.1:8081:8080 -v reconix-dev-embeddings:/data \
  ghcr.io/huggingface/text-embeddings-inference:cpu-1.8 --model-id BAAI/bge-m3 --port 8080

export RECONIX_QDRANT_URL=http://127.0.0.1:6334
export RECONIX_EMBEDDINGS_URL=http://127.0.0.1:8081/v1     # also the default
uv run --package reconix-ai python -m reconix_ai.knowledge.ingest
```

Remove them when you are done: `docker rm -f reconix-dev-qdrant reconix-dev-embeddings`. To use
the API itself on your computer, see "Run it manually" in [`../api/README.md`](../api/README.md).

## Test it

Tests run on your computer with uv, from the repo root. They need no model, no embedding server
and no Qdrant:

```bash
uv sync
uv run --package reconix-ai pytest services/ai/tests                                  # all AI tests
uv run --package reconix-ai pytest services/ai/tests/unit/harness -q
```

`tests/evals/` is for the 20 questions with expected answers that run on every prompt or policy
change.
