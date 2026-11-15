#!/usr/bin/env bash
# Reconix installer: one command on a fresh machine. It checks the tools, installs the
# packages, starts the stack in Docker and loads the knowledge base into Qdrant.
# Run it from anywhere: ./deploy/install.sh   (the same steps by hand are in README.md)
set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f deploy/docker-compose.yml --env-file .env)

# --- 1. Tools -----------------------------------------------------------------------------
# uv and Docker with Compose are needed; Node.js with npm only for the local web.
command -v uv >/dev/null 2>&1 || { echo "uv is missing: https://docs.astral.sh/uv/"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Docker is missing: https://docs.docker.com/get-docker/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose is missing: 'docker compose version' must work."; exit 1; }

# WeasyPrint draws the PDF report with Pango. The API image installs it, so this only
# matters when the API runs on this computer instead of in Docker (services/api/README.md).
if command -v ldconfig >/dev/null 2>&1; then
  ldconfig -p | grep -q pango || echo "note: libpango is missing; needed only to run the API outside Docker"
fi

# --- 2. Settings --------------------------------------------------------------------------
# Same as dev.sh: make .env, stop, and let the person fill it in. This script never asks
# for a model API key and never stores one: keys are added in the app and saved encrypted.
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Fill in the secrets (RECONIX_MODEL_URL for the AI), then run this script again."
  exit 1
fi

# --- 3. Packages --------------------------------------------------------------------------
echo "==> Installing the Python packages (uv sync)"
uv sync

if command -v npm >/dev/null 2>&1; then
  echo "==> Installing the local web packages"
  (cd apps/web && npm ci)
else
  echo "note: npm is missing, skipping the local web (see apps/README.md)"
fi

# The Kali container mounts this folder read-only; create it first, or Docker makes it root-owned.
mkdir -p data/code

# --- 4. Knowledge: download ---------------------------------------------------------------
# The full public set (CISA KEV — the newest 1000 exploited CVEs, CWE, OWASP Top 10 and
# API Top 10, ATT&CK) needs internet and writes services/ai/data/knowledge/. Without it the
# ingest falls back to the committed sample in services/ai/data/knowledge-sample/.
# Do this before the build: the API image copies services/ai, so the data goes in with it.
echo "==> Downloading the knowledge base (needs internet; the committed sample is the offline fallback)"
if uv run --package reconix-ai python -m reconix_ai.knowledge.download; then
  echo "    Full knowledge written to services/ai/data/knowledge/"
else
  echo "    Download failed (no internet, or a source is down): using what is already there -"
  echo "    the full download if you have one from an earlier run, otherwise the committed sample."
fi

# --- 5. Stack -----------------------------------------------------------------------------
echo "==> Building the API and starting the API, Postgres, Qdrant, embeddings and Kali"
echo "    (this also pulls the Kali image; the embedding model downloads on first start)"
"${COMPOSE[@]}" up -d --build --wait api

# --- 6. Knowledge: ingest -----------------------------------------------------------------
# Run inside the API container: it is the only part that reaches Qdrant and the embedding
# server, and neither has a port on this computer. The public knowledge is replaced on every
# run; documents people uploaded stay. See services/ai/README.md.
echo "==> Loading the knowledge base into Qdrant (a few minutes the first time)"
"${COMPOSE[@]}" exec -T api python -m reconix_ai.knowledge.ingest

echo "==> Ready: http://127.0.0.1:8000 (docs at /docs)"
echo "    Check:  curl http://127.0.0.1:8000/api/v1/health"
echo "    Apps:   apps/README.md (terminal app and local web)"
echo "    Logs:   ${COMPOSE[*]} logs -f api"
echo "    Stop:   ${COMPOSE[*]} down"
