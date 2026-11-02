#!/usr/bin/env bash
# Start Reconix for local development: services in Docker, the API on this computer.
# Run from anywhere: ./deploy/dev.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Fill in the secrets, then run this script again."
  exit 1
fi

compose=(docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.dev.yml --env-file .env)

echo "==> Installing Python packages"
uv sync

echo "==> Starting Postgres, Qdrant, Ollama and the Kali MCP container"
"${compose[@]}" up -d --wait postgres
"${compose[@]}" up -d

echo "==> Migrating the database"
uv run --package reconix-api alembic -c services/api/alembic.ini upgrade head

echo "==> Starting the API on http://127.0.0.1:8000 (docs at /docs, Ctrl+C to stop)"
exec uv run --package reconix-api python -m reconix_api.main
