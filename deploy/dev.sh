#!/usr/bin/env bash
# Start Reconix for local development: the API and every service in Docker.
# Run from anywhere: ./deploy/dev.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Fill in the secrets, then run this script again."
  exit 1
fi

# The Kali container mounts this folder; create it first, or Docker makes it owned by root.
mkdir -p data/code

echo "==> Building the API and starting the API, Postgres, Qdrant, embeddings and Kali"
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build --wait api

echo "==> Ready: http://127.0.0.1:8000 (docs at /docs)"
echo "    Logs: docker compose -f deploy/docker-compose.yml --env-file .env logs -f api"
echo "    Stop: docker compose -f deploy/docker-compose.yml --env-file .env down"
