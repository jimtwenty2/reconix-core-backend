# The Reconix API (with the AI Service and harness it imports), for deploy/docker-compose.yml.
# Build context: the repo root.
#   docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
FROM python:3.12-slim

# WeasyPrint draws the PDF report with Pango; git (over https) clones source repos for a
# code scan (POST /code/clone), with ca-certificates for TLS verification.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.12.24 /uv /bin/uv

WORKDIR /app
ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PATH=/app/.venv/bin:$PATH

# Dependencies first, so a code change does not reinstall them. uv needs every workspace
# member's pyproject.toml to read the lock file, the TUI's too.
COPY pyproject.toml uv.lock ./
COPY services/api/pyproject.toml services/api/
COPY services/ai/pyproject.toml services/ai/
COPY apps/tui/pyproject.toml apps/tui/
RUN uv sync --frozen --no-dev --package reconix-api --no-install-workspace

# The code. Installed editable (uv's default): the AI Service finds its data folder
# (services/ai/data) next to its source.
COPY services/api services/api
COPY services/ai services/ai
RUN uv sync --frozen --no-dev --package reconix-api

# Never run as root. data/ (audit log, reports, uploaded code) is a volume.
RUN useradd --uid 1000 --create-home reconix && mkdir -p /app/data && chown reconix /app/data
USER reconix

# Inside the container the API listens on 0.0.0.0; Compose publishes it on 127.0.0.1 only.
ENV RECONIX_IN_CONTAINER=1 \
    RECONIX_HOST=0.0.0.0 \
    RECONIX_PORT=8000
EXPOSE 8000

# Migrate the database, then serve.
CMD ["sh", "-c", "alembic -c services/api/alembic.ini upgrade head && exec python -m reconix_api.main"]
