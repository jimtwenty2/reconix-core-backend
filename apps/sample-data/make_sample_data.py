"""Build the sample JSON files from deploy/seed.sql.

The seed is loaded into an EMPTY PostgreSQL database, then the real API (in-process, no
server, no network) reads it back and each response body is saved as
apps/sample-data/api/<resource>/<operation>.json. So the files always have the exact shape
of docs/openapi.json and the same ids and names as the seed.

    docker run -d --rm --name reconix-sample-db -e POSTGRES_PASSWORD=sample \\
        -p 127.0.0.1:55433:5432 postgres:16
    RECONIX_SAMPLE_DATABASE_URL=postgresql+psycopg://postgres:sample@127.0.0.1:55433/postgres \\
        uv run python apps/sample-data/make_sample_data.py

Never point it at a database you use: it refuses one that holds other assessments.
"""

import json
import os
import secrets
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import get_db, get_session_factory
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.core.wiring import build_interfaces
from reconix_api.main import create_app
from reconix_api.models import Assessment

ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT / "deploy" / "seed.sql"
ALEMBIC_INI = ROOT / "services" / "api" / "alembic.ini"
OUT = Path(__file__).resolve().parent / "api"

# Ids from deploy/seed.sql.
SESSION_ID = "c0000000-0000-4000-8000-000000000001"
ASSESSMENT_ID = "a0000000-0000-4000-8000-000000000001"
MANIFEST_ID = "b0000000-0000-4000-8000-000000000001"
AGENT_RUN_ID = "d0000000-0000-4000-8000-000000000001"
ACTION_ID = "ac000000-0000-4000-8000-000000000003"  # ZAP, waiting for approval
APPROVAL_ID = "ab000000-0000-4000-8000-000000000003"
FINDING_ID = "f0000000-0000-4000-8000-000000000001"  # the confirmed SQL injection
EVIDENCE_ID = "f1000000-0000-4000-8000-000000000001"

# file -> GET path. Only reads whose answer depends on the seed alone (not on the session
# this script opens, or on ids the migration makes at random).
FILES = {
    "assessments/list.json": "/assessments",
    "assessments/get.json": f"/assessments/{ASSESSMENT_ID}",
    "assessments/overview.json": f"/assessments/{ASSESSMENT_ID}/overview",
    "scopes/get.json": f"/scope-manifests/{MANIFEST_ID}",
    "agent-runs/get.json": f"/agent-runs/{AGENT_RUN_ID}",
    "actions/list.json": f"/assessments/{ASSESSMENT_ID}/actions",
    "actions/get.json": f"/actions/{ACTION_ID}",
    "approvals/list.json": "/approvals",
    "approvals/get.json": f"/approvals/{APPROVAL_ID}",
    "findings/list.json": f"/findings?assessment_id={ASSESSMENT_ID}",
    "findings/get.json": f"/findings/{FINDING_ID}",
    "findings/validation-runs.json": f"/findings/{FINDING_ID}/validation-runs",
    "evidence/get.json": f"/evidence/{EVIDENCE_ID}",
    "messages/list.json": f"/sessions/{SESSION_ID}/messages",
}


def database_url() -> str:
    url = os.environ.get("RECONIX_SAMPLE_DATABASE_URL")
    if not url:
        sys.exit("Set RECONIX_SAMPLE_DATABASE_URL to an empty PostgreSQL database (see the top).")
    return url


def migrate(url: str) -> None:
    os.environ["RECONIX_DATABASE_URL"] = url  # alembic/env.py reads the API settings
    get_settings.cache_clear()
    command.upgrade(Config(str(ALEMBIC_INI)), "head")


def load_seed(engine: Engine) -> None:
    """Loads the seed into an empty database; keeps it if it is already there."""
    with Session(engine) as db:
        ids = {str(i) for i in db.scalars(select(Assessment.assessment_id))}
        total = db.scalar(select(func.count()).select_from(Assessment))
    if ids == {ASSESSMENT_ID}:
        return
    if total:
        sys.exit("This database holds other assessments. Use an empty one.")
    connection = engine.raw_connection()
    try:
        connection.autocommit = True  # the file has its own BEGIN and COMMIT
        connection.cursor().execute(SEED.read_text(encoding="utf-8"))
    finally:
        connection.close()


def api_client(url: str, factory: sessionmaker[Session], audit_log: Path) -> TestClient:
    """The real API on this database. Nothing that calls the AI or Kali is wired."""
    tokens = SessionTokens()
    interfaces = build_interfaces(
        session_tokens=tokens, session_factory=factory, audit_log_path=str(audit_log)
    )
    settings = Settings(
        database_url=url,
        job_token_secret=secrets.token_urlsafe(32),  # no tool runs here; any value works
        provider_encryption_key=Fernet.generate_key().decode(),
    )
    app = create_app(interfaces, settings=settings, session_tokens=tokens)

    def db() -> Iterator[Session]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = db
    app.dependency_overrides[get_session_factory] = lambda: factory
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app, base_url="http://127.0.0.1/api/v1")


def write(name: str, body: object) -> None:
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}")


def main() -> None:
    url = database_url()
    migrate(url)
    engine = create_engine(url)
    load_seed(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with tempfile.TemporaryDirectory() as folder:
        client = api_client(url, factory, Path(folder) / "audit.jsonl")
        signed_in = client.post("/sessions", json={"interface": "cli"})
        if signed_in.status_code != 201:
            sys.exit(f"POST /sessions failed: {signed_in.text}")
        headers = {"Authorization": f"Bearer {signed_in.json()['token']}"}
        for name, path in FILES.items():
            response = client.get(path, headers=headers)
            if response.status_code != 200:
                sys.exit(f"GET {path} answered {response.status_code}: {response.text}")
            write(name, response.json())
    engine.dispose()


if __name__ == "__main__":
    main()
