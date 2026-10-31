"""Integration tests need PostgreSQL 16. Set RECONIX_TEST_DATABASE_URL to run them, e.g.

    docker run -d --rm --name reconix-test-db -e POSTGRES_PASSWORD=test \\
        -p 127.0.0.1:55432:5432 postgres:16
    RECONIX_TEST_DATABASE_URL=postgresql+psycopg://postgres:test@127.0.0.1:55432/postgres \\
        uv run pytest services/api/tests/integration

The schema is built with the real Alembic migration, and tables are emptied after each test.
"""

import dataclasses
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import get_db
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.main import create_app
from reconix_api.models import Base
from reconix_api.services.scopes import make_get_approved_scope
from tests.fakes import build_fake_interfaces, fake_mask_secrets

TEST_DATABASE_URL = os.environ.get("RECONIX_TEST_DATABASE_URL")
ALEMBIC_INI = Path(__file__).parents[2] / "alembic.ini"
KEEP_TABLES = {"llm_providers"}  # seed data from the migration
JOB_TOKEN_SECRET = "integration-test-secret"  # noqa: S105
FERNET_KEY = Fernet.generate_key().decode()  # a new one each run


@pytest.fixture(scope="session")
def engine():
    if not TEST_DATABASE_URL:
        pytest.skip("RECONIX_TEST_DATABASE_URL is not set")
    os.environ["RECONIX_DATABASE_URL"] = TEST_DATABASE_URL
    get_settings.cache_clear()
    config = Config(str(ALEMBIC_INI))
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    engine = create_engine(TEST_DATABASE_URL)
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(engine):
    yield sessionmaker(bind=engine, expire_on_commit=False)
    tables = [t.name for t in Base.metadata.sorted_tables if t.name not in KEEP_TABLES]
    with engine.begin() as connection:
        connection.execute(text(f"TRUNCATE {', '.join(tables)} CASCADE"))  # noqa: S608
        # Back to the seed: only the built-in provider, and it is the active one.
        connection.execute(text("DELETE FROM llm_providers WHERE provider_type <> 'RECONIX'"))
        connection.execute(text("UPDATE llm_providers SET is_active = true"))


@pytest.fixture
def db_app(session_factory):
    """The app with the real get_operator, get_approved_scope and database; fakes for the rest."""
    fake_interfaces, parts = build_fake_interfaces()
    tokens = SessionTokens()
    interfaces = dataclasses.replace(
        fake_interfaces,
        get_operator=tokens.get_operator,
        get_approved_scope=make_get_approved_scope(session_factory),
    )
    app = create_app(
        interfaces,
        session_tokens=tokens,
        mask_secrets=fake_mask_secrets,
        finding_memory=parts["memory"].update,
    )
    settings = Settings(
        database_url=TEST_DATABASE_URL, job_token_secret=JOB_TOKEN_SECRET, fernet_key=FERNET_KEY
    )
    parts["mcp"].secret = JOB_TOKEN_SECRET  # checks tokens the way the Kali side does

    def test_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[get_settings] = lambda: settings
    app.state.parts = parts
    return app


@pytest.fixture
def db_client(db_app):
    return TestClient(db_app, base_url="http://127.0.0.1/api/v1")
