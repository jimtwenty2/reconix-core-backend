"""Fixtures for the knowledge routes: Qdrant in this process and a fake embedder."""

import pytest
from cryptography.fernet import Fernet

from reconix_ai.knowledge import store
from reconix_api.core.config import Settings
from reconix_api.core.knowledge_add_ons import KnowledgeStore
from tests.unit.api.test_knowledge_add_ons import fake_embed, make_client


@pytest.fixture
def qdrant():
    return store.connect(":memory:")


@pytest.fixture
def audit_events():
    return []


@pytest.fixture
def settings(tmp_path):
    """A test key, and a private folder for the add-ons waiting to be ingested (never the real
    one, so a test never reads or changes what this computer has waiting)."""
    return Settings(
        provider_encryption_key=Fernet.generate_key().decode(),
        knowledge_pending_dir=str(tmp_path / "pending"),
    )


@pytest.fixture
def client(qdrant, audit_events, settings):
    return make_client(audit_events, KnowledgeStore(client=qdrant, embed=fake_embed), settings)
