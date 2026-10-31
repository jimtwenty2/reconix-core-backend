"""Fixtures for the knowledge routes: Qdrant in this process and a fake embedder."""

import pytest

from reconix_ai.knowledge import store
from reconix_api.core.knowledge_add_ons import KnowledgeStore
from tests.unit.api.test_knowledge_add_ons import fake_embed, make_client


@pytest.fixture
def qdrant():
    return store.connect(":memory:")


@pytest.fixture
def audit_events():
    return []


@pytest.fixture
def client(qdrant, audit_events):
    return make_client(audit_events, KnowledgeStore(client=qdrant, embed=fake_embed))
