import pytest

from reconix_ai.knowledge import store
from tests.unit.knowledge.fakes import FakeEmbedder


@pytest.fixture
def embedder() -> FakeEmbedder:
    return FakeEmbedder()


@pytest.fixture
def client():
    return store.connect(":memory:")
