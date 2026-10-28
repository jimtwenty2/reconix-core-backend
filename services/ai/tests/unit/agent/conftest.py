import pytest
from langgraph.checkpoint.memory import InMemorySaver

from reconix_ai.agent import build_graph


@pytest.fixture
def saver() -> InMemorySaver:
    return InMemorySaver()


@pytest.fixture
def graph(saver: InMemorySaver):
    return build_graph(saver)
