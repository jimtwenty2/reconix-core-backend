"""The real ask_agent on the Postgres checkpointer: a waiting run survives an API restart.

The AI Service is called as a Python package, as the API does it; only the model is scripted.
"""

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import text

from reconix_ai import agent
from reconix_api.core.agent import make_ask_agent, postgres_graph, prepare_checkpoints
from tests.integration.conftest import TEST_DATABASE_URL
from tests.unit.core.test_agent import (
    PLANNED,
    PROVIDER,
    UNDERSTOOD,
    ScriptedModel,
    no_knowledge,
    plan_request,
    resume_of,
)


def make_ask(model: ScriptedModel):
    deps = agent.AgentDeps(
        provider=PROVIDER,
        complete=model.complete,
        search=no_knowledge,
        now=lambda: datetime(2026, 10, 29, 10, tzinfo=UTC),
    )
    return make_ask_agent(postgres_graph(TEST_DATABASE_URL), deps, lambda _run_id: PROVIDER)


@pytest.fixture
async def checkpoints(engine):
    """What the API does when it starts: make the checkpoint tables."""
    await prepare_checkpoints(TEST_DATABASE_URL)


async def test_a_waiting_run_resumes_after_a_restart(checkpoints):
    request = plan_request(uuid4())
    planned = await make_ask(ScriptedModel(UNDERSTOOD, PLANNED))(request)

    restarted = make_ask(ScriptedModel())  # a new ask_agent, as after an API restart
    resumed = await restarted(resume_of(request, "APPROVED"))

    assert planned.waiting
    assert planned.checkpoint_id
    assert resumed.agent_run_id == request.agent_run_id
    assert resumed.decision == "APPROVED"
    assert not resumed.waiting


async def test_asking_never_waits_for_the_requests_own_transaction(engine):
    """A fresh database: the API made the tables at start, and a request holds a
    transaction open while it asks, as POST /plan does. Making the tables during the
    ask used to wait for that transaction forever (CREATE INDEX CONCURRENTLY)."""
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA IF EXISTS langgraph CASCADE"))
    await prepare_checkpoints(TEST_DATABASE_URL)

    with engine.connect() as request_db:
        request_db.execute(text("SELECT 1"))  # the request's transaction, still open
        ask = make_ask(ScriptedModel(UNDERSTOOD, PLANNED))
        planned = await asyncio.wait_for(ask(plan_request(uuid4())), timeout=30)

    assert planned.waiting


async def test_preparing_twice_is_harmless(checkpoints):
    await prepare_checkpoints(TEST_DATABASE_URL)  # e.g. the API restarts


async def test_opening_a_checkpointer_makes_no_tables(engine):
    """Only the start-up may make them: inside a request it would wait forever."""
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA IF EXISTS langgraph CASCADE"))

    async with agent.postgres_checkpointer(TEST_DATABASE_URL):
        pass

    with engine.connect() as connection:
        schemas = text("SELECT count(*) FROM pg_namespace WHERE nspname = 'langgraph'")
        assert connection.scalar(schemas) == 0
    await prepare_checkpoints(TEST_DATABASE_URL)  # back as the API leaves it
