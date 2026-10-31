"""A chat on a new database, set up as the API's startup does it: the API holds no
transaction open while the agent answers (an open one would have hung the first live
chat, before the checkpointer was set up at startup)."""

import asyncio
import dataclasses
from datetime import UTC, datetime

from sqlalchemy import text

from reconix_ai import agent
from reconix_api.core.agent import make_ask_agent, postgres_graph
from reconix_api.core.db import get_db
from tests.integration.conftest import TEST_DATABASE_URL
from tests.integration.test_chat_flow import chat
from tests.integration.test_scope_flow import open_session
from tests.unit.core.test_agent import PROVIDER, ScriptedModel, no_knowledge

ANSWER = {"answer": "A version scan.", "references": []}


def test_a_chat_holds_no_transaction_while_the_agent_answers(db_app, db_client, session_factory):
    with session_factory() as db:  # a new database: the checkpointer was never set up
        db.execute(text("DROP SCHEMA IF EXISTS langgraph CASCADE"))
        db.commit()
    asyncio.run(agent.setup_checkpoints(TEST_DATABASE_URL))  # what startup does
    deps = agent.AgentDeps(
        provider=PROVIDER,
        complete=ScriptedModel(ANSWER).complete,
        search=no_knowledge,
        now=lambda: datetime(2026, 10, 30, 10, tzinfo=UTC),
    )
    db_app.state.interfaces = dataclasses.replace(
        db_app.state.interfaces,
        ask_agent=make_ask_agent(postgres_graph(TEST_DATABASE_URL), deps, lambda _: PROVIDER),
    )

    def short_waits():
        # If the request's transaction were left open, Postgres ends it after 5 s, so
        # this test fails instead of hanging.
        with session_factory() as db:
            db.execute(text("SET idle_in_transaction_session_timeout = '5s'"))
            yield db

    db_app.dependency_overrides[get_db] = short_waits
    headers = open_session(db_client)

    response = chat(db_client, headers, "What does -sV do?")

    assert response.status_code == 201, response.json()
    assert response.json()["reply"]["content_masked"] == "A version scan."
