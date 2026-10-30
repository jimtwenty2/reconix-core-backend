"""The first ask on a new database sets up the agent's checkpointer, which waits for every
open transaction to end. The API must not hold one open while it asks, or the two wait
for each other: this hung the first live chat and the first plan."""

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


def test_the_first_chat_on_a_new_database_does_not_hang(db_app, db_client, session_factory):
    with session_factory() as db:  # a new database: the checkpointer was never set up
        db.execute(text("DROP SCHEMA IF EXISTS langgraph CASCADE"))
        db.commit()
    deps = agent.AgentDeps(
        provider=PROVIDER,
        complete=ScriptedModel(ANSWER).complete,
        search=no_knowledge,
        now=lambda: datetime(2026, 10, 30, 10, tzinfo=UTC),
    )
    db_app.state.interfaces = dataclasses.replace(
        db_app.state.interfaces,
        ask_agent=make_ask_agent(postgres_graph(TEST_DATABASE_URL), deps),
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
