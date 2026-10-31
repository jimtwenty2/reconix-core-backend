import asyncio
import os
import sys
from uuid import uuid4

import pytest

from reconix_ai.agent import (
    ask_agent,
    build_graph,
    postgres_checkpointer,
    resume_agent,
    setup_checkpoints,
)
from reconix_ai.agent.checkpoints import psycopg_url
from tests.unit.agent.fakes import PLANNED, UNDERSTOOD, FakeModel, Request, make_deps

DEFAULT_DATABASE_URL = "postgresql+psycopg://reconix:reconix@127.0.0.1:5432/reconix"


def test_sqlalchemy_url_becomes_a_psycopg_url() -> None:
    assert (
        psycopg_url(DEFAULT_DATABASE_URL) == "postgresql://reconix:reconix@127.0.0.1:5432/reconix"
    )
    assert psycopg_url("postgresql://a@b/c") == "postgresql://a@b/c"


@pytest.mark.skipif(
    os.environ.get("RECONIX_POSTGRES_SMOKE") != "1",
    reason="Set RECONIX_POSTGRES_SMOKE=1 with Postgres running (RECONIX_DATABASE_URL).",
)
def test_smoke_a_waiting_run_survives_a_new_connection() -> None:
    # psycopg's async mode does not work with Windows' default event loop.
    loop_factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    asked, resumed = asyncio.run(ask_then_resume_on_new_connections(), loop_factory=loop_factory)

    assert asked.waiting
    assert resumed.decision == "APPROVED"


async def ask_then_resume_on_new_connections():
    database_url = os.environ.get("RECONIX_DATABASE_URL", DEFAULT_DATABASE_URL)
    deps = make_deps(FakeModel(UNDERSTOOD, PLANNED))
    run = str(uuid4())
    await setup_checkpoints(database_url)  # once, as the API does when it starts
    async with postgres_checkpointer(database_url) as saver:
        asked = await ask_agent(build_graph(saver), Request(), run, deps)
    async with postgres_checkpointer(database_url) as saver:
        resumed = await resume_agent(build_graph(saver), run, approved=True, deps=deps)
    return asked, resumed
