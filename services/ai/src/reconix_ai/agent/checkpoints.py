"""Saves agent progress in Postgres, so a run waiting for a person survives a restart.

LangGraph's checkpoint tables are not part of ERD V3, so they live in their own
schema, "langgraph", and never mix with the Reconix tables in "public".

setup_checkpoints() makes those tables once, when the API starts, and never inside a
request. LangGraph builds its indexes CONCURRENTLY, which waits for every transaction
older than it; a request keeps its own transaction open while it asks the agent, so a
setup inside the request would wait for it forever.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg import AsyncConnection
from psycopg.rows import dict_row

SCHEMA = "langgraph"


async def setup_checkpoints(database_url: str) -> None:
    """Make the schema and LangGraph's tables, or bring them up to date. Once, at start."""
    async with checkpoint_connection(database_url, create_schema=True) as conn:
        await AsyncPostgresSaver(conn=conn).setup()


@asynccontextmanager
async def postgres_checkpointer(database_url: str) -> AsyncIterator[AsyncPostgresSaver]:
    """A checkpointer on the Reconix database. Takes the API's database_url as it is.

    It changes no tables: setup_checkpoints() made them when the API started.
    """
    async with checkpoint_connection(database_url) as conn:
        yield AsyncPostgresSaver(conn=conn)


@asynccontextmanager
async def checkpoint_connection(
    database_url: str, create_schema: bool = False
) -> AsyncIterator[AsyncConnection]:
    """A connection whose tables are the "langgraph" schema's.

    On Windows, psycopg needs the selector event loop; Docker (Linux) needs nothing.
    """
    async with await AsyncConnection.connect(
        psycopg_url(database_url), autocommit=True, prepare_threshold=0, row_factory=dict_row
    ) as conn:
        if create_schema:
            await conn.execute("CREATE SCHEMA IF NOT EXISTS langgraph")
        await conn.execute("SET search_path TO langgraph")
        yield conn


def psycopg_url(database_url: str) -> str:
    """SQLAlchemy's "postgresql+psycopg://" form -> the plain form psycopg reads."""
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)
