"""Saves agent progress in Postgres, so a run waiting for a person survives a restart.

LangGraph's checkpoint tables are not part of ERD V3, so they live in their own
schema, "langgraph", and never mix with the Reconix tables in "public".
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg import AsyncConnection
from psycopg.rows import dict_row

SCHEMA = "langgraph"


@asynccontextmanager
async def postgres_checkpointer(database_url: str) -> AsyncIterator[AsyncPostgresSaver]:
    """A checkpointer on the Reconix database. Takes the API's database_url as it is.

    On Windows, psycopg needs the selector event loop; Docker (Linux) needs nothing.
    """
    async with await AsyncConnection.connect(
        psycopg_url(database_url), autocommit=True, prepare_threshold=0, row_factory=dict_row
    ) as conn:
        await conn.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")
        await conn.execute(f"SET search_path TO {SCHEMA}")
        saver = AsyncPostgresSaver(conn=conn)
        await saver.setup()
        yield saver


def psycopg_url(database_url: str) -> str:
    """SQLAlchemy's "postgresql+psycopg://" form -> the plain form psycopg reads."""
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)
