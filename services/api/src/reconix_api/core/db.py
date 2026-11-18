"""Database engine and the per-request session."""

from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated

import anyio.to_thread
from fastapi import Depends
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from reconix_api.core.config import get_settings

# A sync endpoint holds its connection until FastAPI has serialized its answer, and FastAPI
# does that on a thread from the same pool that runs the endpoints (AnyIO's default: 40).
# When a burst of reads (the web dashboard sends 100+ at once) took every thread, the
# finished requests waited for a thread while holding every connection, the running ones
# waited for a connection, and the whole API (/health too) hung until the 30 s pool timeout,
# again and again while the dashboard polled. So threads must never run out first: far more
# threads than connections, and a waiting endpoint waits only for a connection, which a
# finished request always frees.
POOL_SIZE = 10
MAX_OVERFLOW = 40  # 50 connections in all; Postgres allows 100
SYNC_THREADS = 400  # mostly idle waiting on a connection; a thread costs little memory


def raise_thread_limit() -> None:
    """Call once at startup, inside the event loop."""
    anyio.to_thread.current_default_thread_limiter().total_tokens = SYNC_THREADS


@lru_cache
def get_engine() -> Engine:
    return create_engine(
        get_settings().database_url,
        pool_pre_ping=True,
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """One database session per request. The service commits; anything else rolls back."""
    with get_session_factory()() as db:
        yield db


Db = Annotated[Session, Depends(get_db)]
