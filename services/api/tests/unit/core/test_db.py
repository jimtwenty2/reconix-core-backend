"""Sync endpoints must never run out of threads before the pool runs out of connections."""

import anyio.to_thread
from fastapi.testclient import TestClient

from reconix_api.core import db


def test_threads_far_outnumber_connections():
    """With fewer threads than a burst of requests, finished requests held every connection
    while waiting for a thread to serialize: the API deadlocked under the web dashboard."""
    assert db.SYNC_THREADS >= 4 * (db.POOL_SIZE + db.MAX_OVERFLOW)


def test_the_app_raises_the_thread_limit_at_startup(app):
    with TestClient(app) as client:
        tokens = client.portal.call(
            lambda: anyio.to_thread.current_default_thread_limiter().total_tokens
        )
    assert tokens == db.SYNC_THREADS
