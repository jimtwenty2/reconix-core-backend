"""Knowledge add-ons in Qdrant, through the AI Service's knowledge package.

Like core/agent.py for the agent, this is the one place the API reaches into
reconix_ai for add-ons. A failure comes back as an ApiError: 503 when Qdrant is not
there, and the agent's status for an embedding model error (AGENT_ERROR_STATUS).
"""

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import Depends, Request
from qdrant_client import AsyncQdrantClient

from reconix_ai import knowledge
from reconix_ai.knowledge import (
    AddOn,
    EmbedTexts,
    KnowledgeError,
    KnowledgeFilters,
    KnowledgeHit,
    Source,
    ingest,
    split_passages,
)
from reconix_ai.knowledge.paths import knowledge_data_dir
from reconix_ai.providers import ProviderError, embed_texts
from reconix_api.core.agent import AGENT_ERROR_STATUS
from reconix_api.core.errors import ApiError

__all__ = [
    "AddOn",
    "CurrentKnowledgeStore",
    "KnowledgeStore",
    "ingest_public",
    "list_all",
    "passages",
    "remove",
    "remove_all",
    "save",
    "split_passages",
]


@dataclass
class ReingestJob:
    """The knowledge re-ingest (services/knowledge_reingest.py): one at a time, kept in this
    process only. status: IDLE, RUNNING, COMPLETED or FAILED; step: PUBLIC (ALL only), then
    ADD_ONS."""

    status: str = "IDLE"
    scope: str = "ALL"  # NEW: only the add-ons waiting; ALL: the public knowledge and every add-on
    step: str | None = None
    public_pieces: int = 0
    add_ons_done: int = 0
    add_ons_total: int = 0
    new_ingested: int = 0  # waiting add-ons put into the knowledge search
    started_at: str | None = None
    finished_at: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    task: asyncio.Task | None = field(default=None, repr=False)


@dataclass(frozen=True)
class KnowledgeStore:
    """Where add-ons go. Tests pass Qdrant in this process and a fake embedder."""

    client: AsyncQdrantClient | None = None  # None: the shared client on RECONIX_QDRANT_URL
    embed: EmbedTexts = embed_texts
    # One upload at a time: the add-on limit holds, and only one file is read at once.
    adding: asyncio.Lock = field(default_factory=asyncio.Lock, compare=False)
    reingest: ReingestJob = field(default_factory=ReingestJob, compare=False)
    # Ids removed while a re-ingest runs ("*": all of them), so the job never brings one back
    removed: set[str] = field(default_factory=set, compare=False)


def get_knowledge_store(request: Request) -> KnowledgeStore:
    return request.app.state.knowledge_store


CurrentKnowledgeStore = Annotated[KnowledgeStore, Depends(get_knowledge_store)]


async def save(store: KnowledgeStore, add_on: AddOn, passages: list[str]) -> None:
    with api_errors():
        await knowledge.save_add_on(add_on, passages, store.client, store.embed)


async def list_all(store: KnowledgeStore) -> list[AddOn]:
    with api_errors():
        return await knowledge.list_add_ons(store.client)


async def passages(store: KnowledgeStore, knowledge_add_on_id: str) -> list[str]:
    with api_errors():
        return await knowledge.add_on_passages(knowledge_add_on_id, store.client)


async def ingest_public(store: KnowledgeStore) -> int:
    """Replace the public knowledge (CVE, CWE, OWASP, ATT&CK, tool guides); add-ons stay.
    How many pieces were saved."""
    with api_errors():
        return await ingest.ingest(knowledge_data_dir(), client=store.client, embed=store.embed)


async def remove(store: KnowledgeStore, knowledge_add_on_id: str) -> None:
    with api_errors():
        await knowledge.remove_add_on(knowledge_add_on_id, store.client)


async def remove_all(store: KnowledgeStore) -> None:
    with api_errors():
        await knowledge.remove_all_add_ons(store.client)


async def search(
    store: KnowledgeStore, query: str, sources: list[str], limit: int
) -> list[KnowledgeHit]:
    """The agent's own knowledge search: public knowledge and add-ons, by meaning and
    exact words. The query is masked before it is embedded."""
    filters = KnowledgeFilters(sources=[Source(name) for name in sources])
    with api_errors():
        return await knowledge.search_knowledge(
            query, filters, limit, client=store.client, embed=store.embed
        )


@contextmanager
def api_errors() -> Iterator[None]:
    """Qdrant down (KNOWLEDGE_UNAVAILABLE and the like) -> 503. A model error gets the
    status the agent gives the same code, else 502. Messages are masked by reconix_ai."""
    try:
        yield
    except KnowledgeError as error:
        raise ApiError(503, error.code, error.message) from None
    except ProviderError as error:
        status = AGENT_ERROR_STATUS.get(error.code, 502)
        raise ApiError(status, error.code, error.message) from None
