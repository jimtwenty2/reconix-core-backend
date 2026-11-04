"""Searching the knowledge the agent uses: CVE, CWE, OWASP, ATT&CK, tool guides and add-ons."""

from typing import Annotated

from fastapi import APIRouter, Query

from reconix_api.core.knowledge_add_ons import CurrentKnowledgeStore
from reconix_api.core.security import CurrentOperator
from reconix_api.schemas.knowledge_add_ons import KnowledgeHitOut, KnowledgeSource
from reconix_api.services import knowledge_add_ons

router = APIRouter(prefix="/knowledge", tags=["knowledge add-ons"])


@router.get("/search")
async def search_knowledge(
    _: CurrentOperator,
    store: CurrentKnowledgeStore,
    q: Annotated[str, Query(min_length=1, max_length=500)],
    source: Annotated[list[KnowledgeSource] | None, Query(max_length=7)] = None,
    limit: Annotated[int, Query(ge=1, le=20)] = 5,
) -> list[KnowledgeHitOut]:
    """Searches the knowledge base for q, by meaning and by exact words, and returns the best
    passages.

    Business Rules:
    - An exact CVE, CWE, ATT&CK, or OWASP id comes first.
    - Repeat ?source= to search only those sources.
    - `limit` sets how many passages to return (1 to 20, default 5).

    Operational Considerations:
    - Requires Qdrant and the embedding model; returns 503 without them.

    Security:
    - Requires a valid session token.
    """
    return await knowledge_add_ons.search(store, q, source or [], limit)
