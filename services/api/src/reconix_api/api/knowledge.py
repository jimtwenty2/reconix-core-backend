"""Searching the knowledge the agent uses: CVE, CWE, OWASP, ATT&CK, tool guides and add-ons."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.errors import ApiError
from reconix_api.core.knowledge_add_ons import CurrentKnowledgeStore
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.knowledge_add_ons import (
    KnowledgeHitOut,
    KnowledgeReingestOut,
    KnowledgeSource,
)
from reconix_api.services import knowledge_add_ons, knowledge_reingest

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
    - Returns 422 VALIDATION_ERROR if q is blank.

    Operational Considerations:
    - Requires Qdrant and the embedding model; returns 503 without them.

    Security:
    - Requires a valid session token.
    """
    if not q.strip():
        fields = [{"field": "query.q", "message": "must not be blank"}]
        raise ApiError(422, "VALIDATION_ERROR", "The request is not valid.", {"fields": fields})
    return await knowledge_add_ons.search(store, q, source or [], limit)


@router.post("/reingest", status_code=status.HTTP_202_ACCEPTED)
async def start_knowledge_reingest(
    store: CurrentKnowledgeStore,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: Annotated[Settings, Depends(get_settings)],
    scope: Literal["NEW", "ALL"] = "ALL",
) -> KnowledgeReingestOut:
    """Starts re-ingesting the knowledge, as one background job.

    Business Rules:
    - scope NEW: only the add-ons waiting (ingest_status PENDING) are put into the knowledge
      search. Quick.
    - scope ALL (default): step PUBLIC loads the public knowledge again (CVE, CWE, OWASP,
      ATT&CK, tool guides); step ADD_ONS then embeds every ingested add-on's passages again
      and puts the waiting ones in.
    - One job at a time: 409 REINGEST_RUNNING while one runs. Uploads wait during ADD_ONS.
    - It runs in the API's process: an API restart ends it; waiting add-ons stay waiting.

    Execution Behavior:
    - Answers at once (202); follow it with GET /knowledge/reingest.

    State Changes:
    - Replaces the public knowledge in Qdrant and the add-ons' vectors.
    - Writes KNOWLEDGE_REINGEST_STARTED, KNOWLEDGE_ADD_ON_INGESTED for each waiting add-on
      put in, then KNOWLEDGE_REINGEST_FINISHED.

    Security:
    - Requires a valid session token.
    """
    return knowledge_reingest.start(store, settings, interfaces.write_audit, operator, scope)


@router.get("/reingest")
async def knowledge_reingest_status(
    store: CurrentKnowledgeStore, _: CurrentOperator
) -> KnowledgeReingestOut:
    """Returns the knowledge re-ingest job: IDLE before the first, else the last one.

    Business Rules:
    - status RUNNING, COMPLETED or FAILED (error_code and error_message say why); step is the
      step running, or the last one reached.

    Security:
    - Requires a valid session token.
    """
    return knowledge_reingest.status(store)
