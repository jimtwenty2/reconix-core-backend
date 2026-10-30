"""Accepted findings in Qdrant, so the AI can answer questions about them later.

A finding a person reviewed as OPEN or FIXED is accepted and remembered; one marked
FALSE_POSITIVE is forgotten. The API decides when and calls these; the AI Service
never reads the database.

They live in their own collection, because ingest drops and rebuilds "knowledge".
Every search is limited to one assessment, so one client's findings never reach a
prompt about another. Every text is masked before it is embedded or saved.
"""

import uuid
from collections.abc import Awaitable
from dataclasses import dataclass, field

from qdrant_client import AsyncQdrantClient, models

from reconix_ai.agent.state import masked_findings
from reconix_ai.harness import mask_secrets
from reconix_ai.knowledge import keywords, store
from reconix_ai.knowledge.search import DEFAULT_LIMIT, MAX_HIT_CHARS, MAX_LIMIT, EmbedTexts
from reconix_ai.providers import embed_texts

COLLECTION = "findings"
# Fixed namespace, so a finding always gets the same point id and a new review replaces it.
POINT_NAMESPACE = uuid.UUID("0b6c3f8e-6a51-4c1e-9f3d-2e7a5d4b8c91")


@dataclass(frozen=True)
class AcceptedFinding:
    """A finding a person accepted. Field names match findings in ERD V3."""

    finding_id: str
    assessment_id: str
    code: str
    title: str
    target: str
    description: str
    severity_status: str
    finding_status: str  # OPEN or FIXED
    cwe_ids: list[str] = field(default_factory=list)
    owasp_id: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    impact: str | None = None
    remediation: str | None = None


@dataclass(frozen=True)
class FindingHit:
    """A remembered finding. Its text came from a target, so it is untrusted data."""

    finding_id: str
    code: str
    title: str
    target: str
    severity_status: str
    finding_status: str
    text: str  # masked, cut to MAX_HIT_CHARS
    score: float


async def remember_finding(
    finding: AcceptedFinding,
    client: AsyncQdrantClient | None = None,
    embed: EmbedTexts = embed_texts,
) -> int:
    """Save or replace the finding, masked. Returns how many secrets were hidden.

    Raises KnowledgeError (KNOWLEDGE_UNAVAILABLE) when Qdrant fails and ProviderError
    when the embedding model does."""
    [payload], masked_count = masked_findings([finding])
    payload["text"] = finding_text(payload)
    [vector] = await embed([payload["text"]])
    client = client or store.shared_client()
    point = models.PointStruct(
        id=point_id(finding.finding_id),
        vector={store.DENSE: vector, store.KEYWORDS: keywords.document_vector(payload["text"])},
        payload=payload,
    )
    await qdrant(ensure_and_upsert(client, point))
    return masked_count


async def forget_finding(finding_id: str, client: AsyncQdrantClient | None = None) -> None:
    """Remove the finding, if it was remembered."""
    client = client or store.shared_client()
    await qdrant(delete_point(client, point_id(finding_id)))


async def search_findings(
    query: str,
    assessment_id: str,
    limit: int = DEFAULT_LIMIT,
    client: AsyncQdrantClient | None = None,
    embed: EmbedTexts = embed_texts,
) -> list[FindingHit]:
    """The accepted findings of one assessment that best match the query."""
    text, _ = mask_secrets(query.strip())
    if not text:
        return []
    client = client or store.shared_client()
    if not await qdrant(client.collection_exists(COLLECTION)):
        return []  # nothing accepted yet
    [query_vector] = await embed([text])
    only_this = models.Filter(
        must=[
            models.FieldCondition(key="assessment_id", match=models.MatchValue(value=assessment_id))
        ]
    )
    limit = min(max(limit, 1), MAX_LIMIT)
    points = await qdrant(
        store.fused_search(client, COLLECTION, text, query_vector, only_this, limit)
    )
    return [finding_hit(point.payload or {}, point.score) for point in points]


def finding_text(payload: dict) -> str:
    """What is embedded and shown: the finding in a few labelled lines."""
    ids = ", ".join(payload["cve_ids"] + payload["cwe_ids"] + payload["owasp_id"])
    lines = [
        f"{payload['code']}: {payload['title']}",
        f"Target: {payload['target']}",
        f"Severity: {payload['severity_status']}; status: {payload['finding_status']}",
        payload["description"],
        f"References: {ids}" if ids else "",
        f"Impact: {payload['impact']}" if payload.get("impact") else "",
        f"Fix: {payload['remediation']}" if payload.get("remediation") else "",
    ]
    return "\n".join(line for line in lines if line)


def finding_hit(payload: dict, score: float) -> FindingHit:
    return FindingHit(
        finding_id=payload["finding_id"],
        code=payload["code"],
        title=payload["title"],
        target=payload["target"],
        severity_status=payload["severity_status"],
        finding_status=payload["finding_status"],
        text=payload["text"][:MAX_HIT_CHARS],
        score=score,
    )


def point_id(finding_id: str) -> str:
    return str(uuid.uuid5(POINT_NAMESPACE, str(finding_id)))


async def ensure_and_upsert(client: AsyncQdrantClient, point: models.PointStruct) -> None:
    if not await client.collection_exists(COLLECTION):
        try:
            await store.make_collection(client, COLLECTION, keyword_fields=("assessment_id",))
        except store.QDRANT_ERRORS:
            # Two first remembers at once: the other one made it, which is fine.
            if not await client.collection_exists(COLLECTION):
                raise
    await client.upsert(COLLECTION, [point])


async def delete_point(client: AsyncQdrantClient, point: str) -> None:
    if await client.collection_exists(COLLECTION):
        await client.delete(COLLECTION, models.PointIdsList(points=[point]))


async def qdrant[T](call: Awaitable[T]) -> T:
    """Await a Qdrant call; its errors come back as a masked KnowledgeError."""
    failure = None
    try:
        return await call
    except store.QDRANT_ERRORS as error:
        failure = store.knowledge_error(error)
    raise failure  # outside the except block, so the original error is not attached
