"""search_knowledge(): what the agent calls to find CVE, CWE, OWASP, ATT&CK and tool facts."""

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from qdrant_client import AsyncQdrantClient

from reconix_ai.harness import mask_secrets
from reconix_ai.knowledge import store
from reconix_ai.knowledge.items import Source
from reconix_ai.providers import embed_texts

DEFAULT_LIMIT = 5
MAX_LIMIT = 20
# Above any fused score, so exact id matches sort first.
EXACT_MATCH_SCORE = 1.0
REF_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d+|T\d{4}(?:\.\d{3})?|A\d{2}:\d{4}|API\d{1,2}:\d{4})\b",
    re.IGNORECASE,
)

EmbedTexts = Callable[[list[str]], Awaitable[list[list[float]]]]


@dataclass(frozen=True)
class KnowledgeFilters:
    sources: list[Source] = field(default_factory=list)  # empty: every source


@dataclass(frozen=True)
class KnowledgeHit:
    source: Source
    ref_id: str
    title: str
    text: str  # masked when it was saved
    url: str
    section: str
    score: float


async def search_knowledge(
    query: str,
    filters: KnowledgeFilters | None = None,
    limit: int = DEFAULT_LIMIT,
    client: AsyncQdrantClient | None = None,
    embed: EmbedTexts = embed_texts,
) -> list[KnowledgeHit]:
    """The best pieces for the query, by meaning and by exact words together."""
    masked_query, _ = mask_secrets(query.strip())
    if not masked_query:
        return []
    filters = filters or KnowledgeFilters()
    client = client or store.connect()
    limit = min(max(limit, 1), MAX_LIMIT)

    # An exact id in the query ("CVE-2021-44228") is what the agent wants first.
    exact = []
    ids = ref_ids_in(masked_query)
    if ids:
        records = await store.find_by_ref_ids(client, ids, filters.sources)
        exact = [hit(record.payload or {}, EXACT_MATCH_SCORE) for record in records]

    [query_vector] = await embed([masked_query])
    points = await store.hybrid_search(
        client, masked_query, query_vector, filters.sources, limit + len(exact)
    )
    seen = {(h.ref_id, h.section) for h in exact}
    found = [hit(point.payload or {}, point.score) for point in points]
    rest = [h for h in found if (h.ref_id, h.section) not in seen]
    return (exact + rest)[:limit]


def ref_ids_in(query: str) -> list[str]:
    """CVE, CWE, ATT&CK and OWASP ids in the query, written the way they are saved."""
    return list(dict.fromkeys(match.upper() for match in REF_ID.findall(query)))


def hit(payload: dict, score: float) -> KnowledgeHit:
    return KnowledgeHit(
        source=Source(payload["source"]),
        ref_id=payload["ref_id"],
        title=payload["title"],
        text=payload["text"],
        url=payload.get("url", ""),
        section=payload.get("section", "/"),
        score=score,
    )
