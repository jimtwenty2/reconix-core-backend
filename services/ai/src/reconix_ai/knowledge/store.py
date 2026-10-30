"""The Qdrant collection that holds the knowledge.

Each piece has two vectors: "dense" (BGE-M3, meaning) and "keywords" (exact
words). A search runs both and merges them with Reciprocal Rank Fusion.
"""

import os
import uuid
import warnings
from dataclasses import asdict

import httpx
from qdrant_client import AsyncQdrantClient, models
from qdrant_client.http.exceptions import ResponseHandlingException, UnexpectedResponse

from reconix_ai.harness import mask_secrets
from reconix_ai.knowledge import keywords
from reconix_ai.knowledge.chunks import Chunk
from reconix_ai.knowledge.items import PUBLIC_SOURCES, Source
from reconix_ai.providers import EMBEDDING_SIZE
from reconix_ai.providers.base_url import BaseUrlError, check_base_url

COLLECTION = "knowledge"
DENSE = "dense"
KEYWORDS = "keywords"
# deploy/docker-compose.yml publishes Qdrant on this port.
DEFAULT_QDRANT_URL = "http://127.0.0.1:6333"
UPSERT_BATCH = 256
# Fixed namespace, so the same piece always gets the same point id.
POINT_NAMESPACE = uuid.UUID("6f1d3c52-2b8e-4f0a-9d7e-5c4b3a291807")


IN_PROCESS = ":memory:"  # Qdrant inside this process, for tests
# What a Qdrant call can raise: the server answered badly, could not be
# reached, or (in-process) the collection is not there yet.
QDRANT_ERRORS = (UnexpectedResponse, ResponseHandlingException, httpx.HTTPError, ValueError)

_shared_client: AsyncQdrantClient | None = None


class KnowledgeError(Exception):
    """The knowledge store failed. code is UPPERCASE, e.g. KNOWLEDGE_UNAVAILABLE."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def qdrant_url() -> str:
    """RECONIX_QDRANT_URL, or the local default."""
    return os.environ.get("RECONIX_QDRANT_URL") or DEFAULT_QDRANT_URL


def connect(url: str | None = None) -> AsyncQdrantClient:
    """A new client. Same address rule as a model: plain http only to this computer."""
    url = url or qdrant_url()
    if url != IN_PROCESS:
        try:
            check_base_url(url)
        except BaseUrlError as error:
            raise KnowledgeError("KNOWLEDGE_URL_NOT_ALLOWED", str(error)) from None
    return AsyncQdrantClient(location=url)


def shared_client() -> AsyncQdrantClient:
    """One client for the whole process, so searches reuse its connections."""
    global _shared_client
    if _shared_client is None:
        _shared_client = connect()
    return _shared_client


def knowledge_error(error: Exception) -> KnowledgeError:
    """A clear, masked error the agent can report ("knowledge not loaded") and move on."""
    reason, _ = mask_secrets(str(error))
    return KnowledgeError("KNOWLEDGE_UNAVAILABLE", f"The knowledge search failed: {reason}")


async def create_collection(client: AsyncQdrantClient) -> None:
    """Drop the collection if it is there and make it again, empty."""
    if await client.collection_exists(COLLECTION):
        await client.delete_collection(COLLECTION)
    await make_collection(client, COLLECTION, keyword_fields=("source", "ref_id"))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # see make_collection
        await client.create_payload_index(COLLECTION, "index", models.PayloadSchemaType.INTEGER)


async def make_collection(
    client: AsyncQdrantClient, name: str, keyword_fields: tuple[str, ...]
) -> None:
    """An empty collection with both vectors, and an index on each keyword field."""
    await client.create_collection(
        name,
        vectors_config={
            DENSE: models.VectorParams(size=EMBEDDING_SIZE, distance=models.Distance.COSINE)
        },
        sparse_vectors_config={KEYWORDS: models.SparseVectorParams(modifier=models.Modifier.IDF)},
    )
    with warnings.catch_warnings():
        # In-process Qdrant (tests) has no payload indexes and says so; the server uses it.
        warnings.simplefilter("ignore", UserWarning)
        for field_name in keyword_fields:
            await client.create_payload_index(name, field_name, models.PayloadSchemaType.KEYWORD)


async def ensure_collection(client: AsyncQdrantClient) -> None:
    """Make the collection when it is not there yet. Never empties it."""
    if not await client.collection_exists(COLLECTION):
        await create_collection(client)


async def clear_public_knowledge(client: AsyncQdrantClient) -> None:
    """Remove the public knowledge (PUBLIC_SOURCES) and keep everything else, such as the
    add-ons. Makes the collection when it is not there yet."""
    if not await client.collection_exists(COLLECTION):
        await create_collection(client)
        return
    public = models.FieldCondition(key="source", match=models.MatchAny(any=list(PUBLIC_SOURCES)))
    await client.delete(COLLECTION, models.Filter(must=[public]))


def source_is(source: Source) -> models.FieldCondition:
    return models.FieldCondition(key="source", match=models.MatchValue(value=source))


async def save_chunks(
    client: AsyncQdrantClient, chunks: list[Chunk], vectors: list[list[float]]
) -> None:
    points = [point(chunk, vector) for chunk, vector in zip(chunks, vectors, strict=True)]
    for start in range(0, len(points), UPSERT_BATCH):
        await client.upsert(COLLECTION, points[start : start + UPSERT_BATCH])


def point(chunk: Chunk, vector: list[float]) -> models.PointStruct:
    return models.PointStruct(
        id=point_id(chunk),
        vector={DENSE: vector, KEYWORDS: keywords.document_vector(chunk.title + "\n" + chunk.text)},
        payload=asdict(chunk),
    )


def point_id(chunk: Chunk) -> str:
    return str(uuid.uuid5(POINT_NAMESPACE, f"{chunk.source}:{chunk.ref_id}:{chunk.index}"))


async def find_by_ref_ids(
    client: AsyncQdrantClient, ref_ids: list[str], sources: list[Source]
) -> list[models.Record]:
    """The first piece of each item whose id is given, e.g. CVE-2021-44228."""
    conditions = [
        models.FieldCondition(key="ref_id", match=models.MatchAny(any=ref_ids)),
        models.FieldCondition(key="index", match=models.MatchValue(value=0)),
    ]
    if sources:
        conditions.append(
            models.FieldCondition(key="source", match=models.MatchAny(any=list(sources)))
        )
    records, _ = await client.scroll(
        COLLECTION, scroll_filter=models.Filter(must=conditions), limit=len(ref_ids) * 2
    )
    return records


async def hybrid_search(
    client: AsyncQdrantClient,
    query: str,
    query_vector: list[float],
    sources: list[Source],
    limit: int,
) -> list[models.ScoredPoint]:
    source_filter = None
    if sources:
        source_filter = models.Filter(
            must=[models.FieldCondition(key="source", match=models.MatchAny(any=list(sources)))]
        )
    return await fused_search(client, COLLECTION, query, query_vector, source_filter, limit)


async def fused_search(
    client: AsyncQdrantClient,
    collection: str,
    query: str,
    query_vector: list[float],
    query_filter: models.Filter | None,
    limit: int,
) -> list[models.ScoredPoint]:
    """Meaning and exact words, merged with Reciprocal Rank Fusion."""
    response = await client.query_points(
        collection,
        prefetch=[
            models.Prefetch(query=query_vector, using=DENSE, limit=limit * 4, filter=query_filter),
            models.Prefetch(
                query=keywords.query_vector(query),
                using=KEYWORDS,
                limit=limit * 4,
                filter=query_filter,
            ),
        ],
        query=models.FusionQuery(fusion=models.Fusion.RRF),
        limit=limit,
        with_payload=True,
    )
    return response.points
