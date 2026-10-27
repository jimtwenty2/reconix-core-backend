"""The Qdrant collection that holds the knowledge.

Each piece has two vectors: "dense" (BGE-M3, meaning) and "keywords" (exact
words). A search runs both and merges them with Reciprocal Rank Fusion.
"""

import os
import uuid
import warnings
from dataclasses import asdict

from qdrant_client import AsyncQdrantClient, models

from reconix_ai.knowledge import keywords
from reconix_ai.knowledge.chunks import Chunk
from reconix_ai.knowledge.items import Source
from reconix_ai.providers import EMBEDDING_SIZE

COLLECTION = "knowledge"
DENSE = "dense"
KEYWORDS = "keywords"
# deploy/docker-compose.yml publishes Qdrant on this port.
DEFAULT_QDRANT_URL = "http://127.0.0.1:6333"
UPSERT_BATCH = 256
# Fixed namespace, so the same piece always gets the same point id.
POINT_NAMESPACE = uuid.UUID("6f1d3c52-2b8e-4f0a-9d7e-5c4b3a291807")


def qdrant_url() -> str:
    """RECONIX_QDRANT_URL, or the local default. ":memory:" runs Qdrant in this process."""
    return os.environ.get("RECONIX_QDRANT_URL") or DEFAULT_QDRANT_URL


def connect(url: str | None = None) -> AsyncQdrantClient:
    return AsyncQdrantClient(location=url or qdrant_url())


async def create_collection(client: AsyncQdrantClient) -> None:
    """Drop the collection if it is there and make it again, empty."""
    if await client.collection_exists(COLLECTION):
        await client.delete_collection(COLLECTION)
    await client.create_collection(
        COLLECTION,
        vectors_config={
            DENSE: models.VectorParams(size=EMBEDDING_SIZE, distance=models.Distance.COSINE)
        },
        sparse_vectors_config={KEYWORDS: models.SparseVectorParams(modifier=models.Modifier.IDF)},
    )
    with warnings.catch_warnings():
        # In-process Qdrant (tests) has no payload indexes and says so; the server uses it.
        warnings.simplefilter("ignore", UserWarning)
        for name in ("source", "ref_id"):
            await client.create_payload_index(COLLECTION, name, models.PayloadSchemaType.KEYWORD)


async def save_chunks(
    client: AsyncQdrantClient, chunks: list[Chunk], vectors: list[list[float]]
) -> None:
    points = [point(chunk, vector) for chunk, vector in zip(chunks, vectors, strict=True)]
    for start in range(0, len(points), UPSERT_BATCH):
        await client.upsert(COLLECTION, points[start : start + UPSERT_BATCH])


def point(chunk: Chunk, vector: list[float]) -> models.PointStruct:
    return models.PointStruct(
        id=str(uuid.uuid5(POINT_NAMESPACE, f"{chunk.source}:{chunk.ref_id}:{chunk.index}")),
        vector={DENSE: vector, KEYWORDS: keywords.document_vector(chunk.title + "\n" + chunk.text)},
        payload=asdict(chunk),
    )


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
    response = await client.query_points(
        COLLECTION,
        prefetch=[
            models.Prefetch(query=query_vector, using=DENSE, limit=limit * 4, filter=source_filter),
            models.Prefetch(
                query=keywords.query_vector(query),
                using=KEYWORDS,
                limit=limit * 4,
                filter=source_filter,
            ),
        ],
        query=models.FusionQuery(fusion=models.Fusion.RRF),
        limit=limit,
        with_payload=True,
    )
    return response.points
