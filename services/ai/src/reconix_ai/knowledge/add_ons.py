"""Knowledge add-ons: a person's own documents, searched with the public knowledge.

The API reads an uploaded file and masks its text; this file cuts it into passages and
saves them in the knowledge collection under Source.USER_DOC, with the add-on's id as
ref_id, so search_knowledge() finds them like any other piece. Nothing else is kept: no
file on disk, no original.

The first piece also holds the add-on's details. It gets them last, once every piece is
saved, so the list never shows an add-on that is only half there.
"""

import re
from dataclasses import asdict, dataclass

from qdrant_client import AsyncQdrantClient, models

from reconix_ai.knowledge import store
from reconix_ai.knowledge.chunks import Chunk, masked
from reconix_ai.knowledge.items import Source
from reconix_ai.knowledge.search import EmbedTexts
from reconix_ai.providers import embed_texts

DETAILS = "add_on"  # payload key of the details, on the first piece only
MAX_LISTED = 1000  # far above the number of add-ons the API allows

# Passages, as the TUI cuts them (apps/tui/reconix/store/knowledge/chunk.py): at most
# 1,200 characters, cut between paragraphs, about 150 characters shared with the one
# before, so a sentence on a boundary is found from either side.
MAX_CHARS = 1200
OVERLAP = 150
MAX_PASSAGES = 2000
PARAGRAPH = re.compile(r"\n\s*\n")
SPACE = re.compile(r"\s")


@dataclass(frozen=True)
class AddOn:
    knowledge_add_on_id: str
    name: str  # masked
    kind: str  # TXT, MD, JSON, YAML, DOCX or PDF
    size_bytes: int
    chunk_count: int
    interface: str  # web or cli, as sessions.interface
    created_at: str  # ISO 8601, UTC


async def save_add_on(
    add_on: AddOn,
    passages: list[str],
    client: AsyncQdrantClient | None = None,
    embed: EmbedTexts = embed_texts,
) -> None:
    """Embed the passages and save them. Every text is masked again before it is saved.

    Raises KnowledgeError (KNOWLEDGE_UNAVAILABLE) when Qdrant fails, and ProviderError
    when the embedding model fails. Nothing is left behind on a failure, if Qdrant allows.
    """
    if not passages:
        raise ValueError("An add-on needs at least one passage.")
    chunks = [add_on_chunk(add_on, text, index) for index, text in enumerate(passages)]
    vectors = await embed([chunk.title + "\n" + chunk.text for chunk in chunks])
    client = client or store.shared_client()
    failure = None
    try:
        await store.ensure_collection(client)
        await store.save_chunks(client, chunks, vectors)
        details = {DETAILS: asdict(add_on) | {"name": masked(add_on.name)}}
        await client.set_payload(store.COLLECTION, details, [store.point_id(chunks[0])])
    except store.QDRANT_ERRORS as error:
        failure = store.knowledge_error(error)
    if failure is not None:
        await forget_quietly(client, add_on.knowledge_add_on_id)
        raise failure


async def list_add_ons(client: AsyncQdrantClient | None = None) -> list[AddOn]:
    """Every saved add-on, oldest first. None yet (or no collection yet): []."""
    client = client or store.shared_client()
    failure = None
    records = []
    try:
        if await client.collection_exists(store.COLLECTION):
            first_pieces = models.Filter(
                must=[
                    store.source_is(Source.USER_DOC),
                    models.FieldCondition(key="index", match=models.MatchValue(value=0)),
                ]
            )
            records, _ = await client.scroll(
                store.COLLECTION, scroll_filter=first_pieces, limit=MAX_LISTED
            )
    except store.QDRANT_ERRORS as error:
        failure = store.knowledge_error(error)
    if failure is not None:
        raise failure
    add_ons = [AddOn(**record.payload[DETAILS]) for record in records if has_details(record)]
    return sorted(add_ons, key=lambda add_on: add_on.created_at)


async def remove_add_on(knowledge_add_on_id: str, client: AsyncQdrantClient | None = None) -> None:
    """Remove every piece of one add-on."""
    await delete_pieces(client or store.shared_client(), [ref_id_is(knowledge_add_on_id)])


async def remove_all_add_ons(client: AsyncQdrantClient | None = None) -> None:
    """Remove every add-on. The public knowledge stays."""
    await delete_pieces(client or store.shared_client(), [])


def split_passages(text: str) -> tuple[list[str], bool]:
    """(passages, cut): the passages of text, at most MAX_PASSAGES, and True when that
    limit left text out."""
    passages: list[str] = []
    current = ""
    for unit in paragraphs(text):
        joined = f"{current}\n\n{unit}" if current else unit
        if len(joined) <= MAX_CHARS:
            current = joined
            continue
        if current:
            passages.append(current)
            if len(passages) >= MAX_PASSAGES:
                return passages, True
            tail = overlap_tail(current)
            start = f"{tail}\n\n{unit}" if tail else unit
            current = start if len(start) <= MAX_CHARS else unit
        else:
            current = unit
    if current:
        if len(passages) >= MAX_PASSAGES:
            return passages, True
        passages.append(current)
    return passages, False


def paragraphs(text: str) -> list[str]:
    """The paragraphs of text, each at most MAX_CHARS (a longer one is cut in windows)."""
    units = []
    for block in PARAGRAPH.split(text):
        paragraph = block.strip()
        if len(paragraph) > MAX_CHARS:
            units.extend(windows(paragraph))
        elif paragraph:
            units.append(paragraph)
    return units


def windows(paragraph: str) -> list[str]:
    """Pieces of at most MAX_CHARS that overlap and end at a space when they can."""
    pieces = []
    start = 0
    while start < len(paragraph):
        end = min(start + MAX_CHARS, len(paragraph))
        if end < len(paragraph):
            space = paragraph.rfind(" ", start + MAX_CHARS - OVERLAP, end)
            if space != -1:
                end = space
        pieces.append(paragraph[start:end].strip())
        if end >= len(paragraph):
            break
        start = max(end - OVERLAP, start + 1)
    return [piece for piece in pieces if piece]


def overlap_tail(passage: str) -> str:
    """About OVERLAP characters from the end of passage, starting at a word."""
    tail = passage[-OVERLAP:]
    match = SPACE.search(tail)
    if match and match.end() < len(tail):
        tail = tail[match.end() :]
    return tail.strip()


def add_on_chunk(add_on: AddOn, text: str, index: int) -> Chunk:
    """ref_id is the add-on's id, made by the API and never masked, so remove finds it.
    Each passage has its own section, as the search and the agent tell pieces apart by
    (ref_id, section)."""
    return Chunk(
        source=Source.USER_DOC,
        ref_id=add_on.knowledge_add_on_id,
        title=masked(add_on.name),
        text=masked(text.strip()),
        url="",
        section=f"/Part {index + 1}/",
        index=index,
    )


def ref_id_is(ref_id: str) -> models.FieldCondition:
    return models.FieldCondition(key="ref_id", match=models.MatchValue(value=ref_id))


def has_details(record: models.Record) -> bool:
    return DETAILS in (record.payload or {})


async def delete_pieces(client: AsyncQdrantClient, conditions: list[models.Condition]) -> None:
    failure = None
    try:
        if await client.collection_exists(store.COLLECTION):
            only = models.Filter(must=[store.source_is(Source.USER_DOC), *conditions])
            await client.delete(store.COLLECTION, only)
    except store.QDRANT_ERRORS as error:
        failure = store.knowledge_error(error)
    if failure is not None:
        raise failure


async def forget_quietly(client: AsyncQdrantClient, knowledge_add_on_id: str) -> None:
    """Remove what a failed save left. Qdrant is often down then too: the caller raises
    the first failure, not this one."""
    try:
        await remove_add_on(knowledge_add_on_id, client)
    except store.KnowledgeError:
        pass
