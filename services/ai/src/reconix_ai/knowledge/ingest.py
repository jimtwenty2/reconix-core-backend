"""Load the knowledge into Qdrant.

    uv run --package reconix-ai python -m reconix_ai.knowledge.ingest [folder] [--rebuild]

Uses the full download in data/knowledge/ if it is there, else the committed
sample. Needs Ollama with bge-m3 (`ollama pull bge-m3`) and Qdrant running.
The public knowledge is replaced on every run; the add-ons people uploaded
(USER_DOC, add_ons.py) stay. --rebuild drops the whole collection and makes it
again, add-ons and all: use it when the vectors or indexes change.
"""

import asyncio
import sys
from pathlib import Path

from qdrant_client import AsyncQdrantClient

from reconix_ai.knowledge import store
from reconix_ai.knowledge.chunks import load_items, make_chunks
from reconix_ai.knowledge.paths import TOOL_GUIDES_DIR, knowledge_data_dir
from reconix_ai.knowledge.search import EmbedTexts
from reconix_ai.providers import embed_texts


async def ingest(
    data_dir: Path,
    guides_dir: Path = TOOL_GUIDES_DIR,
    client: AsyncQdrantClient | None = None,
    embed: EmbedTexts = embed_texts,
    rebuild: bool = False,
) -> int:
    """Replace the public knowledge and return how many pieces were saved. rebuild: drop
    the whole collection first, add-ons included."""
    chunks = make_chunks(load_items(data_dir, guides_dir))
    if not chunks:
        raise ValueError(f"No knowledge found in {data_dir}.")
    client = client or store.shared_client()
    vectors = await embed([chunk.title + "\n" + chunk.text for chunk in chunks])
    failure = None
    try:
        if rebuild:
            await store.create_collection(client)
        else:
            await store.clear_public_knowledge(client)
        await store.save_chunks(client, chunks, vectors)
    except store.QDRANT_ERRORS as error:
        failure = store.knowledge_error(error)
    if failure is not None:
        raise failure
    return len(chunks)


if __name__ == "__main__":
    folders = [arg for arg in sys.argv[1:] if arg != "--rebuild"]
    folder = Path(folders[0]) if folders else knowledge_data_dir()
    print(f"Loading {folder} ...")
    count = asyncio.run(ingest(folder, rebuild="--rebuild" in sys.argv[1:]))
    print(f"Saved {count} pieces in Qdrant collection '{store.COLLECTION}'.")
