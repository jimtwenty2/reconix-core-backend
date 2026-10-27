"""Load the knowledge into Qdrant.

    uv run --package reconix-ai python -m reconix_ai.knowledge.ingest

Uses the full download in data/knowledge/ if it is there, else the committed
sample. Needs Ollama with bge-m3 (`ollama pull bge-m3`) and Qdrant running.
The collection is made again from scratch on every run.
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
) -> int:
    """Load every item into a fresh collection and return how many pieces were saved."""
    chunks = make_chunks(load_items(data_dir, guides_dir))
    if not chunks:
        raise ValueError(f"No knowledge found in {data_dir}.")
    client = client or store.connect()
    vectors = await embed([chunk.title + "\n" + chunk.text for chunk in chunks])
    await store.create_collection(client)
    await store.save_chunks(client, chunks, vectors)
    return len(chunks)


if __name__ == "__main__":
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else knowledge_data_dir()
    print(f"Loading {folder} ...")
    count = asyncio.run(ingest(folder))
    print(f"Saved {count} pieces in Qdrant collection '{store.COLLECTION}'.")
