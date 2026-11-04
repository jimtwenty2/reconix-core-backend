"""A fake BGE-M3 for the knowledge and memory tests."""

import math
import zlib

from reconix_ai.providers import EMBEDDING_SIZE


class FakeEmbedder:
    """Stands in for BGE-M3: hashed word counts, so similar words give similar vectors."""

    def __init__(self) -> None:
        self.texts: list[str] = []

    async def embed(self, texts: list[str]) -> list[list[float]]:
        self.texts.extend(texts)
        return [vector(text) for text in texts]


def vector(text: str) -> list[float]:
    values = [0.0] * EMBEDDING_SIZE
    for word in text.lower().split():
        values[zlib.crc32(word.encode()) % EMBEDDING_SIZE] += 1.0
    norm = math.sqrt(sum(v * v for v in values)) or 1.0
    return [v / norm for v in values]
