"""The exact-words half of the hybrid search.

Text becomes a sparse vector of word counts. Qdrant weighs rare words higher
(its IDF modifier), so "CVE-2021-44228" or "T1190" finds the right piece even
when the meaning search does not.
"""

import re
import zlib

from qdrant_client import models

# A word, or a joined id such as "cve-2021-44228", "cwe-89" or "a03:2021".
TOKEN = re.compile(r"[a-z0-9]+(?:[-.:_][a-z0-9]+)*")
# The parts of a joined id ("cwe", "89") are common, so they count less than the whole id.
PART_WEIGHT = 0.5
# BM25's k1: the 2nd mention of a word adds less than the 1st, the 10th almost nothing.
K1 = 1.2


def tokens(text: str) -> list[tuple[str, float]]:
    """Every word with its weight, plus the parts of joined ids, so "44228" finds CVE-2021-44228."""
    words = []
    for match in TOKEN.findall(text.lower()):
        words.append((match, 1.0))
        parts = re.split(r"[-.:_]", match)
        if len(parts) > 1:
            words.extend((part, PART_WEIGHT) for part in parts)
    return words


def token_index(token: str) -> int:
    """A stable number for a word. crc32 gives the same value on every computer."""
    return zlib.crc32(token.encode("utf-8"))


def document_vector(text: str) -> models.SparseVector:
    counts: dict[int, float] = {}
    for token, weight in tokens(text):
        index = token_index(token)
        counts[index] = counts.get(index, 0.0) + weight
    values = [count * (K1 + 1) / (count + K1) for count in counts.values()]
    return models.SparseVector(indices=list(counts), values=values)


def query_vector(text: str) -> models.SparseVector:
    weights: dict[int, float] = {}
    for token, weight in tokens(text):
        index = token_index(token)
        weights[index] = max(weights.get(index, 0.0), weight)
    indices = sorted(weights)
    return models.SparseVector(indices=indices, values=[weights[i] for i in indices])
