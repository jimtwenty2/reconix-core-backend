"""Ingest (LlamaIndex), Qdrant hybrid search (BGE-M3 + keywords), search_knowledge(),
and the add-ons people upload through the API."""

from reconix_ai.knowledge.add_ons import (
    AddOn,
    list_add_ons,
    remove_add_on,
    remove_all_add_ons,
    save_add_on,
    split_passages,
)
from reconix_ai.knowledge.items import KnowledgeItem, Source
from reconix_ai.knowledge.search import (
    EmbedTexts,
    KnowledgeFilters,
    KnowledgeHit,
    search_knowledge,
)
from reconix_ai.knowledge.store import KnowledgeError

__all__ = [
    "AddOn",
    "EmbedTexts",
    "KnowledgeError",
    "KnowledgeFilters",
    "KnowledgeHit",
    "KnowledgeItem",
    "Source",
    "list_add_ons",
    "remove_add_on",
    "remove_all_add_ons",
    "save_add_on",
    "search_knowledge",
    "split_passages",
]
