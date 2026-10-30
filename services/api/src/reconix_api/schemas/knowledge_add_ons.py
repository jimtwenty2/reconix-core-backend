"""Shapes for /knowledge-add-ons. The upload itself is a multipart form (see the route)."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

KnowledgeAddOnKind = Literal["TXT", "MD", "JSON", "YAML", "DOCX", "PDF"]
# Where the person added it from, with the values of sessions.interface.
KnowledgeAddOnInterface = Literal["web", "cli"]
# Which limit cut the text short: 2 MB of text, 2,000 PDF pages or 2,000 passages.
KnowledgeAddOnCut = Literal["TEXT_LIMIT", "PAGE_LIMIT", "PASSAGE_LIMIT"]


class KnowledgeAddOnForm(BaseModel):
    """The text fields of the upload form, next to its file."""

    interface: KnowledgeAddOnInterface
    # The name to show; its extension picks the type. Empty: the file's own name.
    name: str | None = Field(default=None, max_length=255)


class KnowledgeAddOnOut(BaseModel):
    knowledge_add_on_id: UUID
    name: str  # the file name, masked
    kind: KnowledgeAddOnKind
    size_bytes: int  # the file as uploaded
    chunk_count: int  # passages saved for the knowledge search
    interface: KnowledgeAddOnInterface
    created_at: datetime
    # Only in the answer to an upload. None: the whole file was read.
    cut: KnowledgeAddOnCut | None = None


class KnowledgeAddOnsCleared(BaseModel):
    removed_count: int
