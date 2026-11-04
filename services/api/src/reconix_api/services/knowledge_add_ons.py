"""Knowledge add-ons: a person's own documents the AI may search, like the TUI's /add-on.

A file is read once, its name and text are masked, and the text is cut into passages
saved in Qdrant next to the public knowledge (as USER_DOC), so the agent's knowledge
search finds them. Nothing else is kept: no copy of the file and no original. At most
MAX_ADD_ONS add-ons are kept, as in the TUI.
"""

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from reconix_api.core import knowledge_add_ons, knowledge_files
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.core.knowledge_add_ons import AddOn, KnowledgeStore
from reconix_api.core.masking import MaskSecrets
from reconix_api.schemas.knowledge_add_ons import KnowledgeAddOnOut, KnowledgeHitOut
from reconix_api.services.audit import audit

MAX_ADD_ONS = 50
PASSAGE_LIMIT = "PASSAGE_LIMIT"


async def add(
    store: KnowledgeStore,
    write_audit: WriteAudit,
    mask: MaskSecrets,
    operator: Operator,
    file_name: str,
    data: bytes,
    interface: str,
    name: str | None = None,
) -> KnowledgeAddOnOut:
    """Read, mask and save one file. It is searchable once this returns. name is the label
    shown (the file's own name without it); the type comes from the file (pick_kind)."""
    kind = pick_kind(file_name, name)
    async with store.adding:
        if len(await knowledge_add_ons.list_all(store)) >= MAX_ADD_ONS:
            raise ApiError(
                409,
                "KNOWLEDGE_ADD_ON_LIMIT",
                f"The knowledge limit is {MAX_ADD_ONS} add-ons. Remove one first.",
            )
        passages, cut = await asyncio.to_thread(read_passages, mask, kind, data)
        add_on = AddOn(
            knowledge_add_on_id=str(uuid4()),
            name=knowledge_files.display_name(mask(name or file_name)[0]),
            kind=kind,
            size_bytes=len(data),
            chunk_count=len(passages),
            interface=interface,
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        await knowledge_add_ons.save(store, add_on, passages)
    _audit(write_audit, "KNOWLEDGE_ADD_ON_ADDED", operator, add_on)
    return add_on_out(add_on, cut)


def pick_kind(file_name: str, name: str | None) -> str:
    """The uploaded file's own extension decides the type, so a label (Swagger's "string",
    "Company runbook") never changes how the file is read. Only a file whose own name has
    no supported type (a pasted "blob", "upload.bin") takes it from name."""
    try:
        return knowledge_files.kind_of(file_name)
    except ApiError:
        if not name:
            raise
    return knowledge_files.kind_of(name)


def read_passages(mask: MaskSecrets, kind: str, data: bytes) -> tuple[list[str], str | None]:
    """(passages, cut). The whole text is masked before it is cut, so a secret across a
    cut or across two passages is still found."""
    file_text = knowledge_files.read_text(kind, data)
    masked_text, _ = mask(file_text.text)
    text, cut = knowledge_files.cut_text(masked_text, file_text.cut)
    passages, too_many = knowledge_add_ons.split_passages(text)
    if not passages:
        raise ApiError(422, "FILE_HAS_NO_TEXT", "That file has no readable text to add.")
    return passages, PASSAGE_LIMIT if too_many else cut


async def list_add_ons(store: KnowledgeStore) -> list[KnowledgeAddOnOut]:
    return [add_on_out(add_on) for add_on in await knowledge_add_ons.list_all(store)]


async def remove(
    store: KnowledgeStore, write_audit: WriteAudit, operator: Operator, knowledge_add_on_id: UUID
) -> None:
    """An unknown id answers 404 (one audit line), but its pieces are removed anyway: a
    save that failed half way can leave some behind that are searchable but not listed."""
    add_on = await _find(store, knowledge_add_on_id)
    await knowledge_add_ons.remove(store, str(knowledge_add_on_id))
    if add_on is None:
        details = {"knowledge_add_on_id": str(knowledge_add_on_id)}
        audit(write_audit, "KNOWLEDGE_ADD_ON_NOT_FOUND", operator, details=details)
        raise ApiError(404, "KNOWLEDGE_ADD_ON_NOT_FOUND", "No knowledge add-on with this id.")
    _audit(write_audit, "KNOWLEDGE_ADD_ON_REMOVED", operator, add_on)


async def remove_all(store: KnowledgeStore, write_audit: WriteAudit, operator: Operator) -> int:
    """How many were removed. The public knowledge stays."""
    removed_count = len(await knowledge_add_ons.list_all(store))
    await knowledge_add_ons.remove_all(store)
    details = {"removed_count": removed_count}
    audit(write_audit, "KNOWLEDGE_ADD_ONS_CLEARED", operator, details=details)
    return removed_count


def add_on_out(add_on: AddOn, cut: str | None = None) -> KnowledgeAddOnOut:
    return KnowledgeAddOnOut(
        knowledge_add_on_id=UUID(add_on.knowledge_add_on_id),
        name=add_on.name,
        kind=add_on.kind,
        size_bytes=add_on.size_bytes,
        chunk_count=add_on.chunk_count,
        interface=add_on.interface,
        created_at=datetime.fromisoformat(add_on.created_at),
        cut=cut,
    )


async def _find(store: KnowledgeStore, knowledge_add_on_id: UUID) -> AddOn | None:
    for add_on in await knowledge_add_ons.list_all(store):
        if add_on.knowledge_add_on_id == str(knowledge_add_on_id):
            return add_on
    return None


def _audit(write_audit: WriteAudit, event_type: str, operator: Operator, add_on: AddOn) -> None:
    details = {
        "knowledge_add_on_id": add_on.knowledge_add_on_id,
        "name": add_on.name,  # masked
        "kind": add_on.kind,
        "chunk_count": add_on.chunk_count,
    }
    audit(write_audit, event_type, operator, details=details)


async def search(
    store: KnowledgeStore, query: str, sources: list[str], limit: int
) -> list[KnowledgeHitOut]:
    hits = await knowledge_add_ons.search(store, query, sources, limit)
    return [KnowledgeHitOut.model_validate(hit, from_attributes=True) for hit in hits]
