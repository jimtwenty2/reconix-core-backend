"""Knowledge add-ons: a person's own documents the AI may search, like the TUI's /add-on.

A file is read once, its name and text are masked, and the text is cut into passages
saved in Qdrant next to the public knowledge (as USER_DOC), so the agent's knowledge
search finds them. Nothing else is kept: no copy of the file and no original. At most
MAX_ADD_ONS add-ons are kept, as in the TUI, waiting ones included.

An upload with ingest_now=false is not put into Qdrant yet: its masked passages wait,
encrypted (core/knowledge_pending.py), as PENDING until a re-ingest
(services/knowledge_reingest.py). The agent cannot find a waiting add-on; the Security
knowledge page can still read it.
"""

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from reconix_api.core import knowledge_add_ons, knowledge_files, knowledge_pending
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.core.knowledge_add_ons import AddOn, KnowledgeStore
from reconix_api.core.masking import MaskSecrets
from reconix_api.schemas.knowledge_add_ons import (
    KnowledgeAddOnOut,
    KnowledgeAddOnPassagesOut,
    KnowledgeAddOnReferencesOut,
    KnowledgeHitOut,
    KnowledgePassageOut,
    KnowledgeReferenceOut,
    KnowledgeSpanOut,
)
from reconix_api.services import knowledge_references
from reconix_api.services.audit import audit

MAX_ADD_ONS = 50
PASSAGE_LIMIT = "PASSAGE_LIMIT"


async def add(
    store: KnowledgeStore,
    settings: Settings,
    write_audit: WriteAudit,
    mask: MaskSecrets,
    operator: Operator,
    file_name: str,
    data: bytes,
    interface: str,
    name: str | None = None,
    ingest_now: bool = True,
) -> KnowledgeAddOnOut:
    """Read, mask and save one file: searchable once this returns, or with ingest_now
    false, waiting for a re-ingest. name is the label shown (the file's own name without
    it); the type comes from the file (pick_kind)."""
    kind = pick_kind(file_name, name)
    async with store.adding:
        kept = len(await knowledge_add_ons.list_all(store)) + len(
            knowledge_pending.list_all(settings)
        )
        if kept >= MAX_ADD_ONS:
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
        if ingest_now:
            await knowledge_add_ons.save(store, add_on, passages)
        else:
            knowledge_pending.save(settings, add_on, passages)
    status = "INGESTED" if ingest_now else "PENDING"
    _audit(write_audit, "KNOWLEDGE_ADD_ON_ADDED", operator, add_on, status)
    return add_on_out(add_on, cut, status)


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


async def list_add_ons(store: KnowledgeStore, settings: Settings) -> list[KnowledgeAddOnOut]:
    """Every add-on, ingested and waiting, oldest first."""
    ingested = [add_on_out(a) for a in await knowledge_add_ons.list_all(store)]
    known = {str(a.knowledge_add_on_id) for a in ingested}  # a failed re-index can leave both
    waiting = [
        add_on_out(a, status="PENDING")
        for a in knowledge_pending.list_all(settings)
        if a.knowledge_add_on_id not in known
    ]
    return sorted([*ingested, *waiting], key=lambda a: a.created_at)


async def _texts(store: KnowledgeStore, settings: Settings, knowledge_add_on_id: UUID) -> list[str]:
    """One add-on's passages, waiting or ingested; 404 when there is no such add-on."""
    waiting = knowledge_pending.load(settings, str(knowledge_add_on_id))
    if waiting is not None:
        return waiting[1]
    if await _find(store, knowledge_add_on_id) is None:
        raise ApiError(404, "KNOWLEDGE_ADD_ON_NOT_FOUND", "No knowledge add-on with this id.")
    return await knowledge_add_ons.passages(store, str(knowledge_add_on_id))


async def references(
    store: KnowledgeStore, settings: Settings, knowledge_add_on_id: UUID
) -> KnowledgeAddOnReferencesOut:
    """The references and topics in one add-on's passages (knowledge_references.py)."""
    texts = await _texts(store, settings, knowledge_add_on_id)
    found = knowledge_references.references(texts)
    return KnowledgeAddOnReferencesOut(
        knowledge_add_on_id=knowledge_add_on_id,
        references=[KnowledgeReferenceOut(**ref.__dict__) for ref in found],
    )


async def passages(
    store: KnowledgeStore,
    settings: Settings,
    mask: MaskSecrets,
    knowledge_add_on_id: UUID,
    offset: int,
    limit: int,
) -> KnowledgeAddOnPassagesOut:
    """A page of one add-on's passages, each with where its references and topics are named.
    The text was masked when it was saved; it is masked again here (S8), and the places are
    found in the text as it is sent, so they always line up."""
    texts = await _texts(store, settings, knowledge_add_on_id)
    page = []
    for index, text in enumerate(texts[offset : offset + limit], start=offset):
        shown = mask(text)[0]
        spans = [
            KnowledgeSpanOut(type=s.type, ref_id=s.ref_id, start=s.start, end=s.end)
            for s in knowledge_references.spans(shown)
        ]
        page.append(KnowledgePassageOut(index=index, text=shown, spans=spans))
    return KnowledgeAddOnPassagesOut(
        knowledge_add_on_id=knowledge_add_on_id, total=len(texts), offset=offset, passages=page
    )


async def remove(
    store: KnowledgeStore,
    settings: Settings,
    write_audit: WriteAudit,
    operator: Operator,
    knowledge_add_on_id: UUID,
) -> None:
    """A waiting add-on is simply forgotten. An unknown id answers 404 (one audit line),
    but its pieces are removed anyway: a save that failed half way can leave some behind
    that are searchable but not listed."""
    store.removed.add(str(knowledge_add_on_id))  # a running re-ingest must not put it back
    waiting = knowledge_pending.load(settings, str(knowledge_add_on_id))
    if waiting is not None:
        knowledge_pending.remove(settings, str(knowledge_add_on_id))
        _audit(write_audit, "KNOWLEDGE_ADD_ON_REMOVED", operator, waiting[0], "PENDING")
        return
    if knowledge_pending.remove(settings, str(knowledge_add_on_id)):
        # a waiting file that cannot be read any more (another key, or damaged): still removable
        details = {"knowledge_add_on_id": str(knowledge_add_on_id), "ingest_status": "PENDING"}
        audit(write_audit, "KNOWLEDGE_ADD_ON_REMOVED", operator, details=details)
        return
    add_on = await _find(store, knowledge_add_on_id)
    await knowledge_add_ons.remove(store, str(knowledge_add_on_id))
    if add_on is None:
        details = {"knowledge_add_on_id": str(knowledge_add_on_id)}
        audit(write_audit, "KNOWLEDGE_ADD_ON_NOT_FOUND", operator, details=details)
        raise ApiError(404, "KNOWLEDGE_ADD_ON_NOT_FOUND", "No knowledge add-on with this id.")
    _audit(write_audit, "KNOWLEDGE_ADD_ON_REMOVED", operator, add_on)


async def remove_all(
    store: KnowledgeStore, settings: Settings, write_audit: WriteAudit, operator: Operator
) -> int:
    """How many were removed, waiting ones included. The public knowledge stays."""
    store.removed.add("*")  # a running re-ingest must not put any back
    removed_count = len(await knowledge_add_ons.list_all(store))
    await knowledge_add_ons.remove_all(store)
    removed_count += knowledge_pending.remove_all(settings)
    details = {"removed_count": removed_count}
    audit(write_audit, "KNOWLEDGE_ADD_ONS_CLEARED", operator, details=details)
    return removed_count


def add_on_out(
    add_on: AddOn, cut: str | None = None, status: str = "INGESTED"
) -> KnowledgeAddOnOut:
    return KnowledgeAddOnOut(
        knowledge_add_on_id=UUID(add_on.knowledge_add_on_id),
        name=add_on.name,
        kind=add_on.kind,
        size_bytes=add_on.size_bytes,
        chunk_count=add_on.chunk_count,
        interface=add_on.interface,
        created_at=datetime.fromisoformat(add_on.created_at),
        ingest_status=status,
        cut=cut,
    )


async def _find(store: KnowledgeStore, knowledge_add_on_id: UUID) -> AddOn | None:
    for add_on in await knowledge_add_ons.list_all(store):
        if add_on.knowledge_add_on_id == str(knowledge_add_on_id):
            return add_on
    return None


def _audit(
    write_audit: WriteAudit,
    event_type: str,
    operator: Operator,
    add_on: AddOn,
    status: str = "INGESTED",
) -> None:
    details = {
        "ingest_status": status,
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
