"""Knowledge add-ons, the TUI's /add-on: add a file, list them, remove one, remove all."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import ValidationError
from starlette.datastructures import UploadFile

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.errors import ApiError
from reconix_api.core.knowledge_add_ons import CurrentKnowledgeStore
from reconix_api.core.knowledge_files import MAX_FILE_BYTES
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.knowledge_add_ons import (
    KnowledgeAddOnForm,
    KnowledgeAddOnOut,
    KnowledgeAddOnPassagesOut,
    KnowledgeAddOnReferencesOut,
    KnowledgeAddOnsCleared,
)
from reconix_api.services import knowledge_add_ons

router = APIRouter(prefix="/knowledge-add-ons", tags=["knowledge add-ons"])
CurrentSettings = Annotated[Settings, Depends(get_settings)]

MAX_UPLOAD_BYTES = MAX_FILE_BYTES + 64 * 1024  # the file and the form around it
# The route reads the form itself, after the session token is checked, so the form is
# described here for docs/openapi.json.
UPLOAD_FORM = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["file", "interface"],
                    "properties": {
                        "file": {"type": "string", "format": "binary"},
                        "interface": {"type": "string", "enum": ["web", "cli"]},
                        "name": {"type": "string", "maxLength": 255},
                    },
                }
            }
        },
    }
}


@router.post("", status_code=status.HTTP_201_CREATED, openapi_extra=UPLOAD_FORM)
async def create_knowledge_add_on(
    request: Request,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    store: CurrentKnowledgeStore,
    settings: CurrentSettings,
) -> KnowledgeAddOnOut:
    """Adds your own file to the knowledge search.

    Business Rules:
    - Send multipart/form-data: a .txt, .md, .json, .yaml, .yml, .docx, or .pdf file of at most
      10 MB, plus interface (web or cli).
    - The file type comes from the uploaded file's own name. The optional name is only the
      display name, except for a file whose own name has no supported type (such as a pasted
      "blob"): its type then comes from name's extension.
    - Optional ingest_now (default true). false: the file is read and masked now, but waits
      (ingest_status PENDING) until POST /knowledge/reingest puts it into the knowledge
      search; until then the agent cannot find it.

    Execution Behavior:
    - Masks the text, splits it into passages, and saves them in the knowledge search, where the
      agent finds them from then on.

    State Changes:
    - Adds the passages to the knowledge search. No copy of the file itself is kept.

    Operational Considerations:
    - Requires Qdrant and the embedding model; returns 503 without them.

    Security:
    - Requires a valid session token.
    """
    check_upload_size(request)
    async with request.form(max_files=1, max_fields=3) as form:
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise form_error("file", "Field required")
        fields = read_form(form.get("interface"), form.get("name"), form.get("ingest_now"))
        data = await upload.read(MAX_FILE_BYTES + 1)
        file_name = upload.filename or ""
    return await knowledge_add_ons.add(
        store,
        settings,
        interfaces.write_audit,
        mask,
        operator,
        file_name,
        data,
        fields.interface,
        fields.name,
        fields.ingest_now,
    )


@router.get("")
async def list_knowledge_add_ons(
    _: CurrentOperator, store: CurrentKnowledgeStore, settings: CurrentSettings
) -> list[KnowledgeAddOnOut]:
    """Lists your knowledge add-ons, oldest first: ingested ones and ones waiting for a
    re-ingest (ingest_status INGESTED or PENDING).

    Security:
    - Requires a valid session token.
    """
    return await knowledge_add_ons.list_add_ons(store, settings)


@router.get("/{knowledge_add_on_id}/references")
async def knowledge_add_on_references(
    knowledge_add_on_id: UUID,
    store: CurrentKnowledgeStore,
    settings: CurrentSettings,
    _: CurrentOperator,
) -> KnowledgeAddOnReferencesOut:
    """Lists what one add-on talks about: its security references and topics.

    Business Rules:
    - References are exact ids found in its passages: CVE (CVE-2021-44228), CWE (CWE-89),
      OWASP (A03:2021, API1:2023), MITRE ATT&CK (T1190) and Kali catalog tools (NMAP).
    - Topics come from plain words (SQL injection, Cross-site scripting, ...).
    - Each is counted once per passage; most mentioned first, at most 60.
    - Returns 404 KNOWLEDGE_ADD_ON_NOT_FOUND for an unknown id, and 503 when the knowledge
      search (Qdrant) is not there.

    Security:
    - Requires a valid session token.
    - Never returns the passages themselves, only names and counts.
    """
    return await knowledge_add_ons.references(store, settings, knowledge_add_on_id)


@router.get("/{knowledge_add_on_id}/passages")
async def knowledge_add_on_passages(
    knowledge_add_on_id: UUID,
    store: CurrentKnowledgeStore,
    settings: CurrentSettings,
    mask: CurrentMask,
    _: CurrentOperator,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> KnowledgeAddOnPassagesOut:
    """Returns a page of one add-on's passages, to read it on the Security knowledge page.

    Business Rules:
    - Passages come in the document's order: `offset` (0 first) and `limit` (at most 100) page
      through them; `total` says how many there are.
    - Each passage lists where its references and topics are named (`spans`: character
      offsets into its text), found by the same rules as /references.
    - Returns 404 KNOWLEDGE_ADD_ON_NOT_FOUND for an unknown id, and 503 when the knowledge
      search (Qdrant) is not there.

    Security:
    - Requires a valid session token.
    - The text was masked when the file was added, and is masked again before it is sent.
    """
    return await knowledge_add_ons.passages(
        store, settings, mask, knowledge_add_on_id, offset, limit
    )


@router.delete("/{knowledge_add_on_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_knowledge_add_on(
    knowledge_add_on_id: UUID,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    store: CurrentKnowledgeStore,
    settings: CurrentSettings,
) -> None:
    """Deletes one add-on and removes its text from the knowledge search (or forgets it,
    while it waits to be ingested).

    Business Rules:
    - Returns 404 KNOWLEDGE_ADD_ON_NOT_FOUND if no add-on has this id.

    State Changes:
    - Deletes the add-on and its passages.

    Security:
    - Requires a valid session token.
    """
    await knowledge_add_ons.remove(
        store, settings, interfaces.write_audit, operator, knowledge_add_on_id
    )


@router.delete("")
async def delete_all_knowledge_add_ons(
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    store: CurrentKnowledgeStore,
    settings: CurrentSettings,
) -> KnowledgeAddOnsCleared:
    """Deletes every add-on.

    Business Rules:
    - The public knowledge (CVE, CWE, OWASP, ATT&CK, and the tool guides) stays.

    State Changes:
    - Deletes all add-ons and their passages.

    Security:
    - Requires a valid session token.
    """
    removed_count = await knowledge_add_ons.remove_all(
        store, settings, interfaces.write_audit, operator
    )
    return KnowledgeAddOnsCleared(removed_count=removed_count)


def check_upload_size(request: Request) -> None:
    """Refuse a body over the limit before any of it is read. The server never reads
    past Content-Length, so a body without one (chunked) is refused too."""
    length = request.headers.get("content-length", "")
    if not length.isdigit():
        raise ApiError(411, "LENGTH_REQUIRED", "Send the upload with a Content-Length header.")
    if int(length) > MAX_UPLOAD_BYTES:
        raise ApiError(413, "FILE_TOO_LARGE", "That file is over 10 MB.")


def read_form(interface: object, name: object, ingest_now: object = None) -> KnowledgeAddOnForm:
    values = {"interface": interface, "name": name or None}
    if ingest_now is not None:
        values["ingest_now"] = ingest_now
    try:
        return KnowledgeAddOnForm.model_validate(values)
    except ValidationError as error:
        first = error.errors()[0]
        raise form_error(".".join(map(str, first["loc"])), first["msg"]) from None


def form_error(field: str, message: str) -> ApiError:
    """The shape of every other request error; the value sent is never echoed back."""
    fields = [{"field": f"body.{field}", "message": message}]
    return ApiError(422, "VALIDATION_ERROR", "The request is not valid.", {"fields": fields})
