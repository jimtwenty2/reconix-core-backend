"""Knowledge add-ons, the TUI's /add-on: add a file, list them, remove one, remove all."""

from uuid import UUID

from fastapi import APIRouter, Request, status
from pydantic import ValidationError
from starlette.datastructures import UploadFile

from reconix_api.core.errors import ApiError
from reconix_api.core.knowledge_add_ons import CurrentKnowledgeStore
from reconix_api.core.knowledge_files import MAX_FILE_BYTES
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.knowledge_add_ons import (
    KnowledgeAddOnForm,
    KnowledgeAddOnOut,
    KnowledgeAddOnsCleared,
)
from reconix_api.services import knowledge_add_ons

router = APIRouter(prefix="/knowledge-add-ons", tags=["knowledge add-ons"])

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
) -> KnowledgeAddOnOut:
    """Adds your own file to the knowledge search. Send it as multipart/form-data: a .txt, .md,
    .json, .yaml, .yml, .docx or .pdf file of at most 10 MB, plus interface (web or cli). The
    optional name is the name to show, and its extension decides the file type; without it, the
    file's own name is used. The text is masked, cut into passages and saved in the knowledge
    search, where the agent finds it from then on. No copy of the file itself is kept. This
    needs Qdrant and the embedding model, and returns 503 without them."""
    check_upload_size(request)
    async with request.form(max_files=1, max_fields=2) as form:
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise form_error("file", "Field required")
        fields = read_form(form.get("interface"), form.get("name"))
        data = await upload.read(MAX_FILE_BYTES + 1)
        file_name = fields.name or upload.filename or ""
    return await knowledge_add_ons.add(
        store, interfaces.write_audit, mask, operator, file_name, data, fields.interface
    )


@router.get("")
async def list_knowledge_add_ons(
    _: CurrentOperator, store: CurrentKnowledgeStore
) -> list[KnowledgeAddOnOut]:
    """Lists your knowledge add-ons, oldest first."""
    return await knowledge_add_ons.list_add_ons(store)


@router.delete("/{knowledge_add_on_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_knowledge_add_on(
    knowledge_add_on_id: UUID,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    store: CurrentKnowledgeStore,
) -> None:
    """Deletes one add-on, and removes its text from the knowledge search. Returns 404
    KNOWLEDGE_ADD_ON_NOT_FOUND if there is no add-on with this id."""
    await knowledge_add_ons.remove(store, interfaces.write_audit, operator, knowledge_add_on_id)


@router.delete("")
async def delete_all_knowledge_add_ons(
    operator: CurrentOperator, interfaces: CurrentInterfaces, store: CurrentKnowledgeStore
) -> KnowledgeAddOnsCleared:
    """Deletes every add-on. The public knowledge (CVE, CWE, OWASP, ATT&CK and the tool guides)
    stays."""
    removed_count = await knowledge_add_ons.remove_all(store, interfaces.write_audit, operator)
    return KnowledgeAddOnsCleared(removed_count=removed_count)


def check_upload_size(request: Request) -> None:
    """Refuse a body over the limit before any of it is read. The server never reads
    past Content-Length, so a body without one (chunked) is refused too."""
    length = request.headers.get("content-length", "")
    if not length.isdigit():
        raise ApiError(411, "LENGTH_REQUIRED", "Send the upload with a Content-Length header.")
    if int(length) > MAX_UPLOAD_BYTES:
        raise ApiError(413, "FILE_TOO_LARGE", "That file is over 10 MB.")


def read_form(interface: object, name: object) -> KnowledgeAddOnForm:
    try:
        return KnowledgeAddOnForm.model_validate({"interface": interface, "name": name or None})
    except ValidationError as error:
        first = error.errors()[0]
        raise form_error(".".join(map(str, first["loc"])), first["msg"]) from None


def form_error(field: str, message: str) -> ApiError:
    """The shape of every other request error; the value sent is never echoed back."""
    fields = [{"field": f"body.{field}", "message": message}]
    return ApiError(422, "VALIDATION_ERROR", "The request is not valid.", {"fields": fields})
