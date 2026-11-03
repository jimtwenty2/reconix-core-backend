"""Source code of a session, sent by the VS Code extension: sync the list, upload the rest."""

import tempfile
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.errors import ApiError
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.code import CodeSync, CodeSyncOut, CodeUploadOut
from reconix_api.services import code
from reconix_api.services.code import MB

router = APIRouter(prefix="/sessions/{session_id}/code", tags=["code"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]
SPOOL_BYTES = 8 * MB  # bigger uploads go to a temporary file while they arrive
# The route reads the body itself, after the session token is checked, so the body is
# described here for docs/openapi.json.
UPLOAD_BODY = {
    "requestBody": {
        "required": True,
        "content": {"application/gzip": {"schema": {"type": "string", "format": "binary"}}},
    }
}


@router.post("/sync")
def sync_code(
    session_id: UUID,
    body: CodeSync,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> CodeSyncOut:
    """Tells the API which files the workspace has right now, with each file's path, size and
    SHA-256. Stored files that are not in the list are deleted, and `missing` lists the files to
    upload next. Once the scope is approved, files in its excluded folders are never asked for
    or stored. This works only on your own open session: otherwise it returns 403
    NOT_YOUR_SESSION, or 409 SESSION_CLOSED if the session is closed."""
    return code.sync_code(db, interfaces.write_audit, settings, operator, session_id, body.files)


@router.put("", openapi_extra=UPLOAD_BODY)
async def upload_code(
    session_id: UUID,
    request: Request,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> CodeUploadOut:
    """Uploads the missing files as one tar.gz with relative paths. The archive may be at most
    RECONIX_MAX_UPLOAD_MB, both packed and unpacked. A packed archive over the limit returns
    413 UPLOAD_TOO_LARGE. One that is too big unpacked, is broken, or holds a link, a device,
    an absolute path or `..` returns 422 INVALID_CODE_UPLOAD. A refused upload changes
    nothing."""
    code.ensure_own_open_session(db, operator, session_id)  # before reading the body
    limit = settings.max_upload_mb * MB
    with tempfile.SpooledTemporaryFile(max_size=SPOOL_BYTES) as archive:
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                raise ApiError(413, "UPLOAD_TOO_LARGE", "The upload is larger than the limit.")
            archive.write(chunk)
        archive.seek(0)
        return await run_in_threadpool(
            code.upload_code, db, interfaces.write_audit, settings, operator, session_id, archive
        )
