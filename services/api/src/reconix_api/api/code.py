"""Source code of a session: sync the list and upload the rest, clone a GitHub repo, or
copy a folder on this computer."""

import asyncio
import tempfile
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.errors import ApiError
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.code import (
    CodeClonedOut,
    CodeCloneIn,
    CodeFolderIn,
    CodeSync,
    CodeSyncOut,
    CodeUploadOut,
)
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
    """Reports which files the workspace currently has, each with its path, size, and SHA-256.

    Business Rules:
    - The response's `missing` field lists the files to upload next.
    - Once the scope is approved, files in its excluded folders are never asked for or stored.
    - Returns 409 SESSION_CLOSED if the session is closed.

    State Changes:
    - Deletes stored files that are not in the list.

    Security:
    - Requires a valid session token.
    - Works only on your own open session; returns 403 NOT_YOUR_SESSION otherwise.
    """
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
    """Uploads the missing files as one tar.gz of relative paths.

    Business Rules:
    - The archive may be at most RECONIX_MAX_UPLOAD_MB, both packed and unpacked.
    - A packed archive over the limit returns 413 UPLOAD_TOO_LARGE.
    - One that is too large unpacked, is broken, or holds a link, device, absolute path, or `..`
      returns 422 INVALID_CODE_UPLOAD.
    - A refused upload changes nothing.

    State Changes:
    - Stores the uploaded files for the session.

    Security:
    - Requires a valid session token.
    - Works only on your own open session.
    """
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


@router.post("/clone")
async def clone_repo(
    session_id: UUID,
    body: CodeCloneIn,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> CodeClonedOut:
    """Replaces the session's code with a GitHub repo's files.

    Business Rules:
    - `url` must be `https://github.com/<owner>/<repo>`, optionally ending in `.git` or `/`;
      anything else returns 422 INVALID_REPO_URL.
    - A clone of the repo found under RECONIX_LOCAL_REPO_ROOTS (4 folder levels deep, matched
      by the `origin` remote in its `.git/config`) is copied as it is, uncommitted and
      git-ignored files too, and never pulled. `source` is then `LOCAL_CLONE`.
    - Otherwise git makes a shallow clone of the default branch over https only, with no
      tags, no LFS files and no symlinks. `source` is then `GITHUB`.
    - With `token`, git sends it only to github.com, in an Authorization header; without it,
      this computer's own git credentials apply.
    - `.git`, links, non-regular files and the folders `node_modules`, `.venv`, `venv`,
      `__pycache__`, `dist`, `build`, `target`, `.idea` and `.vscode` are left out. The upload
      limits apply: a repo past them returns 422 INVALID_CODE_FOLDER.
    - git failing returns 502 CLONE_FAILED, taking over 300 seconds 504 CLONE_TIMED_OUT, and
      no git on this computer 503 GIT_NOT_FOUND.
    - Returns 409 SCAN_RUNNING while a code scan runs, and 409 SESSION_CLOSED if the session is
      closed.

    State Changes:
    - Deletes the session's stored code, then stores the repo's files.

    Security:
    - Requires a valid session token.
    - Works only on your own open session; returns 403 NOT_YOUR_SESSION otherwise.
    - The GitHub token is never stored, logged, audited or put on git's command line.
    """
    return await asyncio.to_thread(
        code.clone_repo,
        db,
        interfaces.write_audit,
        settings,
        operator,
        session_id,
        body.url,
        body.token,
    )


@router.post("/folder")
async def copy_folder(
    session_id: UUID,
    body: CodeFolderIn,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> CodeUploadOut:
    """Replaces the session's code with a copy of a folder on this computer.

    Business Rules:
    - `path` must be an absolute path to a folder; links in it are followed first. A missing
      folder returns 422 FOLDER_NOT_FOUND.
    - A folder inside or holding `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gh`, `~/.kube`,
      `~/.docker`, `/etc`, `/proc`, `/sys`, `/dev`, `/root`, `/boot` or `/var`, or inside
      Reconix's own code, reports or audit folders, returns 403 FOLDER_NOT_ALLOWED.
    - The same files are left out, and the same limits apply, as for `POST /code/clone`.
    - Returns 409 SCAN_RUNNING while a code scan runs, and 409 SESSION_CLOSED if the session is
      closed.

    State Changes:
    - Deletes the session's stored code, then stores the folder's files. The folder itself is
      never changed.

    Security:
    - Requires a valid session token.
    - Works only on your own open session; returns 403 NOT_YOUR_SESSION otherwise.
    """
    return await asyncio.to_thread(
        code.copy_folder, db, interfaces.write_audit, settings, operator, session_id, body.path
    )
