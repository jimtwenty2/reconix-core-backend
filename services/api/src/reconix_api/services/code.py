"""Source code from VS Code: sync the file list, then upload what is missing.

Only your own open session may change its code. The audit lines hold counts and sizes,
never file names, because a file name can hold a secret too.
"""

from typing import BinaryIO
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core import code_files
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.models.enums import SessionStatus
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import scopes as scope_repo
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.code import CodeFileIn, CodeSyncOut, CodeUploadOut
from reconix_api.services.audit import audit

MB = 1024 * 1024


def sync_code(
    db: Db,
    write_audit: WriteAudit,
    settings: Settings,
    operator: Operator,
    session_id: UUID,
    files: list[CodeFileIn],
) -> CodeSyncOut:
    """Drops stored files the workspace no longer has; answers which ones to upload.
    Once the scope is approved, files in its excluded folders are never asked for."""
    ensure_own_open_session(db, operator, session_id)
    ensure_not_scanning(db, session_id)
    folder = code_files.session_folder(settings.code_dir, session_id)
    try:
        wanted = {file.path: file.sha256 for file in files}
        missing = code_files.sync(folder, wanted, excluded_folders(db, session_id))
    except code_files.CodeFileError as error:
        raise ApiError(422, "INVALID_CODE_FILES", str(error)) from error
    db.commit()  # the lock taken by ensure_not_scanning
    details = {"files": len(files), "missing": len(missing)}
    audit(write_audit, "CODE_SYNCED", operator, details=details)
    return CodeSyncOut(missing=missing, target=code_files.container_path(session_id))


def upload_code(
    db: Db,
    write_audit: WriteAudit,
    settings: Settings,
    operator: Operator,
    session_id: UUID,
    archive: BinaryIO,
) -> CodeUploadOut:
    """Unpacks a tar.gz into the session's code folder. A bad upload changes nothing.
    Once the scope is approved, files in its excluded folders are not stored."""
    ensure_own_open_session(db, operator, session_id)
    ensure_not_scanning(db, session_id)
    folder = code_files.session_folder(settings.code_dir, session_id)
    try:
        limit = settings.max_upload_mb * MB
        files, size = code_files.unpack(archive, folder, limit, excluded_folders(db, session_id))
    except code_files.CodeFileError as error:
        raise ApiError(422, "INVALID_CODE_UPLOAD", str(error)) from error
    db.commit()  # the lock taken by ensure_not_scanning
    audit(write_audit, "CODE_UPLOADED", operator, details={"files": files, "size_bytes": size})
    return CodeUploadOut(files=files, size_bytes=size, target=code_files.container_path(session_id))


def ensure_own_open_session(db: Db, operator: Operator, session_id: UUID) -> None:
    if session_id != operator.session_id:
        raise ApiError(403, "NOT_YOUR_SESSION", "You can only send code to your own session.")
    session = session_repo.get(db, session_id)
    if session is None:
        raise ApiError(404, "SESSION_NOT_FOUND", "No session with this id.")
    if session.session_status != SessionStatus.ACTIVE:
        raise ApiError(409, "SESSION_CLOSED", "This session is closed.")


def ensure_not_scanning(db: Db, session_id: UUID) -> None:
    """The code cannot change while a scan reads it. Holds the assessment row until the
    caller commits, so no scan starts while the code changes."""
    assessment = assessment_repo.get_by_session(db, session_id)
    if assessment is None:
        return
    assessment_repo.lock(db, assessment.assessment_id)
    if agent_run_repo.running_code_scan(db, assessment.assessment_id):
        raise ApiError(409, "SCAN_RUNNING", "Wait for the code scan to end, or cancel it.")


def excluded_folders(db: Db, session_id: UUID) -> list[str]:
    """The approved scope's excluded paths inside this session's code, relative to it
    (e.g. "node_modules"). Empty before the scope is approved."""
    assessment = assessment_repo.get_by_session(db, session_id)
    manifest = assessment and scope_repo.get_approved(db, assessment.assessment_id)
    if not manifest:
        return []
    excluded = [t.value for t in scope_repo.list_targets(db, manifest.manifest_id) if t.excluded]
    return code_files.excluded_inside(excluded, code_files.container_path(session_id))
