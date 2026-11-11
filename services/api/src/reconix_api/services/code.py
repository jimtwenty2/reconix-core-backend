"""A session's source code: sync the file list and upload what is missing, clone a GitHub
repo, or copy a folder on this computer.

Only your own open session may change its code. The audit lines hold counts and sizes,
never file names, because a file name can hold a secret too. A GitHub token is never
stored, logged, audited or put on git's command line.
"""

import base64
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import BinaryIO, Literal
from uuid import UUID

from pydantic import SecretStr
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
from reconix_api.schemas.code import CodeClonedOut, CodeFileIn, CodeSyncOut, CodeUploadOut
from reconix_api.services.audit import audit

MB = 1024 * 1024
GITHUB_URL = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?")
# A GitHub remote in a .git/config: https, ssh:// or git@github.com:owner/name, maybe
# with a user (or a token) before the host and .git after the name.
GITHUB_REMOTE = re.compile(
    r"(?:https?://|ssh://)?(?:[^@/]+@)?github\.com[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?",
    re.IGNORECASE,
)
LOCAL_CLONE_DEPTH = 4  # folder levels searched under each RECONIX_LOCAL_REPO_ROOTS entry
CLONE_SECONDS = 300
# A folder copied into a session never is, or holds, one of these.
# shortcut: a deny list, so a secrets folder it does not name can be copied; switch to an
# allow list (only folders under RECONIX_LOCAL_REPO_ROOTS) if copies must be narrower.
HOME_SECRETS = (
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".config/gh",
    ".config/gcloud",
    ".config/google-chrome",
    ".config/chromium",
    ".mozilla",
    ".kube",
    ".docker",
    ".password-store",
    ".local/share/keyrings",
    ".claude",
)
# shortcut: /var is refused whole, so a home under /var/home (Fedora Silverblue) cannot be
# copied; allow folders under Path.home() first if someone needs that.
SYSTEM_FOLDERS = ("/etc", "/proc", "/sys", "/dev", "/root", "/boot", "/var", "/run")


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


def clone_repo(
    db: Db,
    write_audit: WriteAudit,
    settings: Settings,
    operator: Operator,
    session_id: UUID,
    url: str,
    token: SecretStr | None,
) -> CodeClonedOut:
    """Replaces the session's code with a GitHub repo. A clone of it found under
    RECONIX_LOCAL_REPO_ROOTS is copied as it is (never pulled); otherwise git clones it."""
    if not GITHUB_URL.fullmatch(url):
        raise ApiError(422, "INVALID_REPO_URL", "Use https://github.com/<owner>/<repo>.")
    ensure_own_open_session(db, operator, session_id)
    local = find_local_clone(settings.local_repo_roots, repo_key(url), core_folders(settings))
    if local and not folder_allowed(local, settings):
        local = None  # e.g. Reconix's own repo (its .env) or a dotfiles repo at ~: clone it
    source: Literal["LOCAL_CLONE", "GITHUB"] = "LOCAL_CLONE" if local else "GITHUB"
    try:
        if local:
            files, size = store_folder(db, settings, session_id, local)
        else:
            # shortcut: the clone lands in the system temp folder before the size limit
            # applies; move it if /tmp is too small for the repos people scan.
            with tempfile.TemporaryDirectory(prefix="reconix-clone-") as temp:
                git_clone(url, Path(temp) / "repo", token)
                files, size = store_folder(db, settings, session_id, Path(temp) / "repo")
    except code_files.CodeFileError as error:
        raise ApiError(422, "INVALID_CODE_FOLDER", str(error)) from error
    db.commit()  # the lock taken by ensure_not_scanning
    details = {"url": url, "source": source, "files": files}
    audit(write_audit, "CODE_CLONED", operator, details=details)
    target = code_files.container_path(session_id)
    return CodeClonedOut(files=files, size_bytes=size, target=target, source=source)


def copy_folder(
    db: Db,
    write_audit: WriteAudit,
    settings: Settings,
    operator: Operator,
    session_id: UUID,
    path: str,
) -> CodeUploadOut:
    """Replaces the session's code with a copy of a folder on this computer."""
    ensure_own_open_session(db, operator, session_id)
    if not Path(path).expanduser().is_absolute():
        raise ApiError(422, "FOLDER_NOT_FOUND", "Give the folder's absolute path.")
    try:
        folder = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ApiError(422, "FOLDER_NOT_FOUND", "No folder at this path.") from error
    if not folder.is_dir():
        raise ApiError(422, "FOLDER_NOT_FOUND", "This path is not a folder.")
    try:
        ensure_folder_allowed(folder, settings)
    except ApiError as error:
        audit(write_audit, "CODE_FOLDER_REFUSED", operator, details={"code": error.code})
        raise
    try:
        files, size = store_folder(db, settings, session_id, folder)
    except code_files.CodeFileError as error:
        raise ApiError(422, "INVALID_CODE_FOLDER", str(error)) from error
    db.commit()  # the lock taken by ensure_not_scanning
    audit(write_audit, "CODE_COPIED", operator, details={"path": str(folder), "files": files})
    return CodeUploadOut(files=files, size_bytes=size, target=code_files.container_path(session_id))


def store_folder(db: Db, settings: Settings, session_id: UUID, src: Path) -> tuple[int, int]:
    """Replaces the session's code with the files under src, with every upload limit.
    Returns (files, bytes). The new code is unpacked next to the old one first, so a
    failed unpack leaves the session's code as it was."""
    limit = settings.max_upload_mb * MB
    folder = code_files.session_folder(settings.code_dir, session_id)
    staging = folder.with_name(f".{folder.name}.new")
    with code_files.pack_folder(src, limit, core_folders(settings)) as archive:
        ensure_not_scanning(db, session_id)  # after the slow part, so the lock is short
        code_files.remove(staging)
        try:
            stored = code_files.unpack(archive, staging, limit, excluded_folders(db, session_id))
        except code_files.CodeFileError:
            code_files.remove(staging)
            raise
        code_files.remove(folder)
        staging.rename(folder)
        return stored


def core_folders(settings: Settings) -> list[Path]:
    """Reconix's own data, never copied into a session's code."""
    folders = [settings.code_dir, settings.reports_dir, Path(settings.audit_log_path).parent]
    return [Path(folder) for folder in folders]


def ensure_folder_allowed(folder: Path, settings: Settings) -> None:
    """Refuses a resolved folder inside, or holding, a folder of secrets or system files,
    or Reconix's own data. A folder that holds Reconix's data is its repo, with its .env."""
    denied = [Path.home() / name for name in HOME_SECRETS] + [Path(p) for p in SYSTEM_FOLDERS]
    for secret in (path.resolve() for path in denied):
        if folder.is_relative_to(secret) or secret.is_relative_to(folder):
            raise ApiError(403, "FOLDER_NOT_ALLOWED", "This folder holds secrets or system files.")
    for data in (path.resolve() for path in core_folders(settings)):
        if folder.is_relative_to(data) or data.is_relative_to(folder):
            raise ApiError(403, "FOLDER_NOT_ALLOWED", "This folder holds Reconix's own data.")


def folder_allowed(folder: Path, settings: Settings) -> bool:
    try:
        ensure_folder_allowed(folder, settings)
    except ApiError:
        return False
    return True


def repo_key(remote: str) -> str | None:
    """ "owner/name" in lower case for a GitHub remote in any form, else None."""
    match = GITHUB_REMOTE.fullmatch(remote.strip())
    return f"{match[1]}/{match[2]}".lower() if match else None


def find_local_clone(roots: list[str], key: str | None, private: list[Path]) -> Path | None:
    """The first folder under the roots, at most LOCAL_CLONE_DEPTH levels down, whose
    .git/config has an origin remote for the repo `key`."""
    private = [folder.resolve() for folder in private]
    for root in roots:
        base = Path(root).expanduser().resolve()
        for top, folders, _ in os.walk(base):  # does not follow links into folders
            here = Path(top)
            if (here / ".git").is_dir():
                if repo_key(origin_url(here / ".git" / "config") or "") == key:
                    return here
                folders.clear()  # the rest of a repo holds no other clone to look for
            elif len(here.relative_to(base).parts) >= LOCAL_CLONE_DEPTH:
                folders.clear()
            else:
                folders[:] = sorted(
                    name
                    for name in folders
                    if name not in code_files.SKIP_FOLDERS and here / name not in private
                )
    return None


def origin_url(config: Path) -> str | None:
    """The url of [remote "origin"] in a .git/config, read as text: git is never run."""
    try:
        lines = config.read_text(errors="replace").splitlines()
    except OSError:
        return None
    in_origin = False
    for line in (line.strip() for line in lines):
        if line.startswith("["):
            in_origin = line.replace(" ", "").lower() == '[remote"origin"]'
        elif in_origin and line.split("=", 1)[0].strip().lower() == "url" and "=" in line:
            return line.split("=", 1)[1].strip().strip('"')
    return None


def clone_source(url: str) -> tuple[str, str]:
    """The one protocol git may use, and the address it clones. Tests swap this for a local
    file:// repo, so GITHUB_URL stays strict."""
    return "https", url


def git_clone(url: str, folder: Path, token: SecretStr | None) -> None:
    """A shallow clone of the default branch: no tags, no LFS files, no symlinks, no
    prompts, and no protocol other than the one allowed."""
    git = shutil.which("git")
    if git is None:
        raise ApiError(503, "GIT_NOT_FOUND", "git is not installed on this computer.")
    protocol, address = clone_source(url)
    command = [git, "-c", "protocol.allow=never", "-c", f"protocol.{protocol}.allow=always"]
    # No hook runs on checkout, not even one from this computer's git templates.
    command += ["-c", "core.hooksPath=/dev/null"]
    command += ["-c", "core.symlinks=false", "clone", "--depth", "1", "--single-branch"]
    command += ["--no-tags", "--", address, str(folder)]
    try:
        done = subprocess.run(  # noqa: S603 - a list of arguments, no shell
            command, env=clone_env(token), capture_output=True, timeout=CLONE_SECONDS, check=False
        )
    except subprocess.TimeoutExpired:
        raise ApiError(504, "CLONE_TIMED_OUT", "git took too long to clone the repo.") from None
    if done.returncode != 0:
        # git's own output is not passed on: nothing checks it for secrets.
        message = "git could not clone the repo: it does not exist, it is private and "
        message += "this computer has no access to it, or the network failed."
        raise ApiError(502, "CLONE_FAILED", message)


def clone_env(token: SecretStr | None) -> dict[str, str]:
    """git's environment. A token goes only here, as an HTTP header for github.com, with
    this computer's credential helpers turned off; never on the command line. Reconix's
    own settings (its keys) never reach git, and git never asks for a password."""
    env = {name: value for name, value in os.environ.items() if not name.startswith("RECONIX_")}
    env |= {"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": ""}
    env |= {"GIT_LFS_SKIP_SMUDGE": "1"}
    if not token:
        return env  # this computer's own git credentials apply
    basic = base64.b64encode(f"x-access-token:{token.get_secret_value()}".encode()).decode()
    return env | {
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
        "GIT_CONFIG_KEY_1": "credential.helper",
        "GIT_CONFIG_VALUE_1": "",
    }


def ensure_own_open_session(db: Db, operator: Operator, session_id: UUID) -> None:
    if session_id != operator.session_id:
        raise ApiError(403, "NOT_YOUR_SESSION", "You can only send code to your own session.")
    session = session_repo.get(db, session_id)
    if session is None:
        raise ApiError(404, "SESSION_NOT_FOUND", "No session with this id.")
    if session.session_status != SessionStatus.ACTIVE:
        raise ApiError(409, "SESSION_CLOSED", "This session is closed.")


def ensure_not_scanning(db: Db, session_id: UUID) -> None:
    """The code cannot change while a scan or a fix reads it. Holds the session row (and the
    assessment row) until the caller commits, so no scan starts while the code changes,
    also the session's first one (start_scan locks the session row too)."""
    session_repo.get_for_update(db, session_id)
    assessment = assessment_repo.get_by_session(db, session_id)
    if assessment is None:
        return
    assessment_repo.lock(db, assessment.assessment_id)
    if agent_run_repo.running_code_scan(db, assessment.assessment_id):
        raise ApiError(409, "SCAN_RUNNING", "Wait for the code scan to end, or cancel it.")
    if agent_run_repo.running_code_fix(db, assessment.assessment_id):
        raise ApiError(409, "FIX_RUNNING", "Wait for the code fix to end, or cancel it.")


def excluded_folders(db: Db, session_id: UUID) -> list[str]:
    """The approved scope's excluded paths inside this session's code, relative to it
    (e.g. "node_modules"). Empty before the scope is approved."""
    assessment = assessment_repo.get_by_session(db, session_id)
    manifest = assessment and scope_repo.get_approved(db, assessment.assessment_id)
    if not manifest:
        return []
    excluded = [t.value for t in scope_repo.list_targets(db, manifest.manifest_id) if t.excluded]
    return code_files.excluded_inside(excluded, code_files.container_path(session_id))
