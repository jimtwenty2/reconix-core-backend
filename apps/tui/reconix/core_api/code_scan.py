"""The Core API's code-scan flow for a source-code scope: upload, scan, findings.

The API runs in Docker and cannot see this computer's folders (and its image has no git),
so the local code is read here and uploaded: `POST /code/sync` says which files (by sha256)
it lacks, `PUT /code` takes them as one tar.gz, `POST /code-scans` starts the scan (the API
approves its own code-folder scope), `GET /code-scans/{id}` is polled, and the findings
are read. Network only: nothing here touches the app's store, so a worker can call
`run_scan` and the UI thread applies the answer (store/live.py). Every refusal is the API's
own CoreApiError; nothing is faked.
"""

import hashlib
import io
import os
import tarfile
import time
from typing import Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

from . import connect
from .client import CoreApiError

# The backend's own limits and left-out folders (services/api core/code_files.py); it
# enforces them again, so these only save an upload that would be refused.
MAX_FILES = 20_000
SKIP_FOLDERS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
                          "build", "target", ".idea", ".vscode"})
TOOL_CONFIG_NAMES = frozenset({".gitleaks.toml", ".gitleaksignore", ".semgrepignore"})
# The tools a code scan runs (schemas/code.py CODE_TOOLS).
CODE_TOOLS = ("SEMGREP", "GITLEAKS", "TRIVY", "GRYPE", "OSV_SCANNER", "SYFT", "SONAR_SCAN")
POLL_SECONDS = 2.0
MAX_WAIT_SECONDS = 3600  # a scan that is still RUNNING after this long is reported, not waited on
Progress = Callable[[str], None]


def is_local_path(target: str) -> bool:
    """A source scope's target that is a folder path (else it is a repo URL)."""
    target = target.strip()
    return target.startswith(("/", "~", "./", "../")) or (len(target) > 2 and target[1] == ":")


def local_folder(target: str) -> str:
    """The resolved folder of a local-path target. Raises CoreApiError when it is no folder."""
    folder = os.path.realpath(os.path.expanduser(target.strip()))
    if not os.path.isdir(folder):
        raise CoreApiError("FOLDER_NOT_FOUND", f"{target} is not a folder on this computer")
    return folder


def collect(folder: str, excluded: Iterable[str] = ()) -> Dict[str, str]:
    """The folder's regular files: relative path (forward slashes) -> absolute path. Links,
    other file types, the backend's left-out folders and the scope's excluded paths are
    skipped. Raises CoreApiError past MAX_FILES."""
    skip = {e.strip().strip("/") for e in excluded if e.strip().strip("/")}
    found: Dict[str, str] = {}
    for root, dirs, names in os.walk(folder, followlinks=False):
        rel_root = os.path.relpath(root, folder).replace(os.sep, "/")
        rel_root = "" if rel_root == "." else rel_root
        dirs[:] = sorted(
            d for d in dirs
            if d not in SKIP_FOLDERS and d not in skip and f"{rel_root}/{d}".lstrip("/") not in skip
        )
        for name in sorted(names):
            full = os.path.join(root, name)
            if name in TOOL_CONFIG_NAMES or os.path.islink(full) or not os.path.isfile(full):
                continue
            found[f"{rel_root}/{name}".lstrip("/")] = full
            if len(found) > MAX_FILES:
                raise CoreApiError("TOO_MANY_FILES", f"more than {MAX_FILES} files to scan")
    return found


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _archive(files: Dict[str, str], names: List[str]) -> bytes:
    """A tar.gz of `names` at their relative paths."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name in names:
            tar.add(files[name], arcname=name, recursive=False)
    return buffer.getvalue()


def upload(session_id: str, files: Dict[str, str]) -> Tuple[int, str]:
    """Make the session's code these files. Returns (files uploaded, the API's target)."""
    listing = []
    for rel, full in files.items():
        try:
            listing.append({"path": rel, "size_bytes": os.path.getsize(full),
                            "sha256": _sha256(full)})
        except OSError as exc:
            raise CoreApiError("READ_FAILED", f"can't read {rel}: {exc.strerror}") from None
    synced = connect.request("POST", f"/sessions/{session_id}/code/sync", {"files": listing})
    missing = [name for name in synced.get("missing", []) if name in files]
    target = str(synced.get("target", ""))
    if missing:
        sent = connect.request("PUT", f"/sessions/{session_id}/code",
                               gzip_body=_archive(files, missing))
        target = str(sent.get("target", target))
    return len(missing), target


def start(session_id: str, tools: Optional[List[str]] = None) -> dict:
    """Start a code scan (CodeScanOut). `tools` are some of CODE_TOOLS (None: all)."""
    body: dict = {"analyze": True}
    chosen = [t for t in (tools or []) if t in CODE_TOOLS]
    if chosen:
        body["tools"] = chosen
    return connect.request("POST", f"/sessions/{session_id}/code-scans", body)


def wait(scan: dict, progress: Optional[Progress] = None) -> dict:
    """Poll the scan until it is no longer RUNNING. Raises CoreApiError when it FAILED or
    was cancelled (the API's error code), or never finishes."""
    run_id = quote(str(scan["agent_run_id"]))
    waited, last = 0.0, ""
    while scan.get("agent_runs_status") == "RUNNING":
        line = f"{str(scan.get('stage', '')).title()} · {scan.get('progress', 0)}%"
        if progress and line != last:
            progress(line)
            last = line
        if waited >= MAX_WAIT_SECONDS:
            raise CoreApiError("SCAN_TIMEOUT", "the code scan is still running; check it later")
        time.sleep(POLL_SECONDS)
        waited += max(POLL_SECONDS, 0.001)
        scan = connect.request("GET", f"/code-scans/{run_id}")
    status = scan.get("agent_runs_status")
    if status != "COMPLETED":
        code = str(scan.get("error") or f"SCAN_{status}")
        raise CoreApiError(code, f"the code scan {str(status).lower()}: {code}")
    return scan


def findings(agent_run_id: str) -> List[dict]:
    """The scan's findings (CodeFindingOut rows), in the API's order."""
    return connect.request("GET", f"/code-scans/{quote(agent_run_id)}/findings") or []


def clone(session_id: str, url: str) -> int:
    """Put a GitHub repo on the session (`POST /code/clone`). The API's own refusal (for
    example 503 GIT_NOT_FOUND in Docker) is raised as it came. Returns the file count."""
    return int(connect.request("POST", f"/sessions/{session_id}/code/clone", {"url": url})["files"])


def run_scan(
    target: str, excluded: Iterable[str], tools: Optional[List[str]],
    session: Callable[[], str], progress: Optional[Progress] = None,
) -> Dict[str, object]:
    """Feed the target's code to the API, scan it, read the findings. Blocks: call it in a
    worker. A local folder is uploaded; a repo URL is cloned by the API. Returns
    {"scan": CodeScanOut, "findings": [CodeFindingOut]}."""
    say = progress or (lambda _text: None)
    if is_local_path(target):
        files = collect(local_folder(target), excluded)
        if not files:
            raise CoreApiError("NO_FILES", "the folder has no files to scan")
        session_id = session()
        say(f"Uploading {len(files)} files…")
        sent, _target = upload(session_id, files)
        say(f"Uploaded {sent} new or changed files; starting the scan…")
    else:
        session_id = session()
        say("Asking the Core API to clone the repository…")
        say(f"Cloned {clone(session_id, target)} files; starting the scan…")
    scan = wait(start(session_id, tools), say)
    return {"scan": scan, "findings": findings(str(scan["agent_run_id"]))}
