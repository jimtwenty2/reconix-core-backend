"""Knowledge add-ons waiting to be ingested (uploaded, not yet in the knowledge search).

An upload is read, masked and cut into passages at once; the passages wait here until a
re-ingest puts them into Qdrant (services/knowledge_reingest.py). Only the masked passages
and the add-on's details are kept, never the file, encrypted with
RECONIX_PROVIDER_ENCRYPTION_KEY, one file per add-on in RECONIX_KNOWLEDGE_PENDING_DIR (a
folder only this user can open; files 0600). A file that cannot be read (another key, or
damaged) is skipped, never shown half.
"""

import json
import os
from dataclasses import asdict
from pathlib import Path
from uuid import UUID

from cryptography.fernet import InvalidToken

from reconix_api.core.config import Settings
from reconix_api.core.knowledge_add_ons import AddOn
from reconix_api.core.provider_keys import fernet

SUFFIX = ".json.enc"


def _folder(settings: Settings) -> Path:
    folder = Path(settings.knowledge_pending_dir)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(folder, 0o700)  # whatever the umask made it
    return folder


def _path(settings: Settings, knowledge_add_on_id: str, create: bool = False) -> Path:
    # a UUID, so it can never name a path outside the folder
    folder = _folder(settings) if create else Path(settings.knowledge_pending_dir)
    return folder / f"{UUID(knowledge_add_on_id)}{SUFFIX}"


def _files(settings: Settings) -> list[Path]:
    """The waiting files; none while nothing was ever kept (the folder is made on save)."""
    folder = Path(settings.knowledge_pending_dir)
    return sorted(folder.glob(f"*{SUFFIX}")) if folder.is_dir() else []


def save(settings: Settings, add_on: AddOn, passages: list[str]) -> None:
    """Keep one add-on's masked passages until it is ingested."""
    data = json.dumps({"add_on": asdict(add_on), "passages": passages}).encode()
    token = fernet(settings).encrypt(data)
    path = _path(settings, add_on.knowledge_add_on_id, create=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(token)


def load(settings: Settings, knowledge_add_on_id: str) -> tuple[AddOn, list[str]] | None:
    """The add-on and its passages, or None when none waits under this id."""
    path = _path(settings, knowledge_add_on_id)
    if not path.is_file():
        return None
    return _read(settings, path)


def list_all(settings: Settings) -> list[AddOn]:
    """Every add-on waiting, oldest first (an unreadable file is skipped)."""
    found = []
    for path in _files(settings):
        read = _read(settings, path)
        if read is not None:
            found.append(read[0])
    return sorted(found, key=lambda add_on: add_on.created_at)


def remove(settings: Settings, knowledge_add_on_id: str) -> bool:
    """Forget one waiting add-on; False when none waited under this id."""
    path = _path(settings, knowledge_add_on_id)
    if not path.is_file():
        return False
    path.unlink()
    return True


def remove_all(settings: Settings) -> int:
    paths = _files(settings)
    for path in paths:
        path.unlink(missing_ok=True)
    return len(paths)


def _read(settings: Settings, path: Path) -> tuple[AddOn, list[str]] | None:
    try:
        data = json.loads(fernet(settings).decrypt(path.read_bytes()))
        return AddOn(**data["add_on"]), [str(p) for p in data["passages"]]
    except (InvalidToken, OSError, ValueError, KeyError, TypeError):
        return None
