"""Source code sent from the VS Code extension, one folder per session.

The API writes the files under `RECONIX_CODE_DIR/<session_id>/` on this computer. The Kali
container sees the same folder read-only at `/workspace/code/<session_id>`, and semgrep
and gitleaks get that path as their target.

Paths from the extension are relative, use forward slashes, and have no `..` or empty
parts. An upload is a tar.gz of only the files the server is missing. It is unpacked into a
temporary folder first and refused as a whole if any entry is a link, a device, a bad path,
or past the size limits, so a bad upload changes nothing.
"""

import gzip
import hashlib
import os
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import BinaryIO
from uuid import UUID

CODE_ROOT = "/workspace/code"  # where the Kali container mounts RECONIX_CODE_DIR
MAX_FILES = 20_000  # entries in one upload (folders too), and files in one sync
MAX_PATH = 1024
MAX_PART = 255  # the longest file or folder name most file systems allow
# Room for the tar headers next to the file data: a 512-byte header and up to 511 bytes
# of padding per entry, plus the end of the archive.
HEADER_ROOM = MAX_FILES * 1024 + 64 * 1024
# Files that tell gitleaks or semgrep what to skip. Code sent to be scanned must never
# switch the scanners off, so these are never stored.
TOOL_CONFIG_NAMES = frozenset({".gitleaks.toml", ".gitleaksignore", ".semgrepignore"})
CHUNK = 1024 * 1024
# Folders a cloned or copied tree never brings in: git's own data, installed packages,
# build output and editor settings.
SKIP_FOLDERS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        "target",
        ".idea",
        ".vscode",
    }
)
# A code scan copies the files it reads into <session>/_reconix_scan_<run8>/, every file
# in reconix-<session hex>/ and the changed ones in changed/, so each run has its own
# target folder. Tools report paths inside that copy.
SCAN_FOLDER_PREFIX = "_reconix_scan_"
SCAN_COPY = re.compile(
    r"(/workspace/code/[A-Za-z0-9-]+)/_reconix_scan_[0-9a-f]{8}/(?:reconix-[0-9a-f]{32}|changed)"
    r"(?![A-Za-z0-9._-])"
)
CODE_PATH = re.compile(r"/workspace/code/[A-Za-z0-9._-]+(/[A-Za-z0-9._ -]+)*")
BAD_CHARACTERS = re.compile(r"[\x00-\x1f\x7f\\:]")


class CodeFileError(ValueError):
    """An upload or file list that cannot be used; the message says why."""


def container_path(session_id: UUID) -> str:
    """The session's code folder as the Kali container sees it."""
    return f"{CODE_ROOT}/{session_id}"


def session_folder(code_dir: str, session_id: UUID) -> Path:
    """The session's code folder on this computer."""
    return Path(code_dir).resolve() / str(session_id)


def check_code_path(value: str) -> None:
    """A scope target of type "path": a folder under /workspace/code, written plainly."""
    if not CODE_PATH.fullmatch(value) or posixpath.normpath(value) != value:
        raise ValueError(f"a path target must be a plain folder under {CODE_ROOT}/")
    if ".." in value.split("/"):
        raise ValueError("a path target cannot hold '..'")


def check_rel_path(path: str) -> str:
    """Returns the path if it is a safe relative path, else raises CodeFileError."""
    if not path or len(path) > MAX_PATH or BAD_CHARACTERS.search(path):
        raise CodeFileError(f"not a valid file path: {_shown(path)}")
    parts = path.split("/")
    if path.startswith("/") or any(part in ("", ".", "..") for part in parts):
        raise CodeFileError(f"not a valid file path: {_shown(path)}")
    if any(len(part.encode()) > MAX_PART for part in parts):
        raise CodeFileError(f"a file or folder name is too long: {_shown(path)}")
    return path


def excluded_inside(excluded_targets: list[str], target: str) -> list[str]:
    """The scope's excluded paths inside the code folder `target`, made relative to it:
    "/workspace/code/<s>/node_modules" -> "node_modules". Anything else is left out."""
    prefix = target + "/"
    inside = [entry.removeprefix(prefix) for entry in excluded_targets if entry.startswith(prefix)]
    return sorted({path for path in inside if _is_safe(path)})


def is_excluded(path: str, skip: list[str]) -> bool:
    """True when the relative path is one of the skipped paths or inside one."""
    return any(path == entry or path.startswith(entry + "/") for entry in skip)


def remove_excluded(folder: Path, skip: list[str]) -> int:
    """Deletes the stored files under the skipped paths; returns how many."""
    removed = 0
    for path, file in stored_files(folder).items():
        if is_excluded(path, skip):
            file.unlink()
            removed += 1
    _remove_empty_folders(folder)
    return removed


def scan_files(folder: Path, paths: list[str]) -> dict[str, Path]:
    """The stored files a code scan reads: all of them, or those at or under `paths`.
    A scan's own copy folder is never part of it.

    shortcut: an uploaded top folder named _reconix_scan_* is skipped (and deleted at
    startup); refuse that name at upload if anyone ever needs it."""
    return {
        path: file
        for path, file in stored_files(folder).items()
        if not path.startswith(SCAN_FOLDER_PREFIX) and (not paths or is_excluded(path, paths))
    }


def all_copy_name(session_id: UUID) -> str:
    """The name of a scan's copy folder of every file. sonar_scan names its SonarQube
    project after the folder, so each session keeps a project of its own."""
    return f"reconix-{session_id.hex}"


def link_files(target: Path, files: dict[str, Path]) -> None:
    """Hard links to the files under `target` (a copy where a link fails), plus an empty
    .semgrepignore: without one, semgrep skips its default folders such as tests/."""
    target.mkdir(parents=True, exist_ok=True)
    for path, file in files.items():
        copy = target / path
        copy.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(file, copy)
        except OSError:
            shutil.copy2(file, copy)
    (target / ".semgrepignore").write_bytes(b"")


def canonical_paths(text: str) -> str:
    """Paths inside a scan's copy folder -> the same paths in the session's code folder:
    ".../<session>/_reconix_scan_1a2b3c4d/changed/src/app.js" -> ".../<session>/src/app.js"."""
    return SCAN_COPY.sub(r"\1", text)


def is_tool_config(path: str) -> bool:
    """True for a scanner's own settings file, which is never stored."""
    return path.rsplit("/", 1)[-1] in TOOL_CONFIG_NAMES


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def stored_files(folder: Path) -> dict[str, Path]:
    """Relative path -> file, for every regular file in the folder."""
    if not folder.is_dir():
        return {}
    return {
        file.relative_to(folder).as_posix(): file
        for file in folder.rglob("*")
        if file.is_file() and not file.is_symlink()
    }


def sync(folder: Path, wanted: dict[str, str], skip: list[str] | None = None) -> list[str]:
    """wanted is relative path -> sha256 of every file the workspace has now.

    Returns the paths whose content the server does not have yet, sorted, then deletes
    the stored files the workspace no longer has. Scanner settings files and files under
    a skipped path (the scope's excluded folders) are never asked for, and are deleted
    if stored."""
    if len(wanted) > MAX_FILES:
        raise CodeFileError(f"at most {MAX_FILES} files")
    for path in wanted:
        check_rel_path(path)
    wanted = {
        path: sha256
        for path, sha256 in wanted.items()
        if not is_tool_config(path) and not is_excluded(path, skip or [])
    }
    stored = stored_files(folder)
    try:
        missing = sorted(
            path
            for path, sha256 in wanted.items()
            if path not in stored or file_sha256(stored[path]) != sha256
        )
        for path, file in stored.items():
            if path not in wanted:
                file.unlink()
        _remove_empty_folders(folder)
    except OSError as error:
        raise CodeFileError("the stored code could not be read") from error
    return missing


def unpack(
    archive: BinaryIO, folder: Path, max_bytes: int, skip: list[str] | None = None
) -> tuple[int, int]:
    """Unpacks a tar.gz into the folder, replacing files with the same path.

    Returns (files, bytes) written. Raises CodeFileError and changes nothing if any entry
    is not a plain file or folder, has a bad or repeated path, clashes with a stored
    file or folder, or if the upload or the session's stored code would be larger than
    max_bytes. Every byte is counted as it is unpacked, the tar headers too, so a small
    archive cannot unpack to a huge one. Scanner settings files and files under a skipped
    path (the scope's excluded folders) are not stored."""
    folder.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=folder.parent, prefix=".upload-") as temp:
        files, total = _unpack_to(archive, Path(temp), max_bytes, skip or [])
        _check_fits(folder, files, total, max_bytes)
        try:
            for path in files:
                target = folder / path
                target.parent.mkdir(parents=True, exist_ok=True)
                (Path(temp) / path).replace(target)
        except OSError as error:
            raise CodeFileError("the upload could not be stored") from error
    return len(files), total


def pack_folder(src: Path, max_bytes: int, private: list[Path]) -> BinaryIO:
    """A tar.gz of the regular files under src, in a temporary file, ready for `unpack`.

    Never follows a link. Links and anything that is not a regular file are left out, and
    so are SKIP_FOLDERS and the `private` folders (Reconix's own data) anywhere in the tree.
    Refuses a src inside a private folder, and stops as soon as the tree has more than
    MAX_FILES files or max_bytes, so a huge folder never fills the disk."""
    src = src.resolve()
    private = [folder.resolve() for folder in private]
    if any(src.is_relative_to(folder) for folder in private):
        raise CodeFileError("this folder holds Reconix's own data")
    spool = tempfile.SpooledTemporaryFile(max_size=8 * CHUNK)
    try:
        with tarfile.open(fileobj=spool, mode="w:gz", compresslevel=1) as tar:
            _add_tree(tar, src, max_bytes, private)
    except CodeFileError:
        spool.close()
        raise
    except OSError as error:
        spool.close()
        raise CodeFileError("the folder could not be read") from error
    spool.seek(0)
    return spool


def remove(folder: Path) -> None:
    """Deletes the session's code, e.g. when the session is closed."""
    shutil.rmtree(folder, ignore_errors=True)


class _LimitedReader:
    """Reads from a stream and refuses to give more than `limit` bytes in all."""

    def __init__(self, stream: BinaryIO, limit: int) -> None:
        self.stream = stream
        self.left = limit

    def read(self, size: int = -1) -> bytes:
        want = self.left + 1 if size < 0 else min(size, self.left + 1)
        data = self.stream.read(want)
        self.left -= len(data)
        if self.left < 0:
            raise CodeFileError("the upload is larger than the size limit")
        return data


def _add_tree(tar: tarfile.TarFile, src: Path, max_bytes: int, private: list[Path]) -> None:
    files = 0
    total = 0
    # fwalk reads each folder through its own descriptor and never follows a link, so a
    # folder swapped for a link during the walk is not read through.
    for top, folders, names, top_fd in os.fwalk(src):
        here = Path(top)
        folders[:] = sorted(
            name for name in folders if name not in SKIP_FOLDERS and here / name not in private
        )
        for name in sorted(names):
            path = here / name
            info = os.lstat(name, dir_fd=top_fd)
            if not stat.S_ISREG(info.st_mode):
                continue
            files += 1
            total += info.st_size
            if files > MAX_FILES:
                raise CodeFileError(f"the folder has more than {MAX_FILES} files")
            if total > max_bytes:
                raise CodeFileError("the folder is larger than the size limit")
            # A plain entry, never a hard link entry, which unpack would refuse.
            entry = tarfile.TarInfo(path.relative_to(src).as_posix())
            entry.size = info.st_size
            entry.mtime = int(info.st_mtime)
            # O_NOFOLLOW: a file swapped for a link after the lstat is not read.
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=top_fd)
            with os.fdopen(descriptor, "rb") as file:
                tar.addfile(entry, file)


def _unpack_to(
    archive: BinaryIO, temp: Path, max_bytes: int, skip: list[str]
) -> tuple[list[str], int]:
    files: list[str] = []
    seen: set[str] = set()
    entries = 0
    total = 0
    reader = _LimitedReader(gzip.GzipFile(fileobj=archive, mode="rb"), max_bytes + HEADER_ROOM)
    try:
        # "r|" reads the archive as a stream, front to back, and never seeks.
        with tarfile.open(fileobj=reader, mode="r|") as tar:
            for member in tar:
                entries += 1
                if entries > MAX_FILES:
                    raise CodeFileError(f"at most {MAX_FILES} files and folders")
                name = member.name.removeprefix("./").rstrip("/")
                if member.isdir() and name in ("", "."):
                    continue  # the archive's own top folder
                path = check_rel_path(name)
                if path in seen:
                    raise CodeFileError(f"the upload holds {_shown(path)} twice")
                seen.add(path)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise CodeFileError(f"only plain files are allowed: {_shown(path)}")
                if is_tool_config(path) or is_excluded(path, skip):
                    continue
                source = tar.extractfile(member)
                if source is None:
                    raise CodeFileError(f"cannot read {_shown(path)}")
                target = temp / path
                target.parent.mkdir(parents=True, exist_ok=True)
                total += _copy(source, target, max_bytes - total)
                files.append(path)
    except (tarfile.TarError, EOFError, OSError, zlib.error) as error:
        raise CodeFileError("the upload is not a readable tar.gz") from error
    return files, total


def _check_fits(folder: Path, files: list[str], total: int, max_bytes: int) -> None:
    """No uploaded file may land on a stored folder or under a stored file, and the
    session's code stays within max_bytes after the upload."""
    for path in files:
        target = folder / path
        if target.is_dir() or any(parent.is_file() for parent in _parents(folder, path)):
            raise CodeFileError(f"{_shown(path)} clashes with a stored file or folder")
    replaced = set(files)
    kept = sum(
        file.stat().st_size for path, file in stored_files(folder).items() if path not in replaced
    )
    if kept + total > max_bytes:
        raise CodeFileError("the session's code would be larger than the size limit")


def _parents(folder: Path, path: str) -> list[Path]:
    """The folders between `folder` and the file, e.g. a, a/b for a/b/c.py."""
    parts = path.split("/")[:-1]
    return [folder.joinpath(*parts[: index + 1]) for index in range(len(parts))]


def _copy(source: BinaryIO, target: Path, budget: int) -> int:
    written = 0
    with target.open("wb") as out:
        while chunk := source.read(CHUNK):
            written += len(chunk)
            if written > budget:
                raise CodeFileError("the upload is larger than the size limit")
            out.write(chunk)
    return written


def _remove_empty_folders(folder: Path) -> None:
    if not folder.is_dir():
        return
    for path in sorted(folder.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_dir() and not path.is_symlink() and not any(path.iterdir()):
            path.rmdir()


def _shown(path: str) -> str:
    """The path for an error message, cut short: a bad path can be megabytes long."""
    return repr(path if len(path) <= 120 else path[:120] + "...")


def _is_safe(path: str) -> bool:
    try:
        check_rel_path(path)
    except CodeFileError:
        return False
    return True
