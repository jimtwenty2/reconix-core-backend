"""Source code folders: safe paths, sync and the tar.gz upload."""

import hashlib
import io
import tarfile
import tempfile
from pathlib import Path
from uuid import UUID

import pytest

from reconix_api.core.code_files import (
    CodeFileError,
    check_code_path,
    check_rel_path,
    container_path,
    stored_files,
    sync,
    unpack,
)

SESSION = UUID("11111111-2222-3333-4444-555555555555")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tar_gz(files: dict[str, bytes], extra: list[tarfile.TarInfo] | None = None) -> io.BytesIO:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info in extra or []:
            tar.addfile(info)
    buffer.seek(0)
    return buffer


def test_container_path_is_under_the_mount():
    assert container_path(SESSION) == f"/workspace/code/{SESSION}"


@pytest.mark.parametrize("value", [f"/workspace/code/{SESSION}", "/workspace/code/abc/src"])
def test_plain_code_paths_are_allowed(value):
    check_code_path(value)


@pytest.mark.parametrize(
    "value",
    [
        "/workspace/code",
        "/workspace/code/",
        "/workspace/code/abc/",
        "/workspace/code/../etc",
        "/workspace/code/abc/../../etc",
        "/workspace/code//abc",
        "/etc/passwd",
        "workspace/code/abc",
        "/workspace/code/abc\n",
    ],
)
def test_other_paths_are_refused(value):
    with pytest.raises(ValueError):
        check_code_path(value)


@pytest.mark.parametrize("path", ["src/app.ts", "a", ".env", "dir/.hidden/x.py"])
def test_relative_paths_are_allowed(path):
    assert check_rel_path(path) == path


@pytest.mark.parametrize(
    "path", ["", "/abs", "../up", "a/../b", "a//b", "./a", "a/", "a\\b", "c:x", "a\x00b"]
)
def test_unsafe_relative_paths_are_refused(path):
    with pytest.raises(CodeFileError):
        check_rel_path(path)


def test_sync_asks_for_new_and_changed_files_and_drops_old_ones(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/same.ts").write_bytes(b"same")
    (tmp_path / "src/changed.ts").write_bytes(b"old")
    (tmp_path / "old/gone.ts").parent.mkdir()
    (tmp_path / "old/gone.ts").write_bytes(b"gone")

    missing = sync(
        tmp_path,
        {"src/same.ts": sha(b"same"), "src/changed.ts": sha(b"new"), "src/new.ts": sha(b"x")},
    )

    assert missing == ["src/changed.ts", "src/new.ts"]
    assert set(stored_files(tmp_path)) == {"src/same.ts", "src/changed.ts"}
    assert not (tmp_path / "old").exists()


def test_sync_of_a_new_session_needs_everything(tmp_path):
    assert sync(tmp_path / "none", {"b.py": sha(b"b"), "a.py": sha(b"a")}) == ["a.py", "b.py"]


def test_sync_refuses_a_bad_path_before_changing_anything(tmp_path):
    (tmp_path / "keep.py").write_bytes(b"x")
    with pytest.raises(CodeFileError):
        sync(tmp_path, {"../escape.py": sha(b"x")})
    assert (tmp_path / "keep.py").exists()


def test_unpack_writes_and_replaces_files(tmp_path):
    folder = tmp_path / "code"
    folder.mkdir()
    (folder / "app.js").write_bytes(b"old")

    files, size = unpack(tar_gz({"app.js": b"new", "lib/db.js": b"db"}), folder, 1000)

    assert (files, size) == (2, 5)
    assert (folder / "app.js").read_bytes() == b"new"
    assert (folder / "lib/db.js").read_bytes() == b"db"


def test_unpack_skips_the_archives_top_folder(tmp_path):
    top = tarfile.TarInfo(".")
    top.type = tarfile.DIRTYPE
    assert unpack(tar_gz({"./a.py": b"a"}, [top]), tmp_path / "code", 100) == (1, 1)


def link(kind: bytes, name: str = "evil") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = "/etc/passwd"
    return info


@pytest.mark.parametrize(
    "archive",
    [
        lambda: tar_gz({"../escape.py": b"x"}),
        lambda: tar_gz({"/abs.py": b"x"}),
        lambda: tar_gz({"ok.py": b"x"}, [link(tarfile.SYMTYPE)]),
        lambda: tar_gz({"ok.py": b"x"}, [link(tarfile.LNKTYPE)]),
        lambda: tar_gz({"ok.py": b"x"}, [link(tarfile.CHRTYPE)]),
        lambda: tar_gz({"big.bin": b"x" * 101}),
        lambda: tar_gz({"a.bin": b"x" * 60, "b.bin": b"x" * 60}),
        lambda: io.BytesIO(b"not a tar file"),
    ],
)
def test_bad_uploads_change_nothing(tmp_path, archive):
    folder = tmp_path / "code"
    folder.mkdir()
    (folder / "ok.py").write_bytes(b"before")

    with pytest.raises(CodeFileError):
        unpack(archive(), folder, 100)

    assert (folder / "ok.py").read_bytes() == b"before"
    assert stored_files(folder) == {"ok.py": folder / "ok.py"}
    assert [p.name for p in tmp_path.iterdir()] == ["code"]  # no temp folder left


def test_stored_files_ignores_links(tmp_path):
    (tmp_path / "real.py").write_bytes(b"x")
    Path(tmp_path / "link.py").symlink_to(tmp_path / "real.py")
    assert set(stored_files(tmp_path)) == {"real.py"}


def test_a_huge_tar_header_is_counted_and_refused(tmp_path):
    """A GNU long-name header is read into memory whole by tarfile, so the limit must
    count the unpacked stream itself, not only the file data."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        # More than the room left for headers (HEADER_ROOM, about 20 MB); a few KB packed.
        info = tarfile.TarInfo("a" * 25_000_000)
        tar.addfile(info, io.BytesIO(b""))
    buffer.seek(0)
    assert len(buffer.getvalue()) < 100_000

    with pytest.raises(CodeFileError, match="size limit"):
        unpack(buffer, tmp_path / "code", 100)


def test_too_many_folders_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("reconix_api.core.code_files.MAX_FILES", 3)
    folders = []
    for index in range(5):
        info = tarfile.TarInfo(f"d{index}")
        info.type = tarfile.DIRTYPE
        folders.append(info)
    with pytest.raises(CodeFileError, match="at most 3"):
        unpack(tar_gz({}, folders), tmp_path / "code", 1000)


def test_a_path_twice_in_one_upload_is_refused(tmp_path):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        for data in (b"one", b"two"):
            info = tarfile.TarInfo("a.py")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    archive.seek(0)
    with pytest.raises(CodeFileError, match="twice"):
        unpack(archive, tmp_path / "code", 1000)


@pytest.mark.parametrize(
    ("stored", "uploaded"),
    [("lib/db.js", "lib"), ("lib", "lib/db.js")],  # a file on a folder, a folder under a file
)
def test_a_clash_with_stored_code_changes_nothing(tmp_path, stored, uploaded):
    folder = tmp_path / "code"
    (folder / stored).parent.mkdir(parents=True, exist_ok=True)
    (folder / stored).write_bytes(b"stored")
    (folder / "keep.py").write_bytes(b"keep")

    with pytest.raises(CodeFileError, match="clashes"):
        unpack(tar_gz({"new.py": b"new", uploaded: b"x"}), folder, 1000)

    assert not (folder / "new.py").exists()
    assert (folder / stored).read_bytes() == b"stored"


def test_the_whole_session_stays_within_the_limit(tmp_path):
    folder = tmp_path / "code"
    unpack(tar_gz({"a.bin": b"x" * 60}), folder, 100)

    unpack(tar_gz({"a.bin": b"y" * 90}), folder, 100)  # replacing a file frees its size
    with pytest.raises(CodeFileError, match="session's code"):
        unpack(tar_gz({"b.bin": b"z" * 20}), folder, 100)

    assert set(stored_files(folder)) == {"a.bin"}


@pytest.mark.parametrize("name", [".gitleaks.toml", "src/.gitleaksignore", ".semgrepignore"])
def test_scanner_settings_files_are_never_stored(tmp_path, name):
    folder = tmp_path / "code"
    assert unpack(tar_gz({name: b"[allowlist]", "a.py": b"a"}), folder, 1000) == (1, 1)
    assert set(stored_files(folder)) == {"a.py"}
    assert sync(folder, {name: sha(b"[allowlist]"), "a.py": sha(b"a")}) == []


def test_sync_refuses_a_too_long_name_before_deleting_anything(tmp_path):
    (tmp_path / "keep.py").write_bytes(b"x")
    with pytest.raises(CodeFileError, match="too long"):
        sync(tmp_path, {"a" * 256: sha(b"x")})
    assert (tmp_path / "keep.py").exists()


def test_unpack_reads_a_file_opened_for_writing_too(tmp_path):
    """The route spools the body into a w+b temporary file; gzip must still read it."""
    with tempfile.SpooledTemporaryFile() as spooled:
        spooled.write(tar_gz({"a.py": b"a"}).getvalue())
        spooled.seek(0)
        assert unpack(spooled, tmp_path / "code", 100) == (1, 1)
