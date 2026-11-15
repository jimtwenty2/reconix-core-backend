"""FEATURE D2: /add-on also pushes the file into the Core API's knowledge search.

The local store is what it was (apps/CLAUDE.md "Still local"): the file is read, redacted and
kept here, and now sent to `POST /knowledge-add-ons` besides, so the agent that asks the Core
API finds it in its own knowledge search. The upload runs in the /add-on worker and is best
effort: an API that isn't there leaves a local add-on and says so. The id it answers with is
kept (`store/knowledge/remote.py`), so removing the file here removes it there too.
"""

import pytest

from reconix import store
from reconix.core_api import client, connect, knowledge
from reconix.store.knowledge import paths, remote

from .fakes.fake_api import form_of
from .support import SIZE, settle, wait_until

RUNBOOK = b"# Runbook\nSQL injection reference material for the staging engagement.\n"
ID = "00000000-0000-4000-8000-000000000001"


def _write(tmp_path, name="runbook.md"):
    path = tmp_path / name
    path.write_bytes(RUNBOOK)
    return path


@pytest.fixture
def sent(monkeypatch):
    """`client._send` kept: every request recorded, the API's own answers given back."""

    def _send(request, timeout=None):
        request.path = request.full_url.split("/api/v1", 1)[1]
        _send.seen.append(request)
        if request.path == "/sessions":
            return {"token": "fake-session-token-0001", "session_id": "s-1"}  # noqa: S105
        if isinstance(_send.answer, Exception):
            raise _send.answer  # an error is what the transport raises
        return _send.answer

    _send.seen = []
    _send.answer = {
        "knowledge_add_on_id": ID,
        "name": "runbook.md",
        "kind": "MD",
        "size_bytes": len(RUNBOOK),
        "chunk_count": 3,
        "interface": "cli",
        "created_at": "2026-11-13T00:00:00+00:00",
        "cut": None,
    }
    monkeypatch.setattr(client, "_send", _send)
    connect.reset()
    yield _send
    connect.reset()


# --- the one call the upload makes -----------------------------------------------------------
def test_the_upload_is_one_multipart_form(sent):
    add_on_id = knowledge.upload_add_on(RUNBOOK, "runbook.md")

    assert add_on_id == ID
    [sessions, upload] = sent.seen  # the session opens first, once
    assert upload.get_method() == "POST"
    assert upload.full_url.endswith("/api/v1/knowledge-add-ons")
    assert upload.headers["Authorization"] == "Bearer fake-session-token-0001"  # noqa: S105
    assert upload.headers["Content-type"].startswith("multipart/form-data; boundary=")
    fields, file_name, file_data = form_of(upload.data)
    assert fields == {"interface": "cli", "name": "runbook.md"}
    assert file_name == "runbook.md" and file_data == RUNBOOK  # the bytes, unchanged


def test_a_name_with_a_quote_arrives_as_one_name(sent):
    knowledge.upload_add_on(RUNBOOK, 'run"book.md')

    _fields, file_name, _data = form_of(sent.seen[-1].data)
    assert file_name == 'run"book.md'


def test_the_remove_is_a_delete_on_that_id(sent):
    knowledge.delete_add_on(ID)

    [request] = [r for r in sent.seen if r.get_method() == "DELETE"]
    assert request.full_url.endswith(f"/api/v1/knowledge-add-ons/{ID}")


def test_a_refused_upload_raises_the_api_s_own_error(sent):
    sent.answer = client.CoreApiError("QDRANT_UNAVAILABLE", "Qdrant is not running", 503)

    with pytest.raises(client.CoreApiError) as exc:
        knowledge.upload_add_on(RUNBOOK, "runbook.md")
    assert exc.value.code == "QDRANT_UNAVAILABLE"


def test_raw_bytes_need_a_content_type(sent):
    with pytest.raises(client.CoreApiError) as exc:
        client.call("POST", "/knowledge-add-ons", raw_body=RUNBOOK)
    assert exc.value.code == "NO_CONTENT_TYPE"
    assert sent.seen == []                                # nothing went out


# --- the mapping beside the local source ids -------------------------------------------------
def test_the_mapping_survives_a_reload(tmp_path):
    remote.set_remote("a" * 32, ID)
    remote.set_remote("b" * 32, "00000000-0000-4000-8000-000000000002")

    assert remote.all_remotes() == {"a" * 32: ID, "b" * 32: "00000000-0000-4000-8000-000000000002"}
    assert remote.pop_remote("a" * 32) == ID
    assert remote.all_remotes() == {"b" * 32: "00000000-0000-4000-8000-000000000002"}
    assert remote.pop_remote("a" * 32) is None  # forgotten once, forgotten twice too


def test_no_mapping_yet_reads_as_empty(tmp_path):
    assert not (paths.knowledge_dir() / "remote.json").exists()
    assert remote.all_remotes() == {}
    assert remote.pop_remote("a" * 32) is None
    assert remote.clear_remotes() == []


def test_a_corrupt_mapping_is_no_mapping(tmp_path):
    paths.ensure_dir()
    (paths.knowledge_dir() / "remote.json").write_text("{ not json", encoding="utf-8")

    assert remote.all_remotes() == {}


# --- /add-on through the UI: saved here, uploaded there --------------------------------------
@pytest.fixture
def notes(app, monkeypatch):
    """What the operator is told, in order."""
    seen = []
    monkeypatch.setattr(app, "notify", lambda message, **kw: seen.append((message, kw)))
    return seen


async def test_adding_uploads_the_file_and_records_its_id(app, fake_api, notes, tmp_path):
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line(f"/add-on {_write(tmp_path)}")
        await wait_until(pilot, lambda: notes, what="the notice")
        await app.workers.wait_for_complete()

    [source] = store.list_sources()
    assert store.all_remotes() == {source.id: next(iter(fake_api.add_ons))}
    _fields, file_name, file_data = form_of(fake_api.add_on_bodies[0])
    assert file_name == "runbook.md" and file_data == RUNBOOK
    assert notes[0][0] == ("Added runbook.md — 1 passage. The Core API's agent can search it too.")


async def test_an_unreachable_api_keeps_the_add_on_local(app, fake_api, notes, tmp_path):
    fake_api.down = True
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line(f"/add-on {_write(tmp_path)}")
        await wait_until(pilot, lambda: notes, what="the notice")
        await app.workers.wait_for_complete()

    assert [s.name for s in store.list_sources()] == ["runbook.md"]
    assert store.all_remotes() == {}
    assert fake_api.add_on_bodies == []
    assert notes[0][0].startswith("Added runbook.md — 1 passage. Kept on this computer only (")
    assert "the Core API is not running" in notes[0][0]
    assert "so the Core API's agent can't search it yet." in notes[0][0]


async def test_a_refused_upload_is_said_as_the_api_said_it(app, fake_api, notes, tmp_path):
    fake_api.fail_on["POST /knowledge-add-ons"] = (
        503,
        "QDRANT_UNAVAILABLE",
        "Qdrant is not running",
    )
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line(f"/add-on {_write(tmp_path)}")
        await wait_until(pilot, lambda: notes, what="the notice")
        await app.workers.wait_for_complete()

    assert len(store.list_sources()) == 1
    assert store.all_remotes() == {}
    assert "Qdrant is not running" in notes[0][0]


async def test_removing_the_file_removes_it_in_the_api_too(app, fake_api, tmp_path):
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line(f"/add-on {_write(tmp_path)}")
        await wait_until(pilot, lambda: store.all_remotes(), what="the upload recorded")
        source = store.list_sources()[0]
        app._do_remove_knowledge(source.id)
        await wait_until(pilot, lambda: not fake_api.add_ons, what="the API's remove")
        await app.workers.wait_for_complete()

    assert store.list_sources() == []
    assert store.all_remotes() == {}
    assert fake_api.add_ons == {}
    assert f"DELETE /knowledge-add-ons/{ID}" in fake_api.paths()


async def test_removing_all_empties_the_api_too(app, fake_api, tmp_path):
    async with app.run_test(size=SIZE) as pilot:
        for number in (1, 2):
            app.run_command_line(f"/add-on {_write(tmp_path, f'note{number}.md')}")
            await wait_until(
                pilot, lambda n=number: len(fake_api.add_ons) == n, what=f"upload {number}"
            )
        app._do_clear_knowledge()
        await wait_until(pilot, lambda: not fake_api.add_ons, what="both removes")
        await app.workers.wait_for_complete()

    assert store.list_sources() == []
    assert store.all_remotes() == {}
    assert fake_api.add_ons == {}


async def test_a_file_never_uploaded_needs_no_api_remove(app, fake_api, tmp_path):
    source = store.add_source(str(_write(tmp_path)))  # straight into the local store
    async with app.run_test(size=SIZE) as pilot:
        app._do_remove_knowledge(source.id)
        await settle(pilot)
        await app.workers.wait_for_complete()

    assert [p for p in fake_api.paths() if p.startswith("DELETE ")] == []


async def test_an_api_that_already_dropped_it_does_not_warn(app, fake_api, notes, tmp_path):
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line(f"/add-on {_write(tmp_path)}")
        await wait_until(pilot, lambda: store.all_remotes(), what="the upload recorded")
        source = store.list_sources()[0]
        fake_api.add_ons.clear()  # the API lost it on its own
        app._do_remove_knowledge(source.id)
        await wait_until(pilot, lambda: len(notes) >= 2, what="the remove notice only")
        await app.workers.wait_for_complete()

    assert [text for text, _ in notes if "could not delete" in text] == []
