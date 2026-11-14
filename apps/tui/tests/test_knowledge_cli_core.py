"""FEATURE D2-web: the knowledge CLI also syncs each add-on to the Core API's knowledge store.

The web's Security knowledge page runs `python -m reconix.knowledge add|remove` in a subprocess,
so wiring the upload here (the /add-on shell flow, test_add_on_core.py) makes a file added from
the web searchable by the API's agent too. These tests run the CLI in process, on the conftest
fake API: the local add always happens, and the API copy is best effort, reported in the add
JSON (`agent_searchable`, `remote_problem`) so the web can show its status.
"""

import json

from reconix import store
from reconix.knowledge import cli

from .fakes.fake_api import form_of

TEXT = "# Runbook\nSQL injection reference material for the staging engagement.\n"


def write(tmp_path, name="runbook.md"):
    path = tmp_path / name
    path.write_text(TEXT)
    return path


def run(capsys, *args):
    assert cli.main(list(args)) == 0
    return json.loads(capsys.readouterr().out)


def add(capsys, tmp_path, name="runbook.md"):
    path = write(tmp_path, name)
    return run(capsys, "add", "--file", str(path), "--name", name, "--source", "web"), path


# --- add: saved here, uploaded there, said in the JSON ---------------------------------------
def test_add_sends_the_saved_file_and_records_its_id(capsys, fake_api, tmp_path):
    out, path = add(capsys, tmp_path)

    assert set(out) == {"ok", "source", "agent_searchable", "remote_problem"}
    assert out["ok"] is True and out["agent_searchable"] is True and out["remote_problem"] == ""
    [source] = store.list_sources()
    assert out["source"]["id"] == source.id
    [add_on_id] = fake_api.add_ons
    assert store.all_remotes() == {source.id: add_on_id}
    fields, file_name, file_data = form_of(fake_api.add_on_bodies[0])
    assert fields == {"interface": "cli", "name": "runbook.md"}
    assert (file_name, file_data) == ("runbook.md", path.read_bytes())  # the kept bytes, as is


def test_an_api_that_is_not_running_still_adds_locally(capsys, fake_api, tmp_path):
    fake_api.down = True
    out, _path = add(capsys, tmp_path)

    assert out["ok"] is True and out["agent_searchable"] is False
    assert "the Core API is not running" in out["remote_problem"]
    assert [s.name for s in store.list_sources()] == ["runbook.md"]
    assert store.all_remotes() == {}
    assert fake_api.add_on_bodies == []


def test_a_refused_upload_says_why_and_keeps_the_file(capsys, fake_api, tmp_path):
    fake_api.fail_on["POST /knowledge-add-ons"] = (
        503,
        "QDRANT_UNAVAILABLE",
        "Qdrant is not running",
    )
    out, _path = add(capsys, tmp_path)

    assert out["ok"] is True and out["agent_searchable"] is False
    assert out["remote_problem"] == "Qdrant is not running"
    assert len(store.list_sources()) == 1
    assert store.all_remotes() == {}


# --- remove: the local remove answers, the API copy goes too ---------------------------------
def test_remove_deletes_the_api_copy_too(capsys, fake_api, tmp_path):
    out, _path = add(capsys, tmp_path)
    [add_on_id] = fake_api.add_ons
    source_id = out["source"]["id"]

    assert run(capsys, "remove", source_id) == {"ok": True}
    assert store.list_sources() == []
    assert store.all_remotes() == {}
    assert fake_api.add_ons == {}
    assert f"DELETE /knowledge-add-ons/{add_on_id}" in fake_api.paths()


def test_removing_a_local_only_file_calls_no_delete(capsys, fake_api, tmp_path):
    fake_api.down = True
    out, _path = add(capsys, tmp_path)
    fake_api.down = False

    assert run(capsys, "remove", out["source"]["id"]) == {"ok": True}
    assert [p for p in fake_api.paths() if p.startswith("DELETE")] == []
    assert store.list_sources() == []


def test_a_dead_api_does_not_break_the_remove(capsys, fake_api, tmp_path):
    out, _path = add(capsys, tmp_path)
    fake_api.down = True

    assert run(capsys, "remove", out["source"]["id"]) == {"ok": True}
    assert store.list_sources() == []
