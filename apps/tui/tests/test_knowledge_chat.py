"""/add-on knowledge stays on this computer: the chat goes to the Core API with the line and
where the flow is, never the local knowledge files (apps/CLAUDE.md "Still local")."""

import pytest

from reconix import store

from .support import run_to

_CORPUS = {
    "runbook.md": "SQL injection was found in the search endpoint and marked high severity.",
    "policy.txt": "Scope approval requires a signed authorization from the system owner.",
}


@pytest.fixture
def api_ok(model_active):
    """The active model is approved for the Core API, so chat lines go there."""
    store.core_api_approve()


def _add_corpus(tmp_path):
    for name, text in _CORPUS.items():
        p = tmp_path / name
        p.write_text(text)
        store.add_source(str(p))


def _chats(fake_api) -> list:
    return [body["content"] for m, path, body, _ in fake_api.calls
            if m == "POST" and path.endswith("/chat")]


def test_a_relevant_question_goes_without_the_local_knowledge(api_ok, fake_api, tmp_path):
    _add_corpus(tmp_path)
    run_to("scope")
    store.say_to_assistant("what sql injection severity was in the search endpoint?")
    [sent] = _chats(fake_api)
    assert sent.startswith("what sql injection severity was in the search endpoint?")
    assert all(text not in sent for text in _CORPUS.values())
    assert "runbook.md" not in sent
    assert store.list_chat()[-1].text == fake_api.reply


def test_no_knowledge_note_is_shown_for_an_api_reply(api_ok, fake_api, tmp_path):
    _add_corpus(tmp_path)
    run_to("scope")
    store.say_to_assistant("what sql injection severity was in the search endpoint?")
    assert not any(c.text.startswith("Knowledge:") for c in store.list_chat())


def test_the_knowledge_files_stay_listed_here(api_ok, fake_api, tmp_path):
    _add_corpus(tmp_path)
    assert set(_CORPUS) <= {source.name for source in store.list_sources()}
    assert not any(p.startswith("POST /knowledge") for p in fake_api.paths())
