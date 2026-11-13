"""LLM providers through the Core API: configuration, testing, activation (store level).

The Core API is the source of truth. These tests drive the store against the fake API
(tests/fakes/fake_api.py), so they exercise the real client and store code.
"""

import pytest

from reconix import store
from reconix.core_api import providers as api
from reconix.core_api.client import CoreApiError

SECRET_KEY = "sk-live-SECRET-0ff9a"  # a fake key; only its last 4 are ever shown


# --- set / update / unset ---------------------------------------------------------------------


def test_set_provider_creates_a_row_per_model():
    view = store.set_provider("openai", api_key=SECRET_KEY, models=["gpt-4o-mini", "gpt-4o"])
    assert view.configured
    assert view.models == ("gpt-4o-mini", "gpt-4o")
    assert view.status == "UNTESTED"
    assert view.api_key_hint == "…ff9a"  # only the last 4, never the key
    assert SECRET_KEY not in view.api_key_hint


def test_frontier_provider_needs_only_a_key():
    for pid, expected in [
        ("openai", "gpt-4o-mini"),
        ("anthropic", "claude-sonnet-5-5"),
        ("deepseek", "deepseek-chat"),
    ]:
        view = store.set_provider(pid, api_key=SECRET_KEY)  # no base URL, no models
        assert view.configured
        assert view.base_url == ""
        assert expected in view.models  # the catalog's default lineup


def test_single_model_providers_reject_two_models():
    for pid in ("ollama", "openai_compatible"):
        with pytest.raises(store.StoreValidationError):
            store.set_provider(
                pid, api_key=SECRET_KEY, base_url="http://127.0.0.1/v1", models=["a", "b"]
            )


def test_a_blank_key_on_the_same_models_keeps_the_key():
    store.set_provider("openai", api_key=SECRET_KEY, models=["gpt-4o-mini"])
    before = store.get_provider("openai").api_key_hint
    view = store.set_provider("openai", models=["gpt-4o-mini"])  # blank key, same model
    assert view.api_key_hint == before  # unchanged; the API still holds the key


def test_unset_removes_the_rows():
    store.set_provider("openai", api_key=SECRET_KEY, models=["gpt-4o-mini"])
    store.unset_provider("openai")
    assert store.get_provider("openai").configured is False


def test_unset_removes_the_active_provider_and_all_its_models():
    store.set_provider("openai", api_key=SECRET_KEY, models=["gpt-4o-mini", "gpt-4o"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")
    store.core_api_approve()  # a cloud model: your OK makes it active
    store.unset_provider("openai")
    assert store.get_provider("openai").models == ()  # both rows gone, not one
    assert store.active_model() is None  # nothing was chosen in its place


def test_reconix_is_the_core_apis_own_model():
    with pytest.raises(store.StoreValidationError):
        store.set_provider("reconix", api_key=SECRET_KEY)


# --- testing ----------------------------------------------------------------------------------


def test_test_provider_marks_reachable(fake_api):
    store.set_provider("openai", api_key=SECRET_KEY, models=["gpt-4o-mini"])
    assert store.test_provider("openai").status == "REACHABLE"
    fake_api.provider_test_ok = False
    assert store.test_provider("openai").status == "UNREACHABLE"


# --- activation -------------------------------------------------------------------------------


def test_a_local_model_is_active_at_once():
    store.set_provider("ollama", base_url="http://127.0.0.1:11434", models=["llama3.2"])
    store.test_provider("ollama")
    active = store.activate("ollama", "llama3.2")
    assert active.model == "llama3.2"
    assert not store.core_api_needs_ok()
    assert store.active_model().model == "llama3.2"


def test_a_remote_model_waits_for_your_ok():
    store.set_provider("openai", api_key=SECRET_KEY, models=["gpt-4o-mini"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")
    assert store.core_api_needs_ok()  # not active until you approve
    assert store.active_model() is None
    store.core_api_approve()
    assert not store.core_api_needs_ok()
    assert store.active_model().model == "gpt-4o-mini"


def test_activate_blocked_unless_reachable():
    store.set_provider("openai", api_key=SECRET_KEY, models=["gpt-4o-mini"])
    with pytest.raises(store.StoreValidationError):  # never tested
        store.activate("openai", "gpt-4o-mini")


def test_activate_rejects_an_unknown_model():
    store.set_provider("openai", api_key=SECRET_KEY, models=["gpt-4o-mini"])
    store.test_provider("openai")
    with pytest.raises(store.StoreValidationError):
        store.activate("openai", "gpt-5-turbo")


# --- base URL safety --------------------------------------------------------------------------


def test_base_url_rejects_embedded_credentials():
    with pytest.raises(store.StoreValidationError):
        store.set_provider(
            "openai_compatible", base_url="https://user:pass@host/v1", models=["local-model"]
        )


def test_base_url_rejects_a_metadata_host():
    with pytest.raises(store.StoreValidationError):
        store.set_provider(
            "openai_compatible", base_url="http://169.254.169.254/v1", models=["local-model"]
        )


# --- the provider list ------------------------------------------------------------------------


def test_the_list_has_every_provider_reconix_first():
    ids = [p.id for p in store.list_providers()]
    assert ids[0] == "reconix"
    assert set(ids) == {"reconix", "openai", "anthropic", "deepseek", "ollama", "openai_compatible"}


# --- what a Core API answer that is not OK looks like ------------------------------------------
# The screens and the provider form catch StoreValidationError and nothing else, so a
# CoreApiError escaping here reaches Textual as an unhandled error and crashes the app.

DOWN = [
    pytest.param(lambda: store.list_providers(), id="list"),
    pytest.param(lambda: store.get_provider("openai"), id="get"),
    pytest.param(lambda: store.set_provider("deepseek", api_key=SECRET_KEY), id="set"),
    pytest.param(lambda: store.test_provider("openai"), id="test"),
    pytest.param(lambda: store.unset_provider("openai"), id="unset"),
    pytest.param(lambda: store.activate("openai", "gpt-4o-mini"), id="activate"),
]


@pytest.mark.parametrize("call", DOWN)
def test_an_api_that_is_down_is_a_store_error(fake_api, call):
    store.set_provider("openai", api_key=SECRET_KEY, models=["gpt-4o-mini"])
    fake_api.down = True
    with pytest.raises(store.StoreValidationError):
        call()


@pytest.mark.parametrize(
    "name, call",
    [
        pytest.param(
            "create", lambda: store.set_provider("deepseek", api_key=SECRET_KEY), id="create"
        ),
        pytest.param("delete", lambda: store.unset_provider("openai"), id="delete"),
        pytest.param("test", lambda: store.test_provider("openai"), id="test"),
    ],
)
def test_a_refused_write_is_a_store_error(monkeypatch, name, call):
    """The read succeeds and the write is refused (the API died mid-save, or keeps a row this
    app does not know is active): the screen must still get a warning, not a crash."""
    store.set_provider("openai", api_key=SECRET_KEY, models=["gpt-4o-mini"])

    def refuse(*_args, **_kwargs):
        raise CoreApiError("UNAUTHORIZED", "The session token is not known.")

    monkeypatch.setattr(api, name, refuse)
    with pytest.raises(store.StoreValidationError):
        call()
