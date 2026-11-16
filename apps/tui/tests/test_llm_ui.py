"""Flexible LLM: the /provider menu, the provider form and the status bar (Pilot)."""

from textual.widgets import Input

from reconix import store
from reconix.screens import ChoiceScreen
from reconix.screens.forms import ProviderForm
from reconix.widgets.chrome import SessionBar

from .support import SIZE, settle


def _bar_text(app) -> str:
    bar = app.screen.query_one(SessionBar)
    bar.refresh_line()
    return str(bar.render())


async def test_provider_command_opens_the_menu(app):
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/provider")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        ids = [c.id for c in app.screen._choices]
        assert ids[0] == "reconix" and "openai" in ids


async def test_provider_form_saves_through_the_store(app):
    async with app.run_test(size=SIZE) as pilot:
        app.open_provider_form("openai")
        await settle(pilot)
        assert isinstance(app.screen, ProviderForm)
        # A cloud provider's form is key-only: no base URL or models field.
        assert not app.screen.query("#base_url") and not app.screen.query("#models")
        app.screen.query_one("#api_key", Input).value = "sk-test-key-9999"
        app.screen.query_one("#submit").press()
        await settle(pilot)
        view = store.get_provider("openai")
        assert view.configured and view.models == ("gpt-4o-mini", "gpt-4o")  # built-in


async def test_status_bar_shows_active_model(app, reachable):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        assert "off" in _bar_text(app)  # nothing active yet
        store.set_provider("openai", api_key="sk-1234", models=["gpt-4o-mini"])
        store.test_provider("openai")
        store.activate("openai", "gpt-4o-mini")
        store.core_api_approve()  # a remote model: your OK makes it active
        text = _bar_text(app)
        assert "OpenAI" in text and "gpt-4o-mini" in text


async def test_unset_dialog_defaults_to_keep(app, reachable):
    store.set_provider("ollama", models=["llama3.1"])
    async with app.run_test(size=SIZE) as pilot:
        app.confirm_unset("ollama")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("enter")  # the default is "No, keep it"
        await settle(pilot)
        assert store.get_provider("ollama").configured  # still there


async def test_unset_the_active_model_removes_it_without_crashing(app, reachable):
    store.set_provider("openai", api_key="sk-1234", models=["gpt-4o-mini"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")
    store.core_api_approve()
    async with app.run_test(size=SIZE) as pilot:
        app.confirm_unset("openai")
        await settle(pilot)
        await pilot.press("down")  # "Yes, remove it"
        await pilot.press("enter")
        await settle(pilot)
        assert store.get_provider("openai").configured is False
        assert "off" in _bar_text(app)  # the top bar says there is no model now


# --- the whole flow, keys only ------------------------------------------------------------------


async def test_the_unset_flow_from_the_command_line(app, reachable):
    """The reported path, walked as a person does it: /provider → the provider → Unset →
    Yes, remove it. It removes the provider, leaves no model active, and does not crash."""
    store.set_provider("anthropic", api_key="sk-ant-1234")
    store.test_provider("anthropic")
    store.activate("anthropic", "claude-sonnet-5-5")
    store.core_api_approve()
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/provider anthropic")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)  # the provider's submenu
        for _ in range(3):  # down to "4. Unset"
            await pilot.press("down")
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)  # "REMOVE ANTHROPIC?"
        await pilot.press("down")  # "Yes, remove it"
        await pilot.press("enter")
        await settle(pilot)
        assert not isinstance(app.screen, ChoiceScreen)  # the dialog closed, the app lives
        assert store.get_provider("anthropic").configured is False
        assert "off" in _bar_text(app)  # no model now: the next /model picks one


async def test_unset_after_choosing_another_model_removes_it(app, reachable):
    """What the refusal tells you to do works: choose another model, then Unset removes it."""
    store.set_provider("anthropic", api_key="sk-ant-1234")
    store.test_provider("anthropic")
    store.activate("anthropic", "claude-sonnet-5-5")
    store.core_api_approve()
    store.set_provider("ollama", base_url="http://127.0.0.1:11434", models=["llama3.1"])
    store.test_provider("ollama")
    store.activate("ollama", "llama3.1")
    async with app.run_test(size=SIZE) as pilot:
        app.provider_command("unset anthropic")
        await settle(pilot)
        await pilot.press("down")  # "Yes, remove it"
        await pilot.press("enter")
        await settle(pilot)
        assert store.get_provider("anthropic").configured is False
        assert "llama3.1" in _bar_text(app)


async def test_the_provider_menu_with_the_core_api_down(app, fake_api):
    """Opening /provider must not crash when the API is not running: it says so and stays put."""
    async with app.run_test(size=SIZE) as pilot:
        fake_api.down = True
        app.run_command_line("/provider")
        await settle(pilot)
        assert not isinstance(app.screen, ChoiceScreen)
        app.run_command_line("/model")
        await settle(pilot)
        assert not isinstance(app.screen, ChoiceScreen)


async def test_the_reconix_menu_has_set_test_model_and_unset(app):
    async with app.run_test(size=SIZE) as pilot:
        app.open_provider_submenu("reconix")
        await settle(pilot)
        choices = {c.id: c for c in app.screen._choices}
        assert list(choices) == ["set", "test", "model", "unset"]
        assert choices["set"].label == "Set up Reconix (default)"
        assert choices["set"].hint == "API key"
        assert choices["test"].disabled and choices["unset"].disabled  # not set up yet
        store.set_provider("reconix", api_key="sk-reconix-1111")
        app.open_provider_submenu("reconix")
        await settle(pilot)
        choices = {c.id: c for c in app.screen._choices}
        assert choices["set"].label == "Update Reconix (default)"
        assert not choices["test"].disabled and not choices["unset"].disabled


async def test_update_then_unset_then_set_up_reconix_again(app):
    store.set_provider("reconix", api_key="sk-reconix-1111")
    async with app.run_test(size=SIZE) as pilot:
        app.open_provider_form("reconix")
        await settle(pilot)
        assert isinstance(app.screen, ProviderForm)
        assert not app.screen.query("#base_url") and not app.screen.query("#models")
        app.screen.query_one("#api_key", Input).value = "sk-reconix-2222"
        app.screen.query_one("#submit").press()
        await settle(pilot)
        assert store.get_provider("reconix").api_key_hint == "…2222"
        store.unset_provider("reconix")
        assert not store.get_provider("reconix").configured
        app.open_provider_submenu("reconix")
        await settle(pilot)
        assert app.screen._choices[0].label == "Set up Reconix (default)"
        store.set_provider("reconix", api_key="sk-reconix-3333")
        assert store.get_provider("reconix").configured


async def test_the_reconix_form_has_no_env_wording_and_clears_the_key(app):
    store.set_provider("reconix", api_key="sk-reconix-1111")
    async with app.run_test(size=SIZE) as pilot:
        app.open_provider_form("reconix")
        await settle(pilot)
        assert ".env" not in str(app.screen.note() or "")
        field = app.screen.query_one("#api_key", Input)
        assert field.placeholder == "saved key …1111 · leave blank to remove it"
        field.value = ""  # cleared: the key is unset
        app.screen.query_one("#submit").press()
        await settle(pilot)
        assert store.get_provider("reconix").api_key_hint == ""
        app.screen.dismiss(None)  # the "test it now?" prompt
        await settle(pilot)
        app.open_provider_form("reconix")
        await settle(pilot)
        assert app.screen.query_one("#api_key", Input).placeholder == "no key set · sk-…"
