"""The header shows whether the Core API is reachable, and disabled menu rows say why."""

from reconix import store
from reconix.core_api import client
from reconix.widgets import ChoiceMenu
from reconix.widgets.chrome import SessionBar

from .support import settle


def test_health_is_true_when_the_api_answers(fake_api):
    assert client.health() is True


def test_health_is_false_when_the_api_is_down(fake_api):
    fake_api.down = True
    assert client.health() is False


def test_health_uses_a_short_timeout(fake_api, monkeypatch):
    seen = []

    def record(request, timeout=None):
        seen.append(timeout)
        return fake_api.send(request, timeout)

    monkeypatch.setattr(client, "_send", record)
    client.health()
    assert seen == [client.HEALTH_TIMEOUT_SECONDS]


def _bar_text(app) -> str:
    bar = app.screen.query_one(SessionBar)
    bar.refresh_line()
    return str(bar.render())


async def test_header_says_core_api_before_the_first_check(app):
    async with app.run_test(size=(160, 40)) as pilot:
        await settle(pilot)
        line = _bar_text(app)
        assert "Core API" in line and "offline" not in line


async def test_header_says_online_then_offline(app):
    async with app.run_test(size=(160, 40)) as pilot:
        await settle(pilot)
        store.set_api_online(True)
        assert "Core API" in _bar_text(app) and "offline" not in _bar_text(app)
        store.set_api_online(False)
        assert "Core API offline" in _bar_text(app)


async def test_the_model_menu_says_why_a_row_is_disabled(app, fake_api):
    """A saved-but-untested provider shows its reason, not '(not in demo)'."""
    store.set_provider("openai", api_key="sk-1234", models=["gpt-4o-mini"])
    async with app.run_test(size=(160, 40)) as pilot:
        await settle(pilot)
        app.open_model_menu()
        await settle(pilot)
        menu = app.screen.query_one("#dialog-menu", ChoiceMenu)
        prompts = [str(menu.get_option_at_index(i).prompt) for i in range(menu.option_count)]
        assert not any("not in demo" in p for p in prompts)
        assert any("Test the connection first" in p for p in prompts)
