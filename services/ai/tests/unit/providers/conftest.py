import pytest

from reconix_ai.providers import window


@pytest.fixture(autouse=True)
def no_window_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test asks a real server for its window: Ollama and OpenAI-compatible models get
    the baseline unless a test sets window.probe itself."""

    async def unknown(config: object, base_url: str) -> None:
        return None

    monkeypatch.setattr(window, "probe", unknown)
    monkeypatch.setattr(window, "_probed", {})
    monkeypatch.setattr(window, "_remembered", {})
    monkeypatch.setattr(window, "_failed", {})
