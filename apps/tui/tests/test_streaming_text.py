"""Tests for the StreamLine widget and typewriter streaming animation."""

import pytest
from textual.app import App, ComposeResult

from reconix.widgets.stream_text import StreamLine, tokenize_words


def test_tokenize_words_preserves_full_text():
    sample = "Hello world! This is a test: 123.\nNew line here."
    tokens = tokenize_words(sample)
    assert "".join(tokens) == sample
    assert len(tokens) > 1


def test_stream_line_immediate_under_test_env():
    """In test environment (PYTEST_CURRENT_TEST is set), StreamLine completes immediately."""
    line = StreamLine("Type a target to start.", tone="default", author="")
    assert line.is_finished
    assert "Type a target to start." in line.current_text


def test_stream_line_progressive_ticks():
    """When force_stream is enabled, _tick() advances text chunk-by-chunk until complete."""
    full = "One two three four five."
    line = StreamLine(full, tone="default", author="test-model", force_stream=True)
    assert not line.is_finished
    assert line.current_text != full

    # Advance ticks
    while not line.is_finished:
        line._tick()

    assert line.is_finished
    assert line.current_text == full


def test_stream_line_flush():
    """flush() immediately completes the streaming line and displays full text."""
    full = "A longer message that would normally take several ticks to complete."
    line = StreamLine(full, tone="muted", author="reconix", force_stream=True)
    assert not line.is_finished
    line.flush()
    assert line.is_finished
    assert line.current_text == full


def test_stream_line_update_text():
    """update_text() updates the target text and can re-stream or complete."""
    line = StreamLine("Initial text", force_stream=True)
    line.flush()
    assert line.current_text == "Initial text"

    line.update_text("Updated new text", force_stream=True)
    assert not line.is_finished
    line.flush()
    assert line.current_text == "Updated new text"


class StreamApp(App):
    def __init__(self, text: str, force_stream: bool = False):
        super().__init__()
        self.stream_line = StreamLine(text, force_stream=force_stream)

    def compose(self) -> ComposeResult:
        yield self.stream_line


@pytest.mark.asyncio
async def test_stream_line_in_textual_app():
    app = StreamApp("Testing streaming in pilot", force_stream=False)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.stream_line.is_finished
        assert "Testing streaming in pilot" in app.stream_line.current_text
