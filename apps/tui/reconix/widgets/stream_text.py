"""A streaming typewriter-style line for Reconix AI and static replies.

Reveals text progressively word-by-word with a Textual timer to give canned and AI
messages the responsive feel of a streaming LLM response.
"""

import os
import re
from typing import Callable, List, Optional

from rich.text import Text
from textual.timer import Timer
from textual.widgets import Static

from .. import theme

DEFAULT_INTERVAL = 0.025  # 25ms per tick (~40-50 words/sec)
WORDS_PER_TICK = 1


def tokenize_words(text: str) -> List[str]:
    """Split text into words preserving whitespace so `"".join(tokens) == text`."""
    if not text:
        return []
    return re.findall(r"\S+\s*|\s+", text)


def is_animation_enabled(force: bool = False) -> bool:
    """True when streaming animation is enabled; disabled under tests or explicit opt-out."""
    if force:
        return True
    if os.environ.get("RECONIX_ANIMATE_STREAM", "").lower() in ("0", "false", "no"):
        return False
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return False
    return True


def speaker_label(author: str = "") -> str:
    """`◆ reconix  ` for Reconix's own lines, `◆ <model>  ` for a model's (`author`)."""
    return f"◆ {author or 'reconix'}  "


def reply_line(text: str, tone: str = "default", author: str = "") -> Text:
    """Build the Rich Text line for a reply with cyan speaker tag and tone-colored text."""
    return Text.assemble(
        (speaker_label(author), f"bold {theme.CYAN}"),
        (text, theme.TONE.get(tone, theme.TEXT)),
    )


class StreamLine(Static):
    """A chat reply that streams text progressively like an active LLM generation.

    Calling `flush()` instantly reveals the entire remaining text and cancels the timer.
    """

    def __init__(
        self,
        full_text: str,
        tone: str = "default",
        author: str = "",
        *,
        force_stream: bool = False,
        interval: float = DEFAULT_INTERVAL,
        words_per_tick: int = WORDS_PER_TICK,
        on_done: Optional[Callable[[], None]] = None,
        id: Optional[str] = None,
        classes: Optional[str] = "chat-line",
    ) -> None:
        self.tone = tone
        self.author = author
        self.interval = interval
        self.words_per_tick = words_per_tick
        self.on_done = on_done
        self._force_stream = force_stream

        self._full_text = full_text
        self._tokens: List[str] = tokenize_words(full_text)
        self._token_idx: int = 0
        self._timer: Optional[Timer] = None

        if not is_animation_enabled(force_stream) or not self._tokens:
            self._token_idx = len(self._tokens)
            self._current_text = full_text
        else:
            self._token_idx = min(self.words_per_tick, len(self._tokens))
            self._current_text = "".join(self._tokens[: self._token_idx])

        super().__init__(
            reply_line(self._current_text, self.tone, self.author),
            id=id,
            classes=classes,
        )

    @property
    def is_finished(self) -> bool:
        return self._token_idx >= len(self._tokens)

    @property
    def current_text(self) -> str:
        return self._current_text

    def _render_current(self) -> None:
        content = reply_line(self._current_text, self.tone, self.author)
        try:
            self.update(content)
        except Exception:
            pass

    def on_mount(self) -> None:
        if not self.is_finished:
            self._timer = self.set_interval(self.interval, self._tick)

    def _tick(self) -> None:
        """Advance by the next chunk of words and re-render."""
        if self.is_finished:
            self._stop_timer()
            return

        self._token_idx = min(self._token_idx + self.words_per_tick, len(self._tokens))
        self._current_text = "".join(self._tokens[: self._token_idx])
        self._render_current()

        parent = self.parent
        if parent is not None and hasattr(parent, "scroll_to_end"):
            parent.scroll_to_end()
        elif parent is not None and hasattr(parent, "scroll_end"):
            self.call_after_refresh(parent.scroll_end, animate=False)

        if self.is_finished:
            self._stop_timer()
            if self.on_done:
                self.on_done()

    def _stop_timer(self) -> None:
        if self._timer is not None:
            self._timer.stop()
            self._timer = None

    def flush(self) -> None:
        """Instantly show all remaining text and stop animation."""
        self._stop_timer()
        self._token_idx = len(self._tokens)
        self._current_text = self._full_text
        self._render_current()
        if self.on_done:
            self.on_done()

    def update_text(
        self,
        new_text: str,
        tone: Optional[str] = None,
        author: Optional[str] = None,
        *,
        force_stream: Optional[bool] = None,
    ) -> None:
        """Update the message text; streams newly added content if animated."""
        self._stop_timer()
        if tone is not None:
            self.tone = tone
        if author is not None:
            self.author = author
        if force_stream is not None:
            self._force_stream = force_stream

        self._full_text = new_text
        self._tokens = tokenize_words(new_text)

        if not is_animation_enabled(self._force_stream) or not self._tokens:
            self._token_idx = len(self._tokens)
            self._current_text = new_text
            self._render_current()
        else:
            self._token_idx = min(self.words_per_tick, len(self._tokens))
            self._current_text = "".join(self._tokens[: self._token_idx])
            self._render_current()
            if self.is_mounted:
                self._timer = self.set_interval(self.interval, self._tick)
