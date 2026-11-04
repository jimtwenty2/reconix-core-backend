"""The assistant chat and the activity log the dashboard shows.

`list_activity()` returns copies: changing a returned entry changes nothing in the store.
Store code that has to change a row reaches the assessment's own list instead.
"""

from dataclasses import replace
from typing import List, Optional, Sequence, Tuple

from ..models import ActivityEntry, ChatEntry
from . import lists
from .errors import StoreValidationError

SOURCES = ("SYS", "AI", "USER", "TOOL", "POLICY")
TONES = ("default", "ok", "warn", "block", "muted")
CHAT_KINDS = ("text", "banner", "card", "check", "thought")


def list_chat() -> List[ChatEntry]:
    return list(lists.current().chat)


def last_exchange() -> Tuple[Optional[ChatEntry], List[ChatEntry]]:
    """The operator's latest line and Reconix's entries after it; (None, []) before any."""
    chat = lists.current().chat
    for i in range(len(chat) - 1, -1, -1):
        if chat[i].speaker == "you":
            return chat[i], [e for e in chat[i + 1:] if e.speaker == "reconix"]
    return None, []


def list_activity() -> List[ActivityEntry]:
    return [replace(entry) for entry in lists.current().activity]


def add_chat(
    kind: str, speaker: str, text: str, tone: str = "default",
    rows: Sequence[Tuple[str, str]] = (), author: str = "",
) -> ChatEntry:
    if kind not in CHAT_KINDS:
        raise StoreValidationError(f"Unknown chat entry kind {kind}.")
    if tone not in TONES:
        raise StoreValidationError(f"Unknown tone {tone}.")
    entry = ChatEntry(kind, speaker, text, tone, tuple(rows), seq=lists.next_seq(),
                      author=author)
    lists.current().chat.append(entry)
    return entry


def add_activity(source: str, message: str, tone: str = "default") -> ActivityEntry:
    if source not in SOURCES:
        raise StoreValidationError(f"Unknown activity source {source}.")
    if tone not in TONES:
        raise StoreValidationError(f"Unknown tone {tone}.")
    entry = ActivityEntry(source, message, tone, seq=lists.next_seq())
    lists.current().activity.append(entry)
    return entry
