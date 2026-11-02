"""Masking for a model answer that arrives in pieces, so a screen can show it as it comes.

Only for showing. The whole answer is still masked once at the end, and that copy is the
one that is saved, logged and sent on.

A piece cannot be taken back once it is shown, so text is released only when masking more
text can no longer change it:

- The last HOLD_BACK characters are kept back, and the release stops at a whitespace,
  so a secret that is still arriving is never cut in two.
- What is released must read the same in the masked held-back text and in the masked
  whole text so far. A secret whose end has arrived after the cut is masked in the
  whole text, so the two differ there and the release stops before it.
- Once masking would change text that was already released, nothing more is released.

- Two rules see a secret only once it ends: a quoted value (password: "two words") and
  a secret-named XML tag (<password>two words</password>). While one is still open,
  everything from its start is held back, however long it gets.
"""

import re

from reconix_ai.harness.masking import (
    API_KEY_NAMES,
    ASSIGN,
    NAME_PREFIX,
    PASSWORD_NAMES,
    TOKEN_NAMES,
    mask_secrets,
)

HOLD_BACK = 200  # characters kept back: a secret still arriving may sit in them
WHITESPACE = " \t\r\n"
SECRET_NAMES = "(?:" + PASSWORD_NAMES + "|" + API_KEY_NAMES + "|" + TOKEN_NAMES + ")"
# The start of a quoted secret value: its closing quote may not have come yet.
OPEN_QUOTE = re.compile(NAME_PREFIX + SECRET_NAMES + ASSIGN + r"""(?P<quote>["'])""", re.I)
# The start of a secret-named XML tag: its </tag> may not have come yet.
OPEN_TAG = re.compile(r"<(?P<tag>[A-Za-z_]*" + SECRET_NAMES + r"[A-Za-z_]*)>", re.I)


class StreamMasker:
    def __init__(self) -> None:
        self._raw = ""
        self._released = ""  # masked text already handed out
        self._cut = 0  # raw characters looked at so far
        self._stopped = False

    def feed(self, piece: str) -> str:
        """Add the next raw piece; return the masked text that is safe to show now."""
        self._raw += piece
        if self._stopped:
            return ""
        end = min(len(self._raw) - HOLD_BACK, open_secret_start(self._raw))
        cut = last_whitespace(self._raw, end)
        if cut <= self._cut:
            return ""  # nothing new is safe yet: skip the masking
        self._cut = cut
        held, _ = mask_secrets(self._raw[:cut])
        whole, _ = mask_secrets(self._raw)
        safe = common_prefix(held, whole)
        if not safe.startswith(self._released):
            self._stopped = True  # it would change what was shown: show no more
            return ""
        new = safe[len(self._released) :]
        self._released = safe
        return new


def open_secret_start(text: str) -> int:
    """Where the first secret that has not ended yet starts, or len(text) when none.
    A quoted value ends at its quote or a line break, a tag's value at the next "<",
    as in the masking rules."""
    starts = [len(text)]
    for match in OPEN_QUOTE.finditer(text):
        rest = text[match.end() :]
        if match.group("quote") not in rest and "\n" not in rest:
            starts.append(match.start())
    for match in OPEN_TAG.finditer(text):
        rest = text[match.end() :]
        closing = f"</{match.group('tag')}>".lower()
        after = rest[rest.find("<") :].lower() if "<" in rest else ""
        # Open until a "<" comes that is not the closing tag still arriving.
        if not after or (len(after) < len(closing) and closing.startswith(after)):
            starts.append(match.start())
    return min(starts)


def last_whitespace(text: str, end: int) -> int:
    """The index just after the last whitespace before end, or 0 when there is none."""
    if end <= 0:
        return 0
    return max(text.rfind(char, 0, end) for char in WHITESPACE) + 1


def common_prefix(first: str, second: str) -> str:
    for index, (a, b) in enumerate(zip(first, second, strict=False)):
        if a != b:
            return first[:index]
    return first[: min(len(first), len(second))]
