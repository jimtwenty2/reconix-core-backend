"""Recognising a model's "prompt too long" error, and the window it names.

LiteLLM and the servers behind it word this error in many ways, so it is matched on the
error's text. A rate-limit message is checked first, so a 429 never counts as overflow.
"""

import re

import openai

# Adapted from Strix 1.7.0 (usestrix/strix, Apache-2.0), the context-overflow error phrases.
RATE_LIMIT_PHRASES = (
    "rate limit",
    "too many requests",
    "throttling",
    "service unavailable",
    "quota",
)
OVERFLOW_PHRASES = (
    "context length",
    "context window",
    "context_length_exceeded",
    "prompt is too long",
    "input is too long",
    "maximum prompt length",
    "reduce the length of the messages",
    "too many tokens",
    "token limit exceeded",
    "request entity too large",
)
# "maximum context length is 8192", "context window of 4,096 tokens", "max context length: 8192"
WINDOW_PATTERN = re.compile(
    r"(?:maximum|max)\s+(?:model\s+)?(?:context|input)\s+(?:length|window|size)"
    r"\s*(?:is|of|:|=)?\s*(\d[\d,]*)",
    re.IGNORECASE,
)
MIN_LEARNED_WINDOW = 1_000  # a smaller number is some other figure in the message


def is_overflow(error: Exception) -> bool:
    """True when the model refused the prompt for being longer than its window."""
    import litellm  # only ever called after providers.client has set litellm's settings

    if isinstance(error, litellm.exceptions.ContextWindowExceededError):
        return True
    if not isinstance(error, openai.BadRequestError):
        return False
    text = str(error).lower()
    if any(phrase in text for phrase in RATE_LIMIT_PHRASES):
        return False
    return any(phrase in text for phrase in OVERFLOW_PHRASES)


def learned_window(error: Exception) -> int | None:
    """The window the server names ("maximum context length is 8192"), or None."""
    found = WINDOW_PATTERN.search(str(error))
    if found is None:
        return None
    window = int(found.group(1).replace(",", ""))
    return window if window >= MIN_LEARNED_WINDOW else None
