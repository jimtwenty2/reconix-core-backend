"""Input check: the first of the 5 checks.

Blocks chat text that is too long, has hidden control characters, or tries to
trick the AI (prompt injection).
"""

import re
import unicodedata

from reconix_ai.harness.checks.result import ALLOWED, CheckOutcome, blocked

MAX_INPUT_LENGTH = 4000

# Normal whitespace is fine. Every other control (Cc) or format (Cf) character
# is hidden from the reader, e.g. zero-width spaces and right-to-left overrides.
ALLOWED_CONTROL_CHARACTERS = {"\n", "\r", "\t"}
HIDDEN_CATEGORIES = {"Cc", "Cf"}

PROMPT_INJECTION_PATTERNS = [
    re.compile(pattern)
    for pattern in [
        (
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|your)\b"
            r".{0,20}\b(instructions?|rules?|prompts?|guardrails?|polic(y|ies))\b"
        ),
        r"\b(reveal|show|print|repeat|leak)\b.{0,30}\bsystem prompt\b",
        r"\byou are no longer\b",
        r"\b(developer|god|jailbreak|dan) mode\b",
        # Only Reconix's own controls: "bypass the login checks" is a normal pentest question.
        (
            r"\b(bypass|disable|turn off|skip)\b.{0,30}"
            r"\b(guardrails?|safety checks?|scope checks?|reconix)\b"
        ),
        r"</?(system|assistant)>|\[/?inst\]",
    ]
]


def check_input(text: str | None) -> CheckOutcome:
    if text is None:
        return ALLOWED
    if len(text) > MAX_INPUT_LENGTH:
        return blocked("INPUT_TOO_LONG")
    if has_hidden_characters(text):
        return blocked("HIDDEN_CHARACTERS")
    if looks_like_prompt_injection(text):
        return blocked("PROMPT_INJECTION")
    return ALLOWED


def has_hidden_characters(text: str) -> bool:
    return any(
        unicodedata.category(character) in HIDDEN_CATEGORIES
        and character not in ALLOWED_CONTROL_CHARACTERS
        for character in text
    )


def looks_like_prompt_injection(text: str) -> bool:
    # NFKC turns look-alike letters (e.g. full-width) into plain ones before matching.
    normalized = " ".join(unicodedata.normalize("NFKC", text).casefold().split())
    return any(pattern.search(normalized) for pattern in PROMPT_INJECTION_PATTERNS)
