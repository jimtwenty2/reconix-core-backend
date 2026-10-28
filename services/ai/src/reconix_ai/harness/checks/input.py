"""Input check: the first of the 5 checks.

Blocks chat text that is too long, has hidden control characters, or tries to
trick the AI (prompt injection), also when the attack is hidden in base64 or hex.

The prompt-injection patterns are best-effort: a reworded attack can get past
them. They are not the real defence. The scope, command and risk checks are,
because they judge the action itself, whatever the chat said.
"""

import base64
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
        (
            r"\b(ignore|disregard|forget|override) (the|these|those|any) "
            r"(instructions?|rules?|guardrails?)\b"
        ),
        r"\b(reveal|show|print|repeat|leak)\b.{0,30}\bsystem prompt\b",
        r"\byou are no longer\b",
        (
            r"\byou are now (an? |the )?"
            r"(admin|administrator|root|developer|god|unrestricted|jailbroken)\b"
        ),
        # Only at the start of a sentence: "can a user act as admin?" is a normal pentest question.
        (
            r"(^|[.!?:;] )(please |from now on,? |now |then )?"
            r"(act|behave|pretend) (as|like|to be|you are) (an? |the )?"
            r"(admin|administrator|root|developer|system|unrestricted|jailbroken)\b"
        ),
        r"\b(developer|god|jailbreak|dan) mode\b",
        # Only Reconix's own controls: "bypass the login checks" is a normal pentest question.
        (
            r"\b(bypass|disable|turn off|skip)\b.{0,30}"
            r"\b(guardrails?|safety checks?|scope checks?|reconix)\b"
        ),
        r"</?(system|assistant)>|\[/?inst\]",
    ]
]

# A long run that may be base64 or hex. Only its decoded text is checked, so a
# hash or a token in a normal question is not blocked.
ENCODED_TEXT = re.compile(r"[A-Za-z0-9+/_=-]{16,}")


def check_input(text: str | None) -> CheckOutcome:
    if text is None:
        return ALLOWED
    if len(text) > MAX_INPUT_LENGTH:
        return blocked("INPUT_TOO_LONG")
    if has_hidden_characters(text):
        return blocked("HIDDEN_CHARACTERS")
    if looks_like_prompt_injection(text):
        return blocked("PROMPT_INJECTION")
    if any(looks_like_prompt_injection(decoded) for decoded in decoded_texts(text)):
        return blocked("ENCODED_PROMPT_INJECTION")
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


def decoded_texts(text: str) -> list[str]:
    """The readable text hidden in base64 or hex runs, e.g. "aWdub3Jl..." -> "ignore..."."""
    decoded = []
    for run in ENCODED_TEXT.findall(text):
        for decode in (decode_base64, decode_hex):
            result = decode(run)
            if result is not None:
                decoded.append(result)
    return decoded


def decode_base64(run: str) -> str | None:
    run = run.rstrip("=")
    try:
        # altchars also accepts the URL-safe form ("-" and "_").
        data = base64.b64decode(run + "=" * (-len(run) % 4), altchars=b"-_", validate=True)
        return data.decode("utf-8")
    except ValueError:
        return None


def decode_hex(run: str) -> str | None:
    try:
        return bytes.fromhex(run).decode("utf-8")
    except ValueError:
        return None
