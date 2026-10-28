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
        r"\b(reveal|show|print|repeat|leak)\b.{0,30}\bsystem prompt\b",
        r"\byou are no longer\b",
        # No admin or root: "...and you are now root" is a normal privilege-escalation write-up.
        r"\byou are now (an? )?(developer|god|unrestricted|jailbroken)\b",
        # Only at the start of a sentence or line, and with no article: "can a user act as
        # admin?" and "next step: act as the admin" are normal pentest steps.
        (
            r"(^|[.!?] )(please |from now on,? |now |then )?"
            r"(act|behave|pretend) (as|like|to be|you are) "
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
    return any(is_hidden(character) for character in text)


def is_hidden(character: str) -> bool:
    return (
        unicodedata.category(character) in HIDDEN_CATEGORIES
        and character not in ALLOWED_CONTROL_CHARACTERS
    )


def looks_like_prompt_injection(text: str) -> bool:
    # Hidden characters are dropped so "ig​nore" in decoded text still matches.
    text = "".join(character for character in text if not is_hidden(character))
    # NFKC turns look-alike letters (e.g. full-width) into plain ones before matching.
    text = unicodedata.normalize("NFKC", text).casefold()
    # Each line is also checked on its own, so the start of a line counts as a sentence start.
    pieces = [text, *text.splitlines()]
    return any(
        pattern.search(" ".join(piece.split()))
        for piece in pieces
        for pattern in PROMPT_INJECTION_PATTERNS
    )


def decoded_texts(text: str, levels: int = 2) -> list[str]:
    """The text hidden in base64 or hex runs, e.g. "aWdub3Jl..." -> "ignore...".

    Runs inside the decoded text are decoded too, up to `levels` deep.
    """
    decoded = []
    for run in ENCODED_TEXT.findall(text):
        for decode in (decode_base64, decode_hex):
            result = decode(run)
            if result is None:
                continue
            decoded.append(result)
            if levels > 1:
                decoded.extend(decoded_texts(result, levels - 1))
    return decoded


def decode_base64(run: str) -> str | None:
    run = run.rstrip("=")
    try:
        # altchars also accepts the URL-safe form ("-" and "_").
        data = base64.b64decode(run + "=" * (-len(run) % 4), altchars=b"-_", validate=True)
    except ValueError:
        return None
    # Bad bytes are dropped, so one stray byte cannot hide the readable text.
    return data.decode("utf-8", errors="ignore")


def decode_hex(run: str) -> str | None:
    try:
        return bytes.fromhex(run).decode("utf-8", errors="ignore")
    except ValueError:
        return None
