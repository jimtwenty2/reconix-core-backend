"""Masking secrets that ride along in free text (typed requests, tool output, URLs).

The vault keeps real credentials out of the data model, but an operator can still type
`https://user:pass@host`, paste a cookie into the prompt, or import tool output whose
evidence holds a token. `redact()` masks the common shapes of those before text is saved
or imported; `clean()` replaces characters that can't be encoded (lone surrogates from a
crafted JSON file) and turns every terminal escape sequence and control character XML can't
hold (NUL, ESC…; tab and line breaks stay) into a space, so a bad import can never crash a
save, a redraw or a Word report, and no two words are glued together.
`escaped_secret()` tells when a line hides a secret behind those characters; `redact()` hides
such a line whole (`HIDDEN_LINE`), since no single reading of it is sure to mask the secret.
`redact_all()` masks a list of strings as one text (`redact_lines`), so a private key stored
as one evidence entry per line is masked whole, as the web's lib/report/mask.ts does.
Besides the shapes, every secret Reconix itself holds (the target login, the saved model API
keys: `known_secrets`) is masked by its value wherever it shows up.
"""

import re
import unicodedata
from typing import Any, List

from . import known_secrets

MASK = "••••"

# Authorization schemes kept readable in front of the masked credential. A fixed list: a general
# "word, then a space" would read a bare key as its scheme and leave the key visible.
_SCHEMES = r"bearer|basic|digest|token|negotiate|ntlm|dpop|apikey|aws4-hmac-sha256"

# Plain words after "the token is …" that are no secret (the web's redact.ts: the same list)
_NOT_A_VALUE = (r"a|an|the|not|no|now|set|unset|empty|missing|invalid|expired|required|wrong|"
                r"correct|valid|stored|saved|masked|hidden|needed|ok|in|on|from|being|still|"
                r"also|only|never|always|used|sent|shown|kept|encrypted|this|that|it")

_PATTERNS = (
    # https://user:password@host → https://••••@host. The scheme starts where no scheme
    # character precedes it (a lookbehind, not \b): from every boundary inside a run such as
    # "a.a.a.…" the scheme would swallow the rest of the run and back off, quadratic in its length
    (re.compile(r"(?i)(?<![a-z0-9+.-])([a-z][a-z0-9+.-]*://)[^/\s@:]+:[^/\s@]*@"),
     rf"\g<1>{MASK}@"),
    # Authorization: Bearer … → keep the header and the scheme, mask the credential
    (re.compile(r"(?i)\b((?:proxy-)?authorization)\b(\s*[:=]\s*)((?:" + _SCHEMES + r")\s+)?"
                r"(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"), rf"\g<1>\g<2>\g<3>{MASK}"),
    # Cookie: a=1; sid=2 → every cookie on the header line, not just the first
    (re.compile(r"(?i)\b((?:set-)?cookie)(\s*:\s*)[^\r\n]+"), rf"\g<1>\g<2>{MASK}"),
    # cookie=…, password=…, api_key: "…", DB_PASSWORD=…, OPENAI_API_KEY: … → keep the name, mask
    # the value. The keyword may end a longer name (an env-style "DB_", "AWS_SECRET_" or "x-" in
    # front stays as it is): it starts where no letter or digit precedes it ("bypass=1" and
    # "compass: north" are no secret) and ":" or "=" must follow it ("passport=" is none either).
    # A lookbehind, not a scanned name prefix: a prefix tried after every "_" of a long "a_a_a…"
    # run would scan the rest of the run each time, quadratic in its length.
    (re.compile(
        r"(?i)(?<![a-z0-9])((?:set-)?cookie|pass|password|passwd|pwd|secret|"
        r"client[_-]?secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|"
        r"access[_-]?key|private[_-]?key|session[_-]?id|sessionid)"
        r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"),
     rf"\g<1>\g<2>{MASK}"),
    # "my password is hunter2", "the api key is …", "token is …": the next word is the secret,
    # unless it is one of a few plain words ("the token is invalid", "the secret is not set")
    (re.compile(
        r"(?i)(?<![a-z0-9])(pass(?:word|phrase)|passwd|api[ _-]?key|token|secret)(\s+is:?\s+)"
        r"(?!(?:" + _NOT_A_VALUE + r")(?![^\s.,;:!?]))(\"[^\"]*\"|'[^']*'|\S+)"),
     rf"\g<1>\g<2>{MASK}"),
    (re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}"), f"Bearer {MASK}"),
    # A JWT starts where no base64url character precedes it (not \b, which also matches after
    # each "-" of a run like "eyJ-eyJ-…": every start would scan to the run's end, quadratic)
    (re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
     f"{MASK} (JWT)"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), rf"\g<1>{MASK}"),
    # Provider and service keys, by their fixed prefix (kept readable, as AKIA above): OpenAI /
    # Anthropic sk-… (sk-proj-, sk-ant-), GitHub tokens, Google API keys, Slack tokens. Each
    # starts where no key character precedes it ("task-…" is no key) and needs a long body, so
    # short ids ("sk-1") stay.
    (re.compile(r"(?<![A-Za-z0-9_-])(sk-(?:proj-|ant-)?)[A-Za-z0-9_-]{20,}"), rf"\g<1>{MASK}"),
    (re.compile(r"(?<![A-Za-z0-9_])(gh[pousr]_)[A-Za-z0-9]{36,}"), rf"\g<1>{MASK}"),
    (re.compile(r"(?<![A-Za-z0-9_])(github_pat_)[A-Za-z0-9_]{22,}"), rf"\g<1>{MASK}"),
    (re.compile(r"(?<![A-Za-z0-9_-])(AIza)[0-9A-Za-z_-]{35,}"), rf"\g<1>{MASK}"),
    (re.compile(r"(?<![A-Za-z0-9-])(xox[abprs]-)[A-Za-z0-9-]{10,}"), rf"\g<1>{MASK}"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
     f"{MASK} (private key)"),
)


# Every control (Cc: C0 but tab and line feed, DEL, C1 — U+009B is an 8-bit CSI and U+009D an
# 8-bit OSC, a terminal acts on them) and format character (Cf: zero-width, bidi marks and
# isolates, soft hyphen, BOM, tags…), plus invisible characters of other classes (combining
# grapheme joiner, Mongolian variation selectors, variation selectors, Hangul fillers), the
# two non-characters (XML 1.0 can't hold them, a Word report would fail) and a lone carriage
# return (CR LF stays a line break). Any of them would split "token=" or "password" so the
# masking misses it. The web's redact.ts uses the same classes (\p{Cc}\p{Cf} and these extras).
_INVISIBLE_EXTRAS = ((0x034F, 0x034F), (0x115F, 0x1160), (0x180B, 0x180F), (0x3164, 0x3164),
                     (0xFE00, 0xFE0F), (0xFFA0, 0xFFA0), (0xFFFE, 0xFFFF), (0xE0000, 0xE007F),
                     (0xE0100, 0xE01EF))


def _control_class() -> str:
    """The character class of `_CONTROL`, built once: Cc and Cf exist only in planes 0, 1 and
    14, so only those are scanned."""
    points = {cp for start, end in ((0, 0x1FFFF), (0xE0000, 0xE0FFF))
              for cp in range(start, end + 1)
              if unicodedata.category(chr(cp)) in ("Cc", "Cf")}
    points -= {0x09, 0x0A, 0x0D}            # tab and line breaks stay; a lone CR: see below
    for start, end in _INVISIBLE_EXTRAS:
        points.update(range(start, end + 1))
    ranges, ordered = [], sorted(points)
    start = prev = ordered[0]
    for cp in ordered[1:] + [-1]:
        if cp != prev + 1:
            ranges.append(f"\\U{start:08x}" + (f"-\\U{prev:08x}" if prev != start else ""))
            start = cp
        prev = cp
    return "".join(ranges)


_CONTROL_CLASS = _control_class()
_CONTROL = re.compile(f"[{_CONTROL_CLASS}]|\\r(?!\\n)")
# The same with the tab: `clean()` keeps a tab, but one inside a secret's name splits it the
# way the other controls do ("pass<TAB>word=…" read "pass word=…"), so the hidden-secret check
# (`escaped_secret`) treats it as one of them.
_CONTROL_TAB = re.compile(f"[{_CONTROL_CLASS}\\t]|\\r(?!\\n)")


# --- control characters and terminal escape sequences ------------------------------------------
# A pasted line may carry terminal escape sequences (colour codes and worse) and invisible
# characters. Dropping them glues the words around them ("10.0.0.1<ESC>[31mtoken=x" became
# "10.0.0.1token=x": no target, and "token=" no longer masked); turning them into a space can
# split a secret's name ("pass<NUL>word=x" became "pass word=x"). So:
#   strip_controls(text) -> str   every sequence and control character becomes one space
#   escaped_secret(text) -> bool  some reading of the line (glued, spaced, control bytes dropped
#                                 or spaced, a CSI's parameters dropped) holds something the
#                                 masking hides
# A typed line where escaped_secret() is True is refused; in stored text `redact()` hides it.

# One whole sequence: CSI (ESC [ or U+009B, its parameter and intermediate bytes, then a final
# byte, or the line's end), OSC / DCS / SOS / PM / APC (ESC ] P X ^ _ or U+009D / 0090 / 0098 /
# 009E / 009F … BEL, ESC \, U+009C or the line's end) and the short ESC forms (ESC, any
# intermediate bytes, one final byte: ESC ( B, ESC M…).
_SEQUENCE = re.compile(
    r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]?"
    r"|(?:\x1b[\]PX^_]|[\x90\x98\x9d\x9e\x9f])[^\x07\x1b\x9c\n]*(?:\x07|\x1b\\|\x9c)?"
    r"|\x1b[ -/]*[0-~]?"
)
# A CSI read as if only its introducer and parameters were there: "<ESC>[31token=x" is a CSI
# whose final byte is the "t" of "token", which a terminal eats; masking must still see it.
_CSI_HEAD = re.compile(r"(?:\x1b\[|\x9b)[0-?]*")
HIDDEN_LINE = "[line hidden: control codes around a secret]"


def _encodable(text: str) -> str:
    return text.encode("utf-8", "replace").decode("utf-8")


def strip_controls(text: str) -> str:
    """`text` with every terminal escape sequence and every other control or invisible
    character (`_CONTROL`) turned into one space; tab and line breaks stay."""
    return _CONTROL.sub(" ", _SEQUENCE.sub(" ", text))


def _readings(text: str) -> List[str]:
    """The ways a line with control characters (a tab counts here) may be read: glued (each
    sequence and control removed), spaced (`strip_controls`, the tab a space too), only the
    control bytes dropped (the sequence's text stays), each control byte a space (the
    sequence's text stays: "<ESC>token=" is an ESC form that eats the "t") and only a CSI's
    introducer and parameters dropped."""
    return [
        _CONTROL_TAB.sub("", _SEQUENCE.sub("", text)),
        _CONTROL_TAB.sub(" ", _SEQUENCE.sub(" ", text)),
        _CONTROL_TAB.sub("", text),
        _CONTROL_TAB.sub(" ", text),
        _CONTROL_TAB.sub("", _CSI_HEAD.sub("", text)),
    ]


def escaped_secret(text: str) -> bool:
    """`text` holds a terminal escape sequence or a control/invisible character (a tab counts)
    AND some reading of it (`_readings`) holds something the masking hides."""
    text = _encodable(text)
    if not _CONTROL_TAB.search(text):
        return False
    readings = dict.fromkeys(_readings(text))   # each distinct reading once (a tab alone: two)
    return any(_mask(reading) != reading for reading in readings)


def _hide_lines(text: str) -> str:
    """Every line of `text` that hides a secret behind control characters, replaced whole."""
    if not _CONTROL_TAB.search(text):
        return text
    return "\n".join(HIDDEN_LINE if escaped_secret(line) else line
                     for line in text.split("\n"))


def clean(text: str) -> str:
    """`text` with characters that can't be encoded as UTF-8 (lone surrogates) replaced and
    every escape sequence and control character but tab and line breaks turned into a space."""
    return strip_controls(_encodable(text))


def _mask_known(text: str) -> str:
    """`text` with every secret Reconix holds (`known_secrets.values`, longest first) masked
    wherever it occurs as is."""
    for value in known_secrets.values():
        if value in text:
            text = text.replace(value, MASK)
    return text


def _mask(text: str) -> str:
    text = _mask_known(text)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(text: str) -> str:
    """`text` with credentials, tokens and keys masked; a line hiding a secret behind control
    characters (`escaped_secret`) becomes `HIDDEN_LINE`."""
    return _mask(clean(_hide_lines(_encodable(text))))


def redact_lines(items: List[str]) -> List[str]:
    """A list of strings masked as one text, then split back on the element boundaries.

    The elements are joined by a separator that starts and ends with a newline (so a value or
    a header line ends at an element's end, as at a line's end) around a NUL-delimited core no
    element holds (`clean()` turns NUL into a space; the round trip is checked all the same), so
    the split is exact. A match that ran across elements — a private key stored one line per
    element, which element by element would leave its middle lines bare — makes the elements
    it covered one.
    """
    if not items:
        return []
    items = [clean(_hide_lines(_encodable(item))) for item in items]
    n = 0
    while True:
        separator = f"\n\x00{n}\x00\n"
        if (not any(f"\x00{n}\x00" in item for item in items)
                and separator.join(items).split(separator) == items):
            break
        n += 1
    return _mask(separator.join(items)).split(separator)


def redact_all(value: Any) -> Any:
    """`redact()` every string inside nested dicts, lists and tuples (a list of strings as one
    text, `redact_lines`)."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_all(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        if value and all(isinstance(item, str) for item in value):
            return redact_lines(list(value))
        return [redact_all(item) for item in value]
    return value
