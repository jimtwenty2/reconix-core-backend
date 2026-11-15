"""Secret masking.

Replaces passwords, tokens and API keys with a label such as [MASKED:password]
and counts how many it hid. This runs before anything is saved, shown, logged,
sent to the AI or stored in Qdrant.

Text is masked by shape (a known key format, or "password=..." and similar).
Audit details are also masked by key name, so {"password": "x"} is hidden
even though "x" looks like nothing.
"""

import dataclasses
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any


@dataclass(frozen=True)
class MaskRule:
    kind: str  # the label, e.g. "password" -> "[MASKED:password]"
    pattern: re.Pattern[str]
    # Mask only this named group and keep the rest (e.g. keep "password=").
    # None masks the whole match.
    group: str | None = None


def label(kind: str) -> str:
    return f"[MASKED:{kind}]"


# A value is quoted ("..." or '...'), or ends at whitespace, a quote, "&", "," or ";".
# A quoted value ends only at the same quote it started with, so "it's" stays whole.
VALUE = (
    r"""(?P<quote>["'])?"""
    r"""(?P<secret>(?(quote)(?:(?!(?P=quote))[^\n])+|[^\s"'&,;]+))"""
    r"""(?(quote)(?P=quote))"""
)

# A key name may have a prefix, as in DB_PASSWORD or PGPASSWORD. A separated
# prefix (ending in _ or -) is always allowed; a glued prefix only when it is
# ALL CAPS, so prose like "Bypass: OpenSSL" is never read as "pass = OpenSSL".
# (?-i:...) keeps the glued prefix strictly uppercase even though the rules
# compile with re.IGNORECASE (under that flag [A-Z] would also match lowercase).
NAME_PREFIX = r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]*[_-]|(?-i:[A-Z0-9]+))?"
ASSIGN = r"""["']?\s*[:=]\s*"""

# Patterns for key names, not secrets themselves.
PASSWORD_NAMES = r"(?:password|passwd|pwd|pass)"  # noqa: S105
API_KEY_NAMES = (
    r"(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key)"
)
TOKEN_NAMES = r"(?:token|sess(?:ion)?[_-]?id|secret|credentials?)"  # noqa: S105

# Order matters: the specific shapes run first, so "Bearer eyJ..." is one token.
MASK_RULES = [
    # Up to the END line, or to the end of the text when the output was cut off.
    MaskRule(
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"
            r".*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
            re.DOTALL,
        ),
    ),
    # The whole value of a Cookie or Set-Cookie header.
    MaskRule(
        "token",
        re.compile(
            r"^[ \t]*(?:Set-)?Cookie:[ \t]*(?P<secret>[^\r\n]+)", re.IGNORECASE | re.MULTILINE
        ),
        "secret",
    ),
    # An auth header: any value shape is a secret here (also pure-letter base64).
    # Anchored to the header name like the Cookie rule above, so prose that merely
    # starts with "Token ..." ("Token Impersonation/Theft") is never a credential.
    MaskRule(
        "token",
        re.compile(
            r"(?:Authorization|Proxy-Authorization)[ \t]*:[ \t]*"
            r"(?:Bearer|Basic|Token)[ \t]+(?P<secret>[A-Za-z0-9._~+/=-]{8,})",
            re.IGNORECASE,
        ),
        "secret",
    ),
    # Elsewhere the value must contain a digit: real tokens do, English words
    # ("Basic Input/Output", "Token mechanism") do not. Known token shapes
    # (JWT, ghp_, AKIA, ...) are masked by their own rules below, digit or not.
    MaskRule(
        "token",
        re.compile(
            r"\b(?:Bearer|Basic|Token)\s+"
            r"(?P<secret>(?=[A-Za-z0-9._~+/=-]*[0-9])[A-Za-z0-9._~+/=-]{8,})",
            re.IGNORECASE,
        ),
        "secret",
    ),
    MaskRule("token", re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    MaskRule("token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    MaskRule("token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    MaskRule("token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    MaskRule("token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    MaskRule("api_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    MaskRule("api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    MaskRule("api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    MaskRule("api_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    # user:password@host inside a URL. The password may contain "@", so it runs
    # to the last "@" before the host.
    MaskRule(
        "password",
        re.compile(r"(?<=://)[^/\s:@]+:(?P<secret>[^/\s]+)(?=@[^@/\s]+)"),
        "secret",
    ),
    # <password>...</password> and similar XML tags
    MaskRule(
        "password",
        re.compile(
            r"<(?P<tag>[A-Za-z_]*" + PASSWORD_NAMES + r"[A-Za-z_]*)>(?P<secret>[^<]+)</(?P=tag)>",
            re.IGNORECASE,
        ),
        "secret",
    ),
    MaskRule(
        "token",
        re.compile(
            r"<(?P<tag>[A-Za-z_]*(?:" + API_KEY_NAMES + "|" + TOKEN_NAMES + r")[A-Za-z_]*)>"
            r"(?P<secret>[^<]+)</(?P=tag)>",
            re.IGNORECASE,
        ),
        "secret",
    ),
    # password=..., "password": "...", DB_PASSWORD: ...
    MaskRule(
        "password",
        re.compile(NAME_PREFIX + PASSWORD_NAMES + ASSIGN + VALUE, re.IGNORECASE),
        "secret",
    ),
    MaskRule(
        "api_key",
        re.compile(NAME_PREFIX + API_KEY_NAMES + ASSIGN + VALUE, re.IGNORECASE),
        "secret",
    ),
    MaskRule(
        "token",
        re.compile(NAME_PREFIX + TOKEN_NAMES + ASSIGN + VALUE, re.IGNORECASE),
        "secret",
    ),
]

# Key names in audit details whose value is always a secret, checked in order.
SECRET_KEYS = [
    ("password", re.compile(PASSWORD_NAMES, re.IGNORECASE)),
    ("private_key", re.compile(r"private[_-]?key", re.IGNORECASE)),
    ("api_key", re.compile(API_KEY_NAMES, re.IGNORECASE)),
    ("token", re.compile(TOKEN_NAMES + r"|authorization|cookie", re.IGNORECASE)),
]


def mask_secrets(text: str) -> tuple[str, int]:
    """Return the text with every secret replaced, and how many were replaced."""
    total = 0
    for rule in MASK_RULES:
        text, count = apply_rule(rule, text)
        total += count
    return text, total


def apply_rule(rule: MaskRule, text: str) -> tuple[str, int]:
    count = 0

    def swap(match: re.Match[str]) -> str:
        nonlocal count
        if rule.group is None:
            count += 1
            return label(rule.kind)
        if match.group(rule.group).startswith("[MASKED:"):
            return match.group(0)  # already masked by an earlier rule
        count += 1
        # Keep the text around the secret, e.g. the "password=" in front of it.
        start = match.start(rule.group) - match.start()
        end = match.end(rule.group) - match.start()
        whole = match.group(0)
        return whole[:start] + label(rule.kind) + whole[end:]

    return rule.pattern.sub(swap, text), count


def mask_value(value: Any) -> tuple[Any, int]:
    """Mask every string inside a value, for audit details.

    Dicts, lists, tuples and sets are walked; a value under a secret key name
    is masked whole. Anything else (bytes, models, objects) becomes masked text,
    so nothing reaches the log through its str().
    """
    if value is None or isinstance(value, bool | int | float):
        return value, 0
    if isinstance(value, str):
        return mask_secrets(value)
    if isinstance(value, dict):
        return mask_dict(value)
    if isinstance(value, list | tuple | set | frozenset):
        items, total = [], 0
        for item in value:
            masked_item, count = mask_value(item)
            items.append(masked_item)
            total += count
        return (tuple(items) if isinstance(value, tuple) else items), total
    return mask_value(plain_value(value))


def mask_dict(value: dict) -> tuple[dict, int]:
    masked, total = {}, 0
    for key, item in value.items():
        masked_key, key_count = mask_secrets(str(key))
        kind = secret_key_kind(masked_key)
        if kind is not None and isinstance(item, str | bytes) and item:
            masked[masked_key], count = label(kind), 1
        else:
            masked[masked_key], count = mask_value(item)
        total += key_count + count
    return masked, total


def secret_key_kind(key: str) -> str | None:
    for kind, pattern in SECRET_KEYS:
        if pattern.search(key):
            return kind
    return None


def plain_value(value: Any) -> Any:
    """Turn a value that is not plain JSON into a dict or text that can be masked."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, datetime | date):
        return value.isoformat()
    if hasattr(value, "model_dump"):  # a pydantic model
        return value.model_dump(mode="json")
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    return str(value)
